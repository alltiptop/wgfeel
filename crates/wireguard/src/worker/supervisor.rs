use super::{
    RequestId, Submission, WorkerError, WorkerEvent, WorkerInfo, WorkerOptions, WorkerState,
    process::Process,
    protocol::{self, Operation, Output, Reply, Request},
};
use crate::{
    ContextConfig, ContextId, DatagramEvent, Limits, PacketBytes, PeerConfig, PeerId, PrivateKey,
    WireGuardError,
    dispatch::{DispatchContext, DispatchError, IndexBinding, MAX_INDICES_PER_PEER},
    framing,
    gateway::{validate_context_configs, validate_endpoint},
    router::{Router, Verification},
};
use gotatun::{noise::rate_limiter::RateLimiter, packet::Packet, x25519::PublicKey};
use rustix::event::{PollFd, PollFlags, Timespec};
use std::{
    fmt,
    net::SocketAddr,
    os::fd::BorrowedFd,
    sync::Arc,
    time::{Duration, Instant},
};
use wgfeel_core::DevicePublicKey;
use zeroize::Zeroizing;

struct Peer {
    id: PeerId,
    public_key: DevicePublicKey,
    endpoint: Option<SocketAddr>,
}
enum Phase {
    AwaitReady,
    Bootstrap,
    Idle,
    Pending(Pending),
    Failed,
}
struct Worker {
    context: ContextId,
    public_key: DevicePublicKey,
    peers: Vec<Peer>,
    generation: u64,
    pid: u32,
    process: Option<Process>,
    bootstrap: Option<Zeroizing<Vec<u8>>>,
    phase: Phase,
    deadline: Option<Instant>,
    next_sequence: u64,
}
struct Pending {
    request: RequestId,
    operation: Expected,
}
enum Expected {
    Receive {
        peer: Option<u16>,
        kind: u8,
        source: SocketAddr,
        sender: Option<u32>,
    },
    Initiate {
        peer: u16,
        destination: SocketAddr,
    },
    Send {
        peer: u16,
        destination: SocketAddr,
    },
    Tick {
        peer: u16,
        destination: Option<SocketAddr>,
    },
    Reset {
        peer: u16,
    },
    SetServicePeers {
        peers: Vec<PeerConfig>,
    },
}
impl Expected {
    fn peer(&self) -> Option<u16> {
        match self {
            Self::SetServicePeers { .. } => None,
            Self::Receive { peer, .. } => *peer,
            Self::Initiate { peer, .. }
            | Self::Send { peer, .. }
            | Self::Tick { peer, .. }
            | Self::Reset { peer } => Some(*peer),
        }
    }
    fn destination(&self) -> Option<SocketAddr> {
        match self {
            Self::Receive { source, .. } => Some(*source),
            Self::Initiate { destination, .. } | Self::Send { destination, .. } => {
                Some(*destination)
            }
            Self::Tick { destination, .. } => *destination,
            Self::Reset { .. } | Self::SetServicePeers { .. } => None,
        }
    }
}

/// Trusted public packet dispatcher. Each context's crypto state lives in a
/// fresh confined process. Raw plaintext still needs source binding and ACLs.
pub struct WorkerGateway {
    workers: Vec<Worker>,
    router: Router,
    options: WorkerOptions,
    limits: Limits,
    cursor: usize,
}
impl fmt::Debug for WorkerGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerGateway")
            .field("workers", &self.workers())
            .finish_non_exhaustive()
    }
}

impl WorkerGateway {
    /// The current executable must call worker_main before other initialization.
    /// All configurations are checked before any child is spawned. No keys are
    /// sent until that child's mandatory confinement has reported readiness.
    /// The calling thread must outlive the workers: Linux delivers SIGKILL to
    /// each worker when the thread that spawned it exits, even if other parent
    /// threads remain alive. The same requirement applies when restarting.
    pub fn spawn(
        configs: Vec<ContextConfig>,
        limits: Limits,
        options: WorkerOptions,
    ) -> Result<Self, WorkerError> {
        validate_options(options)?;
        let public_keys =
            validate_context_configs(&configs, limits).map_err(WorkerError::WireGuard)?;
        let metadata = configs
            .iter()
            .zip(&public_keys)
            .map(|(config, key)| {
                (
                    DispatchContext {
                        context: config.id.clone(),
                        peers: config.peers.iter().map(|peer| peer.id.clone()).collect(),
                    },
                    Arc::new(RateLimiter::new(
                        &PublicKey::from(*key.as_bytes()),
                        u64::from(limits.handshake_limit_per_ip),
                    )),
                )
            })
            .collect();
        let router = Router::new(metadata).map_err(WorkerError::WireGuard)?;
        let mut gateway = Self {
            workers: Vec::with_capacity(configs.len()),
            router,
            options,
            limits,
            cursor: 0,
        };
        for (slot, (config, key)) in configs.into_iter().zip(public_keys).enumerate() {
            let generation = gateway.router.generation(slot);
            gateway
                .workers
                .push(Worker::spawn(config, key, generation, limits, options)?);
        }
        Ok(gateway)
    }
    pub fn workers(&self) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .map(|worker| WorkerInfo {
                context: worker.context.clone(),
                generation: worker.generation,
                pid: worker.pid,
                state: match worker.phase {
                    Phase::AwaitReady | Phase::Bootstrap => WorkerState::Starting,
                    Phase::Idle => WorkerState::Ready,
                    Phase::Pending(_) => WorkerState::Busy,
                    Phase::Failed => WorkerState::Failed,
                },
            })
            .collect()
    }
    /// Wait for worker pipe activity or caller-owned readable descriptors.
    /// No bytes are consumed and no worker state changes; call poll afterwards
    /// to process readiness, child exit and deadlines. At most eight external
    /// descriptors and sixty seconds are accepted, including a zero timeout.
    pub fn wait_for_activity(
        &self,
        readable: &[BorrowedFd<'_>],
        maximum: Duration,
    ) -> Result<(), WorkerError> {
        if readable.len() > 8 || maximum > Duration::from_secs(60) {
            return Err(WorkerError::InvalidConfiguration);
        }
        let mut descriptors = Vec::with_capacity(self.workers.len() * 2 + readable.len());
        for descriptor in readable {
            descriptors.push(PollFd::from_borrowed_fd(*descriptor, PollFlags::IN));
        }
        let now = Instant::now();
        let mut timeout = maximum;
        for worker in &self.workers {
            // Failed workers have no live process. Their closed/EOF pipes
            // must not keep an otherwise idle foreground loop awake.
            if let Some(process) = &worker.process {
                process.append_poll_fds(&mut descriptors)?;
                // The I/O budget can end after the final body byte but before
                // the trailing-byte probe. Finish that work without waiting
                // for another byte or allowing the operation deadline to pass.
                if process.has_complete_buffered_frame() {
                    timeout = Duration::ZERO;
                }
                if let Some(deadline) = worker.deadline {
                    timeout = timeout.min(deadline.saturating_duration_since(now));
                }
            }
        }
        let timeout = Timespec::try_from(timeout).map_err(|_| WorkerError::InvalidConfiguration)?;
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(_) => Err(WorkerError::Io),
        }
    }

    /// Drives bounded nonblocking I/O in round-robin order. The caller must
    /// keep polling for deadlines and child death to be observed.
    pub fn poll(&mut self) -> Option<WorkerEvent> {
        for _ in 0..self.workers.len() {
            let slot = self.cursor;
            self.cursor = (self.cursor + 1) % self.workers.len();
            if matches!(self.workers[slot].phase, Phase::Failed) {
                continue;
            }
            match self.poll_one(slot) {
                Ok(Some(event)) => return Some(event),
                Ok(None) => {}
                Err(reason) => return Some(self.fail(slot, reason)),
            }
        }
        None
    }
    pub fn receive_datagram(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Submission, WorkerError> {
        validate_endpoint(source).map_err(WorkerError::WireGuard)?;
        let admission = self
            .router
            .admit(source, bytes)
            .map_err(WorkerError::WireGuard)?;
        let slot = admission.slot;
        self.workers[slot].ready()?;
        match admission.verified {
            Verification::Challenge(packet) => {
                let packet: Packet = packet.into();
                Ok(Submission::Immediate(DatagramEvent::Network {
                    destination: source,
                    context: self.workers[slot].context.clone(),
                    peer: admission.peer,
                    packet: PacketBytes(packet.to_vec()),
                }))
            }
            Verification::Packet(_) => {
                let peer = admission
                    .peer
                    .as_ref()
                    .map(|peer| self.workers[slot].peer(peer))
                    .transpose()?;
                let expected = Expected::Receive {
                    peer,
                    kind: bytes[0],
                    source,
                    sender: matches!(bytes[0], 1 | 2).then(|| index_at(bytes, 4)),
                };
                self.submit(
                    slot,
                    Operation::Receive {
                        peer,
                        packet: bytes.to_vec(),
                    },
                    expected,
                )
                .map(Submission::Queued)
            }
        }
    }
    pub fn initiate_at(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        destination: SocketAddr,
    ) -> Result<RequestId, WorkerError> {
        validate_endpoint(destination).map_err(WorkerError::WireGuard)?;
        let (slot, peer) = self.select(context, peer)?;
        let request = self.submit(
            slot,
            Operation::Initiate { peer },
            Expected::Initiate { peer, destination },
        )?;
        self.workers[slot].peers[usize::from(peer)].endpoint = Some(destination);
        Ok(request)
    }
    pub fn send_datagram(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        packet: &[u8],
    ) -> Result<RequestId, WorkerError> {
        let (slot, peer) = self.select(context, peer)?;
        self.workers[slot].ready()?;
        framing::ip_length(packet, false).map_err(WorkerError::WireGuard)?;
        let destination = self.workers[slot].peers[usize::from(peer)]
            .endpoint
            .ok_or(WorkerError::WireGuard(WireGuardError::NoEndpoint))?;
        self.submit(
            slot,
            Operation::Send {
                peer,
                packet: packet.to_vec(),
            },
            Expected::Send { peer, destination },
        )
    }
    pub fn tick(&mut self, context: &ContextId, peer: &PeerId) -> Result<RequestId, WorkerError> {
        let (slot, peer) = self.select(context, peer)?;
        let destination = self.workers[slot].peers[usize::from(peer)].endpoint;
        self.submit(
            slot,
            Operation::Tick { peer },
            Expected::Tick { peer, destination },
        )
    }
    pub fn reset(&mut self, context: &ContextId, peer: &PeerId) -> Result<RequestId, WorkerError> {
        let (slot, peer) = self.select(context, peer)?;
        self.submit(slot, Operation::Reset { peer }, Expected::Reset { peer })
    }
    /// Trusted coordinator operation. Changes only the service worker and keeps
    /// unchanged peer sessions alive. Publication happens after a checked reply.
    pub fn set_service_peers(&mut self, peers: Vec<PeerConfig>) -> Result<RequestId, WorkerError> {
        let slot = self.slot(&ContextId::Service)?;
        if peers.len() > crate::MAX_SERVICE_PEERS {
            return Err(WorkerError::InvalidConfiguration);
        }
        for (index, peer) in peers.iter().enumerate() {
            if !matches!(peer.id, PeerId::Node(_))
                || peers[..index]
                    .iter()
                    .any(|prior| prior.id == peer.id || prior.public_key == peer.public_key)
            {
                return Err(WorkerError::InvalidConfiguration);
            }
        }
        self.submit(
            slot,
            Operation::SetServicePeers {
                peers: peers.clone(),
            },
            Expected::SetServicePeers { peers },
        )
    }
    pub(super) fn service_peers(&self) -> Result<Vec<PeerConfig>, WorkerError> {
        let slot = self.slot(&ContextId::Service)?;
        Ok(self.workers[slot]
            .peers
            .iter()
            .map(|peer| PeerConfig {
                id: peer.id.clone(),
                public_key: peer.public_key.clone(),
            })
            .collect())
    }

    pub(super) fn inherit_service(&mut self, previous: &mut Self) -> Result<(), WorkerError> {
        let slot = self.slot(&ContextId::Service)?;
        let old = previous.slot(&ContextId::Service)?;
        self.workers[slot].ready()?;
        previous.workers[old].ready()?;
        if self.workers[slot].public_key != previous.workers[old].public_key {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.router
            .inherit_service(&mut previous.router)
            .map_err(WorkerError::WireGuard)?;
        std::mem::swap(&mut self.workers[slot], &mut previous.workers[old]);
        // Idle workers have no outstanding request IDs. Subsequent requests use
        // the destination registry's lease, retaining the process sequence.
        self.workers[slot].generation = self.router.generation(slot);
        Ok(())
    }
    /// Restart only the identical configured public identity. Desired-state
    /// changes must be accepted through the Management projection boundary.
    pub fn restart(&mut self, config: ContextConfig) -> Result<(), WorkerError> {
        let slot = self.slot(&config.id)?;
        let keys = validate_context_configs(std::slice::from_ref(&config), self.limits)
            .map_err(WorkerError::WireGuard)?;
        let current = &self.workers[slot];
        if keys[0] != current.public_key
            || config.peers.len() != current.peers.len()
            || config
                .peers
                .iter()
                .zip(&current.peers)
                .any(|(a, b)| a.id != b.id || a.public_key != b.public_key)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        // Revocation precedes replacement. Spawn failure leaves only this
        // context failed and without receiver routes; no automatic retry.
        self.fail(slot, WorkerError::NotReady);
        self.router.restart(slot).map_err(WorkerError::WireGuard)?;
        let generation = self.router.generation(slot);
        match Worker::spawn(
            config,
            keys[0].clone(),
            generation,
            self.limits,
            self.options,
        ) {
            Ok(worker) => {
                self.workers[slot] = worker;
                Ok(())
            }
            Err(error) => {
                self.router.release(slot).map_err(WorkerError::WireGuard)?;
                Err(error)
            }
        }
    }
    pub fn endpoint(
        &self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<SocketAddr>, WorkerError> {
        let (slot, peer) = self.select(context, peer)?;
        Ok(self.workers[slot].peers[usize::from(peer)].endpoint)
    }
    pub(super) fn generation_is_active(&self, context: &ContextId, generation: u64) -> bool {
        self.workers.iter().any(|worker| {
            &worker.context == context
                && worker.generation == generation
                && !matches!(worker.phase, Phase::Failed)
        })
    }
    /// A projection-bound restart cannot supply a different configured peer set.
    pub(super) fn restart_with_key(
        &mut self,
        context: &ContextId,
        private_key: PrivateKey,
    ) -> Result<(), WorkerError> {
        let slot = self.slot(context)?;
        if !matches!(
            (context, &private_key),
            (ContextId::Tenant(_), PrivateKey::Tenant(_))
                | (ContextId::Service, PrivateKey::Service(_))
                | (ContextId::Gateway, PrivateKey::Gateway(_))
        ) {
            return Err(WorkerError::InvalidConfiguration);
        }
        let peers = self.workers[slot]
            .peers
            .iter()
            .map(|peer| PeerConfig {
                id: peer.id.clone(),
                public_key: peer.public_key.clone(),
            })
            .collect();
        self.restart(ContextConfig {
            id: context.clone(),
            private_key,
            peers,
        })
    }
    fn slot(&self, context: &ContextId) -> Result<usize, WorkerError> {
        self.workers
            .iter()
            .position(|worker| &worker.context == context)
            .ok_or(WorkerError::UnknownContext)
    }
    fn select(&self, context: &ContextId, peer: &PeerId) -> Result<(usize, u16), WorkerError> {
        let slot = self.slot(context)?;
        Ok((slot, self.workers[slot].peer(peer)?))
    }
    fn submit(
        &mut self,
        slot: usize,
        operation: Operation,
        expected: Expected,
    ) -> Result<RequestId, WorkerError> {
        self.workers[slot].ready()?;
        if let Err(error) = self.workers[slot]
            .process
            .as_mut()
            .ok_or(WorkerError::NotReady)?
            .ensure_quiet()
        {
            self.fail(slot, error);
            return Err(error);
        }
        let worker = &mut self.workers[slot];
        let sequence = worker.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(WorkerError::SequenceExhausted)?;
        let bytes = protocol::encode_request(&Request {
            sequence,
            operation,
        })
        .map_err(|_| WorkerError::Protocol)?;
        let request = RequestId {
            context: worker.context.clone(),
            generation: worker.generation,
            sequence,
        };
        worker
            .process
            .as_mut()
            .ok_or(WorkerError::NotReady)?
            .queue(Zeroizing::new(bytes))?;
        worker.next_sequence = next;
        worker.deadline = Some(Instant::now() + self.options.operation_timeout);
        worker.phase = Phase::Pending(Pending {
            request: request.clone(),
            operation: expected,
        });
        Ok(request)
    }
    fn poll_one(&mut self, slot: usize) -> Result<Option<WorkerEvent>, WorkerError> {
        let worker = &mut self.workers[slot];
        if worker
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(WorkerError::Timeout);
        }
        let process = worker.process.as_mut().ok_or(WorkerError::Io)?;
        if matches!(worker.phase, Phase::Idle) {
            process.ensure_quiet()?;
            return Ok(None);
        }
        let Some(body) = process.poll()? else {
            return Ok(None);
        };
        if process.pending_write() {
            return Err(WorkerError::Protocol);
        }
        if matches!(worker.phase, Phase::AwaitReady) {
            if !protocol::is_ready(&body) {
                return Err(WorkerError::Protocol);
            }
            process.queue(worker.bootstrap.take().ok_or(WorkerError::Protocol)?)?;
            worker.phase = Phase::Bootstrap;
            return Ok(None);
        }
        let reply = protocol::decode_reply(&body).map_err(|_| WorkerError::Protocol)?;
        if matches!(worker.phase, Phase::Bootstrap) {
            if reply.sequence != 0
                || !reply.indices.is_empty()
                || reply.authenticated_peer.is_some()
                || !matches!(reply.outcome, Ok(None))
            {
                return Err(WorkerError::Protocol);
            }
            worker.phase = Phase::Idle;
            worker.deadline = None;
            return Ok(Some(WorkerEvent::Ready {
                context: worker.context.clone(),
                generation: worker.generation,
            }));
        }
        let Phase::Pending(pending) = &worker.phase else {
            return Err(WorkerError::Protocol);
        };
        validate_reply(worker, pending, &reply)?;
        if let Expected::SetServicePeers { peers } = &pending.operation
            && matches!(reply.outcome, Ok(None))
        {
            let bindings = reply
                .indices
                .iter()
                .map(|binding| IndexBinding {
                    index: binding.index,
                    peer: peers[usize::from(binding.peer)].id.clone(),
                })
                .collect();
            self.router
                .replace_service_peers(
                    slot,
                    peers.iter().map(|peer| peer.id.clone()).collect(),
                    bindings,
                )
                .map_err(|error| match error {
                    DispatchError::IndexCollision => WorkerError::IndexCollision,
                    _ => WorkerError::Protocol,
                })?;
            worker.peers = peers
                .iter()
                .map(|peer| Peer {
                    id: peer.id.clone(),
                    public_key: peer.public_key.clone(),
                    endpoint: worker
                        .peers
                        .iter()
                        .find(|prior| prior.id == peer.id && prior.public_key == peer.public_key)
                        .and_then(|prior| prior.endpoint),
                })
                .collect();
        }
        let bindings = reply
            .indices
            .iter()
            .map(|binding| IndexBinding {
                index: binding.index,
                peer: worker.peers[usize::from(binding.peer)].id.clone(),
            })
            .collect();
        self.router
            .publish_worker(slot, bindings)
            .map_err(|error| match error {
                DispatchError::IndexCollision => WorkerError::IndexCollision,
                _ => WorkerError::Protocol,
            })?;
        let Phase::Pending(pending) = std::mem::replace(&mut worker.phase, Phase::Idle) else {
            return Err(WorkerError::Protocol);
        };
        worker.deadline = None;
        if let (Expected::Receive { source, .. }, Some(peer)) =
            (&pending.operation, reply.authenticated_peer)
        {
            worker.peers[usize::from(peer)].endpoint = Some(*source);
        }
        if let Expected::Reset { peer } = &pending.operation {
            worker.peers[usize::from(*peer)].endpoint = None;
        }
        let result = reply.outcome.and_then(|output| {
            output
                .map(|output| match output {
                    Output::Network { peer, packet } => Ok(DatagramEvent::Network {
                        destination: pending
                            .operation
                            .destination()
                            .ok_or(WireGuardError::NoEndpoint)?,
                        context: worker.context.clone(),
                        peer: Some(worker.peers[usize::from(peer)].id.clone()),
                        packet: PacketBytes(packet),
                    }),
                    Output::Plaintext { peer, packet } => Ok(DatagramEvent::Plaintext {
                        context: worker.context.clone(),
                        peer: worker.peers[usize::from(peer)].id.clone(),
                        packet: PacketBytes(packet),
                    }),
                })
                .transpose()
        });
        Ok(Some(WorkerEvent::Completed {
            request: pending.request,
            result,
        }))
    }
    fn fail(&mut self, slot: usize, reason: WorkerError) -> WorkerEvent {
        let _ = self.router.release(slot);
        let worker = &mut self.workers[slot];
        worker.phase = Phase::Failed;
        worker.deadline = None;
        worker.bootstrap = None;
        for peer in &mut worker.peers {
            peer.endpoint = None;
        }
        worker.process = None;
        WorkerEvent::Failed {
            context: worker.context.clone(),
            generation: worker.generation,
            reason,
        }
    }
}
impl Worker {
    fn spawn(
        config: ContextConfig,
        public_key: DevicePublicKey,
        generation: u64,
        limits: Limits,
        options: WorkerOptions,
    ) -> Result<Self, WorkerError> {
        let bootstrap = protocol::encode_bootstrap(&config, limits)
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        let deadline = Instant::now() + options.startup_timeout;
        let process = Process::spawn(&config.id, options.address_space_bytes)?;
        Ok(Self {
            context: config.id,
            public_key,
            generation,
            pid: process.pid(),
            process: Some(process),
            peers: config
                .peers
                .into_iter()
                .map(|peer| Peer {
                    id: peer.id,
                    public_key: peer.public_key,
                    endpoint: None,
                })
                .collect(),
            bootstrap: Some(bootstrap),
            phase: Phase::AwaitReady,
            deadline: Some(deadline),
            next_sequence: 1,
        })
    }
    fn ready(&self) -> Result<(), WorkerError> {
        match self.phase {
            Phase::Idle => Ok(()),
            Phase::Pending(_) => Err(WorkerError::Busy),
            _ => Err(WorkerError::NotReady),
        }
    }
    fn peer(&self, peer: &PeerId) -> Result<u16, WorkerError> {
        self.peers
            .iter()
            .position(|candidate| &candidate.id == peer)
            .map(|index| index as u16)
            .ok_or(WorkerError::UnknownPeer)
    }
}
fn validate_options(options: WorkerOptions) -> Result<(), WorkerError> {
    if !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&options.address_space_bytes)
        || [options.startup_timeout, options.operation_timeout]
            .iter()
            .any(|duration| duration.is_zero() || *duration > Duration::from_secs(60))
    {
        return Err(WorkerError::InvalidConfiguration);
    }
    Ok(())
}
/// Validate all output metadata and bytes before the registry can be changed.
fn validate_reply(worker: &Worker, pending: &Pending, reply: &Reply) -> Result<(), WorkerError> {
    let peer_count = match &pending.operation {
        Expected::SetServicePeers { peers } if matches!(reply.outcome, Ok(None)) => peers.len(),
        _ => worker.peers.len(),
    };
    if reply.sequence != pending.request.sequence
        || reply.indices.len() > peer_count * MAX_INDICES_PER_PEER
        || reply
            .indices
            .iter()
            .any(|binding| usize::from(binding.peer) >= peer_count)
    {
        return Err(WorkerError::Protocol);
    }
    let expected = &pending.operation;
    if matches!(expected, Expected::SetServicePeers { .. })
        && (reply.authenticated_peer.is_some() || matches!(reply.outcome, Ok(Some(_))))
    {
        return Err(WorkerError::Protocol);
    }
    if let Some(peer) = reply.authenticated_peer {
        if usize::from(peer) >= worker.peers.len()
            || expected.peer().is_some_and(|expected| expected != peer)
            || !matches!(
                expected,
                Expected::Receive {
                    kind: 1 | 2 | 4,
                    ..
                }
            )
        {
            return Err(WorkerError::Protocol);
        }
        // Authentication may survive inner-IP rejection or an empty keepalive,
        // but never a failed cryptographic operation. Handshakes authenticate
        // only when they produce the matching response/confirmation below.
        let consistent = match expected {
            Expected::Receive { kind: 1 | 2, .. } => {
                matches!(reply.outcome, Ok(Some(Output::Network { .. })))
            }
            Expected::Receive { kind: 4, .. } => matches!(
                reply.outcome,
                Ok(None | Some(Output::Plaintext { .. }))
                    | Err(WireGuardError::InvalidPacket | WireGuardError::PacketTooLarge)
            ),
            _ => false,
        };
        if !consistent {
            return Err(WorkerError::Protocol);
        }
    }
    if let Expected::Reset { peer } = expected
        && (reply.indices.iter().any(|binding| binding.peer == *peer)
            || !matches!(reply.outcome, Ok(None)))
    {
        return Err(WorkerError::Protocol);
    }
    let Ok(Some(output)) = &reply.outcome else {
        return Ok(());
    };
    let peer = match output {
        Output::Network { peer, .. } | Output::Plaintext { peer, .. } => *peer,
    };
    if usize::from(peer) >= worker.peers.len()
        || expected.peer().is_some_and(|expected| expected != peer)
    {
        return Err(WorkerError::Protocol);
    }
    match output {
        Output::Plaintext { packet, .. } => {
            if !matches!(expected, Expected::Receive { kind: 4, .. })
                || reply.authenticated_peer != Some(peer)
            {
                return Err(WorkerError::Protocol);
            }
            framing::ip_length(packet, false).map_err(|_| WorkerError::Protocol)?;
        }
        Output::Network { packet, .. } => {
            framing::datagram(packet).map_err(|_| WorkerError::Protocol)?;
            let allowed = match expected {
                Expected::Receive {
                    kind: 1, sender, ..
                } => packet[0] == 2 && *sender == Some(index_at(packet, 8)),
                Expected::Receive {
                    kind: 2, sender, ..
                } => packet[0] == 4 && *sender == Some(index_at(packet, 4)),
                Expected::Initiate { .. } => packet[0] == 1,
                Expected::Send { .. } => packet[0] == 4,
                Expected::Tick { .. } => matches!(packet[0], 1 | 4),
                _ => false,
            };
            if !allowed {
                return Err(WorkerError::Protocol);
            }
            if matches!(expected, Expected::Receive { .. })
                && reply.authenticated_peer != Some(peer)
            {
                return Err(WorkerError::Protocol);
            }
            if matches!(packet[0], 1 | 2)
                && !reply
                    .indices
                    .iter()
                    .any(|binding| binding.peer == peer && binding.index == index_at(packet, 4))
            {
                return Err(WorkerError::Protocol);
            }
        }
    }
    Ok(())
}
fn index_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
