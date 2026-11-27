//! Main uses the same confined forwarding workers, DNS and mesh as children.
//! The application owns authoritative storage and the external HTTP listener.
use super::{BATCH, Timer, control, dns, mesh, receive, send, timers};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};
use wgfeel_core::{ControlMode, GatewayProjection, NodeId, NodeKeys};
use wgfeel_store::LocalTenants;
use wgfeel_wireguard::{
    ContextId, Limits, MAX_DATAGRAM_SIZE, PacketBytes, PeerConfig, PeerId, UdpListener,
    worker::{LocalError, LocalEvent, LocalGateway, WorkerError},
};
use zeroize::Zeroizing;

const QUEUE: usize = 128;

struct ServicePeer {
    id: NodeId,
    endpoints: Vec<SocketAddr>,
    next_endpoint: usize,
    retry: Instant,
}
fn service_peers(projection: &GatewayProjection, socket: &UdpListener) -> Vec<ServicePeer> {
    projection
        .mesh()
        .iter()
        .filter(|node| node.recipient() != projection.recipient())
        .map(|node| ServicePeer {
            id: node.recipient().clone(),
            endpoints: node
                .endpoints()
                .iter()
                .copied()
                .filter(|ep| socket.supports_endpoint(*ep))
                .collect(),
            next_endpoint: 0,
            retry: Instant::now(),
        })
        .collect()
}

pub enum MainEvent {
    Control { peer: NodeId, packet: PacketBytes },
    Applied { generation: u64 },
    WorkerFailed { context: ContextId, generation: u64 },
    ConfigurationRejected,
}

struct Candidate {
    gateway: LocalGateway,
    remaining: usize,
    deadline: Instant,
}
fn spawn(
    previous: Option<&LocalGateway>,
    projection: &GatewayProjection,
    key: &NodeKeys,
    tenants: &LocalTenants,
) -> Result<Candidate, &'static str> {
    if projection.control_mode() != ControlMode::Main {
        return Err("main forwarding requires its own authoritative projection");
    }
    let assigned = tenants
        .network_ids()
        .filter_map(|id| tenants.private_key(id).map(|key| (id, key)));
    let pin = projection.assignment().service_public_key();
    let gateway = match previous {
        Some(previous) => previous.prepare_replacement(projection, pin, key, assigned),
        None => LocalGateway::spawn_managed(
            projection,
            pin,
            key,
            assigned,
            Limits::default(),
            control::options(),
        ),
    }
    .map_err(|_| "cannot construct main forwarding workers")?;
    Ok(Candidate {
        remaining: gateway.starting_workers(),
        gateway,
        deadline: Instant::now() + Duration::from_secs(10),
    })
}

/// One UDP owner for main's service, tenant and encrypted gateway traffic.
/// Call on the thread that owns the workers, and poll until ready before announcing
/// startup. Configuration supplied here must already be durably committed by main.
pub struct MainForwarder {
    socket: UdpListener,
    active: Candidate,
    pending: Option<Candidate>,
    mesh: mesh::Runtime,
    dns: dns::Runtime,
    timers: Vec<Timer>,
    controls: Vec<PeerConfig>,
    applied_controls: Option<Vec<PeerConfig>>,
    pending_controls: Option<Vec<PeerConfig>>,
    control_timer: Timer,
    service_peers: Vec<ServicePeer>,
    outgoing: VecDeque<(NodeId, Zeroizing<Vec<u8>>, Instant)>,
    incoming: VecDeque<(SocketAddr, Vec<u8>, Instant)>,
    started: Instant,
    buffer: Box<[u8; MAX_DATAGRAM_SIZE + 1]>,
    ingress_first: bool,
}
impl MainForwarder {
    pub fn bind(
        listen: SocketAddr,
        projection: &GatewayProjection,
        key: &NodeKeys,
        tenants: &LocalTenants,
    ) -> Result<Self, &'static str> {
        let socket = UdpListener::bind(listen).map_err(|_| "cannot bind main WireGuard socket")?;
        let active = spawn(None, projection, key, tenants)?;
        let service_peers = service_peers(projection, &socket);
        Ok(Self {
            socket,
            mesh: mesh::Runtime::new(projection)?,
            dns: dns::Runtime::default(),
            timers: timers(&active.gateway, true),
            active,
            pending: None,
            controls: vec![],
            applied_controls: Some(vec![]),
            pending_controls: None,
            control_timer: control_timer(&[]),
            service_peers,
            outgoing: VecDeque::with_capacity(QUEUE),
            incoming: VecDeque::with_capacity(64),
            started: Instant::now(),
            buffer: Box::new([0; MAX_DATAGRAM_SIZE + 1]),
            ingress_first: false,
        })
    }
    pub fn ready(&self) -> bool {
        self.active.remaining == 0
            && self.pending_controls.is_none()
            && self.applied_controls.as_ref() == Some(&self.controls)
            && !self.control_timer.failed
            && self.timers.iter().all(|timer| !timer.failed)
    }
    pub fn generation(&self) -> u64 {
        self.active.gateway.projection().generation()
    }
    pub fn configure(
        &mut self,
        projection: &GatewayProjection,
        key: &NodeKeys,
        tenants: &LocalTenants,
    ) -> Result<(), &'static str> {
        let current = self.active.gateway.projection();
        if projection.recipient() != current.recipient()
            || projection.assignment().service_public_key()
                != current.assignment().service_public_key()
            || projection.assignment().gateway_public_key()
                != current.assignment().gateway_public_key()
            || projection.generation() < current.generation()
            || (projection.generation() == current.generation() && projection != current)
        {
            return Err("main forwarding identity or revision changed unexpectedly");
        }
        if projection == current
            || self.pending.as_ref().is_some_and(|pending| {
                pending.gateway.projection().generation() >= projection.generation()
            })
        {
            return Ok(());
        }
        if self.pending.is_none()
            && self.pending_controls.is_none()
            && self.active.gateway.can_replace_projection(projection)
        {
            // Prepare all fallible routing state before publishing the revision.
            // A policy-only update keeps crypto sessions, but not old mesh ACLs,
            // fragment assemblies, queued output or outstanding DNS decisions.
            let mesh = self.mesh.replacement(projection)?;
            self.active
                .gateway
                .replace_projection(projection)
                .map_err(|_| "cannot apply main forwarding policy")?;
            self.mesh = mesh;
            self.dns.reset();
            return Ok(());
        }
        self.pending = Some(spawn(Some(&self.active.gateway), projection, key, tenants)?);
        Ok(())
    }
    pub fn control_peers(&mut self, peers: Vec<PeerConfig>) {
        self.controls = peers;
    }
    pub fn control_transport(&mut self) -> std::io::Result<wgfeel_wireguard::UdpTransport> {
        self.socket.control_transport()
    }
    pub fn endpoint(&self, peer: &NodeId) -> Option<SocketAddr> {
        self.active
            .gateway
            .endpoint(&ContextId::Service, &PeerId::Node(peer.clone()))
            .ok()
            .flatten()
    }
    /// Bounded backpressure is packet loss; the control TCP stream retransmits.
    pub fn send_control(&mut self, peer: &NodeId, bytes: &[u8]) {
        if self.outgoing.len() < QUEUE && bytes.len() <= wgfeel_wireguard::MAX_PLAINTEXT_SIZE {
            self.outgoing.push_back((
                peer.clone(),
                Zeroizing::new(bytes.to_vec()),
                Instant::now() + Duration::from_secs(1),
            ));
        }
    }
    pub fn poll(&mut self) -> Result<Vec<MainEvent>, &'static str> {
        let mut events = Vec::with_capacity(BATCH + 1);
        if self.active.remaining != 0 {
            candidate_ready(&mut self.active)?;
            return Ok(events);
        }
        for _ in 0..BATCH {
            match self.active.gateway.poll() {
                Some(LocalEvent::Network(datagram)) => send(&self.socket, datagram),
                Some(event @ (LocalEvent::Mesh { .. } | LocalEvent::MeshOutput { .. })) => {
                    self.mesh
                        .event(event, self.started.elapsed(), &self.active.gateway);
                }
                Some(LocalEvent::Dns { source, packet }) => {
                    self.dns.receive(source, packet.as_bytes())
                }
                Some(LocalEvent::Control { peer, packet }) => {
                    if let Some(connection) = self.service_peers.iter_mut().find(|p| p.id == peer) {
                        // Only authenticated service input confirms the endpoint.
                        // Gateway health must never establish service connectivity.
                        connection.retry = Instant::now() + Duration::from_secs(3);
                        if let Some(endpoint) = self
                            .active
                            .gateway
                            .endpoint(&ContextId::Service, &PeerId::Node(peer.clone()))
                            .ok()
                            .flatten()
                            && let Some(index) =
                                connection.endpoints.iter().position(|e| *e == endpoint)
                        {
                            connection.next_endpoint = index;
                        }
                    }
                    events.push(MainEvent::Control { peer, packet })
                }
                Some(LocalEvent::ControlConfigured { result }) => {
                    result.map_err(|_| "cannot configure main API peers")?;
                    let applied = self
                        .pending_controls
                        .take()
                        .ok_or("unexpected main peer update")?;
                    self.control_timer = control_timer(&applied);
                    self.applied_controls = Some(applied);
                }
                Some(LocalEvent::Failed {
                    context,
                    generation,
                    ..
                }) => {
                    if context == ContextId::Service {
                        self.control_timer.failed = true;
                    }
                    if let Some(timer) = self
                        .timers
                        .iter_mut()
                        .find(|timer| timer.context == context)
                    {
                        timer.failed = true;
                    }
                    events.push(MainEvent::WorkerFailed {
                        context,
                        generation,
                    });
                }
                Some(
                    LocalEvent::Management { .. }
                    | LocalEvent::Enrollment { .. }
                    | LocalEvent::EnrollmentConfigured { .. },
                ) => {
                    return Err("unexpected child control event in main runtime");
                }
                Some(LocalEvent::Ready { .. } | LocalEvent::Dropped { .. }) => (),
                None => break,
            }
        }
        if let Some(pending) = &mut self.pending {
            match candidate_ready(pending) {
                Ok(true) if self.pending_controls.is_none() => {
                    let mesh = self.mesh.replacement(pending.gateway.projection())?;
                    // A failed worker has no session to inherit. A newly
                    // committed revision may activate its prepared replacement;
                    // mere worker failure never triggers an automatic restart.
                    let failed = self.active.gateway.workers().iter().any(|worker| {
                        worker.context == ContextId::Service
                            && worker.state == wgfeel_wireguard::worker::WorkerState::Failed
                    });
                    let activated = pending
                        .gateway
                        .handoff(&mut self.active.gateway)
                        .and_then(|handoff| handoff.activate());
                    match activated {
                        Ok(()) => {
                            self.pending = None;
                            self.active.remaining = 0;
                            self.mesh = mesh;
                            self.dns.reset();
                            self.timers = timers(&self.active.gateway, true);
                            self.service_peers =
                                service_peers(self.active.gateway.projection(), &self.socket);
                            self.applied_controls = None;
                            if failed {
                                self.control_timer = control_timer(&[]);
                            }
                            events.push(MainEvent::Applied {
                                generation: self.generation(),
                            });
                        }
                        Err(LocalError::Worker(WorkerError::Busy)) => (),
                        Err(_) => {
                            self.pending = None;
                            events.push(MainEvent::ConfigurationRejected);
                        }
                    }
                }
                Ok(_) => (),
                Err(_) => {
                    self.pending = None;
                    events.push(MainEvent::ConfigurationRejected);
                }
            }
        }
        if self.pending_controls.is_none() && self.applied_controls.as_ref() != Some(&self.controls)
        {
            match self.active.gateway.set_control_peers(self.controls.clone()) {
                Ok(()) => self.pending_controls = Some(self.controls.clone()),
                Err(LocalError::Worker(WorkerError::Busy | WorkerError::NotReady)) => (),
                Err(_) => return Err("invalid main API peer configuration"),
            }
        }
        self.ingress_first = !self.ingress_first;
        if self.ingress_first {
            receive(
                &self.socket,
                &mut self.active.gateway,
                self.buffer.as_mut(),
                &mut self.incoming,
            )?;
        }
        for _ in 0..BATCH {
            let Some((peer, bytes, deadline)) = self.outgoing.front() else {
                break;
            };
            if Instant::now() < *deadline {
                if let Some(connection) = self.service_peers.iter_mut().find(|p| p.id == *peer)
                    && Instant::now() >= connection.retry
                    && !connection.endpoints.is_empty()
                {
                    // Distribution establishes its own authenticated session
                    // after the short-lived enrollment proof.
                    let endpoint = connection.endpoints[connection.next_endpoint];
                    if matches!(
                        self.active.gateway.initiate_at(
                            &ContextId::Service,
                            &PeerId::Node(peer.clone()),
                            endpoint,
                        ),
                        Err(LocalError::Worker(WorkerError::Busy))
                    ) {
                        break;
                    }
                    connection.next_endpoint =
                        (connection.next_endpoint + 1) % connection.endpoints.len();
                    connection.retry = Instant::now() + Duration::from_secs(3);
                    break; // Drain the handshake before submitting plaintext.
                }
                let result = self.active.gateway.send_control(peer, bytes);
                if matches!(result, Err(LocalError::Worker(WorkerError::Busy))) {
                    break;
                }
            }
            self.outgoing.pop_front();
        }
        self.mesh.poll(
            &mut self.active.gateway,
            &self.socket,
            self.started.elapsed(),
        );
        self.dns
            .poll(&mut self.active.gateway, self.started.elapsed());
        self.control_timer
            .tick(&mut self.active.gateway, Instant::now());
        for timer in &mut self.timers {
            timer.tick(&mut self.active.gateway, Instant::now());
        }
        if !self.ingress_first {
            receive(
                &self.socket,
                &mut self.active.gateway,
                self.buffer.as_mut(),
                &mut self.incoming,
            )?;
        }
        Ok(events)
    }
}
fn candidate_ready(candidate: &mut Candidate) -> Result<bool, &'static str> {
    if candidate.remaining == 0 {
        return Ok(true);
    }
    if Instant::now() >= candidate.deadline {
        return Err("main forwarding worker startup timed out");
    }
    for _ in 0..BATCH {
        match candidate.gateway.poll() {
            Some(LocalEvent::Ready { .. }) => {
                candidate.remaining = candidate
                    .remaining
                    .checked_sub(1)
                    .ok_or("unexpected main worker readiness")?;
            }
            Some(_) => return Err("main forwarding worker startup failed"),
            None => break,
        }
    }
    Ok(candidate.remaining == 0)
}
fn control_timer(peers: &[PeerConfig]) -> Timer {
    Timer {
        context: ContextId::Service,
        peers: peers
            .iter()
            .map(|peer| (peer.id.clone(), Instant::now()))
            .collect(),
        cursor: 0,
        blocked: false,
        failed: false,
    }
}
