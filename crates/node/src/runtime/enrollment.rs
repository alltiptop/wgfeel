//! Owner-initiated enrollment. Pending authority exists only in memory and has
//! a separate plaintext handler until a complete new runtime is committed.
use super::control::Updates;
use crate::join::{Failure, Phase};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId, ServicePrivateKey};
use wgfeel_protocol::{
    Request, Response,
    enrollment::{ENROLLMENT_PATH, EnrollmentClaim, EnrollmentProbe, Invitation, PROBE_PATH},
    http, tcp,
};
use wgfeel_store::Store;
use wgfeel_wireguard::{
    ContextConfig, ContextId, Gateway, Limits, PeerConfig, PeerId, UdpEvent, UdpTransport,
    WireGuardError,
    worker::{LocalError, LocalGateway, WorkerError},
};

#[derive(PartialEq, Eq)]
enum Status {
    Pending,
    Applied,
    Failed(Failure),
}
enum ClaimEvent {
    Accepted,
    Finished(Result<u64, Failure>),
}
struct Session {
    operation: u64,
    invitation: Option<Invitation>,
    id: NodeId,
    management: NodeId,
    pin: DevicePublicKey,
    claim: EnrollmentClaim,
    status: Status,
    deadline: Instant,
    next_tick: Instant,
    preparing: bool,
    receiver: Option<Receiver<ClaimEvent>>,
    accepted: bool,
    received_probe: bool,
    registered: Option<u64>,
    cancelled: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}
impl Session {
    fn phase(&self) -> Phase {
        if self.registered.is_some() {
            Phase::Configuration
        } else if self.received_probe {
            Phase::Registration
        } else if self.accepted {
            Phase::ReverseProof
        } else {
            Phase::Contact
        }
    }
}
#[derive(Default)]
pub(super) struct Runtime {
    sequence: u64,
    session: Option<Session>,
}
impl Runtime {
    pub fn result(&self) -> Option<Result<(), &'static str>> {
        match self.session.as_ref()?.status {
            Status::Pending => None,
            Status::Applied => Some(Ok(())),
            Status::Failed(reason) => Some(Err(reason.message())),
        }
    }
    pub fn progress(&self) -> Phase {
        self.session.as_ref().map_or(Phase::Contact, Session::phase)
    }
    pub fn active(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| session.status == Status::Pending)
    }
    pub fn local(
        &mut self,
        store: &Store,
        gateway: &LocalGateway,
        state_dir: &Path,
        listen: SocketAddr,
        assigned_port: bool,
        request: Request<'_>,
    ) -> Response {
        if request.target != crate::join::PATH
            || request.authorization.is_some()
            || request.if_match.is_some()
        {
            return Response::error(403, "join_only");
        }
        if request.method == "GET" && request.body.is_empty() {
            return self.status();
        }
        if request.method != "POST" || request.body.len() > 8192 {
            return Response::error(400, "invalid_join_request");
        }
        if self.active() || gateway.enrollment_peer().is_some() {
            return Response::error(409, "join_in_progress");
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input<'a> {
            invitation: &'a str,
            endpoints: Vec<SocketAddr>,
        }
        let result = (|| {
            let input: Input<'_> =
                serde_json::from_slice(request.body).map_err(|_| "invalid_join_request")?;
            let invitation =
                Invitation::decode(input.invitation).map_err(|_| "invalid_invitation")?;
            if assigned_port
                && (invitation.mesh_port() != listen.port()
                    || input.endpoints.iter().any(|a| a.port() != listen.port())
                    || input.endpoints.is_empty())
            {
                return Err("stop_child_before_changing_mesh_port");
            }
            let state = store
                .load()
                .map_err(|_| "storage_unavailable")?
                .ok_or("storage_unavailable")?;
            if state.projection() != gateway.projection() {
                return Err("runtime_state_mismatch");
            }
            let mut endpoints = input.endpoints;
            if endpoints.is_empty() {
                endpoints = gateway.projection().assignment().endpoints().to_vec();
                if let Some(home) = state_dir.parent() {
                    let path = home.join("config/config.json");
                    if wgfeel_host::validate_private_parent(&path).is_ok()
                        && let Ok(bytes) = std::fs::read(path)
                        && let Ok(config) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        && let Some(endpoint) = config["endpoint"]
                            .as_str()
                            .and_then(|value| value.parse::<SocketAddr>().ok())
                        && !endpoints.contains(&endpoint)
                    {
                        endpoints.insert(0, endpoint);
                    }
                }
                if !listen.ip().is_unspecified() && !endpoints.contains(&listen) {
                    endpoints.push(listen);
                }
                for endpoint in wgfeel_host::discover_endpoints(listen.port()) {
                    if endpoints.len() < wgfeel_core::MAX_NODE_ENDPOINTS
                        && !endpoints.contains(&endpoint)
                    {
                        endpoints.push(endpoint);
                    }
                }
            }
            let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|_| "hostname_unavailable")?;
            let claim = EnrollmentClaim::new(
                state.node_id().clone(),
                gateway
                    .projection()
                    .assignment()
                    .service_public_key()
                    .clone(),
                gateway
                    .projection()
                    .assignment()
                    .gateway_public_key()
                    .clone(),
                hostname.trim().into(),
                endpoints,
                wgfeel_host::node::generated_id().map_err(|_| "cannot_generate_join_attempt")?,
            )
            .map_err(|_| "invalid_node_contact")?;
            self.sequence = self.sequence.checked_add(1).ok_or("operation_exhausted")?;
            self.session = Some(Session {
                operation: self.sequence,
                id: invitation.id().clone(),
                management: invitation.management().clone(),
                pin: invitation.management_public_key().clone(),
                invitation: Some(invitation),
                claim,
                status: Status::Pending,
                deadline: Instant::now() + Duration::from_secs(60),
                next_tick: Instant::now(),
                preparing: false,
                receiver: None,
                accepted: false,
                received_probe: false,
                registered: None,
                cancelled: Arc::new(AtomicBool::new(false)),
                thread: None,
            });
            Ok(())
        })();
        match result {
            Ok(()) => {
                let mut response = self.status();
                response.status = 202;
                response
            }
            Err(error @ "stop_child_before_changing_mesh_port") => Response::error(409, error),
            Err(error) => Response::error(422, error),
        }
    }
    fn status(&self) -> Response {
        let body = if let Some(session) = &self.session {
            let (state, failure) = match session.status {
                Status::Pending => ("pending", None),
                Status::Applied => ("applied", None),
                Status::Failed(reason) => ("failed", Some(reason)),
            };
            serde_json::json!({"operation":session.operation,"management":session.management,"state":state,"phase":session.phase(),"failure":failure})
        } else {
            serde_json::json!({"operation":0,"state":"idle"})
        };
        Response {
            status: 200,
            generation: None,
            body: body.to_string().into_bytes(),
            is_config: false,
        }
    }
    pub fn configured(&mut self, result: Result<(), LocalError>) {
        if result.is_err()
            && let Some(session) = &mut self.session
            && session.status == Status::Pending
        {
            session.status = Status::Failed(Failure::LocalSetup);
        }
    }
    pub fn handle(
        &mut self,
        updates: &mut Updates,
        store: &mut Store,
        gateway: &mut LocalGateway,
        request: Request<'_>,
    ) -> Response {
        let Some(session) = &mut self.session else {
            return Response::error(403, "join_not_authorized");
        };
        if session.status != Status::Pending || Instant::now() >= session.deadline {
            return Response::error(403, "join_not_authorized");
        }
        if request.target == PROBE_PATH {
            if request.method != "POST"
                || request.authorization.is_some()
                || request.if_match.is_some()
                || request.body.len() > 512
            {
                return Response::error(400, "invalid_probe");
            }
            let Ok(probe) = serde_json::from_slice::<EnrollmentProbe>(request.body) else {
                return Response::error(400, "invalid_probe");
            };
            if probe.invitation != session.id.as_str() {
                return Response::error(403, "wrong_invitation");
            }
            session.received_probe = true;
            return Response {
                status: 200,
                generation: None,
                body: request.body.to_vec(),
                is_config: false,
            };
        }
        updates.handle_join(store, gateway, request, &session.management, &session.pin)
    }
    pub fn same_manager(&self, store: &Store, gateway: &LocalGateway) -> bool {
        self.session.as_ref().is_some_and(|session| {
            session.status == Status::Pending
                && &session.management == gateway.projection().management_id()
                && store.load().is_ok_and(|state| {
                    state.is_some_and(|state| state.management_public_key() == Some(&session.pin))
                })
        })
    }
    pub fn poll(
        &mut self,
        store: &Store,
        gateway: &mut LocalGateway,
        socket: &mut wgfeel_wireguard::UdpListener,
    ) {
        let Some(session) = &mut self.session else {
            return;
        };
        if session.status == Status::Pending
            && let Some(receiver) = &session.receiver
        {
            for event in receiver.try_iter() {
                match event {
                    ClaimEvent::Accepted => session.accepted = true,
                    ClaimEvent::Finished(Ok(generation)) => session.registered = Some(generation),
                    ClaimEvent::Finished(Err(error)) => session.status = Status::Failed(error),
                }
            }
        }
        if session.status == Status::Pending && Instant::now() >= session.deadline {
            session.status = Status::Failed(match session.phase() {
                Phase::Contact => Failure::NoClaimReply,
                Phase::ReverseProof => Failure::NoProbe,
                Phase::Registration => Failure::NoRegistration,
                Phase::Configuration => Failure::NoConfiguration,
            });
        }
        if session.status != Status::Pending {
            session.cancelled.store(true, Ordering::Relaxed);
            session.invitation = None;
            let _ = gateway.clear_enrollment();
            if session
                .thread
                .as_ref()
                .is_some_and(|thread| thread.is_finished())
            {
                let _ = session.thread.take().expect("finished thread").join();
            }
            return;
        }
        if Instant::now() >= session.next_tick
            && let Some(peer) = gateway.enrollment_peer().cloned()
        {
            match gateway.tick(&ContextId::Service, &PeerId::Node(peer)) {
                Err(LocalError::Worker(WorkerError::Busy)) => {}
                _ => session.next_tick = Instant::now() + Duration::from_millis(250),
            }
        }
        if !session.preparing {
            match gateway.prepare_enrollment(session.id.clone(), session.pin.clone()) {
                Ok(()) => session.preparing = true,
                Err(LocalError::Worker(WorkerError::Busy)) => return,
                Err(_) => {
                    session.status = Status::Failed(Failure::LocalSetup);
                    return;
                }
            }
        }
        if gateway.enrollment_peer().is_some() && session.receiver.is_none() {
            let Some(invitation) = session.invitation.take() else {
                session.status = Status::Failed(Failure::LocalSetup);
                return;
            };
            let claim = session.claim.clone();
            let Ok(udp) = socket.control_transport() else {
                session.status = Status::Failed(Failure::LocalSetup);
                return;
            };
            let cancelled = session.cancelled.clone();
            let (sender, receiver) = mpsc::sync_channel(2);
            match thread::Builder::new()
                .name("node-join".into())
                .spawn(move || {
                    let result = enroll(invitation, claim, &cancelled, &udp, &sender);
                    let _ = sender.send(ClaimEvent::Finished(result));
                }) {
                Ok(thread) => {
                    session.thread = Some(thread);
                    session.receiver = Some(receiver);
                }
                Err(_) => {
                    session.status = Status::Failed(Failure::LocalSetup);
                    return;
                }
            }
        }
        if let Some(generation) = session.registered
            && gateway.projection().management_id() == &session.management
            && gateway.projection().generation() >= generation
            && store.load().is_ok_and(|state| {
                state.is_some_and(|state| {
                    state.management_public_key() == Some(&session.pin)
                        && state.projection() == gateway.projection()
                })
            })
            && store.confirm_delivery().is_ok()
        {
            session.status = Status::Applied;
            let _ = gateway.clear_enrollment();
        }
    }
}
fn enroll(
    invitation: Invitation,
    claim: EnrollmentClaim,
    cancelled: &AtomicBool,
    udp: &UdpTransport,
    progress: &mpsc::SyncSender<ClaimEvent>,
) -> Result<u64, Failure> {
    let body = serde_json::to_vec(&claim).map_err(|_| Failure::LocalSetup)?;
    let peer = PeerId::Node(invitation.management().clone());
    let mut gateway = Gateway::new(
        vec![ContextConfig::service(
            ServicePrivateKey::new(*invitation.temporary_private_key().expose_bytes())
                .map_err(|_| Failure::LocalSetup)?,
            vec![PeerConfig {
                id: peer.clone(),
                public_key: invitation.management_public_key().clone(),
            }],
        )],
        Limits::default(),
    )
    .map_err(|_| Failure::LocalSetup)?;
    let mut accepted = false;
    let mut selected = 0;
    while !cancelled.load(Ordering::Relaxed) {
        match exchange(
            &mut gateway,
            &peer,
            invitation.endpoints()[selected],
            &body,
            cancelled,
            udp,
        ) {
            Ok(response) if response.status == 200 => {
                return response.generation.ok_or(Failure::Rejected);
            }
            Ok(response) if response.status == 202 => {
                if !accepted {
                    let _ = progress.try_send(ClaimEvent::Accepted);
                    accepted = true;
                }
                thread::sleep(Duration::from_secs(1));
            }
            Ok(response) => {
                let body = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
                return Err(match body.as_ref().and_then(|v| v["error"].as_str()) {
                    Some("invitation_already_claimed") => Failure::InvitationClaimed,
                    Some("node_identity_conflict") => Failure::IdentityConflict,
                    _ => Failure::Rejected,
                });
            }
            Err(_) => {
                gateway
                    .reset(&ContextId::Service, &peer)
                    .map_err(|_| Failure::LocalSetup)?;
                selected = (selected + 1) % invitation.endpoints().len();
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(Failure::NoClaimReply)
}
fn exchange(
    gateway: &mut Gateway,
    peer: &PeerId,
    endpoint: SocketAddr,
    body: &[u8],
    cancelled: &AtomicBool,
    udp: &UdpTransport,
) -> Result<Response, &'static str> {
    let mut buffers = tcp::Buffers::new(1).map_err(|_| "cannot allocate enrollment buffers")?;
    let encoded = http::encode_request(Request {
        method: "POST",
        target: ENROLLMENT_PATH,
        authorization: None,
        if_match: None,
        body,
    })
    .map_err(|_| "invalid enrollment request")?;
    let mut client = tcp::Client::new(&mut buffers, wgfeel_host::random_seed()?, encoded)
        .map_err(|_| "cannot create enrollment client")?;
    if gateway
        .endpoint(&ContextId::Service, peer)
        .map_err(|_| "invalid enrollment peer")?
        .is_none()
        && let Some(event) = gateway
            .initiate_at(&ContextId::Service, peer, endpoint)
            .map_err(|_| "enrollment handshake failed")?
    {
        udp.transmit(event).map_err(|_| "enrollment send failed")?;
    }
    let start = Instant::now();
    let mut tick = start;
    while start.elapsed() < Duration::from_secs(3) && !cancelled.load(Ordering::Relaxed) {
        for _ in 0..32 {
            if let Ok(Some(UdpEvent::Plaintext {
                context: ContextId::Service,
                peer: source,
                packet,
            })) = udp.poll(gateway)
                && &source == peer
            {
                let _ = client.receive(packet.as_bytes());
            }
        }
        client
            .poll(start.elapsed())
            .map_err(|_| "enrollment request failed")?;
        while let Some(packet) = client.take_packet() {
            match gateway.send_datagram(&ContextId::Service, peer, &packet) {
                Ok(event) => udp.transmit(event).map_err(|_| "enrollment send failed")?,
                Err(WireGuardError::NoEndpoint | WireGuardError::NoSession) => (),
                Err(_) => return Err("enrollment encryption failed"),
            }
        }
        if let Some(response) = client.take_response() {
            return response.map_err(|_| "invalid enrollment response");
        }
        if tick.elapsed() >= Duration::from_millis(100) {
            tick = Instant::now();
            if let Ok(Some(event)) = gateway.tick_datagram(&ContextId::Service, peer) {
                let _ = udp.transmit(event);
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    Err("enrollment endpoint unavailable")
}
