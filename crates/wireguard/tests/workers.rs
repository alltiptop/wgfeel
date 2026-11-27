//! Real self-exec worker acceptance. Only children enter the syscall policy.
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
    x25519::{PublicKey, StaticSecret},
};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, Signal, kill_process};
use wgfeel_core::{
    DeviceId, DevicePublicKey, NetworkId, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use wgfeel_sandbox::{WorkerLimits, enter_worker};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Limits, PeerConfig, PeerId, WireGuardError,
    worker::{
        RequestId, Submission, WorkerError, WorkerEvent, WorkerGateway, WorkerOptions, WorkerState,
        worker_main,
    },
};

const MEMORY: u64 = 64 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(5);

fn options() -> WorkerOptions {
    WorkerOptions {
        address_space_bytes: MEMORY,
        startup_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
    }
}
fn tenant(name: &str) -> ContextId {
    ContextId::Tenant(NetworkId::new(name).unwrap())
}
fn device(name: &str) -> PeerId {
    PeerId::Device(DeviceId::new(name).unwrap())
}
fn seed(number: u8) -> [u8; 32] {
    let mut bytes = [83; 32];
    bytes[14] = number;
    bytes
}
fn public(number: u8) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(seed(number))).to_bytes()
}
fn peer_identity(context: &ContextId) -> PeerId {
    if matches!(context, ContextId::Service | ContextId::Gateway) {
        PeerId::Node(NodeId::new("remote").unwrap())
    } else {
        device("client")
    }
}
fn config(context: ContextId, key: u8, peer_key: u8) -> ContextConfig {
    let peers = vec![PeerConfig {
        id: peer_identity(&context),
        public_key: DevicePublicKey::new(public(peer_key)).unwrap(),
    }];
    match context {
        ContextId::External(_) => unreachable!("public listener fixture"),
        ContextId::Tenant(network) => {
            ContextConfig::tenant(network, TenantPrivateKey::new(seed(key)).unwrap(), peers)
        }
        ContextId::Gateway => ContextConfig::gateway(
            wgfeel_core::GatewayPrivateKey::new(seed(key)).unwrap(),
            peers,
        ),
        ContextId::Service => {
            ContextConfig::service(ServicePrivateKey::new(seed(key)).unwrap(), peers)
        }
    }
}
fn server_address() -> SocketAddr {
    "198.51.100.1:51820".parse().unwrap()
}

struct Peer {
    context: ContextId,
    id: PeerId,
    address: SocketAddr,
    engine: Tunn,
    limiter: Arc<RateLimiter>,
}
impl Peer {
    fn new(context: ContextId, key: u8, server_key: u8) -> Self {
        let private = StaticSecret::from(seed(key));
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&private), 100));
        let id = peer_identity(&context);
        Self {
            context,
            id,
            address: SocketAddr::from((Ipv4Addr::new(198, 51, 100, key), 40000 + u16::from(key))),
            engine: Tunn::new(
                private,
                PublicKey::from(public(server_key)),
                None,
                None,
                IndexTable::from_os_rng(),
                Arc::clone(&limiter),
            ),
            limiter,
        }
    }
    fn initiate(&mut self) -> Vec<u8> {
        self.engine
            .format_handshake_initiation(false)
            .unwrap()
            .into_bytes()
            .as_ref()
            .to_vec()
    }
    fn receive(&mut self, server: SocketAddr, bytes: &[u8]) -> TunnResult {
        self.limiter.try_reset_count();
        let verified = self
            .limiter
            .verify_packet(server, Packet::copy_from(bytes))
            .unwrap();
        self.engine.handle_incoming_packet(verified)
    }
    fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.engine
            .encapsulate_with_session(Packet::copy_from(bytes))
            .unwrap()
            .into_bytes()
            .as_ref()
            .to_vec()
    }
    fn assert_plaintext(&mut self, server: SocketAddr, bytes: &[u8], expected: &[u8]) {
        let TunnResult::WriteToTunnel(packet) = self.receive(server, bytes) else {
            panic!("worker output did not authenticate for expected peer");
        };
        assert!(packet.as_ref().len() >= expected.len());
        assert!(packet.as_ref().len() - expected.len() <= 15);
        assert_eq!(&packet.as_ref()[..expected.len()], expected);
    }
}

fn plaintext(ipv6: bool) -> Vec<u8> {
    // The same addresses deliberately recur in every tenant and service context.
    let mut packet = vec![0; if ipv6 { 48 } else { 28 }];
    if ipv6 {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 253;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    } else {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 253;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    }
    let start = packet.len() - 8;
    packet[start..].copy_from_slice(b"ipc-test");
    packet
}
fn wait_ready(gateway: &mut WorkerGateway) {
    let deadline = Instant::now() + WAIT;
    loop {
        if gateway
            .workers()
            .iter()
            .all(|worker| worker.state == WorkerState::Ready)
        {
            return;
        }
        if let Some(event) = gateway.poll() {
            assert!(
                matches!(event, WorkerEvent::Ready { .. }),
                "unexpected startup event: {event:?}"
            );
        }
        assert!(Instant::now() < deadline, "workers did not become ready");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn completed(
    gateway: &mut WorkerGateway,
    wanted: RequestId,
) -> Result<Option<DatagramEvent>, WireGuardError> {
    let deadline = Instant::now() + WAIT;
    loop {
        match gateway.poll() {
            Some(WorkerEvent::Completed { request, result }) => {
                assert_eq!(request, wanted);
                return result;
            }
            Some(WorkerEvent::Ready { .. }) => {}
            Some(event) => panic!("worker failed while completing a valid request: {event:?}"),
            None => {}
        }
        assert!(Instant::now() < deadline, "worker operation deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn receive(
    gateway: &mut WorkerGateway,
    source: SocketAddr,
    bytes: &[u8],
) -> Result<Option<DatagramEvent>, WireGuardError> {
    match gateway.receive_datagram(source, bytes).unwrap() {
        Submission::Queued(request) => completed(gateway, request),
        Submission::Immediate(event) => Ok(Some(event)),
    }
}
fn encrypted(event: DatagramEvent, peer: &Peer) -> Vec<u8> {
    let DatagramEvent::Network {
        destination,
        context,
        peer: actual,
        packet,
    } = event
    else {
        panic!("expected encrypted output");
    };
    assert_eq!(destination, peer.address);
    assert_eq!(context, peer.context);
    assert_eq!(actual.as_ref(), Some(&peer.id));
    packet.as_bytes().to_vec()
}
fn establish(gateway: &mut WorkerGateway, peer: &mut Peer) {
    let initiation = peer.initiate();
    let response = encrypted(
        receive(gateway, peer.address, &initiation)
            .unwrap()
            .unwrap(),
        peer,
    );
    let TunnResult::WriteToNetwork(confirmation) = peer.receive(server_address(), &response) else {
        panic!("missing handshake confirmation");
    };
    let confirmation: Packet = confirmation.into();
    // This immediate reply must already find the response's published local index.
    assert!(
        receive(gateway, peer.address, confirmation.as_ref())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
}
fn exchange(gateway: &mut WorkerGateway, peer: &mut Peer, ipv6: bool) {
    let packet = plaintext(ipv6);
    let wire = peer.encrypt(&packet);
    let DatagramEvent::Plaintext {
        context,
        peer: actual,
        packet: received,
    } = receive(gateway, peer.address, &wire).unwrap().unwrap()
    else {
        panic!("expected authenticated inner packet");
    };
    assert_eq!(context, peer.context);
    assert_eq!(actual, peer.id);
    assert_eq!(received.as_bytes(), packet);
    let request = gateway
        .send_datagram(&peer.context, &peer.id, &packet)
        .unwrap();
    let wire = encrypted(completed(gateway, request).unwrap().unwrap(), peer);
    peer.assert_plaintext(server_address(), &wire, &packet);
}

fn real_workers_install_policy_have_distinct_processes_and_drop_reaps_them() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
            config(ContextId::Service, 3, 13),
            config(ContextId::Gateway, 4, 14),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    assert_eq!(gateway.workers().len(), 4);
    wait_ready(&mut gateway);
    let workers = gateway.workers();
    for (index, worker) in workers.iter().enumerate() {
        assert_ne!(worker.pid, std::process::id());
        assert!(
            !workers[..index]
                .iter()
                .any(|earlier| earlier.pid == worker.pid)
        );
        assert!(worker.generation > 0);
        let status = fs::read_to_string(format!("/proc/{}/status", worker.pid)).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        assert!(status.lines().any(|line| line == "Seccomp:\t2"));
        assert!(status.lines().any(|line| line == "Threads:\t1"));
        let limits = fs::read_to_string(format!("/proc/{}/limits", worker.pid)).unwrap();
        for (name, expected) in [
            ("Max core file size", "0"),
            ("Max address space", "67108864"),
        ] {
            let row = limits
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap();
            assert_eq!(
                row.split_whitespace().take(2).collect::<Vec<_>>(),
                [expected, expected]
            );
        }
        let argv = fs::read(format!("/proc/{}/cmdline", worker.pid)).unwrap();
        for marker in [
            seed(1),
            seed(2),
            seed(3),
            seed(4),
            seed(14),
            seed(11),
            seed(12),
            seed(13),
        ] {
            assert!(!argv.windows(marker.len()).any(|bytes| bytes == marker));
        }
    }
    drop(gateway);
    for worker in workers {
        assert!(
            !std::path::Path::new(&format!("/proc/{}", worker.pid)).exists(),
            "direct child must be killed and reaped on Drop"
        );
    }
}

fn tenant_and_system_workers_complete_real_bidirectional_ipv4_ipv6() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
            config(ContextId::Service, 3, 13),
            config(ContextId::Gateway, 4, 14),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut peers = [
        Peer::new(tenant("alpha"), 11, 1),
        Peer::new(tenant("beta"), 12, 2),
        Peer::new(ContextId::Service, 13, 3),
        Peer::new(ContextId::Gateway, 14, 4),
    ];
    for peer in &mut peers {
        establish(&mut gateway, peer);
    }
    for ipv6 in [false, true] {
        for peer in &mut peers {
            exchange(&mut gateway, peer, ipv6);
        }
    }
}

fn gateway_initiation_busy_and_reset_preserve_other_context() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut alpha = Peer::new(tenant("alpha"), 11, 1);
    let mut beta = Peer::new(tenant("beta"), 12, 2);
    establish(&mut gateway, &mut beta);
    let first = gateway
        .initiate_at(&alpha.context, &alpha.id, alpha.address)
        .unwrap();
    assert!(matches!(
        gateway.tick(&alpha.context, &alpha.id),
        Err(WorkerError::Busy)
    ));
    let initiation = encrypted(completed(&mut gateway, first).unwrap().unwrap(), &alpha);
    let TunnResult::WriteToNetwork(response) = alpha.receive(server_address(), &initiation) else {
        panic!("expected peer response");
    };
    let response: Packet = response.into();
    let confirmation = encrypted(
        receive(&mut gateway, alpha.address, response.as_ref())
            .unwrap()
            .unwrap(),
        &alpha,
    );
    assert!(
        matches!(alpha.receive(server_address(), &confirmation), TunnResult::WriteToTunnel(packet) if packet.is_empty())
    );
    exchange(&mut gateway, &mut alpha, false);
    let old = alpha.encrypt(&plaintext(false));
    let reset = gateway.reset(&alpha.context, &alpha.id).unwrap();
    assert!(completed(&mut gateway, reset).unwrap().is_none());
    assert_eq!(gateway.endpoint(&alpha.context, &alpha.id).unwrap(), None);
    assert!(matches!(
        gateway.receive_datagram(alpha.address, &old),
        Err(WorkerError::WireGuard(WireGuardError::UnknownIndex))
    ));
    exchange(&mut gateway, &mut beta, true);
}

fn service_peer_changes_preserve_sessions_and_never_reconfigure_tenants() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(ContextId::Service, 1, 2),
            config(tenant("alpha"), 3, 4),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let before = gateway.workers();
    let mut manager = Peer::new(ContextId::Service, 2, 1);
    let mut user = Peer::new(tenant("alpha"), 4, 3);
    establish(&mut gateway, &mut manager);
    establish(&mut gateway, &mut user);
    let mut candidate = Peer::new(ContextId::Service, 5, 1);
    candidate.id = PeerId::Node(NodeId::new("candidate").unwrap());
    candidate.address.set_port(45001);
    let manager_id = manager.id.clone();
    let candidate_id = candidate.id.clone();
    let manager_config = || PeerConfig {
        id: manager_id.clone(),
        public_key: DevicePublicKey::new(public(2)).unwrap(),
    };
    let candidate_config = || PeerConfig {
        id: candidate_id.clone(),
        public_key: DevicePublicKey::new(public(5)).unwrap(),
    };
    let request = gateway
        .set_service_peers(vec![candidate_config(), manager_config()])
        .unwrap();
    assert!(completed(&mut gateway, request).unwrap().is_none());
    assert_eq!(
        gateway
            .workers()
            .iter()
            .map(|worker| (worker.pid, worker.generation))
            .collect::<Vec<_>>(),
        before
            .iter()
            .map(|worker| (worker.pid, worker.generation))
            .collect::<Vec<_>>()
    );
    exchange(&mut gateway, &mut manager, false);
    exchange(&mut gateway, &mut user, true);
    establish(&mut gateway, &mut candidate);
    exchange(&mut gateway, &mut candidate, false);
    let request = gateway.set_service_peers(vec![manager_config()]).unwrap();
    assert!(completed(&mut gateway, request).unwrap().is_none());
    assert!(
        gateway
            .receive_datagram(candidate.address, &candidate.encrypt(&plaintext(false)))
            .is_err()
    );
    exchange(&mut gateway, &mut manager, true);
    exchange(&mut gateway, &mut user, false);
    assert!(
        gateway
            .set_service_peers(vec![PeerConfig {
                id: device("forged"),
                public_key: DevicePublicKey::new(public(6)).unwrap()
            }])
            .is_err()
    );
    let mut low_order = [0; 32];
    low_order[0] = 1;
    let request = gateway
        .set_service_peers(vec![
            PeerConfig {
                id: PeerId::Node(NodeId::new("bad-key").unwrap()),
                public_key: DevicePublicKey::new(low_order).unwrap(),
            },
            manager_config(),
        ])
        .unwrap();
    // An invalid cryptographic key must fail without losing the old peer set.
    assert!(matches!(
        completed(&mut gateway, request),
        Err(WireGuardError::InvalidPeerKey)
    ));
    exchange(&mut gateway, &mut manager, false);
}

fn restart_rejects_public_identity_changes_and_retires_previous_generation() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut alpha = Peer::new(tenant("alpha"), 11, 1);
    let mut beta = Peer::new(tenant("beta"), 12, 2);
    establish(&mut gateway, &mut alpha);
    establish(&mut gateway, &mut beta);
    for changed in [
        config(tenant("alpha"), 4, 11),
        config(tenant("alpha"), 1, 14),
        config(tenant("unknown"), 1, 11),
    ] {
        assert!(gateway.restart(changed).is_err());
        exchange(&mut gateway, &mut alpha, false);
    }
    let previous = gateway
        .workers()
        .into_iter()
        .find(|worker| worker.context == alpha.context)
        .unwrap();
    let old = alpha.encrypt(&plaintext(true));
    gateway.restart(config(tenant("alpha"), 1, 11)).unwrap();
    assert!(matches!(
        gateway.receive_datagram(alpha.address, &old),
        Err(WorkerError::WireGuard(WireGuardError::UnknownIndex))
    ));
    wait_ready(&mut gateway);
    let current = gateway
        .workers()
        .into_iter()
        .find(|worker| worker.context == alpha.context)
        .unwrap();
    assert!(current.generation > previous.generation);
    assert_ne!(current.pid, previous.pid);
    assert!(!std::path::Path::new(&format!("/proc/{}", previous.pid)).exists());
    exchange(&mut gateway, &mut beta, true);
    alpha = Peer::new(tenant("alpha"), 11, 1);
    establish(&mut gateway, &mut alpha);
    exchange(&mut gateway, &mut alpha, true);
}

fn unexpected_worker_death_revokes_its_indices_without_disrupting_healthy_peer() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut alpha = Peer::new(tenant("alpha"), 11, 1);
    let mut beta = Peer::new(tenant("beta"), 12, 2);
    establish(&mut gateway, &mut alpha);
    establish(&mut gateway, &mut beta);
    let victim = gateway
        .workers()
        .into_iter()
        .find(|worker| worker.context == alpha.context)
        .unwrap();
    let old = alpha.encrypt(&plaintext(false));
    kill_process(Pid::from_raw(victim.pid as i32).unwrap(), Signal::KILL).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        match gateway.poll() {
            Some(WorkerEvent::Failed {
                context,
                generation,
                ..
            }) => {
                assert_eq!(context, alpha.context);
                assert_eq!(generation, victim.generation);
                break;
            }
            Some(WorkerEvent::Ready { .. }) | None => {}
            Some(event) => panic!("unexpected post-crash output: {event:?}"),
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(
        gateway.receive_datagram(alpha.address, &old),
        Err(WorkerError::WireGuard(WireGuardError::UnknownIndex))
    ));
    assert!(!std::path::Path::new(&format!("/proc/{}", victim.pid)).exists());
    exchange(&mut gateway, &mut beta, false);
    gateway.restart(config(tenant("alpha"), 1, 11)).unwrap();
    wait_ready(&mut gateway);
    alpha = Peer::new(tenant("alpha"), 11, 1);
    establish(&mut gateway, &mut alpha);
    exchange(&mut gateway, &mut alpha, true);
}

fn invalid_options_and_public_diagnostics_exclude_private_bytes() {
    for invalid in [
        WorkerOptions {
            address_space_bytes: 1,
            ..options()
        },
        WorkerOptions {
            startup_timeout: Duration::ZERO,
            ..options()
        },
        WorkerOptions {
            operation_timeout: Duration::from_secs(61),
            ..options()
        },
    ] {
        assert!(matches!(
            WorkerGateway::spawn(
                vec![config(tenant("alpha"), 1, 11)],
                Limits::default(),
                invalid
            ),
            Err(WorkerError::InvalidConfiguration)
        ));
    }
    let mut gateway = WorkerGateway::spawn(
        vec![config(tenant("alpha"), 1, 11)],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let diagnostics = format!(
        "{gateway:?} {:?} {}",
        gateway.workers(),
        WorkerError::Protocol
    );
    for marker in [seed(1), seed(11)] {
        assert!(!diagnostics.contains(&format!("{marker:?}")));
    }
}

fn shared_udp_port_drives_all_worker_contexts_without_child_sockets() {
    // The real supervisor already owns its public socket when workers spawn;
    // a successful child preflight must not inherit that network descriptor.
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("alpha"), 1, 11),
            config(tenant("beta"), 2, 12),
            config(ContextId::Service, 3, 13),
            config(ContextId::Gateway, 4, 14),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let server_address = server.local_addr().unwrap();
    let mut buffer = [0; 1313];
    for (context, key, server_key) in [
        (tenant("alpha"), 11, 1),
        (tenant("beta"), 12, 2),
        (ContextId::Service, 13, 3),
        (ContextId::Gateway, 14, 4),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut peer = Peer::new(context, key, server_key);
        peer.address = socket.local_addr().unwrap();
        socket.send_to(&peer.initiate(), server_address).unwrap();
        let (length, source) = server.recv_from(&mut buffer).unwrap();
        let response = encrypted(
            receive(&mut gateway, source, &buffer[..length])
                .unwrap()
                .unwrap(),
            &peer,
        );
        server.send_to(&response, peer.address).unwrap();
        let (length, source) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(source, server_address);
        let TunnResult::WriteToNetwork(confirmation) =
            peer.receive(server_address, &buffer[..length])
        else {
            panic!("missing confirmation");
        };
        let confirmation: Packet = confirmation.into();
        socket
            .send_to(confirmation.as_ref(), server_address)
            .unwrap();
        let (length, source) = server.recv_from(&mut buffer).unwrap();
        assert!(
            receive(&mut gateway, source, &buffer[..length])
                .unwrap()
                .is_none()
        );
        for ipv6 in [false, true] {
            let packet = plaintext(ipv6);
            let ciphertext = peer.encrypt(&packet);
            socket.send_to(&ciphertext, server_address).unwrap();
            let (length, source) = server.recv_from(&mut buffer).unwrap();
            let DatagramEvent::Plaintext {
                context,
                peer: identity,
                packet: received,
            } = receive(&mut gateway, source, &buffer[..length])
                .unwrap()
                .unwrap()
            else {
                panic!("expected authenticated worker plaintext");
            };
            assert_eq!(context, peer.context);
            assert_eq!(identity, peer.id);
            assert_eq!(received.as_bytes(), packet);
            let request = gateway
                .send_datagram(&peer.context, &peer.id, &packet)
                .unwrap();
            let wire = encrypted(completed(&mut gateway, request).unwrap().unwrap(), &peer);
            server.send_to(&wire, peer.address).unwrap();
            let (length, source) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(source, server_address);
            peer.assert_plaintext(server_address, &buffer[..length], &packet);
        }
    }
}

// The following codec is hand-authored from the accepted wire contract. It is
// deliberately independent of the production encoder and decoder.
fn read_fixture_frame() -> Vec<u8> {
    let mut length = [0; 4];
    io::stdin().read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!((2..=131072).contains(&length));
    let mut body = vec![0; length];
    io::stdin().read_exact(&mut body).unwrap();
    body
}
fn write_fixture_frame(body: &[u8]) {
    let mut output = io::stdout().lock();
    output
        .write_all(&(body.len() as u32).to_le_bytes())
        .unwrap();
    output.write_all(body).unwrap();
    output.flush().unwrap();
}
fn fixture_reply(sequence: u64, auth: u16, indices: &[(u16, u32)]) -> Vec<u8> {
    let mut reply = vec![1, 4];
    reply.extend_from_slice(&sequence.to_le_bytes());
    reply.extend_from_slice(&auth.to_le_bytes());
    reply.extend_from_slice(&(indices.len() as u16).to_le_bytes());
    for (peer, index) in indices {
        reply.extend_from_slice(&peer.to_le_bytes());
        reply.extend_from_slice(&index.to_le_bytes());
    }
    reply.push(0);
    reply
}
fn fixture_child(arguments: &[OsString]) -> Option<ExitCode> {
    if arguments
        .first()
        .is_none_or(|value| value != "__wgfeel-worker-v1")
    {
        return None;
    }
    let context = arguments.get(1)?.to_str()?;
    let mode = context.strip_prefix("tenant:probe_")?;
    let result = std::panic::catch_unwind(|| {
        assert_eq!(std::env::vars_os().count(), 0);
        assert_eq!(arguments.len(), 3);
        assert_eq!(arguments[2], MEMORY.to_string().as_str());
        if mode == "input" {
            let input = io::stdin();
            let flags = fcntl_getfl(&input).unwrap();
            fcntl_setfl(&input, flags | OFlags::NONBLOCK).unwrap();
            let deadline = Instant::now() + Duration::from_millis(100);
            let mut byte = [0];
            while Instant::now() < deadline {
                assert_eq!(
                    input.lock().read(&mut byte).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock,
                    "supervisor sent data before sandbox readiness"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            fcntl_setfl(&input, flags).unwrap();
        }
        enter_worker(WorkerLimits {
            address_space_bytes: MEMORY,
        })
        .unwrap();
        if mode == "input" {
            assert_eq!(
                UdpSocket::bind("127.0.0.1:0").unwrap_err().raw_os_error(),
                Some(1)
            );
        }
        if mode == "startup" {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        write_fixture_frame(&[1, 1]);
        let bootstrap = read_fixture_frame();
        assert_eq!(&bootstrap[..2], &[1, 2]);
        if mode == "input" {
            let mut expected = vec![1, 2];
            expected.extend_from_slice(&seed(4));
            expected.extend_from_slice(&10_u32.to_le_bytes());
            expected.extend_from_slice(&1_u16.to_le_bytes());
            expected.push(6);
            expected.extend_from_slice(b"client");
            expected.extend_from_slice(&public(14));
            assert_eq!(
                bootstrap, expected,
                "bootstrap must contain exactly this worker's secret and its configured public peer"
            );
            for foreign in [seed(5), seed(14), seed(15)] {
                assert!(!bootstrap.windows(32).any(|bytes| bytes == foreign));
            }
        }
        write_fixture_frame(&fixture_reply(0, u16::MAX, &[]));
        if mode == "idle_partial" {
            // Let the ordinary bootstrap reply be consumed before violating
            // the rule that an idle child must not emit even a partial frame.
            std::thread::sleep(Duration::from_millis(100));
            io::stdout().write_all(&[2]).unwrap();
            io::stdout().flush().unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        loop {
            let request = read_fixture_frame();
            assert_eq!(&request[..2], &[1, 3]);
            assert!(request.len() >= 13);
            let sequence = u64::from_le_bytes(request[2..10].try_into().unwrap());
            match mode {
                "input" => write_fixture_frame(&fixture_reply(sequence, u16::MAX, &[])),
                "stall" => loop {
                    std::thread::sleep(Duration::from_secs(1));
                },
                "oversize" => {
                    io::stdout().write_all(&131073_u32.to_le_bytes()).unwrap();
                    io::stdout().flush().unwrap();
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                "truncated" => {
                    io::stdout().write_all(&20_u32.to_le_bytes()).unwrap();
                    io::stdout().write_all(&[1, 4, 0]).unwrap();
                    io::stdout().flush().unwrap();
                    return;
                }
                "stale" => {
                    write_fixture_frame(&fixture_reply(sequence - 1, u16::MAX, &[]));
                }
                "peer" => {
                    write_fixture_frame(&fixture_reply(sequence, 65534, &[]));
                }
                "auth_reset" => {
                    assert_eq!(request[10], 5);
                    write_fixture_frame(&fixture_reply(sequence, 0, &[]));
                }
                "plaintext_reset" => {
                    assert_eq!(request[10], 5);
                    let mut reply = fixture_reply(sequence, u16::MAX, &[]);
                    *reply.last_mut().unwrap() = 2;
                    reply.extend_from_slice(&0_u16.to_le_bytes());
                    let packet = plaintext(false);
                    reply.extend_from_slice(&(packet.len() as u16).to_le_bytes());
                    reply.extend_from_slice(&packet);
                    write_fixture_frame(&reply);
                }
                "auth_handshake_none" | "auth_handshake_error" => {
                    assert_eq!(request[10], 1);
                    assert_eq!(&request[11..13], &[255, 255]);
                    let mut reply = fixture_reply(sequence, 0, &[]);
                    if mode == "auth_handshake_error" {
                        *reply.last_mut().unwrap() = 3;
                        reply.push(14);
                    }
                    write_fixture_frame(&reply);
                }
                "auth_transport_error" => {
                    if request[10] == 2 {
                        write_fixture_frame(&fixture_reply(
                            sequence,
                            u16::MAX,
                            &[(0, 0x1020_3040)],
                        ));
                    } else {
                        assert_eq!(request[10], 1);
                        assert_eq!(&request[11..13], &[0, 0]);
                        let mut reply = fixture_reply(sequence, 0, &[(0, 0x1020_3040)]);
                        *reply.last_mut().unwrap() = 3;
                        reply.push(14);
                        write_fixture_frame(&reply);
                    }
                }
                "flood" => {
                    let bytes = [0xff; 4096];
                    loop {
                        if io::stdout().write_all(&bytes).is_err() {
                            return;
                        }
                    }
                }
                "owner" | "collision" => {
                    write_fixture_frame(&fixture_reply(sequence, u16::MAX, &[(0, 0x1020_3040)]))
                }
                _ => panic!("unrecognized fixed test-only child mode"),
            }
        }
    });
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn no_private_input_before_ready_and_bootstrap_contains_only_own_material() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("probe_input"), 4, 14),
            config(tenant("healthy"), 5, 15),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let request = gateway
        .reset(&tenant("probe_input"), &device("client"))
        .unwrap();
    assert!(completed(&mut gateway, request).unwrap().is_none());
    let mut healthy = Peer::new(tenant("healthy"), 15, 5);
    establish(&mut gateway, &mut healthy);
    exchange(&mut gateway, &mut healthy, false);
}

fn wait_failed(gateway: &mut WorkerGateway, expected: &ContextId) -> WorkerError {
    let deadline = Instant::now() + WAIT;
    loop {
        match gateway.poll() {
            Some(WorkerEvent::Failed {
                context, reason, ..
            }) => {
                assert_eq!(&context, expected);
                return reason;
            }
            Some(WorkerEvent::Ready { .. }) | None => {}
            Some(event) => panic!("malformed or stalled worker released output: {event:?}"),
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn healthy_worker_progresses_before_stalled_sibling_operation_deadline() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("probe_stall"), 4, 14),
            config(tenant("healthy"), 5, 15),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut healthy = Peer::new(tenant("healthy"), 15, 5);
    establish(&mut gateway, &mut healthy);
    let started = Instant::now();
    let stalled = gateway
        .reset(&tenant("probe_stall"), &device("client"))
        .unwrap();
    exchange(&mut gateway, &mut healthy, true);
    assert!(
        started.elapsed() < options().operation_timeout,
        "healthy exchange must finish while sibling is still awaiting its timeout"
    );
    assert_eq!(
        gateway
            .workers()
            .into_iter()
            .find(|worker| worker.context == stalled.context)
            .unwrap()
            .state,
        WorkerState::Busy
    );
    assert_eq!(
        wait_failed(&mut gateway, &tenant("probe_stall")),
        WorkerError::Timeout
    );
    exchange(&mut gateway, &mut healthy, false);
}

fn healthy_worker_progresses_while_sibling_never_reports_sandbox_ready() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("probe_startup"), 4, 14),
            config(tenant("healthy"), 5, 15),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    let started = Instant::now();
    loop {
        if gateway
            .workers()
            .iter()
            .any(|worker| worker.context == tenant("healthy") && worker.state == WorkerState::Ready)
        {
            break;
        }
        if let Some(event) = gateway.poll() {
            assert!(
                matches!(event, WorkerEvent::Ready { .. }),
                "startup blocked healthy worker: {event:?}"
            );
        }
        assert!(started.elapsed() < options().startup_timeout);
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut healthy = Peer::new(tenant("healthy"), 15, 5);
    establish(&mut gateway, &mut healthy);
    exchange(&mut gateway, &mut healthy, false);
    assert!(started.elapsed() < options().startup_timeout);
    assert_eq!(
        wait_failed(&mut gateway, &tenant("probe_startup")),
        WorkerError::Timeout
    );
    exchange(&mut gateway, &mut healthy, true);
}

fn malformed_stale_oversized_and_flooded_replies_fail_closed_without_harming_peer() {
    for mode in ["oversize", "truncated", "stale", "peer", "flood"] {
        let context = tenant(&format!("probe_{mode}"));
        let mut gateway = WorkerGateway::spawn(
            vec![
                config(context.clone(), 4, 14),
                config(tenant("healthy"), 5, 15),
            ],
            Limits::default(),
            options(),
        )
        .unwrap();
        wait_ready(&mut gateway);
        let mut healthy = Peer::new(tenant("healthy"), 15, 5);
        establish(&mut gateway, &mut healthy);
        let victim = gateway
            .workers()
            .into_iter()
            .find(|worker| worker.context == context)
            .unwrap();
        gateway.reset(&context, &device("client")).unwrap();
        let reason = wait_failed(&mut gateway, &context);
        assert!(
            matches!(reason, WorkerError::Protocol | WorkerError::Io),
            "unexpected bounded frame failure category: {reason:?}"
        );
        assert!(!std::path::Path::new(&format!("/proc/{}", victim.pid)).exists());
        exchange(&mut gateway, &mut healthy, true);
    }
}

fn colliding_child_snapshot_cannot_replace_other_channels_index() {
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(tenant("probe_owner"), 4, 14),
            config(tenant("probe_collision"), 6, 16),
            config(tenant("healthy"), 5, 15),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut healthy = Peer::new(tenant("healthy"), 15, 5);
    establish(&mut gateway, &mut healthy);
    let owner = gateway
        .initiate_at(
            &tenant("probe_owner"),
            &device("client"),
            "198.51.100.4:40004".parse().unwrap(),
        )
        .unwrap();
    assert!(completed(&mut gateway, owner).unwrap().is_none());
    gateway
        .initiate_at(
            &tenant("probe_collision"),
            &device("client"),
            "198.51.100.6:40006".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(
        wait_failed(&mut gateway, &tenant("probe_collision")),
        WorkerError::IndexCollision
    );
    let mut probe = [0; 32];
    probe[0] = 4;
    probe[4..8].copy_from_slice(&0x1020_3040_u32.to_le_bytes());
    let Submission::Queued(request) = gateway
        .receive_datagram("198.51.100.4:40004".parse().unwrap(), &probe)
        .unwrap()
    else {
        panic!("transport index cannot generate cookie output");
    };
    assert_eq!(request.context, tenant("probe_owner"));
    assert!(completed(&mut gateway, request).unwrap().is_none());
    exchange(&mut gateway, &mut healthy, false);
}

fn reset_cannot_claim_authentication_or_release_plaintext_for_valid_peer() {
    for mode in ["auth_reset", "plaintext_reset"] {
        let context = tenant(&format!("probe_{mode}"));
        let mut gateway = WorkerGateway::spawn(
            vec![
                config(context.clone(), 4, 14),
                config(tenant("healthy"), 5, 15),
            ],
            Limits::default(),
            options(),
        )
        .unwrap();
        wait_ready(&mut gateway);
        let mut healthy = Peer::new(tenant("healthy"), 15, 5);
        establish(&mut gateway, &mut healthy);
        assert_eq!(gateway.endpoint(&context, &device("client")).unwrap(), None);
        gateway.reset(&context, &device("client")).unwrap();
        assert_eq!(wait_failed(&mut gateway, &context), WorkerError::Protocol);
        assert_eq!(gateway.endpoint(&context, &device("client")).unwrap(), None);
        exchange(&mut gateway, &mut healthy, true);
    }
}

fn authentication_claim_must_match_successful_receive_outcome() {
    for mode in [
        "auth_handshake_none",
        "auth_handshake_error",
        "auth_transport_error",
    ] {
        let context = tenant(&format!("probe_{mode}"));
        let mut gateway = WorkerGateway::spawn(
            vec![
                config(context.clone(), 4, 14),
                config(tenant("healthy"), 5, 15),
            ],
            Limits::default(),
            options(),
        )
        .unwrap();
        wait_ready(&mut gateway);
        let mut healthy = Peer::new(tenant("healthy"), 15, 5);
        establish(&mut gateway, &mut healthy);
        let source = "198.51.100.77:40077".parse().unwrap();
        let wire = if mode == "auth_transport_error" {
            let request = gateway
                .initiate_at(
                    &context,
                    &device("client"),
                    "198.51.100.4:40004".parse().unwrap(),
                )
                .unwrap();
            assert!(completed(&mut gateway, request).unwrap().is_none());
            let mut packet = vec![0; 32];
            packet[0] = 4;
            packet[4..8].copy_from_slice(&0x1020_3040_u32.to_le_bytes());
            packet
        } else {
            let mut peer = Peer::new(context.clone(), 14, 4);
            peer.initiate()
        };
        assert!(matches!(
            gateway.receive_datagram(source, &wire),
            Ok(Submission::Queued(_))
        ));
        assert_eq!(wait_failed(&mut gateway, &context), WorkerError::Protocol);
        assert_eq!(gateway.endpoint(&context, &device("client")).unwrap(), None);
        exchange(&mut gateway, &mut healthy, false);
    }
}

fn unsolicited_partial_prefix_is_rejected_while_worker_is_idle() {
    let context = tenant("probe_idle_partial");
    let mut gateway = WorkerGateway::spawn(
        vec![
            config(context.clone(), 4, 14),
            config(tenant("healthy"), 5, 15),
        ],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let started = Instant::now();
    loop {
        match gateway.poll() {
            Some(WorkerEvent::Failed {
                context: actual,
                reason,
                ..
            }) => {
                assert_eq!(actual, context);
                assert_eq!(reason, WorkerError::Protocol);
                break;
            }
            Some(WorkerEvent::Ready { .. }) | None => {}
            Some(event) => panic!("idle child emitted an accepted event: {event:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "unsolicited partial prefix retained without an outstanding request or deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(started.elapsed() < options().operation_timeout);
    let mut healthy = Peer::new(tenant("healthy"), 15, 5);
    establish(&mut gateway, &mut healthy);
    exchange(&mut gateway, &mut healthy, true);
}

fn parent_cookie_admission_is_single_and_retry_reaches_real_confined_worker() {
    let mut gateway = WorkerGateway::spawn(
        vec![config(tenant("alpha"), 1, 11)],
        Limits {
            handshake_limit_per_ip: 0,
        },
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut peer = Peer::new(tenant("alpha"), 11, 1);
    let before = gateway.workers();
    let initiation = peer.initiate();
    let Submission::Immediate(DatagramEvent::Network {
        destination,
        context,
        peer: identity,
        packet,
    }) = gateway.receive_datagram(peer.address, &initiation).unwrap()
    else {
        panic!("cookie admission must remain in the public supervisor");
    };
    assert_eq!(destination, peer.address);
    assert_eq!(context, peer.context);
    assert!(identity.is_none());
    assert_eq!(packet.as_bytes().len(), 64);
    assert_eq!(&packet.as_bytes()[..4], &[3, 0, 0, 0]);
    assert_eq!(gateway.workers(), before);
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    assert!(matches!(
        peer.receive(server_address(), packet.as_bytes()),
        TunnResult::Done
    ));
    let deadline = Instant::now() + Duration::from_secs(8);
    let retry = loop {
        if let Some(retry) = peer.engine.update_timers().unwrap() {
            let packet: Packet = retry.into();
            break packet.as_ref().to_vec();
        }
        assert!(
            gateway.poll().is_none(),
            "idle worker must not mutate or emit on its own"
        );
        assert!(
            Instant::now() < deadline,
            "real engine cookie retry deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(retry.len(), 148);
    assert_eq!(&retry[..4], &[1, 0, 0, 0]);
    let changed_port = SocketAddr::new(peer.address.ip(), peer.address.port() + 1);
    let Submission::Immediate(DatagramEvent::Network {
        destination,
        peer: identity,
        packet,
        ..
    }) = gateway.receive_datagram(changed_port, &retry).unwrap()
    else {
        panic!("cookie from the original UDP port must not authorize a different port");
    };
    assert_eq!(destination, changed_port);
    assert!(identity.is_none());
    assert_eq!(packet.as_bytes().len(), 64);
    assert_eq!(&packet.as_bytes()[..4], &[3, 0, 0, 0]);
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    let Submission::Queued(request) = gateway.receive_datagram(peer.address, &retry).unwrap()
    else {
        panic!("valid cookie retry must reach the configured worker");
    };
    assert_eq!(
        request.sequence, 1,
        "public cookie challenges must not consume worker operations"
    );
    let response = encrypted(completed(&mut gateway, request).unwrap().unwrap(), &peer);
    assert_eq!(response.len(), 92);
    assert_eq!(&response[..4], &[2, 0, 0, 0]);
    let TunnResult::WriteToNetwork(confirmation) = peer.receive(server_address(), &response) else {
        panic!("actual worker handshake response did not authenticate");
    };
    let confirmation: Packet = confirmation.into();
    assert!(
        receive(&mut gateway, peer.address, confirmation.as_ref())
            .unwrap()
            .is_none()
    );
    exchange(&mut gateway, &mut peer, false);
    exchange(&mut gateway, &mut peer, true);
}

fn roaming_requires_crypto_authentication_and_includes_malformed_ip_and_keepalive() {
    let mut gateway = WorkerGateway::spawn(
        vec![config(tenant("alpha"), 1, 11)],
        Limits::default(),
        options(),
    )
    .unwrap();
    wait_ready(&mut gateway);
    let mut peer = Peer::new(tenant("alpha"), 11, 1);
    establish(&mut gateway, &mut peer);
    let original = peer.encrypt(&plaintext(false));
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let roaming = "198.51.100.77:40077".parse().unwrap();
    assert_eq!(
        receive(&mut gateway, roaming, &tampered).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    let DatagramEvent::Plaintext {
        context,
        peer: identity,
        packet,
    } = receive(&mut gateway, roaming, &original).unwrap().unwrap()
    else {
        panic!("valid roaming packet must authenticate");
    };
    assert_eq!(context, peer.context);
    assert_eq!(identity, peer.id);
    assert_eq!(packet.as_bytes(), plaintext(false));
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(roaming)
    );
    let malformed_source = "198.51.100.78:40078".parse().unwrap();
    assert_eq!(
        receive(&mut gateway, malformed_source, &original).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(roaming)
    );
    let malformed = peer.encrypt(&[0x45; 19]);
    assert_eq!(
        receive(&mut gateway, malformed_source, &malformed).unwrap_err(),
        WireGuardError::InvalidPacket
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(malformed_source)
    );
    let keepalive_source = "198.51.100.79:40079".parse().unwrap();
    let keepalive = peer.encrypt(&[]);
    assert!(
        receive(&mut gateway, keepalive_source, &keepalive)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(keepalive_source)
    );
    assert_eq!(gateway.workers()[0].state, WorkerState::Ready);
    peer.address = keepalive_source;
    let reply = plaintext(true);
    let request = gateway
        .send_datagram(&peer.context, &peer.id, &reply)
        .unwrap();
    let wire = encrypted(completed(&mut gateway, request).unwrap().unwrap(), &peer);
    peer.assert_plaintext(server_address(), &wire, &reply);
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Some(status) = fixture_child(&arguments) {
        return status;
    }
    if let Some(status) = worker_main(&arguments) {
        return status;
    }
    let cases: &[(&str, fn())] = &[
        (
            "service_peer_changes_preserve_sessions_and_never_reconfigure_tenants",
            service_peer_changes_preserve_sessions_and_never_reconfigure_tenants,
        ),
        (
            "real_workers_install_policy_have_distinct_processes_and_drop_reaps_them",
            real_workers_install_policy_have_distinct_processes_and_drop_reaps_them,
        ),
        (
            "tenant_and_system_workers_complete_real_bidirectional_ipv4_ipv6",
            tenant_and_system_workers_complete_real_bidirectional_ipv4_ipv6,
        ),
        (
            "gateway_initiation_busy_and_reset_preserve_other_context",
            gateway_initiation_busy_and_reset_preserve_other_context,
        ),
        (
            "restart_rejects_public_identity_changes_and_retires_previous_generation",
            restart_rejects_public_identity_changes_and_retires_previous_generation,
        ),
        (
            "unexpected_worker_death_revokes_its_indices_without_disrupting_healthy_peer",
            unexpected_worker_death_revokes_its_indices_without_disrupting_healthy_peer,
        ),
        (
            "invalid_options_and_public_diagnostics_exclude_private_bytes",
            invalid_options_and_public_diagnostics_exclude_private_bytes,
        ),
        (
            "shared_udp_port_drives_all_worker_contexts_without_child_sockets",
            shared_udp_port_drives_all_worker_contexts_without_child_sockets,
        ),
        (
            "no_private_input_before_ready_and_bootstrap_contains_only_own_material",
            no_private_input_before_ready_and_bootstrap_contains_only_own_material,
        ),
        (
            "healthy_worker_progresses_before_stalled_sibling_operation_deadline",
            healthy_worker_progresses_before_stalled_sibling_operation_deadline,
        ),
        (
            "healthy_worker_progresses_while_sibling_never_reports_sandbox_ready",
            healthy_worker_progresses_while_sibling_never_reports_sandbox_ready,
        ),
        (
            "malformed_stale_oversized_and_flooded_replies_fail_closed_without_harming_peer",
            malformed_stale_oversized_and_flooded_replies_fail_closed_without_harming_peer,
        ),
        (
            "colliding_child_snapshot_cannot_replace_other_channels_index",
            colliding_child_snapshot_cannot_replace_other_channels_index,
        ),
        (
            "reset_cannot_claim_authentication_or_release_plaintext_for_valid_peer",
            reset_cannot_claim_authentication_or_release_plaintext_for_valid_peer,
        ),
        (
            "authentication_claim_must_match_successful_receive_outcome",
            authentication_claim_must_match_successful_receive_outcome,
        ),
        (
            "unsolicited_partial_prefix_is_rejected_while_worker_is_idle",
            unsolicited_partial_prefix_is_rejected_while_worker_is_idle,
        ),
        (
            "parent_cookie_admission_is_single_and_retry_reaches_real_confined_worker",
            parent_cookie_admission_is_single_and_retry_reaches_real_confined_worker,
        ),
        (
            "roaming_requires_crypto_authentication_and_includes_malformed_ip_and_keepalive",
            roaming_requires_crypto_authentication_and_includes_malformed_ip_and_keepalive,
        ),
    ];
    let filter = arguments
        .iter()
        .filter_map(|argument| argument.to_str())
        .find(|argument| !argument.starts_with('-'));
    let (mut passed, mut failed) = (0, 0);
    for (name, case) in cases {
        if filter.is_some_and(|filter| !name.contains(filter)) {
            continue;
        }
        if std::panic::catch_unwind(*case).is_ok() {
            passed += 1;
            println!("test {name} ... ok");
        } else {
            failed += 1;
            println!("test {name} ... FAILED");
        }
    }
    println!("workers result: {passed} passed; {failed} failed");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
