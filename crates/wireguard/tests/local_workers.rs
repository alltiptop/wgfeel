//! Projection-bound forwarding through real self-executed confined workers.
use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
    x25519::{PublicKey, StaticSecret},
};
use rustix::process::{Pid, Signal, kill_process};
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};
use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, GatewayAssignment,
    GatewayProjection, Grant, ManagementConfig, Network, NetworkId, NodeId, NodeKeys, Policy, Rule,
    TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_sandbox::{WorkerLimits, enter_worker};
use wgfeel_wireguard::{
    ContextId, ForwardError, Limits, PeerId, UdpTransport, WireGuardError,
    worker::{
        EncryptedDatagram, LocalError, LocalEvent, LocalGateway, WorkerError, WorkerOptions,
        WorkerState, worker_main,
    },
};

const MEMORY: u64 = 64 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(3);
fn options() -> WorkerOptions {
    WorkerOptions {
        address_space_bytes: MEMORY,
        startup_timeout: WAIT,
        operation_timeout: WAIT,
    }
}
fn network(name: &str) -> NetworkId {
    NetworkId::new(name).unwrap()
}
fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}
fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}
fn context(name: &str) -> ContextId {
    ContextId::Tenant(network(name))
}
fn peer(name: &str) -> PeerId {
    PeerId::Device(device(name))
}
fn endpoint(net: &str, name: &str) -> Endpoint {
    Endpoint::new(network(net), device(name))
}
fn seed(number: u8) -> [u8; 32] {
    let mut bytes = [97; 32];
    bytes[13] = number;
    bytes
}
fn public(number: u8) -> DevicePublicKey {
    DevicePublicKey::new(PublicKey::from(&StaticSecret::from(seed(number))).to_bytes()).unwrap()
}
fn allow(net: &str, source: &str, destination: &str) -> Rule {
    Rule::new(
        endpoint(net, source),
        endpoint(net, destination),
        Action::Allow,
    )
}
fn both(net: &str) -> Vec<Rule> {
    vec![allow(net, "first", "second"), allow(net, "second", "first")]
}
fn cross(source_net: &str, source: &str, target_net: &str, target: &str) -> Grant {
    Grant::new(endpoint(source_net, source), endpoint(target_net, target))
}
fn server() -> SocketAddr {
    "198.51.100.1:51820".parse().unwrap()
}

struct Client {
    context: ContextId,
    peer: PeerId,
    address: SocketAddr,
    engine: Tunn,
    limiter: Arc<RateLimiter>,
}
impl Client {
    fn new(net: &str, name: &str, key: u8, server_key: u8) -> Self {
        let secret = StaticSecret::from(seed(key));
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&secret), 100));
        Self {
            context: context(net),
            peer: peer(name),
            address: SocketAddr::from((Ipv4Addr::new(198, 51, 100, key), 40000 + u16::from(key))),
            engine: Tunn::new(
                secret,
                PublicKey::from(*public(server_key).as_bytes()),
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
    fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.engine
            .encapsulate_with_session(Packet::copy_from(bytes))
            .unwrap()
            .into_bytes()
            .as_ref()
            .to_vec()
    }
    fn receive(&mut self, source: SocketAddr, bytes: &[u8]) -> TunnResult {
        self.limiter.try_reset_count();
        let packet = self
            .limiter
            .verify_packet(source, Packet::copy_from(bytes))
            .unwrap();
        self.engine.handle_incoming_packet(packet)
    }
    fn assert_plaintext(&mut self, source: SocketAddr, encrypted: &[u8], expected: &[u8]) {
        let TunnResult::WriteToTunnel(packet) = self.receive(source, encrypted) else {
            panic!("destination did not authenticate forwarded bytes");
        };
        assert!(packet.as_ref().len() >= expected.len());
        assert!(packet.as_ref().len() - expected.len() <= 15);
        assert_eq!(&packet.as_ref()[..expected.len()], expected);
        assert!(
            packet.as_ref()[expected.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }
}

fn projection(alpha: &str, policy: Policy, local: &[&str]) -> GatewayProjection {
    let specs = [
        (alpha, 1, 1),
        ("beta", 2, 2),
        ("isolated", 3, 1),
        ("gamma", 4, 2),
    ];
    let networks = specs
        .iter()
        .map(|(net, key, subnet)| {
            let devices = [("first", 1), ("second", 2)]
                .into_iter()
                .map(|(name, host)| {
                    Device::new(
                        device(name),
                        public(20 + key * 2 + host),
                        vec![
                            format!("10.{subnet}.0.{host}").parse::<IpAddr>().unwrap(),
                            format!("fd00:{subnet}::{host}").parse().unwrap(),
                        ],
                    )
                    .unwrap()
                })
                .collect();
            Network::new(network(net), devices).unwrap()
        })
        .collect();
    let assignment = GatewayAssignment::new(
        node("gateway"),
        (public(9)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(public(9))),
        specs.iter().map(|(net, _, _)| network(net)).collect(),
        specs
            .iter()
            .filter(|(net, _, _)| local.contains(net))
            .map(|(net, key, _)| TenantKeyAssignment::new(network(net), public(*key)))
            .collect(),
    )
    .unwrap();
    ManagementConfig::new(
        node("management"),
        Config::new(41, networks, policy).unwrap(),
        vec![assignment],
    )
    .unwrap()
    .project_for(&node("gateway"))
    .unwrap()
}
fn keys(alpha: &str, local: &[&str]) -> Vec<(NetworkId, TenantPrivateKey)> {
    [(alpha, 1), ("beta", 2), ("isolated", 3), ("gamma", 4)]
        .into_iter()
        .filter(|(net, _)| local.contains(net))
        .map(|(net, key)| (network(net), TenantPrivateKey::new(seed(key)).unwrap()))
        .collect()
}
fn build(
    projection: &GatewayProjection,
    management: &NodeId,
    recipient: &NodeId,
    node_key: &NodeKeys,
    keys: &[(NetworkId, TenantPrivateKey)],
) -> Result<LocalGateway, LocalError> {
    LocalGateway::spawn(
        projection,
        management,
        recipient,
        node_key,
        keys.iter().map(|(net, key)| (net, key)),
        Limits {
            handshake_limit_per_ip: 100,
        },
        options(),
    )
}
struct Fixture {
    gateway: LocalGateway,
    clients: Vec<Client>,
}
impl Fixture {
    fn new(policy: Policy, local: &[&str]) -> Self {
        let projection = projection("alpha", policy, local);
        let material = keys("alpha", local);
        let gateway = build(
            &projection,
            &node("management"),
            &node("gateway"),
            &wgfeel_test_support::fixture_node_keys(seed(9)),
            &material,
        )
        .unwrap();
        let clients = [("alpha", 1), ("beta", 2), ("isolated", 3), ("gamma", 4)]
            .into_iter()
            .flat_map(|(net, key)| {
                [("first", 1), ("second", 2)]
                    .into_iter()
                    .map(move |(name, host)| Client::new(net, name, 20 + key * 2 + host, key))
            })
            .collect();
        let mut fixture = Self { gateway, clients };
        fixture.ready();
        fixture
    }
    fn ready(&mut self) {
        let deadline = Instant::now() + WAIT;
        loop {
            if self
                .gateway
                .workers()
                .iter()
                .all(|worker| worker.state == WorkerState::Ready)
            {
                break;
            }
            if let Some(event) = self.gateway.poll() {
                assert!(
                    matches!(event, LocalEvent::Ready { .. }),
                    "unexpected startup event: {event:?}"
                );
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn event(&mut self) -> LocalEvent {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(event) = self.gateway.poll()
                && !matches!(event, LocalEvent::Ready { .. })
            {
                return event;
            }
            assert!(Instant::now() < deadline, "missing local worker result");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn establish(&mut self, index: usize) {
        let wire = self.clients[index].initiate();
        let source = self.clients[index].address;
        let immediate = self.gateway.receive_datagram(source, &wire).unwrap();
        let response = immediate.unwrap_or_else(|| match self.event() {
            LocalEvent::Network(packet) => packet,
            event => panic!("expected handshake output: {event:?}"),
        });
        let bytes = encrypted(response, &self.clients[index]);
        let TunnResult::WriteToNetwork(confirmation) =
            self.clients[index].receive(server(), &bytes)
        else {
            panic!("expected handshake confirmation");
        };
        let confirmation: Packet = confirmation.into();
        assert!(
            self.gateway
                .receive_datagram(source, confirmation.as_ref())
                .unwrap()
                .is_none()
        );
        self.wait_idle(&self.clients[index].context.clone());
    }
    fn wait_idle(&mut self, context: &ContextId) {
        let deadline = Instant::now() + WAIT;
        loop {
            if self
                .gateway
                .workers()
                .iter()
                .any(|worker| &worker.context == context && worker.state == WorkerState::Ready)
            {
                return;
            }
            if let Some(event) = self.gateway.poll() {
                assert!(
                    matches!(event, LocalEvent::Ready { .. }),
                    "unexpected idle transition output: {event:?}"
                );
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn submit(&mut self, source: usize, bytes: &[u8]) {
        let wire = self.clients[source].encrypt(bytes);
        assert!(
            self.gateway
                .receive_datagram(self.clients[source].address, &wire)
                .unwrap()
                .is_none()
        );
    }
    fn drop_packet(&mut self, source: usize, bytes: &[u8], reason: LocalError) {
        self.submit(source, bytes);
        let LocalEvent::Dropped {
            context,
            peer,
            reason: actual,
        } = self.event()
        else {
            panic!("rejected plaintext escaped as network output");
        };
        assert_eq!(context, self.clients[source].context);
        assert_eq!(peer.as_ref(), Some(&self.clients[source].peer));
        assert_eq!(actual, reason);
    }
    fn forward(&mut self, source: usize, destination: usize, bytes: &[u8]) {
        let projection = self.gateway.projection().to_json().unwrap();
        let expected = decrement(bytes);
        self.submit(source, bytes);
        let LocalEvent::Network(packet) = self.event() else {
            panic!("permitted packet did not produce encrypted destination output");
        };
        let bytes = encrypted(packet, &self.clients[destination]);
        self.clients[destination].assert_plaintext(server(), &bytes, &expected);
        assert_eq!(self.gateway.projection().to_json().unwrap(), projection);
    }
}

fn encrypted(packet: EncryptedDatagram, client: &Client) -> Vec<u8> {
    assert_eq!(packet.destination, client.address);
    assert_eq!(packet.context, client.context);
    assert_eq!(packet.peer.as_ref(), Some(&client.peer));
    packet.packet.as_bytes().to_vec()
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn repair_ipv4(bytes: &mut [u8]) {
    bytes[10..12].fill(0);
    let sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
}
fn decrement(bytes: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_vec();
    if result[0] >> 4 == 4 {
        result[8] -= 1;
        repair_ipv4(&mut result);
        assert_eq!(checksum(&result[..20]), 0);
    } else {
        result[7] -= 1;
    }
    result
}
fn udp(ipv6: bool, source: &str, destination: &str, hops: u8, marker: u8) -> Vec<u8> {
    let header = if ipv6 { 40 } else { 20 };
    let mut bytes = vec![0; header + 12];
    if ipv6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&12_u16.to_be_bytes());
        bytes[6] = 17;
        bytes[7] = hops;
        bytes[8..24].copy_from_slice(&source.parse::<Ipv6Addr>().unwrap().octets());
        bytes[24..40].copy_from_slice(&destination.parse::<Ipv6Addr>().unwrap().octets());
    } else {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&32_u16.to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = hops;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
        bytes[16..20].copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
        repair_ipv4(&mut bytes);
    }
    bytes[header..header + 4].copy_from_slice(&[0x9c, 0x40, 0x1f, 0x90]);
    bytes[header + 4..header + 6].copy_from_slice(&12_u16.to_be_bytes());
    bytes[header + 8..].fill(marker);
    let mut pseudo = if ipv6 {
        bytes[8..40].to_vec()
    } else {
        bytes[12..20].to_vec()
    };
    if ipv6 {
        pseudo.extend_from_slice(&[0, 0, 0, 12, 0, 0, 0, 17]);
    } else {
        pseudo.extend_from_slice(&[0, 17, 0, 12]);
    }
    pseudo.extend_from_slice(&bytes[header..]);
    let check = checksum(&pseudo);
    bytes[header + 6..header + 8]
        .copy_from_slice(&if check == 0 { 0xffff } else { check }.to_be_bytes());
    bytes
}

fn projection_pins_and_exact_local_keys_are_required_before_workers_start() {
    let projection = projection(
        "alpha",
        Policy::new(vec![], both("alpha"), vec![]),
        &["alpha"],
    );
    let correct = keys("alpha", &["alpha"]);
    let node_key = wgfeel_test_support::fixture_node_keys(seed(9));
    for (management, recipient) in [("wrong", "gateway"), ("management", "wrong")] {
        assert!(
            build(
                &projection,
                &node(management),
                &node(recipient),
                &node_key,
                &correct
            )
            .is_err()
        );
    }
    assert!(
        build(
            &projection,
            &node("management"),
            &node("gateway"),
            &wgfeel_test_support::fixture_node_keys(seed(8)),
            &correct
        )
        .is_err()
    );
    for material in [
        vec![],
        keys("alpha", &["alpha", "beta"]),
        vec![(network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())],
        vec![
            (network("alpha"), TenantPrivateKey::new(seed(1)).unwrap()),
            (network("alpha"), TenantPrivateKey::new(seed(1)).unwrap()),
        ],
    ] {
        assert!(
            build(
                &projection,
                &node("management"),
                &node("gateway"),
                &node_key,
                &material
            )
            .is_err()
        );
    }
    let gateway = build(
        &projection,
        &node("management"),
        &node("gateway"),
        &node_key,
        &correct,
    )
    .unwrap();
    assert_eq!(gateway.workers().len(), 3);
    assert_eq!(gateway.projection(), &projection);
    assert!(gateway.workers().iter().all(|worker| matches!(
        &worker.context,
        ContextId::Service | ContextId::Gateway
    ) || worker.context == context("alpha")));
}

fn overlapping_tenants_forward_ipv4_ipv6_only_to_their_own_device_with_one_hop() {
    let mut rules = both("alpha");
    rules.extend(both("isolated"));
    let mut fixture = Fixture::new(Policy::new(vec![], rules, vec![]), &["alpha", "isolated"]);
    for index in [0, 1, 4, 5] {
        fixture.establish(index);
    }
    assert_eq!(fixture.gateway.workers().len(), 4);
    for (ipv6, source, destination) in [
        (false, "10.1.0.1", "10.1.0.2"),
        (true, "fd00:1::1", "fd00:1::2"),
    ] {
        let bytes = udp(ipv6, source, destination, 2, 11);
        fixture.forward(0, 1, &bytes);
        fixture.forward(4, 5, &bytes);
        fixture.forward(1, 0, &udp(ipv6, destination, source, 64, 12));
    }
}

fn directional_grants_global_denies_and_ambiguous_remote_addresses_survive_worker_boundary() {
    let grants = vec![
        cross("alpha", "first", "beta", "first"),
        cross("alpha", "second", "beta", "second"),
        cross("alpha", "second", "beta", "first"),
        cross("alpha", "second", "gamma", "first"),
    ];
    let deny = Rule::new(
        endpoint("alpha", "second"),
        endpoint("beta", "second"),
        Action::Deny,
    );
    let mut fixture = Fixture::new(
        Policy::new(vec![deny], vec![], grants),
        &["alpha", "beta", "gamma"],
    );
    for index in [0, 1, 2, 3, 6] {
        fixture.establish(index);
    }
    for (ipv6, source, destination) in [
        (false, "10.1.0.1", "10.2.0.1"),
        (true, "fd00:1::1", "fd00:2::1"),
    ] {
        fixture.forward(0, 2, &udp(ipv6, source, destination, 64, 21));
        fixture.drop_packet(
            2,
            &udp(ipv6, destination, source, 64, 22),
            LocalError::Forward(ForwardError::UnknownDestination),
        );
    }
    fixture.drop_packet(
        1,
        &udp(false, "10.1.0.2", "10.2.0.2", 64, 23),
        LocalError::Forward(ForwardError::Denied),
    );
    fixture.drop_packet(
        1,
        &udp(true, "fd00:1::2", "fd00:2::1", 64, 24),
        LocalError::Forward(ForwardError::AmbiguousDestination),
    );
}

fn unavailable_nonlocal_and_invalid_packets_drop_without_a_later_payload_queue() {
    let mut fixture = Fixture::new(
        Policy::new(
            vec![],
            both("alpha"),
            vec![cross("alpha", "first", "beta", "first")],
        ),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.drop_packet(
        0,
        &udp(false, "10.1.0.1", "10.2.0.1", 64, 31),
        LocalError::Forward(ForwardError::NotLocal),
    );
    fixture.drop_packet(
        0,
        &udp(false, "10.1.0.1", "203.0.113.10", 64, 32),
        LocalError::Forward(ForwardError::UnknownDestination),
    );
    fixture.drop_packet(
        0,
        &udp(false, "10.1.0.1", "10.1.0.2", 64, 33),
        LocalError::Worker(WorkerError::WireGuard(WireGuardError::NoEndpoint)),
    );
    fixture.drop_packet(
        0,
        &udp(true, "fd00:1::1", "fd00:1::2", 1, 34),
        LocalError::Forward(ForwardError::HopLimitExceeded),
    );
    let mut invalid = udp(false, "10.1.0.1", "10.1.0.2", 64, 35);
    invalid[10] ^= 1;
    fixture.drop_packet(
        0,
        &invalid,
        LocalError::Forward(ForwardError::InvalidPacket),
    );
    let mut fragment = udp(false, "10.1.0.1", "10.1.0.2", 64, 36);
    fragment[6] = 0x20;
    repair_ipv4(&mut fragment);
    fixture.drop_packet(
        0,
        &fragment,
        LocalError::Forward(ForwardError::UnsupportedPacket),
    );
    fixture.establish(1);
    fixture.forward(0, 1, &udp(false, "10.1.0.1", "10.1.0.2", 64, 37));
    assert!(
        fixture.gateway.poll().is_none(),
        "old rejected plaintext must not be replayed after the destination appears"
    );
}

fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let deadline = Instant::now() + WAIT;
    let mut buffer = [0; 1313];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => return (buffer[..length].to_vec(), source),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("test UDP receive failed: {error}"),
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn actual_udp_denies_global_rule_and_spoof_then_delivers_permitted_reverse_flow() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let transport = UdpTransport::from_socket(server_socket.try_clone().unwrap()).unwrap();
    let address = transport.local_addr().unwrap();
    let deny = Rule::new(
        endpoint("alpha", "first"),
        endpoint("alpha", "second"),
        Action::Deny,
    );
    let mut fixture = Fixture::new(Policy::new(vec![deny], both("alpha"), vec![]), &["alpha"]);
    let clients = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    for (index, socket) in clients.iter().enumerate() {
        socket
            .set_read_timeout(Some(Duration::from_millis(120)))
            .unwrap();
        fixture.clients[index].address = socket.local_addr().unwrap();
        socket
            .send_to(&fixture.clients[index].initiate(), address)
            .unwrap();
        let (wire, source) = recv(&server_socket);
        assert!(
            fixture
                .gateway
                .receive_datagram(source, &wire)
                .unwrap()
                .is_none()
        );
        let LocalEvent::Network(response) = fixture.event() else {
            panic!("expected handshake output");
        };
        transport.transmit(response.into()).unwrap();
        let (wire, source) = recv(socket);
        assert_eq!(source, address);
        let TunnResult::WriteToNetwork(confirmation) =
            fixture.clients[index].receive(address, &wire)
        else {
            panic!("expected confirmation");
        };
        let confirmation: Packet = confirmation.into();
        socket.send_to(confirmation.as_ref(), address).unwrap();
        let (wire, source) = recv(&server_socket);
        assert!(
            fixture
                .gateway
                .receive_datagram(source, &wire)
                .unwrap()
                .is_none()
        );
        fixture.wait_idle(&context("alpha"));
    }
    for (source_index, target_index, bytes, reason) in [
        (
            0,
            1,
            udp(false, "10.1.0.1", "10.1.0.2", 64, 41),
            ForwardError::Denied,
        ),
        (
            1,
            0,
            udp(true, "fd00:1::1", "fd00:1::1", 64, 42),
            ForwardError::SourceMismatch,
        ),
    ] {
        let wire = fixture.clients[source_index].encrypt(&bytes);
        clients[source_index].send_to(&wire, address).unwrap();
        let (wire, source) = recv(&server_socket);
        assert!(
            fixture
                .gateway
                .receive_datagram(source, &wire)
                .unwrap()
                .is_none()
        );
        let LocalEvent::Dropped {
            context: owner,
            peer: identity,
            reason: actual,
        } = fixture.event()
        else {
            panic!("forbidden UDP input emitted an encrypted packet");
        };
        assert_eq!(owner, context("alpha"));
        assert_eq!(identity.as_ref(), Some(&fixture.clients[source_index].peer));
        assert_eq!(actual, LocalError::Forward(reason));
        let error = clients[target_index].recv_from(&mut [0; 1313]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }
    let bytes = udp(true, "fd00:1::2", "fd00:1::1", 64, 43);
    let wire = fixture.clients[1].encrypt(&bytes);
    clients[1].send_to(&wire, address).unwrap();
    let (wire, source) = recv(&server_socket);
    assert!(
        fixture
            .gateway
            .receive_datagram(source, &wire)
            .unwrap()
            .is_none()
    );
    let LocalEvent::Network(output) = fixture.event() else {
        panic!("permitted UDP input was not forwarded");
    };
    assert_eq!(output.destination, clients[0].local_addr().unwrap());
    transport.transmit(output.into()).unwrap();
    let (wire, source) = recv(&clients[0]);
    assert_eq!(source, address);
    fixture.clients[0].assert_plaintext(address, &wire, &decrement(&bytes));
}

struct PausedChild(Option<Pid>);
impl PausedChild {
    fn new(pid: u32) -> Self {
        let pid = Pid::from_raw(pid as i32).unwrap();
        kill_process(pid, Signal::STOP).unwrap();
        Self(Some(pid))
    }
    fn resume(self) {
        drop(self);
    }
    fn disarm(mut self) {
        self.0 = None;
    }
}
impl Drop for PausedChild {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = kill_process(pid, Signal::CONT);
        }
    }
}
fn cross_fixture() -> Fixture {
    let mut fixture = Fixture::new(
        Policy::new(
            vec![],
            both("isolated"),
            vec![cross("alpha", "first", "beta", "first")],
        ),
        &["alpha", "beta", "isolated"],
    );
    for index in [0, 2, 4, 5] {
        fixture.establish(index);
    }
    fixture
}
fn worker_pid(fixture: &Fixture, net: &str) -> u32 {
    fixture
        .gateway
        .workers()
        .into_iter()
        .find(|worker| worker.context == context(net))
        .unwrap()
        .pid
}
fn wait_egress_busy(fixture: &mut Fixture) {
    let deadline = Instant::now() + WAIT;
    loop {
        if fixture
            .gateway
            .workers()
            .iter()
            .any(|worker| worker.context == context("beta") && worker.state == WorkerState::Busy)
        {
            return;
        }
        if let Some(event) = fixture.gateway.poll() {
            assert!(
                matches!(event, LocalEvent::Ready { .. }),
                "egress completed while destination was stopped: {event:?}"
            );
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn busy_destination_drops_without_replay_and_other_tenant_keeps_progressing() {
    let mut fixture = cross_fixture();
    let pause = PausedChild::new(worker_pid(&fixture, "beta"));
    fixture
        .gateway
        .tick(&context("beta"), &peer("first"))
        .unwrap();
    fixture.drop_packet(
        0,
        &udp(false, "10.1.0.1", "10.2.0.1", 64, 51),
        LocalError::Worker(WorkerError::Busy),
    );
    fixture.forward(4, 5, &udp(true, "fd00:1::1", "fd00:1::2", 64, 52));
    pause.resume();
    fixture.wait_idle(&context("beta"));
    fixture.forward(0, 2, &udp(false, "10.1.0.1", "10.2.0.1", 64, 53));
    assert!(
        fixture.gateway.poll().is_none(),
        "busy destination must not replay discarded payload later"
    );
}

fn source_restart_suppresses_pending_cross_worker_output_without_killing_destination() {
    let mut fixture = cross_fixture();
    let destination_pid = worker_pid(&fixture, "beta");
    let pause = PausedChild::new(destination_pid);
    fixture.submit(0, &udp(false, "10.1.0.1", "10.2.0.1", 64, 61));
    wait_egress_busy(&mut fixture);
    let old_generation = fixture
        .gateway
        .workers()
        .into_iter()
        .find(|worker| worker.context == context("alpha"))
        .unwrap()
        .generation;
    fixture
        .gateway
        .restart_tenant(&network("alpha"), &TenantPrivateKey::new(seed(1)).unwrap())
        .unwrap();
    fixture.forward(4, 5, &udp(false, "10.1.0.1", "10.1.0.2", 64, 62));
    pause.resume();
    let LocalEvent::Dropped {
        context: origin,
        peer: identity,
        reason,
    } = fixture.event()
    else {
        panic!("old source generation released destination ciphertext");
    };
    assert_eq!(origin, context("alpha"));
    assert_eq!(identity, Some(peer("first")));
    assert_eq!(reason, LocalError::Cancelled);
    assert_eq!(worker_pid(&fixture, "beta"), destination_pid);
    fixture.wait_idle(&context("alpha"));
    assert!(
        fixture
            .gateway
            .workers()
            .iter()
            .any(|worker| worker.context == context("alpha") && worker.generation > old_generation)
    );
    fixture.clients[0] = Client::new("alpha", "first", 23, 1);
    fixture.establish(0);
    fixture.forward(0, 2, &udp(true, "fd00:1::1", "fd00:2::1", 64, 63));
}

fn observed_source_death_cancels_pending_output_and_destination_death_clears_its_work() {
    for victim in ["alpha", "beta"] {
        let mut fixture = cross_fixture();
        let mut pause = Some(PausedChild::new(worker_pid(&fixture, "beta")));
        fixture.submit(0, &udp(false, "10.1.0.1", "10.2.0.1", 64, 71));
        wait_egress_busy(&mut fixture);
        kill_process(
            Pid::from_raw(worker_pid(&fixture, victim) as i32).unwrap(),
            Signal::KILL,
        )
        .unwrap();
        if victim == "beta" {
            pause.take().unwrap().disarm();
        }
        let LocalEvent::Failed {
            context: failed, ..
        } = fixture.event()
        else {
            panic!("expected affected worker failure before any ciphertext");
        };
        assert_eq!(failed, context(victim));
        fixture.forward(4, 5, &udp(true, "fd00:1::1", "fd00:1::2", 64, 72));
        if let Some(pause) = pause {
            pause.resume();
        }
        if victim == "alpha" {
            let LocalEvent::Dropped {
                context: origin,
                reason,
                ..
            } = fixture.event()
            else {
                panic!("dead source released stale ciphertext");
            };
            assert_eq!(origin, context("alpha"));
            assert_eq!(reason, LocalError::Cancelled);
        }
        fixture
            .gateway
            .restart_tenant(
                &network(victim),
                &TenantPrivateKey::new(seed(if victim == "alpha" { 1 } else { 2 })).unwrap(),
            )
            .unwrap();
        fixture.wait_idle(&context(victim));
        let index = if victim == "alpha" { 0 } else { 2 };
        let key = if victim == "alpha" { 23 } else { 25 };
        let server_key = if victim == "alpha" { 1 } else { 2 };
        fixture.clients[index] = Client::new(victim, "first", key, server_key);
        fixture.establish(index);
        fixture.forward(0, 2, &udp(false, "10.1.0.1", "10.2.0.1", 64, 73));
    }
}

// Independent wire fixture: a compromised own-context worker can claim its
// assigned peer authenticated. The parent must still apply source ownership,
// policy and packet checks. This does not claim parent-side AEAD verification.
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
fn fixture_reply(sequence: u64, authenticated: bool, index: bool) -> Vec<u8> {
    let mut body = vec![1, 4];
    body.extend_from_slice(&sequence.to_le_bytes());
    body.extend_from_slice(&(if authenticated { 0_u16 } else { u16::MAX }).to_le_bytes());
    body.extend_from_slice(&u16::from(index).to_le_bytes());
    if index {
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&0x10203040_u32.to_le_bytes());
    }
    body
}
fn hostile_child(arguments: &[OsString]) -> Option<ExitCode> {
    if arguments
        .first()
        .is_none_or(|value| value != "__wgfeel-worker-v1")
    {
        return None;
    }
    let mode = arguments.get(1)?.to_str()?.strip_prefix("tenant:probe_")?;
    let result = std::panic::catch_unwind(|| {
        assert_eq!(std::env::vars_os().count(), 0);
        assert_eq!(arguments.len(), 3);
        assert_eq!(arguments[2], MEMORY.to_string().as_str());
        enter_worker(WorkerLimits {
            address_space_bytes: MEMORY,
        })
        .unwrap();
        write_fixture_frame(&[1, 1]);
        let bootstrap = read_fixture_frame();
        assert_eq!(&bootstrap[..2], &[1, 2]);
        assert_eq!(&bootstrap[2..34], &seed(1));
        let mut initial = fixture_reply(0, false, false);
        initial.push(0);
        write_fixture_frame(&initial);
        loop {
            let request = read_fixture_frame();
            assert_eq!(&request[..2], &[1, 3]);
            let sequence = u64::from_le_bytes(request[2..10].try_into().unwrap());
            let mut reply = fixture_reply(sequence, request[10] == 1, true);
            match request[10] {
                2 => reply.push(0),
                1 => {
                    assert_eq!(&request[11..13], &0_u16.to_le_bytes());
                    let mut packet = udp(
                        false,
                        if mode == "spoof" {
                            "10.1.0.2"
                        } else {
                            "10.1.0.1"
                        },
                        "10.1.0.2",
                        64,
                        81,
                    );
                    if mode == "malformed" {
                        packet[10] ^= 1;
                    }
                    reply.push(2);
                    reply.extend_from_slice(&0_u16.to_le_bytes());
                    reply.extend_from_slice(&(packet.len() as u16).to_le_bytes());
                    reply.extend_from_slice(&packet);
                }
                _ => panic!("unexpected operation in hostile fixture"),
            }
            write_fixture_frame(&reply);
        }
    });
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
fn hostile_own_context_plaintext_cannot_bypass_parent_source_policy_or_packet_checks() {
    for (name, expected) in [
        ("probe_spoof", ForwardError::SourceMismatch),
        ("probe_deny", ForwardError::Denied),
        ("probe_malformed", ForwardError::InvalidPacket),
    ] {
        let global = if name == "probe_deny" {
            vec![Rule::new(
                endpoint(name, "first"),
                endpoint(name, "second"),
                Action::Deny,
            )]
        } else {
            vec![]
        };
        let projection = projection(name, Policy::new(global, both(name), vec![]), &[name]);
        let material = keys(name, &[name]);
        let gateway = build(
            &projection,
            &node("management"),
            &node("gateway"),
            &wgfeel_test_support::fixture_node_keys(seed(9)),
            &material,
        )
        .unwrap();
        let mut fixture = Fixture {
            gateway,
            clients: vec![],
        };
        fixture.ready();
        let source = "198.51.100.81:40081".parse().unwrap();
        fixture
            .gateway
            .initiate_at(&context(name), &peer("first"), source)
            .unwrap();
        fixture.wait_idle(&context(name));
        let mut datagram = [0; 32];
        datagram[0] = 4;
        datagram[4..8].copy_from_slice(&0x10203040_u32.to_le_bytes());
        assert!(
            fixture
                .gateway
                .receive_datagram(source, &datagram)
                .unwrap()
                .is_none()
        );
        let LocalEvent::Dropped {
            context: origin,
            peer: identity,
            reason,
        } = fixture.event()
        else {
            panic!("hostile plaintext escaped parent checks");
        };
        assert_eq!(origin, context(name));
        assert_eq!(identity, Some(peer("first")));
        assert_eq!(reason, LocalError::Forward(expected));
        assert!(fixture.gateway.poll().is_none());
    }
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Some(status) = hostile_child(&arguments) {
        return status;
    }
    if let Some(status) = worker_main(&arguments) {
        return status;
    }
    let cases: &[(&str, fn())] = &[
        (
            "projection_pins_and_exact_local_keys_are_required_before_workers_start",
            projection_pins_and_exact_local_keys_are_required_before_workers_start,
        ),
        (
            "overlapping_tenants_forward_ipv4_ipv6_only_to_their_own_device_with_one_hop",
            overlapping_tenants_forward_ipv4_ipv6_only_to_their_own_device_with_one_hop,
        ),
        (
            "directional_grants_global_denies_and_ambiguous_remote_addresses_survive_worker_boundary",
            directional_grants_global_denies_and_ambiguous_remote_addresses_survive_worker_boundary,
        ),
        (
            "unavailable_nonlocal_and_invalid_packets_drop_without_a_later_payload_queue",
            unavailable_nonlocal_and_invalid_packets_drop_without_a_later_payload_queue,
        ),
        (
            "actual_udp_denies_global_rule_and_spoof_then_delivers_permitted_reverse_flow",
            actual_udp_denies_global_rule_and_spoof_then_delivers_permitted_reverse_flow,
        ),
        (
            "busy_destination_drops_without_replay_and_other_tenant_keeps_progressing",
            busy_destination_drops_without_replay_and_other_tenant_keeps_progressing,
        ),
        (
            "source_restart_suppresses_pending_cross_worker_output_without_killing_destination",
            source_restart_suppresses_pending_cross_worker_output_without_killing_destination,
        ),
        (
            "observed_source_death_cancels_pending_output_and_destination_death_clears_its_work",
            observed_source_death_cancels_pending_output_and_destination_death_clears_its_work,
        ),
        (
            "hostile_own_context_plaintext_cannot_bypass_parent_source_policy_or_packet_checks",
            hostile_own_context_plaintext_cannot_bypass_parent_source_policy_or_packet_checks,
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
    println!("local workers result: {passed} passed; {failed} failed");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
