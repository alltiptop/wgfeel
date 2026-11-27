use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
    x25519::{PublicKey, StaticSecret},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, GatewayAssignment, Grant,
    ManagementConfig, Network, NetworkId, NodeId, Policy, Rule, TenantKeyAssignment,
    TenantPrivateKey,
};
use wgfeel_wireguard::{
    ContextId, DatagramEvent, ForwardError, Gateway, Limits, PeerId, TransportError, UdpEvent,
    UdpTransport, WireGuardError,
};

fn network(name: &str) -> NetworkId {
    NetworkId::new(name).unwrap()
}
fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}
fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}
fn endpoint(net: &str, name: &str) -> Endpoint {
    Endpoint::new(network(net), device(name))
}
fn seed(number: u8) -> [u8; 32] {
    let mut bytes = [79; 32];
    bytes[12] = number;
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
fn both_directions(net: &str) -> Vec<Rule> {
    vec![allow(net, "first", "second"), allow(net, "second", "first")]
}
fn server_address() -> SocketAddr {
    "198.51.100.1:51820".parse().unwrap()
}

struct RawPeer {
    context: ContextId,
    id: PeerId,
    address: SocketAddr,
    engine: Tunn,
    limiter: Arc<RateLimiter>,
}
impl RawPeer {
    fn new(net: &str, name: &str, key: u8, server_key: u8, port: u16) -> Self {
        let secret = StaticSecret::from(seed(key));
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&secret), 100));
        Self {
            context: ContextId::Tenant(network(net)),
            id: PeerId::Device(device(name)),
            address: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), port)),
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
    fn initiation(&mut self) -> Vec<u8> {
        self.engine
            .format_handshake_initiation(false)
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
    fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.engine
            .encapsulate_with_session(Packet::copy_from(bytes))
            .unwrap()
            .into_bytes()
            .as_ref()
            .to_vec()
    }
    fn assert_plaintext(&mut self, source: SocketAddr, bytes: &[u8], expected: &[u8]) {
        let TunnResult::WriteToTunnel(packet) = self.receive(source, bytes) else {
            panic!("forwarded ciphertext did not authenticate for the destination device");
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

struct Fixture {
    gateway: Gateway,
    peers: Vec<RawPeer>,
}
impl Fixture {
    fn new(policy: Policy, local: &[&str]) -> Self {
        Self::with_link_local_device(policy, local, None)
    }
    fn with_link_local_device(
        policy: Policy,
        local: &[&str],
        link_local_device: Option<&str>,
    ) -> Self {
        let specifications = [
            ("alpha", 1, 1),
            ("beta", 2, 2),
            ("gamma", 3, 2),
            ("isolated", 4, 1),
        ];
        let mut peers = Vec::new();
        let networks = specifications
            .iter()
            .map(|(net, server_key, subnet)| {
                let devices = [("first", 1), ("second", 2)]
                    .into_iter()
                    .map(|(name, host)| {
                        let key = 20 + server_key * 2 + host;
                        peers.push(RawPeer::new(
                            net,
                            name,
                            key,
                            *server_key,
                            40000 + u16::from(key),
                        ));
                        let addresses = if *net == "alpha" && link_local_device == Some(name) {
                            vec![
                                format!("169.254.0.{host}").parse::<IpAddr>().unwrap(),
                                format!("fe80::{host}").parse().unwrap(),
                            ]
                        } else {
                            vec![
                                format!("10.{subnet}.0.{host}").parse::<IpAddr>().unwrap(),
                                format!("fd00:{subnet}::{host}").parse().unwrap(),
                            ]
                        };
                        Device::new(device(name), public(key), addresses).unwrap()
                    })
                    .collect();
                Network::new(network(net), devices).unwrap()
            })
            .collect();
        let assignment = GatewayAssignment::new(
            node("gateway"),
            (public(9)).clone(),
            wgfeel_test_support::fixture_gateway_public(&(public(9))),
            specifications
                .iter()
                .map(|(net, _, _)| network(net))
                .collect(),
            specifications
                .iter()
                .filter(|(net, _, _)| local.contains(net))
                .map(|(net, key, _)| TenantKeyAssignment::new(network(net), public(*key)))
                .collect(),
        )
        .unwrap();
        let projection = ManagementConfig::new(
            node("management"),
            Config::new(17, networks, policy).unwrap(),
            vec![assignment],
        )
        .unwrap()
        .project_for(&node("gateway"))
        .unwrap();
        let keys: Vec<_> = specifications
            .iter()
            .filter(|(net, _, _)| local.contains(net))
            .map(|(net, key, _)| (network(net), TenantPrivateKey::new(seed(*key)).unwrap()))
            .collect();
        let gateway = Gateway::from_local_projection(
            &projection,
            &node("management"),
            &node("gateway"),
            &wgfeel_test_support::fixture_node_keys(seed(9)),
            keys.iter().map(|(net, key)| (net, key)),
            Limits {
                handshake_limit_per_ip: 100,
            },
        )
        .unwrap();
        Self { gateway, peers }
    }
    fn establish(&mut self, index: usize) {
        let peer = &mut self.peers[index];
        let initiation = peer.initiation();
        let response = self
            .gateway
            .receive_local_datagram(peer.address, &initiation)
            .unwrap()
            .unwrap();
        let response = encrypted(response, peer);
        let TunnResult::WriteToNetwork(confirmation) = peer.receive(server_address(), &response)
        else {
            panic!("expected authenticated handshake confirmation");
        };
        let confirmation: Packet = confirmation.into();
        assert!(
            self.gateway
                .receive_local_datagram(peer.address, confirmation.as_ref())
                .unwrap()
                .is_none()
        );
    }
    fn submit(
        &mut self,
        index: usize,
        packet: &[u8],
    ) -> Result<Option<DatagramEvent>, ForwardError> {
        let peer = &mut self.peers[index];
        let ciphertext = peer.encrypt(packet);
        self.gateway
            .receive_local_datagram(peer.address, &ciphertext)
    }
    fn forward(&mut self, source: usize, destination: usize, packet: &[u8]) {
        let before = self.gateway.projection().unwrap().to_json().unwrap();
        let event = self.submit(source, packet).unwrap().unwrap();
        let bytes = encrypted(event, &self.peers[destination]);
        self.peers[destination].assert_plaintext(server_address(), &bytes, &decremented(packet));
        assert_eq!(
            self.gateway.projection().unwrap().to_json().unwrap(),
            before
        );
    }
}

fn encrypted(event: DatagramEvent, destination_peer: &RawPeer) -> Vec<u8> {
    let DatagramEvent::Network {
        destination,
        context,
        peer,
        packet,
    } = event
    else {
        panic!("local forwarding must never expose authenticated plaintext");
    };
    assert_eq!(destination, destination_peer.address);
    assert_eq!(context, destination_peer.context);
    assert_eq!(peer.as_ref(), Some(&destination_peer.id));
    packet.as_bytes().to_vec()
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
fn repair_ipv4(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let value = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&value.to_be_bytes());
}
fn decremented(packet: &[u8]) -> Vec<u8> {
    let mut expected = packet.to_vec();
    if expected[0] >> 4 == 4 {
        expected[8] -= 1;
        repair_ipv4(&mut expected);
        assert_eq!(checksum(&expected[..20]), 0);
    } else {
        expected[7] -= 1;
    }
    expected
}
fn packet(v6: bool, source: &str, destination: &str, protocol: u8, hops: u8) -> Vec<u8> {
    let header = if v6 { 40 } else { 20 };
    let body = if protocol == 6 { 24 } else { 12 };
    let mut bytes = vec![0; header + body];
    if v6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(body as u16).to_be_bytes());
        bytes[6] = protocol;
        bytes[7] = hops;
        bytes[8..24].copy_from_slice(&source.parse::<Ipv6Addr>().unwrap().octets());
        bytes[24..40].copy_from_slice(&destination.parse::<Ipv6Addr>().unwrap().octets());
    } else {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&((header + body) as u16).to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = hops;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
        bytes[16..20].copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
        repair_ipv4(&mut bytes);
    }
    let transport = &mut bytes[header..];
    match protocol {
        6 => {
            transport[0..4].copy_from_slice(&[0x9c, 0x40, 0x1f, 0x90]);
            transport[12] = 0x50;
            transport[13] = 0x10;
        }
        17 => {
            transport[0..4].copy_from_slice(&[0x9c, 0x40, 0x1f, 0x90]);
            transport[4..6].copy_from_slice(&(body as u16).to_be_bytes());
        }
        1 => transport[0] = 8,
        58 => transport[0] = 128,
        _ => {}
    }
    transport[body - 4..].copy_from_slice(b"test");
    let checksum_offset = match protocol {
        6 => Some(16),
        17 => Some(6),
        1 | 58 => Some(2),
        _ => None,
    };
    if let Some(offset) = checksum_offset {
        let mut checked = Vec::new();
        if protocol != 1 {
            if v6 {
                checked.extend_from_slice(&bytes[8..40]);
                checked.extend_from_slice(&(body as u32).to_be_bytes());
                checked.extend_from_slice(&[0, 0, 0, protocol]);
            } else {
                checked.extend_from_slice(&bytes[12..20]);
                checked.extend_from_slice(&[0, protocol]);
                checked.extend_from_slice(&(body as u16).to_be_bytes());
            }
        }
        checked.extend_from_slice(&bytes[header..]);
        let value = checksum(&checked);
        let value = if protocol == 17 && value == 0 {
            0xffff
        } else {
            value
        };
        bytes[header + offset..header + offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}
fn udp(v6: bool, source: &str, destination: &str) -> Vec<u8> {
    packet(v6, source, destination, 17, 64)
}

#[test]
fn authenticated_ipv4_ipv6_tcp_udp_and_icmp_are_forwarded_with_one_hop_decrement() {
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.establish(1);
    for (v6, source, destination, protocols) in [
        (false, "10.1.0.1", "10.1.0.2", [6, 17, 1]),
        (true, "fd00:1::1", "fd00:1::2", [6, 17, 58]),
    ] {
        for protocol in protocols {
            fixture.forward(0, 1, &packet(v6, source, destination, protocol, 2));
            fixture.forward(1, 0, &packet(v6, destination, source, protocol, 64));
        }
    }
}

#[test]
fn overlapping_tenant_addresses_and_device_ids_keep_exact_authenticated_destination() {
    let mut rules = both_directions("alpha");
    rules.extend(both_directions("isolated"));
    let mut fixture = Fixture::new(Policy::new(vec![], rules, vec![]), &["alpha", "isolated"]);
    for index in [0, 1, 6, 7] {
        fixture.establish(index);
    }
    for (v6, source, destination) in [
        (false, "10.1.0.1", "10.1.0.2"),
        (true, "fd00:1::1", "fd00:1::2"),
    ] {
        let bytes = udp(v6, source, destination);
        fixture.forward(0, 1, &bytes);
        fixture.forward(6, 7, &bytes);
    }
}

#[test]
fn valid_wireguard_authentication_does_not_authorize_spoofed_inner_source() {
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.establish(1);
    for (v6, source, destination) in [
        (false, "10.1.0.2", "10.1.0.2"),
        (false, "10.2.0.1", "10.1.0.2"),
        (true, "fd00:1::2", "fd00:1::2"),
        (true, "fd00:2::1", "fd00:1::2"),
    ] {
        assert!(matches!(
            fixture.submit(0, &udp(v6, source, destination)),
            Err(ForwardError::SourceMismatch)
        ));
    }
    fixture.forward(0, 1, &udp(false, "10.1.0.1", "10.1.0.2"));
}

#[test]
fn default_local_and_global_denies_win_even_when_destination_has_live_session() {
    for policy in [
        Policy::new(vec![], vec![], vec![]),
        Policy::new(
            vec![],
            vec![
                allow("alpha", "first", "second"),
                Rule::new(
                    endpoint("alpha", "first"),
                    endpoint("alpha", "second"),
                    Action::Deny,
                ),
            ],
            vec![],
        ),
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "first"),
                endpoint("alpha", "second"),
                Action::Deny,
            )],
            vec![allow("alpha", "first", "second")],
            vec![],
        ),
    ] {
        let mut fixture = Fixture::new(policy, &["alpha"]);
        fixture.establish(0);
        fixture.establish(1);
        for (v6, source, destination) in [
            (false, "10.1.0.1", "10.1.0.2"),
            (true, "fd00:1::1", "fd00:1::2"),
        ] {
            assert!(matches!(
                fixture.submit(0, &udp(v6, source, destination)),
                Err(ForwardError::Denied)
            ));
        }
    }
}

#[test]
fn explicit_cross_tenant_grant_is_directional_and_global_deny_remains_mandatory() {
    let grant = Grant::new(endpoint("alpha", "first"), endpoint("beta", "first"));
    let mut fixture = Fixture::new(
        Policy::new(vec![], vec![], vec![grant.clone()]),
        &["alpha", "beta"],
    );
    fixture.establish(0);
    fixture.establish(2);
    for (v6, source, destination) in [
        (false, "10.1.0.1", "10.2.0.1"),
        (true, "fd00:1::1", "fd00:2::1"),
    ] {
        fixture.forward(0, 2, &udp(v6, source, destination));
        assert!(matches!(
            fixture.submit(2, &udp(v6, destination, source)),
            Err(ForwardError::UnknownDestination)
        ));
    }
    let mut denied = Fixture::new(
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "first"),
                endpoint("beta", "first"),
                Action::Deny,
            )],
            vec![],
            vec![grant],
        ),
        &["alpha", "beta"],
    );
    denied.establish(0);
    denied.establish(2);
    assert!(matches!(
        denied.submit(0, &udp(false, "10.1.0.1", "10.2.0.1")),
        Err(ForwardError::Denied)
    ));
}

#[test]
fn ambiguous_grants_and_known_but_unprovisioned_destinations_cannot_route() {
    let grants = vec![
        Grant::new(endpoint("alpha", "first"), endpoint("beta", "first")),
        Grant::new(endpoint("alpha", "first"), endpoint("gamma", "first")),
    ];
    let mut ambiguous = Fixture::new(
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "first"),
                endpoint("beta", "first"),
                Action::Deny,
            )],
            vec![],
            grants,
        ),
        &["alpha", "beta", "gamma"],
    );
    for index in [0, 2, 4] {
        ambiguous.establish(index);
    }
    for (v6, source, destination) in [
        (false, "10.1.0.1", "10.2.0.1"),
        (true, "fd00:1::1", "fd00:2::1"),
    ] {
        assert!(matches!(
            ambiguous.submit(0, &udp(v6, source, destination)),
            Err(ForwardError::AmbiguousDestination)
        ));
    }
    let mut remote = Fixture::new(
        Policy::new(
            vec![],
            vec![],
            vec![Grant::new(
                endpoint("alpha", "first"),
                endpoint("beta", "first"),
            )],
        ),
        &["alpha"],
    );
    remote.establish(0);
    assert!(matches!(
        remote.submit(0, &udp(false, "10.1.0.1", "10.2.0.1")),
        Err(ForwardError::NotLocal)
    ));
    assert!(matches!(
        remote.submit(0, &udp(false, "10.1.0.1", "203.0.113.10")),
        Err(ForwardError::UnknownDestination)
    ));
}

#[test]
fn expired_hops_and_bad_ipv4_checksum_never_reencrypt() {
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.establish(1);
    for hops in [0, 1] {
        for (v6, source, destination) in [
            (false, "10.1.0.1", "10.1.0.2"),
            (true, "fd00:1::1", "fd00:1::2"),
        ] {
            assert!(matches!(
                fixture.submit(0, &packet(v6, source, destination, 17, hops)),
                Err(ForwardError::HopLimitExceeded)
            ));
        }
    }
    let mut corrupt = udp(false, "10.1.0.1", "10.1.0.2");
    corrupt[10] ^= 1;
    assert!(matches!(
        fixture.submit(0, &corrupt),
        Err(ForwardError::InvalidPacket)
    ));
}

#[test]
fn fragments_options_extensions_and_unrecognized_protocols_fail_closed() {
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.establish(1);
    let mut unsupported = Vec::new();
    for fragment in [0x8000_u16, 0x2000, 1] {
        let mut bytes = udp(false, "10.1.0.1", "10.1.0.2");
        bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
        repair_ipv4(&mut bytes);
        unsupported.push(bytes);
    }
    let mut options = udp(false, "10.1.0.1", "10.1.0.2");
    options.splice(20..20, [1, 1, 0, 0]);
    options[0] = 0x46;
    let length = options.len() as u16;
    options[2..4].copy_from_slice(&length.to_be_bytes());
    options[10..12].fill(0);
    let check = checksum(&options[..24]);
    options[10..12].copy_from_slice(&check.to_be_bytes());
    unsupported.push(options);
    for protocol in [0, 43, 44, 50, 51, 60, 59, 253, 1] {
        unsupported.push(packet(true, "fd00:1::1", "fd00:1::2", protocol, 64));
    }
    for protocol in [253, 58] {
        unsupported.push(packet(false, "10.1.0.1", "10.1.0.2", protocol, 64));
    }
    for bytes in unsupported {
        assert!(matches!(
            fixture.submit(0, &bytes),
            Err(ForwardError::UnsupportedPacket)
        ));
    }
}

#[test]
fn malformed_transport_lengths_and_ip_lengths_fail_closed_after_authentication() {
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    fixture.establish(1);
    for v6 in [false, true] {
        let (source, destination, header) = if v6 {
            ("fd00:1::1", "fd00:1::2", 40)
        } else {
            ("10.1.0.1", "10.1.0.2", 20)
        };
        for protocol in [6, 17, if v6 { 58 } else { 1 }] {
            let mut short = packet(v6, source, destination, protocol, 64);
            short.truncate(header + if protocol == 6 { 19 } else { 7 });
            let length = short.len();
            if v6 {
                short[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
            } else {
                short[2..4].copy_from_slice(&(length as u16).to_be_bytes());
                repair_ipv4(&mut short);
            }
            assert!(matches!(
                fixture.submit(0, &short),
                Err(ForwardError::InvalidPacket)
            ));
        }
        let mut wrong_udp = udp(v6, source, destination);
        wrong_udp[header + 4..header + 6].copy_from_slice(&8_u16.to_be_bytes());
        assert!(matches!(
            fixture.submit(0, &wrong_udp),
            Err(ForwardError::InvalidPacket)
        ));
        for offset in [0x40, 0xf0] {
            let mut wrong_tcp = packet(v6, source, destination, 6, 64);
            wrong_tcp[header + 12] = offset;
            assert!(matches!(
                fixture.submit(0, &wrong_tcp),
                Err(ForwardError::InvalidPacket)
            ));
        }
        let mut wrong_ip = udp(v6, source, destination);
        if v6 {
            wrong_ip[4..6].copy_from_slice(&100_u16.to_be_bytes());
        } else {
            wrong_ip[2..4].copy_from_slice(&100_u16.to_be_bytes());
            repair_ipv4(&mut wrong_ip);
        }
        assert!(matches!(
            fixture.submit(0, &wrong_ip),
            Err(ForwardError::InvalidPacket
                | ForwardError::WireGuard(WireGuardError::InvalidPacket))
        ));
    }
}

#[test]
fn local_entry_requires_projection_and_does_not_queue_for_unestablished_destination() {
    let mut raw = Gateway::new(vec![], Limits::default()).unwrap();
    assert!(matches!(
        raw.receive_local_datagram(server_address(), b"not a packet"),
        Err(ForwardError::MissingProjection)
    ));
    let mut fixture = Fixture::new(
        Policy::new(vec![], both_directions("alpha"), vec![]),
        &["alpha"],
    );
    fixture.establish(0);
    assert!(matches!(
        fixture.submit(0, &udp(false, "10.1.0.1", "10.1.0.2")),
        Err(ForwardError::WireGuard(
            WireGuardError::NoEndpoint | WireGuardError::NoSession
        ))
    ));
    fixture.establish(1);
    fixture.forward(0, 1, &udp(false, "10.1.0.1", "10.1.0.2"));
}

#[test]
fn configured_link_local_source_or_destination_remains_outside_forwarding_scope() {
    for link_local_device in ["first", "second"] {
        let mut fixture = Fixture::with_link_local_device(
            Policy::new(vec![], both_directions("alpha"), vec![]),
            &["alpha"],
            Some(link_local_device),
        );
        fixture.establish(0);
        fixture.establish(1);
        for v6 in [false, true] {
            let (source, destination) = match (v6, link_local_device) {
                (false, "first") => ("169.254.0.1", "10.1.0.2"),
                (false, _) => ("10.1.0.1", "169.254.0.2"),
                (true, "first") => ("fe80::1", "fd00:1::2"),
                (true, _) => ("fd00:1::1", "fe80::2"),
            };
            assert!(matches!(
                fixture.submit(0, &udp(v6, source, destination)),
                Err(ForwardError::UnsupportedPacket)
            ));
        }
    }
}

fn poll_output(
    transport: &UdpTransport,
    gateway: &mut Gateway,
) -> Result<UdpEvent, TransportError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(event) = transport.poll_local(gateway)? {
            return Ok(event);
        }
        assert!(
            Instant::now() < deadline,
            "local UDP forwarding produced no result"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn udp_local_entry_emits_nothing_for_denied_payload_then_forwards_allowed_reply() {
    let mut fixture = Fixture::new(
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "first"),
                endpoint("alpha", "second"),
                Action::Deny,
            )],
            both_directions("alpha"),
            vec![],
        ),
        &["alpha"],
    );
    let transport = UdpTransport::from_socket(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
    let server = transport.local_addr().unwrap();
    let sockets = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    let mut buffer = [0; 2048];
    for (index, socket) in sockets.iter().enumerate() {
        socket
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let peer = &mut fixture.peers[index];
        peer.address = socket.local_addr().unwrap();
        socket.send_to(&peer.initiation(), server).unwrap();
        assert!(matches!(
            poll_output(&transport, &mut fixture.gateway).unwrap(),
            UdpEvent::Sent { .. }
        ));
        let (length, source) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(source, server);
        let TunnResult::WriteToNetwork(confirmation) = peer.receive(server, &buffer[..length])
        else {
            panic!("missing confirmation");
        };
        let confirmation: Packet = confirmation.into();
        socket.send_to(confirmation.as_ref(), server).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while fixture.gateway.endpoint(&peer.context, &peer.id).unwrap() != Some(peer.address) {
            assert!(
                transport
                    .poll_local(&mut fixture.gateway)
                    .unwrap()
                    .is_none()
            );
            assert!(Instant::now() < deadline);
        }
        // Drain the confirmation even when initiation already learned this endpoint.
        for _ in 0..4 {
            assert!(
                transport
                    .poll_local(&mut fixture.gateway)
                    .unwrap()
                    .is_none()
            );
        }
    }
    let denied = fixture.peers[0].encrypt(&udp(false, "10.1.0.1", "10.1.0.2"));
    sockets[0].send_to(&denied, server).unwrap();
    assert!(matches!(
        poll_output(&transport, &mut fixture.gateway),
        Err(TransportError::Forward(ForwardError::Denied))
    ));
    let error = sockets[1].recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    let allowed = udp(true, "fd00:1::2", "fd00:1::1");
    let wire = fixture.peers[1].encrypt(&allowed);
    sockets[1].send_to(&wire, server).unwrap();
    let UdpEvent::Sent {
        destination,
        context,
        peer,
    } = poll_output(&transport, &mut fixture.gateway).unwrap()
    else {
        panic!("local transport exposed plaintext");
    };
    assert_eq!(destination, sockets[0].local_addr().unwrap());
    assert_eq!(context, fixture.peers[0].context);
    assert_eq!(peer.as_ref(), Some(&fixture.peers[0].id));
    let (length, source) = sockets[0].recv_from(&mut buffer).unwrap();
    assert_eq!(source, server);
    fixture.peers[0].assert_plaintext(server, &buffer[..length], &decremented(&allowed));
}

fn discovery_fixture() -> Fixture {
    let mut peers = Vec::new();
    let devices = [
        ("sender", "10.203.0.2", true),
        ("one", "10.203.0.3", true),
        ("two", "10.203.0.4", true),
        ("denied", "10.203.0.5", true),
        ("silent", "10.203.0.6", false),
        ("custom", "10.4.0.7", true),
        ("ipv6", "fd77:77::8", true),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (name, ip, enabled))| {
        let key = 40 + i as u8;
        peers.push(RawPeer::new("lan", name, key, 1, 40000 + u16::from(key)));
        Device::new(device(name), public(key), vec![ip.parse().unwrap()])
            .unwrap()
            .with_broadcast(enabled.then_some(true))
    })
    .collect();
    let lan = network("lan");
    let net = Network::new(lan.clone(), devices)
        .unwrap()
        .with_private_lan(true)
        .with_broadcast(false);
    let acl = Policy::new(
        vec![Rule::new(
            endpoint("lan", "sender"),
            endpoint("lan", "denied"),
            Action::Deny,
        )],
        vec![],
        vec![],
    );
    let assignment = GatewayAssignment::new(
        node("entry"),
        public(9),
        wgfeel_test_support::fixture_gateway_public(&public(9)),
        vec![lan.clone()],
        vec![TenantKeyAssignment::new(lan.clone(), public(1))],
    )
    .unwrap();
    let projection = ManagementConfig::new(
        node("main"),
        Config::new(1, vec![net], acl).unwrap(),
        vec![assignment],
    )
    .unwrap()
    .project_for(&node("entry"))
    .unwrap();
    let gateway = Gateway::from_local_projection(
        &projection,
        &node("main"),
        &node("entry"),
        &wgfeel_test_support::fixture_node_keys(seed(9)),
        [(&lan, &TenantPrivateKey::new(seed(1)).unwrap())],
        Limits::default(),
    )
    .unwrap();
    Fixture { gateway, peers }
}
#[test]
fn directed_udp_preserves_one_hop_and_delivers_two_independently_checksummed_unicasts() {
    let mut f = discovery_fixture();
    for i in 0..f.peers.len() {
        f.establish(i);
    }
    let source = "10.203.0.2";
    let dst = "10.203.255.255";
    let request = packet(false, source, dst, 17, 1);
    let first = f.submit(0, &request).unwrap().unwrap();
    for (i, ip, event) in [
        (1, "10.203.0.3", first),
        (
            2,
            "10.203.0.4",
            f.gateway.drain_local_broadcast().unwrap().unwrap(),
        ),
    ] {
        let wire = encrypted(event, &f.peers[i]);
        f.peers[i].assert_plaintext(server_address(), &wire, &packet(false, source, ip, 17, 1));
    }
    assert!(f.gateway.drain_local_broadcast().unwrap().is_none());
    f.forward(1, 0, &udp(false, "10.203.0.3", source));
    for (i, ip) in [(4, "10.203.0.6"), (5, "10.4.0.7")] {
        assert!(f.submit(i, &packet(false, ip, dst, 17, 1)).is_err());
    }
    for (protocol, ttl) in [(6, 1), (1, 64), (2, 2), (17, 0)] {
        assert!(
            f.submit(0, &packet(false, source, dst, protocol, ttl))
                .is_err()
        );
    }
    assert!(
        f.submit(0, &packet(false, "10.203.0.3", dst, 17, 1))
            .is_err()
    );
    for (offset, value) in [
        (0, 0x46),
        (6, 0x20),
        (6, 0x80),
        (7, 1),
        (24, 1),
        (22, 0),
        (26, 42),
        (31, 0),
    ] {
        let mut damaged = request.clone();
        damaged[offset] = value;
        if offset == 22 {
            damaged[23] = 0;
        }
        repair_ipv4(&mut damaged);
        assert!(f.submit(0, &damaged).is_err(), "offset {offset}");
        assert!(f.gateway.drain_local_broadcast().unwrap().is_none());
    }
}

#[test]
fn broadcast_odd_payload_absent_checksum_zero_source_port_and_computed_zero() {
    let mut f = discovery_fixture();
    f.establish(0);
    f.establish(1);
    let mut bytes = packet(false, "10.203.0.2", "10.203.255.255", 17, 1);
    bytes.push(7);
    bytes[2..4].copy_from_slice(&33u16.to_be_bytes());
    bytes[20..22].fill(0);
    bytes[24..26].copy_from_slice(&13u16.to_be_bytes());
    bytes[26..28].fill(0);
    repair_ipv4(&mut bytes);
    let mut expected = bytes.clone();
    expected[16..20].copy_from_slice(&[10, 203, 0, 3]);
    repair_ipv4(&mut expected);
    let wire = encrypted(f.submit(0, &bytes).unwrap().unwrap(), &f.peers[1]);
    f.peers[1].assert_plaintext(server_address(), &wire, &expected);
    // Choose two payload bytes such that the target pseudo-header checksum is zero.
    fn udp_sum(p: &[u8]) -> u16 {
        let mut b = p[12..20].to_vec();
        b.extend_from_slice(&[0, 17, 0, 13]);
        b.extend_from_slice(&p[20..]);
        checksum(&b)
    }
    expected[28..30].fill(0);
    let fix = udp_sum(&expected).to_be_bytes();
    expected[28..30].copy_from_slice(&fix);
    assert_eq!(udp_sum(&expected), 0);
    bytes[28..30].copy_from_slice(&fix);
    let original = udp_sum(&bytes);
    assert_ne!(original, 0);
    bytes[26..28].copy_from_slice(&original.to_be_bytes());
    expected[26..28].fill(255);
    let wire = encrypted(f.submit(0, &bytes).unwrap().unwrap(), &f.peers[1]);
    f.peers[1].assert_plaintext(server_address(), &wire, &expected);
}
