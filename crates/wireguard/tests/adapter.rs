use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wgfeel_core::{
    DeviceId, DevicePublicKey, NetworkId, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use wgfeel_wireguard::{
    ContextConfig, ContextId, Event, Gateway, Limits, MAX_DATAGRAM_SIZE, MAX_DEVICE_PEERS,
    MAX_HANDSHAKE_SOURCES, MAX_PLAINTEXT_SIZE, MAX_SERVICE_PEERS, MAX_TENANTS, PeerConfig, PeerId,
    WireGuardError,
};

// Independent fixed vectors, RFC 7748 section 6.1:
// https://www.rfc-editor.org/rfc/rfc7748.txt
const ALICE_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_SECRET: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

fn hex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

fn seed(index: u16) -> [u8; 32] {
    let mut value = [42; 32];
    value[8..10].copy_from_slice(&index.to_be_bytes());
    value
}

fn fixture_public(secret: [u8; 32]) -> DevicePublicKey {
    // Fixture identity creation uses the reviewed primitive directly. The fixed
    // RFC vectors above independently check the adapter's public-key result.
    let secret = gotatun::x25519::StaticSecret::from(secret);
    DevicePublicKey::new(gotatun::x25519::PublicKey::from(&secret).to_bytes()).unwrap()
}

fn context(name: &str) -> ContextId {
    ContextId::Tenant(NetworkId::new(name).unwrap())
}
fn device(name: &str) -> PeerId {
    PeerId::Device(DeviceId::new(name).unwrap())
}
fn node(name: &str) -> PeerId {
    PeerId::Node(NodeId::new(name).unwrap())
}
fn peer(id: PeerId, public_key: DevicePublicKey) -> PeerConfig {
    PeerConfig { id, public_key }
}
fn tenant(name: &str, secret: [u8; 32], peers: Vec<PeerConfig>) -> ContextConfig {
    ContextConfig::tenant(
        NetworkId::new(name).unwrap(),
        TenantPrivateKey::new(secret).unwrap(),
        peers,
    )
}
fn system(secret: [u8; 32], peers: Vec<PeerConfig>) -> ContextConfig {
    ContextConfig::service(ServicePrivateKey::new(secret).unwrap(), peers)
}
fn address(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)), port)
}
fn server_address() -> SocketAddr {
    address(1, 51820)
}
fn client_address() -> SocketAddr {
    address(2, 40000)
}

fn pair(server_limits: Limits) -> (Gateway, Gateway) {
    let server = Gateway::new(
        vec![tenant(
            "alice",
            hex(ALICE_SECRET),
            vec![peer(
                device("client"),
                DevicePublicKey::new(hex(BOB_PUBLIC)).unwrap(),
            )],
        )],
        server_limits,
    )
    .unwrap();
    let client = Gateway::new(
        vec![tenant(
            "alice",
            hex(BOB_SECRET),
            vec![peer(
                device("server"),
                DevicePublicKey::new(hex(ALICE_PUBLIC)).unwrap(),
            )],
        )],
        Limits::default(),
    )
    .unwrap();
    (server, client)
}

fn network(event: Event, expected_context: &ContextId, expected_peer: &PeerId) -> Vec<u8> {
    match event {
        Event::Network {
            context,
            peer,
            packet,
        } => {
            assert_eq!(&context, expected_context);
            assert_eq!(&peer, expected_peer);
            assert!(packet.as_bytes().len() <= MAX_DATAGRAM_SIZE);
            packet.as_bytes().to_vec()
        }
        Event::Plaintext { .. } => panic!("expected encrypted network output"),
    }
}

fn plaintext(event: Event, expected_context: &ContextId, expected_peer: &PeerId, expected: &[u8]) {
    match event {
        Event::Plaintext {
            context,
            peer,
            packet,
        } => {
            assert_eq!(&context, expected_context);
            assert_eq!(&peer, expected_peer);
            assert_eq!(packet.as_bytes(), expected);
        }
        Event::Network { .. } => panic!("expected authenticated plaintext"),
    }
}

fn header(packet: &[u8], kind: u8, length: usize) {
    assert_eq!(packet.len(), length);
    assert_eq!(&packet[..4], &[kind, 0, 0, 0]);
}

fn establish(
    initiator: &mut Gateway,
    initiator_context: &ContextId,
    initiator_peer: &PeerId,
    responder: &mut Gateway,
    responder_context: &ContextId,
    responder_peer: &PeerId,
) {
    let initiation = network(
        initiator
            .initiate(initiator_context, initiator_peer)
            .unwrap()
            .unwrap(),
        initiator_context,
        initiator_peer,
    );
    header(&initiation, 1, 148);
    let response = network(
        responder
            .receive(
                responder_context,
                responder_peer,
                client_address(),
                &initiation,
            )
            .unwrap()
            .unwrap(),
        responder_context,
        responder_peer,
    );
    header(&response, 2, 92);
    let confirmation = network(
        initiator
            .receive(
                initiator_context,
                initiator_peer,
                server_address(),
                &response,
            )
            .unwrap()
            .unwrap(),
        initiator_context,
        initiator_peer,
    );
    header(&confirmation, 4, 32);
    assert!(
        responder
            .receive(
                responder_context,
                responder_peer,
                client_address(),
                &confirmation
            )
            .unwrap()
            .is_none()
    );
}

fn ipv4(payload_length: usize, options: bool) -> Vec<u8> {
    let header_length = if options { 24 } else { 20 };
    let mut packet = vec![0; header_length + payload_length];
    packet[0] = if options { 0x46 } else { 0x45 };
    let packet_length = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 253; // Experimental protocol: only IP framing is under test.
    packet[12..16].copy_from_slice(&[10, 20, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 20, 0, 3]);
    packet[header_length..].fill(0xab);
    let sum: u32 = packet[..header_length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !u16::try_from((sum & 0xffff) + (sum >> 16)).unwrap();
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn ipv6(payload_length: usize) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(payload_length).unwrap().to_be_bytes());
    packet[6] = 253;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&"fd20::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(&"fd20::3".parse::<std::net::Ipv6Addr>().unwrap().octets());
    packet[40..].fill(0xcd);
    packet
}

#[test]
fn public_keys_match_independent_rfc_7748_vectors() {
    let gateway = Gateway::new(
        vec![
            tenant("alice", hex(ALICE_SECRET), vec![]),
            system(hex(BOB_SECRET), vec![]),
        ],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        gateway.public_key(&context("alice")).unwrap().as_bytes(),
        &hex(ALICE_PUBLIC)
    );
    assert_eq!(
        gateway.public_key(&ContextId::Service).unwrap().as_bytes(),
        &hex(BOB_PUBLIC)
    );
    assert!(gateway.public_key(&context("missing")).is_none());
}

#[test]
fn clamping_equivalent_gateway_keys_cannot_define_distinct_contexts() {
    let mut equivalent = hex(ALICE_SECRET);
    equivalent[0] ^= 7;
    equivalent[31] ^= 0x80;
    assert_ne!(equivalent, hex(ALICE_SECRET));
    for second in [
        tenant("bob", equivalent, vec![]),
        system(equivalent, vec![]),
    ] {
        assert_eq!(
            Gateway::new(
                vec![tenant("alice", hex(ALICE_SECRET), vec![]), second],
                Limits::default()
            )
            .unwrap_err(),
            WireGuardError::DuplicateGatewayKey
        );
    }
}

#[test]
fn duplicate_contexts_and_wrong_peer_kinds_are_rejected() {
    for configs in [
        vec![
            tenant("alice", seed(1), vec![]),
            tenant("alice", seed(2), vec![]),
        ],
        vec![system(seed(1), vec![]), system(seed(2), vec![])],
    ] {
        assert_eq!(
            Gateway::new(configs, Limits::default()).unwrap_err(),
            WireGuardError::DuplicateContext
        );
    }
    for config in [
        tenant(
            "alice",
            seed(1),
            vec![peer(node("node"), fixture_public(seed(2)))],
        ),
        system(
            seed(1),
            vec![peer(device("device"), fixture_public(seed(2)))],
        ),
    ] {
        assert_eq!(
            Gateway::new(vec![config], Limits::default()).unwrap_err(),
            WireGuardError::InvalidConfiguration
        );
    }
}

#[test]
fn duplicate_peer_ids_or_keys_are_rejected_within_a_context() {
    for peers in [
        vec![
            peer(device("same"), fixture_public(seed(2))),
            peer(device("same"), fixture_public(seed(3))),
        ],
        vec![
            peer(device("one"), fixture_public(seed(2))),
            peer(device("two"), fixture_public(seed(2))),
        ],
    ] {
        assert_eq!(
            Gateway::new(vec![tenant("alice", seed(1), peers)], Limits::default()).unwrap_err(),
            WireGuardError::DuplicatePeer
        );
    }
}

#[test]
fn self_noncontributory_and_noncanonical_peer_keys_are_rejected() {
    let mut one = [0; 32];
    one[0] = 1;
    let mut alias = hex(BOB_PUBLIC);
    alias[31] |= 0x80;
    let mut prime = [255; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    for bytes in [hex(ALICE_PUBLIC), one, alias, prime] {
        let peer = peer(device("client"), DevicePublicKey::new(bytes).unwrap());
        assert_eq!(
            Gateway::new(
                vec![tenant("alice", hex(ALICE_SECRET), vec![peer])],
                Limits::default()
            )
            .unwrap_err(),
            WireGuardError::InvalidPeerKey
        );
    }
}

#[test]
fn context_peer_and_per_ip_settings_have_separate_fixed_bounds() {
    assert_eq!(
        (MAX_TENANTS, MAX_DEVICE_PEERS, MAX_SERVICE_PEERS),
        // 149 other nodes, one administrator, and all 32 pending invitations.
        (150, 750, 182)
    );
    assert_eq!(
        (MAX_PLAINTEXT_SIZE, MAX_DATAGRAM_SIZE, MAX_HANDSHAKE_SOURCES),
        (1280, 1312, 64)
    );
    assert_eq!(Limits::default().handshake_limit_per_ip, 10);
    Gateway::new(
        vec![],
        Limits {
            handshake_limit_per_ip: 0,
        },
    )
    .unwrap();
    Gateway::new(
        vec![],
        Limits {
            handshake_limit_per_ip: 1000,
        },
    )
    .unwrap();
    assert_eq!(
        Gateway::new(
            vec![],
            Limits {
                handshake_limit_per_ip: 1001
            }
        )
        .unwrap_err(),
        WireGuardError::InvalidConfiguration
    );
    let contexts = (0..=MAX_TENANTS)
        .map(|index| {
            tenant(
                &format!("tenant-{index}"),
                seed(u16::try_from(index).unwrap()),
                vec![],
            )
        })
        .collect();
    assert_eq!(
        Gateway::new(contexts, Limits::default()).unwrap_err(),
        WireGuardError::InvalidConfiguration
    );
    let peers = (0..=MAX_DEVICE_PEERS)
        .map(|index| {
            peer(
                device(&format!("peer-{index}")),
                fixture_public(seed(u16::try_from(index + 1000).unwrap())),
            )
        })
        .collect();
    assert_eq!(
        Gateway::new(vec![tenant("alice", seed(1), peers)], Limits::default()).unwrap_err(),
        WireGuardError::InvalidConfiguration
    );
    let mut peers: Vec<_> = (0..=MAX_SERVICE_PEERS)
        .map(|index| {
            peer(
                node(&format!("peer-{index}")),
                fixture_public(seed(u16::try_from(index + 1000).unwrap())),
            )
        })
        .collect();
    assert_eq!(
        Gateway::new(vec![system(seed(1), peers.clone())], Limits::default()).unwrap_err(),
        WireGuardError::InvalidConfiguration
    );
    peers.pop();
    Gateway::new(vec![system(seed(1), peers)], Limits::default()).unwrap();
}

#[test]
fn unknown_selectors_are_errors_and_send_without_session_never_queues() {
    let (mut server, _) = pair(Limits::default());
    assert_eq!(
        server
            .send(&context("missing"), &device("client"), &ipv4(4, false))
            .unwrap_err(),
        WireGuardError::UnknownContext
    );
    assert_eq!(
        server
            .initiate(&context("alice"), &device("missing"))
            .unwrap_err(),
        WireGuardError::UnknownPeer
    );
    assert_eq!(
        server
            .reset(&context("alice"), &device("missing"))
            .unwrap_err(),
        WireGuardError::UnknownPeer
    );
    for _ in 0..300 {
        assert_eq!(
            server
                .send(&context("alice"), &device("client"), &ipv4(4, false))
                .unwrap_err(),
            WireGuardError::NoSession
        );
    }
    assert!(
        server
            .tick(&context("alice"), &device("client"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn either_peer_can_initiate_and_ipv4_ipv6_and_options_round_trip_exactly() {
    for reverse in [false, true] {
        let (mut server, mut client) = pair(Limits::default());
        let context = context("alice");
        let server_peer = device("client");
        let client_peer = device("server");
        if reverse {
            establish(
                &mut server,
                &context,
                &server_peer,
                &mut client,
                &context,
                &client_peer,
            );
        } else {
            establish(
                &mut client,
                &context,
                &client_peer,
                &mut server,
                &context,
                &server_peer,
            );
        }
        for input in [
            ipv4(5, false),
            ipv4(7, true),
            ipv6(9),
            ipv6(MAX_PLAINTEXT_SIZE - 40),
        ] {
            let encrypted = network(
                client.send(&context, &client_peer, &input).unwrap(),
                &context,
                &client_peer,
            );
            header(&encrypted, 4, 32 + input.len().div_ceil(16) * 16);
            plaintext(
                server
                    .receive(&context, &server_peer, client_address(), &encrypted)
                    .unwrap()
                    .unwrap(),
                &context,
                &server_peer,
                &input,
            );
            let back = network(
                server.send(&context, &server_peer, &input).unwrap(),
                &context,
                &server_peer,
            );
            plaintext(
                client
                    .receive(&context, &client_peer, server_address(), &back)
                    .unwrap()
                    .unwrap(),
                &context,
                &client_peer,
                &input,
            );
        }
    }
}

#[test]
fn two_tenants_and_service_keep_overlapping_addresses_and_equal_device_names_separate() {
    let mut gateway = Gateway::new(
        vec![
            tenant(
                "alice",
                seed(1),
                vec![
                    peer(device("laptop"), fixture_public(seed(101))),
                    peer(device("phone"), fixture_public(seed(102))),
                ],
            ),
            tenant(
                "bob",
                seed(2),
                vec![
                    peer(device("laptop"), fixture_public(seed(103))),
                    peer(device("phone"), fixture_public(seed(104))),
                ],
            ),
            system(
                seed(3),
                vec![peer(node("gateway-b"), fixture_public(seed(105)))],
            ),
        ],
        Limits::default(),
    )
    .unwrap();
    let cases = [
        (context("alice"), device("laptop"), seed(1), seed(101)),
        (context("alice"), device("phone"), seed(1), seed(102)),
        (context("bob"), device("laptop"), seed(2), seed(103)),
        (context("bob"), device("phone"), seed(2), seed(104)),
        (ContextId::Service, node("gateway-b"), seed(3), seed(105)),
    ];
    let mut indices = std::collections::HashSet::new();
    for (context, gateway_peer, gateway_secret, client_secret) in cases {
        let remote_peer = if context == ContextId::Service {
            node("gateway-a")
        } else {
            device("gateway")
        };
        let remote_config = match &context {
            ContextId::Tenant(network) => tenant(
                network.as_str(),
                client_secret,
                vec![peer(remote_peer.clone(), fixture_public(gateway_secret))],
            ),
            ContextId::Gateway => ContextConfig::gateway(
                wgfeel_core::GatewayPrivateKey::new(client_secret).unwrap(),
                vec![peer(remote_peer.clone(), fixture_public(gateway_secret))],
            ),
            ContextId::Service => system(
                client_secret,
                vec![peer(remote_peer.clone(), fixture_public(gateway_secret))],
            ),
        };
        let mut remote = Gateway::new(vec![remote_config], Limits::default()).unwrap();
        // Gateway initiates so its shared-index ownership is visible in each handshake.
        let initiation = network(
            gateway.initiate(&context, &gateway_peer).unwrap().unwrap(),
            &context,
            &gateway_peer,
        );
        header(&initiation, 1, 148);
        assert!(indices.insert(u32::from_le_bytes(initiation[4..8].try_into().unwrap())));
        let response = network(
            remote
                .receive(&context, &remote_peer, server_address(), &initiation)
                .unwrap()
                .unwrap(),
            &context,
            &remote_peer,
        );
        let confirmation = network(
            gateway
                .receive(&context, &gateway_peer, client_address(), &response)
                .unwrap()
                .unwrap(),
            &context,
            &gateway_peer,
        );
        assert!(
            remote
                .receive(&context, &remote_peer, server_address(), &confirmation)
                .unwrap()
                .is_none()
        );
        for input in [ipv4(4, false), ipv6(4)] {
            let encrypted = network(
                remote.send(&context, &remote_peer, &input).unwrap(),
                &context,
                &remote_peer,
            );
            plaintext(
                gateway
                    .receive(&context, &gateway_peer, client_address(), &encrypted)
                    .unwrap()
                    .unwrap(),
                &context,
                &gateway_peer,
                &input,
            );
        }
    }
}

#[test]
fn wrong_context_wrong_peer_mac_index_and_ciphertext_never_yield_plaintext() {
    let mut gateway = Gateway::new(
        vec![
            tenant(
                "alice",
                hex(ALICE_SECRET),
                vec![
                    peer(
                        device("client"),
                        DevicePublicKey::new(hex(BOB_PUBLIC)).unwrap(),
                    ),
                    peer(device("other"), fixture_public(seed(3))),
                ],
            ),
            tenant(
                "bob",
                seed(2),
                vec![peer(
                    device("client"),
                    DevicePublicKey::new(hex(BOB_PUBLIC)).unwrap(),
                )],
            ),
        ],
        Limits::default(),
    )
    .unwrap();
    let (_, mut client) = pair(Limits::default());
    let context = context("alice");
    let client_peer = device("server");
    let server_peer = device("client");
    let initiation = network(
        client.initiate(&context, &client_peer).unwrap().unwrap(),
        &context,
        &client_peer,
    );
    let mut invalid_mac = initiation.clone();
    invalid_mac[116] ^= 1;
    assert!(
        gateway
            .receive(&context, &server_peer, client_address(), &invalid_mac)
            .is_err()
    );
    assert!(
        gateway
            .receive(
                &ContextId::Tenant(NetworkId::new("bob").unwrap()),
                &server_peer,
                client_address(),
                &initiation
            )
            .is_err()
    );
    assert!(
        gateway
            .receive(&context, &device("other"), client_address(), &initiation)
            .is_err()
    );
    let response = network(
        gateway
            .receive(&context, &server_peer, client_address(), &initiation)
            .unwrap()
            .unwrap(),
        &context,
        &server_peer,
    );
    let confirmation = network(
        client
            .receive(&context, &client_peer, server_address(), &response)
            .unwrap()
            .unwrap(),
        &context,
        &client_peer,
    );
    assert!(
        gateway
            .receive(&context, &server_peer, client_address(), &confirmation)
            .unwrap()
            .is_none()
    );
    let original = ipv4(4, false);
    let encrypted = network(
        client.send(&context, &client_peer, &original).unwrap(),
        &context,
        &client_peer,
    );
    let mut index = encrypted.clone();
    index[4] ^= 1;
    let mut corrupt = encrypted.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for packet in [index, corrupt] {
        assert!(
            gateway
                .receive(&context, &server_peer, client_address(), &packet)
                .is_err()
        );
    }
    assert!(
        gateway
            .receive(&context, &device("other"), client_address(), &encrypted)
            .is_err()
    );
    assert!(
        gateway
            .receive(
                &ContextId::Tenant(NetworkId::new("bob").unwrap()),
                &server_peer,
                client_address(),
                &encrypted,
            )
            .is_err()
    );
    plaintext(
        gateway
            .receive(&context, &server_peer, client_address(), &encrypted)
            .unwrap()
            .unwrap(),
        &context,
        &server_peer,
        &original,
    );
    assert!(
        gateway
            .receive(&context, &server_peer, client_address(), &encrypted)
            .is_err()
    );
}

#[test]
fn malformed_lengths_reserved_bytes_and_oversize_datagrams_are_rejected() {
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let peer = device("client");
    let valid = network(
        client
            .initiate(&context, &device("server"))
            .unwrap()
            .unwrap(),
        &context,
        &device("server"),
    );
    let mut cases = vec![vec![], vec![1], vec![5, 0, 0, 0], valid[..147].to_vec()];
    let mut long = valid.clone();
    long.push(0);
    cases.push(long);
    for byte in 1..4 {
        let mut reserved = valid.clone();
        reserved[byte] = 1;
        cases.push(reserved);
    }
    for (kind, length) in [(2, 91), (2, 93), (3, 63), (3, 65), (4, 31)] {
        let mut packet = vec![0; length];
        packet[0] = kind;
        cases.push(packet);
    }
    for packet in cases {
        assert_eq!(
            server
                .receive(&context, &peer, client_address(), &packet)
                .unwrap_err(),
            WireGuardError::InvalidPacket
        );
    }
    assert_eq!(
        server
            .receive(
                &context,
                &peer,
                client_address(),
                &vec![0; MAX_DATAGRAM_SIZE + 1]
            )
            .unwrap_err(),
        WireGuardError::PacketTooLarge
    );
}

#[test]
fn plaintext_framing_rejects_incomplete_headers_lengths_and_oversize() {
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    establish(
        &mut client,
        &context,
        &source,
        &mut server,
        &context,
        &destination,
    );
    let mut too_short_ihl = ipv4(4, false);
    too_short_ihl[0] = 0x44;
    let mut missing_options = ipv4(0, false);
    missing_options[0] = 0x46;
    let mut options_exceed_total = ipv4(4, true);
    options_exceed_total[2..4].copy_from_slice(&20_u16.to_be_bytes());
    let mut extra = ipv4(4, false);
    extra.push(0);
    let mut short_v6 = ipv6(4);
    short_v6.pop();
    for packet in [
        vec![],
        vec![0x45; 19],
        vec![0x60; 39],
        too_short_ihl,
        missing_options,
        options_exceed_total,
        extra,
        short_v6,
    ] {
        assert_eq!(
            client.send(&context, &source, &packet).unwrap_err(),
            WireGuardError::InvalidPacket
        );
    }
    assert_eq!(
        client
            .send(&context, &source, &ipv6(MAX_PLAINTEXT_SIZE - 40 + 1))
            .unwrap_err(),
        WireGuardError::PacketTooLarge
    );
}

#[test]
fn authenticated_inbound_ip_lengths_and_padding_are_checked_independently() {
    use gotatun::noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter};
    use gotatun::packet::Packet;
    use gotatun::x25519::{PublicKey, StaticSecret};
    use std::sync::Arc;

    let context = context("alice");
    let destination = device("client");
    let mut server = Gateway::new(
        vec![tenant(
            "alice",
            hex(ALICE_SECRET),
            vec![peer(
                destination.clone(),
                DevicePublicKey::new(hex(BOB_PUBLIC)).unwrap(),
            )],
        )],
        Limits::default(),
    )
    .unwrap();
    // Direct upstream encryption bypasses the adapter's outbound IP checks.
    // Expected IP lengths and padding below are hand-authored test inputs.
    let private = StaticSecret::from(hex(BOB_SECRET));
    let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&private), 10));
    let mut raw_peer = Tunn::new(
        private,
        PublicKey::from(hex(ALICE_PUBLIC)),
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::clone(&limiter),
    );
    let initiation = raw_peer
        .format_handshake_initiation(false)
        .unwrap()
        .into_bytes();
    let response = network(
        server
            .receive(
                &context,
                &destination,
                client_address(),
                initiation.as_ref(),
            )
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    let response = limiter
        .verify_packet(server_address(), Packet::copy_from(response.as_slice()))
        .unwrap();
    let confirmation: Packet = match raw_peer.handle_incoming_packet(response) {
        TunnResult::WriteToNetwork(packet) => packet.into(),
        _ => panic!("direct engine did not confirm the handshake"),
    };
    assert!(
        server
            .receive(
                &context,
                &destination,
                client_address(),
                confirmation.as_ref()
            )
            .unwrap()
            .is_none()
    );

    let mut missing_v4_payload = ipv4(4, false);
    missing_v4_payload[2..4].copy_from_slice(&100_u16.to_be_bytes());
    let mut options_exceed_total = ipv4(4, true);
    options_exceed_total[2..4].copy_from_slice(&20_u16.to_be_bytes());
    let mut missing_v6_payload = ipv6(4);
    missing_v6_payload[4..6].copy_from_slice(&100_u16.to_be_bytes());
    let mut padding_16 = ipv4(4, false);
    padding_16.extend_from_slice(&[0; 16]);
    for invalid in [
        vec![0x45; 19],
        vec![0x60; 39],
        missing_v4_payload,
        options_exceed_total,
        missing_v6_payload,
        padding_16,
    ] {
        let encrypted = raw_peer
            .encapsulate_with_session(Packet::copy_from(invalid.as_slice()))
            .unwrap()
            .into_bytes();
        assert_eq!(
            server
                .receive(&context, &destination, client_address(), encrypted.as_ref())
                .unwrap_err(),
            WireGuardError::InvalidPacket,
        );
    }

    for original in [ipv4(0, false), ipv4(9, true), ipv6(1)] {
        let mut padded = original.clone();
        // The IPv4-options packet is 33 bytes, exercising the exact 15-byte
        // padding boundary. Incoming padding need not contain zero bytes.
        padded.resize(original.len().next_multiple_of(16), 0xa5);
        let encrypted = raw_peer
            .encapsulate_with_session(Packet::copy_from(padded.as_slice()))
            .unwrap()
            .into_bytes();
        plaintext(
            server
                .receive(&context, &destination, client_address(), encrypted.as_ref())
                .unwrap()
                .unwrap(),
            &context,
            &destination,
            &original,
        );
    }
}

#[test]
fn reset_retires_sessions_and_stale_transport_cannot_recreate_them() {
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    establish(
        &mut client,
        &context,
        &source,
        &mut server,
        &context,
        &destination,
    );
    let input = ipv4(4, false);
    let stale = network(
        client.send(&context, &source, &input).unwrap(),
        &context,
        &source,
    );
    server.reset(&context, &destination).unwrap();
    assert!(
        server
            .receive(&context, &destination, client_address(), &stale)
            .is_err()
    );
    assert_eq!(
        server.send(&context, &destination, &input).unwrap_err(),
        WireGuardError::NoSession
    );
    client.reset(&context, &source).unwrap();
    establish(
        &mut client,
        &context,
        &source,
        &mut server,
        &context,
        &destination,
    );
    let fresh = network(
        client.send(&context, &source, &input).unwrap(),
        &context,
        &source,
    );
    plaintext(
        server
            .receive(&context, &destination, client_address(), &fresh)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
        &input,
    );
}

#[test]
fn authenticated_transport_accepts_new_outer_endpoint_without_changing_identity() {
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    establish(
        &mut client,
        &context,
        &source,
        &mut server,
        &context,
        &destination,
    );
    let input = ipv6(4);
    let encrypted = network(
        client.send(&context, &source, &input).unwrap(),
        &context,
        &source,
    );
    plaintext(
        server
            .receive(&context, &destination, address(200, 54321), &encrypted)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
        &input,
    );
}

#[test]
fn invalid_macs_do_not_consume_the_distinct_handshake_source_budget() {
    let started = Instant::now();
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    let initiation = network(
        client.initiate(&context, &source).unwrap().unwrap(),
        &context,
        &source,
    );
    let mut invalid = initiation.clone();
    invalid[116] ^= 1;
    for host in 1..=MAX_HANDSHAKE_SOURCES {
        assert!(
            server
                .receive(
                    &context,
                    &destination,
                    address(u8::try_from(host).unwrap(), 40000),
                    &invalid
                )
                .is_err()
        );
    }
    let response = network(
        server
            .receive(&context, &destination, address(250, 40000), &initiation)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    assert_source_window(started);
    header(&response, 2, 92);
}

fn assert_source_window(started: Instant) {
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "source-budget fixture exceeded the one-second admission window"
    );
}

#[test]
fn authenticated_mac_sources_are_bounded_even_when_handshake_authentication_fails_later() {
    let started = Instant::now();
    let (mut server, mut client) = pair(Limits::default());
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    let initiation = network(
        client.initiate(&context, &source).unwrap().unwrap(),
        &context,
        &source,
    );
    let response = network(
        server
            .receive(&context, &destination, address(1, 40000), &initiation)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    header(&response, 2, 92);
    for host in 2..=MAX_HANDSHAKE_SOURCES {
        let result = server.receive(
            &context,
            &destination,
            address(u8::try_from(host).unwrap(), 40000),
            &initiation,
        );
        assert_eq!(result.unwrap_err(), WireGuardError::Protocol);
    }
    let exhausted = server.receive(&context, &destination, address(250, 40000), &initiation);
    assert_source_window(started);
    assert_eq!(exhausted.unwrap_err(), WireGuardError::SourceLimit);

    // The source budget gates handshakes, not authenticated transport.
    let confirmation = network(
        client
            .receive(&context, &source, server_address(), &response)
            .unwrap()
            .unwrap(),
        &context,
        &source,
    );
    assert!(
        server
            .receive(&context, &destination, address(250, 40000), &confirmation)
            .unwrap()
            .is_none()
    );
    let input = ipv4(4, false);
    let encrypted = network(
        client.send(&context, &source, &input).unwrap(),
        &context,
        &source,
    );
    plaintext(
        server
            .receive(&context, &destination, address(250, 40000), &encrypted)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
        &input,
    );
    server.reset(&context, &destination).unwrap();
    let after_reset = server.receive(&context, &destination, address(250, 40000), &initiation);
    assert_source_window(started);
    assert_eq!(after_reset.unwrap_err(), WireGuardError::SourceLimit);
}

#[test]
fn distinct_handshake_source_budget_renews_after_its_window() {
    let started = Instant::now();
    let (mut server, mut client) = pair(Limits {
        handshake_limit_per_ip: 0,
    });
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    let initiation = network(
        client.initiate(&context, &source).unwrap().unwrap(),
        &context,
        &source,
    );
    for host in 1..=MAX_HANDSHAKE_SOURCES {
        let challenge = network(
            server
                .receive(
                    &context,
                    &destination,
                    address(u8::try_from(host).unwrap(), 40000),
                    &initiation,
                )
                .unwrap()
                .unwrap(),
            &context,
            &destination,
        );
        header(&challenge, 3, 64);
    }
    let exhausted = server.receive(&context, &destination, address(250, 40000), &initiation);
    assert_source_window(started);
    assert_eq!(exhausted.unwrap_err(), WireGuardError::SourceLimit);
    // Upstream uses a real clock. This is a bounded actual-time check, not a
    // claim that ManualClock controls cryptographic engine timers.
    std::thread::sleep(Duration::from_millis(1100));
    let renewed = network(
        server
            .receive(&context, &destination, address(250, 40000), &initiation)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    header(&renewed, 3, 64);
}

#[test]
fn cookie_challenge_uses_real_timer_retry_and_binds_the_source_socket() {
    let started = Instant::now();
    let (mut server, mut client) = pair(Limits {
        handshake_limit_per_ip: 0,
    });
    let context = context("alice");
    let source = device("server");
    let destination = device("client");
    let initiation = network(
        client.initiate(&context, &source).unwrap().unwrap(),
        &context,
        &source,
    );
    let cookie = network(
        server
            .receive(&context, &destination, client_address(), &initiation)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    header(&cookie, 3, 64);

    // Challenges consume the same per-context distinct-source budget.
    for host in 1..=MAX_HANDSHAKE_SOURCES {
        if host == 2 {
            continue; // client_address already occupied this source slot.
        }
        let challenge = network(
            server
                .receive(
                    &context,
                    &destination,
                    address(u8::try_from(host).unwrap(), 40000),
                    &initiation,
                )
                .unwrap()
                .unwrap(),
            &context,
            &destination,
        );
        header(&challenge, 3, 64);
    }
    let exhausted = server.receive(&context, &destination, address(250, 40000), &initiation);
    assert_source_window(started);
    assert_eq!(exhausted.unwrap_err(), WireGuardError::SourceLimit);

    // Fill the client's admission budget using MAC-valid initiations from an
    // unconfigured static key. They cannot authenticate as its configured peer.
    let mut outsider = Gateway::new(
        vec![tenant(
            "alice",
            seed(500),
            vec![peer(
                device("client"),
                DevicePublicKey::new(hex(BOB_PUBLIC)).unwrap(),
            )],
        )],
        Limits::default(),
    )
    .unwrap();
    let unconfigured = network(
        outsider.initiate(&context, &destination).unwrap().unwrap(),
        &context,
        &destination,
    );
    for host in 1..=MAX_HANDSHAKE_SOURCES {
        assert_eq!(
            client
                .receive(
                    &context,
                    &source,
                    address(u8::try_from(host).unwrap(), 51820),
                    &unconfigured,
                )
                .unwrap_err(),
            WireGuardError::Protocol,
        );
    }
    let exhausted = client.receive(&context, &source, address(250, 51820), &unconfigured);
    assert_source_window(started);
    assert_eq!(exhausted.unwrap_err(), WireGuardError::SourceLimit);
    assert!(
        client
            .receive(&context, &source, address(250, 51820), &cookie)
            .unwrap()
            .is_none()
    );
    assert_source_window(started);
    let deadline = Instant::now() + Duration::from_secs(8);
    let retry = loop {
        if let Some(event) = client.tick(&context, &source).unwrap() {
            break network(event, &context, &source);
        }
        assert!(
            Instant::now() < deadline,
            "upstream timer did not retry the cookie handshake"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    header(&retry, 1, 148);
    let changed_port = SocketAddr::new(client_address().ip(), client_address().port() + 1);
    let rechallenge = network(
        server
            .receive(&context, &destination, changed_port, &retry)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    header(&rechallenge, 3, 64);
    let response = network(
        server
            .receive(&context, &destination, client_address(), &retry)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
    );
    header(&response, 2, 92);
    let confirmation = network(
        client
            .receive(&context, &source, server_address(), &response)
            .unwrap()
            .unwrap(),
        &context,
        &source,
    );
    assert!(
        server
            .receive(&context, &destination, client_address(), &confirmation)
            .unwrap()
            .is_none()
    );
    let input = ipv4(4, false);
    let encrypted = network(
        client.send(&context, &source, &input).unwrap(),
        &context,
        &source,
    );
    plaintext(
        server
            .receive(&context, &destination, client_address(), &encrypted)
            .unwrap()
            .unwrap(),
        &context,
        &destination,
        &input,
    );
}

#[test]
fn debug_and_errors_redact_private_keys_and_packet_contents() {
    let secret = seed(77);
    let config = tenant(
        "alice",
        secret,
        vec![peer(device("client"), fixture_public(seed(78)))],
    );
    assert!(!format!("{config:?}").contains(&format!("{secret:?}")));
    let mut gateway = Gateway::new(vec![config], Limits::default()).unwrap();
    assert!(!format!("{gateway:?}").contains(&format!("{secret:?}")));
    let event = gateway
        .initiate(&context("alice"), &device("client"))
        .unwrap()
        .unwrap();
    if let Event::Network { packet, .. } = &event {
        assert!(!format!("{packet:?}").contains(&format!("{:?}", packet.as_bytes())));
        assert!(!format!("{event:?}").contains(&format!("{:?}", packet.as_bytes())));
    } else {
        panic!("expected initiation");
    }
    let error = WireGuardError::Protocol;
    let error: &dyn std::error::Error = &error;
    assert!(!error.to_string().is_empty());
    assert!(error.source().is_none());
}
