use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gotatun::noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use wgfeel_core::{
    DeviceId, DevicePublicKey, NetworkId, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Gateway, Limits, MAX_DATAGRAM_SIZE,
    MAX_HANDSHAKE_SOURCES, PeerConfig, PeerId, TransportError, UdpEvent, UdpTransport,
    WireGuardError,
};

fn seed(number: u16) -> [u8; 32] {
    let mut bytes = [43; 32];
    bytes[8..10].copy_from_slice(&number.to_be_bytes());
    bytes
}

fn public(number: u16) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(seed(number))).to_bytes()
}

fn tenant(name: &str) -> ContextId {
    ContextId::Tenant(NetworkId::new(name).unwrap())
}

fn device(name: &str) -> PeerId {
    PeerId::Device(DeviceId::new(name).unwrap())
}

fn address(host: u8, port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(198, 51, 100, host), port))
}

fn server_address() -> SocketAddr {
    address(1, 51820)
}

enum RawOutput {
    Network(Vec<u8>),
    Plaintext(Vec<u8>),
    None,
}

struct RawPeer {
    context: ContextId,
    id: PeerId,
    address: SocketAddr,
    public: [u8; 32],
    engine: Tunn,
    limiter: Arc<RateLimiter>,
}

impl RawPeer {
    fn new(
        context: ContextId,
        id: PeerId,
        key: u16,
        server_key: u16,
        address: SocketAddr,
        limit: u64,
    ) -> Self {
        let private = StaticSecret::from(seed(key));
        let public = PublicKey::from(&private);
        let limiter = Arc::new(RateLimiter::new(&public, limit));
        let engine = Tunn::new(
            private,
            PublicKey::from(self::public(server_key)),
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::clone(&limiter),
        );
        Self {
            context,
            id,
            address,
            public: public.to_bytes(),
            engine,
            limiter,
        }
    }

    fn config(&self) -> PeerConfig {
        PeerConfig {
            id: self.id.clone(),
            public_key: DevicePublicKey::new(self.public).unwrap(),
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

    fn receive(&mut self, source: SocketAddr, bytes: &[u8]) -> RawOutput {
        self.limiter.try_reset_count();
        let result = match self.limiter.verify_packet(source, Packet::copy_from(bytes)) {
            Ok(packet) => self.engine.handle_incoming_packet(packet),
            Err(result) => result,
        };
        match result {
            TunnResult::Done => RawOutput::None,
            TunnResult::WriteToNetwork(packet) => {
                let packet: Packet = packet.into();
                RawOutput::Network(packet.as_ref().to_vec())
            }
            TunnResult::WriteToTunnel(packet) => RawOutput::Plaintext(packet.as_ref().to_vec()),
            TunnResult::Err(_) => panic!("direct engine rejected a fixture packet"),
        }
    }

    fn encrypt(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.engine
            .encapsulate_with_session(Packet::copy_from(bytes))
            .unwrap()
            .into_bytes()
            .as_ref()
            .to_vec()
    }

    fn retry(&mut self) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(packet) = self.engine.update_timers().unwrap() {
                let packet: Packet = packet.into();
                return packet.as_ref().to_vec();
            }
            assert!(
                Instant::now() < deadline,
                "upstream handshake retry did not occur"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn context_config(context: &ContextId, key: u16, peers: Vec<PeerConfig>) -> ContextConfig {
    match context {
        ContextId::External(_) => unreachable!("public listener fixture"),
        ContextId::Tenant(id) => {
            ContextConfig::tenant(id.clone(), TenantPrivateKey::new(seed(key)).unwrap(), peers)
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

fn pair(limits: Limits, raw_limit: u64) -> (Gateway, RawPeer) {
    let peer = RawPeer::new(
        tenant("alice"),
        device("client"),
        11,
        1,
        address(2, 40000),
        raw_limit,
    );
    let gateway = Gateway::new(
        vec![context_config(&peer.context, 1, vec![peer.config()])],
        limits,
    )
    .unwrap();
    (gateway, peer)
}

#[test]
fn temporary_service_peers_can_be_added_and_revoked_without_resetting_admin_session() {
    let mut admin = RawPeer::new(
        ContextId::Service,
        PeerId::Node(NodeId::new("admin").unwrap()),
        11,
        1,
        address(2, 40000),
        100,
    );
    let mut invite = RawPeer::new(
        ContextId::Service,
        PeerId::Node(NodeId::new("invite").unwrap()),
        12,
        1,
        address(3, 40000),
        100,
    );
    let mut gateway = Gateway::new(
        vec![context_config(&ContextId::Service, 1, vec![admin.config()])],
        Limits::default(),
    )
    .unwrap();
    connect_from_peer(&mut gateway, &mut admin);
    gateway
        .set_service_peers(vec![invite.config(), admin.config()])
        .unwrap();
    // Reordering the peer list must not attach an existing receiver index to
    // the newly added capability, and must not require an admin re-handshake.
    let bytes = ipv4(2);
    plaintext(
        gateway
            .receive_datagram(admin.address, &admin.encrypt(&bytes))
            .unwrap()
            .unwrap(),
        &admin,
        &bytes,
    );
    connect_from_peer(&mut gateway, &mut invite);
    plaintext(
        gateway
            .receive_datagram(invite.address, &invite.encrypt(&bytes))
            .unwrap()
            .unwrap(),
        &invite,
        &bytes,
    );
    assert!(
        gateway
            .set_service_peers(vec![admin.config(), admin.config()])
            .is_err()
    );
    plaintext(
        gateway
            .receive_datagram(admin.address, &admin.encrypt(&bytes))
            .unwrap()
            .unwrap(),
        &admin,
        &bytes,
    );
    gateway.set_service_peers(vec![admin.config()]).unwrap();
    assert!(
        gateway
            .receive_datagram(invite.address, &invite.encrypt(&bytes))
            .is_err()
    );
    plaintext(
        gateway
            .receive_datagram(admin.address, &admin.encrypt(&bytes))
            .unwrap()
            .unwrap(),
        &admin,
        &bytes,
    );
}

fn multiple_contexts(limits: Limits) -> (Gateway, Vec<RawPeer>) {
    let peers = vec![
        RawPeer::new(
            tenant("alice"),
            device("first"),
            11,
            1,
            address(2, 40000),
            10,
        ),
        RawPeer::new(
            tenant("alice"),
            device("second"),
            12,
            1,
            address(2, 40001),
            10,
        ),
        RawPeer::new(tenant("bob"), device("first"), 13, 2, address(2, 40002), 10),
        RawPeer::new(
            tenant("bob"),
            device("second"),
            14,
            2,
            address(2, 40003),
            10,
        ),
        RawPeer::new(
            ContextId::Service,
            PeerId::Node(NodeId::new("node-one").unwrap()),
            15,
            3,
            address(3, 40000),
            10,
        ),
        RawPeer::new(
            ContextId::Gateway,
            PeerId::Node(NodeId::new("node-one").unwrap()),
            16,
            4,
            address(3, 40001),
            10,
        ),
    ];
    let gateway = Gateway::new(
        vec![
            context_config(
                &tenant("alice"),
                1,
                peers[..2].iter().map(RawPeer::config).collect(),
            ),
            context_config(
                &tenant("bob"),
                2,
                peers[2..4].iter().map(RawPeer::config).collect(),
            ),
            context_config(
                &ContextId::Service,
                3,
                peers[4..5].iter().map(RawPeer::config).collect(),
            ),
            context_config(&ContextId::Gateway, 4, vec![peers[5].config()]),
        ],
        limits,
    )
    .unwrap();
    (gateway, peers)
}

fn network(
    event: DatagramEvent,
    context: &ContextId,
    peer: Option<&PeerId>,
    destination: SocketAddr,
) -> Vec<u8> {
    match event {
        DatagramEvent::Network {
            destination: actual,
            context: owner,
            peer: identity,
            packet,
        } => {
            assert_eq!(actual, destination);
            assert_eq!(&owner, context);
            assert_eq!(identity.as_ref(), peer);
            assert!(packet.as_bytes().len() <= MAX_DATAGRAM_SIZE);
            packet.as_bytes().to_vec()
        }
        DatagramEvent::Plaintext { .. } => panic!("expected encrypted network event"),
    }
}

fn plaintext(event: DatagramEvent, peer: &RawPeer, expected: &[u8]) {
    match event {
        DatagramEvent::Plaintext {
            context,
            peer: identity,
            packet,
        } => {
            assert_eq!(context, peer.context);
            assert_eq!(identity, peer.id);
            assert_eq!(packet.as_bytes(), expected);
        }
        DatagramEvent::Network { .. } => panic!("expected authenticated plaintext"),
    }
}

fn raw_network(output: RawOutput) -> Vec<u8> {
    match output {
        RawOutput::Network(bytes) => bytes,
        _ => panic!("expected direct-engine network packet"),
    }
}

fn header(bytes: &[u8], kind: u8, length: usize) {
    assert_eq!(bytes.len(), length);
    assert_eq!(&bytes[..4], &[kind, 0, 0, 0]);
}

fn connect_from_peer(gateway: &mut Gateway, peer: &mut RawPeer) -> u32 {
    let initiation = peer.initiate();
    let response = network(
        gateway
            .receive_datagram(peer.address, &initiation)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    header(&response, 2, 92);
    let local_index = u32::from_le_bytes(response[4..8].try_into().unwrap());
    let confirmation = raw_network(peer.receive(server_address(), &response));
    header(&confirmation, 4, 32);
    assert!(
        gateway
            .receive_datagram(peer.address, &confirmation)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    local_index
}

fn finish_gateway_handshake(gateway: &mut Gateway, peer: &mut RawPeer, initiation: &[u8]) {
    let response = raw_network(peer.receive(server_address(), initiation));
    header(&response, 2, 92);
    let confirmation = network(
        gateway
            .receive_datagram(peer.address, &response)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    header(&confirmation, 4, 32);
    match peer.receive(server_address(), &confirmation) {
        RawOutput::Plaintext(bytes) => assert!(bytes.is_empty()),
        RawOutput::None => {}
        RawOutput::Network(_) => panic!("key confirmation unexpectedly emitted network traffic"),
    }
}

fn ipv4(host: u8) -> Vec<u8> {
    // Independent complete IPv4 packet, experimental next protocol, no L4 claim.
    let mut bytes = vec![0; 25];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&25_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 253;
    bytes[12..16].copy_from_slice(&[10, 40, 0, host]);
    bytes[16..20].copy_from_slice(&[10, 40, 0, 99]);
    bytes[20..].copy_from_slice(b"HELLO");
    let sum: u32 = bytes[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !u16::try_from((sum & 0xffff) + (sum >> 16)).unwrap();
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn ipv6(host: u8) -> Vec<u8> {
    let mut bytes = vec![0; 45];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&5_u16.to_be_bytes());
    bytes[6] = 253;
    bytes[7] = 64;
    bytes[8] = 0xfd;
    bytes[9] = 40;
    bytes[23] = host;
    bytes[24] = 0xfd;
    bytes[25] = 40;
    bytes[39] = 99;
    bytes[40..].copy_from_slice(b"HELLO");
    bytes
}

#[test]
fn incoming_datagrams_discover_two_tenants_service_and_gateway_without_selectors() {
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    for peer in &mut peers {
        connect_from_peer(&mut gateway, peer);
    }
    for (number, peer) in peers.iter_mut().enumerate() {
        // Corresponding devices in both tenants have exactly the same inner IPs.
        let host = u8::try_from(number % 2 + 1).unwrap();
        for input in [ipv4(host), ipv6(host)] {
            let encrypted = peer.encrypt(&input);
            plaintext(
                gateway
                    .receive_datagram(peer.address, &encrypted)
                    .unwrap()
                    .unwrap(),
                peer,
                &input,
            );
            let response = network(
                gateway
                    .send_datagram(&peer.context, &peer.id, &input)
                    .unwrap(),
                &peer.context,
                Some(&peer.id),
                peer.address,
            );
            match peer.receive(server_address(), &response) {
                RawOutput::Plaintext(bytes) => {
                    assert_eq!(&bytes[..input.len()], input.as_slice());
                    assert!(bytes.len() - input.len() <= 15);
                    assert!(bytes[input.len()..].iter().all(|byte| *byte == 0));
                }
                _ => panic!("direct peer did not decrypt the response"),
            }
        }
    }
}

#[test]
fn gateway_initiation_publishes_indices_before_immediate_responses() {
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    for peer in &mut peers {
        let initiation = network(
            gateway
                .initiate_at(&peer.context, &peer.id, peer.address)
                .unwrap()
                .unwrap(),
            &peer.context,
            Some(&peer.id),
            peer.address,
        );
        header(&initiation, 1, 148);
        finish_gateway_handshake(&mut gateway, peer, &initiation);
        let input = ipv6(1);
        let encrypted = peer.encrypt(&input);
        plaintext(
            gateway
                .receive_datagram(peer.address, &encrypted)
                .unwrap()
                .unwrap(),
            peer,
            &input,
        );
    }
}

#[test]
fn same_node_cannot_move_authenticated_packets_between_service_and_gateway_contexts() {
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    let service_index = connect_from_peer(&mut gateway, &mut peers[4]);
    let gateway_index = connect_from_peer(&mut gateway, &mut peers[5]);
    assert_ne!(service_index, gateway_index);
    assert_eq!(peers[4].id, peers[5].id);
    for (source, other_index) in [(4, gateway_index), (5, service_index)] {
        let bytes = ipv4(1);
        let encrypted = peers[source].encrypt(&bytes);
        let mut misdirected = encrypted.clone();
        misdirected[4..8].copy_from_slice(&other_index.to_le_bytes());
        assert!(
            gateway
                .receive_datagram(peers[source].address, &misdirected)
                .is_err()
        );
        plaintext(
            gateway
                .receive_datagram(peers[source].address, &encrypted)
                .unwrap()
                .unwrap(),
            &peers[source],
            &bytes,
        );
    }
    // Knowing the service private key and gateway public key does not grant
    // membership in the gateway context, even with the same configured node ID.
    let mut wrong_role = RawPeer::new(
        ContextId::Gateway,
        peers[4].id.clone(),
        15,
        4,
        address(3, 40002),
        10,
    );
    assert!(
        gateway
            .receive_datagram(wrong_role.address, &wrong_role.initiate())
            .is_err()
    );
}

#[test]
fn endpoint_validation_and_trusted_bootstrap_are_explicit_and_atomic() {
    let (mut gateway, peer) = pair(Limits::default(), 10);
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    assert_eq!(
        gateway
            .send_datagram(&peer.context, &peer.id, &ipv4(1))
            .unwrap_err(),
        WireGuardError::NoEndpoint
    );
    assert_eq!(
        gateway.tick_datagram(&peer.context, &peer.id).unwrap_err(),
        WireGuardError::NoEndpoint
    );
    let invalid: Vec<SocketAddr> = [
        "198.51.100.2:0",
        "0.0.0.0:51820",
        "224.0.0.1:51820",
        "255.255.255.255:51820",
        "[::]:51820",
        "[ff02::1]:51820",
        "[::ffff:0.0.0.0]:51820",
        "[::ffff:224.0.0.1]:51820",
        "[::ffff:255.255.255.255]:51820",
    ]
    .into_iter()
    .map(|value| value.parse().unwrap())
    .collect();
    for address in &invalid {
        assert_eq!(
            gateway
                .initiate_at(&peer.context, &peer.id, *address)
                .unwrap_err(),
            WireGuardError::InvalidConfiguration
        );
        assert_eq!(
            gateway
                .receive_datagram(*address, &[1, 0, 0, 0])
                .unwrap_err(),
            WireGuardError::InvalidConfiguration
        );
        assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    }
    gateway
        .initiate_at(&peer.context, &peer.id, peer.address)
        .unwrap()
        .unwrap();
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    assert_eq!(
        gateway
            .send_datagram(&peer.context, &peer.id, &ipv4(1))
            .unwrap_err(),
        WireGuardError::NoSession
    );
    for address in invalid {
        assert_eq!(
            gateway
                .initiate_at(&peer.context, &peer.id, address)
                .unwrap_err(),
            WireGuardError::InvalidConfiguration
        );
        assert_eq!(
            gateway.endpoint(&peer.context, &peer.id).unwrap(),
            Some(peer.address)
        );
    }
    let updated = address(9, 45678);
    assert!(
        gateway
            .initiate_at(&peer.context, &peer.id, updated)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(updated)
    );
}

#[test]
fn malformed_and_unknown_handshakes_do_not_learn_endpoints() {
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    let initiation = peer.initiate();
    let mut invalid_mac = initiation.clone();
    invalid_mac[116] ^= 1;
    assert_eq!(
        gateway
            .receive_datagram(peer.address, &invalid_mac)
            .unwrap_err(),
        WireGuardError::Protocol
    );
    let mut outsider = RawPeer::new(
        peer.context.clone(),
        device("outsider"),
        99,
        1,
        peer.address,
        10,
    );
    assert!(
        gateway
            .receive_datagram(peer.address, &outsider.initiate())
            .is_err()
    );
    for bytes in [vec![], initiation[..147].to_vec(), vec![5, 0, 0, 0]] {
        assert_eq!(
            gateway.receive_datagram(peer.address, &bytes).unwrap_err(),
            WireGuardError::InvalidPacket
        );
    }
    for reserved in 1..4 {
        let mut bytes = initiation.clone();
        bytes[reserved] = 1;
        assert_eq!(
            gateway.receive_datagram(peer.address, &bytes).unwrap_err(),
            WireGuardError::InvalidPacket
        );
    }
    assert_eq!(
        gateway
            .receive_datagram(peer.address, &vec![0; MAX_DATAGRAM_SIZE + 1])
            .unwrap_err(),
        WireGuardError::PacketTooLarge
    );
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    let response = network(
        gateway
            .receive_datagram(peer.address, &initiation)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    header(&response, 2, 92);
}

#[test]
fn spoofed_indices_ciphertext_and_replays_cannot_deliver_or_move_an_endpoint() {
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    let alice_index = connect_from_peer(&mut gateway, &mut peers[0]);
    let bob_index = connect_from_peer(&mut gateway, &mut peers[2]);
    assert_ne!(alice_index, bob_index);
    let input = ipv4(1);
    let original = peers[0].encrypt(&input);
    let forged_source = address(250, 60000);
    let mut wrong_owner = original.clone();
    wrong_owner[4..8].copy_from_slice(&bob_index.to_le_bytes());
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for packet in [wrong_owner, corrupt] {
        assert!(gateway.receive_datagram(forged_source, &packet).is_err());
    }
    let unknown = (0_u32..)
        .find(|index| *index != alice_index && *index != bob_index)
        .unwrap();
    let mut unknown_index = original.clone();
    unknown_index[4..8].copy_from_slice(&unknown.to_le_bytes());
    assert_eq!(
        gateway
            .receive_datagram(forged_source, &unknown_index)
            .unwrap_err(),
        WireGuardError::UnknownIndex
    );
    for peer in [&peers[0], &peers[2]] {
        assert_eq!(
            gateway.endpoint(&peer.context, &peer.id).unwrap(),
            Some(peer.address)
        );
    }
    plaintext(
        gateway
            .receive_datagram(peers[0].address, &original)
            .unwrap()
            .unwrap(),
        &peers[0],
        &input,
    );
    assert!(gateway.receive_datagram(forged_source, &original).is_err());
    assert_eq!(
        gateway.endpoint(&peers[0].context, &peers[0].id).unwrap(),
        Some(peers[0].address)
    );
}

#[test]
fn exhausted_tenant_does_not_block_another_context_and_admission_runs_once() {
    let started = Instant::now();
    let (mut gateway, mut peers) = multiple_contexts(Limits {
        handshake_limit_per_ip: 1,
    });
    let initiation = peers[0].initiate();
    for host in 1..=MAX_HANDSHAKE_SOURCES {
        let source = address(u8::try_from(host).unwrap(), 41000);
        let result = gateway.receive_datagram(source, &initiation);
        if host == 1 {
            let response = network(
                result.unwrap().unwrap(),
                &peers[0].context,
                Some(&peers[0].id),
                source,
            );
            header(&response, 2, 92); // A second verification would require a cookie.
        } else {
            assert_eq!(result.unwrap_err(), WireGuardError::Protocol);
        }
    }
    let exhausted = gateway.receive_datagram(address(250, 41000), &initiation);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "source-budget fixture exceeded its window"
    );
    assert_eq!(exhausted.unwrap_err(), WireGuardError::SourceLimit);
    for position in [2, 4] {
        let host = if position == 2 { 251 } else { 252 };
        peers[position].address = address(host, peers[position].address.port());
        let initiation = peers[position].initiate();
        let peer = &peers[position];
        let response = network(
            gateway
                .receive_datagram(peer.address, &initiation)
                .unwrap()
                .unwrap(),
            &peer.context,
            Some(&peer.id),
            peer.address,
        );
        header(&response, 2, 92);
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "source-budget fixture exceeded its window"
    );
}

#[test]
fn incoming_cookie_challenges_are_public_only_and_preserve_source_socket_binding() {
    let (mut gateway, mut peer) = pair(
        Limits {
            handshake_limit_per_ip: 0,
        },
        10,
    );
    let initiation = peer.initiate();
    let cookie = network(
        gateway
            .receive_datagram(peer.address, &initiation)
            .unwrap()
            .unwrap(),
        &peer.context,
        None,
        peer.address,
    );
    header(&cookie, 3, 64);
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    assert!(matches!(
        peer.receive(server_address(), &cookie),
        RawOutput::None
    ));
    let retry = peer.retry();
    header(&retry, 1, 148);
    let changed_port = SocketAddr::new(peer.address.ip(), peer.address.port() + 1);
    let second_cookie = network(
        gateway
            .receive_datagram(changed_port, &retry)
            .unwrap()
            .unwrap(),
        &peer.context,
        None,
        changed_port,
    );
    header(&second_cookie, 3, 64);
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    let response = network(
        gateway
            .receive_datagram(peer.address, &retry)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    header(&response, 2, 92);
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    let confirmation = raw_network(peer.receive(server_address(), &response));
    assert!(
        gateway
            .receive_datagram(peer.address, &confirmation)
            .unwrap()
            .is_none()
    );
    let input = ipv4(1);
    let encrypted = peer.encrypt(&input);
    plaintext(
        gateway
            .receive_datagram(peer.address, &encrypted)
            .unwrap()
            .unwrap(),
        &peer,
        &input,
    );
}

#[test]
fn gateway_cookie_reply_uses_published_index_without_learning_its_source() {
    let (mut gateway, mut peer) = pair(Limits::default(), 0);
    let initiation = network(
        gateway
            .initiate_at(&peer.context, &peer.id, peer.address)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    let cookie = raw_network(peer.receive(server_address(), &initiation));
    header(&cookie, 3, 64);
    assert!(
        gateway
            .receive_datagram(address(250, 60000), &cookie)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    let retry = loop {
        if let Some(event) = gateway.tick_datagram(&peer.context, &peer.id).unwrap() {
            break network(event, &peer.context, Some(&peer.id), peer.address);
        }
        assert!(
            Instant::now() < deadline,
            "gateway handshake retry did not occur"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    header(&retry, 1, 148);
    finish_gateway_handshake(&mut gateway, &mut peer, &retry);
}

#[test]
fn authenticated_keepalive_and_invalid_inner_ip_learn_endpoints_but_reset_retires_session() {
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    connect_from_peer(&mut gateway, &mut peer);
    let keepalive_source = address(100, 51000);
    let keepalive = peer.encrypt(&[]);
    assert!(
        gateway
            .receive_datagram(keepalive_source, &keepalive)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(keepalive_source)
    );
    let malformed_source = address(101, 51001);
    let malformed = peer.encrypt(&[0x45; 19]);
    assert_eq!(
        gateway
            .receive_datagram(malformed_source, &malformed)
            .unwrap_err(),
        WireGuardError::InvalidPacket
    );
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(malformed_source)
    );
    let stale = peer.encrypt(&ipv4(1));
    gateway.reset(&peer.context, &peer.id).unwrap();
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    assert_eq!(
        gateway.receive_datagram(peer.address, &stale).unwrap_err(),
        WireGuardError::UnknownIndex
    );
    connect_from_peer(&mut gateway, &mut peer);
}

#[test]
fn reset_retires_pending_handshake_indices_before_late_responses() {
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    let initiation = network(
        gateway
            .initiate_at(&peer.context, &peer.id, peer.address)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    let response = raw_network(peer.receive(server_address(), &initiation));
    header(&response, 2, 92);
    gateway.reset(&peer.context, &peer.id).unwrap();
    assert_eq!(
        gateway
            .receive_datagram(peer.address, &response)
            .unwrap_err(),
        WireGuardError::UnknownIndex
    );
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    let fresh = network(
        gateway
            .initiate_at(&peer.context, &peer.id, peer.address)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    finish_gateway_handshake(&mut gateway, &mut peer, &fresh);
}

#[test]
fn rekey_preserves_old_session_until_ring_replacement_and_retires_its_index() {
    // Released GotaTun0.10.3 noise/mod.rs specifies N_SESSIONS=8 and inserts
    // each accepted handshake into the next round-robin slot. This is explicit
    // rehandshake coverage; it does not claim timer-triggered rekey evidence.
    const UPSTREAM_SESSION_SLOTS: usize = 8;
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    let original_index = connect_from_peer(&mut gateway, &mut peers[0]);
    connect_from_peer(&mut gateway, &mut peers[2]);
    connect_from_peer(&mut gateway, &mut peers[4]);
    let old_ip = ipv4(1);
    let old_outbound = network(
        gateway
            .send_datagram(&peers[0].context, &peers[0].id, &old_ip)
            .unwrap(),
        &peers[0].context,
        Some(&peers[0].id),
        peers[0].address,
    );
    let mut previous_peer_index = u32::from_le_bytes(old_outbound[4..8].try_into().unwrap());
    match peers[0].receive(server_address(), &old_outbound) {
        RawOutput::Plaintext(bytes) => assert_eq!(&bytes[..old_ip.len()], old_ip.as_slice()),
        _ => panic!("initial session did not decrypt the gateway packet"),
    }
    // Every old-session packet has a fresh, unused counter. A later rejection
    // therefore proves retired ownership rather than rejection of a replay.
    let old_packets: Vec<_> = (0..UPSTREAM_SESSION_SLOTS)
        .map(|_| peers[0].encrypt(&old_ip))
        .collect();
    let mut previous_index = original_index;
    for (replacement, old_packet) in old_packets.into_iter().enumerate() {
        assert_eq!(
            u32::from_le_bytes(old_packet[4..8].try_into().unwrap()),
            original_index,
        );
        let initiation = peers[0].initiate();
        header(&initiation, 1, 148);
        let new_peer_index = u32::from_le_bytes(initiation[4..8].try_into().unwrap());
        assert_ne!(new_peer_index, previous_peer_index);
        let peer = &peers[0];
        let response = network(
            gateway
                .receive_datagram(peer.address, &initiation)
                .unwrap()
                .unwrap(),
            &peer.context,
            Some(&peer.id),
            peer.address,
        );
        header(&response, 2, 92);
        let new_index = u32::from_le_bytes(response[4..8].try_into().unwrap());
        assert_ne!(new_index, previous_index);
        // Check before the response is delivered and key confirmation arrives:
        // installing a new responder session must not prematurely drop the old
        // session. The eighth replacement, however, actually evicts its slot.
        if replacement + 1 < UPSTREAM_SESSION_SLOTS {
            plaintext(
                gateway
                    .receive_datagram(peer.address, &old_packet)
                    .unwrap()
                    .unwrap(),
                peer,
                &old_ip,
            );
        } else {
            assert_eq!(
                gateway
                    .receive_datagram(peer.address, &old_packet)
                    .unwrap_err(),
                WireGuardError::UnknownIndex,
            );
        }
        let confirmation = raw_network(peers[0].receive(server_address(), &response));
        header(&confirmation, 4, 32);
        assert!(
            gateway
                .receive_datagram(peers[0].address, &confirmation)
                .unwrap()
                .is_none()
        );
        previous_index = new_index;
        previous_peer_index = new_peer_index;

        for input in [ipv4(1), ipv6(1)] {
            let encrypted = peers[0].encrypt(&input);
            assert_eq!(
                u32::from_le_bytes(encrypted[4..8].try_into().unwrap()),
                new_index
            );
            plaintext(
                gateway
                    .receive_datagram(peers[0].address, &encrypted)
                    .unwrap()
                    .unwrap(),
                &peers[0],
                &input,
            );
            let outbound = network(
                gateway
                    .send_datagram(&peers[0].context, &peers[0].id, &input)
                    .unwrap(),
                &peers[0].context,
                Some(&peers[0].id),
                peers[0].address,
            );
            assert_eq!(
                u32::from_le_bytes(outbound[4..8].try_into().unwrap()),
                new_peer_index
            );
            match peers[0].receive(server_address(), &outbound) {
                RawOutput::Plaintext(bytes) => {
                    assert_eq!(&bytes[..input.len()], input.as_slice());
                    assert!(bytes.len() - input.len() <= 15);
                }
                _ => panic!("fresh session did not decrypt the gateway packet"),
            }
        }
        for position in [2, 4] {
            let input = ipv6(1);
            let encrypted = peers[position].encrypt(&input);
            plaintext(
                gateway
                    .receive_datagram(peers[position].address, &encrypted)
                    .unwrap()
                    .unwrap(),
                &peers[position],
                &input,
            );
        }
    }
}

#[test]
#[ignore = "real 120-second WireGuard rekey acceptance; run explicitly"]
fn timers_initiator_automatically_rekeys_after_real_120_seconds() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(130);
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    let initiation = network(
        gateway
            .initiate_at(&peer.context, &peer.id, peer.address)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    let original_index = u32::from_le_bytes(initiation[4..8].try_into().unwrap());
    finish_gateway_handshake(&mut gateway, &mut peer, &initiation);

    // Rekey-after-time is armed by sending data after session establishment.
    // An authenticated empty reply clears the separate 15-second silence retry,
    // so that the observed new initiation is specifically the 120-second timer.
    assert!(
        gateway
            .tick_datagram(&peer.context, &peer.id)
            .unwrap()
            .is_none()
    );
    let input = ipv4(1);
    let encrypted = network(
        gateway
            .send_datagram(&peer.context, &peer.id, &input)
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    match peer.receive(server_address(), &encrypted) {
        RawOutput::Plaintext(bytes) => assert_eq!(&bytes[..input.len()], input.as_slice()),
        _ => panic!("initial data did not arrive at the direct peer"),
    }
    let reply = peer.encrypt(&[]);
    assert!(
        gateway
            .receive_datagram(peer.address, &reply)
            .unwrap()
            .is_none()
    );

    let rekey = loop {
        assert!(
            Instant::now() < deadline,
            "automatic 120-second rekey did not occur"
        );
        assert!(peer.engine.update_timers().unwrap().is_none());
        if let Some(event) = gateway.tick_datagram(&peer.context, &peer.id).unwrap() {
            assert!(
                started.elapsed() >= Duration::from_secs(120),
                "unexpected early handshake timer"
            );
            break network(event, &peer.context, Some(&peer.id), peer.address);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    header(&rekey, 1, 148);
    assert_ne!(
        u32::from_le_bytes(rekey[4..8].try_into().unwrap()),
        original_index
    );
    finish_gateway_handshake(&mut gateway, &mut peer, &rekey);
    for input in [ipv4(1), ipv6(1)] {
        let encrypted = peer.encrypt(&input);
        plaintext(
            gateway
                .receive_datagram(peer.address, &encrypted)
                .unwrap()
                .unwrap(),
            &peer,
            &input,
        );
    }
}

#[test]
#[ignore = "real 90-second WireGuard retry exhaustion acceptance; run explicitly"]
fn timers_stalled_handshake_exhausts_after_real_90_seconds_and_retires_pending_indices() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(100);
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    let initiation = network(
        gateway
            .initiate_at(&peer.context, &peer.id, peer.address)
            .unwrap()
            .unwrap(),
        &peer.context,
        Some(&peer.id),
        peer.address,
    );
    let mut latest_response = raw_network(peer.receive(server_address(), &initiation));
    let mut retries = 0;
    loop {
        // A forged MAC1 must reach admission for the latest published index but
        // cannot complete the handshake or postpone its retry-exhaustion timer.
        header(&latest_response, 2, 92);
        let mut probe = latest_response.clone();
        probe[60] ^= 1;
        assert_eq!(
            gateway.receive_datagram(peer.address, &probe).unwrap_err(),
            WireGuardError::Protocol
        );
        loop {
            assert!(
                Instant::now() < deadline,
                "handshake retries did not exhaust by the deadline"
            );
            match gateway.tick_datagram(&peer.context, &peer.id) {
                Ok(Some(event)) => {
                    let retry = network(event, &peer.context, Some(&peer.id), peer.address);
                    header(&retry, 1, 148);
                    latest_response = raw_network(peer.receive(server_address(), &retry));
                    retries += 1;
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    assert_eq!(error, WireGuardError::Protocol);
                    assert!(
                        started.elapsed() >= Duration::from_secs(90),
                        "handshake expired before 90 seconds"
                    );
                    assert!(
                        retries > 0,
                        "no actual handshake retransmission was observed"
                    );
                    assert_eq!(
                        gateway
                            .receive_datagram(peer.address, &latest_response)
                            .unwrap_err(),
                        WireGuardError::UnknownIndex
                    );
                    return;
                }
            }
        }
    }
}

#[test]
#[ignore = "real 180-second WireGuard session expiry acceptance; run explicitly"]
fn timers_idle_session_expires_after_real_180_seconds_and_retires_receiver_route() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(195);
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    connect_from_peer(&mut gateway, &mut peer); // Gateway is the responder.
    let before_expiry = peer.encrypt(&[]);
    let unused_data = peer.encrypt(&ipv4(1));
    let mut checked_before_expiry = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "session-expiry fixture exceeded its deadline"
        );
        assert!(
            gateway
                .tick_datagram(&peer.context, &peer.id)
                .unwrap()
                .is_none()
        );
        let elapsed = started.elapsed();
        if !checked_before_expiry && elapsed >= Duration::from_secs(178) {
            assert!(
                elapsed < Duration::from_secs(180),
                "scheduling skipped the pre-expiry probe"
            );
            // An authenticated empty keepalive proves ownership still exists
            // without creating application traffic or extending session age.
            assert!(
                gateway
                    .receive_datagram(peer.address, &before_expiry)
                    .unwrap()
                    .is_none()
            );
            checked_before_expiry = true;
        }
        if elapsed >= Duration::from_secs(181) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(checked_before_expiry);
    assert_eq!(
        gateway
            .receive_datagram(peer.address, &unused_data)
            .unwrap_err(),
        WireGuardError::UnknownIndex
    );
    assert_eq!(
        gateway
            .send_datagram(&peer.context, &peer.id, &ipv4(1))
            .unwrap_err(),
        WireGuardError::NoSession
    );
}

fn loopback_socket() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn receive_udp(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0; MAX_DATAGRAM_SIZE + 1];
    let (length, source) = socket.recv_from(&mut buffer).unwrap();
    assert!(length <= MAX_DATAGRAM_SIZE, "oversized loopback datagram");
    (buffer[..length].to_vec(), source)
}

fn poll_udp(transport: &UdpTransport, gateway: &mut Gateway) -> Result<UdpEvent, TransportError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match transport.poll(gateway) {
            Ok(Some(event)) => return Ok(event),
            Err(error) => return Err(error),
            Ok(None) => {}
        }
        assert!(
            Instant::now() < deadline,
            "UDP transport did not produce the expected result"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn sent(event: UdpEvent, peer: &RawPeer) {
    match event {
        UdpEvent::Sent {
            destination,
            context,
            peer: identity,
        } => {
            assert_eq!(destination, peer.address);
            assert_eq!(context, peer.context);
            assert_eq!(identity, Some(peer.id.clone()));
        }
        UdpEvent::Plaintext { .. } => panic!("expected completed network transmission"),
    }
}

#[test]
fn udp_transport_one_socket_carries_tenants_service_and_gateway() {
    let (mut gateway, mut peers) = multiple_contexts(Limits::default());
    let server = loopback_socket();
    let server_address = server.local_addr().unwrap();
    let transport = UdpTransport::from_socket(server).unwrap();
    assert_eq!(transport.local_addr().unwrap(), server_address);
    let sockets: Vec<_> = peers.iter().map(|_| loopback_socket()).collect();
    for (peer, socket) in peers.iter_mut().zip(&sockets) {
        peer.address = socket.local_addr().unwrap();
        let initiation = peer.initiate();
        assert_eq!(
            socket.send_to(&initiation, server_address).unwrap(),
            initiation.len()
        );
        sent(poll_udp(&transport, &mut gateway).unwrap(), peer);
        let (response, source) = receive_udp(socket);
        assert_eq!(source, server_address);
        let confirmation = raw_network(peer.receive(source, &response));
        socket.send_to(&confirmation, server_address).unwrap();
        for input in [ipv4(1), ipv6(1)] {
            let encrypted = peer.encrypt(&input);
            socket.send_to(&encrypted, server_address).unwrap();
            match poll_udp(&transport, &mut gateway).unwrap() {
                UdpEvent::Plaintext {
                    context,
                    peer: identity,
                    packet,
                } => {
                    assert_eq!(context, peer.context);
                    assert_eq!(identity, peer.id);
                    assert_eq!(packet.as_bytes(), input.as_slice());
                }
                UdpEvent::Sent { .. } => panic!("expected authenticated UDP input"),
            }
            transport
                .transmit(
                    gateway
                        .send_datagram(&peer.context, &peer.id, &input)
                        .unwrap(),
                )
                .unwrap();
            let (encrypted, source) = receive_udp(socket);
            assert_eq!(source, server_address);
            match peer.receive(source, &encrypted) {
                RawOutput::Plaintext(bytes) => {
                    assert_eq!(&bytes[..input.len()], input.as_slice());
                    assert!(bytes.len() - input.len() <= 15);
                }
                _ => panic!("direct peer did not decrypt the UDP reply"),
            }
        }
    }
}

#[test]
fn udp_transport_empty_poll_is_nonblocking_and_preserves_supplied_bind_address() {
    let socket = loopback_socket();
    let bound = socket.local_addr().unwrap();
    let transport = UdpTransport::from_socket(socket).unwrap();
    assert_eq!(transport.local_addr().unwrap(), bound);
    let mut gateway = Gateway::new(vec![], Limits::default()).unwrap();
    let started = Instant::now();
    assert!(transport.poll(&mut gateway).unwrap().is_none());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "empty poll used the socket's blocking timeout"
    );
}

#[test]
fn udp_transport_rejects_oversize_before_gateway_and_consumes_one_datagram_per_poll() {
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    let server = loopback_socket();
    let server_address = server.local_addr().unwrap();
    let transport = UdpTransport::from_socket(server).unwrap();
    let client = loopback_socket();
    peer.address = client.local_addr().unwrap();
    let initiation = peer.initiate();
    client
        .send_to(&vec![0; MAX_DATAGRAM_SIZE + 100], server_address)
        .unwrap();
    client.send_to(&initiation, server_address).unwrap();
    assert_eq!(
        poll_udp(&transport, &mut gateway).unwrap_err(),
        TransportError::WireGuard(WireGuardError::PacketTooLarge)
    );
    assert_eq!(gateway.endpoint(&peer.context, &peer.id).unwrap(), None);
    sent(poll_udp(&transport, &mut gateway).unwrap(), &peer);
    let (response, source) = receive_udp(&client);
    assert_eq!(source, server_address);
    header(&response, 2, 92);
    assert_eq!(
        gateway.endpoint(&peer.context, &peer.id).unwrap(),
        Some(peer.address)
    );
    client.send_to(&[5, 0, 0, 0], server_address).unwrap();
    assert_eq!(
        poll_udp(&transport, &mut gateway).unwrap_err(),
        TransportError::WireGuard(WireGuardError::InvalidPacket)
    );
    assert!(transport.poll(&mut gateway).unwrap().is_none());
}

#[test]
fn udp_transport_rejects_plaintext_and_reports_socket_send_failure() {
    let (mut gateway, mut peer) = pair(Limits::default(), 10);
    connect_from_peer(&mut gateway, &mut peer);
    let encrypted = peer.encrypt(&ipv4(1));
    let authenticated = gateway
        .receive_datagram(peer.address, &encrypted)
        .unwrap()
        .unwrap();
    let transport = UdpTransport::from_socket(loopback_socket()).unwrap();
    assert_eq!(
        transport.transmit(authenticated).unwrap_err(),
        TransportError::NotNetwork
    );

    // IPv6 loopback is valid endpoint metadata but cannot be sent through this
    // explicitly IPv4 socket. No external network destination is involved.
    gateway.reset(&peer.context, &peer.id).unwrap();
    let ipv6_loopback = "[::1]:51820".parse().unwrap();
    let network = gateway
        .initiate_at(&peer.context, &peer.id, ipv6_loopback)
        .unwrap()
        .unwrap();
    assert_eq!(transport.transmit(network).unwrap_err(), TransportError::Io);
    assert!(transport.poll(&mut gateway).unwrap().is_none());
    let error: &dyn std::error::Error = &TransportError::Io;
    assert!(!error.to_string().is_empty());
}
