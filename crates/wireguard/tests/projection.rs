use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, GatewayAssignment,
    GatewayProjection, ManagementConfig, Network, NetworkId, NodeId, NodeKeys, Policy, Rule,
    TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Gateway, Limits, PeerConfig, PeerId, WireGuardError,
};

fn node(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn network(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn seed(number: u8) -> [u8; 32] {
    let mut bytes = [61; 32];
    bytes[9] = number;
    bytes
}
fn public(number: u8) -> DevicePublicKey {
    let secret = gotatun::x25519::StaticSecret::from(seed(number));
    DevicePublicKey::new(gotatun::x25519::PublicKey::from(&secret).to_bytes()).unwrap()
}
fn projection(recipient: &str, provisioned: bool) -> GatewayProjection {
    let device = Device::new(
        DeviceId::new("client").unwrap(),
        public(5),
        vec!["10.1.0.1".parse().unwrap()],
    )
    .unwrap();
    let endpoint = Endpoint::new(network("alpha"), DeviceId::new("client").unwrap());
    let policy = Policy::new(
        vec![Rule::new(endpoint.clone(), endpoint.clone(), Action::Deny)],
        vec![Rule::new(endpoint.clone(), endpoint, Action::Allow)],
        vec![],
    );
    let config = Config::new(
        17,
        vec![
            Network::new(network("alpha"), vec![device]).unwrap(),
            Network::new(network("beta"), vec![]).unwrap(),
        ],
        policy,
    )
    .unwrap();
    let first = GatewayAssignment::new(
        node("gateway-a"),
        (public(1)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(public(1))),
        vec![network("alpha"), network("beta")],
        if provisioned {
            vec![TenantKeyAssignment::new(network("alpha"), public(2))]
        } else {
            vec![]
        },
    )
    .unwrap();
    let second = GatewayAssignment::new(
        node("gateway-b"),
        (public(3)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(public(3))),
        vec![network("alpha")],
        vec![TenantKeyAssignment::new(network("alpha"), public(4))],
    )
    .unwrap();
    ManagementConfig::new(node("management"), config, vec![first, second])
        .unwrap()
        .project_for(&node(recipient))
        .unwrap()
}
fn build(
    projection: &GatewayProjection,
    node_key: &NodeKeys,
    tenants: &[(NetworkId, TenantPrivateKey)],
) -> Result<Gateway, WireGuardError> {
    Gateway::from_local_projection(
        projection,
        &node("management"),
        &node("gateway-a"),
        node_key,
        tenants.iter().map(|(network, key)| (network, key)),
        Limits::default(),
    )
}
fn encrypted(event: DatagramEvent) -> Vec<u8> {
    match event {
        DatagramEvent::Network { packet, .. } => packet.as_bytes().to_vec(),
        DatagramEvent::Plaintext { .. } => panic!("expected encrypted output"),
    }
}

#[test]
fn local_projection_builds_only_expected_crypto_contexts_and_keeps_policy_independent() {
    let accepted = projection("gateway-a", true);
    let accepted_json = accepted.to_json().unwrap();
    let local = [(network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())];
    let mut gateway = build(
        &accepted,
        &wgfeel_test_support::fixture_node_keys(seed(1)),
        &local,
    )
    .unwrap();
    assert_eq!(gateway.public_key(&ContextId::Service), Some(&public(1)));
    assert_eq!(
        gateway.public_key(&ContextId::Tenant(network("alpha"))),
        Some(&public(2))
    );
    assert!(
        gateway
            .public_key(&ContextId::Tenant(network("beta")))
            .is_none(),
        "transit scope does not invent private contexts"
    );
    let mut client = Gateway::new(
        vec![ContextConfig::tenant(
            network("alpha"),
            TenantPrivateKey::new(seed(5)).unwrap(),
            vec![PeerConfig {
                id: PeerId::Device(DeviceId::new("server").unwrap()),
                public_key: public(2),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    assert!(client.projection().is_none());
    let source = "198.51.100.20:40000".parse().unwrap();
    let server = "198.51.100.10:51820".parse().unwrap();
    let context = ContextId::Tenant(network("alpha"));
    let peer = PeerId::Device(DeviceId::new("client").unwrap());
    let initiation = encrypted(
        client
            .initiate_at(
                &context,
                &PeerId::Device(DeviceId::new("server").unwrap()),
                server,
            )
            .unwrap()
            .unwrap(),
    );
    let response = encrypted(
        gateway
            .receive_datagram(source, &initiation)
            .unwrap()
            .unwrap(),
    );
    let confirmation = encrypted(client.receive_datagram(server, &response).unwrap().unwrap());
    assert!(
        gateway
            .receive_datagram(source, &confirmation)
            .unwrap()
            .is_none()
    );
    let mut plaintext = vec![0_u8; 20];
    plaintext[0] = 0x45;
    plaintext[2..4].copy_from_slice(&20_u16.to_be_bytes());
    plaintext[8] = 64;
    plaintext[9] = 253;
    let ciphertext = encrypted(
        client
            .send_datagram(
                &context,
                &PeerId::Device(DeviceId::new("server").unwrap()),
                &plaintext,
            )
            .unwrap(),
    );
    match gateway
        .receive_datagram(source, &ciphertext)
        .unwrap()
        .unwrap()
    {
        DatagramEvent::Plaintext {
            context: actual_context,
            peer: actual_peer,
            packet,
        } => {
            assert_eq!(actual_context, context);
            assert_eq!(actual_peer, peer);
            assert_eq!(packet.as_bytes(), plaintext);
        }
        DatagramEvent::Network { .. } => panic!("expected raw authenticated plaintext"),
    }
    assert_eq!(gateway.endpoint(&context, &peer).unwrap(), Some(source));
    let endpoint = Endpoint::new(network("alpha"), DeviceId::new("client").unwrap());
    assert_eq!(
        gateway.projection().unwrap().decision(&endpoint, &endpoint),
        Action::Deny,
        "crypto authentication is not forwarding permission"
    );
    assert_eq!(
        gateway.projection().unwrap().to_json().unwrap(),
        accepted_json
    );
    gateway.reset(&context, &peer).unwrap();
    assert_eq!(gateway.endpoint(&context, &peer).unwrap(), None);
    assert_eq!(
        gateway.projection().unwrap().to_json().unwrap(),
        accepted_json
    );
}

#[test]
fn local_material_requires_exact_set_and_real_derived_key_identity() {
    let accepted = projection("gateway-a", true);
    let correct_node = wgfeel_test_support::fixture_node_keys(seed(1));
    let correct = [(network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())];
    assert!(matches!(
        build(
            &accepted,
            &wgfeel_test_support::fixture_node_keys(seed(3)),
            &correct
        ),
        Err(WireGuardError::InvalidConfiguration)
    ));
    assert!(matches!(
        build(
            &accepted,
            &correct_node,
            &[(network("alpha"), TenantPrivateKey::new(seed(4)).unwrap())]
        ),
        Err(WireGuardError::InvalidConfiguration)
    ));
    assert!(matches!(
        build(&accepted, &correct_node, &[]),
        Err(WireGuardError::InvalidConfiguration)
    ));
    assert!(matches!(
        build(
            &accepted,
            &correct_node,
            &[
                (network("alpha"), TenantPrivateKey::new(seed(2)).unwrap()),
                (network("beta"), TenantPrivateKey::new(seed(4)).unwrap())
            ]
        ),
        Err(WireGuardError::InvalidConfiguration)
    ));
    assert!(matches!(
        build(
            &accepted,
            &correct_node,
            &[
                (network("alpha"), TenantPrivateKey::new(seed(2)).unwrap()),
                (network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())
            ]
        ),
        Err(WireGuardError::InvalidConfiguration)
    ));
    let mut equivalent = seed(2);
    equivalent[0] ^= 1;
    assert_ne!(equivalent, seed(2));
    assert!(
        build(
            &accepted,
            &correct_node,
            &[(network("alpha"), TenantPrivateKey::new(equivalent).unwrap())]
        )
        .is_ok(),
        "X25519 ownership comparison must use derived public identity"
    );
}

#[test]
fn recipient_and_management_pins_cannot_select_another_nodes_material() {
    let accepted = projection("gateway-a", true);
    let local_node = wgfeel_test_support::fixture_node_keys(seed(1));
    let local_tenant = TenantPrivateKey::new(seed(2)).unwrap();
    let alpha = network("alpha");
    for (management, recipient) in [
        ("other-management", "gateway-a"),
        ("management", "gateway-b"),
    ] {
        assert!(matches!(
            Gateway::from_local_projection(
                &accepted,
                &node(management),
                &node(recipient),
                &local_node,
                [(&alpha, &local_tenant)],
                Limits::default()
            ),
            Err(WireGuardError::InvalidConfiguration)
        ));
    }
    assert!(matches!(
        build(
            &projection("gateway-b", true),
            &local_node,
            &[(network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())]
        ),
        Err(WireGuardError::InvalidConfiguration)
    ));
}

#[test]
fn transit_only_projection_uses_own_service_identity_without_inventing_tenant_secrets() {
    let accepted = projection("gateway-a", false);
    let gateway = build(
        &accepted,
        &wgfeel_test_support::fixture_node_keys(seed(1)),
        &[],
    )
    .unwrap();
    assert_eq!(gateway.public_key(&ContextId::Service), Some(&public(1)));
    assert!(
        gateway
            .public_key(&ContextId::Tenant(network("alpha")))
            .is_none()
    );
    assert!(matches!(
        gateway.endpoint(
            &ContextId::Service,
            &PeerId::Node(node("unassigned-remote"))
        ),
        Err(WireGuardError::UnknownPeer)
    ));
    assert_eq!(gateway.projection().unwrap().generation(), 17);
}

#[test]
fn public_projection_and_diagnostics_never_encode_owned_or_foreign_private_material() {
    let accepted = projection("gateway-a", true);
    let gateway = build(
        &accepted,
        &wgfeel_test_support::fixture_node_keys(seed(1)),
        &[(network("alpha"), TenantPrivateKey::new(seed(2)).unwrap())],
    )
    .unwrap();
    let encoded = accepted.to_json().unwrap();
    let debug = format!("{accepted:?} {gateway:?}");
    for number in 1..=5 {
        assert!(!encoded.contains(&format!("{:?}", seed(number)).replace(' ', "")));
        assert!(!debug.contains(&format!("{:?}", seed(number))));
    }
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("gateway-b"));
    assert_eq!(
        gateway.projection().unwrap().assignment().tenants()[0].public_key(),
        &public(2)
    );
}
