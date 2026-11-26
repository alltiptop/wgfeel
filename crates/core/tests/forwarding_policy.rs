use wgfeel_core::*;

fn node(id: &str) -> NodeId {
    NodeId::new(id).unwrap()
}
fn net(id: &str) -> NetworkId {
    NetworkId::new(id).unwrap()
}
fn key(byte: u8) -> DevicePublicKey {
    DevicePublicKey::new([byte; 32]).unwrap()
}
fn endpoint(network: &str, device: &str) -> Endpoint {
    Endpoint::new(net(network), DeviceId::new(device).unwrap())
}
fn config(private: bool, suspended: bool, deny: bool) -> ManagementConfig {
    let networks = ["alice", "bob"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let devices = [("phone", "a"), ("laptop", "b"), ("desktop", "a")]
                .into_iter()
                .enumerate()
                .map(|(i, (id, home))| {
                    Device::new(
                        DeviceId::new(id).unwrap(),
                        key((index * 3 + i + 1) as u8),
                        vec![format!("10.1.0.{}", i + 1).parse().unwrap()],
                    )
                    .unwrap()
                    .with_gateway(Some(node(home)))
                })
                .collect();
            Network::new(net(name), devices)
                .unwrap()
                .with_private_lan(private)
                .with_suspended(suspended && name == "alice")
        })
        .collect();
    let assignments = [
        ("a", TrafficMode::Entry),
        ("b", TrafficMode::Entry),
        ("relay", TrafficMode::Relay),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (id, mode))| {
        let scopes = vec![net("alice"), net("bob")];
        let tenants = if mode == TrafficMode::Entry {
            scopes
                .iter()
                .enumerate()
                .map(|(n, network)| {
                    TenantKeyAssignment::new(network.clone(), key((40 + i * 2 + n) as u8))
                })
                .collect()
        } else {
            vec![]
        };
        GatewayAssignment::new(
            node(id),
            key((20 + i * 2) as u8),
            key((21 + i * 2) as u8),
            scopes,
            tenants,
        )
        .unwrap()
        .with_traffic(mode)
        .unwrap()
    })
    .collect();
    let denies = if deny {
        vec![Rule::new(
            endpoint("alice", "phone"),
            endpoint("alice", "laptop"),
            Action::Deny,
        )]
    } else {
        vec![]
    };
    ManagementConfig::new(
        node("a"),
        Config::new(1, networks, Policy::new(denies, vec![], vec![])).unwrap(),
        assignments,
    )
    .unwrap()
}

#[test]
fn one_policy_contract_covers_ingress_relay_and_exit_and_binds_device_homes() {
    let source = endpoint("alice", "phone");
    let destination = endpoint("alice", "laptop");
    for (private, suspended, deny, expected) in [
        (true, false, false, Action::Allow),
        (false, false, false, Action::Deny),
        (true, true, false, Action::Deny),
        (true, false, true, Action::Deny),
    ] {
        let config = config(private, suspended, deny);
        for recipient in ["a", "relay", "b"] {
            let projection = config.project_mesh_for(&node(recipient)).unwrap();
            assert_eq!(
                projection.forwarding_decision(&source, &destination, &node("a"), &node("b")),
                expected
            );
            assert_eq!(
                projection.forwarding_decision(&source, &destination, &node("relay"), &node("b")),
                Action::Deny
            );
            assert_eq!(
                projection.forwarding_decision(&source, &destination, &node("a"), &node("a")),
                Action::Deny
            );
            assert_eq!(
                projection.forwarding_decision(
                    &source,
                    &endpoint("bob", "laptop"),
                    &node("a"),
                    &node("b")
                ),
                Action::Deny
            );
            assert_eq!(
                projection.forwarding_decision(
                    &endpoint("alice", "unknown"),
                    &destination,
                    &node("a"),
                    &node("b")
                ),
                Action::Deny
            );
        }
        for local in [
            config.project_mesh_for(&node("a")).unwrap(),
            config.project_for(&node("a")).unwrap(),
        ] {
            assert_eq!(
                local.forwarding_decision(
                    &source,
                    &endpoint("alice", "desktop"),
                    &node("a"),
                    &node("a")
                ),
                if !private || suspended {
                    Action::Deny
                } else {
                    Action::Allow
                }
            );
        }
    }
}

#[test]
fn decoded_mesh_cannot_reuse_a_device_key_as_a_transport_identity() {
    let config = config(true, false, false);
    let projection = config.project_mesh_for(&node("a")).unwrap();
    let valid: serde_json::Value = serde_json::from_str(&projection.to_json().unwrap()).unwrap();
    for role in ["service_public_key", "gateway_public_key"] {
        let mut invalid = valid.clone();
        invalid["mesh"][1][role] = serde_json::json!([1; 32].to_vec());
        assert!(GatewayProjection::from_json(&invalid.to_string()).is_err());
    }
}
