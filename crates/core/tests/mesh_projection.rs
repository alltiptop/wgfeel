use wgfeel_core::*;

#[test]
fn node_contact_survives_projection_scope_changes_and_withdrawal() {
    let endpoints = vec![
        "203.0.113.20:55125".parse().unwrap(),
        "[2001:db8::20]:55125".parse().unwrap(),
    ];
    let node = assignment("one", 1, 10001)
        .with_endpoints(endpoints.clone())
        .unwrap()
        .with_hostname(Some("vps1.example".into()))
        .unwrap();
    let scoped = node.with_scope(vec![], vec![]).unwrap();
    assert_eq!(scoped.endpoints(), endpoints);
    assert_eq!(scoped.hostname(), Some("vps1.example"));
    let config = ManagementConfig::new(
        NodeId::new("management").unwrap(),
        Config::new(4, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![node.clone()],
    )
    .unwrap();
    let removed = ManagementConfig::new(
        NodeId::new("management").unwrap(),
        Config::new(5, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![],
    )
    .unwrap();
    for projection in [
        config.project_mesh_for(node.recipient()).unwrap(),
        removed.withdraw_for(&node).unwrap(),
    ] {
        let decoded = GatewayProjection::from_json(&projection.to_json().unwrap()).unwrap();
        assert_eq!(decoded.assignment().endpoints(), endpoints);
        assert_eq!(decoded.assignment().hostname(), Some("vps1.example"));
    }
}

#[test]
fn node_contact_rejects_ambiguous_unreachable_or_unbounded_input() {
    let node = assignment("one", 1, 10001);
    let endpoint = "203.0.113.20:55125".parse().unwrap();
    assert!(
        node.clone()
            .with_endpoints(vec![endpoint, endpoint])
            .is_err()
    );
    assert!(
        node.clone()
            .with_endpoints(
                (1..=17)
                    .map(|port| format!("127.0.0.1:{port}").parse().unwrap())
                    .collect()
            )
            .is_err()
    );
    for address in [
        "[fe80::1]:55125",
        "[2001:db8::1%3]:55125",
        "[::]:55125",
        "0.0.0.0:55125",
    ] {
        assert!(
            node.clone()
                .with_endpoints(vec![address.parse().unwrap()])
                .is_err(),
            "{address}"
        );
    }
    for hostname in ["", "vps\nforged", "vps: address", "-invalid", "bad..name"] {
        assert!(
            node.clone().with_hostname(Some(hostname.into())).is_err(),
            "{hostname}"
        );
    }
    let mut encoded = serde_json::to_value(&node).unwrap();
    encoded["endpoints"] = serde_json::json!(["0.0.0.0:55125"]);
    assert!(serde_json::from_value::<GatewayAssignment>(encoded).is_err());
}

fn assignment(id: &str, key: u8, port: u16) -> GatewayAssignment {
    GatewayAssignment::new(
        NodeId::new(id).unwrap(),
        (DevicePublicKey::new([key; 32]).unwrap()).clone(),
        fixture_gateway_public(&(DevicePublicKey::new([key; 32]).unwrap())),
        vec![],
        vec![],
    )
    .unwrap()
    .with_endpoint(Some(format!("127.0.0.1:{port}").parse().unwrap()))
    .unwrap()
}
#[test]
fn each_gateway_receives_same_public_mesh_and_its_own_projection() {
    let nodes = vec![assignment("one", 1, 10001), assignment("two", 2, 10002)];
    let config = ManagementConfig::new(
        NodeId::new("management").unwrap(),
        Config::new(4, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        nodes.clone(),
    )
    .unwrap();
    for node in &nodes {
        let projection = config.project_mesh_for(node.recipient()).unwrap();
        assert_eq!(projection.mesh(), nodes);
        assert_eq!(projection.assignment(), node);
        assert!(!projection.is_revoked());
        assert_eq!(
            GatewayProjection::from_json(&projection.to_json().unwrap()).unwrap(),
            projection
        );
    }
    let withdrawn = config
        .withdraw_for(&assignment("removed", 3, 10003))
        .unwrap();
    assert!(withdrawn.is_revoked());
    assert!(withdrawn.assignment().networks().is_empty());
    assert_eq!(withdrawn.mesh(), nodes);
    assert_eq!(
        GatewayProjection::from_json(&withdrawn.to_json().unwrap()).unwrap(),
        withdrawn
    );
}
#[test]
fn mesh_endpoints_must_be_concrete_and_membership_cannot_be_forged_in_projection() {
    let node = assignment("one", 1, 10001);
    for address in [
        "0.0.0.0:1",
        "127.0.0.1:0",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "[::ffff:127.0.0.1]:1",
    ] {
        assert!(
            node.clone()
                .with_endpoint(Some(address.parse().unwrap()))
                .is_err()
        );
    }
    let config = ManagementConfig::new(
        NodeId::new("management").unwrap(),
        Config::new(4, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![node.clone()],
    )
    .unwrap();
    let text = config
        .project_mesh_for(node.recipient())
        .unwrap()
        .to_json()
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["mesh"] = serde_json::json!([]);
    assert!(GatewayProjection::from_json(&value.to_string()).is_err());
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["mesh"][0]["service_public_key"] = serde_json::json!([3; 32].to_vec());
    assert!(GatewayProjection::from_json(&value.to_string()).is_err());
}

fn fixture_gateway_public(service: &wgfeel_core::DevicePublicKey) -> wgfeel_core::DevicePublicKey {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    wgfeel_core::DevicePublicKey::new(bytes).unwrap()
}
