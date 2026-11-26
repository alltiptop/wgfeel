use wgfeel_core::*;

fn assignment(id: &str, mode: &str) -> GatewayAssignment {
    let node = GatewayAssignment::new(
        NodeId::new(id).unwrap(),
        (DevicePublicKey::new([3; 32]).unwrap()).clone(),
        fixture_gateway_public(&(DevicePublicKey::new([3; 32]).unwrap())),
        vec![],
        vec![],
    )
    .unwrap();
    let mut wire = serde_json::to_value(node).unwrap();
    wire["traffic"] = serde_json::json!(mode);
    serde_json::from_value(wire).unwrap()
}

#[test]
fn main_and_child_can_each_have_all_three_traffic_modes() {
    for recipient in ["main", "child"] {
        for mode in ["entry", "relay", "off"] {
            let node = assignment(recipient, mode);
            let config = ManagementConfig::new(
                NodeId::new("main").unwrap(),
                Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
                vec![node.clone()],
            )
            .unwrap();
            let projection = config.project_mesh_for(node.recipient()).unwrap();
            let restored = GatewayProjection::from_json(&projection.to_json().unwrap()).unwrap();
            assert_eq!(restored, projection);
            assert_eq!(
                serde_json::to_value(restored.assignment()).unwrap()["traffic"],
                mode
            );
        }
    }
}

#[test]
fn restricted_modes_cannot_receive_tenant_keys_and_off_has_no_user_scope() {
    for mode in ["relay", "off"] {
        let mut wire = serde_json::to_value(assignment("child", mode)).unwrap();
        wire["networks"] = serde_json::json!(["tenant"]);
        wire["tenants"] = serde_json::json!([{"network":"tenant", "public_key":vec![7;32]}]);
        assert!(serde_json::from_value::<GatewayAssignment>(wire).is_err());
    }
    let mut wire = serde_json::to_value(assignment("child", "off")).unwrap();
    wire["networks"] = serde_json::json!(["tenant"]);
    assert!(serde_json::from_value::<GatewayAssignment>(wire).is_err());
}

#[test]
fn capability_parser_requires_an_explicit_valid_traffic_mode() {
    let mut wire = serde_json::to_value(assignment("child", "entry")).unwrap();
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!("gateway"),
        serde_json::json!(true),
    ] {
        wire["traffic"] = invalid;
        assert!(serde_json::from_value::<GatewayAssignment>(wire.clone()).is_err());
    }
    wire.as_object_mut().unwrap().remove("traffic");
    assert!(serde_json::from_value::<GatewayAssignment>(wire).is_err());
}

#[test]
fn scope_changes_preserve_relay_mode_and_cannot_add_private_keys() {
    let node = assignment("relay", "relay");
    let scope = vec![NetworkId::new("tenant").unwrap()];
    let scoped = node.with_scope(scope.clone(), vec![]).unwrap();
    assert_eq!(serde_json::to_value(scoped).unwrap()["traffic"], "relay");
    assert!(
        node.with_scope(
            scope,
            vec![TenantKeyAssignment::new(
                NetworkId::new("tenant").unwrap(),
                DevicePublicKey::new([7; 32]).unwrap()
            )]
        )
        .is_err()
    );
}

fn fixture_gateway_public(service: &wgfeel_core::DevicePublicKey) -> wgfeel_core::DevicePublicKey {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    wgfeel_core::DevicePublicKey::new(bytes).unwrap()
}
