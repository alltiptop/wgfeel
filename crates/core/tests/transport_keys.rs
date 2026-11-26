use wgfeel_core::{
    Config, DevicePublicKey, DomainError, GatewayAssignment, GatewayPrivateKey, ManagementConfig,
    NodeId, NodeKeys, Policy, ServicePrivateKey,
};

fn public(byte: u8) -> DevicePublicKey {
    DevicePublicKey::new([byte; 32]).unwrap()
}
fn node(id: &str, service: u8, gateway: u8) -> GatewayAssignment {
    GatewayAssignment::new(
        NodeId::new(id).unwrap(),
        public(service),
        public(gateway),
        vec![],
        vec![],
    )
    .unwrap()
}

#[test]
fn service_and_gateway_keys_cannot_be_reused_within_or_between_nodes() {
    assert_eq!(
        GatewayAssignment::new(
            NodeId::new("a").unwrap(),
            public(1),
            public(1),
            vec![],
            vec![]
        )
        .unwrap_err(),
        DomainError::DuplicateGatewayKey
    );
    for (service, gateway) in [(1, 3), (3, 1), (2, 3), (3, 2)] {
        let result = ManagementConfig::new(
            NodeId::new("main").unwrap(),
            Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![node("a", 1, 2), node("b", service, gateway)],
        );
        assert_eq!(result.unwrap_err(), DomainError::DuplicateGatewayKey);
    }
}

#[test]
fn assignment_decoder_requires_the_independent_gateway_key() {
    let value = serde_json::to_value(node("a", 1, 2)).unwrap();
    for replacement in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!([1; 32].to_vec())),
    ] {
        let mut invalid = value.clone();
        match replacement {
            None => {
                invalid
                    .as_object_mut()
                    .unwrap()
                    .remove("gateway_public_key");
            }
            Some(key) => invalid["gateway_public_key"] = key,
        }
        assert!(serde_json::from_value::<GatewayAssignment>(invalid).is_err());
    }
    let decoded: GatewayAssignment = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.service_public_key(), &public(1));
    assert_eq!(decoded.gateway_public_key(), &public(2));
}

#[test]
fn permanent_identity_compares_both_secrets_and_redacts_them() {
    let keys = |service, gateway| {
        NodeKeys::new(
            ServicePrivateKey::new([service; 32]).unwrap(),
            GatewayPrivateKey::new([gateway; 32]).unwrap(),
        )
    };
    assert!(keys(1, 1).is_err());
    let original = keys(37, 47).unwrap();
    assert!(original.same_identity(&keys(37, 47).unwrap()));
    assert!(!original.same_identity(&keys(37, 48).unwrap()));
    assert!(!original.same_identity(&keys(38, 47).unwrap()));
    let diagnostic = format!("{original:?}");
    assert!(diagnostic.contains("REDACTED"));
    assert!(!diagnostic.contains("37"));
    assert!(!diagnostic.contains("47"));
}
