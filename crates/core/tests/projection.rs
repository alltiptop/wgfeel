use std::net::IpAddr;
use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, GatewayAssignment,
    GatewayProjection, Grant, ManagementConfig, Network, NetworkId, NodeId, Policy, Rule,
    TenantKeyAssignment,
};

fn node(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn network(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn key(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}
fn endpoint(net: &str, device: &str) -> Endpoint {
    Endpoint::new(network(net), DeviceId::new(device).unwrap())
}
fn rule(source: (&str, &str), destination: (&str, &str), action: Action) -> Rule {
    Rule::new(
        endpoint(source.0, source.1),
        endpoint(destination.0, destination.1),
        action,
    )
}
fn grant(source: (&str, &str), destination: (&str, &str)) -> Grant {
    Grant::new(
        endpoint(source.0, source.1),
        endpoint(destination.0, destination.1),
    )
}

fn config(generation: u64) -> Config {
    let networks = [("alpha", 1), ("beta", 2), ("unrelated", 3)]
        .into_iter()
        .map(|(name, number)| {
            let devices = [("first", 1), ("second", 2)]
                .into_iter()
                .map(|(id, host)| {
                    Device::new(
                        DeviceId::new(id).unwrap(),
                        key(number * 10 + host),
                        vec![format!("10.{number}.0.{host}").parse::<IpAddr>().unwrap()],
                    )
                    .unwrap()
                })
                .collect();
            Network::new(network(name), devices).unwrap()
        })
        .collect();
    Config::new(
        generation,
        networks,
        Policy::new(
            vec![
                rule(("alpha", "first"), ("alpha", "second"), Action::Deny),
                rule(("alpha", "first"), ("beta", "first"), Action::Deny),
            ],
            vec![
                rule(("alpha", "first"), ("alpha", "second"), Action::Allow),
                rule(("beta", "first"), ("beta", "second"), Action::Allow),
            ],
            vec![
                grant(("alpha", "first"), ("beta", "first")),
                grant(("alpha", "second"), ("beta", "second")),
                grant(("beta", "first"), ("unrelated", "first")),
            ],
        ),
    )
    .unwrap()
}

fn assignment(id: &str, system: u8, tenant: u8) -> GatewayAssignment {
    GatewayAssignment::new(
        node(id),
        (key(system)).clone(),
        fixture_gateway_public(&(key(system))),
        vec![network("alpha")],
        vec![TenantKeyAssignment::new(network("alpha"), key(tenant))],
    )
    .unwrap()
}

fn management(generation: u64) -> ManagementConfig {
    ManagementConfig::new(
        node("management"),
        config(generation),
        vec![
            assignment("gateway-a", 101, 102),
            assignment("gateway-b", 103, 104),
        ],
    )
    .unwrap()
}

#[test]
fn projection_keeps_global_denies_and_direct_grants_without_unrelated_policy() {
    let projection = management(7).project_for(&node("gateway-a")).unwrap();
    assert_eq!(projection.management_id(), &node("management"));
    assert_eq!(projection.recipient(), &node("gateway-a"));
    assert_eq!(projection.generation(), 7);
    assert_eq!(projection.config().generation(), 7);
    let retained: Vec<_> = projection
        .config()
        .networks()
        .iter()
        .map(|value| value.id().as_str())
        .collect();
    assert_eq!(retained, ["alpha", "beta"]);
    assert_eq!(projection.assignment().networks(), &[network("alpha")]);
    assert_eq!(
        projection.decision(&endpoint("alpha", "first"), &endpoint("alpha", "second")),
        Action::Deny
    );
    assert_eq!(
        projection.decision(&endpoint("alpha", "first"), &endpoint("beta", "first")),
        Action::Deny
    );
    assert_eq!(
        projection.decision(&endpoint("alpha", "second"), &endpoint("beta", "second")),
        Action::Allow
    );
    assert_eq!(
        projection.decision(&endpoint("beta", "second"), &endpoint("alpha", "second")),
        Action::Deny
    );
    assert_eq!(
        projection.decision(&endpoint("beta", "first"), &endpoint("beta", "second")),
        Action::Deny,
        "remote metadata alone does not assign work"
    );
    assert_eq!(
        projection.decision(&endpoint("beta", "first"), &endpoint("unrelated", "first")),
        Action::Deny
    );
    assert_eq!(
        projection.decision(&endpoint("alpha", "absent"), &endpoint("beta", "second")),
        Action::Deny
    );
}

#[test]
fn recipients_share_public_device_policy_but_have_distinct_server_keys() {
    let global = management(9);
    let first = global.project_for(&node("gateway-a")).unwrap();
    let second = global.project_for(&node("gateway-b")).unwrap();
    assert_eq!(first.config(), second.config());
    assert_eq!(first.assignment().service_public_key(), &key(101));
    assert_eq!(second.assignment().service_public_key(), &key(103));
    assert_eq!(first.assignment().tenants()[0].network(), &network("alpha"));
    assert_eq!(first.assignment().tenants()[0].public_key(), &key(102));
    assert_eq!(second.assignment().tenants()[0].public_key(), &key(104));
    let encoded = first.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["assignment"]["recipient"], "gateway-a");
    assert_eq!(
        value["assignment"]["tenants"][0]["public_key"],
        serde_json::json!(vec![102_u8; 32])
    );
    assert!(!encoded.contains("gateway-b"));
    for forbidden in [
        "private_key",
        "credential",
        "password",
        "token",
        "observed",
        "counters",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn projection_target_checks_are_metadata_pins_and_reject_mismatch() {
    let projection = management(1).project_for(&node("gateway-a")).unwrap();
    assert!(
        projection
            .validate_target(&node("management"), &node("gateway-a"))
            .is_ok()
    );
    assert!(
        projection
            .validate_target(&node("other-management"), &node("gateway-a"))
            .is_err()
    );
    assert!(
        projection
            .validate_target(&node("management"), &node("gateway-b"))
            .is_err()
    );
    assert!(management(1).project_for(&node("absent")).is_err());
}

#[test]
fn assignment_scope_and_local_contexts_are_unique_and_bounded_by_membership() {
    assert!(
        GatewayAssignment::new(
            node("gateway-a"),
            (key(1)).clone(),
            fixture_gateway_public(&(key(1))),
            vec![network("alpha"), network("alpha")],
            vec![]
        )
        .is_err()
    );
    assert!(
        GatewayAssignment::new(
            node("gateway-a"),
            (key(1)).clone(),
            fixture_gateway_public(&(key(1))),
            vec![network("alpha")],
            vec![TenantKeyAssignment::new(network("beta"), key(2))]
        )
        .is_err()
    );
    assert!(
        GatewayAssignment::new(
            node("gateway-a"),
            (key(1)).clone(),
            fixture_gateway_public(&(key(1))),
            vec![network("alpha")],
            vec![
                TenantKeyAssignment::new(network("alpha"), key(2)),
                TenantKeyAssignment::new(network("alpha"), key(3))
            ]
        )
        .is_err()
    );
    assert!(
        ManagementConfig::new(
            node("management"),
            config(1),
            vec![
                GatewayAssignment::new(
                    node("gateway-a"),
                    (key(1)).clone(),
                    fixture_gateway_public(&(key(1))),
                    vec![network("absent")],
                    vec![]
                )
                .unwrap()
            ]
        )
        .is_err()
    );
    assert!(
        ManagementConfig::new(
            node("management"),
            config(1),
            vec![
                assignment("gateway-a", 101, 102),
                assignment("gateway-a", 103, 104)
            ]
        )
        .is_err()
    );
}

#[test]
fn advertised_context_keys_cannot_be_reused_within_or_across_gateways() {
    assert!(
        GatewayAssignment::new(
            node("gateway-a"),
            (key(1)).clone(),
            fixture_gateway_public(&(key(1))),
            vec![network("alpha")],
            vec![TenantKeyAssignment::new(network("alpha"), key(1))]
        )
        .is_err()
    );
    for second in [
        assignment("gateway-b", 101, 104),
        assignment("gateway-b", 103, 102),
        assignment("gateway-b", 102, 104),
        assignment("gateway-b", 103, 101),
    ] {
        assert!(
            ManagementConfig::new(
                node("management"),
                config(1),
                vec![assignment("gateway-a", 101, 102), second]
            )
            .is_err()
        );
    }
    for candidate in [
        assignment("gateway-a", 11, 102),
        assignment("gateway-a", 101, 11),
    ] {
        assert!(
            ManagementConfig::new(node("management"), config(1), vec![candidate]).is_err(),
            "device key cannot also identify a gateway context"
        );
    }
}

#[test]
fn transit_scope_does_not_require_local_tenant_keys_and_empty_scope_has_no_policy() {
    let assignment = GatewayAssignment::new(
        node("transit"),
        (key(101)).clone(),
        fixture_gateway_public(&(key(101))),
        vec![network("alpha")],
        vec![],
    )
    .unwrap();
    let projection = ManagementConfig::new(node("management"), config(1), vec![assignment])
        .unwrap()
        .project_for(&node("transit"))
        .unwrap();
    assert!(projection.assignment().tenants().is_empty());
    assert_eq!(
        projection.decision(&endpoint("alpha", "second"), &endpoint("beta", "second")),
        Action::Allow
    );
    let assignment = GatewayAssignment::new(
        node("empty"),
        (key(101)).clone(),
        fixture_gateway_public(&(key(101))),
        vec![],
        vec![],
    )
    .unwrap();
    let projection = ManagementConfig::new(node("management"), config(1), vec![assignment])
        .unwrap()
        .project_for(&node("empty"))
        .unwrap();
    assert!(projection.config().networks().is_empty());
    assert_eq!(
        projection.decision(&endpoint("alpha", "second"), &endpoint("beta", "second")),
        Action::Deny
    );
}

fn hand_authored_projection() -> String {
    let system = vec![101_u8; 32];
    let gateway = vec![103_u8; 32];
    let tenant = vec![102_u8; 32];
    let device = vec![11_u8; 32];
    // This fixture is independent of all production encoders/projectors.
    format!(
        r#"{{"projection_version":1,"management_id":"management","assignment":{{"recipient":"gateway-a","traffic":"entry","service_public_key":{system:?},"gateway_public_key":{gateway:?},"networks":["alpha"],"tenants":[{{"network":"alpha","public_key":{tenant:?}}}]}},"config":{{"schema_version":1,"generation":17,"networks":[{{"id":"alpha","devices":[{{"id":"first","public_key":{device:?},"addresses":["10.1.0.1"]}}]}}],"policy":{{"global_rules":[],"local_rules":[{{"source":{{"network":"alpha","device":"first"}},"destination":{{"network":"alpha","device":"first"}},"action":"allow"}}],"grants":[]}}}}}}"#
    )
}

#[test]
fn independent_wire_fixture_preserves_revision_scope_and_explicit_policy() {
    let projection = GatewayProjection::from_json(&hand_authored_projection()).unwrap();
    assert_eq!(projection.generation(), 17);
    assert_eq!(projection.recipient(), &node("gateway-a"));
    assert_eq!(
        projection.decision(&endpoint("alpha", "first"), &endpoint("alpha", "first")),
        Action::Allow
    );
    assert_eq!(
        projection.decision(&endpoint("alpha", "first"), &endpoint("alpha", "absent")),
        Action::Deny
    );
    assert_eq!(
        GatewayProjection::from_json(&projection.to_json().unwrap())
            .unwrap()
            .config(),
        projection.config()
    );
}

#[test]
fn projection_decoder_rejects_ambiguous_unknown_and_unrelated_data() {
    let valid = hand_authored_projection();
    let cases = [
        valid.replacen("\"projection_version\":1", "\"projection_version\":2", 1),
        valid.replacen(
            "\"management_id\":\"management\"",
            "\"management_id\":\"management\",\"management_id\":\"other\"",
            1,
        ),
        valid.replacen(
            "\"recipient\":\"gateway-a\"",
            "\"recipient\":\"gateway-a\",\"recipient\":\"gateway-b\"",
            1,
        ),
        valid.replacen(
            "\"networks\":[\"alpha\"]",
            "\"networks\":[\"alpha\",\"alpha\"]",
            1,
        ),
        valid.replacen(
            "\"network\":\"alpha\",\"public_key\"",
            "\"network\":\"alpha\",\"network\":\"beta\",\"public_key\"",
            1,
        ),
        valid.replacen(
            "\"projection_version\":1",
            "\"projection_version\":1,\"observed_counters\":{\"allow\":true}",
            1,
        ),
        valid.replacen(
            "\"recipient\":\"gateway-a\"",
            "\"recipient\":\"gateway-a\",\"private_key\":[99]",
            1,
        ),
        valid.replacen("\"networks\":[\"alpha\"]", "\"networks\":[\"absent\"]", 1),
        valid.replacen(
            "\"networks\":[{\"id\":\"alpha\"",
            "\"networks\":[{\"id\":\"unrelated\",\"devices\":[]},{\"id\":\"alpha\"",
            1,
        ),
    ];
    for (index, case) in cases.iter().enumerate() {
        assert_ne!(case, &valid);
        assert!(
            GatewayProjection::from_json(case).is_err(),
            "invalid fixture case {index} accepted"
        );
    }
}

#[test]
fn incoming_grants_retain_remote_metadata_without_authorizing_remote_only_flows() {
    let source = Config::new(
        1,
        config(1).networks().to_vec(),
        Policy::new(
            vec![],
            vec![],
            vec![
                grant(("beta", "first"), ("alpha", "first")),
                grant(("unrelated", "first"), ("alpha", "first")),
                grant(("beta", "second"), ("unrelated", "second")),
            ],
        ),
    )
    .unwrap();
    let projection = ManagementConfig::new(
        node("management"),
        source,
        vec![assignment("gateway-a", 101, 102)],
    )
    .unwrap()
    .project_for(&node("gateway-a"))
    .unwrap();
    assert_eq!(projection.config().networks().len(), 3);
    assert_eq!(
        projection.decision(&endpoint("beta", "first"), &endpoint("alpha", "first")),
        Action::Allow
    );
    assert_eq!(
        projection.decision(&endpoint("unrelated", "first"), &endpoint("alpha", "first")),
        Action::Allow
    );
    assert_eq!(
        projection.decision(&endpoint("alpha", "first"), &endpoint("beta", "first")),
        Action::Deny
    );
    assert_eq!(
        projection.config().decision(
            &endpoint("beta", "second"),
            &endpoint("unrelated", "second")
        ),
        Action::Deny,
        "remote-only grant is removed even when its endpoints remain"
    );
    let mut injected: serde_json::Value =
        serde_json::from_str(&projection.to_json().unwrap()).unwrap();
    injected["config"]["policy"]["grants"].as_array_mut().unwrap().push(serde_json::json!({"source":{"network":"beta","device":"second"},"destination":{"network":"unrelated","device":"second"}}));
    assert!(GatewayProjection::from_json(&serde_json::to_string(&injected).unwrap()).is_err());
}

#[test]
fn overlapping_tenant_addresses_and_device_names_do_not_widen_projection_scope() {
    let device = Device::new(
        DeviceId::new("same-device").unwrap(),
        key(11),
        vec!["10.1.0.1".parse().unwrap(), "fd01::1".parse().unwrap()],
    )
    .unwrap();
    let source = Config::new(
        1,
        vec![
            Network::new(network("alpha"), vec![device.clone()]).unwrap(),
            Network::new(network("beta"), vec![device]).unwrap(),
        ],
        Policy::new(
            vec![],
            vec![
                rule(
                    ("alpha", "same-device"),
                    ("alpha", "same-device"),
                    Action::Allow,
                ),
                rule(
                    ("beta", "same-device"),
                    ("beta", "same-device"),
                    Action::Allow,
                ),
            ],
            vec![],
        ),
    )
    .unwrap();
    let projection = ManagementConfig::new(
        node("management"),
        source,
        vec![assignment("gateway-a", 101, 102)],
    )
    .unwrap()
    .project_for(&node("gateway-a"))
    .unwrap();
    assert_eq!(projection.config().networks().len(), 1);
    assert_eq!(
        projection.decision(
            &endpoint("alpha", "same-device"),
            &endpoint("alpha", "same-device")
        ),
        Action::Allow
    );
    assert_eq!(
        projection.decision(
            &endpoint("beta", "same-device"),
            &endpoint("beta", "same-device")
        ),
        Action::Deny
    );
    assert_eq!(
        projection.decision(
            &endpoint("alpha", "same-device"),
            &endpoint("beta", "same-device")
        ),
        Action::Deny
    );
}

fn fixture_gateway_public(service: &wgfeel_core::DevicePublicKey) -> wgfeel_core::DevicePublicKey {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    wgfeel_core::DevicePublicKey::new(bytes).unwrap()
}
