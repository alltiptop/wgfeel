use std::net::IpAddr;

use wgfeel_core::{
    Action, AdminCredential, Config, Device, DeviceId, DevicePublicKey, DomainError, Endpoint,
    Grant, InvitationToken, MAX_CONFIG_BYTES, MAX_DEVICES, MAX_NETWORKS, MAX_POLICY_RULES, Network,
    NetworkId, NodeId, Policy, Rule, SCHEMA_VERSION, ServicePrivateKey, TenantPrivateKey,
};

fn network_id(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}

fn device_id(value: &str) -> DeviceId {
    DeviceId::new(value).unwrap()
}

fn key(value: u16) -> DevicePublicKey {
    let mut bytes = [7; 32];
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    DevicePublicKey::new(bytes).unwrap()
}

fn device(name: &str, public_key: u16, addresses: &[&str]) -> Device {
    Device::new(
        device_id(name),
        key(public_key),
        addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect(),
    )
    .unwrap()
}

fn network(name: &str, devices: Vec<Device>) -> Network {
    Network::new(network_id(name), devices).unwrap()
}

fn endpoint(network: &str, device: &str) -> Endpoint {
    Endpoint::new(network_id(network), device_id(device))
}

fn rule(source: &Endpoint, destination: &Endpoint, action: Action) -> Rule {
    Rule::new(source.clone(), destination.clone(), action)
}

fn policy() -> Policy {
    Policy::new(vec![], vec![], vec![])
}

fn local_network() -> Network {
    network(
        "alice",
        vec![
            device("laptop", 1, &["10.20.0.2", "fd20::2"]),
            device("phone", 2, &["10.20.0.3", "fd20::3"]),
        ],
    )
}

fn distinct_networks() -> Vec<Network> {
    vec![
        local_network(),
        network("bob", vec![device("laptop", 3, &["10.21.0.2", "fd21::2"])]),
    ]
}

fn empty_json() -> &'static str {
    r#"{"schema_version":1,"generation":1,"networks":[],"policy":{"global_rules":[],"local_rules":[],"grants":[]}}"#
}

fn populated_json() -> String {
    let bytes = ["7"; 32].join(",");
    format!(
        r#"{{"schema_version":1,"generation":4,"networks":[{{"id":"alice","devices":[{{"id":"laptop","public_key":[{bytes}],"addresses":["10.20.0.2","fd20::2"]}}]}}],"policy":{{"global_rules":[],"local_rules":[],"grants":[]}}}}"#
    )
}

// Independent schema fixture: do not use the production serializer here.
fn policy_json() -> String {
    let alice_key = ["7"; 32].join(",");
    let phone_key = ["8"; 32].join(",");
    let bob_key = ["9"; 32].join(",");
    format!(
        r#"{{"schema_version":1,"generation":8,"networks":[{{"id":"alice","devices":[{{"id":"laptop","public_key":[{alice_key}],"addresses":["10.20.0.2","fd20::2"]}},{{"id":"phone","public_key":[{phone_key}],"addresses":["10.20.0.3","fd20::3"]}}]}},{{"id":"bob","devices":[{{"id":"laptop","public_key":[{bob_key}],"addresses":["10.21.0.2","fd21::2"]}}]}}],"policy":{{"global_rules":[{{"source":{{"network":"alice","device":"laptop"}},"destination":{{"network":"bob","device":"laptop"}},"action":"deny"}}],"local_rules":[{{"source":{{"network":"alice","device":"laptop"}},"destination":{{"network":"alice","device":"phone"}},"action":"allow"}}],"grants":[{{"source":{{"network":"alice","device":"laptop"}},"destination":{{"network":"bob","device":"laptop"}}}}]}}}}"#
    )
}

#[test]
fn identifiers_accept_bounded_ascii_without_normalization() {
    for value in ["a", "A_9-", &"z".repeat(64)] {
        assert_eq!(NetworkId::new(value).unwrap().as_str(), value);
        assert_eq!(DeviceId::new(value).unwrap().as_str(), value);
        assert_eq!(NodeId::new(value).unwrap().as_str(), value);
    }
    assert_ne!(network_id("Alice"), network_id("alice"));
}

#[test]
fn identifiers_reject_empty_oversized_and_ambiguous_input() {
    for value in [
        "",
        " alice",
        "alice ",
        "a/b",
        "a.b",
        "a:b",
        "a\n",
        "сеть",
        &"a".repeat(65),
    ] {
        assert_eq!(
            NetworkId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
        assert_eq!(
            DeviceId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
        assert_eq!(
            NodeId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
    }
}

#[test]
fn public_key_preserves_bytes_and_rejects_zero() {
    assert_eq!(
        DevicePublicKey::new([42; 32]).unwrap().as_bytes(),
        &[42; 32]
    );
    assert_eq!(
        DevicePublicKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
}

#[test]
fn secret_types_preserve_explicit_access_and_redact_debug() {
    let bytes = [83; 32];
    let admin = AdminCredential::new(bytes).unwrap();
    let invitation = InvitationToken::new(bytes).unwrap();
    let node = ServicePrivateKey::new(bytes).unwrap();
    let tenant = TenantPrivateKey::new(bytes).unwrap();
    assert_eq!(admin.expose_bytes(), &bytes);
    assert_eq!(invitation.expose_bytes(), &bytes);
    assert_eq!(node.expose_bytes(), &bytes);
    assert_eq!(tenant.expose_bytes(), &bytes);
    for (name, debug) in [
        ("AdminCredential", format!("{admin:?}")),
        ("InvitationToken", format!("{invitation:?}")),
        ("ServicePrivateKey", format!("{node:?}")),
        ("TenantPrivateKey", format!("{tenant:?}")),
    ] {
        assert!(debug.contains(name), "missing type name: {debug}");
        assert!(
            debug.contains("[REDACTED]"),
            "missing redaction marker: {debug}"
        );
        assert!(!debug.contains("83"), "secret bytes in Debug: {debug}");
        assert!(
            !debug.contains("5353"),
            "hex secret bytes in Debug: {debug}"
        );
    }
    assert_eq!(
        AdminCredential::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        InvitationToken::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        ServicePrivateKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        TenantPrivateKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
}

#[test]
fn devices_accept_ipv4_ipv6_or_one_of_each() {
    for addresses in [
        vec!["10.20.0.2"],
        vec!["fd20::2"],
        vec!["10.20.0.2", "fd20::2"],
    ] {
        device("laptop", 1, &addresses);
    }
}

#[test]
fn devices_reject_empty_and_duplicate_address_families() {
    for addresses in [
        vec![],
        vec!["10.20.0.2", "10.20.0.2"],
        vec!["10.20.0.2", "10.20.0.3"],
        vec!["fd20::2", "fd20::3"],
        vec!["10.20.0.2", "fd20::2", "fd20::3"],
    ] {
        assert_eq!(
            Device::new(
                device_id("laptop"),
                key(1),
                addresses
                    .iter()
                    .map(|value| value.parse().unwrap())
                    .collect()
            )
            .unwrap_err(),
            DomainError::InvalidAddressCount
        );
    }
}

#[test]
fn devices_reject_nonunicast_loopback_and_mapped_addresses() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "127.12.1.2",
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
        "::ffff:10.20.0.2",
    ] {
        assert_eq!(
            Device::new(device_id("laptop"), key(1), vec![address.parse().unwrap()]).unwrap_err(),
            DomainError::InvalidAddress,
            "accepted invalid device address {address}"
        );
    }
}

#[test]
fn duplicate_device_identity_is_rejected_inside_one_network() {
    assert_eq!(
        Network::new(
            network_id("alice"),
            vec![
                device("laptop", 1, &["10.20.0.2"]),
                device("laptop", 2, &["10.20.0.3"])
            ]
        )
        .unwrap_err(),
        DomainError::DuplicateDeviceId
    );
}

#[test]
fn duplicate_device_key_is_rejected_inside_one_network() {
    assert_eq!(
        Network::new(
            network_id("alice"),
            vec![
                device("laptop", 1, &["10.20.0.2"]),
                device("phone", 1, &["10.20.0.3"])
            ]
        )
        .unwrap_err(),
        DomainError::DuplicateDeviceKey
    );
}

#[test]
fn duplicate_ipv4_or_ipv6_is_rejected_inside_one_network() {
    for addresses in [
        (vec!["10.20.0.2", "fd20::2"], vec!["10.20.0.2", "fd20::3"]),
        (vec!["10.20.0.2", "fd20::2"], vec!["10.20.0.3", "fd20::2"]),
    ] {
        assert_eq!(
            Network::new(
                network_id("alice"),
                vec![
                    device("laptop", 1, &addresses.0),
                    device("phone", 2, &addresses.1)
                ]
            )
            .unwrap_err(),
            DomainError::DuplicateDeviceAddress
        );
    }
}

#[test]
fn separate_networks_allow_equal_ids_keys_and_ipv4_ipv6() {
    let devices = || vec![device("laptop", 1, &["10.20.0.2", "fd20::2"])];
    let config = Config::new(
        1,
        vec![network("alice", devices()), network("bob", devices())],
        policy(),
    )
    .unwrap();
    assert_eq!(config.networks().len(), 2);
    assert_eq!(
        config.decision(&endpoint("alice", "laptop"), &endpoint("bob", "laptop")),
        Action::Deny
    );
}

#[test]
fn duplicate_network_id_is_rejected() {
    assert_eq!(
        Config::new(
            1,
            vec![network("alice", vec![]), network("alice", vec![])],
            policy()
        )
        .unwrap_err(),
        DomainError::DuplicateNetworkId
    );
}

#[test]
fn empty_configuration_and_empty_network_are_valid() {
    assert_eq!(Config::new(1, vec![], policy()).unwrap().generation(), 1);
    Config::new(1, vec![network("alice", vec![])], policy()).unwrap();
}

#[test]
fn generations_are_nonzero_and_successors_strictly_increase() {
    assert_eq!(
        Config::new(0, vec![], policy()).unwrap_err(),
        DomainError::InvalidGeneration
    );
    let current = Config::new(4, vec![], policy()).unwrap();
    for generation in [1, 3, 4] {
        let candidate = Config::new(generation, vec![], policy()).unwrap();
        assert_eq!(
            current.validate_successor(&candidate),
            Err(DomainError::GenerationNotIncreasing)
        );
    }
    current
        .validate_successor(&Config::new(5, vec![], policy()).unwrap())
        .unwrap();
    current
        .validate_successor(&Config::new(u64::MAX, vec![], policy()).unwrap())
        .unwrap();
    assert_eq!(
        Config::new(u64::MAX, vec![], policy())
            .unwrap()
            .validate_successor(&current),
        Err(DomainError::GenerationNotIncreasing)
    );
}

#[test]
fn configured_network_count_has_an_inclusive_bound() {
    assert_eq!(MAX_NETWORKS, 150);
    let networks = |count| {
        (0..count)
            .map(|index| network(&format!("network-{index}"), vec![]))
            .collect()
    };
    Config::new(1, networks(MAX_NETWORKS), policy()).unwrap();
    assert_eq!(
        Config::new(1, networks(MAX_NETWORKS + 1), policy()).unwrap_err(),
        DomainError::LimitExceeded
    );
}

fn devices(count: usize) -> Vec<Device> {
    (0..count)
        .map(|index| {
            let value = u16::try_from(index + 1).unwrap();
            let address = IpAddr::from([10, 20, value.to_be_bytes()[0], value.to_be_bytes()[1]]);
            Device::new(
                device_id(&format!("device-{index}")),
                key(value),
                vec![address],
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn total_devices_are_bounded_without_an_invented_five_device_limit() {
    assert_eq!(MAX_DEVICES, 750);
    Config::new(1, vec![network("alice", devices(MAX_DEVICES))], policy()).unwrap();
    assert_eq!(
        Config::new(
            1,
            vec![
                network("alice", devices(MAX_DEVICES)),
                network("bob", devices(1))
            ],
            policy()
        )
        .unwrap_err(),
        DomainError::LimitExceeded
    );
}

#[test]
fn total_policy_rules_are_bounded_across_collections() {
    assert_eq!(MAX_POLICY_RULES, 4096);
    let source = endpoint("alice", "laptop");
    let destination = endpoint("alice", "phone");
    let global = vec![rule(&source, &destination, Action::Allow); MAX_POLICY_RULES - 1];
    let local = vec![rule(&source, &destination, Action::Allow)];
    Config::new(
        1,
        vec![local_network()],
        Policy::new(global.clone(), local.clone(), vec![]),
    )
    .unwrap();
    assert_eq!(
        Config::new(
            1,
            vec![local_network()],
            Policy::new(global, [local.clone(), local].concat(), vec![])
        )
        .unwrap_err(),
        DomainError::LimitExceeded
    );
}

#[test]
fn grant_collection_counts_toward_the_total_policy_bound() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("bob", "laptop");
    let global = vec![rule(&source, &destination, Action::Deny)];
    let local = vec![rule(&source, &endpoint("alice", "phone"), Action::Allow)];
    let grants = vec![Grant::new(source, destination); MAX_POLICY_RULES - 2];
    Config::new(
        1,
        distinct_networks(),
        Policy::new(global.clone(), local.clone(), grants.clone()),
    )
    .unwrap();
    let mut over_limit = grants;
    over_limit.push(Grant::new(
        endpoint("alice", "laptop"),
        endpoint("bob", "laptop"),
    ));
    assert_eq!(
        Config::new(
            1,
            distinct_networks(),
            Policy::new(global, local, over_limit)
        )
        .unwrap_err(),
        DomainError::LimitExceeded
    );
}

#[test]
fn all_traffic_requires_explicit_local_permission_or_cross_network_grant() {
    let config = Config::new(1, distinct_networks(), policy()).unwrap();
    let source = endpoint("alice", "laptop");
    assert_eq!(
        config.decision(&source, &endpoint("alice", "phone")),
        Action::Deny
    );
    assert_eq!(
        config.decision(&source, &endpoint("bob", "laptop")),
        Action::Deny
    );
}

#[test]
fn local_allow_is_directional_and_unknown_identities_are_denied() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("alice", "phone");
    let config = Config::new(
        1,
        vec![local_network()],
        Policy::new(
            vec![],
            vec![rule(&source, &destination, Action::Allow)],
            vec![],
        ),
    )
    .unwrap();
    assert_eq!(config.decision(&source, &destination), Action::Allow);
    assert_eq!(config.decision(&destination, &source), Action::Deny);
    assert_eq!(
        config.decision(&source, &endpoint("alice", "absent")),
        Action::Deny
    );
    assert_eq!(
        config.decision(&endpoint("missing", "laptop"), &destination),
        Action::Deny
    );
}

#[test]
fn global_deny_cannot_be_overridden_by_local_or_global_allow_in_any_order() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("alice", "phone");
    for global in [
        vec![
            rule(&source, &destination, Action::Deny),
            rule(&source, &destination, Action::Allow),
        ],
        vec![
            rule(&source, &destination, Action::Allow),
            rule(&source, &destination, Action::Deny),
        ],
    ] {
        let config = Config::new(
            1,
            vec![local_network()],
            Policy::new(
                global,
                vec![rule(&source, &destination, Action::Allow)],
                vec![],
            ),
        )
        .unwrap();
        assert_eq!(config.decision(&source, &destination), Action::Deny);
    }
}

#[test]
fn local_deny_dominates_local_allow_in_any_order() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("alice", "phone");
    for local in [
        vec![
            rule(&source, &destination, Action::Deny),
            rule(&source, &destination, Action::Allow),
        ],
        vec![
            rule(&source, &destination, Action::Allow),
            rule(&source, &destination, Action::Deny),
        ],
    ] {
        let config =
            Config::new(1, vec![local_network()], Policy::new(vec![], local, vec![])).unwrap();
        assert_eq!(config.decision(&source, &destination), Action::Deny);
    }
}

#[test]
fn global_allow_cannot_create_local_permission_or_cross_network_grant() {
    let source = endpoint("alice", "laptop");
    for destination in [endpoint("alice", "phone"), endpoint("bob", "laptop")] {
        let config = Config::new(
            1,
            distinct_networks(),
            Policy::new(
                vec![rule(&source, &destination, Action::Allow)],
                vec![],
                vec![],
            ),
        )
        .unwrap();
        assert_eq!(config.decision(&source, &destination), Action::Deny);
    }
}

#[test]
fn cross_network_grant_is_directional_specific_and_subject_to_global_deny() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("bob", "laptop");
    let grant = Grant::new(source.clone(), destination.clone());
    let config = Config::new(
        1,
        distinct_networks(),
        Policy::new(vec![], vec![], vec![grant.clone()]),
    )
    .unwrap();
    assert_eq!(config.decision(&source, &destination), Action::Allow);
    assert_eq!(config.decision(&destination, &source), Action::Deny);
    assert_eq!(
        config.decision(&endpoint("alice", "phone"), &destination),
        Action::Deny
    );
    let denied = Config::new(
        1,
        distinct_networks(),
        Policy::new(
            vec![rule(&source, &destination, Action::Deny)],
            vec![],
            vec![grant],
        ),
    )
    .unwrap();
    assert_eq!(denied.decision(&source, &destination), Action::Deny);
}

#[test]
fn cross_network_local_rule_is_not_a_grant() {
    assert_eq!(
        Config::new(
            1,
            distinct_networks(),
            Policy::new(
                vec![],
                vec![rule(
                    &endpoint("alice", "laptop"),
                    &endpoint("bob", "laptop"),
                    Action::Allow
                )],
                vec![]
            )
        )
        .unwrap_err(),
        DomainError::CrossNetworkLocalRule
    );
}

#[test]
fn grant_inside_one_network_is_rejected() {
    assert_eq!(
        Config::new(
            1,
            vec![local_network()],
            Policy::new(
                vec![],
                vec![],
                vec![Grant::new(
                    endpoint("alice", "laptop"),
                    endpoint("alice", "phone")
                )]
            )
        )
        .unwrap_err(),
        DomainError::InvalidGrant
    );
}

#[test]
fn every_policy_collection_rejects_unknown_network_or_device_references() {
    let source = endpoint("alice", "laptop");
    for destination in [endpoint("absent", "laptop"), endpoint("alice", "absent")] {
        for policy in [
            Policy::new(
                vec![rule(&source, &destination, Action::Deny)],
                vec![],
                vec![],
            ),
            Policy::new(
                vec![],
                vec![rule(&source, &destination, Action::Allow)],
                vec![],
            ),
            Policy::new(
                vec![],
                vec![],
                vec![Grant::new(source.clone(), destination.clone())],
            ),
        ] {
            assert_eq!(
                Config::new(1, vec![local_network()], policy).unwrap_err(),
                DomainError::InvalidPolicyReference
            );
        }
    }
}

#[test]
fn grants_reject_ipv4_or_ipv6_overlap_anywhere_in_the_selected_networks() {
    for addresses in [vec!["10.20.0.3", "fd21::2"], vec!["10.21.0.2", "fd20::3"]] {
        let networks = vec![
            local_network(),
            network("bob", vec![device("laptop", 3, &addresses)]),
        ];
        let grant = Grant::new(endpoint("alice", "laptop"), endpoint("bob", "laptop"));
        assert_eq!(
            Config::new(1, networks, Policy::new(vec![], vec![], vec![grant])).unwrap_err(),
            DomainError::AmbiguousGrant
        );
    }
}

#[test]
fn schema_one_fixture_and_round_trip_preserve_domain_values() {
    assert_eq!(SCHEMA_VERSION, 1);
    assert_eq!(
        Config::from_json(empty_json()).unwrap(),
        Config::new(1, vec![], policy()).unwrap()
    );
    let config = Config::from_json(&populated_json()).unwrap();
    assert_eq!(config.generation(), 4);
    assert_eq!(config.networks().len(), 1);
    assert_eq!(
        Config::from_json(&config.to_json().unwrap()).unwrap(),
        config
    );
}

#[test]
fn policy_round_trip_preserves_identity_and_deny_precedence() {
    let source = endpoint("alice", "laptop");
    let destination = endpoint("bob", "laptop");
    let config = Config::new(
        9,
        distinct_networks(),
        Policy::new(
            vec![rule(&source, &destination, Action::Deny)],
            vec![],
            vec![Grant::new(source.clone(), destination.clone())],
        ),
    )
    .unwrap();
    let loaded = Config::from_json(&config.to_json().unwrap()).unwrap();
    assert_eq!(loaded, config);
    assert_eq!(loaded.decision(&source, &destination), Action::Deny);
}

#[test]
fn hand_authored_policy_schema_enforces_directional_grants_and_deny_precedence() {
    let source = endpoint("alice", "laptop");
    let local_destination = endpoint("alice", "phone");
    let cross_destination = endpoint("bob", "laptop");
    let json = policy_json();
    let denied = Config::from_json(&json).unwrap();
    assert_eq!(denied.generation(), 8);
    assert_eq!(denied.decision(&source, &local_destination), Action::Allow);
    assert_eq!(denied.decision(&local_destination, &source), Action::Deny);
    assert_eq!(denied.decision(&source, &cross_destination), Action::Deny);
    let granted =
        Config::from_json(&json.replace("\"action\":\"deny\"", "\"action\":\"allow\"")).unwrap();
    assert_eq!(granted.decision(&source, &cross_destination), Action::Allow);
    assert_eq!(granted.decision(&cross_destination, &source), Action::Deny);
    assert_eq!(
        granted.decision(&local_destination, &cross_destination),
        Action::Deny
    );
}

#[test]
fn json_rejects_unknown_actions_and_unknown_grant_fields() {
    let json = policy_json();
    for invalid in [
        json.replace("\"action\":\"deny\"", "\"action\":\"permit\""),
        json.replace("\"grants\":[{", "\"grants\":[{\"unknown\":true,"),
    ] {
        assert_eq!(
            Config::from_json(&invalid).unwrap_err(),
            DomainError::InvalidJson
        );
    }
}

#[test]
fn json_rejects_nested_duplicate_fields() {
    let json = policy_json();
    for invalid in [
        json.replacen("\"id\":\"alice\"", "\"id\":\"alice\",\"id\":\"shadow\"", 1),
        json.replacen(
            "\"id\":\"laptop\"",
            "\"id\":\"laptop\",\"id\":\"shadow\"",
            1,
        ),
        json.replacen(
            "\"network\":\"alice\"",
            "\"network\":\"alice\",\"network\":\"bob\"",
            1,
        ),
        json.replacen(
            "\"action\":\"deny\"",
            "\"action\":\"deny\",\"action\":\"allow\"",
            1,
        ),
        json.replace(
            "\"grants\":[{",
            "\"grants\":[{\"source\":{\"network\":\"bob\",\"device\":\"laptop\"},",
        ),
        json.replace("\"local_rules\":[", "\"global_rules\":[],\"local_rules\":["),
    ] {
        assert_eq!(
            Config::from_json(&invalid).unwrap_err(),
            DomainError::InvalidJson
        );
    }
}

#[test]
fn json_rejects_unsupported_schema_and_zero_generation() {
    for version in [0, 2, 999, u64::from(u32::MAX) + 1, u64::MAX] {
        assert_eq!(
            Config::from_json(&empty_json().replace(
                "\"schema_version\":1",
                &format!("\"schema_version\":{version}")
            ))
            .unwrap_err(),
            DomainError::UnsupportedSchemaVersion
        );
    }
    assert_eq!(
        Config::from_json(&empty_json().replace("\"generation\":1", "\"generation\":0"))
            .unwrap_err(),
        DomainError::InvalidGeneration
    );
}

#[test]
fn schema_version_requires_an_unsigned_64_bit_integer() {
    for version in ["-1", "1.5", "18446744073709551616"] {
        assert_eq!(
            Config::from_json(&empty_json().replace(
                "\"schema_version\":1",
                &format!("\"schema_version\":{version}")
            ))
            .unwrap_err(),
            DomainError::InvalidJson
        );
    }
}

#[test]
fn json_cannot_bypass_identifier_address_or_key_validation() {
    let json = populated_json();
    for (input, error) in [
        (
            json.replace("\"alice\"", "\"../alice\""),
            DomainError::InvalidIdentifier,
        ),
        (
            json.replace("10.20.0.2", "127.0.0.1"),
            DomainError::InvalidAddress,
        ),
        (
            json.replace(&["7"; 32].join(","), &["0"; 32].join(",")),
            DomainError::InvalidKey,
        ),
    ] {
        assert_eq!(Config::from_json(&input).unwrap_err(), error);
    }
}

#[test]
fn json_rejects_unknown_fields_at_each_object_level() {
    let populated = populated_json();
    let source = endpoint("alice", "laptop");
    let destination = endpoint("alice", "phone");
    let with_rule = Config::new(
        1,
        vec![local_network()],
        Policy::new(
            vec![],
            vec![rule(&source, &destination, Action::Allow)],
            vec![],
        ),
    )
    .unwrap()
    .to_json()
    .unwrap();
    for json in [
        empty_json().replacen('{', "{\"private_key\":\"DO_NOT_ECHO\",", 1),
        populated.replace("\"devices\":", "\"unknown\":true,\"devices\":"),
        populated.replace("\"addresses\":", "\"unknown\":true,\"addresses\":"),
        empty_json().replace("\"grants\":", "\"unknown\":true,\"grants\":"),
        with_rule.replace("\"action\":", "\"unknown\":true,\"action\":"),
        with_rule.replace("\"network\":", "\"unknown\":true,\"network\":"),
    ] {
        let error = Config::from_json(&json).unwrap_err();
        assert_eq!(error, DomainError::InvalidJson);
        assert!(!error.to_string().contains("DO_NOT_ECHO"));
        assert!(!format!("{error:?}").contains("DO_NOT_ECHO"));
    }
}

#[test]
fn json_rejects_duplicate_missing_malformed_and_mistyped_fields() {
    for json in [
        "{".to_owned(),
        "null".to_owned(),
        empty_json().replace("\"generation\":1", "\"generation\":1,\"generation\":2"),
        empty_json().replace("\"generation\":1,", ""),
        empty_json().replace("\"generation\":1", "\"generation\":\"1\""),
        empty_json().replace("\"schema_version\":1", "\"schema_version\":\"1\""),
        populated_json().replace("10.20.0.2", "not-an-IP"),
        populated_json().replace(&["7"; 32].join(","), "7,7"),
    ] {
        assert_eq!(
            Config::from_json(&json).unwrap_err(),
            DomainError::InvalidJson
        );
    }
}

#[test]
fn parser_rejects_oversized_input_before_parsing() {
    assert_eq!(MAX_CONFIG_BYTES, 4_194_304);
    assert_eq!(
        Config::from_json(&" ".repeat(MAX_CONFIG_BYTES + 1)).unwrap_err(),
        DomainError::LimitExceeded
    );
}

#[test]
fn errors_have_standard_error_contract_without_input_echo() {
    fn standard_error(error: &dyn std::error::Error) {
        assert!(!error.to_string().is_empty());
    }
    standard_error(&DomainError::InvalidIdentifier);
    standard_error(&DomainError::InvalidJson);
}
