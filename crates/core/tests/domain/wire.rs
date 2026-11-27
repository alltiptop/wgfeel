use super::{device, distinct_networks, endpoint, local_network, network, policy, rule};
use wgfeel_core::{Action, Config, DomainError, Grant, MAX_CONFIG_BYTES, Policy, SCHEMA_VERSION};

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
fn broadcast_policy_round_trips_and_survives_membership_changes() {
    let pc = device("pc", 1, &["10.203.1.7"]);
    let base = network("user", vec![]);
    assert!(base.broadcast());
    assert_eq!(pc.broadcast(), None);
    for (enabled, setting, expected) in [
        (true, None, true),
        (true, Some(false), false),
        (false, None, false),
        (false, Some(true), true),
    ] {
        let net = base
            .clone()
            .with_broadcast(enabled)
            .with_devices(vec![pc.clone().with_broadcast(setting)])
            .unwrap();
        let config = Config::new(1, vec![net], policy()).unwrap();
        let copy = Config::from_json(&config.to_json().unwrap()).unwrap();
        let net = &copy.networks()[0];
        assert_eq!(net.broadcast(), enabled);
        assert_eq!(net.devices()[0].broadcast(), setting);
        assert_eq!(net.effective_broadcast(&net.devices()[0]), expected);
    }
}
