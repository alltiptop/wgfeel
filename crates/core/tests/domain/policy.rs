use super::{device, distinct_networks, endpoint, local_network, network, policy, rule};
use wgfeel_core::{Action, Config, DomainError, Grant, MAX_POLICY_RULES, Policy};

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
