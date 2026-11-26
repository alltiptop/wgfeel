use std::net::IpAddr;
use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, Grant, Network, NetworkId, Policy,
    RouteError, Rule,
};

fn endpoint(network: &str, device: &str) -> Endpoint {
    Endpoint::new(
        NetworkId::new(network).unwrap(),
        DeviceId::new(device).unwrap(),
    )
}

fn config(grants: Vec<Grant>, global: Vec<Rule>) -> Config {
    let networks = [("alpha", 1), ("beta", 2), ("gamma", 2), ("isolated", 1)]
        .into_iter()
        .enumerate()
        .map(|(index, (name, subnet))| {
            Network::new(
                NetworkId::new(name).unwrap(),
                ["first", "second"]
                    .into_iter()
                    .enumerate()
                    .map(|(host, name)| {
                        Device::new(
                            DeviceId::new(name).unwrap(),
                            DevicePublicKey::new([(index * 2 + host + 1) as u8; 32]).unwrap(),
                            vec![
                                format!("10.{subnet}.0.{}", host + 1).parse().unwrap(),
                                format!("fd00:{subnet}::{}", host + 1).parse().unwrap(),
                            ],
                        )
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    Config::new(1, networks, Policy::new(global, vec![], grants)).unwrap()
}

#[test]
fn same_network_addresses_resolve_without_cross_tenant_aliases_or_permission() {
    let config = config(vec![], vec![]);
    for (network, ip) in [
        ("alpha", "10.1.0.2"),
        ("alpha", "fd00:1::2"),
        ("isolated", "10.1.0.2"),
        ("isolated", "fd00:1::2"),
    ] {
        let source = endpoint(network, "first");
        let destination = config
            .resolve_destination(&source, ip.parse().unwrap())
            .unwrap();
        assert_eq!(destination, endpoint(network, "second"));
        assert_eq!(config.decision(&source, &destination), Action::Deny);
    }
}

#[test]
fn unknown_source_precedes_destination_lookup_and_unknown_destination_fails_closed() {
    let config = config(vec![], vec![]);
    for source in [endpoint("missing", "first"), endpoint("alpha", "missing")] {
        assert_eq!(
            config.resolve_destination(&source, "10.1.0.2".parse().unwrap()),
            Err(RouteError::UnknownSource)
        );
    }
    for ip in ["10.2.0.1", "fd00:2::1", "203.0.113.1"] {
        assert_eq!(
            config.resolve_destination(&endpoint("alpha", "first"), ip.parse().unwrap()),
            Err(RouteError::UnknownDestination)
        );
    }
}

#[test]
fn only_exact_directional_grants_resolve_remote_addresses() {
    let config = config(
        vec![Grant::new(
            endpoint("alpha", "first"),
            endpoint("beta", "second"),
        )],
        vec![],
    );
    for ip in ["10.2.0.2", "fd00:2::2"] {
        assert_eq!(
            config.resolve_destination(&endpoint("alpha", "first"), ip.parse().unwrap()),
            Ok(endpoint("beta", "second"))
        );
        assert_eq!(
            config.resolve_destination(&endpoint("alpha", "second"), ip.parse().unwrap()),
            Err(RouteError::UnknownDestination)
        );
    }
    assert_eq!(
        config.resolve_destination(&endpoint("beta", "second"), "10.1.0.1".parse().unwrap()),
        Err(RouteError::UnknownDestination)
    );
}

#[test]
fn duplicate_grants_to_same_endpoint_are_one_candidate_and_deny_still_applies() {
    let source = endpoint("alpha", "first");
    let destination = endpoint("beta", "first");
    let config = config(
        vec![Grant::new(source.clone(), destination.clone()); 2],
        vec![Rule::new(source.clone(), destination.clone(), Action::Deny)],
    );
    assert_eq!(
        config.resolve_destination(&source, "10.2.0.1".parse().unwrap()),
        Ok(destination.clone())
    );
    assert_eq!(config.decision(&source, &destination), Action::Deny);
}

#[test]
fn overlapping_remote_grants_are_ambiguous_even_when_one_candidate_is_denied() {
    let source = endpoint("alpha", "first");
    let config = config(
        vec![
            Grant::new(source.clone(), endpoint("beta", "first")),
            Grant::new(source.clone(), endpoint("gamma", "first")),
        ],
        vec![Rule::new(
            source.clone(),
            endpoint("beta", "first"),
            Action::Deny,
        )],
    );
    for ip in ["10.2.0.1", "fd00:2::1"] {
        assert_eq!(
            config.resolve_destination(&source, ip.parse::<IpAddr>().unwrap()),
            Err(RouteError::AmbiguousDestination)
        );
    }
}
