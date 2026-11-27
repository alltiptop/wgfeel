use super::{device, device_id, endpoint, key, network, network_id, policy};
use std::net::IpAddr;
use wgfeel_core::{Action, Config, Device, DomainError, MAX_DEVICES, MAX_NETWORKS, Network};

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
fn directed_broadcast_reserves_only_the_two_subnet_boundaries() {
    for address in ["10.203.0.0", "10.203.255.255"] {
        assert_eq!(
            Device::new(device_id("pc"), key(1), vec![address.parse().unwrap()]),
            Err(DomainError::InvalidAddress)
        );
    }
    for address in ["10.203.1.0", "10.203.0.255"] {
        let pc = device("pc", 1, &[address]);
        assert_eq!(pc.internal_ipv4(), Some(address.parse().unwrap()));
    }
}

#[test]
fn worker_registration_changes_only_when_worker_configuration_changes() {
    let pc = device("pc", 1, &["10.20.0.2"]);
    for broadcast in [None, Some(false), Some(true)] {
        assert!(pc.same_worker_registration(&pc.clone().with_broadcast(broadcast)));
    }
    for changed in [
        device("phone", 1, &["10.20.0.2"]),
        device("pc", 2, &["10.20.0.2"]),
        device("pc", 1, &["10.20.0.3"]),
        pc.clone()
            .with_gateway(Some(wgfeel_core::NodeId::new("entry").unwrap())),
        pc.clone().with_hostname(Some("desktop".into())).unwrap(),
    ] {
        assert!(!pc.same_worker_registration(&changed));
    }
}
