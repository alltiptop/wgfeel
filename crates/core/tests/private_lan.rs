use wgfeel_core::*;
fn net(id: &str) -> NetworkId {
    NetworkId::new(id).unwrap()
}
fn ep(network: &str, id: &str) -> Endpoint {
    Endpoint::new(net(network), DeviceId::new(id).unwrap())
}
fn device(id: &str, key: u8, address: &str) -> Device {
    Device::new(
        DeviceId::new(id).unwrap(),
        DevicePublicKey::new([key; 32]).unwrap(),
        vec![address.parse().unwrap()],
    )
    .unwrap()
}
#[test]
fn private_lan_allows_only_own_devices_and_explicit_denies_still_win() {
    let devices = vec![
        device("phone", 1, "10.77.0.2"),
        device("laptop", 2, "10.77.0.3"),
    ];
    let alpha = Network::new(net("alpha"), devices.clone())
        .unwrap()
        .with_private_lan(true);
    let beta = Network::new(net("beta"), devices)
        .unwrap()
        .with_private_lan(true);
    let config = Config::new(
        1,
        vec![alpha, beta],
        Policy::new(
            vec![Rule::new(
                ep("alpha", "phone"),
                ep("alpha", "laptop"),
                Action::Deny,
            )],
            vec![],
            vec![],
        ),
    )
    .unwrap();
    assert_eq!(
        config.decision(&ep("alpha", "phone"), &ep("alpha", "laptop")),
        Action::Deny
    );
    assert_eq!(
        config.decision(&ep("alpha", "laptop"), &ep("alpha", "phone")),
        Action::Allow
    );
    assert_eq!(
        config.decision(&ep("beta", "phone"), &ep("beta", "laptop")),
        Action::Allow
    );
    assert_eq!(
        config.decision(&ep("alpha", "phone"), &ep("beta", "laptop")),
        Action::Deny
    );
    assert_eq!(
        config
            .resolve_destination(&ep("alpha", "phone"), "10.77.0.3".parse().unwrap())
            .unwrap(),
        ep("alpha", "laptop")
    );
    assert_eq!(
        Config::from_json(&config.to_json().unwrap()).unwrap(),
        config
    );
}
#[test]
fn device_home_and_private_network_policy_survive_device_changes() {
    let network = Network::new(
        net("home"),
        vec![device("phone", 1, "10.77.0.2").with_gateway(Some(NodeId::new("one").unwrap()))],
    )
    .unwrap()
    .with_private_lan(true);
    let changed = network
        .with_devices(vec![
            device("laptop", 2, "10.77.0.3").with_gateway(Some(NodeId::new("two").unwrap())),
        ])
        .unwrap();
    assert!(changed.private_lan());
    let config = Config::new(1, vec![changed], Policy::new(vec![], vec![], vec![])).unwrap();
    let restored = Config::from_json(&config.to_json().unwrap()).unwrap();
    assert_eq!(
        restored.networks()[0].devices()[0].gateway(),
        Some(&NodeId::new("two").unwrap())
    );
}
