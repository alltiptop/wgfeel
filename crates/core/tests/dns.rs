use wgfeel_core::*;
fn device(id: &str, key: u8, ip: &str, name: &str) -> Device {
    Device::new(
        DeviceId::new(id).unwrap(),
        DevicePublicKey::new([key; 32]).unwrap(),
        vec![ip.parse().unwrap()],
    )
    .unwrap()
    .with_hostname(Some(name.into()))
    .unwrap()
}
#[test]
fn dns_labels_are_scoped_and_reserved_service_addresses_cannot_be_devices() {
    let a = device("a", 1, "10.203.0.2", "pc");
    let b = device("b", 2, "10.203.0.3", "pc");
    assert_eq!(
        Network::new(NetworkId::new("a").unwrap(), vec![a.clone(), b.clone()]),
        Err(DomainError::DuplicateHostname)
    );
    let networks = [a.clone(), b]
        .into_iter()
        .enumerate()
        .map(|(index, d)| {
            Network::new(NetworkId::new(&format!("net{index}")).unwrap(), vec![d]).unwrap()
        })
        .collect();
    let config = Config::new(1, networks, Policy::new(vec![], vec![], vec![])).unwrap();
    assert_eq!(
        Config::from_json(&config.to_json().unwrap()).unwrap(),
        config
    );
    for address in ["10.203.0.1", "fd77:77::1"] {
        assert_eq!(
            Device::new(
                DeviceId::new("reserved").unwrap(),
                DevicePublicKey::new([3; 32]).unwrap(),
                vec![address.parse().unwrap()]
            ),
            Err(DomainError::InvalidAddress)
        );
    }
    for name in [
        "",
        "PC",
        "pc.feel.internal",
        "-pc",
        "pc-",
        "pc\nfoo",
        "привет",
    ] {
        assert_eq!(
            a.clone().with_hostname(Some(name.into())),
            Err(DomainError::InvalidHostname)
        );
    }
}
