use wgfeel_core::{
    Action, Device, DeviceId, DevicePublicKey, Endpoint, Network, NetworkId, Policy, Rule,
};

#[path = "domain/devices.rs"]
mod devices;
#[path = "domain/identity.rs"]
mod identity;
#[path = "domain/policy.rs"]
mod policy;
#[path = "domain/wire.rs"]
mod wire;

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
