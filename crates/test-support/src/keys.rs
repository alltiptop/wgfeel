//! Deterministic, publicly reproducible key fixtures. Never use in product code.
use wgfeel_core::{DevicePublicKey, GatewayPrivateKey, NodeKeys, ServicePrivateKey};

pub fn fixture_public(bytes: &[u8; 32]) -> DevicePublicKey {
    let private =
        aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, bytes)
            .expect("fixture private key");
    DevicePublicKey::new(
        private
            .compute_public_key()
            .expect("fixture public key")
            .as_ref()
            .try_into()
            .expect("X25519 public key length"),
    )
    .unwrap()
}

// The public seed makes fixture assignments independent of how each test names
// its service-key helper. Production generates both keys independently at random.
fn gateway_seed(service: &DevicePublicKey) -> [u8; 32] {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    bytes
}

pub fn fixture_gateway_public(service: &DevicePublicKey) -> DevicePublicKey {
    fixture_public(&gateway_seed(service))
}

pub fn fixture_node_keys(service: [u8; 32]) -> NodeKeys {
    let gateway = gateway_seed(&fixture_public(&service));
    NodeKeys::new(
        ServicePrivateKey::new(service).unwrap(),
        GatewayPrivateKey::new(gateway).unwrap(),
    )
    .expect("distinct fixture keys")
}

pub fn fixture_projection(
    config: &wgfeel_core::Config,
    node: &wgfeel_core::NodeId,
    keys: &NodeKeys,
    tenants: Vec<wgfeel_core::TenantKeyAssignment>,
) -> wgfeel_core::GatewayProjection {
    let assignment = wgfeel_core::GatewayAssignment::new(
        node.clone(),
        fixture_public(keys.service().expose_bytes()),
        fixture_public(keys.gateway().expose_bytes()),
        config
            .networks()
            .iter()
            .map(|net| net.id().clone())
            .collect(),
        tenants,
    )
    .expect("valid fixture assignment");
    wgfeel_core::ManagementConfig::new(
        wgfeel_core::NodeId::new("main").unwrap(),
        config.clone(),
        vec![assignment],
    )
    .and_then(|routing| routing.project_for(node))
    .expect("valid fixture projection")
}
