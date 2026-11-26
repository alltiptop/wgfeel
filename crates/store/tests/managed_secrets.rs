use std::{fs, os::unix::fs::PermissionsExt};
use wgfeel_core::*;
use wgfeel_store::*;
#[test]
fn managed_device_and_gateway_keys_survive_restart_without_public_projection_leakage() {
    let path = std::env::temp_dir().join(format!("wgfeel-managed-secrets-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let user = ClientId::new("alice").unwrap();
    let network = NetworkId::new("home").unwrap();
    let id = DeviceId::new("phone").unwrap();
    let node = NodeId::new("node").unwrap();
    let config = Config::new(
        1,
        vec![
            Network::new(
                network.clone(),
                vec![
                    Device::new(
                        id.clone(),
                        DevicePublicKey::new([11; 32]).unwrap(),
                        vec!["10.77.0.2".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
            .with_private_lan(true),
        ],
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let assignment = GatewayAssignment::new(
        node.clone(),
        (DevicePublicKey::new([21; 32]).unwrap()).clone(),
        wgfeel_test_support::fixture_gateway_public(&(DevicePublicKey::new([21; 32]).unwrap())),
        vec![network.clone()],
        vec![TenantKeyAssignment::new(
            network.clone(),
            DevicePublicKey::new([31; 32]).unwrap(),
        )],
    )
    .unwrap();
    let document = ManagementDocument::new(
        ManagementConfig::new(NodeId::new("management").unwrap(), config, vec![assignment])
            .unwrap(),
        vec![
            Client::new(
                user.clone(),
                vec![network.clone()],
                vec![ClientDevice::new(
                    id.clone(),
                    DeviceMetadata::new(Some("Phone".into()), None).unwrap(),
                )],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let mut secrets = ManagementSecrets::default();
    secrets
        .insert_device(
            user.clone(),
            id.clone(),
            DevicePrivateKey::new([111; 32]).unwrap(),
        )
        .unwrap();
    secrets
        .insert_tenant(
            node.clone(),
            network.clone(),
            TenantPrivateKey::new([131; 32]).unwrap(),
        )
        .unwrap();
    let mut store = ManagementStore::initialize(&path.join("management")).unwrap();
    store
        .commit_with_secrets(
            &document,
            &wgfeel_test_support::fixture_node_keys([141; 32]),
            &AdminCredential::new([151; 32]).unwrap(),
            &secrets,
            None,
        )
        .unwrap();
    drop(store);
    let state = ManagementStore::open(&path.join("management"))
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        state.secrets().device(&user, &id).unwrap().expose_bytes(),
        &[111; 32]
    );
    assert_eq!(
        state
            .secrets()
            .tenant(&node, &network)
            .unwrap()
            .expose_bytes(),
        &[131; 32]
    );
    assert!(!state.document().to_json().unwrap().contains("private_key"));
    assert!(!format!("{state:?}").contains("131, 131"));
    let projection = state.document().routing().project_mesh_for(&node).unwrap();
    let delivery = state.delivery(&projection).unwrap();
    let decoded = GatewayDelivery::decode(&delivery).unwrap();
    assert_eq!(decoded.projection(), &projection);
    assert_eq!(
        decoded.keys().private_key(&network).unwrap().expose_bytes(),
        &[131; 32]
    );
    assert!(!std::str::from_utf8(&delivery).unwrap().contains("111,111"));
    fs::remove_dir_all(path).unwrap();
}
