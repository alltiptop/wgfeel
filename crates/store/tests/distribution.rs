use std::{fs, os::unix::fs::PermissionsExt};
use wgfeel_core::*;
use wgfeel_store::*;
#[test]
fn authority_pin_and_withdrawal_targets_survive_restart() {
    let directory =
        std::env::temp_dir().join(format!("wgfeel-distribution-store-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let gateway = GatewayAssignment::new(
        NodeId::new("node").unwrap(),
        (DevicePublicKey::new([31; 32]).unwrap()).clone(),
        wgfeel_test_support::fixture_gateway_public(&(DevicePublicKey::new([31; 32]).unwrap())),
        vec![],
        vec![],
    )
    .unwrap()
    .with_endpoint(Some("127.0.0.1:12345".parse().unwrap()))
    .unwrap();
    let routing = ManagementConfig::new(
        NodeId::new("management").unwrap(),
        Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![gateway.clone()],
    )
    .unwrap();
    let document = ManagementDocument::new(routing, vec![]).unwrap();
    let projection = document
        .routing()
        .project_mesh_for(gateway.recipient())
        .unwrap();
    let key = wgfeel_test_support::fixture_node_keys([31; 32]);
    let management_key = DevicePublicKey::new([41; 32]).unwrap();
    let mut local = Store::initialize(&directory.join("gateway")).unwrap();
    local
        .commit_managed_projection(&projection, &key, &LocalTenants::default(), &management_key)
        .unwrap();
    drop(local);
    let local = Store::open(&directory.join("gateway")).unwrap();
    assert_eq!(
        local.load().unwrap().unwrap().management_public_key(),
        Some(&management_key)
    );
    drop(local);
    let mut management = ManagementStore::initialize(&directory.join("management")).unwrap();
    let credential = AdminCredential::new([42; 32]).unwrap();
    management
        .commit(&document, &key, &credential, None)
        .unwrap();
    let removed = document
        .apply_change(
            1,
            &ManagementChange::RemoveGateway {
                gateway: gateway.recipient().clone(),
            },
        )
        .unwrap();
    management
        .commit(&removed, &key, &credential, Some(1))
        .unwrap();
    drop(management);
    let mut management = ManagementStore::open(&directory.join("management")).unwrap();
    assert_eq!(
        management.load().unwrap().unwrap().retired_gateways(),
        std::slice::from_ref(&gateway)
    );
    let recreated = removed
        .apply_change(
            2,
            &ManagementChange::AddGateway {
                assignment: gateway.clone(),
            },
        )
        .unwrap();
    assert!(
        management
            .commit(&recreated, &key, &credential, Some(2))
            .is_err(),
        "re-enrollment must not erase an unacknowledged withdrawal"
    );
    assert_eq!(management.load().unwrap().unwrap().document(), &removed);
    assert!(matches!(
        management.confirm_withdrawal(gateway.recipient(), gateway.service_public_key(), 1),
        Err(StoreError::RevisionConflict)
    ));
    assert!(matches!(
        management.confirm_withdrawal(gateway.recipient(), &management_key, 2),
        Err(StoreError::IdentityChanged)
    ));
    assert_eq!(
        management.load().unwrap().unwrap().retired_gateways().len(),
        1
    );
    management
        .confirm_withdrawal(gateway.recipient(), gateway.service_public_key(), 2)
        .unwrap();
    assert!(
        management
            .load()
            .unwrap()
            .unwrap()
            .retired_gateways()
            .is_empty()
    );
    assert_eq!(management.load().unwrap().unwrap().document(), &removed);
    let mut local = Store::open(&directory.join("gateway")).unwrap();
    let withdrawal = removed.routing().withdraw_for(&gateway).unwrap();
    assert!(matches!(
        local.commit_managed_projection(
            &withdrawal,
            &key,
            &LocalTenants::default(),
            &DevicePublicKey::new([51; 32]).unwrap()
        ),
        Err(StoreError::AuthorityChanged)
    ));
    assert_eq!(local.load().unwrap().unwrap().config().generation(), 1);
    // Ordinary local writes cannot downgrade or implicitly change the pin.
    local
        .commit_projection(
            withdrawal.management_id(),
            &withdrawal,
            withdrawal.recipient(),
            &key,
            &LocalTenants::default(),
        )
        .unwrap();
    local.confirm_delivery().unwrap();
    assert_eq!(
        local.load().unwrap().unwrap().management_public_key(),
        Some(&management_key)
    );
    drop(local);
    drop(management);
    fs::remove_dir_all(directory).unwrap();
}
