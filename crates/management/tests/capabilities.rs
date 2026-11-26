use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, os::unix::fs::PermissionsExt};
use wgfeel_core::*;
use wgfeel_management::{ManagementService, Request};
use wgfeel_store::ManagementStore;

#[test]
fn provisioning_gives_private_keys_only_to_entries_and_assigns_devices_only_there() {
    let root = std::env::temp_dir().join(format!("wgfeel-capabilities-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let document = ManagementDocument::new(
        ManagementConfig::new(
            NodeId::new("main").unwrap(),
            Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![],
        )
        .unwrap(),
        vec![],
    )
    .unwrap();
    let mut store = ManagementStore::initialize(&root.join("state")).unwrap();
    store
        .commit(
            &document,
            &wgfeel_test_support::fixture_node_keys([197; 32]),
            &AdminCredential::new([211; 32]).unwrap(),
            None,
        )
        .unwrap();
    drop(store);
    let mut service = ManagementService::open(&root.join("state")).unwrap();
    let mut revision = 1;
    let mut post = |path: &str, value: serde_json::Value| {
        let body = serde_json::to_vec(&value).unwrap();
        let response = service.handle_local(Request {
            method: "POST",
            target: path,
            authorization: None,
            if_match: Some(&format!("\"{revision}\"")),
            body: &body,
        });
        assert!(
            (200..300).contains(&response.status),
            "HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
        revision += 1;
        let result: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        result["id"].as_str().unwrap().to_owned()
    };
    for (key, mode) in [(31, "entry"), (32, "relay"), (33, "off")] {
        post(
            "/api/v1/gateways",
            serde_json::json!({
                "id": mode, "public_key": STANDARD.encode([key;32]), "gateway_public_key":STANDARD.encode([key+100;32]),
                "endpoint": format!("192.0.2.{key}:51820"), "traffic": mode
            }),
        );
    }
    let user = post("/api/v1/users", serde_json::json!({"name":"Alice"}));
    let device = post(
        &format!("/api/v1/users/{user}/devices"),
        serde_json::json!({"name":"phone"}),
    );
    let exported = service.handle_local(Request {
        method: "GET",
        target: &format!("/api/v1/users/{user}/devices/{device}/config"),
        authorization: None,
        if_match: None,
        body: b"",
    });
    assert_eq!(exported.status, 200);
    let config = std::str::from_utf8(&exported.body).unwrap();
    assert_eq!(
        config
            .lines()
            .filter_map(|line| line.strip_prefix("# Node: "))
            .collect::<Vec<_>>(),
        ["entry"]
    );
    let snapshot = service.delivery_snapshot().unwrap();
    let routing = snapshot.document().routing();
    let network = &routing.config().networks()[0];
    assert_eq!(network.devices()[0].gateway().unwrap().as_str(), "entry");
    for node in routing.assignments() {
        let entry = node.recipient().as_str() == "entry";
        let off = node.recipient().as_str() == "off";
        assert_eq!(node.tenants().is_empty(), !entry);
        assert_eq!(node.networks().is_empty(), off);
        assert_eq!(
            snapshot
                .secrets()
                .tenant(node.recipient(), network.id())
                .is_some(),
            entry
        );
        let projection = routing.project_mesh_for(node.recipient()).unwrap();
        let delivery =
            wgfeel_store::GatewayDelivery::decode(&snapshot.delivery(&projection).unwrap())
                .unwrap();
        assert_eq!(delivery.keys().network_ids().count(), usize::from(entry));
    }
    drop(snapshot);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
