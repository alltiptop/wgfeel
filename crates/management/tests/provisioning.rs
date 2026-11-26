use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, os::unix::fs::PermissionsExt};
use wgfeel_core::*;
use wgfeel_management::{ManagementService, Request, Response};
use wgfeel_store::ManagementStore;
fn get(service: &mut ManagementService, path: &str) -> Response {
    service.handle_local(Request {
        method: "GET",
        target: path,
        authorization: None,
        if_match: None,
        body: b"",
    })
}
fn change(
    service: &mut ManagementService,
    revision: &mut u64,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> String {
    let body = if method == "DELETE" {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let response = service.handle_local(Request {
        method,
        target: path,
        authorization: None,
        if_match: Some(&format!("\"{revision}\"")),
        body: &body,
    });
    assert!(
        (200..300).contains(&response.status),
        "HTTP {}",
        response.status
    );
    *revision += 1;
    assert_eq!(response.generation, Some(*revision));
    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
#[test]
fn private_lan_provisioning_exports_persistent_native_configs_without_leaking_device_keys_to_nodes()
{
    let root = std::env::temp_dir().join(format!("wgfeel-provisioning-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let dual = GatewayAssignment::new(
        NodeId::new("edge-3").unwrap(),
        DevicePublicKey::new([33; 32]).unwrap(),
        DevicePublicKey::new([133; 32]).unwrap(),
        vec![],
        vec![],
    )
    .unwrap()
    .with_hostname(Some("oslo.example".into()))
    .unwrap()
    .with_endpoints(vec![
        "[2001:db8::3]:51820".parse().unwrap(),
        "192.0.2.3:51820".parse().unwrap(),
        "[2001:db8::4]:51821".parse().unwrap(),
    ])
    .unwrap()
    .with_auto_networks(true);
    let document = ManagementDocument::new(
        ManagementConfig::new(
            NodeId::new("management").unwrap(),
            Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![dual],
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
    for (id, key, endpoint) in [
        ("one", 31, "192.0.2.1:51820"),
        ("two", 32, "192.0.2.2:51820"),
    ] {
        change(
            &mut service,
            &mut revision,
            "POST",
            "/api/v1/gateways",
            serde_json::json!({"id":id,"public_key":STANDARD.encode([key;32]),"gateway_public_key":STANDARD.encode([key+100;32]),"endpoint":endpoint}),
        );
    }
    let alice = change(
        &mut service,
        &mut revision,
        "POST",
        "/api/v1/users",
        serde_json::json!({"name":"Alice"}),
    );
    let bob = change(
        &mut service,
        &mut revision,
        "POST",
        "/api/v1/users",
        serde_json::json!({"name":"Bob"}),
    );
    let mut devices = Vec::new();
    for (user, name, gateway, addresses) in [
        (&alice, "phone", "one", vec![]),
        (&alice, "laptop", "two", vec![]),
        (&bob, "phone", "two", vec![]),
        (&alice, "custom", "edge-3", vec!["10.77.0.4"]),
    ] {
        devices.push(change(
            &mut service,
            &mut revision,
            "POST",
            &format!("/api/v1/users/{user}/devices"),
            serde_json::json!({"name":name,"gateway":gateway,"addresses":addresses}),
        ));
    }
    let unique: std::collections::BTreeSet<_> = devices.iter().chain([&alice, &bob]).collect();
    assert_eq!(unique.len(), 6);
    let config_path = format!("/api/v1/users/{alice}/devices/{}/config", devices[0]);
    let exported = get(&mut service, &config_path);
    assert_eq!(exported.status, 200);
    let text = std::str::from_utf8(&exported.body).unwrap();
    assert!(text.contains("[Interface]\nPrivateKey = "));
    assert!(text.contains("Endpoint = 192.0.2.1:51820"));
    assert!(text.contains("Address = 10.203.0.2/32, fd77:77::2/128\n"));
    assert!(text.contains("DNS = 10.203.0.1\n"));
    assert!(text.contains(&format!("# User: Alice ({alice})\n")));
    assert!(text.contains(&format!("# Device: phone ({})\n", devices[0])));
    assert!(text.contains("# available at phone.feel.internal\n"));
    assert!(text.contains("AllowedIPs = 10.203.0.0/16, fd77:77::/64, 10.77.0.4/32\n"));
    assert!(exported.is_config);
    assert_eq!(text.lines().filter(|line| *line == "[Peer]").count(), 3);
    assert!(text.contains("# Node: one\n[Peer]\n"));
    assert!(text.contains("# IPv4\nEndpoint = 192.0.2.1:51820\n"));
    assert!(text.contains("# IPv4\nEndpoint = 192.0.2.2:51820\n"));
    assert!(text.contains("# IPv4\n# Endpoint = 192.0.2.3:51820\n# IPv6\nEndpoint = [2001:db8::3]:51820\n# Endpoint = [2001:db8::4]:51821\n"));
    for (index, address) in [(1, "10.203.0.3/32, fd77:77::3/128"), (3, "10.77.0.4/32")] {
        let response = get(
            &mut service,
            &format!("/api/v1/users/{alice}/devices/{}/config", devices[index]),
        );
        assert_eq!(response.status, 200);
        let config = std::str::from_utf8(&response.body).unwrap();
        assert!(config.contains(&format!("Address = {address}\n")));
        if index == 3 {
            assert!(config.contains("# Node: oslo.example (edge-3)\n[Peer]\n"));
            assert!(config.contains("# IPv4\n# Endpoint = 192.0.2.3:51820\n# IPv6\nEndpoint = [2001:db8::3]:51820\n# Endpoint = [2001:db8::4]:51821\n"));
            assert_eq!(
                config
                    .lines()
                    .filter(|line| line.starts_with("AllowedIPs = "))
                    .count(),
                1
            );
            let home = config.split("\n# Node: ").nth(1).unwrap();
            assert!(home.starts_with("oslo.example (edge-3)\n"));
            assert!(home.lines().any(|line| line.starts_with("AllowedIPs = ")));
        }
    }
    let a = Endpoint::new(
        NetworkId::new(&alice).unwrap(),
        DeviceId::new(&devices[0]).unwrap(),
    );
    let laptop = Endpoint::new(
        NetworkId::new(&alice).unwrap(),
        DeviceId::new(&devices[1]).unwrap(),
    );
    let b = Endpoint::new(
        NetworkId::new(&bob).unwrap(),
        DeviceId::new(&devices[2]).unwrap(),
    );
    let snapshot = service.delivery_snapshot().unwrap();
    let routing = snapshot.document().routing();
    for gateway in routing.assignments() {
        let projection = snapshot
            .document()
            .project_for(gateway.recipient())
            .unwrap();
        let restored = GatewayProjection::from_json(&projection.to_json().unwrap()).unwrap();
        for network in restored.config().networks() {
            for device in network.devices() {
                assert!(device.hostname().is_some());
            }
        }
    }
    assert_eq!(routing.config().decision(&a, &laptop), Action::Allow);
    assert_eq!(routing.config().decision(&a, &b), Action::Deny);
    let private = snapshot
        .secrets()
        .device(
            &ClientId::new(&alice).unwrap(),
            &DeviceId::new(&devices[0]).unwrap(),
        )
        .unwrap()
        .expose_bytes();
    assert!(text.contains(&STANDARD.encode(private)));
    for node in routing.assignments() {
        assert_eq!(node.tenants().len(), 2);
        for tenant in node.tenants() {
            let key = STANDARD.encode(tenant.public_key().as_bytes());
            if tenant.network().as_str() == alice {
                let name = node.hostname().unwrap_or(node.recipient().as_str());
                let block = text
                    .split("\n# Node: ")
                    .skip(1)
                    .find(|block| block.starts_with(name))
                    .unwrap();
                assert!(block.contains(&format!("\n[Peer]\nPublicKey = {key}\n")));
                assert_eq!(
                    block
                        .lines()
                        .filter(|line| line.starts_with("Endpoint = "))
                        .count(),
                    1
                );
                let assigned = node.recipient().as_str() == "one";
                assert_eq!(
                    block.lines().any(|line| line.starts_with("AllowedIPs = ")),
                    assigned
                );
                assert_eq!(
                    block
                        .lines()
                        .any(|line| line.starts_with("PersistentKeepalive = ")),
                    assigned
                );
            } else {
                assert!(!text.contains(&key));
            }
        }
        let delivery = snapshot
            .delivery(&routing.project_mesh_for(node.recipient()).unwrap())
            .unwrap();
        assert!(
            !std::str::from_utf8(&delivery)
                .unwrap()
                .contains(&serde_json::to_string(private).unwrap())
        );
    }
    drop(snapshot);
    change(
        &mut service,
        &mut revision,
        "POST",
        &format!("/api/v1/users/{alice}/suspend"),
        serde_json::json!({}),
    );
    drop(service);
    let mut service = ManagementService::open(&root.join("state")).unwrap();
    let snapshot = service.delivery_snapshot().unwrap();
    let routing = snapshot.document().routing();
    assert_eq!(routing.config().decision(&a, &laptop), Action::Deny);
    assert_eq!(routing.config().decision(&laptop, &a), Action::Deny);
    for node in routing.assignments() {
        let projected = routing.project_mesh_for(node.recipient()).unwrap();
        assert_eq!(projected.config().decision(&a, &laptop), Action::Deny);
    }
    assert_eq!(get(&mut service, &config_path).body, exported.body);
    drop(snapshot);
    change(
        &mut service,
        &mut revision,
        "POST",
        &format!("/api/v1/users/{alice}/resume"),
        serde_json::json!({}),
    );
    assert_eq!(
        service
            .delivery_snapshot()
            .unwrap()
            .document()
            .routing()
            .config()
            .decision(&a, &laptop),
        Action::Allow
    );
    change(
        &mut service,
        &mut revision,
        "DELETE",
        &format!("/api/v1/users/{alice}/devices/{}", devices[0]),
        serde_json::Value::Null,
    );
    assert_eq!(get(&mut service, &config_path).status, 404);
    assert!(
        service
            .delivery_snapshot()
            .unwrap()
            .secrets()
            .device(
                &ClientId::new(&alice).unwrap(),
                &DeviceId::new(&devices[0]).unwrap()
            )
            .is_none()
    );
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
