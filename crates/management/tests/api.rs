use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use wgfeel_core::{
    Action, AdminCredential, Client, ClientDevice, ClientId, Config, Device, DeviceId,
    DeviceMetadata, DevicePublicKey, Endpoint, GatewayAssignment, Grant, ManagementConfig,
    ManagementDocument, Network, NetworkId, NodeId, Policy, Rule, TenantKeyAssignment,
};
use wgfeel_management::{ManagementService, Request, Response};
use wgfeel_store::{ManagementStore, Store, StoreError};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self::with_document(&initial())
    }
    fn with_document(document: &ManagementDocument) -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-management-api-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self(root);
        let mut store = ManagementStore::initialize(&fixture.path()).unwrap();
        store
            .commit(document, &node_key(), &credential(211), None)
            .unwrap();
        fixture
    }
    fn path(&self) -> PathBuf {
        self.0.join("state")
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.path().join("state.json")).unwrap()
    }
    fn service(&self) -> ManagementService {
        ManagementService::open(&self.path()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn node(id: &str) -> NodeId {
    NodeId::new(id).unwrap()
}
fn network(id: &str) -> NetworkId {
    NetworkId::new(id).unwrap()
}
fn device(id: &str) -> DeviceId {
    DeviceId::new(id).unwrap()
}
fn key(byte: u8) -> DevicePublicKey {
    DevicePublicKey::new([byte; 32]).unwrap()
}
fn node_key() -> wgfeel_core::NodeKeys {
    wgfeel_test_support::fixture_node_keys([197; 32])
}
fn credential(byte: u8) -> AdminCredential {
    AdminCredential::new([byte; 32]).unwrap()
}
fn bearer(byte: u8) -> String {
    format!("Bearer {}", STANDARD.encode([byte; 32]))
}

#[test]
fn rotating_token_revokes_old_bearer_durably_without_changing_networks_or_keys() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let before = service.delivery_snapshot().unwrap();
    let generation = before.document().routing().generation();
    let revision = format!("\"{generation}\"");
    let old = bearer(211);
    // Requests for the embedded document must go through the current token verifier.
    assert_eq!(
        authorized(&mut service, "GET", "/api/v1/openapi.json", None, b"").status,
        200
    );
    let response = service.handle(Request {
        method: "POST",
        target: "/api/v1/token/rotate",
        authorization: Some(&old),
        if_match: Some(&revision),
        body: b"",
    });
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let token = body["token"].as_str().unwrap();
    let decoded = STANDARD.decode(token).unwrap();
    assert_eq!(decoded.len(), 32);
    assert_ne!(decoded, [211; 32]);
    let new = format!("Bearer {token}");
    let after = service.delivery_snapshot().unwrap();
    assert_eq!(after.document(), before.document());
    assert_eq!(
        after.service_private_key().expose_bytes(),
        before.service_private_key().expose_bytes()
    );
    assert_eq!(after.api(), before.api());
    assert_eq!(after.retired_gateways(), before.retired_gateways());
    for restart in [false, true] {
        if restart {
            drop(service);
            service = fixture.service();
        }
        for (authorization, expected) in [(&old, 401), (&new, 200)] {
            for target in ["/api/v1/users", "/api/v1/openapi.json"] {
                assert_eq!(
                    service
                        .handle(Request {
                            method: "GET",
                            target,
                            authorization: Some(authorization),
                            if_match: None,
                            body: b"",
                        })
                        .status,
                    expected
                );
            }
        }
        assert_eq!(
            service
                .handle(Request {
                    method: "POST",
                    target: "/api/v1/token/rotate",
                    authorization: Some(&old),
                    if_match: Some(&revision),
                    body: b"",
                })
                .status,
            401
        );
    }
}

#[test]
fn rotation_rejects_invalid_requests_and_storage_failure_without_exposing_a_token() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let before = fixture.bytes();
    let revision = format!("\"{}\"", initial().routing().generation());
    let auth = bearer(211);
    for (method, revision, body, expected) in [
        ("GET", Some(revision.as_str()), b"".as_slice(), 405),
        ("POST", None, b"", 428),
        ("POST", Some("\"999\""), b"", 412),
        ("POST", Some(revision.as_str()), b"{}", 400),
    ] {
        let response = service.handle(Request {
            method,
            target: "/api/v1/token/rotate",
            authorization: Some(&auth),
            if_match: revision,
            body,
        });
        assert_eq!(response.status, expected);
        assert!(
            !std::str::from_utf8(&response.body)
                .unwrap()
                .contains("\"token\"")
        );
        assert_eq!(fixture.bytes(), before);
    }
    fs::create_dir(fixture.path().join(".pending")).unwrap();
    let response = service.handle(Request {
        method: "POST",
        target: "/api/v1/token/rotate",
        authorization: Some(&auth),
        if_match: Some(&revision),
        body: b"",
    });
    assert_eq!(response.status, 503);
    assert!(
        !std::str::from_utf8(&response.body)
            .unwrap()
            .contains("\"token\"")
    );
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn opening_authority_keeps_its_document_identity_and_hashed_credential() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    assert_eq!(document(&mut service), initial());
    assert_eq!(fixture.bytes(), before);
    let state: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(state["admin_verifier"]["algorithm"], "hmac-sha256");
    assert!(state.get("admin_credential").is_none());
}
fn metadata(name: &str) -> DeviceMetadata {
    DeviceMetadata::new(Some(name.into()), Some(format!("description {name}"))).unwrap()
}
fn catalog(id: &str, name: &str) -> ClientDevice {
    ClientDevice::new(device(id), metadata(name))
}
fn registration(id: &str, public: u8, address: &str) -> Device {
    Device::new(device(id), key(public), vec![address.parse().unwrap()]).unwrap()
}
fn endpoint(net: &str, id: &str) -> Endpoint {
    Endpoint::new(network(net), device(id))
}
fn assignment(id: &str, system: u8, scope: &[&str], tenants: &[(&str, u8)]) -> GatewayAssignment {
    GatewayAssignment::new(
        node(id),
        (key(system)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(key(system))),
        scope.iter().map(|id| network(id)).collect(),
        tenants
            .iter()
            .map(|(id, public)| TenantKeyAssignment::new(network(id), key(*public)))
            .collect(),
    )
    .unwrap()
}
fn owner(id: &str, networks: &[&str], devices: Vec<ClientDevice>) -> Client {
    Client::new(
        ClientId::new(id).unwrap(),
        networks.iter().map(|id| network(id)).collect(),
        devices,
    )
    .unwrap()
}
fn beta() -> Network {
    Network::new(
        network("beta"),
        vec![registration("shared-beta", 31, "10.3.0.1")],
    )
    .unwrap()
}
fn initial() -> ManagementDocument {
    let config = Config::new(
        7,
        vec![
            Network::new(
                network("alpha"),
                vec![
                    registration("shared", 11, "10.1.0.1"),
                    registration("keep", 12, "10.1.0.2"),
                ],
            )
            .unwrap(),
            Network::new(
                network("alpha-two"),
                vec![registration("shared-alpha-two", 21, "10.2.0.1")],
            )
            .unwrap(),
            beta(),
        ],
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "shared"),
                endpoint("alpha", "keep"),
                Action::Deny,
            )],
            vec![
                Rule::new(
                    endpoint("alpha", "shared"),
                    endpoint("alpha", "keep"),
                    Action::Allow,
                ),
                Rule::new(
                    endpoint("beta", "shared-beta"),
                    endpoint("beta", "shared-beta"),
                    Action::Allow,
                ),
            ],
            vec![
                Grant::new(endpoint("alpha", "shared"), endpoint("beta", "shared-beta")),
                Grant::new(
                    endpoint("beta", "shared-beta"),
                    endpoint("alpha-two", "shared-alpha-two"),
                ),
            ],
        ),
    )
    .unwrap();
    ManagementDocument::new(
        ManagementConfig::new(
            node("management"),
            config,
            vec![
                assignment(
                    "gateway-one",
                    101,
                    &["alpha", "alpha-two", "beta"],
                    &[("alpha", 102), ("alpha-two", 103), ("beta", 104)],
                ),
                assignment("gateway-two", 111, &["beta"], &[("beta", 112)]),
            ],
        )
        .unwrap(),
        vec![
            owner(
                "alice",
                &["alpha"],
                vec![
                    catalog("shared", "Alice laptop"),
                    catalog("keep", "Alice retained"),
                ],
            ),
            owner("bob", &["beta"], vec![catalog("shared-beta", "Bob laptop")]),
            owner(
                "alice-work",
                &["alpha-two"],
                vec![catalog("shared-alpha-two", "Alice work laptop")],
            ),
        ],
    )
    .unwrap()
}
fn no_secrets(response: &Response) {
    let text = String::from_utf8_lossy(&response.body);
    for byte in [197_u8, 211, 212] {
        assert!(!text.contains(&STANDARD.encode([byte; 32])));
        assert!(!text.contains(&format!("{:?}", [byte; 32])));
        assert!(!text.contains(&format!("{:?}", [byte; 32]).replace(' ', "")));
    }
    assert!(!text.contains("service_private_key"));
    assert!(!text.contains("admin_credential"));
    assert!(!text.contains("NEVER_ECHO_INPUT"));
}
fn request(
    service: &mut ManagementService,
    method: &str,
    target: &str,
    authorization: Option<&str>,
    revision: Option<&str>,
    body: &[u8],
) -> Response {
    let response = service.handle(Request {
        method,
        target,
        authorization,
        if_match: revision,
        body,
    });
    no_secrets(&response);
    response
}
fn authorized(
    service: &mut ManagementService,
    method: &str,
    target: &str,
    revision: Option<u64>,
    body: &[u8],
) -> Response {
    let revision = revision.map(|value| format!("\"{value}\""));
    request(
        service,
        method,
        target,
        Some(&bearer(211)),
        revision.as_deref(),
        body,
    )
}
fn document(service: &mut ManagementService) -> ManagementDocument {
    let response = authorized(service, "GET", "/api/v1/config", None, b"");
    assert_eq!(response.status, 200);
    let document =
        ManagementDocument::from_json(std::str::from_utf8(&response.body).unwrap()).unwrap();
    assert_eq!(response.generation, Some(document.routing().generation()));
    document
}
fn error(response: &Response, expected: u16) {
    assert_eq!(response.status, expected);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert!(!body["error"].as_str().unwrap().is_empty());
}
fn success(response: &Response, status: u16, id: &str, generation: u64) {
    let generated;
    let id = if id == "dave" {
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        generated = value["id"].as_str().unwrap().to_owned();
        assert_uuid_v4(&generated);
        generated.as_str()
    } else {
        id
    };
    assert_eq!(response.status, status);
    assert_eq!(response.generation, Some(generation));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
        serde_json::json!({"id": id, "generation": generation, "distribution": "pending"})
    );
}
fn reopen(fixture: &Fixture, mut service: ManagementService) -> ManagementService {
    let expected = document(&mut service);
    drop(service);
    let store = ManagementStore::open(&fixture.path()).unwrap();
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.document(), &expected);
    assert!(stored.service_private_key().expose_bytes() == &[197; 32]);
    assert!(stored.admin_verifier().verify(&[211; 32]));
    drop(store);
    let mut reopened = fixture.service();
    assert_eq!(document(&mut reopened), expected);
    reopened
}
fn device_body(id: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({"name": "New device", "description": "Public description", "public_key": STANDARD.encode([51; 32]), "addresses": ["10.1.0.3", "fd00:1::3"]});
    if let Some(id) = id {
        body["id"] = id.into();
    }
    body
}
fn gateway_body(id: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({"public_key": STANDARD.encode([201; 32]), "gateway_public_key":STANDARD.encode(wgfeel_test_support::fixture_gateway_public(&key(201)).as_bytes()), "networks": [], "tenants": []});
    if let Some(id) = id {
        body["id"] = id.into();
    }
    body
}

#[test]
fn open_requires_existing_management_state_and_owns_the_exclusive_store_lock() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let service = fixture.service();
    assert!(matches!(
        ManagementStore::open(&fixture.path()),
        Err(StoreError::Locked)
    ));
    assert!(matches!(
        ManagementService::open(&fixture.path()),
        Err(StoreError::Locked)
    ));
    drop(service);
    assert!(ManagementService::open(&fixture.0.join("missing")).is_err());
    assert!(!fixture.0.join("missing").exists());
    let empty = fixture.0.join("empty");
    drop(ManagementStore::initialize(&empty).unwrap());
    assert!(matches!(
        ManagementService::open(&empty),
        Err(StoreError::InvalidState)
    ));
    let gateway_path = fixture.0.join("gateway");
    let mut gateway = Store::initialize(&gateway_path).unwrap();
    let projection = wgfeel_test_support::fixture_projection(
        &Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        &node("gateway"),
        &node_key(),
        vec![],
    );
    gateway
        .commit_projection(
            projection.management_id(),
            &projection,
            projection.recipient(),
            &node_key(),
            &Default::default(),
        )
        .unwrap();
    drop(gateway);
    let gateway_bytes = fs::read(gateway_path.join("state.json")).unwrap();
    assert!(matches!(
        ManagementService::open(&gateway_path),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(
        fs::read(gateway_path.join("state.json")).unwrap(),
        gateway_bytes
    );
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn gateway_user_scope_resolves_the_assigned_network_without_changing_its_identity() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let before = document(&mut service);
    for body in [
        serde_json::json!({"id":"scoped","public_key":STANDARD.encode([201;32]),"gateway_public_key":STANDARD.encode(wgfeel_test_support::fixture_gateway_public(&key(201)).as_bytes()),"users":["missing"]}),
        serde_json::json!({"id":"scoped","public_key":STANDARD.encode([201;32]),"gateway_public_key":STANDARD.encode(wgfeel_test_support::fixture_gateway_public(&key(201)).as_bytes()),"users":["alice"],"networks":["beta"]}),
    ] {
        let bytes = fixture.bytes();
        error(
            &authorized(
                &mut service,
                "POST",
                "/api/v1/gateways",
                Some(7),
                &serde_json::to_vec(&body).unwrap(),
            ),
            422,
        );
        assert_eq!(fixture.bytes(), bytes);
    }
    let body = serde_json::json!({"id":"scoped","public_key":STANDARD.encode([201;32]),"gateway_public_key":STANDARD.encode(wgfeel_test_support::fixture_gateway_public(&key(201)).as_bytes()),"users":["alice"],"tenants":[{"user":"alice","public_key":STANDARD.encode([202;32])}]});
    success(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/gateways",
            Some(7),
            &serde_json::to_vec(&body).unwrap(),
        ),
        201,
        "scoped",
        8,
    );
    service = reopen(&fixture, service);
    let after = document(&mut service);
    assert_eq!(after.clients(), before.clients());
    assert_eq!(
        after.routing().config().networks(),
        before.routing().config().networks()
    );
    assert_eq!(
        after.routing().assignments().last().unwrap(),
        &assignment("scoped", 201, &["alpha"], &[("alpha", 202)])
    );
    let response = authorized(&mut service, "GET", "/api/v1/gateways/scoped", None, b"");
    let public: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(public["users"], serde_json::json!(["alice"]));
    assert_eq!(public["tenants"][0]["user"], "alice");
    assert!(public.get("networks").is_none());
}

#[test]
fn authenticated_reads_are_public_exact_and_do_not_mutate_the_snapshot() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    let expected = initial();
    assert_eq!(document(&mut service), expected);
    let users = expected
        .clients()
        .iter()
        .map(|client| {
            let network = expected
                .routing()
                .config()
                .networks()
                .iter()
                .find(|network| network.id() == client.network())
                .unwrap();
            serde_json::json!({
                "id": client.id(),
                "name": client.name(),
                "suspended": false,
                "broadcast": true,
                "devices": client.devices().iter().map(|d| {
                    let addresses = network
                        .devices()
                        .iter()
                        .find(|entry| entry.id() == d.id())
                        .map_or(&[][..], Device::addresses);
                    serde_json::json!({
                        "id": d.id(),
                        "metadata": d.metadata(),
                        "addresses": addresses,
                        "registration": {"broadcast": null, "effective_broadcast": true}
                    })
                }).collect::<Vec<_>>(),
                "egresses": []
            })
        })
        .collect::<Vec<_>>();
    let gateways = vec![
        serde_json::json!({"recipient":"gateway-one","service_public_key":key(101),"gateway_public_key":wgfeel_test_support::fixture_gateway_public(&key(101)),"endpoint":null,"endpoints":[],"hostname":null,"auto_users":false,"traffic":"entry","users":["alice","alice-work","bob"],"tenants":[{"user":"alice","public_key":key(102)},{"user":"alice-work","public_key":key(103)},{"user":"bob","public_key":key(104)}]}),
        serde_json::json!({"recipient":"gateway-two","service_public_key":key(111),"gateway_public_key":wgfeel_test_support::fixture_gateway_public(&key(111)),"endpoint":null,"endpoints":[],"hostname":null,"auto_users":false,"traffic":"entry","users":["bob"],"tenants":[{"user":"bob","public_key":key(112)}]}),
    ];
    for (target, body) in [
        ("/api/v1/users", serde_json::json!({"users": users})),
        ("/api/v1/users/alice", users[0].clone()),
        (
            "/api/v1/users/alice/devices",
            serde_json::json!({"devices": users[0]["devices"]}),
        ),
        (
            "/api/v1/gateways",
            serde_json::json!({"gateways": gateways}),
        ),
        ("/api/v1/gateways/gateway-one", gateways[0].clone()),
    ] {
        let response = authorized(&mut service, "GET", target, None, b"");
        assert_eq!(response.status, 200);
        assert_eq!(response.generation, Some(7));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
            body
        );
    }
    assert_eq!(fixture.bytes(), before);
}

const PUBLIC_ROUTES: &[(&str, &str)] = &[
    ("openapi.json", "GET"),
    ("identity", "GET"),
    ("config", "GET"),
    ("distribution", "GET"),
    ("users", "GET POST"),
    ("users/{user}", "DELETE GET"),
    ("users/{user}/broadcast", "GET PUT"),
    ("users/{user}/devices/{device}/broadcast", "GET PUT"),
    ("users/{user}/suspend", "POST"),
    ("users/{user}/resume", "POST"),
    ("users/{user}/devices", "GET POST"),
    ("users/{user}/devices/{device}", "DELETE GET"),
    ("users/{user}/devices/{device}/config", "GET"),
    ("users/{user}/devices/{device}/config/{network}", "GET"),
    ("egresses", "GET POST"),
    ("egresses/{egress}", "DELETE GET PUT"),
    ("egresses/{egress}/node", "GET PUT"),
    ("users/{user}/egresses", "GET PUT"),
    ("users/{user}/egresses/{egress}", "DELETE PUT"),
    ("gateways", "GET POST"),
    ("gateways/{gateway}", "DELETE GET"),
    ("node-invitations", "POST"),
    ("token/rotate", "POST"),
];

#[test]
fn every_route_requires_the_retained_bearer_before_any_mutation() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    let wrong_token = bearer(212);
    for &(route, methods) in PUBLIC_ROUTES {
        let path = format!("/api/v1/{route}")
            .replace("{user}", "alice")
            .replace("{device}", "shared")
            .replace("{network}", "alpha")
            .replace("{gateway}", "gateway-one")
            .replace("{egress}", "office");
        for method in methods.split_whitespace() {
            for token in [None, Some(wrong_token.as_str())] {
                let response = request(&mut service, method, &path, token, Some("\"7\""), b"");
                assert_eq!(response.status, 401, "{method} {path}");
                error(&response, 401);
            }
            // An unknown route also rejects anonymous requests. Prove that this
            // method reaches its own validation with a valid bearer, without writing.
            let (revision, body, status) = if method == "GET" {
                (None, b"{}".as_slice(), 400)
            } else {
                (Some(6), b"".as_slice(), 412)
            };
            let response = authorized(&mut service, method, &path, revision, body);
            assert_eq!(response.status, status, "{method} {path}");
        }
    }
    for invalid in [
        "Bearer NEVER_ECHO_INPUT".to_owned(),
        STANDARD.encode([211; 32]),
        format!("Bearer {}", STANDARD.encode([211; 31])),
        format!(
            "Bearer {}",
            STANDARD.encode([211; 32]).trim_end_matches('=')
        ),
    ] {
        let response = request(
            &mut service,
            "GET",
            "/api/v1/config",
            Some(&invalid),
            None,
            b"",
        );
        error(&response, 401);
    }
    assert!(
        fixture.bytes() == before,
        "unauthorized or rejected request changed state"
    );
    assert_eq!(document(&mut service), initial());
}

#[test]
fn six_mutations_persist_cascades_and_preserve_unrelated_owners_and_secrets() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let user = created_id(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/users",
            Some(7),
            br#"{"name":"dave"}"#,
        ),
        8,
    );
    service = reopen(&fixture, service);
    let added = document(&mut service);
    assert_eq!(added.clients()[3].name(), "dave");
    assert_eq!(added.clients()[3].id().as_str(), user);
    assert_eq!(added.clients()[3].network().as_str(), user);
    assert_eq!(
        added.routing().assignments(),
        initial().routing().assignments()
    );
    let fresh = created_id(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/users/alice/devices",
            Some(8),
            &serde_json::to_vec(&device_body(None)).unwrap(),
        ),
        9,
    );
    service = reopen(&fixture, service);
    let added = document(&mut service);
    let selected = added
        .select_device(&ClientId::new("alice").unwrap(), &device(&fresh), None)
        .unwrap();
    assert_eq!(selected.device.metadata().name(), Some("New device"));
    assert_eq!(
        selected.device.metadata().description(),
        Some("Public description")
    );
    assert_eq!(selected.registration.public_key(), &key(51));
    assert_eq!(
        selected.registration.addresses(),
        [
            "10.1.0.3".parse::<std::net::IpAddr>().unwrap(),
            "fd00:1::3".parse().unwrap()
        ]
    );
    let new_gateway = serde_json::json!({"id":"gateway-new", "public_key":STANDARD.encode([201;32]),"gateway_public_key":STANDARD.encode(wgfeel_test_support::fixture_gateway_public(&key(201)).as_bytes()), "users":[user], "tenants":[{"user":user,"public_key":STANDARD.encode([202;32])}]});
    success(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/gateways",
            Some(9),
            &serde_json::to_vec(&new_gateway).unwrap(),
        ),
        201,
        "gateway-new",
        10,
    );
    service = reopen(&fixture, service);
    success(
        &authorized(
            &mut service,
            "DELETE",
            "/api/v1/users/alice/devices/shared",
            Some(10),
            b"",
        ),
        200,
        "shared",
        11,
    );
    service = reopen(&fixture, service);
    let after_device = document(&mut service);
    assert!(
        after_device
            .select_device(&ClientId::new("alice").unwrap(), &device("shared"), None)
            .is_err()
    );
    for owner in ["bob", "alice-work"] {
        assert_eq!(
            after_device
                .clients()
                .iter()
                .find(|c| c.id().as_str() == owner),
            initial()
                .clients()
                .iter()
                .find(|c| c.id().as_str() == owner)
        );
    }
    success(
        &authorized(&mut service, "DELETE", "/api/v1/users/alice", Some(11), b""),
        200,
        "alice",
        12,
    );
    service = reopen(&fixture, service);
    let after_user = document(&mut service);
    assert!(
        !after_user
            .clients()
            .iter()
            .any(|c| c.id().as_str() == "alice")
    );
    assert!(
        !after_user
            .routing()
            .config()
            .networks()
            .iter()
            .any(|n| n.id().as_str() == "alpha")
    );
    for gateway in after_user.routing().assignments() {
        assert!(!gateway.networks().contains(&network("alpha")));
        assert!(
            !gateway
                .tenants()
                .iter()
                .any(|tenant| tenant.network() == &network("alpha"))
        );
        after_user.project_for(gateway.recipient()).unwrap();
    }
    success(
        &authorized(
            &mut service,
            "DELETE",
            "/api/v1/gateways/gateway-new",
            Some(12),
            b"",
        ),
        200,
        "gateway-new",
        13,
    );
    service = reopen(&fixture, service);
    assert!(
        document(&mut service)
            .project_for(&node("gateway-new"))
            .is_err()
    );
    assert_eq!(
        document(&mut service).routing().config().decision(
            &endpoint("beta", "shared-beta"),
            &endpoint("beta", "shared-beta")
        ),
        Action::Allow
    );
}
#[test]
fn missing_stale_and_malformed_revision_or_semantic_failure_never_changes_state() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    let body = br#"{"name":"dave"}"#;
    error(
        &authorized(&mut service, "POST", "/api/v1/users", None, body),
        428,
    );
    for revision in [6, 8] {
        error(
            &authorized(&mut service, "POST", "/api/v1/users", Some(revision), body),
            412,
        );
    }
    for revision in ["7", "W/\"7\"", "\"not-a-number\"", "\"7\",\"8\""] {
        error(
            &request(
                &mut service,
                "POST",
                "/api/v1/users",
                Some(&bearer(211)),
                Some(revision),
                body,
            ),
            400,
        );
    }
    for (method, target, bytes, status) in [
        (
            "POST",
            "/api/v1/users",
            br#"{"name":"alice"}"#.to_vec(),
            409,
        ),
        ("DELETE", "/api/v1/users/missing", vec![], 404),
        ("DELETE", "/api/v1/users/alice/devices/missing", vec![], 404),
        ("DELETE", "/api/v1/gateways/missing", vec![], 404),
        (
            "POST",
            "/api/v1/users/alice/devices",
            serde_json::to_vec(&device_body(Some("shared"))).unwrap(),
            400,
        ),
        (
            "POST",
            "/api/v1/users/missing/devices",
            serde_json::to_vec(&device_body(None)).unwrap(),
            404,
        ),
        (
            "POST",
            "/api/v1/users/alice/devices",
            serde_json::to_vec(&serde_json::json!({"network":"beta", "name":"Foreign network"}))
                .unwrap(),
            400,
        ),
        (
            "POST",
            "/api/v1/gateways",
            serde_json::to_vec(&gateway_body(Some("gateway-one"))).unwrap(),
            409,
        ),
    ] {
        error(
            &authorized(&mut service, method, target, Some(7), &bytes),
            status,
        );
    }
    for (field, value) in [
        ("public_key", serde_json::json!("NEVER_ECHO_INPUT")),
        ("public_key", serde_json::json!(STANDARD.encode([0; 32]))),
        ("addresses", serde_json::json!(["127.0.0.1"])),
        ("name", serde_json::json!("")),
    ] {
        let mut body = device_body(None);
        body[field] = value;
        error(
            &authorized(
                &mut service,
                "POST",
                "/api/v1/users/alice/devices",
                Some(7),
                &serde_json::to_vec(&body).unwrap(),
            ),
            422,
        );
    }
    assert_eq!(fixture.bytes(), before);
    assert_eq!(document(&mut service), initial());
}

#[test]
fn strict_json_targets_methods_and_empty_read_delete_bodies_are_checked() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    for body in [
        br#"{"id":"new","id":"other"}"#.as_slice(),
        br#"{"id":"new","unknown":"NEVER_ECHO_INPUT"}"#,
        b"[]",
        b"null",
        b"{",
        &[0xff],
    ] {
        error(
            &authorized(&mut service, "POST", "/api/v1/users", Some(7), body),
            400,
        );
    }
    let gateway = gateway_body(Some("new"));
    let prefix = serde_json::to_string(&gateway).unwrap();
    let duplicate_nested = prefix.replace(
        "\"tenants\":[]",
        &format!(
            "\"tenants\":[{{\"network\":\"alpha\",\"network\":\"beta\",\"public_key\":\"{}\"}}]",
            STANDARD.encode([202; 32])
        ),
    );
    error(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/gateways",
            Some(7),
            duplicate_nested.as_bytes(),
        ),
        400,
    );
    let mut device = device_body(None);
    device.as_object_mut().unwrap().remove("name");
    error(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/users/alice/devices",
            Some(7),
            &serde_json::to_vec(&device).unwrap(),
        ),
        400,
    );
    for target in [
        "/api/v1/users?query=1",
        "/api/v1/users/%61lice",
        "/api/v1/users/../alice",
        "/api/v1/users/./alice",
    ] {
        error(&authorized(&mut service, "GET", target, None, b""), 400);
    }
    error(
        &authorized(
            &mut service,
            "PUT",
            "/api/v1/users",
            Some(7),
            br#"{"name":"New user"}"#,
        ),
        405,
    );
    error(
        &authorized(&mut service, "GET", "/api/v1/unknown", None, b""),
        404,
    );
    error(
        &authorized(&mut service, "GET", "/api/v1/users/missing", None, b""),
        404,
    );
    error(
        &authorized(&mut service, "GET", "/api/v1/gateways/missing", None, b""),
        404,
    );
    error(
        &authorized(&mut service, "GET", "/api/v1/config", None, b"{}"),
        400,
    );
    error(
        &authorized(
            &mut service,
            "DELETE",
            "/api/v1/users/alice",
            Some(7),
            b"{}",
        ),
        400,
    );
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn request_body_limit_is_inclusive_and_oversized_request_cannot_commit() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    let mut body = br#"{"name":"dave"}"#.to_vec();
    body.resize(65_537, b' ');
    error(
        &authorized(&mut service, "POST", "/api/v1/users", Some(7), &body),
        413,
    );
    assert_eq!(fixture.bytes(), before);
    body.pop();
    success(
        &authorized(&mut service, "POST", "/api/v1/users", Some(7), &body),
        201,
        "dave",
        8,
    );
    reopen(&fixture, service);
}

fn assert_uuid_v4(value: &str) {
    assert_eq!(value.len(), 36);
    for (index, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            assert_eq!(byte, b'-');
        } else {
            assert!(byte.is_ascii_hexdigit());
        }
    }
    assert_eq!(value.as_bytes()[14], b'4');
    assert!(b"89abAB".contains(&value.as_bytes()[19]));
}
fn created_id(response: &Response, generation: u64) -> String {
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let id = body["id"].as_str().unwrap();
    assert_uuid_v4(id);
    success(response, 201, id, generation);
    id.to_owned()
}

#[test]
fn generated_user_owns_same_id_network_and_device_gateway_ids_are_distinct_and_persist() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let user = created_id(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/users",
            Some(7),
            br#"{"name":"New user"}"#,
        ),
        8,
    );
    let added = document(&mut service);
    let assigned = added
        .clients()
        .iter()
        .find(|client| client.id().as_str() == user)
        .unwrap()
        .networks()[0]
        .as_str()
        .to_owned();
    assert_uuid_v4(&assigned);
    assert_eq!(assigned, user);
    let device = created_id(
        &authorized(
            &mut service,
            "POST",
            &format!("/api/v1/users/{user}/devices"),
            Some(8),
            &serde_json::to_vec(&device_body(None)).unwrap(),
        ),
        9,
    );
    let gateway = created_id(
        &authorized(
            &mut service,
            "POST",
            "/api/v1/gateways",
            Some(9),
            &serde_json::to_vec(&gateway_body(None)).unwrap(),
        ),
        10,
    );
    let unique: std::collections::BTreeSet<_> =
        [&user, &assigned, &device, &gateway].into_iter().collect();
    assert_eq!(unique.len(), 3);
    service = reopen(&fixture, service);
    let stored = document(&mut service);
    assert!(
        stored
            .select_device(
                &ClientId::new(&user).unwrap(),
                &DeviceId::new(&device).unwrap(),
                Some(&network(&assigned))
            )
            .is_ok()
    );
    assert!(stored.project_for(&node(&gateway)).is_ok());
    let retry = serde_json::to_vec(&serde_json::json!({"name":"New user"})).unwrap();
    error(
        &authorized(&mut service, "POST", "/api/v1/users", Some(7), &retry),
        412,
    );
    error(
        &authorized(&mut service, "POST", "/api/v1/users", Some(10), &retry),
        409,
    );
    assert_eq!(document(&mut service), stored);
}

#[test]
fn failed_publication_cannot_report_success_or_consume_identity_or_revision() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    let obstruction = fixture.path().join(".pending");
    fs::create_dir(&obstruction).unwrap();
    fs::set_permissions(&obstruction, fs::Permissions::from_mode(0o700)).unwrap();
    let body = br#"{"name":"dave"}"#;
    let response = authorized(&mut service, "POST", "/api/v1/users", Some(7), body);
    assert!((500..600).contains(&response.status));
    error(&response, response.status);
    assert_eq!(fixture.bytes(), before);
    assert!(obstruction.is_dir());
    assert_eq!(document(&mut service), initial());
    fs::remove_dir(&obstruction).unwrap();
    success(
        &authorized(&mut service, "POST", "/api/v1/users", Some(7), body),
        201,
        "dave",
        8,
    );
    reopen(&fixture, service);
}

#[test]
fn each_request_reloads_committed_revision_and_credential_instead_of_cached_authority() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    assert_eq!(document(&mut service), initial());
    let mut envelope: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    envelope["document"]["config"]["generation"] = 8.into();
    envelope["admin_verifier"] =
        serde_json::to_value(wgfeel_store::AdminVerifier::new(&credential(212)).unwrap()).unwrap();
    let replacement = fixture.path().join("test-published-snapshot");
    fs::write(&replacement, serde_json::to_vec(&envelope).unwrap()).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, fixture.path().join("state.json")).unwrap();
    error(
        &authorized(&mut service, "GET", "/api/v1/config", None, b""),
        401,
    );
    let response = request(
        &mut service,
        "GET",
        "/api/v1/config",
        Some(&bearer(212)),
        None,
        b"",
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.generation, Some(8));
    assert_eq!(
        ManagementDocument::from_json(std::str::from_utf8(&response.body).unwrap())
            .unwrap()
            .routing()
            .generation(),
        8
    );
    let stale = request(
        &mut service,
        "POST",
        "/api/v1/users",
        Some(&bearer(212)),
        Some("\"7\""),
        br#"{"name":"dave"}"#,
    );
    error(&stale, 412);
}

#[test]
fn malformed_authorization_and_oversized_bodies_are_rejected_before_loading_state() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    fs::write(fixture.path().join("state.json"), b"invalid snapshot").unwrap();
    let valid_format = bearer(109);
    let request = |authorization| Request {
        method: "GET",
        target: "/api/v1/users",
        authorization,
        if_match: None,
        body: b"",
    };
    assert_eq!(service.handle(request(None)).status, 401);
    assert_eq!(
        service
            .handle_local(request(Some("Bearer malformed")))
            .status,
        401
    );
    let body = vec![0; wgfeel_management::MAX_REQUEST_BODY + 1];
    assert_eq!(
        service
            .handle(Request {
                body: &body,
                ..request(Some(&valid_format))
            })
            .status,
        413
    );
    assert_eq!(service.handle(request(Some(&valid_format))).status, 503);
}

#[test]
fn openapi_contract_covers_public_operations_and_preserves_wire_types() {
    use serde_json::{Value, json};
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let path = "/api/v1/openapi.json";
    let snapshot = fixture.bytes();
    for authorization in [None, Some(&*bearer(19))] {
        let response = service.handle_local(Request {
            target: path,
            method: "GET",
            authorization,
            if_match: None,
            body: b"",
        });
        assert_eq!(response.status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!({"error":"unauthorized"})
        );
    }
    let response = authorized(&mut service, "GET", path, None, b"");
    assert_eq!((response.status, response.generation), (200, Some(7)));
    let api: Value = serde_json::from_slice(&response.body).unwrap();
    let paths = api["paths"].as_object().unwrap();
    assert_eq!(api["security"], json!([{"adminBearer": []}]));
    let bearer = &api["components"]["securitySchemes"]["adminBearer"];
    assert_eq!(bearer["type"], "http");
    assert_eq!(bearer["scheme"], "bearer");
    assert_eq!(paths.len(), PUBLIC_ROUTES.len());
    for &(route, methods) in PUBLIC_ROUTES {
        let operations = paths[&format!("/api/v1/{route}")].as_object().unwrap();
        assert_eq!(
            operations
                .keys()
                .filter(|name| matches!(
                    name.as_str(),
                    "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace"
                ))
                .count(),
            methods.split_whitespace().count(),
            "{route}"
        );
        for method in methods.split_whitespace() {
            let operation = operations
                .get(&method.to_ascii_lowercase())
                .unwrap_or_else(|| panic!("missing {method} {route}"));
            assert_eq!(
                operation.get("security").unwrap_or(&api["security"]),
                &api["security"],
                "{method} {route} must require a bearer"
            );
        }
    }
    fn check_local_refs(api: &Value, value: &Value) {
        match value {
            Value::Object(object) => {
                if let Some(pointer) = object
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix('#'))
                {
                    assert!(
                        api.pointer(pointer).is_some(),
                        "unresolved schema reference {pointer}"
                    );
                }
                for child in object.values() {
                    check_local_refs(api, child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    check_local_refs(api, item);
                }
            }
            _ => {}
        }
    }
    check_local_refs(&api, &api);
    let if_match = |operation: &Value| {
        operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "If-Match" && p["in"] == "header")
            .expect("If-Match header missing")["required"]
            .as_bool()
            .unwrap()
    };

    let schema = &paths["/api/v1/users/{user}/devices/{device}/broadcast"]["put"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert_eq!(schema["required"], json!(["broadcast"]));
    assert_eq!(
        schema["properties"]["broadcast"]["type"],
        json!(["boolean", "null"])
    );
    let post = &paths["/api/v1/users"]["post"];
    let input = &post["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(input["required"], json!(["name"]));
    assert_eq!(input["additionalProperties"], false);
    assert_eq!(input["properties"]["name"]["type"], "string");
    assert!(if_match(post));
    assert!(post["responses"]["201"]["headers"]["ETag"].is_object());
    assert!(post["responses"]["412"].is_object());
    assert!(post["responses"]["428"].is_object());
    let invitation = &paths["/api/v1/node-invitations"]["post"];
    assert!(!if_match(invitation));
    assert_eq!(invitation["requestBody"]["required"], false);
    let traffic = &invitation["requestBody"]["content"]["application/json"]["schema"]["properties"]
        ["traffic"];
    assert_eq!(traffic["default"], "entry");
    assert_eq!(traffic["enum"], json!(["entry", "relay", "off"]));
    let config = &paths["/api/v1/users/{user}/devices/{device}/config/{network}"]["get"];
    assert_eq!(
        config["responses"]["200"]["content"]["text/plain"]["schema"]["type"],
        "string"
    );
    assert_eq!(config["parameters"].as_array().unwrap().len(), 3);
    let schemas = &api["components"]["schemas"];
    assert_eq!(
        schemas["WireManagement"]["properties"]["config"]["$ref"],
        "#/components/schemas/WireConfig"
    );
    assert_eq!(schemas["DevicePublicKey"]["type"], "array");
    assert_eq!(schemas["DevicePublicKey"]["minItems"], 32);
    assert!(
        schemas["DeviceMetadata"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("description"))
    );
    assert!(
        !schemas["Device"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("hostname"))
    );
    assert_eq!(fixture.bytes(), snapshot);
}

#[path = "api/egress.rs"]
mod egress;

#[test]
fn broadcast_put_checks_revision_and_persists_the_override_independently_of_its_effect() {
    use serde_json::{Value, json};
    let f = Fixture::new();
    let mut service = f.service();
    let device = "/api/v1/users/alice/devices/shared/broadcast";
    let user = "/api/v1/users/alice/broadcast";
    for (path, rev, body, status, generation) in [
        (device, 7, "{}", 400, 7),
        (
            device,
            7,
            r#"{"effective_broadcast":true,"broadcast":false}"#,
            400,
            7,
        ),
        (device, 7, r#"{"broadcast":null}"#, 200, 7),
        (device, 7, r#"{"broadcast":true}"#, 200, 8),
        (device, 7, r#"{"broadcast":true}"#, 412, 8),
        (device, 8, r#"{"broadcast":true}"#, 200, 8),
        (user, 8, r#"{"broadcast":null}"#, 400, 8),
        (user, 8, r#"{"broadcast":false}"#, 200, 9),
        (user, 9, r#"{"broadcast":false}"#, 200, 9),
        (device, 9, r#"{"broadcast":false}"#, 200, 10),
        (device, 10, r#"{"broadcast":null}"#, 200, 11),
    ] {
        let r = authorized(&mut service, "PUT", path, Some(rev), body.as_bytes());
        assert_eq!(r.status, status);
        service = reopen(&f, service);
        let r = authorized(&mut service, "GET", device, None, b"");
        assert_eq!(r.generation, Some(generation));
        let expected = match generation {
            7 => json!({"broadcast":null,"effective_broadcast":true}),
            8 | 9 => json!({"broadcast":true,"effective_broadcast":true}),
            10 => json!({"broadcast":false,"effective_broadcast":false}),
            _ => json!({"broadcast":null,"effective_broadcast":false}),
        };
        assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap(), expected);
        let p = document(&mut service)
            .routing()
            .project_for(&node("gateway-one"))
            .unwrap();
        let saved = wgfeel_core::GatewayProjection::from_json(&p.to_json().unwrap()).unwrap();
        let net = saved
            .config()
            .networks()
            .iter()
            .find(|n| n.id() == &network("alpha"))
            .unwrap();
        let dev = saved.device(&endpoint("alpha", "shared")).unwrap();
        assert_eq!(json!(dev.broadcast()), expected["broadcast"]);
        assert_eq!(
            json!(net.effective_broadcast(dev)),
            expected["effective_broadcast"]
        );
    }
    let r = authorized(
        &mut service,
        "POST",
        "/api/v1/users",
        Some(11),
        br#"{"name":"u","broadcast":null}"#,
    );
    assert_eq!(r.status, 400);
}

#[test]
fn catalog_only_devices_are_visible_and_neither_broadcast_operation_can_register_them() {
    use serde_json::{Value, json};
    let initial = initial();
    let mut clients = initial.clients().to_vec();
    let mut devices = clients[0].devices().to_vec();
    devices.push(catalog("spare", "Unassigned"));
    clients[0] = owner("alice", &["alpha"], devices);
    let f = Fixture::with_document(
        &ManagementDocument::new(initial.routing().clone(), clients).unwrap(),
    );
    let mut service = f.service();
    let r = authorized(
        &mut service,
        "GET",
        "/api/v1/users/alice/devices/spare",
        None,
        b"",
    );
    let obj = serde_json::from_slice::<Value>(&r.body).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(obj.get("addresses"), Some(&json!([])));
    assert_eq!(obj.get("registration"), Some(&Value::Null));
    for (method, rev, b) in [
        ("GET", None, ""),
        ("PUT", Some(7), r#"{"broadcast":false}"#),
    ] {
        let r = authorized(
            &mut service,
            method,
            "/api/v1/users/alice/devices/spare/broadcast",
            rev,
            b.as_bytes(),
        );
        assert_eq!(r.status, 409);
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap(),
            json!({"error":"device_unassigned"})
        );
        let r = authorized(
            &mut service,
            method,
            "/api/v1/users/bob/devices/spare/broadcast",
            rev,
            b.as_bytes(),
        );
        assert_eq!(r.status, 404);
    }
}
