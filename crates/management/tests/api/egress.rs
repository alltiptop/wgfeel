use super::*;
use wgfeel_core::Destination;

fn external_profile() -> String {
    format!(
        "[Interface]\r\nPrivateKey = {}\nAddress = 172.16.0.42/24\nAddress = fd80::2/64\nDNS = 10.40.0.53, fd80::53\nMTU = 1280\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = VPN.Example.net.:51820 # provider\nAllowedIPs = 10.40.1.2/16\nAllowedIPs = ::/0\nPersistentKeepalive = 25\n",
        STANDARD.encode([41; 32]),
        STANDARD.encode([42; 32]),
        STANDARD.encode([43; 32])
    )
}

#[test]
fn unplaced_egress_survives_other_changes_and_restart_only_on_main() {
    let doc = initial();
    let mut nodes = doc.routing().assignments().to_vec();
    nodes.push(
        assignment("management", 51, &[], &[])
            .with_endpoint(Some("192.0.2.77:51820".parse().unwrap()))
            .unwrap(),
    );
    let routing =
        ManagementConfig::new(node("management"), doc.routing().config().clone(), nodes).unwrap();
    let fixture =
        Fixture::with_document(&ManagementDocument::new(routing, doc.clients().to_vec()).unwrap());
    // Start from the shape written by the previous release.
    let mut legacy: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    legacy["management_storage_version"] = 6.into();
    legacy["document"]["management_version"] = 1.into();
    legacy["document"]
        .as_object_mut()
        .unwrap()
        .remove("egresses");
    for field in ["user_egresses", "egress_key_reservations"] {
        legacy["document"].as_object_mut().unwrap().remove(field);
    }
    fs::write(
        fixture.path().join("state.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    let mut service = fixture.service();
    let body = serde_json::to_vec(
        &serde_json::json!({"config": external_profile(), "node": null, "users": []}),
    )
    .unwrap();
    let collection = "/api/v1/egresses";
    let response = authorized(&mut service, "POST", collection, Some(7), &body);
    assert_eq!(response.status, 201);
    assert_eq!(response.generation, Some(8));
    let receipt: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let id = receipt["id"].as_str().unwrap();
    let path = format!("{collection}/{id}");
    error(
        &authorized(&mut service, "POST", collection, Some(7), &body),
        412,
    );
    error(
        &authorized(&mut service, "POST", collection, Some(8), &body),
        422,
    );
    assert_eq!(
        authorized(
            &mut service,
            "POST",
            "/api/v1/users",
            Some(8),
            br#"{"name":"Later"}"#
        )
        .status,
        201
    );
    drop(service);
    let mut service = fixture.service();
    let response = authorized(&mut service, "GET", &path, None, b"");
    assert_eq!(response.status, 200);
    let view: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(view["id"], id);
    assert_eq!(view["name"], "vpn.example.net");
    assert_eq!(view["placement_state"], "unassigned");
    assert_eq!(view.get("node"), Some(&serde_json::Value::Null));
    assert_eq!(view.get("pending_node"), Some(&serde_json::Value::Null));
    assert_eq!(
        view["addresses"],
        serde_json::json!(["172.16.0.42", "fd80::2"])
    );
    assert_eq!(
        view["allowed_ips"],
        serde_json::json!(["10.40.0.0/16", "::/0"])
    );
    assert_eq!(view["endpoint"], "vpn.example.net.:51820");
    assert_eq!(view["peer_public_key"], STANDARD.encode([42; 32]));
    assert_eq!(view["has_preshared_key"], true);
    let list = authorized(&mut service, "GET", collection, None, b"");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&list.body).unwrap()["egresses"],
        serde_json::json!([view])
    );
    let state = service.delivery_snapshot().unwrap();
    let routing = state.document().routing();
    let public = state.document().to_json().unwrap();
    assert!(public.contains(id));
    let private_state: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    assert_eq!(private_state["management_storage_version"], 7);
    assert_eq!(private_state["document"]["management_version"], 2);
    let saved = &private_state["secrets"]["egresses"][0];
    assert!(saved["private_key"] == serde_json::json!([41u8; 32].to_vec()));
    assert!(saved["preshared_key"] == serde_json::json!([43u8; 32].to_vec()));
    for byte in [41, 43] {
        for output in [&public, std::str::from_utf8(&response.body).unwrap()] {
            assert!(!output.contains(&STANDARD.encode([byte; 32])));
            assert!(!output.contains(&serde_json::to_string(&[byte; 32]).unwrap()));
        }
    }
    for node in routing.assignments() {
        let projection = routing.project_mesh_for(node.recipient()).unwrap();
        let delivery = state.delivery(&projection).unwrap();
        assert_eq!(
            wgfeel_store::GatewayDelivery::decode(&delivery)
                .unwrap()
                .projection(),
            &projection
        );
        let wire = std::str::from_utf8(&delivery).unwrap();
        assert!(!wire.contains(id));
        for byte in [41, 43] {
            assert!(!wire.contains(&STANDARD.encode([byte; 32])));
            assert!(!wire.contains(&serde_json::to_string(&[byte; 32]).unwrap()));
        }
    }
    assert_eq!(
        authorized(&mut service, "DELETE", &path, Some(9), b"").status,
        200
    );
    drop(service);
    error(
        &authorized(&mut fixture.service(), "GET", &path, None, b""),
        404,
    );
    let deleted: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    assert_eq!(deleted["secrets"]["egresses"], serde_json::json!([]));
}

#[test]
fn invalid_profile_or_unknown_placement_leaves_the_snapshot_unchanged() {
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let mut service = fixture.service();
    for invalid in [
        external_profile().replace("MTU = 1280", "MTU = 1279"),
        external_profile().replace("PrivateKey =", "PostUp = NEVER_ECHO_INPUT\nPrivateKey ="),
        external_profile().replace("Endpoint =", "Endpoint = gateway:80\nEndpoint ="),
        external_profile().replace("VPN.Example.net.", "127.1.2.3"),
        external_profile().replace(
            &STANDARD.encode([42; 32]),
            &STANDARD.encode({
                let mut key = [0u8; 32];
                key[0] = 1;
                key
            }),
        ),
        external_profile() + &" ".repeat(16_384),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({"config":invalid})).unwrap();
        error(
            &authorized(&mut service, "POST", "/api/v1/egresses", Some(7), &body),
            422,
        );
    }
    for (extra, status, reason) in [
        (serde_json::json!({"node":"gateway-a"}), 404, "not_found"),
        (
            serde_json::json!({"users":[{"user":"alice","routes":["0.0.0.0/0"],"dns":{"mode":"none"}}]}),
            409,
            "egress_node_required",
        ),
    ] {
        let mut body = extra;
        body["config"] = external_profile().into();
        let response = authorized(
            &mut service,
            "POST",
            "/api/v1/egresses",
            Some(7),
            &serde_json::to_vec(&body).unwrap(),
        );
        error(&response, status);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["error"],
            reason
        );
    }
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn provider_peer_can_be_shared_but_local_wireguard_identities_cannot() {
    let fixture = Fixture::new();
    let mut service = fixture.service();
    let mut revision = 7;
    let collection = "/api/v1/egresses";
    let import = |service: &mut ManagementService, revision, config| {
        let body =
            serde_json::to_vec(&serde_json::json!({"config": config, "name":"Office"})).unwrap();
        authorized(service, "POST", collection, Some(revision), &body)
    };
    let private = STANDARD.encode([41; 32]);
    for other_private in [41, 45] {
        let response = import(
            &mut service,
            revision,
            external_profile().replace(&private, &STANDARD.encode([other_private; 32])),
        );
        assert_eq!(response.status, 201);
        revision += 1;
    }
    // Importing main's own key must also fail in a deployment where main has
    // no public forwarding assignment.
    let authority = STANDARD.encode(node_key().service().expose_bytes());
    error(
        &import(
            &mut service,
            revision,
            external_profile().replace(&private, &authority),
        ),
        422,
    );
    let list = authorized(&mut service, "GET", collection, None, b"");
    let body: serde_json::Value = serde_json::from_slice(&list.body).unwrap();
    let interface = body["egresses"][0]["interface_public_key"]
        .as_str()
        .unwrap();
    let mut alias = STANDARD.decode(interface).unwrap();
    alias[31] |= 0x80;
    for key in [interface.to_owned(), STANDARD.encode(alias)] {
        let gateway = serde_json::to_vec(&serde_json::json!({
            "id": "collision", "public_key":key, "gateway_public_key":STANDARD.encode([85;32])
        }))
        .unwrap();
        error(
            &authorized(
                &mut service,
                "POST",
                "/api/v1/gateways",
                Some(revision),
                &gateway,
            ),
            422,
        );
    }
    assert_eq!(service.identity().unwrap().1, revision);
}

#[test]
fn snapshot_requires_each_saved_egress_to_match_its_private_material() {
    let fixture = Fixture::new();
    let body = serde_json::to_vec(&serde_json::json!({"config": external_profile()})).unwrap();
    assert_eq!(
        authorized(
            &mut fixture.service(),
            "POST",
            "/api/v1/egresses",
            Some(7),
            &body
        )
        .status,
        201
    );
    let saved: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    for (field, value) in [
        ("private_key", serde_json::json!(vec![48; 32])),
        ("preshared_key", serde_json::Value::Null),
        ("id", "different".into()),
    ] {
        let mut damaged = saved.clone();
        damaged["secrets"]["egresses"][0][field] = value;
        fs::write(
            fixture.path().join("state.json"),
            serde_json::to_vec(&damaged).unwrap(),
        )
        .unwrap();
        assert!(ManagementService::open(&fixture.path()).is_err());
    }
    let mut missing = saved;
    missing.as_object_mut().unwrap().remove("secrets");
    fs::write(
        fixture.path().join("state.json"),
        serde_json::to_vec(&missing).unwrap(),
    )
    .unwrap();
    assert!(ManagementService::open(&fixture.path()).is_err());
}

#[test]
fn remote_administrator_wireguard_key_is_reserved() {
    let fixture = Fixture::new();
    let mut state: serde_json::Value = serde_json::from_slice(&fixture.bytes()).unwrap();
    state["api"] = serde_json::json!({"listen":"127.0.0.1:51820","admin_public_key":vec![42;32]});
    fs::write(
        fixture.path().join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    let mut service = fixture.service();
    let body = serde_json::to_vec(&serde_json::json!({"config":external_profile()})).unwrap();
    error(
        &authorized(&mut service, "POST", "/api/v1/egresses", Some(7), &body),
        422,
    );
    assert_eq!(service.identity().unwrap().1, 7);
}

fn two_entries() -> Fixture {
    let doc = initial();
    let entries = doc
        .routing()
        .assignments()
        .iter()
        .enumerate()
        .map(|(i, n)| {
            n.clone()
                .with_endpoint(Some(format!("192.0.2.{}:51820", i + 1).parse().unwrap()))
                .unwrap()
        })
        .collect();
    let routing =
        ManagementConfig::new(node("management"), doc.routing().config().clone(), entries).unwrap();
    Fixture::with_document(&ManagementDocument::new(routing, doc.clients().to_vec()).unwrap())
}

#[test]
fn move_requires_the_former_nodes_authenticated_release_after_main_restart() {
    let fixture = two_entries();
    let mut service = fixture.service();
    let body =
        serde_json::to_vec(&serde_json::json!({"config":external_profile(),"node":"gateway-one"}))
            .unwrap();
    let response = authorized(&mut service, "POST", "/api/v1/egresses", Some(7), &body);
    assert_eq!(response.status, 201);
    let receipt: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let path = format!("/api/v1/egresses/{}/node", receipt["id"].as_str().unwrap());
    let check_owner = |service: &ManagementService, expected: Option<&str>| {
        let state = service.delivery_snapshot().unwrap();
        for node in state.document().routing().assignments() {
            let projection = state
                .document()
                .routing()
                .project_mesh_for(node.recipient())
                .unwrap();
            let bytes = state.delivery(&projection).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let keys = wire["egress_private_keys"].as_array().unwrap();
            assert_eq!(
                keys.len(),
                usize::from(Some(node.recipient().as_str()) == expected)
            );
            if let Some(entry) = keys.first() {
                assert!(entry["private_key"] == serde_json::json!(vec![41; 32]));
                assert!(entry["preshared_key"] == serde_json::json!(vec![43; 32]));
            }
        }
    };
    check_owner(&service, Some("gateway-one"));
    let response = authorized(
        &mut service,
        "PUT",
        &path,
        Some(8),
        br#"{"node":"gateway-two"}"#,
    );
    assert_eq!(response.status, 202);
    assert_eq!(response.generation, Some(9));
    check_owner(&service, None);
    drop(service);
    let mut service = fixture.service();
    assert!(
        service
            .acknowledge(node("gateway-one"), &key(111), 9)
            .is_err()
    );
    service
        .acknowledge(node("gateway-two"), &key(111), 9)
        .unwrap();
    check_owner(&service, None);
    service
        .acknowledge(node("gateway-one"), &key(101), 9)
        .unwrap();
    check_owner(&service, Some("gateway-two"));
    assert_eq!(service.identity().unwrap().1, 10);
}

fn json_request(
    service: &mut ManagementService,
    method: &str,
    path: &str,
    generation: u64,
    input: serde_json::Value,
    expected: u16,
) -> serde_json::Value {
    let body = if method == "DELETE" {
        vec![]
    } else {
        serde_json::to_vec(&input).unwrap()
    };
    let response = authorized(service, method, path, Some(generation), &body);
    let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        response.status, expected,
        "{method} {path}: {}",
        value["error"]
    );
    value
}
fn imported_id(
    service: &mut ManagementService,
    generation: u64,
    input: serde_json::Value,
) -> String {
    json_request(service, "POST", "/api/v1/egresses", generation, input, 201)["id"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn grants_follow_lpm_and_stay_in_the_export_while_the_secret_is_withdrawn() {
    use serde_json::json;
    let fixture = two_entries();
    let mut service = fixture.service();
    let native = json_request(
        &mut service,
        "POST",
        "/api/v1/users/bob/devices",
        7,
        json!({"name":"Bob phone","gateway":"gateway-one"}),
        201,
    );
    let device = native["id"].as_str().unwrap();
    let export_path = format!("/api/v1/users/bob/devices/{device}/config");
    let export = |svc: &mut ManagementService| {
        let r = authorized(svc, "GET", &export_path, None, b"");
        assert_eq!(r.status, 200);
        std::str::from_utf8(&r.body).unwrap().to_owned()
    };
    let classify = |svc: &mut ManagementService, source: Endpoint, dst: &str| {
        document(svc)
            .routing()
            .project_mesh_for(&node("gateway-one"))
            .unwrap()
            .classify_destination(&source, dst.parse().unwrap())
    };
    let src = endpoint("beta", device);
    let baseline = export(&mut service);
    assert!(!baseline.lines().any(|l| l.starts_with("DNS =")));
    let corp = imported_id(
        &mut service,
        8,
        json!({"config":external_profile(),"node":"gateway-one","users":[
        {"user":"bob","routes":["10.40.0.0/16"],"dns":{"mode":"zones","zones":["Corp.Example"]}}]}),
    );
    let zones_only = export(&mut service);
    assert!(zones_only.contains("# Split DNS: corp.example via 10.40.0.53\n"));
    assert!(!zones_only.lines().any(|l| l.starts_with("DNS =")));
    let broad_config = external_profile()
        .replace(&STANDARD.encode([41; 32]), &STANDARD.encode([61; 32]))
        .replace("10.40.1.2/16", "0.0.0.0/0")
        .replace("10.40.0.53, fd80::53", "9.9.9.9");
    let broad = imported_id(
        &mut service,
        9,
        json!({"config":broad_config,"node":"gateway-two","users":[
        {"user":"bob","routes":["0.0.0.0/0"],"dns":{"mode":"default"}}]}),
    );
    let both = export(&mut service);
    assert!(both.contains("DNS = 9.9.9.9\n"));
    assert!(both.contains("# Split DNS: corp.example via 10.40.0.53\n"));
    assert!(both.contains("# IPv6 internet traffic remains outside the tunnel."));
    assert_eq!(both.matches("AllowedIPs =").count(), 1);
    let allowed = both.lines().find(|l| l.starts_with("AllowedIPs")).unwrap();
    for cidr in ["0.0.0.0/0", "10.40.0.0/16", "10.203.0.0/16", "fd77:77::/64"] {
        assert!(allowed.contains(cidr))
    }
    assert!(
        matches!(classify(&mut service,src.clone(),"10.40.0.9"),Destination::Egress{egress,..} if egress.as_str()==corp)
    );
    assert!(
        matches!(classify(&mut service,src.clone(),"8.8.8.8"),Destination::Egress{egress,..} if egress.as_str()==broad)
    );
    assert_eq!(
        classify(&mut service, src.clone(), "10.203.0.1"),
        Destination::InternalDns
    );
    assert_eq!(
        classify(&mut service, src.clone(), "10.203.99.99"),
        Destination::Drop
    );
    assert_eq!(
        classify(&mut service, src.clone(), "10.3.0.1"),
        Destination::Drop
    );
    assert_eq!(
        classify(&mut service, endpoint("alpha", "shared"), "8.8.8.8"),
        Destination::Drop
    );
    let path = format!("/api/v1/egresses/{corp}/node");
    assert_eq!(
        json_request(
            &mut service,
            "PUT",
            &path,
            10,
            json!({"node":"gateway-two"}),
            202
        )["placement_state"],
        "moving"
    );
    assert!(export(&mut service) == both);
    assert_eq!(
        classify(&mut service, src.clone(), "10.40.0.9"),
        Destination::Drop
    );
    assert!(
        matches!(classify(&mut service,src.clone(),"8.8.8.8"),Destination::Egress{egress,..} if egress.as_str()==broad)
    );
    let grant_path = format!("/api/v1/users/bob/egresses/{corp}");
    assert_eq!(
        json_request(
            &mut service,
            "PUT",
            &path,
            11,
            json!({"node":"gateway-two"}),
            200
        )["placement_state"],
        "moving"
    );
    json_request(&mut service, "DELETE", &grant_path, 11, json!(null), 200);
    let default_only = export(&mut service);
    assert!(default_only.contains("DNS = 9.9.9.9\n"));
    assert!(!default_only.contains("corp.example"));
}

#[test]
fn manual_scope_dns_replacement_and_atomic_initial_grants_reject_before_commit() {
    use serde_json::json;
    let fixture = two_entries();
    let mut service = fixture.service();
    let grant =
        |user: &str| json!({"user":user,"routes":["10.40.0.0/16"],"dns":{"mode":"default"}});
    let config = external_profile().replace("10.40.0.53, fd80::53", "10.40.0.53, 10.40.0.54");
    let before = fixture.bytes();
    assert_eq!(
        json_request(
            &mut service,
            "POST",
            "/api/v1/egresses",
            7,
            json!({"config":config,"node":"gateway-two","users":[grant("bob"),grant("alice")]}),
            409
        )["error"],
        "node_out_of_scope"
    );
    assert_eq!(before, fixture.bytes());
    let id = imported_id(
        &mut service,
        7,
        json!({"name":"Corporate","config":config,"node":"gateway-one","users":[grant("alice"),grant("bob")]}),
    );
    let path = format!("/api/v1/egresses/{id}");
    let stable = fixture.bytes();
    json_request(
        &mut service,
        "PUT",
        &path,
        8,
        json!({"config":config.replace(", 10.40.0.54","")}),
        422,
    );
    json_request(
        &mut service,
        "PUT",
        &format!("{path}/node"),
        8,
        json!({}),
        400,
    );
    json_request(
        &mut service,
        "PUT",
        &format!("{path}/node"),
        8,
        json!({"node":"gateway-two"}),
        409,
    );
    assert_eq!(
        json_request(&mut service, "DELETE", &path, 8, json!(null), 409)["error"],
        "egress_in_use"
    );
    assert_eq!(
        json_request(
            &mut service,
            "DELETE",
            "/api/v1/gateways/gateway-one",
            8,
            json!(null),
            409
        )["error"],
        "node_owns_egresses"
    );
    assert_eq!(stable, fixture.bytes());
    let rotated = config.replace(&STANDARD.encode([43; 32]), &STANDARD.encode([44; 32]));
    assert_eq!(
        json_request(
            &mut service,
            "PUT",
            &path,
            8,
            json!({"config":rotated}),
            200
        )["name"],
        "Corporate"
    );
    let current = document(&mut service);
    assert_eq!(current.routing().egresses()[0].secret_revision, 2);
    assert!(current.routing().egress_policy().reservations.is_empty());
    json_request(&mut service, "PUT", &path, 8, json!({"config":config}), 412);
}

#[test]
fn a_dead_former_owner_cannot_reclaim_the_recovery_key_or_block_a_fresh_key() {
    use serde_json::json;
    let fixture = two_entries();
    let mut svc = fixture.service();
    let config = external_profile();
    let id = imported_id(
        &mut svc,
        7,
        json!({"config":config,"node":"gateway-one","users":[{"user":"bob","routes":["10.40.0.0/16"],"dns":{"mode":"none"}}]}),
    );
    let path = format!("/api/v1/egresses/{id}");
    let placement = format!("{path}/node");
    json_request(
        &mut svc,
        "PUT",
        &placement,
        8,
        json!({"node":"gateway-two"}),
        202,
    );
    json_request(&mut svc, "PUT", &path, 9, json!({"config":config}), 409);
    json_request(&mut svc, "PUT", &placement, 9, json!({"node":null}), 202);
    json_request(
        &mut svc,
        "DELETE",
        "/api/v1/gateways/gateway-one",
        10,
        json!(null),
        200,
    );
    json_request(
        &mut svc,
        "PUT",
        &placement,
        11,
        json!({"node":"gateway-two"}),
        409,
    );
    let fresh = config.replace(&STANDARD.encode([41; 32]), &STANDARD.encode([95; 32]));
    json_request(&mut svc, "PUT", &path, 11, json!({"config":fresh}), 200);
    json_request(
        &mut svc,
        "PUT",
        &placement,
        12,
        json!({"node":"gateway-two"}),
        200,
    );
    assert_eq!(
        json_request(
            &mut svc,
            "POST",
            "/api/v1/egresses",
            13,
            json!({"config":config}),
            409
        )["error"],
        "egress_key_pending_withdrawal"
    );
    let public = document(&mut svc);
    assert_eq!(public.routing().egress_policy().reservations.len(), 1);
    assert_eq!(
        public
            .routing()
            .egress_policy()
            .grants(&ClientId::new("bob").unwrap())[0]
            .egress_id
            .as_str(),
        id
    );
    drop(svc);
    let mut svc = fixture.service();
    assert!(svc.acknowledge(node("gateway-one"), &key(111), 13).is_err());
    svc.acknowledge(node("gateway-one"), &key(101), 13).unwrap();
    assert!(
        document(&mut svc)
            .routing()
            .egress_policy()
            .reservations
            .is_empty()
    );
    assert_eq!(
        document(&mut svc).routing().egresses()[0].node,
        Some(node("gateway-two"))
    );
}

#[test]
fn whole_set_swaps_prefixes_and_dns_atomically_and_rejects_ambiguous_wire_tables() {
    use serde_json::json;
    let fixture = two_entries();
    let mut svc = fixture.service();
    let config = external_profile()
        .replace("10.40.1.2/16", "0.0.0.0/0")
        .replace("10.40.0.53, fd80::53", "10.40.0.53, 10.50.0.53");
    let a = imported_id(&mut svc, 7, json!({"config":config,"node":"gateway-one"}));
    let b = imported_id(
        &mut svc,
        8,
        json!({"config":config.replace(&STANDARD.encode([41;32]),&STANDARD.encode([62;32])),"node":"gateway-one"}),
    );
    let path = "/api/v1/users/bob/egresses";
    let grant = |id: &str, route: &str, dns: serde_json::Value| json!({"egress_id":id,"routes":[route],"dns":dns});
    let default = json!({"mode":"default"});
    let none = json!({"mode":"none"});
    let entry = |id: &str, r: &str| grant(id, r, none.clone());
    let one = "10.40.0.0/16";
    let two = "10.50.0.0/16";
    json_request(
        &mut svc,
        "PUT",
        path,
        9,
        json!({"egresses":[grant(&a,one,default.clone()),entry(&b,two)]}),
        200,
    );
    let before = fixture.bytes();
    assert_eq!(
        json_request(
            &mut svc,
            "PUT",
            path,
            10,
            json!({"egresses":[entry(&a,one),entry(&b,"10.40.3.4/16")]}),
            409
        )["error"],
        "duplicate_egress_prefix"
    );
    assert_eq!(
        json_request(
            &mut svc,
            "PUT",
            path,
            10,
            json!({"egresses":[grant(&a,one,default.clone()),grant(&b,two,default.clone())]}),
            409
        )["error"],
        "conflicting_dns_selection"
    );
    json_request(
        &mut svc,
        "PUT",
        path,
        10,
        json!({"egresses":[grant(&a,"10.55.0.0/16",default.clone())]}),
        422,
    );
    json_request(
        &mut svc,
        "PUT",
        path,
        10,
        json!({"egresses":[entry(&a,"10.203.0.2/32")]}),
        422,
    );
    json_request(
        &mut svc,
        "PUT",
        path,
        10,
        json!({"egresses":[entry("absent",one)]}),
        404,
    );
    assert_eq!(fixture.bytes(), before);
    json_request(
        &mut svc,
        "PUT",
        path,
        10,
        json!({"egresses":[entry(&a,two),grant(&b,one,default)]}),
        200,
    );
    let public = document(&mut svc);
    let projected = public
        .routing()
        .project_mesh_for(&node("gateway-one"))
        .unwrap();
    assert!(
        matches!(projected.classify_destination(&endpoint("beta","shared-beta"),"10.40.0.53".parse().unwrap()),Destination::Egress{egress,..} if egress.as_str()==b)
    );
    let wire = projected.to_json().unwrap();
    let double = wire.replacen(
        "\"routes\":{\"beta\":",
        "\"routes\":{\"beta\":[],\"beta\":",
        1,
    );
    assert_ne!(double, wire);
    assert!(wgfeel_core::GatewayProjection::from_json(&double).is_err());
}

#[test]
fn auto_entry_provisions_a_non_private_lan_tenant_for_an_initial_grant() {
    use serde_json::json;
    let doc = initial();
    let node_id = node("auto-entry");
    let auto = assignment(node_id.as_str(), 121, &[], &[])
        .with_endpoint(Some("192.0.2.83:51820".parse().unwrap()))
        .unwrap()
        .with_auto_networks(true);
    let mut nodes = doc.routing().assignments().to_vec();
    nodes.push(auto);
    let routing =
        ManagementConfig::new(node("management"), doc.routing().config().clone(), nodes).unwrap();
    let fixture =
        Fixture::with_document(&ManagementDocument::new(routing, doc.clients().to_vec()).unwrap());
    let mut svc = fixture.service();
    let id = imported_id(
        &mut svc,
        7,
        json!({"node":"auto-entry","config":external_profile(),"users":[{"user":"alice","routes":["10.40.0.0/16"],"dns":{"mode":"none"}}]}),
    );
    let state = svc.delivery_snapshot().unwrap();
    let routing = state.document().routing();
    let projection = routing.project_mesh_for(&node_id).unwrap();
    assert_eq!(projection.assignment().networks(), &[network("alpha")]);
    assert!(
        state
            .secrets()
            .tenant(&node_id, &network("alpha"))
            .is_some()
    );
    assert!(state.secrets().tenant(&node_id, &network("beta")).is_none());
    let scoped =
        wgfeel_store::GatewayDelivery::decode(&state.delivery(&projection).unwrap()).unwrap();
    assert!(
        scoped
            .egress_keys()
            .get(&wgfeel_core::EgressId::new(&id).unwrap())
            .is_some()
    );
}

#[test]
fn ipv4_only_device_exports_only_its_usable_family_and_rejects_ipv6_only_dns() {
    use serde_json::json;
    let fixture = two_entries();
    let mut svc = fixture.service();
    let device = json_request(
        &mut svc,
        "POST",
        "/api/v1/users/bob/devices",
        7,
        json!({"name":"IPv4 phone","gateway":"gateway-one","addresses":["10.203.0.19"]}),
        201,
    );
    let config = external_profile().replace("10.40.1.2/16", "0.0.0.0/0");
    let id = imported_id(
        &mut svc,
        8,
        json!({"node":"gateway-one","config":config,"users":[{"user":"bob","routes":["0.0.0.0/0","::/0"],"dns":{"mode":"default"}}]}),
    );
    let path = format!(
        "/api/v1/users/bob/devices/{}/config",
        device["id"].as_str().unwrap()
    );
    let export = authorized(&mut svc, "GET", &path, None, b"");
    let text = std::str::from_utf8(&export.body).unwrap();
    assert!(text.contains("DNS = 10.40.0.53\n"));
    let allowed = text.lines().find(|l| l.starts_with("AllowedIPs")).unwrap();
    assert!(allowed.contains("0.0.0.0/0") && !allowed.contains(':'));
    assert!(!text.contains("IPv6 internet traffic remains"));
    let current = fixture.bytes();
    json_request(
        &mut svc,
        "PUT",
        &format!("/api/v1/users/bob/egresses/{id}"),
        9,
        json!({"routes":["::/0"],"dns":{"mode":"default"}}),
        422,
    );
    assert_eq!(current, fixture.bytes());
}

#[test]
fn independent_entry_nodes_cannot_claim_the_same_interface_key_or_egress_id() {
    use serde_json::json;
    let fixture = two_entries();
    let mut svc = fixture.service();
    let profile = external_profile();
    let first = imported_id(&mut svc, 7, json!({"config":profile,"node":"gateway-one"}));
    json_request(
        &mut svc,
        "POST",
        "/api/v1/egresses",
        8,
        json!({"config":profile,"node":"gateway-two"}),
        422,
    );
    imported_id(
        &mut svc,
        8,
        json!({"config":profile.replace(&STANDARD.encode([41;32]),&STANDARD.encode([84;32])),"node":"gateway-two"}),
    );
    let doc = document(&mut svc);
    let wire: serde_json::Value = serde_json::from_str(&doc.to_json().unwrap()).unwrap();
    for field in ["id", "interface_public_key"] {
        let mut invalid = wire.clone();
        invalid["egresses"][1][field] = wire["egresses"][0][field].clone();
        assert!(ManagementDocument::from_json(&invalid.to_string()).is_err());
    }
    let placement = format!("/api/v1/egresses/{first}/node");
    json_request(&mut svc, "PUT", &placement, 9, json!({"node":null}), 202);
    json_request(
        &mut svc,
        "DELETE",
        "/api/v1/gateways/gateway-one",
        10,
        json!(null),
        200,
    );
    let before = fixture.bytes();
    json_request(
        &mut svc,
        "POST",
        "/api/v1/gateways",
        11,
        json!({
            "id":"gateway-one", "public_key":STANDARD.encode([89;32]),
            "gateway_public_key":STANDARD.encode([90;32]),"endpoint":"192.0.2.129:51820"
        }),
        409,
    );
    assert_eq!(before, fixture.bytes());
}
