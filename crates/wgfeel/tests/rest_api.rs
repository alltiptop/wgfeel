//! External integrations use HTTP/TCP, independently of the node WG transport.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};
use wgfeel_protocol::{Request, Response, http};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

const WAIT: Duration = Duration::from_secs(10);
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command(args: Vec<OsString>) -> ManagedChild {
    ManagedChild::spawn(
        ProcessSpec::new(env!("CARGO_BIN_EXE_wgfeel").into(), args, vec![], None),
        ProcessLimits {
            max_stdout_bytes: 16384,
            max_stderr_bytes: 8192,
        },
    )
    .unwrap()
}
fn run(args: Vec<OsString>) -> wgfeel_test_support::CapturedOutput {
    command(args).wait(WAIT).unwrap()
}
fn exchange(address: SocketAddr, token: Option<&str>, target: &str) -> Response {
    let header = token.map(|token| zeroize::Zeroizing::new(format!("Bearer {token}")));
    let bytes = http::encode_request(Request {
        method: "GET",
        target,
        authorization: header.as_ref().map(|s| s.as_str()),
        if_match: None,
        body: b"",
    })
    .unwrap();
    tcp_exchange(address, &bytes)
}

fn tcp_exchange(address: SocketAddr, bytes: &[u8]) -> Response {
    let mut stream = TcpStream::connect_timeout(&address, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream.write_all(bytes).unwrap();
    let mut bytes = Vec::new();
    stream
        .take(http::MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    http::decode_response(&bytes).unwrap().unwrap()
}

fn start_external(name: &str) -> (Root, SocketAddr, SocketAddr, ManagedChild) {
    let root =
        Root(std::env::temp_dir().join(format!("wgfeel-rest-{name}-{}", std::process::id())));
    fs::create_dir(&root.0).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let mesh = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mesh_address = mesh.local_addr().unwrap();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let rest = reserve.local_addr().unwrap();
    let state = root.0.join("state");
    let profile = root.0.join("admin.json");
    let initialized = run(vec![
        "init".into(),
        "--control".into(),
        "main".into(),
        "--state-dir".into(),
        state.clone().into(),
        "--profile".into(),
        profile.into(),
        "--listen".into(),
        mesh_address.to_string().into(),
        "--endpoint".into(),
        mesh_address.to_string().into(),
        "--api-port".into(),
        rest.port().to_string().into(),
    ]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    drop(reserve);
    drop(mesh);
    let mut server = command(vec![
        "serve".into(),
        "--control".into(),
        "main".into(),
        "--state-dir".into(),
        state.clone().into(),
    ]);
    let ready: serde_json::Value =
        serde_json::from_slice(&server.next_stdout_line(WAIT).unwrap()).unwrap();
    assert_eq!(ready["event"], "ready");
    (root, mesh_address, rest, server)
}

fn rotate_token(state: &std::path::Path) -> (zeroize::Zeroizing<String>, u64) {
    // Rotate through the owner-only socket; do not persist or print the token.
    let mut stream = UnixStream::connect(state.join("api.sock")).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream
        .write_all(
            &http::encode_request(Request {
                method: "POST",
                target: "/api/v1/token/rotate",
                authorization: None,
                if_match: Some("\"1\""),
                body: b"",
            })
            .unwrap(),
        )
        .unwrap();
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    stream.read_to_end(&mut bytes).unwrap();
    let response = http::decode_response(&bytes).unwrap().unwrap();
    assert_eq!(response.status, 200);
    #[derive(serde::Deserialize)]
    struct Issued<'a> {
        token: &'a str,
    }
    let issued: Issued<'_> = serde_json::from_slice(&response.body).unwrap();
    (
        zeroize::Zeroizing::new(issued.token.to_owned()),
        response.generation.unwrap(),
    )
}

#[test]
fn external_http_requires_a_token_excludes_internal_rpc_and_changes_port_atomically() {
    let (root, mesh_address, rest, server) = start_external("port");
    let state = root.0.join("state");
    assert_eq!(exchange(rest, None, "/api/v1/users").status, 401);
    assert_eq!(
        exchange(rest, Some(&STANDARD.encode([9; 32])), "/api/v1/users").status,
        401
    );
    let (token, _) = rotate_token(&state);
    let token = token.as_str();
    assert_eq!(exchange(rest, Some(token), "/api/v1/users").status, 200);
    assert_eq!(
        exchange(rest, Some(token), "/internal/v1/config").status,
        404
    );
    assert_eq!(
        exchange(rest, Some(token), "/local/v1/rest-api").status,
        404
    );
    let before = fs::read(state.join("state.json")).unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let rejected = run(vec![
        "api".into(),
        "port".into(),
        occupied.local_addr().unwrap().port().to_string().into(),
        "--state-dir".into(),
        state.clone().into(),
    ]);
    assert!(!rejected.status.success());
    assert_eq!(fs::read(state.join("state.json")).unwrap(), before);
    let next = occupied.local_addr().unwrap();
    drop(occupied);
    let changed = run(vec![
        "api".into(),
        "port".into(),
        next.port().to_string().into(),
        "--state-dir".into(),
        state.clone().into(),
    ]);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    assert!(TcpStream::connect(rest).is_err());
    assert_eq!(exchange(next, Some(token), "/api/v1/users").status, 200);
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("state.json")).unwrap()).unwrap();
    let mut expected: serde_json::Value = serde_json::from_slice(&before).unwrap();
    expected["rest_api"]["listen"] = serde_json::json!(next);
    assert_eq!(after, expected);
    assert!(
        UdpSocket::bind(mesh_address).is_err(),
        "mesh listener must remain active"
    );
    server.terminate().unwrap();
    let mut server = command(vec![
        "serve".into(),
        "--control".into(),
        "main".into(),
        "--state-dir".into(),
        state.into(),
    ]);
    let ready: serde_json::Value =
        serde_json::from_slice(&server.next_stdout_line(WAIT).unwrap()).unwrap();
    assert_eq!(ready["event"], "ready");
    assert_eq!(exchange(next, Some(token), "/api/v1/users").status, 200);
    let schema = "/api/v1/openapi.json";
    assert_eq!(exchange(next, None, schema).status, 401);
    assert_eq!(
        exchange(next, Some(&STANDARD.encode([9; 32])), schema).status,
        401
    );
    let response = exchange(next, Some(token), schema);
    assert_eq!(
        (response.status, response.generation, response.is_config),
        (200, Some(1), false)
    );
    assert_eq!(
        response.body.as_slice(),
        include_bytes!("../../../docs/openapi.json").as_slice()
    );
    let document: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(document["openapi"], "3.1.2");
    assert_eq!(
        document["security"],
        serde_json::json!([{"adminBearer":[]}])
    );
    assert_eq!(
        document["components"]["securitySchemes"]["adminBearer"]["scheme"],
        "bearer"
    );
    server.terminate().unwrap();
}

#[test]
fn external_http_put_checks_framing_revision_and_redacts_provider_secrets() {
    use zeroize::{Zeroize, Zeroizing};
    #[derive(serde::Deserialize)]
    struct Admin {
        admin_private_key: [u8; 32],
    }
    impl Drop for Admin {
        fn drop(&mut self) {
            self.admin_private_key.zeroize();
        }
    }
    let (root, _, address, server) = start_external("put");
    let profile = Zeroizing::new(fs::read(root.0.join("admin.json")).unwrap());
    let admin: Admin = serde_json::from_slice(&profile).unwrap();
    let (token, initial_revision) = rotate_token(&root.0.join("state"));
    let credential = Zeroizing::new(STANDARD.decode(token.as_bytes()).unwrap());
    let private = [41; 32];
    let preshared = [43; 32];
    let config = Zeroizing::new(format!(
        "[Interface]\nPrivateKey = {}\nAddress = 172.16.0.41/24\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\n",
        STANDARD.encode(private),
        STANDARD.encode([42; 32]),
        STANDARD.encode(preshared)
    ));
    let body = |name: &str| {
        #[derive(serde::Serialize)]
        struct Import<'a> {
            config: &'a str,
            name: &'a str,
        }
        Zeroizing::new(
            serde_json::to_vec(&Import {
                config: &config,
                name,
            })
            .unwrap(),
        )
    };
    let send = |method: &str, path: &str, revision: Option<u64>, headers: &str, body: &[u8]| {
        let revision = revision
            .map(|g| format!("If-Match: \"{g}\"\r\n"))
            .unwrap_or_default();
        let head = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: wgfeel\r\nAuthorization: Bearer {}\r\n{revision}{headers}Connection: close\r\n\r\n",
            token.as_str()
        ));
        let mut bytes = Zeroizing::new(Vec::with_capacity(head.len() + body.len()));
        bytes.extend_from_slice(head.as_bytes());
        bytes.extend_from_slice(body);
        tcp_exchange(address, &bytes)
    };
    let redacted = |response: &Response| {
        let text = std::str::from_utf8(&response.body).unwrap();
        for marker in [
            "[Interface]",
            "PrivateKey =",
            "PresharedKey =",
            "\"config\":",
        ] {
            assert!(
                !text.contains(marker),
                "response exposed the submitted configuration"
            );
        }
        for key in [
            private.as_slice(),
            preshared.as_slice(),
            credential.as_slice(),
            admin.admin_private_key.as_slice(),
        ] {
            let encoded = Zeroizing::new(STANDARD.encode(key));
            let array = Zeroizing::new(serde_json::to_string(key).unwrap());
            assert!(
                !text.contains(encoded.as_str()) && !text.contains(array.as_str()),
                "response exposed private material"
            );
        }
    };
    let valid = |body: &[u8]| {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let collection = "/api/v1/egresses";
    let create = body("original");
    let created = send(
        "POST",
        collection,
        Some(initial_revision),
        &valid(&create),
        &create,
    );
    redacted(&created);
    assert_eq!(created.status, 201);
    let record: serde_json::Value = serde_json::from_slice(&created.body).unwrap();
    let path = format!("{collection}/{}", record["id"].as_str().unwrap());
    let generation = created.generation.unwrap();
    let update = body("updated");
    let framing = valid(&update);
    let repeated = format!("{framing}Content-Length: {}\r\n", update.len());
    let plain = format!(
        "Content-Type: text/plain\r\nContent-Length: {}\r\n",
        update.len()
    );
    for (headers, revision, expected) in [
        (repeated.as_str(), Some(generation), 400),
        ("Content-Type: application/json\r\n", Some(generation), 411),
        (plain.as_str(), Some(generation), 415),
        (framing.as_str(), Some(initial_revision), 412),
    ] {
        let rejected = send("PUT", &path, revision, headers, &update);
        assert_eq!(rejected.status, expected);
        redacted(&rejected);
    }
    let updated = send("PUT", &path, Some(generation), &framing, &update);
    assert_eq!(
        (updated.status, updated.generation),
        (200, Some(generation + 1))
    );
    redacted(&updated);
    let saved = exchange(address, Some(&token), &path);
    assert_eq!((saved.status, saved.generation), (200, updated.generation));
    redacted(&saved);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&saved.body).unwrap()["name"],
        "updated"
    );
    server.terminate().unwrap();
}

#[test]
fn stopped_main_can_enable_http_and_rejects_invalid_or_occupied_ports_without_writes() {
    let root =
        Root(std::env::temp_dir().join(format!("wgfeel-rest-stopped-{}", std::process::id())));
    fs::create_dir(&root.0).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.0.join("state");
    let initialized = run(vec![
        "init".into(),
        "--control".into(),
        "main".into(),
        "--state-dir".into(),
        state.clone().into(),
        "--profile".into(),
        root.0.join("admin.json").into(),
        "--listen".into(),
        "127.0.0.1:51820".into(),
        "--endpoint".into(),
        "127.0.0.1:51820".into(),
    ]);
    assert!(initialized.status.success());
    let settings = |port: Option<String>| {
        let mut args: Vec<OsString> = vec!["api".into(), "port".into()];
        args.extend(port.map(OsString::from));
        args.extend(["--state-dir".into(), state.clone().into()]);
        run(args)
    };
    let show = settings(None);
    assert!(show.status.success());
    assert!(
        String::from_utf8(show.stdout)
            .unwrap()
            .contains("not configured")
    );
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap();
    let before = fs::read(state.join("state.json")).unwrap();
    for invalid in [
        "0".into(),
        "65536".into(),
        "-1".into(),
        address.port().to_string(),
    ] {
        assert!(!settings(Some(invalid)).status.success());
        assert_eq!(fs::read(state.join("state.json")).unwrap(), before);
    }
    drop(occupied);
    assert!(settings(Some(address.port().to_string())).status.success());
    let show = settings(None);
    assert!(show.status.success());
    assert!(
        String::from_utf8(show.stdout)
            .unwrap()
            .contains(&address.to_string())
    );
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("state.json")).unwrap()).unwrap();
    let mut expected: serde_json::Value = serde_json::from_slice(&before).unwrap();
    expected["rest_api"] = serde_json::json!({"listen":address});
    assert_eq!(after, expected);
    assert!(
        TcpListener::bind(address).is_ok(),
        "offline command must not retain a listener"
    );
}
