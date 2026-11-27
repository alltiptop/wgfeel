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
    let mut stream = TcpStream::connect_timeout(&address, WAIT).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    let header = token.map(|token| format!("Bearer {token}"));
    stream
        .write_all(
            &http::encode_request(Request {
                method: "GET",
                target,
                authorization: header.as_deref(),
                if_match: None,
                body: b"",
            })
            .unwrap(),
        )
        .unwrap();
    let mut bytes = Vec::new();
    stream
        .take(http::MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    http::decode_response(&bytes).unwrap().unwrap()
}

#[test]
fn external_http_requires_a_token_excludes_internal_rpc_and_changes_port_atomically() {
    let root = Root(std::env::temp_dir().join(format!("wgfeel-rest-{}", std::process::id())));
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
    assert_eq!(exchange(rest, None, "/api/v1/users").status, 401);
    assert_eq!(
        exchange(rest, Some(&STANDARD.encode([9; 32])), "/api/v1/users").status,
        401
    );
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
    let token = zeroize::Zeroizing::new(issued.token.to_owned());
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
