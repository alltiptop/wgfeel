use super::*;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use wgfeel_management::ManagementService;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Installation {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}
impl Installation {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-default-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let config = path.join("instance/config");
        fs::create_dir_all(&config).unwrap();
        fs::set_permissions(path.join("instance"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        // A deliberately unreachable advertised endpoint proves local commands
        // use the installed service without relying on public-IP hairpin routing.
        crate::management::bootstrap::run(&[
            "--traffic".into(),
            "off".into(),
            "--state-dir".into(),
            path.join("instance/state").into_os_string(),
            "--profile".into(),
            config.join("admin.json").into_os_string(),
            "--listen".into(),
            "127.0.0.1:51820".into(),
            "--endpoint".into(),
            "192.0.2.1:51820".into(),
        ])
        .unwrap();
        let mut service = ManagementService::open(&path.join("instance/state")).unwrap();
        let socket = path.join("instance/state/api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let server = thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Zeroizing::new(Vec::new());
                loop {
                    let mut chunk = [0; 4096];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                    assert!(
                        bytes.len() <= http::MAX_HEADER_BYTES + wgfeel_management::MAX_REQUEST_BODY
                    );
                    if let Some(request) = http::decode_request(&bytes).unwrap() {
                        let response = service.handle_local(request);
                        stream.write_all(&http::encode_response(&response)).unwrap();
                        break;
                    }
                }
            }
        });
        Self {
            path,
            stop,
            server: Some(server),
        }
    }
    fn call(&self, args: &[&str]) -> Result<(), &'static str> {
        run_installed(
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            &self.path,
        )
    }
}

#[test]
fn node_add_without_arguments_prints_one_join_command_without_changing_membership() {
    let install = Installation::new();
    let snapshot = fs::read(install.path.join("instance/state/state.json")).unwrap();
    let output = install.ui(&["node", "add"], "").unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("wgfeel join"))
            .collect::<Vec<_>>(),
        ["wgfeel join --invitation-stdin"]
    );
    let uri = output
        .lines()
        .find(|line| line.starts_with("wgfeel://join/"))
        .unwrap();
    let invitation = wgfeel_protocol::enrollment::Invitation::decode(uri).unwrap();
    assert_eq!(
        invitation.endpoints(),
        &["192.0.2.1:51820".parse().unwrap()]
    );
    assert_eq!(output.matches("wgfeel://join/").count(), 1);
    assert_eq!(
        fs::read(install.path.join("instance/state/state.json")).unwrap(),
        snapshot
    );
}
impl Drop for Installation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let result = self.server.take().unwrap().join();
        let _ = fs::remove_dir_all(&self.path);
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

impl Installation {
    fn ui(&self, args: &[&str], input: &str) -> Result<String, &'static str> {
        let mut out = Vec::new();
        run_with_io(
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            &self.path,
            &mut io::Cursor::new(input),
            &mut out,
        )?;
        Ok(String::from_utf8(out).unwrap())
    }
    fn users(&self) -> serde_json::Value {
        let response = call(
            &self.path.join("instance/state/api.sock"),
            "",
            "GET",
            "/api/v1/users",
            None,
            b"",
        )
        .unwrap();
        assert_eq!(response.status, 200);
        serde_json::from_slice(&response.body).unwrap()
    }
    fn gateway(&self) {
        let body = serde_json::json!({
            "id": "edge", "public_key": STANDARD.encode([51; 32]),
            "gateway_public_key": STANDARD.encode([52; 32]), "endpoint": "192.0.2.2:51821"
        });
        let response = call(
            &self.path.join("instance/state/api.sock"),
            "",
            "POST",
            "/api/v1/gateways",
            Some(1),
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        assert!((200..300).contains(&response.status));
    }
}
fn uuid(value: &str) {
    assert_eq!(value.len(), 36);
    assert_eq!(value.as_bytes()[14], b'4');
    assert!(b"89ab".contains(&value.as_bytes()[19]));
}
#[test]
fn installed_menus_generate_ids_show_native_config_and_confirm_every_deletion() {
    let installation = Installation::new();
    installation.gateway();
    let profile = fs::read(installation.path.join("instance/config/admin.json")).unwrap();
    let added = installation
        .ui(&["user", "add", "Alice"], "laptop\n0\n")
        .unwrap();
    assert!(added.contains("User added: Alice"));
    assert!(added.contains("1. add device\n2. remove user\n3. suspend user\n4. show devices"));
    let users = installation.users();
    let id = users["users"][0]["id"].as_str().unwrap();
    let device = users["users"][0]["devices"][0]["id"].as_str().unwrap();
    uuid(id);
    uuid(device);
    assert_ne!(id, device);
    assert_eq!(users["users"][0]["name"], "Alice");
    let screen = installation
        .ui(&["user", "list"], "1\n4\n1\n0\n0\n0\n")
        .unwrap();
    assert!(screen.contains("1. Alice, 1 devices"));
    assert!(screen.contains("1. laptop"));
    assert!(screen.contains("[Interface]\nPrivateKey = "));
    assert!(screen.contains("Address = 10.203.0.2/32, fd77:77::2/128"));
    assert!(screen.contains("Endpoint = 192.0.2.2:51821"));
    assert!(
        installation
            .ui(&["device", "show", device], "")
            .unwrap()
            .contains("laptop:")
    );
    let state = installation.path.join("instance/state/state.json");
    let before = fs::read(&state).unwrap();
    for input in ["", "\n", "n\n", "yes\n", "Y\n"] {
        let screen = installation
            .ui(&["device", "delete", device], input)
            .unwrap();
        assert!(screen.contains(&format!(
            "Delete device laptop ({device}) from user Alice ({id})? (y/n) [n]:"
        )));
        assert!(screen.contains("Cancelled."));
        installation
            .ui(&["user", "remove", "--id", id], input)
            .unwrap();
        installation.ui(&["node", "delete", "edge"], input).unwrap();
        assert_eq!(fs::read(&state).unwrap(), before);
    }
    assert!(
        installation
            .ui(&["user", "add", "Alice"], "phone\n")
            .is_err()
    );
    assert_eq!(fs::read(&state).unwrap(), before);
    installation.ui(&["device", "delete"], "1\n1\ny\n").unwrap();
    assert_eq!(
        installation.users()["users"][0]["devices"],
        serde_json::json!([])
    );
    installation
        .ui(&["device", "add"], "1\nphone\n0\n")
        .unwrap();
    let second = installation.users()["users"][0]["devices"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(second, device);
    uuid(&second);
    installation.ui(&["user", "remove"], "1\ny\n").unwrap();
    assert_eq!(installation.users()["users"], serde_json::json!([]));
    installation.ui(&["node", "delete", "edge"], "y\n").unwrap();
    assert_eq!(
        fs::read(installation.path.join("instance/config/admin.json")).unwrap(),
        profile
    );
}
#[test]
fn suspend_resume_and_token_rotation_preserve_devices_names_and_keys() {
    let installation = Installation::new();
    installation.gateway();
    installation
        .ui(&["user"], "1\nAlice\nlaptop\n0\n0\n")
        .unwrap();
    let users = installation.users();
    let id = users["users"][0]["id"].as_str().unwrap();
    let path = installation.path.join("instance/state/state.json");
    installation.ui(&["user", "show", id], "3\n0\n").unwrap();
    assert_eq!(installation.users()["users"][0]["suspended"], true);
    installation.ui(&["user", "show", id], "3\n0\n").unwrap();
    assert_eq!(installation.users(), users);
    let before: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let first = installation.ui(&["token", "rotate"], "").unwrap();
    let second = installation.ui(&["token", "rotate"], "").unwrap();
    assert_ne!(first, second);
    assert_eq!(STANDARD.decode(first.trim()).unwrap().len(), 32);
    let mut after: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_ne!(before["admin_verifier"], after["admin_verifier"]);
    after["admin_verifier"] = before["admin_verifier"].clone();
    assert_eq!(after, before);
}
#[test]
fn invalid_commands_and_eof_cannot_mutate_state() {
    let installation = Installation::new();
    let path = installation.path.join("instance/state/state.json");
    let before = fs::read(&path).unwrap();
    for args in [
        vec!["user", "list", "--unknown", "value"],
        vec!["user", "add", "Alice", "unexpected"],
        vec!["device", "add", "--name", "a", "--name", "b"],
        vec!["node", "add", "--unknown", "value"],
        vec!["token", "unknown"],
        vec!["user", "remove", "alice"],
    ] {
        assert!(installation.ui(&args, "y\n").is_err());
    }
    for args in [
        vec!["user"],
        vec!["user", "add"],
        vec!["user", "add", "Alice"],
        vec!["device", "delete"],
        vec!["user", "show"],
    ] {
        installation.ui(&args, "").unwrap();
    }
    assert_eq!(fs::read(path).unwrap(), before);
}
#[test]
fn connection_options_and_private_socket_boundaries_remain_enforced() {
    let installation = Installation::new();
    for args in [
        vec!["user", "list", "--socket", "/missing"],
        vec!["user", "list", "--credential-file", "/missing"],
        vec![
            "user",
            "list",
            "--profile",
            "/missing",
            "--socket",
            "/missing",
        ],
    ] {
        assert_eq!(
            installation.call(&args),
            Err("choose --profile or both --socket and --credential-file")
        );
    }
    assert!(
        installation
            .call(&["user", "list", "--profile", "/missing"])
            .is_err()
    );
    let socket = installation.path.join("instance/state/api.sock");
    let state = installation.path.join("instance/state/state.json");
    let before = fs::read(&state).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(installation.ui(&["user", "list"], "").is_err());
    fs::remove_file(socket).unwrap();
    assert!(installation.ui(&["user", "list"], "").is_err());
    assert_eq!(fs::read(state).unwrap(), before);
}
