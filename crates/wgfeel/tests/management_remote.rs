#![cfg(target_os = "linux")]
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::process::{Pid, Signal, kill_process};
use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    net::UdpSocket,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const WAIT: Duration = Duration::from_secs(15);
#[path = "support/api.rs"]
mod api;
#[path = "support/enrollment.rs"]
mod enrollment;
#[path = "support/mesh.rs"]
mod mesh;
#[path = "support/put.rs"]
mod put;
#[path = "support/token.rs"]
mod token;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-remote-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn profile(&self) -> PathBuf {
        self.0.join("admin.json")
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn initialize(&self) {
        self.initialize_on("127.0.0.1:0");
    }
    fn initialize_on(&self, address: &str) {
        self.initialize_with_traffic(address, None);
    }
    fn initialize_with_traffic(&self, address: &str, traffic: Option<&str>) {
        let reserved = UdpSocket::bind(address).unwrap();
        let endpoint = reserved.local_addr().unwrap().to_string();
        drop(reserved);
        let mut args = vec![
            "init".into(),
            "--control".into(),
            "main".into(),
            "--state-dir".into(),
            self.state().into_os_string(),
            "--profile".into(),
            self.profile().into_os_string(),
            "--listen".into(),
            endpoint.clone().into(),
            "--endpoint".into(),
            endpoint.into(),
            "--id".into(),
            "management".into(),
        ];
        args.extend(["--traffic".into(), traffic.unwrap_or("off").into()]);
        let output = spawn(args).wait(WAIT).unwrap();
        assert!(
            output.status.success(),
            "initialization failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn start(&self, generation: u64) -> ManagedChild {
        let mut child = spawn(vec![
            "serve".into(),
            "--control".into(),
            "main".into(),
            "--state-dir".into(),
            self.state().into_os_string(),
        ]);
        let ready: Value = serde_json::from_slice(&child.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["generation"], generation);
        token::provision_remote_profile(&self.state(), &self.profile(), generation);
        child
    }
    fn start_child(&self, id: &str) -> (ManagedChild, std::net::SocketAddr) {
        let state = self.0.join(id);
        let initialized = spawn(vec![
            "init".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            state.as_os_str().into(),
            "--id".into(),
            id.into(),
        ])
        .wait(WAIT)
        .unwrap();
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let mut child = spawn(vec![
            "serve".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            state.into_os_string(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ]);
        let ready: Value = serde_json::from_slice(&child.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["node_id"], id);
        (child, ready["listen"].as_str().unwrap().parse().unwrap())
    }
    fn join_child(&self, id: &str, endpoint: std::net::SocketAddr) {
        let invitation = enrollment::invitation(self);
        let result = spawn(vec![
            "join".into(),
            invitation.encode().unwrap().as_str().into(),
            "--state-dir".into(),
            self.0.join(id).into_os_string(),
            "--endpoint".into(),
            endpoint.to_string().into(),
        ])
        .wait(Duration::from_secs(75))
        .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fn with_wrong_bearer(&self, check: impl FnOnce()) {
        let profile = fs::read(self.profile()).unwrap();
        let mut invalid: Value = serde_json::from_slice(&profile).unwrap();
        invalid["credential"] = serde_json::json!([77; 32].to_vec());
        fs::write(self.profile(), serde_json::to_vec(&invalid).unwrap()).unwrap();
        check();
        fs::write(self.profile(), profile).unwrap();
    }
    fn remote(&self, args: &[&str], input: &str, success: bool) -> String {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        let mut child = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .args(args)
            .arg("--profile")
            .arg(self.profile())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let read = std::thread::spawn(move || {
            let mut s = String::new();
            stdout.read_to_string(&mut s).unwrap();
            s
        });
        let errors = std::thread::spawn(move || {
            let mut s = String::new();
            stderr.read_to_string(&mut s).unwrap();
            s
        });
        // A user operation can perform several separately timed remote API calls.
        let until = std::time::Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("remote command timed out: {:?}", &args[..args.len().min(2)])
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = read.join().unwrap();
        let error = errors.join().unwrap();
        assert_eq!(
            status.success(),
            success,
            "command {:?}: {error}",
            &args[..args.len().min(2)]
        );
        output + &error
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn spawn(args: Vec<OsString>) -> ManagedChild {
    let executable = env!("CARGO_BIN_EXE_wgfeel");
    ManagedChild::spawn(
        ProcessSpec::new(executable.into(), args, vec![], None),
        ProcessLimits {
            max_stdout_bytes: 128 * 1024,
            max_stderr_bytes: 8192,
        },
    )
    .unwrap()
}
fn stop(child: ManagedChild) {
    kill_process(Pid::from_raw(child.id() as i32).unwrap(), Signal::TERM).unwrap();
    assert!(child.wait(WAIT).unwrap().status.success());
}

#[test]
fn remote_commands_share_durable_authority_across_restart_and_require_bearer() {
    for traffic in ["relay", "off"] {
        let fixture = Fixture::new();
        fixture.initialize_with_traffic("127.0.0.1:0", Some(traffic));
        let main = fixture.start(1);
        assert!(
            fixture
                .remote(&["user", "list"], "", true)
                .contains("No users.")
        );
        fixture.with_wrong_bearer(|| {
            assert!(
                fixture
                    .remote(&["user", "list"], "", false)
                    .contains("unauthorized")
            );
        });
        stop(main);
    }

    let fixture = Fixture::new();
    fixture.initialize_with_traffic("127.0.0.1:0", Some("entry"));
    let child = fixture.start(1);
    let (gateway, endpoint) = fixture.start_child("gateway1");
    fixture.join_child("gateway1", endpoint);
    assert!(
        fixture
            .remote(&["user", "add", "Alice"], "Alice’s phone\n0\n", true)
            .contains("User added: Alice")
    );
    let users = api::json(&fixture.state(), "GET", "/api/v1/users", Value::Null);
    let user = users["users"][0]["id"].as_str().unwrap();
    let device = users["users"][0]["devices"][0]["id"].as_str().unwrap();
    assert_eq!(
        fixture.remote(&["_complete", "2", "--", "user", "show", user], "", true),
        format!("{user}\tAlice\n")
    );
    assert_eq!(
        fixture.remote(
            &["_complete", "2", "--", "device", "show", device],
            "",
            true
        ),
        format!("{device}\tAlice / Alice’s phone\n")
    );
    assert!(
        fixture
            .remote(
                &["_complete", "2", "--", "node", "show", "gateway"],
                "",
                true
            )
            .starts_with("gateway1\t")
    );
    let output = std::process::Command::new("bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            r#"source <("$1" completions bash)
COMP_WORDS=("$1" device show "$3" --profile "$2")
COMP_CWORD=3
_wgfeel
printf '%s\n' "${COMPREPLY[@]}"
"#,
            "completion-test",
        ])
        .arg(env!("CARGO_BIN_EXE_wgfeel"))
        .arg(fixture.profile())
        .arg(device)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, format!("{device}\n").as_bytes());
    let before = fixture.remote(&["device", "show", device], "", true);
    assert!(before.contains("Alice’s phone:"));
    assert!(before.contains("[Interface]"));
    stop(child);
    let child = fixture.start(4);
    assert_eq!(
        fixture.remote(&["device", "show", device], "", true),
        before
    );
    fixture.with_wrong_bearer(|| {
        assert_eq!(
            fixture.remote(&["_complete", "2", "--", "user", "show", user], "", true),
            ""
        );
        assert!(
            fixture
                .remote(&["user", "remove", "--id", user], "y\n", false)
                .contains("unauthorized")
        );
    });
    assert_eq!(
        api::json(&fixture.state(), "GET", "/api/v1/users", Value::Null),
        users
    );
    fixture.remote(&["device", "delete", device], "y\n", true);
    fixture.remote(&["user", "remove", "--id", user], "y\n", true);
    fixture.remote(&["node", "delete", "gateway1"], "y\n", true);
    stop(gateway);
    stop(child);
    let child = fixture.start(7);
    assert!(
        fixture
            .remote(&["user", "list"], "", true)
            .contains("No users.")
    );
    let nodes = api::json(&fixture.state(), "GET", "/api/v1/gateways", Value::Null);
    assert_eq!(nodes["gateways"].as_array().unwrap().len(), 1);
    assert_eq!(nodes["gateways"][0]["recipient"], "management");
    stop(child);
}

#[test]
fn management_pushes_mesh_revisions_to_two_gateways_and_withdraws_removed_node() {
    let fixture = Fixture::new();
    fixture.initialize();
    let management = fixture.start(1);
    let mut nodes = Vec::new();
    for (index, id) in ["one", "two"].into_iter().enumerate() {
        let (child, endpoint) = fixture.start_child(id);
        fixture.join_child(id, endpoint);
        let distribution = api::json(&fixture.state(), "GET", "/api/v1/distribution", Value::Null);
        assert_eq!(distribution["generation"], (index + 2) as u64);
        nodes.push((fixture.0.join(id), endpoint.to_string(), child));
    }
    let wait_revision = |state: &PathBuf, generation: u64, revoked: bool| {
        let until = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let disk: Value =
                serde_json::from_slice(&fs::read(state.join("state.json")).unwrap()).unwrap();
            if disk["projection"]["config"]["generation"] == generation {
                assert_eq!(disk["projection"]["revoked"], revoked);
                return disk;
            }
            assert!(
                std::time::Instant::now() < until,
                "configuration was not delivered"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    };
    for (state, _, _) in &nodes {
        let disk = wait_revision(state, 3, false);
        assert_eq!(disk["projection"]["mesh"].as_array().unwrap().len(), 3);
    }
    let wait_applied = |generation: u64, count: usize| {
        let until = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let status = api::json(&fixture.state(), "GET", "/api/v1/distribution", Value::Null);
            let nodes = status["gateways"].as_array().unwrap();
            if status["generation"] == generation
                && nodes.len() == count
                && nodes
                    .iter()
                    .all(|node| node["status"] == "applied" && node["acknowledged"] == generation)
            {
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "application was not acknowledged: {status}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    wait_applied(3, 3);
    stop(management);
    let before: Vec<_> = nodes
        .iter()
        .map(|(state, _, _)| fs::read(state.join("state.json")).unwrap())
        .collect();
    let management = fixture.start(3);
    for (index, (state, _, _)) in nodes.iter().enumerate() {
        assert_eq!(fs::read(state.join("state.json")).unwrap(), before[index]);
    }
    let (offline_state, endpoint, offline) = nodes.remove(0);
    stop(offline);
    api::json(
        &fixture.state(),
        "DELETE",
        "/api/v1/gateways/one",
        Value::Null,
    );
    wait_revision(&nodes[0].0, 4, false);
    let status = api::json(&fixture.state(), "GET", "/api/v1/distribution", Value::Null);
    assert_eq!(status["generation"], 4);
    assert!(
        status["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["id"] == "one" && node["status"] == "pending")
    );
    // The withdrawal target must survive Management restart while offline.
    stop(management);
    let management = fixture.start(4);
    let mut restored = spawn(vec![
        "serve".into(),
        "--control".into(),
        "child".into(),
        "--state-dir".into(),
        offline_state.clone().into_os_string(),
        "--listen".into(),
        endpoint.clone().into(),
    ]);
    let ready: Value = serde_json::from_slice(&restored.next_stdout_line(WAIT).unwrap()).unwrap();
    assert_eq!(ready["generation"], 3);
    wait_revision(&offline_state, 4, true);
    wait_applied(4, 2);
    nodes.push((offline_state, endpoint, restored));
    stop(management);
    for (state, endpoint, child) in nodes {
        stop(child);
        let mut restored = spawn(vec![
            "serve".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            state.into_os_string(),
            "--listen".into(),
            endpoint.into(),
        ]);
        let ready: Value =
            serde_json::from_slice(&restored.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["generation"], 4);
        stop(restored);
    }
}
