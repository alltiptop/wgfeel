#![cfg(target_os = "linux")]

use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::{
    fd::OwnedFd,
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, listen, socket_with},
    pipe::{PipeFlags, pipe_with},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, kill_process_group, waitid},
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use wgfeel_core::{AdminCredential, Config, ManagementConfig, ManagementDocument, NodeId, Policy};
use wgfeel_store::ManagementStore;
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

const WAIT: Duration = Duration::from_secs(5);
const CAPTURE: usize = 128 * 1024;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-mcli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self(root);
        ManagementStore::initialize(&fixture.state())
            .unwrap()
            .commit(
                &empty_document(7),
                &wgfeel_test_support::fixture_node_keys([197; 32]),
                &AdminCredential::new([211; 32]).unwrap(),
                None,
            )
            .unwrap();
        private_write(
            &fixture.token(),
            format!("{}\n", STANDARD.encode([211; 32])).as_bytes(),
        );
        fixture
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn socket(&self) -> PathBuf {
        self.state().join("api.sock")
    }
    fn token(&self) -> PathBuf {
        self.0.join("admin.token")
    }
    fn state_bytes(&self) -> Vec<u8> {
        fs::read(self.state().join("state.json")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn empty_document(generation: u64) -> ManagementDocument {
    ManagementDocument::new(
        ManagementConfig::new(
            NodeId::new("management").unwrap(),
            Config::new(generation, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![],
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}

fn private_write(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn spawn(arguments: Vec<OsString>) -> ManagedChild {
    ManagedChild::spawn(
        ProcessSpec::new(env!("CARGO_BIN_EXE_wgfeel").into(), arguments, vec![], None),
        ProcessLimits {
            max_stdout_bytes: CAPTURE,
            max_stderr_bytes: CAPTURE,
        },
    )
    .unwrap()
}

fn assert_no_secrets(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for byte in [197_u8, 211, 212] {
        assert!(
            !text.contains(&STANDARD.encode([byte; 32])),
            "secret in output"
        );
        assert!(
            !text.contains(&format!("{:?}", [byte; 32])),
            "secret in output"
        );
        assert!(
            !text.contains(&format!("{:?}", [byte; 32]).replace(' ', "")),
            "secret in output"
        );
    }
    assert!(!text.contains("service_private_key"));
    assert!(!text.contains("admin_credential"));
}

fn checked_output(output: CapturedOutput, success: bool) -> Vec<u8> {
    assert_no_secrets(&output.stdout);
    assert_no_secrets(&output.stderr);
    assert_eq!(
        output.status.success(),
        success,
        "unexpected CLI exit status"
    );
    output
        .stdout
        .strip_suffix(b"\n")
        .unwrap_or(&output.stdout)
        .to_vec()
}

struct Runtime(ManagedChild);
impl Runtime {
    fn spawn(fixture: &Fixture) -> Self {
        Self(spawn(vec![
            "serve".into(),
            "--control".into(),
            "main".into(),
            "--state-dir".into(),
            fixture.state().into_os_string(),
        ]))
    }
    fn ready(&mut self, generation: u64) {
        let line = self
            .0
            .next_stdout_line(WAIT)
            .expect("Management exited before readiness");
        assert_no_secrets(&line);
        let event: Value = serde_json::from_slice(&line).expect("ready event must be JSON");
        assert_eq!(event["event"], "ready");
        assert_eq!(event["control"], "main");
        assert_eq!(event["management_id"], "management");
        assert_eq!(event["generation"], generation);
    }
    fn stop(self) {
        kill_process(Pid::from_raw(self.0.id() as i32).unwrap(), Signal::TERM).unwrap();
        let output = self
            .0
            .wait(WAIT)
            .expect("Management did not shut down promptly");
        checked_output(output, true);
    }
}

fn client_at(socket: &Path, token: &Path, args: &[&str], success: bool) -> Vec<u8> {
    // Global options before the subcommand exercise parsing anywhere after the verb.
    let mut arguments = vec![
        args[0].into(),
        "--socket".into(),
        socket.as_os_str().to_owned(),
        "--credential-file".into(),
        token.as_os_str().to_owned(),
    ];
    arguments.extend(args[1..].iter().map(OsString::from));
    checked_output(spawn(arguments).wait(WAIT).unwrap(), success)
}

fn client_human(fixture: &Fixture, args: &[&str], success: bool) -> Vec<u8> {
    client_at(&fixture.socket(), &fixture.token(), args, success)
}

struct HttpResponse {
    status: u16,
    generation: Option<u64>,
    body: Vec<u8>,
}

// Independent framing deliberately does not call wgfeel_management::http.
fn http(
    fixture: &Fixture,
    method: &str,
    path: &str,
    revision: Option<u64>,
    body: &[u8],
    credential: u8,
) -> HttpResponse {
    let mut stream = UnixStream::connect(fixture.socket()).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: wgfeel\r\nAuthorization: Bearer {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        STANDARD.encode([credential; 32]),
        body.len()
    );
    if method == "POST" {
        request.push_str("Content-Type: application/json\r\n");
    }
    if let Some(revision) = revision {
        request.push_str(&format!("If-Match: \"{revision}\"\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut output = vec![];
    stream
        .take((CAPTURE + 1) as u64)
        .read_to_end(&mut output)
        .unwrap();
    assert!(
        output.len() <= CAPTURE,
        "HTTP response exceeded fixture bound"
    );
    assert_no_secrets(&output);
    let end = output
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&output[..end]).unwrap();
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap();
    assert!(status_line.starts_with("HTTP/1.1 "));
    let status = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let (mut length, mut generation) = (None, None);
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            assert!(length.replace(value.parse::<usize>().unwrap()).is_none());
        }
        if name.eq_ignore_ascii_case("etag") {
            let revision = value.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
            assert!(generation.replace(revision.parse().unwrap()).is_none());
        }
    }
    let body = output[end + 4..].to_vec();
    assert_eq!(length, Some(body.len()));
    HttpResponse {
        status,
        generation,
        body,
    }
}

fn config(fixture: &Fixture) -> ManagementDocument {
    let response = http(fixture, "GET", "/api/v1/config", None, b"", 211);
    assert_eq!(response.status, 200);
    let document =
        ManagementDocument::from_json(std::str::from_utf8(&response.body).unwrap()).unwrap();
    assert_eq!(response.generation, Some(document.routing().generation()));
    document
}

#[test]
fn command_help_is_multiline_and_invalid_arguments_are_rejected_before_connecting() {
    for kind in ["user", "device", "node", "config", "token"] {
        let output = spawn(vec![kind.into(), "--help".into()])
            .wait(WAIT)
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        let listed: Vec<_> = help
            .lines()
            .filter(|line| line.starts_with("  wgfeel "))
            .collect();
        assert!(!listed.is_empty());
        assert!(
            listed
                .iter()
                .all(|line| line.split_whitespace().nth(1) == Some(kind))
        );
    }
    for args in [
        vec!["user", "list", "--unknown", "value"],
        vec!["user", "add", "alice", "unexpected"],
        vec!["device", "add", "--name", "a", "--name", "b"],
        vec!["user", "remove", "alice"],
    ] {
        let output = spawn(args.iter().map(OsString::from).collect())
            .wait(WAIT)
            .unwrap();
        assert!(!output.status.success());
    }
    let fixture = Fixture::new();
    assert!(
        terminal(&fixture, &["user"], "", true)
            .contains("1. add user\n2. remove user\n3. show list")
    );
}
fn terminal(fixture: &Fixture, args: &[&str], input: &str, success: bool) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
        .args(args)
        .arg("--socket")
        .arg(fixture.socket())
        .arg("--credential-file")
        .arg(fixture.token())
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
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("interactive command timed out")
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    assert_no_secrets(&stderr);
    assert_eq!(
        status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    String::from_utf8(stdout).unwrap()
}
#[test]
fn interactive_cli_and_rest_share_generated_ids_names_configs_and_confirmed_deletions() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    let added = http(
        &fixture,
        "POST",
        "/api/v1/gateways",
        Some(7),
        &serde_json::to_vec(&json!({"id":"edge", "public_key":STANDARD.encode([51;32]),
            "gateway_public_key":STANDARD.encode([52;32]),"endpoint":"192.0.2.2:51821"}))
        .unwrap(),
        211,
    );
    assert!((200..300).contains(&added.status));
    let added = terminal(&fixture, &["user", "add", "Alice"], "laptop\n0\n", true);
    assert!(added.contains("User added: Alice"));
    let document = config(&fixture);
    assert_eq!(document.routing().generation(), 10);
    let user = document.clients()[0].id().as_str();
    let device = document.clients()[0].devices()[0].id().as_str();
    assert_eq!(document.clients()[0].name(), "Alice");
    assert_eq!(user.len(), 36);
    assert_eq!(device.len(), 36);
    assert_ne!(user, device);
    let exported = http(
        &fixture,
        "GET",
        &format!("/api/v1/users/{user}/devices/{device}/config"),
        None,
        b"",
        211,
    );
    assert_eq!(exported.status, 200);
    let config_text = std::str::from_utf8(&exported.body).unwrap();
    assert!(config_text.contains("# Node: edge\n[Peer]\n"));
    assert!(config_text.contains("# IPv4\nEndpoint = 192.0.2.2:51821\n"));
    assert!(terminal(&fixture, &["device", "show", device], "", true).contains(config_text));
    let before = fixture.state_bytes();
    // The UI tests cover every cancellation spelling. Here each command must
    // also leave the running service's durable state untouched.
    for (args, input) in [
        (vec!["device", "delete", device], ""),
        (vec!["user", "remove", "--id", user], "n\n"),
        (vec!["node", "delete", "edge"], "yes\n"),
    ] {
        assert!(terminal(&fixture, &args, input, true).contains("Cancelled."));
        assert_eq!(fixture.state_bytes(), before);
    }
    terminal(
        &fixture,
        &["device", "add", "--user", user, "--name", "phone"],
        "0\n",
        true,
    );
    assert_eq!(config(&fixture).clients()[0].devices().len(), 2);
    terminal(&fixture, &["device", "delete"], "1\n1\ny\n", true);
    assert_eq!(config(&fixture).clients()[0].devices().len(), 1);
    terminal(&fixture, &["user", "remove"], "1\ny\n", true);
    assert!(config(&fixture).clients().is_empty());
    terminal(&fixture, &["node", "delete", "edge"], "y\n", true);
    assert!(config(&fixture).routing().assignments().is_empty());
    runtime.stop();
    let mut restarted = Runtime::spawn(&fixture);
    restarted.ready(14);
    assert!(config(&fixture).clients().is_empty());
    restarted.stop();
}
#[test]
fn stale_revision_wrong_bearer_and_manual_ids_never_change_durable_state() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    let response = http(
        &fixture,
        "POST",
        "/api/v1/users",
        Some(7),
        br#"{"name":"Alice"}"#,
        211,
    );
    assert_eq!(response.status, 201);
    let id = serde_json::from_slice::<Value>(&response.body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = fixture.state_bytes();
    assert_eq!(
        http(
            &fixture,
            "POST",
            "/api/v1/users",
            Some(7),
            br#"{"name":"Bob"}"#,
            211
        )
        .status,
        412
    );
    assert_eq!(
        http(
            &fixture,
            "POST",
            "/api/v1/users",
            Some(8),
            br#"{"name":"Bob","id":"manual"}"#,
            211
        )
        .status,
        400
    );
    assert_eq!(
        http(
            &fixture,
            "DELETE",
            &format!("/api/v1/users/{id}"),
            None,
            b"",
            211
        )
        .status,
        428
    );
    assert_eq!(
        http(
            &fixture,
            "DELETE",
            &format!("/api/v1/users/{id}"),
            Some(8),
            b"",
            212
        )
        .status,
        401
    );
    let wrong = fixture.0.join("wrong.token");
    private_write(&wrong, STANDARD.encode([212; 32]).as_bytes());
    client_at(&fixture.socket(), &wrong, &["config", "show"], false);
    assert_eq!(fixture.state_bytes(), before);
    runtime.stop();
}
#[test]
fn graceful_service_restart_preserves_document_identity_and_credential() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    assert_eq!(
        http(
            &fixture,
            "POST",
            "/api/v1/users",
            Some(7),
            br#"{"name":"Alice"}"#,
            211
        )
        .status,
        201
    );
    let before = config(&fixture);
    runtime.stop();
    assert!(
        !fixture.socket().exists(),
        "shutdown retained its API socket"
    );
    let store = ManagementStore::open(&fixture.state()).unwrap();
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.document(), &before);
    assert!(state.service_private_key().expose_bytes() == &[197; 32]);
    assert!(state.admin_verifier().verify(&[211; 32]));
    drop(store);
    let mut restarted = Runtime::spawn(&fixture);
    restarted.ready(8);
    assert_eq!(config(&fixture), before);
    assert!(
        String::from_utf8(client_human(&fixture, &["config", "show"], true))
            .unwrap()
            .starts_with("Configuration\n")
    );
    restarted.stop();
}

#[test]
fn killed_service_recovers_only_its_stale_socket_and_retains_committed_state() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    assert_eq!(
        http(
            &fixture,
            "POST",
            "/api/v1/users",
            Some(7),
            br#"{"name":"Alice"}"#,
            211
        )
        .status,
        201
    );
    let before = config(&fixture);
    let bytes = fixture.state_bytes();
    // ManagedChild retains ownership through SIGKILL and reaps before restart.
    checked_output(runtime.0.terminate().unwrap(), false);
    assert!(
        fs::symlink_metadata(fixture.socket())
            .unwrap()
            .file_type()
            .is_socket()
    );
    let mut restarted = Runtime::spawn(&fixture);
    restarted.ready(8);
    assert_eq!(config(&fixture), before);
    assert_eq!(fixture.state_bytes(), bytes);
    restarted.stop();
    let store = ManagementStore::open(&fixture.state()).unwrap();
    let state = store.load().unwrap().unwrap();
    assert!(state.service_private_key().expose_bytes() == &[197; 32]);
    assert!(state.admin_verifier().verify(&[211; 32]));
}

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    let deadline = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                return stream;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => panic!("CLI did not connect within the fixture deadline"),
        }
    }
}

fn read_client_request(stream: &mut UnixStream) -> (String, Vec<(String, String)>, Vec<u8>) {
    let mut input = vec![];
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(
            Instant::now() < deadline,
            "CLI request exceeded fixture deadline"
        );
        assert!(input.len() < 8192, "CLI request exceeded fixture bound");
        let mut chunk = [0; 1024];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "CLI ended an incomplete request");
        input.extend_from_slice(&chunk[..count]);
        let Some(end) = input.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            continue;
        };
        let text = std::str::from_utf8(&input[..end]).unwrap();
        let mut lines = text.split("\r\n");
        let first = lines.next().unwrap().to_owned();
        let headers: Vec<(String, String)> = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let lengths: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name == "content-length")
            .collect();
        assert!(lengths.len() <= 1);
        let length = lengths
            .first()
            .map_or(0, |entry| entry.1.parse::<usize>().unwrap());
        assert!(length <= 4096);
        if input.len() < end + 4 + length {
            continue;
        }
        assert_eq!(input.len(), end + 4 + length);
        return (first, headers, input[end + 4..].to_vec());
    }
}

fn reply(stream: &mut UnixStream, status: &str, revision: u64, body: &[u8]) {
    stream.write_all(format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nETag: \"{revision}\"\r\nConnection: close\r\n\r\n",
        body.len()
    ).as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

#[test]
fn omitted_revision_fetches_etag_then_sends_one_conditional_mutation_without_retry() {
    let fixture = Fixture::new();
    // This independent local peer returns a deliberate concurrent-write conflict.
    // It never reads or mutates the authoritative fixture's state.
    let listener = UnixListener::bind(fixture.socket()).unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let child = spawn(vec![
        "node".into(),
        "add".into(),
        "--traffic".into(),
        "relay".into(),
        "--socket".into(),
        fixture.socket().into_os_string(),
        "--credential-file".into(),
        fixture.token().into_os_string(),
    ]);
    let mut first = accept_bounded(&listener);
    let (line, headers, body) = read_client_request(&mut first);
    assert_eq!(line, "GET /api/v1/config HTTP/1.1");
    assert!(body.is_empty());
    assert!(!headers.iter().any(|(name, _)| name == "if-match"));
    assert!(headers.iter().any(|(name, value)| name == "authorization"
        && value == &format!("Bearer {}", STANDARD.encode([211; 32]))));
    reply(
        &mut first,
        "200 OK",
        7,
        empty_document(7).to_json().unwrap().as_bytes(),
    );
    drop(first);
    let mut second = accept_bounded(&listener);
    let (line, headers, body) = read_client_request(&mut second);
    assert_eq!(line, "POST /api/v1/node-invitations HTTP/1.1");
    let revisions: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "if-match")
        .collect();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].1, "\"7\"");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"traffic":"relay"})
    );
    let conflict = br#"{"error":"revision_conflict"}"#;
    reply(&mut second, "412 Precondition Failed", 8, conflict);
    drop(second);
    assert!(checked_output(child.wait(WAIT).unwrap(), false).is_empty());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "CLI retried a conflict"
    );
}

#[test]
fn partial_request_does_not_block_a_healthy_cli_client_or_graceful_shutdown() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    let metadata = fs::symlink_metadata(fixture.socket()).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let mut slow = UnixStream::connect(fixture.socket()).unwrap();
    slow.set_write_timeout(Some(WAIT)).unwrap();
    slow.write_all(b"GET /api/v1/config HTTP/1.1\r\nHost: wgfeel\r\nAuthorization: Bearer ")
        .unwrap();
    assert!(
        String::from_utf8(client_human(&fixture, &["config", "show"], true))
            .unwrap()
            .starts_with("Configuration\n")
    );
    runtime.stop();
}

#[test]
fn service_refuses_existing_regular_or_symlink_socket_paths_without_deleting_them() {
    for link in [false, true] {
        let fixture = Fixture::new();
        let protected = fixture.0.join("must-remain");
        private_write(&protected, b"unrelated protected file");
        if link {
            symlink(&protected, fixture.socket()).unwrap();
        } else {
            private_write(&fixture.socket(), b"unrelated socket-path file");
        }
        let before = fixture.state_bytes();
        checked_output(Runtime::spawn(&fixture).0.wait(WAIT).unwrap(), false);
        assert_eq!(fixture.state_bytes(), before);
        assert_eq!(fs::read(&protected).unwrap(), b"unrelated protected file");
        if link {
            assert!(
                fs::symlink_metadata(fixture.socket())
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read_link(fixture.socket()).unwrap(), protected);
        } else {
            assert_eq!(
                fs::read(fixture.socket()).unwrap(),
                b"unrelated socket-path file"
            );
        }
    }
}

#[test]
fn client_refuses_unsafe_token_and_socket_paths_without_mutating_state() {
    let fixture = Fixture::new();
    let mut runtime = Runtime::spawn(&fixture);
    runtime.ready(7);
    let before = fixture.state_bytes();
    let linked_token = fixture.0.join("linked.token");
    symlink(fixture.token(), &linked_token).unwrap();
    client_at(&fixture.socket(), &linked_token, &["config", "show"], false);
    fs::set_permissions(fixture.token(), fs::Permissions::from_mode(0o644)).unwrap();
    client_human(&fixture, &["config", "show"], false);
    fs::set_permissions(fixture.token(), fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = fixture.0.join("hardlink.token");
    fs::hard_link(fixture.token(), &hardlink).unwrap();
    client_at(&fixture.socket(), &hardlink, &["config", "show"], false);
    fs::remove_file(hardlink).unwrap();
    let socket_alias = fixture.0.join("api-alias.sock");
    symlink(fixture.socket(), &socket_alias).unwrap();
    client_at(&socket_alias, &fixture.token(), &["config", "show"], false);
    assert_eq!(fixture.state_bytes(), before);
    assert!(
        String::from_utf8(client_human(&fixture, &["config", "show"], true))
            .unwrap()
            .starts_with("Configuration\n")
    );
    runtime.stop();
}

#[test]
fn cli_rejects_private_credential_leaf_under_writable_intermediate_directory() {
    for mode in [0o777, 0o770] {
        let fixture = Fixture::new();
        let mut runtime = Runtime::spawn(&fixture);
        runtime.ready(7);
        let unsafe_parent = fixture.0.join("writable");
        let private_leaf = unsafe_parent.join("private");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::create_dir(&private_leaf).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(mode)).unwrap();
        fs::set_permissions(&private_leaf, fs::Permissions::from_mode(0o700)).unwrap();
        let token = private_leaf.join("admin.token");
        let token_bytes = format!("{}\n", STANDARD.encode([211; 32]));
        private_write(&token, token_bytes.as_bytes());
        let before = fixture.state_bytes();
        client_at(&fixture.socket(), &token, &["config", "show"], false);
        assert!(fs::read(&token).unwrap() == token_bytes.as_bytes());
        assert_eq!(fixture.state_bytes(), before);
        assert!(
            String::from_utf8(client_human(&fixture, &["config", "show"], true))
                .unwrap()
                .starts_with("Configuration\n")
        );
        runtime.stop();
    }
}

#[test]
fn cli_rejects_private_socket_leaf_under_writable_intermediate_directory() {
    let credentials = Fixture::new();
    for mode in [0o777, 0o770] {
        let fixture = Fixture::new();
        let mut runtime = Runtime::spawn(&fixture);
        runtime.ready(7);
        let before = fixture.state_bytes();
        let socket = fs::symlink_metadata(fixture.socket()).unwrap();
        // The leaf state directory remains 0700. Only its intermediate parent
        // becomes writable; this is not the root-owned sticky /tmp exception.
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(mode)).unwrap();
        client_at(
            &fixture.socket(),
            &credentials.token(),
            &["config", "show"],
            false,
        );
        assert_eq!(fixture.state_bytes(), before);
        let after = fs::symlink_metadata(fixture.socket()).unwrap();
        assert_eq!((after.dev(), after.ino()), (socket.dev(), socket.ino()));
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        runtime.stop();
    }
}

// ManagedChild supplies captured pipes. This one fixture instead needs fully
// occupied inherited pipes, so it owns a Child with the same group/reap rules.
struct BlockedLogChild(Option<Child>);
impl BlockedLogChild {
    fn pid(&self) -> Pid {
        Pid::from_raw(self.0.as_ref().unwrap().id() as i32).unwrap()
    }
    fn exited(&self) -> bool {
        waitid(
            WaitId::Pid(self.pid()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .is_some()
    }
    fn finish(mut self) {
        let deadline = Instant::now() + WAIT;
        while !self.exited() {
            assert!(
                Instant::now() < deadline,
                "full output pipes blocked shutdown"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        // A timeout uses Drop cleanup and fails; group killing cannot make this
        // normal-success assertion pass.
        assert!(self.0.take().unwrap().wait().unwrap().success());
    }
}
impl Drop for BlockedLogChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = Pid::from_raw(child.id() as i32).unwrap();
            assert!(pid.as_raw_pid() > 1);
            let _ = kill_process_group(pid, Signal::KILL);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn full_diagnostic_pipe() -> (OwnedFd, OwnedFd) {
    let (reader, writer) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC).unwrap();
    let mut filled = false;
    for _ in 0..1024 {
        match rustix::io::write(&writer, &[0x71; 4096]) {
            Ok(_) => (),
            Err(rustix::io::Errno::AGAIN) => {
                filled = true;
                break;
            }
            Err(_) => panic!("cannot prefill fixture output pipe"),
        }
    }
    assert!(filled, "pipe exceeded the fixture bound");
    assert_eq!(
        rustix::io::write(&writer, b"x"),
        Err(rustix::io::Errno::AGAIN)
    );
    let flags = fcntl_getfl(&writer).unwrap();
    fcntl_setfl(&writer, flags & !OFlags::NONBLOCK).unwrap();
    (reader, writer)
}

#[test]
fn full_blocking_stdout_and_stderr_do_not_prevent_signal_cleanup() {
    for signal in [Signal::TERM, Signal::INT] {
        let fixture = Fixture::new();
        let before = fixture.state_bytes();
        let (_stdout_reader, stdout) = full_diagnostic_pipe();
        let (_stderr_reader, stderr) = full_diagnostic_pipe();
        let child = BlockedLogChild(Some(
            Command::new(env!("CARGO_BIN_EXE_wgfeel"))
                .args(["serve", "--control", "main", "--state-dir"])
                .arg(fixture.state())
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .process_group(0)
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + WAIT;
        loop {
            assert!(!child.exited(), "Management exited before signal readiness");
            let status =
                fs::read_to_string(format!("/proc/{}/status", child.pid().as_raw_pid())).unwrap();
            let blocked = status
                .lines()
                .find_map(|line| line.strip_prefix("SigBlk:"))
                .map(|value| u64::from_str_radix(value.trim(), 16).unwrap())
                .unwrap();
            if fixture.socket().exists()
                && blocked & ((1 << 1) | (1 << 14)) == ((1 << 1) | (1 << 14))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Management did not install shutdown handling"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        kill_process(child.pid(), signal).unwrap();
        child.finish();
        assert!(!fixture.socket().exists());
        assert_eq!(fixture.state_bytes(), before);
        assert!(ManagementStore::open(&fixture.state()).is_ok());
    }
}

fn saturated_listener(path: &Path) -> (UnixListener, Vec<OwnedFd>) {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listen(&listener, 0).unwrap();
    let address = SocketAddrUnix::new(path).unwrap();
    let mut connections = vec![];
    for _ in 0..32 {
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        match connect(&socket, &address) {
            Ok(()) => connections.push(socket),
            Err(rustix::io::Errno::AGAIN) => {
                assert!(!connections.is_empty());
                return (listener, connections);
            }
            Err(_) => panic!("unexpected fixture Unix connect result"),
        }
    }
    panic!("Unix listener queue did not saturate within the fixture bound");
}

#[test]
fn saturated_unix_listener_cannot_block_cli_connect_indefinitely() {
    let fixture = Fixture::new();
    let (_listener, _connections) = saturated_listener(&fixture.socket());
    let before = fixture.state_bytes();
    let socket = fs::symlink_metadata(fixture.socket()).unwrap();
    client_human(&fixture, &["config", "show"], false);
    assert_eq!(fixture.state_bytes(), before);
    let after = fs::symlink_metadata(fixture.socket()).unwrap();
    assert_eq!((after.dev(), after.ino()), (socket.dev(), socket.ino()));
}

#[test]
fn saturated_unix_listener_is_not_removed_or_waited_on_as_a_stale_socket() {
    let fixture = Fixture::new();
    let (_listener, _connections) = saturated_listener(&fixture.socket());
    let before = fixture.state_bytes();
    let socket = fs::symlink_metadata(fixture.socket()).unwrap();
    let output = Runtime::spawn(&fixture)
        .0
        .wait(WAIT)
        .expect("saturated active socket blocked Management startup indefinitely");
    checked_output(output, false);
    let after = fs::symlink_metadata(fixture.socket()).unwrap();
    assert_eq!((after.dev(), after.ino()), (socket.dev(), socket.ino()));
    assert_eq!(fixture.state_bytes(), before);
    assert!(ManagementStore::open(&fixture.state()).is_ok());
}
