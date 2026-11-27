use base64::{Engine, engine::general_purpose::STANDARD};
use std::process::Command;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use wgfeel_protocol::{Response, http};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "wgfeel-completion-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("token"))
            .unwrap()
            .write_all(STANDARD.encode([211; 32]).as_bytes())
            .unwrap();
        Self(path)
    }
    fn listener(&self) -> UnixListener {
        let listener = UnixListener::bind(self.0.join("api.sock")).unwrap();
        fs::set_permissions(self.0.join("api.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }
    fn command(&self, words: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wgfeel"));
        // Connection flags after the cursor must still select this socket.
        command
            .args(["_complete", &(words.len() - 1).to_string(), "--"])
            .args(words)
            .arg("--socket")
            .arg(self.0.join("api.sock"))
            .arg("--credential-file")
            .arg(self.0.join("token"));
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn accept(listener: &UnixListener) -> std::os::unix::net::UnixStream {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => panic!("completion did not connect: {error}"),
        }
    }
}

#[test]
fn dynamic_ids_are_read_only_and_display_only_public_names() {
    for (words, path, body, expected) in [
        (
            vec!["device", "broadcast", "set", "d"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice","devices":[{"id":"d1","metadata":{"name":"Laptop"},"registration":null}]}]}"#,
            "d1\tAlice / Laptop\n",
        ),
        (
            vec!["user", "broadcast", "show", "u"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice","devices":[]}]}"#,
            "u1\tAlice\n",
        ),
        (
            vec!["user", "show", "u"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice\n\u001b[31m","devices":[],"private_key":"must-not-print"}]}"#,
            "u1\tAlice  [31m\n",
        ),
        (
            vec!["device", "delete", "d"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice","devices":[{"id":"d1","metadata":{"name":"Laptop"}},{"id":"$(touch bad)","metadata":{"name":"invalid"}}]}]}"#,
            "d1\tAlice / Laptop\n",
        ),
        (
            vec!["node", "show", "n"],
            "/api/v1/gateways",
            r#"{"gateways":[{"recipient":"n1","hostname":"server1"}]}"#,
            "n1\tserver1\n",
        ),
        (
            vec!["user", "egress", "set", "alice", "eg_"],
            "/api/v1/egresses",
            r#"{"egresses":[{"name":"Corporate","id":"eg_office","private_key":"must-not-print"}]}"#,
            "eg_office\tCorporate\n",
        ),
        (
            vec!["egress", "add", "--node", "n"],
            "/api/v1/gateways",
            r#"{"gateways":[{"recipient":"n1","hostname":"server1","traffic":"entry","endpoint":"192.0.2.1:51820"},{"recipient":"n2","traffic":"relay","endpoint":"192.0.2.2:51820"},{"recipient":"n3","traffic":"entry","endpoint":null}]}"#,
            "n1\tserver1\n",
        ),
        (
            vec!["egress", "add", "--users", "u1,u"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice","devices":[]},{"id":"u2","name":"Bob","devices":[]}]}"#,
            "u1,u2\tBob\n",
        ),
        (
            vec!["device", "add", "--user", "u"],
            "/api/v1/users",
            r#"{"users":[{"id":"u1","name":"Alice","devices":[]}]}"#,
            "u1\tAlice\n",
        ),
    ] {
        let fixture = Fixture::new();
        let listener = fixture.listener();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            let mut bytes = vec![];
            loop {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(request) = http::decode_request(&bytes).unwrap() {
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.target, path);
                    assert!(request.body.is_empty());
                    assert!(request.if_match.is_none());
                    assert_eq!(
                        request.authorization.unwrap(),
                        format!("Bearer {}", STANDARD.encode([211; 32]))
                    );
                    break;
                }
            }
            stream
                .write_all(&http::encode_response(&Response {
                    status: 200,
                    generation: Some(7),
                    body: body.as_bytes().to_vec(),
                    is_config: false,
                }))
                .unwrap();
        });
        let output = fixture.command(&words).output().unwrap();
        server.join().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[test]
fn unavailable_and_stalled_management_do_not_block_completion() {
    let fixture = Fixture::new();
    let missing = fixture.command(&["user", "show", ""]).output().unwrap();
    assert!(missing.status.success());
    assert!(missing.stderr.is_empty());
    assert!(!String::from_utf8(missing.stdout).unwrap().contains("u1"));
    let listener = fixture.listener();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        let mut buffer = [0; 4096];
        // Consume the request, never send a response, and wait for client EOF.
        while stream.read(&mut buffer).unwrap() != 0 {}
    });
    let started = Instant::now();
    let output = fixture.command(&["device", "show", "d"]).output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    server.join().unwrap();
}

#[test]
fn bash_adapter_uses_native_completion_without_evaluating_values() {
    let adapter = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../share/bash-completion/completions/wgfeel");
    let script = r#"source "$2"
COMP_WORDS=("$1" device add --u)
COMP_CWORD=3
_wgfeel
printf '%s\n' "${COMPREPLY[@]}"
"#;
    let output = Command::new("bash")
        .args(["--noprofile", "--norc", "-c", script, "completion-test"])
        .arg(env!("CARGO_BIN_EXE_wgfeel"))
        .arg(adapter)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"--user\n");
}

#[test]
fn shell_adapters_offer_subcommands_after_the_binary_name() {
    let bash = r#"source "$2/bash-completion/completions/$3"
COMP_WORDS=("$1" "")
COMP_CWORD=1
"_${3//-/_}" "$3" "" "$3"
printf '%s\n' "${COMPREPLY[@]}"
"#;
    let zsh = r#"fpath=("$2/zsh/site-functions" $fpath)
autoload -Uz compinit
compinit -D -i
words=("$1" "")
CURRENT=2
PREFIX=""
compadd() {
    [[ "$1" == -d && "$2" == descriptions && "$3" == -- ]] || return 1
    shift 3
    print -rl -- "$@"
}
"${_comps[$3]}"
"#;
    let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../share");
    for (shell, flags, script) in [
        ("bash", vec!["--noprofile", "--norc"], bash),
        ("zsh", vec!["-f"], zsh),
    ] {
        for (binary, name, expected) in [(env!("CARGO_BIN_EXE_wgfeel"), "wgfeel", "user")] {
            let output = Command::new(shell)
                .args(&flags)
                .args(["-c", script, "completion-test", binary])
                .arg(&resources)
                .arg(name)
                .output()
                .unwrap();
            assert!(
                output.status.success() && output.stderr.is_empty(),
                "{shell} {name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            let candidates: Vec<_> = text.lines().collect();
            for command in ["install", "update", expected] {
                assert!(candidates.contains(&command), "{shell} {name}: {text}");
            }
            assert!(!candidates.contains(&"wgfeel"), "{shell} {name}: {text}");
        }
    }
}

#[test]
fn zsh_autoload_invokes_the_adapter_on_its_first_request() {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../share/zsh/site-functions");
    // Only the final display sink is substituted: compadd needs a live ZLE
    // widget. Exercise actual compinit discovery and the first autoload call.
    let script = r#"fpath=("$2" $fpath)
autoload -Uz compinit
compinit -D -i
words=("$1" jo)
CURRENT=2
PREFIX=jo
compadd() {
    [[ "$1" == -d && "$2" == descriptions && "$3" == -- ]] || return 1
    shift 3
    print -rl -- "$@"
}
"${_comps[wgfeel]}"
"#;
    let output = Command::new("zsh")
        .args(["-f", "-c", script, "completion-test"])
        .arg(env!("CARGO_BIN_EXE_wgfeel"))
        .arg(directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"join\n");
}

fn complete(words: &[&str]) -> String {
    let binary = env!("CARGO_BIN_EXE_wgfeel");
    let output = Command::new(binary)
        .args(["_complete", "--"])
        .args(words)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn root_flags_and_enrollment_options_match_the_cli() {
    for prefix in ["--", "--b", "--build-info"] {
        assert!(
            complete(&[prefix])
                .lines()
                .any(|line| line.starts_with("--build-info\t"))
        );
    }
    let flags = complete(&["node", "add", "--"]);
    assert_eq!(
        flags
            .lines()
            .map(|line| line.split_once('\t').unwrap().0)
            .collect::<Vec<_>>(),
        [
            "--credential-file",
            "--help",
            "--profile",
            "--revision",
            "--socket",
            "--traffic"
        ]
    );
    assert!(
        complete(&["join", "--endpoint", "192.0.2.2:51820", "--end"]).starts_with("--endpoint\t")
    );
    assert!(!complete(&["install", "--b"]).contains("--build-info"));
}

#[test]
fn static_completion_selects_commands_flags_and_capability_values() {
    let root = complete(&[""]);
    assert!(root.lines().any(|line| line.starts_with("user\t")));
    assert!(!root.contains("_complete"));
    let node = complete(&[""]);
    assert!(node.lines().any(|line| line.starts_with("join\t")));
    assert!(complete(&["device", "add", "--u"]).starts_with("--user\t"));
    assert_eq!(
        complete(&["user", "broadcast", "set", "u1", "o"]),
        "off\t\non\t\n"
    );
    assert_eq!(
        complete(&["device", "broadcast", "set", "d1", "i"]),
        "inherit\t\n"
    );
    assert!(complete(&["user", "broadcast", "set", "u1", "i"]).is_empty());
    assert_eq!(
        complete(&["user", "add", "--broadcast", ""]),
        "off\t\non\t\n"
    );
    assert_eq!(
        complete(&["device", "add", "--broadcast", ""]),
        "inherit\t\noff\t\non\t\n"
    );
    assert!(complete(&["install", "--unknown", ""]).is_empty());
    assert_eq!(complete(&["install", "--control", ""]), "child\t\nmain\t\n");
    for words in [
        vec!["install", "--traffic", ""],
        vec!["node", "add", "--traffic", ""],
    ] {
        assert_eq!(complete(&words), "entry\t\noff\t\nrelay\t\n");
    }
    assert!(complete(&["device", "add", "--name", ""]).is_empty());
    assert!(complete(&["token", "rotate", "--p"]).is_empty());
    assert_eq!(complete(&["user", "--profile", ""]), "@files\t\n");
}

#[test]
fn completion_never_dispatches_the_command_being_completed() {
    for words in [
        vec!["token", "rotate", ""],
        vec!["uninstall", "--purge", ""],
        vec!["node", "add", "--traffic", ""],
        vec!["unknown", ""],
    ] {
        let _ = complete(&words);
    }
}
