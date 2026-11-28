#![cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    fs,
    net::{IpAddr, TcpListener, UdpSocket},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};
static NEXT: AtomicUsize = AtomicUsize::new(0);
#[path = "support/api.rs"]
mod api;
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn call(&self, args: &[&str]) -> CapturedOutput {
        self.call_binary(env!("CARGO_BIN_EXE_wgfeel"), args)
    }
    fn node(&self, args: &[&str]) -> CapturedOutput {
        self.call_binary(
            env!("CARGO_BIN_EXE_wgfeel"),
            &[&["--control", "child"][..], args].concat(),
        )
    }
    fn call_binary(&self, binary: &str, args: &[&str]) -> CapturedOutput {
        let mut command: Vec<OsString> = vec![
            "install".into(),
            "--root".into(),
            self.0.as_os_str().into(),
            "--no-start".into(),
        ];
        command.extend(args.iter().map(OsString::from));
        run(binary.into(), command)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(program: PathBuf, args: Vec<OsString>) -> CapturedOutput {
    spawn(program, args).wait(Duration::from_secs(20)).unwrap()
}
fn spawn(program: PathBuf, args: Vec<OsString>) -> ManagedChild {
    ManagedChild::spawn(
        ProcessSpec::new(program, args, vec![], None),
        ProcessLimits {
            max_stdout_bytes: 32768,
            max_stderr_bytes: 8192,
        },
    )
    .unwrap()
}
fn success(output: &CapturedOutput) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unified_install_uses_one_owned_binary_and_service_for_each_control_capability() {
    for (control, traffic) in [
        ("main", Some("entry")),
        ("main", Some("relay")),
        ("main", Some("off")),
        ("child", None),
    ] {
        let root = Root::new();
        let mut args = vec![
            "--control",
            control,
            "--endpoint",
            if control == "main" {
                "192.0.2.1:53120"
            } else {
                "192.0.2.1"
            },
        ];
        if let Some(traffic) = traffic {
            args.extend(["--traffic", traffic, "--port", "53120"]);
        }
        success(&root.call(&args));
        let home = root.0.join("opt/wgfeel/instance");
        assert!(home.join("state/state.json").is_file());
        assert_eq!(
            fs::read(home.join("bin/wgfeel")).unwrap(),
            fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap()
        );
        assert_eq!(
            fs::read_link(root.0.join("usr/local/bin/wgfeel")).unwrap(),
            home.join("bin/wgfeel")
        );
        assert_eq!(
            fs::read_dir(root.0.join("usr/local/bin")).unwrap().count(),
            1
        );
        assert_eq!(fs::read_dir(root.0.join("opt/wgfeel")).unwrap().count(), 1);
        let unit = fs::read_to_string(root.0.join("etc/systemd/system/wgfeel.service")).unwrap();
        assert!(unit.contains(&format!(" serve --control {control} --state-dir ")));
        assert_eq!(unit.contains(" --listen-ip "), control == "child");
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(home.join("install.json")).unwrap()).unwrap();
        assert_eq!(receipt["version"], 1);
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(home.join("config/config.json")).unwrap()).unwrap();
        assert_eq!(settings["control"], control);
        if let Some(traffic) = traffic {
            let service = wgfeel_management::ManagementService::open(&home.join("state")).unwrap();
            let state = service.delivery_snapshot().unwrap();
            let nodes = state.document().routing().assignments();
            assert_eq!(nodes.len(), 1);
            assert_eq!(serde_json::to_value(nodes[0].traffic()).unwrap(), traffic);
            assert_eq!(state.rest_api().unwrap().listen().port(), 9280);
        }
        let before = fs::read(home.join("state/state.json")).unwrap();
        assert!(
            !root.call(&args).status.success(),
            "setup options must not silently modify an existing installation"
        );
        let update = vec![
            "update".into(),
            "--root".into(),
            root.0.clone().into_os_string(),
            "--no-start".into(),
        ];
        success(&run(env!("CARGO_BIN_EXE_wgfeel").into(), update.clone()));
        assert_eq!(before, fs::read(home.join("state/state.json")).unwrap());
        let preview = run(
            home.join("bin/wgfeel"),
            vec!["uninstall".into(), "--dry-run".into()],
        );
        success(&preview);
        assert!(
            String::from_utf8(preview.stdout)
                .unwrap()
                .contains("wgfeel.service")
        );
        assert!(home.join("bin/wgfeel").is_file());
        let unit_path = root.0.join("etc/systemd/system/wgfeel.service");
        fs::write(unit_path, format!("{unit}\n# unrelated edit\n")).unwrap();
        assert!(
            !run(env!("CARGO_BIN_EXE_wgfeel").into(), update)
                .status
                .success()
        );
        assert_eq!(before, fs::read(home.join("state/state.json")).unwrap());
    }
}

#[test]
fn common_installations_discover_their_state_join_and_change_only_the_http_port() {
    let main_root = Root::new();
    let child_root = Root::new();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let main_endpoint = udp.local_addr().unwrap();
    let child_endpoint =
        std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), main_endpoint.port());
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_endpoint = http.local_addr().unwrap();
    success(&main_root.call(&[
        "--control",
        "main",
        "--traffic",
        "entry",
        "--endpoint",
        &main_endpoint.to_string(),
        "--listen-ip",
        "127.0.0.1",
        "--port",
        &main_endpoint.port().to_string(),
        "--api-port",
        &http_endpoint.port().to_string(),
    ]));
    success(&child_root.call(&[
        "--control",
        "child",
        "--endpoint",
        "127.0.0.2",
        "--listen-ip",
        "127.0.0.2",
        "--id",
        "child-two",
    ]));
    drop(udp);
    drop(http);
    let main_binary = main_root.0.join("usr/local/bin/wgfeel");
    let child_binary = child_root.0.join("usr/local/bin/wgfeel");
    let main_state = main_root.0.join("opt/wgfeel/instance/state");
    let child_state = child_root.0.join("opt/wgfeel/instance/state");
    let mut main = spawn(
        main_binary.clone(),
        vec![
            "serve".into(),
            "--control".into(),
            "main".into(),
            "--state-dir".into(),
            main_state.clone().into_os_string(),
        ],
    );
    main.next_stdout_line(Duration::from_secs(10)).unwrap();
    // Exercise completion with a live, writable installation. The snapshot includes
    // the revision and administrator verifier, so an accidental rotation is observable.
    let snapshot = main_state.join("state.json");
    let before_completion = fs::read(&snapshot).unwrap();
    for words in [
        vec!["node", "delete", "main"],
        vec!["token", "rotate", ""],
        vec![
            "uninstall",
            "--root",
            main_root.0.to_str().unwrap(),
            "--purge",
            "",
        ],
        vec!["node", "add", "--traffic", "r"],
        vec!["unknown", ""],
    ] {
        let mut args = vec!["_complete".into(), "--".into()];
        args.extend(words.iter().map(OsString::from));
        let output = run(main_binary.clone(), args);
        assert!(output.status.success() && output.stderr.is_empty());
        match words.as_slice() {
            ["node", "delete", ..] => assert!(output.stdout.starts_with(b"main\t")),
            ["node", "add", ..] => assert_eq!(output.stdout, b"relay\t\n"),
            _ => (),
        }
        assert!(
            fs::read(&snapshot).unwrap() == before_completion,
            "completion changed state"
        );
    }
    assert!(!child_state.join("api.sock").exists());
    let serve_child = || {
        spawn(
            child_binary.clone(),
            vec![
                "serve".into(),
                "--control".into(),
                "child".into(),
                "--state-dir".into(),
                child_state.clone().into_os_string(),
                "--listen-ip".into(),
                "127.0.0.2".into(),
            ],
        )
    };
    let before_join = serve_child().wait(Duration::from_secs(5)).unwrap();
    assert!(!before_join.status.success());
    assert!(String::from_utf8_lossy(&before_join.stderr).contains("awaiting enrollment"));
    let issued = run(
        main_binary.clone(),
        vec![
            "node".into(),
            "add".into(),
            "--traffic".into(),
            "relay".into(),
        ],
    );
    success(&issued);
    let text = String::from_utf8(issued.stdout).unwrap();
    let invitation = text
        .lines()
        .find(|line| line.starts_with("wgfeel://join/"))
        .unwrap();
    assert!(text.contains(&format!("Main main (WireGuard UDP): {main_endpoint}")));
    assert!(text.contains(&format!(
        "Child WireGuard UDP port: {}",
        main_endpoint.port()
    )));
    let occupied = UdpSocket::bind(child_endpoint).unwrap();
    let unbound = fs::read(child_state.join("state.json")).unwrap();
    let refused = run(child_binary.clone(), vec!["join".into(), invitation.into()]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("cannot bind node UDP socket"));
    assert_eq!(fs::read(child_state.join("state.json")).unwrap(), unbound);
    assert!(!child_state.join("api.sock").exists());
    drop(occupied);
    let mut join = spawn(
        child_binary.clone(),
        vec!["join".into(), "--invitation-stdin".into()],
    );
    join.write_stdin_line(invitation.as_bytes()).unwrap();
    let joined = join.wait(Duration::from_secs(80)).unwrap();
    success(&joined);
    assert!(!child_state.join("api.sock").exists());
    // --no-start leaves the unit stopped. Starting its installed command must
    // recover the assigned port entirely from the committed binding.
    let mut child = serve_child();
    let ready: serde_json::Value =
        serde_json::from_slice(&child.next_stdout_line(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(ready["listen"], child_endpoint.to_string());
    let listed = run(main_binary.clone(), vec!["node".into(), "list".into()]);
    success(&listed);
    assert!(
        String::from_utf8(listed.stdout)
            .unwrap()
            .contains(ready["node_id"].as_str().unwrap())
    );
    let before = fs::read(main_state.join("state.json")).unwrap();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let next = reserve.local_addr().unwrap();
    drop(reserve);
    success(&run(
        main_binary,
        vec!["api".into(), "port".into(), next.port().to_string().into()],
    ));
    assert!(TcpListener::bind(next).is_err());
    TcpListener::bind(http_endpoint).unwrap();
    assert!(UdpSocket::bind(main_endpoint).is_err());
    let mut before: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let mut after: serde_json::Value =
        serde_json::from_slice(&fs::read(main_state.join("state.json")).unwrap()).unwrap();
    before.as_object_mut().unwrap().remove("rest_api");
    after.as_object_mut().unwrap().remove("rest_api");
    assert_eq!(before, after);
    child.terminate().unwrap();
    main.terminate().unwrap();
}
#[test]
fn preview_never_writes() {
    let root = Root::new();
    let output = root.call(&[
        "--control",
        "main",
        "--endpoint",
        "192.0.2.1:53100",
        "--port",
        "53100",
        "--dry-run",
    ]);
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("wgfeel.service"));
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    let output = root.node(&["--endpoint", "192.0.2.1", "--dry-run"]);
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("wgfeel.service"));
    assert!(text.contains("--listen-ip 0.0.0.0"));
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    let output = run(
        env!("CARGO_BIN_EXE_wgfeel").into(),
        ["install", "--unknown", "--port", "53100"]
            .into_iter()
            .map(OsString::from)
            .collect(),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
fn ipv6_install_persists_matching_listeners_and_advertised_endpoints() {
    for control in ["main", "child"] {
        let root = Root::new();
        let mut args = vec!["--control", control, "--endpoint"];
        if control == "main" {
            args.extend([
                "[2001:db8::7]:53100",
                "--port",
                "53100",
                "--endpoint",
                "192.0.2.7:53999",
            ]);
        } else {
            args.extend(["2001:db8::7", "--endpoint", "192.0.2.7"]);
        }
        success(&root.call(&args));
        for (relative, marker) in [
            ("man/man1/wgfeel.1", ".SH SYNOPSIS"),
            ("bash-completion/completions/wgfeel", "complete -F"),
            ("zsh/site-functions/_wgfeel", "#compdef"),
        ] {
            let path = root.0.join("usr/local/share").join(relative);
            assert!(fs::read_to_string(&path).unwrap().contains(marker));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        let config: serde_json::Value = serde_json::from_slice(
            &fs::read(root.0.join("opt/wgfeel/instance/config/config.json")).unwrap(),
        )
        .unwrap();
        if control == "main" {
            assert_eq!(config["listen"], "[::]:53100");
            assert_eq!(
                config["endpoints"],
                serde_json::json!(["[2001:db8::7]:53100", "192.0.2.7:53999"])
            );
            let state =
                wgfeel_store::ManagementStore::open(&root.0.join("opt/wgfeel/instance/state"))
                    .unwrap()
                    .load()
                    .unwrap()
                    .unwrap();
            assert_eq!(
                serde_json::to_value(state.api().unwrap().endpoints()).unwrap(),
                config["endpoints"]
            );
            assert_eq!(state.api().unwrap().listen(), "[::]:53100".parse().unwrap());
        } else {
            let unit =
                fs::read_to_string(root.0.join("etc/systemd/system/wgfeel.service")).unwrap();
            assert_eq!(
                config["addresses"],
                serde_json::json!(["2001:db8::7", "192.0.2.7"])
            );
            assert!(unit.contains("--listen-ip ::"));
        }
    }
}

#[test]
fn missing_endpoint_and_mismatched_listen_family_never_install() {
    for args in [
        vec!["--control", "main"],
        vec![
            "--control",
            "main",
            "--endpoint",
            "[2001:db8::7]:51820",
            "--listen-ip",
            "0.0.0.0",
        ],
        vec![
            "--control",
            "main",
            "--endpoint",
            "192.0.2.7:51820",
            "--listen-ip",
            "::",
        ],
    ] {
        let root = Root::new();
        assert!(!root.call(&args).status.success());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
}

#[test]
fn separately_installed_node_joins_and_receives_updates_over_ipv4_and_ipv6() {
    for ip in ["127.0.0.1", "::1"] {
        let ip: IpAddr = ip.parse().unwrap();
        let management_socket = UdpSocket::bind((ip, 0)).unwrap();
        let gateway_socket = UdpSocket::bind((ip, 0)).unwrap();
        let http_socket = TcpListener::bind((ip, 0)).unwrap();
        let management_endpoint = management_socket.local_addr().unwrap();
        let gateway_endpoint = gateway_socket.local_addr().unwrap();
        let root = Root::new();
        let child_root = Root::new();
        let output = root.call(&[
            "--control",
            "main",
            "--endpoint",
            &management_endpoint.to_string(),
            "--port",
            &management_endpoint.port().to_string(),
            "--listen-ip",
            &ip.to_string(),
            "--api-port",
            &http_socket.local_addr().unwrap().port().to_string(),
            "--api-listen-ip",
            &ip.to_string(),
        ]);
        success(&output);
        success(&child_root.node(&[
            "--id",
            "node1",
            "--endpoint",
            &ip.to_string(),
            "--listen-ip",
            &ip.to_string(),
        ]));
        let binary = root.0.join("opt/wgfeel/instance/bin/wgfeel");
        drop(management_socket);
        drop(gateway_socket);
        drop(http_socket);
        let mut management = spawn(
            binary.clone(),
            vec![
                "serve".into(),
                "--control".into(),
                "main".into(),
                "--state-dir".into(),
                root.0.join("opt/wgfeel/instance/state").into_os_string(),
            ],
        );
        let ready: serde_json::Value = serde_json::from_slice(
            &management
                .next_stdout_line(Duration::from_secs(20))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ready["generation"], 1);
        let start_gateway = || {
            let mut child = spawn(
                child_root.0.join("usr/local/bin/wgfeel"),
                vec![
                    "serve".into(),
                    "--control".into(),
                    "child".into(),
                    "--state-dir".into(),
                    child_root
                        .0
                        .join("opt/wgfeel/instance/state")
                        .into_os_string(),
                    "--listen".into(),
                    gateway_endpoint.to_string().into(),
                ],
            );
            let ready: serde_json::Value =
                serde_json::from_slice(&child.next_stdout_line(Duration::from_secs(20)).unwrap())
                    .unwrap();
            assert_eq!(ready["node_id"], "node1");
            (child, ready)
        };
        assert!(
            wgfeel_store::Store::open(&child_root.0.join("opt/wgfeel/instance/state"))
                .unwrap()
                .load()
                .unwrap()
                .unwrap()
                .management_public_key()
                .is_none()
        );
        let (gateway, ready) = start_gateway();
        assert_eq!(ready["management_id"], "unbound");
        let invitation = run(binary.clone(), vec!["node".into(), "add".into()]);
        success(&invitation);
        let output = String::from_utf8(invitation.stdout).unwrap();
        let uri = output
            .lines()
            .find(|line| line.starts_with("wgfeel://join/"))
            .expect("one-time join command");
        let joined = spawn(
            child_root.0.join("usr/local/bin/wgfeel"),
            vec![
                "join".into(),
                uri.into(),
                "--endpoint".into(),
                gateway_endpoint.to_string().into(),
            ],
        )
        .wait(Duration::from_secs(75))
        .unwrap();
        success(&joined);
        let state = root.0.join("opt/wgfeel/instance/state");
        let wait_applied = |generation: u64| {
            let until = Instant::now() + Duration::from_secs(20);
            loop {
                let status = api::json(
                    &state,
                    "GET",
                    "/api/v1/distribution",
                    serde_json::Value::Null,
                );
                let nodes = status["gateways"].as_array().unwrap();
                assert_eq!(nodes.len(), 2);
                let child = nodes.iter().find(|node| node["id"] == "node1").unwrap();
                if child["status"] == "applied" && child["acknowledged"] == generation {
                    return;
                }
                assert!(
                    Instant::now() < until,
                    "local enrollment was not applied: {status}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        wait_applied(2);
        let user = api::json(
            &state,
            "POST",
            "/api/v1/users",
            serde_json::json!({"name":"alice"}),
        );
        wait_applied(user["generation"].as_u64().unwrap());
        let device = api::json(
            &state,
            "POST",
            &format!("/api/v1/users/{}/devices", user["id"].as_str().unwrap()),
            serde_json::json!({"name":"Alice phone"}),
        );
        let generation = device["generation"].as_u64().unwrap();
        wait_applied(generation);
        // Enrollment and delivered state survive independently of Management.
        management.terminate().unwrap();
        gateway.terminate().unwrap();
        let (gateway, ready) = start_gateway();
        assert_eq!(ready["management_id"], "main");
        assert_eq!(ready["generation"], generation);
        assert_eq!(ready["local_contexts"], 1);
        gateway.terminate().unwrap();
    }
}

#[test]
fn linked_paths_and_invalid_role_settings_fail_before_identity_creation() {
    let root = Root::new();
    let outside = Root::new();
    symlink(&outside.0, root.0.join("etc")).unwrap();
    assert!(
        !root
            .call(&["--control", "main", "--endpoint", "192.0.2.1:51820"])
            .status
            .success()
    );
    assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 0);
    for extra in [vec!["--port", "0"], vec!["--control", "child"]] {
        let root = Root::new();
        let mut args = vec!["--control", "main", "--endpoint", "192.0.2.1:51820"];
        args.extend(extra);
        assert!(!root.call(&args).status.success());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
}

#[test]
fn unknown_options_never_install_or_update_files() {
    for existing in [false, true] {
        let root = Root::new();
        let binary = root.0.join("opt/wgfeel/instance/bin/wgfeel");
        let state = root.0.join("opt/wgfeel/instance/state/state.json");
        let before = if existing {
            success(&root.call(&["--control", "main", "--endpoint", "192.0.2.1:51820"]));
            fs::copy("/proc/self/exe", &binary).unwrap();
            Some(fs::read(&state).unwrap())
        } else {
            None
        };
        let output = root.call(&[
            "--control",
            "main",
            "--endpoint",
            "192.0.2.1:51820",
            "--unknown",
        ]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("wgfeel install"));
        if let Some(before) = &before {
            assert_eq!(
                fs::read(&binary).unwrap(),
                fs::read("/proc/self/exe").unwrap()
            );
            assert_eq!(&fs::read(&state).unwrap(), before);
        } else {
            assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
        }
    }
}

#[test]
fn install_and_update_replace_existing_binary_without_changing_configuration() {
    for (command, control) in [
        ("install", "main"),
        ("install", "child"),
        ("update", "main"),
        ("update", "child"),
    ] {
        let root = Root::new();
        let setup = [
            "--control",
            control,
            "--endpoint",
            if control == "main" {
                "192.0.2.1:51820"
            } else {
                "192.0.2.1"
            },
        ];
        let mut install: Vec<OsString> = vec![
            "-c".into(),
            r#"umask 077; exec "$@""#.into(),
            "install-test".into(),
            env!("CARGO_BIN_EXE_wgfeel").into(),
            "install".into(),
            "--root".into(),
            root.0.clone().into(),
            "--no-start".into(),
        ];
        install.extend(setup.iter().map(OsString::from));
        success(&run("/bin/sh".into(), install));
        assert_eq!(
            fs::metadata(root.0.join("usr/local/bin/wgfeel"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        let mut files = vec![
            "opt/wgfeel/instance/state/state.json",
            "opt/wgfeel/instance/config/admin.json",
            "opt/wgfeel/instance/config/config.json",
            "opt/wgfeel/instance/install.json",
            "etc/systemd/system/wgfeel.service",
        ];
        if control == "child" {
            files.retain(|path| !path.ends_with("admin.json"));
        }
        let before: Vec<_> = files
            .iter()
            .map(|name| fs::read(root.0.join(name)).unwrap())
            .collect();
        let installed = root.0.join("opt/wgfeel/instance/bin/wgfeel");
        let candidate = fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap();
        let old = fs::read("/proc/self/exe").unwrap();
        fs::write(&installed, &old).unwrap();
        let args: Vec<OsString> = vec![
            command.into(),
            "--root".into(),
            root.0.clone().into_os_string(),
            "--no-start".into(),
        ];
        let mut preview = args.clone();
        preview.push("--dry-run".into());
        success(&run(env!("CARGO_BIN_EXE_wgfeel").into(), preview));
        assert_eq!(fs::read(&installed).unwrap(), old);
        success(&run(env!("CARGO_BIN_EXE_wgfeel").into(), args.clone()));
        assert_eq!(fs::read(&installed).unwrap(), candidate);
        assert!(
            fs::read_dir(installed.parent().unwrap())
                .unwrap()
                .any(|entry| {
                    let entry = entry.unwrap();
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("wgfeel.previous-")
                        && fs::read(entry.path()).unwrap() == old
                })
        );
        success(&run(env!("CARGO_BIN_EXE_wgfeel").into(), args));
        for (name, contents) in files.iter().zip(before) {
            assert_eq!(
                fs::read(root.0.join(name)).unwrap(),
                contents,
                "changed {name}"
            );
        }
    }
}

#[test]
fn update_refuses_missing_or_incomplete_installation_without_creating_files() {
    let root = Root::new();
    let update = || {
        run(
            env!("CARGO_BIN_EXE_wgfeel").into(),
            vec![
                "update".into(),
                "--root".into(),
                root.0.clone().into_os_string(),
                "--no-start".into(),
            ],
        )
    };
    assert!(!update().status.success());
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    success(&root.call(&["--control", "main", "--endpoint", "192.0.2.1:51820"]));
    let binary = fs::read(root.0.join("opt/wgfeel/instance/bin/wgfeel")).unwrap();
    fs::remove_file(root.0.join("opt/wgfeel/instance/config/config.json")).unwrap();
    assert!(!update().status.success());
    assert!(!root.call(&[]).status.success());
    assert_eq!(
        fs::read(root.0.join("opt/wgfeel/instance/bin/wgfeel")).unwrap(),
        binary
    );
}

#[test]
fn unbound_node_install_generates_durable_identity_without_manager_parameters() {
    let root = Root::new();
    let args = vec![
        "install".into(),
        "--control".into(),
        "child".into(),
        "--root".into(),
        root.0.clone().into_os_string(),
        "--no-start".into(),
        "--install-dir".into(),
        "/srv/feel".into(),
        "--endpoint".into(),
        "192.0.2.2".into(),
    ];
    let output = run(env!("CARGO_BIN_EXE_wgfeel").into(), args.clone());
    success(&output);
    let path = root.0.join("srv/feel/instance/state/state.json");
    let bytes = fs::read(&path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = state["node_id"].as_str().unwrap();
    let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let name = host.trim().split('.').next().unwrap();
    if wgfeel_core::NodeId::new(name).is_ok() {
        assert_eq!(id, name);
    } else {
        assert_eq!(id.len(), 36);
    }
    assert!(state["management_public_key"].is_null());
    assert!(state["tenant_private_keys"].as_array().unwrap().is_empty());
    assert!(root.0.join("etc/systemd/system/wgfeel.service").is_file());
    assert!(!root.0.join("srv/feel/manager").exists());
    assert!(
        !run(env!("CARGO_BIN_EXE_wgfeel").into(), args)
            .status
            .success()
    );
    success(&run(
        env!("CARGO_BIN_EXE_wgfeel").into(),
        vec![
            "update".into(),
            "--root".into(),
            root.0.clone().into_os_string(),
            "--install-dir".into(),
            "/srv/feel".into(),
            "--no-start".into(),
        ],
    ));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn custom_install_directory_is_used_by_update_and_default_cli() {
    let root = Root::new();
    success(&root.call(&[
        "--install-dir",
        "/srv/wgfeel-test",
        "--control",
        "main",
        "--endpoint",
        "127.0.0.1:53800",
        "--port",
        "53800",
    ]));
    assert!(!root.0.join("opt/wgfeel").exists());
    let base = root.0.join("srv/wgfeel-test");
    let installed = base.join("instance/bin/wgfeel");
    let before = fs::read(base.join("instance/state/state.json")).unwrap();
    let alias = root.0.join("usr/local/bin/wgfeel");
    assert_eq!(fs::read_link(&alias).unwrap(), installed);
    let dry = run(alias, vec!["uninstall".into(), "--dry-run".into()]);
    success(&dry);
    assert!(String::from_utf8_lossy(&dry.stdout).contains(base.join("instance").to_str().unwrap()));
    fs::copy("/proc/self/exe", &installed).unwrap();
    success(&run(
        env!("CARGO_BIN_EXE_wgfeel").into(),
        vec![
            "update".into(),
            "--root".into(),
            root.0.clone().into_os_string(),
            "--install-dir".into(),
            "/srv/wgfeel-test".into(),
            "--no-start".into(),
        ],
    ));
    assert_eq!(
        fs::read(&installed).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap()
    );
    assert_eq!(
        fs::read(base.join("instance/state/state.json")).unwrap(),
        before
    );
    // Owner-local CLI must derive the custom path from its executable, not /opt.
    let socket = base.join("instance/state/api.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let child = spawn(
        base.join("instance/bin/wgfeel"),
        vec!["user".into(), "list".into()],
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                use std::io::{Read, Write};
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 4096];
                let count = stream.read(&mut request).unwrap();
                assert!(
                    String::from_utf8_lossy(&request[..count]).starts_with("GET /api/v1/users ")
                );
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nETag: \"1\"\r\nConnection: close\r\n\r\n{\"users\":[]}",
                    )
                    .unwrap();
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("custom installation CLI did not connect: {error}"),
        }
    }
    success(&child.wait(Duration::from_secs(5)).unwrap());
}
