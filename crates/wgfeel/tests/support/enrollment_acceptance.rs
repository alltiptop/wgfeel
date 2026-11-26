//! Enrollment exercised through real CLIs, isolated workers and native WG
//! clients. Only loopback sockets and disposable files are used.
use super::super::enrollment::invitation;
use super::*;
use std::net::Ipv6Addr;
use wgfeel_core::{DevicePublicKey, GatewayProjection, NodeId, ServicePrivateKey};
use wgfeel_protocol::enrollment::Invitation;

struct Node {
    id: NodeId,
    state: PathBuf,
    actual: [SocketAddr; 2],
    child: Option<ManagedChild>,
}
impl Node {
    fn new(parent: &Fixture, name: &str) -> Self {
        Self::listening(parent, name, "0.0.0.0:0".parse().unwrap())
    }
    fn listening(parent: &Fixture, name: &str, listen: SocketAddr) -> Self {
        let state = parent.0.join(name);
        let id = wgfeel_host::node::generated_id().unwrap();
        wgfeel_host::node::initialize_unbound(&state, id.clone()).unwrap();
        let mut child = spawn(vec![
            "serve".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            state.clone().into_os_string(),
            "--listen".into(),
            listen.to_string().into(),
        ]);
        let ready: Value = serde_json::from_slice(&child.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["node_id"], id.as_str());
        let port = ready["listen"]
            .as_str()
            .unwrap()
            .parse::<SocketAddr>()
            .unwrap()
            .port();
        Self {
            id,
            state,
            actual: [
                if listen.ip().is_unspecified() {
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
                } else {
                    listen
                },
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            ],
            child: Some(child),
        }
    }
    fn join_command(&self, invite: &Invitation, endpoints: &[SocketAddr]) -> ManagedChild {
        let mut args = vec![
            "join".into(),
            invite.encode().unwrap().as_str().into(),
            "--state-dir".into(),
            self.state.clone().into_os_string(),
        ];
        for endpoint in endpoints {
            args.extend(["--endpoint".into(), endpoint.to_string().into()]);
        }
        spawn(args)
    }
    fn join(&self, manager: &Fixture, endpoints: &[SocketAddr]) {
        let output = self
            .join_command(&invitation(manager), endpoints)
            .wait(Duration::from_secs(75))
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.state.join("state.json")).unwrap()
    }
    fn projection(&self) -> GatewayProjection {
        let value: Value = serde_json::from_slice(&self.bytes()).unwrap();
        GatewayProjection::from_json(&value["projection"].to_string()).unwrap()
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            stop(child);
        }
    }
}

fn wait_applied(manager: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = api::json(&manager.state(), "GET", "/api/v1/distribution", Value::Null);
        let nodes = status["gateways"].as_array().unwrap();
        if !nodes.is_empty() && nodes.iter().all(|node| node["status"] == "applied") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "configuration not applied: {status}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
fn users(manager: &Fixture, homes: [&NodeId; 2]) -> Vec<Client> {
    for name in ["alice", "bob"] {
        let user = api::json(
            &manager.state(),
            "POST",
            "/api/v1/users",
            serde_json::json!({"name":name}),
        );
        let user = user["id"].as_str().unwrap();
        for (name, home) in ["phone", "laptop"].into_iter().zip(homes) {
            api::json(
                &manager.state(),
                "POST",
                &format!("/api/v1/users/{user}/devices"),
                serde_json::json!({"name":name, "gateway":home}),
            );
        }
    }
    wait_applied(manager);
    let mut clients: Vec<_> = [
        ("alice", "phone"),
        ("alice", "laptop"),
        ("bob", "phone"),
        ("bob", "laptop"),
    ]
    .into_iter()
    .map(|(user, device)| Client::from_config(&exported(manager, user, device)))
    .collect();
    assert_eq!(clients[0].address, clients[2].address);
    assert_eq!(clients[1].address, clients[3].address);
    for client in &mut clients {
        client.establish();
    }
    clients
}
fn local_exchange(clients: &mut [Client], source: usize, target: usize, marker: u8) {
    exchange_with_limits(clients, source, target, marker, 1, Duration::from_secs(2));
}

#[test]
fn main_mesh_applies_policy_only_revisions_and_recovers_without_restarting() {
    let manager = Fixture::new();
    manager.initialize_with_traffic("127.0.0.1:0", Some("entry"));
    let running = manager.start(1);
    let mut node = Node::new(&manager, "child");
    let joined = node
        .join_command(&invitation(&manager), &node.actual[..1])
        .wait(Duration::from_secs(75))
        .unwrap();
    if !joined.status.success() {
        let child_output = node.child.take().unwrap().terminate().unwrap();
        let main_output = running.terminate().unwrap();
        panic!(
            "join failed; child diagnostics: {}; main diagnostics: {}",
            String::from_utf8_lossy(&child_output.stderr),
            String::from_utf8_lossy(&main_output.stderr)
        );
    }
    let main = NodeId::new("management").unwrap();
    let mut clients = users(&manager, [&main, &node.id]);
    exchange(&mut clients, 0, 1, 81);
    let (alice, _) = ids(&manager, "alice", "phone");
    api::json(
        &manager.state(),
        "POST",
        &format!("/api/v1/users/{alice}/suspend"),
        serde_json::json!({}),
    );
    wait_applied(&manager);
    let denied = packet(clients[0].address, clients[1].address, 82);
    clients[0].send(&denied);
    no_plaintext(&mut clients);
    exchange(&mut clients, 2, 3, 83);
    api::json(
        &manager.state(),
        "POST",
        &format!("/api/v1/users/{alice}/resume"),
        serde_json::json!({}),
    );
    wait_applied(&manager);
    exchange(&mut clients, 0, 1, 84);
    exchange(&mut clients, 1, 0, 85);
    stop(running);
}

#[test]
fn committed_main_revision_replaces_a_failed_service_worker_without_stopping_user_traffic() {
    let manager = Fixture::new();
    manager.initialize_with_traffic("127.0.0.1:0", Some("entry"));
    let running = manager.start(1);
    let main = NodeId::new("management").unwrap();
    let mut clients = users(&manager, [&main, &main]);
    local_exchange(&mut clients, 2, 3, 91);
    let children = format!("/proc/{}/task/{}/children", running.id(), running.id());
    let service: u32 = fs::read_to_string(&children)
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .find(|pid: &u32| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .unwrap()
                .split(|b| *b == 0)
                .any(|arg| arg == b"service")
        })
        .unwrap();
    kill_process(Pid::from_raw(service as i32).unwrap(), Signal::KILL).unwrap();
    let until = Instant::now() + WAIT;
    while fs::read_to_string(&children)
        .unwrap()
        .split_whitespace()
        .any(|pid| pid == service.to_string())
    {
        assert!(
            Instant::now() < until,
            "failed service worker was not reaped"
        );
        thread::sleep(Duration::from_millis(10));
    }
    local_exchange(&mut clients, 2, 3, 92);
    let (alice, _) = ids(&manager, "alice", "phone");
    api::json(
        &manager.state(),
        "POST",
        &format!("/api/v1/users/{alice}/suspend"),
        serde_json::json!({}),
    );
    wait_applied(&manager);
    assert!(manager.remote(&["user", "list"], "", true).contains("bob"));
    for client in &mut clients {
        client.establish();
    }
    local_exchange(&mut clients, 2, 3, 93);
    let denied = packet(clients[0].address, clients[1].address, 94);
    clients[0].send(&denied);
    no_plaintext(&mut clients);
    stop(running);
}

#[test]
fn common_child_enrollment_applies_main_selected_entry_relay_and_off_policy() {
    let manager = Fixture::new();
    manager.initialize_with_traffic("127.0.0.1:0", Some("off"));
    let running = manager.start(1);
    let mut nodes = Vec::new();
    for mode in ["entry", "relay", "off"] {
        let node = Node::new(&manager, mode);
        let invite = super::super::enrollment::invitation_mode(&manager, Some(mode));
        let result = node
            .join_command(&invite, &node.actual[..1])
            .wait(Duration::from_secs(75))
            .unwrap();
        assert!(
            result.status.success(),
            "{mode} join: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        nodes.push(node);
    }
    api::json(
        &manager.state(),
        "POST",
        "/api/v1/users",
        serde_json::json!({"name":"policy-test"}),
    );
    wait_applied(&manager);
    for (node, mode) in nodes.iter().zip(["entry", "relay", "off"]) {
        let projection = node.projection();
        assert_eq!(
            serde_json::to_value(projection.assignment().traffic()).unwrap(),
            mode
        );
        assert_eq!(
            projection.assignment().networks().len(),
            usize::from(mode != "off")
        );
        assert_eq!(
            projection.assignment().tenants().len(),
            usize::from(mode == "entry")
        );
    }
    stop(running);
}

#[test]
fn unified_main_enrolls_children_and_forwards_in_each_traffic_mode() {
    for mode in ["entry", "relay", "off"] {
        let manager = Fixture::new();
        manager.initialize_with_traffic("127.0.0.1:0", Some(mode));
        let running = manager.start(1);
        let first = Node::new(&manager, "first");
        first.join(&manager, &first.actual[..1]);
        let second = Node::new(&manager, "second");
        second.join(&manager, &second.actual[..1]);
        let main = NodeId::new("management").unwrap();
        let homes = if mode == "entry" {
            [&main, &first.id]
        } else {
            [&first.id, &second.id]
        };
        let mut clients = users(&manager, homes);
        exchange(&mut clients, 0, 1, 61);
        exchange(&mut clients, 3, 2, 62);
        let own = first
            .projection()
            .mesh()
            .iter()
            .find(|node| node.recipient() == &main)
            .unwrap()
            .clone();
        assert_eq!(serde_json::to_value(own.traffic()).unwrap(), mode);
        if mode != "entry" {
            assert!(own.tenants().is_empty());
        }
        if mode == "off" {
            assert!(own.networks().is_empty());
        }
        stop(running);
        // Child-only traffic remains independent of the main's availability.
        if mode != "entry" {
            exchange(&mut clients, 0, 1, 63);
            exchange(&mut clients, 3, 2, 64);
        }
    }
}

// Each family has two proxy endpoints. Node-to-node packets are forwarded from
// the sender's advertised proxy; clients/control get independent return sockets.
struct DualLinks {
    enabled: Arc<[AtomicBool; 2]>,
    forwarded: Arc<[AtomicUsize; 2]>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    addresses: [[SocketAddr; 2]; 2],
}
impl DualLinks {
    fn new(actual: [[SocketAddr; 2]; 2]) -> Self {
        let sockets: [[UdpSocket; 2]; 2] = std::array::from_fn(|_| {
            [
                UdpSocket::bind("127.0.0.1:0").unwrap(),
                UdpSocket::bind("[::1]:0").unwrap(),
            ]
        });
        let addresses = std::array::from_fn(|node| {
            std::array::from_fn(|family| {
                sockets[node][family].set_nonblocking(true).unwrap();
                sockets[node][family].local_addr().unwrap()
            })
        });
        let enabled = Arc::new([AtomicBool::new(true), AtomicBool::new(true)]);
        let forwarded = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let done = Arc::new(AtomicBool::new(false));
        let flags = (enabled.clone(), forwarded.clone(), done.clone());
        let thread = thread::spawn(move || {
            let mut external: Vec<(usize, usize, SocketAddr, UdpSocket)> = vec![];
            let mut buffer = [0; 1500];
            while !flags.2.load(Ordering::Relaxed) {
                for to in 0..2 {
                    for family in 0..2 {
                        for _ in 0..64 {
                            let (len, source) = match sockets[to][family].recv_from(&mut buffer) {
                                Ok(received) => received,
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                                Err(error) => panic!("dual link: {error}"),
                            };
                            if let Some(from) = actual
                                .iter()
                                .position(|addresses| addresses[family] == source)
                            {
                                if flags.0[family].load(Ordering::Relaxed) {
                                    sockets[from][family]
                                        .send_to(&buffer[..len], actual[to][family])
                                        .unwrap();
                                    flags.1[family].fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                let index = external
                                    .iter()
                                    .position(|(node, f, address, _)| {
                                        *node == to && *f == family && *address == source
                                    })
                                    .unwrap_or_else(|| {
                                        assert!(external.len() < 128);
                                        let bridge = UdpSocket::bind(if family == 0 {
                                            "127.0.0.1:0"
                                        } else {
                                            "[::1]:0"
                                        })
                                        .unwrap();
                                        bridge.set_nonblocking(true).unwrap();
                                        external.push((to, family, source, bridge));
                                        external.len() - 1
                                    });
                                external[index]
                                    .3
                                    .send_to(&buffer[..len], actual[to][family])
                                    .unwrap();
                            }
                        }
                    }
                }
                for (node, family, peer, bridge) in &external {
                    while let Ok((len, source)) = bridge.recv_from(&mut buffer) {
                        assert_eq!(source, actual[*node][*family]);
                        sockets[*node][*family]
                            .send_to(&buffer[..len], peer)
                            .unwrap();
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        Self {
            enabled,
            forwarded,
            done,
            thread: Some(thread),
            addresses,
        }
    }
}
impl Drop for DualLinks {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn installed_node_joins_without_path_or_endpoint_options() {
    let manager = Fixture::new();
    manager.initialize();
    let management = manager.start(1);
    let root = manager.0.join("installed-root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let invite = invitation(&manager);
    let endpoint = SocketAddr::new("127.0.0.2".parse().unwrap(), invite.mesh_port());
    let output = spawn(vec![
        "install".into(),
        "--control".into(),
        "child".into(),
        "--root".into(),
        root.clone().into_os_string(),
        "--install-dir".into(),
        "/srv/feel".into(),
        "--no-start".into(),
        "--listen-ip".into(),
        endpoint.ip().to_string().into(),
        "--endpoint".into(),
        endpoint.ip().to_string().into(),
    ])
    .wait(WAIT)
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let executable = root.join("srv/feel/instance/bin/wgfeel");
    let state = root.join("srv/feel/instance/state");
    let before: Value =
        serde_json::from_slice(&fs::read(state.join("state.json")).unwrap()).unwrap();
    assert!(!state.join("api.sock").exists());
    // This is exactly the printed command, run using the installed executable.
    // Address selection comes from its installation file, not test-only flags.
    let output = ManagedChild::spawn(
        ProcessSpec::new(
            executable,
            vec!["join".into(), invite.encode().unwrap().as_str().into()],
            vec![],
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 128 * 1024,
            max_stderr_bytes: 8192,
        },
    )
    .unwrap()
    .wait(Duration::from_secs(75))
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after: Value =
        serde_json::from_slice(&fs::read(state.join("state.json")).unwrap()).unwrap();
    assert_eq!(after["node_id"], before["node_id"]);
    assert_eq!(after["service_private_key"], before["service_private_key"]);
    assert_eq!(
        after["management_public_key"],
        serde_json::to_value(invite.management_public_key()).unwrap()
    );
    let nodes = api::json(&manager.state(), "GET", "/api/v1/gateways", Value::Null);
    assert_eq!(nodes["gateways"].as_array().unwrap().len(), 2);
    let node_details = nodes["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["recipient"] == before["node_id"])
        .unwrap();
    assert_eq!(node_details["endpoint"], endpoint.to_string());
    assert!(
        node_details["hostname"]
            .as_str()
            .is_some_and(|name| !name.is_empty())
    );
    assert!(!state.join("api.sock").exists());
    stop(management);
}

#[test]
fn enrollment_and_withdrawal_use_only_the_listening_mesh_port_in_both_directions() {
    let fixture = Fixture::new();
    fixture.initialize();
    let manager = fixture.start(1);
    let issued = invitation(&fixture);
    let port = issued.mesh_port();
    let main = issued.endpoints()[0];
    let node = Node::listening(&fixture, "child", ([127, 0, 0, 2], port).into());
    let public = [
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 3], port))).unwrap(),
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 4], port))).unwrap(),
    ];
    let addresses = public.each_ref().map(|socket| socket.local_addr().unwrap());
    let invite = Invitation::new(
        issued.id().clone(),
        issued.management().clone(),
        issued.management_public_key().clone(),
        vec![addresses[0]],
        port,
        issued.expires_at(),
        ServicePrivateKey::new(*issued.temporary_private_key().expose_bytes()).unwrap(),
    )
    .unwrap();
    for socket in &public {
        socket.set_nonblocking(true).unwrap();
    }
    let join = node.join_command(&invite, &addresses[1..]);
    let actual = [main, node.actual[0]];
    let done = AtomicBool::new(false);
    let (output, claim_handshakes, revoked) = thread::scope(|scope| {
        let link = scope.spawn(|| {
            let mut packet = [0; 1500];
            let mut probes = 0;
            let mut claim_handshakes = 0;
            let deadline = Instant::now() + Duration::from_secs(60);
            while !done.load(Ordering::Relaxed) && Instant::now() < deadline {
                for to in 0..2 {
                    while let Ok((len, source)) = public[to].recv_from(&mut packet) {
                        if source != actual[1 - to] {
                            continue;
                        }
                        if len == 148 && packet[..4] == [1, 0, 0, 0] {
                            if to == 1 {
                                probes += 1;
                                if probes == 1 {
                                    continue;
                                } // Lose the first reverse handshake.
                            } else if probes < 2 {
                                claim_handshakes += 1;
                            }
                        }
                        public[1 - to].send_to(&packet[..len], actual[to]).unwrap();
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            claim_handshakes
        });
        let result = join.wait(Duration::from_secs(20));
        let mut revoked = false;
        if result.as_ref().is_ok_and(|out| out.status.success()) {
            api::json(
                &fixture.state(),
                "DELETE",
                &format!("/api/v1/gateways/{}", node.id.as_str()),
                Value::Null,
            );
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if node.projection().is_revoked() {
                    revoked = true;
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
        done.store(true, Ordering::Relaxed);
        (result, link.join().unwrap(), revoked)
    });
    let output = output.expect("join must complete using the bound ports");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(node.projection().management_id(), issued.management());
    assert_eq!(
        claim_handshakes, 1,
        "polling a pending claim must reuse its authenticated tunnel"
    );
    assert_eq!(
        node.projection().assignment().endpoint(),
        Some(addresses[1])
    );
    assert!(
        revoked,
        "withdrawal must reach the child on the same mesh port"
    );
    stop(manager);
}

#[test]
fn enrolled_nodes_switch_outer_ip_families_with_isolated_user_traffic_without_manager() {
    let manager = Fixture::new();
    manager.initialize();
    let process = manager.start(1);
    let first = Node::new(&manager, "first");
    let second = Node::new(&manager, "second");
    let links = DualLinks::new([first.actual, second.actual]);
    first.join(&manager, &links.addresses[0]);
    second.join(&manager, &links.addresses[1]);
    let mut clients = users(&manager, [&first.id, &second.id]);
    exchange(&mut clients, 0, 1, 101);
    exchange(&mut clients, 3, 2, 102);
    assert!(links.forwarded[0].load(Ordering::Relaxed) > 0);
    stop(process);
    for (family, marker) in [(1, 110), (0, 120), (1, 130)] {
        links.enabled[family].store(true, Ordering::Relaxed);
        links.enabled[1 - family].store(false, Ordering::Relaxed);
        let before = links.forwarded[family].load(Ordering::Relaxed);
        exchange(&mut clients, 0, 1, marker);
        exchange(&mut clients, 3, 2, marker + 1);
        assert!(links.forwarded[family].load(Ordering::Relaxed) > before);
        let spoofed = packet(
            "10.203.0.99".parse().unwrap(),
            clients[1].address,
            marker + 2,
        );
        clients[0].send(&spoofed);
        no_plaintext(&mut clients);
    }
}

#[test]
fn manager_transfer_preserves_live_traffic_on_failure_and_revokes_old_users_and_authority() {
    let first = Fixture::new();
    first.initialize();
    let second = Fixture::new();
    second.initialize();
    let manager1 = first.start(1);
    let manager2 = second.start(1);
    let node = Node::new(&first, "node");
    node.join(&first, &node.actual);
    let mut clients = users(&first, [&node.id, &node.id]);
    local_exchange(&mut clients, 0, 1, 140);
    local_exchange(&mut clients, 3, 2, 141);
    let before = node.bytes();
    let invite = invitation(&second);
    let unreachable = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bad = Invitation::new(
        invite.id().clone(),
        invite.management().clone(),
        invite.management_public_key().clone(),
        vec![unreachable.local_addr().unwrap()],
        invite.mesh_port(),
        invite.expires_at(),
        ServicePrivateKey::new(*invite.temporary_private_key().expose_bytes()).unwrap(),
    )
    .unwrap();
    let attempt = node.join_command(&bad, &node.actual);
    let deadline = Instant::now() + Duration::from_secs(70);
    let mut pending = 0;
    loop {
        let response = api::get(&node.state, "/internal/v1/join");
        let state: Value = serde_json::from_slice(&response.body).unwrap();
        if state["state"] == "failed" {
            break;
        }
        if state["state"] == "pending" {
            pending += 1;
        }
        local_exchange(&mut clients, 0, 1, 142);
        local_exchange(&mut clients, 3, 2, 143);
        assert_eq!(node.bytes(), before);
        assert!(Instant::now() < deadline, "failed join did not terminate");
        thread::sleep(Duration::from_millis(200));
    }
    assert!(pending >= 10, "no sustained traffic while joining");
    let output = attempt.wait(WAIT).unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("waiting for an authenticated reply from main")
    );
    assert_eq!(node.bytes(), before);
    local_exchange(&mut clients, 0, 1, 144);
    // Let the failed candidate removal complete before a fresh owner request.
    thread::sleep(Duration::from_millis(300));
    node.join(&second, &node.actual);
    let old_networks: Vec<_> = clients.iter().map(|client| client.address).collect();
    let mut fresh = users(&second, [&node.id, &node.id]);
    assert_eq!(
        fresh
            .iter()
            .map(|client| client.address)
            .collect::<Vec<_>>(),
        old_networks
    );
    local_exchange(&mut fresh, 0, 1, 150);
    local_exchange(&mut fresh, 3, 2, 151);
    let after = node.bytes();
    // Old sessions have valid ciphertext and overlapping inner addresses, but
    // no old tenant key/context may survive the authority switch.
    for index in [0, 3] {
        let target = if index == 0 { 1 } else { 2 };
        let bytes = packet(clients[index].address, clients[target].address, 152);
        clients[index].send(&bytes);
    }
    no_plaintext(&mut clients);
    no_plaintext(&mut fresh);
    assert!(
        !authenticates(&first, &node),
        "old Manager still authenticates"
    );
    assert!(
        authenticates(&second, &node),
        "new Manager cannot authenticate"
    );
    assert_eq!(node.bytes(), after);
    stop(manager1);
    stop(manager2);
    local_exchange(&mut fresh, 0, 1, 153);
}

fn authenticates(manager: &Fixture, node: &Node) -> bool {
    use wgfeel_wireguard::{
        ContextConfig, ContextId, Gateway, Limits, PeerConfig, PeerId, UdpTransport,
    };
    let state: Value =
        serde_json::from_slice(&fs::read(manager.state().join("state.json")).unwrap()).unwrap();
    let key: [u8; 32] = serde_json::from_value(state["service_private_key"].clone()).unwrap();
    let public: DevicePublicKey = node.projection().assignment().service_public_key().clone();
    let peer = PeerId::Node(node.id.clone());
    let mut wg = Gateway::new(
        vec![ContextConfig::service(
            ServicePrivateKey::new(key).unwrap(),
            vec![PeerConfig {
                id: peer.clone(),
                public_key: public,
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let udp = UdpTransport::from_socket(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
    if let Some(event) = wg
        .initiate_at(&ContextId::Service, &peer, node.actual[0])
        .unwrap()
    {
        udp.transmit(event).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let _ = udp.poll(&mut wg);
        if wg
            .send_datagram(
                &ContextId::Service,
                &peer,
                &packet(
                    "10.253.0.2".parse().unwrap(),
                    "10.253.0.1".parse().unwrap(),
                    159,
                ),
            )
            .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(2));
    }
    false
}
