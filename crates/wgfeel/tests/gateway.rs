#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]

use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
    x25519::{PublicKey, StaticSecret},
};
use rustix::{
    fd::OwnedFd,
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    pipe::{PipeFlags, pipe_with},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, kill_process_group, waitid},
};
use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, GatewayAssignment,
    ManagementConfig, Network, NetworkId, NodeId, Policy, Rule, TenantKeyAssignment,
    TenantPrivateKey,
};
use wgfeel_store::{LocalTenants, Store, StoreError};
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

const WAIT: Duration = Duration::from_secs(5);
const CAPTURE: usize = 16 * 1024;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn seed(value: u8) -> [u8; 32] {
    let mut bytes = [61; 32];
    bytes[13] = value;
    bytes
}
fn public(value: u8) -> DevicePublicKey {
    DevicePublicKey::new(PublicKey::from(&StaticSecret::from(seed(value))).to_bytes()).unwrap()
}
fn network(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn node(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn endpoint(net: &str, device: &str) -> Endpoint {
    Endpoint::new(network(net), DeviceId::new(device).unwrap())
}

fn populated() -> Directory {
    populated_with_dns(false)
}
fn populated_with_dns(dns: bool) -> Directory {
    let directory = Directory::new();
    let mut local = vec![];
    let networks = [("alpha", 1), ("beta", 2)]
        .into_iter()
        .map(|(name, key)| {
            local.push(Rule::new(
                endpoint(name, "first"),
                endpoint(name, "second"),
                Action::Allow,
            ));
            local.push(Rule::new(
                endpoint(name, "second"),
                endpoint(name, "first"),
                Action::Allow,
            ));
            Network::new(
                network(name),
                [("first", 1), ("second", 2)]
                    .into_iter()
                    .map(|(id, host)| {
                        Device::new(
                            DeviceId::new(id).unwrap(),
                            public(20 + key * 2 + host),
                            vec![
                                format!("10.1.0.{host}").parse().unwrap(),
                                format!("fd00:1::{host}").parse().unwrap(),
                            ],
                        )
                        .unwrap()
                        .with_hostname(dns.then(|| {
                            if (key == 1 && host == 1) || (key == 2 && host == 2) {
                                "pc".into()
                            } else {
                                "other".into()
                            }
                        }))
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    let config = Config::new(
        71,
        networks,
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "first"),
                endpoint("alpha", "second"),
                Action::Deny,
            )],
            local,
            vec![],
        ),
    )
    .unwrap();
    let assignment = GatewayAssignment::new(
        node("node"),
        (public(9)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(public(9))),
        vec![network("alpha"), network("beta")],
        vec![
            TenantKeyAssignment::new(network("alpha"), public(1)),
            TenantKeyAssignment::new(network("beta"), public(2)),
        ],
    )
    .unwrap();
    let projection = ManagementConfig::new(node("management"), config, vec![assignment])
        .unwrap()
        .project_for(&node("node"))
        .unwrap();
    Store::initialize(&directory.state())
        .unwrap()
        .commit_projection(
            &node("management"),
            &projection,
            &node("node"),
            &wgfeel_test_support::fixture_node_keys(seed(9)),
            &LocalTenants::new(vec![
                (network("alpha"), TenantPrivateKey::new(seed(1)).unwrap()),
                (network("beta"), TenantPrivateKey::new(seed(2)).unwrap()),
            ])
            .unwrap(),
        )
        .unwrap();
    directory
}

#[path = "support/capacity.rs"]
mod capacity;
#[path = "support/dns.rs"]
mod dns;

struct Runtime {
    child: ManagedChild,
}
impl Runtime {
    fn spawn(path: &Path, listen: &str) -> Self {
        Self::spawn_binary(env!("CARGO_BIN_EXE_wgfeel").into(), path, listen)
    }
    fn spawn_binary(binary: PathBuf, path: &Path, listen: &str) -> Self {
        Self {
            child: ManagedChild::spawn(
                ProcessSpec::new(
                    binary,
                    vec![
                        "serve".into(),
                        "--control".into(),
                        "child".into(),
                        "--state-dir".into(),
                        path.as_os_str().to_owned(),
                        "--listen".into(),
                        listen.into(),
                    ],
                    vec![],
                    None,
                ),
                ProcessLimits {
                    max_stdout_bytes: CAPTURE,
                    max_stderr_bytes: CAPTURE,
                },
            )
            .unwrap(),
        }
    }
    fn pid(&self) -> Pid {
        Pid::from_raw(self.child.id() as i32).unwrap()
    }
    fn ready(&mut self) -> SocketAddr {
        let line = self
            .child
            .next_stdout_line(WAIT)
            .expect("production gateway exited before readiness");
        let event: serde_json::Value =
            serde_json::from_slice(&line).expect("public startup log must be JSON");
        assert_eq!(event["event"], "ready");
        assert_eq!(event["node_id"], "node");
        assert_eq!(event["management_id"], "management");
        assert_eq!(event["generation"], 71);
        assert_eq!(event["local_contexts"], 2);
        let address: SocketAddr = event["listen"].as_str().unwrap().parse().unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        address
    }
    fn children(&self) -> Vec<u32> {
        let pid = self.pid().as_raw_pid();
        fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect()
    }
    fn signal(&self, signal: Signal) {
        kill_process(self.pid(), signal).unwrap();
    }
    fn finish(self) -> CapturedOutput {
        self.child.wait(WAIT).unwrap()
    }
}
fn no_secrets(output: &CapturedOutput) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("private_key"));
        for key in [1, 2, 9, 23, 24, 25, 26] {
            assert!(!text.contains(&format!("{:?}", seed(key))));
            assert!(!text.contains(&format!("{:?}", seed(key)).replace(' ', "")));
        }
    }
}

struct Peer {
    socket: UdpSocket,
    tunnel: Tunn,
    limiter: Arc<RateLimiter>,
}
impl Peer {
    fn new(key: u8, server_key: u8) -> Self {
        Self::with_keys(seed(key), public(server_key))
    }
    fn with_keys(secret: [u8; 32], server_public: DevicePublicKey) -> Self {
        let secret = StaticSecret::from(secret);
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&secret), 100));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        Self {
            socket,
            tunnel: Tunn::new(
                secret,
                PublicKey::from(*server_public.as_bytes()),
                None,
                None,
                IndexTable::from_os_rng(),
                Arc::clone(&limiter),
            ),
            limiter,
        }
    }
    fn receive(&mut self, source: SocketAddr, bytes: &[u8]) -> TunnResult {
        self.limiter.try_reset_count();
        let packet = self
            .limiter
            .verify_packet(source, Packet::copy_from(bytes))
            .unwrap();
        self.tunnel.handle_incoming_packet(packet)
    }
    fn wire(&self, timeout: Duration) -> (Vec<u8>, SocketAddr) {
        let deadline = Instant::now() + timeout;
        let mut bytes = [0; 1313];
        loop {
            match self.socket.recv_from(&mut bytes) {
                Ok((length, source)) => return (bytes[..length].to_vec(), source),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("peer UDP read failed: {error}"),
            }
            assert!(Instant::now() < deadline, "no encrypted gateway response");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn establish(&mut self, address: SocketAddr) {
        let initiation = self
            .tunnel
            .format_handshake_initiation(false)
            .unwrap()
            .into_bytes();
        self.socket.send_to(initiation.as_ref(), address).unwrap();
        let (response, source) = self.wire(WAIT);
        assert_eq!(source, address);
        let TunnResult::WriteToNetwork(confirmation) = self.receive(address, &response) else {
            panic!("expected authenticated handshake response");
        };
        let confirmation: Packet = confirmation.into();
        self.socket.send_to(confirmation.as_ref(), address).unwrap();
        // Let the one outstanding operation finish before this test sends data.
        std::thread::sleep(Duration::from_millis(20));
    }
    fn send(&mut self, address: SocketAddr, bytes: &[u8]) {
        let packet = self
            .tunnel
            .encapsulate_with_session(Packet::copy_from(bytes))
            .unwrap()
            .into_bytes();
        self.socket.send_to(packet.as_ref(), address).unwrap();
    }
    fn plaintext(&mut self, address: SocketAddr, expected: &[u8]) {
        let (wire, source) = self.wire(WAIT);
        assert_eq!(source, address);
        let TunnResult::WriteToTunnel(packet) = self.receive(address, &wire) else {
            panic!("destination did not authenticate forwarded packet");
        };
        assert!(packet.as_ref().len() >= expected.len());
        assert!(packet.as_ref().len() - expected.len() <= 15);
        assert_eq!(&packet.as_ref()[..expected.len()], expected);
    }
    fn no_datagram(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut bytes = [0; 1313];
        while Instant::now() < deadline {
            assert_eq!(
                self.socket.recv_from(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock,
                "denied packet produced UDP egress"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(ipv6: bool, source: u8, destination: u8, hops: u8, marker: u8) -> Vec<u8> {
    let offset = if ipv6 { 40 } else { 20 };
    let mut bytes = vec![0; offset + 12];
    if ipv6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&12_u16.to_be_bytes());
        bytes[6] = 17;
        bytes[7] = hops;
        bytes[8..24].copy_from_slice(
            &format!("fd00:1::{source}")
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        bytes[24..40].copy_from_slice(
            &format!("fd00:1::{destination}")
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
    } else {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&32_u16.to_be_bytes());
        bytes[6] = 0x40;
        bytes[8] = hops;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&Ipv4Addr::new(10, 1, 0, source).octets());
        bytes[16..20].copy_from_slice(&Ipv4Addr::new(10, 1, 0, destination).octets());
        let check = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&check.to_be_bytes());
    }
    bytes[offset..offset + 4].copy_from_slice(&[0x9c, 0x40, 0x1f, 0x90]);
    bytes[offset + 4..offset + 6].copy_from_slice(&12_u16.to_be_bytes());
    bytes[offset + 8..].fill(marker);
    let mut pseudo = if ipv6 {
        bytes[8..40].to_vec()
    } else {
        bytes[12..20].to_vec()
    };
    pseudo.extend_from_slice(if ipv6 {
        &[0, 0, 0, 12, 0, 0, 0, 17]
    } else {
        &[0, 17, 0, 12]
    });
    pseudo.extend_from_slice(&bytes[offset..]);
    let check = checksum(&pseudo);
    bytes[offset + 6..offset + 8]
        .copy_from_slice(&if check == 0 { 0xffff } else { check }.to_be_bytes());
    bytes
}
fn assert_reaped(children: &[u32]) {
    let deadline = Instant::now() + WAIT;
    loop {
        if children
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "gateway did not reap workers before harness cleanup"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

// Independent WG peer + in-memory TCP client exercises the actual encrypted
// delivery boundary; no host TCP listener or interface is used by this fixture.
fn deliver(address: SocketAddr, body: &str) -> Option<wgfeel_management::Response> {
    use wgfeel_management::{Request, http, tcp};
    let mut peer = Peer::new(70, 9);
    peer.establish(address);
    let mut buffers = tcp::Buffers::new(1).unwrap();
    let request = http::encode_request_with_limit(
        Request {
            method: "POST",
            target: "/internal/v1/config",
            authorization: None,
            if_match: None,
            body: body.as_bytes(),
        },
        wgfeel_core::MAX_PROJECTION_BYTES,
    )
    .unwrap();
    let mut client = tcp::Client::distribution(
        &mut buffers,
        NEXT.fetch_add(1, Ordering::Relaxed) as u64 + 1000,
        request,
    )
    .unwrap();
    let start = Instant::now();
    let mut wire = [0; 1313];
    while start.elapsed() < Duration::from_secs(6) {
        client.poll(start.elapsed()).unwrap();
        while let Some(packet) = client.take_packet() {
            peer.send(address, &packet);
        }
        for _ in 0..16 {
            match peer.socket.recv_from(&mut wire) {
                Ok((length, source)) => match peer.receive(source, &wire[..length]) {
                    TunnResult::WriteToTunnel(packet) => {
                        let bytes = packet.as_ref();
                        if bytes.is_empty() {
                            continue; // Authenticated WireGuard keepalive.
                        }
                        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                        // Main can also be a mesh participant on this same WG peer.
                        // Mesh health frames are not part of the TCP RPC stream.
                        if bytes[9] == 6 {
                            client.receive(&bytes[..length]).unwrap();
                        }
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        let packet: Packet = packet.into();
                        peer.socket.send_to(packet.as_ref(), address).unwrap();
                    }
                    _ => (),
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("control UDP failed: {error}"),
            }
        }
        if let Some(response) = client.take_response() {
            return Some(response.unwrap());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}
fn apply(address: SocketAddr, projection: &wgfeel_core::GatewayProjection) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(response) = deliver(address, &projection.to_json().unwrap()) {
            if response.status == 200 {
                assert_eq!(response.generation, Some(projection.generation()));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["applied"],
                    true
                );
                return;
            }
            assert_eq!(response.status, 202);
        }
        assert!(
            Instant::now() < deadline,
            "Node did not confirm applying configuration"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn pinned_main_in_mesh_exchanges_health_and_configuration_on_the_same_node_port() {
    use wgfeel_wireguard::mesh::{Action as MeshAction, Mesh};
    let directory = populated();
    let reserve = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reserve.local_addr().unwrap();
    let mut peer = Peer::with_keys(
        *wgfeel_test_support::fixture_node_keys(seed(70))
            .gateway()
            .expose_bytes(),
        wgfeel_test_support::fixture_gateway_public(&public(9)),
    );
    let main_address = peer.socket.local_addr().unwrap();
    let mut store = Store::open(&directory.state()).unwrap();
    let previous = store.load().unwrap().unwrap();
    let old = previous.projection();
    let mut value: serde_json::Value =
        serde_json::from_str(&old.config().to_json().unwrap()).unwrap();
    value["generation"] = 72.into();
    let routing = ManagementConfig::new(
        node("management"),
        Config::from_json(&value.to_string()).unwrap(),
        vec![
            GatewayAssignment::new(
                node("management"),
                (public(70)).clone(),
                wgfeel_test_support::fixture_gateway_public(&(public(70))),
                vec![],
                vec![],
            )
            .unwrap()
            .with_traffic(wgfeel_core::TrafficMode::Off)
            .unwrap()
            .with_endpoint(Some(main_address))
            .unwrap(),
            old.assignment()
                .clone()
                .with_endpoint(Some(address))
                .unwrap(),
        ],
    )
    .unwrap();
    let initial = routing.project_mesh_for(&node("node")).unwrap();
    store
        .commit_managed_projection(
            &initial,
            previous.node_keys(),
            previous.local_tenants(),
            &public(70),
        )
        .unwrap();
    drop(previous);
    drop(store);
    drop(reserve);
    let mut runtime = Runtime::spawn(&directory.state(), &address.to_string());
    let ready: serde_json::Value =
        serde_json::from_slice(&runtime.child.next_stdout_line(WAIT).unwrap()).unwrap();
    assert_eq!(ready["event"], "ready");
    assert_eq!(ready["listen"], address.to_string());
    let main_projection = routing.project_mesh_for(&node("management")).unwrap();
    let mut mesh = Mesh::new(&main_projection, 137);
    let start = Instant::now();
    let mut wire = [0; 2048];
    while mesh.next_hop(&node("node"), start.elapsed()).is_none() {
        assert!(
            start.elapsed() < WAIT,
            "main mesh health did not reach the child's mesh handler"
        );
        let mut actions = mesh.tick(start.elapsed());
        for _ in 0..16 {
            match peer.socket.recv_from(&mut wire) {
                Ok((length, source)) => match peer.receive(source, &wire[..length]) {
                    TunnResult::WriteToTunnel(packet) => {
                        let bytes = packet.as_ref();
                        if bytes.is_empty() {
                            continue; // Authenticated WireGuard keepalive.
                        }
                        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                        actions.extend(mesh.receive(
                            &node("node"),
                            source,
                            &bytes[..length],
                            start.elapsed(),
                        ));
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        let packet: Packet = packet.into();
                        peer.socket.send_to(packet.as_ref(), address).unwrap();
                    }
                    _ => (),
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("mesh receive failed: {error}"),
            }
        }
        for action in actions {
            match action {
                MeshAction::Initiate {
                    node: target,
                    endpoint,
                } => {
                    assert_eq!(target, node("node"));
                    assert_eq!(endpoint, address);
                    let initiation = peer
                        .tunnel
                        .format_handshake_initiation(false)
                        .unwrap()
                        .into_bytes();
                    peer.socket.send_to(initiation.as_ref(), address).unwrap();
                }
                MeshAction::Send {
                    node: target,
                    packet,
                } => {
                    assert_eq!(target, node("node"));
                    if let Ok(packet) = peer
                        .tunnel
                        .encapsulate_with_session(Packet::copy_from(packet.as_bytes()))
                    {
                        peer.socket
                            .send_to(packet.into_bytes().as_ref(), address)
                            .unwrap();
                    }
                }
                _ => panic!("unexpected mesh user traffic"),
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    apply(address, &initial);
    let mut first = Peer::new(25, 2);
    let mut second = Peer::new(26, 2);
    first.establish(address);
    second.establish(address);
    first.send(address, &packet(false, 1, 2, 64, 99));
    second.plaintext(address, &packet(false, 1, 2, 63, 99));
    runtime.signal(Signal::TERM);
    assert!(runtime.finish().status.success());
}

#[test]
fn management_delivery_enforces_pins_revisions_and_live_policy_before_acknowledging() {
    let directory = populated();
    let mut store = Store::open(&directory.state()).unwrap();
    let previous = store.load().unwrap().unwrap();
    let old = previous.projection();
    let mut serialized: serde_json::Value =
        serde_json::from_str(&old.config().to_json().unwrap()).unwrap();
    serialized["generation"] = 72.into();
    let config = Config::from_json(&serialized.to_string()).unwrap();
    let routing =
        ManagementConfig::new(node("management"), config, vec![old.assignment().clone()]).unwrap();
    let initial = routing.project_mesh_for(&node("node")).unwrap();
    store
        .commit_managed_projection(
            &initial,
            previous.node_keys(),
            previous.local_tenants(),
            &public(70),
        )
        .unwrap();
    drop(previous);
    drop(store);
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let ready: serde_json::Value =
        serde_json::from_slice(&runtime.child.next_stdout_line(WAIT).unwrap()).unwrap();
    let address = ready["listen"].as_str().unwrap().parse().unwrap();
    let mut first = Peer::new(25, 2);
    let mut second = Peer::new(26, 2);
    first.establish(address);
    second.establish(address);
    first.send(address, &packet(false, 1, 2, 64, 21));
    second.plaintext(address, &packet(false, 1, 2, 63, 21));
    let mut impostor = Peer::new(71, 9);
    let handshake = impostor
        .tunnel
        .format_handshake_initiation(false)
        .unwrap()
        .into_bytes();
    impostor
        .socket
        .send_to(handshake.as_ref(), address)
        .unwrap();
    impostor.no_datagram(Duration::from_millis(150));
    let policy = Policy::new(
        vec![Rule::new(
            endpoint("beta", "first"),
            endpoint("beta", "second"),
            Action::Deny,
        )],
        vec![Rule::new(
            endpoint("beta", "second"),
            endpoint("beta", "first"),
            Action::Allow,
        )],
        vec![],
    );
    let config = Config::new(73, initial.config().networks().to_vec(), policy).unwrap();
    let changed = ManagementConfig::new(
        node("management"),
        config,
        vec![initial.assignment().clone()],
    )
    .unwrap()
    .project_mesh_for(&node("node"))
    .unwrap();
    let original_workers = runtime.children();
    apply(address, &changed);
    assert_eq!(runtime.children(), original_workers);
    // Policy-only delivery preserves existing sessions, including while no
    // Management connection or process exists after the exchange has returned.
    first.send(address, &packet(false, 1, 2, 64, 22));
    second.no_datagram(Duration::from_millis(150));
    second.send(address, &packet(false, 2, 1, 64, 23));
    first.plaintext(address, &packet(false, 2, 1, 63, 23));
    assert_eq!(
        deliver(address, &initial.to_json().unwrap())
            .unwrap()
            .status,
        409
    );
    let mut conflict: serde_json::Value =
        serde_json::from_str(&initial.to_json().unwrap()).unwrap();
    conflict["config"]["generation"] = 73.into();
    assert_eq!(deliver(address, &conflict.to_string()).unwrap().status, 409);
    let mut wrong: serde_json::Value = serde_json::from_str(&changed.to_json().unwrap()).unwrap();
    wrong["assignment"]["recipient"] = "other".into();
    wrong["mesh"][0]["recipient"] = "other".into();
    assert_eq!(deliver(address, &wrong.to_string()).unwrap().status, 403);
    let mut missing: serde_json::Value = serde_json::from_str(&changed.to_json().unwrap()).unwrap();
    missing["config"]["generation"] = 74.into();
    missing["assignment"]["tenants"][1]["public_key"] = serde_json::to_value(public(65)).unwrap();
    missing["mesh"][0]["tenants"][1]["public_key"] = serde_json::to_value(public(65)).unwrap();
    assert_eq!(deliver(address, &missing.to_string()).unwrap().status, 422);
    let disk: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.state().join("state.json")).unwrap()).unwrap();
    assert_eq!(disk["projection"]["config"]["generation"], 73);
    second.send(address, &packet(false, 2, 1, 64, 24));
    first.plaintext(address, &packet(false, 2, 1, 63, 24));
    // A new revision must activate ready workers even when the peer set is
    // unchanged and one of the old crypto workers has already failed.
    kill_process(
        Pid::from_raw(runtime.children()[1] as i32).unwrap(),
        Signal::KILL,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let mut recovered: serde_json::Value =
        serde_json::from_str(&changed.to_json().unwrap()).unwrap();
    recovered["config"]["generation"] = 74.into();
    let recovered = wgfeel_core::GatewayProjection::from_json(&recovered.to_string()).unwrap();
    apply(address, &recovered);
    let mut first = Peer::new(25, 2);
    let mut second = Peer::new(26, 2);
    first.establish(address);
    second.establish(address);
    second.send(address, &packet(false, 2, 1, 64, 26));
    first.plaintext(address, &packet(false, 2, 1, 63, 26));
    let removed = ManagementConfig::new(
        node("management"),
        Config::new(75, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![],
    )
    .unwrap();
    let withdrawal = removed.withdraw_for(changed.assignment()).unwrap();
    apply(address, &withdrawal);
    second.send(address, &packet(false, 2, 1, 64, 25));
    first.no_datagram(Duration::from_millis(150));
    runtime.signal(Signal::TERM);
    assert!(runtime.finish().status.success());
    let restored = Store::open(&directory.state())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(restored.projection(), &withdrawal);
    assert!(restored.local_tenants().is_empty());
}

#[test]
fn production_gateway_forwards_persisted_policy_on_one_port_without_changing_state() {
    let directory = populated();
    let state_path = directory.state().join("state.json");
    let before = fs::read(&state_path).unwrap();
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    let children = runtime.children();
    assert_eq!(
        children.len(),
        4,
        "two isolated tenants and separate service and gateway workers"
    );
    let mut peers = [
        Peer::new(23, 1),
        Peer::new(24, 1),
        Peer::new(25, 2),
        Peer::new(26, 2),
    ];
    for peer in &mut peers {
        peer.establish(address);
    }
    peers[0].send(address, &packet(false, 1, 2, 64, 8));
    peers[1].no_datagram(Duration::from_millis(120));
    peers[3].send(address, &packet(true, 1, 1, 64, 9));
    peers[2].no_datagram(Duration::from_millis(120));
    for (source, target, ipv6, marker) in [(1, 0, false, 11), (2, 3, true, 12), (3, 2, false, 13)] {
        let from = if source % 2 == 0 { 1 } else { 2 };
        let to = if target % 2 == 0 { 1 } else { 2 };
        peers[source].send(address, &packet(ipv6, from, to, 64, marker));
        peers[target].plaintext(address, &packet(ipv6, from, to, 63, marker));
    }
    assert_eq!(fs::read(&state_path).unwrap(), before);
    runtime.signal(Signal::TERM);
    assert_reaped(&children);
    let output = runtime.finish();
    assert!(output.status.success());
    no_secrets(&output);
    assert_eq!(fs::read(&state_path).unwrap(), before);
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(directory.state()).unwrap().count(), 1);
    assert!(UdpSocket::bind(address).is_ok());
    assert!(Store::open(&directory.state()).is_ok());
}

#[test]
fn invalid_and_mismatched_material_never_become_ready_or_repair_state() {
    for variant in [
        "unknown_format",
        "recipient",
        "node_key",
        "tenant_key",
        "malformed",
    ] {
        let directory = populated();
        let state = directory.state().join("state.json");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        match variant {
            "unknown_format" => envelope["storage_version"] = u64::MAX.into(),
            "recipient" => envelope["projection"]["assignment"]["recipient"] = "foreign".into(),
            "node_key" => envelope["service_private_key"] = serde_json::json!(seed(8)),
            "tenant_key" => {
                envelope["tenant_private_keys"][0]["private_key"] = serde_json::json!(seed(7))
            }
            "malformed" => envelope["projection"] = serde_json::Value::Null,
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&envelope).unwrap();
        fs::write(&state, &bytes).unwrap();
        let output = Runtime::spawn(&directory.state(), "127.0.0.1:0").finish();
        assert!(
            !output.status.success(),
            "invalid fixture accepted: {variant}"
        );
        assert!(
            output.stdout.is_empty(),
            "invalid startup emitted readiness: {variant}"
        );
        assert!(!output.stderr.is_empty());
        no_secrets(&output);
        assert_eq!(fs::read(&state).unwrap(), bytes);
        assert!(Store::open(&directory.state()).is_ok());
    }
    let directory = populated();
    let before = fs::read(directory.state().join("state.json")).unwrap();
    for listen in ["localhost:51820", "127.0.0.1", "127.0.0.1:99999"] {
        let output = Runtime::spawn(&directory.state(), listen).finish();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        no_secrets(&output);
    }
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        before
    );
}

#[test]
fn socket_conflict_and_duplicate_runtime_fail_without_disrupting_owner() {
    let directory = populated();
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let output = Runtime::spawn(
        &directory.state(),
        &occupied.local_addr().unwrap().to_string(),
    )
    .finish();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    no_secrets(&output);
    assert!(Store::open(&directory.state()).is_ok());

    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    assert!(matches!(
        Store::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    let duplicate = Runtime::spawn(&directory.state(), "127.0.0.1:0").finish();
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    no_secrets(&duplicate);
    let mut first = Peer::new(25, 2);
    let mut second = Peer::new(26, 2);
    first.establish(address);
    second.establish(address);
    first.send(address, &packet(true, 1, 2, 64, 21));
    second.plaintext(address, &packet(true, 1, 2, 63, 21));
    let children = runtime.children();
    runtime.signal(Signal::TERM);
    assert_reaped(&children);
    assert!(runtime.finish().status.success());
}

#[test]
fn term_and_int_reap_workers_then_fresh_process_reuses_same_snapshot_and_port() {
    let directory = populated();
    let before = fs::read(directory.state().join("state.json")).unwrap();
    let mut listen = "127.0.0.1:0".to_owned();
    for signal in [Signal::TERM, Signal::INT] {
        let mut runtime = Runtime::spawn(&directory.state(), &listen);
        let address = runtime.ready();
        listen = address.to_string();
        let mut first = Peer::new(25, 2);
        let mut second = Peer::new(26, 2);
        first.establish(address);
        second.establish(address);
        first.send(address, &packet(false, 1, 2, 64, 31));
        second.plaintext(address, &packet(false, 1, 2, 63, 31));
        let children = runtime.children();
        // Stopping a worker makes graceful parent cleanup prove kill+reap,
        // rather than relying on the worker voluntarily reading pipe EOF.
        kill_process(Pid::from_raw(children[0] as i32).unwrap(), Signal::STOP).unwrap();
        runtime.signal(signal);
        assert_reaped(&children);
        let output = runtime.finish();
        assert!(output.status.success());
        no_secrets(&output);
        assert!(UdpSocket::bind(address).is_ok());
        assert!(Store::open(&directory.state()).is_ok());
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            before
        );
    }
}

fn child_context(pid: u32) -> String {
    let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    let value = args
        .split(|byte| *byte == 0)
        .find(|arg| arg.starts_with(b"tenant:"))
        .unwrap();
    String::from_utf8(value.to_vec()).unwrap()
}
fn terminated(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Ok(stat) => matches!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().next(),
            Some("Z" | "X")
        ),
        Err(error) => panic!("cannot inspect owned process: {error}"),
    }
}

#[test]
fn abrupt_parent_death_terminates_even_a_stopped_worker_before_harness_cleanup() {
    let directory = populated();
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    let children = runtime.children();
    assert_eq!(children.len(), 4);
    kill_process(Pid::from_raw(children[0] as i32).unwrap(), Signal::STOP).unwrap();
    runtime.signal(Signal::KILL);
    let deadline = Instant::now() + WAIT;
    // Do not wait/drop ManagedChild until death is independently observed;
    // that harness otherwise kills the entire process group and masks orphans.
    while !children.iter().copied().all(terminated) {
        assert!(
            Instant::now() < deadline,
            "owned worker survived parent death"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!runtime.finish().status.success());
    assert!(UdpSocket::bind(address).is_ok());
    assert!(Store::open(&directory.state()).is_ok());
}

#[test]
fn one_worker_death_disables_only_its_context_without_automatic_restart() {
    let directory = populated();
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    let children = runtime.children();
    let alpha = children
        .iter()
        .copied()
        .find(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .unwrap()
                .split(|byte| *byte == 0)
                .any(|arg| arg == b"tenant:alpha")
        })
        .unwrap();
    assert_eq!(child_context(alpha), "tenant:alpha");
    kill_process(Pid::from_raw(alpha as i32).unwrap(), Signal::KILL).unwrap();
    assert_reaped(&[alpha]);
    let mut failed_peer = Peer::new(23, 1);
    let initiation = failed_peer
        .tunnel
        .format_handshake_initiation(false)
        .unwrap()
        .into_bytes();
    failed_peer
        .socket
        .send_to(initiation.as_ref(), address)
        .unwrap();
    failed_peer.no_datagram(Duration::from_millis(120));
    let mut first = Peer::new(25, 2);
    let mut second = Peer::new(26, 2);
    first.establish(address);
    second.establish(address);
    first.send(address, &packet(true, 1, 2, 64, 41));
    second.plaintext(address, &packet(true, 1, 2, 63, 41));
    let remaining = runtime.children();
    assert_eq!(remaining.len(), 3);
    assert!(
        remaining
            .iter()
            .all(|pid| children.contains(pid) && *pid != alpha)
    );
    runtime.signal(Signal::TERM);
    assert_reaped(&remaining);
    let output = runtime.finish();
    assert!(output.status.success());
    no_secrets(&output);
    assert!(output.stderr.len() < 4096);
}

#[test]
fn default_keepalive_timer_runs_for_each_peer_despite_denied_traffic_and_udp_noise() {
    let directory = populated();
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    let mut first = Peer::new(23, 1);
    let mut second = Peer::new(24, 1);
    first.establish(address);
    second.establish(address);
    // Neither authenticated packet gets a local forwarding reply: first is
    // globally denied; second spoofs first's source address. Both still arm
    // the engine's real passive-keepalive timer in the same context.
    first.send(address, &packet(false, 1, 2, 64, 51));
    std::thread::sleep(Duration::from_millis(30));
    second.send(address, &packet(true, 1, 1, 64, 52));
    let started = Instant::now();
    let noise = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut heard = [false; 2];
    let mut buffer = [0; 1313];
    while !heard.iter().all(|value| *value) {
        for _ in 0..8 {
            noise.send_to(&[0; 32], address).unwrap();
        }
        for (index, peer) in [&mut first, &mut second].into_iter().enumerate() {
            match peer.socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    assert_eq!(source, address);
                    assert_eq!(buffer[0], 4, "expected automatic encrypted keepalive");
                    let TunnResult::WriteToTunnel(cleartext) =
                        peer.receive(source, &buffer[..length])
                    else {
                        panic!("timer output must authenticate as empty keepalive");
                    };
                    assert!(cleartext.as_ref().is_empty());
                    assert!(
                        started.elapsed() >= Duration::from_secs(8),
                        "default 10s timer was shortened"
                    );
                    heard[index] = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("UDP receive: {error}"),
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(18),
            "timer or peer rotation starved"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let children = runtime.children();
    runtime.signal(Signal::TERM);
    assert_reaped(&children);
    let output = runtime.finish();
    assert!(output.status.success());
    assert!(
        output.stderr.len() < 4096,
        "invalid UDP must not generate per-packet logs"
    );
    no_secrets(&output);
}

// Only this OS-boundary case needs controlled output descriptors: ordinary
// process tests above use ManagedChild's bounded capture and cleanup.
struct LogBoundaryChild(Option<Child>);
impl LogBoundaryChild {
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
                "diagnostic backpressure blocked shutdown"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(self.0.take().unwrap().wait().unwrap().success());
    }
}
impl Drop for LogBoundaryChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = Pid::from_raw(child.id() as i32).unwrap();
            assert!(pid.as_raw_pid() > 1);
            // No method reaps before taking ownership out of the guard.
            let _ = kill_process_group(pid, Signal::KILL);
            let _ = child.wait();
        }
    }
}
fn diagnostic_pipe(full: bool) -> (OwnedFd, Option<OwnedFd>) {
    let (reader, writer) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC).unwrap();
    if full {
        loop {
            match rustix::io::write(&writer, &[0x71; 4096]) {
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN) => break,
                Err(error) => panic!("cannot prefill test pipe: {error}"),
            }
        }
        // Confirm that even the short public readiness record cannot fit.
        assert_eq!(
            rustix::io::write(&writer, b"x"),
            Err(rustix::io::Errno::AGAIN)
        );
        // The child receives an ordinary blocking output pipe. It must apply
        // its own bounded logging policy, not inherit safety from this fixture.
        let flags = fcntl_getfl(&writer).unwrap();
        fcntl_setfl(&writer, flags & !OFlags::NONBLOCK).unwrap();
        (writer, Some(reader))
    } else {
        drop(reader);
        (writer, None)
    }
}
fn establish_during_startup(peer: &mut Peer, address: SocketAddr) {
    let initiation = peer
        .tunnel
        .format_handshake_initiation(false)
        .unwrap()
        .into_bytes();
    let deadline = Instant::now() + WAIT;
    let mut next_send = Instant::now();
    let mut buffer = [0; 1313];
    loop {
        if Instant::now() >= next_send {
            peer.socket.send_to(initiation.as_ref(), address).unwrap();
            next_send = Instant::now() + Duration::from_millis(200);
        }
        match peer.socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                assert_eq!(source, address);
                let TunnResult::WriteToNetwork(confirmation) =
                    peer.receive(source, &buffer[..length])
                else {
                    panic!("startup did not produce an authenticated response");
                };
                let confirmation: Packet = confirmation.into();
                peer.socket.send_to(confirmation.as_ref(), address).unwrap();
                std::thread::sleep(Duration::from_millis(20));
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("startup UDP read: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "unread diagnostics blocked gateway startup"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn full_or_closed_log_pipes_do_not_block_forwarding_worker_failure_or_shutdown() {
    for full in [true, false] {
        let directory = populated();
        // No readiness record can be consumed in this case; explicitly request
        // a freshly selected local port instead of adding product test controls.
        let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let (stdout, _stdout_reader) = diagnostic_pipe(full);
        let (stderr, _stderr_reader) = diagnostic_pipe(full);
        let child = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .args(["serve", "--control", "child", "--state-dir"])
            .arg(directory.state())
            .args(["--listen", &address.to_string()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0)
            .spawn()
            .unwrap();
        let child = LogBoundaryChild(Some(child));
        let mut first = Peer::new(25, 2);
        let mut second = Peer::new(26, 2);
        establish_during_startup(&mut first, address);
        second.establish(address);
        let pid = child.pid().as_raw_pid();
        let children: Vec<u32> = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect();
        assert_eq!(children.len(), 4);
        let alpha = children
            .iter()
            .copied()
            .find(|pid| {
                fs::read(format!("/proc/{pid}/cmdline"))
                    .unwrap()
                    .split(|byte| *byte == 0)
                    .any(|arg| arg == b"tenant:alpha")
            })
            .unwrap();
        kill_process(Pid::from_raw(alpha as i32).unwrap(), Signal::KILL).unwrap();
        assert_reaped(&[alpha]);
        first.send(address, &packet(false, 1, 2, 64, 61));
        second.plaintext(address, &packet(false, 1, 2, 63, 61));
        kill_process(child.pid(), Signal::TERM).unwrap();
        assert_reaped(&children);
        // This wait observes normal exit; the guard's group kill is fallback
        // only and cannot make the success assertion pass.
        child.finish();
        assert!(Store::open(&directory.state()).is_ok());
        assert!(UdpSocket::bind(address).is_ok());
    }
}
