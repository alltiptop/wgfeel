//! Opt-in interoperability: five Linux kernel peers, IPv4/IPv6 and forced cookies.
//! Exercises in-process Gateway + UdpTransport, not the foreground service or mesh.
//! Requires approved disposable user/network namespaces, an already-loaded WG
//! module, ip/unshare/nsenter, and a reviewed wg utility (reference: 1.0.20260223).
//! Build only wg with RUNSTATEDIR=/dev/null to avoid host userspace sockets;
//! set WIREGUARD_TOOLS_VERSION explicitly to suppress its Makefile's Git probe.
//! Never fall back to host networking. Select only the parent entry, not all ignored tests:
//! ```text
//! WGFEEL_NATIVE_APPROVED=1 WGFEEL_NATIVE_WG=/absolute/reviewed/wg \
//! cargo test --offline --locked -p wgfeel-wireguard --test native_wireguard \
//! kernel_wireguard_one_port_acceptance -- --ignored --exact --nocapture --test-threads=1
//! ```

use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gotatun::x25519::{PublicKey, StaticSecret};
use wgfeel_core::{
    DeviceId, DevicePublicKey, NetworkId, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};
use wgfeel_wireguard::{
    ContextConfig, ContextId, Gateway, Limits, PeerConfig, PeerId, UdpEvent, UdpTransport,
};

const APPROVAL: &str = "WGFEEL_NATIVE_APPROVED";
const TOOL: &str = "WGFEEL_NATIVE_WG";
const ROOT: &str = "WGFEEL_NATIVE_ROOT";
const HOST_NS: &str = "WGFEEL_NATIVE_HOST_NS";
const OUTER_NS: &str = "WGFEEL_NATIVE_OUTER_NS";
const MODE: &str = "WGFEEL_NATIVE_MODE";
const INDEX: &str = "WGFEEL_NATIVE_INDEX";
const ROLE: &str = "WGFEEL_NATIVE_ROLE";
const EXPECTED_NS: &str = "WGFEEL_NATIVE_EXPECTED_NS";
const USER_NS: &str = "WGFEEL_NATIVE_USER_NS";
const OPERATION: &str = "WGFEEL_NATIVE_OPERATION";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);
const HELPER_TIMEOUT: Duration = Duration::from_secs(150);
const PAUSE: Duration = Duration::from_millis(2);
const PEERS: usize = 5;
const CLIENT_PORT: u16 = 31000;
const GATEWAY_PORT: u16 = 31001;
const CLIENT_V4: [u8; 4] = [10, 222, 0, 2];
const GATEWAY_V4: [u8; 4] = [10, 222, 0, 1];
const CLIENT_V6: [u8; 16] = [0xfd, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const GATEWAY_V6: [u8; 16] = [0xfd, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn create() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("wgfeel-native-{}-{suffix}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        // This directory was created exclusively above and contains fixture material only.
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Guard {
    namespace: PathBuf,
    host: PathBuf,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl Guard {
    fn helper(role: &str) -> Self {
        assert_eq!(
            std::env::var(APPROVAL).as_deref(),
            Ok("1"),
            "native opt-in missing"
        );
        assert_eq!(
            std::env::var(ROLE).as_deref(),
            Ok(role),
            "wrong helper role"
        );
        let host = PathBuf::from(required(HOST_NS));
        let namespace = net_namespace(std::process::id());
        assert_ne!(
            namespace, host,
            "refusing to operate in launcher's network namespace"
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let watch = Arc::clone(&cancelled);
        std::thread::spawn(move || {
            let mut byte = [0];
            loop {
                match io::stdin().read(&mut byte) {
                    Ok(0) | Err(_) => {
                        watch.store(true, Ordering::Release);
                        break;
                    }
                    Ok(_) => {}
                }
            }
        });
        Self {
            namespace,
            host,
            cancelled,
            deadline: Instant::now() + HELPER_TIMEOUT,
        }
    }

    fn check(&self) {
        assert!(
            !self.cancelled.load(Ordering::Acquire),
            "native supervisor disconnected"
        );
        assert!(
            Instant::now() < self.deadline,
            "native helper deadline exceeded"
        );
        assert_eq!(
            net_namespace(std::process::id()),
            self.namespace,
            "namespace changed"
        );
        assert_ne!(
            self.namespace, self.host,
            "host network namespace forbidden"
        );
    }
}

fn required(name: &str) -> OsString {
    std::env::var_os(name).expect("required native fixture setting missing")
}

fn net_namespace(pid: u32) -> PathBuf {
    fs::read_link(format!("/proc/{pid}/ns/net")).expect("cannot inspect network namespace")
}

fn limits() -> ProcessLimits {
    ProcessLimits {
        max_stdout_bytes: 16 * 1024,
        max_stderr_bytes: 16 * 1024,
    }
}

fn environment() -> Vec<(OsString, OsString)> {
    vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LC_ALL".into(), "C".into()),
    ]
}

fn helper_arguments(name: &str) -> Vec<OsString> {
    vec![
        "--ignored".into(),
        "--exact".into(),
        name.into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ]
}

fn spawn_namespace(
    helper: &str,
    user_namespace: bool,
    environment: Vec<(OsString, OsString)>,
) -> ManagedChild {
    let mut arguments: Vec<OsString> = Vec::new();
    if user_namespace {
        arguments.extend(["--user".into(), "--map-root-user".into()]);
    }
    arguments.extend([
        "--net".into(),
        "--".into(),
        std::env::current_exe().unwrap().into(),
    ]);
    arguments.extend(helper_arguments(helper));
    ManagedChild::spawn(
        ProcessSpec::new("/usr/bin/unshare".into(), arguments, environment, None),
        limits(),
    )
    .expect("cannot launch native namespace helper")
}

fn run(guard: &Guard, executable: &Path, arguments: &[OsString]) {
    // Every ip/wg invocation, including read-only calls, crosses this guard.
    guard.check();
    let child = ManagedChild::spawn(
        ProcessSpec::new(
            executable.to_path_buf(),
            arguments.to_vec(),
            environment(),
            None,
        ),
        limits(),
    )
    .expect("native utility launch failed");
    let output = child
        .wait(COMMAND_TIMEOUT)
        .expect("native utility did not finish within bounds");
    assert!(
        output.status.success(),
        "native utility rejected fixture configuration"
    );
    guard.check();
}

fn ip(guard: &Guard, arguments: &[&str]) {
    run(
        guard,
        Path::new("/usr/bin/ip"),
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
    );
}

fn marker(value: &str) {
    // libtest may have written its test label without a newline first.
    println!("\n{value}");
    io::stdout().flush().unwrap();
}

fn last_phase(stdout: &[u8]) -> &'static str {
    let complete = stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(&[][..], |end| &stdout[..end]);
    complete
        .split(|byte| *byte == b'\n')
        .rev()
        .find_map(|line| match line {
            b"namespace-entered" => Some("namespace-entered"),
            b"peers-configured" => Some("peers-configured"),
            b"gateway-handshakes-established" => Some("gateway-handshakes-established"),
            b"ipv4-pass" => Some("ipv4-pass"),
            b"ipv6-pass" => Some("ipv6-pass"),
            b"native-pass" => Some("native-pass"),
            _ => None,
        })
        .unwrap_or("before-namespace-entry")
}

fn checked_root() -> PathBuf {
    let root = PathBuf::from(required(ROOT));
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(root.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), fs::metadata("/proc/self").unwrap().uid());
    root
}

fn protected_file(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
}

fn barrier(root: &Path, index: usize, stage: &str) -> PathBuf {
    root.join(format!("peer-{index}-{stage}"))
}

fn release(root: &Path, index: usize, stage: &str) {
    protected_file(&barrier(root, index, stage), b"ready\n");
}

fn wait_barrier(guard: &Guard, root: &Path, index: usize, stage: &str) {
    let path = barrier(root, index, stage);
    loop {
        guard.check();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                assert_eq!(fs::read(&path).unwrap(), b"ready\n");
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => std::thread::sleep(PAUSE),
            Err(_) => panic!("cannot inspect native fixture barrier"),
        }
    }
}

fn validate_wg(path: &Path) {
    assert!(path.is_absolute(), "native wg path must be absolute");
    let metadata = fs::symlink_metadata(path).expect("reviewed native wg utility missing");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() > 0 && metadata.len() <= 16 * 1024 * 1024);
    assert_eq!(
        metadata.permissions().mode() & 0o022,
        0,
        "wg utility must not be group/world writable"
    );
    let binary = fs::read(path).unwrap();
    let contains = |pattern: &[u8]| binary.windows(pattern.len()).any(|part| part == pattern);
    assert!(
        contains(b"/dev/null/wireguard/"),
        "wg runtime path override missing"
    );
    assert!(
        !contains(b"/var/run/wireguard/"),
        "wg host runtime path is forbidden"
    );
}

fn secret(number: u8) -> [u8; 32] {
    [number; 32] // Deliberately public, disposable test identities; never product credentials.
}

fn public(number: u8) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret(number))).to_bytes()
}

fn context(index: usize) -> ContextId {
    match index {
        0 | 1 => ContextId::Tenant(NetworkId::new("native-alice").unwrap()),
        2 | 3 => ContextId::Tenant(NetworkId::new("native-bob").unwrap()),
        4 => ContextId::Service,
        _ => panic!("fixture peer out of range"),
    }
}

fn identity(index: usize) -> PeerId {
    match index {
        0 | 2 => PeerId::Device(DeviceId::new("first").unwrap()),
        1 | 3 => PeerId::Device(DeviceId::new("second").unwrap()),
        4 => PeerId::Node(NodeId::new("native-node").unwrap()),
        _ => panic!("fixture peer out of range"),
    }
}

fn server_key(index: usize) -> u8 {
    (index / 2 + 1) as u8
}
fn peer_key(index: usize) -> u8 {
    11 + index as u8
}
fn outer_port(index: usize) -> u16 {
    41000 + index as u16
}

fn gateway(cookie: bool) -> Gateway {
    let peers = |range: std::ops::Range<usize>| {
        range
            .map(|index| PeerConfig {
                id: identity(index),
                public_key: DevicePublicKey::new(public(peer_key(index))).unwrap(),
            })
            .collect()
    };
    Gateway::new(
        vec![
            ContextConfig::tenant(
                NetworkId::new("native-alice").unwrap(),
                TenantPrivateKey::new(secret(1)).unwrap(),
                peers(0..2),
            ),
            ContextConfig::tenant(
                NetworkId::new("native-bob").unwrap(),
                TenantPrivateKey::new(secret(2)).unwrap(),
                peers(2..4),
            ),
            ContextConfig::service(ServicePrivateKey::new(secret(3)).unwrap(), peers(4..5)),
        ],
        Limits {
            handshake_limit_per_ip: if cookie { 0 } else { 100 },
        },
    )
    .unwrap()
}

// Fixed-size fixture serialization, not a product key-export implementation.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for part in bytes.chunks(3) {
        let value = (u32::from(part[0]) << 16)
            | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
            | u32::from(*part.get(2).unwrap_or(&0));
        result.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        result.push(if part.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if part.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

fn configure_peer(
    guard: &Guard,
    root: &Path,
    wg: &Path,
    index: usize,
    gateway_port: u16,
    pid: u32,
) {
    let name = format!("wgn{index}");
    let config = root.join(format!("peer-{index}.conf"));
    let contents = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.222.0.1/32, fd22::1/128\nEndpoint = 127.0.0.1:{}\n",
        base64(&secret(peer_key(index))),
        outer_port(index),
        base64(&public(server_key(index))),
        gateway_port,
    );
    protected_file(&config, contents.as_bytes());
    assert!(
        fs::read_to_string("/proc/modules")
            .unwrap()
            .lines()
            .any(|line| line.split_whitespace().next() == Some("wireguard")),
        "WireGuard must already be loaded; module loading is outside this fixture"
    );
    ip(guard, &["link", "add", "dev", &name, "type", "wireguard"]);
    run(
        guard,
        wg,
        &["setconf".into(), name.clone().into(), config.into()],
    );
    // Bind the owned ready child to its announced namespace; never adopt an external PID.
    let child_ns = net_namespace(pid);
    let announced_ns = PathBuf::from(
        String::from_utf8(fs::read(root.join(format!("peer-{index}-namespace"))).unwrap()).unwrap(),
    );
    assert_eq!(child_ns, announced_ns, "peer namespace identity changed");
    assert_eq!(
        fs::read_link(format!("/proc/{pid}/ns/user")).unwrap(),
        fs::read_link("/proc/self/ns/user").unwrap(),
        "peer must remain in the fixture's user namespace"
    );
    assert_ne!(child_ns, guard.namespace);
    assert_ne!(child_ns, guard.host);
    ip(
        guard,
        &["link", "set", "dev", &name, "netns", &pid.to_string()],
    );
    for operation in 0..6 {
        run_peer_configuration(guard, index, pid, &child_ns, operation);
    }
    release(root, index, "configured");
}

fn interface_arguments(index: usize, operation: usize) -> Vec<OsString> {
    assert!(index < PEERS);
    let name = format!("wgn{index}");
    let arguments = match operation {
        0 => vec!["link", "set", "dev", "lo", "up"],
        1 => vec!["address", "add", "10.222.0.2/32", "dev", &name],
        2 => vec!["-6", "address", "add", "fd22::2/128", "dev", &name, "nodad"],
        3 => vec!["link", "set", "dev", &name, "mtu", "1280", "up"],
        4 => vec!["route", "add", "10.222.0.1/32", "dev", &name],
        5 => vec!["-6", "route", "add", "fd22::1/128", "dev", &name],
        _ => panic!("unknown native interface operation"),
    };
    arguments.into_iter().map(OsString::from).collect()
}

fn run_peer_configuration(
    guard: &Guard,
    index: usize,
    pid: u32,
    expected: &Path,
    operation: usize,
) {
    guard.check();
    assert_eq!(
        net_namespace(pid),
        expected,
        "peer disappeared or changed namespace"
    );
    let user_ns = fs::read_link("/proc/self/ns/user").unwrap();
    assert_eq!(
        fs::read_link(format!("/proc/{pid}/ns/user")).unwrap(),
        user_ns
    );
    let mut env = environment();
    env.extend([
        (APPROVAL.into(), "1".into()),
        (ROLE.into(), "interface".into()),
        (HOST_NS.into(), guard.host.clone().into()),
        (EXPECTED_NS.into(), expected.as_os_str().to_owned()),
        (USER_NS.into(), user_ns.into()),
        (INDEX.into(), index.to_string().into()),
        (OPERATION.into(), operation.to_string().into()),
    ]);
    let mut arguments = vec![
        "--no-fork".into(),
        format!("--net=/proc/{pid}/ns/net").into(),
        "--".into(),
        std::env::current_exe().unwrap().into(),
    ];
    arguments.extend(helper_arguments("native_interface_helper"));
    let child = ManagedChild::spawn(
        ProcessSpec::new("/usr/bin/nsenter".into(), arguments, env, None),
        limits(),
    )
    .expect("cannot launch peer namespace configuration");
    let output = child
        .wait(COMMAND_TIMEOUT)
        .expect("peer namespace configuration timed out");
    assert!(
        output.status.success(),
        "peer namespace configuration failed"
    );
    guard.check();
}

#[test]
#[ignore = "private leaf helper; verifies namespace then replaces itself with a fixed ip operation"]
fn native_interface_helper() {
    let guard = Guard::helper("interface");
    assert_eq!(guard.namespace, PathBuf::from(required(EXPECTED_NS)));
    assert_eq!(
        fs::read_link("/proc/self/ns/user").unwrap(),
        PathBuf::from(required(USER_NS))
    );
    let index: usize = required(INDEX).to_str().unwrap().parse().unwrap();
    let operation: usize = required(OPERATION).to_str().unwrap().parse().unwrap();
    let arguments = interface_arguments(index, operation);
    guard.check();
    // nsenter and this helper both exec: the outer ManagedChild retains the same
    // direct PID/process group throughout, with no utility grandchildren.
    let _error = Command::new("/usr/bin/ip")
        .args(arguments)
        .env_clear()
        .envs(environment())
        .exec();
    panic!("cannot replace native interface helper with ip");
}

fn tick(guard: &Guard, gateway: &mut Gateway, transport: &UdpTransport) {
    guard.check();
    for index in 0..PEERS {
        if gateway
            .endpoint(&context(index), &identity(index))
            .unwrap()
            .is_none()
        {
            continue;
        }
        if let Some(event) = gateway
            .tick_datagram(&context(index), &identity(index))
            .unwrap()
        {
            transport.transmit(event).unwrap();
        }
    }
}

fn payload(index: usize, ipv6: bool, reply: bool) -> Vec<u8> {
    format!("wgfeel-native/{index}/{}/{reply}", if ipv6 { 6 } else { 4 }).into_bytes()
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for part in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn response_packet(index: usize, ipv6: bool) -> Vec<u8> {
    let body = payload(index, ipv6, true);
    let header = if ipv6 { 40 } else { 20 };
    let mut packet = vec![0; header + 8 + body.len()];
    let length = packet.len();
    let udp_length = (8 + body.len()) as u16;
    if ipv6 {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&udp_length.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&GATEWAY_V6);
        packet[24..40].copy_from_slice(&CLIENT_V6);
    } else {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&GATEWAY_V4);
        packet[16..20].copy_from_slice(&CLIENT_V4);
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }
    packet[header..header + 2].copy_from_slice(&GATEWAY_PORT.to_be_bytes());
    packet[header + 2..header + 4].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    packet[header + 4..header + 6].copy_from_slice(&udp_length.to_be_bytes());
    packet[header + 8..].copy_from_slice(&body);
    if ipv6 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&GATEWAY_V6);
        pseudo.extend_from_slice(&CLIENT_V6);
        pseudo.extend_from_slice(&u32::from(udp_length).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&packet[header..]);
        let value = checksum(&pseudo);
        packet[header + 6..header + 8]
            .copy_from_slice(&if value == 0 { u16::MAX } else { value }.to_be_bytes());
    }
    packet
}

fn assert_request(packet: &[u8], index: usize, ipv6: bool) {
    let header = if ipv6 { 40 } else { 20 };
    assert!(packet.len() >= header + 8);
    if ipv6 {
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet[6], 17);
        assert_eq!(&packet[8..24], &CLIENT_V6);
        assert_eq!(&packet[24..40], &GATEWAY_V6);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40,
            packet.len()
        );
    } else {
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[9], 17);
        assert_eq!(&packet[12..16], &CLIENT_V4);
        assert_eq!(&packet[16..20], &GATEWAY_V4);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            packet.len()
        );
        assert_eq!(checksum(&packet[..20]), 0);
    }
    assert_eq!(&packet[header..header + 2], &CLIENT_PORT.to_be_bytes());
    assert_eq!(&packet[header + 2..header + 4], &GATEWAY_PORT.to_be_bytes());
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[header + 4], packet[header + 5]])),
        packet.len() - header
    );
    assert_eq!(&packet[header + 8..], payload(index, ipv6, false));
}

fn peer_index(owner: &ContextId, peer: &PeerId) -> usize {
    (0..PEERS)
        .find(|&index| context(index) == *owner && identity(index) == *peer)
        .expect("unexpected authenticated native peer")
}

fn establish_from_gateway(guard: &Guard, gateway: &mut Gateway, transport: &UdpTransport) {
    let mut confirmed = [false; PEERS];
    for index in 0..PEERS {
        let event = gateway
            .initiate_at(
                &context(index),
                &identity(index),
                SocketAddr::from((Ipv4Addr::LOCALHOST, outer_port(index))),
            )
            .unwrap()
            .unwrap();
        transport.transmit(event).unwrap();
    }
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    while !confirmed.iter().all(|value| *value) {
        tick(guard, gateway, transport);
        assert!(
            Instant::now() < deadline,
            "gateway-initiated native handshake timed out"
        );
        if let Some(event) = transport.poll(gateway).unwrap() {
            match event {
                UdpEvent::Sent {
                    context,
                    peer: Some(peer),
                    destination,
                } => {
                    let index = peer_index(&context, &peer);
                    assert_eq!(
                        destination,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, outer_port(index)))
                    );
                    confirmed[index] = true;
                }
                _ => panic!("unexpected event before native application traffic"),
            }
        }
        std::thread::sleep(PAUSE);
    }
}

fn exchange(
    guard: &Guard,
    root: &Path,
    gateway: &mut Gateway,
    transport: &UdpTransport,
    children: &mut [ManagedChild],
    ipv6: bool,
) -> [bool; PEERS] {
    let stage = if ipv6 { "v6" } else { "v4" };
    for index in 0..PEERS {
        release(root, index, stage);
    }
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let mut received = [false; PEERS];
    let mut challenges = [false; PEERS];
    while !received.iter().all(|value| *value) {
        tick(guard, gateway, transport);
        assert!(
            Instant::now() < deadline,
            "native plaintext exchange timed out"
        );
        if let Some(event) = transport.poll(gateway).unwrap() {
            match event {
                UdpEvent::Sent {
                    peer: None,
                    context,
                    destination,
                } => {
                    let index = (0..PEERS)
                        .find(|&index| {
                            destination
                                == SocketAddr::from((Ipv4Addr::LOCALHOST, outer_port(index)))
                        })
                        .expect("cookie sent outside fixture peer endpoints");
                    assert_eq!(context, self::context(index));
                    challenges[index] = true;
                }
                UdpEvent::Sent { .. } => {}
                UdpEvent::Plaintext {
                    context,
                    peer,
                    packet,
                } => {
                    let index = peer_index(&context, &peer);
                    assert!(!received[index], "duplicate native plaintext");
                    assert_request(packet.as_bytes(), index, ipv6);
                    let reply = gateway
                        .send_datagram(&context, &peer, &response_packet(index, ipv6))
                        .unwrap();
                    transport.transmit(reply).unwrap();
                    received[index] = true;
                }
            }
        }
        std::thread::sleep(PAUSE);
    }
    for child in children {
        child
            .wait_for_stdout_line(format!("{stage}-received").as_bytes(), COMMAND_TIMEOUT)
            .unwrap();
    }
    challenges
}

#[test]
#[ignore = "requires separate approval for reviewed wg utility and disposable user/network namespaces"]
fn kernel_wireguard_one_port_acceptance() {
    assert_eq!(
        std::env::var(APPROVAL).as_deref(),
        Ok("1"),
        "explicit native fixture opt-in missing"
    );
    let wg = PathBuf::from(required(TOOL));
    validate_wg(&wg);
    let host = net_namespace(std::process::id());
    for mode in ["gateway-initiation", "forced-cookie"] {
        let root = FixtureDir::create();
        let mut env = environment();
        env.extend([
            (APPROVAL.into(), "1".into()),
            (ROLE.into(), "outer".into()),
            (TOOL.into(), wg.clone().into()),
            (ROOT.into(), root.0.clone().into()),
            (HOST_NS.into(), host.clone().into()),
            (MODE.into(), mode.into()),
        ]);
        let child = spawn_namespace("native_outer_helper", true, env);
        let output = child
            .wait(Duration::from_secs(180))
            .unwrap_or_else(|error| {
                panic!("native case {mode}: process failure {error}; phase unavailable")
            });
        assert!(
            output.status.success(),
            "native case {mode}: {}; last phase: {}",
            output.status,
            last_phase(&output.stdout),
        );
        assert!(
            output
                .stdout
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"native-pass")
        );
        assert_eq!(net_namespace(std::process::id()), host);
    }
}

#[test]
#[ignore = "private helper; launched only by the approved native acceptance test"]
fn native_outer_helper() {
    let guard = Guard::helper("outer");
    marker("namespace-entered");
    let root = checked_root();
    let wg = PathBuf::from(required(TOOL));
    validate_wg(&wg);
    let mode = required(MODE);
    assert!(mode == "gateway-initiation" || mode == "forced-cookie");
    let cookie = mode == "forced-cookie";
    ip(&guard, &["link", "set", "dev", "lo", "up"]);
    // Fresh namespace: a disjoint fixed port cannot collide with the peer ports.
    let transport =
        UdpTransport::from_socket(UdpSocket::bind((Ipv4Addr::LOCALHOST, 51820)).unwrap()).unwrap();
    let gateway_port = transport.local_addr().unwrap().port();
    let mut gateway = gateway(cookie);
    let mut children = Vec::with_capacity(PEERS);
    for index in 0..PEERS {
        guard.check();
        let mut env = environment();
        env.extend([
            (APPROVAL.into(), "1".into()),
            (ROLE.into(), "peer".into()),
            (ROOT.into(), root.clone().into()),
            (HOST_NS.into(), guard.host.clone().into()),
            (OUTER_NS.into(), guard.namespace.clone().into()),
            (INDEX.into(), index.to_string().into()),
        ]);
        let mut child = spawn_namespace("native_peer_helper", false, env);
        child
            .wait_for_stdout_line(b"namespace-ready", COMMAND_TIMEOUT)
            .unwrap();
        configure_peer(&guard, &root, &wg, index, gateway_port, child.id());
        child
            .wait_for_stdout_line(b"peer-ready", COMMAND_TIMEOUT)
            .unwrap();
        children.push(child);
    }
    marker("peers-configured");
    if !cookie {
        establish_from_gateway(&guard, &mut gateway, &transport);
        marker("gateway-handshakes-established");
    }
    let challenges = exchange(
        &guard,
        &root,
        &mut gateway,
        &transport,
        &mut children,
        false,
    );
    if cookie {
        assert!(
            challenges.iter().all(|challenged| *challenged),
            "native peers did not all require cookies"
        );
    }
    marker("ipv4-pass");
    exchange(&guard, &root, &mut gateway, &transport, &mut children, true);
    marker("ipv6-pass");
    for index in 0..PEERS {
        release(&root, index, "stop");
    }
    for child in children {
        let output = child.wait(COMMAND_TIMEOUT).unwrap();
        assert!(output.status.success(), "native peer helper failed");
    }
    marker("native-pass");
}

fn receive_reply(guard: &Guard, socket: &UdpSocket, index: usize, ipv6: bool) {
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let mut bytes = [0; 256];
    loop {
        guard.check();
        assert!(
            Instant::now() < deadline,
            "kernel peer did not receive gateway plaintext"
        );
        match socket.recv_from(&mut bytes) {
            Ok((length, source)) => {
                let expected = if ipv6 {
                    SocketAddr::from((Ipv6Addr::from(GATEWAY_V6), GATEWAY_PORT))
                } else {
                    SocketAddr::from((Ipv4Addr::from(GATEWAY_V4), GATEWAY_PORT))
                };
                assert_eq!(source, expected);
                assert_eq!(&bytes[..length], payload(index, ipv6, true));
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(PAUSE),
            Err(_) => panic!("native UDP receive failed"),
        }
    }
}

#[test]
#[ignore = "private helper; launched only by the approved native acceptance test"]
fn native_peer_helper() {
    let guard = Guard::helper("peer");
    let root = checked_root();
    assert_ne!(
        guard.namespace,
        PathBuf::from(required(OUTER_NS)),
        "peer must have its own namespace"
    );
    let index: usize = required(INDEX).to_str().unwrap().parse().unwrap();
    assert!(index < PEERS);
    protected_file(
        &root.join(format!("peer-{index}-namespace")),
        guard.namespace.to_str().unwrap().as_bytes(),
    );
    marker("namespace-ready");
    wait_barrier(&guard, &root, index, "configured");
    let v4 = UdpSocket::bind((Ipv4Addr::from(CLIENT_V4), CLIENT_PORT)).unwrap();
    let v6 = UdpSocket::bind((Ipv6Addr::from(CLIENT_V6), CLIENT_PORT)).unwrap();
    v4.set_nonblocking(true).unwrap();
    v6.set_nonblocking(true).unwrap();
    marker("peer-ready");
    for (ipv6, socket, stage, destination) in [
        (
            false,
            &v4,
            "v4",
            SocketAddr::from((Ipv4Addr::from(GATEWAY_V4), GATEWAY_PORT)),
        ),
        (
            true,
            &v6,
            "v6",
            SocketAddr::from((Ipv6Addr::from(GATEWAY_V6), GATEWAY_PORT)),
        ),
    ] {
        wait_barrier(&guard, &root, index, stage);
        let bytes = payload(index, ipv6, false);
        assert_eq!(socket.send_to(&bytes, destination).unwrap(), bytes.len());
        receive_reply(&guard, socket, index, ipv6);
        marker(&format!("{stage}-received"));
    }
    wait_barrier(&guard, &root, index, "stop");
}

#[test]
fn fixture_encodings_match_known_vectors() {
    for (bytes, expected) in [
        (&b""[..], ""),
        (&b"f"[..], "Zg=="),
        (&b"fo"[..], "Zm8="),
        (&b"foo"[..], "Zm9v"),
        (&b"foobar"[..], "Zm9vYmFy"),
    ] {
        assert_eq!(base64(bytes), expected);
    }
    // RFC 1071 section 3's eight-byte example; independently specified checksum.
    assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
}

#[test]
fn response_fixtures_have_valid_ip_and_udp_checksums() {
    let v4 = response_packet(0, false);
    assert_eq!(checksum(&v4[..20]), 0);
    assert_eq!(&v4[26..28], &[0, 0]); // IPv4 UDP explicitly permits checksum omission.
    let v6 = response_packet(4, true);
    let mut pseudo = v6[8..40].to_vec();
    pseudo.extend_from_slice(&((v6.len() - 40) as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&v6[40..]);
    assert_eq!(checksum(&pseudo), 0);
    assert_ne!(&v6[46..48], &[0, 0]);
}

#[test]
fn diagnostic_phase_accepts_only_complete_allowlisted_markers() {
    assert_eq!(
        last_phase(b"secret-looking output\nprefix namespace-entered\n"),
        "before-namespace-entry"
    );
    assert_eq!(
        last_phase(b"namespace-entered\npeers-configured\nsecret-looking output\n"),
        "peers-configured"
    );
    assert_eq!(last_phase(b"namespace-entered\nipv4-pass\n"), "ipv4-pass");
    assert_eq!(
        last_phase(b"namespace-entered\nipv4-pass"),
        "namespace-entered"
    );
}
