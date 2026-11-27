use super::*;
use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
    x25519::{PublicKey, StaticSecret},
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, atomic::AtomicBool},
    thread::{self, JoinHandle},
    time::Instant,
};

#[path = "enrollment_acceptance.rs"]
mod enrollment_acceptance;

// The test owns only UDP sockets and child processes. Each advertised address
// is a controllable link: no host firewall, interface or route is modified.
struct Links {
    connected: Arc<Mutex<Vec<Vec<bool>>>>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Links {
    fn start(actual: Vec<SocketAddr>) -> (Self, Vec<SocketAddr>) {
        let mut sockets = Vec::new();
        let mut advertised = Vec::new();
        for _ in &actual {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            advertised.push(socket.local_addr().unwrap());
            sockets.push(socket);
        }
        let connected = Arc::new(Mutex::new(vec![vec![true; actual.len()]; actual.len()]));
        let topology = Arc::clone(&connected);
        let done = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&done);
        let thread = thread::spawn(move || {
            let mut external: Vec<(usize, SocketAddr, UdpSocket)> = vec![];
            let mut buffer = [0; 1500];
            while !shutdown.load(Ordering::Relaxed) {
                for (to, socket) in sockets.iter().enumerate() {
                    for _ in 0..64 {
                        let (len, source) = match socket.recv_from(&mut buffer) {
                            Ok(value) => value,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => panic!("link read: {error}"),
                        };
                        if let Some(from) = actual.iter().position(|address| *address == source) {
                            if !topology.lock().unwrap()[from][to] {
                                continue;
                            }
                            sockets[from].send_to(&buffer[..len], actual[to]).unwrap();
                        } else {
                            let index = external
                                .iter()
                                .position(|(target, peer, _)| *target == to && *peer == source)
                                .unwrap_or_else(|| {
                                    assert!(external.len() < 128);
                                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                                    socket.set_nonblocking(true).unwrap();
                                    external.push((to, source, socket));
                                    external.len() - 1
                                });
                            external[index]
                                .2
                                .send_to(&buffer[..len], actual[to])
                                .unwrap();
                        }
                    }
                }
                for (target, peer, bridge) in &external {
                    while let Ok((len, source)) = bridge.recv_from(&mut buffer) {
                        assert_eq!(source, actual[*target]);
                        sockets[*target].send_to(&buffer[..len], peer).unwrap();
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        (
            Self {
                connected,
                done,
                thread: Some(thread),
            },
            advertised,
        )
    }
    fn connect_only(&self, links: &[(usize, usize)]) {
        let mut connected = self.connected.lock().unwrap();
        for neighbors in connected.iter_mut() {
            neighbors.fill(false);
        }
        for &(from, to) in links {
            connected[from][to] = true;
            connected[to][from] = true;
        }
    }
}
impl Drop for Links {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

struct Client {
    socket: UdpSocket,
    tunnel: Tunn,
    limiter: Arc<RateLimiter>,
    endpoint: SocketAddr,
    address: Ipv4Addr,
}
impl Client {
    fn from_config(bytes: &[u8]) -> Self {
        let config = std::str::from_utf8(bytes).unwrap();
        let get = |name: &str| {
            config
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name} = ")))
                .unwrap()
        };
        assert_eq!(get("MTU"), "1280");
        let key: [u8; 32] = STANDARD
            .decode(get("PrivateKey"))
            .unwrap()
            .try_into()
            .unwrap();
        let public: [u8; 32] = STANDARD
            .decode(get("PublicKey"))
            .unwrap()
            .try_into()
            .unwrap();
        let secret = StaticSecret::from(key);
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&secret), 100));
        let tunnel = Tunn::new(
            secret,
            PublicKey::from(public),
            None,
            None,
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        Self {
            socket,
            tunnel,
            limiter,
            endpoint: get("Endpoint").parse().unwrap(),
            address: get("Address").split('/').next().unwrap().parse().unwrap(),
        }
    }
    fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut output = vec![];
        let mut bytes = [0; 1313];
        self.limiter.try_reset_count();
        while let Ok((len, from)) = self.socket.recv_from(&mut bytes) {
            assert_eq!(from, self.endpoint);
            if let Ok(packet) = self
                .limiter
                .verify_packet(from, Packet::copy_from(&bytes[..len]))
            {
                match self.tunnel.handle_incoming_packet(packet) {
                    TunnResult::WriteToNetwork(packet) => {
                        let packet: Packet = packet.into();
                        self.socket.send_to(packet.as_ref(), self.endpoint).unwrap();
                    }
                    TunnResult::WriteToTunnel(packet) if !packet.as_ref().is_empty() => {
                        output.push(packet.as_ref().to_vec());
                    }
                    _ => (),
                }
            }
        }
        output
    }
    fn establish(&mut self) {
        let until = Instant::now() + WAIT;
        loop {
            if let Some(packet) = self.tunnel.format_handshake_initiation(false) {
                self.socket
                    .send_to(packet.into_bytes().as_ref(), self.endpoint)
                    .unwrap();
            }
            self.poll();
            if self
                .tunnel
                .encapsulate_with_session(Packet::copy_from(&[]))
                .is_ok()
            {
                thread::sleep(Duration::from_millis(30));
                return;
            }
            assert!(
                Instant::now() < until,
                "native-format client did not connect"
            );
            thread::sleep(Duration::from_millis(30));
        }
    }
    fn send(&mut self, packet: &[u8]) {
        let wire = self
            .tunnel
            .encapsulate_with_session(Packet::copy_from(packet))
            .unwrap()
            .into_bytes();
        self.socket.send_to(wire.as_ref(), self.endpoint).unwrap();
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|part| u32::from(u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(from: Ipv4Addr, to: Ipv4Addr, marker: u8) -> Vec<u8> {
    let mut packet = vec![marker; 1280];
    packet[..28].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&1280u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&from.octets());
    packet[16..20].copy_from_slice(&to.octets());
    let check = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&check.to_be_bytes());
    packet[20..24].copy_from_slice(&[0x12, 0x34, 0x12, 0x35]);
    packet[24..26].copy_from_slice(&1260u16.to_be_bytes());
    packet
}
fn exchange(clients: &mut [Client], source: usize, target: usize, marker: u8) {
    exchange_with_limits(clients, source, target, marker, 2, Duration::from_secs(25));
}
fn exchange_with_limits(
    clients: &mut [Client],
    source: usize,
    target: usize,
    marker: u8,
    hops: u8,
    timeout: Duration,
) {
    let bytes = packet(clients[source].address, clients[target].address, marker);
    let mut expected = bytes.clone();
    expected[8] = 64 - hops;
    expected[10..12].fill(0);
    let check = checksum(&expected[..20]);
    expected[10..12].copy_from_slice(&check.to_be_bytes());
    let until = Instant::now() + timeout;
    let mut next = Instant::now();
    loop {
        if Instant::now() >= next {
            clients[source].send(&bytes);
            next = Instant::now() + Duration::from_millis(150);
        }
        let mut delivered = false;
        for (index, client) in clients.iter_mut().enumerate() {
            for received in client.poll() {
                assert_eq!(index, target, "packet leaked into another user's network");
                assert_eq!(received, expected, "full MTU packet or source was altered");
                delivered = true;
            }
        }
        if delivered {
            return;
        }
        assert!(
            Instant::now() < until,
            "mesh did not deliver marker {marker}"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn no_plaintext(clients: &mut [Client]) {
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        for client in clients.iter_mut() {
            assert!(client.poll().is_empty(), "unauthorized plaintext escaped");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn ids(fixture: &Fixture, username: &str, name: &str) -> (String, String) {
    let users = api::json(&fixture.state(), "GET", "/api/v1/users", Value::Null);
    let user = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["name"] == username)
        .unwrap();
    let device = user["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["metadata"]["name"] == name)
        .unwrap();
    (
        user["id"].as_str().unwrap().to_owned(),
        device["id"].as_str().unwrap().to_owned(),
    )
}
fn exported(fixture: &Fixture, user: &str, device: &str) -> Vec<u8> {
    let (user, device) = ids(fixture, user, device);
    let response = api::get(
        &fixture.state(),
        &format!("/api/v1/users/{user}/devices/{device}/config"),
    );
    assert_eq!(response.status, 200);
    response.body.clone()
}
fn applied(fixture: &Fixture, generation: u64, children: &mut Vec<ManagedChild>) {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let status = api::json(&fixture.state(), "GET", "/api/v1/distribution", Value::Null);
        if status["generation"] == generation
            && status["gateways"]
                .as_array()
                .unwrap()
                .iter()
                .all(|node| node["status"] == "applied")
        {
            return;
        }
        if Instant::now() >= until {
            let durable: Vec<_> = ["one", "two", "three"]
                .iter()
                .map(|id| {
                    let disk: Value = serde_json::from_slice(
                        &fs::read(fixture.0.join(id).join("state.json")).unwrap(),
                    )
                    .unwrap();
                    (*id, disk["projection"]["config"]["generation"].clone())
                })
                .collect();
            for child in children.drain(..) {
                let output = child.terminate().unwrap();
                eprintln!(
                    "Node diagnostics: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            panic!("mesh configuration was not applied: {status}; durable revisions: {durable:?}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn main_entry_applies_its_own_configuration_and_serves_native_clients_on_its_udp_port() {
    main_entry(false);
}

#[test]
#[ignore = "release timing of one administrative request alongside established WireGuard traffic"]
fn forwarding_latency_during_bearer_verification() {
    main_entry(true);
}

fn main_entry(measure_auth: bool) {
    let fixture = Fixture::new();
    let reserve = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = reserve.local_addr().unwrap();
    let initialized = spawn(vec![
        "init".into(),
        "--control".into(),
        "main".into(),
        "--state-dir".into(),
        fixture.state().into(),
        "--profile".into(),
        fixture.profile().into(),
        "--id".into(),
        "management".into(),
        "--listen".into(),
        endpoint.to_string().into(),
        "--endpoint".into(),
        endpoint.to_string().into(),
        "--traffic".into(),
        "entry".into(),
    ])
    .wait(WAIT)
    .unwrap();
    assert!(initialized.status.success());
    drop(reserve);
    let mut server = fixture.start(1);
    let user = api::json(
        &fixture.state(),
        "POST",
        "/api/v1/users",
        serde_json::json!({"name":"alice"}),
    );
    let user = user["id"].as_str().unwrap();
    for name in ["phone", "laptop"] {
        api::json(
            &fixture.state(),
            "POST",
            &format!("/api/v1/users/{user}/devices"),
            serde_json::json!({"name":name}),
        );
    }
    let wait_for_main = |generation: u64| {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let status = api::json(&fixture.state(), "GET", "/api/v1/distribution", Value::Null);
            let nodes = status["gateways"].as_array().unwrap();
            assert_eq!(nodes.len(), 1);
            if status["generation"] == generation && nodes[0]["status"] == "applied" {
                break;
            }
            assert!(
                Instant::now() < until,
                "main did not apply its local forwarding revision"
            );
            thread::sleep(Duration::from_millis(50));
        }
    };
    wait_for_main(4);
    let phone = exported(&fixture, "alice", "phone");
    let laptop = exported(&fixture, "alice", "laptop");
    let mut clients = [Client::from_config(&phone), Client::from_config(&laptop)];
    assert!(clients.iter().all(|client| client.endpoint == endpoint));
    for client in &mut clients {
        client.establish();
    }
    exchange_with_limits(&mut clients, 0, 1, 71, 1, Duration::from_secs(5));
    exchange_with_limits(&mut clients, 1, 0, 72, 1, Duration::from_secs(5));
    if measure_auth {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let token = format!("Bearer {}", STANDARD.encode([9; 32]));
        for (index, header) in ["Bearer invalid", token.as_str()]
            .iter()
            .cycle()
            .take(6)
            .enumerate()
        {
            let mut stream = UnixStream::connect(fixture.state().join("api.sock")).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            let request = wgfeel_protocol::http::encode_request(wgfeel_protocol::Request {
                method: "GET",
                target: "/api/v1/users",
                authorization: Some(header),
                if_match: None,
                body: b"",
            })
            .unwrap();
            stream.write_all(&request).unwrap();
            thread::sleep(Duration::from_millis(2));
            let begin = Instant::now();
            exchange_with_limits(&mut clients, 0, 1, 80 + index as u8, 1, WAIT);
            let micros = begin.elapsed().as_micros();
            let mut bytes = vec![];
            stream.read_to_end(&mut bytes).unwrap();
            assert_eq!(
                wgfeel_protocol::http::decode_response(&bytes)
                    .unwrap()
                    .unwrap()
                    .status,
                401
            );
            eprintln!(
                "valid_bearer_encoding={} forwarding_us={micros}",
                index % 2 == 1
            );
        }
    }
    let bob = api::json(
        &fixture.state(),
        "POST",
        "/api/v1/users",
        serde_json::json!({"name":"bob"}),
    );
    let bob = bob["id"].as_str().unwrap();
    api::json(
        &fixture.state(),
        "POST",
        &format!("/api/v1/users/{bob}/devices"),
        serde_json::json!({"name":"desk"}),
    );
    wait_for_main(6);
    exchange_with_limits(&mut clients, 0, 1, 74, 1, Duration::from_secs(5));
    server.terminate().unwrap();
    server = fixture.start(6);
    for client in &mut clients {
        client.establish();
    }
    exchange_with_limits(&mut clients, 0, 1, 73, 1, Duration::from_secs(5));
    server.terminate().unwrap();
}

#[test]
fn three_gateways_two_private_lans_export_restart_relay_and_recover_without_management() {
    scenario(false);
}
#[test]
#[ignore = "real 105-second mesh outage and WireGuard handshake retry exhaustion"]
fn mesh_reconnects_after_long_outage_without_management() {
    scenario(true);
}
fn scenario(long_outage: bool) {
    let fixture = Fixture::new();
    fixture.initialize();
    let mut actual = vec![];
    let mut nodes = vec![];
    for id in ["one", "two", "three"] {
        let (child, listen) = fixture.start_child(id);
        actual.push(listen);
        nodes.push(child);
    }
    let (links, advertised) = Links::start(actual.clone());
    let management = fixture.start(1);
    for (id, endpoint) in ["one", "two", "three"].into_iter().zip(&advertised) {
        fixture.join_child(id, *endpoint);
    }
    for name in ["alice", "bob"] {
        let user = api::json(
            &fixture.state(),
            "POST",
            "/api/v1/users",
            serde_json::json!({"name":name}),
        );
        let user = user["id"].as_str().unwrap();
        for (name, gateway) in [("phone", "one"), ("laptop", "three")] {
            api::json(
                &fixture.state(),
                "POST",
                &format!("/api/v1/users/{user}/devices"),
                serde_json::json!({"name":name,"gateway":gateway}),
            );
        }
    }
    applied(&fixture, 10, &mut nodes);
    let configs: Vec<_> = [
        ("alice", "phone"),
        ("alice", "laptop"),
        ("bob", "phone"),
        ("bob", "laptop"),
    ]
    .into_iter()
    .map(|(user, device)| exported(&fixture, user, device))
    .collect();
    let mut clients: Vec<_> = configs
        .iter()
        .map(|bytes| Client::from_config(bytes))
        .collect();
    if !long_outage {
        let (_, device) = ids(&fixture, "alice", "phone");
        let screen = fixture.remote(&["device", "show", &device], "", true);
        assert!(screen.contains(std::str::from_utf8(&configs[0]).unwrap()));
    }
    assert_eq!(clients[0].address, clients[2].address);
    assert_eq!(clients[1].address, clients[3].address);
    for client in &mut clients {
        client.establish();
    }
    exchange(&mut clients, 0, 1, 11);
    exchange(&mut clients, 3, 2, 12);
    let spoofed = packet("10.203.0.99".parse().unwrap(), clients[1].address, 19);
    clients[0].send(&spoofed);
    no_plaintext(&mut clients);
    let (alice, phone) = ids(&fixture, "alice", "phone");
    api::json(
        &fixture.state(),
        "POST",
        &format!("/api/v1/users/{alice}/suspend"),
        serde_json::json!({}),
    );
    applied(&fixture, 11, &mut nodes);
    let suspended_packet = packet(clients[0].address, clients[1].address, 20);
    clients[0].send(&suspended_packet);
    no_plaintext(&mut clients);
    exchange(&mut clients, 3, 2, 26);
    api::json(
        &fixture.state(),
        "POST",
        &format!("/api/v1/users/{alice}/resume"),
        serde_json::json!({}),
    );
    applied(&fixture, 12, &mut nodes);
    exchange(&mut clients, 0, 1, 27);
    stop(management);
    links.connect_only(&[(0, 1), (1, 2)]);
    thread::sleep(Duration::from_secs(5));
    exchange(&mut clients, 0, 1, 21);
    exchange(&mut clients, 3, 2, 22);
    if long_outage {
        links.connect_only(&[]);
        let until = Instant::now() + Duration::from_secs(105);
        while Instant::now() < until {
            for client in &mut clients {
                assert!(client.poll().is_empty());
            }
            thread::sleep(Duration::from_millis(20));
        }
        links.connect_only(&[(0, 1), (1, 2)]);
        exchange(&mut clients, 0, 1, 24);
        exchange(&mut clients, 3, 2, 25);
    }
    // Force a fresh native handshake while the authority and direct link are absent.
    clients[0] = Client::from_config(&configs[0]);
    clients[0].establish();
    exchange(&mut clients, 0, 1, 23);
    links.connect_only(&[(0, 1), (1, 2), (0, 2)]);
    thread::sleep(Duration::from_secs(5));
    links.connect_only(&[(0, 2)]);
    exchange(&mut clients, 0, 1, 31);
    exchange(&mut clients, 3, 2, 32);
    // Restart every process from its files. Exported keys and addresses survive.
    for child in nodes.drain(..) {
        stop(child);
    }
    for (index, id) in ["one", "two", "three"].iter().enumerate() {
        let mut child = spawn(vec![
            "serve".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            fixture.0.join(id).into_os_string(),
            "--listen".into(),
            actual[index].to_string().into(),
        ]);
        let ready: Value = serde_json::from_slice(&child.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["generation"], 12);
        nodes.push(child);
    }
    clients = configs
        .iter()
        .map(|bytes| Client::from_config(bytes))
        .collect();
    for client in &mut clients {
        client.establish();
    }
    exchange(&mut clients, 0, 1, 41);
    exchange(&mut clients, 3, 2, 42);
    links.connect_only(&[(0, 1), (1, 2), (0, 2)]);
    let management = fixture.start(12);
    assert_eq!(exported(&fixture, "alice", "phone"), configs[0]);
    api::json(
        &fixture.state(),
        "DELETE",
        &format!("/api/v1/users/{alice}/devices/{phone}"),
        Value::Null,
    );
    applied(&fixture, 13, &mut nodes);
    let revoked = packet(clients[0].address, clients[1].address, 49);
    clients[0].send(&revoked);
    no_plaintext(&mut clients);
    api::json(
        &fixture.state(),
        "DELETE",
        &format!("/api/v1/users/{alice}"),
        Value::Null,
    );
    applied(&fixture, 14, &mut nodes);
    // Revocation must not disable another user with the same addresses.
    clients = configs[2..]
        .iter()
        .map(|bytes| Client::from_config(bytes))
        .collect();
    for client in &mut clients {
        client.establish();
    }
    exchange(&mut clients, 0, 1, 51);
    stop(management);
    for child in nodes {
        stop(child);
    }
}
