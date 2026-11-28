//! Opt-in Linux acceptance workload. Run each size in its own 1 GiB cgroup.
use super::*;
use wgfeel_core::GatewayProjection;

fn key(network: u16, device: u8) -> [u8; 32] {
    let mut secret = [42; 32];
    secret[10..12].copy_from_slice(&network.to_le_bytes());
    secret[12] = device;
    secret
}

fn public_key(secret: [u8; 32]) -> DevicePublicKey {
    DevicePublicKey::new(PublicKey::from(&StaticSecret::from(secret)).to_bytes()).unwrap()
}

fn projection(count: u16, revision: u64) -> (GatewayProjection, LocalTenants) {
    let mut networks = Vec::new();
    let mut tenants = Vec::new();
    let mut secrets = Vec::new();
    for index in 0..count {
        let id = network(&format!("net-{index}"));
        let devices = (1..=5)
            .map(|host| {
                let rotated = index == 0 && host == 5 && revision == 2;
                Device::new(
                    DeviceId::new(&format!("device-{host}")).unwrap(),
                    public_key(key(index, if rotated { 6 } else { host })),
                    vec![Ipv4Addr::new(10, 1, 0, host).into()],
                )
                .unwrap()
            })
            .collect();
        networks.push(
            Network::new(id.clone(), devices)
                .unwrap()
                .with_private_lan(true),
        );
        tenants.push(TenantKeyAssignment::new(
            id.clone(),
            public_key(key(index, 0)),
        ));
        secrets.push((id, TenantPrivateKey::new(key(index, 0)).unwrap()));
    }
    let keys = wgfeel_test_support::fixture_node_keys(seed(9));
    let assignment = GatewayAssignment::new(
        node("node"),
        public(9),
        public_key(*keys.gateway().expose_bytes()),
        networks
            .iter()
            .map(|network| network.id().clone())
            .collect(),
        tenants,
    )
    .unwrap();
    let config = Config::new(revision, networks, Policy::new(vec![], vec![], vec![])).unwrap();
    let projection = ManagementConfig::new(node("management"), config, vec![assignment])
        .unwrap()
        .project_mesh_for(&node("node"))
        .unwrap();
    (projection, LocalTenants::new(secrets).unwrap())
}

fn cpu_usec(group: &Path) -> u64 {
    fs::read_to_string(group.join("cpu.stat"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .unwrap()
        .parse()
        .unwrap()
}
fn memory(group: &Path, counter: &str) -> u64 {
    fs::read_to_string(group.join(counter))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn workload(count: u16) {
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap();
    let group = Path::new("/sys/fs/cgroup").join(
        membership
            .trim()
            .strip_prefix("0::/")
            .expect("cgroup v2 required"),
    );
    assert_eq!(
        memory(&group, "memory.max"),
        1 << 30,
        "run in an isolated 1 GiB scope"
    );
    let directory = Directory::new();
    let (initial, tenants) = projection(count, 1);
    let (next, _) = projection(count, 2);
    Store::initialize(&directory.state())
        .unwrap()
        .commit_managed_projection(
            &initial,
            &wgfeel_test_support::fixture_node_keys(seed(9)),
            &tenants,
            &public(70),
        )
        .unwrap();
    let binary = std::env::var_os("WGFEEL_CAPACITY_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_wgfeel").into());
    let mut runtime = Runtime::spawn_binary(binary, &directory.state(), "127.0.0.1:0");
    let ready: serde_json::Value = serde_json::from_slice(
        &runtime
            .child
            .next_stdout_line(Duration::from_secs(15))
            .unwrap(),
    )
    .unwrap();
    let address = ready["listen"].as_str().unwrap().parse().unwrap();
    let workers = runtime.children();
    assert_eq!(workers.len(), usize::from(count) + 2);
    let start = Instant::now();
    let cpu = cpu_usec(&group);
    std::thread::sleep(Duration::from_secs(1));
    eprintln!(
        "networks={count} devices={} idle_cpu_pct={:.1} idle_bytes={} workers={}",
        count * 5,
        (cpu_usec(&group) - cpu) as f64 / (start.elapsed().as_secs_f64() * 10_000.0),
        memory(&group, "memory.current"),
        workers.len()
    );
    let mut src = Peer::with_keys(key(1, 1), public_key(key(1, 0)));
    let mut dst = Peer::with_keys(key(1, 2), public_key(key(1, 0)));
    let handshake = Instant::now();
    src.establish(address);
    dst.establish(address);
    eprintln!(
        "handshake_pair_ms={} (includes two 20 ms fixture pauses)",
        handshake.elapsed().as_millis()
    );
    src.send(address, &packet(false, 1, 2, 64, 0));
    dst.plaintext(address, &packet(false, 1, 2, 63, 0));
    let update = Instant::now();
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut worst = Duration::ZERO;
    let sample_window = Duration::from_millis(30);
    std::thread::scope(|scope| {
        let delivery = scope.spawn(|| apply(address, &next));
        loop {
            sent += 1;
            let payload = sent.to_be_bytes();
            let probe = packet_with_payload(false, 1, 2, 64, payload);
            let expected = packet_with_payload(false, 1, 2, 63, payload);
            let begin = Instant::now();
            src.send(address, &probe);
            while begin.elapsed() < sample_window {
                let mut buffer = [0; 1313];
                if let Ok((n, from)) = dst.socket.recv_from(&mut buffer)
                    && from == address
                    && let TunnResult::WriteToTunnel(plain) = dst.receive(from, &buffer[..n])
                    && plain.as_ref().starts_with(&expected)
                {
                    let latency = begin.elapsed();
                    if latency <= sample_window {
                        received += 1;
                        worst = worst.max(latency);
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if delivery.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        delivery.join().unwrap();
    });
    let remaining = runtime.children();
    let retained = workers.iter().filter(|id| remaining.contains(id)).count();
    eprintln!(
        "update_ms={} sent={sent} received_in_30ms={received} worst_received_us={} retained={retained} peak_bytes={}",
        update.elapsed().as_millis(),
        worst.as_micros(),
        memory(&group, "memory.peak")
    );
    assert!(
        received > 0,
        "none of {sent} update probes arrived within {sample_window:?}"
    );
    if std::env::var_os("WGFEEL_CAPACITY_BINARY").is_none() {
        assert_eq!(retained, workers.len() - 1);
        // The idle group poll must also observe EOF on a worker with no requests.
        let idle = remaining
            .iter()
            .copied()
            .find(|pid| !workers.contains(pid))
            .unwrap();
        assert_eq!(child_context(idle), "tenant:net-0");
        kill_process(Pid::from_raw(idle as i32).unwrap(), Signal::KILL).unwrap();
        assert_reaped(&[idle]);
        src.send(address, &packet(false, 1, 2, 64, 211));
        dst.plaintext(address, &packet(false, 1, 2, 63, 211));
    }
    runtime.signal(Signal::TERM);
    assert!(runtime.finish().status.success());
}

#[test]
#[ignore = "requires a dedicated 1 GiB cgroup"]
fn small_entry() {
    workload(2);
}

#[test]
#[ignore = "requires a dedicated 1 GiB cgroup"]
fn target_entry() {
    workload(150);
}
