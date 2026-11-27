use super::{provider_probe::ProviderProbe, *};

const DEFAULT: &str = "0.0.0.0/0";
const INSIDE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 19);
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 23);
const DEVICE_PROBES: [(usize, usize, u8); 3] = [(0, 1, 12), (2, 3, 13), (4, 5, 14)];

fn add_user(manager: &Fixture, name: &str, laptop: &str) -> String {
    let user = api::json(
        &manager.state(),
        "POST",
        "/api/v1/users",
        json!({"name": name}),
    );
    let id = user["id"].as_str().unwrap();
    // All three phones use the same inside tuple. Each laptop has a distinct
    // internal address so a cross-tenant probe targets a real, reachable peer.
    for (device, gateway, address) in [
        ("phone", "management", "10.203.0.2"),
        ("laptop", "exit", laptop),
    ] {
        api::json(
            &manager.state(),
            "POST",
            &format!("/api/v1/users/{id}/devices"),
            json!({"name": device, "gateway": gateway, "addresses": [address]}),
        );
    }
    id.to_owned()
}

fn assert_allowed_ips(profile: &[u8], expected: &[&str]) {
    let mut peers = std::str::from_utf8(profile)
        .unwrap()
        .split("\n[Peer]\n")
        .skip(1);
    let home = peers.next().expect("missing home peer");
    let mut home_routes = home
        .lines()
        .filter_map(|line| line.strip_prefix("AllowedIPs = "));
    let routes = home_routes.next().expect("missing home routes");
    assert!(home_routes.next().is_none(), "duplicate home AllowedIPs");
    assert!(
        peers.all(|peer| !peer.lines().any(|line| line.starts_with("AllowedIPs = "))),
        "an additional peer received routes"
    );
    let mut actual: Vec<_> = routes.split(", ").collect();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn observe_window(
    provider: &mut ProviderProbe,
    clients: &mut [Client; 6],
    duration: Duration,
    waiting_for: Option<u8>,
) -> bool {
    let device_packets = DEVICE_PROBES.map(|(source, target, marker)| {
        let mut expected = packet(clients[source].address, clients[target].address, marker);
        expected[8] -= 2;
        expected[10..12].fill(0);
        let check = checksum(&expected[..20]);
        expected[10..12].copy_from_slice(&check.to_be_bytes());
        expected
    });
    let mut received = false;
    let until = Instant::now() + duration;
    while Instant::now() < until {
        provider.service();
        for (index, client) in clients.iter_mut().enumerate() {
            for ip in provider.poll_client(client) {
                let marker = ip[28];
                match marker {
                    10 | 11 | 22..=24 | 50 | 51 => {
                        panic!("forbidden marker {marker} reached device {index}")
                    }
                    12..=14 => {
                        let probe = usize::from(marker - 12);
                        assert_eq!(index, DEVICE_PROBES[probe].1, "wrong tenant for {marker}");
                        assert_eq!(ip, device_packets[probe]);
                        received |= Some(marker) == waiting_for;
                    }
                    _ => (), // poll_client checks provider replies against their intended socket.
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    received
}

#[test]
fn shared_child_egress_enforces_each_users_routes_and_revocation() {
    let mut provider = ProviderProbe::start(Provider::new());
    let manager = Fixture::new();
    manager.initialize_with_traffic("127.0.0.1:0", Some("entry"));
    let _main = manager.start(1);
    let (_child, endpoint) = manager.start_child("exit");
    manager.join_child("exit", endpoint);
    let alice_id = add_user(&manager, "alice", "10.203.1.11");
    let bob_id = add_user(&manager, "bob", "10.203.1.12");
    add_user(&manager, "carol", "10.203.1.13");
    let receipt = api::json(
        &manager.state(),
        "POST",
        "/api/v1/egresses",
        json!({
            "config": provider_config(provider.endpoint(), DEFAULT), "node": "exit",
            "users": [
                {"user": alice_id, "routes": [DEFAULT], "dns": {"mode": "none"}},
                {"user": bob_id, "routes": [PREFIX], "dns": {"mode": "none"}}
            ]
        }),
    );
    let egress = receipt["id"].as_str().unwrap();
    let placement = format!("/api/v1/egresses/{egress}/node");
    wait_for_placement(
        &manager,
        &placement,
        "exit",
        receipt["generation"].as_u64().unwrap(),
    );

    let mut clients = [
        ("alice", "phone"),
        ("alice", "laptop"),
        ("bob", "phone"),
        ("bob", "laptop"),
        ("carol", "phone"),
        ("carol", "laptop"),
    ]
    .map(|(user, device)| {
        let profile = exported(&manager, user, device);
        let expected: &[&str] = match user {
            "alice" => &["10.203.0.0/16", DEFAULT],
            "bob" => &["10.203.0.0/16", PREFIX],
            _ => &["10.203.0.0/16"],
        };
        assert_allowed_ips(&profile, expected);
        let mut client = Client::from_config(&profile);
        client.establish();
        client
    });

    let [alice, alice_laptop, bob, bob_laptop, carol, _] = &mut clients;
    assert_eq!(alice.address, bob.address);
    assert_eq!(alice.address, carol.address);
    provider.exchange(alice, INSIDE, 9);
    for _ in 0..3 {
        alice.send(&packet(alice.address, bob_laptop.address, 10));
        bob.send(&packet(bob.address, alice_laptop.address, 11));
    }
    // Delayed duplicates must still reach the same laptop as the first copy.
    for (source, target, marker) in DEVICE_PROBES {
        let probe = packet(clients[source].address, clients[target].address, marker);
        let until = Instant::now() + Duration::from_secs(25);
        loop {
            clients[source].send(&probe);
            if observe_window(
                &mut provider,
                &mut clients,
                Duration::from_millis(150),
                Some(marker),
            ) {
                break;
            }
            assert!(
                Instant::now() < until,
                "own laptop did not receive {marker}"
            );
        }
    }
    observe_window(
        &mut provider,
        &mut clients,
        Duration::from_millis(300),
        None,
    );
    assert_eq!(provider.observed(clients[3].address, 10), 0);
    assert_eq!(provider.observed(clients[1].address, 11), 0);

    let [alice, _, bob, _, carol, _] = &mut clients;
    provider.exchange_overlapping(alice, bob, INSIDE, [20, 21]);
    for round in 0..3 {
        // Client::send injects native WireGuard payloads even when the
        // destination isn't in the exported AllowedIPs.
        bob.send(&packet(bob.address, OUTSIDE, 22));
        carol.send(&packet(carol.address, INSIDE, 23));
        carol.send(&packet(carol.address, OUTSIDE, 24));
        provider.exchange(bob, INSIDE, 30 + round);
        provider.exchange(alice, OUTSIDE, 40 + round);
    }
    observe_window(
        &mut provider,
        &mut clients,
        Duration::from_millis(300),
        None,
    );
    assert_eq!(provider.observed(OUTSIDE, 22), 0, "split route leaked");
    assert_eq!(
        provider.observed(INSIDE, 23),
        0,
        "unassigned user reached the split destination"
    );
    assert_eq!(
        provider.observed(OUTSIDE, 24),
        0,
        "unassigned user used the default route"
    );

    let revoked = api::json(
        &manager.state(),
        "DELETE",
        &format!("/api/v1/users/{alice_id}/egresses/{egress}"),
        Value::Null,
    );
    wait_for_placement(
        &manager,
        &placement,
        "exit",
        revoked["generation"].as_u64().unwrap(),
    );
    // Deliver to Bob's pre-revocation mapping before his client sends any
    // more traffic that could recreate it.
    let [alice, _, bob, _, _, _] = &mut clients;
    provider.reply_to_observed(bob, INSIDE, 32, 49);
    assert_allowed_ips(&exported(&manager, "alice", "phone"), &["10.203.0.0/16"]);
    assert_allowed_ips(
        &exported(&manager, "bob", "phone"),
        &["10.203.0.0/16", PREFIX],
    );
    // Keep the old client sessions, addresses and UDP ports across the change.
    for round in 0..3 {
        alice.send(&packet(alice.address, INSIDE, 50));
        alice.send(&packet(alice.address, OUTSIDE, 51));
        provider.exchange(bob, INSIDE, 60 + round);
    }
    observe_window(
        &mut provider,
        &mut clients,
        Duration::from_millis(300),
        None,
    );
    assert_eq!(provider.observed(INSIDE, 50), 0, "revoked flow survived");
    assert_eq!(
        provider.observed(OUTSIDE, 51),
        0,
        "revoked default route survived"
    );
}
