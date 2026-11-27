use super::*;
use serde_json::json;

const INTERFACE_KEY: [u8; 32] = [41; 32];
const PROVIDER_KEY: [u8; 32] = [42; 32];
const PSK: [u8; 32] = [43; 32];
const TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(172, 16, 8, 7);
const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
const PREFIX: &str = "203.0.113.0/24";

// Production rejects loopback provider endpoints. Use an address assigned to
// this host, so the encrypted UDP traffic still stays on this machine.
fn provider_socket() -> UdpSocket {
    let ip = nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter(|iface| iface.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP))
        .filter_map(|iface| {
            let addr = iface.address?;
            addr.as_sockaddr_in()
                .map(|addr| std::net::IpAddr::V4(addr.ip()))
                .or_else(|| {
                    addr.as_sockaddr_in6()
                        .map(|addr| std::net::IpAddr::V6(addr.ip()))
                })
        })
        .find(|ip| wgfeel_core::validate_external_endpoint(SocketAddr::new(*ip, 1)).is_ok())
        .expect("provider test requires an eligible local non-loopback IP address");
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

fn provider_config(endpoint: SocketAddr) -> String {
    let public = PublicKey::from(&StaticSecret::from(PROVIDER_KEY));
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {TUNNEL_ADDRESS}/32\n\
         [Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {PREFIX}\n",
        STANDARD.encode(INTERFACE_KEY),
        STANDARD.encode(public.as_bytes()),
        STANDARD.encode(PSK),
    )
}

struct Provider {
    socket: UdpSocket,
    tunnel: Tunn,
    limiter: Arc<RateLimiter>,
}

impl Provider {
    fn new() -> Self {
        let secret = StaticSecret::from(PROVIDER_KEY);
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&secret), 100));
        let tunnel = Tunn::new(
            secret,
            PublicKey::from(&StaticSecret::from(INTERFACE_KEY)),
            Some(PSK),
            None,
            IndexTable::from_os_rng(),
            limiter.clone(),
        );
        Self {
            socket: provider_socket(),
            tunnel,
            limiter,
        }
    }
    fn exchange(&mut self, client: &mut Client, marker: u8) {
        let socket = &self.socket;
        let wrong_port = UdpSocket::bind((socket.local_addr().unwrap().ip(), 0)).unwrap();
        let request = packet(client.address, REMOTE, marker);
        let mut expected = packet(REMOTE, client.address, marker);
        expected[8] -= 1;
        expected[10..12].fill(0);
        let check = checksum(&expected[..20]);
        expected[10..12].copy_from_slice(&check.to_be_bytes());
        expected[20..22].copy_from_slice(&request[22..24]);
        expected[22..24].copy_from_slice(&request[20..22]);

        let mut received_request = false;
        let mut next_send = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut bytes = [0; 1500];
        loop {
            if Instant::now() >= next_send {
                client.send(&request);
                next_send = Instant::now() + Duration::from_millis(250);
            }
            self.limiter.try_reset_count();
            while let Ok((size, from)) = socket.recv_from(&mut bytes) {
                let Ok(verified) = self
                    .limiter
                    .verify_packet(from, Packet::copy_from(&bytes[..size]))
                else {
                    continue;
                };
                match self.tunnel.handle_incoming_packet(verified) {
                    TunnResult::WriteToNetwork(packet) => {
                        let packet: Packet = packet.into();
                        socket.send_to(packet.as_ref(), from).unwrap();
                    }
                    TunnResult::WriteToTunnel(packet) if !packet.as_ref().is_empty() => {
                        let ip = packet.as_ref();
                        assert_eq!(ip.len(), request.len());
                        assert_eq!(ip[8], 63);
                        assert_eq!(checksum(&ip[..20]), 0);
                        assert_eq!(&ip[12..16], &TUNNEL_ADDRESS.octets());
                        assert_eq!(&ip[16..20], &REMOTE.octets());
                        assert_eq!(&ip[22..24], &request[22..24]);
                        assert_eq!(&ip[28..], &request[28..]);
                        let mut reply = super::packet(REMOTE, TUNNEL_ADDRESS, marker);
                        reply[20..22].copy_from_slice(&ip[22..24]);
                        reply[22..24].copy_from_slice(&ip[20..22]);
                        // Respond to the first request from the wrong port. Only
                        // the reply to a retransmission comes from the provider.
                        let reply_socket = if received_request {
                            socket
                        } else {
                            reply[28] = !marker;
                            &wrong_port
                        };
                        let wire = self
                            .tunnel
                            .encapsulate_with_session(Packet::copy_from(&reply))
                            .unwrap()
                            .into_bytes();
                        reply_socket.send_to(wire.as_ref(), from).unwrap();
                        received_request = true;
                    }
                    _ => (),
                }
            }
            let replies = client.poll();
            if !replies.is_empty() {
                for reply in replies {
                    assert_eq!(reply, expected);
                }
                assert!(received_request);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "provider roundtrip timed out (translated request received: {received_request})"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn wait_for_placement(manager: &Fixture, placement: &str, owner: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let placed = api::json(&manager.state(), "GET", placement, Value::Null);
        let status = api::json(&manager.state(), "GET", "/api/v1/distribution", Value::Null);
        let gateways = status["gateways"].as_array().unwrap();
        if placed["node"] == owner
            && gateways.len() == 2
            && gateways.iter().all(|node| node["status"] == "applied")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "egress placement on {owner} was not applied"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn provider_udp_roundtrip_survives_a_move_from_main_to_child() {
    let mut provider = Provider::new();
    let manager = Fixture::new();
    manager.initialize_with_traffic("127.0.0.1:0", Some("entry"));
    let _server = manager.start(1);
    let (_child, endpoint) = manager.start_child("exit");
    manager.join_child("exit", endpoint);
    let user = api::json(
        &manager.state(),
        "POST",
        "/api/v1/users",
        json!({"name":"alice"}),
    );
    let user = user["id"].as_str().unwrap();
    api::json(
        &manager.state(),
        "POST",
        &format!("/api/v1/users/{user}/devices"),
        json!({"name":"phone", "gateway":"management"}),
    );
    let egress = api::json(
        &manager.state(),
        "POST",
        "/api/v1/egresses",
        json!({"config":provider_config(provider.socket.local_addr().unwrap()), "node":"management",
            "users":[{"user":user, "routes":[PREFIX], "dns":{"mode":"none"}}]}),
    );
    let placement = format!("/api/v1/egresses/{}/node", egress["id"].as_str().unwrap());
    wait_for_placement(&manager, &placement, "management");
    let mut client = Client::from_config(&exported(&manager, "alice", "phone"));
    client.establish();
    provider.exchange(&mut client, 17);

    api::json(&manager.state(), "PUT", &placement, json!({"node":"exit"}));
    wait_for_placement(&manager, &placement, "exit");
    provider.exchange(&mut client, 39);
}
