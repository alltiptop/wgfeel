use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, RecordType,
        rdata::{A, AAAA},
    },
};
use smoltcp::{
    iface::{Config as IpConfig, Interface, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant as IpInstant,
    wire::{HardwareAddress, IpCidr},
};
use std::collections::VecDeque;

fn query(name: &str, ipv6: bool) -> Vec<u8> {
    let mut message = Message::new(121, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(name).unwrap(),
        if ipv6 {
            RecordType::AAAA
        } else {
            RecordType::A
        },
    ));
    message.to_vec().unwrap()
}
fn udp(name: &str, ipv6: bool, source: u8) -> Vec<u8> {
    let body = query(name, ipv6);
    let offset = if ipv6 { 40 } else { 20 };
    let mut bytes = vec![0; offset + 8 + body.len()];
    let payload_len = (8 + body.len()) as u16;
    if ipv6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&payload_len.to_be_bytes());
        bytes[6] = 17;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(
            &format!("fd00:1::{source}")
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        bytes[24..40].copy_from_slice(&wgfeel_core::DNS_IPV6.octets());
    } else {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(20 + payload_len).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 1, 0, source]);
        bytes[16..20].copy_from_slice(&wgfeel_core::DNS_IPV4.octets());
        let sum = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    bytes[offset..offset + 2].copy_from_slice(&53000_u16.to_be_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&53_u16.to_be_bytes());
    bytes[offset + 4..offset + 6].copy_from_slice(&payload_len.to_be_bytes());
    bytes[offset + 8..].copy_from_slice(&body);
    let mut pseudo = if ipv6 {
        bytes[8..40].to_vec()
    } else {
        bytes[12..20].to_vec()
    };
    if ipv6 {
        pseudo.extend_from_slice(&u32::from(payload_len).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
    } else {
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&payload_len.to_be_bytes());
    }
    pseudo.extend_from_slice(&bytes[offset..]);
    let sum = checksum(&pseudo);
    let sum = if sum == 0 { u16::MAX } else { sum };
    bytes[offset + 6..offset + 8].copy_from_slice(&sum.to_be_bytes());
    bytes
}
fn udp_answer(peer: &mut Peer, address: SocketAddr, name: &str, ipv6: bool) -> Message {
    peer.send(address, &udp(name, ipv6, 1));
    let (bytes, _) = peer.wire(WAIT);
    let TunnResult::WriteToTunnel(packet) = peer.receive(address, &bytes) else {
        panic!("DNS response must be encrypted to requesting peer")
    };
    let bytes = packet.as_ref();
    let offset = if ipv6 { 40 } else { 20 };
    assert_eq!(&bytes[offset..offset + 2], &53_u16.to_be_bytes());
    let len = usize::from(u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]));
    let reply = Message::from_vec(&bytes[offset + 8..offset + len]).unwrap();
    assert_eq!(reply.metadata.id, 121);
    assert!(
        reply
            .authorities
            .iter()
            .chain(&reply.additionals)
            .all(|record| !matches!(record.data, RData::A(_) | RData::AAAA(_))),
        "unexpected address outside the answer section"
    );
    reply
}

#[test]
fn encrypted_dns_is_tenant_scoped_source_bound_and_survives_restart_without_manager() {
    let directory = populated_with_dns(true);
    let before = fs::read(directory.state().join("state.json")).unwrap();
    for _ in 0..2 {
        let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
        let address = runtime.ready();
        let mut alice = Peer::new(23, 1);
        let mut bob = Peer::new(25, 2);
        alice.establish(address);
        bob.establish(address);
        for ipv6 in [false, true] {
            for (peer, host) in [(&mut alice, 1), (&mut bob, 2)] {
                let reply = udp_answer(peer, address, "pc.feel.internal.", ipv6);
                let expected = if ipv6 {
                    RData::AAAA(AAAA(format!("fd00:1::{host}").parse().unwrap()))
                } else {
                    RData::A(A(format!("10.1.0.{host}").parse().unwrap()))
                };
                assert_eq!(reply.answers.len(), 1, "unexpected records for {host}");
                assert_eq!(reply.answers[0].data, expected);
                let external = udp_answer(peer, address, "example.org.", ipv6);
                assert_eq!(external.metadata.response_code, ResponseCode::Refused);
                assert!(external.answers.is_empty());
                assert!(!external.metadata.recursion_available);
            }
        }
        // Alice's ACL denies her second device. Bob's second device is visible only in Bob's context.
        for name in ["other.feel.internal.", "missing.feel.internal."] {
            for ipv6 in [false, true] {
                let reply = udp_answer(&mut alice, address, name, ipv6);
                assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
                assert!(reply.answers.is_empty());
            }
        }
        alice.send(address, &udp("pc.feel.internal.", false, 2));
        alice.no_datagram(Duration::from_millis(100));
        bob.no_datagram(Duration::from_millis(100));
        runtime.signal(Signal::TERM);
        assert!(runtime.finish().status.success());
        assert_eq!(
            before,
            fs::read(directory.state().join("state.json")).unwrap()
        );
    }
}

#[test]
fn service_wg_delivery_replaces_dns_records_and_suspension_revokes_dns() {
    let directory = populated_with_dns(true);
    let mut store = Store::open(&directory.state()).unwrap();
    let previous = store.load().unwrap().unwrap();
    let old = previous.projection();
    let policy = || {
        Policy::new(
            vec![],
            vec![Rule::new(
                endpoint("beta", "first"),
                endpoint("beta", "second"),
                Action::Allow,
            )],
            vec![],
        )
    };
    let initial = ManagementConfig::new(
        node("management"),
        Config::new(72, old.config().networks().to_vec(), policy()).unwrap(),
        vec![old.assignment().clone()],
    )
    .unwrap()
    .project_mesh_for(&node("node"))
    .unwrap();
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
    let mut peer = Peer::new(25, 2);
    peer.establish(address);
    assert_eq!(
        udp_answer(&mut peer, address, "pc.feel.internal.", false)
            .answers
            .len(),
        1
    );
    let mut networks = initial.config().networks().to_vec();
    for network in &mut networks {
        if network.id().as_str() == "beta" {
            *network = network
                .with_devices(
                    network
                        .devices()
                        .iter()
                        .map(|d| {
                            if d.id().as_str() == "second" {
                                d.clone().with_hostname(Some("laptop".into())).unwrap()
                            } else {
                                d.clone()
                            }
                        })
                        .collect(),
                )
                .unwrap();
        }
    }
    let changed = ManagementConfig::new(
        node("management"),
        Config::new(73, networks.clone(), policy()).unwrap(),
        vec![initial.assignment().clone()],
    )
    .unwrap()
    .project_mesh_for(&node("node"))
    .unwrap();
    apply(address, &changed);
    let mut peer = Peer::new(25, 2);
    peer.establish(address);
    assert_eq!(
        udp_answer(&mut peer, address, "pc.feel.internal.", false)
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        udp_answer(&mut peer, address, "laptop.feel.internal.", false)
            .answers
            .len(),
        1
    );
    for network in &mut networks {
        if network.id().as_str() == "beta" {
            *network = network
                .with_devices(
                    network
                        .devices()
                        .iter()
                        .filter(|d| d.id().as_str() != "second")
                        .cloned()
                        .collect(),
                )
                .unwrap();
        }
    }
    let deleted = ManagementConfig::new(
        node("management"),
        Config::new(74, networks.clone(), Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![initial.assignment().clone()],
    )
    .unwrap()
    .project_mesh_for(&node("node"))
    .unwrap();
    apply(address, &deleted);
    let mut peer = Peer::new(25, 2);
    peer.establish(address);
    assert_eq!(
        udp_answer(&mut peer, address, "laptop.feel.internal.", false)
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        udp_answer(&mut peer, address, "other.feel.internal.", false)
            .answers
            .len(),
        1
    );
    for network in &mut networks {
        if network.id().as_str() == "beta" {
            *network = network.clone().with_suspended(true);
        }
    }
    let suspended = ManagementConfig::new(
        node("management"),
        Config::new(75, networks, Policy::new(vec![], vec![], vec![])).unwrap(),
        vec![initial.assignment().clone()],
    )
    .unwrap()
    .project_mesh_for(&node("node"))
    .unwrap();
    apply(address, &suspended);
    peer.send(address, &udp("other.feel.internal.", false, 1));
    peer.no_datagram(Duration::from_millis(150));
    runtime.signal(Signal::TERM);
    assert!(runtime.finish().status.success());
    let restored = Store::open(&directory.state())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(restored.projection(), &suspended);
}

struct Link {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}
impl phy::Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: IpInstant) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.input.pop_front()?), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: IpInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}

#[test]
fn encrypted_dns_tcp_stream_handles_split_frames_and_repeated_queries_over_both_families() {
    let directory = populated_with_dns(true);
    let mut runtime = Runtime::spawn(&directory.state(), "127.0.0.1:0");
    let address = runtime.ready();
    for ipv6 in [false, true] {
        let mut peer = Peer::new(23, 1);
        peer.establish(address);
        let mut link = Link {
            input: VecDeque::new(),
            output: VecDeque::new(),
        };
        let mut config = IpConfig::new(HardwareAddress::Ip);
        config.random_seed = if ipv6 { 123 } else { 456 };
        let mut interface = Interface::new(config, &mut link, IpInstant::ZERO);
        let source: smoltcp::wire::IpAddress = if ipv6 {
            "fd00:1::1".parse().unwrap()
        } else {
            "10.1.0.1".parse().unwrap()
        };
        let dns: smoltcp::wire::IpAddress = if ipv6 {
            wgfeel_core::DNS_IPV6.into()
        } else {
            wgfeel_core::DNS_IPV4.into()
        };
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(source, if ipv6 { 128 } else { 32 }))
                .unwrap();
        });
        if ipv6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(wgfeel_core::DNS_IPV6)
                .unwrap();
        } else {
            interface
                .routes_mut()
                .add_default_ipv4_route(wgfeel_core::DNS_IPV4)
                .unwrap();
        }
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        socket.set_ack_delay(None);
        socket
            .connect(interface.context(), (dns, 53), (source, 54000))
            .unwrap();
        let handle = sockets.add(socket);
        let body = query("pc.feel.internal.", ipv6);
        let mut request = (body.len() as u16).to_be_bytes().to_vec();
        request.extend(body);
        let mut sent = 0;
        let mut replies = Vec::new();
        let mut received = Vec::new();
        let start = Instant::now();
        while replies.len() < 3 && start.elapsed() < WAIT {
            let time = IpInstant::from_micros(start.elapsed().as_micros() as i64);
            interface.poll_maintenance(time);
            interface.poll_ingress_single(time, &mut link, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_send() && sent < request.len() {
                // Deliberately split the two-byte length prefix and question.
                let end = (sent + 1).min(request.len());
                sent += socket.send_slice(&request[sent..end]).unwrap();
            }
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if received.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([received[0], received[1]]));
                if received.len() >= len + 2 {
                    replies.push(Message::from_vec(&received[2..len + 2]).unwrap());
                    received.drain(..len + 2);
                    let name = if replies.len() == 1 {
                        "example.org."
                    } else {
                        "pc.feel.internal."
                    };
                    let body = query(name, ipv6);
                    request = (body.len() as u16).to_be_bytes().to_vec();
                    request.extend(body);
                    sent = 0;
                }
            }
            interface.poll_egress(time, &mut link, &mut sockets);
            while let Some(bytes) = link.output.pop_front() {
                peer.send(address, &bytes);
            }
            let mut bytes = [0; 1313];
            while let Ok((len, from)) = peer.socket.recv_from(&mut bytes) {
                if let TunnResult::WriteToTunnel(packet) = peer.receive(from, &bytes[..len]) {
                    let raw = packet.as_ref();
                    let len = if ipv6 {
                        40 + usize::from(u16::from_be_bytes([raw[4], raw[5]]))
                    } else {
                        usize::from(u16::from_be_bytes([raw[2], raw[3]]))
                    };
                    link.input.push_back(raw[..len].to_vec());
                }
            }
            std::thread::sleep(Duration::from_millis(3));
        }
        assert_eq!(replies.len(), 3, "three framed replies, ipv6={ipv6}");
        let external = replies.remove(1);
        assert_eq!(external.metadata.response_code, ResponseCode::Refused);
        assert!(!external.metadata.recursion_available);
        for reply in replies {
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.answers.len(), 1);
        }
    }
    runtime.signal(Signal::TERM);
    assert!(runtime.finish().status.success());
}
