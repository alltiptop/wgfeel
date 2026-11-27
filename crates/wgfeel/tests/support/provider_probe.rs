use super::*;
use std::collections::BTreeMap;
const ECHO_PORTS: [u8; 4] = [0x12, 0x35, 0x12, 0x34];

#[derive(Clone, Copy, Debug)]
struct Observation {
    destination: Ipv4Addr,
    marker: u8,
    source: (Ipv4Addr, u16),
    destination_port: u16,
    peer: SocketAddr,
}

struct Reply {
    probe: Observation,
    ip: Vec<u8>,
}
impl Reply {
    fn send(&self, provider: &mut Provider) {
        // Every retry gets a fresh WireGuard counter.
        let wire = provider
            .tunnel
            .encapsulate_with_session(Packet::copy_from(&self.ip))
            .unwrap()
            .into_bytes();
        provider
            .socket
            .send_to(wire.as_ref(), self.probe.peer)
            .unwrap();
    }
}

pub(super) struct ProviderProbe {
    provider: Provider,
    seen: Vec<Observation>,
    expected: BTreeMap<u8, (SocketAddr, Vec<u8>)>,
}

impl ProviderProbe {
    pub(super) fn start(provider: Provider) -> Self {
        Self {
            provider,
            seen: vec![],
            expected: BTreeMap::new(),
        }
    }

    pub(super) fn endpoint(&self) -> SocketAddr {
        self.provider.socket.local_addr().unwrap()
    }

    pub(super) fn observed(&mut self, destination: Ipv4Addr, marker: u8) -> usize {
        self.service();
        self.seen
            .iter()
            .filter(|p| p.destination == destination && p.marker == marker)
            .count()
    }

    pub(super) fn service(&mut self) {
        self.poll(&[]);
    }

    fn expect(&mut self, client: &Client, destination: Ipv4Addr, marker: u8) {
        let peer = client.socket.local_addr().unwrap();
        let packet = expected_echo(client.address, destination, marker);
        assert!(
            self.expected.insert(marker, (peer, packet)).is_none(),
            "reused probe marker {marker}"
        );
    }

    pub(super) fn poll_client(&self, client: &mut Client) -> Vec<Vec<u8>> {
        let packets = client.poll();
        for ip in &packets {
            let Some(&marker) = ip.get(28) else { continue };
            if let Some((peer, expected)) = self.expected.get(&marker) {
                assert_eq!(
                    client.socket.local_addr().unwrap(),
                    *peer,
                    "provider marker {marker} reached another WireGuard client"
                );
                assert!(
                    ip == expected,
                    "incorrect plaintext for provider marker {marker}"
                );
            } else if ip[0] == 0x45 && ip[9] == 17 {
                assert_ne!(
                    ip[20..24],
                    ECHO_PORTS,
                    "unexpected provider reply for marker {marker}"
                );
            }
        }
        packets
    }

    // Record incoming probes at the independent peer before constructing their
    // replies. Selected replies can then be delivered in a different order.
    fn poll(&mut self, hold: &[u8]) -> Vec<Reply> {
        let provider = &mut self.provider;
        provider.limiter.try_reset_count();
        let mut held = Vec::new();
        let mut buf = [0; 1500];
        loop {
            let (n, peer) = match provider.socket.recv_from(&mut buf) {
                Ok(datagram) => datagram,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("failed to read native provider socket: {e}"),
            };
            let Ok(wire) = provider
                .limiter
                .verify_packet(peer, Packet::copy_from(&buf[..n]))
            else {
                continue;
            };
            match provider.tunnel.handle_incoming_packet(wire) {
                TunnResult::WriteToNetwork(response) => {
                    let wire: Packet = response.into();
                    provider.socket.send_to(wire.as_ref(), peer).unwrap();
                }
                TunnResult::WriteToTunnel(ip) if !ip.as_ref().is_empty() => {
                    let ip = ip.as_ref();
                    if ip.len() < 29 || ip[0] != 0x45 || ip[9] != 17 {
                        continue;
                    }
                    let source = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                    let destination = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
                    let probe = Observation {
                        destination,
                        marker: ip[28],
                        source: (source, u16::from_be_bytes([ip[20], ip[21]])),
                        destination_port: u16::from_be_bytes([ip[22], ip[23]]),
                        peer,
                    };
                    self.seen.push(probe);
                    let mut reply = ip.to_vec();
                    reply[12..16].copy_from_slice(&destination.octets());
                    reply[16..20].copy_from_slice(&source.octets());
                    reply[20..22].copy_from_slice(&ip[22..24]);
                    reply[22..24].copy_from_slice(&ip[20..22]);
                    reply[8] = 64;
                    reply[10..12].fill(0);
                    let check = checksum(&reply[..20]);
                    reply[10..12].copy_from_slice(&check.to_be_bytes());
                    let reply = Reply { probe, ip: reply };
                    if hold.contains(&probe.marker) {
                        held.push(reply);
                    } else {
                        reply.send(provider);
                    }
                }
                _ => (),
            }
        }
        held
    }

    pub(super) fn exchange(&mut self, client: &mut Client, destination: Ipv4Addr, marker: u8) {
        self.exchange_group([client], destination, [marker]);
    }

    pub(super) fn exchange_overlapping(
        &mut self,
        first: &mut Client,
        second: &mut Client,
        destination: Ipv4Addr,
        markers: [u8; 2],
    ) {
        assert_eq!(first.address, second.address);
        assert_ne!(markers[0], markers[1]);
        self.exchange_group([first, second], destination, markers);
    }

    fn exchange_group<const N: usize>(
        &mut self,
        mut clients: [&mut Client; N],
        destination: Ipv4Addr,
        markers: [u8; N],
    ) {
        for (client, marker) in clients.iter().zip(markers) {
            self.expect(client, destination, marker);
        }
        let until = Instant::now() + Duration::from_secs(30);
        let mut next = Instant::now();
        let mut received = [false; N];
        let mut held: [Option<Reply>; N] = std::array::from_fn(|_| None);
        let mut sent = [0; N];
        let mut echoed = [0; N];
        let mut next_request = 0;
        let mut last_client_packet = [None; N];
        let start_seen = self.seen.len();
        loop {
            if Instant::now() >= next {
                if let Some(i) = (0..N)
                    .map(|offset| (next_request + offset) % N)
                    .find(|&i| held[i].is_none())
                {
                    let client = &mut clients[i];
                    client.send(&packet(client.address, destination, markers[i]));
                    sent[i] += 1;
                    next_request = (i + 1) % N;
                } else {
                    // Repeat the full burst in the same order. A receive loop
                    // that consumes UDP while the worker is busy starves the
                    // same client on every attempt.
                    for (i, reply) in held.iter().enumerate().rev() {
                        reply.as_ref().unwrap().send(&mut self.provider);
                        echoed[i] += 1;
                    }
                }
                next = Instant::now() + Duration::from_millis(200);
            }
            for reply in self.poll(&markers) {
                assert_eq!(reply.probe.destination, destination);
                assert_eq!(reply.probe.source.0, TUNNEL_ADDRESS);
                let index = markers
                    .iter()
                    .position(|m| *m == reply.probe.marker)
                    .unwrap();
                if held[index].is_none() {
                    assert!(
                        held.iter()
                            .flatten()
                            .all(|other| other.probe.source.1 != reply.probe.source.1),
                        "colliding users shared a translated UDP port"
                    );
                    held[index] = Some(reply);
                    next = Instant::now();
                }
            }
            for (i, client) in clients.iter_mut().enumerate() {
                for ip in self.poll_client(client) {
                    last_client_packet[i] =
                        Some((ip.len(), ip.get(28).copied(), ip.get(8).copied()));
                    if ip.get(28) == Some(&markers[i]) {
                        assert_ne!(
                            echoed[i], 0,
                            "client received a probe before the provider replied"
                        );
                        received[i] = true;
                    }
                }
            }
            if received.iter().all(|got| *got) {
                return;
            }
            if Instant::now() >= until {
                let observed = &self.seen[start_seen..];
                let counts = markers.map(|m| observed.iter().filter(|p| p.marker == m).count());
                let last = markers.map(|m| observed.iter().rfind(|p| p.marker == m));
                panic!(
                    "provider echo timed out for {destination}, markers {markers:?}; client requests {sent:?}, decrypted {counts:?} of {} packets, last probes {last:?}, provider replies sent {echoed:?}, client responses {received:?}, last client (length, marker, TTL) {last_client_packet:?}",
                    observed.len()
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn reply_to_observed(
        &mut self,
        client: &mut Client,
        destination: Ipv4Addr,
        previous_marker: u8,
        fresh_marker: u8,
    ) {
        assert_ne!(previous_marker, fresh_marker);
        let observed = self
            .seen
            .iter()
            .rev()
            .find(|p| p.destination == destination && p.marker == previous_marker)
            .copied()
            .expect("a pre-revision provider request is required");
        let mut reply = packet(destination, observed.source.0, fresh_marker);
        reply[20..22].copy_from_slice(&observed.destination_port.to_be_bytes());
        reply[22..24].copy_from_slice(&observed.source.1.to_be_bytes());
        let reply = Reply {
            probe: observed,
            ip: reply,
        };
        self.expect(client, destination, fresh_marker);
        let until = Instant::now() + WAIT;
        let mut next = Instant::now();
        loop {
            self.service();
            if Instant::now() >= next {
                reply.send(&mut self.provider);
                next = Instant::now() + Duration::from_millis(200);
            }
            if self
                .poll_client(client)
                .iter()
                .any(|ip| ip.get(28) == Some(&fresh_marker))
            {
                return;
            }
            assert!(
                Instant::now() < until,
                "fresh provider reply could not use the pre-revision translation"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn expected_echo(client: Ipv4Addr, destination: Ipv4Addr, marker: u8) -> Vec<u8> {
    let mut reply = packet(destination, client, marker);
    reply[20..24].copy_from_slice(&ECHO_PORTS);
    reply[8] -= 1;
    reply[10..12].fill(0);
    let check = checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&check.to_be_bytes());
    reply
}
