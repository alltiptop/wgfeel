use super::*;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use wgfeel_core::{DeviceId, DevicePublicKey, EgressEndpoint, EgressProfileFields, NetworkId};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
const INSIDE: &str = "10.203.0.4";
const TUNNEL: &str = "172.16.0.6";
const REMOTE: &str = "198.51.100.22";

fn profile() -> EgressProfile {
    EgressProfileFields {
        id: EgressId::new("office").unwrap(),
        name: "office".to_owned(),
        node: None,
        pending_node: None,
        secret_revision: 1,
        interface_public_key: DevicePublicKey::new([41; 32]).unwrap(),
        addresses: vec![ip(TUNNEL), ip("fd80::6")],
        dns_servers: vec![],
        mtu: Some(1280),
        peer_public_key: DevicePublicKey::new([42; 32]).unwrap(),
        endpoint: "vpn.example.org:51820".parse::<EgressEndpoint>().unwrap(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
        persistent_keepalive: None,
        has_preshared_key: false,
    }
    .try_into()
    .unwrap()
}
fn owner(user: &str, inside: IpAddr) -> NatBinding {
    NatBinding {
        device: Endpoint::new(
            NetworkId::new(user).unwrap(),
            DeviceId::new("phone").unwrap(),
        ),
        home: NodeId::new("home").unwrap(),
        prefix: if inside.is_ipv4() {
            "0.0.0.0/0"
        } else {
            "::/0"
        }
        .parse()
        .unwrap(),
        inside,
    }
}

// A byte-at-a-time reference checksum, independent of the translator. Input to
// UDP/TCP/ICMPv6 verification includes the wire pseudo-header.
fn reference(bytes: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (index, &byte) in bytes.iter().enumerate() {
        let n = u16::from(byte) << if index % 2 == 0 { 8 } else { 0 };
        let (s, carry) = sum.overflowing_add(n);
        sum = s + u16::from(carry);
    }
    !sum
}
fn make_packet(src: IpAddr, dst: IpAddr, proto: u8, mut l4: Vec<u8>) -> Vec<u8> {
    let mut ph = Vec::new();
    let mut h = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ph.extend(s.octets());
            ph.extend(d.octets());
            ph.extend([0, proto]);
            ph.extend((l4.len() as u16).to_be_bytes());
            let mut v = vec![0x45, 0, 0, 0, 0, 42, 0x40, 0, 64, proto, 0, 0];
            v.extend(s.octets());
            v.extend(d.octets());
            v[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
            let sum = reference(&v);
            v[10..12].copy_from_slice(&sum.to_be_bytes());
            v
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ph.extend(s.octets());
            ph.extend(d.octets());
            ph.extend((l4.len() as u32).to_be_bytes());
            ph.extend([0, 0, 0, proto]);
            let mut v = vec![0x60, 0, 0, 0];
            v.extend((l4.len() as u16).to_be_bytes());
            v.extend([proto, 64]);
            v.extend(s.octets());
            v.extend(d.octets());
            v
        }
        _ => panic!("test mixed address families"),
    };
    if proto == 1 {
        ph.clear();
    }
    let offset = match proto {
        6 => 16,
        17 => 6,
        _ => 2,
    };
    l4[offset..offset + 2].fill(0);
    ph.extend(&l4);
    let c = reference(&ph);
    l4[offset..offset + 2]
        .copy_from_slice(&(if proto == 17 && c == 0 { u16::MAX } else { c }).to_be_bytes());
    h.extend(l4);
    h
}
fn udp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::from(sport.to_be_bytes());
    b.extend(dport.to_be_bytes());
    b.extend(((8 + body.len()) as u16).to_be_bytes());
    b.extend([0; 2]);
    b.extend(body);
    make_packet(src, dst, 17, b)
}
fn fix_ipv4(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let c = reference(&packet[..20]);
    packet[10..12].copy_from_slice(&c.to_be_bytes());
}
fn forwarded(mut packet: Vec<u8>) -> Vec<u8> {
    if packet[0] >> 4 == 4 {
        packet[8] -= 1;
        fix_ipv4(&mut packet);
    } else {
        packet[7] -= 1;
    }
    packet
}
fn provider(action: Option<NatAction>) -> PacketBytes {
    let Some(NatAction::ToProvider(p)) = action else {
        panic!("expected provider packet")
    };
    p
}
fn reply(action: Option<NatAction>) -> (NatBinding, IpAddr, PacketBytes) {
    let Some(NatAction::ToDevice {
        binding,
        remote,
        packet,
    }) = action
    else {
        panic!("expected device packet")
    };
    (binding, remote, packet)
}
#[test]
fn overlapping_udp_flows_require_the_right_provider_and_remote_and_preserve_the_other_user() {
    let mut table = NatTable::default();
    let p = profile();
    let now = Instant::now();
    let alice = owner("alice", ip(INSIDE));
    let boris = owner("boris", ip(INSIDE));
    let request = udp(ip(INSIDE), ip(REMOTE), 4534, 53, b"hello");
    let mut ports = Vec::new();
    for user in [&alice, &boris] {
        let out = provider(table.outbound(&p, user, &request, 1280, now));
        let port = u16::from_be_bytes(out.as_bytes()[20..22].try_into().unwrap());
        assert_eq!(
            out.as_bytes(),
            forwarded(udp(ip(TUNNEL), ip(REMOTE), port, 53, b"hello"))
        );
        ports.push(port);
    }
    assert_ne!(ports[0], ports[1]);
    let wrong = udp(ip("198.51.100.23"), ip(TUNNEL), 53, ports[0], b"bad");
    assert!(table.inbound(&p, &wrong, 1280, now).is_none());
    let wrong = udp(ip(REMOTE), ip(TUNNEL), 55, ports[0], b"bad");
    assert!(table.inbound(&p, &wrong, 1280, now).is_none());
    let good = |port| udp(ip(REMOTE), ip(TUNNEL), 53, port, b"reply!");
    table.retain(now, |_, owner, _| owner != &alice);
    assert!(table.inbound(&p, &good(ports[0]), 1280, now).is_none());
    let (who, remote, inner) = reply(table.inbound(&p, &good(ports[1]), 1280, now));
    assert_eq!(who, boris);
    assert_eq!(remote, ip(REMOTE));
    assert_eq!(
        inner.as_bytes(),
        forwarded(udp(ip(REMOTE), ip(INSIDE), 53, 4534, b"reply!"))
    );
    assert!(
        table
            .inbound(&p, &good(ports[1]), 1280, now + Duration::from_secs(120))
            .is_none()
    );
}

fn address_families() -> [(IpAddr, IpAddr, IpAddr, IpAddr); 2] {
    [
        (ip(INSIDE), ip(TUNNEL), ip(REMOTE), ip("203.0.113.7")),
        (
            ip("fd01::4"),
            ip("fd80::6"),
            ip("2001:db8:1::22"),
            ip("2001:db8:2::7"),
        ),
    ]
}
fn offset(address: IpAddr) -> usize {
    if address.is_ipv4() { 20 } else { 40 }
}
fn get_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([bytes[off], bytes[off + 1]])
}
fn tcp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, flags: u8, options: &[u8]) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = ((20 + options.len()) as u8 / 4) << 4;
    l4[13] = flags;
    l4[14..16].copy_from_slice(&8192u16.to_be_bytes());
    l4.extend(options);
    make_packet(src, dst, 6, l4)
}
fn echo(src: IpAddr, dst: IpAddr, request: bool, id: u16) -> Vec<u8> {
    let ty = match (src.is_ipv4(), request) {
        (true, true) => 8,
        (true, false) => 0,
        (false, true) => 128,
        (false, false) => 129,
    };
    let mut b = vec![ty, 0, 0, 0];
    b.extend(id.to_be_bytes());
    b.extend([0, 1, 1, 23, 45, 67, 89]);
    make_packet(src, dst, if src.is_ipv4() { 1 } else { 58 }, b)
}
fn error_packet(src: IpAddr, dst: IpAddr, header: [u8; 8], quote: &[u8]) -> Vec<u8> {
    let mut b = header.to_vec();
    b.extend(quote);
    make_packet(src, dst, if src.is_ipv4() { 1 } else { 58 }, b)
}

#[test]
fn tcp_checks_open_handshake_lifetimes_and_clamps_mss_on_both_syn_segments() {
    let p = profile();
    let now = Instant::now();
    for (inside, external, remote, _) in address_families() {
        let mut table = NatTable::default();
        let user = owner("alice", inside);
        let h = offset(inside);
        let mtu = if inside.is_ipv4() { 1100 } else { 1280 };
        let limit: u16 = if inside.is_ipv4() { 1060 } else { 1220 };
        let options = |value: u16| {
            let [a, b] = value.to_be_bytes();
            [1, 2, 4, a, b, 1, 0, 0]
        };
        let outgoing = |flags, options: &[u8]| tcp(inside, remote, 15000, 443, flags, options);
        let incoming =
            |port, flags, options: &[u8]| tcp(remote, external, 443, port, flags, options);
        assert!(
            table
                .outbound(&p, &user, &outgoing(ACK, &[]), mtu, now)
                .is_none()
        );
        assert!(
            table
                .outbound(&p, &user, &outgoing(SYN | FIN, &[]), mtu, now)
                .is_none()
        );
        assert!(
            table
                .outbound(&p, &user, &outgoing(SYN, &[2, 5, 0, 4]), mtu, now)
                .is_none()
        );
        assert!(table.forward.is_empty());
        let syn = provider(table.outbound(&p, &user, &outgoing(SYN, &options(1460)), mtu, now));
        let port = get_u16(syn.as_bytes(), h);
        assert_eq!(
            syn.as_bytes(),
            forwarded(tcp(external, remote, port, 443, SYN, &options(limit)))
        );
        assert!(
            table
                .inbound(&p, &incoming(port, ACK, &[]), mtu, now)
                .is_none()
        );
        assert!(
            table
                .outbound(&p, &user, &outgoing(ACK, &[]), mtu, now)
                .is_none()
        );
        let (_, _, syn_ack) =
            reply(table.inbound(&p, &incoming(port, SYN | ACK, &options(1450)), mtu, now));
        assert_eq!(
            syn_ack.as_bytes(),
            forwarded(tcp(remote, inside, 443, 15000, SYN | ACK, &options(limit)))
        );
        provider(table.outbound(&p, &user, &outgoing(ACK, &[]), mtu, now));
        let established = now + Duration::from_secs(7199);
        reply(table.inbound(&p, &incoming(port, FIN | ACK, &[]), mtu, established));
        assert!(
            table
                .inbound(
                    &p,
                    &incoming(port, ACK, &[]),
                    mtu,
                    established + Duration::from_secs(120)
                )
                .is_none()
        );
        let late = established + Duration::from_secs(121);
        let syn = provider(table.outbound(&p, &user, &outgoing(SYN, &options(900)), mtu, late));
        let port = get_u16(syn.as_bytes(), h);
        assert_eq!(
            syn.as_bytes(),
            forwarded(tcp(external, remote, port, 443, SYN, &options(900)))
        );
        assert!(
            table
                .inbound(
                    &p,
                    &incoming(port, SYN | ACK, &[]),
                    mtu,
                    late + Duration::from_secs(60)
                )
                .is_none()
        );
    }
}

#[test]
fn malformed_packets_and_unsupported_headers_never_open_or_extend_a_flow() {
    let p = profile();
    let now = Instant::now();
    for (inside, external, remote, _) in address_families() {
        let mut table = NatTable::default();
        let user = owner("alice", inside);
        let h = offset(inside);
        let valid = udp(inside, remote, 3499, 80, b"12345");
        let mut truncated = valid.clone();
        truncated.pop();
        let mut bad_length = valid.clone();
        bad_length[h + 5] -= 1;
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut bad_checksum = valid.clone();
        bad_checksum[h + 8] ^= 1;
        let mut expired = valid.clone();
        let mut fragment = valid.clone();
        let mut extended = valid.clone();
        if inside.is_ipv4() {
            expired[8] = 1;
            fragment[6] = 0x20;
            extended[0] = 0x46;
            for b in [&mut expired, &mut fragment, &mut extended] {
                fix_ipv4(b);
            }
        } else {
            expired[7] = 1;
            fragment[6] = 44;
            extended[6] = 0;
        }
        for packet in [
            truncated,
            bad_length,
            trailing,
            bad_checksum.clone(),
            expired,
            fragment,
            extended,
            udp(inside, external, 3499, 80, b""),
            udp(remote, inside, 3499, 80, b""),
        ] {
            assert!(table.outbound(&p, &user, &packet, 1280, now).is_none());
        }
        assert!(table.forward.is_empty());
        let mut no_sum = valid.clone();
        no_sum[h + 6..h + 8].fill(0);
        if inside.is_ipv4() {
            let packet = provider(table.outbound(&p, &user, &no_sum, 1280, now));
            assert_eq!(get_u16(packet.as_bytes(), h + 6), 0);
        } else {
            assert!(table.outbound(&p, &user, &no_sum, 1280, now).is_none());
        }
        let packet = provider(table.outbound(&p, &user, &valid, 1280, now));
        let port = get_u16(packet.as_bytes(), h);
        assert_eq!(
            packet.as_bytes(),
            forwarded(udp(external, remote, port, 80, b"12345"))
        );
        let last = now + Duration::from_secs(119);
        assert!(
            table
                .outbound(&p, &user, &bad_checksum, 1280, last)
                .is_none()
        );
        let mut invalid = udp(remote, external, 80, port, b"reply");
        invalid[h + 8] ^= 1;
        assert!(table.inbound(&p, &invalid, 1280, last).is_none());
        assert!(
            table
                .inbound(
                    &p,
                    &udp(remote, external, 80, port, b"reply"),
                    1280,
                    now + Duration::from_secs(120)
                )
                .is_none()
        );
    }
}
#[test]
fn echo_identifiers_preserve_tenant_and_remote_and_expire_after_thirty_seconds() {
    let p = profile();
    let now = Instant::now();
    for (inside, external, remote, other) in address_families() {
        let mut table = NatTable::default();
        let alice = owner("alice", inside);
        let boris = owner("boris", inside);
        let mut ids = Vec::new();
        for user in [&alice, &boris] {
            assert!(
                table
                    .outbound(&p, user, &echo(inside, remote, false, 1234), 1280, now)
                    .is_none()
            );
            let request =
                provider(table.outbound(&p, user, &echo(inside, remote, true, 1234), 1280, now));
            let id = get_u16(request.as_bytes(), offset(inside) + 4);
            assert_eq!(
                request.as_bytes(),
                forwarded(echo(external, remote, true, id))
            );
            assert!(
                table
                    .inbound(&p, &echo(other, external, false, id), 1280, now)
                    .is_none()
            );
            let (binding, from, restored) =
                reply(table.inbound(&p, &echo(remote, external, false, id), 1280, now));
            assert_eq!((&binding, from), (user, remote));
            assert_eq!(
                restored.as_bytes(),
                forwarded(echo(remote, inside, false, 1234))
            );
            ids.push(id);
        }
        assert_ne!(ids[0], ids[1]);
        assert!(
            table
                .inbound(
                    &p,
                    &echo(remote, external, false, ids[0]),
                    1280,
                    now + Duration::from_secs(30)
                )
                .is_none()
        );
    }
}
#[test]
fn related_icmp_errors_repair_both_directions_and_do_not_refresh_state() {
    let p = profile();
    let now = Instant::now();
    for (inside, external, remote, router) in address_families() {
        let mut table = NatTable::default();
        let user = owner("alice", inside);
        let h = offset(inside);
        let request = udp(inside, remote, 12345, 53, b"odd payload");
        let translated = provider(table.outbound(&p, &user, &request, 1280, now));
        let port = get_u16(translated.as_bytes(), h);
        let answer = udp(remote, external, 53, port, b"reply!!");
        let (_, _, restored) = reply(table.inbound(&p, &answer, 1280, now));
        let header = if inside.is_ipv4() {
            [3, 4, 0, 0, 0, 0, 4, 176]
        } else {
            [2, 0, 0, 0, 0, 0, 5, 0]
        };
        for quote_len in [h + 8, translated.as_bytes().len()] {
            let delivered = error_packet(
                router,
                external,
                header,
                &translated.as_bytes()[..quote_len],
            );
            let late = now + Duration::from_secs(119);
            let (who, to, err) = reply(table.inbound(&p, &delivered, 1280, late));
            assert_eq!((&who, to), (&user, remote));
            assert_eq!(
                err.as_bytes(),
                forwarded(error_packet(
                    router,
                    inside,
                    header,
                    &forwarded(request.clone())[..quote_len]
                ))
            );
            assert_eq!(return_remote(err.as_bytes()), Some(remote));
        }
        let outgoing = error_packet(inside, remote, header, &restored.as_bytes()[..h + 8]);
        let restored_error =
            provider(table.outbound(&p, &user, &outgoing, 1280, now + Duration::from_secs(119)));
        assert_eq!(
            restored_error.as_bytes(),
            forwarded(error_packet(
                external,
                remote,
                header,
                &forwarded(answer)[..h + 8]
            ))
        );
        let short = error_packet(router, external, header, &translated.as_bytes()[..h + 7]);
        assert!(table.inbound(&p, &short, 1280, now).is_none());
        let wrong = error_packet(
            router,
            external,
            header,
            &udp(external, router, port, 53, b"forged"),
        );
        assert!(table.inbound(&p, &wrong, 1280, now).is_none());
        let wrong_owner = error_packet(
            router,
            inside,
            header,
            &udp(external, remote, port, 53, b"forged"),
        );
        assert!(return_remote(&wrong_owner).is_none());
        table.expire(now + Duration::from_secs(120));
        assert!(table.forward.is_empty());
        assert!(
            table
                .outbound(&p, &user, &outgoing, 1280, now + Duration::from_secs(120))
                .is_none()
        );
    }
}

#[test]
fn split_route_pmtu_uses_the_internal_gateway_even_when_device_and_provider_addresses_overlap() {
    let now = Instant::now();
    for (_, external, remote, _) in address_families() {
        let inside = external;
        let split = IpPrefix::host(remote);
        let mut fields = (*profile()).clone();
        fields.allowed_ips = vec![split];
        let p = EgressProfile::try_from(fields).unwrap();
        let mut table = NatTable::default();
        let mut user = owner("alice", inside);
        user.prefix = split;
        // The native home peer allows the internal pool and the split grant.
        // The provider's assigned address lies outside both prefixes.
        let (pool, gateway) = if inside.is_ipv4() {
            (IpPrefix::internal_v4(), IpAddr::V4(wgfeel_core::DNS_IPV4))
        } else {
            (IpPrefix::internal_v6(), IpAddr::V6(wgfeel_core::DNS_IPV6))
        };
        assert!(!pool.contains(external) && !split.contains(external));
        let h = offset(inside);
        let mtu = if inside.is_ipv4() { 1040 } else { 1280 };
        let body = vec![45; 1452];
        let oversize = udp(inside, remote, 3456, 53, &body);
        if inside.is_ipv4() {
            let mut no_df = oversize.clone();
            no_df[6] = 0;
            fix_ipv4(&mut no_df);
            assert!(table.outbound(&p, &user, &no_df, mtu, now).is_none());
        } else {
            assert!(table.outbound(&p, &user, &oversize, 1279, now).is_none());
        }
        let header = if inside.is_ipv4() {
            [3, 4, 0, 0, 0, 0, 4, 16]
        } else {
            [2, 0, 0, 0, 0, 0, 5, 0]
        };
        for _ in 0..PMTU_BURST {
            let (who, dest, msg) = reply(table.outbound(&p, &user, &oversize, mtu, now));
            assert_eq!((who, dest), (user.clone(), remote));
            let (src, dst) = crate::forwarding::addresses(msg.as_bytes()).unwrap();
            assert_eq!((src, dst), (gateway, inside));
            assert!(pool.contains(src));
            assert_eq!(return_remote(msg.as_bytes()), Some(remote));
            let expected_len = if inside.is_ipv4() { 576 } else { 1280 };
            let mut expected =
                error_packet(gateway, inside, header, &oversize[..expected_len - h - 8]);
            if inside.is_ipv4() {
                // Locally originated errors carry zero IP identification and no DF bit.
                expected[4..8].fill(0);
                fix_ipv4(&mut expected);
            }
            assert_eq!(msg.as_bytes(), expected);
        }
        assert!(table.forward.is_empty());
        assert!(table.outbound(&p, &user, &oversize, mtu, now).is_none());
        let next = now + Duration::from_secs(1);
        let small = udp(inside, remote, 3456, 53, b"ok");
        let out = provider(table.outbound(&p, &user, &small, mtu, next));
        let port = get_u16(out.as_bytes(), h);
        assert!(
            table
                .inbound(&p, &udp(remote, external, 54, port, &body), mtu, next)
                .is_none()
        );
        let oversize_reply = udp(remote, external, 53, port, &body);
        let error = provider(table.inbound(&p, &oversize_reply, mtu, next));
        assert_eq!(
            crate::forwarding::addresses(error.as_bytes()).unwrap(),
            (external, remote)
        );
        assert_eq!(
            &error.as_bytes()[h + 8..],
            &oversize_reply[..error.as_bytes().len() - h - 8]
        );
        assert_eq!(return_remote(error.as_bytes()), Some(external));
    }
}

#[test]
fn quota_preserves_existing_users_and_external_tuples_remain_quarantined() {
    let p = profile();
    let now = Instant::now();
    let inside = ip(INSIDE);
    let remote = ip(REMOTE);
    let external = ip(TUNNEL);
    let mut table = NatTable::default();
    let alice = owner("alice", inside);
    let boris = owner("boris", inside);
    let other =
        provider(table.outbound(&p, &boris, &udp(inside, remote, 9000, 80, b"b"), 1280, now));
    let stable = get_u16(other.as_bytes(), 20);
    let mut first = 0;
    for port in 1..=1024 {
        let out =
            provider(table.outbound(&p, &alice, &udp(inside, remote, port, 80, b"a"), 1280, now));
        if port == 1 {
            first = get_u16(out.as_bytes(), 20);
        }
    }
    assert!(
        table
            .outbound(&p, &alice, &udp(inside, remote, 1025, 80, b"a"), 1280, now)
            .is_none()
    );
    assert_eq!(
        reply(table.inbound(&p, &udp(remote, external, 80, stable, b"c"), 1280, now)).0,
        boris
    );
    table.retain(now, |_, owner, _| owner != &alice);
    assert_eq!(table.forward.len(), 1);
    table.next_port = first;
    assert!(
        table
            .outbound(&p, &alice, &udp(inside, remote, 30000, 80, b"a"), 1280, now)
            .is_none()
    );
    // All 128 bounded candidates are held during the reuse quarantine.
    assert_eq!(table.next_port, first + 128);
    assert!(
        table
            .inbound(&p, &udp(remote, external, 80, first, b"late"), 1280, now)
            .is_none()
    );
    let late = now + REUSE_DELAY;
    table.expire(late);
    table.next_port = first;
    let fresh = provider(table.outbound(
        &p,
        &alice,
        &udp(inside, remote, 30000, 80, b"a"),
        1280,
        late,
    ));
    assert_eq!(get_u16(fresh.as_bytes(), 20), first);
}

#[test]
fn short_tcp_error_quotes_require_the_matching_family_egress_and_destination_port() {
    let p = profile();
    let mut fields = (*p).clone();
    fields.id = EgressId::new("backup").unwrap();
    let other = EgressProfile::try_from(fields).unwrap();
    let now = Instant::now();
    for (inside, external, remote, router) in address_families() {
        let mut table = NatTable::default();
        let user = owner("alice", inside);
        let h = offset(inside);
        let syn = tcp(inside, remote, 3456, 443, SYN, &[]);
        let out = provider(table.outbound(&p, &user, &syn, 1280, now));
        let header = if inside.is_ipv4() {
            [11, 0, 0, 0, 0, 0, 0, 0]
        } else {
            [3, 0, 0, 0, 0, 0, 0, 0]
        };
        for n in [8, 16, 18, 20] {
            let error = error_packet(router, external, header, &out.as_bytes()[..h + n]);
            assert!(table.inbound(&other, &error, 1280, now).is_none());
            let (_, _, msg) = reply(table.inbound(&p, &error, 1280, now));
            assert_eq!(
                msg.as_bytes(),
                forwarded(error_packet(
                    router,
                    inside,
                    header,
                    &forwarded(syn.clone())[..h + n]
                ))
            );
        }
        let malformed = error_packet(router, external, header, &out.as_bytes()[..h + 17]);
        assert!(table.inbound(&p, &malformed, 1280, now).is_none());
        let wrong = tcp(external, remote, get_u16(out.as_bytes(), h), 444, SYN, &[]);
        assert!(
            table
                .inbound(
                    &p,
                    &error_packet(router, external, header, &wrong[..h + 8]),
                    1280,
                    now
                )
                .is_none()
        );
    }
}

#[test]
fn pmtu_feedback_requires_valid_flow_direction_and_open_state() {
    let p = profile();
    let now = Instant::now();
    let mut table = NatTable::default();
    let (inside, external, remote, _) = address_families()[0];
    let user = owner("alice", inside);
    let syn = tcp(inside, remote, 2211, 443, SYN, &[]);
    let out = provider(table.outbound(&p, &user, &syn, 576, now));
    let port = get_u16(out.as_bytes(), 20);
    for (src, dst, sport, dport, outbound) in [
        (remote, external, 443, port, false),
        (inside, remote, 9999, 443, true),
    ] {
        let ack = tcp(src, dst, sport, dport, ACK, &[]);
        let mut segment = ack[20..].to_vec();
        segment.resize(600, 9);
        let oversized = make_packet(src, dst, 6, segment);
        let result = if outbound {
            table.outbound(&p, &user, &oversized, 576, now)
        } else {
            table.inbound(&p, &oversized, 576, now)
        };
        assert!(result.is_none());
    }
}

#[test]
fn outbound_addresses_must_be_covered_by_the_winning_rule_and_provider() {
    let p = profile();
    let mut fields = (*p).clone();
    fields.allowed_ips = vec!["203.0.113.0/24".parse().unwrap()];
    let limited = EgressProfile::try_from(fields).unwrap();
    let now = Instant::now();
    let mut table = NatTable::default();
    let inside = ip(INSIDE);
    let remote = ip(REMOTE);
    let mut user = owner("alice", inside);
    let packet = udp(inside, remote, 3456, 80, b"ok");
    assert!(
        table
            .outbound(&limited, &user, &packet, 1280, now)
            .is_none()
    );
    user.prefix = "203.0.113.0/24".parse().unwrap();
    assert!(table.outbound(&p, &user, &packet, 1280, now).is_none());
}

#[test]
fn discarding_one_egress_clears_its_live_and_quarantined_tuples_only() {
    let mut table = NatTable::default();
    let first = profile();
    let mut fields = (*first).clone();
    fields.id = EgressId::new("second").unwrap();
    let second: EgressProfile = fields.try_into().unwrap();
    let now = Instant::now();
    let active = owner("alice", ip(INSIDE));
    let withdrawn = owner("boris", ip(INSIDE));
    let outgoing = udp(ip(INSIDE), ip(REMOTE), 7777, 53, b"query");
    let mut ports = Vec::new();
    for exit in [&first, &second] {
        for device in [&active, &withdrawn] {
            let packet = provider(table.outbound(exit, device, &outgoing, 1280, now));
            ports.push(get_u16(packet.as_bytes(), 20));
        }
    }
    // Each provider now has one live flow and one previously quarantined slot.
    table.retain(now, |_, binding, _| binding != &withdrawn);
    assert_eq!((table.forward.len(), table.quarantine.len()), (2, 2));
    table.discard_egress(&first.id);
    table.discard_egress(&first.id);
    assert_eq!(
        (
            table.forward.len(),
            table.reverse.len(),
            table.deadlines.len()
        ),
        (1, 1, 1)
    );
    assert_eq!((table.quarantine.len(), table.reusable.len()), (1, 1));
    assert!(table.quarantine.iter().all(|slot| slot.egress == second.id));
    assert!(
        table
            .reusable
            .iter()
            .all(|(_, slot)| slot.egress == second.id)
    );
    assert_eq!(table.users.get(active.device.network()), Some(&1));
    assert!(!table.egress_counts.contains_key(&first.id));
    assert_eq!(table.egress_counts.get(&second.id), Some(&1));

    let inbound = |port| udp(ip(REMOTE), ip(TUNNEL), 53, port, b"reply");
    assert!(
        table
            .inbound(&first, &inbound(ports[0]), 1280, now)
            .is_none()
    );
    let (binding, _, packet) = reply(table.inbound(&second, &inbound(ports[2]), 1280, now));
    assert_eq!(binding, active);
    assert_eq!(
        packet.as_bytes(),
        forwarded(udp(ip(REMOTE), ip(INSIDE), 53, 7777, b"reply"))
    );
    // A fresh provider incarnation may immediately reuse the retired namespace.
    table.next_port = ports[1];
    let opened = provider(table.outbound(&first, &active, &outgoing, 1280, now));
    assert_eq!(get_u16(opened.as_bytes(), 20), ports[1]);
}
