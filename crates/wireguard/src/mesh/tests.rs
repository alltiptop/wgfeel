use super::*;
use wgfeel_core::{
    Config, Device, DevicePublicKey, ManagementConfig, Network, Policy, TenantKeyAssignment,
};
fn id(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn net(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn ep(network: &str, device: &str) -> Endpoint {
    Endpoint::new(net(network), DeviceId::new(device).unwrap())
}
fn models() -> Vec<Mesh> {
    models_with_transit(wgfeel_core::TrafficMode::Entry)
}
fn models_with_transit(mode: wgfeel_core::TrafficMode) -> Vec<Mesh> {
    models_at_revision(mode, 10)
}
fn models_at_revision(mode: wgfeel_core::TrafficMode, generation: u64) -> Vec<Mesh> {
    models_with_policy(mode, generation, wgfeel_core::EgressPolicy::default())
}
fn models_with_policy(
    mode: wgfeel_core::TrafficMode,
    generation: u64,
    policy: wgfeel_core::EgressPolicy,
) -> Vec<Mesh> {
    let networks = ["alice", "bob"]
        .iter()
        .enumerate()
        .map(|(index, name)| {
            Network::new(
                net(name),
                vec![
                    Device::new(
                        DeviceId::new("phone").unwrap(),
                        DevicePublicKey::new([61 + index as u8; 32]).unwrap(),
                        vec!["10.203.1.2".parse().unwrap()],
                    )
                    .unwrap()
                    .with_gateway(Some(id("a"))),
                    Device::new(
                        DeviceId::new("laptop").unwrap(),
                        DevicePublicKey::new([71 + index as u8; 32]).unwrap(),
                        vec!["10.203.1.3".parse().unwrap()],
                    )
                    .unwrap()
                    .with_gateway(Some(id("c"))),
                ],
            )
            .unwrap()
            .with_private_lan(true)
        })
        .collect();
    let nodes = ["a", "b", "c"]
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let node = GatewayAssignment::new(
                id(name),
                (DevicePublicKey::new([11 + index as u8; 32]).unwrap()).clone(),
                wgfeel_test_support::fixture_gateway_public(
                    &(DevicePublicKey::new([11 + index as u8; 32]).unwrap()),
                ),
                vec![net("alice"), net("bob")],
                vec![
                    TenantKeyAssignment::new(
                        net("alice"),
                        DevicePublicKey::new([21 + index as u8; 32]).unwrap(),
                    ),
                    TenantKeyAssignment::new(
                        net("bob"),
                        DevicePublicKey::new([31 + index as u8; 32]).unwrap(),
                    ),
                ],
            )
            .unwrap();
            let node = if *name == "b" && mode != wgfeel_core::TrafficMode::Entry {
                node.with_scope(
                    if mode.carries_user_traffic() {
                        vec![net("alice"), net("bob")]
                    } else {
                        vec![]
                    },
                    vec![],
                )
                .unwrap()
                .with_traffic(mode)
                .unwrap()
            } else {
                node
            };
            node.with_endpoint(Some(
                format!("127.0.0.1:{}", 10000 + index).parse().unwrap(),
            ))
            .unwrap()
        })
        .collect();
    let routing = ManagementConfig::new(
        id("management"),
        Config::new(generation, networks, Policy::new(vec![], vec![], vec![])).unwrap(),
        nodes,
    )
    .unwrap();
    let routing = routing.with_egress_policy(policy).unwrap();
    ["a", "b", "c"]
        .iter()
        .enumerate()
        .map(|(index, name)| {
            Mesh::new(
                &routing.project_mesh_for(&id(name)).unwrap(),
                index as u64 * 1000 + 1,
            )
        })
        .collect()
}
fn pump(
    models: &mut [Mesh],
    links: &[[bool; 3]; 3],
    queue: Vec<(usize, Action)>,
    now: Duration,
) -> Vec<Action> {
    let mut queue: VecDeque<_> = queue.into();
    let mut terminal = vec![];
    let mut steps = 0;
    while let Some((from, action)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 10000, "unbounded control flood");
        if let Action::Send { node, packet } = action {
            let target = ["a", "b", "c"]
                .iter()
                .position(|value| *value == node.as_str())
                .unwrap();
            if links[from][target] {
                let source = id(["a", "b", "c"][from]);
                queue.extend(
                    models[target]
                        .receive(
                            &source,
                            format!("127.0.0.1:{}", 10000 + from).parse().unwrap(),
                            packet.as_bytes(),
                            now,
                        )
                        .into_iter()
                        .map(|action| (target, action)),
                );
            }
        } else if matches!(action, Action::Deliver { .. } | Action::Wire { .. }) {
            terminal.push(action);
        }
    }
    terminal
}
fn advance(models: &mut [Mesh], links: &[[bool; 3]; 3], from: u64, until: u64) {
    for millis in (from..=until).step_by(100) {
        let now = Duration::from_millis(millis);
        let queue = models
            .iter_mut()
            .enumerate()
            .flat_map(|(index, model)| {
                model
                    .tick(now)
                    .into_iter()
                    .map(move |action| (index, action))
            })
            .collect();
        pump(models, links, queue, now);
    }
}
#[test]
fn topology_updates_have_a_hop_budget_and_restart_after_the_previous_lease() {
    let mut nodes = models();
    let now = Duration::from_secs(1);
    let mut source = nodes.remove(0);
    let mut middle = nodes.remove(0);
    for node in [&mut source, &mut middle] {
        for (index, peer) in node.peers.iter_mut().enumerate() {
            if Some(index) != node.own {
                peer.pong = Some(now);
            }
        }
    }
    let send_update = |source: &mut Mesh, now| {
        source
            .tick(now)
            .into_iter()
            .find_map(|action| {
                if let Action::Send { node, packet } = action
                    && node == id("b")
                    && decode(packet.as_bytes()).unwrap().1 == 3
                {
                    return Some(packet);
                }
                None
            })
            .unwrap()
    };
    let receive = |middle: &mut Mesh, packet: &PacketBytes, now| {
        middle.receive(
            &id("a"),
            "127.0.0.1:10000".parse().unwrap(),
            packet.as_bytes(),
            now,
        )
    };
    let packet = send_update(&mut source, now);
    let forwarded = receive(&mut middle, &packet, now);
    let [Action::Send { packet: next, .. }] = forwarded.as_slice() else {
        panic!("expected one forwarded advertisement");
    };
    assert_eq!(next.as_bytes()[8] + 1, packet.as_bytes()[8]);
    let mut restarted = Mesh::new(&source.projection, 999);
    restarted.peers[1].pong = Some(now);
    let after_restart = send_update(&mut restarted, now);
    receive(&mut middle, &after_restart, now);
    assert_eq!(middle.advertisements[0].as_ref().unwrap().boot, source.boot);
    receive(&mut middle, &after_restart, now + LSA_LEASE);
    assert_eq!(
        middle.advertisements[0].as_ref().unwrap().boot,
        restarted.boot
    );
    receive(&mut middle, &packet, now + LSA_LEASE);
    assert_eq!(
        middle.advertisements[0].as_ref().unwrap().boot,
        restarted.boot
    );
}

#[test]
fn relay_carries_tenant_ciphertext_without_keys_while_off_keeps_only_control_paths() {
    for mode in [
        wgfeel_core::TrafficMode::Relay,
        wgfeel_core::TrafficMode::Off,
    ] {
        let mut models = models_with_transit(mode);
        let links = [[true, true, false], [true, true, true], [false, true, true]];
        advance(&mut models, &links, 0, 6500);
        let now = Duration::from_millis(6500);
        assert_eq!(
            models[0].next_hop(&id("c"), now),
            Some(id("b")),
            "control route through {mode:?}"
        );
        assert!(models[1].projection.assignment().tenants().is_empty());
        let mut ciphertext = vec![42; MAX_DATAGRAM_SIZE];
        ciphertext[..4].copy_from_slice(&[4, 0, 0, 0]);
        let frames = models[0].transmit(
            &net("alice"),
            &id("c"),
            &ciphertext,
            Some(Traffic {
                source: ep("alice", "phone"),
                destination: ep("alice", "laptop"),
            }),
            now,
        );
        if mode == wgfeel_core::TrafficMode::Off {
            assert!(
                frames.is_empty(),
                "off node must never provide a user route"
            );
        } else {
            let delivered = pump(
                &mut models,
                &links,
                frames.into_iter().map(|action| (0, action)).collect(),
                now,
            );
            assert_eq!(delivered.len(), 1);
            let Action::Deliver { packet, .. } = &delivered[0] else {
                panic!("expected opaque tenant delivery")
            };
            assert_eq!(packet.as_bytes(), ciphertext);
        }
    }
}

#[test]
fn mesh_rotates_ip_families_and_sends_data_only_to_the_confirmed_path() {
    let mut models = models();
    let mesh = &mut models[0];
    let ipv4: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    let ipv6: SocketAddr = "[::1]:10002".parse().unwrap();
    mesh.peers[2].assignment = mesh.peers[2]
        .assignment
        .clone()
        .with_endpoints(vec![ipv4, ipv6])
        .unwrap();
    let initiation = |actions: Vec<Action>| {
        actions.into_iter().find_map(|action| match action {
            Action::Initiate { node, endpoint } if node == id("c") => Some(endpoint),
            _ => None,
        })
    };
    assert_eq!(initiation(mesh.tick(Duration::ZERO)), Some(ipv4));
    let now = Duration::from_secs(2);
    assert_eq!(initiation(mesh.tick(now)), Some(ipv6));
    let nonce = mesh.peers[2].nonce.unwrap();
    mesh.receive(
        &id("c"),
        ipv6,
        encode(10, 2, &nonce.wrapping_add(1).to_le_bytes()).as_bytes(),
        now,
    );
    assert_eq!(mesh.next_hop(&id("c"), now), None);
    mesh.receive(
        &id("c"),
        ipv6,
        encode(10, 2, &nonce.to_le_bytes()).as_bytes(),
        now,
    );
    assert_eq!(mesh.next_hop(&id("c"), now), Some(id("c")));
    assert_eq!(initiation(mesh.tick(Duration::from_secs(3))), None);
    let mut ciphertext = vec![42; 64];
    ciphertext[..4].copy_from_slice(&[4, 0, 0, 0]);
    let traffic = Traffic {
        source: ep("alice", "phone"),
        destination: ep("alice", "laptop"),
    };
    let wire = mesh.transmit(
        &net("alice"),
        &id("c"),
        &ciphertext,
        Some(traffic.clone()),
        now,
    );
    assert!(matches!(&wire[..], [Action::Wire { endpoint, .. }] if *endpoint == ipv6));
    // Once IPv6 stops answering, the next attempt returns to IPv4. Payloads
    // remain unavailable until a fresh, authenticated probe confirms it.
    let now = Duration::from_secs(6);
    assert_eq!(initiation(mesh.tick(now)), Some(ipv4));
    assert!(
        mesh.transmit(
            &net("alice"),
            &id("c"),
            &ciphertext,
            Some(traffic.clone()),
            now
        )
        .is_empty()
    );
    let nonce = mesh.peers[2].nonce.unwrap();
    mesh.receive(
        &id("c"),
        ipv4,
        encode(10, 2, &nonce.to_le_bytes()).as_bytes(),
        now,
    );
    let wire = mesh.transmit(&net("alice"), &id("c"), &ciphertext, Some(traffic), now);
    assert!(matches!(&wire[..], [Action::Wire { endpoint, .. }] if *endpoint == ipv4));
}

#[test]
fn mesh_detects_direct_link_loss_relays_full_mtu_and_restores_direct_route() {
    let mut models = models();
    let mut links = [[true; 3]; 3];
    advance(&mut models, &links, 0, 2000);
    assert_eq!(
        models[0].next_hop(&id("c"), Duration::from_secs(2)),
        Some(id("c"))
    );
    links[0][2] = false;
    links[2][0] = false;
    advance(&mut models, &links, 2100, 6500);
    let now = Duration::from_millis(6500);
    assert_eq!(models[0].next_hop(&id("c"), now), Some(id("b")));
    let mut ciphertext = vec![42; MAX_DATAGRAM_SIZE];
    ciphertext[..4].copy_from_slice(&[4, 0, 0, 0]);
    let traffic = Traffic {
        source: ep("alice", "phone"),
        destination: ep("alice", "laptop"),
    };
    let frames = models[0].transmit(
        &net("alice"),
        &id("c"),
        &ciphertext,
        Some(traffic.clone()),
        now,
    );
    assert_eq!(frames.len(), 2);
    let mut result = pump(
        &mut models,
        &links,
        frames.into_iter().rev().map(|action| (0, action)).collect(),
        now,
    );
    assert_eq!(result.len(), 1);
    let Action::Deliver {
        network,
        origin,
        packet,
        traffic: received,
    } = result.pop().unwrap()
    else {
        panic!("relayed delivery")
    };
    assert_eq!(network, net("alice"));
    assert_eq!(origin, id("a"));
    assert_eq!(received, Some(MeshTraffic::Device(traffic)));
    assert_eq!(packet.as_bytes(), ciphertext);
    links[0][2] = true;
    links[2][0] = true;
    advance(&mut models, &links, 6600, 8500);
    assert_eq!(
        models[0].next_hop(&id("c"), Duration::from_millis(8500)),
        Some(id("c"))
    );
    links[0][1] = false;
    links[1][0] = false;
    links[0][2] = false;
    links[2][0] = false;
    advance(&mut models, &links, 8600, 12500);
    assert_eq!(
        models[0].next_hop(&id("c"), Duration::from_millis(12500)),
        None
    );
}
#[test]
fn relays_enforce_scope_home_bindings_and_acl_and_reject_control_data_confusion() {
    let mut models = models();
    let mut links = [[true; 3]; 3];
    links[0][2] = false;
    links[2][0] = false;
    advance(&mut models, &links, 0, 2000);
    let now = Duration::from_secs(2);
    let mut ciphertext = vec![42; 64];
    ciphertext[..4].copy_from_slice(&[4, 0, 0, 0]);
    let traffic = Traffic {
        source: ep("alice", "phone"),
        destination: ep("alice", "laptop"),
    };
    let mut relay = Relay {
        id: 9999,
        origin: 0,
        target: 2,
        network: net("alice"),
        traffic: Some(MeshTraffic::Device(traffic)),
        ttl: 3,
        total: 64,
    };
    relay.traffic = Some(MeshTraffic::Device(Traffic {
        source: ep("bob", "phone"),
        destination: ep("alice", "laptop"),
    }));
    assert!(!models[1].allowed(&relay, 0));
    relay.traffic = None;
    assert!(
        models[1]
            .receive(
                &id("a"),
                "127.0.0.1:10000".parse().unwrap(),
                relay_packet(10, &relay, 0, &ciphertext).as_bytes(),
                now
            )
            .is_empty()
    );
    relay.traffic = Some(MeshTraffic::Device(Traffic {
        source: ep("alice", "phone"),
        destination: ep("alice", "laptop"),
    }));
    relay.origin = 1;
    assert!(!models[1].allowed(&relay, 0));
    relay.origin = 0;
    let config = Config::new(
        10,
        models[1].projection.config().networks().to_vec(),
        Policy::new(
            vec![wgfeel_core::Rule::new(
                ep("alice", "phone"),
                ep("alice", "laptop"),
                Decision::Deny,
            )],
            vec![],
            vec![],
        ),
    )
    .unwrap();
    models[1].projection = ManagementConfig::new(
        id("management"),
        config,
        models[1].projection.mesh().to_vec(),
    )
    .unwrap()
    .project_mesh_for(&id("b"))
    .unwrap();
    assert!(
        models[1]
            .receive(
                &id("a"),
                "127.0.0.1:10000".parse().unwrap(),
                relay_packet(10, &relay, 0, &ciphertext).as_bytes(),
                now
            )
            .is_empty()
    );
    assert!(
        models[2]
            .receive(
                &id("b"),
                "127.0.0.1:10001".parse().unwrap(),
                relay_packet(9, &relay, 0, &ciphertext).as_bytes(),
                now
            )
            .is_empty()
    );
}
#[test]
fn relay_codec_is_bounded_for_maximum_identifiers_and_rejects_every_truncation() {
    let name = "x".repeat(64);
    let network = net(&name);
    let endpoint = Endpoint::new(network.clone(), DeviceId::new(&name).unwrap());
    for label in [
        MeshTraffic::Broadcast(BroadcastTraffic {
            source: endpoint.clone(),
            witness: endpoint.clone(),
        }),
        MeshTraffic::Device(Traffic {
            source: endpoint.clone(),
            destination: endpoint,
        }),
    ] {
        let relay = Relay {
            id: 1,
            origin: 0,
            target: 1,
            network: network.clone(),
            traffic: Some(label),
            ttl: 150,
            total: MAX_DATAGRAM_SIZE,
        };
        let packet = relay_packet(1, &relay, 0, &[42; CHUNK]);
        assert!(packet.as_bytes().len() <= crate::MAX_PLAINTEXT_SIZE);
        for length in 0..packet.as_bytes().len() {
            assert!(decode(&packet.as_bytes()[..length]).is_none());
        }
        let (_, kind, body) = decode(packet.as_bytes()).unwrap();
        assert!(read_relay(kind, body).is_some());
        for length in 0..body.len() {
            assert!(read_relay(kind, &body[..length]).is_none());
        }
    }
}

#[test]
fn route_selection_excludes_a_live_transit_outside_the_tenant_scope() {
    let mut models = models();
    let mut links = [[true; 3]; 3];
    links[0][2] = false;
    links[2][0] = false;
    advance(&mut models, &links, 0, 2000);
    let now = Duration::from_secs(2);
    assert_eq!(models[0].next_hop(&id("c"), now), Some(id("b")));
    let restricted = models[0].peers[1]
        .assignment
        .clone()
        .with_scope(
            vec![net("bob")],
            vec![TenantKeyAssignment::new(
                net("bob"),
                DevicePublicKey::new([32; 32]).unwrap(),
            )],
        )
        .unwrap();
    models[0].peers[1].assignment = restricted;
    assert_eq!(models[0].route(2, Some(&net("alice")), now), None);
    assert_eq!(models[0].route(2, Some(&net("bob")), now), Some(1));
}

#[test]
fn rolling_revision_preserves_direct_probes_and_expires_old_indexed_routes() {
    let links = [[true; 3]; 3];
    let mut nodes = models();
    advance(&mut nodes, &links, 0, 2000);
    let mut updated = models_at_revision(wgfeel_core::TrafficMode::Entry, 11).remove(0);
    updated.inherit_health(&nodes[0]);
    assert_eq!(
        updated.next_hop(&id("b"), Duration::from_secs(2)),
        Some(id("b"))
    );
    assert!(updated.advertisements.iter().all(Option::is_none));
    let last_old_advertisement = nodes[1].advertisements[0].as_ref().unwrap().received;
    nodes[0] = updated;
    advance(&mut nodes, &links, 2100, 8000);
    for (index, neighbor) in [(0, "b"), (1, "a")] {
        assert_eq!(
            nodes[index].next_hop(&id(neighbor), Duration::from_secs(8)),
            Some(id(neighbor))
        );
    }
    assert!(nodes[0].advertisements[1].is_none());
    assert_eq!(
        nodes[1].advertisements[0].as_ref().unwrap().received,
        last_old_advertisement
    );
}

#[test]
fn fragments_with_different_remaining_hops_reassemble_only_inside_their_revision() {
    let mut target = models().remove(2);
    let mut data = vec![0; MAX_DATAGRAM_SIZE];
    data[0] = 4;
    let mut relay = Relay {
        id: 17,
        origin: 0,
        target: 2,
        network: net("alice"),
        traffic: Some(MeshTraffic::Device(Traffic {
            source: ep("alice", "phone"),
            destination: ep("alice", "laptop"),
        })),
        ttl: 2,
        total: data.len(),
    };
    let now = Duration::from_secs(1);
    let from = id("b");
    let addr = "127.0.0.1:10001".parse().unwrap();
    let first = relay_packet(10, &relay, 0, &data[..CHUNK]);
    assert!(
        target
            .receive(&from, addr, first.as_bytes(), now)
            .is_empty()
    );
    relay.ttl = 1;
    let last = |generation| relay_packet(generation, &relay, 1, &data[CHUNK..]);
    assert!(
        target
            .receive(&from, addr, last(11).as_bytes(), now)
            .is_empty()
    );
    assert!(
        matches!(&target.receive(&from, addr, last(10).as_bytes(), now)[..],
        [Action::Deliver { packet, .. }] if packet.as_bytes() == data)
    );
}

#[test]
fn revision_preserves_the_next_probe_after_a_failed_secondary_endpoint() {
    let mut old = models().remove(0);
    let mut new = models_at_revision(wgfeel_core::TrafficMode::Entry, 11).remove(0);
    let active = old.peers[1].assignment.endpoints()[0];
    let second = "[2001:db8::2]:10001".parse().unwrap();
    let third = "192.0.2.3:10001".parse().unwrap();
    for mesh in [&mut old, &mut new] {
        mesh.peers[1].assignment = mesh.peers[1]
            .assignment
            .clone()
            .with_endpoints(vec![active, second, third])
            .unwrap();
    }
    let neighbor = id("b");
    let probe = |mesh: &mut Mesh, now| {
        mesh.tick(now).into_iter().find_map(|action| match action {
            Action::Initiate { node, endpoint } if node == neighbor => Some(endpoint),
            _ => None,
        })
    };
    assert_eq!(probe(&mut old, Duration::ZERO), Some(active));
    let nonce = old.peers[1].nonce.unwrap();
    old.receive(
        &neighbor,
        active,
        encode(10, 2, &nonce.to_le_bytes()).as_bytes(),
        Duration::ZERO,
    );
    assert_eq!(probe(&mut old, DEAD), Some(second));
    new.inherit_health(&old);
    assert_eq!(probe(&mut new, DEAD + Duration::from_secs(2)), Some(third));
}

#[test]
fn inherit_health_preserves_active_endpoint_when_secondary_endpoints_change() {
    let links = [[true; 3]; 3];
    let mut nodes = models();
    advance(&mut nodes, &links, 0, 2000);
    let old_mesh = nodes[0].projection.mesh().to_vec();
    let active = nodes[0].peers[1].active_endpoint.unwrap();
    let secondary: SocketAddr = "[2001:db8::2]:10001".parse().unwrap();
    let updated_nodes: Vec<_> = old_mesh
        .into_iter()
        .map(|node| {
            if node.recipient() == &id("b") {
                node.with_endpoints(vec![secondary, active]).unwrap()
            } else {
                node
            }
        })
        .collect();
    let projection = ManagementConfig::new(
        id("management"),
        Config::new(
            11,
            nodes[0].projection.config().networks().to_vec(),
            Policy::new(vec![], vec![], vec![]),
        )
        .unwrap(),
        updated_nodes,
    )
    .unwrap()
    .project_mesh_for(&id("a"))
    .unwrap();
    let mut updated = Mesh::new(&projection, 99);
    updated.inherit_health(&nodes[0]);
    assert_eq!(updated.peers[1].active_endpoint, Some(active));
    assert!(updated.peers[1].pong.is_some());
    assert_eq!(updated.peers[1].next_endpoint, 0);
}

#[test]
fn external_frames_use_canonical_prefix_and_960_byte_fragments() {
    let id = "x".repeat(64);
    let network = net(&id);
    let prefix: IpPrefix = "2001:db8::/32".parse().unwrap();
    for outbound in [false, true] {
        let relay = Relay {
            id: 44,
            origin: 1,
            target: 0,
            network: network.clone(),
            ttl: 2,
            total: 1312,
            traffic: Some(MeshTraffic::External(ExternalTraffic {
                direction: if outbound {
                    Direction::ToEgress
                } else {
                    Direction::FromEgress
                },
                device: Endpoint::new(network.clone(), DeviceId::new(&id).unwrap()),
                egress: EgressId::new(&id).unwrap(),
                prefix,
            })),
        };
        for (fragment, len) in [(0, 960), (1, 352)] {
            let bytes = relay_packet(12, &relay, fragment, &vec![1; len]);
            assert_eq!(bytes.as_bytes().len(), 263 + len);
            let (_, kind, body) = decode(bytes.as_bytes()).unwrap();
            assert_eq!(kind, if outbound { 5 } else { 6 });
            let (decoded, idx, data) = read_relay(kind, body).unwrap();
            assert_eq!(relay.traffic, decoded.traffic);
            assert_eq!((idx, data.len()), (fragment, len));
            let mut noncanonical = body.to_vec();
            noncanonical[12 + 195 + 2 + 15] = 1;
            assert!(read_relay(kind, &noncanonical).is_none());
            assert!(read_relay(kind, &body[..body.len() - 1]).is_none());
        }
    }
}

#[test]
fn typed_provider_traffic_uses_both_direct_and_relay_paths_and_honors_partition() {
    use wgfeel_core::{
        ClientId, EgressDnsSelection, EgressPolicy, EgressProfileFields, UserEgressAssignment,
        UserEgresses,
    };
    let egress = EgressId::new("provider").unwrap();
    let prefix: IpPrefix = "203.0.113.0/24".parse().unwrap();
    let profile = EgressProfileFields {
        id: egress.clone(),
        name: "provider".into(),
        node: Some(id("c")),
        pending_node: None,
        secret_revision: 1,
        interface_public_key: DevicePublicKey::new([67; 32]).unwrap(),
        peer_public_key: DevicePublicKey::new([99; 32]).unwrap(),
        endpoint: "192.0.2.3:51820".parse().unwrap(),
        addresses: vec!["172.20.0.2".parse().unwrap()],
        dns_servers: vec![],
        mtu: None,
        allowed_ips: vec![prefix],
        persistent_keepalive: None,
        has_preshared_key: false,
    }
    .try_into()
    .unwrap();
    let policy = EgressPolicy {
        profiles: vec![profile],
        users: vec![UserEgresses {
            user: ClientId::new("alice").unwrap(),
            network: net("alice"),
            egresses: vec![UserEgressAssignment {
                egress_id: egress.clone(),
                routes: vec![prefix],
                dns: EgressDnsSelection::None {},
            }],
        }],
        reservations: vec![],
    };
    let mut models = models_with_policy(wgfeel_core::TrafficMode::Relay, 10, policy);
    let mut ciphertext = vec![42; MAX_DATAGRAM_SIZE];
    ciphertext[..4].copy_from_slice(&[4, 0, 0, 0]);
    let mut links = [[true; 3]; 3];
    for (start, end, hop) in [
        (0, 2000, Some("c")),
        (2100, 7000, Some("b")),
        (7100, 14000, None),
        (14100, 20500, Some("c")),
    ] {
        if start == 2100 {
            links[0][2] = false;
            links[2][0] = false
        }
        if start == 7100 {
            links[1][2] = false;
            links[2][1] = false
        }
        if start == 14100 {
            links = [[true; 3]; 3]
        }
        advance(&mut models, &links, start, end);
        let now = Duration::from_millis(end);
        for (source, target, direction) in
            [(0, 2, Direction::ToEgress), (2, 0, Direction::FromEgress)]
        {
            let label = ExternalTraffic {
                direction,
                egress: egress.clone(),
                prefix,
                device: ep("alice", "phone"),
            };
            let dest = if target == 0 { id("a") } else { id("c") };
            let frames = models[source].transmit_scoped(
                &net("alice"),
                &dest,
                &ciphertext,
                Some(MeshTraffic::External(label.clone())),
                now,
            );
            let Some(hop) = hop else {
                assert!(frames.is_empty());
                continue;
            };
            assert_eq!(frames.len(), 2);
            let expected_hop = if hop == "c" && target == 0 { "a" } else { hop };
            assert!(frames.iter().all(|frame| matches!(frame,Action::Send{node,packet} if node==&id(expected_hop) && packet.as_bytes()[33]==if source==0{5}else{6})));
            let delivered = pump(
                &mut models,
                &links,
                frames.into_iter().rev().map(|f| (source, f)).collect(),
                now,
            );
            assert!(
                matches!(&delivered[..],[Action::Deliver{packet,traffic:Some(MeshTraffic::External(received)),..}] if received==&label && packet.as_bytes()==ciphertext)
            );
            let spoof = ExternalTraffic {
                device: ep("alice", "laptop"),
                ..label
            };
            assert!(
                models[source]
                    .transmit_scoped(
                        &net("alice"),
                        &dest,
                        &ciphertext,
                        Some(MeshTraffic::External(spoof)),
                        now
                    )
                    .is_empty()
            );
        }
    }
}

#[test]
fn broadcast_fragments_bind_the_witness_and_revision_and_expire_out_of_order() {
    let mut nodes = models_with_transit(wgfeel_core::TrafficMode::Relay);
    let links = [[true, true, false], [true, true, true], [false, true, true]];
    advance(&mut nodes, &links, 0, 3000);
    let now = Duration::from_secs(3);
    let label = MeshTraffic::Broadcast(BroadcastTraffic {
        source: ep("alice", "phone"),
        witness: ep("alice", "laptop"),
    });
    let mut data = vec![73; 1312];
    data[..4].copy_from_slice(&[4, 0, 0, 0]);
    let frames = nodes[0].transmit_scoped(&net("alice"), &id("c"), &data, Some(label.clone()), now);
    assert_eq!(frames.len(), 2);
    let [first, second] = [0, 1].map(|index| {
        let Action::Send { node, packet } = &frames[index] else {
            panic!("expected framed broadcast")
        };
        assert_eq!(node, &id("b"));
        let (generation, kind, body) = decode(packet.as_bytes()).unwrap();
        let (relay, fragment, chunk) = read_relay(kind, body).unwrap();
        assert_eq!(
            (generation, kind, fragment, chunk.len()),
            (10, 7, index, [1024, 288][index])
        );
        assert_eq!(relay.traffic, Some(label.clone()));
        let hop = nodes[1].receive(
            &id("a"),
            "127.0.0.1:10000".parse().unwrap(),
            packet.as_bytes(),
            now,
        );
        let [Action::Send { node, packet }] = hop.as_slice() else {
            panic!("relay must forward one fragment")
        };
        assert_eq!(node, &id("c"));
        packet.as_bytes().to_vec()
    });
    let target = &mut nodes[2];
    let receive = |target: &mut Mesh, frame: &[u8], at| {
        target.receive(&id("b"), "127.0.0.1:10001".parse().unwrap(), frame, at)
    };
    assert!(receive(target, &second, now).is_empty());
    assert!(receive(target, &second, now).is_empty());
    let later = now + FRAGMENT_LEASE;
    assert!(
        receive(target, &first, later).is_empty(),
        "expired tail cannot complete the frame"
    );
    let (_, kind, body) = decode(&second).unwrap();
    let (mut relay, index, chunk) = read_relay(kind, body).unwrap();
    let changed = relay_packet(11, &relay, index, chunk);
    assert!(receive(target, changed.as_bytes(), later).is_empty());
    for wrong in [ep("alice", "phone"), ep("alice", "missing")] {
        relay.traffic = Some(MeshTraffic::Broadcast(BroadcastTraffic {
            source: ep("alice", "phone"),
            witness: wrong,
        }));
        let frame = relay_packet(10, &relay, index, chunk);
        assert!(receive(target, frame.as_bytes(), later).is_empty());
    }
    assert!(matches!(receive(target,&second,later).as_slice(),
        [Action::Deliver{packet,traffic:Some(t),origin,..}] if t == &label && origin == &id("a") && packet.as_bytes()==data));
}
