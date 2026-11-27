use super::*;

fn connected_entries(egress: Option<&wgfeel_core::EgressId>) -> (Fixture, Fixture) {
    use wgfeel_core::{EgressDnsSelection, EgressPolicy, UserEgressAssignment, UserEgresses};
    let home = node("home");
    let owner = node("owner");
    let net = network("alice");
    let devices = [
        (&home, "phone", 23, "10.203.0.9"),
        (&owner, "tablet", 24, "10.203.0.10"),
        (&owner, "laptop", 25, "10.203.0.11"),
    ]
    .map(|(gateway, name, key, address)| {
        Device::new(device(name), public(key), vec![address.parse().unwrap()])
            .unwrap()
            .with_gateway(Some(gateway.clone()))
    });
    let assignments = [
        (&home, 9, 1, server()),
        (&owner, 10, 2, "198.51.100.2:51820".parse().unwrap()),
    ]
    .map(|(node, key, tenant, addr)| {
        GatewayAssignment::new(
            node.clone(),
            public(key),
            wgfeel_test_support::fixture_gateway_public(&public(key)),
            vec![net.clone()],
            vec![TenantKeyAssignment::new(net.clone(), public(tenant))],
        )
        .unwrap()
        .with_endpoint(Some(addr))
        .unwrap()
    });
    let mut routing = ManagementConfig::new(
        home.clone(),
        Config::new(
            1,
            vec![
                Network::new(net.clone(), devices.into())
                    .unwrap()
                    .with_private_lan(true),
            ],
            Policy::new(vec![], vec![], vec![]),
        )
        .unwrap(),
        assignments.to_vec(),
    )
    .unwrap();
    if let Some(egress) = egress {
        routing = routing
            .with_egress_policy(EgressPolicy {
                profiles: vec![external_profile(egress, &owner)],
                users: vec![UserEgresses {
                    user: wgfeel_core::ClientId::new("alice").unwrap(),
                    network: net.clone(),
                    egresses: vec![UserEgressAssignment {
                        egress_id: egress.clone(),
                        routes: vec!["0.0.0.0/0".parse().unwrap()],
                        dns: EgressDnsSelection::None {},
                    }],
                }],
                reservations: vec![],
            })
            .unwrap();
    }
    let [mut entry, mut exit] = [(&home, 9, 1), (&owner, 10, 2)].map(|(node, key, tenant)| {
        let projection = routing.project_mesh_for(node).unwrap();
        let interface = wgfeel_core::EgressPrivateKey::new(seed(50)).unwrap();
        let psk = wgfeel_core::PresharedKey::new(seed(52)).unwrap();
        let providers = egress
            .filter(|_| node == &owner)
            .map(|id| (id, &interface, Some(&psk)));
        let gateway = LocalGateway::spawn_with_egresses(
            &projection,
            &public(9),
            &wgfeel_test_support::fixture_node_keys(seed(key)),
            [(&net, &TenantPrivateKey::new(seed(tenant)).unwrap())],
            providers,
            Limits::default(),
            options(),
        )
        .unwrap();
        let mut fixture = Fixture {
            gateway,
            clients: if node == &owner {
                vec![
                    Client::new("alice", "tablet", 24, 2),
                    Client::new("alice", "laptop", 25, 2),
                ]
            } else {
                vec![Client::new("alice", "phone", 23, 1)]
            },
        };
        fixture.ready();
        fixture
    });
    entry.establish(0);
    let context = ContextId::Tenant(net.clone());
    entry
        .gateway
        .initiate_at(
            &context,
            &PeerId::Gateway(owner.clone()),
            assignments[1].endpoint().unwrap(),
        )
        .unwrap();
    for outbound in [true, false, true] {
        let (sender, receiver, origin) = if outbound {
            (&mut entry, &mut exit, &home)
        } else {
            (&mut exit, &mut entry, &owner)
        };
        let LocalEvent::MeshOutput {
            packet,
            traffic: None,
            ..
        } = sender.event()
        else {
            panic!("tenant handshake missing")
        };
        receiver
            .gateway
            .receive_mesh(&net, origin, packet.as_bytes(), None)
            .unwrap();
    }
    exit.wait_idle(&context);
    (entry, exit)
}

pub(super) fn remote_egress_requires_typed_inner_wireguard_bound_to_the_authenticated_home_and_owner()
 {
    use wgfeel_wireguard::mesh::{Direction, MeshTraffic};
    let egress = wgfeel_core::EgressId::new("vpn").unwrap();
    let (mut entry, mut exit) = connected_entries(Some(&egress));
    let mut provider = establish_provider(&mut exit, &egress);
    let net = network("alice");
    let home = node("home");
    let owner = node("owner");
    let packet = udp(false, "10.203.0.9", "203.0.113.23", 64, 73);
    entry.submit(0, &packet);
    let LocalEvent::MeshOutput {
        packet: unlabelled,
        traffic: Some(MeshTraffic::External(_)),
        ..
    } = entry.event()
    else {
        panic!("missing egress frame")
    };
    assert!(
        exit.gateway
            .receive_datagram(server(), unlabelled.as_bytes())
            .unwrap()
            .is_none()
    );
    assert!(
        matches!(exit.event(), LocalEvent::Dropped { .. }),
        "raw inter-entry input must not reach the provider"
    );
    entry.submit(0, &packet);
    let LocalEvent::MeshOutput {
        packet: wire,
        traffic: Some(MeshTraffic::External(to)),
        ..
    } = entry.event()
    else {
        panic!("missing typed egress output")
    };
    assert_eq!(to.direction, Direction::ToEgress);
    exit.gateway
        .receive_mesh(
            &net,
            &home,
            wire.as_bytes(),
            Some(MeshTraffic::External(to)),
        )
        .unwrap();
    let LocalEvent::ProviderOutput(out) = exit.event() else {
        panic!("provider did not receive remotely originated traffic")
    };
    let TunnResult::WriteToTunnel(translated) = provider.receive(server(), out.packet.as_bytes())
    else {
        panic!("provider could not authenticate")
    };
    assert_eq!(&translated[12..16], &[172, 16, 4, 2]);
    let mut reply = udp(false, "203.0.113.23", "172.16.4.2", 63, 45);
    reply[20..22].copy_from_slice(&packet[22..24]);
    reply[22..24].copy_from_slice(&translated[20..22]);
    reply[26..28].fill(0);
    let wire = provider.encrypt(&reply);
    exit.gateway
        .receive_provider(&egress, provider.address, &wire)
        .unwrap();
    let LocalEvent::MeshOutput {
        packet: wire,
        traffic: Some(MeshTraffic::External(from)),
        ..
    } = exit.event()
    else {
        panic!("missing typed return")
    };
    assert_eq!(from.direction, Direction::FromEgress);
    entry
        .gateway
        .receive_mesh(
            &net,
            &owner,
            wire.as_bytes(),
            Some(MeshTraffic::External(from)),
        )
        .unwrap();
    let LocalEvent::Network(out) = entry.event() else {
        panic!("home denied legitimate provider return")
    };
    let TunnResult::WriteToTunnel(response) =
        entry.clients[0].receive(server(), out.packet.as_bytes())
    else {
        panic!("device could not authenticate reply")
    };
    assert_eq!(&response[16..20], &[10, 203, 0, 9]);
    assert_eq!(response[8], 62);
}

pub(super) fn remote_broadcast_checks_the_witness_and_delivers_once_to_each_device() {
    use wgfeel_wireguard::mesh::{BroadcastTraffic, MeshTraffic, Traffic};
    let (mut entry, mut exit) = connected_entries(None);
    exit.establish(0);
    exit.establish(1);
    let src = "10.203.0.9";
    let directed = "10.203.255.255";
    let source = endpoint("alice", "phone");
    let target = endpoint("alice", "tablet");
    let broadcast = MeshTraffic::Broadcast(BroadcastTraffic {
        source: source.clone(),
        witness: target.clone(),
    });
    let unicast = MeshTraffic::Device(Traffic {
        source: source.clone(),
        destination: target,
    });
    // Both forms of a mismatch must be rejected *after* authenticating the tenant ciphertext.
    for (dest, override_label) in [
        (directed, Some(unicast)),
        ("10.203.0.10", Some(broadcast)),
        (
            directed,
            Some(MeshTraffic::Broadcast(BroadcastTraffic {
                source: source.clone(),
                witness: source.clone(),
            })),
        ),
        (directed, None),
    ] {
        entry.submit(0, &udp(false, src, dest, 4, 88));
        let LocalEvent::MeshOutput {
            packet,
            traffic: Some(label),
            peer: home,
            ..
        } = entry.event()
        else {
            panic!("missing remote tenant packet")
        };
        assert_eq!(home, node("owner"));
        assert_eq!(matches!(label, MeshTraffic::Broadcast(_)), dest == directed);
        let expect_delivery = override_label.is_none();
        exit.gateway
            .receive_mesh(
                &network("alice"),
                &node("home"),
                packet.as_bytes(),
                Some(override_label.unwrap_or(label)),
            )
            .unwrap();
        if expect_delivery {
            for (i, dest) in ["10.203.0.10", "10.203.0.11"].into_iter().enumerate() {
                let LocalEvent::Network(out) = exit.event() else {
                    panic!("missing recipient")
                };
                let wire = encrypted(out, &exit.clients[i]);
                exit.clients[i].assert_plaintext(server(), &wire, &udp(false, src, dest, 4, 88));
            }
        } else {
            exit.wait_idle(&context("alice"));
        }
        for fixture in [&mut entry, &mut exit] {
            let deadline = Instant::now() + WAIT;
            while fixture.gateway.has_broadcast_jobs() {
                assert!(fixture.gateway.poll().is_none(), "extra copy or re-relay");
                assert!(Instant::now() < deadline);
            }
        }
    }
}
