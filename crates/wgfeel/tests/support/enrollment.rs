use super::*;
use std::{net::SocketAddr, thread, time::Instant};
use wgfeel_core::{DevicePublicKey, ServicePrivateKey};
use wgfeel_protocol::{
    Request, Response,
    enrollment::{ENROLLMENT_PATH, EnrollmentClaim, Invitation},
    http, tcp,
};
use wgfeel_wireguard::{
    ContextConfig, ContextId, Gateway, Limits, PeerConfig, PeerId, UdpEvent, UdpTransport,
    WireGuardError,
};

pub(super) fn invitation(fixture: &Fixture) -> Invitation {
    invitation_mode(fixture, None)
}
pub(super) fn invitation_mode(fixture: &Fixture, mode: Option<&str>) -> Invitation {
    let mut args = vec!["node", "add"];
    if let Some(mode) = mode {
        args.extend(["--traffic", mode]);
    }
    let output = fixture.remote(&args, "", true);
    assert!(
        output
            .lines()
            .any(|line| line == "wgfeel join --invitation-stdin")
    );
    let uri = output
        .lines()
        .find(|line| line.starts_with("wgfeel://join/"))
        .unwrap();
    Invitation::decode(uri).unwrap()
}
fn exchange(invitation: &Invitation, request: Request<'_>, timeout: Duration) -> Option<Response> {
    wire_exchange(
        invitation.endpoints()[0],
        invitation.management(),
        invitation.management_public_key(),
        ServicePrivateKey::new(*invitation.temporary_private_key().expose_bytes()).unwrap(),
        http::encode_request(request).unwrap(),
        timeout,
    )
}
pub(super) fn wire_exchange(
    endpoint: SocketAddr,
    manager: &wgfeel_core::NodeId,
    server_key: &DevicePublicKey,
    private: ServicePrivateKey,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    timeout: Duration,
) -> Option<Response> {
    let listen: SocketAddr = if endpoint.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    }
    .parse()
    .unwrap();
    let peer = PeerId::Node(manager.clone());
    let mut gateway = Gateway::new(
        vec![ContextConfig::service(
            private,
            vec![PeerConfig {
                id: peer.clone(),
                public_key: server_key.clone(),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let transport = UdpTransport::from_socket(UdpSocket::bind(listen).unwrap()).unwrap();
    let mut buffers = tcp::Buffers::new(1).unwrap();
    let mut tcp =
        tcp::Client::new(&mut buffers, wgfeel_host::random_seed().unwrap(), bytes).unwrap();
    if let Some(event) = gateway
        .initiate_at(&ContextId::Service, &peer, endpoint)
        .unwrap()
    {
        transport.transmit(event).unwrap();
    }
    let started = Instant::now();
    let mut tick = started;
    while started.elapsed() < timeout {
        for _ in 0..32 {
            if let Ok(Some(UdpEvent::Plaintext {
                context,
                peer: received,
                packet,
            })) = transport.poll(&mut gateway)
            {
                assert_eq!(context, ContextId::Service);
                assert_eq!(received, peer);
                tcp.receive(packet.as_bytes()).unwrap();
            }
        }
        tcp.poll(started.elapsed()).unwrap();
        while let Some(packet) = tcp.take_packet() {
            match gateway.send_datagram(&ContextId::Service, &peer, &packet) {
                Ok(event) => transport.transmit(event).unwrap(),
                Err(WireGuardError::NoEndpoint | WireGuardError::NoSession) => (),
                Err(error) => panic!("{error:?}"),
            }
        }
        if let Some(response) = tcp.take_response() {
            return Some(response.unwrap());
        }
        if tick.elapsed() >= Duration::from_millis(100) {
            tick = Instant::now();
            if let Ok(Some(event)) = gateway.tick_datagram(&ContextId::Service, &peer) {
                transport.transmit(event).unwrap();
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    None
}
fn request<'a>(target: &'a str, body: &'a [u8]) -> Request<'a> {
    Request {
        method: "POST",
        target,
        authorization: None,
        if_match: None,
        body,
    }
}

#[test]
fn temporary_wireguard_peer_enrolls_on_manager_port_but_never_reaches_admin_api() {
    let fixture = Fixture::new();
    fixture.initialize();
    let manager = fixture.start(1);
    let snapshot = fs::read(fixture.state().join("state.json")).unwrap();
    let invitation = invitation(&fixture);
    let (_, permanent) = wgfeel_host::generate_service_key().unwrap();
    let claim = EnrollmentClaim::new(
        wgfeel_core::NodeId::new("node-1").unwrap(),
        (permanent).clone(),
        wgfeel_test_support::fixture_gateway_public(&(permanent)),
        "vps1".into(),
        vec![
            "203.0.113.20:55125".parse().unwrap(),
            "[2001:db8::20]:55125".parse().unwrap(),
        ],
        wgfeel_core::NodeId::new("attempt-1").unwrap(),
    )
    .unwrap();
    let body = serde_json::to_vec(&claim).unwrap();
    let response = exchange(
        &invitation,
        request(ENROLLMENT_PATH, &body),
        Duration::from_secs(5),
    )
    .expect("enrollment over service WireGuard");
    assert_eq!(response.status, 202);
    for target in [
        "/api/v1/config",
        "/api/v1/token/rotate",
        "/api/v1/node-invitations",
    ] {
        assert_eq!(
            exchange(&invitation, request(target, b""), Duration::from_secs(5))
                .unwrap()
                .status,
            403
        );
    }
    let other = EnrollmentClaim::new(
        claim.node_id().clone(),
        (DevicePublicKey::new([9; 32]).unwrap()).clone(),
        wgfeel_test_support::fixture_gateway_public(&(DevicePublicKey::new([9; 32]).unwrap())),
        "vps1".into(),
        claim.endpoints().to_vec(),
        wgfeel_core::NodeId::new("attempt-1").unwrap(),
    )
    .unwrap();
    assert_eq!(
        exchange(
            &invitation,
            request(ENROLLMENT_PATH, &serde_json::to_vec(&other).unwrap()),
            Duration::from_secs(5)
        )
        .unwrap()
        .status,
        409
    );
    assert_eq!(
        fs::read(fixture.state().join("state.json")).unwrap(),
        snapshot
    );
    let nodes = api::json(&fixture.state(), "GET", "/api/v1/gateways", Value::Null);
    assert_eq!(nodes["gateways"].as_array().unwrap().len(), 1);
    assert_eq!(nodes["gateways"][0]["recipient"], "management");
    stop(manager);
    let manager = fixture.start(1);
    assert!(
        exchange(
            &invitation,
            request(ENROLLMENT_PATH, &body),
            Duration::from_millis(500)
        )
        .is_none(),
        "restart must revoke temporary WG admission"
    );
    stop(manager);
}

#[test]
fn join_command_registers_unbound_node_and_switches_to_one_new_manager_durably() {
    let first = Fixture::new();
    first.initialize();
    let second = Fixture::new();
    second.initialize_on("[::1]:0");
    let manager1 = first.start(1);
    let manager2 = second.start(1);
    let node_dir = first.0.join("node-state");
    let node_id = wgfeel_host::node::generated_id().unwrap();
    wgfeel_host::node::initialize_unbound(&node_dir, node_id.clone()).unwrap();
    let original: Value =
        serde_json::from_slice(&fs::read(node_dir.join("state.json")).unwrap()).unwrap();
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = reservation.local_addr().unwrap();
    let endpoint_v6: std::net::SocketAddr = format!("[::1]:{}", endpoint.port()).parse().unwrap();
    drop(reservation);
    let start_node = || {
        let mut node = spawn(vec![
            "serve".into(),
            "--control".into(),
            "child".into(),
            "--state-dir".into(),
            node_dir.clone().into_os_string(),
            "--listen".into(),
            format!("0.0.0.0:{}", endpoint.port()).into(),
        ]);
        let ready: Value = serde_json::from_slice(&node.next_stdout_line(WAIT).unwrap()).unwrap();
        assert_eq!(ready["node_id"], node_id.as_str());
        node
    };
    let node = start_node();
    // A bound but silent IPv4 address forces proof and config delivery to try
    // the next endpoint, IPv6, during the second Manager's enrollment.
    let unavailable = UdpSocket::bind("127.0.0.1:0").unwrap();
    let join = |invite: &Invitation, success: bool| {
        let ipv6 = invite.endpoints().last().unwrap().is_ipv6();
        let mut args = vec![
            "join".into(),
            invite.encode().unwrap().as_str().into(),
            "--state-dir".into(),
            node_dir.clone().into_os_string(),
        ];
        let endpoints = if ipv6 {
            vec![unavailable.local_addr().unwrap(), endpoint_v6, endpoint]
        } else {
            vec![endpoint, endpoint_v6]
        };
        for endpoint in endpoints {
            args.extend(["--endpoint".into(), endpoint.to_string().into()]);
        }
        let output = spawn(args).wait(Duration::from_secs(75)).unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if success {
            assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration saved"));
        }
    };
    let invite1 = invitation(&first);
    join(&invite1, true);
    let state1: Value =
        serde_json::from_slice(&fs::read(node_dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        state1["service_private_key"],
        original["service_private_key"]
    );
    assert_eq!(
        state1["management_public_key"],
        serde_json::to_value(invite1.management_public_key()).unwrap()
    );
    let nodes: Value =
        serde_json::from_slice(&api::get(&first.state(), "/api/v1/gateways").body).unwrap();
    assert_eq!(nodes["gateways"].as_array().unwrap().len(), 2);
    let node_details = nodes["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["recipient"] == node_id.as_str())
        .unwrap();
    assert_eq!(
        node_details["hostname"],
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim()
    );
    assert_eq!(
        node_details["endpoints"],
        serde_json::json!([endpoint.to_string(), endpoint_v6.to_string()])
    );
    let joined = fs::read(node_dir.join("state.json")).unwrap();
    // A fresh CLI operation cannot reuse a consumed invitation, even for the
    // exact same permanent node. Only retransmissions of the first operation
    // may receive its original receipt.
    join(&invite1, false);
    assert_eq!(fs::read(node_dir.join("state.json")).unwrap(), joined);
    let repeat = invitation(&first);
    join(&repeat, true);
    assert_eq!(
        serde_json::from_slice::<Value>(&api::get(&first.state(), "/api/v1/gateways").body)
            .unwrap()["gateways"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Invalid candidate key fails before the temporary invitation is claimed;
    // the currently active Manager and complete disk snapshot remain intact.
    let issued = invitation(&second);
    // Bootstrap must also switch from a silent IPv4 Manager address to IPv6;
    // the permanent Manager identity and temporary credential stay unchanged.
    let second_invite = Invitation::new(
        issued.id().clone(),
        issued.management().clone(),
        issued.management_public_key().clone(),
        vec![unavailable.local_addr().unwrap(), issued.endpoints()[0]],
        issued.mesh_port(),
        issued.expires_at(),
        ServicePrivateKey::new(*issued.temporary_private_key().expose_bytes()).unwrap(),
    )
    .unwrap();
    let mut invalid_key = [0; 32];
    invalid_key[0] = 1;
    let invalid = Invitation::new(
        second_invite.id().clone(),
        second_invite.management().clone(),
        DevicePublicKey::new(invalid_key).unwrap(),
        second_invite.endpoints().to_vec(),
        second_invite.mesh_port(),
        second_invite.expires_at(),
        ServicePrivateKey::new(*second_invite.temporary_private_key().expose_bytes()).unwrap(),
    )
    .unwrap();
    let before = fs::read(node_dir.join("state.json")).unwrap();
    join(&invalid, false);
    assert_eq!(fs::read(node_dir.join("state.json")).unwrap(), before);
    // Both managers intentionally have the same display ID. Their pinned keys,
    // rather than the string name alone, must determine the authority change.
    join(&second_invite, true);
    let state2: Value =
        serde_json::from_slice(&fs::read(node_dir.join("state.json")).unwrap()).unwrap();
    let nodes: Value =
        serde_json::from_slice(&api::get(&second.state(), "/api/v1/gateways").body).unwrap();
    assert_eq!(nodes["gateways"].as_array().unwrap().len(), 2);
    let node_details = nodes["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["recipient"] == node_id.as_str())
        .unwrap();
    assert_eq!(node_details["endpoint"], endpoint_v6.to_string());
    assert_eq!(node_details["endpoints"][0], endpoint_v6.to_string());
    assert_eq!(
        state2["service_private_key"],
        original["service_private_key"]
    );
    assert_eq!(
        state2["management_public_key"],
        serde_json::to_value(second_invite.management_public_key()).unwrap()
    );
    assert_ne!(
        state2["management_public_key"],
        state1["management_public_key"]
    );
    let committed = fs::read(node_dir.join("state.json")).unwrap();
    stop(node);
    stop(manager1);
    stop(manager2);
    let node = start_node();
    assert_eq!(fs::read(node_dir.join("state.json")).unwrap(), committed);
    stop(node);
}
