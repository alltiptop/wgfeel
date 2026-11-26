use super::*;
use hickory_proto::{
    op::{MessageType, OpCode, Query},
    rr::{Name, RData, RecordType, rdata::A},
};
use wgfeel_core::*;

fn projection() -> GatewayProjection {
    let networks: Vec<_> = [("alice", "10.203.0.2"), ("bob", "10.203.0.3")]
        .into_iter()
        .map(|(id, ip)| {
            let device = Device::new(
                DeviceId::new("pc").unwrap(),
                DevicePublicKey::new([id.len() as u8; 32]).unwrap(),
                vec![ip.parse().unwrap(), "fd77:77::2".parse().unwrap()],
            )
            .unwrap()
            .with_hostname(Some("pc".into()))
            .unwrap();
            Network::new(NetworkId::new(id).unwrap(), vec![device])
                .unwrap()
                .with_private_lan(true)
        })
        .collect();
    let assignments = vec![
        GatewayAssignment::new(
            NodeId::new("node").unwrap(),
            (DevicePublicKey::new([31; 32]).unwrap()).clone(),
            wgfeel_test_support::fixture_gateway_public(&(DevicePublicKey::new([31; 32]).unwrap())),
            networks.iter().map(|n| n.id().clone()).collect(),
            networks
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    TenantKeyAssignment::new(
                        n.id().clone(),
                        DevicePublicKey::new([32 + i as u8; 32]).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap(),
    ];
    ManagementConfig::new(
        NodeId::new("manager").unwrap(),
        Config::new(1, networks, Policy::new(vec![], vec![], vec![])).unwrap(),
        assignments,
    )
    .unwrap()
    .project_for(&NodeId::new("node").unwrap())
    .unwrap()
}
fn query(name: &str, kind: RecordType) -> Message {
    let mut query = Message::new(99, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query
}
#[test]
fn independent_answers_and_local_negative_results() {
    let projection = projection();
    for (index, expected) in [(0, "10.203.0.2"), (1, "10.203.0.3")] {
        let network = &projection.config().networks()[index];
        let answer = |name, kind| {
            resolver::answer(
                &query(name, kind).to_vec().unwrap(),
                network,
                &DeviceId::new("pc").unwrap(),
                &projection,
            )
            .unwrap()
        };
        let Answer::Local(reply) = answer("PC.Feel.Internal.", RecordType::A) else {
            panic!("private query escaped")
        };
        assert_eq!(
            reply.answers[0].data,
            RData::A(A(expected.parse().unwrap()))
        );
        assert!(reply.metadata.authoritative);
        let Answer::Local(reply) = answer("pc.feel.internal.", RecordType::AAAA) else {
            panic!()
        };
        assert_eq!(reply.answers[0].data.to_string(), "fd77:77::2");
        let Answer::Local(reply) = answer("missing.feel.internal.", RecordType::A) else {
            panic!("negative query escaped")
        };
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(reply.authorities.len(), 1);
        let Answer::Local(reply) = answer("pc.feel.internal.", RecordType::TXT) else {
            panic!()
        };
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        assert!(matches!(
            answer("example.org.", RecordType::A),
            Answer::Forward(_)
        ));
        assert!(matches!(
            answer("evilfeel.internal.", RecordType::A),
            Answer::Forward(_)
        ));
    }
}

#[test]
fn multiple_questions_and_compression_loops_never_forward() {
    let projection = projection();
    let network = &projection.config().networks()[0];
    let mut message = query("example.org.", RecordType::A);
    message.add_query(Query::query(
        Name::from_ascii("secret.feel.internal.").unwrap(),
        RecordType::A,
    ));
    let Answer::Local(reply) = resolver::answer(
        &message.to_vec().unwrap(),
        network,
        &DeviceId::new("pc").unwrap(),
        &projection,
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    let looped = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
    assert!(
        resolver::answer(&looped, network, &DeviceId::new("pc").unwrap(), &projection).is_none()
    );
}

#[test]
fn disabled_external_resolution_and_udp_truncation() {
    let projection = projection();
    let network = projection.config().networks()[0]
        .clone()
        .with_dns_upstreams(vec![])
        .unwrap();
    let message = query("example.org.", RecordType::A);
    let Answer::Local(reply) = resolver::answer(
        &message.to_vec().unwrap(),
        &network,
        &DeviceId::new("pc").unwrap(),
        &projection,
    )
    .unwrap() else {
        panic!("external resolution disabled")
    };
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    let mut reply = response(&message, ResponseCode::NoError);
    for index in 1..=64 {
        reply.add_answer(hickory_proto::rr::Record::from_rdata(
            message.queries[0].name().clone(),
            30,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, index))),
        ));
    }
    let udp = encode(&reply, Some(512)).unwrap();
    assert!(udp.len() <= 512);
    assert!(Message::from_vec(&udp).unwrap().metadata.truncation);
    let tcp = Message::from_vec(&encode(&reply, None).unwrap()).unwrap();
    assert!(!tcp.metadata.truncation);
    assert_eq!(tcp.answers.len(), 64);
}

#[test]
fn late_upstream_reply_cannot_cross_a_configuration_reset() {
    let projection = projection();
    let mut runtime = Runtime::new().unwrap();
    let (results_tx, results) = std::sync::mpsc::sync_channel(4);
    runtime.pool.results = results;
    let network = NetworkId::new("alice").unwrap();
    let make_pending = || Pending {
        network: network.clone(),
        target: Target::Udp {
            remote: (std::net::Ipv4Addr::new(10, 203, 0, 2), 53000).into(),
            local: DNS_IPV4.into(),
        },
        query: query("example.org.", RecordType::A),
        deadline: Instant::now() + Duration::from_secs(5),
        limit: Some(512),
    };
    runtime.pending.insert(0, make_pending());
    runtime.next = 1;
    runtime.reset();
    runtime.pending.insert(1, make_pending());
    runtime.next = 2;
    results_tx
        .send(upstream::Completed {
            id: 0,
            response: Some(response(
                &query("example.org.", RecordType::A),
                ResponseCode::NoError,
            )),
        })
        .unwrap();
    runtime.resolve(&projection, Duration::ZERO);
    assert!(runtime.pending.contains_key(&1));
    assert_eq!(runtime.next, 2);
    assert!(runtime.tenants.is_empty());
}

#[test]
fn upstream_uses_local_mock_and_matches_transaction_and_question() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = listener.local_addr().unwrap();
    let mock = thread::spawn(move || {
        for valid in [true, false] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 2];
            socket.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; usize::from(u16::from_be_bytes(length))];
            socket.read_exact(&mut bytes).unwrap();
            let query = Message::from_vec(&bytes).unwrap();
            let mut reply = response(&query, ResponseCode::NoError);
            if !valid {
                reply.metadata.id = reply.metadata.id.wrapping_add(1);
            }
            reply.metadata.authentic_data = true;
            reply.add_answer(hickory_proto::rr::Record::from_rdata(
                query.queries[0].name().clone(),
                30,
                RData::A(A("192.0.2.25".parse().unwrap())),
            ));
            let bytes = reply.to_vec().unwrap();
            socket
                .write_all(&(bytes.len() as u16).to_be_bytes())
                .unwrap();
            socket.write_all(&bytes).unwrap();
        }
    });
    let pool = upstream::Pool::new().unwrap();
    for id in 0..2 {
        pool.jobs
            .send(upstream::Job {
                id,
                query: query("example.org.", RecordType::A),
                servers: vec![server],
                deadline: Instant::now() + Duration::from_secs(2),
            })
            .unwrap();
        let result = pool.results.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(result.id, id);
        if id == 0 {
            let reply = result.response.unwrap();
            assert_eq!(reply.metadata.id, 99);
            assert!(!reply.metadata.authentic_data);
            assert_eq!(
                reply.answers[0].data,
                RData::A(A("192.0.2.25".parse().unwrap()))
            );
        } else {
            assert!(result.response.is_none());
        }
    }
    mock.join().unwrap();
}
