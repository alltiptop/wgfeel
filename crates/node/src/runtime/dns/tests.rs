use super::*;
use hickory_proto::{
    op::{MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, RecordType,
        rdata::{A, AAAA},
    },
};
use wgfeel_core::*;

fn projection() -> GatewayProjection {
    let networks: Vec<_> = [
        ("alice", "10.203.0.2", "fd77:77::2"),
        ("bob", "10.203.0.3", "fd77:77::3"),
    ]
    .into_iter()
    .map(|(id, ipv4, ipv6)| {
        let device = Device::new(
            DeviceId::new("pc").unwrap(),
            DevicePublicKey::new([id.len() as u8; 32]).unwrap(),
            vec![ipv4.parse().unwrap(), ipv6.parse().unwrap()],
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
    for (tenant, ipv4, ipv6) in [
        ("alice", "10.203.0.2", "fd77:77::2"),
        ("bob", "10.203.0.3", "fd77:77::3"),
    ] {
        let network = projection
            .config()
            .networks()
            .iter()
            .find(|network| network.id().as_str() == tenant)
            .unwrap();
        let answer = |name, kind| {
            resolver::answer(
                &query(name, kind).to_vec().unwrap(),
                network,
                &DeviceId::new("pc").unwrap(),
                &projection,
            )
            .unwrap()
        };
        let reply = answer("PC.Feel.Internal.", RecordType::A);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].data, RData::A(A(ipv4.parse().unwrap())));
        assert!(reply.metadata.authoritative);
        let reply = answer("pc.feel.internal.", RecordType::AAAA);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(
            reply.answers[0].data,
            RData::AAAA(AAAA(ipv6.parse().unwrap()))
        );
        let reply = answer("missing.feel.internal.", RecordType::A);
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(reply.answers.is_empty());
        assert_eq!(reply.authorities.len(), 1);
        let reply = answer("pc.feel.internal.", RecordType::TXT);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        for external in ["example.org.", "evilfeel.internal."] {
            let reply = answer(external, RecordType::A);
            assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
            assert!(!reply.metadata.recursion_available);
        }
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
    let reply = resolver::answer(
        &message.to_vec().unwrap(),
        network,
        &DeviceId::new("pc").unwrap(),
        &projection,
    )
    .unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    let looped = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
    assert!(
        resolver::answer(&looped, network, &DeviceId::new("pc").unwrap(), &projection).is_none()
    );
}

#[test]
fn disabled_external_resolution_and_udp_truncation() {
    let projection = projection();
    let network = &projection.config().networks()[0];
    let message = query("example.org.", RecordType::A);
    let reply = resolver::answer(
        &message.to_vec().unwrap(),
        network,
        &DeviceId::new("pc").unwrap(),
        &projection,
    )
    .unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    let mut reply = resolver::response(&message, ResponseCode::NoError);
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
