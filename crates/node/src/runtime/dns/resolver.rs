//! DNS messages only; no transport identity is accepted from the query itself.
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, SOA},
    },
};
use std::net::IpAddr;
use wgfeel_core::{Action, DNS_ZONE, DeviceId, Endpoint, GatewayProjection, Network};

pub(super) const MAX_MESSAGE: usize = 16_384;
pub(super) enum Answer {
    Local(Message),
    Forward(Message),
}

pub(super) fn response(query: &Message, code: ResponseCode) -> Message {
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = code;
    reply.queries = query.queries.clone();
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        reply.edns = Some(edns);
    }
    reply
}

pub(super) fn answer(
    bytes: &[u8],
    network: &Network,
    source: &DeviceId,
    projection: &GatewayProjection,
) -> Option<Answer> {
    if bytes.len() > MAX_MESSAGE {
        return None;
    }
    let query = Message::from_vec(bytes).ok()?;
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    if query.metadata.op_code != OpCode::Query {
        return Some(Answer::Local(response(&query, ResponseCode::NotImp)));
    }
    if query.queries.len() != 1
        || !query.answers.is_empty()
        || !query.authorities.is_empty()
        || query.signature.is_some()
    {
        return Some(Answer::Local(response(&query, ResponseCode::FormErr)));
    }
    let question = &query.queries[0];
    if question.query_class() != DNSClass::IN {
        return Some(Answer::Local(response(&query, ResponseCode::Refused)));
    }
    let zone = Name::from_ascii(format!("{DNS_ZONE}.")).ok()?;
    // zone_of compares labels, not a string suffix (evilfeel.internal is external).
    if !zone.zone_of(question.name()) {
        if network.dns_upstreams().is_empty() || !query.metadata.recursion_desired {
            return Some(Answer::Local(response(&query, ResponseCode::Refused)));
        }
        // Forward a fresh query without client-supplied additional records/ECS.
        let mut forwarded = Message::new(query.metadata.id, MessageType::Query, OpCode::Query);
        forwarded.metadata.recursion_desired = true;
        forwarded.metadata.checking_disabled = query.metadata.checking_disabled;
        forwarded.add_query(question.clone());
        if let Some(edns) = &query.edns {
            let mut opt = Edns::new();
            opt.set_dnssec_ok(edns.flags().dnssec_ok);
            opt.set_max_payload(edns.max_payload().clamp(512, 1232));
            forwarded.edns = Some(opt);
        }
        return Some(Answer::Forward(forwarded));
    }
    let mut reply = response(&query, ResponseCode::NoError);
    reply.metadata.authoritative = true;
    let fqdn = question.name().to_ascii().to_ascii_lowercase();
    let label = fqdn.strip_suffix(&format!(".{DNS_ZONE}."));
    let endpoint = Endpoint::new(network.id().clone(), source.clone());
    let device = network.devices().iter().find(|device| {
        device.hostname().is_some()
            && device.hostname() == label
            && (device.id() == source
                || projection.decision(
                    &endpoint,
                    &Endpoint::new(network.id().clone(), device.id().clone()),
                ) == Action::Allow)
    });
    if let Some(device) = device {
        for address in device.addresses() {
            let data = match (question.query_type(), address) {
                (RecordType::A, IpAddr::V4(ip)) => RData::A(A(*ip)),
                (RecordType::AAAA, IpAddr::V6(ip)) => RData::AAAA(AAAA(*ip)),
                _ => continue,
            };
            reply.add_answer(Record::from_rdata(question.name().clone(), 30, data));
        }
    } else if question.name() != &zone {
        reply.metadata.response_code = ResponseCode::NXDomain;
    }
    // Negative caching is short; missing private names never reach an upstream.
    if reply.answers.is_empty() {
        let soa = Record::from_rdata(
            zone.clone(),
            30,
            RData::SOA(SOA::new(
                zone.clone(),
                Name::from_ascii(format!("hostmaster.{DNS_ZONE}.")).ok()?,
                projection.generation() as u32,
                60,
                30,
                300,
                30,
            )),
        );
        if question.name() == &zone && question.query_type() == RecordType::SOA {
            reply.add_answer(soa);
        } else {
            reply.add_authority(soa);
        }
    }
    Some(Answer::Local(reply))
}

pub(super) fn encode(reply: &Message, udp_limit: Option<usize>) -> Option<Vec<u8>> {
    let bytes = reply.to_vec().ok()?;
    let limit = udp_limit.unwrap_or(MAX_MESSAGE);
    if bytes.len() <= limit {
        return Some(bytes);
    }
    reply
        .truncate()
        .to_vec()
        .ok()
        .filter(|bytes| bytes.len() <= limit)
}
