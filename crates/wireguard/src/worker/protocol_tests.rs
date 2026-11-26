//! Independent literal-wire contracts. Expected bytes do not use the codec's
//! encoders; these tests cover the private format, not engine authentication.
use super::{
    Operation, Output, ProtocolError, decode_bootstrap, decode_reply, decode_request,
    encode_bootstrap, encode_ready, is_ready, read_frame,
};
use crate::{ContextId, PeerId, WireGuardError};
use std::io::{self, Cursor, Read};
use wgfeel_core::{DeviceId, NetworkId};

const INITIATE: &[u8] = &[1, 3, 9, 0, 0, 0, 0, 0, 0, 0, 2, 7, 0];
const DONE: &[u8] = &[1, 4, 9, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0];

fn tenant() -> ContextId {
    ContextId::Tenant(NetworkId::new("alpha").unwrap())
}

fn bootstrap(count: u16) -> Vec<u8> {
    let mut bytes = vec![1, 2];
    bytes.extend_from_slice(&[91; 32]);
    bytes.extend_from_slice(&10_u32.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    for index in 0..count {
        let id = format!("peer{index}");
        bytes.push(id.len() as u8);
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&[17; 32]);
    }
    bytes
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn ready_is_exact_version_and_type_not_a_prefix() {
    assert_eq!(encode_ready(), [2, 0, 0, 0, 1, 1]);
    assert!(is_ready(&[1, 1]));
    for invalid in [&[][..], &[1], &[0, 1], &[2, 1], &[1, 2], &[1, 1, 0]] {
        assert!(!is_ready(invalid));
    }
}

#[test]
fn service_peer_replacement_has_a_bounded_unambiguous_wire_contract() {
    // version, request tag, sequence, operation, absent single-peer index, count
    let mut body = vec![1, 3, 9, 0, 0, 0, 0, 0, 0, 0, 6, 255, 255, 1, 0];
    body.extend_from_slice(&[7, b'm', b'a', b'n', b'a', b'g', b'e', b'r']);
    body.extend_from_slice(&[17; 32]);
    let request = decode_request(&body).unwrap();
    assert_eq!(request.sequence, 9);
    let Operation::SetServicePeers { peers } = &request.operation else {
        panic!("wrong operation")
    };
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].id,
        PeerId::Node(wgfeel_core::NodeId::new("manager").unwrap())
    );
    assert_eq!(peers[0].public_key.as_bytes(), &[17; 32]);
    assert_eq!(super::encode_request(&request).unwrap(), framed(&body));
    for end in 0..body.len() {
        assert!(decode_request(&body[..end]).is_err());
    }
    for (offset, value) in [
        (11, 0),
        (12, 0),
        (13, 152),
        (14, 1),
        (15, 0),
        (15, 65),
        (16, 255),
    ] {
        let mut invalid = body.clone();
        invalid[offset] = value;
        assert!(decode_request(&invalid).is_err(), "offset {offset}");
    }
    let mut surplus = body.clone();
    surplus.push(0);
    assert!(decode_request(&surplus).is_err());
    // Empty replacement explicitly revokes all service peers.
    let mut empty = body[..15].to_vec();
    empty[13] = 0;
    assert!(
        matches!(decode_request(&empty).unwrap().operation, Operation::SetServicePeers { peers } if peers.is_empty())
    );
}

#[test]
fn literal_request_has_exact_fields_and_rejects_all_truncations_or_surplus() {
    let request = decode_request(INITIATE).unwrap();
    assert_eq!(request.sequence, 9);
    assert!(matches!(request.operation, Operation::Initiate { peer: 7 }));
    for end in 0..INITIATE.len() {
        assert!(decode_request(&INITIATE[..end]).is_err());
    }
    let mut surplus = INITIATE.to_vec();
    surplus.push(0);
    assert!(decode_request(&surplus).is_err());
    for (offset, value) in [(0, 2), (1, 4), (10, 0), (10, 6), (10, 255)] {
        let mut invalid = INITIATE.to_vec();
        invalid[offset] = value;
        assert!(decode_request(&invalid).is_err());
    }
    let mut absent_required_peer = INITIATE.to_vec();
    absent_required_peer[11..13].fill(255);
    assert!(decode_request(&absent_required_peer).is_err());
}

#[test]
fn request_packet_bounds_distinguish_encrypted_and_plaintext_payloads() {
    for (tag, maximum) in [(1, 1312), (3, 1280)] {
        for size in [0, maximum, maximum + 1] {
            let mut bytes = vec![1, 3, 1, 0, 0, 0, 0, 0, 0, 0, tag, 0, 0];
            bytes.extend_from_slice(&(size as u16).to_le_bytes());
            bytes.resize(15 + size, 7);
            let result = decode_request(&bytes);
            if size == maximum {
                let packet = match result.unwrap().operation {
                    Operation::Receive {
                        peer: Some(0),
                        packet,
                    }
                    | Operation::Send { peer: 0, packet } => packet,
                    _ => panic!("wrong decoded operation"),
                };
                assert_eq!(packet, vec![7; maximum]);
                bytes.pop();
                assert!(decode_request(&bytes).is_err());
            } else {
                assert!(result.is_err());
            }
        }
    }
    let anonymous = [1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255, 1, 0, 4];
    assert!(matches!(
        decode_request(&anonymous).unwrap().operation,
        Operation::Receive { peer: None, packet } if packet == [4]
    ));
}

#[test]
fn bootstrap_literal_roundtrip_encoding_and_role_specific_peer_limits() {
    let body = bootstrap(1);
    let (config, limits) = decode_bootstrap(&body, &tenant()).unwrap();
    assert_eq!(config.id, tenant());
    assert_eq!(config.private_key.expose_bytes(), &[91; 32]);
    assert_eq!(config.peers.len(), 1);
    assert_eq!(
        config.peers[0].id,
        PeerId::Device(DeviceId::new("peer0").unwrap())
    );
    assert_eq!(config.peers[0].public_key.as_bytes(), &[17; 32]);
    assert_eq!(limits.handshake_limit_per_ip, 10);
    assert_eq!(
        encode_bootstrap(&config, limits).unwrap().as_slice(),
        framed(&body)
    );
    for end in 0..body.len() {
        assert!(decode_bootstrap(&body[..end], &tenant()).is_err());
    }
    let mut extra = body.clone();
    extra.push(0);
    assert!(decode_bootstrap(&extra, &tenant()).is_err());
    for (context, allowed, rejected) in [
        (ContextId::Service, 182, 183),
        (ContextId::Gateway, 150, 151),
        (tenant(), 750, 751),
    ] {
        assert_eq!(
            decode_bootstrap(&bootstrap(allowed), &context)
                .unwrap()
                .0
                .peers
                .len(),
            usize::from(allowed)
        );
        assert!(decode_bootstrap(&bootstrap(rejected), &context).is_err());
    }
}

#[test]
fn bootstrap_rejects_invalid_key_rate_identifier_and_version() {
    let body = bootstrap(1);
    let mut invalid = body.clone();
    invalid[2..34].fill(0);
    assert!(decode_bootstrap(&invalid, &tenant()).is_err());
    invalid = body.clone();
    invalid[34..38].copy_from_slice(&1001_u32.to_le_bytes());
    assert!(decode_bootstrap(&invalid, &tenant()).is_err());
    for length in [0, 65, 255] {
        invalid = body.clone();
        invalid[40] = length;
        assert!(decode_bootstrap(&invalid, &tenant()).is_err());
    }
    invalid = body.clone();
    invalid[41] = 255;
    assert!(decode_bootstrap(&invalid, &tenant()).is_err());
    for (offset, value) in [(0, 0), (0, 2), (1, 1), (1, 255)] {
        invalid = body.clone();
        invalid[offset] = value;
        assert!(decode_bootstrap(&invalid, &tenant()).is_err());
    }
}

#[test]
fn reply_requires_exact_exhaustion_and_known_outcome_and_error_codes() {
    let reply = decode_reply(DONE).unwrap();
    assert_eq!(reply.sequence, 9);
    assert!(reply.indices.is_empty());
    assert!(reply.authenticated_peer.is_none());
    assert!(matches!(reply.outcome, Ok(None)));
    for end in 0..DONE.len() {
        assert!(decode_reply(&DONE[..end]).is_err());
    }
    let mut extra = DONE.to_vec();
    extra.push(0);
    assert!(decode_reply(&extra).is_err());
    for (offset, value) in [(0, 2), (1, 3), (14, 4), (14, 255)] {
        let mut invalid = DONE.to_vec();
        invalid[offset] = value;
        assert!(decode_reply(&invalid).is_err());
    }
    for (code, expected) in [
        (1, WireGuardError::InvalidConfiguration),
        (7, WireGuardError::UnknownPeer),
        (8, WireGuardError::InvalidPacket),
        (9, WireGuardError::PacketTooLarge),
        (10, WireGuardError::NoSession),
        (14, WireGuardError::Protocol),
    ] {
        let mut error = DONE.to_vec();
        error[14] = 3;
        error.push(code);
        assert!(matches!(decode_reply(&error).unwrap().outcome, Err(actual) if actual == expected));
    }
    for code in [0, 15, 255] {
        let mut error = DONE.to_vec();
        error[14] = 3;
        error.push(code);
        assert!(decode_reply(&error).is_err());
    }
}

#[test]
fn reply_binding_count_and_required_peer_sentinels_are_bounded() {
    let mut body = DONE[..12].to_vec();
    body.extend_from_slice(&12000_u16.to_le_bytes());
    for index in 0..12000_u32 {
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&index.to_le_bytes());
    }
    body.push(0);
    let reply = decode_reply(&body).unwrap();
    assert_eq!(reply.indices.len(), 12000);
    assert_eq!(reply.indices[11999].index, 11999);
    body[12..14].copy_from_slice(&12001_u16.to_le_bytes());
    assert!(decode_reply(&body).is_err());
    body[12..14].copy_from_slice(&12000_u16.to_le_bytes());
    body[14..16].fill(255);
    assert!(decode_reply(&body).is_err());
    let mut truncated = DONE.to_vec();
    truncated[12..14].copy_from_slice(&1_u16.to_le_bytes());
    assert!(decode_reply(&truncated).is_err());
}

#[test]
fn reply_payload_bounds_and_authentication_metadata_are_separate_fields() {
    for (tag, maximum) in [(1, 1312), (2, 1280)] {
        for size in [0, maximum, maximum + 1] {
            let mut body = DONE[..14].to_vec();
            body[10..12].copy_from_slice(&2_u16.to_le_bytes());
            body.push(tag);
            body.extend_from_slice(&2_u16.to_le_bytes());
            body.extend_from_slice(&(size as u16).to_le_bytes());
            body.resize(19 + size, 6);
            let result = decode_reply(&body);
            if size == maximum {
                let reply = result.unwrap();
                assert_eq!(reply.authenticated_peer, Some(2));
                let packet = match reply.outcome {
                    Ok(Some(
                        Output::Network { peer: 2, packet } | Output::Plaintext { peer: 2, packet },
                    )) => packet,
                    _ => panic!("wrong reply fields"),
                };
                assert_eq!(packet, vec![6; maximum]);
                body[15..17].fill(255);
                assert!(decode_reply(&body).is_err());
            } else {
                assert!(result.is_err());
            }
        }
    }
}

struct InterruptedChunks {
    bytes: Cursor<Vec<u8>>,
    calls: usize,
}
impl Read for InterruptedChunks {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 2 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let maximum = target.len().min(3);
        self.bytes.read(&mut target[..maximum])
    }
}

#[test]
fn framed_read_handles_interrupted_fragments_and_consumes_one_frame_only() {
    let mut wire = framed(DONE);
    let next = framed(&[1, 1]);
    wire.extend_from_slice(&next);
    let mut reader = InterruptedChunks {
        bytes: Cursor::new(wire),
        calls: 0,
    };
    assert_eq!(read_frame(&mut reader).unwrap().as_slice(), DONE);
    assert_eq!(reader.bytes.position(), (4 + DONE.len()) as u64);
    assert_eq!(read_frame(&mut reader).unwrap().as_slice(), [1, 1]);
}

#[test]
fn framed_read_rejects_oversize_before_payload_read_and_all_truncated_frames() {
    struct PrefixOnly {
        prefix: Cursor<[u8; 4]>,
    }
    impl Read for PrefixOnly {
        fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
            assert!(
                self.prefix.position() < 4,
                "invalid size must not read payload"
            );
            self.prefix.read(target)
        }
    }
    for size in [0_u32, 1, 131073, u32::MAX] {
        let mut reader = PrefixOnly {
            prefix: Cursor::new(size.to_le_bytes()),
        };
        assert!(matches!(
            read_frame(&mut reader),
            Err(ProtocolError::InvalidFrame)
        ));
    }
    let wire = framed(DONE);
    for end in 0..wire.len() {
        assert!(matches!(
            read_frame(&mut Cursor::new(&wire[..end])),
            Err(ProtocolError::Io)
        ));
    }
    let maximum = vec![6; 131072];
    assert_eq!(
        read_frame(&mut Cursor::new(framed(&maximum)))
            .unwrap()
            .as_slice(),
        maximum
    );
}
