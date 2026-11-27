//! Private versioned pipe protocol. Decoders accept bodies; encoders add framing.
use crate::{
    ContextConfig, ContextId, Limits, MAX_DATAGRAM_SIZE, MAX_DEVICE_PEERS, MAX_PLAINTEXT_SIZE,
    MAX_SERVICE_PEERS, PeerConfig, PeerId, WireGuardError, dispatch::MAX_INDICES_PER_PEER,
};
use std::io::Read;
use wgfeel_core::{
    DeviceId, DevicePublicKey, GatewayPrivateKey, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

pub(super) const MAX_FRAME_BYTES: usize = 131_072;
const NONE: u16 = u16::MAX;
const MAX_BINDINGS: usize = (MAX_DEVICE_PEERS + MAX_SERVICE_PEERS) * MAX_INDICES_PER_PEER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProtocolError {
    InvalidFrame,
    Io,
}
pub(super) struct Request {
    pub sequence: u64,
    pub operation: Operation,
}
pub(super) enum Operation {
    Receive { peer: Option<u16>, packet: Vec<u8> },
    Initiate { peer: u16 },
    Send { peer: u16, packet: Vec<u8> },
    Tick { peer: u16 },
    Reset { peer: u16 },
    SetServicePeers { peers: Vec<PeerConfig> },
}
pub(super) struct Binding {
    pub peer: u16,
    pub index: u32,
}
pub(super) struct Reply {
    pub sequence: u64,
    pub indices: Vec<Binding>,
    pub authenticated_peer: Option<u16>,
    pub outcome: Result<Option<Output>, WireGuardError>,
}
pub(super) enum Output {
    Network { peer: u16, packet: Vec<u8> },
    Plaintext { peer: u16, packet: Vec<u8> },
}

pub(super) fn encode_ready() -> Vec<u8> {
    vec![2, 0, 0, 0, 1, 1]
}
pub(super) fn is_ready(body: &[u8]) -> bool {
    body == [1, 1]
}

pub(super) fn encode_bootstrap(
    config: &ContextConfig,
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let maximum = peer_limit(&config.id);
    if config.peers.len() > maximum
        || !peer_counts(&config.peers)
        || limits.handshake_limit_per_ip > 1000
    {
        return Err(ProtocolError::InvalidFrame);
    }
    let mut size = 40;
    if let crate::PrivateKey::External { psk, .. } = &config.private_key {
        if config.peers.len() != 1 {
            return Err(ProtocolError::InvalidFrame);
        }
        size += 3 + if psk.is_some() { 32 } else { 0 };
    }
    for peer in &config.peers {
        let id = peer_name(&peer.id);
        if id.is_empty() || id.len() > 64 || !role_matches(&config.id, &peer.id) {
            return Err(ProtocolError::InvalidFrame);
        }
        size += 1 + id.len() + 32;
    }
    // Allocate the complete frame before copying the private key. No growth or
    // ordinary Vec containing bootstrap secret bytes is allowed afterwards.
    let mut frame = Zeroizing::new(frame_start(size, 2)?);
    frame.extend_from_slice(config.private_key.expose_bytes());
    frame.extend_from_slice(&limits.handshake_limit_per_ip.to_le_bytes());
    frame.extend_from_slice(&(config.peers.len() as u16).to_le_bytes());
    for peer in &config.peers {
        let id = peer_name(&peer.id);
        frame.push(
            id.len() as u8
                | if matches!(peer.id, PeerId::Gateway(_)) {
                    0x80
                } else {
                    0
                },
        );
        frame.extend_from_slice(id.as_bytes());
        frame.extend_from_slice(peer.public_key.as_bytes());
    }
    if let crate::PrivateKey::External { psk, keepalive, .. } = &config.private_key {
        frame.extend_from_slice(&keepalive.map_or(0, |k| k.get()).to_le_bytes());
        frame.push(u8::from(psk.is_some()));
        if let Some(key) = psk {
            frame.extend_from_slice(key.expose_bytes());
        }
    }
    Ok(frame)
}

pub(super) fn decode_bootstrap(
    body: &[u8],
    context: &ContextId,
) -> Result<(ContextConfig, Limits), ProtocolError> {
    let mut cursor = Cursor::new(body, 2)?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(cursor.take(32)?);
    let handshake_limit_per_ip = cursor.u32()?;
    let count = usize::from(cursor.u16()?);
    if handshake_limit_per_ip > 1000 || count > peer_limit(context) {
        return Err(ProtocolError::InvalidFrame);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let tagged = cursor.u8()?;
        let mesh = tagged & 0x80 != 0;
        let length = usize::from(tagged & 0x7f);
        if length == 0 || length > 64 {
            return Err(ProtocolError::InvalidFrame);
        }
        let name =
            std::str::from_utf8(cursor.take(length)?).map_err(|_| ProtocolError::InvalidFrame)?;
        let id = match (context, mesh) {
            (ContextId::External(_), false) if name == "provider" => PeerId::Provider,
            (ContextId::Tenant(_), true) => {
                PeerId::Gateway(NodeId::new(name).map_err(|_| ProtocolError::InvalidFrame)?)
            }
            (ContextId::Tenant(_), false) => {
                PeerId::Device(DeviceId::new(name).map_err(|_| ProtocolError::InvalidFrame)?)
            }
            (ContextId::Service | ContextId::Gateway, false) => {
                PeerId::Node(NodeId::new(name).map_err(|_| ProtocolError::InvalidFrame)?)
            }
            _ => return Err(ProtocolError::InvalidFrame),
        };
        let public_key = DevicePublicKey::new(
            cursor
                .take(32)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidFrame)?,
        )
        .map_err(|_| ProtocolError::InvalidFrame)?;
        peers.push(PeerConfig { id, public_key });
    }
    if !peer_counts(&peers) {
        return Err(ProtocolError::InvalidFrame);
    }
    let config = match context {
        ContextId::External(id) => {
            if peers.len() != 1 {
                return Err(ProtocolError::InvalidFrame);
            }
            let keepalive = std::num::NonZeroU16::new(cursor.u16()?);
            let psk = match cursor.u8()? {
                0 => None,
                1 => Some(
                    wgfeel_core::PresharedKey::new(
                        cursor
                            .take(32)?
                            .try_into()
                            .map_err(|_| ProtocolError::InvalidFrame)?,
                    )
                    .map_err(|_| ProtocolError::InvalidFrame)?,
                ),
                _ => return Err(ProtocolError::InvalidFrame),
            };
            let peer = peers.pop().ok_or(ProtocolError::InvalidFrame)?;
            ContextConfig::external(
                id.clone(),
                wgfeel_core::EgressPrivateKey::new(*key)
                    .map_err(|_| ProtocolError::InvalidFrame)?,
                psk,
                keepalive,
                peer.public_key,
            )
        }
        ContextId::Tenant(id) => ContextConfig::tenant(
            id.clone(),
            TenantPrivateKey::new(*key).map_err(|_| ProtocolError::InvalidFrame)?,
            peers,
        ),
        ContextId::Gateway => ContextConfig::gateway(
            GatewayPrivateKey::new(*key).map_err(|_| ProtocolError::InvalidFrame)?,
            peers,
        ),
        ContextId::Service => ContextConfig::service(
            ServicePrivateKey::new(*key).map_err(|_| ProtocolError::InvalidFrame)?,
            peers,
        ),
    };
    cursor.finish()?;
    Ok((
        config,
        Limits {
            handshake_limit_per_ip,
        },
    ))
}

#[cfg(test)]
pub(super) fn encode_request(request: &Request) -> Result<Vec<u8>, ProtocolError> {
    encode_request_scoped(false, request)
}
pub(super) fn encode_request_scoped(
    external: bool,
    request: &Request,
) -> Result<Vec<u8>, ProtocolError> {
    if let Operation::SetServicePeers { peers } = &request.operation {
        if peers.len() > MAX_SERVICE_PEERS
            || peers.iter().any(|peer| !matches!(peer.id, PeerId::Node(_)))
        {
            return Err(ProtocolError::InvalidFrame);
        }
        let size = 15
            + peers
                .iter()
                .map(|peer| 33 + peer_name(&peer.id).len())
                .sum::<usize>();
        let mut frame = frame_start(size, 3)?;
        frame.extend_from_slice(&request.sequence.to_le_bytes());
        frame.push(6);
        frame.extend_from_slice(&NONE.to_le_bytes());
        frame.extend_from_slice(&(peers.len() as u16).to_le_bytes());
        for peer in peers {
            let id = peer_name(&peer.id);
            frame.push(id.len() as u8);
            frame.extend_from_slice(id.as_bytes());
            frame.extend_from_slice(peer.public_key.as_bytes());
        }
        return Ok(frame);
    }
    let (tag, peer, packet) = match &request.operation {
        Operation::Receive { peer, packet } => (
            1,
            peer.unwrap_or(NONE),
            Some((
                packet,
                if external {
                    crate::MAX_PROVIDER_DATAGRAM_SIZE
                } else {
                    MAX_DATAGRAM_SIZE
                },
            )),
        ),
        Operation::Initiate { peer } => (2, required_peer(*peer)?, None),
        Operation::Send { peer, packet } => {
            (3, required_peer(*peer)?, Some((packet, MAX_PLAINTEXT_SIZE)))
        }
        Operation::Tick { peer } => (4, required_peer(*peer)?, None),
        Operation::Reset { peer } => (5, required_peer(*peer)?, None),
        Operation::SetServicePeers { .. } => unreachable!("handled above"),
    };
    if matches!(
        &request.operation,
        Operation::Receive {
            peer: Some(NONE),
            ..
        }
    ) {
        return Err(ProtocolError::InvalidFrame);
    }
    let size = 13 + packet.map_or(0, |(packet, _)| 2 + packet.len());
    let mut frame = frame_start(size, 3)?;
    frame.extend_from_slice(&request.sequence.to_le_bytes());
    frame.push(tag);
    frame.extend_from_slice(&peer.to_le_bytes());
    if let Some((packet, limit)) = packet {
        put_packet(&mut frame, packet, limit)?;
    }
    Ok(frame)
}

#[cfg(test)]
pub(super) fn decode_request(body: &[u8]) -> Result<Request, ProtocolError> {
    decode_request_scoped(false, body)
}
pub(super) fn decode_request_scoped(external: bool, body: &[u8]) -> Result<Request, ProtocolError> {
    let mut cursor = Cursor::new(body, 3)?;
    let sequence = cursor.u64()?;
    let tag = cursor.u8()?;
    let peer = cursor.u16()?;
    let operation = match tag {
        1 => Operation::Receive {
            peer: optional_peer(peer),
            packet: cursor.packet(if external {
                crate::MAX_PROVIDER_DATAGRAM_SIZE
            } else {
                MAX_DATAGRAM_SIZE
            })?,
        },
        2 => Operation::Initiate {
            peer: required_peer(peer)?,
        },
        3 => Operation::Send {
            peer: required_peer(peer)?,
            packet: cursor.packet(MAX_PLAINTEXT_SIZE)?,
        },
        4 => Operation::Tick {
            peer: required_peer(peer)?,
        },
        5 => Operation::Reset {
            peer: required_peer(peer)?,
        },
        6 if peer == NONE => {
            let count = usize::from(cursor.u16()?);
            if count > MAX_SERVICE_PEERS {
                return Err(ProtocolError::InvalidFrame);
            }
            let mut peers = Vec::with_capacity(count);
            for _ in 0..count {
                let length = usize::from(cursor.u8()?);
                if length == 0 || length > 64 {
                    return Err(ProtocolError::InvalidFrame);
                }
                let name = std::str::from_utf8(cursor.take(length)?)
                    .map_err(|_| ProtocolError::InvalidFrame)?;
                let id = PeerId::Node(NodeId::new(name).map_err(|_| ProtocolError::InvalidFrame)?);
                let public_key = DevicePublicKey::new(
                    cursor
                        .take(32)?
                        .try_into()
                        .map_err(|_| ProtocolError::InvalidFrame)?,
                )
                .map_err(|_| ProtocolError::InvalidFrame)?;
                peers.push(PeerConfig { id, public_key });
            }
            Operation::SetServicePeers { peers }
        }
        _ => return Err(ProtocolError::InvalidFrame),
    };
    cursor.finish()?;
    Ok(Request {
        sequence,
        operation,
    })
}

pub(super) fn encode_reply_scoped(external: bool, reply: &Reply) -> Result<Vec<u8>, ProtocolError> {
    if reply.indices.len() > MAX_BINDINGS || reply.authenticated_peer == Some(NONE) {
        return Err(ProtocolError::InvalidFrame);
    }
    let extra = match &reply.outcome {
        Ok(None) => 0,
        Err(_) => 1,
        Ok(Some(Output::Network { packet, .. } | Output::Plaintext { packet, .. })) => {
            4 + packet.len()
        }
    };
    let mut frame = frame_start(15 + reply.indices.len() * 6 + extra, 4)?;
    frame.extend_from_slice(&reply.sequence.to_le_bytes());
    frame.extend_from_slice(&reply.authenticated_peer.unwrap_or(NONE).to_le_bytes());
    frame.extend_from_slice(&(reply.indices.len() as u16).to_le_bytes());
    for binding in &reply.indices {
        frame.extend_from_slice(&required_peer(binding.peer)?.to_le_bytes());
        frame.extend_from_slice(&binding.index.to_le_bytes());
    }
    match &reply.outcome {
        Ok(None) => frame.push(0),
        Ok(Some(Output::Network { peer, packet })) => {
            frame.push(1);
            frame.extend_from_slice(&required_peer(*peer)?.to_le_bytes());
            put_packet(&mut frame, packet, MAX_DATAGRAM_SIZE)?;
        }
        Ok(Some(Output::Plaintext { peer, packet })) => {
            frame.push(2);
            frame.extend_from_slice(&required_peer(*peer)?.to_le_bytes());
            put_packet(
                &mut frame,
                packet,
                if external {
                    crate::MAX_PROVIDER_PLAINTEXT
                } else {
                    MAX_PLAINTEXT_SIZE
                },
            )?;
        }
        Err(error) => {
            frame.push(3);
            frame.push(error_code(*error));
        }
    }
    Ok(frame)
}

#[cfg(test)]
pub(super) fn decode_reply(body: &[u8]) -> Result<Reply, ProtocolError> {
    decode_reply_scoped(false, body)
}
pub(super) fn decode_reply_scoped(external: bool, body: &[u8]) -> Result<Reply, ProtocolError> {
    let mut cursor = Cursor::new(body, 4)?;
    let sequence = cursor.u64()?;
    let authenticated_peer = optional_peer(cursor.u16()?);
    let count = usize::from(cursor.u16()?);
    if count > MAX_BINDINGS || count * 6 > cursor.remaining() {
        return Err(ProtocolError::InvalidFrame);
    }
    let mut indices = Vec::with_capacity(count);
    for _ in 0..count {
        indices.push(Binding {
            peer: required_peer(cursor.u16()?)?,
            index: cursor.u32()?,
        });
    }
    let outcome = match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Output::Network {
            peer: required_peer(cursor.u16()?)?,
            packet: cursor.packet(MAX_DATAGRAM_SIZE)?,
        })),
        2 => Ok(Some(Output::Plaintext {
            peer: required_peer(cursor.u16()?)?,
            packet: cursor.packet(if external {
                crate::MAX_PROVIDER_PLAINTEXT
            } else {
                MAX_PLAINTEXT_SIZE
            })?,
        })),
        3 => Err(decode_error(cursor.u8()?)?),
        _ => return Err(ProtocolError::InvalidFrame),
    };
    cursor.finish()?;
    Ok(Reply {
        sequence,
        indices,
        authenticated_peer,
        outcome,
    })
}

pub(super) fn read_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ProtocolError::Io)?;
    let size = u32::from_le_bytes(prefix) as usize;
    if !(2..=MAX_FRAME_BYTES).contains(&size) {
        return Err(ProtocolError::InvalidFrame);
    }
    let mut body = Zeroizing::new(vec![0; size]);
    reader
        .read_exact(&mut body)
        .map_err(|_| ProtocolError::Io)?;
    Ok(body)
}

fn frame_start(size: usize, tag: u8) -> Result<Vec<u8>, ProtocolError> {
    if !(2..=MAX_FRAME_BYTES).contains(&size) {
        return Err(ProtocolError::InvalidFrame);
    }
    let mut frame = Vec::with_capacity(size + 4);
    frame.extend_from_slice(&(size as u32).to_le_bytes());
    frame.extend_from_slice(&[1, tag]);
    Ok(frame)
}
fn put_packet(frame: &mut Vec<u8>, packet: &[u8], maximum: usize) -> Result<(), ProtocolError> {
    if packet.is_empty() || packet.len() > maximum {
        return Err(ProtocolError::InvalidFrame);
    }
    frame.extend_from_slice(&(packet.len() as u16).to_le_bytes());
    frame.extend_from_slice(packet);
    Ok(())
}
fn peer_counts(peers: &[PeerConfig]) -> bool {
    peers
        .iter()
        .filter(|peer| matches!(peer.id, PeerId::Device(_)))
        .count()
        <= crate::MAX_DEVICE_PEERS
        && peers
            .iter()
            .filter(|peer| matches!(peer.id, PeerId::Gateway(_)))
            .count()
            <= wgfeel_core::MAX_GATEWAYS
}
fn peer_limit(context: &ContextId) -> usize {
    if matches!(context, ContextId::External(_)) {
        1
    } else if matches!(context, ContextId::Service) {
        MAX_SERVICE_PEERS
    } else if *context == ContextId::Gateway {
        wgfeel_core::MAX_GATEWAYS
    } else {
        MAX_DEVICE_PEERS + wgfeel_core::MAX_GATEWAYS
    }
}
fn peer_name(peer: &PeerId) -> &str {
    match peer {
        PeerId::Provider => "provider",
        PeerId::Device(id) => id.as_str(),
        PeerId::Node(id) | PeerId::Gateway(id) => id.as_str(),
    }
}
fn role_matches(context: &ContextId, peer: &PeerId) -> bool {
    matches!(
        (context, peer),
        (ContextId::Tenant(_), PeerId::Device(_) | PeerId::Gateway(_))
            | (ContextId::Service | ContextId::Gateway, PeerId::Node(_))
            | (ContextId::External(_), PeerId::Provider)
    )
}
fn required_peer(peer: u16) -> Result<u16, ProtocolError> {
    if peer == NONE {
        Err(ProtocolError::InvalidFrame)
    } else {
        Ok(peer)
    }
}
fn optional_peer(peer: u16) -> Option<u16> {
    (peer != NONE).then_some(peer)
}
struct Cursor<'a> {
    body: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(body: &'a [u8], tag: u8) -> Result<Self, ProtocolError> {
        if body.len() > MAX_FRAME_BYTES || !body.starts_with(&[1, tag]) {
            return Err(ProtocolError::InvalidFrame);
        }
        Ok(Self { body, position: 2 })
    }
    fn remaining(&self) -> usize {
        self.body.len() - self.position
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8], ProtocolError> {
        if size > self.remaining() {
            return Err(ProtocolError::InvalidFrame);
        }
        let start = self.position;
        self.position += size;
        Ok(&self.body[start..self.position])
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidFrame)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidFrame)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProtocolError::InvalidFrame)?,
        ))
    }
    fn packet(&mut self, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
        let size = usize::from(self.u16()?);
        if size == 0 || size > maximum {
            return Err(ProtocolError::InvalidFrame);
        }
        Ok(self.take(size)?.to_vec())
    }
    fn finish(self) -> Result<(), ProtocolError> {
        if self.position == self.body.len() {
            Ok(())
        } else {
            Err(ProtocolError::InvalidFrame)
        }
    }
}
fn error_code(error: WireGuardError) -> u8 {
    match error {
        WireGuardError::InvalidConfiguration => 1,
        WireGuardError::DuplicateContext => 2,
        WireGuardError::DuplicateGatewayKey => 3,
        WireGuardError::DuplicatePeer => 4,
        WireGuardError::InvalidPeerKey => 5,
        WireGuardError::UnknownContext => 6,
        WireGuardError::UnknownPeer => 7,
        WireGuardError::InvalidPacket => 8,
        WireGuardError::PacketTooLarge => 9,
        WireGuardError::NoSession => 10,
        WireGuardError::NoEndpoint => 11,
        WireGuardError::UnknownIndex => 12,
        WireGuardError::SourceLimit => 13,
        WireGuardError::Protocol => 14,
    }
}
fn decode_error(code: u8) -> Result<WireGuardError, ProtocolError> {
    Ok(match code {
        1 => WireGuardError::InvalidConfiguration,
        2 => WireGuardError::DuplicateContext,
        3 => WireGuardError::DuplicateGatewayKey,
        4 => WireGuardError::DuplicatePeer,
        5 => WireGuardError::InvalidPeerKey,
        6 => WireGuardError::UnknownContext,
        7 => WireGuardError::UnknownPeer,
        8 => WireGuardError::InvalidPacket,
        9 => WireGuardError::PacketTooLarge,
        10 => WireGuardError::NoSession,
        11 => WireGuardError::NoEndpoint,
        12 => WireGuardError::UnknownIndex,
        13 => WireGuardError::SourceLimit,
        14 => WireGuardError::Protocol,
        _ => return Err(ProtocolError::InvalidFrame),
    })
}
