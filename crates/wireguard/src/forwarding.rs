use crate::{ContextId, DatagramEvent, Gateway, PacketBytes, PeerId, WireGuardError, framing};
use gotatun::packet::{
    Decoder, Ipv4, Ipv4Decoder, Tcp, TcpDecoder, Udp, UdpDecoder, checksum_ipv4_with_skip,
};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use wgfeel_core::{Action, Endpoint, GatewayProjection, RouteError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardError {
    MissingProjection,
    InvalidPacket,
    UnsupportedPacket,
    SourceMismatch,
    UnknownDestination,
    AmbiguousDestination,
    Denied,
    NotLocal,
    HopLimitExceeded,
    WireGuard(WireGuardError),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Local forwarding rejected: {self:?}")
    }
}
impl std::error::Error for ForwardError {}

impl Gateway {
    /// Authenticate one encrypted datagram and forward permitted tenant traffic
    /// directly to an established local peer. No plaintext or caller-supplied
    /// identity is accepted at this boundary, and no payload is queued.
    pub fn receive_local_datagram(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Option<DatagramEvent>, ForwardError> {
        if self.projection().is_none() {
            return Err(ForwardError::MissingProjection);
        }
        match self
            .receive_datagram(source, bytes)
            .map_err(ForwardError::WireGuard)?
        {
            Some(DatagramEvent::Plaintext {
                context,
                peer,
                packet,
            }) => self.forward_local(context, peer, packet).map(Some),
            event => Ok(event),
        }
    }

    fn forward_local(
        &mut self,
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
    ) -> Result<DatagramEvent, ForwardError> {
        let projection = self.projection().ok_or(ForwardError::MissingProjection)?;
        let (destination, packet) = authorize_local(projection, context, peer, packet)?;
        self.send_datagram(
            &ContextId::Tenant(destination.network().clone()),
            &PeerId::Device(destination.device().clone()),
            packet.as_bytes(),
        )
        .map_err(ForwardError::WireGuard)
    }
}

/// Trusted shared forwarding policy for already authenticated channel/peer
/// metadata. This remains crate-private: it is not a plaintext ingress API.
pub(crate) fn authorize_local(
    projection: &GatewayProjection,
    context: ContextId,
    peer: PeerId,
    packet: PacketBytes,
) -> Result<(Endpoint, PacketBytes), ForwardError> {
    if !matches!(peer, PeerId::Device(_)) {
        return Err(ForwardError::NotLocal);
    }
    let (traffic, home, packet) = authorize_routed(projection, context, peer, packet)?;
    if home.is_some_and(|home| home != *projection.recipient()) {
        return Err(ForwardError::NotLocal);
    }
    Ok((traffic.destination, packet))
}

pub(crate) fn authorize_routed(
    projection: &GatewayProjection,
    context: ContextId,
    peer: PeerId,
    mut packet: PacketBytes,
) -> Result<
    (
        crate::mesh::Traffic,
        Option<wgfeel_core::NodeId>,
        PacketBytes,
    ),
    ForwardError,
> {
    let ContextId::Tenant(network) = context else {
        return Err(ForwardError::NotLocal);
    };
    if !projection
        .assignment()
        .tenants()
        .iter()
        .any(|tenant| tenant.network() == &network)
    {
        return Err(ForwardError::NotLocal);
    }
    let parsed = parse(packet.as_bytes())?;
    if packet.as_bytes()[parsed.hop_offset] <= 1 {
        return Err(ForwardError::HopLimitExceeded);
    }
    let configured_network = projection
        .config()
        .networks()
        .iter()
        .find(|candidate| candidate.id() == &network)
        .ok_or(ForwardError::SourceMismatch)?;
    let configured_source = configured_network
        .devices()
        .iter()
        .find(|device| {
            device.addresses().contains(&parsed.source)
                && match &peer {
                    PeerId::Device(id) => {
                        device.id() == id
                            && device
                                .gateway()
                                .is_none_or(|home| home == projection.recipient())
                    }
                    PeerId::Gateway(origin) => {
                        origin != projection.recipient() && device.gateway() == Some(origin)
                    }
                    _ => false,
                }
        })
        .ok_or(ForwardError::SourceMismatch)?;
    let source = Endpoint::new(network, configured_source.id().clone());
    let destination = projection
        .config()
        .resolve_destination(&source, parsed.destination)
        .map_err(|error| match error {
            RouteError::UnknownSource => ForwardError::SourceMismatch,
            RouteError::UnknownDestination => ForwardError::UnknownDestination,
            RouteError::AmbiguousDestination => ForwardError::AmbiguousDestination,
        })?;
    if !projection
        .assignment()
        .tenants()
        .iter()
        .any(|tenant| tenant.network() == destination.network())
    {
        return Err(ForwardError::NotLocal);
    }
    let home = projection
        .device(&destination)
        .and_then(|device| device.gateway())
        .cloned();
    // Decrypted inter-node traffic must terminate here. Relays handle only the
    // opaque inner ciphertext; they cannot open a fresh plaintext ingress.
    if matches!(peer, PeerId::Gateway(_)) && home.as_ref() != Some(projection.recipient()) {
        return Err(ForwardError::NotLocal);
    }
    let origin = match &peer {
        PeerId::Device(_) => projection.recipient(),
        PeerId::Gateway(origin) => origin,
        _ => return Err(ForwardError::SourceMismatch),
    };
    if projection.forwarding_decision(
        &source,
        &destination,
        origin,
        home.as_ref().unwrap_or(projection.recipient()),
    ) != Action::Allow
    {
        return Err(ForwardError::Denied);
    }
    packet.0[parsed.hop_offset] -= 1;
    if parsed.hop_offset == 8 {
        let checksum = checksum_ipv4_with_skip(&packet.0[..20]);
        packet.0[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    Ok((
        crate::mesh::Traffic {
            source,
            destination,
        },
        home,
        packet,
    ))
}

struct ParsedIp {
    source: IpAddr,
    destination: IpAddr,
    hop_offset: usize,
    protocol: u8,
    transport_offset: usize,
}

/// DNS is a local service, reachable only from a source-bound device in its
/// authenticated tenant. Mesh/service peers cannot become DNS clients.
pub(crate) fn authorize_dns(
    projection: &GatewayProjection,
    context: &ContextId,
    peer: &PeerId,
    bytes: &[u8],
    reply: bool,
) -> Result<bool, ForwardError> {
    let parsed = parse(bytes)?;
    let (service, client) = if reply {
        (parsed.source, parsed.destination)
    } else {
        (parsed.destination, parsed.source)
    };
    if !wgfeel_core::is_dns_address(service) {
        return Ok(false);
    }
    let (ContextId::Tenant(network), PeerId::Device(id)) = (context, peer) else {
        return Err(ForwardError::Denied);
    };
    if projection.is_revoked()
        || !projection
            .assignment()
            .tenants()
            .iter()
            .any(|tenant| tenant.network() == network)
    {
        return Err(ForwardError::Denied);
    }
    let network = projection
        .config()
        .networks()
        .iter()
        .find(|n| n.id() == network)
        .filter(|n| !n.suspended())
        .ok_or(ForwardError::Denied)?;
    if !network.devices().iter().any(|device| {
        device.id() == id
            && device.addresses().contains(&client)
            && device
                .gateway()
                .is_none_or(|home| home == projection.recipient())
    }) {
        return Err(ForwardError::SourceMismatch);
    }
    let offset = parsed.transport_offset + if reply { 0 } else { 2 };
    if !matches!(parsed.protocol, 6 | 17) || bytes[offset..offset + 2] != [0, 53] {
        return Err(ForwardError::Denied);
    }
    Ok(true)
}

/// Restrict the forwarding surface to base IP headers and complete TCP, UDP or
/// family-specific ICMP headers. L4 checksums and connection state are not
/// evaluated: the current ACL grants complete directional endpoint access.
fn parse(bytes: &[u8]) -> Result<ParsedIp, ForwardError> {
    framing::ip_length(bytes, false).map_err(|_| ForwardError::InvalidPacket)?;
    let (source, destination, hop_offset, protocol, payload) = match bytes[0] >> 4 {
        4 => {
            if bytes[0] & 0x0f != 5 {
                return Err(ForwardError::UnsupportedPacket);
            }
            Decoder::<[u8], Ipv4>::validate(&Ipv4Decoder::CHECK_ALL, bytes)
                .map_err(|_| ForwardError::InvalidPacket)?;
            // Only DF is supported. Reserved bits, MF and every fragment offset
            // fail closed rather than bypassing transport-header checks.
            if u16::from_be_bytes([bytes[6], bytes[7]]) & !0x4000 != 0 {
                return Err(ForwardError::UnsupportedPacket);
            }
            (
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                8,
                bytes[9],
                &bytes[20..],
            )
        }
        6 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| ForwardError::InvalidPacket)?,
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[24..40]).map_err(|_| ForwardError::InvalidPacket)?,
            )),
            7,
            bytes[6],
            &bytes[40..],
        ),
        _ => return Err(ForwardError::InvalidPacket),
    };
    if [source, destination].iter().any(|address| match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }) {
        return Err(ForwardError::UnsupportedPacket);
    }
    match protocol {
        // The raw-slice decoders check lengths/data offset only; their checksum
        // option applies only with an IP wrapper. No packet allocation is needed.
        6 => {
            Decoder::<[u8], Tcp>::validate(&TcpDecoder::CHECK_ALL, payload)
                .map_err(|_| ForwardError::InvalidPacket)?;
        }
        17 => {
            Decoder::<[u8], Udp>::validate(&UdpDecoder::CHECK_ALL, payload)
                .map_err(|_| ForwardError::InvalidPacket)?;
        }
        1 if source.is_ipv4() => {
            if payload.len() < 8 {
                return Err(ForwardError::InvalidPacket);
            }
        }
        58 if source.is_ipv6() => {
            if payload.len() < 8 {
                return Err(ForwardError::InvalidPacket);
            }
        }
        // This allowlist excludes IPv6 extension chains, including fragments,
        // routing/AH/ESP headers, and unsupported tunneling protocols.
        _ => return Err(ForwardError::UnsupportedPacket),
    }
    if bytes[hop_offset] == 0 {
        return Err(ForwardError::HopLimitExceeded);
    }
    Ok(ParsedIp {
        source,
        destination,
        hop_offset,
        protocol,
        transport_offset: if source.is_ipv4() { 20 } else { 40 },
    })
}
