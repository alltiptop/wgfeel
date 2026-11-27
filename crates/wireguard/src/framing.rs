use crate::{MAX_DATAGRAM_SIZE, MAX_PLAINTEXT_SIZE, WireGuardError};
use gotatun::packet::{Decoder, Ipv4, Ipv4Decoder, Ipv4Options, Ipv6, Ipv6Decoder};

/// Check framing before the upstream packet allocation/parser. Returns whether
/// this packet can add a source to the upstream handshake rate limiter.
pub(crate) fn datagram(bytes: &[u8]) -> Result<bool, WireGuardError> {
    datagram_for(bytes, false)
}
pub(crate) fn datagram_for(bytes: &[u8], external: bool) -> Result<bool, WireGuardError> {
    if bytes.len()
        > if external {
            crate::MAX_PROVIDER_DATAGRAM_SIZE
        } else {
            MAX_DATAGRAM_SIZE
        }
    {
        return Err(WireGuardError::PacketTooLarge);
    }
    if bytes.len() < 4 || bytes[1..4] != [0; 3] {
        return Err(WireGuardError::InvalidPacket);
    }
    match (bytes[0], bytes.len()) {
        (1, 148) | (2, 92) => Ok(true),
        (3, 64) => Ok(false),
        (4, 32..) => Ok(false),
        _ => Err(WireGuardError::InvalidPacket),
    }
}

/// Public routing hint only. An initiation carries no receiver index.
pub(crate) fn receiver_index(bytes: &[u8]) -> Result<Option<u32>, WireGuardError> {
    receiver_index_for(bytes, false)
}
pub(crate) fn receiver_index_for(
    bytes: &[u8],
    external: bool,
) -> Result<Option<u32>, WireGuardError> {
    datagram_for(bytes, external)?;
    if bytes[0] == 1 {
        return Ok(None);
    }
    let offset = if bytes[0] == 2 { 8 } else { 4 };
    Ok(Some(u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated WG header"),
    )))
}

/// Upstream IP framing validation, including IPv4 options. Checksums, source
/// ownership, extensions and fragment policy belong to the forwarding layer.
pub(crate) fn ip_length(bytes: &[u8], padded: bool) -> Result<usize, WireGuardError> {
    ip_length_for(bytes, padded, false)
}
pub(crate) fn ip_length_for(
    bytes: &[u8],
    padded: bool,
    external: bool,
) -> Result<usize, WireGuardError> {
    if bytes.len()
        > if external {
            crate::MAX_PROVIDER_PLAINTEXT
        } else {
            MAX_PLAINTEXT_SIZE
        }
    {
        return Err(WireGuardError::PacketTooLarge);
    }
    let length = match bytes.first().map(|b| b >> 4) {
        Some(4) => Decoder::<[u8], Ipv4<Ipv4Options>>::validate(
            &Ipv4Decoder {
                checksum: false,
                ..Ipv4Decoder::CHECK_ALL
            },
            bytes,
        ),
        Some(6) => Decoder::<[u8], Ipv6>::validate(&Ipv6Decoder::CHECK_ALL, bytes),
        _ => return Err(WireGuardError::InvalidPacket),
    }
    .map_err(|_| WireGuardError::InvalidPacket)?;
    let padding = bytes
        .len()
        .checked_sub(length)
        .ok_or(WireGuardError::InvalidPacket)?;
    if padding > if padded { 15 } else { 0 } {
        return Err(WireGuardError::InvalidPacket);
    }
    Ok(length)
}
