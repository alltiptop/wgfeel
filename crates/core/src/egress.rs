//! Public, provider-supplied session parameters. Placement and user grants are
//! separate management operations.
use crate::{
    DevicePublicKey, DomainError, EgressId, canonical_public_key, validate_node_endpoints,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

pub const MAX_EGRESSES: usize = 64;
pub const MAX_PROFILE_BYTES: usize = 16_384;
pub const MAX_ALLOWED_IPS_PER_EGRESS: usize = 64;
pub const MAX_DNS_SERVERS_PER_EGRESS: usize = 4;

/// Canonical CIDR. The network address is masked even for input with host bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, schemars::JsonSchema)]
#[schemars(with = "String")]
pub struct IpPrefix {
    network: IpAddr,
    length: u8,
}
impl FromStr for IpPrefix {
    type Err = DomainError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, bits) = value.split_once('/').ok_or(DomainError::InvalidAddress)?;
        let ip: IpAddr = address.parse().map_err(|_| DomainError::InvalidAddress)?;
        let length: u8 = bits.parse().map_err(|_| DomainError::InvalidAddress)?;
        if !bits.bytes().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::InvalidAddress);
        }
        Self::new(ip, length)
    }
}
impl IpPrefix {
    pub fn new(ip: IpAddr, length: u8) -> Result<Self, DomainError> {
        let network = match ip {
            IpAddr::V4(ip) if length <= 32 => IpAddr::V4(Ipv4Addr::from_bits(
                ip.to_bits() & u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0),
            )),
            IpAddr::V6(ip) if length <= 128 => IpAddr::V6(Ipv6Addr::from_bits(
                ip.to_bits() & u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0),
            )),
            _ => return Err(DomainError::InvalidAddress),
        };
        Ok(Self { network, length })
    }
    pub fn network(self) -> IpAddr {
        self.network
    }
    pub fn length(self) -> u8 {
        self.length
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (a.to_bits() ^ b.to_bits()).leading_zeros() >= u32::from(self.length)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                (a.to_bits() ^ b.to_bits()).leading_zeros() >= u32::from(self.length)
            }
            _ => false,
        }
    }
    pub fn covers(self, other: Self) -> bool {
        self.length <= other.length && self.contains(other.network)
    }
    pub fn host(ip: IpAddr) -> Self {
        Self {
            network: ip,
            length: if ip.is_ipv4() { 32 } else { 128 },
        }
    }
    pub fn internal_v4() -> Self {
        Self {
            network: IpAddr::V4(Ipv4Addr::new(10, 203, 0, 0)),
            length: 16,
        }
    }
    pub fn internal_v6() -> Self {
        Self {
            network: IpAddr::V6(Ipv6Addr::new(0xfd77, 0x77, 0, 0, 0, 0, 0, 0)),
            length: 64,
        }
    }
    pub fn internal(self) -> bool {
        Self::internal_v4().covers(self) || Self::internal_v6().covers(self)
    }
}
impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

pub fn validate_external_endpoint(endpoint: SocketAddr) -> Result<(), DomainError> {
    validate_node_endpoints(&[endpoint]).map_err(|_| DomainError::InvalidAddress)?;
    if endpoint.ip().is_loopback() {
        return Err(DomainError::InvalidAddress);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, schemars::JsonSchema)]
#[schemars(with = "String")]
pub struct EgressEndpoint {
    host: String,
    port: u16,
}
impl EgressEndpoint {
    pub fn default_name(&self) -> &str {
        // Hostnames are ASCII and IP literals are shorter than the name limit.
        let name = self.host.strip_suffix('.').unwrap_or(&self.host);
        &name[..name.len().min(128)]
    }
}
impl FromStr for EgressEndpoint {
    type Err = DomainError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            validate_external_endpoint(address)?;
            return Ok(Self {
                host: address.ip().to_string(),
                port: address.port(),
            });
        }
        let (dns_name, port) = value.rsplit_once(':').ok_or(DomainError::InvalidAddress)?;
        let host = dns_name.strip_suffix('.').unwrap_or(dns_name);
        if host.len() > 253
            || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || !port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(DomainError::InvalidAddress);
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or(DomainError::InvalidAddress)?;
        Ok(Self {
            host: dns_name.to_ascii_lowercase(),
            port,
        })
    }
}
impl fmt::Display for EgressEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

macro_rules! string_wire {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                String::deserialize(de)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
string_wire!(IpPrefix);
string_wire!(EgressEndpoint);

pub(crate) mod public_key {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    pub fn serialize<S: serde::Serializer>(
        key: &DevicePublicKey,
        se: S,
    ) -> Result<S::Ok, S::Error> {
        se.serialize_str(&STANDARD.encode(key.as_bytes()))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        de: D,
    ) -> Result<DevicePublicKey, D::Error> {
        let text = String::deserialize(de)?;
        let mut key = [0; 32];
        if text.len() != 44 || STANDARD.decode_slice(text, &mut key).ok() != Some(32) {
            return Err(serde::de::Error::custom(DomainError::InvalidKey));
        }
        DevicePublicKey::new(key).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "EgressProfileFields")]
pub struct EgressProfile(EgressProfileFields);

impl EgressProfile {
    pub fn with_placement(
        mut self,
        node: Option<crate::NodeId>,
        pending: Option<crate::NodeId>,
    ) -> Result<Self, DomainError> {
        self.0.node = node;
        self.0.pending_node = pending;
        self.0.validate()?;
        Ok(self)
    }
    pub fn with_secret_revision(mut self, revision: u64) -> Result<Self, DomainError> {
        if revision == 0 {
            return Err(DomainError::InvalidGeneration);
        }
        self.0.secret_revision = revision;
        Ok(self)
    }
}
impl std::ops::Deref for EgressProfile {
    type Target = EgressProfileFields;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressProfileFields {
    pub id: EgressId,
    pub name: String,
    pub node: Option<crate::NodeId>,
    pub pending_node: Option<crate::NodeId>,
    pub secret_revision: u64,
    #[serde(with = "public_key")]
    #[schemars(with = "String")]
    pub interface_public_key: DevicePublicKey,
    pub addresses: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u16>,
    #[serde(with = "public_key")]
    #[schemars(with = "String")]
    pub peer_public_key: DevicePublicKey,
    pub endpoint: EgressEndpoint,
    pub allowed_ips: Vec<IpPrefix>,
    pub persistent_keepalive: Option<std::num::NonZeroU16>,
    pub has_preshared_key: bool,
}

impl TryFrom<EgressProfileFields> for EgressProfile {
    type Error = DomainError;
    fn try_from(mut fields: EgressProfileFields) -> Result<Self, DomainError> {
        fields.validate()?;
        let mut resolvers = std::collections::BTreeSet::new();
        fields.dns_servers.retain(|ip| resolvers.insert(*ip));
        let mut prefixes = std::collections::BTreeSet::new();
        fields.allowed_ips.retain(|prefix| prefixes.insert(*prefix));
        Ok(Self(fields))
    }
}
impl EgressProfileFields {
    fn validate(&self) -> Result<(), DomainError> {
        let usable = |ip: &IpAddr| validate_external_endpoint(SocketAddr::new(*ip, 1)).is_ok();
        let ipv6 = self.addresses.iter().any(IpAddr::is_ipv6);
        if self.name.trim() != self.name
            || self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
            || (self.node.is_some() && self.pending_node.is_some())
            || self.secret_revision == 0
            || !canonical_public_key(self.interface_public_key.as_bytes())
            || !canonical_public_key(self.peer_public_key.as_bytes())
            || self.interface_public_key == self.peer_public_key
            || self.addresses.is_empty()
            || self.addresses.len() > 2
            || self.addresses.len() == 2
                && self.addresses[0].is_ipv4() == self.addresses[1].is_ipv4()
            || !self.addresses.iter().all(usable)
            || self.dns_servers.len() > MAX_DNS_SERVERS_PER_EGRESS
            || !self.dns_servers.iter().all(usable)
            || self.allowed_ips.is_empty()
            || self.allowed_ips.len() > MAX_ALLOWED_IPS_PER_EGRESS
            || self
                .mtu
                .is_some_and(|mtu| mtu > 1500 || mtu < if ipv6 { 1280 } else { 576 })
        {
            return Err(DomainError::InvalidEgress);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_endpoint_filters_literal_candidates_and_accepts_lan_gateways() {
        for addr in [
            "127.42.0.1:1",
            "[::1]:1",
            "0.0.0.0:1",
            "[::]:1",
            "239.1.2.3:1",
            "[ff02::5]:1",
            "255.255.255.255:1",
            "169.254.169.254:80",
            "[fe80::5]:80",
            "[::ffff:10.0.0.2]:80",
            "10.0.0.1:0",
        ] {
            assert!(addr.parse::<EgressEndpoint>().is_err(), "{addr}");
        }
        for addr in ["[fd42::1]:51820", "10.0.0.1:443"] {
            assert_eq!(addr.parse::<EgressEndpoint>().unwrap().to_string(), addr);
        }
        assert_eq!(
            "[2001:db8::5]:51820"
                .parse::<EgressEndpoint>()
                .unwrap()
                .default_name(),
            "2001:db8::5"
        );
    }

    #[test]
    fn canonical_prefixes_round_trip_through_both_wire_families() {
        for (input, network) in [
            ("203.0.113.7/0", "0.0.0.0/0"),
            ("203.0.113.7/31", "203.0.113.6/31"),
            ("203.0.113.7/32", "203.0.113.7/32"),
            ("fd01::1/0", "::/0"),
            ("fd01::1234/117", "fd01::1000/117"),
            ("::1/128", "::1/128"),
        ] {
            let prefix = serde_json::from_value::<IpPrefix>(input.into()).unwrap();
            assert_eq!(serde_json::to_value(prefix).unwrap(), network);
        }
        for invalid in ["::/129", "0.0.0.0/33", "fd00::1/+64", "10.0.0.1"] {
            assert!(serde_json::from_value::<IpPrefix>(invalid.into()).is_err());
        }
    }
}
