//! WireGuard packet integration using GotaTun and the approved AWS-LC backend.
//!
//! Routing metadata is untrusted until engine authentication. Plaintext events
//! authenticate the peer; the projection-bound local entry additionally checks
//! source-IP ownership and identity ACLs. The worker LocalGateway applies that
//! same policy in the trusted supervisor around isolated cryptographic workers.
//! UDP transport accepts a caller-owned socket and never injects inner IP into
//! the host network stack.

use std::{fmt, net::SocketAddr};
use wgfeel_core::{
    DeviceId, DevicePublicKey, EgressId, EgressPrivateKey, GatewayPrivateKey, NetworkId, NodeId,
    PresharedKey, ServicePrivateKey, TenantPrivateKey,
};

pub mod dispatch;
mod forwarding;
mod framing;
mod gateway;
pub mod mesh;
pub mod nat;
mod router;
mod transport;
mod udp;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub mod worker;
pub use forwarding::ForwardError;
pub use gateway::Gateway;
pub use transport::{TransportError, UdpEvent, UdpTransport};
pub use udp::UdpListener;

pub const MAX_TENANTS: usize = 150;
pub const MAX_DEVICE_PEERS: usize = 750;
// Main needs 149 other mesh members, an administrator, and 32 pending
// invitation identities. This also covers a child's pinned authority and
// owner-authorized candidate during transfer.
pub const MAX_SERVICE_PEERS: usize = wgfeel_core::MAX_GATEWAYS + wgfeel_core::MAX_INVITATIONS;
pub const MAX_MESH_PEERS: usize = MAX_TENANTS * wgfeel_core::MAX_GATEWAYS;
pub const MAX_PLAINTEXT_SIZE: usize = 1280;
/// Maximum padded WireGuard data message fitting a non-jumbo UDP payload.
pub const MAX_PROVIDER_DATAGRAM_SIZE: usize = 65_504;
pub(crate) const MAX_PROVIDER_PLAINTEXT: usize = MAX_PROVIDER_DATAGRAM_SIZE - 32;
pub const MAX_DATAGRAM_SIZE: usize = MAX_PLAINTEXT_SIZE + 32;
pub const MAX_HANDSHAKE_SOURCES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextId {
    External(EgressId),
    Tenant(NetworkId),
    Service,
    Gateway,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerId {
    Provider,
    Device(DeviceId),
    /// A Gateway authenticated with this tenant's key, never a service key.
    Gateway(NodeId),
    Node(NodeId),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub id: PeerId,
    pub public_key: DevicePublicKey,
}

#[derive(Debug)]
enum PrivateKey {
    External {
        key: EgressPrivateKey,
        psk: Option<PresharedKey>,
        keepalive: Option<std::num::NonZeroU16>,
    },
    Tenant(TenantPrivateKey),
    Service(ServicePrivateKey),
    Gateway(GatewayPrivateKey),
}
impl PrivateKey {
    fn expose_bytes(&self) -> &[u8; 32] {
        match self {
            Self::External { key, .. } => key.expose_bytes(),
            Self::Tenant(k) => k.expose_bytes(),
            Self::Service(k) => k.expose_bytes(),
            Self::Gateway(k) => k.expose_bytes(),
        }
    }
}
#[derive(Debug)]
pub struct ContextConfig {
    id: ContextId,
    private_key: PrivateKey,
    peers: Vec<PeerConfig>,
}
impl ContextConfig {
    pub(crate) fn external(
        id: EgressId,
        key: EgressPrivateKey,
        psk: Option<PresharedKey>,
        keepalive: Option<std::num::NonZeroU16>,
        public_key: DevicePublicKey,
    ) -> Self {
        Self {
            id: ContextId::External(id),
            private_key: PrivateKey::External {
                key,
                psk,
                keepalive,
            },
            peers: vec![PeerConfig {
                id: PeerId::Provider,
                public_key,
            }],
        }
    }
    pub fn tenant(id: NetworkId, key: TenantPrivateKey, peers: Vec<PeerConfig>) -> Self {
        Self {
            id: ContextId::Tenant(id),
            private_key: PrivateKey::Tenant(key),
            peers,
        }
    }
    pub fn gateway(key: GatewayPrivateKey, peers: Vec<PeerConfig>) -> Self {
        Self {
            id: ContextId::Gateway,
            private_key: PrivateKey::Gateway(key),
            peers,
        }
    }
    pub fn service(key: ServicePrivateKey, peers: Vec<PeerConfig>) -> Self {
        Self {
            id: ContextId::Service,
            private_key: PrivateKey::Service(key),
            peers,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Handshakes per source IP per upstream one-second window before cookies.
    /// Zero always requires a cookie. Values above 1000 are rejected.
    pub handshake_limit_per_ip: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake_limit_per_ip: 10,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardError {
    InvalidConfiguration,
    DuplicateContext,
    DuplicateGatewayKey,
    DuplicatePeer,
    InvalidPeerKey,
    UnknownContext,
    UnknownPeer,
    InvalidPacket,
    PacketTooLarge,
    NoSession,
    NoEndpoint,
    UnknownIndex,
    SourceLimit,
    Protocol,
}
impl fmt::Display for WireGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireGuard operation rejected: {self:?}")
    }
}
impl std::error::Error for WireGuardError {}
/// Owned packet bytes. Debug deliberately omits the contents.
pub struct PacketBytes(Vec<u8>);
impl PacketBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for PacketBytes {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl fmt::Debug for PacketBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketBytes([REDACTED])")
    }
}
#[derive(Debug)]
pub enum Event {
    /// Routing hints for encrypted output, including unauthenticated challenges.
    Network {
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
    },
    /// Authenticated peer and IP bytes. IP source/ACL authorization is still required.
    Plaintext {
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
    },
}

/// Packet-level events for the shared UDP entry point. Network output is
/// encrypted; only Plaintext represents authenticated inner traffic.
#[derive(Debug)]
pub enum DatagramEvent {
    Network {
        destination: SocketAddr,
        context: ContextId,
        peer: Option<PeerId>,
        packet: PacketBytes,
    },
    Plaintext {
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
    },
}
