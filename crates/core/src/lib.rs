//! Validated configuration contracts for isolated WireGuard tenant networks.

use std::fmt;

mod capabilities;
mod change;
mod config;
mod identity;
mod management;
mod projection;
mod wire;
pub use capabilities::*;
pub use change::*;
pub use config::*;
pub use identity::*;
pub use management::*;
pub use projection::*;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_NETWORKS: usize = 150;
pub const MAX_DEVICES: usize = 750;
/// Pending one-use enrollment identities, separate from durable mesh members.
pub const MAX_INVITATIONS: usize = 32;
pub const MAX_POLICY_RULES: usize = 4096;
pub const MAX_CONFIG_BYTES: usize = 4_194_304;
/// Maximum recipient projection plus its private key envelope on the service transport.
pub const MAX_DELIVERY_BYTES: usize = MAX_PROJECTION_BYTES + 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    InvalidIdentifier,
    InvalidKey,
    InvalidAddress,
    InvalidAddressCount,
    DuplicateNetworkId,
    DuplicateDeviceId,
    DuplicateDeviceKey,
    DuplicateDeviceAddress,
    InvalidHostname,
    DuplicateHostname,
    UnsupportedSchemaVersion,
    InvalidGeneration,
    GenerationNotIncreasing,
    LimitExceeded,
    InvalidPolicyReference,
    CrossNetworkLocalRule,
    InvalidGrant,
    AmbiguousGrant,
    InvalidJson,
    InvalidGatewayAssignment,
    DuplicateGatewayId,
    DuplicateGatewayKey,
    InvalidManagementIdentity,
    UnknownGateway,
    ProjectionTargetMismatch,
    InvalidProjection,
    InvalidMetadata,
    InvalidClientOwnership,
}
impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DomainError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    UnknownSource,
    UnknownDestination,
    AmbiguousDestination,
}
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RouteError {}
