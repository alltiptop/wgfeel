//! Wire types used for both HTTP encoding and OpenAPI generation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use wgfeel_core::{ClientDevice, ClientId, DevicePublicKey, NodeId, TrafficMode};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddUser {
    /// Display name. The server assigns the user's ID and network.
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddDevice {
    /// Display name used when provisioning this device.
    pub name: String,
    /// Optional description shown in the device's metadata.
    pub description: Option<String>,
    /// Base64 WireGuard public key. Omit to have main generate the key pair.
    pub public_key: Option<String>,
    /// Preferred entry node ID. Omit to select an eligible node automatically.
    pub gateway: Option<String>,
    /// Tunnel IP addresses. An empty list requests automatic allocation.
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddGateway {
    /// Node ID. Omit to have the server assign an ID.
    pub id: Option<String>,
    /// Base64 public key for the node's service identity.
    pub public_key: String,
    /// Distinct base64 public key for mesh traffic.
    pub gateway_public_key: String,
    /// Scope expressed as user IDs. Use either users or networks.
    #[serde(default)]
    pub users: Vec<String>,
    /// Scope expressed as network IDs.
    #[serde(default)]
    pub networks: Vec<String>,
    /// Public keys for tenant networks terminated by this node.
    #[serde(default)]
    pub tenants: Vec<Tenant>,
    /// Automatically include user networks. Defaults to true for a node with an endpoint and no explicit scope or tenants.
    pub auto_networks: Option<bool>,
    /// Node contact address and UDP port.
    pub endpoint: Option<SocketAddr>,
    /// Traffic capability assigned to this node.
    #[serde(default)]
    pub traffic: TrafficMode,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Tenant {
    /// Identify the tenant by exactly one of network or user.
    pub network: Option<String>,
    /// User who owns the network.
    pub user: Option<String>,
    /// Base64 tenant public key.
    pub public_key: String,
}

#[derive(Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationOptions {
    /// Traffic capability to assign when the node enrolls.
    #[serde(default)]
    pub traffic: TrafficMode,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct IssuedInvitation {
    /// One-time enrollment URI. Treat it as a secret until it expires.
    #[schemars(with = "String")]
    pub invitation: zeroize::Zeroizing<String>,
    /// Expiration time in Unix seconds.
    pub expires_at: u64,
    /// Traffic capability selected at issuance.
    pub traffic: TrafficMode,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct RotatedToken {
    /// New administrator bearer token, returned once.
    #[schemars(with = "String")]
    pub token: zeroize::Zeroizing<String>,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct ChangeReceipt {
    /// ID of the affected user, device or node.
    pub id: String,
    /// Configuration revision after the change.
    pub generation: u64,
    /// Newly committed changes await delivery to nodes.
    pub distribution: ChangeDistribution,
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum ChangeDistribution {
    Pending,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Identity<'a> {
    pub management_id: &'a NodeId,
    /// Base64 service public key of main.
    pub public_key: String,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Distribution<'a> {
    /// Current configuration revision.
    pub generation: u64,
    pub gateways: Vec<GatewayDelivery<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct GatewayDelivery<'a> {
    pub id: &'a NodeId,
    /// Revision this node should apply.
    pub desired: u64,
    /// Last revision acknowledged by the node, if any.
    pub acknowledged: Option<u64>,
    pub status: DeliveryStatus,
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum DeliveryStatus {
    Unconfigured,
    Applied,
    Pending,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Users<'a> {
    pub users: Vec<User<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct User<'a> {
    pub id: &'a ClientId,
    pub name: &'a str,
    /// Whether traffic for this user's network is suspended.
    pub suspended: bool,
    pub devices: &'a [ClientDevice],
}
#[derive(Serialize, JsonSchema)]
pub(super) struct Devices<'a> {
    pub devices: &'a [ClientDevice],
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Gateways<'a> {
    pub gateways: Vec<Gateway<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct Gateway<'a> {
    /// ID of the node receiving configuration.
    pub recipient: &'a NodeId,
    pub service_public_key: &'a DevicePublicKey,
    pub gateway_public_key: &'a DevicePublicKey,
    /// Preferred contact address, when configured.
    pub endpoint: Option<SocketAddr>,
    pub endpoints: &'a [SocketAddr],
    pub hostname: Option<&'a str>,
    /// Whether newly created user networks are assigned automatically.
    pub auto_users: bool,
    pub users: Vec<Option<&'a ClientId>>,
    pub tenants: Vec<GatewayTenant<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct GatewayTenant<'a> {
    pub user: Option<&'a ClientId>,
    pub public_key: &'a DevicePublicKey,
}

/// Send exactly the two bytes `{}` as the request body.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct EmptyObject {}
