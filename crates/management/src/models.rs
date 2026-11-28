//! Wire types used for both HTTP encoding and OpenAPI generation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use wgfeel_core::{ClientId, DeviceId, DeviceMetadata, DevicePublicKey, NodeId, TrafficMode};

fn default_broadcast() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddUser {
    /// Default directed broadcast policy inherited by devices.
    #[serde(default = "default_broadcast")]
    pub broadcast: bool,
    /// Display name. The server assigns the user's ID and network.
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddDevice {
    /// Override the user's directed broadcast policy. Null inherits it.
    pub broadcast: Option<bool>,
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
    pub egresses: Vec<AssignmentView>,
    pub id: &'a ClientId,
    pub name: &'a str,
    /// Whether traffic for this user's network is suspended.
    pub suspended: bool,
    pub broadcast: bool,
    pub devices: Vec<DeviceView<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct Devices<'a> {
    pub devices: Vec<DeviceView<'a>>,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct DeviceView<'a> {
    pub id: &'a DeviceId,
    pub metadata: &'a DeviceMetadata,
    /// Tunnel IP addresses assigned to the device; empty when the device exists only in the catalog.
    pub addresses: &'a [IpAddr],
    /// Null when the device exists only in the catalog.
    pub registration: Option<DeviceBroadcast>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct UserBroadcast {
    pub broadcast: bool,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct DeviceBroadcast {
    pub broadcast: Option<bool>,
    pub effective_broadcast: bool,
}

/// Omitting the setting is a malformed replacement. Explicit null selects inheritance.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SetDeviceBroadcast {
    #[serde(deserialize_with = "required_broadcast")]
    #[schemars(schema_with = "nullable_boolean")]
    pub broadcast: Option<bool>,
}
fn required_broadcast<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<bool>, D::Error> {
    Option::deserialize(de)
}
fn nullable_boolean(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":["boolean","null"]})
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Gateways<'a> {
    pub gateways: Vec<Gateway<'a>>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct Gateway<'a> {
    pub traffic: TrafficMode,
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AddEgress<'a> {
    /// WireGuard profile contents. Write only.
    #[schemars(with = "String", extend("writeOnly" = true))]
    #[serde(borrow)]
    pub config: &'a serde_json::value::RawValue,
    /// Display name. Defaults to the provider endpoint host.
    pub name: Option<String>,
    /// Optional entry node that will receive the provider key.
    pub node: Option<NodeId>,
    /// User grants to create in the same transaction. Grants require placement.
    #[serde(default)]
    pub users: Vec<InitialGrant>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlacementState {
    Unassigned,
    Placed,
    Detaching,
    Moving,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct Egress {
    pub id: wgfeel_core::EgressId,
    pub name: String,
    pub node: Option<NodeId>,
    pub pending_node: Option<NodeId>,
    pub placement_state: PlacementState,
    pub interface_public_key: String,
    pub addresses: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub peer_public_key: String,
    pub endpoint: wgfeel_core::EgressEndpoint,
    pub allowed_ips: Vec<wgfeel_core::IpPrefix>,
    pub persistent_keepalive: Option<std::num::NonZeroU16>,
    pub has_preshared_key: bool,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct Egresses {
    pub egresses: Vec<Egress>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialGrant {
    pub user: ClientId,
    pub routes: Vec<wgfeel_core::IpPrefix>,
    pub dns: wgfeel_core::EgressDnsSelection,
}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantInput {
    pub routes: Vec<wgfeel_core::IpPrefix>,
    pub dns: wgfeel_core::EgressDnsSelection,
}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantSet {
    pub egresses: Vec<wgfeel_core::UserEgressAssignment>,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct AssignmentView {
    #[serde(flatten)]
    pub grant: wgfeel_core::UserEgressAssignment,
    pub dormant: bool,
}
#[derive(Serialize, JsonSchema)]
pub(super) struct AssignmentList {
    pub egresses: Vec<AssignmentView>,
}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplaceEgress<'a> {
    #[schemars(with="String",extend("writeOnly"=true))]
    #[serde(borrow)]
    pub config: &'a serde_json::value::RawValue,
    pub name: Option<String>,
}
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SetEgressNode {
    #[serde(deserialize_with = "required_node")]
    #[schemars(required)]
    pub node: Option<NodeId>,
}
fn required_node<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<NodeId>, D::Error> {
    Option::deserialize(de)
}
#[derive(Serialize, JsonSchema)]
pub(super) struct EgressNode {
    pub egress_id: wgfeel_core::EgressId,
    pub node: Option<NodeId>,
    pub pending_node: Option<NodeId>,
    pub placement_state: PlacementState,
    pub former_node: Option<NodeId>,
    pub withdrawal_generation: Option<u64>,
}
