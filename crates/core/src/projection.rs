use crate::{
    Action, Config, ControlMode, DevicePublicKey, DomainError, Endpoint, NetworkId, NodeId,
    TrafficMode,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::net::SocketAddr;

pub const MAX_GATEWAYS: usize = 150;
pub const MAX_NODE_ENDPOINTS: usize = 16;
pub const MAX_PROJECTION_BYTES: usize = crate::MAX_CONFIG_BYTES + 65_536;
pub const PROJECTION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct TenantKeyAssignment {
    network: NetworkId,
    public_key: DevicePublicKey,
}

impl TenantKeyAssignment {
    pub fn new(network: NetworkId, public_key: DevicePublicKey) -> Self {
        Self {
            network,
            public_key,
        }
    }

    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }
}

/// Policy scope is independent of the subset of locally terminated tenant contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct GatewayAssignment {
    recipient: NodeId,
    service_public_key: DevicePublicKey,
    gateway_public_key: DevicePublicKey,
    networks: Vec<NetworkId>,
    tenants: Vec<TenantKeyAssignment>,
    endpoints: Vec<SocketAddr>,
    traffic: TrafficMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    auto_networks: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}

impl GatewayAssignment {
    pub fn new(
        recipient: NodeId,
        service_public_key: DevicePublicKey,
        gateway_public_key: DevicePublicKey,
        networks: Vec<NetworkId>,
        tenants: Vec<TenantKeyAssignment>,
    ) -> Result<Self, DomainError> {
        if networks.len() > crate::MAX_NETWORKS || tenants.len() > crate::MAX_NETWORKS {
            return Err(DomainError::LimitExceeded);
        }
        let scope: BTreeSet<_> = networks.iter().collect();
        if scope.len() != networks.len() {
            return Err(DomainError::InvalidGatewayAssignment);
        }
        let mut tenant_networks = BTreeSet::new();
        let mut keys = BTreeSet::from([&service_public_key, &gateway_public_key]);
        if keys.len() != 2 {
            return Err(DomainError::DuplicateGatewayKey);
        }
        for tenant in &tenants {
            if !scope.contains(&tenant.network) || !tenant_networks.insert(&tenant.network) {
                return Err(DomainError::InvalidGatewayAssignment);
            }
            if !keys.insert(&tenant.public_key) {
                return Err(DomainError::DuplicateGatewayKey);
            }
        }
        Ok(Self {
            recipient,
            service_public_key,
            gateway_public_key,
            networks,
            tenants,
            endpoints: vec![],
            traffic: TrafficMode::Entry,
            hostname: None,
            auto_networks: false,
        })
    }

    pub fn with_endpoint(self, endpoint: Option<SocketAddr>) -> Result<Self, DomainError> {
        self.with_endpoints(endpoint.into_iter().collect())
    }
    pub fn traffic(&self) -> TrafficMode {
        self.traffic
    }
    /// Relays forward tenant ciphertext and never receive tenant private keys.
    /// Off participants have no tenant context or user-network scope.
    pub fn with_traffic(mut self, traffic: TrafficMode) -> Result<Self, DomainError> {
        if (!traffic.accepts_devices() && !self.tenants.is_empty())
            || (!traffic.carries_user_traffic() && !self.networks.is_empty())
        {
            return Err(DomainError::InvalidGatewayAssignment);
        }
        self.traffic = traffic;
        Ok(self)
    }
    pub fn with_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Result<Self, DomainError> {
        validate_node_endpoints(&endpoints)?;
        self.endpoints = endpoints;
        Ok(self)
    }
    /// Preferred endpoint for formats that accept only one address (native WG export).
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoints.first().copied()
    }
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }
    pub fn with_hostname(mut self, hostname: Option<String>) -> Result<Self, DomainError> {
        if let Some(hostname) = &hostname {
            validate_node_hostname(hostname)?;
        }
        self.hostname = hostname;
        Ok(self)
    }
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    pub fn auto_networks(&self) -> bool {
        self.auto_networks
    }
    pub fn with_auto_networks(mut self, enabled: bool) -> Self {
        self.auto_networks = enabled;
        self
    }
    pub fn with_scope(
        &self,
        networks: Vec<NetworkId>,
        tenants: Vec<TenantKeyAssignment>,
    ) -> Result<Self, DomainError> {
        Ok(Self::new(
            self.recipient.clone(),
            self.service_public_key.clone(),
            self.gateway_public_key.clone(),
            networks,
            tenants,
        )?
        .with_endpoints(self.endpoints.clone())?
        .with_hostname(self.hostname.clone())?
        .with_traffic(self.traffic)?
        .with_auto_networks(self.auto_networks))
    }

    pub fn recipient(&self) -> &NodeId {
        &self.recipient
    }

    pub fn service_public_key(&self) -> &DevicePublicKey {
        &self.service_public_key
    }

    pub fn gateway_public_key(&self) -> &DevicePublicKey {
        &self.gateway_public_key
    }

    pub fn transport_public_keys(&self) -> [&DevicePublicKey; 2] {
        [&self.service_public_key, &self.gateway_public_key]
    }
    pub fn networks(&self) -> &[NetworkId] {
        &self.networks
    }

    pub fn tenants(&self) -> &[TenantKeyAssignment] {
        &self.tenants
    }
}

/// Public routing/projection revision, including gateway assignments.
///
/// This primitive has no client ownership catalog; ManagementDocument supplies
/// the complete administrative aggregate. Neither value carries credentials or
/// authenticates its producer. Only an authenticated Management boundary may
/// supply authoritative desired state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementConfig {
    management: NodeId,
    config: Config,
    assignments: Vec<GatewayAssignment>,
}

impl ManagementConfig {
    pub fn management_id(&self) -> &NodeId {
        &self.management
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn assignments(&self) -> &[GatewayAssignment] {
        &self.assignments
    }
    pub fn generation(&self) -> u64 {
        self.config.generation()
    }
    pub fn new(
        management: NodeId,
        config: Config,
        assignments: Vec<GatewayAssignment>,
    ) -> Result<Self, DomainError> {
        if assignments.len() > MAX_GATEWAYS {
            return Err(DomainError::LimitExceeded);
        }
        let mut recipients = BTreeSet::new();
        // Device keys may repeat across isolated networks, but never double as
        // service, gateway or tenant-server identities in this revision.
        let mut keys: BTreeSet<_> = config
            .networks()
            .iter()
            .flat_map(|network| network.devices().iter().map(|device| device.public_key()))
            .collect();
        for assignment in &assignments {
            if !recipients.insert(&assignment.recipient) {
                return Err(DomainError::DuplicateGatewayId);
            }
            validate_membership(assignment, &config)?;
            for key in std::iter::once(&assignment.service_public_key)
                .chain(std::iter::once(&assignment.gateway_public_key))
                .chain(assignment.tenants.iter().map(|tenant| &tenant.public_key))
            {
                if !keys.insert(key) {
                    return Err(DomainError::DuplicateGatewayKey);
                }
            }
        }
        Ok(Self {
            management,
            config,
            assignments,
        })
    }

    /// Retains every rule relevant to the assigned scope and its direct grant
    /// partners. Policy and assignments always come from this same revision.
    pub fn project_for(&self, recipient: &NodeId) -> Result<GatewayProjection, DomainError> {
        let assignment = self
            .assignments
            .iter()
            .find(|assignment| assignment.recipient == *recipient)
            .ok_or(DomainError::UnknownGateway)?;
        GatewayProjection::new(
            self.management.clone(),
            assignment.clone(),
            self.config.project_networks(&assignment.networks)?,
        )
    }

    pub fn project_mesh_for(&self, recipient: &NodeId) -> Result<GatewayProjection, DomainError> {
        self.project_for(recipient)?
            .with_mesh(self.assignments.clone(), false)
    }

    /// Authenticated withdrawal for a former member, using its retained public identity.
    pub fn withdraw_for(
        &self,
        former: &GatewayAssignment,
    ) -> Result<GatewayProjection, DomainError> {
        let assignment = former.with_scope(vec![], vec![])?.with_auto_networks(false);
        GatewayProjection::new(
            self.management.clone(),
            assignment,
            Config::new(
                self.generation(),
                vec![],
                crate::Policy::new(vec![], vec![], vec![]),
            )?,
        )?
        .with_mesh(self.assignments.clone(), true)
    }
}

/// Public configuration metadata for one gateway; these fields do not authenticate its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayProjection {
    management_id: NodeId,
    assignment: GatewayAssignment,
    config: Config,
    mesh: Option<Vec<GatewayAssignment>>,
    revoked: bool,
}

impl GatewayProjection {
    fn new(
        management_id: NodeId,
        assignment: GatewayAssignment,
        config: Config,
    ) -> Result<Self, DomainError> {
        validate_membership(&assignment, &config)?;
        let device_keys: BTreeSet<_> = config
            .networks()
            .iter()
            .flat_map(|network| network.devices().iter().map(|device| device.public_key()))
            .collect();
        if std::iter::once(&assignment.service_public_key)
            .chain(std::iter::once(&assignment.gateway_public_key))
            .chain(assignment.tenants.iter().map(|tenant| &tenant.public_key))
            .any(|key| device_keys.contains(key))
        {
            return Err(DomainError::DuplicateGatewayKey);
        }
        if config.project_networks(&assignment.networks)? != config {
            return Err(DomainError::InvalidProjection);
        }
        Ok(Self {
            management_id,
            assignment,
            config,
            mesh: None,
            revoked: false,
        })
    }

    fn with_mesh(
        mut self,
        mesh: Vec<GatewayAssignment>,
        revoked: bool,
    ) -> Result<Self, DomainError> {
        if mesh.len() > MAX_GATEWAYS {
            return Err(DomainError::LimitExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let device_keys: BTreeSet<_> = self
            .config
            .networks()
            .iter()
            .flat_map(|network| network.devices())
            .map(|device| device.public_key())
            .collect();
        for node in &mesh {
            if !ids.insert(&node.recipient) {
                return Err(DomainError::InvalidProjection);
            }
            for key in std::iter::once(&node.service_public_key)
                .chain(std::iter::once(&node.gateway_public_key))
                .chain(node.tenants.iter().map(|tenant| &tenant.public_key))
            {
                if !keys.insert(key) || device_keys.contains(key) {
                    return Err(DomainError::DuplicateGatewayKey);
                }
            }
        }
        let member = mesh
            .iter()
            .find(|node| node.recipient == self.assignment.recipient);
        if (!revoked && member != Some(&self.assignment))
            || (revoked
                && (member.is_some()
                    || !self.assignment.networks.is_empty()
                    || !self.assignment.tenants.is_empty()
                    || !self.config.networks().is_empty()))
        {
            return Err(DomainError::InvalidProjection);
        }
        self.mesh = Some(mesh);
        self.revoked = revoked;
        Ok(self)
    }
    pub fn mesh(&self) -> &[GatewayAssignment] {
        self.mesh.as_deref().unwrap_or_default()
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn management_id(&self) -> &NodeId {
        &self.management_id
    }

    pub fn control_mode(&self) -> ControlMode {
        if self.management_id == *self.recipient() {
            ControlMode::Main
        } else {
            ControlMode::Child
        }
    }

    pub fn recipient(&self) -> &NodeId {
        self.assignment.recipient()
    }

    pub fn assignment(&self) -> &GatewayAssignment {
        &self.assignment
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn generation(&self) -> u64 {
        self.config.generation()
    }

    pub fn validate_target(
        &self,
        expected_management: &NodeId,
        expected_recipient: &NodeId,
    ) -> Result<(), DomainError> {
        if self.management_id != *expected_management || self.recipient() != expected_recipient {
            return Err(DomainError::ProjectionTargetMismatch);
        }
        Ok(())
    }

    /// Configuration-level authorization for this gateway's assigned work.
    /// Packet identity and source-address binding are separate runtime checks.
    pub fn decision(&self, source: &Endpoint, destination: &Endpoint) -> Action {
        if !self.assignment.traffic.carries_user_traffic() {
            return Action::Deny;
        }
        if !self.assignment.networks.contains(source.network())
            && !self.assignment.networks.contains(destination.network())
        {
            return Action::Deny;
        }
        self.config.decision(source, destination)
    }

    /// Resolve public device ownership in this revision. Callers must still bind
    /// decrypted source addresses to the authenticated device or tenant peer.
    pub fn device(&self, endpoint: &Endpoint) -> Option<&crate::Device> {
        self.config
            .networks()
            .iter()
            .find(|n| n.id() == endpoint.network())?
            .devices()
            .iter()
            .find(|d| d.id() == endpoint.device())
    }

    /// The same placement and ACL contract at ingress, relay and exit. Relay
    /// metadata is only a filtering hint; the exit authenticates the inner WG
    /// peer and rederives these endpoints from the decrypted IP packet.
    pub fn forwarding_decision(
        &self,
        source: &Endpoint,
        destination: &Endpoint,
        origin: &NodeId,
        target: &NodeId,
    ) -> Action {
        let owns = |endpoint: &Endpoint, node: &NodeId| {
            let assignment = if node == self.recipient() {
                Some(self.assignment())
            } else {
                self.mesh()
                    .iter()
                    .find(|assignment| assignment.recipient() == node)
            };
            self.device(endpoint)
                .is_some_and(|device| device.gateway().unwrap_or(self.recipient()) == node)
                && assignment.is_some_and(|assignment| {
                    assignment
                        .tenants()
                        .iter()
                        .any(|tenant| tenant.network() == endpoint.network())
                })
        };
        if self.is_revoked()
            || !owns(source, origin)
            || !owns(destination, target)
            || (origin != target && source.network() != destination.network())
        {
            return Action::Deny;
        }
        self.decision(source, destination)
    }

    /// Validates structural references and minimal scope closure, not origin or
    /// completeness against an unseen authoritative revision. An authenticated
    /// distribution boundary must supply the bytes and separately enforce pins.
    pub fn from_json(input: &str) -> Result<Self, DomainError> {
        if input.len() > MAX_PROJECTION_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let raw: RawProjection<'_> =
            serde_json::from_str(input).map_err(|_| DomainError::InvalidJson)?;
        let mesh = match (raw.projection_version, raw.mesh, raw.revoked) {
            (1, None, None) => None,
            (2, Some(mesh), Some(revoked)) => Some((
                mesh.into_iter()
                    .map(RawAssignment::validate)
                    .collect::<Result<Vec<_>, _>>()?,
                revoked,
            )),
            _ => return Err(DomainError::UnsupportedSchemaVersion),
        };
        let assignment = raw.assignment.validate()?;
        let projection = Self::new(
            NodeId::new(&raw.management_id)?,
            assignment,
            Config::from_json(raw.config.get())?,
        )?;
        match mesh {
            Some((nodes, revoked)) => projection.with_mesh(nodes, revoked),
            None => Ok(projection),
        }
    }

    pub fn to_json(&self) -> Result<String, DomainError> {
        #[derive(Serialize)]
        struct WireProjection<'a> {
            projection_version: u32,
            management_id: &'a NodeId,
            assignment: &'a GatewayAssignment,
            config: &'a RawValue,
            #[serde(skip_serializing_if = "Option::is_none")]
            mesh: Option<&'a [GatewayAssignment]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            revoked: Option<bool>,
        }
        let config = self.config.to_json()?;
        if config.len() > crate::MAX_CONFIG_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let config = RawValue::from_string(config).map_err(|_| DomainError::InvalidJson)?;
        let encoded = serde_json::to_string(&WireProjection {
            projection_version: if self.mesh.is_some() {
                2
            } else {
                PROJECTION_VERSION
            },
            management_id: &self.management_id,
            assignment: &self.assignment,
            config: &config,
            mesh: self.mesh.as_deref(),
            revoked: self.mesh.as_ref().map(|_| self.revoked),
        })
        .map_err(|_| DomainError::InvalidJson)?;
        if encoded.len() > MAX_PROJECTION_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        Ok(encoded)
    }
}

fn validate_membership(assignment: &GatewayAssignment, config: &Config) -> Result<(), DomainError> {
    if assignment
        .networks
        .iter()
        .any(|id| !config.networks().iter().any(|network| network.id() == id))
    {
        return Err(DomainError::InvalidGatewayAssignment);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProjection<'a> {
    projection_version: u64,
    management_id: String,
    assignment: RawAssignment,
    #[serde(borrow)]
    config: &'a RawValue,
    #[serde(default, deserialize_with = "present")]
    mesh: Option<Vec<RawAssignment>>,
    #[serde(default, deserialize_with = "present")]
    revoked: Option<bool>,
}
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    de: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(de).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAssignment {
    recipient: String,
    service_public_key: [u8; 32],
    gateway_public_key: [u8; 32],
    networks: Vec<String>,
    tenants: Vec<RawTenantAssignment>,
    #[serde(default)]
    endpoints: Vec<SocketAddr>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    auto_networks: bool,
    traffic: TrafficMode,
}

impl<'de> Deserialize<'de> for GatewayAssignment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RawAssignment::deserialize(deserializer)?
            .validate()
            .map_err(serde::de::Error::custom)
    }
}

impl RawAssignment {
    pub(crate) fn validate(self) -> Result<GatewayAssignment, DomainError> {
        GatewayAssignment::new(
            NodeId::new(&self.recipient)?,
            DevicePublicKey::new(self.service_public_key)?,
            DevicePublicKey::new(self.gateway_public_key)?,
            self.networks
                .into_iter()
                .map(|network| NetworkId::new(&network))
                .collect::<Result<_, _>>()?,
            self.tenants
                .into_iter()
                .map(|tenant| {
                    Ok(TenantKeyAssignment::new(
                        NetworkId::new(&tenant.network)?,
                        DevicePublicKey::new(tenant.public_key)?,
                    ))
                })
                .collect::<Result<_, DomainError>>()?,
        )?
        .with_endpoints(self.endpoints)?
        .with_hostname(self.hostname)?
        .with_traffic(self.traffic)
        .map(|assignment| assignment.with_auto_networks(self.auto_networks))
    }
}

/// Public contact candidates must be bounded, distinct and usable without a
/// host-specific IPv6 scope ID. Private addresses remain valid for LAN meshes.
pub fn validate_node_endpoints(endpoints: &[SocketAddr]) -> Result<(), DomainError> {
    if endpoints.len() > MAX_NODE_ENDPOINTS {
        return Err(DomainError::LimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for address in endpoints {
        if !seen.insert(address)
            || address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || match address {
                SocketAddr::V4(address) => {
                    address.ip().is_broadcast() || address.ip().is_link_local()
                }
                SocketAddr::V6(address) => {
                    address.ip().to_ipv4_mapped().is_some()
                        || address.ip().is_unicast_link_local()
                        || address.scope_id() != 0
                        || address.flowinfo() != 0
                }
            }
        {
            return Err(DomainError::InvalidGatewayAssignment);
        }
    }
    Ok(())
}

/// Hostname is display metadata, never an identity or an executable argument.
pub fn validate_node_hostname(hostname: &str) -> Result<(), DomainError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(DomainError::InvalidHostname);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTenantAssignment {
    network: String,
    public_key: [u8; 32],
}
