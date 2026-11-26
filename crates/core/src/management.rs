use crate::{
    ClientId, Config, Device, DeviceId, DomainError, GatewayAssignment, GatewayProjection,
    ManagementConfig, Network, NetworkId, NodeId, projection::RawAssignment,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{collections::BTreeSet, fmt};

pub const MANAGEMENT_VERSION: u32 = 1;
pub const MAX_CLIENTS: usize = 750;
pub const MAX_CLIENT_DEVICES: usize = 750;
pub const MAX_DEVICE_NAME_BYTES: usize = 128;
pub const MAX_DEVICE_DESCRIPTION_BYTES: usize = 1024;
pub const MAX_MANAGEMENT_BYTES: usize = 16_777_216;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceMetadata {
    name: Option<String>,
    description: Option<String>,
}
impl DeviceMetadata {
    pub fn new(name: Option<String>, description: Option<String>) -> Result<Self, DomainError> {
        for (value, limit) in [
            (&name, MAX_DEVICE_NAME_BYTES),
            (&description, MAX_DEVICE_DESCRIPTION_BYTES),
        ] {
            if value.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > limit || value.chars().any(char::is_control)
            }) {
                return Err(DomainError::InvalidMetadata);
            }
        }
        Ok(Self { name, description })
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientDevice {
    id: DeviceId,
    metadata: DeviceMetadata,
}
impl ClientDevice {
    pub fn new(id: DeviceId, metadata: DeviceMetadata) -> Self {
        Self { id, metadata }
    }
    pub fn id(&self) -> &DeviceId {
        &self.id
    }
    pub fn metadata(&self) -> &DeviceMetadata {
        &self.metadata
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Client {
    id: ClientId,
    name: String,
    networks: Vec<NetworkId>,
    devices: Vec<ClientDevice>,
}
impl Client {
    pub fn new(
        id: ClientId,
        networks: Vec<NetworkId>,
        devices: Vec<ClientDevice>,
    ) -> Result<Self, DomainError> {
        if networks.len() > crate::MAX_NETWORKS || devices.len() > MAX_CLIENT_DEVICES {
            return Err(DomainError::LimitExceeded);
        }
        if networks.len() != 1 {
            return Err(DomainError::InvalidClientOwnership);
        }
        if devices
            .iter()
            .map(|device| &device.id)
            .collect::<BTreeSet<_>>()
            .len()
            != devices.len()
        {
            return Err(DomainError::DuplicateDeviceId);
        }
        Ok(Self {
            name: id.as_str().to_owned(),
            id,
            networks,
            devices,
        })
    }
    pub fn id(&self) -> &ClientId {
        &self.id
    }
    pub fn with_name(mut self, name: String) -> Result<Self, DomainError> {
        if name.trim() != name
            || name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
        {
            return Err(DomainError::InvalidMetadata);
        }
        self.name = name;
        Ok(self)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn networks(&self) -> &[NetworkId] {
        &self.networks
    }
    /// The user's single isolation context. The network and the user have independent identifiers.
    pub fn network(&self) -> &NetworkId {
        &self.networks[0]
    }
    pub fn devices(&self) -> &[ClientDevice] {
        &self.devices
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Ownership-complete public desired state. No credentials, API authentication
/// or key export is supplied by this value. Gateway projections omit the catalog.
pub struct ManagementDocument {
    routing: ManagementConfig,
    clients: Vec<Client>,
}
impl ManagementDocument {
    pub fn new(routing: ManagementConfig, clients: Vec<Client>) -> Result<Self, DomainError> {
        if clients.len() > MAX_CLIENTS
            || clients
                .iter()
                .map(|client| client.devices.len())
                .sum::<usize>()
                > MAX_CLIENT_DEVICES
        {
            return Err(DomainError::LimitExceeded);
        }
        let mut owners = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut devices = BTreeSet::new();
        for client in &clients {
            if !ids.insert(&client.id) || !names.insert(&client.name) {
                return Err(DomainError::InvalidClientOwnership);
            }
            for network_id in &client.networks {
                let network = routing
                    .config()
                    .networks()
                    .iter()
                    .find(|network| network.id() == network_id)
                    .ok_or(DomainError::InvalidClientOwnership)?;
                if !owners.insert(network_id)
                    || network.devices().iter().any(|registration| {
                        !client
                            .devices
                            .iter()
                            .any(|device| &device.id == registration.id())
                    })
                {
                    return Err(DomainError::InvalidClientOwnership);
                }
            }
        }
        if owners.len() != routing.config().networks().len() {
            return Err(DomainError::InvalidClientOwnership);
        }
        if clients
            .iter()
            .flat_map(Client::devices)
            .any(|device| !devices.insert(device.id()))
        {
            return Err(DomainError::DuplicateDeviceId);
        }
        Ok(Self { routing, clients })
    }
    pub fn routing(&self) -> &ManagementConfig {
        &self.routing
    }
    pub fn clients(&self) -> &[Client] {
        &self.clients
    }
    pub fn project_for(&self, recipient: &NodeId) -> Result<GatewayProjection, DomainError> {
        self.routing.project_for(recipient)
    }
    pub fn select_device(
        &self,
        client: &ClientId,
        device: &DeviceId,
        network: Option<&NetworkId>,
    ) -> Result<SelectedDevice<'_>, DeviceLookupError> {
        let client = self
            .clients
            .iter()
            .find(|entry| &entry.id == client)
            .ok_or(DeviceLookupError::UnknownDevice)?;
        let device = client
            .devices
            .iter()
            .find(|entry| &entry.id == device)
            .ok_or(DeviceLookupError::UnknownDevice)?;
        let mut registrations = self
            .routing
            .config()
            .networks()
            .iter()
            .filter(|entry| {
                client.networks.contains(entry.id()) && network.is_none_or(|id| entry.id() == id)
            })
            .filter_map(|network| {
                network
                    .devices()
                    .iter()
                    .find(|entry| entry.id() == &device.id)
                    .map(|registration| SelectedDevice {
                        client,
                        device,
                        network,
                        registration,
                    })
            });
        let selected = registrations.next().ok_or(if network.is_some() {
            DeviceLookupError::InvalidNetwork
        } else {
            DeviceLookupError::UnassignedDevice
        })?;
        if registrations.next().is_some() {
            return Err(DeviceLookupError::AmbiguousNetwork);
        }
        Ok(selected)
    }
    pub fn from_json(input: &str) -> Result<Self, DomainError> {
        if input.len() > MAX_MANAGEMENT_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let raw: RawManagement<'_> =
            serde_json::from_str(input).map_err(|_| DomainError::InvalidJson)?;
        if raw.management_version != u64::from(MANAGEMENT_VERSION) {
            return Err(DomainError::UnsupportedSchemaVersion);
        }
        if raw.assignments.len() > crate::MAX_GATEWAYS || raw.clients.len() > MAX_CLIENTS {
            return Err(DomainError::LimitExceeded);
        }
        let routing = ManagementConfig::new(
            NodeId::new(&raw.management_id)?,
            Config::from_json(raw.config.get())?,
            raw.assignments
                .into_iter()
                .map(RawAssignment::validate)
                .collect::<Result<_, _>>()?,
        )?;
        let clients = raw
            .clients
            .into_iter()
            .map(|client| {
                Client::new(
                    ClientId::new(&client.id)?,
                    client
                        .networks
                        .into_iter()
                        .map(|id| NetworkId::new(&id))
                        .collect::<Result<_, _>>()?,
                    client
                        .devices
                        .into_iter()
                        .map(|device| {
                            Ok(ClientDevice::new(
                                DeviceId::new(&device.id)?,
                                DeviceMetadata::new(
                                    device.metadata.name,
                                    device.metadata.description,
                                )?,
                            ))
                        })
                        .collect::<Result<_, DomainError>>()?,
                )?
                .with_name(client.name.unwrap_or(client.id))
            })
            .collect::<Result<_, _>>()?;
        Self::new(routing, clients)
    }
    pub fn to_json(&self) -> Result<String, DomainError> {
        #[derive(Serialize)]
        struct WireManagement<'a> {
            management_version: u32,
            management_id: &'a NodeId,
            config: &'a RawValue,
            assignments: &'a [GatewayAssignment],
            clients: &'a [Client],
        }
        let config = self.routing.config().to_json()?;
        if config.len() > crate::MAX_CONFIG_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let config = RawValue::from_string(config).map_err(|_| DomainError::InvalidJson)?;
        let encoded = serde_json::to_string(&WireManagement {
            management_version: MANAGEMENT_VERSION,
            management_id: self.routing.management_id(),
            config: &config,
            assignments: self.routing.assignments(),
            clients: &self.clients,
        })
        .map_err(|_| DomainError::InvalidJson)?;
        if encoded.len() > MAX_MANAGEMENT_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        Ok(encoded)
    }
}

#[derive(Debug)]
pub struct SelectedDevice<'a> {
    pub client: &'a Client,
    pub device: &'a ClientDevice,
    pub network: &'a Network,
    pub registration: &'a Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLookupError {
    UnknownDevice,
    UnassignedDevice,
    AmbiguousNetwork,
    InvalidNetwork,
}
impl fmt::Display for DeviceLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for DeviceLookupError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManagement<'a> {
    management_version: u64,
    management_id: String,
    #[serde(borrow)]
    config: &'a RawValue,
    assignments: Vec<RawAssignment>,
    clients: Vec<RawClient>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    id: String,
    name: Option<String>,
    networks: Vec<String>,
    devices: Vec<RawClientDevice>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientDevice {
    id: String,
    metadata: RawMetadata,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetadata {
    name: Option<String>,
    description: Option<String>,
}
