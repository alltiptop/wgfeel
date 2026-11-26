use crate::{
    Client, ClientDevice, ClientId, Config, Device, DeviceId, DeviceMetadata, DomainError,
    GatewayAssignment, ManagementConfig, ManagementDocument, Network, NetworkId, NodeId,
};
use std::fmt;

/// Public desired-state changes. Authentication and durable publication belong
/// to Management; this value cannot itself authorize or apply a remote change.
#[derive(Debug, Clone)]
pub enum ManagementChange {
    AddClient {
        client: ClientId,
        network: NetworkId,
        name: String,
    },
    SetClientSuspended {
        client: ClientId,
        suspended: bool,
    },
    RemoveClient {
        client: ClientId,
    },
    AddDevice {
        client: ClientId,
        network: NetworkId,
        device: Device,
        metadata: DeviceMetadata,
    },
    RemoveDevice {
        client: ClientId,
        device: DeviceId,
    },
    AddGateway {
        assignment: GatewayAssignment,
    },
    SetGatewayContact {
        gateway: NodeId,
        hostname: String,
        endpoints: Vec<std::net::SocketAddr>,
    },
    RemoveGateway {
        gateway: NodeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementChangeError {
    RevisionConflict,
    GenerationExhausted,
    UnknownClient,
    UnknownDevice,
    NetworkNotOwned,
    DuplicateClient,
    DuplicateDevice,
    UnknownGateway,
    ProtectedManagement,
    Invalid(DomainError),
}
impl fmt::Display for ManagementChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Management change rejected: {self:?}")
    }
}
impl std::error::Error for ManagementChangeError {}
impl From<DomainError> for ManagementChangeError {
    fn from(error: DomainError) -> Self {
        Self::Invalid(error)
    }
}

impl ManagementDocument {
    /// Return a complete validated successor for a caller-authorized operation.
    /// No side effects occur here; commit with the same expected revision.
    pub fn apply_change(
        &self,
        expected_generation: u64,
        change: &ManagementChange,
    ) -> Result<Self, ManagementChangeError> {
        if self.routing().generation() != expected_generation {
            return Err(ManagementChangeError::RevisionConflict);
        }
        let generation = expected_generation
            .checked_add(1)
            .ok_or(ManagementChangeError::GenerationExhausted)?;
        let mut clients = self.clients().to_vec();
        let mut networks = self.routing().config().networks().to_vec();
        let mut assignments = self.routing().assignments().to_vec();
        match change {
            ManagementChange::SetGatewayContact {
                gateway,
                hostname,
                endpoints,
            } => {
                let assignment = assignments
                    .iter_mut()
                    .find(|node| node.recipient() == gateway)
                    .ok_or(ManagementChangeError::UnknownGateway)?;
                *assignment = assignment
                    .clone()
                    .with_hostname(Some(hostname.clone()))?
                    .with_endpoints(endpoints.clone())?;
            }
            ManagementChange::AddClient {
                client,
                network,
                name,
            } => {
                if clients
                    .iter()
                    .any(|entry| entry.id() == client || entry.name() == name)
                {
                    return Err(ManagementChangeError::DuplicateClient);
                }
                clients.push(
                    Client::new(client.clone(), vec![network.clone()], vec![])?
                        .with_name(name.clone())?,
                );
                networks.push(Network::new(network.clone(), vec![])?);
            }
            ManagementChange::SetClientSuspended { client, suspended } => {
                let owner = &clients[client_index(&clients, client)?];
                let network = networks
                    .iter_mut()
                    .find(|network| network.id() == owner.network())
                    .ok_or(ManagementChangeError::NetworkNotOwned)?;
                *network = network.clone().with_suspended(*suspended);
            }
            ManagementChange::RemoveClient { client } => {
                let index = client_index(&clients, client)?;
                let removed = clients.remove(index);
                networks.retain(|network| !removed.networks().contains(network.id()));
                for assignment in &mut assignments {
                    *assignment = assignment.with_scope(
                        assignment
                            .networks()
                            .iter()
                            .filter(|network| !removed.networks().contains(network))
                            .cloned()
                            .collect(),
                        assignment
                            .tenants()
                            .iter()
                            .filter(|tenant| !removed.networks().contains(tenant.network()))
                            .cloned()
                            .collect(),
                    )?;
                }
            }
            ManagementChange::AddDevice {
                client,
                network,
                device,
                metadata,
            } => {
                if clients
                    .iter()
                    .flat_map(Client::devices)
                    .any(|entry| entry.id() == device.id())
                {
                    return Err(ManagementChangeError::DuplicateDevice);
                }
                let owner = &mut clients[client_index(self.clients(), client)?];
                if !owner.networks().contains(network) {
                    return Err(ManagementChangeError::NetworkNotOwned);
                }
                if owner
                    .devices()
                    .iter()
                    .any(|entry| entry.id() == device.id())
                {
                    return Err(ManagementChangeError::DuplicateDevice);
                }
                let target = networks
                    .iter_mut()
                    .find(|entry| entry.id() == network)
                    .ok_or(ManagementChangeError::NetworkNotOwned)?;
                let mut registrations = target.devices().to_vec();
                registrations.push(device.clone());
                *target = target.with_devices(registrations)?;
                let mut devices = owner.devices().to_vec();
                devices.push(ClientDevice::new(device.id().clone(), metadata.clone()));
                *owner = Client::new(owner.id().clone(), owner.networks().to_vec(), devices)?
                    .with_name(owner.name().to_owned())?;
            }
            ManagementChange::RemoveDevice { client, device } => {
                let owner = &mut clients[client_index(self.clients(), client)?];
                if !owner.devices().iter().any(|entry| entry.id() == device) {
                    return Err(ManagementChangeError::UnknownDevice);
                }
                for network in &mut networks {
                    if owner.networks().contains(network.id()) {
                        let devices = network
                            .devices()
                            .iter()
                            .filter(|entry| entry.id() != device)
                            .cloned()
                            .collect();
                        *network = network.with_devices(devices)?;
                    }
                }
                let devices = owner
                    .devices()
                    .iter()
                    .filter(|entry| entry.id() != device)
                    .cloned()
                    .collect();
                *owner = Client::new(owner.id().clone(), owner.networks().to_vec(), devices)?
                    .with_name(owner.name().to_owned())?;
            }
            ManagementChange::AddGateway { assignment } => {
                // Main joins the routing model during local bootstrap. A remote
                // node-add operation must never replace its control identity.
                if assignment.recipient() == self.routing().management_id() {
                    return Err(DomainError::InvalidManagementIdentity.into());
                }
                assignments.push(assignment.clone());
            }
            ManagementChange::RemoveGateway { gateway } => {
                if gateway == self.routing().management_id() {
                    return Err(ManagementChangeError::ProtectedManagement);
                }
                let index = assignments
                    .iter()
                    .position(|entry| entry.recipient() == gateway)
                    .ok_or(ManagementChangeError::UnknownGateway)?;
                assignments.remove(index);
            }
        }
        let policy = match change {
            ManagementChange::RemoveClient { .. } | ManagementChange::RemoveDevice { .. } => self
                .routing()
                .config()
                .policy
                .retaining_endpoints(&networks),
            _ => self.routing().config().policy.clone(),
        };
        let routing = ManagementConfig::new(
            self.routing().management_id().clone(),
            Config::new(generation, networks, policy)?,
            assignments,
        )?;
        Ok(Self::new(routing, clients)?)
    }
}

fn client_index(clients: &[Client], id: &ClientId) -> Result<usize, ManagementChangeError> {
    clients
        .iter()
        .position(|client| client.id() == id)
        .ok_or(ManagementChangeError::UnknownClient)
}
