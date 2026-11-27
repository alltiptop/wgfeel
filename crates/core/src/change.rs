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
    AddEgress {
        profile: Box<crate::EgressProfile>,
        users: Vec<(ClientId, crate::UserEgressAssignment)>,
    },
    ReplaceEgress(Box<crate::EgressProfile>),
    SetEgressNode {
        egress: crate::EgressId,
        node: Option<NodeId>,
    },
    ReleaseEgressKeys {
        former: NodeId,
        service_key: crate::DevicePublicKey,
    },
    SetUserEgresses {
        user: ClientId,
        egresses: Vec<crate::UserEgressAssignment>,
    },
    RemoveEgress(crate::EgressId),
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
    UnknownEgress,
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

struct Draft {
    routing: ManagementConfig,
    policy: crate::EgressPolicy,
    clients: Vec<Client>,
}

impl ManagementDocument {
    /// Return a complete validated successor for a caller-authorized operation.
    /// No side effects occur here; commit with the same expected revision.
    pub fn apply_change(
        &self,
        expected_generation: u64,
        change: &ManagementChange,
    ) -> Result<Self, ManagementChangeError> {
        self.apply_change_with_scope(expected_generation, change, |routing, _| Ok(routing))
    }

    /// Provision automatic tenant scope before checking grants against the final routing model.
    pub fn apply_change_with_scope<E: From<ManagementChangeError>>(
        &self,
        expected_generation: u64,
        change: &ManagementChange,
        reconcile: impl FnOnce(ManagementConfig, &crate::EgressPolicy) -> Result<ManagementConfig, E>,
    ) -> Result<Self, E> {
        let Some(draft) = self.draft_change(expected_generation, change)? else {
            return Ok(self.clone());
        };
        let routing = reconcile(draft.routing, &draft.policy)?
            .with_egress_policy(draft.policy)
            .map_err(ManagementChangeError::from)?;
        Ok(Self::new(routing, draft.clients).map_err(ManagementChangeError::from)?)
    }

    fn draft_change(
        &self,
        expected_generation: u64,
        change: &ManagementChange,
    ) -> Result<Option<Draft>, ManagementChangeError> {
        if self.routing().generation() != expected_generation {
            return Err(ManagementChangeError::RevisionConflict);
        }
        let generation = expected_generation
            .checked_add(1)
            .ok_or(ManagementChangeError::GenerationExhausted)?;
        let mut clients = self.clients().to_vec();
        let mut networks = self.routing().config().networks().to_vec();
        let mut assignments = self.routing().assignments().to_vec();
        let mut egress = self.routing().egress_policy().clone();
        match change {
            ManagementChange::AddEgress { profile, users } => {
                if egress.reservation(&profile.interface_public_key).is_some() {
                    return Err(DomainError::EgressKeyPendingWithdrawal.into());
                }
                if profile.pending_node.is_some() {
                    return Err(DomainError::InvalidEgress.into());
                }
                egress.profiles.push((**profile).clone());
                let mut seen = std::collections::BTreeSet::new();
                for (id, grant) in users {
                    if grant.egress_id != profile.id || !seen.insert(id) {
                        return Err(DomainError::InvalidEgress.into());
                    }
                    let client = &clients[client_index(&clients, id)?];
                    let mut grants = egress.grants(id).to_vec();
                    grants.push(grant.clone());
                    egress.set_grants(client, grants)?;
                }
            }
            ManagementChange::ReplaceEgress(profile) => {
                let i = egress.index(&profile.id)?;
                let old = egress.profiles[i].clone();
                if old.pending_node.is_some() {
                    return Err(DomainError::EgressMovePending.into());
                }
                for user in &egress.users {
                    if let Some(grant) = user.egresses.iter().find(|g| {
                        g.egress_id == old.id
                            && !matches!(g.dns, crate::EgressDnsSelection::None {})
                    }) {
                        let config = self.routing().config();
                        let network = config
                            .networks()
                            .iter()
                            .find(|n| n.id() == &user.network)
                            .ok_or(DomainError::InvalidClientOwnership)?;
                        let removed = |device| {
                            egress
                                .dns_servers(user, grant, config, device)
                                .iter()
                                .any(|ip| !profile.dns_servers.contains(ip))
                        };
                        if (network.devices().is_empty() && removed(None))
                            || network.devices().iter().any(|d| removed(Some(d)))
                        {
                            return Err(DomainError::InvalidEgress.into());
                        }
                    }
                }
                if old.interface_public_key != profile.interface_public_key {
                    if egress.reservation(&profile.interface_public_key).is_some() {
                        return Err(DomainError::EgressKeyPendingWithdrawal.into());
                    }
                    egress.reserve(&old, self.routing(), generation)?;
                }
                egress.profiles[i] = (**profile).clone().with_placement(old.node.clone(), None)?;
            }
            ManagementChange::SetEgressNode { egress: id, node } => {
                let i = egress.index(id)?;
                let old = egress.profiles[i].clone();
                if old.pending_node.is_some() && node.is_some() && old.pending_node != *node {
                    return Err(DomainError::EgressMovePending.into());
                }
                if (old.node == *node && old.pending_node.is_none())
                    || (node.is_some() && old.pending_node == *node)
                {
                    return Ok(None);
                }
                let next = if old.node.is_some() {
                    egress.reserve(&old, self.routing(), generation)?;
                    old.with_placement(None, node.clone())?
                } else if node.is_some() && egress.reservation(&old.interface_public_key).is_some()
                {
                    return Err(DomainError::EgressKeyPendingWithdrawal.into());
                } else {
                    old.with_placement(node.clone(), None)?
                };
                egress.profiles[i] = next;
            }
            ManagementChange::ReleaseEgressKeys {
                former,
                service_key,
            } => {
                let mut released = std::collections::BTreeSet::new();
                egress.reservations.retain(|r| {
                    if &r.former_node == former
                        && &r.former_service_public_key == service_key
                        && r.removal_generation <= expected_generation
                    {
                        released.insert(r.interface_public_key.clone());
                        false
                    } else {
                        true
                    }
                });
                if released.is_empty() {
                    return Ok(None);
                }
                for p in &mut egress.profiles {
                    if released.contains(&p.interface_public_key) && p.pending_node.is_some() {
                        *p = p.clone().with_placement(p.pending_node.clone(), None)?;
                    }
                }
            }
            ManagementChange::SetUserEgresses { user, egresses } => {
                let owner = &clients[client_index(&clients, user)?];
                egress.set_grants(owner, egresses.clone())?;
            }
            ManagementChange::RemoveEgress(id) => {
                if egress
                    .users
                    .iter()
                    .any(|u| u.egresses.iter().any(|g| &g.egress_id == id))
                {
                    return Err(DomainError::EgressInUse.into());
                }
                let i = egress.index(id)?;
                let old = egress.profiles.remove(i);
                egress.reserve(&old, self.routing(), generation)?;
            }
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
                egress.users.retain(|u| &u.user != client);
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
                if egress.profiles.iter().any(|p| {
                    p.node.as_ref() == Some(gateway) || p.pending_node.as_ref() == Some(gateway)
                }) {
                    return Err(DomainError::NodeOwnsEgresses.into());
                }
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
        Ok(Some(Draft {
            routing,
            policy: egress,
            clients,
        }))
    }
}

fn client_index(clients: &[Client], id: &ClientId) -> Result<usize, ManagementChangeError> {
    clients
        .iter()
        .position(|client| client.id() == id)
        .ok_or(ManagementChangeError::UnknownClient)
}

impl crate::EgressPolicy {
    fn index(&self, id: &crate::EgressId) -> Result<usize, ManagementChangeError> {
        self.profiles
            .iter()
            .position(|p| &p.id == id)
            .ok_or(ManagementChangeError::UnknownEgress)
    }
    fn reserve(
        &mut self,
        old: &crate::EgressProfile,
        routing: &ManagementConfig,
        generation: u64,
    ) -> Result<(), DomainError> {
        if let Some(node) = &old.node {
            let former = routing
                .assignments()
                .iter()
                .find(|n| n.recipient() == node)
                .ok_or(DomainError::UnknownGateway)?;
            self.reservations.push(crate::EgressKeyReservation {
                interface_public_key: old.interface_public_key.clone(),
                former_node: node.clone(),
                former_service_public_key: former.service_public_key().clone(),
                removal_generation: generation,
            });
        }
        Ok(())
    }
    fn set_grants(
        &mut self,
        client: &Client,
        grants: Vec<crate::UserEgressAssignment>,
    ) -> Result<(), ManagementChangeError> {
        for g in &grants {
            let p = self
                .profile(&g.egress_id)
                .ok_or(ManagementChangeError::UnknownEgress)?;
            if p.node.is_none()
                && !self.grants(client.id()).iter().any(|old| {
                    old.egress_id == g.egress_id
                        && g.routes
                            .iter()
                            .all(|new| old.routes.iter().any(|r| r.covers(*new)))
                        && (g.dns == old.dns || matches!(g.dns, crate::EgressDnsSelection::None {}))
                })
            {
                return Err(if p.pending_node.is_some() {
                    DomainError::EgressMovePending
                } else {
                    DomainError::EgressNodeRequired
                }
                .into());
            }
        }
        self.users.retain(|u| &u.user != client.id());
        if !grants.is_empty() {
            self.users.push(crate::UserEgresses {
                user: client.id().clone(),
                network: client.network().clone(),
                egresses: grants,
            })
        }
        Ok(())
    }
}
