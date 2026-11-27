use crate::{
    AdminVerifier, CommitStage, DiskSecret, GatewayDelivery, LocalTenants, ManagementSecrets,
    StoreError, secrets::WriteSecrets, snapshot::LockedDirectory,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use wgfeel_core::{
    AdminCredential, DevicePublicKey, GatewayAssignment, GatewayPrivateKey, MAX_GATEWAYS,
    MAX_MANAGEMENT_BYTES, ManagementDocument, NodeId, NodeKeys, ServicePrivateKey,
};
use zeroize::Zeroizing;

const MAX_MANAGEMENT_STATE_BYTES: usize = MAX_MANAGEMENT_BYTES + 4096;
const MAX_PRIVATE_STATE_BYTES: usize = MAX_MANAGEMENT_BYTES * 2;

#[cfg(test)]
mod durability_tests;

/// External HTTP integrations. Independent of the internal WireGuard listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ReadRestApi")]
pub struct RestApi {
    listen: SocketAddr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRestApi {
    listen: SocketAddr,
}
impl TryFrom<ReadRestApi> for RestApi {
    type Error = StoreError;
    fn try_from(raw: ReadRestApi) -> Result<Self, Self::Error> {
        Self::new(raw.listen)
    }
}
impl RestApi {
    pub fn new(listen: SocketAddr) -> Result<Self, StoreError> {
        if listen.port() == 0
            || listen.ip().is_multicast()
            || match listen {
                SocketAddr::V4(address) => address.ip().is_broadcast(),
                SocketAddr::V6(address) => {
                    address.ip().to_ipv4_mapped().is_some()
                        || address.scope_id() != 0
                        || address.flowinfo() != 0
                }
            }
        {
            return Err(StoreError::InvalidState);
        }
        Ok(Self { listen })
    }
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagementApi {
    listen: SocketAddr,
    admin_public_key: DevicePublicKey,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<SocketAddr>,
}
impl ManagementApi {
    pub fn new(listen: SocketAddr, admin_public_key: DevicePublicKey) -> Result<Self, StoreError> {
        if listen.port() == 0
            || listen.ip().is_multicast()
            || match listen.ip() {
                IpAddr::V4(address) => address.is_broadcast(),
                IpAddr::V6(address) => address.to_ipv4_mapped().is_some(),
            }
        {
            return Err(StoreError::InvalidState);
        }
        Ok(Self {
            listen,
            admin_public_key,
            endpoints: if wgfeel_core::validate_node_endpoints(&[listen]).is_ok() {
                vec![listen]
            } else {
                vec![]
            },
        })
    }
    pub fn with_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Result<Self, StoreError> {
        wgfeel_core::validate_node_endpoints(&endpoints).map_err(StoreError::InvalidConfig)?;
        self.endpoints = endpoints;
        Ok(self)
    }
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }
    pub fn admin_public_key(&self) -> &DevicePublicKey {
        &self.admin_public_key
    }
}

#[derive(Debug)]
pub struct StoredManagement {
    document: ManagementDocument,
    keys: NodeKeys,
    admin_verifier: AdminVerifier,
    api: Option<ManagementApi>,
    rest_api: Option<RestApi>,
    retired: Vec<GatewayAssignment>,
    secrets: ManagementSecrets,
    managed: bool,
}

impl StoredManagement {
    pub fn rest_api(&self) -> Option<&RestApi> {
        self.rest_api.as_ref()
    }
    pub fn secrets(&self) -> &ManagementSecrets {
        &self.secrets
    }
    pub fn delivery(
        &self,
        projection: &wgfeel_core::GatewayProjection,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let routing = self.document.routing();
        let expected = if let Some(former) = self
            .retired
            .iter()
            .find(|n| n.recipient() == projection.recipient())
        {
            routing.withdraw_for(former)
        } else {
            routing.project_mesh_for(projection.recipient())
        }
        .map_err(StoreError::InvalidConfig)?;
        if &expected != projection {
            return Err(StoreError::IdentityChanged);
        }
        let (tenants, egresses) = delivery_keys(Some(&self.secrets), projection)?;
        GatewayDelivery::encode(projection, &tenants, &egresses)
    }
    pub fn retired_gateways(&self) -> &[GatewayAssignment] {
        &self.retired
    }
    pub fn api(&self) -> Option<&ManagementApi> {
        self.api.as_ref()
    }
    pub fn document(&self) -> &ManagementDocument {
        &self.document
    }
    pub fn service_private_key(&self) -> &ServicePrivateKey {
        self.keys.service()
    }
    pub fn node_keys(&self) -> &NodeKeys {
        &self.keys
    }
    pub fn admin_verifier(&self) -> &AdminVerifier {
        &self.admin_verifier
    }
}

/// Protected authoritative desired state, separate from Gateway snapshots.
/// This local storage boundary does not authenticate an administrator.
#[derive(Debug)]
pub struct ManagementStore {
    directory: LockedDirectory,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadManagement<'a> {
    management_storage_version: u64,
    #[serde(borrow)]
    document: &'a RawValue,
    service_private_key: DiskSecret,
    gateway_private_key: DiskSecret,
    admin_verifier: AdminVerifier,
    #[serde(default, deserialize_with = "read_api")]
    api: Option<ReadApi>,
    #[serde(default, deserialize_with = "read_rest_api")]
    rest_api: Option<RestApi>,
    #[serde(default, deserialize_with = "read_retired")]
    retired_gateways: Option<Vec<GatewayAssignment>>,
    #[serde(default, deserialize_with = "read_secrets")]
    secrets: Option<ManagementSecrets>,
}
fn read_rest_api<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<RestApi>, D::Error> {
    RestApi::deserialize(de).map(Some)
}
fn read_secrets<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<ManagementSecrets>, D::Error> {
    ManagementSecrets::deserialize(de).map(Some)
}
fn read_retired<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<Vec<GatewayAssignment>>, D::Error> {
    Vec::<GatewayAssignment>::deserialize(de).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadApi {
    listen: SocketAddr,
    admin_public_key: [u8; 32],
    #[serde(default)]
    endpoints: Vec<SocketAddr>,
}
fn read_api<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ReadApi>, D::Error> {
    ReadApi::deserialize(deserializer).map(Some)
}

// Secrets are encoded only at this private durable boundary.
#[derive(Serialize)]
struct WriteManagement<'a> {
    management_storage_version: u32,
    document: &'a RawValue,
    service_private_key: &'a [u8; 32],
    gateway_private_key: &'a [u8; 32],
    admin_verifier: &'a AdminVerifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    api: Option<&'a ManagementApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rest_api: Option<&'a RestApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retired_gateways: Option<&'a [GatewayAssignment]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets: Option<WriteSecrets<'a>>,
}

impl ManagementStore {
    /// Bootstrap both independent listeners in the same authoritative snapshot.
    pub fn initialize_with_apis(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        mesh: &ManagementApi,
        rest: Option<&RestApi>,
    ) -> Result<(), StoreError> {
        self.publish(
            document,
            key,
            &AdminVerifier::new(credential)?,
            Some(mesh),
            rest,
            None,
            None,
            |_| Ok(()),
        )
    }

    /// Explicit local configuration operation; never inferred from a revision.
    /// The caller binds the proposed listener before publishing this setting.
    pub fn set_rest_api(&mut self, rest: &RestApi) -> Result<(), StoreError> {
        self.set_rest_api_with_checkpoint(rest, |_| Ok(()))
    }
    pub fn set_rest_api_with_checkpoint(
        &mut self,
        rest: &RestApi,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let state = self.load()?.ok_or(StoreError::InvalidState)?;
        self.write(
            &state.document,
            &state.keys,
            &state.admin_verifier,
            state.api.as_ref(),
            Some(rest),
            &state.retired,
            state.managed.then_some(&state.secrets),
            checkpoint,
        )
    }

    pub fn commit_with_secrets(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        secrets: &ManagementSecrets,
        expected_generation: Option<u64>,
    ) -> Result<(), StoreError> {
        self.publish(
            document,
            key,
            &AdminVerifier::new(credential)?,
            None,
            None,
            Some(secrets),
            expected_generation,
            |_| Ok(()),
        )
    }
    pub fn commit_with_verifier(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        verifier: &AdminVerifier,
        secrets: &ManagementSecrets,
        expected_generation: Option<u64>,
    ) -> Result<(), StoreError> {
        self.publish(
            document,
            key,
            verifier,
            None,
            None,
            Some(secrets),
            expected_generation,
            |_| Ok(()),
        )
    }
    /// Confirm the exact peer applied a projection excluding the reserved keys.
    /// Publish release, pending ownership and any retired-node removal together.
    pub fn acknowledge_release(
        &mut self,
        id: &NodeId,
        key: &DevicePublicKey,
        generation: u64,
    ) -> Result<(), StoreError> {
        let mut state = self.load()?.ok_or(StoreError::InvalidState)?;
        if state.document.routing().generation() != generation {
            return Err(StoreError::RevisionConflict);
        }
        let retired = state.retired.iter().position(|n| n.recipient() == id);
        let projection = if let Some(i) = retired {
            state.document.routing().withdraw_for(&state.retired[i])
        } else {
            state.document.routing().project_mesh_for(id)
        }
        .map_err(StoreError::InvalidConfig)?;
        if projection.assignment().service_public_key() != key {
            return Err(StoreError::IdentityChanged);
        }
        let reserved = state
            .document
            .routing()
            .egress_policy()
            .reservations
            .iter()
            .filter(|r| &r.former_node == id);
        let mut release = false;
        for r in reserved {
            if &r.former_service_public_key != key
                || r.removal_generation > generation
                || projection
                    .owned_egresses()
                    .iter()
                    .any(|p| p.interface_public_key == r.interface_public_key)
            {
                return Err(StoreError::IdentityChanged);
            }
            release = true;
        }
        if !release && retired.is_none() {
            return Ok(());
        }
        if release {
            state.document = state
                .document
                .apply_change(
                    generation,
                    &wgfeel_core::ManagementChange::ReleaseEgressKeys {
                        former: id.clone(),
                        service_key: key.clone(),
                    },
                )
                .map_err(|_| StoreError::InvalidState)?;
        }
        if let Some(i) = retired {
            state.retired.remove(i);
        }
        self.write(
            &state.document,
            &state.keys,
            &state.admin_verifier,
            state.api.as_ref(),
            state.rest_api.as_ref(),
            &state.retired,
            state.managed.then_some(&state.secrets),
            |_| Ok(()),
        )
    }
    pub fn confirm_withdrawal(
        &mut self,
        id: &NodeId,
        key: &DevicePublicKey,
        generation: u64,
    ) -> Result<(), StoreError> {
        let state = self.load()?.ok_or(StoreError::InvalidState)?;
        if state.document.routing().generation() != generation {
            return Err(StoreError::RevisionConflict);
        }
        if state.retired.iter().any(|n| n.recipient() == id) {
            self.acknowledge_release(id, key, generation)
        } else {
            Ok(())
        }
    }
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            directory: LockedDirectory::acquire(path, false)?,
        })
    }
    pub fn initialize(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            directory: LockedDirectory::acquire(path, true)?,
        })
    }
    pub fn load(&self) -> Result<Option<StoredManagement>, StoreError> {
        let Some(bytes) = self.directory.read(MAX_PRIVATE_STATE_BYTES)? else {
            return Ok(None);
        };
        let state = Self::decode(&bytes)?;
        // Management can distribute or build on this generation only after its
        // durability is known, including a reopened or uncertain publication.
        self.directory.confirm_if_needed()?;
        Ok(Some(state))
    }

    fn decode(bytes: &[u8]) -> Result<StoredManagement, StoreError> {
        let stored: ReadManagement<'_> =
            serde_json::from_slice(bytes).map_err(|_| StoreError::InvalidState)?;
        if !matches!(stored.management_storage_version, 6 | 7) {
            return Err(StoreError::InvalidState);
        }
        let managed = stored.secrets.is_some();
        if !managed && bytes.len() > MAX_MANAGEMENT_STATE_BYTES {
            return Err(StoreError::InvalidState);
        }
        let secrets = stored.secrets.unwrap_or_default();
        let api = stored
            .api
            .map(|api| {
                ManagementApi::new(
                    api.listen,
                    DevicePublicKey::new(api.admin_public_key)
                        .map_err(|_| StoreError::InvalidState)?,
                )?
                .with_endpoints(api.endpoints)
            })
            .transpose()?;
        let document = ManagementDocument::from_json(stored.document.get())
            .map_err(|_| StoreError::InvalidState)?;
        let retired = stored.retired_gateways.unwrap_or_default();
        if retired.len() > MAX_GATEWAYS {
            return Err(StoreError::InvalidState);
        }
        for (index, node) in retired.iter().enumerate() {
            if node.endpoint().is_none()
                || !node.networks().is_empty()
                || !node.tenants().is_empty()
                || node.recipient() == document.routing().management_id()
                || retired[..index]
                    .iter()
                    .any(|other| other.recipient() == node.recipient())
                || document
                    .routing()
                    .assignments()
                    .iter()
                    .any(|other| other.recipient() == node.recipient())
            {
                return Err(StoreError::InvalidState);
            }
        }
        let keys = NodeKeys::new(
            ServicePrivateKey::new(*stored.service_private_key.0)
                .map_err(|_| StoreError::InvalidState)?,
            GatewayPrivateKey::new(*stored.gateway_private_key.0)
                .map_err(|_| StoreError::InvalidState)?,
        )
        .map_err(|_| StoreError::InvalidState)?;
        if stored.management_storage_version == 6
            && document.routing().egress_policy() != &wgfeel_core::EgressPolicy::default()
        {
            return Err(StoreError::InvalidState);
        }
        validate_egress_node_keys(&document, &keys, api.as_ref(), &retired)
            .map_err(|_| StoreError::InvalidState)?;
        secrets.validate(&document)?;
        Ok(StoredManagement {
            document,
            keys,
            admin_verifier: stored.admin_verifier,
            api,
            rest_api: stored.rest_api,
            retired,
            secrets,
            managed,
        })
    }

    pub fn rotate_admin_credential(
        &mut self,
        credential: &AdminCredential,
    ) -> Result<(), StoreError> {
        self.rotate_admin_credential_with_checkpoint(credential, |_| Ok(()))
    }

    pub fn rotate_admin_credential_with_checkpoint(
        &mut self,
        credential: &AdminCredential,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let state = self.load()?.ok_or(StoreError::InvalidState)?;
        self.write(
            &state.document,
            &state.keys,
            &AdminVerifier::new(credential)?,
            state.api.as_ref(),
            state.rest_api.as_ref(),
            &state.retired,
            state.managed.then_some(&state.secrets),
            checkpoint,
        )
    }

    pub fn commit_with_api(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        api: &ManagementApi,
        expected_generation: Option<u64>,
    ) -> Result<(), StoreError> {
        self.commit_with_api_and_checkpoint(
            document,
            key,
            credential,
            api,
            expected_generation,
            |_| Ok(()),
        )
    }

    pub fn commit_with_api_and_checkpoint(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        api: &ManagementApi,
        expected_generation: Option<u64>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.publish(
            document,
            key,
            &AdminVerifier::new(credential)?,
            Some(api),
            None,
            None,
            expected_generation,
            checkpoint,
        )
    }

    /// Publish one complete revision after a caller has authorized the change.
    /// None expects an empty store; Some(g) requires exactly the stored generation.
    pub fn commit(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        expected_generation: Option<u64>,
    ) -> Result<(), StoreError> {
        self.commit_with_checkpoint(document, key, credential, expected_generation, |_| Ok(()))
    }
    pub fn commit_with_checkpoint(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminCredential,
        expected_generation: Option<u64>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.publish(
            document,
            key,
            &AdminVerifier::new(credential)?,
            None,
            None,
            None,
            expected_generation,
            checkpoint,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminVerifier,
        requested_api: Option<&ManagementApi>,
        requested_rest_api: Option<&RestApi>,
        requested_secrets: Option<&ManagementSecrets>,
        expected_generation: Option<u64>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let previous = self.load()?;
        if previous
            .as_ref()
            .map(|state| state.document.routing().generation())
            != expected_generation
        {
            return Err(StoreError::RevisionConflict);
        }
        if let Some(previous) = &previous {
            if previous.document.routing().management_id() != document.routing().management_id() {
                return Err(StoreError::AuthorityChanged);
            }
            if !previous.keys.same_identity(key) {
                return Err(StoreError::IdentityChanged);
            }
            previous
                .document
                .routing()
                .config()
                .validate_successor(document.routing().config())
                .map_err(|_| StoreError::RevisionNotIncreasing)?;
            if let (Some(retained), Some(requested)) = (previous.api(), requested_api)
                && retained != requested
            {
                return Err(StoreError::ApiSettingsChanged);
            }
        }
        let api = requested_api.or_else(|| previous.as_ref().and_then(StoredManagement::api));
        let rest_api =
            requested_rest_api.or_else(|| previous.as_ref().and_then(StoredManagement::rest_api));
        if let Some(previous) = &previous
            && requested_rest_api.is_some_and(|requested| Some(requested) != previous.rest_api())
        {
            return Err(StoreError::ApiSettingsChanged);
        }
        let retained_secrets = if let Some(state) = previous.as_ref().filter(|state| state.managed)
        {
            let mut secrets = state.secrets.copy_owned()?;
            secrets.retain_document(document);
            Some(secrets)
        } else {
            None
        };
        let secrets = requested_secrets.or(retained_secrets.as_ref());
        if let Some(secrets) = secrets {
            secrets.validate(document)?;
        }
        if secrets.is_none() && !document.routing().egresses().is_empty() {
            return Err(StoreError::InvalidState);
        }
        let mut retired = previous
            .as_ref()
            .map(|state| state.retired.clone())
            .unwrap_or_default();
        if let Some(previous) = &previous {
            for node in previous.document.routing().assignments() {
                if node.endpoint().is_some()
                    && !document
                        .routing()
                        .assignments()
                        .iter()
                        .any(|current| current.recipient() == node.recipient())
                {
                    retired.push(
                        node.with_scope(vec![], vec![])
                            .map(|node| node.with_auto_networks(false))
                            .map_err(StoreError::InvalidConfig)?,
                    );
                }
            }
        }
        validate_egress_node_keys(document, key, api, &retired)?;
        for node in &retired {
            if document.routing().assignments().iter().any(|current| {
                current.recipient() == node.recipient()
                    || current
                        .transport_public_keys()
                        .iter()
                        .any(|key| node.transport_public_keys().contains(key))
                    || current
                        .tenants()
                        .iter()
                        .any(|tenant| node.transport_public_keys().contains(&tenant.public_key()))
            }) || document
                .routing()
                .config()
                .networks()
                .iter()
                .flat_map(|network| network.devices())
                .any(|device| node.transport_public_keys().contains(&device.public_key()))
            {
                return Err(StoreError::WithdrawalPending);
            }
        }
        if retired.len() > MAX_GATEWAYS {
            return Err(StoreError::InvalidState);
        }
        self.write(
            document, key, credential, api, rest_api, &retired, secrets, checkpoint,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        document: &ManagementDocument,
        key: &NodeKeys,
        credential: &AdminVerifier,
        api: Option<&ManagementApi>,
        rest_api: Option<&RestApi>,
        retired: &[GatewayAssignment],
        secrets: Option<&ManagementSecrets>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        check_deliveries(document, retired, secrets)?;
        check_pending_deliveries(document, retired, secrets)?;
        let document =
            RawValue::from_string(document.to_json().map_err(StoreError::InvalidConfig)?)
                .map_err(|_| StoreError::InvalidState)?;
        let envelope = WriteManagement {
            management_storage_version: 7,
            document: &document,
            service_private_key: key.service().expose_bytes(),
            gateway_private_key: key.gateway().expose_bytes(),
            admin_verifier: credential,
            api,
            rest_api,
            retired_gateways: (!retired.is_empty()).then_some(retired),
            secrets: secrets.map(WriteSecrets),
        };
        let mut bytes = Zeroizing::new(vec![
            0u8;
            if secrets.is_some() {
                MAX_PRIVATE_STATE_BYTES
            } else {
                MAX_MANAGEMENT_STATE_BYTES
            }
        ]);
        let mut writer = io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut writer, &envelope)
            .map_err(|_| StoreError::InvalidConfig(wgfeel_core::DomainError::LimitExceeded))?;
        let written = writer.position() as usize;
        self.directory.publish(&bytes[..written], checkpoint)
    }
}

fn check_deliveries(
    document: &ManagementDocument,
    retired: &[GatewayAssignment],
    secrets: Option<&ManagementSecrets>,
) -> Result<(), StoreError> {
    let routing = document.routing();
    for projection in routing
        .assignments()
        .iter()
        .map(|node| routing.project_mesh_for(node.recipient()))
        .chain(retired.iter().map(|former| routing.withdraw_for(former)))
    {
        let projection = projection.map_err(StoreError::InvalidConfig)?;
        let (tenants, egresses) = delivery_keys(secrets, &projection)?;
        GatewayDelivery::check_size(&projection, &tenants, &egresses)?;
    }
    Ok(())
}

type Release<'a> = (&'a NodeId, &'a DevicePublicKey);

/// Size hypothetical releases without making their projections deliverable.
fn check_pending_deliveries(
    document: &ManagementDocument,
    retired: &[GatewayAssignment],
    secrets: Option<&ManagementSecrets>,
) -> Result<(), StoreError> {
    let routing = document.routing();
    let policy = routing.egress_policy();
    if !policy.profiles.iter().any(|p| p.pending_node.is_some()) {
        return Ok(());
    }

    // Release is atomic per authenticated former owner. Include release-only
    // reservations as well: their ACK can increase the revision's JSON width.
    let mut groups: BTreeMap<Release<'_>, Vec<(&wgfeel_core::EgressId, &NodeId)>> = BTreeMap::new();
    for reservation in &policy.reservations {
        let group = groups
            .entry((
                &reservation.former_node,
                &reservation.former_service_public_key,
            ))
            .or_default();
        if let Some((profile, destination)) = policy
            .profiles
            .iter()
            .find(|p| p.interface_public_key == reservation.interface_public_key)
            .and_then(|p| p.pending_node.as_ref().map(|n| (p, n)))
        {
            group.push((&profile.id, destination));
        }
    }
    let all: Vec<_> = groups.keys().copied().collect();
    check_deliveries(&simulate_releases(document, &all)?, retired, secrets)?;

    // A one-character node ID makes a public route descriptor one byte shorter
    // ("x" replaces null). Some ACK orders can then be larger than the final
    // state. For each recipient, release all groups with nonnegative growth.
    if groups.len() == 1
        || !groups
            .values()
            .flatten()
            .any(|(_, node)| node.as_str().len() == 1)
    {
        return Ok(());
    }
    let mut views: BTreeMap<Vec<Release<'_>>, Vec<&NodeId>> = BTreeMap::new();
    for node in routing.assignments() {
        let used: BTreeSet<_> = policy
            .users
            .iter()
            .filter(|u| node.networks().contains(&u.network))
            .flat_map(|u| u.egresses.iter().map(|g| &g.egress_id))
            .collect();
        let largest: Vec<_> = groups
            .iter()
            .filter(|(_, moves)| {
                // One owned profile outweighs the possible single-byte reductions
                // from other profiles (at most MAX_EGRESSES in total).
                moves.iter().any(|(_, target)| *target == node.recipient())
                    || moves
                        .iter()
                        .filter(|(id, _)| used.contains(id))
                        .map(|(_, target)| target.as_str().len() as isize - 2)
                        .sum::<isize>()
                        >= 0
            })
            .map(|(&release, _)| release)
            .collect();
        if !largest.is_empty() && largest.len() != all.len() {
            views.entry(largest).or_default().push(node.recipient());
        }
    }
    for (releases, recipients) in views {
        let future = simulate_releases(document, &releases)?;
        for node in recipients {
            let projection = future
                .routing()
                .project_mesh_for(node)
                .map_err(StoreError::InvalidConfig)?;
            let (tenants, egresses) = delivery_keys(secrets, &projection)?;
            GatewayDelivery::check_size(&projection, &tenants, &egresses)?;
        }
    }
    Ok(())
}

/// Use the domain operation itself so the public ownership, selected private
/// keys and encoded revision agree with actual authenticated ACKs.
fn simulate_releases(
    document: &ManagementDocument,
    releases: &[Release<'_>],
) -> Result<ManagementDocument, StoreError> {
    use wgfeel_core::{DomainError, ManagementChange, ManagementChangeError};
    let mut promoted: Option<ManagementDocument> = None;
    for &(former, key) in releases {
        let previous = promoted.as_ref().unwrap_or(document);
        promoted = Some(
            previous
                .apply_change(
                    previous.routing().generation(),
                    &ManagementChange::ReleaseEgressKeys {
                        former: former.clone(),
                        service_key: key.clone(),
                    },
                )
                .map_err(|err| match err {
                    ManagementChangeError::Invalid(reason) => StoreError::InvalidConfig(reason),
                    ManagementChangeError::GenerationExhausted => {
                        StoreError::InvalidConfig(DomainError::InvalidGeneration)
                    }
                    _ => StoreError::InvalidState,
                })?,
        );
    }
    promoted.ok_or(StoreError::InvalidState)
}

fn validate_egress_node_keys(
    document: &ManagementDocument,
    keys: &NodeKeys,
    api: Option<&ManagementApi>,
    retired: &[GatewayAssignment],
) -> Result<(), StoreError> {
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    let profiles = document.routing().egresses();
    let reservations = &document.routing().egress_policy().reservations;
    if profiles.is_empty() && reservations.is_empty() {
        return Ok(());
    }
    let public = |key: &[u8; 32]| {
        PrivateKey::from_private_key(&X25519, key)
            .map_err(|_| StoreError::InvalidState)?
            .compute_public_key()
            .map_err(|_| StoreError::InvalidState)
    };
    let service = public(keys.service().expose_bytes())?;
    let gateway = public(keys.gateway().expose_bytes())?;
    for r in reservations {
        if !document
            .routing()
            .assignments()
            .iter()
            .chain(retired)
            .any(|node| {
                node.recipient() == &r.former_node
                    && node.service_public_key() == &r.former_service_public_key
            })
        {
            return Err(StoreError::InvalidState);
        }
        let reserved = r.interface_public_key.as_bytes();
        if reserved == service.as_ref()
            || reserved == gateway.as_ref()
            || api.is_some_and(|api| &api.admin_public_key().x25519_coordinate() == reserved)
            || retired
                .iter()
                .flat_map(GatewayAssignment::transport_public_keys)
                .any(|k| &k.x25519_coordinate() == reserved)
        {
            return Err(StoreError::InvalidConfig(
                wgfeel_core::DomainError::EgressKeyPendingWithdrawal,
            ));
        }
    }
    for profile in profiles {
        for key in [&profile.interface_public_key, &profile.peer_public_key] {
            if retired
                .iter()
                .flat_map(GatewayAssignment::transport_public_keys)
                .any(|old| &old.x25519_coordinate() == key.as_bytes())
            {
                return Err(StoreError::WithdrawalPending);
            }
            if key.as_bytes() == service.as_ref()
                || key.as_bytes() == gateway.as_ref()
                || api.is_some_and(|api| {
                    &api.admin_public_key().x25519_coordinate() == key.as_bytes()
                })
            {
                return Err(StoreError::InvalidConfig(
                    wgfeel_core::DomainError::InvalidEgress,
                ));
            }
        }
    }
    Ok(())
}

fn delivery_keys(
    secrets: Option<&ManagementSecrets>,
    projection: &wgfeel_core::GatewayProjection,
) -> Result<(LocalTenants, crate::LocalEgressSecrets), StoreError> {
    let mut entries = Vec::with_capacity(projection.assignment().tenants().len());
    for tenant in projection.assignment().tenants() {
        if let Some(key) = secrets.and_then(|s| s.tenant(projection.recipient(), tenant.network()))
        {
            entries.push((
                tenant.network().clone(),
                wgfeel_core::TenantPrivateKey::new(*key.expose_bytes())
                    .map_err(StoreError::InvalidConfig)?,
            ));
        }
    }
    let egresses = secrets
        .map(|s| s.select_egress_keys(projection))
        .transpose()?
        .unwrap_or_default();
    egresses.validate(projection)?;
    Ok((LocalTenants::new(entries)?, egresses))
}
