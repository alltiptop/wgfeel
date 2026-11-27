use crate::{
    AdminVerifier, CommitStage, DiskSecret, GatewayDelivery, LocalTenants, ManagementSecrets,
    StoreError, secrets::WriteSecrets, snapshot::LockedDirectory,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
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
        projection
            .validate_target(
                self.document.routing().management_id(),
                projection.recipient(),
            )
            .map_err(StoreError::InvalidConfig)?;
        let mut entries = Vec::with_capacity(projection.assignment().tenants().len());
        for tenant in projection.assignment().tenants() {
            if let Some(key) = self
                .secrets
                .tenant(projection.recipient(), tenant.network())
            {
                entries.push((
                    tenant.network().clone(),
                    wgfeel_core::TenantPrivateKey::new(*key.expose_bytes())
                        .map_err(StoreError::InvalidConfig)?,
                ));
            }
        }
        GatewayDelivery::encode(projection, &LocalTenants::new(entries)?)
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
    /// Retire a delivery tombstone only after the exact peer confirms applying
    /// the current withdrawal. This never changes the authoritative document.
    pub fn confirm_withdrawal(
        &mut self,
        id: &NodeId,
        key: &DevicePublicKey,
        generation: u64,
    ) -> Result<(), StoreError> {
        let mut state = self.load()?.ok_or(StoreError::InvalidState)?;
        if state.document.routing().generation() != generation {
            return Err(StoreError::RevisionConflict);
        }
        let Some(index) = state.retired.iter().position(|node| node.recipient() == id) else {
            return Ok(());
        };
        if state.retired[index].service_public_key() != key {
            return Err(StoreError::IdentityChanged);
        }
        state.retired.remove(index);
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
        if stored.management_storage_version != 6 {
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
        // Reject a globally valid but undeliverable revision before publishing.
        for node in document.routing().assignments() {
            document
                .routing()
                .project_mesh_for(node.recipient())
                .and_then(|projection| projection.to_json())
                .map_err(StoreError::InvalidConfig)?;
        }
        for node in &retired {
            document
                .routing()
                .withdraw_for(node)
                .and_then(|projection| projection.to_json())
                .map_err(StoreError::InvalidConfig)?;
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
        let document =
            RawValue::from_string(document.to_json().map_err(StoreError::InvalidConfig)?)
                .map_err(|_| StoreError::InvalidState)?;
        let envelope = WriteManagement {
            management_storage_version: 6,
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
        serde_json::to_writer(&mut writer, &envelope).map_err(|_| StoreError::InvalidState)?;
        let written = writer.position() as usize;
        self.directory.publish(&bytes[..written], checkpoint)
    }
}
