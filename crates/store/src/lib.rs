//! Protected local snapshots. Linux is the initial supported platform.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{fmt, io, path::Path};
use wgfeel_core::{
    Config, DevicePublicKey, DomainError, GatewayPrivateKey, GatewayProjection,
    MAX_PROJECTION_BYTES, NodeId, NodeKeys, ServicePrivateKey,
};
use zeroize::Zeroizing;

mod admin_auth;
mod delivery;
pub use admin_auth::AdminVerifier;
mod management;
mod path;
mod secrets;
mod snapshot;
mod tenants;
pub use delivery::{GatewayDelivery, MAX_DELIVERY_BYTES};
pub use management::{ManagementApi, ManagementStore, RestApi, StoredManagement};
pub use secrets::ManagementSecrets;
pub use tenants::LocalTenants;
const MAX_STATE_BYTES: usize = MAX_PROJECTION_BYTES + 65_536;

pub enum StoreError {
    Io(io::Error),
    InvalidConfig(DomainError),
    InvalidState,
    InvalidLocalTenants,
    UnsafePath,
    Locked,
    RevisionNotIncreasing,
    IdentityChanged,
    CommitUncertain,
    AuthorityChanged,
    RevisionConflict,
    ApiSettingsChanged,
    WithdrawalPending,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O error ({:?})", error.kind()),
            Self::InvalidConfig(error) => write!(f, "invalid configuration: {error}"),
            Self::InvalidState => f.write_str("invalid stored state"),
            Self::InvalidLocalTenants => f.write_str("invalid local tenant key contexts"),
            Self::UnsafePath => f.write_str("unsafe storage path or permissions"),
            Self::Locked => f.write_str("storage is locked by another process"),
            Self::RevisionNotIncreasing => f.write_str("configuration generation must increase"),
            Self::IdentityChanged => f.write_str("stored node identity cannot be replaced"),
            Self::CommitUncertain => f.write_str(
                "state was published; durability acknowledgement failed; reload required",
            ),
            Self::AuthorityChanged => f.write_str("pinned Management authority cannot be replaced"),
            Self::RevisionConflict => {
                f.write_str("stored generation differs from expected revision")
            }
            Self::ApiSettingsChanged => {
                f.write_str("Management API settings cannot be implicitly replaced")
            }
            Self::WithdrawalPending => {
                f.write_str("Gateway identity has an unacknowledged withdrawal")
            }
        }
    }
}
impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for StoreError {}
impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rustix::io::Errno> for StoreError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStage {
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}
#[derive(Debug)]
pub struct StoredState {
    projection: GatewayProjection,
    node_id: NodeId,
    key: NodeKeys,
    local_tenants: LocalTenants,
    management_public_key: Option<DevicePublicKey>,
}
impl StoredState {
    pub fn management_public_key(&self) -> Option<&DevicePublicKey> {
        self.management_public_key.as_ref()
    }
    pub fn config(&self) -> &Config {
        self.projection.config()
    }
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
    pub fn service_private_key(&self) -> &ServicePrivateKey {
        self.key.service()
    }
    pub fn node_keys(&self) -> &NodeKeys {
        &self.key
    }
    pub fn local_tenants(&self) -> &LocalTenants {
        &self.local_tenants
    }
    pub fn projection(&self) -> &GatewayProjection {
        &self.projection
    }
}
#[derive(Debug)]
pub struct Store {
    directory: snapshot::LockedDirectory,
}

// Secret encoding is explicit and confined to this private durable format.
#[derive(Serialize)]
struct WriteState<'a> {
    storage_version: u32,
    node_id: &'a str,
    service_private_key: &'a [u8; 32],
    gateway_private_key: &'a [u8; 32],
    projection: &'a RawValue,
    tenant_private_keys: tenants::WriteTenants<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    management_public_key: Option<&'a DevicePublicKey>,
}

struct DiskSecret(Zeroizing<[u8; 32]>);
impl<'de> Deserialize<'de> for DiskSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;
        impl<'de> serde::de::Visitor<'de> for SecretVisitor {
            type Value = DiskSecret;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 secret bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut value = Zeroizing::new([0u8; 32]);
                for item in value.iter_mut() {
                    *item = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("invalid secret length"))?;
                }
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("invalid secret length"));
                }
                Ok(DiskSecret(value))
            }
        }
        deserializer.deserialize_seq(SecretVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadState<'a> {
    storage_version: u64,
    node_id: String,
    service_private_key: DiskSecret,
    gateway_private_key: DiskSecret,
    #[serde(borrow)]
    projection: &'a RawValue,
    tenant_private_keys: tenants::ReadTenants,
    #[serde(default, deserialize_with = "read_management_key")]
    management_public_key: Option<[u8; 32]>,
}
fn read_management_key<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    <[u8; 32]>::deserialize(de).map(Some)
}

impl Store {
    /// Retry durability confirmation after a published but uncertain commit.
    pub fn confirm_delivery(&self) -> Result<(), StoreError> {
        self.directory.confirm()
    }
    pub fn commit_managed_projection(
        &mut self,
        projection: &GatewayProjection,
        key: &NodeKeys,
        tenants: &LocalTenants,
        management_key: &DevicePublicKey,
    ) -> Result<(), StoreError> {
        self.commit_projection_inner(
            projection.management_id(),
            projection,
            projection.recipient(),
            key,
            tenants,
            Some(management_key),
            |_| Ok(()),
        )
    }
    /// Explicit owner-authorized join/transfer boundary. Authenticate the new
    /// Manager and prepare its runtime before calling this method. Ordinary
    /// remote config delivery must continue to use commit_managed_projection.
    /// The old projection and pin fence stale local join attempts; permanent
    /// node identity is preserved and old tenant material is never merged.
    pub fn accept_manager_with_checkpoint(
        &mut self,
        expected: &GatewayProjection,
        expected_pin: Option<&DevicePublicKey>,
        projection: &GatewayProjection,
        tenants: &LocalTenants,
        management_key: &DevicePublicKey,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let previous = self.load()?.ok_or(StoreError::InvalidState)?;
        if previous.projection() != expected || previous.management_public_key() != expected_pin {
            return Err(StoreError::RevisionConflict);
        }
        if projection.recipient() != previous.node_id()
            || projection.assignment().service_public_key()
                != expected.assignment().service_public_key()
            || projection.assignment().gateway_public_key()
                != expected.assignment().gateway_public_key()
            || projection.is_revoked()
        {
            return Err(StoreError::IdentityChanged);
        }
        if projection.management_id() == expected.management_id()
            && Some(management_key) == expected_pin
        {
            return self.commit_projection_inner(
                expected.management_id(),
                projection,
                previous.node_id(),
                previous.node_keys(),
                tenants,
                Some(management_key),
                checkpoint,
            );
        }
        self.publish_projection(
            projection,
            previous.node_keys(),
            tenants,
            Some(management_key),
            checkpoint,
        )
    }
    /// Persist an already authenticated Management projection. The caller must
    /// authenticate its origin before this local persistence boundary; node IDs
    /// and increasing revisions alone do not establish Management authority.
    pub fn commit_projection(
        &mut self,
        expected_management: &NodeId,
        projection: &GatewayProjection,
        node_id: &NodeId,
        key: &NodeKeys,
        tenants: &LocalTenants,
    ) -> Result<(), StoreError> {
        self.commit_projection_with_checkpoint(
            expected_management,
            projection,
            node_id,
            key,
            tenants,
            |_| Ok(()),
        )
    }

    pub fn commit_projection_with_checkpoint(
        &mut self,
        expected_management: &NodeId,
        projection: &GatewayProjection,
        node_id: &NodeId,
        key: &NodeKeys,
        tenants: &LocalTenants,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.commit_projection_inner(
            expected_management,
            projection,
            node_id,
            key,
            tenants,
            None,
            checkpoint,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn commit_projection_inner(
        &mut self,
        expected_management: &NodeId,
        projection: &GatewayProjection,
        node_id: &NodeId,
        key: &NodeKeys,
        tenants: &LocalTenants,
        requested_management_key: Option<&DevicePublicKey>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        projection
            .validate_target(expected_management, node_id)
            .map_err(StoreError::InvalidConfig)?;
        let previous = self.load()?;
        if let Some(previous) = &previous {
            let accepted = previous.projection();
            // Persisted pins dominate new caller-supplied pins. A transfer needs
            // a separate, explicitly authenticated and fenced protocol.
            if accepted.management_id() != projection.management_id() {
                return Err(StoreError::AuthorityChanged);
            }
            if previous.node_id() != node_id || !previous.node_keys().same_identity(key) {
                return Err(StoreError::IdentityChanged);
            }
            previous
                .config()
                .validate_successor(projection.config())
                .map_err(|_| StoreError::RevisionNotIncreasing)?;
            if let (Some(old), Some(new)) =
                (previous.management_public_key(), requested_management_key)
                && old != new
            {
                return Err(StoreError::AuthorityChanged);
            }
        }
        let management_public_key = requested_management_key.or_else(|| {
            previous
                .as_ref()
                .and_then(StoredState::management_public_key)
        });
        self.publish_projection(projection, key, tenants, management_public_key, checkpoint)
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::acquire(path, false)
    }
    pub fn initialize(path: &Path) -> Result<Self, StoreError> {
        Self::acquire(path, true)
    }
    fn acquire(path: &Path, initialize: bool) -> Result<Self, StoreError> {
        Ok(Self {
            directory: snapshot::LockedDirectory::acquire(path, initialize)?,
        })
    }
    pub fn load(&self) -> Result<Option<StoredState>, StoreError> {
        let Some(bytes) = self.directory.read(MAX_STATE_BYTES)? else {
            return Ok(None);
        };
        let state: ReadState<'_> =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidState)?;
        let management_public_key = match (state.storage_version, state.management_public_key) {
            (3, None) => None,
            (4, Some(key)) => {
                Some(DevicePublicKey::new(key).map_err(|_| StoreError::InvalidState)?)
            }
            _ => return Err(StoreError::InvalidState),
        };
        let projection = GatewayProjection::from_json(state.projection.get())
            .map_err(|_| StoreError::InvalidState)?;
        let local_tenants = state.tenant_private_keys.0;
        let node_id = NodeId::new(&state.node_id).map_err(|_| StoreError::InvalidState)?;
        let key = NodeKeys::new(
            ServicePrivateKey::new(*state.service_private_key.0)
                .map_err(|_| StoreError::InvalidState)?,
            GatewayPrivateKey::new(*state.gateway_private_key.0)
                .map_err(|_| StoreError::InvalidState)?,
        )
        .map_err(|_| StoreError::InvalidState)?;
        let state = StoredState {
            projection,
            node_id,
            key,
            local_tenants,
            management_public_key,
        };
        state
            .projection
            .validate_target(state.projection.management_id(), state.node_id())
            .map_err(|_| StoreError::InvalidState)?;
        state
            .local_tenants
            .validate_projection(&state.projection, &state.key)
            .map_err(|_| StoreError::InvalidState)?;
        Ok(Some(state))
    }
    fn publish_projection(
        &self,
        projection: &GatewayProjection,
        key: &NodeKeys,
        tenants: &LocalTenants,
        management_public_key: Option<&DevicePublicKey>,
        checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let recipient = projection.recipient();
        tenants.validate_projection(projection, key)?;
        let projection =
            RawValue::from_string(projection.to_json().map_err(StoreError::InvalidConfig)?)
                .map_err(|_| StoreError::InvalidState)?;
        let envelope = WriteState {
            storage_version: if management_public_key.is_some() {
                4
            } else {
                3
            },
            node_id: recipient.as_str(),
            service_private_key: key.service().expose_bytes(),
            gateway_private_key: key.gateway().expose_bytes(),
            projection: &projection,
            tenant_private_keys: tenants::WriteTenants(tenants),
            management_public_key,
        };
        // Cursor<&mut [u8]> fails at the bound instead of reallocating secrets.
        let mut bytes = Zeroizing::new(vec![0u8; MAX_STATE_BYTES]);
        let mut writer = io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut writer, &envelope).map_err(|_| StoreError::InvalidState)?;
        let written = writer.position() as usize;
        self.directory.publish(&bytes[..written], checkpoint)
    }
}
