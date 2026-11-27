//! Authoritative Management operations shared by REST and CLI clients.
use std::path::Path;
use wgfeel_core::{DevicePublicKey, DomainError, ManagementChangeError, NodeId};
use wgfeel_store::{ManagementStore, StoreError};

mod egress;
pub use egress::preview_egress_profile;
mod enrollment;
mod enrollment_api;
mod models;
mod openapi;
mod operations;
mod provision;
mod routes;
pub use enrollment::{EnrollmentError, INVITATION_LIFETIME, MAX_INVITATIONS};
use models::AddDevice;
pub use openapi::render_openapi;

pub use wgfeel_protocol::{http, tcp};

pub use wgfeel_protocol::{MAX_REQUEST_BODY, Request, Response, decode_key};
pub struct ManagementService {
    store: ManagementStore,
    delivered: std::collections::BTreeMap<NodeId, u64>,
    invitations: enrollment::Invitations,
}

impl ManagementService {
    /// Owner-only local listener operation. Never expose through REST dispatch.
    pub fn set_rest_api_local(
        &mut self,
        settings: &wgfeel_store::RestApi,
    ) -> Result<(), StoreError> {
        self.store.set_rest_api(settings)
    }
    /// Private runtime snapshot; never expose this value through REST.
    pub fn delivery_snapshot(&self) -> Result<wgfeel_store::StoredManagement, StoreError> {
        self.store.load()?.ok_or(StoreError::InvalidState)
    }
    pub fn acknowledge(
        &mut self,
        id: NodeId,
        key: &DevicePublicKey,
        generation: u64,
    ) -> Result<(), StoreError> {
        let state = self.delivery_snapshot()?;
        self.delivered.retain(|id, _| {
            state
                .document()
                .routing()
                .assignments()
                .iter()
                .any(|node| node.recipient() == id)
        });
        if generation != state.document().routing().generation() {
            return Err(StoreError::RevisionConflict);
        }
        if state
            .retired_gateways()
            .iter()
            .any(|node| node.recipient() == &id)
        {
            return self.store.confirm_withdrawal(&id, key, generation);
        }
        let node = state
            .document()
            .routing()
            .assignments()
            .iter()
            .find(|node| node.recipient() == &id)
            .ok_or(StoreError::IdentityChanged)?;
        if node.service_public_key() != key {
            return Err(StoreError::IdentityChanged);
        }
        if state
            .document()
            .routing()
            .egress_policy()
            .reservations
            .iter()
            .any(|r| r.former_node == id)
        {
            self.store.acknowledge_release(&id, key, generation)?;
        }
        self.delivered.insert(id, generation);
        Ok(())
    }
    /// Private transport identity; callers must not serialize or log this tuple.
    pub fn service_api(
        &self,
    ) -> Result<Option<(wgfeel_store::ManagementApi, wgfeel_core::ServicePrivateKey)>, StoreError>
    {
        let state = self.store.load()?.ok_or(StoreError::InvalidState)?;
        state
            .api()
            .map(|api| {
                let key = wgfeel_core::ServicePrivateKey::new(
                    *state.service_private_key().expose_bytes(),
                )
                .map_err(|_| StoreError::InvalidState)?;
                Ok((api.clone(), key))
            })
            .transpose()
    }

    /// Public startup metadata for the local process supervisor.
    pub fn identity(&self) -> Result<(NodeId, u64), StoreError> {
        let state = self.store.load()?.ok_or(StoreError::InvalidState)?;
        Ok((
            state.document().routing().management_id().clone(),
            state.document().routing().generation(),
        ))
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let store = ManagementStore::open(path)?;
        store.load()?.ok_or(StoreError::InvalidState)?;
        Ok(Self {
            store,
            delivered: std::collections::BTreeMap::new(),
            invitations: enrollment::Invitations::default(),
        })
    }

    pub fn handle(&mut self, request: Request<'_>) -> Response {
        match self.dispatch(request, false) {
            Ok(response) => response,
            Err(error) => Response::error(error.0, error.1),
        }
    }

    /// Only for an owner-authenticated Unix peer. Never call for network traffic.
    /// Explicit bearer headers still require verification, even on this transport.
    pub fn handle_local(&mut self, request: Request<'_>) -> Response {
        let local = request.authorization.is_none() && !routes::is_schema_path(request.target);
        match self.dispatch(request, local) {
            Ok(response) => response,
            Err(error) => Response::error(error.0, error.1),
        }
    }

    fn dispatch(&mut self, request: Request<'_>, local: bool) -> Result<Response, ApiError> {
        let supplied = if local {
            None
        } else {
            Some(
                request
                    .authorization
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .and_then(|value| decode_key(value).ok())
                    .ok_or(ApiError(401, "unauthorized"))?,
            )
        };
        if request.body.len() > MAX_REQUEST_BODY {
            return Err(ApiError(413, "body_too_large"));
        }
        // No cached authority/revision survives a failed or uncertain commit.
        let state = self
            .store
            .load()
            .map_err(storage_error)?
            .ok_or(ApiError(503, "unavailable"))?;
        if supplied.is_some_and(|token| !state.admin_verifier().verify(token.as_slice())) {
            return Err(ApiError(401, "unauthorized"));
        }
        routes::dispatch(self, &state, request)
    }
}

impl wgfeel_protocol::Handler for ManagementService {
    fn handle(&mut self, request: Request<'_>) -> Response {
        self.handle(request)
    }
}

struct ApiError(u16, &'static str);
impl From<DomainError> for ApiError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::DuplicateEgressPrefix => Self(409, "duplicate_egress_prefix"),
            DomainError::ConflictingDnsSelection => Self(409, "conflicting_dns_selection"),
            DomainError::NodeOutOfScope => Self(409, "node_out_of_scope"),
            DomainError::EgressNodeRequired => Self(409, "egress_node_required"),
            DomainError::EgressMovePending => Self(409, "egress_move_pending"),
            DomainError::EgressInUse => Self(409, "egress_in_use"),
            DomainError::NodeOwnsEgresses => Self(409, "node_owns_egresses"),
            DomainError::EgressKeyPendingWithdrawal => Self(409, "egress_key_pending_withdrawal"),
            DomainError::InvalidEgress => Self(422, "invalid_egress"),
            _ => Self(422, "invalid_configuration"),
        }
    }
}
fn storage_error(error: StoreError) -> ApiError {
    match error {
        StoreError::RevisionConflict => ApiError(412, "revision_conflict"),
        StoreError::InvalidConfig(error) => error.into(),
        StoreError::WithdrawalPending => ApiError(409, "withdrawal_pending"),
        StoreError::CommitUncertain => ApiError(503, "commit_uncertain_reload_required"),
        _ => ApiError(503, "storage_unavailable"),
    }
}
impl From<ManagementChangeError> for ApiError {
    fn from(error: ManagementChangeError) -> Self {
        change_error(error)
    }
}
fn change_error(error: ManagementChangeError) -> ApiError {
    use ManagementChangeError::*;
    match error {
        DeviceUnassigned => ApiError(409, "device_unassigned"),
        RevisionConflict => ApiError(412, "revision_conflict"),
        UnknownClient | UnknownDevice | UnknownGateway | UnknownEgress => {
            ApiError(404, "not_found")
        }
        DuplicateClient | DuplicateDevice | Invalid(DomainError::DuplicateGatewayId) => {
            ApiError(409, "already_exists")
        }
        Invalid(error) => error.into(),
        _ => ApiError(422, "invalid_change"),
    }
}

fn generated_id(value: Option<String>) -> Result<String, ApiError> {
    if let Some(value) = value {
        return Ok(value);
    }
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| ApiError(503, "random_unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let mut output = String::with_capacity(36);
    use std::fmt::Write;
    for (i, byte) in bytes.into_iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}
