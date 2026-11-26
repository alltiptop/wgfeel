//! Authoritative Management operations shared by REST and CLI clients.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{net::IpAddr, path::Path};
use wgfeel_core::{
    Client, ClientId, DeviceId, DevicePublicKey, DomainError, GatewayAssignment, ManagementChange,
    ManagementChangeError, ManagementDocument, NetworkId, NodeId, TenantKeyAssignment,
};
use wgfeel_store::{ManagementStore, StoreError};

mod enrollment;
mod enrollment_api;
mod provision;
pub use enrollment::{EnrollmentError, INVITATION_LIFETIME, MAX_INVITATIONS};

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
        let local = request.authorization.is_none();
        match self.dispatch(request, local) {
            Ok(response) => response,
            Err(error) => Response::error(error.0, error.1),
        }
    }

    fn dispatch(&mut self, request: Request<'_>, local: bool) -> Result<Response, ApiError> {
        // No cached authority/revision survives a failed or uncertain commit.
        let state = self
            .store
            .load()
            .map_err(storage_error)?
            .ok_or(ApiError(503, "unavailable"))?;
        if !local {
            let supplied = request
                .authorization
                .and_then(|value| value.strip_prefix("Bearer "))
                .and_then(|value| decode_key(value).ok())
                .ok_or(ApiError(401, "unauthorized"))?;
            if !state.admin_verifier().verify(supplied.as_slice()) {
                return Err(ApiError(401, "unauthorized"));
            }
        }
        if request.body.len() > MAX_REQUEST_BODY {
            return Err(ApiError(413, "body_too_large"));
        }
        if request.target == "/api/v1/node-invitations" {
            if request.method != "POST" {
                return Err(ApiError(405, "method_not_allowed"));
            }
            if let Some(expected) = request.if_match {
                let expected =
                    http::parse_revision(expected).ok_or(ApiError(400, "invalid_revision"))?;
                if expected != state.document().routing().generation() {
                    return Err(ApiError(412, "revision_conflict"));
                }
            }
            return self.issue_invitation(&state, request.body);
        }
        if request.target == "/api/v1/token/rotate" {
            if request.method != "POST" {
                return Err(ApiError(405, "method_not_allowed"));
            }
            if !request.body.is_empty() {
                return Err(ApiError(400, "unexpected_body"));
            }
            let expected = request.if_match.ok_or(ApiError(428, "revision_required"))?;
            let expected =
                http::parse_revision(expected).ok_or(ApiError(400, "invalid_revision"))?;
            if expected != state.document().routing().generation() {
                return Err(ApiError(412, "revision_conflict"));
            }
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            aws_lc_rs::rand::fill(bytes.as_mut_slice())
                .map_err(|_| ApiError(503, "randomness_unavailable"))?;
            let credential = wgfeel_core::AdminCredential::new(*bytes)
                .map_err(|_| ApiError(503, "randomness_unavailable"))?;
            let token = zeroize::Zeroizing::new(STANDARD.encode(credential.expose_bytes()));
            #[derive(serde::Serialize)]
            struct Rotated<'a> {
                token: &'a str,
            }
            let response = Response {
                status: 200,
                generation: Some(expected),
                body: serde_json::to_vec(&Rotated { token: &token })
                    .map_err(|_| ApiError(500, "encoding_failed"))?,
                is_config: false,
            };
            self.store
                .rotate_admin_credential(&credential)
                .map_err(storage_error)?;
            return Ok(response);
        }
        let route = Route::parse(request.target)?;
        let document = state.document();
        if request.method == "GET" {
            if !request.body.is_empty() {
                return Err(ApiError(400, "unexpected_body"));
            }
            if let Route::DeviceConfig(user, device, network) = route {
                return Ok(Response {
                    status: 200,
                    generation: Some(document.routing().generation()),
                    body: provision::export(&state, user, device, network)?,
                    is_config: true,
                });
            }
            let body = match route {
                Route::Distribution => serde_json::to_vec(&serde_json::json!({"generation":document.routing().generation(),"gateways":
                    document.routing().assignments().iter().chain(state.retired_gateways()).map(|node|serde_json::json!({
                        "id":node.recipient(),"desired":document.routing().generation(),"acknowledged":self.delivered.get(node.recipient()),
                        "status":if node.endpoint().is_none(){"unconfigured"}else if self.delivered.get(node.recipient())==Some(&document.routing().generation()){"applied"}else{"pending"}
                    })).collect::<Vec<_>>() })).map_err(|_|ApiError(500,"encoding_failed"))?,
                Route::Identity => {
                    let public=aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519,state.service_private_key().expose_bytes())
                        .map_err(|_|ApiError(503,"identity_unavailable"))?.compute_public_key().map_err(|_|ApiError(503,"identity_unavailable"))?;
                    serde_json::to_vec(&serde_json::json!({"management_id":document.routing().management_id(),"public_key":STANDARD.encode(public.as_ref())}))
                        .map_err(|_|ApiError(500,"encoding_failed"))?
                },
                _=>read(document, route)?,
            };
            return Ok(Response {
                status: 200,
                generation: Some(document.routing().generation()),
                body,
                is_config: false,
            });
        }
        if !matches!(
            (request.method, &route),
            (
                "POST",
                Route::Users | Route::Devices(_) | Route::Gateways | Route::Suspension(_, _)
            ) | (
                "DELETE",
                Route::User(_) | Route::Device(_, _) | Route::Gateway(_)
            )
        ) {
            return Err(ApiError(405, "method_not_allowed"));
        }
        if request.method == "DELETE" && !request.body.is_empty() {
            return Err(ApiError(400, "unexpected_body"));
        }
        let expected = request.if_match.ok_or(ApiError(428, "revision_required"))?;
        let expected = http::parse_revision(expected).ok_or(ApiError(400, "invalid_revision"))?;
        if expected != document.routing().generation() {
            return Err(ApiError(412, "revision_conflict"));
        }
        let mut secrets = state.secrets().copy_owned().map_err(storage_error)?;
        let (change, id) = mutation(document, &mut secrets, route, request.body)?;
        let next = document
            .apply_change(expected, &change)
            .map_err(change_error)?;
        let next = provision::reconcile(next, &change, &mut secrets)?;
        self.store
            .commit_with_verifier(
                &next,
                state.node_keys(),
                state.admin_verifier(),
                &secrets,
                Some(expected),
            )
            .map_err(storage_error)?;
        Ok(Response {
            status: if request.method == "POST" { 201 } else { 200 },
            generation: Some(next.routing().generation()),
            body: serde_json::to_vec(&serde_json::json!({
                "id": id, "generation": next.routing().generation(), "distribution": "pending",
            }))
            .map_err(|_| ApiError(500, "encoding_failed"))?,
            is_config: false,
        })
    }
}

impl wgfeel_protocol::Handler for ManagementService {
    fn handle(&mut self, request: Request<'_>) -> Response {
        self.handle(request)
    }
}

struct ApiError(u16, &'static str);
impl From<DomainError> for ApiError {
    fn from(_: DomainError) -> Self {
        Self(422, "invalid_configuration")
    }
}
fn storage_error(error: StoreError) -> ApiError {
    match error {
        StoreError::RevisionConflict => ApiError(412, "revision_conflict"),
        StoreError::WithdrawalPending => ApiError(409, "withdrawal_pending"),
        StoreError::CommitUncertain => ApiError(503, "commit_uncertain_reload_required"),
        _ => ApiError(503, "storage_unavailable"),
    }
}
fn change_error(error: ManagementChangeError) -> ApiError {
    use ManagementChangeError::*;
    match error {
        RevisionConflict => ApiError(412, "revision_conflict"),
        UnknownClient | UnknownDevice | UnknownGateway => ApiError(404, "not_found"),
        DuplicateClient | DuplicateDevice | Invalid(DomainError::DuplicateGatewayId) => {
            ApiError(409, "already_exists")
        }
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

enum Route<'a> {
    DeviceConfig(&'a str, &'a str, Option<&'a str>),
    Distribution,
    Identity,
    Config,
    Users,
    User(&'a str),
    Suspension(&'a str, bool),
    Devices(&'a str),
    Device(&'a str, &'a str),
    Gateways,
    Gateway(&'a str),
}
impl<'a> Route<'a> {
    fn parse(target: &'a str) -> Result<Self, ApiError> {
        if target.len() > 512
            || !target.starts_with('/')
            || !target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-".contains(&byte))
        {
            return Err(ApiError(400, "invalid_target"));
        }
        let parts: Vec<_> = target.split('/').collect();
        match parts.as_slice() {
            ["", "api", "v1", "users", user, "devices", device, "config"] => {
                Ok(Self::DeviceConfig(user, device, None))
            }
            [
                "",
                "api",
                "v1",
                "users",
                user,
                "devices",
                device,
                "config",
                network,
            ] => Ok(Self::DeviceConfig(user, device, Some(network))),
            ["", "api", "v1", "distribution"] => Ok(Self::Distribution),
            ["", "api", "v1", "identity"] => Ok(Self::Identity),
            ["", "api", "v1", "config"] => Ok(Self::Config),
            ["", "api", "v1", "users"] => Ok(Self::Users),
            ["", "api", "v1", "users", user] => Ok(Self::User(user)),
            ["", "api", "v1", "users", user, "suspend"] => Ok(Self::Suspension(user, true)),
            ["", "api", "v1", "users", user, "resume"] => Ok(Self::Suspension(user, false)),
            ["", "api", "v1", "users", user, "devices"] => Ok(Self::Devices(user)),
            ["", "api", "v1", "users", user, "devices", device] => Ok(Self::Device(user, device)),
            ["", "api", "v1", "gateways"] => Ok(Self::Gateways),
            ["", "api", "v1", "gateways", gateway] => Ok(Self::Gateway(gateway)),
            _ => Err(ApiError(404, "not_found")),
        }
    }
}

fn read(document: &ManagementDocument, route: Route<'_>) -> Result<Vec<u8>, ApiError> {
    let user_view = |client: &Client| serde_json::json!({"id":client.id(), "name":client.name(), "suspended":document.routing().config().networks().iter().any(|network| network.id() == client.network() && network.suspended()), "devices":client.devices()});
    let gateway_view = |gateway: &GatewayAssignment| {
        let owner = |network: &NetworkId| {
            document
                .clients()
                .iter()
                .find(|client| client.network() == network)
                .map(|client| client.id())
        };
        serde_json::json!({
            "recipient":gateway.recipient(), "service_public_key":gateway.service_public_key(), "gateway_public_key":gateway.gateway_public_key(),
            "endpoint":gateway.endpoint(), "endpoints":gateway.endpoints(), "hostname":gateway.hostname(), "auto_users":gateway.auto_networks(),
            "users":gateway.networks().iter().map(owner).collect::<Vec<_>>(),
            "tenants":gateway.tenants().iter().map(|tenant| serde_json::json!({"user":owner(tenant.network()), "public_key":tenant.public_key()})).collect::<Vec<_>>()
        })
    };
    let user = |id: &str| {
        document
            .clients()
            .iter()
            .find(|client| client.id().as_str() == id)
            .ok_or(ApiError(404, "not_found"))
    };
    let value = match route {
        Route::DeviceConfig(..) | Route::Distribution | Route::Identity | Route::Suspension(..) => {
            return Err(ApiError(405, "method_not_allowed"));
        }
        Route::Config => {
            return document
                .to_json()
                .map(String::into_bytes)
                .map_err(Into::into);
        }
        Route::Users => {
            serde_json::json!({"users": document.clients().iter().map(user_view).collect::<Vec<_>>()})
        }
        Route::User(id) => user_view(user(id)?),
        Route::Devices(id) => serde_json::json!({"devices": user(id)?.devices()}),
        Route::Device(id, device) => serde_json::json!(
            user(id)?
                .devices()
                .iter()
                .find(|entry| entry.id().as_str() == device)
                .ok_or(ApiError(404, "not_found"))?
        ),
        Route::Gateways => {
            serde_json::json!({"gateways": document.routing().assignments().iter().map(gateway_view).collect::<Vec<_>>()})
        }
        Route::Gateway(id) => gateway_view(
            document
                .routing()
                .assignments()
                .iter()
                .find(|entry| entry.recipient().as_str() == id)
                .ok_or(ApiError(404, "not_found"))?,
        ),
    };
    serde_json::to_vec(&value).map_err(|_| ApiError(500, "encoding_failed"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddUser {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddDevice {
    name: String,
    description: Option<String>,
    public_key: Option<String>,
    gateway: Option<String>,
    #[serde(default)]
    addresses: Vec<IpAddr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddGateway {
    id: Option<String>,
    public_key: String,
    gateway_public_key: String,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    tenants: Vec<Tenant>,
    auto_networks: Option<bool>,
    endpoint: Option<std::net::SocketAddr>,
    #[serde(default)]
    traffic: wgfeel_core::TrafficMode,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tenant {
    network: Option<String>,
    user: Option<String>,
    public_key: String,
}

fn json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError(400, "invalid_json"))
}
fn public_key(value: &str) -> Result<DevicePublicKey, ApiError> {
    let bytes = decode_key(value).map_err(|_| ApiError(422, "invalid_public_key"))?;
    DevicePublicKey::new(*bytes).map_err(Into::into)
}
fn mutation(
    document: &ManagementDocument,
    secrets: &mut wgfeel_store::ManagementSecrets,
    route: Route<'_>,
    body: &[u8],
) -> Result<(ManagementChange, String), ApiError> {
    match route {
        Route::Users => {
            let value: AddUser = json(body)?;
            let id = generated_id(None)?;
            Ok((
                ManagementChange::AddClient {
                    client: ClientId::new(&id)?,
                    network: NetworkId::new(&id)?,
                    name: value.name,
                },
                id,
            ))
        }
        Route::User(id) => Ok((
            ManagementChange::RemoveClient {
                client: ClientId::new(id)?,
            },
            id.into(),
        )),
        Route::Suspension(id, suspended) => {
            if body != b"{}" {
                return Err(ApiError(400, "unexpected_body"));
            }
            Ok((
                ManagementChange::SetClientSuspended {
                    client: ClientId::new(id)?,
                    suspended,
                },
                id.into(),
            ))
        }
        Route::Devices(user) => {
            let value: AddDevice = json(body)?;
            provision::device(document, secrets, user, value)
        }
        Route::Device(user, device) => Ok((
            ManagementChange::RemoveDevice {
                client: ClientId::new(user)?,
                device: DeviceId::new(device)?,
            },
            device.into(),
        )),
        Route::Gateways => {
            let mut value: AddGateway = json(body)?;
            if !value.users.is_empty() && !value.networks.is_empty() {
                return Err(ApiError(422, "conflicting_scope"));
            }
            let user_network = |id: &str| -> Result<NetworkId, ApiError> {
                document
                    .clients()
                    .iter()
                    .find(|client| client.id().as_str() == id)
                    .map(|client| client.network().clone())
                    .ok_or(ApiError(422, "unknown_user"))
            };
            for user in &value.users {
                value.networks.push(user_network(user)?.as_str().to_owned());
            }
            let automatic = value.auto_networks.unwrap_or(
                value.endpoint.is_some() && value.networks.is_empty() && value.tenants.is_empty(),
            );
            let id = generated_id(value.id)?;
            let tenants = value
                .tenants
                .into_iter()
                .map(|tenant| {
                    Ok(TenantKeyAssignment::new(
                        match (tenant.user, tenant.network) {
                            (Some(user), None) => user_network(&user)?,
                            (None, Some(network)) => NetworkId::new(&network)?,
                            _ => return Err(ApiError(422, "invalid_tenant")),
                        },
                        public_key(&tenant.public_key)?,
                    ))
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            Ok((
                ManagementChange::AddGateway {
                    assignment: GatewayAssignment::new(
                        NodeId::new(&id)?,
                        public_key(&value.public_key)?,
                        public_key(&value.gateway_public_key)?,
                        value
                            .networks
                            .into_iter()
                            .map(|network| NetworkId::new(&network))
                            .collect::<Result<_, _>>()?,
                        tenants,
                    )?
                    .with_endpoint(value.endpoint)?
                    .with_traffic(value.traffic)?
                    .with_auto_networks(automatic),
                },
                id,
            ))
        }
        Route::Gateway(id) => Ok((
            ManagementChange::RemoveGateway {
                gateway: NodeId::new(id)?,
            },
            id.into(),
        )),
        Route::DeviceConfig(..) | Route::Config | Route::Distribution | Route::Identity => {
            Err(ApiError(405, "method_not_allowed"))
        }
    }
}
