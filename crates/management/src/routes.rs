//! The same declarations match incoming requests and describe the public API.
use super::{
    ApiError, ManagementService, Request, Response, http,
    models::*,
    openapi::{self, ApiDocument, Payload, PublicConfig, WireGuardProfile},
    operations::Context,
};
use serde::Deserialize;
use wgfeel_store::StoredManagement;

const PREFIX: &str = "/api/v1/";
const SCHEMA_FILE: &str = "openapi.json";
pub(super) fn is_schema_path(target: &str) -> bool {
    target.strip_prefix(PREFIX) == Some(SCHEMA_FILE)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Read,
    Create,
    Replace,
    Placement,
    Delete,
    Suspension,
    Invite,
    Rotate,
}
impl Kind {
    pub fn method(self) -> &'static str {
        match self {
            Self::Read => "GET",
            Self::Delete => "DELETE",
            Self::Replace | Self::Placement => "PUT",
            _ => "POST",
        }
    }
    pub fn status(self) -> u16 {
        match self {
            Self::Create | Self::Suspension | Self::Invite => 201,
            _ => 200,
        }
    }
    pub fn requires_revision(self) -> bool {
        !matches!(self, Self::Read | Self::Invite)
    }

    fn check(self, request: &Request<'_>, revision: u64) -> Result<(), ApiError> {
        if matches!(self, Self::Read | Self::Delete | Self::Rotate) && !request.body.is_empty() {
            return Err(ApiError(400, "unexpected_body"));
        }
        if self == Self::Read {
            return Ok(());
        }
        match request.if_match {
            None if self.requires_revision() => Err(ApiError(428, "revision_required")),
            None => Ok(()),
            Some(value) => {
                let expected =
                    http::parse_revision(value).ok_or(ApiError(400, "invalid_revision"))?;
                if expected == revision {
                    Ok(())
                } else {
                    Err(ApiError(412, "revision_conflict"))
                }
            }
        }
    }

    fn decode<'de, T: Deserialize<'de>>(self, bytes: &'de [u8]) -> Result<T, ApiError> {
        if self == Self::Suspension && bytes != b"{}" {
            return Err(ApiError(400, "unexpected_body"));
        }
        if self == Self::Invite {
            return serde_json::from_slice(if bytes.is_empty() { b"{}" } else { bytes })
                .map_err(|_| ApiError(400, "invalid_invitation_options"));
        }
        serde_json::from_slice(bytes).map_err(|_| ApiError(400, "invalid_json"))
    }
}

macro_rules! segment_pattern {
    ({$name:ident}) => {
        $name
    };
    ($fixed:tt) => {
        $fixed
    };
}
macro_rules! segment_template {
    ({$name:ident}) => {
        concat!("{", stringify!($name), "}")
    };
    ($fixed:tt) => {
        $fixed
    };
}

macro_rules! request_schema {
    ($api:ident, $input:ty) => {
        Some($api.input::<$input>())
    };
    ($api:ident,) => {
        None
    };
}

fn segments(target: &str) -> Result<Vec<&str>, ApiError> {
    if target.len() > 512
        || !target.starts_with('/')
        || (!is_schema_path(target)
            && !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b)))
    {
        return Err(ApiError(400, "invalid_target"));
    }
    Ok(target
        .strip_prefix(PREFIX)
        .ok_or(ApiError(404, "not_found"))?
        .split('/')
        .collect())
}

// Braced segments bind path parameters. Each entry names the actual handler,
// its JSON input (if any) and its wire response type, checked at the call site.
macro_rules! routes {
    ($( [$($segment:tt),+] { $(
        #[doc = $summary:literal] $(#[doc = $detail:literal])*
        $kind:ident $handler:ident ($($arg:ident),* $(; $input:ty)?) -> $output:ty $(, errors($($error:literal),+))?;
    )+ } )+) => {
        pub(super) fn dispatch(
            service: &mut ManagementService, state: &StoredManagement, request: Request<'_>
        ) -> Result<Response, ApiError> {
            let parts = segments(request.target)?;
            let mut ctx = Context { service, state, status: None, revision: state.document().routing().generation() };
            match parts.as_slice() {
                $( [$(segment_pattern!($segment)),+] => {
                    $( let kind = Kind::$kind;
                    if request.method == kind.method() {
                        kind.check(&request, ctx.revision)?;
                        let output: $output = ctx.$handler(
                            $($arg,)* $(kind.decode::<$input>(request.body)?)?
                        )?;
                        return Ok(Response {
                            status: ctx.status.unwrap_or(kind.status()),
                            generation: Some(ctx.revision),
                            is_config: <$output as Payload>::MEDIA_TYPE == "text/plain",
                            body: output.encode()?,
                        });
                    } )+
                    // Resource reads reject a body even on a write-only suspension path.
                    if request.method == "GET" && [$(Kind::$kind),+].contains(&Kind::Suspension) {
                        Kind::Read.check(&request, ctx.revision)?;
                    }
                    Err(ApiError(405, "method_not_allowed"))
                } )+
                _ => Err(ApiError(404, "not_found")),
            }
        }

        pub(super) fn describe(api: &mut openapi::Builder) {
            $( let path = format!("{PREFIX}{}", [$(segment_template!($segment)),+].join("/"));
                $( {
                    let input = request_schema!(api, $($input)?);
                    api.operation::<$output>(
                        &path, Kind::$kind, stringify!($handler),
                        &[$summary, $($detail),*], input, &[$($($error),+)?],
                    );
                } )+
            )+
        }
    };
}

routes! {
    [SCHEMA_FILE] {
        /// Get the OpenAPI contract for the running server.
        /// A current administrator bearer token is required on every transport, including the owner socket.
        Read openapi() -> ApiDocument;
    }
    ["identity"] {
        /// Get main's public service identity.
        Read get_identity() -> Identity<'_>;
    }
    ["config"] {
        /// Read the public management configuration at the current revision.
        Read get_config() -> PublicConfig<'_>, errors(422);
    }
    ["distribution"] {
        /// List the desired and acknowledged configuration revision for each node.
        Read get_distribution() -> Distribution<'_>;
    }
    ["users"] {
        /// List users and their devices.
        Read list_users() -> Users<'_>;
        /// Create a user and an isolated network.
        Create create_user(; AddUser) -> ChangeReceipt, errors(409, 422);
    }
    ["users", {user}] {
        /// Get one user and their devices.
        Read get_user(user) -> User<'_>, errors(404);
        /// Remove the user and their network.
        Delete delete_user(user) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["users", {user}, "broadcast"] {
        /// Read the user's default directed broadcast policy.
        Read get_user_broadcast(user) -> UserBroadcast, errors(404);
        /// Set the user's default directed broadcast policy.
        Replace set_user_broadcast(user; UserBroadcast) -> UserBroadcast, errors(404);
    }
    ["users", {user}, "devices", {device}, "broadcast"] {
        /// Read the device override and effective directed broadcast policy.
        Read get_device_broadcast(user, device) -> DeviceBroadcast, errors(404, 409);
        /// Set the device override. Null restores inheritance.
        Replace set_device_broadcast(user, device; SetDeviceBroadcast) -> DeviceBroadcast, errors(404, 409);
    }
    ["users", {user}, "suspend"] {
        /// Suspend traffic on the user's network.
        Suspension suspend_user(user; EmptyObject) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["users", {user}, "resume"] {
        /// Resume traffic on the user's network.
        Suspension resume_user(user; EmptyObject) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["users", {user}, "devices"] {
        /// List the user's device IDs and metadata.
        Read list_devices(user) -> Devices<'_>, errors(404);
        /// Provision a device in the user's network.
        Create create_device(user; AddDevice) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["users", {user}, "devices", {device}] {
        /// Get the device ID and metadata.
        Read get_device(user, device) -> DeviceView<'_>, errors(404);
        /// Remove this device from the user's network.
        Delete delete_device(user, device) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["users", {user}, "devices", {device}, "config"] {
        /// Export a WireGuard profile containing the device's private key.
        Read device_config(user, device) -> WireGuardProfile, errors(404, 409, 422);
    }
    ["users", {user}, "devices", {device}, "config", {network}] {
        /// Export the device's private WireGuard profile for the specified network.
        Read network_device_config(user, device, network) -> WireGuardProfile, errors(404, 409, 422);
    }
    ["egresses"] {
        /// List external WireGuard profiles saved on main.
        Read list_egresses() -> Egresses;
        /// Import an unassigned external WireGuard profile on main.
        Create create_egress(; AddEgress<'_>) -> ChangeReceipt, errors(409, 422);
    }
    ["egresses", {egress}] {
        /// Read the public metadata of a saved external profile.
        Read get_egress(egress) -> Egress, errors(404);
        /// Replace the provider profile while retaining its ID and grants.
        Replace replace_egress(egress; ReplaceEgress<'_>) -> Egress, errors(404,409,422);
        /// Delete an unused external profile and its saved keys.
        Delete delete_egress(egress) -> ChangeReceipt, errors(404,409, 422);
    }
    ["egresses",{egress},"node"] {
        /// Read the current egress placement and any pending handoff.
        Read get_egress_node(egress) -> EgressNode, errors(404);
        /// Attach, detach or move an external profile.
        Placement set_egress_node(egress; SetEgressNode) -> EgressNode, errors(404,409,422);
    }
    ["users",{user},"egresses"] {
        /// List the user's assigned routes and DNS selections.
        Read get_user_egresses(user) -> AssignmentList, errors(404);
        /// Replace all of the user's grants in one revision.
        Replace set_user_egresses(user; GrantSet) -> AssignmentList, errors(404,409,422);
    }
    ["users",{user},"egresses",{egress}] {
        /// Set the user's routes and DNS for one external profile.
        Replace set_user_egress(user,egress; GrantInput) -> AssignmentView, errors(404,409,422);
        /// Revoke one grant while preserving the user's other egresses.
        Delete delete_user_egress(user,egress) -> ChangeReceipt, errors(404,409,422);
    }
    ["gateways"] {
        /// List registered nodes and their public keys.
        Read list_gateways() -> Gateways<'_>;
        /// Register a node with its service and mesh public keys.
        Create create_gateway(; AddGateway) -> ChangeReceipt, errors(409, 422);
    }
    ["gateways", {gateway}] {
        /// Get a registered node and its user assignments.
        Read get_gateway(gateway) -> Gateway<'_>, errors(404);
        /// Remove a node from the configuration.
        Delete delete_gateway(gateway) -> ChangeReceipt, errors(404, 409, 422);
    }
    ["node-invitations"] {
        /// Issue a temporary node enrollment invitation.
        /// The child consumes the invitation over WireGuard. Issuing it leaves the configuration revision unchanged.
        Invite issue_invitation(; InvitationOptions) -> IssuedInvitation;
    }
    ["token", "rotate"] {
        /// Replace the administrator bearer token and return the new token once.
        Rotate rotate_token() -> RotatedToken;
    }
}

impl<'a> Context<'a> {
    fn openapi(&self) -> Result<ApiDocument, ApiError> {
        Ok(ApiDocument)
    }
    fn get_config(&self) -> Result<PublicConfig<'a>, ApiError> {
        Ok(PublicConfig(self.state.document()))
    }
    fn device_config(&self, user: &str, device: &str) -> Result<WireGuardProfile, ApiError> {
        super::provision::export(self.state, user, device, None).map(WireGuardProfile)
    }
    fn network_device_config(
        &self,
        user: &str,
        device: &str,
        network: &str,
    ) -> Result<WireGuardProfile, ApiError> {
        super::provision::export(self.state, user, device, Some(network)).map(WireGuardProfile)
    }
}
