use super::{
    ApiError, ManagementService, Request, Response, change_error, provision, storage_error,
};
use std::{
    net::SocketAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use wgfeel_core::{DevicePublicKey, GatewayAssignment, ManagementChange, NodeId, TrafficMode};
use wgfeel_protocol::enrollment::{ENROLLMENT_PATH, EnrollmentClaim};
use wgfeel_store::StoredManagement;

impl ManagementService {
    pub(super) fn issue_invitation(
        &mut self,
        state: &StoredManagement,
        body: &[u8],
    ) -> Result<Response, ApiError> {
        #[derive(Default, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            #[serde(default)]
            traffic: TrafficMode,
        }
        let input: Input = if body.is_empty() {
            Input::default()
        } else {
            serde_json::from_slice(body).map_err(|_| ApiError(400, "invalid_invitation_options"))?
        };
        let api = state
            .api()
            .ok_or(ApiError(503, "service_api_unavailable"))?;
        if api.endpoints().is_empty() {
            return Err(ApiError(503, "management_endpoint_required"));
        }
        let public = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::X25519,
            state.service_private_key().expose_bytes(),
        )
        .map_err(|_| ApiError(503, "identity_unavailable"))?
        .compute_public_key()
        .map_err(|_| ApiError(503, "identity_unavailable"))?;
        let public = DevicePublicKey::new(
            public
                .as_ref()
                .try_into()
                .map_err(|_| ApiError(503, "identity_unavailable"))?,
        )?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError(503, "clock_unavailable"))?
            .as_secs();
        let invitation = self
            .invitations
            .issue(
                state.document().routing().management_id().clone(),
                public,
                (api.endpoints().to_vec(), api.listen().port()),
                input.traffic,
                Instant::now(),
                unix_seconds,
            )
            .map_err(enrollment_error)?;
        let uri = invitation
            .encode()
            .map_err(|_| ApiError(500, "encoding_failed"))?;
        #[derive(serde::Serialize)]
        struct Issued<'a> {
            invitation: &'a str,
            expires_at: u64,
            traffic: TrafficMode,
        }
        Ok(Response {
            status: 201,
            generation: Some(state.document().routing().generation()),
            is_config: false,
            body: serde_json::to_vec(&Issued {
                invitation: &uri,
                expires_at: invitation.expires_at(),
                traffic: input.traffic,
            })
            .map_err(|_| ApiError(500, "encoding_failed"))?,
        })
    }
    /// Public keys for temporary WG peers only. The transport must retire peers
    /// and their inner TCP sessions when they disappear from this list.
    pub fn invitation_peers(&mut self) -> Vec<(NodeId, DevicePublicKey)> {
        self.invitations.peers(Instant::now())
    }
    pub fn pending_enrollments(&mut self) -> Vec<(NodeId, DevicePublicKey, EnrollmentClaim)> {
        self.invitations.pending(Instant::now())
    }
    /// Separate capability boundary, never forwarded to the administrative
    /// router. Peer identity must be supplied by the authenticated WG transport.
    pub fn handle_enrollment(
        &mut self,
        invitation: &NodeId,
        authenticated_key: &DevicePublicKey,
        request: Request<'_>,
    ) -> Response {
        let result = (|| {
            if request.method != "POST"
                || request.target != ENROLLMENT_PATH
                || request.authorization.is_some()
                || request.if_match.is_some()
            {
                return Err(ApiError(403, "enrollment_only"));
            }
            let claim = EnrollmentClaim::decode(request.body)
                .map_err(|_| ApiError(400, "invalid_enrollment"))?;
            let generation = self
                .invitations
                .claim_generation(invitation, authenticated_key, &claim, Instant::now())
                .map_err(enrollment_error)?;
            let state = self.delivery_snapshot().map_err(storage_error)?;
            if generation.is_some()
                && !state.document().routing().assignments().iter().any(|node| {
                    node.recipient() == claim.node_id()
                        && node.service_public_key() == claim.public_key()
                        && node.gateway_public_key() == claim.gateway_public_key()
                })
            {
                return Err(ApiError(410, "enrollment_revoked"));
            }
            validate_identity(&state, &claim)?;
            let claim = self
                .invitations
                .claim(invitation, authenticated_key, claim, Instant::now())
                .map_err(enrollment_error)?;
            Ok(Response { status: if generation.is_some() { 200 } else { 202 }, generation, is_config: false,
                body: serde_json::to_vec(&serde_json::json!({"node_id":claim.node_id(),"registered":generation.is_some()}))
                    .map_err(|_| ApiError(500, "encoding_failed"))? })
        })();
        match result {
            Ok(response) => response,
            Err(ApiError(status, code)) => Response::error(status, code),
        }
    }
    /// Trusted transport boundary: invoke only after a challenge response over
    /// permanent-key WG initiated to `verified_endpoint`. Invitation possession
    /// alone never authorizes activation or access to recipient private config.
    pub fn complete_enrollment(
        &mut self,
        invitation: &NodeId,
        temporary_key: &DevicePublicKey,
        permanent_key: &DevicePublicKey,
        verified_endpoint: SocketAddr,
    ) -> Response {
        let result = (|| {
            let now = Instant::now();
            let claim = self
                .invitations
                .claimed(invitation, temporary_key, now)
                .map_err(enrollment_error)?
                .clone();
            if claim.public_key() != permanent_key
                || !claim.endpoints().contains(&verified_endpoint)
            {
                return Err(ApiError(403, "invalid_node_proof"));
            }
            let state = self.delivery_snapshot().map_err(storage_error)?;
            let current = state
                .document()
                .routing()
                .assignments()
                .iter()
                .find(|node| node.recipient() == claim.node_id());
            let traffic = self
                .invitations
                .traffic(invitation, temporary_key, now)
                .map_err(enrollment_error)?;
            if self
                .invitations
                .generation(invitation, temporary_key, now)
                .map_err(enrollment_error)?
                .is_some()
            {
                if current.is_none_or(|node| {
                    node.service_public_key() != claim.public_key()
                        || node.gateway_public_key() != claim.gateway_public_key()
                }) {
                    return Err(ApiError(410, "enrollment_revoked"));
                }
                return Ok(Response {
                    status: 200,
                    generation: Some(state.document().routing().generation()),
                    body: vec![],
                    is_config: false,
                });
            }
            validate_identity(&state, &claim)?;
            if current.is_some_and(|node| node.traffic() != traffic) {
                return Err(ApiError(409, "traffic_mode_conflict"));
            }
            // Native WG profiles have one Endpoint. Do not export an address
            // that already failed the enrollment proof as their primary path.
            let mut endpoints = claim.endpoints().to_vec();
            endpoints.retain(|endpoint| *endpoint != verified_endpoint);
            endpoints.insert(0, verified_endpoint);
            let change = if let Some(current) = current {
                if current.hostname() == Some(claim.hostname()) && current.endpoints() == endpoints
                {
                    None
                } else {
                    Some(ManagementChange::SetGatewayContact {
                        gateway: claim.node_id().clone(),
                        hostname: claim.hostname().into(),
                        endpoints,
                    })
                }
            } else {
                Some(ManagementChange::AddGateway {
                    assignment: GatewayAssignment::new(
                        claim.node_id().clone(),
                        claim.public_key().clone(),
                        claim.gateway_public_key().clone(),
                        vec![],
                        vec![],
                    )?
                    .with_traffic(traffic)?
                    .with_hostname(Some(claim.hostname().into()))?
                    .with_endpoints(endpoints)?
                    .with_auto_networks(true),
                })
            };
            let generation = if let Some(change) = change {
                let expected = state.document().routing().generation();
                let mut secrets = state.secrets().copy_owned().map_err(storage_error)?;
                let next = state
                    .document()
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
                next.routing().generation()
            } else {
                state.document().routing().generation()
            };
            self.invitations
                .activated(invitation, temporary_key, permanent_key, generation, now)
                .map_err(enrollment_error)?;
            Ok(Response {
                status: 200,
                generation: Some(generation),
                body: vec![],
                is_config: false,
            })
        })();
        match result {
            Ok(response) => response,
            Err(ApiError(status, code)) => Response::error(status, code),
        }
    }
}

fn validate_identity(state: &StoredManagement, claim: &EnrollmentClaim) -> Result<(), ApiError> {
    let claimed = claim.public_keys();
    if claim.node_id() == state.document().routing().management_id()
        || state
            .api()
            .is_some_and(|api| claimed.contains(&api.admin_public_key()))
        || state.document().routing().assignments().iter().any(|node| {
            if node.recipient() == claim.node_id() {
                node.service_public_key() != claim.public_key()
                    || node.gateway_public_key() != claim.gateway_public_key()
            } else {
                node.transport_public_keys()
                    .iter()
                    .any(|key| claimed.contains(key))
                    || node
                        .tenants()
                        .iter()
                        .any(|tenant| claimed.contains(&tenant.public_key()))
            }
        })
        || state.retired_gateways().iter().any(|node| {
            node.recipient() == claim.node_id()
                || node
                    .transport_public_keys()
                    .iter()
                    .any(|key| claimed.contains(key))
        })
        || state
            .document()
            .routing()
            .config()
            .networks()
            .iter()
            .flat_map(|network| network.devices())
            .any(|device| claimed.contains(&device.public_key()))
    {
        return Err(ApiError(409, "node_identity_conflict"));
    }
    Ok(())
}
fn enrollment_error(error: super::EnrollmentError) -> ApiError {
    use super::EnrollmentError::*;
    match error {
        Unavailable => ApiError(503, "enrollment_unavailable"),
        Limit => ApiError(429, "invitation_limit"),
        ExpiredOrUnknown => ApiError(410, "invitation_expired_or_unknown"),
        AlreadyClaimed => ApiError(409, "invitation_already_claimed"),
        InvalidIdentity => ApiError(403, "invalid_node_identity"),
        NotClaimed => ApiError(409, "invitation_not_claimed"),
    }
}
