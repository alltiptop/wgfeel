//! Authenticated delivery endpoint. Called only for the pinned Management peer.
use super::{LocalGateway, WorkerOptions};
use std::time::{Duration, Instant};
use wgfeel_core::{DevicePublicKey, GatewayProjection, NodeId, TenantPrivateKey};
use wgfeel_protocol::{Request, Response};
use wgfeel_store::{
    GatewayDelivery, LocalEgressSecrets, LocalTenants, Store, StoreError, StoredState,
};
use wgfeel_wireguard::{
    Limits,
    worker::{LocalError, LocalEvent, WorkerError},
};

pub(super) fn options() -> WorkerOptions {
    WorkerOptions {
        address_space_bytes: 64 * 1024 * 1024,
        startup_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(2),
    }
}
pub(super) fn provider_keys<'a>(
    projection: &'a GatewayProjection,
    keys: &'a LocalEgressSecrets,
) -> impl Iterator<
    Item = (
        &'a wgfeel_core::EgressId,
        &'a wgfeel_core::EgressPrivateKey,
        Option<&'a wgfeel_core::PresharedKey>,
    ),
> {
    projection.owned_egresses().iter().filter_map(move |p| {
        keys.get(&p.id)
            .map(|k| (&p.id, k.private_key(), k.preshared_key()))
    })
}
pub(super) fn spawn(state: &StoredState) -> Result<LocalGateway, &'static str> {
    let projection = state.projection();
    let tenants = state
        .local_tenants()
        .network_ids()
        .filter_map(|id| state.local_tenants().private_key(id).map(|key| (id, key)));
    match state.management_public_key() {
        Some(pin) => LocalGateway::spawn_with_egresses(
            projection,
            pin,
            state.node_keys(),
            tenants,
            provider_keys(projection, state.egress_keys()),
            Limits::default(),
            options(),
        ),
        None => LocalGateway::spawn(
            projection,
            projection.management_id(),
            state.node_id(),
            state.node_keys(),
            tenants,
            Limits::default(),
            options(),
        ),
    }
    .map_err(|_| "cannot construct node workers")
}

struct Candidate {
    gateway: LocalGateway,
    delivery: GatewayDelivery,
    remaining: usize,
    deadline: Instant,
    prior: GatewayProjection,
    prior_pin: Option<DevicePublicKey>,
    pin: DevicePublicKey,
    joined: bool,
}
pub(super) enum Activation {
    SameAuthority,
    NewAuthority,
}

#[derive(Default)]
pub(super) struct Updates {
    pending: Option<Candidate>,
}
impl Updates {
    pub(super) fn cancel_pending(&mut self) {
        self.pending = None;
    }
    pub(super) fn cancel_join(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|candidate| candidate.joined)
        {
            self.pending = None;
        }
    }
    pub(super) fn handle(
        &mut self,
        store: &mut Store,
        gateway: &mut LocalGateway,
        request: Request<'_>,
    ) -> Response {
        self.handle_inner(store, gateway, request, None)
    }
    pub(super) fn handle_join(
        &mut self,
        store: &mut Store,
        gateway: &mut LocalGateway,
        request: Request<'_>,
        management: &NodeId,
        pin: &DevicePublicKey,
    ) -> Response {
        self.handle_inner(store, gateway, request, Some((management, pin)))
    }
    fn handle_inner(
        &mut self,
        store: &mut Store,
        gateway: &mut LocalGateway,
        request: Request<'_>,
        joining: Option<(&NodeId, &DevicePublicKey)>,
    ) -> Response {
        if request.target != "/internal/v1/config" {
            return Response::error(404, "not_found");
        }
        if request.method != "POST" {
            return Response::error(405, "method_not_allowed");
        }
        if request.authorization.is_some() || request.if_match.is_some() {
            return Response::error(400, "unexpected_credentials");
        }
        let delivery = GatewayDelivery::decode(request.body).ok();
        let next = match delivery
            .as_ref()
            .map(|delivery| delivery.projection().clone())
            .or_else(|| {
                std::str::from_utf8(request.body)
                    .ok()
                    .and_then(|body| GatewayProjection::from_json(body).ok())
            }) {
            Some(next) => next,
            None => return Response::error(422, "invalid_projection"),
        };
        let current = gateway.projection();
        if next
            .validate_target(
                joining.map_or(current.management_id(), |(id, _)| id),
                current.recipient(),
            )
            .is_err()
            || next.assignment().service_public_key() != current.assignment().service_public_key()
            || next.assignment().gateway_public_key() != current.assignment().gateway_public_key()
        {
            return Response::error(403, "identity_mismatch");
        }
        let state = match store.load() {
            Ok(Some(state)) => state,
            _ => return Response::error(503, "storage_unavailable"),
        };
        let Some(pin) = joining
            .map(|(_, pin)| pin)
            .or_else(|| state.management_public_key())
        else {
            return Response::error(403, "authority_not_pinned");
        };
        if state.projection() != current {
            return Response::error(503, "runtime_state_mismatch");
        }
        let transfer = Some(pin) != state.management_public_key()
            || current.management_id() != next.management_id();
        if !transfer
            && (next.generation() < current.generation()
                || (next.generation() == current.generation() && &next != current))
        {
            return Response::error(409, "revision_conflict");
        }
        if delivery.is_none() && !next.owned_egresses().is_empty() {
            return Response::error(422, "local_keys_unavailable");
        }
        if !transfer
            && next.owned_egresses().iter().any(|p| {
                current
                    .owned_egresses()
                    .iter()
                    .find(|old| old.id == p.id)
                    .is_some_and(|old| {
                        p.secret_revision < old.secret_revision
                            || (p.secret_revision == old.secret_revision
                                && !delivery
                                    .as_ref()
                                    .and_then(|d| d.egress_keys().get(&p.id))
                                    .zip(state.egress_keys().get(&p.id))
                                    .is_some_and(|(a, b)| a.same_material(b)))
                    })
            })
        {
            return Response::error(409, "key_revision_conflict");
        }
        if &next == current && !transfer {
            if delivery.as_ref().is_some_and(|delivery| {
                delivery.keys().network_ids().any(|id| {
                    delivery
                        .keys()
                        .private_key(id)
                        .map(|key| key.expose_bytes())
                        != state
                            .local_tenants()
                            .private_key(id)
                            .map(|key| key.expose_bytes())
                })
            }) {
                return Response::error(409, "key_revision_conflict");
            }
            return if store.confirm_delivery().is_ok() {
                applied(current)
            } else {
                Response::error(503, "durability_unconfirmed")
            };
        }
        if let Some(pending) = &self.pending {
            let proposed = pending.gateway.projection();
            if &next == proposed {
                if delivery.as_ref().is_some_and(|d| {
                    !d.egress_keys()
                        .same_material(pending.delivery.egress_keys())
                }) {
                    return Response::error(409, "key_revision_conflict");
                }
                return pending_response(next.generation());
            }
            if next.generation() <= proposed.generation() {
                return Response::error(409, "revision_conflict");
            }
        }
        let tenants = match selected_tenants(
            &state,
            &next,
            delivery.as_ref().map(GatewayDelivery::keys),
            transfer,
        ) {
            Ok(tenants) => tenants,
            Err(()) => return Response::error(422, "local_keys_unavailable"),
        };
        let egress_keys = delivery
            .map(GatewayDelivery::into_egress_keys)
            .unwrap_or_default();
        let Ok(delivery) = GatewayDelivery::from_parts(next.clone(), tenants, egress_keys) else {
            return Response::error(422, "invalid_local_contexts");
        };
        // Crypto validation and worker readiness precede the commit. The old
        // runtime continues forwarding while this isolated candidate starts.
        let candidate = match gateway.replace_with_egresses(
            &next,
            pin,
            state.node_keys(),
            delivery
                .keys()
                .network_ids()
                .filter_map(|id| delivery.keys().private_key(id).map(|key| (id, key))),
            provider_keys(&next, delivery.egress_keys()),
        ) {
            Ok(candidate) => candidate,
            Err(_) => return Response::error(422, "invalid_local_contexts"),
        };
        self.pending = Some(Candidate {
            remaining: candidate.starting_workers(),
            gateway: candidate,
            delivery,
            deadline: Instant::now() + Duration::from_secs(10),
            prior: current.clone(),
            prior_pin: state.management_public_key().cloned(),
            pin: pin.clone(),
            joined: joining.is_some(),
        });
        pending_response(next.generation())
    }

    /// Reports which authenticated transport can outlive the published revision.
    pub(super) fn poll(
        &mut self,
        store: &mut Store,
        gateway: &mut LocalGateway,
    ) -> Result<Option<Activation>, &'static str> {
        let Some(candidate) = self.pending.as_mut() else {
            return Ok(None);
        };
        if Instant::now() > candidate.deadline {
            self.pending = None;
            return Ok(None);
        }
        for _ in 0..super::BATCH {
            match candidate.gateway.poll() {
                Some(LocalEvent::Ready { .. }) => {
                    candidate.remaining = candidate
                        .remaining
                        .checked_sub(1)
                        .ok_or("unexpected child worker readiness")?
                }
                Some(_) => {
                    self.pending = None;
                    return Ok(None);
                }
                None => break,
            }
        }
        if candidate.remaining != 0 {
            return Ok(None);
        }
        let handoff = match candidate.gateway.handoff(gateway) {
            Ok(handoff) => handoff,
            Err(LocalError::Worker(WorkerError::Busy)) => return Ok(None),
            Err(_) => {
                self.pending = None;
                return Ok(None);
            }
        };
        let state = store
            .load()
            .map_err(|_| "cannot read Node state during apply")?
            .ok_or("missing Node state during apply")?;
        if state.projection() != &candidate.prior
            || state.management_public_key() != candidate.prior_pin.as_ref()
        {
            self.pending = None;
            return Ok(None);
        }
        let committed = if candidate.joined {
            store.accept_delivery_with_checkpoint(
                &candidate.prior,
                candidate.prior_pin.as_ref(),
                &candidate.delivery,
                &candidate.pin,
                |_| Ok(()),
            )
        } else {
            store.commit_managed_delivery(&candidate.delivery, state.node_keys(), &candidate.pin)
        };
        match committed {
            Ok(()) => (),
            Err(StoreError::CommitUncertain) => {
                // A published revocation must immediately govern traffic even
                // if the final fsync failed. No ACK until a later sync succeeds.
                let published = store
                    .load()
                    .map_err(|_| "uncertain Node state; stopping forwarding")?
                    .ok_or("uncertain Node state; stopping forwarding")?;
                if published.projection() != handoff.projection()
                    || published.management_public_key() != Some(&candidate.pin)
                {
                    return Err("uncertain Node state; stopping forwarding");
                }
            }
            Err(_) => {
                self.pending = None;
                return Ok(None);
            }
        }
        handoff
            .activate()
            .map_err(|_| "cannot activate committed Node policy")?;
        let same_authority = candidate.prior_pin.as_ref() == Some(&candidate.pin)
            && candidate.prior.management_id() == gateway.projection().management_id();
        self.pending = None;
        Ok(Some(if same_authority {
            Activation::SameAuthority
        } else {
            Activation::NewAuthority
        }))
    }
}
fn selected_tenants(
    state: &StoredState,
    next: &GatewayProjection,
    delivered: Option<&LocalTenants>,
    transfer: bool,
) -> Result<LocalTenants, ()> {
    let mut entries = Vec::with_capacity(next.assignment().tenants().len());
    for tenant in next.assignment().tenants() {
        let key = delivered
            .and_then(|keys| keys.private_key(tenant.network()))
            .or_else(|| {
                if transfer {
                    None
                } else {
                    state.local_tenants().private_key(tenant.network())
                }
            })
            .ok_or(())?;
        entries.push((
            tenant.network().clone(),
            TenantPrivateKey::new(*key.expose_bytes()).map_err(|_| ())?,
        ));
    }
    LocalTenants::new(entries).map_err(|_| ())
}
fn applied(projection: &GatewayProjection) -> Response {
    Response{status:200,generation:Some(projection.generation()),body:serde_json::json!({"applied":true,"generation":projection.generation(),"recipient":projection.recipient()}).to_string().into_bytes(),is_config:false}
}
fn pending_response(generation: u64) -> Response {
    Response {
        status: 202,
        generation: Some(generation),
        body: b"{\"applied\":false}".to_vec(),
        is_config: false,
    }
}
