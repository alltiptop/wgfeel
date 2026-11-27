use crate::{
    ContextConfig, ContextId, DatagramEvent, Event, Limits, MAX_DEVICE_PEERS, MAX_SERVICE_PEERS,
    MAX_TENANTS, PacketBytes, PeerConfig, PeerId, WireGuardError,
    dispatch::{DispatchContext, IndexBinding, MAX_INDICES_PER_PEER},
    framing,
    router::{Router, Verification},
};
use gotatun::{
    noise::{
        Tunn, TunnResult, handshake::parse_handshake_anon, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, PacketBufPool, WgKind},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use wgfeel_core::{
    DevicePublicKey, GatewayPrivateKey, GatewayProjection, NetworkId, NodeId, NodeKeys,
    ServicePrivateKey, TenantPrivateKey,
};
use zeroize::Zeroize;

// The engine consumes a plaintext Packet and allocates separate ciphertext.
// Retain that allocation in a private one-packet pool and wipe its full extent
// after both successful encryption and failure, including unwinding.
struct ClearPlaintext<'a>(&'a PacketBufPool<{ crate::MAX_PLAINTEXT_SIZE }>);
impl Drop for ClearPlaintext<'_> {
    fn drop(&mut self) {
        self.0.get().buf_mut().as_mut().zeroize();
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;

struct Peer {
    id: PeerId,
    public_key: DevicePublicKey,
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
    indices: Vec<u32>,
}
struct Context {
    id: ContextId,
    public_key: DevicePublicKey,
    secret: StaticSecret,
    peers: Vec<Peer>,
    rate_limiter: Arc<RateLimiter>,
}

pub(crate) struct WorkerReceive {
    pub outcome: Result<Option<Event>, WireGuardError>,
    pub authenticated_peer: Option<PeerId>,
}

/// Fixed configured contexts sharing the engine's in-process index allocator.
/// A serialized coordinator for public admission and context-owned engines.
/// These owners are in one process; this is not a worker isolation boundary.
pub struct Gateway {
    contexts: Vec<Context>,
    indices: IndexTable,
    // None marks a failed invariant. All engines and routing state are then
    // dropped; callers must reconstruct the gateway from trusted configuration.
    router: Option<Router>,
    pub(crate) projection: Option<GatewayProjection>,
    pub(crate) broadcast_jobs: std::collections::VecDeque<crate::forwarding::LocalBroadcast>,
    pub(crate) broadcast_first: bool,
    pub(crate) broadcast_limits: crate::broadcast::Limits,
    plaintext_pool: PacketBufPool<{ crate::MAX_PLAINTEXT_SIZE }>,
}
impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway")
            .field("contexts", &self.contexts.len())
            .finish_non_exhaustive()
    }
}
impl Gateway {
    /// Build local crypto contexts from a recipient-bound public projection.
    /// The caller must authenticate Management delivery before invoking this
    /// constructor. Raw plaintext events still require forwarding authorization.
    pub fn from_local_projection<'a>(
        projection: &GatewayProjection,
        expected_management: &NodeId,
        local_node_id: &NodeId,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        limits: Limits,
    ) -> Result<Self, WireGuardError> {
        let contexts = local_contexts(
            projection,
            expected_management,
            local_node_id,
            node_key,
            tenants,
        )?;
        let mut gateway = Self::new(contexts, limits)?;
        gateway.projection = Some(projection.clone());
        Ok(gateway)
    }

    pub fn projection(&self) -> Option<&GatewayProjection> {
        self.projection.as_ref()
    }

    pub fn receive_datagram(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Option<DatagramEvent>, WireGuardError> {
        validate_endpoint(source)?;
        let admission = self
            .router
            .as_mut()
            .ok_or(WireGuardError::Protocol)?
            .admit(source, bytes)?;
        let slot = admission.slot;
        let packet = match admission.verified {
            Verification::Challenge(packet) => {
                let packet: Packet = packet.into();
                return Ok(Some(DatagramEvent::Network {
                    destination: source,
                    context: self.contexts[slot].id.clone(),
                    peer: admission.peer,
                    packet: PacketBytes(packet.to_vec()),
                }));
            }
            Verification::Packet(packet) => packet,
        };
        let peer_index = self.admitted_peer(slot, admission.peer.as_ref(), &packet)?;
        self.receive_verified(slot, peer_index, packet, Some(source))
            .map(|event| event.map(|event| datagram(event, source)))
    }

    pub fn initiate_at(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        destination: SocketAddr,
    ) -> Result<Option<DatagramEvent>, WireGuardError> {
        validate_endpoint(destination)?;
        let (slot, peer_index) = self.select(context, peer)?;
        self.contexts[slot].peers[peer_index].endpoint = Some(destination);
        self.initiate(context, peer)
            .map(|event| event.map(|event| datagram(event, destination)))
    }

    pub fn send_datagram(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        bytes: &[u8],
    ) -> Result<DatagramEvent, WireGuardError> {
        let destination = self
            .endpoint(context, peer)?
            .ok_or(WireGuardError::NoEndpoint)?;
        self.send(context, peer, bytes)
            .map(|event| datagram(event, destination))
    }

    pub fn tick_datagram(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<DatagramEvent>, WireGuardError> {
        let destination = self
            .endpoint(context, peer)?
            .ok_or(WireGuardError::NoEndpoint)?;
        self.tick(context, peer)
            .map(|event| event.map(|event| datagram(event, destination)))
    }

    pub fn endpoint(
        &self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<SocketAddr>, WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        Ok(self.contexts[slot].peers[peer_index].endpoint)
    }

    pub fn new(configs: Vec<ContextConfig>, limits: Limits) -> Result<Self, WireGuardError> {
        let public_keys = validate_context_configs(&configs, limits)?;
        let indices = IndexTable::from_os_rng();
        let mut contexts: Vec<Context> = Vec::with_capacity(configs.len());
        let mut routes = Vec::with_capacity(configs.len());
        for (config, public_key) in configs.into_iter().zip(public_keys) {
            // Explicit secret-copy boundary required by the engine's owned key API.
            let secret = StaticSecret::from(*config.private_key.expose_bytes());
            let public = PublicKey::from(&secret);
            let rate_limiter = Arc::new(RateLimiter::new(
                &public,
                u64::from(limits.handshake_limit_per_ip),
            ));
            let peers: Vec<_> = config
                .peers
                .into_iter()
                .map(|peer| Peer {
                    id: peer.id,
                    tunnel: Tunn::new(
                        secret.clone(),
                        PublicKey::from(*peer.public_key.as_bytes()),
                        match &config.private_key {
                            crate::PrivateKey::External { psk, .. } => {
                                psk.as_ref().map(|k| *k.expose_bytes())
                            }
                            _ => None,
                        },
                        match &config.private_key {
                            crate::PrivateKey::External { keepalive, .. } => {
                                keepalive.map(|k| k.get())
                            }
                            _ => None,
                        },
                        indices.clone(),
                        rate_limiter.clone(),
                    ),
                    public_key: peer.public_key,
                    endpoint: None,
                    indices: Vec::new(),
                })
                .collect();
            routes.push((
                DispatchContext {
                    context: config.id.clone(),
                    peers: peers.iter().map(|peer| peer.id.clone()).collect(),
                },
                rate_limiter.clone(),
            ));
            contexts.push(Context {
                id: config.id,
                public_key,
                peers,
                secret,
                rate_limiter,
            });
        }
        Ok(Self {
            contexts,
            indices,
            router: Some(Router::new(routes)?),
            projection: None,
            broadcast_jobs: Default::default(),
            broadcast_first: false,
            broadcast_limits: Default::default(),
            plaintext_pool: PacketBufPool::new(1),
        })
    }

    pub fn public_key(&self, context: &ContextId) -> Option<&DevicePublicKey> {
        self.contexts
            .iter()
            .find(|c| &c.id == context)
            .map(|c| &c.public_key)
    }

    /// Replace peers of a standalone service endpoint, preserving sessions for
    /// unchanged identities. Only a trusted coordinator may change this list.
    /// Tenant workers and projection-backed gateways cannot use this operation.
    pub fn set_service_peers(&mut self, configs: Vec<PeerConfig>) -> Result<(), WireGuardError> {
        if self.router.is_none()
            || self.projection.is_some()
            || self.contexts.len() != 1
            || self.contexts[0].id != ContextId::Service
            || configs.len() > MAX_SERVICE_PEERS
        {
            return Err(WireGuardError::InvalidConfiguration);
        }
        let context = &self.contexts[0];
        for (i, peer) in configs.iter().enumerate() {
            if !matches!(peer.id, PeerId::Node(_)) {
                return Err(WireGuardError::InvalidConfiguration);
            }
            if configs[..i]
                .iter()
                .any(|old| old.id == peer.id || old.public_key == peer.public_key)
            {
                return Err(WireGuardError::DuplicatePeer);
            }
            let raw = peer.public_key.as_bytes();
            if raw == context.public_key.as_bytes()
                || !wgfeel_core::canonical_public_key(raw)
                || !context
                    .secret
                    .diffie_hellman(&PublicKey::from(*raw))
                    .was_contributory()
            {
                return Err(WireGuardError::InvalidPeerKey);
            }
        }
        let mut router = Router::new(vec![(
            DispatchContext {
                context: ContextId::Service,
                peers: configs.iter().map(|peer| peer.id.clone()).collect(),
            },
            context.rate_limiter.clone(),
        )])?;
        let bindings = context
            .peers
            .iter()
            .filter(|peer| {
                configs
                    .iter()
                    .any(|config| config.id == peer.id && config.public_key == peer.public_key)
            })
            .flat_map(|peer| {
                peer.indices
                    .iter()
                    .filter(|index| self.indices.in_use(**index))
                    .map(|index| IndexBinding {
                        index: *index,
                        peer: peer.id.clone(),
                    })
            })
            .collect();
        router.publish(0, bindings)?;
        // All fallible validation is complete. Moving retained tunnels keeps
        // counters, session keys and receiver indices, including admin traffic.
        let context = &mut self.contexts[0];
        let peers =
            configs
                .into_iter()
                .map(|config| {
                    if let Some(index) = context.peers.iter().position(|peer| {
                        peer.id == config.id && peer.public_key == config.public_key
                    }) {
                        let mut retained = context.peers.swap_remove(index);
                        retained.indices.retain(|index| self.indices.in_use(*index));
                        retained
                    } else {
                        Peer {
                            id: config.id,
                            tunnel: Tunn::new(
                                context.secret.clone(),
                                PublicKey::from(*config.public_key.as_bytes()),
                                None,
                                None,
                                self.indices.clone(),
                                context.rate_limiter.clone(),
                            ),
                            public_key: config.public_key,
                            endpoint: None,
                            indices: vec![],
                        }
                    }
                })
                .collect();
        context.peers = peers;
        self.router = Some(router);
        Ok(())
    }

    pub fn initiate(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<Event>, WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        let result = self.operate(slot, peer_index, true, |tunnel| {
            Ok(tunnel
                .format_handshake_initiation(false)
                .map_or(TunnResult::Done, |packet| {
                    TunnResult::WriteToNetwork(packet.into())
                }))
        })?;
        event(context, peer, result)
    }

    pub fn receive(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Option<Event>, WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        match self
            .router
            .as_mut()
            .ok_or(WireGuardError::Protocol)?
            .verify(slot, source, bytes)?
        {
            Verification::Packet(packet) => self.receive_verified(slot, peer_index, packet, None),
            Verification::Challenge(packet) => Ok(Some(network(context, peer, packet))),
        }
    }

    /// Send immediately through an existing session. No payload is queued when
    /// no session exists; the caller initiates and retries explicitly.
    pub fn send(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        bytes: &[u8],
    ) -> Result<Event, WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        framing::ip_length(bytes, false)?;
        let _clear = ClearPlaintext(&self.plaintext_pool);
        let mut packet = self.plaintext_pool.get();
        packet.buf_mut().as_mut().zeroize();
        packet.buf_mut().truncate(bytes.len().next_multiple_of(16));
        packet.buf_mut()[..bytes.len()].copy_from_slice(bytes);
        let peer_state = &mut self.contexts[slot].peers[peer_index];
        let packet = peer_state
            .tunnel
            .encapsulate_with_session(packet)
            .map_err(|_| WireGuardError::NoSession)?;
        // GotaTun's encapsulate_with_session updates counters/timers only; it
        // never allocates or retires a receiver index. No global scan per data.
        Ok(network(context, peer, packet.into()))
    }

    /// Drive upstream real-time timers without changing their protocol values.
    pub fn tick(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<Event>, WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        let result = self.operate(slot, peer_index, true, |tunnel| {
            tunnel
                .update_timers()
                .map(|packet| packet.map_or(TunnResult::Done, TunnResult::WriteToNetwork))
                .map_err(|_| WireGuardError::Protocol)
        })?;
        event(context, peer, result)
    }

    pub fn reset(&mut self, context: &ContextId, peer: &PeerId) -> Result<(), WireGuardError> {
        let (slot, peer_index) = self.select(context, peer)?;
        self.operate(slot, peer_index, true, |tunnel| {
            tunnel.reset();
            Ok(TunnResult::Done)
        })?;
        self.contexts[slot].peers[peer_index].endpoint = None;
        Ok(())
    }

    fn select(&self, id: &ContextId, peer: &PeerId) -> Result<(usize, usize), WireGuardError> {
        if self.router.is_none() {
            return Err(WireGuardError::Protocol);
        }
        let slot = self
            .contexts
            .iter()
            .position(|c| &c.id == id)
            .ok_or(WireGuardError::UnknownContext)?;
        let index = self.contexts[slot]
            .peers
            .iter()
            .position(|p| &p.id == peer)
            .ok_or(WireGuardError::UnknownPeer)?;
        Ok((slot, index))
    }

    fn receive_verified(
        &mut self,
        slot: usize,
        peer_index: usize,
        packet: WgKind,
        source: Option<SocketAddr>,
    ) -> Result<Option<Event>, WireGuardError> {
        self.receive_outcome(slot, peer_index, packet, source)?
            .outcome
    }

    /// Only the private child loop can enter here after parent MAC/cookie
    /// admission. This method is deliberately absent from the public API.
    pub(crate) fn receive_admitted(
        &mut self,
        peer: Option<&PeerId>,
        packet: WgKind,
    ) -> Result<WorkerReceive, WireGuardError> {
        if self.contexts.len() != 1 || self.router.is_none() {
            return Err(WireGuardError::Protocol);
        }
        match self.admitted_peer(0, peer, &packet) {
            Ok(peer_index) => self.receive_outcome(0, peer_index, packet, None),
            Err(error) => Ok(WorkerReceive {
                outcome: Err(error),
                authenticated_peer: None,
            }),
        }
    }

    fn admitted_peer(
        &self,
        slot: usize,
        peer: Option<&PeerId>,
        packet: &WgKind,
    ) -> Result<usize, WireGuardError> {
        let context = &self.contexts[slot];
        match (packet, peer) {
            (WgKind::HandshakeInit(init), expected) => {
                // This partial parse only selects a configured peer. Tunn must
                // authenticate it before metadata or plaintext is trusted.
                let half = parse_handshake_anon(
                    &context.secret,
                    &PublicKey::from(*context.public_key.as_bytes()),
                    init,
                )
                .map_err(|_| WireGuardError::Protocol)?;
                context
                    .peers
                    .iter()
                    .position(|candidate| {
                        candidate.public_key.as_bytes() == &half.peer_static_public
                            && expected.is_none_or(|id| id == &candidate.id)
                    })
                    .ok_or(WireGuardError::UnknownPeer)
            }
            (_, Some(peer)) => context
                .peers
                .iter()
                .position(|candidate| &candidate.id == peer)
                .ok_or(WireGuardError::UnknownPeer),
            _ => Err(WireGuardError::Protocol),
        }
    }

    /// Complete live ledger for the sole child context, including retirements.
    /// Allocation and mutation are serialized between request/reply boundaries.
    pub(crate) fn live_indices(&mut self) -> Result<Vec<IndexBinding>, WireGuardError> {
        if self.contexts.len() != 1 || self.router.is_none() {
            return Err(WireGuardError::Protocol);
        }
        if let Err(error) = self.prune_all() {
            self.fail_closed();
            return Err(error);
        }
        Ok(self.contexts[0]
            .peers
            .iter()
            .flat_map(|peer| {
                peer.indices.iter().map(|index| IndexBinding {
                    index: *index,
                    peer: peer.id.clone(),
                })
            })
            .collect())
    }

    fn receive_outcome(
        &mut self,
        slot: usize,
        peer_index: usize,
        packet: WgKind,
        source: Option<SocketAddr>,
    ) -> Result<WorkerReceive, WireGuardError> {
        let handshake = matches!(packet, WgKind::HandshakeInit(_) | WgKind::HandshakeResp(_));
        let transport = matches!(packet, WgKind::Data(_));
        let result = self.operate(slot, peer_index, handshake, |tunnel| {
            Ok(tunnel.handle_incoming_packet(packet))
        })?;
        let context = &mut self.contexts[slot];
        let peer = &mut context.peers[peer_index];
        let authenticated = (handshake && matches!(&result, TunnResult::WriteToNetwork(_)))
            || (transport && matches!(&result, TunnResult::WriteToTunnel(_)));
        if authenticated && let Some(source) = source {
            // Authentication is independent of inner IP validity. In particular
            // empty keepalives and malformed authenticated IP update roaming.
            peer.endpoint = Some(source);
        }
        // Preserve successful authentication even if the inner IP parser
        // rejects the decrypted packet, or an empty keepalive yields no event.
        Ok(WorkerReceive {
            authenticated_peer: authenticated.then(|| peer.id.clone()),
            outcome: event(&context.id, &peer.id, result),
        })
    }

    fn operate(
        &mut self,
        slot: usize,
        peer_index: usize,
        changes_indices: bool,
        operation: impl FnOnce(&mut Tunn) -> Result<TunnResult, WireGuardError>,
    ) -> Result<TunnResult, WireGuardError> {
        if changes_indices && let Err(error) = self.prune_all() {
            self.fail_closed();
            return Err(error);
        }
        let result = operation(&mut self.contexts[slot].peers[peer_index].tunnel);
        if changes_indices {
            let emitted = match &result {
                Ok(TunnResult::WriteToNetwork(WgKind::HandshakeInit(packet))) => {
                    Some(packet.sender_idx.get())
                }
                Ok(TunnResult::WriteToNetwork(WgKind::HandshakeResp(packet))) => {
                    Some(packet.sender_idx.get())
                }
                _ => None,
            };
            // Timers may free indices even when returning an error or None.
            // Synchronize before releasing any network output to the caller.
            if let Err(error) = self.synchronize(slot, peer_index, emitted) {
                self.fail_closed();
                return Err(error);
            }
        }
        result
    }

    fn prune_all(&mut self) -> Result<(), WireGuardError> {
        // Only this serialized coordinator can invoke an allocating operation.
        // Remove every dead owner's route BEFORE the allocator can reuse it.
        for slot in 0..self.contexts.len() {
            if self.prune(slot) {
                self.publish(slot)?;
            }
        }
        Ok(())
    }

    fn prune(&mut self, slot: usize) -> bool {
        let mut changed = false;
        for peer in &mut self.contexts[slot].peers {
            let old_len = peer.indices.len();
            peer.indices.retain(|index| self.indices.in_use(*index));
            changed |= peer.indices.len() != old_len;
        }
        changed
    }

    fn synchronize(
        &mut self,
        slot: usize,
        peer_index: usize,
        emitted: Option<u32>,
    ) -> Result<(), WireGuardError> {
        self.prune(slot);
        if let Some(index) = emitted {
            if !self.indices.in_use(index) {
                return Err(WireGuardError::Protocol);
            }
            let peer = &mut self.contexts[slot].peers[peer_index];
            if !peer.indices.contains(&index) {
                if peer.indices.len() == MAX_INDICES_PER_PEER {
                    return Err(WireGuardError::Protocol);
                }
                peer.indices.push(index);
            }
        }
        self.publish(slot)
    }

    fn publish(&mut self, slot: usize) -> Result<(), WireGuardError> {
        let bindings = self.contexts[slot]
            .peers
            .iter()
            .flat_map(|peer| {
                peer.indices.iter().map(|index| IndexBinding {
                    index: *index,
                    peer: peer.id.clone(),
                })
            })
            .collect();
        self.router
            .as_mut()
            .ok_or(WireGuardError::Protocol)?
            .publish(slot, bindings)
    }

    fn fail_closed(&mut self) {
        // Publication failure is an internal invariant breach, not an ordinary
        // bad datagram. Drop all leases, keys and sessions before accepting any
        // further work; reconstructing from trusted config is required.
        self.router = None;
        self.broadcast_jobs.clear();
        self.contexts.clear();
    }
}

/// Bind local keys to an already authenticated Management projection. Engine
/// limits and peer-key validity are checked by new/spawn before any engine or
/// child is created; this helper does not construct either.
pub(crate) fn local_contexts<'a>(
    projection: &GatewayProjection,
    expected_management: &NodeId,
    local_node_id: &NodeId,
    node_key: &NodeKeys,
    tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
) -> Result<Vec<ContextConfig>, WireGuardError> {
    projection
        .validate_target(expected_management, local_node_id)
        .map_err(|_| WireGuardError::InvalidConfiguration)?;
    let assignment = projection.assignment();
    if PublicKey::from(&StaticSecret::from(*node_key.service().expose_bytes())).as_bytes()
        != assignment.service_public_key().as_bytes()
    {
        return Err(WireGuardError::InvalidConfiguration);
    }
    if PublicKey::from(&StaticSecret::from(*node_key.gateway().expose_bytes())).as_bytes()
        != assignment.gateway_public_key().as_bytes()
    {
        return Err(WireGuardError::InvalidConfiguration);
    }
    let expected = assignment.tenants();
    // Collect only references and reject the first surplus item. Never trust
    // an arbitrary iterator's size_hint or collect an unbounded key stream.
    let mut local: Vec<(&NetworkId, &TenantPrivateKey)> = Vec::with_capacity(expected.len());
    for (network, key) in tenants {
        if local.len() == expected.len() || local.iter().any(|(previous, _)| *previous == network) {
            return Err(WireGuardError::InvalidConfiguration);
        }
        let expected_key = expected
            .iter()
            .find(|candidate| candidate.network() == network)
            .ok_or(WireGuardError::InvalidConfiguration)?;
        if PublicKey::from(&StaticSecret::from(*key.expose_bytes())).as_bytes()
            != expected_key.public_key().as_bytes()
        {
            return Err(WireGuardError::InvalidConfiguration);
        }
        local.push((network, key));
    }
    if local.len() != expected.len() {
        return Err(WireGuardError::InvalidConfiguration);
    }
    // The full capacity is allocated before copying any owned secrets.
    let mut contexts = Vec::with_capacity(local.len() + 2);
    for (network, key) in local {
        let configured = projection
            .config()
            .networks()
            .iter()
            .find(|candidate| candidate.id() == network)
            .ok_or(WireGuardError::InvalidConfiguration)?;
        let mut peers: Vec<_> = configured
            .devices()
            .iter()
            .filter(|device| device.gateway().is_none_or(|home| home == local_node_id))
            .map(|device| PeerConfig {
                id: PeerId::Device(device.id().clone()),
                public_key: device.public_key().clone(),
            })
            .collect();
        peers.extend(
            projection
                .mesh()
                .iter()
                .filter(|node| node.recipient() != local_node_id)
                .filter_map(|node| {
                    node.tenants()
                        .iter()
                        .find(|tenant| tenant.network() == network)
                        .map(|tenant| PeerConfig {
                            id: PeerId::Gateway(node.recipient().clone()),
                            public_key: tenant.public_key().clone(),
                        })
                }),
        );
        contexts.push(ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(*key.expose_bytes())
                .map_err(|_| WireGuardError::InvalidConfiguration)?,
            peers,
        ));
    }
    contexts.push(ContextConfig::gateway(
        GatewayPrivateKey::new(*node_key.gateway().expose_bytes())
            .map_err(|_| WireGuardError::InvalidConfiguration)?,
        projection
            .mesh()
            .iter()
            .filter(|node| node.recipient() != local_node_id && !projection.is_revoked())
            .map(|node| PeerConfig {
                id: PeerId::Node(node.recipient().clone()),
                public_key: node.gateway_public_key().clone(),
            })
            .collect(),
    ));
    // No mesh membership is inferred from a network scope or Management ID.
    contexts.push(ContextConfig::service(
        ServicePrivateKey::new(*node_key.service().expose_bytes())
            .map_err(|_| WireGuardError::InvalidConfiguration)?,
        vec![],
    ));
    Ok(contexts)
}

/// Validate all public metadata and key roles before constructing any tunnel or
/// spawning any child. The returned keys are public admission configuration.
pub(crate) fn validate_context_configs(
    configs: &[ContextConfig],
    limits: Limits,
) -> Result<Vec<DevicePublicKey>, WireGuardError> {
    let tenant_count = configs
        .iter()
        .filter(|c| matches!(c.id, ContextId::Tenant(_)))
        .count();
    if limits.handshake_limit_per_ip > 1000
        || tenant_count > MAX_TENANTS
        || configs
            .iter()
            .filter(|c| matches!(c.id, ContextId::External(_)))
            .count()
            > wgfeel_core::MAX_EGRESSES_PER_NODE
        || configs.len() > MAX_TENANTS + 2 + wgfeel_core::MAX_EGRESSES_PER_NODE
    {
        return Err(WireGuardError::InvalidConfiguration);
    }
    let mut device_peers = 0usize;
    let mut service_peers = 0usize;
    let mut gateway_peers = 0usize;
    let mut mesh_peers = 0usize;
    for (i, config) in configs.iter().enumerate() {
        if configs[..i].iter().any(|other| other.id == config.id) {
            return Err(WireGuardError::DuplicateContext);
        }
        if matches!(config.id, ContextId::External(_)) && config.peers.len() != 1 {
            return Err(WireGuardError::InvalidConfiguration);
        }
        let mesh = config
            .peers
            .iter()
            .filter(|peer| matches!(peer.id, PeerId::Gateway(_)))
            .count();
        mesh_peers += mesh;
        device_peers += config
            .peers
            .iter()
            .filter(|peer| matches!(peer.id, PeerId::Device(_)))
            .count();
        let nodes = config
            .peers
            .iter()
            .filter(|peer| matches!(peer.id, PeerId::Node(_)))
            .count();
        if config.id == ContextId::Gateway {
            gateway_peers += nodes;
        } else {
            service_peers += nodes;
        }
        if gateway_peers > wgfeel_core::MAX_GATEWAYS
            || mesh > wgfeel_core::MAX_GATEWAYS
            || mesh_peers > crate::MAX_MESH_PEERS
            || device_peers > MAX_DEVICE_PEERS
            || service_peers > MAX_SERVICE_PEERS
        {
            return Err(WireGuardError::InvalidConfiguration);
        }
    }
    let mut public_keys: Vec<DevicePublicKey> = Vec::with_capacity(configs.len());
    for config in configs {
        let secret = StaticSecret::from(*config.private_key.expose_bytes());
        let public = PublicKey::from(&secret);
        if public_keys
            .iter()
            .any(|key| key.as_bytes() == public.as_bytes())
        {
            return Err(WireGuardError::DuplicateGatewayKey);
        }
        for (i, peer) in config.peers.iter().enumerate() {
            if !matches!(
                (&config.id, &peer.id),
                (ContextId::Tenant(_), PeerId::Device(_) | PeerId::Gateway(_))
                    | (ContextId::Service | ContextId::Gateway, PeerId::Node(_))
                    | (ContextId::External(_), PeerId::Provider)
            ) {
                return Err(WireGuardError::InvalidConfiguration);
            }
            if config.peers[..i]
                .iter()
                .any(|p| p.id == peer.id || p.public_key == peer.public_key)
            {
                return Err(WireGuardError::DuplicatePeer);
            }
            let raw = peer.public_key.as_bytes();
            if raw == public.as_bytes()
                || !wgfeel_core::canonical_public_key(raw)
                || !secret
                    .diffie_hellman(&PublicKey::from(*raw))
                    .was_contributory()
            {
                return Err(WireGuardError::InvalidPeerKey);
            }
        }
        public_keys.push(
            DevicePublicKey::new(*public.as_bytes())
                .map_err(|_| WireGuardError::InvalidConfiguration)?,
        );
    }
    Ok(public_keys)
}

pub(crate) fn validate_endpoint(address: SocketAddr) -> Result<(), WireGuardError> {
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    if address.port() == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(WireGuardError::InvalidConfiguration);
    }
    Ok(())
}

fn datagram(event: Event, destination: SocketAddr) -> DatagramEvent {
    match event {
        Event::Network {
            context,
            peer,
            packet,
        } => DatagramEvent::Network {
            destination,
            context,
            peer: Some(peer),
            packet,
        },
        Event::Plaintext {
            context,
            peer,
            packet,
        } => DatagramEvent::Plaintext {
            context,
            peer,
            packet,
        },
    }
}

fn network(context: &ContextId, peer: &PeerId, packet: WgKind) -> Event {
    let packet: Packet = packet.into();
    Event::Network {
        context: context.clone(),
        peer: peer.clone(),
        packet: PacketBytes(packet.to_vec()),
    }
}
fn event(
    context: &ContextId,
    peer: &PeerId,
    result: TunnResult,
) -> Result<Option<Event>, WireGuardError> {
    match result {
        TunnResult::Done => Ok(None),
        TunnResult::Err(_) => Err(WireGuardError::Protocol),
        TunnResult::WriteToNetwork(packet) => Ok(Some(network(context, peer, packet))),
        TunnResult::WriteToTunnel(packet) if packet.is_empty() => Ok(None),
        TunnResult::WriteToTunnel(mut packet) => {
            let bytes =
                framing::ip_length_for(&packet, true, matches!(context, ContextId::External(_)))
                    .map(|length| PacketBytes(packet[..length].to_vec()));
            packet.buf_mut().as_mut().zeroize();
            Ok(Some(Event::Plaintext {
                context: context.clone(),
                peer: peer.clone(),
                packet: bytes?,
            }))
        }
    }
}
