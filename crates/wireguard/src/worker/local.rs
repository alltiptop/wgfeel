use super::{
    RequestId, Submission, WorkerError, WorkerEvent, WorkerGateway, WorkerInfo, WorkerOptions,
};
use crate::{
    ContextId, DatagramEvent, ForwardError, Limits, PacketBytes, PeerId, PrivateKey,
    WireGuardError,
    forwarding::{authorize_dns, authorize_routed},
    gateway::local_contexts,
    mesh::{Direction, ExternalTraffic, MeshTraffic},
    nat::{NatAction, NatBinding, NatTable},
};
use std::{
    fmt,
    net::SocketAddr,
    os::fd::BorrowedFd,
    time::{Duration, Instant},
};
use wgfeel_core::{
    Destination, DevicePublicKey, EgressId, EgressPrivateKey, EgressProfile, Endpoint,
    GatewayProjection, NetworkId, NodeId, NodeKeys, PresharedKey, TenantPrivateKey,
};

pub fn same_provider_session(a: &EgressProfile, b: &EgressProfile) -> bool {
    a.id == b.id
        && a.node == b.node
        && a.secret_revision == b.secret_revision
        && a.interface_public_key == b.interface_public_key
        && a.peer_public_key == b.peer_public_key
        && a.has_preshared_key == b.has_preshared_key
        && a.endpoint == b.endpoint
        && a.persistent_keepalive == b.persistent_keepalive
        && a.addresses == b.addresses
        && a.allowed_ips == b.allowed_ips
        && a.mtu == b.mtu
}
type ProviderKeys<'a> = (&'a EgressId, &'a EgressPrivateKey, Option<&'a PresharedKey>);

// Compare opaque key material across retries without retaining a second secret.
struct KeyFingerprint(aws_lc_rs::digest::Digest);
impl KeyFingerprint {
    fn new(private: &EgressPrivateKey, psk: Option<&PresharedKey>) -> Self {
        let mut input = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        input.update(private.expose_bytes());
        if let Some(key) = psk {
            input.update(key.expose_bytes())
        }
        Self(input.finish())
    }
}
impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

const PMTU_LEASE: Duration = Duration::from_secs(600);

#[derive(Debug, Default)]
struct PathMtu(std::collections::BTreeMap<EgressId, (u16, Instant)>);
impl PathMtu {
    fn record(&mut self, id: &EgressId, mtu: u16, now: Instant) {
        self.0.insert(id.clone(), (mtu, now + PMTU_LEASE));
    }
    fn get(&self, id: &EgressId, now: Instant) -> u16 {
        self.0
            .get(id)
            .filter(|(_, expires)| *expires > now)
            .map_or(crate::MAX_PLAINTEXT_SIZE as u16, |(mtu, _)| *mtu)
    }
    fn clear(&mut self, id: &EgressId) {
        self.0.remove(id);
    }
}

/// Encrypted output for the caller's existing UDP socket. Debug omits bytes.
#[derive(Debug)]
pub struct EncryptedDatagram {
    pub destination: SocketAddr,
    pub context: ContextId,
    pub peer: Option<PeerId>,
    pub packet: PacketBytes,
}
impl From<EncryptedDatagram> for DatagramEvent {
    fn from(value: EncryptedDatagram) -> Self {
        Self::Network {
            destination: value.destination,
            context: value.context,
            peer: value.peer,
            packet: value.packet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalError {
    Worker(WorkerError),
    Forward(ForwardError),
    Cancelled,
}
impl fmt::Display for LocalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local worker forwarding rejected: {self:?}")
    }
}
impl std::error::Error for LocalError {}

#[derive(Debug)]
pub enum LocalEvent {
    Dns {
        source: DnsSource,
        packet: PacketBytes,
    },
    Mesh {
        peer: NodeId,
        packet: PacketBytes,
    },
    MeshOutput {
        network: NetworkId,
        peer: NodeId,
        packet: PacketBytes,
        traffic: Option<MeshTraffic>,
    },
    /// Authenticated system traffic from the pinned Management peer only.
    Management {
        packet: PacketBytes,
    },
    /// A locally authorized candidate Manager has no configuration authority.
    Enrollment {
        packet: PacketBytes,
    },
    EnrollmentConfigured {
        result: Result<(), LocalError>,
    },
    /// Authenticated main-only API peer registered by the local authority.
    Control {
        peer: NodeId,
        packet: PacketBytes,
    },
    ControlConfigured {
        result: Result<(), LocalError>,
    },
    Ready {
        context: ContextId,
        generation: u64,
    },
    Network(EncryptedDatagram),
    ProviderOutput(EncryptedDatagram),
    /// Forwarding rejections identify the original authenticated source,
    /// including when the destination cannot encrypt or the source was retired.
    Dropped {
        context: ContextId,
        peer: Option<PeerId>,
        reason: LocalError,
    },
    Failed {
        context: ContextId,
        generation: u64,
        reason: WorkerError,
    },
}

#[derive(Debug, Clone)]
struct Origin {
    context: ContextId,
    generation: u64,
    peer: PeerId,
}
/// Opaque proof of authenticated DNS ingress. Replies are fenced by both the
/// policy revision and worker incarnation, and checked against device IPs.
#[derive(Debug, Clone)]
pub struct DnsSource {
    origin: Origin,
    revision: u64,
}
impl DnsSource {
    pub fn incarnation(&self) -> u64 {
        self.origin.generation
    }
    pub fn network(&self) -> &NetworkId {
        match &self.origin.context {
            ContextId::Tenant(id) => id,
            ContextId::External(_) | ContextId::Service | ContextId::Gateway => {
                unreachable!("tenant DNS only")
            }
        }
    }
}
#[derive(Debug)]
enum Stage {
    Receive,
    ProviderReceive,
    ReceiveMesh {
        network: NetworkId,
        origin: NodeId,
        traffic: Option<MeshTraffic>,
    },
    Control(PeerId),
    Timer(PeerId),
    Forward(Origin, Option<MeshTraffic>),
    Cancelled(ContextId, Option<PeerId>),
    ConfigureEnrollment(Option<NodeId>),
    ConfigureControl(Vec<crate::PeerConfig>),
}
#[derive(Debug)]
struct Flight {
    request: RequestId,
    stage: Stage,
}

impl Stage {
    /// Cancel stages carrying old-revision forwarding/relay decisions while
    /// preserving raw crypto receives, timers and non-relay control operations.
    fn across_revision(self, context: &ContextId) -> Self {
        match self {
            Self::ProviderReceive => Self::Cancelled(context.clone(), Some(PeerId::Provider)),
            Self::Control(peer) | Self::Timer(peer)
                if matches!(context, ContextId::External(_)) =>
            {
                Self::Cancelled(context.clone(), Some(peer))
            }
            Self::Receive | Self::Timer(_) => self,
            Self::Control(peer) if *context != ContextId::Gateway => Self::Control(peer),
            Self::Control(peer) => Self::Cancelled(context.clone(), Some(peer)),
            Self::Cancelled(origin, peer) => Self::Cancelled(origin, peer),
            Self::Forward(origin, _) => Self::Cancelled(origin.context, Some(origin.peer)),
            Self::ReceiveMesh {
                network, origin, ..
            } => Self::Cancelled(ContextId::Tenant(network), Some(PeerId::Gateway(origin))),
            Self::ConfigureEnrollment(_) | Self::ConfigureControl(_) => {
                Self::Cancelled(context.clone(), None)
            }
        }
    }
}

/// Projection-bound local forwarding with crypto in confined processes.
/// User traffic enters and leaves encrypted. Only pinned Management traffic
/// reaches the separate control handler. Forwarding does not depend on it.
#[derive(Debug)]
pub struct LocalGateway {
    projection: GatewayProjection,
    raw: WorkerGateway,
    nat: NatTable,
    provider_keys: std::collections::BTreeMap<EgressId, KeyFingerprint>,
    path_mtu: PathMtu,
    // Exactly one record per pending raw request, at most one per worker.
    // Forwarding stores only provenance here, never pending plaintext.
    flights: Vec<Flight>,
    management: Option<NodeId>,
    management_key: Option<DevicePublicKey>,
    enrollment: Option<NodeId>,
    control_peers: Vec<crate::PeerConfig>,
}

pub struct GatewayHandoff<'a> {
    next: &'a mut LocalGateway,
    previous: &'a mut LocalGateway,
}

impl GatewayHandoff<'_> {
    pub fn projection(&self) -> &GatewayProjection {
        self.next.projection()
    }
    pub fn activate(self) -> Result<(), LocalError> {
        let inherited = self
            .next
            .raw
            .take_workers(&mut self.previous.raw)
            .map_err(LocalError::Worker)?;
        if inherited
            .iter()
            .any(|(context, _)| *context == ContextId::Service)
        {
            self.next.control_peers = std::mem::take(&mut self.previous.control_peers);
        }
        for mut flight in self.previous.flights.drain(..) {
            let Some((_, generation)) = inherited
                .iter()
                .find(|(context, _)| *context == flight.request.context)
            else {
                continue;
            };
            flight.request.generation = *generation;
            flight.stage = flight.stage.across_revision(&flight.request.context);
            self.next.flights.push(flight);
        }
        self.next.nat = std::mem::take(&mut self.previous.nat);
        self.next.path_mtu = std::mem::take(&mut self.previous.path_mtu);
        for previous in self.previous.projection.owned_egresses() {
            if !inherited
                .iter()
                .any(|(context, _)| matches!(context, ContextId::External(id) if id==&previous.id))
            {
                self.next.nat.discard_egress(&previous.id);
                self.next.path_mtu.clear(&previous.id);
            }
        }
        retain_nat(
            &mut self.next.nat,
            &self.previous.projection,
            &self.next.projection,
        );
        std::mem::swap(self.next, self.previous);
        Ok(())
    }
}

fn managed_service_peers(
    projection: &GatewayProjection,
    management_key: &DevicePublicKey,
) -> Result<Vec<crate::PeerConfig>, LocalError> {
    let main = projection.management_id();
    let local_is_main = projection.recipient() == main;
    if (local_is_main && projection.assignment().service_public_key() != management_key)
        || projection
            .mesh()
            .iter()
            .any(|node| node.recipient() == main && node.service_public_key() != management_key)
    {
        return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
    }
    let mut peers = Vec::new();
    if !local_is_main {
        peers.push(crate::PeerConfig {
            id: PeerId::Node(main.clone()),
            public_key: management_key.clone(),
        });
    }
    if local_is_main && !projection.is_revoked() {
        peers.extend(
            projection
                .mesh()
                .iter()
                .filter(|node| {
                    node.recipient() != projection.recipient() && node.recipient() != main
                })
                .map(|node| crate::PeerConfig {
                    id: PeerId::Node(node.recipient().clone()),
                    public_key: node.service_public_key().clone(),
                }),
        );
    }
    Ok(peers)
}

// Called only for plaintext returned by the authenticated service worker.
// Packet framing selects a handler; it never establishes configuration authority.
fn service_event(
    projection: &GatewayProjection,
    management: Option<&NodeId>,
    enrollment: Option<&NodeId>,
    controls: &[crate::PeerConfig],
    peer: PeerId,
    packet: PacketBytes,
) -> LocalEvent {
    // The context is the authority boundary. A mesh envelope on a service
    // session never becomes user transit, even when the peer is main.
    if crate::mesh::is_packet(packet.as_bytes()) {
        return dropped(
            ContextId::Service,
            Some(peer),
            LocalError::Forward(ForwardError::Denied),
        );
    }
    if management.is_some_and(|id| peer == PeerId::Node(id.clone())) {
        return LocalEvent::Management { packet };
    }
    if enrollment.is_some_and(|id| peer == PeerId::Node(id.clone())) {
        return LocalEvent::Enrollment { packet };
    }
    if projection.control_mode() == wgfeel_core::ControlMode::Main
        && let PeerId::Node(id) = &peer
        && (controls.iter().any(|control| control.id == peer)
            || (!projection.is_revoked()
                && projection.mesh().iter().any(|node| node.recipient() == id)))
    {
        return LocalEvent::Control {
            peer: id.clone(),
            packet,
        };
    }
    dropped(
        ContextId::Service,
        Some(peer),
        LocalError::Forward(ForwardError::Denied),
    )
}

fn gateway_event(projection: &GatewayProjection, peer: PeerId, packet: PacketBytes) -> LocalEvent {
    if let PeerId::Node(id) = &peer
        && !projection.is_revoked()
        && projection.mesh().iter().any(|node| node.recipient() == id)
        && crate::mesh::is_packet(packet.as_bytes())
    {
        return LocalEvent::Mesh {
            peer: id.clone(),
            packet,
        };
    }
    dropped(
        ContextId::Gateway,
        Some(peer),
        LocalError::Forward(ForwardError::Denied),
    )
}

impl LocalGateway {
    /// The caller must authenticate Management delivery before assembly and
    /// dispatch worker_main in the current executable before initialization.
    /// Pins, exact key assignment and engine limits are checked before spawn.
    /// The calling thread must outlive all spawned workers, including workers
    /// it restarts. Linux kills a worker when its spawning thread exits, even
    /// if other threads in the parent process remain alive.
    pub fn spawn<'a>(
        projection: &GatewayProjection,
        expected_management: &NodeId,
        local_node: &NodeId,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        limits: Limits,
        options: WorkerOptions,
    ) -> Result<Self, LocalError> {
        if !projection.owned_egresses().is_empty() {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        let contexts = local_contexts(
            projection,
            expected_management,
            local_node,
            node_key,
            tenants,
        )
        .map_err(|error| LocalError::Worker(WorkerError::WireGuard(error)))?;
        let flights = Vec::with_capacity(contexts.len());
        let raw = WorkerGateway::spawn(contexts, limits, options).map_err(LocalError::Worker)?;
        Ok(Self {
            projection: projection.clone(),
            raw,
            nat: NatTable::default(),
            provider_keys: Default::default(),
            path_mtu: Default::default(),
            flights,
            management: None,
            management_key: None,
            enrollment: None,
            control_peers: Vec::new(),
        })
    }
    pub fn spawn_managed<'a>(
        projection: &GatewayProjection,
        management_key: &DevicePublicKey,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        limits: Limits,
        options: WorkerOptions,
    ) -> Result<Self, LocalError> {
        Self::spawn_with_egresses(
            projection,
            management_key,
            node_key,
            tenants,
            std::iter::empty(),
            limits,
            options,
        )
    }
    pub fn spawn_with_egresses<'a>(
        projection: &GatewayProjection,
        management_key: &DevicePublicKey,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        providers: impl IntoIterator<Item = ProviderKeys<'a>>,
        limits: Limits,
        options: WorkerOptions,
    ) -> Result<Self, LocalError> {
        Self::managed(
            projection,
            management_key,
            node_key,
            tenants,
            providers,
            |contexts| WorkerGateway::spawn(contexts, limits, options),
        )
    }

    /// Validate all assigned keys before preparing only the changed crypto contexts.
    pub fn prepare_replacement<'a>(
        &self,
        projection: &GatewayProjection,
        management_key: &DevicePublicKey,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
    ) -> Result<Self, LocalError> {
        self.replace_with_egresses(
            projection,
            management_key,
            node_key,
            tenants,
            std::iter::empty(),
        )
    }
    pub fn replace_with_egresses<'a>(
        &self,
        projection: &GatewayProjection,
        management_key: &DevicePublicKey,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        providers: impl IntoIterator<Item = ProviderKeys<'a>>,
    ) -> Result<Self, LocalError> {
        let mut material = Vec::new();
        for (id, key, psk) in providers {
            if material.len() >= wgfeel_core::MAX_EGRESSES_PER_NODE {
                return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
            }
            if self
                .projection
                .owned_egresses()
                .iter()
                .find(|p| &p.id == id)
                .zip(projection.owned_egresses().iter().find(|p| &p.id == id))
                .is_some_and(|(old, new)| {
                    self.management_key.as_ref() == Some(management_key)
                        && self.projection.management_id() == projection.management_id()
                        && (new.secret_revision < old.secret_revision
                            || (old.secret_revision == new.secret_revision
                                && !self.material_matches(id, key, psk)))
                })
            {
                return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
            }
            material.push((id, key, psk));
        }
        let retain = self.management_key.as_ref() == Some(management_key)
            && self.projection.management_id() == projection.management_id()
            && self.projection.recipient() == projection.recipient()
            && self.projection.control_mode() == projection.control_mode()
            && projection.generation() > self.projection.generation()
            && !self.projection.is_revoked()
            && !projection.is_revoked()
            && self.enrollment.is_none()
            && !self
                .flights
                .iter()
                .any(|flight| matches!(flight.stage, Stage::ConfigureEnrollment(_)));
        let retain_main_service = projection.control_mode() == wgfeel_core::ControlMode::Main
            && self.projection.mesh().iter().all(|old| {
                projection.mesh().iter().any(|new| {
                    old.recipient() == new.recipient()
                        && old.service_public_key() == new.service_public_key()
                })
            });
        let reusable: Vec<_> = projection
            .owned_egresses()
            .iter()
            .filter(|new| {
                self.projection
                    .owned_egresses()
                    .iter()
                    .any(|old| same_provider_session(old, new))
            })
            .map(|profile| profile.id.clone())
            .collect();
        Self::managed(
            projection,
            management_key,
            node_key,
            tenants,
            material,
            |contexts| {
                self.raw
                    .replacement(contexts, retain, retain_main_service, &reusable)
            },
        )
    }

    fn managed<'a>(
        projection: &GatewayProjection,
        management_key: &DevicePublicKey,
        node_key: &NodeKeys,
        tenants: impl IntoIterator<Item = (&'a NetworkId, &'a TenantPrivateKey)>,
        providers: impl IntoIterator<Item = ProviderKeys<'a>>,
        build: impl FnOnce(Vec<crate::ContextConfig>) -> Result<WorkerGateway, WorkerError>,
    ) -> Result<Self, LocalError> {
        let mut contexts = local_contexts(
            projection,
            projection.management_id(),
            projection.recipient(),
            node_key,
            tenants,
        )
        .map_err(|error| LocalError::Worker(WorkerError::WireGuard(error)))?;
        let expected = projection.owned_egresses();
        let mut provider_keys = std::collections::BTreeMap::new();
        for (id, private, psk) in providers {
            let invalid = LocalError::Worker(WorkerError::InvalidConfiguration);
            let profile = expected.iter().find(|p| &p.id == id).ok_or(invalid)?;
            if provider_keys.contains_key(id)
                || profile.node.as_ref() != Some(projection.recipient())
                || profile.has_preshared_key != psk.is_some()
                || gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from(
                    *private.expose_bytes(),
                ))
                .as_bytes()
                    != profile.interface_public_key.as_bytes()
            {
                return Err(invalid);
            }
            provider_keys.insert(id.clone(), KeyFingerprint::new(private, psk));
            contexts.push(crate::ContextConfig::external(
                id.clone(),
                EgressPrivateKey::new(*private.expose_bytes()).map_err(|_| invalid)?,
                psk.map(|p| PresharedKey::new(*p.expose_bytes()))
                    .transpose()
                    .map_err(|_| invalid)?,
                profile.persistent_keepalive,
                profile.peer_public_key.clone(),
            ));
        }
        if expected.len() != provider_keys.len() {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        let service = contexts
            .iter_mut()
            .find(|context| context.id == ContextId::Service)
            .ok_or(LocalError::Worker(WorkerError::InvalidConfiguration))?;
        service.peers = managed_service_peers(projection, management_key)?;
        let flights = Vec::with_capacity(contexts.len());
        let raw = build(contexts).map_err(LocalError::Worker)?;
        Ok(Self {
            projection: projection.clone(),
            raw,
            nat: NatTable::default(),
            provider_keys,
            path_mtu: Default::default(),
            flights,
            management_key: Some(management_key.clone()),
            management: (projection.recipient() != projection.management_id())
                .then(|| projection.management_id().clone()),
            enrollment: None,
            control_peers: Vec::new(),
        })
    }

    pub fn starting_workers(&self) -> usize {
        self.raw.startup_count()
    }

    /// The exclusive borrows fence changes between validation, durable publication and activation.
    pub fn handoff<'a>(
        &'a mut self,
        previous: &'a mut Self,
    ) -> Result<GatewayHandoff<'a>, LocalError> {
        if previous.flights.iter().any(|flight| {
            matches!(
                flight.stage,
                Stage::ConfigureEnrollment(_) | Stage::ConfigureControl(_)
            )
        }) {
            return Err(LocalError::Worker(WorkerError::Busy));
        }
        self.raw
            .prepare_handoff(&previous.raw)
            .map_err(LocalError::Worker)?;
        Ok(GatewayHandoff {
            next: self,
            previous,
        })
    }

    /// Only the local main runtime may register external control identities.
    /// Mesh configuration cannot grant this capability to a child.
    pub fn set_control_peers(
        &mut self,
        controls: Vec<crate::PeerConfig>,
    ) -> Result<(), LocalError> {
        if self.projection.control_mode() != wgfeel_core::ControlMode::Main {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        if self.flights.iter().any(|flight| {
            matches!(
                flight.stage,
                Stage::ConfigureControl(_) | Stage::ConfigureEnrollment(_)
            )
        }) {
            return Err(LocalError::Worker(WorkerError::Busy));
        }
        if controls.iter().any(|peer| {
            !matches!(&peer.id, PeerId::Node(id) if id != self.projection.recipient()
                && !self.projection.mesh().iter().any(|node| node.recipient() == id))
        }) {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        let mut peers = managed_service_peers(
            &self.projection,
            self.projection.assignment().service_public_key(),
        )?;
        peers.extend(controls.iter().cloned());
        let request = self
            .raw
            .set_service_peers(peers)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::ConfigureControl(controls),
        });
        Ok(())
    }

    pub fn send_control(&mut self, peer: &NodeId, packet: &[u8]) -> Result<(), LocalError> {
        let id = PeerId::Node(peer.clone());
        if self.projection.control_mode() != wgfeel_core::ControlMode::Main
            || (!self.control_peers.iter().any(|control| control.id == id)
                && !self
                    .projection
                    .mesh()
                    .iter()
                    .any(|node| node.recipient() == peer && peer != self.projection.recipient()))
        {
            return Err(LocalError::Worker(WorkerError::UnknownPeer));
        }
        let request = self
            .raw
            .send_datagram(&ContextId::Service, &id, packet)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(id),
        });
        Ok(())
    }
    pub fn enrollment_peer(&self) -> Option<&NodeId> {
        self.enrollment.as_ref()
    }
    /// Owner-authorized local preparation only. No remote policy projection can
    /// add this capability, and its plaintext never enters tenant forwarding.
    pub fn prepare_enrollment(
        &mut self,
        id: NodeId,
        public_key: DevicePublicKey,
    ) -> Result<(), LocalError> {
        if self.enrollment.is_some()
            || self
                .flights
                .iter()
                .any(|flight| matches!(flight.stage, Stage::ConfigureEnrollment(_)))
        {
            return Err(LocalError::Worker(WorkerError::Busy));
        }
        let mut peers = self.raw.service_peers().map_err(LocalError::Worker)?;
        if let Some(existing) = peers.iter().find(|peer| peer.public_key == public_key) {
            if self
                .management
                .as_ref()
                .is_some_and(|management| existing.id == PeerId::Node(management.clone()))
            {
                self.enrollment = self.management.clone();
                return Ok(());
            }
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        if peers.iter().any(|peer| peer.id == PeerId::Node(id.clone()))
            || &id == self.projection.recipient()
        {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        peers.push(crate::PeerConfig {
            id: PeerId::Node(id.clone()),
            public_key,
        });
        let request = self
            .raw
            .set_service_peers(peers)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::ConfigureEnrollment(Some(id)),
        });
        Ok(())
    }
    pub fn clear_enrollment(&mut self) -> Result<(), LocalError> {
        if self
            .flights
            .iter()
            .any(|flight| matches!(flight.stage, Stage::ConfigureEnrollment(_)))
        {
            return Err(LocalError::Worker(WorkerError::Busy));
        }
        let Some(id) = &self.enrollment else {
            return Ok(());
        };
        if self.management.as_ref() == Some(id) {
            self.enrollment = None;
            return Ok(());
        }
        let peers = self
            .raw
            .service_peers()
            .map_err(LocalError::Worker)?
            .into_iter()
            .filter(|peer| peer.id != PeerId::Node(id.clone()))
            .collect();
        let request = self
            .raw
            .set_service_peers(peers)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::ConfigureEnrollment(None),
        });
        Ok(())
    }
    pub fn send_enrollment(&mut self, packet: &[u8]) -> Result<(), LocalError> {
        let peer = PeerId::Node(
            self.enrollment
                .clone()
                .ok_or(LocalError::Worker(WorkerError::NotReady))?,
        );
        let request = self
            .raw
            .send_datagram(&ContextId::Service, &peer, packet)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(peer),
        });
        Ok(())
    }
    pub fn send_management(&mut self, packet: &[u8]) -> Result<(), LocalError> {
        let peer = PeerId::Node(
            self.management
                .clone()
                .ok_or(LocalError::Worker(WorkerError::InvalidConfiguration))?,
        );
        let request = self
            .raw
            .send_datagram(&ContextId::Service, &peer, packet)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(peer),
        });
        Ok(())
    }
    pub fn send_dns(&mut self, source: &DnsSource, packet: &[u8]) -> Result<(), LocalError> {
        if source.revision != self.projection.generation()
            || !self
                .raw
                .generation_is_active(&source.origin.context, source.origin.generation)
            || !authorize_dns(
                &self.projection,
                &source.origin.context,
                &source.origin.peer,
                packet,
                true,
            )
            .map_err(LocalError::Forward)?
        {
            return Err(LocalError::Cancelled);
        }
        let request = self
            .raw
            .send_datagram(&source.origin.context, &source.origin.peer, packet)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Forward(source.origin.clone(), None),
        });
        Ok(())
    }
    pub fn send_mesh(&mut self, node: &NodeId, packet: &[u8]) -> Result<(), LocalError> {
        if self.projection.is_revoked()
            || node == self.projection.recipient()
            || !self
                .projection
                .mesh()
                .iter()
                .any(|entry| entry.recipient() == node)
        {
            return Err(LocalError::Forward(ForwardError::Denied));
        }
        let peer = PeerId::Node(node.clone());
        let request = self
            .raw
            .send_datagram(&ContextId::Gateway, &peer, packet)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(peer),
        });
        Ok(())
    }
    pub fn receive_mesh(
        &mut self,
        network: &NetworkId,
        origin: &NodeId,
        bytes: &[u8],
        traffic: Option<MeshTraffic>,
    ) -> Result<Option<LocalEvent>, LocalError> {
        let endpoint = self
            .projection
            .mesh()
            .iter()
            .find(|node| {
                node.recipient() == origin
                    && origin != self.projection.recipient()
                    && node
                        .tenants()
                        .iter()
                        .any(|tenant| tenant.network() == network)
            })
            .and_then(|node| node.endpoint())
            .ok_or(LocalError::Forward(ForwardError::Denied))?;
        if !self
            .projection
            .assignment()
            .tenants()
            .iter()
            .any(|tenant| tenant.network() == network)
        {
            return Err(LocalError::Forward(ForwardError::Denied));
        }
        let context = ContextId::Tenant(network.clone());
        let peer = PeerId::Gateway(origin.clone());
        match self
            .raw
            .receive_mesh(endpoint, bytes, &context, &peer)
            .map_err(LocalError::Worker)?
        {
            Submission::Queued(request) => {
                self.flights.push(Flight {
                    request,
                    stage: Stage::ReceiveMesh {
                        network: network.clone(),
                        origin: origin.clone(),
                        traffic,
                    },
                });
                Ok(None)
            }
            Submission::Immediate(DatagramEvent::Network {
                context: actual,
                peer: Some(sender),
                packet,
                ..
            }) if actual == context && sender == peer => Ok(Some(LocalEvent::MeshOutput {
                network: network.clone(),
                peer: origin.clone(),
                packet,
                traffic: None,
            })),
            _ => Err(LocalError::Worker(WorkerError::Protocol)),
        }
    }
    fn material_matches(
        &self,
        id: &EgressId,
        key: &EgressPrivateKey,
        psk: Option<&PresharedKey>,
    ) -> bool {
        self.provider_keys
            .get(id)
            .is_some_and(|old| old.0.as_ref() == KeyFingerprint::new(key, psk).0.as_ref())
    }
    pub fn provider_keys_match<'a>(
        &self,
        providers: impl IntoIterator<Item = ProviderKeys<'a>>,
    ) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        providers
            .into_iter()
            .all(|(id, key, psk)| seen.insert(id) && self.material_matches(id, key, psk))
            && seen.len() == self.provider_keys.len()
    }
    /// Preserve crypto sessions when only policy/public revision changes.
    pub fn can_replace_projection(&self, next: &GatewayProjection) -> bool {
        self.enrollment.is_none()
            && !self.flights.iter().any(|flight| {
                matches!(
                    flight.stage,
                    Stage::ConfigureEnrollment(_) | Stage::ConfigureControl(_)
                )
            })
            && self.raw.workers().iter().all(|worker| {
                matches!(
                    worker.state,
                    super::WorkerState::Ready | super::WorkerState::Busy
                )
            })
            && self.projection.management_id() == next.management_id()
            && self.projection.owned_egresses().len() == next.owned_egresses().len()
            && self.projection.owned_egresses().iter().all(|p| {
                next.owned_egresses()
                    .iter()
                    .any(|n| same_provider_session(p, n))
            })
            && self.projection.assignment() == next.assignment()
            && self.projection.mesh() == next.mesh()
            && self.projection.is_revoked() == next.is_revoked()
            && self.projection.assignment().tenants().iter().all(|tenant| {
                fn devices<'a>(
                    projection: &'a GatewayProjection,
                    id: &NetworkId,
                ) -> Option<&'a [wgfeel_core::Device]> {
                    projection
                        .config()
                        .networks()
                        .iter()
                        .find(|network| network.id() == id)
                        .map(wgfeel_core::Network::devices)
                }
                devices(&self.projection, tenant.network()) == devices(next, tenant.network())
            })
    }
    pub fn replace_projection(&mut self, next: &GatewayProjection) -> Result<(), LocalError> {
        if next.generation() <= self.projection.generation() || !self.can_replace_projection(next) {
            return Err(LocalError::Worker(WorkerError::InvalidConfiguration));
        }
        // Cancel old-revision forwarding/relay flights without breaking 1:1
        // request tracking for raw crypto receives, timers and control ops.
        for flight in &mut self.flights {
            let stage = std::mem::replace(
                &mut flight.stage,
                Stage::Cancelled(flight.request.context.clone(), None),
            );
            flight.stage = stage.across_revision(&flight.request.context);
        }
        retain_nat(&mut self.nat, &self.projection, next);
        self.projection = next.clone();
        Ok(())
    }
    pub fn workers(&self) -> Vec<WorkerInfo> {
        self.raw.workers()
    }
    /// Wait without consuming worker output or exposing private pipe handles.
    /// The caller must then poll and service its own readable descriptors.
    pub fn wait_for_activity(
        &self,
        readable: &[BorrowedFd<'_>],
        maximum: Duration,
    ) -> Result<(), WorkerError> {
        self.raw.wait_for_activity(readable, maximum)
    }
    pub fn projection(&self) -> &GatewayProjection {
        &self.projection
    }
    pub fn endpoint(
        &self,
        context: &ContextId,
        peer: &PeerId,
    ) -> Result<Option<SocketAddr>, LocalError> {
        self.raw.endpoint(context, peer).map_err(LocalError::Worker)
    }
    /// None means accepted for processing; a cookie challenge may be immediate.
    /// Keep polling even without input to observe child exit and deadlines.
    pub fn receive_datagram(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Option<EncryptedDatagram>, LocalError> {
        match self
            .raw
            .receive_datagram(source, bytes)
            .map_err(LocalError::Worker)?
        {
            Submission::Queued(request) => {
                self.flights.push(Flight {
                    request,
                    stage: Stage::Receive,
                });
                Ok(None)
            }
            Submission::Immediate(event) => encrypted(event).map(Some),
        }
    }
    pub fn receive_provider(
        &mut self,
        id: &EgressId,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Option<EncryptedDatagram>, LocalError> {
        wgfeel_core::validate_external_endpoint(source)
            .map_err(|_| LocalError::Worker(WorkerError::InvalidConfiguration))?;
        let context = ContextId::External(id.clone());
        match self
            .raw
            .receive_mesh(source, bytes, &context, &PeerId::Provider)
            .map_err(LocalError::Worker)?
        {
            Submission::Queued(request) => {
                self.flights.push(Flight {
                    request,
                    stage: Stage::ProviderReceive,
                });
                Ok(None)
            }
            Submission::Immediate(event) => encrypted(event).map(Some),
        }
    }

    pub fn provider_authenticated(&self, id: &EgressId) -> Option<Instant> {
        self.raw.provider_authenticated(id)
    }
    pub fn clear_path_mtu(&mut self, id: &EgressId) {
        self.path_mtu.clear(id);
    }

    pub fn set_path_mtu(&mut self, id: &EgressId, mtu: u16) {
        if self.projection.owned_egresses().iter().any(|p| p.id == *id) {
            self.path_mtu.record(id, mtu, Instant::now());
        }
    }
    pub fn expire_translations(&mut self, now: Instant) {
        self.nat.expire(now)
    }

    /// Drives bounded worker I/O and at most one forwarding transition. Busy or
    /// unavailable destinations drop the packet; no deferred replay is retained.
    pub fn poll(&mut self) -> Option<LocalEvent> {
        match self.raw.poll()? {
            WorkerEvent::Ready {
                context,
                generation,
            } => Some(LocalEvent::Ready {
                context,
                generation,
            }),
            WorkerEvent::Failed {
                context,
                generation,
                reason,
            } => {
                if let ContextId::External(id) = &context {
                    self.nat.discard_egress(id);
                    self.path_mtu.clear(id);
                }
                self.flights.retain(|flight| {
                    flight.request.context != context || flight.request.generation != generation
                });
                Some(LocalEvent::Failed {
                    context,
                    generation,
                    reason,
                })
            }
            WorkerEvent::Completed { request, result } => {
                let Some(slot) = self
                    .flights
                    .iter()
                    .position(|flight| flight.request == request)
                else {
                    return Some(dropped(
                        request.context,
                        None,
                        LocalError::Worker(WorkerError::Protocol),
                    ));
                };
                let flight = self.flights.swap_remove(slot);
                match flight.stage {
                    Stage::ProviderReceive => match result {
                        Ok(Some(DatagramEvent::Plaintext {
                            context: ContextId::External(id),
                            peer: PeerId::Provider,
                            packet,
                        })) if request.context == ContextId::External(id.clone()) => {
                            let profile = self
                                .projection
                                .owned_egresses()
                                .iter()
                                .find(|p| p.id == id)?;
                            let mtu = self.path_mtu.get(&id, Instant::now());
                            let action = self.nat.inbound(
                                profile,
                                packet.as_bytes(),
                                mtu,
                                Instant::now(),
                            )?;
                            self.nat_output(
                                Origin {
                                    context: request.context,
                                    generation: request.generation,
                                    peer: PeerId::Provider,
                                },
                                id,
                                action,
                            )
                        }
                        other => emit(request.context, Some(PeerId::Provider), other, None),
                    },
                    Stage::Receive => match result {
                        Ok(Some(DatagramEvent::Plaintext {
                            context: ContextId::Gateway,
                            peer,
                            packet,
                        })) => Some(gateway_event(&self.projection, peer, packet)),
                        Ok(Some(DatagramEvent::Plaintext {
                            context: ContextId::Service,
                            peer,
                            packet,
                        })) => Some(service_event(
                            &self.projection,
                            self.management.as_ref(),
                            self.enrollment.as_ref(),
                            &self.control_peers,
                            peer,
                            packet,
                        )),
                        Ok(Some(DatagramEvent::Plaintext {
                            context,
                            peer,
                            packet,
                        })) => {
                            match authorize_dns(
                                &self.projection,
                                &context,
                                &peer,
                                packet.as_bytes(),
                                false,
                            ) {
                                Ok(true) => Some(LocalEvent::Dns {
                                    source: DnsSource {
                                        origin: Origin {
                                            context,
                                            peer,
                                            generation: request.generation,
                                        },
                                        revision: self.projection.generation(),
                                    },
                                    packet,
                                }),
                                Ok(false) => self.forward(request, context, peer, packet, None),
                                Err(error) => {
                                    Some(dropped(context, Some(peer), LocalError::Forward(error)))
                                }
                            }
                        }
                        other => emit(request.context, None, other, None),
                    },
                    Stage::ReceiveMesh {
                        network,
                        origin,
                        traffic,
                    } => {
                        let expected_context = ContextId::Tenant(network);
                        let expected_peer = PeerId::Gateway(origin);
                        match result {
                            Ok(Some(DatagramEvent::Plaintext {
                                context,
                                peer,
                                packet,
                            })) if context == expected_context
                                && peer == expected_peer
                                && traffic.is_some() =>
                            {
                                self.forward(request, context, peer, packet, traffic)
                            }
                            Ok(Some(event @ DatagramEvent::Network { .. })) => {
                                let matches = matches!(&event, DatagramEvent::Network { context, peer: Some(peer), .. } if context == &expected_context && peer == &expected_peer);
                                if matches {
                                    emit(
                                        expected_context,
                                        Some(expected_peer),
                                        Ok(Some(event)),
                                        None,
                                    )
                                } else {
                                    Some(dropped(
                                        expected_context,
                                        Some(expected_peer),
                                        LocalError::Forward(ForwardError::Denied),
                                    ))
                                }
                            }
                            Ok(Some(_)) => Some(dropped(
                                expected_context,
                                Some(expected_peer),
                                LocalError::Forward(ForwardError::Denied),
                            )),
                            other => emit(expected_context, Some(expected_peer), other, None),
                        }
                    }
                    Stage::Control(peer) => emit(request.context, Some(peer), result, None),
                    Stage::ConfigureEnrollment(next) => {
                        let result = match result {
                            Ok(None) => {
                                self.enrollment = next;
                                Ok(())
                            }
                            Err(error) => Err(LocalError::Worker(WorkerError::WireGuard(error))),
                            Ok(Some(_)) => Err(LocalError::Worker(WorkerError::Protocol)),
                        };
                        Some(LocalEvent::EnrollmentConfigured { result })
                    }
                    Stage::ConfigureControl(next) => {
                        let result = match result {
                            Ok(None) => {
                                self.control_peers = next;
                                Ok(())
                            }
                            Err(error) => Err(LocalError::Worker(WorkerError::WireGuard(error))),
                            Ok(Some(_)) => Err(LocalError::Worker(WorkerError::Protocol)),
                        };
                        Some(LocalEvent::ControlConfigured { result })
                    }
                    Stage::Timer(peer) => {
                        // Only a timer completion may reset an expired peer.
                        // Malformed received packets must never trigger reset.
                        if matches!(result, Err(WireGuardError::Protocol)) {
                            let _ = self.reset(&request.context, &peer);
                        }
                        emit(request.context, Some(peer), result, None)
                    }
                    Stage::Cancelled(context, peer) => {
                        Some(dropped(context, peer, LocalError::Cancelled))
                    }
                    Stage::Forward(origin, traffic) => {
                        // A reply already in another worker's pipe must not
                        // escape an observed origin failure or explicit restart.
                        if !self
                            .raw
                            .generation_is_active(&origin.context, origin.generation)
                        {
                            return Some(dropped(
                                origin.context,
                                Some(origin.peer),
                                LocalError::Cancelled,
                            ));
                        }
                        emit(origin.context, Some(origin.peer), result, traffic)
                    }
                }
            }
        }
    }
    pub fn initiate_at(
        &mut self,
        context: &ContextId,
        peer: &PeerId,
        destination: SocketAddr,
    ) -> Result<(), LocalError> {
        let request = self
            .raw
            .initiate_at(context, peer, destination)
            .map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(peer.clone()),
        });
        Ok(())
    }
    pub fn tick(&mut self, context: &ContextId, peer: &PeerId) -> Result<(), LocalError> {
        let request = self.raw.tick(context, peer).map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Timer(peer.clone()),
        });
        Ok(())
    }
    /// Reset the local session without changing desired policy or identity.
    /// Already authorized work in another worker keeps its original provenance.
    pub fn reset(&mut self, context: &ContextId, peer: &PeerId) -> Result<(), LocalError> {
        let request = self.raw.reset(context, peer).map_err(LocalError::Worker)?;
        self.flights.push(Flight {
            request,
            stage: Stage::Control(peer.clone()),
        });
        Ok(())
    }
    pub fn restart_tenant(
        &mut self,
        network: &NetworkId,
        key: &TenantPrivateKey,
    ) -> Result<(), LocalError> {
        let key = TenantPrivateKey::new(*key.expose_bytes())
            .map_err(|_| LocalError::Worker(WorkerError::InvalidConfiguration))?;
        self.restart(&ContextId::Tenant(network.clone()), PrivateKey::Tenant(key))
    }

    fn restart(&mut self, context: &ContextId, key: PrivateKey) -> Result<(), LocalError> {
        let result = self
            .raw
            .restart_with_key(context, key)
            .map_err(LocalError::Worker);
        // Invalid keys preserve the old generation. A failed spawn has already
        // revoked it, just as a successful replacement has retired it.
        self.flights.retain(|flight| {
            self.raw
                .generation_is_active(&flight.request.context, flight.request.generation)
        });
        result
    }
    fn forward(
        &mut self,
        request: RequestId,
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
        expected: Option<MeshTraffic>,
    ) -> Option<LocalEvent> {
        let origin = Origin {
            context: context.clone(),
            generation: request.generation,
            peer: peer.clone(),
        };
        let (src, dst) = crate::forwarding::addresses(packet.as_bytes()).ok()?;
        let ContextId::Tenant(network) = &context else {
            return None;
        };
        let external = match (&peer, &expected) {
            (PeerId::Gateway(sender), Some(MeshTraffic::External(label))) => {
                if label.device.network() != network {
                    return None;
                }
                let device = self.projection.device(&label.device)?;
                match label.direction {
                    Direction::FromEgress => {
                        let remote = crate::nat::return_remote(packet.as_bytes())?;
                        if device.gateway() != Some(self.projection.recipient())
                            || !device.addresses().contains(&dst)
                            || !winner(
                                &self.projection,
                                &label.device,
                                remote,
                                &label.egress,
                                sender,
                                label.prefix,
                            )
                        {
                            return None;
                        }
                        let target = PeerId::Device(label.device.device().clone());
                        return self.encrypt(origin, context.clone(), target, packet, None);
                    }
                    Direction::ToEgress => {
                        if device.gateway() != Some(sender)
                            || !device.addresses().contains(&src)
                            || !winner(
                                &self.projection,
                                &label.device,
                                dst,
                                &label.egress,
                                self.projection.recipient(),
                                label.prefix,
                            )
                        {
                            return None;
                        }
                        Some((
                            label.clone(),
                            sender.clone(),
                            self.projection.recipient().clone(),
                        ))
                    }
                }
            }
            (PeerId::Device(id), None) => {
                let endpoint = Endpoint::new(network.clone(), id.clone());
                if let Destination::Egress {
                    egress,
                    node,
                    prefix,
                } = self.projection.classify_destination(&endpoint, dst)
                {
                    let device = self.projection.device(&endpoint)?;
                    if !device.addresses().contains(&src)
                        || device.gateway() != Some(self.projection.recipient())
                    {
                        return None;
                    }
                    Some((
                        ExternalTraffic {
                            direction: Direction::ToEgress,
                            device: endpoint,
                            egress,
                            prefix,
                        },
                        self.projection.recipient().clone(),
                        node,
                    ))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some((label, home, owner)) = external {
            if owner != *self.projection.recipient() {
                return self.encrypt(
                    origin,
                    context,
                    PeerId::Gateway(owner),
                    packet,
                    Some(MeshTraffic::External(label)),
                );
            }
            let profile = self
                .projection
                .owned_egresses()
                .iter()
                .find(|p| p.id == label.egress)?;
            let binding = NatBinding {
                device: label.device,
                home,
                inside: src,
                prefix: label.prefix,
            };
            let mtu = self.path_mtu.get(&label.egress, Instant::now());
            let action =
                self.nat
                    .outbound(profile, &binding, packet.as_bytes(), mtu, Instant::now())?;
            return self.nat_output(origin, label.egress, action);
        }
        let (traffic, home, packet) =
            match authorize_routed(&self.projection, context, peer, packet) {
                Ok(value) => value,
                Err(error) => {
                    return Some(dropped(
                        origin.context,
                        Some(origin.peer),
                        LocalError::Forward(error),
                    ));
                }
            };
        if expected
            .as_ref()
            .is_some_and(|expected| expected != &MeshTraffic::Device(traffic.clone()))
        {
            return Some(dropped(
                origin.context,
                Some(origin.peer),
                LocalError::Forward(ForwardError::SourceMismatch),
            ));
        }
        let target = match home {
            Some(home) if &home != self.projection.recipient() => PeerId::Gateway(home),
            _ => PeerId::Device(traffic.destination.device().clone()),
        };
        let context = ContextId::Tenant(traffic.destination.network().clone());
        let remote = matches!(target, PeerId::Gateway(_));
        self.encrypt(
            origin,
            context,
            target,
            packet,
            remote.then_some(MeshTraffic::Device(traffic)),
        )
    }

    fn nat_output(
        &mut self,
        origin: Origin,
        id: EgressId,
        action: NatAction,
    ) -> Option<LocalEvent> {
        match action {
            NatAction::ToProvider(packet) => self.encrypt(
                origin,
                ContextId::External(id),
                PeerId::Provider,
                packet,
                None,
            ),
            NatAction::ToDevice {
                binding,
                remote,
                packet,
            } => {
                let device = self.projection.device(&binding.device)?;
                if device.gateway() != Some(&binding.home)
                    || !device.addresses().contains(&binding.inside)
                    || !winner(
                        &self.projection,
                        &binding.device,
                        remote,
                        &id,
                        self.projection.recipient(),
                        binding.prefix,
                    )
                {
                    return None;
                }
                let ctx = ContextId::Tenant(binding.device.network().clone());
                if binding.home == *self.projection.recipient() {
                    self.encrypt(
                        origin,
                        ctx,
                        PeerId::Device(binding.device.device().clone()),
                        packet,
                        None,
                    )
                } else {
                    let label = ExternalTraffic {
                        direction: Direction::FromEgress,
                        device: binding.device,
                        egress: id,
                        prefix: binding.prefix,
                    };
                    self.encrypt(
                        origin,
                        ctx,
                        PeerId::Gateway(binding.home),
                        packet,
                        Some(MeshTraffic::External(label)),
                    )
                }
            }
        }
    }

    fn encrypt(
        &mut self,
        origin: Origin,
        context: ContextId,
        target: PeerId,
        packet: PacketBytes,
        traffic: Option<MeshTraffic>,
    ) -> Option<LocalEvent> {
        match self.raw.send_datagram(&context, &target, packet.as_bytes()) {
            Ok(request) => {
                self.flights.push(Flight {
                    request,
                    stage: Stage::Forward(origin, traffic),
                });
                None
            }
            Err(error) => Some(dropped(
                origin.context,
                Some(origin.peer),
                LocalError::Worker(error),
            )),
        }
    }
}

fn winner(
    projection: &GatewayProjection,
    device: &Endpoint,
    remote: std::net::IpAddr,
    id: &EgressId,
    owner: &NodeId,
    rule: wgfeel_core::IpPrefix,
) -> bool {
    matches!(projection.classify_destination(device,remote), Destination::Egress{egress,node,prefix} if egress==*id && node==*owner && prefix==rule)
}

fn home_tenant_key<'a>(
    projection: &'a GatewayProjection,
    binding: &NatBinding,
) -> Option<&'a DevicePublicKey> {
    projection
        .mesh()
        .iter()
        .find(|n| n.recipient() == &binding.home)?
        .tenants()
        .iter()
        .find(|t| t.network() == binding.device.network())
        .map(|t| t.public_key())
}

fn retain_nat(table: &mut NatTable, previous: &GatewayProjection, projection: &GatewayProjection) {
    table.retain(Instant::now(), |id, binding, remote| {
        previous
            .device(&binding.device)
            .zip(projection.device(&binding.device))
            .is_some_and(|(old, d)| {
                old.public_key() == d.public_key()
                    && d.gateway() == Some(&binding.home)
                    && d.addresses().contains(&binding.inside)
            })
            && home_tenant_key(previous, binding) == home_tenant_key(projection, binding)
            && winner(
                projection,
                &binding.device,
                remote,
                id,
                projection.recipient(),
                binding.prefix,
            )
    });
}

fn dropped(context: ContextId, peer: Option<PeerId>, reason: LocalError) -> LocalEvent {
    LocalEvent::Dropped {
        context,
        peer,
        reason,
    }
}
fn emit(
    context: ContextId,
    peer: Option<PeerId>,
    result: Result<Option<DatagramEvent>, WireGuardError>,
    traffic: Option<MeshTraffic>,
) -> Option<LocalEvent> {
    match result {
        Ok(None) => None,
        Ok(Some(event)) => Some(match encrypted(event) {
            Ok(EncryptedDatagram {
                context: ContextId::Tenant(network),
                peer: Some(PeerId::Gateway(peer)),
                packet,
                ..
            }) => LocalEvent::MeshOutput {
                network,
                peer,
                packet,
                traffic,
            },
            Ok(packet) if matches!(packet.context, ContextId::External(_)) => {
                LocalEvent::ProviderOutput(packet)
            }
            Ok(packet) => LocalEvent::Network(packet),
            Err(error) => dropped(context, peer, error),
        }),
        Err(error) => Some(dropped(
            context,
            peer,
            LocalError::Worker(WorkerError::WireGuard(error)),
        )),
    }
}
fn encrypted(event: DatagramEvent) -> Result<EncryptedDatagram, LocalError> {
    match event {
        DatagramEvent::Network {
            destination,
            context,
            peer,
            packet,
        } => Ok(EncryptedDatagram {
            destination,
            context,
            peer,
            packet,
        }),
        DatagramEvent::Plaintext { .. } => Err(LocalError::Worker(WorkerError::Protocol)),
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use wgfeel_core::{Config, GatewayAssignment, ManagementConfig, Policy, TrafficMode};

    fn projection(recipient: &str, mode: TrafficMode) -> GatewayProjection {
        let nodes = [("main", 31), ("child", 32), ("relay", 33)]
            .into_iter()
            .map(|(id, byte)| {
                GatewayAssignment::new(
                    NodeId::new(id).unwrap(),
                    (DevicePublicKey::new([byte; 32]).unwrap()).clone(),
                    wgfeel_test_support::fixture_gateway_public(
                        &(DevicePublicKey::new([byte; 32]).unwrap()),
                    ),
                    vec![],
                    vec![],
                )
                .unwrap()
                .with_traffic(mode)
                .unwrap()
            })
            .collect();
        ManagementConfig::new(
            NodeId::new("main").unwrap(),
            Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            nodes,
        )
        .unwrap()
        .project_mesh_for(&NodeId::new(recipient).unwrap())
        .unwrap()
    }

    #[test]
    fn main_in_mesh_has_no_self_peer_and_child_has_one_pinned_authority() {
        let pin = DevicePublicKey::new([31; 32]).unwrap();
        for mode in [TrafficMode::Entry, TrafficMode::Relay, TrafficMode::Off] {
            let main = managed_service_peers(&projection("main", mode), &pin).unwrap();
            assert_eq!(main.len(), 2);
            assert_eq!(main[0].id, PeerId::Node(NodeId::new("child").unwrap()));
            assert_eq!(main[1].id, PeerId::Node(NodeId::new("relay").unwrap()));
            let child = managed_service_peers(&projection("child", mode), &pin).unwrap();
            assert_eq!(child.len(), 1);
            assert_eq!(child[0].id, PeerId::Node(NodeId::new("main").unwrap()));
            assert_eq!(child[0].public_key, pin);
        }
    }

    #[test]
    fn mesh_membership_cannot_replace_the_pinned_authority_key() {
        let wrong = DevicePublicKey::new([44; 32]).unwrap();
        for recipient in ["main", "child"] {
            assert!(
                managed_service_peers(&projection(recipient, TrafficMode::Off), &wrong).is_err()
            );
        }
    }

    #[test]
    fn registered_control_identity_is_dispatched_only_by_the_local_main() {
        let invite = NodeId::new("invitation").unwrap();
        let controls = [crate::PeerConfig {
            id: PeerId::Node(invite.clone()),
            public_key: DevicePublicKey::new([77; 32]).unwrap(),
        }];
        let dispatch = |recipient| {
            service_event(
                &projection(recipient, TrafficMode::Off),
                None,
                None,
                &controls,
                PeerId::Node(invite.clone()),
                PacketBytes(vec![]),
            )
        };
        assert!(matches!(dispatch("main"), LocalEvent::Control { peer, .. } if peer == invite));
        assert!(matches!(dispatch("child"), LocalEvent::Dropped { .. }));
    }

    #[test]
    fn service_and_gateway_frames_cannot_cross_context_authority() {
        let local = projection("child", TrafficMode::Off);
        let main = NodeId::new("main").unwrap();
        let child = NodeId::new("relay").unwrap();
        let mut main_projection = projection("main", TrafficMode::Off);
        // Real mesh output uses its own IP protocol and framing.
        let nodes: Vec<_> = main_projection
            .mesh()
            .iter()
            .cloned()
            .map(|node| {
                node.with_endpoint(Some("192.0.2.1:51820".parse().unwrap()))
                    .unwrap()
            })
            .collect();
        main_projection =
            ManagementConfig::new(main.clone(), main_projection.config().clone(), nodes)
                .unwrap()
                .project_mesh_for(&main)
                .unwrap();
        let frame = crate::mesh::Mesh::new(&main_projection, 17)
            .tick(Duration::ZERO)
            .into_iter()
            .find_map(|action| match action {
                crate::mesh::Action::Send { packet, .. } => Some(packet),
                _ => None,
            })
            .unwrap();
        // Re-enrollment with the same main must not steal its mesh health frames.
        for enrollment in [None, Some(&main)] {
            assert!(matches!(
                service_event(
                    &local,
                    Some(&main),
                    enrollment,
                    &[],
                    PeerId::Node(main.clone()),
                    PacketBytes(frame.as_bytes().to_vec())
                ),
                LocalEvent::Dropped {
                    context: ContextId::Service,
                    ..
                }
            ));
            assert!(
                matches!(gateway_event(&local, PeerId::Node(main.clone()), PacketBytes(frame.as_bytes().to_vec())),
                LocalEvent::Mesh { peer, .. } if peer == main)
            );
        }
        let command = || {
            PacketBytes(vec![
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 253, 0, 1, 10, 253, 0, 2,
            ])
        };
        assert!(matches!(
            service_event(
                &local,
                Some(&main),
                None,
                &[],
                PeerId::Node(main.clone()),
                command()
            ),
            LocalEvent::Management { .. }
        ));
        assert!(matches!(
            service_event(
                &local,
                Some(&main),
                None,
                &[],
                PeerId::Node(child.clone()),
                command()
            ),
            LocalEvent::Dropped {
                context: ContextId::Service,
                ..
            }
        ));
        assert!(matches!(
            gateway_event(&local, PeerId::Node(main.clone()), command()),
            LocalEvent::Dropped {
                context: ContextId::Gateway,
                ..
            }
        ));
        assert!(matches!(service_event(&main_projection, None, None, &[],
            PeerId::Node(child.clone()), command()), LocalEvent::Control { peer, .. } if peer == child));
        let invitation = NodeId::new("invitation").unwrap();
        assert!(matches!(
            service_event(
                &local,
                Some(&main),
                Some(&invitation),
                &[],
                PeerId::Node(invitation.clone()),
                command()
            ),
            LocalEvent::Enrollment { .. }
        ));
        assert!(matches!(
            service_event(
                &local,
                Some(&main),
                None,
                &[],
                PeerId::Node(invitation),
                command()
            ),
            LocalEvent::Dropped { .. }
        ));
    }

    #[test]
    fn revision_flight_transition_cancels_forwarding_and_relay_while_preserving_crypto_work() {
        let tenant = ContextId::Tenant(NetworkId::new("alice").unwrap());
        let peer = PeerId::Device(wgfeel_core::DeviceId::new("phone").unwrap());
        let node = PeerId::Node(NodeId::new("child").unwrap());
        assert!(matches!(
            Stage::Receive.across_revision(&tenant),
            Stage::Receive
        ));
        assert!(matches!(
            Stage::Timer(peer.clone()).across_revision(&tenant),
            Stage::Timer(_)
        ));
        assert!(matches!(
            Stage::Control(node.clone()).across_revision(&ContextId::Service),
            Stage::Control(_)
        ));
        assert!(matches!(
            Stage::Control(node.clone()).across_revision(&ContextId::Gateway),
            Stage::Cancelled(ContextId::Gateway, Some(_))
        ));
        assert!(matches!(
            Stage::Forward(
                Origin {
                    context: tenant.clone(),
                    generation: 1,
                    peer: peer.clone(),
                },
                None,
            )
            .across_revision(&tenant),
            Stage::Cancelled(ContextId::Tenant(_), Some(PeerId::Device(_)))
        ));
        assert!(matches!(
            Stage::ReceiveMesh {
                network: NetworkId::new("alice").unwrap(),
                origin: NodeId::new("remote").unwrap(),
                traffic: None,
            }
            .across_revision(&tenant),
            Stage::Cancelled(ContextId::Tenant(_), Some(PeerId::Gateway(_)))
        ));
    }
}

#[cfg(test)]
mod path_mtu_tests {
    use super::*;
    #[test]
    fn pmtu_below_ipv6_minimum_expires_and_a_reconnected_socket_starts_fresh() {
        let id = EgressId::new("vpn").unwrap();
        let now = Instant::now();
        let mut cache = PathMtu::default();
        cache.record(&id, 1200, now);
        assert_eq!(cache.get(&id, now + Duration::from_secs(1)), 1200);
        assert_eq!(cache.get(&id, now + PMTU_LEASE), 1280);
        cache.record(&id, 1120, now + PMTU_LEASE);
        cache.clear(&id);
        assert_eq!(cache.get(&id, now + PMTU_LEASE), 1280);
    }
}
