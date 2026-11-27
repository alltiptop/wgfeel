//! Gateway-local health, link-state routes and opaque tenant-WG relay frames.
//! Gateway peers authenticate the transport. Tenant ciphertext is authenticated
//! again by its own worker at the destination, including its routing identity.
use crate::{MAX_DATAGRAM_SIZE, PacketBytes};
use std::{collections::VecDeque, net::SocketAddr, time::Duration};
use wgfeel_core::{
    Action as Decision, DeviceId, EgressId, Endpoint, GatewayAssignment, GatewayProjection,
    IpPrefix, NetworkId, NodeId,
};

const CHUNK: usize = 1024;
const EXTERNAL_CHUNK: usize = 960;
const _: () = assert!(34 + 12 + 3 * 65 + 18 + 4 + EXTERNAL_CHUNK <= crate::MAX_PLAINTEXT_SIZE);
const _: () = assert!(MAX_DATAGRAM_SIZE <= 2 * EXTERNAL_CHUNK);
const _: () = assert!(34 + 12 + 3 * 65 + 4 + CHUNK <= crate::MAX_PLAINTEXT_SIZE);
const _: () = assert!(MAX_DATAGRAM_SIZE <= 2 * CHUNK);
const BITS: usize = 19;
const DEAD: Duration = Duration::from_secs(3);
const LSA_LEASE: Duration = Duration::from_secs(6);
const FRAGMENT_LEASE: Duration = Duration::from_secs(2);
const MAX_ASSEMBLIES: usize = 256;
const MAGIC: &[u8; 5] = b"WGFM\x01";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traffic {
    pub source: Endpoint,
    pub destination: Endpoint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToEgress,
    FromEgress,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTraffic {
    pub device: Endpoint,
    pub egress: EgressId,
    pub prefix: IpPrefix,
    pub direction: Direction,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastTraffic {
    pub source: Endpoint,
    pub witness: Endpoint,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshTraffic {
    Broadcast(BroadcastTraffic),
    Device(Traffic),
    External(ExternalTraffic),
}

#[derive(Debug)]
pub enum Action {
    Initiate {
        node: NodeId,
        endpoint: SocketAddr,
    },
    Send {
        node: NodeId,
        packet: PacketBytes,
    },
    Wire {
        endpoint: SocketAddr,
        packet: PacketBytes,
    },
    Deliver {
        network: NetworkId,
        origin: NodeId,
        packet: PacketBytes,
        traffic: Option<MeshTraffic>,
    },
}
impl Action {
    pub fn is_broadcast(&self) -> bool {
        match self {
            Action::Send { packet, .. } => packet.as_bytes().get(33) == Some(&7),
            Action::Deliver { traffic, .. } => matches!(traffic, Some(MeshTraffic::Broadcast(_))),
            _ => false,
        }
    }
}
struct Peer {
    assignment: GatewayAssignment,
    pong: Option<Duration>,
    nonce: Option<u64>,
    probe: Duration,
    initiate: Duration,
    next_endpoint: usize,
    active_endpoint: Option<SocketAddr>,
}
#[derive(Clone)]
struct Lsa {
    boot: u64,
    sequence: u64,
    neighbors: [u8; BITS],
    received: Duration,
}
struct Assembly {
    header: Relay,
    first: Option<Vec<u8>>,
    second: Option<Vec<u8>>,
    expires: Duration,
}
#[derive(Clone, PartialEq, Eq)]
struct Relay {
    id: u64,
    origin: usize,
    target: usize,
    network: NetworkId,
    traffic: Option<MeshTraffic>,
    ttl: u8,
    total: usize,
}
fn chunk_size(kind: u8) -> usize {
    if matches!(kind, 5 | 6) {
        EXTERNAL_CHUNK
    } else {
        CHUNK
    }
}
impl Relay {
    fn kind(&self) -> u8 {
        match &self.traffic {
            Some(MeshTraffic::Broadcast(_)) => 7,
            Some(MeshTraffic::External(t)) => {
                if t.direction == Direction::ToEgress {
                    5
                } else {
                    6
                }
            }
            _ => 4,
        }
    }
    fn chunk_size(&self) -> usize {
        chunk_size(self.kind())
    }
}
pub struct Mesh {
    projection: GatewayProjection,
    peers: Vec<Peer>,
    own: Option<usize>,
    boot: u64,
    sequence: u64,
    advertisements: Vec<Option<Lsa>>,
    advertise: Duration,
    packet: u64,
    assemblies: Vec<Assembly>,
    broadcast_fragments: std::collections::BTreeMap<NetworkId, (Duration, u32)>,
}
impl Mesh {
    pub fn new(projection: &GatewayProjection, boot: u64) -> Self {
        let mut peers: Vec<_> = projection
            .mesh()
            .iter()
            .map(|assignment| Peer {
                assignment: assignment.clone(),
                pong: None,
                nonce: None,
                probe: Duration::ZERO,
                initiate: Duration::ZERO,
                next_endpoint: 0,
                active_endpoint: None,
            })
            .collect();
        peers.sort_by(|a, b| a.assignment.recipient().cmp(b.assignment.recipient()));
        let own = if projection.is_revoked() {
            None
        } else {
            peers
                .iter()
                .position(|peer| peer.assignment.recipient() == projection.recipient())
        };
        Self {
            projection: projection.clone(),
            advertisements: vec![None; peers.len()],
            peers,
            own,
            boot,
            sequence: 0,
            advertise: Duration::ZERO,
            packet: boot,
            broadcast_fragments: Default::default(),
            assemblies: Vec::with_capacity(MAX_ASSEMBLIES),
        }
    }
    /// Carry authenticated direct reachability across a revision. Topology
    /// advertisements, relay queues and fragment assemblies belong to one revision.
    pub fn inherit_health(&mut self, previous: &Self) {
        if self.own.is_none()
            || previous.own.is_none()
            || self.projection.management_id() != previous.projection.management_id()
            || self.projection.recipient() != previous.projection.recipient()
            || self.projection.assignment().gateway_public_key()
                != previous.projection.assignment().gateway_public_key()
        {
            return;
        }
        let authority_key = |mesh: &Self| {
            mesh.projection
                .mesh()
                .iter()
                .find(|n| n.recipient() == mesh.projection.management_id())
                .map(|n| n.service_public_key().clone())
        };
        if authority_key(self) == authority_key(previous) {
            self.broadcast_fragments.extend(
                previous
                    .broadcast_fragments
                    .iter()
                    .filter(|(n, _)| self.projection.assignment().networks().contains(n))
                    .map(|(n, v)| (n.clone(), *v)),
            );
        }
        self.boot = previous.boot;
        self.sequence = previous.sequence;
        self.packet = previous.packet;
        for peer in &mut self.peers {
            let Ok(index) = previous.peers.binary_search_by(|old| {
                old.assignment.recipient().cmp(peer.assignment.recipient())
            }) else {
                continue;
            };
            let old = &previous.peers[index];
            if old.assignment.gateway_public_key() != peer.assignment.gateway_public_key() {
                continue;
            }
            let endpoints = peer.assignment.endpoints();
            let same_endpoints = endpoints == old.assignment.endpoints();
            if same_endpoints {
                peer.next_endpoint = old.next_endpoint;
            }
            if let Some(endpoint) = old.active_endpoint
                && let Some(position) = endpoints
                    .iter()
                    .position(|candidate| *candidate == endpoint)
            {
                peer.active_endpoint = Some(endpoint);
                peer.pong = old.pong;
                if !same_endpoints {
                    peer.next_endpoint = (position + 1) % endpoints.len();
                }
            }
        }
    }
    fn live(&self, index: usize, now: Duration) -> bool {
        self.peers[index]
            .pong
            .is_some_and(|last| now.saturating_sub(last) < DEAD)
    }
    pub fn tick(&mut self, now: Duration) -> Vec<Action> {
        let Some(own) = self.own else {
            return vec![];
        };
        self.assemblies.retain(|entry| entry.expires > now);
        let mut actions = Vec::new();
        for index in 0..self.peers.len() {
            if index == own {
                continue;
            }
            let live = self.live(index, now);
            let peer = &mut self.peers[index];
            if peer.assignment.endpoints().is_empty() {
                continue;
            }
            if !live && now >= peer.initiate {
                let endpoint = peer.assignment.endpoints()[peer.next_endpoint];
                peer.next_endpoint = (peer.next_endpoint + 1) % peer.assignment.endpoints().len();
                actions.push(Action::Initiate {
                    node: peer.assignment.recipient().clone(),
                    endpoint,
                });
                peer.initiate = now + Duration::from_secs(2);
            }
            if now >= peer.probe {
                self.packet = self.packet.wrapping_add(1);
                peer.nonce = Some(self.packet);
                actions.push(Action::Send {
                    node: peer.assignment.recipient().clone(),
                    packet: encode(self.projection.generation(), 1, &self.packet.to_le_bytes()),
                });
                peer.probe = now + Duration::from_secs(1);
            }
        }
        if now >= self.advertise {
            self.advertise = now + Duration::from_millis(500);
            self.sequence = self.sequence.wrapping_add(1);
            let mut neighbors = [0; BITS];
            for index in 0..self.peers.len() {
                if self.live(index, now) {
                    set(&mut neighbors, index);
                }
            }
            let lsa = Lsa {
                boot: self.boot,
                sequence: self.sequence,
                neighbors,
                received: now,
            };
            self.advertisements[own] = Some(lsa.clone());
            for index in 0..self.peers.len() {
                if self.live(index, now) {
                    actions.push(Action::Send {
                        node: self.peers[index].assignment.recipient().clone(),
                        packet: lsa_packet(
                            self.projection.generation(),
                            own,
                            &lsa,
                            self.peers.len() as u8,
                        ),
                    });
                }
            }
        }
        actions
    }
    /// Returns the direct next hop for an available permitted mesh route.
    pub fn next_hop(&self, target: &NodeId, now: Duration) -> Option<NodeId> {
        let target = self
            .peers
            .iter()
            .position(|peer| peer.assignment.recipient() == target)?;
        self.route(target, None, now)
            .map(|hop| self.peers[hop].assignment.recipient().clone())
    }
    fn route(&self, target: usize, network: Option<&NetworkId>, now: Duration) -> Option<usize> {
        let own = self.own?;
        let eligible = |index: usize| {
            network.is_none_or(|network| self.peers[index].assignment.networks().contains(network))
        };
        if !eligible(own) || !eligible(target) {
            return None;
        }
        if target == own {
            return None;
        }
        if self.live(target, now) {
            return Some(target);
        }
        let mut visited = vec![false; self.peers.len()];
        visited[own] = true;
        let mut queue = VecDeque::new();
        for (index, seen) in visited.iter_mut().enumerate() {
            if index != own && eligible(index) && self.live(index, now) {
                *seen = true;
                queue.push_back((index, index));
            }
        }
        while let Some((node, first)) = queue.pop_front() {
            if node == target {
                return Some(first);
            }
            let Some(lsa) = self.advertisements[node]
                .as_ref()
                .filter(|lsa| now.saturating_sub(lsa.received) < LSA_LEASE)
            else {
                continue;
            };
            for (next, seen) in visited.iter_mut().enumerate() {
                if *seen || !eligible(next) || !has(&lsa.neighbors, next) {
                    continue;
                }
                let Some(reverse) = self.advertisements[next]
                    .as_ref()
                    .filter(|lsa| now.saturating_sub(lsa.received) < LSA_LEASE)
                else {
                    continue;
                };
                if !has(&reverse.neighbors, node) {
                    continue;
                }
                *seen = true;
                queue.push_back((next, first));
            }
        }
        None
    }
    /// Only encrypted output from a tenant worker enters this method.
    pub fn transmit(
        &mut self,
        network: &NetworkId,
        target: &NodeId,
        packet: &[u8],
        traffic: Option<Traffic>,
        now: Duration,
    ) -> Vec<Action> {
        self.transmit_scoped(
            network,
            target,
            packet,
            traffic.map(MeshTraffic::Device),
            now,
        )
    }
    pub fn clear_broadcast_assemblies(&mut self) {
        self.assemblies.retain(|a| a.header.kind() != 7);
    }
    pub fn transmit_scoped(
        &mut self,
        network: &NetworkId,
        target: &NodeId,
        packet: &[u8],
        traffic: Option<MeshTraffic>,
        now: Duration,
    ) -> Vec<Action> {
        let Some(origin) = self.own else {
            return vec![];
        };
        let Some(target) = self
            .peers
            .iter()
            .position(|peer| peer.assignment.recipient() == target)
        else {
            return vec![];
        };
        let Some(hop) = self.route(target, Some(network), now) else {
            return vec![];
        };
        if !valid_wire(packet, traffic.is_some()) {
            return vec![];
        }
        self.packet = self.packet.wrapping_add(1);
        let relay = Relay {
            id: self.packet,
            origin,
            target,
            network: network.clone(),
            traffic,
            ttl: self.peers.len() as u8,
            total: packet.len(),
        };
        if !self.allowed(&relay, origin) {
            return vec![];
        }
        if hop == target && relay.kind() == 4 {
            return self.peers[target]
                .active_endpoint
                .map(|endpoint| {
                    vec![Action::Wire {
                        endpoint,
                        packet: PacketBytes(packet.to_vec()),
                    }]
                })
                .unwrap_or_default();
        }
        packet
            .chunks(relay.chunk_size())
            .enumerate()
            .map(|(fragment, chunk)| Action::Send {
                node: self.peers[hop].assignment.recipient().clone(),
                packet: relay_packet(self.projection.generation(), &relay, fragment, chunk),
            })
            .collect()
    }
    /// Both the peer identity and outer source must come from an authenticated
    /// gateway-WG receive. Only a response to our live probe confirms a path.
    pub fn receive(
        &mut self,
        source: &NodeId,
        endpoint: SocketAddr,
        packet: &[u8],
        now: Duration,
    ) -> Vec<Action> {
        let Some(own) = self.own else {
            return vec![];
        };
        let Some(from) = self
            .peers
            .iter()
            .position(|peer| peer.assignment.recipient() == source)
        else {
            return vec![];
        };
        if from == own {
            return vec![];
        }
        let Some((generation, kind, body)) = decode(packet) else {
            return vec![];
        };
        // Ping contains only a nonce. Echo the sender's revision so it can
        // validate its own probe during a rolling configuration update.
        if kind != 1 && generation != self.projection.generation() {
            return vec![];
        }
        match kind {
            1 if body.len() == 8 => vec![Action::Send {
                node: source.clone(),
                packet: encode(generation, 2, body),
            }],
            2 if body.len() == 8 => {
                if Some(u64::from_le_bytes(body.try_into().expect("eight bytes")))
                    == self.peers[from].nonce
                {
                    self.peers[from].nonce = None;
                    self.peers[from].pong = Some(now);
                    self.peers[from].active_endpoint = Some(endpoint);
                    if let Some(index) = self.peers[from]
                        .assignment
                        .endpoints()
                        .iter()
                        .position(|candidate| *candidate == endpoint)
                    {
                        self.peers[from].next_endpoint =
                            (index + 1) % self.peers[from].assignment.endpoints().len();
                    }
                }
                vec![]
            }
            3 => self.advertisement(from, body, packet[8], now),
            4..=7 => self.relay(from, kind, body, now),
            _ => vec![],
        }
    }
    fn advertisement(&mut self, from: usize, body: &[u8], hops: u8, now: Duration) -> Vec<Action> {
        if body.len() != 18 + BITS || hops == 0 || usize::from(hops) > self.peers.len() {
            return vec![];
        }
        let origin = usize::from(u16::from_le_bytes([body[0], body[1]]));
        if origin >= self.peers.len() || Some(origin) == self.own {
            return vec![];
        }
        let boot = u64::from_le_bytes(body[2..10].try_into().expect("fixed body"));
        let sequence = u64::from_le_bytes(body[10..18].try_into().expect("fixed body"));
        let neighbors = body[18..].try_into().expect("fixed bitset");
        if has(&neighbors, origin) || (self.peers.len()..BITS * 8).any(|bit| has(&neighbors, bit)) {
            return vec![];
        }
        if self.advertisements[origin].as_ref().is_some_and(|old| {
            if old.boot == boot {
                old.sequence >= sequence
            } else {
                // Boot IDs are random. Keep a live origin's epoch until its lease expires.
                now.saturating_sub(old.received) < LSA_LEASE
            }
        }) {
            return vec![];
        }
        let lsa = Lsa {
            boot,
            sequence,
            neighbors,
            received: now,
        };
        self.advertisements[origin] = Some(lsa.clone());
        if hops == 1 {
            return vec![];
        }
        // Complete meshes already receive each origin directly. Gossip only
        // across missing edges, which also repairs sparse connected topologies.
        (0..self.peers.len())
            .filter(|index| *index != from && self.live(*index, now))
            .filter(|index| {
                self.advertisements[*index]
                    .as_ref()
                    .is_none_or(|peer| !has(&peer.neighbors, origin))
            })
            .map(|index| Action::Send {
                node: self.peers[index].assignment.recipient().clone(),
                packet: lsa_packet(self.projection.generation(), origin, &lsa, hops - 1),
            })
            .collect()
    }
    fn allowed(&self, relay: &Relay, from: usize) -> bool {
        if relay.origin >= self.peers.len()
            || relay.target >= self.peers.len()
            || relay.origin == relay.target
            || !self
                .projection
                .assignment()
                .networks()
                .contains(&relay.network)
            || !self.peers[from]
                .assignment
                .networks()
                .contains(&relay.network)
            || [relay.origin, relay.target].iter().any(|index| {
                !self.peers[*index]
                    .assignment
                    .tenants()
                    .iter()
                    .any(|tenant| tenant.network() == &relay.network)
            })
        {
            return false;
        }
        let Some(traffic) = &relay.traffic else {
            return true;
        };
        let traffic = match traffic {
            MeshTraffic::Broadcast(t) => {
                return t.source.network() == &relay.network
                    && self.projection.broadcast_recipient(
                        &t.source,
                        &t.witness,
                        self.peers[relay.origin].assignment.recipient(),
                        self.peers[relay.target].assignment.recipient(),
                    );
            }
            MeshTraffic::Device(t) => t,
            MeshTraffic::External(t) => {
                let (home, owner) = match t.direction {
                    Direction::ToEgress => (relay.origin, relay.target),
                    Direction::FromEgress => (relay.target, relay.origin),
                };
                return t.device.network() == &relay.network
                    && self.projection.device(&t.device).and_then(|d| d.gateway())
                        == Some(self.peers[home].assignment.recipient())
                    && self
                        .projection
                        .egress_route(&relay.network, &t.egress, t.prefix)
                        == Some(self.peers[owner].assignment.recipient());
            }
        };
        if traffic.source.network() != &relay.network
            || traffic.destination.network() != &relay.network
        {
            return false;
        }
        self.projection.forwarding_decision(
            &traffic.source,
            &traffic.destination,
            self.peers[relay.origin].assignment.recipient(),
            self.peers[relay.target].assignment.recipient(),
        ) == Decision::Allow
    }
    fn relay(&mut self, from: usize, kind: u8, body: &[u8], now: Duration) -> Vec<Action> {
        let Some((mut relay, fragment, chunk)) = read_relay(kind, body) else {
            return vec![];
        };
        if kind == 7 {
            if !self
                .projection
                .assignment()
                .networks()
                .contains(&relay.network)
                || !self.peers[from]
                    .assignment
                    .networks()
                    .contains(&relay.network)
            {
                return vec![];
            }
            let (since, count) = self
                .broadcast_fragments
                .entry(relay.network.clone())
                .or_insert((now, 0));
            if now.saturating_sub(*since) >= Duration::from_secs(1) {
                *since = now;
                *count = 0;
            }
            if *count >= 64 {
                return vec![];
            }
            *count += 1;
        }
        if !self.allowed(&relay, from)
            || relay.ttl == 0
            || usize::from(relay.ttl) > self.peers.len()
        {
            return vec![];
        }
        if relay.traffic.is_none()
            && (fragment != 0 || !valid_wire(chunk, false) || relay.total != chunk.len())
        {
            return vec![];
        }
        if relay.traffic.is_some()
            && fragment == 0
            && (chunk.len() < 4 || chunk[..4] != [4, 0, 0, 0])
        {
            return vec![];
        }
        if Some(relay.target) != self.own {
            if relay.ttl <= 1 {
                return vec![];
            }
            relay.ttl -= 1;
            let Some(hop) = self
                .route(relay.target, Some(&relay.network), now)
                .filter(|hop| *hop != from)
            else {
                return vec![];
            };
            return vec![Action::Send {
                node: self.peers[hop].assignment.recipient().clone(),
                packet: relay_packet(self.projection.generation(), &relay, fragment, chunk),
            }];
        }
        let packet = if relay.total <= relay.chunk_size() {
            chunk.to_vec()
        } else {
            self.assemblies.retain(|entry| entry.expires > now);
            let index = if let Some(index) = self.assemblies.iter().position(|entry| {
                entry.header.origin == relay.origin && entry.header.id == relay.id
            }) {
                // TTL belongs to each fragment's path and was checked above.
                // A different remaining hop count can reach the same assembly.
                let header = &self.assemblies[index].header;
                if header.target != relay.target
                    || header.network != relay.network
                    || header.traffic != relay.traffic
                    || header.total != relay.total
                {
                    return vec![];
                }
                index
            } else {
                if (kind == 7
                    && (self
                        .assemblies
                        .iter()
                        .filter(|e| e.header.kind() == 7)
                        .count()
                        >= MAX_ASSEMBLIES / 2
                        || self
                            .assemblies
                            .iter()
                            .filter(|e| e.header.kind() == 7 && e.header.network == relay.network)
                            .count()
                            >= 2))
                    || self.assemblies.len() == MAX_ASSEMBLIES
                    || self
                        .assemblies
                        .iter()
                        .filter(|entry| entry.header.network == relay.network)
                        .count()
                        >= 4
                {
                    return vec![];
                }
                self.assemblies.push(Assembly {
                    header: relay.clone(),
                    first: None,
                    second: None,
                    expires: now + FRAGMENT_LEASE,
                });
                self.assemblies.len() - 1
            };
            let entry = &mut self.assemblies[index];
            let slot = if fragment == 0 {
                &mut entry.first
            } else {
                &mut entry.second
            };
            if slot.is_some() {
                return vec![];
            }
            *slot = Some(chunk.to_vec());
            if entry.first.is_none() || entry.second.is_none() {
                return vec![];
            }
            let entry = self.assemblies.swap_remove(index);
            let mut packet = entry.first.expect("complete assembly");
            packet.extend_from_slice(&entry.second.expect("complete assembly"));
            packet
        };
        if !valid_wire(&packet, relay.traffic.is_some()) {
            return vec![];
        }
        vec![Action::Deliver {
            network: relay.network,
            origin: self.peers[relay.origin].assignment.recipient().clone(),
            packet: PacketBytes(packet),
            traffic: relay.traffic,
        }]
    }
}
fn has(bits: &[u8; BITS], index: usize) -> bool {
    bits[index / 8] & (1 << (index % 8)) != 0
}
fn set(bits: &mut [u8; BITS], index: usize) {
    bits[index / 8] |= 1 << (index % 8);
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|part| u32::from(u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn encode(generation: u64, kind: u8, body: &[u8]) -> PacketBytes {
    encode_with_ttl(generation, kind, body, 64)
}
fn encode_with_ttl(generation: u64, kind: u8, body: &[u8], ttl: u8) -> PacketBytes {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[8] = ttl;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&[10, 254, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 254, 0, 1]);
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&generation.to_le_bytes());
    packet.push(kind);
    packet.extend_from_slice(body);
    let length = packet.len() as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    let check = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&check.to_be_bytes());
    PacketBytes(packet)
}
/// Dispatch only: callers must first authenticate the gateway WireGuard peer.
pub(crate) fn is_packet(packet: &[u8]) -> bool {
    decode(packet).is_some()
}
fn decode(packet: &[u8]) -> Option<(u64, u8, &[u8])> {
    if packet.len() < 34
        || packet.len() > crate::MAX_PLAINTEXT_SIZE
        || packet[0] != 0x45
        || packet[9] != 253
        || packet[6..8] != [0, 0]
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || checksum(&packet[..20]) != 0
        || packet[12..20] != [10, 254, 0, 1, 10, 254, 0, 1]
        || &packet[20..25] != MAGIC
    {
        return None;
    }
    Some((
        u64::from_le_bytes(packet[25..33].try_into().ok()?),
        packet[33],
        &packet[34..],
    ))
}
fn lsa_packet(generation: u64, origin: usize, lsa: &Lsa, hops: u8) -> PacketBytes {
    let mut body = Vec::with_capacity(18 + BITS);
    body.extend_from_slice(&(origin as u16).to_le_bytes());
    body.extend_from_slice(&lsa.boot.to_le_bytes());
    body.extend_from_slice(&lsa.sequence.to_le_bytes());
    body.extend_from_slice(&lsa.neighbors);
    encode_with_ttl(generation, 3, &body, hops)
}
fn valid_wire(packet: &[u8], data: bool) -> bool {
    if packet.len() < 4 || packet.len() > MAX_DATAGRAM_SIZE {
        return false;
    }
    let kind = u32::from_le_bytes(packet[..4].try_into().expect("header"));
    if data {
        kind == 4 && packet.len() > 32 && (packet.len() - 32).is_multiple_of(16)
    } else {
        matches!((kind, packet.len()), (1, 148) | (2, 92) | (3, 64) | (4, 32))
    }
}
fn text(body: &mut Vec<u8>, value: &str) {
    body.push(value.len() as u8);
    body.extend_from_slice(value.as_bytes());
}
fn relay_packet(generation: u64, relay: &Relay, fragment: usize, chunk: &[u8]) -> PacketBytes {
    let mut body = Vec::with_capacity(240 + chunk.len());
    body.extend_from_slice(&relay.id.to_le_bytes());
    body.extend_from_slice(&(relay.origin as u16).to_le_bytes());
    body.extend_from_slice(&(relay.target as u16).to_le_bytes());
    text(&mut body, relay.network.as_str());
    let kind = relay.kind();
    match &relay.traffic {
        Some(MeshTraffic::Broadcast(t)) => {
            text(&mut body, t.source.device().as_str());
            text(&mut body, t.witness.device().as_str());
        }
        Some(MeshTraffic::Device(t)) => {
            text(&mut body, t.source.device().as_str());
            text(&mut body, t.destination.device().as_str());
        }
        Some(MeshTraffic::External(t)) => {
            text(&mut body, t.device.device().as_str());
            text(&mut body, t.egress.as_str());
            match t.prefix.network() {
                std::net::IpAddr::V4(ip) => {
                    body.extend_from_slice(&[4, t.prefix.length()]);
                    body.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    body.extend_from_slice(&[6, t.prefix.length()]);
                    body.extend_from_slice(&ip.octets());
                }
            }
        }
        None => {
            body.extend_from_slice(&[0, 0]);
        }
    };
    body.push(relay.ttl);
    body.push(fragment as u8);
    body.extend_from_slice(&(relay.total as u16).to_le_bytes());
    body.extend_from_slice(chunk);
    encode(generation, kind, &body)
}
fn read_relay(kind: u8, body: &[u8]) -> Option<(Relay, usize, &[u8])> {
    fn name<'a>(bytes: &mut &'a [u8]) -> Option<&'a str> {
        let length = usize::from(*bytes.first()?);
        if length > 64 || bytes.len() < length + 1 {
            return None;
        }
        let name = std::str::from_utf8(&bytes[1..length + 1]).ok()?;
        *bytes = &bytes[length + 1..];
        Some(name)
    }
    if body.len() < 12 {
        return None;
    }
    let id = u64::from_le_bytes(body[..8].try_into().ok()?);
    let origin = usize::from(u16::from_le_bytes(body[8..10].try_into().ok()?));
    let target = usize::from(u16::from_le_bytes(body[10..12].try_into().ok()?));
    let mut rest = &body[12..];
    let network = NetworkId::new(name(&mut rest)?).ok()?;
    let source = name(&mut rest)?;
    let destination = name(&mut rest)?;
    let traffic = match kind {
        7 => Some(MeshTraffic::Broadcast(BroadcastTraffic {
            source: Endpoint::new(network.clone(), DeviceId::new(source).ok()?),
            witness: Endpoint::new(network.clone(), DeviceId::new(destination).ok()?),
        })),
        4 if source.is_empty() && destination.is_empty() => None,
        4 => Some(MeshTraffic::Device(Traffic {
            source: Endpoint::new(network.clone(), DeviceId::new(source).ok()?),
            destination: Endpoint::new(network.clone(), DeviceId::new(destination).ok()?),
        })),
        5 | 6 => {
            let (&family, bytes) = rest.split_first()?;
            let (&len, bytes) = bytes.split_first()?;
            let (address, remaining) = match family {
                4 => {
                    let (ip, remaining) = bytes.split_at_checked(4)?;
                    (
                        std::net::IpAddr::from(<[u8; 4]>::try_from(ip).ok()?),
                        remaining,
                    )
                }
                6 => {
                    let (ip, remaining) = bytes.split_at_checked(16)?;
                    (
                        std::net::IpAddr::from(<[u8; 16]>::try_from(ip).ok()?),
                        remaining,
                    )
                }
                _ => return None,
            };
            let prefix = IpPrefix::new(address, len).ok()?;
            if prefix.network() != address {
                return None;
            }
            rest = remaining;
            Some(MeshTraffic::External(ExternalTraffic {
                direction: if kind == 5 {
                    Direction::ToEgress
                } else {
                    Direction::FromEgress
                },
                device: Endpoint::new(network.clone(), DeviceId::new(source).ok()?),
                egress: EgressId::new(destination).ok()?,
                prefix,
            }))
        }
        _ => return None,
    };
    let size = chunk_size(kind);
    if rest.len() < 4 {
        return None;
    }
    let ttl = rest[0];
    let fragment = usize::from(rest[1]);
    let total = usize::from(u16::from_le_bytes([rest[2], rest[3]]));
    let chunk = &rest[4..];
    if !(32..=MAX_DATAGRAM_SIZE).contains(&total)
        || fragment > 1
        || fragment * size >= total
        || chunk.len() != (total - fragment * size).min(size)
    {
        return None;
    }
    Some((
        Relay {
            id,
            origin,
            target,
            network,
            traffic,
            ttl,
            total,
        },
        fragment,
        chunk,
    ))
}

#[cfg(test)]
mod tests;
