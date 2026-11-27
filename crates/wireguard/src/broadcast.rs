//! Directed UDP validation, per-entry quotas and incremental recipient selection.
use crate::{
    ForwardError, PacketBytes, PeerId,
    framing::{self, finish, sum},
    mesh::BroadcastTraffic,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use wgfeel_core::{
    Destination, DeviceId, Endpoint, GatewayProjection, INTERNAL_BROADCAST_IPV4, NetworkId, NodeId,
};

pub(crate) const BATCH: usize = 8;
pub(crate) const MAX_JOBS: usize = 16;
const SCAN: usize = 32;
const LEASE: Duration = Duration::from_millis(250);

/// Validated original IP packet. Scratch rewrites cannot alter the parked original.
#[derive(Debug)]
pub(crate) struct Packet(PacketBytes);
impl Packet {
    pub fn new(packet: PacketBytes, source: Ipv4Addr) -> Result<Self, ForwardError> {
        let b = packet.as_bytes();
        framing::ip_length(b, false).map_err(|_| ForwardError::InvalidPacket)?;
        if b.len() < 28
            || b[0] != 0x45
            || b[9] != 17
            || u16::from_be_bytes([b[6], b[7]]) & !0x4000 != 0
        {
            return Err(ForwardError::UnsupportedPacket);
        }
        if b[8] == 0 {
            return Err(ForwardError::HopLimitExceeded);
        }
        if b[12..16] != source.octets() || b[16..20] != INTERNAL_BROADCAST_IPV4.octets() {
            return Err(ForwardError::SourceMismatch);
        }
        if finish(sum(&b[..20])) != 0
            || usize::from(u16::from_be_bytes([b[24], b[25]])) != b.len() - 20
            || b[22..24] == [0, 0]
            || (b[26..28] != [0, 0] && udp_checksum(b) != 0)
        {
            return Err(ForwardError::InvalidPacket);
        }
        Ok(Self(packet))
    }
    pub fn into_bytes(self) -> PacketBytes {
        self.0
    }
    pub fn original(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn unicast(&self, target: Ipv4Addr) -> PacketBytes {
        let mut copy = PacketBytes(self.original().to_vec());
        let b = &mut copy.0;
        b[16..20].copy_from_slice(&target.octets());
        b[10..12].fill(0);
        let ip = finish(sum(&b[..20]));
        b[10..12].copy_from_slice(&ip.to_be_bytes());
        if b[26..28] != [0, 0] {
            b[26..28].fill(0);
            let checksum = udp_checksum(b);
            b[26..28]
                .copy_from_slice(&(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes());
        }
        copy
    }
}
fn udp_checksum(b: &[u8]) -> u16 {
    finish(sum(&b[12..20]) + 17 + u32::from(u16::from_be_bytes([b[24], b[25]])) + sum(&b[20..]))
}

const TOKEN: u64 = 1_000_000_000;
#[derive(Debug)]
pub(crate) struct Bucket {
    credit: u64,
    at: Instant,
}
impl Bucket {
    pub fn full(burst: u32, now: Instant) -> Self {
        Self {
            credit: u64::from(burst) * TOKEN,
            at: now,
        }
    }
    pub fn take(&mut self, rate: u32, burst: u32, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at);
        self.at = now;
        let cap = u64::from(burst) * TOKEN;
        self.credit = (u128::from(self.credit) + elapsed.as_nanos() * u128::from(rate))
            .min(u128::from(cap)) as u64;
        if self.credit < TOKEN {
            return false;
        }
        self.credit -= TOKEN;
        true
    }
}
#[derive(Debug, Default)]
pub(crate) struct Limits {
    sources: BTreeMap<(NetworkId, DeviceId), Bucket>,
    networks: BTreeMap<NetworkId, Bucket>,
    copies: BTreeMap<NetworkId, Bucket>,
}
impl Limits {
    pub fn update(&mut self, projection: &GatewayProjection, same_authority: bool) {
        if !same_authority {
            *self = Self::default();
            return;
        }
        let assigned = projection.assignment().networks();
        self.sources.retain(|(n, d), _| {
            assigned.contains(n)
                && projection
                    .device(&Endpoint::new(n.clone(), d.clone()))
                    .is_some()
        });
        self.networks.retain(|n, _| assigned.contains(n));
        self.copies.retain(|n, _| assigned.contains(n));
    }
    fn admit(&mut self, source: &Endpoint, now: Instant) -> bool {
        let sender = self
            .sources
            .entry((source.network().clone(), source.device().clone()))
            .or_insert_with(|| Bucket::full(8, now));
        if !sender.take(4, 8, now) {
            return false;
        }
        if self
            .networks
            .entry(source.network().clone())
            .or_insert_with(|| Bucket::full(32, now))
            .take(16, 32, now)
        {
            return true;
        }
        sender.credit += TOKEN;
        false
    }
    pub fn charge_batch(
        &mut self,
        network: &NetworkId,
        targets: &mut Vec<Target>,
        now: Instant,
    ) -> bool {
        let available = (0..targets.len())
            .take_while(|_| self.copy(network, now))
            .count();
        let exhausted = available < targets.len();
        targets.truncate(available);
        exhausted
    }
    fn copy(&mut self, network: &NetworkId, now: Instant) -> bool {
        self.copies
            .entry(network.clone())
            .or_insert_with(|| Bucket::full(750, now))
            .take(1024, 750, now)
    }
}
#[derive(Debug)]
pub(crate) struct Target {
    pub peer: PeerId,
    pub rewrite: Option<Ipv4Addr>,
    pub label: Option<BroadcastTraffic>,
}
#[derive(Debug)]
pub(crate) struct Scan {
    pub source: Endpoint,
    origin: NodeId,
    pub expires: Instant,
    cursor: usize,
    sent: BTreeSet<NodeId>,
}
impl Scan {
    pub fn start(
        projection: &GatewayProjection,
        source: Endpoint,
        origin: &NodeId,
        packet: PacketBytes,
        limits: &mut Limits,
        now: Instant,
    ) -> Result<(Self, Packet), ForwardError> {
        let device = projection
            .device(&source)
            .ok_or(ForwardError::SourceMismatch)?;
        if device.gateway().unwrap_or(projection.recipient()) != origin
            || projection.classify_destination(&source, INTERNAL_BROADCAST_IPV4.into())
                != Destination::Broadcast
            || !projection
                .assignment()
                .tenants()
                .iter()
                .any(|t| t.network() == source.network())
        {
            return Err(ForwardError::Denied);
        }
        let packet = Packet::new(
            packet,
            device.internal_ipv4().ok_or(ForwardError::SourceMismatch)?,
        )?;
        if !limits.admit(&source, now) {
            return Err(ForwardError::Denied);
        }
        Ok((
            Self {
                source,
                origin: origin.clone(),
                expires: now + LEASE,
                cursor: 0,
                sent: BTreeSet::new(),
            },
            packet,
        ))
    }
    /// At most one encryption per remote entry. Remote ingress terminates locally.
    pub fn next(
        &mut self,
        projection: &GatewayProjection,
        online: impl Fn(&PeerId) -> bool,
        remote: bool,
        now: Instant,
    ) -> (Vec<Target>, bool) {
        let mut targets = vec![];
        if now >= self.expires {
            return (targets, true);
        }
        let Some(network) = projection
            .config()
            .networks()
            .iter()
            .find(|n| n.id() == self.source.network())
        else {
            return (targets, true);
        };
        let own = projection.recipient();
        for device in network.devices().iter().skip(self.cursor).take(SCAN) {
            self.cursor += 1;
            let home = device.gateway().unwrap_or(own);
            if home != own && (!remote || &self.origin != own || self.sent.contains(home)) {
                continue;
            }
            let dest = Endpoint::new(network.id().clone(), device.id().clone());
            if !projection.broadcast_recipient(&self.source, &dest, &self.origin, home) {
                continue;
            }
            let peer = if home == own {
                PeerId::Device(device.id().clone())
            } else {
                PeerId::Gateway(home.clone())
            };
            if !online(&peer) {
                continue;
            }
            targets.push(if home == own {
                Target {
                    peer,
                    rewrite: device.internal_ipv4(),
                    label: None,
                }
            } else {
                self.sent.insert(home.clone());
                Target {
                    peer,
                    rewrite: None,
                    label: Some(BroadcastTraffic {
                        source: self.source.clone(),
                        witness: dest,
                    }),
                }
            });
            if targets.len() == BATCH {
                break;
            }
        }
        (targets, self.cursor == network.devices().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(user: &str, id: usize) -> Endpoint {
        Endpoint::new(
            NetworkId::new(user).unwrap(),
            DeviceId::new(&format!("dev-{id}")).unwrap(),
        )
    }
    #[test]
    fn policy_revision_preserves_surviving_balances_and_authority_change_resets_them() {
        use wgfeel_core::{Config, Device, DevicePublicKey, Network, Policy, TenantKeyAssignment};
        let t = Instant::now();
        let a = endpoint("a", 0);
        let removed = endpoint("a", 1);
        let b = endpoint("b", 0);
        let mut limits = Limits::default();
        for _ in 0..8 {
            for ep in [&a, &removed, &b] {
                assert!(limits.admit(ep, t));
            }
        }
        for _ in 0..750 {
            assert!(limits.copy(a.network(), t));
        }
        let key = DevicePublicKey::new([82; 32]).unwrap();
        let device =
            Device::new(a.device().clone(), key, vec!["10.203.0.3".parse().unwrap()]).unwrap();
        let cfg = Config::new(
            2,
            vec![Network::new(a.network().clone(), vec![device]).unwrap()],
            Policy::new(vec![], vec![], vec![]),
        )
        .unwrap();
        let projection = wgfeel_test_support::fixture_projection(
            &cfg,
            &NodeId::new("entry").unwrap(),
            &wgfeel_test_support::fixture_node_keys([45; 32]),
            vec![TenantKeyAssignment::new(
                a.network().clone(),
                DevicePublicKey::new([81; 32]).unwrap(),
            )],
        );
        limits.update(&projection, true);
        assert!(!limits.admit(&a, t));
        assert!(!limits.copy(a.network(), t));
        assert_eq!(limits.sources.len(), 1);
        assert_eq!(limits.networks.len(), 1);
        limits.update(&projection, false);
        assert!(limits.admit(&a, t));
        assert!(limits.copy(a.network(), t));
    }

    #[test]
    fn monotonic_quotas_bound_sources_networks_and_physical_copies() {
        let t = Instant::now();
        let mut limits = Limits::default();
        let a = endpoint("a", 0);
        for i in 0..8 {
            assert!(limits.admit(&a, t), "packet {i}");
        }
        assert!(!limits.admit(&a, t + Duration::from_millis(249)));
        assert!(limits.admit(&a, t + Duration::from_millis(250)));
        for i in 0..32 {
            assert!(limits.admit(&endpoint("b", i), t));
        }
        assert!(!limits.admit(&endpoint("b", 32), t));
        assert!(limits.admit(&endpoint("b", 32), t + Duration::from_millis(63)));
        for _ in 0..750 {
            assert!(limits.copy(a.network(), t));
        }
        assert!(!limits.copy(a.network(), t));
        assert!(limits.copy(a.network(), t + Duration::from_millis(1)));
        assert!(!limits.copy(a.network(), t + Duration::from_millis(1)));
    }
}
