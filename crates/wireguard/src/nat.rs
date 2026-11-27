//! Same-family, symmetric NAPT after tenant and route authorization. Only the
//! designated entry calls this table. Protocols never allocate from inbound
//! traffic. A routed ICMP error must quote an existing mapping.
use crate::PacketBytes;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};
use wgfeel_core::{DeviceId, EgressId, EgressProfile, Endpoint, IpPrefix, NetworkId, NodeId};
use wire::{ACK, Body, FIN, Flow, Packet, Protocol, RST, SYN};
#[cfg(test)]
mod tests;
mod wire;

const MAX_PER_NETWORK: usize = 1024;
const MAX_PER_EGRESS: usize = 16_384;
const MAX_PER_NODE: usize = 65_536;
const FIRST_PORT: u16 = 49_152;
const MAX_PROBES: usize = 128;
const REUSE_DELAY: Duration = Duration::from_secs(120);
const PMTU_BURST: u8 = 16;

/// The logical source and LPM result authenticated by the gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatBinding {
    pub device: Endpoint,
    pub home: NodeId,
    pub inside: IpAddr,
    pub prefix: IpPrefix,
}
#[derive(Debug)]
pub enum NatAction {
    ToProvider(PacketBytes),
    ToDevice {
        binding: NatBinding,
        remote: IpAddr,
        packet: PacketBytes,
    },
}

/// Destination of the original flow, for checking the active return route at
/// the home entry. Related errors can come from an intermediate router.
pub(crate) fn return_remote(bytes: &[u8]) -> Option<IpAddr> {
    Packet::delivery_remote(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ForwardKey {
    egress: EgressId,
    network: NetworkId,
    device: DeviceId,
    proto: Protocol,
    inside: IpAddr,
    inside_port: u16,
    remote: IpAddr,
    remote_port: u16,
}
impl ForwardKey {
    fn new(
        egress: &EgressId,
        binding: &NatBinding,
        remote: IpAddr,
        flow: Flow,
        outbound: bool,
    ) -> Option<Self> {
        let (inside_port, remote_port) = flow.tuple(outbound)?;
        Some(Self {
            egress: egress.clone(),
            network: binding.device.network().clone(),
            device: binding.device.device().clone(),
            proto: flow.protocol,
            inside: binding.inside,
            inside_port,
            remote,
            remote_port,
        })
    }
}

/// Allocate the translated port exclusively within this egress, family and
/// transport. The reverse index also checks the exact remote address and port
/// in the indexed forward key before restoring the logical device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Slot {
    egress: EgressId,
    ip: IpAddr,
    proto: Protocol,
    port: u16,
}
#[derive(Clone, Copy, Debug)]
enum State {
    Udp,
    Echo,
    SynSent,
    SynReceived,
    Established,
    Closing,
}
impl State {
    fn open(flow: Flow) -> Option<Self> {
        match flow.protocol {
            Protocol::Udp => Some(Self::Udp),
            Protocol::Echo => Some(Self::Echo),
            Protocol::Tcp if flow.flags & (SYN | ACK | FIN | RST) == SYN => Some(Self::SynSent),
            _ => None,
        }
    }
    fn advance(self, flow: Flow, outbound: bool) -> Option<Self> {
        if flow.protocol != Protocol::Tcp {
            return Some(self);
        }
        let flags = flow.flags;
        if flags & RST != 0 {
            return Some(Self::Closing);
        }
        match self {
            Self::SynSent | Self::SynReceived if outbound && flags & (SYN | ACK | FIN) == SYN => {
                Some(self)
            }
            Self::SynSent | Self::SynReceived
                if !outbound && flags & (SYN | ACK | FIN) == (SYN | ACK) =>
            {
                Some(Self::SynReceived)
            }
            Self::SynReceived if outbound && flags & (ACK | SYN) == ACK => {
                Some(if flags & FIN != 0 {
                    Self::Closing
                } else {
                    Self::Established
                })
            }
            Self::SynSent | Self::SynReceived => None,
            Self::Established if flags & FIN != 0 => Some(Self::Closing),
            Self::Closing if flags & SYN != 0 => None,
            _ => Some(self),
        }
    }
    fn timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::Udp | Self::Closing => 120,
            Self::Echo => 30,
            Self::SynSent | Self::SynReceived => 60,
            Self::Established => 7200,
        })
    }
}
struct Mapping {
    binding: NatBinding,
    slot: Slot,
    state: State,
    expiration: Instant,
}

pub struct NatTable {
    forward: BTreeMap<ForwardKey, Mapping>,
    reverse: BTreeMap<Slot, ForwardKey>,
    deadlines: BTreeSet<(Instant, ForwardKey)>,
    users: BTreeMap<NetworkId, usize>,
    egress_counts: BTreeMap<EgressId, usize>,
    quarantine: BTreeSet<Slot>,
    reusable: VecDeque<(Instant, Slot)>,
    next_port: u16,
    pmtu_window: Option<Instant>,
    pmtu_count: u8,
}
impl std::fmt::Debug for NatTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatTable")
            .field("live_mappings", &self.forward.len())
            .field("quarantined_slots", &self.quarantine.len())
            .finish_non_exhaustive()
    }
}
impl Default for NatTable {
    fn default() -> Self {
        Self {
            forward: BTreeMap::new(),
            reverse: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            users: BTreeMap::new(),
            egress_counts: BTreeMap::new(),
            quarantine: BTreeSet::new(),
            reusable: VecDeque::new(),
            next_port: FIRST_PORT,
            pmtu_window: None,
            pmtu_count: 0,
        }
    }
}

impl NatTable {
    /// Expiration uses a monotonic clock. Due tuples remain protected even if
    /// policy changes immediately release their live mappings.
    pub fn expire(&mut self, now: Instant) {
        while self.reusable.front().is_some_and(|(when, _)| *when <= now) {
            if let Some((_, slot)) = self.reusable.pop_front() {
                self.quarantine.remove(&slot);
            }
        }
        while let Some((deadline, key)) = self.deadlines.first() {
            if *deadline > now {
                break;
            }
            let key = key.clone();
            self.remove(&key, now);
        }
    }
    /// Destroy one provider incarnation. Its worker and connected socket are
    /// retired, so even previously quarantined tuples no longer need a lease.
    pub fn discard_egress(&mut self, egress: &EgressId) {
        self.forward.retain(|key, _| {
            if &key.egress == egress {
                decrement(&mut self.users, &key.network);
                false
            } else {
                true
            }
        });
        self.egress_counts.remove(egress);
        self.reverse.retain(|slot, _| &slot.egress != egress);
        self.deadlines.retain(|(_, key)| &key.egress != egress);
        self.quarantine.retain(|slot| &slot.egress != egress);
        self.reusable.retain(|(_, slot)| &slot.egress != egress);
    }
    /// Run on policy activation. The caller checks the original device, home,
    /// inside address, winning prefix and external session against the new
    /// active revision. Unaffected users retain their TCP and UDP state.
    pub fn retain(
        &mut self,
        now: Instant,
        mut keep: impl FnMut(&EgressId, &NatBinding, IpAddr) -> bool,
    ) {
        self.expire(now);
        let removed: Vec<_> = self
            .forward
            .iter()
            .filter(|(k, m)| !keep(&k.egress, &m.binding, k.remote))
            .map(|(k, _)| k.clone())
            .collect();
        for key in removed {
            self.remove(&key, now);
        }
    }
    fn remove(&mut self, key: &ForwardKey, now: Instant) {
        let Some(mapping) = self.forward.remove(key) else {
            return;
        };
        self.deadlines.remove(&(mapping.expiration, key.clone()));
        self.reverse.remove(&mapping.slot);
        self.quarantine.insert(mapping.slot.clone());
        self.reusable.push_back((now + REUSE_DELAY, mapping.slot));
        decrement(&mut self.users, &key.network);
        decrement(&mut self.egress_counts, &key.egress);
    }
    fn room(&self, key: &ForwardKey) -> bool {
        self.forward.len() + self.quarantine.len() < MAX_PER_NODE
            && self.users.get(&key.network).copied().unwrap_or_default() < MAX_PER_NETWORK
            && self
                .egress_counts
                .get(&key.egress)
                .copied()
                .unwrap_or_default()
                < MAX_PER_EGRESS
    }
    fn allocate(&mut self, key: &ForwardKey, translated: IpAddr) -> Option<Slot> {
        if !self.room(key) {
            return None;
        }
        let mut slot = Slot {
            egress: key.egress.clone(),
            ip: translated,
            proto: key.proto,
            port: self.next_port,
        };
        for _ in 0..MAX_PROBES {
            slot.port = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(FIRST_PORT);
            if !self.reverse.contains_key(&slot) && !self.quarantine.contains(&slot) {
                return Some(slot);
            }
        }
        None
    }
    fn refresh(&mut self, key: &ForwardKey, state: State, now: Instant) -> Option<()> {
        let map = self.forward.get_mut(key)?;
        self.deadlines.remove(&(map.expiration, key.clone()));
        map.state = state;
        map.expiration = now + state.timeout();
        self.deadlines.insert((map.expiration, key.clone()));
        Some(())
    }
    fn lookup(
        &self,
        egress: &EgressId,
        external: IpAddr,
        remote: IpAddr,
        flow: Flow,
        outbound: bool,
    ) -> Option<&ForwardKey> {
        let (port, remote_port) = flow.tuple(outbound)?;
        let id = self.reverse.get(&Slot {
            egress: egress.clone(),
            ip: external,
            proto: flow.protocol,
            port,
        })?;
        (id.remote == remote && id.remote_port == remote_port).then_some(id)
    }
    fn too_big(
        &mut self,
        pkt: Packet,
        bytes: &[u8],
        router: IpAddr,
        mtu: u16,
        now: Instant,
    ) -> Option<PacketBytes> {
        if self
            .pmtu_window
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
        {
            self.pmtu_window = Some(now);
            self.pmtu_count = 0;
        }
        if self.pmtu_count >= PMTU_BURST {
            return None;
        }
        let packet = pkt.pmtu_error(bytes, router, mtu)?;
        self.pmtu_count += 1;
        Some(PacketBytes(packet))
    }
    /// The caller binds the decrypted source to the authenticated device and
    /// authorizes the remote destination before invoking this operation.
    pub fn outbound(
        &mut self,
        profile: &EgressProfile,
        binding: &NatBinding,
        bytes: &[u8],
        path_mtu: u16,
        now: Instant,
    ) -> Option<NatAction> {
        let pkt = Packet::parse(bytes)?;
        if pkt.ip.src != binding.inside
            || profile.addresses.contains(&pkt.ip.dst)
            || !binding.prefix.contains(pkt.ip.dst)
            || !profile
                .allowed_ips
                .iter()
                .any(|prefix| prefix.contains(pkt.ip.dst))
        {
            return None;
        }
        let translated = *profile
            .addresses
            .iter()
            .find(|addr| addr.is_ipv4() == pkt.ip.src.is_ipv4())?;
        let mtu = inner_mtu(profile, path_mtu, translated)?;
        self.expire(now);
        let flow = match pkt.body {
            Body::Flow(flow) => flow,
            Body::Related => {
                if bytes.len() > usize::from(mtu) {
                    return None;
                }
                let quote = Packet::quoted(&bytes[pkt.ip.offset + 8..])?;
                if quote.ip.dst != binding.inside || quote.ip.src != pkt.ip.dst {
                    return None;
                }
                let Body::Flow(inner) = quote.body else {
                    return None;
                };
                let key = ForwardKey::new(&profile.id, binding, quote.ip.src, inner, false)?;
                let mapping = self.forward.get(&key)?;
                if mapping.binding != *binding || mapping.slot.ip != translated {
                    return None;
                }
                return Some(NatAction::ToProvider(PacketBytes(pkt.translate_error(
                    bytes,
                    quote,
                    true,
                    translated,
                    mapping.slot.port,
                ))));
            }
        };
        let key = ForwardKey::new(&profile.id, binding, pkt.ip.dst, flow, true)?;
        let existing = self.forward.get(&key);
        let state = if let Some(entry) = existing {
            if entry.binding != *binding || entry.slot.ip != translated {
                return None;
            }
            entry.state.advance(flow, true)?
        } else {
            State::open(flow)?
        };
        if bytes.len() > usize::from(mtu) {
            // The device's home peer always covers its internal address pool,
            // even when a split egress grant excludes the provider tunnel IP.
            let gateway = match binding.inside {
                IpAddr::V4(_) => IpAddr::V4(wgfeel_core::DNS_IPV4),
                IpAddr::V6(_) => IpAddr::V6(wgfeel_core::DNS_IPV6),
            };
            return Some(NatAction::ToDevice {
                binding: binding.clone(),
                remote: pkt.ip.dst,
                packet: self.too_big(pkt, bytes, gateway, mtu, now)?,
            });
        }
        let port = if let Some(entry) = existing {
            let port = entry.slot.port;
            self.refresh(&key, state, now)?;
            port
        } else {
            let slot = self.allocate(&key, translated)?;
            let port = slot.port;
            let expiration = now + state.timeout();
            self.reverse.insert(slot.clone(), key.clone());
            self.deadlines.insert((expiration, key.clone()));
            *self.users.entry(key.network.clone()).or_default() += 1;
            *self.egress_counts.entry(key.egress.clone()).or_default() += 1;
            self.forward.insert(
                key,
                Mapping {
                    binding: binding.clone(),
                    slot,
                    state,
                    expiration,
                },
            );
            port
        };
        Some(NatAction::ToProvider(PacketBytes(
            pkt.translate(bytes, true, translated, port, mtu),
        )))
    }
    /// Called only for authenticated plaintext from this profile's provider.
    /// `remote` in a ToDevice result names the original routed destination,
    /// including when an intermediate router sent a related ICMP error.
    pub fn inbound(
        &mut self,
        profile: &EgressProfile,
        bytes: &[u8],
        path_mtu: u16,
        now: Instant,
    ) -> Option<NatAction> {
        let pkt = Packet::parse(bytes)?;
        if !profile.addresses.contains(&pkt.ip.dst) || profile.addresses.contains(&pkt.ip.src) {
            return None;
        }
        let mtu = inner_mtu(profile, path_mtu, pkt.ip.dst)?;
        self.expire(now);
        let (key, quote) = match pkt.body {
            Body::Flow(flow) => (
                self.lookup(&profile.id, pkt.ip.dst, pkt.ip.src, flow, false)?
                    .clone(),
                None,
            ),
            Body::Related => {
                let quote = Packet::quoted(&bytes[pkt.ip.offset + 8..])?;
                let Body::Flow(inner) = quote.body else {
                    return None;
                };
                if quote.ip.src != pkt.ip.dst {
                    return None;
                }
                (
                    self.lookup(&profile.id, quote.ip.src, quote.ip.dst, inner, true)?
                        .clone(),
                    Some(quote),
                )
            }
        };
        let entry = self.forward.get(&key)?;
        let binding = entry.binding.clone();
        let state = match pkt.body {
            Body::Flow(flow) => Some(entry.state.advance(flow, false)?),
            Body::Related => None,
        };
        if bytes.len() > usize::from(mtu) {
            return Some(NatAction::ToProvider(
                self.too_big(pkt, bytes, pkt.ip.dst, mtu, now)?,
            ));
        }
        let packet = if let Some(quote) = quote {
            pkt.translate_error(bytes, quote, false, key.inside, key.inside_port)
        } else {
            self.refresh(&key, state?, now)?;
            pkt.translate(bytes, false, key.inside, key.inside_port, mtu)
        };
        Some(NatAction::ToDevice {
            binding,
            remote: key.remote,
            packet: PacketBytes(packet),
        })
    }
}

fn inner_mtu(profile: &EgressProfile, path: u16, addr: IpAddr) -> Option<u16> {
    let mtu = path.min(profile.mtu.unwrap_or(1280)).min(1280);
    (mtu >= if addr.is_ipv4() { 68 } else { 1280 }).then_some(mtu)
}
fn decrement<K: Ord>(counts: &mut BTreeMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}
