//! Tenant-scoped DNS over authenticated WireGuard. No host listener or shared cache.
mod resolver;
mod stack;
#[cfg(test)]
mod tests;
mod upstream;

use hickory_proto::op::{Message, ResponseCode};
use resolver::{Answer, encode, response};
use stack::{Stack, Target};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use wgfeel_core::{GatewayProjection, NetworkId};
use wgfeel_wireguard::worker::{DnsSource, LocalError, LocalGateway, WorkerError};

struct Tenant {
    stack: Stack,
    incarnation: u64,
    sources: BTreeMap<IpAddr, DnsSource>,
}
struct Pending {
    network: NetworkId,
    target: Target,
    query: Message,
    deadline: Instant,
    limit: Option<usize>,
}
pub(super) struct Runtime {
    tenants: BTreeMap<NetworkId, Tenant>,
    pool: upstream::Pool,
    pending: BTreeMap<u64, Pending>,
    next: u64,
}
impl Runtime {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            tenants: BTreeMap::new(),
            pool: upstream::Pool::new().map_err(|_| "cannot start DNS workers")?,
            pending: BTreeMap::new(),
            next: 0,
        })
    }
    pub fn reset(&mut self) {
        self.tenants.clear();
        self.pending.clear();
        // IDs never restart: late replies cannot attach to a new policy/query.
    }
    pub fn receive(&mut self, source: DnsSource, bytes: &[u8]) {
        let Some((ip, _)) = addresses(bytes) else {
            return;
        };
        let network = source.network().clone();
        if self
            .tenants
            .get(&network)
            .is_some_and(|t| t.incarnation != source.incarnation())
        {
            self.tenants.remove(&network);
            self.pending.retain(|_, pending| pending.network != network);
        }
        if !self.tenants.contains_key(&network) {
            if self.tenants.len() >= wgfeel_core::MAX_NETWORKS {
                return;
            }
            let Ok(seed) = wgfeel_host::random_seed() else {
                return;
            };
            self.tenants.insert(
                network.clone(),
                Tenant {
                    stack: Stack::new(seed),
                    incarnation: source.incarnation(),
                    sources: BTreeMap::new(),
                },
            );
        }
        let tenant = self.tenants.get_mut(&network).expect("just inserted");
        tenant.sources.insert(ip, source);
        tenant.stack.receive(bytes);
    }
    pub fn poll(&mut self, gateway: &mut LocalGateway, now: Duration) {
        self.resolve(gateway.projection(), now);
        // Separate tenant queues: a busy crypto worker cannot block other users.
        for tenant in self.tenants.values_mut() {
            for _ in 0..16 {
                let Some(bytes) = tenant.stack.packets.egress.front() else {
                    break;
                };
                let source =
                    addresses(bytes).and_then(|(_, destination)| tenant.sources.get(&destination));
                if let Some(source) = source
                    && matches!(
                        gateway.send_dns(source, bytes),
                        Err(LocalError::Worker(WorkerError::Busy))
                    )
                {
                    break;
                }
                tenant.stack.packets.egress.pop_front();
            }
        }
    }
    fn resolve(&mut self, projection: &GatewayProjection, now: Duration) {
        for (id, tenant) in &mut self.tenants {
            let Some(network) = projection.config().networks().iter().find(|n| n.id() == id) else {
                continue;
            };
            for request in tenant.stack.poll(now) {
                let source_ip: IpAddr = request.source.into();
                let Some(device) = network
                    .devices()
                    .iter()
                    .find(|d| d.addresses().contains(&source_ip))
                else {
                    continue;
                };
                let limit = match request.target {
                    Target::Tcp { .. } => None,
                    Target::Udp { .. } => Some(
                        Message::from_vec(&request.bytes)
                            .ok()
                            .and_then(|m| {
                                m.edns
                                    .map(|e| usize::from(e.max_payload()).clamp(512, 1232))
                            })
                            .unwrap_or(512),
                    ),
                };
                match resolver::answer(&request.bytes, network, device.id(), projection) {
                    Some(Answer::Local(reply)) => {
                        if let Some(bytes) = encode(&reply, limit) {
                            tenant.stack.reply(request.target, &bytes);
                        }
                    }
                    Some(Answer::Forward(query)) => {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        let job = upstream::Job {
                            id: self.next,
                            query: query.clone(),
                            servers: network.dns_upstreams().to_vec(),
                            deadline,
                        };
                        let allowed = self.pending.len() < 64
                            && self.pending.values().filter(|p| &p.network == id).count() < 8;
                        if self.next < u64::MAX && allowed && self.pool.jobs.try_send(job).is_ok() {
                            self.pending.insert(
                                self.next,
                                Pending {
                                    network: id.clone(),
                                    target: request.target,
                                    query,
                                    deadline,
                                    limit,
                                },
                            );
                            self.next += 1;
                        } else if let Some(bytes) =
                            encode(&response(&query, ResponseCode::ServFail), limit)
                        {
                            tenant.stack.reply(request.target, &bytes);
                        }
                    }
                    None => {}
                }
            }
        }
        for _ in 0..64 {
            let Ok(result) = self.pool.results.try_recv() else {
                break;
            };
            if let Some(pending) = self.pending.remove(&result.id) {
                self.complete(pending, result.response);
            }
        }
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| Instant::now() >= p.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(pending) = self.pending.remove(&id) {
                self.complete(pending, None);
            }
        }
    }
    fn complete(&mut self, pending: Pending, reply: Option<Message>) {
        let Some(tenant) = self.tenants.get_mut(&pending.network) else {
            return;
        };
        let reply = reply.unwrap_or_else(|| response(&pending.query, ResponseCode::ServFail));
        if let Some(bytes) = encode(&reply, pending.limit) {
            tenant.stack.reply(pending.target, &bytes);
        }
    }
}
fn addresses(bytes: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match bytes.first()? >> 4 {
        4 => Some((
            Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(12..16)?).ok()?).into(),
            Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(16..20)?).ok()?).into(),
        )),
        6 => Some((
            Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?).into(),
            Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(24..40)?).ok()?).into(),
        )),
        _ => None,
    }
}
