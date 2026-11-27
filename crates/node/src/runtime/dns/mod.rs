//! Tenant-scoped DNS over authenticated WireGuard. No host listener or shared cache.
mod resolver;
mod stack;
#[cfg(test)]
mod tests;

use hickory_proto::op::Message;
use resolver::encode;
use stack::{Stack, Target};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use wgfeel_core::{GatewayProjection, NetworkId};
use wgfeel_wireguard::worker::{DnsSource, LocalError, LocalGateway, WorkerError};

struct Tenant {
    stack: Stack,
    incarnation: u64,
    sources: BTreeMap<IpAddr, DnsSource>,
}
#[derive(Default)]
pub(super) struct Runtime {
    tenants: BTreeMap<NetworkId, Tenant>,
}
impl Runtime {
    pub fn reset(&mut self) {
        self.tenants.clear();
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
                    tenant.stack.discard(request.target);
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
                let reply = resolver::answer(&request.bytes, network, device.id(), projection)
                    .and_then(|reply| encode(&reply, limit));
                if let Some(bytes) = reply {
                    tenant.stack.reply(request.target, &bytes);
                } else {
                    tenant.stack.discard(request.target);
                }
            }
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
