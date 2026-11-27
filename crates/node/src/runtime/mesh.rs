//! Bounded scheduling for local mesh state; queued user bytes remain encrypted.
use std::{collections::VecDeque, time::Duration};
use wgfeel_core::{GatewayProjection, NodeId};
use wgfeel_wireguard::{
    ContextId, PeerId, UdpListener,
    mesh::{Action, Mesh},
    worker::{LocalError, LocalEvent, LocalGateway, WorkerError, WorkerLease},
};

const BROADCAST_QUEUE: usize = 32;
type Queued = (Duration, Action, Option<WorkerLease>);
const QUEUE: usize = 1024;
pub(super) struct Runtime {
    mesh: Mesh,
    pending: VecDeque<Queued>,
    broadcasts: VecDeque<Queued>,
    tenant_peers: Vec<(ContextId, NodeId, std::net::SocketAddr, Duration)>,
    cursor: usize,
}
impl Runtime {
    pub fn new(projection: &GatewayProjection) -> Result<Self, &'static str> {
        let mut tenant_peers = vec![];
        for tenant in projection.assignment().tenants() {
            for node in projection
                .mesh()
                .iter()
                .filter(|node| node.recipient() != projection.recipient())
            {
                if node
                    .tenants()
                    .iter()
                    .any(|remote| remote.network() == tenant.network())
                    && let Some(endpoint) = node.endpoint()
                {
                    tenant_peers.push((
                        ContextId::Tenant(tenant.network().clone()),
                        node.recipient().clone(),
                        endpoint,
                        Duration::ZERO,
                    ));
                }
            }
        }
        Ok(Self {
            mesh: Mesh::new(projection, wgfeel_host::random_seed()?),
            pending: VecDeque::with_capacity(QUEUE),
            broadcasts: VecDeque::with_capacity(BROADCAST_QUEUE),
            tenant_peers,
            cursor: 0,
        })
    }
    pub fn clear_broadcast_assemblies(&mut self) {
        self.mesh.clear_broadcast_assemblies();
    }
    pub fn replacement(&self, projection: &GatewayProjection) -> Result<Self, &'static str> {
        let mut next = Self::new(projection)?;
        next.mesh.inherit_health(&self.mesh);
        Ok(next)
    }
    pub fn event(&mut self, event: LocalEvent, now: Duration, gateway: &LocalGateway) {
        let (actions, lease) = match event {
            LocalEvent::Mesh { peer, packet } => {
                let Ok(Some(endpoint)) =
                    gateway.endpoint(&ContextId::Gateway, &PeerId::Node(peer.clone()))
                else {
                    return;
                };
                (
                    self.mesh.receive(&peer, endpoint, packet.as_bytes(), now),
                    gateway.worker_lease(&ContextId::Gateway),
                )
            }
            LocalEvent::MeshOutput {
                network,
                peer,
                packet,
                traffic,
                provenance,
            } => (
                self.mesh
                    .transmit_scoped(&network, &peer, packet.as_bytes(), traffic, now),
                provenance,
            ),
            _ => return,
        };
        self.enqueue(actions, now, lease);
    }
    fn enqueue(&mut self, actions: Vec<Action>, now: Duration, lease: Option<WorkerLease>) {
        for action in actions {
            if action.is_broadcast() {
                if self.broadcasts.len() < BROADCAST_QUEUE && lease.is_some() {
                    self.broadcasts.push_back((
                        now + Duration::from_millis(250),
                        action,
                        lease.clone(),
                    ));
                }
            } else if self.pending.len() < QUEUE {
                self.pending
                    .push_back((now + Duration::from_secs(1), action, None));
            }
        }
    }
    pub fn poll(&mut self, gateway: &mut LocalGateway, socket: &UdpListener, now: Duration) {
        let actions = self.mesh.tick(now);
        self.enqueue(actions, now, None);
        let normal = self.pending.len().min(super::BATCH);
        let low = self.broadcasts.len().min(2);
        for i in 0..normal + low {
            let queue = if i < normal {
                &mut self.pending
            } else {
                &mut self.broadcasts
            };
            let (expires, action, lease) = queue.pop_front().expect("bounded queue");
            if now >= expires || lease.as_ref().is_some_and(|l| !gateway.lease_active(l)) {
                continue;
            }
            let result = match &action {
                Action::Initiate { node, endpoint } => {
                    gateway.initiate_at(&ContextId::Gateway, &PeerId::Node(node.clone()), *endpoint)
                }
                Action::Send { node, packet } => {
                    gateway.send_mesh_scoped(node, packet.as_bytes(), lease.as_ref())
                }
                Action::Wire { endpoint, packet } => {
                    let _ = socket.send_to(packet.as_bytes(), *endpoint);
                    Ok(())
                }
                Action::Deliver {
                    network,
                    origin,
                    packet,
                    traffic,
                } => {
                    match gateway.receive_mesh(network, origin, packet.as_bytes(), traffic.clone())
                    {
                        Ok(Some(event)) => {
                            self.event(event, now, gateway);
                            Ok(())
                        }
                        Ok(None) => Ok(()),
                        Err(error) => Err(error),
                    }
                }
            };
            if matches!(result, Err(LocalError::Worker(WorkerError::Busy))) {
                let queue = if lease.is_some() {
                    &mut self.broadcasts
                } else {
                    &mut self.pending
                };
                queue.push_back((expires, action, lease));
            }
        }
        // Rotate across tenant contexts so one busy worker cannot starve others.
        // Periodic handshakes also recover a peer restarted with the same keys.
        for _ in 0..self.tenant_peers.len().min(super::BATCH) {
            let (context, node, endpoint, due) = &mut self.tenant_peers[self.cursor];
            if now >= *due
                && self.mesh.next_hop(node, now).is_some()
                && !matches!(
                    gateway.initiate_at(context, &PeerId::Gateway(node.clone()), *endpoint),
                    Err(LocalError::Worker(WorkerError::Busy))
                )
            {
                *due = now + Duration::from_secs(15);
            }
            self.cursor = (self.cursor + 1) % self.tenant_peers.len();
        }
    }
}
