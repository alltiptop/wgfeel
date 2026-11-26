//! Bounded scheduling for local mesh state; queued user bytes remain encrypted.
use std::{collections::VecDeque, time::Duration};
use wgfeel_core::{GatewayProjection, NodeId};
use wgfeel_wireguard::{
    ContextId, PeerId, UdpListener,
    mesh::{Action, Mesh},
    worker::{LocalError, LocalEvent, LocalGateway, WorkerError},
};

const QUEUE: usize = 1024;
pub(super) struct Runtime {
    mesh: Mesh,
    pending: VecDeque<(Duration, Action)>,
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
            tenant_peers,
            cursor: 0,
        })
    }
    pub fn event(&mut self, event: LocalEvent, now: Duration, gateway: &LocalGateway) {
        let actions = match event {
            LocalEvent::Mesh { peer, packet } => {
                let Ok(Some(endpoint)) =
                    gateway.endpoint(&ContextId::Gateway, &PeerId::Node(peer.clone()))
                else {
                    return;
                };
                self.mesh.receive(&peer, endpoint, packet.as_bytes(), now)
            }
            LocalEvent::MeshOutput {
                network,
                peer,
                packet,
                traffic,
            } => self
                .mesh
                .transmit(&network, &peer, packet.as_bytes(), traffic, now),
            _ => return,
        };
        self.enqueue(actions, now);
    }
    fn enqueue(&mut self, actions: Vec<Action>, now: Duration) {
        for action in actions
            .into_iter()
            .take(QUEUE.saturating_sub(self.pending.len()))
        {
            self.pending
                .push_back((now + Duration::from_secs(1), action));
        }
    }
    pub fn poll(&mut self, gateway: &mut LocalGateway, socket: &UdpListener, now: Duration) {
        let actions = self.mesh.tick(now);
        self.enqueue(actions, now);
        for _ in 0..self.pending.len().min(super::BATCH) {
            let (expires, action) = self.pending.pop_front().expect("bounded queue");
            if now >= expires {
                continue;
            }
            let result = match &action {
                Action::Initiate { node, endpoint } => {
                    gateway.initiate_at(&ContextId::Gateway, &PeerId::Node(node.clone()), *endpoint)
                }
                Action::Send { node, packet } => gateway.send_mesh(node, packet.as_bytes()),
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
                self.pending.push_back((expires, action));
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
