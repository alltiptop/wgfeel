//! Bounded independent deliveries. A slow mesh node cannot block Management.
use super::{main_transport::Transport, remote, transport::Tunnel};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, GatewayAssignment, NodeId, ServicePrivateKey};
use wgfeel_management::{ManagementService, Request};
use zeroize::Zeroizing;
mod common;

struct Job {
    node: GatewayAssignment,
    withdrawal: Option<Tunnel>,
    generation: u64,
    projection: Zeroizing<Vec<u8>>,
}
struct ResultMessage {
    id: NodeId,
    key: DevicePublicKey,
    generation: u64,
    applied: bool,
}
struct Worker {
    sender: SyncSender<Job>,
    busy: Option<NodeId>,
    incoming: SyncSender<common::Packet>,
}
pub(super) struct Distributor {
    workers: Vec<Worker>,
    results: Receiver<ResultMessage>,
    due: BTreeMap<NodeId, Instant>,
    generation: u64,
    next_poll: Instant,
    current: Arc<AtomicU64>,
    outgoing: Receiver<common::Packet>,
}
impl Distributor {
    pub(super) fn new() -> Result<Self, &'static str> {
        let (results_tx, results) = mpsc::sync_channel(4);
        let current = Arc::new(AtomicU64::new(0));
        let mut workers = Vec::with_capacity(4);
        let (outgoing_tx, outgoing) = mpsc::sync_channel(128);
        for _ in 0..4 {
            let (sender, jobs) = mpsc::sync_channel::<Job>(1);
            let results = results_tx.clone();
            let current = current.clone();
            let (incoming, packets) = mpsc::sync_channel(64);
            let outgoing = outgoing_tx.clone();
            thread::Builder::new()
                .name("configuration-delivery".into())
                .spawn(move || {
                    while let Ok(mut job) = jobs.recv() {
                        let accepted = |response: Result<
                            wgfeel_protocol::Response,
                            &'static str,
                        >| {
                            response.is_ok_and(|response| {
                                response.status == 200
                                    && response.generation == Some(job.generation)
                                    && serde_json::from_slice::<serde_json::Value>(&response.body)
                                        .is_ok_and(|body| {
                                            body["applied"] == true
                                                && body["generation"] == job.generation
                                                && body["recipient"]
                                                    == job.node.recipient().as_str()
                                        })
                            })
                        };
                        let applied = if let Some(mut tunnel) = job.withdrawal.take() {
                            job.node.endpoints().iter().any(|endpoint| {
                                if current.load(Ordering::Relaxed) != job.generation
                                    || tunnel.reset().is_err()
                                {
                                    return false;
                                }
                                accepted(remote::exchange_on(
                                    &mut tunnel,
                                    *endpoint,
                                    Request {
                                        method: "POST",
                                        target: "/internal/v1/config",
                                        authorization: None,
                                        if_match: None,
                                        body: &job.projection,
                                    },
                                    true,
                                    || current.load(Ordering::Relaxed) != job.generation,
                                ))
                            })
                        } else {
                            accepted(common::exchange(&job, &outgoing, &packets, &current))
                        };
                        if results
                            .send(ResultMessage {
                                id: job.node.recipient().clone(),
                                key: job.node.service_public_key().clone(),
                                generation: job.generation,
                                applied,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
                .map_err(|_| "cannot start configuration delivery worker")?;
            workers.push(Worker {
                sender,
                busy: None,
                incoming,
            });
        }
        Ok(Self {
            workers,
            results,
            due: BTreeMap::new(),
            generation: 0,
            next_poll: Instant::now(),
            current,
            outgoing,
        })
    }
    pub(super) fn receive(&self, peer: &NodeId, packet: &[u8]) {
        if packet.len() > wgfeel_wireguard::MAX_PLAINTEXT_SIZE {
            return;
        }
        if let Some(worker) = self
            .workers
            .iter()
            .find(|worker| worker.busy.as_ref() == Some(peer))
        {
            let _ = worker.incoming.try_send(common::Packet {
                peer: peer.clone(),
                generation: self.generation,
                bytes: Zeroizing::new(packet.to_vec()),
            });
        }
    }
    pub(super) fn flush(&self, tunnel: &mut super::main_transport::Transport) {
        for packet in self.outgoing.try_iter().take(64) {
            if packet.generation == self.generation {
                tunnel.send_distribution(&packet.peer, &packet.bytes);
            }
        }
    }
    pub(super) fn poll(&mut self, service: &mut ManagementService, transport: &mut Transport) {
        while let Ok(result) = self.results.try_recv() {
            if let Some(worker) = self
                .workers
                .iter_mut()
                .find(|worker| worker.busy.as_ref() == Some(&result.id))
            {
                worker.busy = None;
            }
            let confirmed = result.applied
                && service
                    .acknowledge(result.id.clone(), &result.key, result.generation)
                    .is_ok();
            let delay = if result.generation != self.generation {
                0
            } else if confirmed {
                30
            } else {
                1
            };
            self.due
                .insert(result.id, Instant::now() + Duration::from_secs(delay));
        }
        if Instant::now() < self.next_poll {
            return;
        }
        self.next_poll = Instant::now() + Duration::from_millis(250);
        let Ok(state) = service.delivery_snapshot() else {
            return;
        };
        let generation = state.document().routing().generation();
        if generation != self.generation {
            self.generation = generation;
            self.current.store(generation, Ordering::Relaxed);
            self.due.clear();
        }
        let targets = state
            .document()
            .routing()
            .assignments()
            .iter()
            .chain(state.retired_gateways());
        let targets: Vec<_> = targets
            .filter(|node| {
                node.endpoint().is_some()
                    && node.recipient() != state.document().routing().management_id()
            })
            .collect();
        self.due
            .retain(|id, _| targets.iter().any(|node| node.recipient() == id));
        for node in targets {
            if self
                .workers
                .iter()
                .any(|worker| worker.busy.as_ref() == Some(node.recipient()))
                || self
                    .due
                    .get(node.recipient())
                    .is_some_and(|due| *due > Instant::now())
            {
                continue;
            }
            let Some(worker) = self.workers.iter_mut().find(|worker| worker.busy.is_none()) else {
                break;
            };
            let routing = state.document().routing();
            let retired = state
                .retired_gateways()
                .iter()
                .any(|old| old.recipient() == node.recipient());
            let projection = if retired {
                routing.withdraw_for(node)
            } else {
                routing.project_mesh_for(node.recipient())
            };
            let Ok(projection) = projection
                .map_err(wgfeel_store::StoreError::InvalidConfig)
                .and_then(|projection| state.delivery(&projection))
            else {
                continue;
            };
            let withdrawal = if retired {
                let Ok(socket) = transport.control_transport() else {
                    continue;
                };
                let Ok(key) = ServicePrivateKey::new(*state.service_private_key().expose_bytes())
                else {
                    continue;
                };
                let Ok(tunnel) = Tunnel::new(
                    socket,
                    key,
                    node.recipient().clone(),
                    node.service_public_key().clone(),
                ) else {
                    continue;
                };
                Some(tunnel)
            } else {
                None
            };
            if worker
                .sender
                .try_send(Job {
                    node: node.clone(),
                    withdrawal,
                    generation,
                    projection,
                })
                .is_ok()
            {
                worker.busy = Some(node.recipient().clone());
            }
        }
    }
}
