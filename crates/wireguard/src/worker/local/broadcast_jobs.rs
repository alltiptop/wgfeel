use super::{BroadcastJob, Flight, LocalEvent, LocalGateway, RequestId, Stage, WorkerLease};
use crate::{ContextId, PacketBytes, PeerId, broadcast, mesh::MeshTraffic};
use std::{collections::VecDeque, time::Instant};
use wgfeel_core::{Endpoint, NodeId};

impl LocalGateway {
    pub(super) fn start_broadcast(
        &mut self,
        origin: RequestId,
        source: Endpoint,
        home: &NodeId,
        bytes: PacketBytes,
    ) {
        if self.broadcast_jobs.len() >= broadcast::MAX_JOBS
            || self
                .broadcast_jobs
                .iter()
                .any(|j| j.origin.context == origin.context)
        {
            return;
        }
        let now = Instant::now();
        let Ok((scan, packet)) = broadcast::Scan::start(
            &self.projection,
            source,
            home,
            bytes,
            &mut self.broadcast_limits,
            now,
        ) else {
            return;
        };
        let len = packet.original().len();
        let job = BroadcastJob {
            outer: if home != self.projection.recipient() {
                self.raw.incarnation(&ContextId::Gateway)
            } else {
                None
            },
            origin,
            revision: self.projection.generation(),
            scan,
            len,
            last: false,
            outputs: VecDeque::new(),
        };
        self.queue_broadcast_batch(job, Some(packet.into_bytes()), now);
    }
    pub(super) fn drain_broadcast(&mut self) -> Option<LocalEvent> {
        for job in &mut self.broadcast_jobs {
            if job
                .outer
                .is_some_and(|g| !self.raw.generation_is_active(&ContextId::Gateway, g))
                || job.scan.expires <= Instant::now()
                || !self
                    .raw
                    .generation_is_active(&job.origin.context, job.origin.generation)
            {
                job.outputs.clear();
                continue;
            }
            if let Some((data, label)) = job.outputs.pop_front() {
                return Some(
                    if let (Some(label), Some(PeerId::Gateway(peer))) = (label, data.peer.as_ref())
                    {
                        LocalEvent::MeshOutput {
                            provenance: Some(WorkerLease {
                                context: job.origin.context.clone(),
                                generation: job.origin.generation,
                                revision: job.revision,
                            }),
                            network: job.scan.source.network().clone(),
                            peer: peer.clone(),
                            packet: data.packet,
                            traffic: Some(MeshTraffic::Broadcast(label)),
                        }
                    } else {
                        LocalEvent::Network(data)
                    },
                );
            }
        }
        None
    }
    pub fn has_broadcast_jobs(&self) -> bool {
        !self.broadcast_jobs.is_empty()
    }
    pub fn has_pending_broadcast(&self) -> bool {
        self.broadcast_jobs
            .iter()
            .any(|j| !j.outputs.is_empty() || self.raw.ready_for(&j.origin.context))
    }
    /// Advance at most one scan slice on the runtime's broadcast turn.
    pub fn advance_broadcast(&mut self) {
        self.progress_broadcast(false);
    }
    pub(super) fn progress_broadcast(&mut self, expired_only: bool) {
        if self.broadcast_jobs.is_empty() {
            return;
        }
        let now = Instant::now();
        for _ in 0..self.broadcast_jobs.len() {
            let Some(mut job) = self.broadcast_jobs.pop_front() else {
                return;
            };
            if !self
                .raw
                .generation_is_active(&job.origin.context, job.origin.generation)
            {
                continue;
            }
            let expired = now >= job.scan.expires
                || job
                    .outer
                    .is_some_and(|g| !self.raw.generation_is_active(&ContextId::Gateway, g));
            if expired_only && !expired {
                self.broadcast_jobs.push_back(job);
                continue;
            }
            if expired {
                job.scan.expires = now;
                job.outputs.clear();
            }
            if !job.outputs.is_empty() || !self.raw.ready_for(&job.origin.context) {
                self.broadcast_jobs.push_back(job);
                continue;
            }
            if job.last {
                continue;
            }
            self.queue_broadcast_batch(job, None, now);
            break;
        }
    }

    fn queue_broadcast_batch(
        &mut self,
        mut job: BroadcastJob,
        packet: Option<PacketBytes>,
        now: Instant,
    ) {
        let online = |peer: &PeerId| {
            self.raw
                .endpoint(&job.origin.context, peer)
                .ok()
                .flatten()
                .is_some()
        };
        let (mut targets, last) = job.scan.next(&self.projection, online, true, now);
        let exhausted =
            self.broadcast_limits
                .charge_batch(job.scan.source.network(), &mut targets, now);
        job.last = last || exhausted;
        if targets.is_empty() {
            match (packet.is_some(), job.last) {
                (true, true) => return, // No recipients and nothing parked in the worker.
                (false, false) => {
                    self.broadcast_jobs.push_back(job);
                    return;
                }
                _ => (), // Park the first packet or release it after the last slice.
            }
        }
        if let Ok(request) = self.raw.broadcast_batch(
            &job.origin.context,
            job.origin.sequence,
            packet,
            targets,
            job.last,
            job.len,
        ) {
            self.flights.push(Flight {
                request,
                stage: Stage::Broadcast,
            });
            self.broadcast_jobs.push_back(job);
        }
    }
}
