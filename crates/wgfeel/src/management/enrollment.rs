//! Reverse reachability and permanent-key possession proof for pending joins.
use super::{main_transport::Transport, remote, transport::Tunnel};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId};
use wgfeel_management::ManagementService;
use wgfeel_protocol::{
    Request,
    enrollment::{EnrollmentClaim, EnrollmentProbe, PROBE_PATH},
};

struct Job {
    invitation: NodeId,
    temporary: DevicePublicKey,
    claim: EnrollmentClaim,
    tunnel: Tunnel,
}
struct ResultMessage {
    invitation: NodeId,
    temporary: DevicePublicKey,
    key: DevicePublicKey,
    endpoint: Option<SocketAddr>,
}
struct Worker {
    sender: SyncSender<Job>,
    busy: Option<NodeId>,
}
pub(super) struct Verifier {
    workers: Vec<Worker>,
    results: Receiver<ResultMessage>,
    due: BTreeMap<NodeId, Instant>,
    next_poll: Instant,
}
impl Verifier {
    pub fn new() -> Result<Self, &'static str> {
        let (sender, results) = mpsc::sync_channel(2);
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (jobs, receiver) = mpsc::sync_channel::<Job>(1);
            let results = sender.clone();
            thread::Builder::new()
                .name("node-enrollment-proof".into())
                .spawn(move || {
                    while let Ok(mut job) = receiver.recv() {
                        let endpoint = verify(&mut job);
                        if results
                            .send(ResultMessage {
                                invitation: job.invitation,
                                temporary: job.temporary,
                                key: job.claim.public_key().clone(),
                                endpoint,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
                .map_err(|_| "cannot start enrollment verifier")?;
            workers.push(Worker {
                sender: jobs,
                busy: None,
            });
        }
        Ok(Self {
            workers,
            results,
            due: BTreeMap::new(),
            next_poll: Instant::now(),
        })
    }
    pub fn poll(
        &mut self,
        service: &mut ManagementService,
        transport: &mut Transport,
        report: impl Fn(String),
    ) {
        while let Ok(result) = self.results.try_recv() {
            if let Some(worker) = self
                .workers
                .iter_mut()
                .find(|worker| worker.busy.as_ref() == Some(&result.invitation))
            {
                worker.busy = None;
            }
            if let Some(endpoint) = result.endpoint {
                let response = service.complete_enrollment(
                    &result.invitation,
                    &result.temporary,
                    &result.key,
                    endpoint,
                );
                if response.status != 200 {
                    // This response originates in the local management store/API.
                    let body = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
                    let code = body
                        .as_ref()
                        .and_then(|value| value["error"].as_str())
                        .unwrap_or("registration_failed");
                    report(format!(
                        "child endpoint {endpoint} passed the WireGuard probe; registration failed ({}, {code})",
                        response.status
                    ));
                }
            }
            self.due
                .insert(result.invitation, Instant::now() + Duration::from_secs(1));
        }
        if Instant::now() < self.next_poll {
            return;
        }
        self.next_poll = Instant::now() + Duration::from_millis(250);
        let pending = service.pending_enrollments();
        self.due
            .retain(|id, _| pending.iter().any(|(candidate, _, _)| candidate == id));
        for (invitation, temporary, claim) in pending {
            if self
                .workers
                .iter()
                .any(|worker| worker.busy.as_ref() == Some(&invitation))
                || self
                    .due
                    .get(&invitation)
                    .is_some_and(|due| *due > Instant::now())
            {
                continue;
            }
            let Some(worker) = self.workers.iter_mut().find(|worker| worker.busy.is_none()) else {
                break;
            };
            let Ok(Some((_, key))) = service.service_api() else {
                return;
            };
            let Ok(udp) = transport.control_transport() else {
                return;
            };
            let Ok(tunnel) = Tunnel::new(
                udp,
                key,
                claim.node_id().clone(),
                claim.public_key().clone(),
            ) else {
                continue;
            };
            if worker
                .sender
                .try_send(Job {
                    invitation: invitation.clone(),
                    temporary,
                    claim,
                    tunnel,
                })
                .is_ok()
            {
                worker.busy = Some(invitation);
            }
        }
    }
}
fn verify(job: &mut Job) -> Option<SocketAddr> {
    let mut nonce = [0; 32];
    aws_lc_rs::rand::fill(&mut nonce).ok()?;
    let body = serde_json::to_vec(&EnrollmentProbe {
        invitation: job.invitation.as_str().into(),
        nonce,
    })
    .ok()?;
    for endpoint in job.claim.endpoints() {
        let started = Instant::now();
        job.tunnel.reset().ok()?;
        let response = remote::exchange_on(
            &mut job.tunnel,
            *endpoint,
            Request {
                method: "POST",
                target: PROBE_PATH,
                authorization: None,
                if_match: None,
                body: &body,
            },
            false,
            || started.elapsed() >= Duration::from_secs(3),
        );
        if response.is_ok_and(|response| response.status == 200 && response.body == body) {
            return Some(*endpoint);
        }
    }
    None
}
