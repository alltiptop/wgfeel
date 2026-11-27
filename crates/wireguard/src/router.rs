//! Public admission and receiver-index routing. No tenant static private keys.

use crate::{
    ContextId, MAX_HANDSHAKE_SOURCES, PeerId, WireGuardError,
    dispatch::{DispatchContext, DispatchError, IndexBinding, Registry, RouteHint, WorkerLease},
    framing,
};
use gotatun::{
    noise::{TunnResult, errors::WireGuardError as EngineError, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) enum Verification {
    Packet(WgKind),
    Challenge(WgKind),
}

pub(crate) struct Admission {
    pub slot: usize,
    pub peer: Option<PeerId>,
    pub verified: Verification,
}

struct Context {
    id: ContextId,
    limiter: Arc<RateLimiter>,
    sources: SourceWindow,
    lease: WorkerLease,
    active: bool,
}

pub(crate) struct Router {
    contexts: Vec<Context>,
    registry: Registry,
}

impl Router {
    pub fn new(configs: Vec<(DispatchContext, Arc<RateLimiter>)>) -> Result<Self, WireGuardError> {
        let (metadata, limiters): (Vec<_>, Vec<_>) = configs.into_iter().unzip();
        let ids: Vec<_> = metadata.iter().map(|c| c.context.clone()).collect();
        let mut registry = Registry::new(metadata).map_err(dispatch_error)?;
        let mut contexts = Vec::with_capacity(ids.len());
        for (id, limiter) in ids.into_iter().zip(limiters) {
            let lease = registry.restart(&id).map_err(dispatch_error)?;
            contexts.push(Context {
                id,
                limiter,
                sources: SourceWindow::new(),
                lease,
                active: true,
            });
        }
        Ok(Self { contexts, registry })
    }

    pub fn publish(
        &mut self,
        slot: usize,
        bindings: Vec<IndexBinding>,
    ) -> Result<(), WireGuardError> {
        self.publish_worker(slot, bindings).map_err(dispatch_error)
    }

    pub fn publish_worker(
        &mut self,
        slot: usize,
        bindings: Vec<IndexBinding>,
    ) -> Result<(), DispatchError> {
        let context = self
            .contexts
            .get(slot)
            .ok_or(DispatchError::UnknownContext)?;
        if !context.active {
            return Err(DispatchError::InvalidLease);
        }
        self.registry.replace(&context.lease, bindings)
    }

    pub fn replace_service_peers(
        &mut self,
        slot: usize,
        peers: Vec<PeerId>,
        bindings: Vec<IndexBinding>,
    ) -> Result<(), DispatchError> {
        let context = self
            .contexts
            .get(slot)
            .ok_or(DispatchError::UnknownContext)?;
        if !context.active {
            return Err(DispatchError::InvalidLease);
        }
        self.registry
            .replace_service_peers(&context.lease, peers, bindings)
    }

    pub fn release(&mut self, slot: usize) -> Result<(), WireGuardError> {
        let context = self
            .contexts
            .get_mut(slot)
            .ok_or(WireGuardError::UnknownContext)?;
        if context.active {
            self.registry
                .release(&context.lease)
                .map_err(dispatch_error)?;
            context.active = false;
        }
        Ok(())
    }

    pub fn restart(&mut self, slot: usize) -> Result<(), WireGuardError> {
        let context = self
            .contexts
            .get_mut(slot)
            .ok_or(WireGuardError::UnknownContext)?;
        context.lease = self.registry.restart(&context.id).map_err(dispatch_error)?;
        context.active = true;
        Ok(())
    }

    pub fn generation(&self, slot: usize) -> u64 {
        self.contexts[slot].lease.generation()
    }

    pub(super) fn prepare_routes(
        &mut self,
        slot: usize,
        previous: &Self,
        old: usize,
    ) -> Result<(), WireGuardError> {
        if self.contexts[slot].id != previous.contexts[old].id {
            return Err(WireGuardError::InvalidConfiguration);
        }
        let (peers, bindings) = previous
            .registry
            .context_snapshot(&previous.contexts[old].lease)
            .map_err(dispatch_error)?;
        if self.contexts[slot].id == ContextId::Service {
            self.replace_service_peers(slot, peers, bindings)
                .map_err(dispatch_error)
        } else {
            self.publish(slot, bindings)
        }
    }

    pub(super) fn move_admission(
        &mut self,
        slot: usize,
        previous: &mut Self,
        old: usize,
    ) -> Result<(), WireGuardError> {
        previous.release(old)?;
        std::mem::swap(
            &mut self.contexts[slot].limiter,
            &mut previous.contexts[old].limiter,
        );
        std::mem::swap(
            &mut self.contexts[slot].sources,
            &mut previous.contexts[old].sources,
        );
        Ok(())
    }

    pub fn admit(&mut self, source: SocketAddr, bytes: &[u8]) -> Result<Admission, WireGuardError> {
        self.admit_scoped(source, bytes, None)
    }

    pub fn admit_scoped(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
        expected: Option<(usize, &PeerId)>,
    ) -> Result<Admission, WireGuardError> {
        match self.registry.route(bytes).map_err(dispatch_error)? {
            RouteHint::NeedsHandshakeAdmission => {
                if let Some((slot, peer)) = expected {
                    return Ok(Admission {
                        slot,
                        peer: Some(peer.clone()),
                        verified: self.verify(slot, source, bytes)?,
                    });
                }
                let mut source_capped = false;
                for slot in 0..self.contexts.len() {
                    if !self.contexts[slot].active {
                        continue;
                    }
                    match self.verify_candidate(slot, source, bytes) {
                        Ok(verified) => {
                            return Ok(Admission {
                                slot,
                                peer: None,
                                verified,
                            });
                        }
                        Err(AdmissionError::InvalidMac) => (),
                        Err(AdmissionError::Rejected(WireGuardError::SourceLimit)) => {
                            source_capped = true;
                        }
                        Err(AdmissionError::Rejected(error)) => return Err(error),
                    }
                }
                Err(if source_capped {
                    WireGuardError::SourceLimit
                } else {
                    WireGuardError::Protocol
                })
            }
            RouteHint::Receiver {
                context,
                peer,
                generation,
            } => {
                let slot = self
                    .contexts
                    .iter()
                    .position(|c| c.id == context)
                    .ok_or(WireGuardError::Protocol)?;
                if expected.is_some_and(|(expected_slot, expected_peer)| {
                    slot != expected_slot || &peer != expected_peer
                }) || !self.contexts[slot].active
                    || self.contexts[slot].lease.generation() != generation
                {
                    return Err(WireGuardError::Protocol);
                }
                let verified = self.verify(slot, source, bytes)?;
                Ok(Admission {
                    slot,
                    peer: Some(peer),
                    verified,
                })
            }
        }
    }

    pub fn verify(
        &mut self,
        slot: usize,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Verification, WireGuardError> {
        self.verify_candidate(slot, source, bytes)
            .map_err(|error| match error {
                AdmissionError::InvalidMac => WireGuardError::Protocol,
                AdmissionError::Rejected(error) => error,
            })
    }

    fn verify_candidate(
        &mut self,
        slot: usize,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<Verification, AdmissionError> {
        let handshake = framing::datagram_for(
            bytes,
            self.contexts
                .get(slot)
                .is_some_and(|c| matches!(c.id, ContextId::External(_))),
        )
        .map_err(AdmissionError::Rejected)?;
        let context = self
            .contexts
            .get_mut(slot)
            .ok_or(AdmissionError::Rejected(WireGuardError::UnknownContext))?;
        if !context.active {
            return Err(AdmissionError::Rejected(WireGuardError::UnknownContext));
        }
        context.limiter.try_reset_count();
        if handshake {
            context
                .sources
                .admit(source.ip())
                .map_err(AdmissionError::Rejected)?;
        }
        // One verifier owns each context's counters and cookies. Workers must
        // not repeat this call after public admission has succeeded.
        match context
            .limiter
            .verify_packet(source, Packet::copy_from(bytes))
        {
            Ok(packet) => {
                if handshake {
                    context.sources.record(source.ip());
                }
                Ok(Verification::Packet(packet))
            }
            Err(TunnResult::WriteToNetwork(packet)) => {
                if handshake {
                    context.sources.record(source.ip());
                }
                Ok(Verification::Challenge(packet))
            }
            Err(TunnResult::Err(EngineError::InvalidMac)) => Err(AdmissionError::InvalidMac),
            Err(_) => Err(AdmissionError::Rejected(WireGuardError::Protocol)),
        }
    }
}

enum AdmissionError {
    InvalidMac,
    Rejected(WireGuardError),
}

fn dispatch_error(error: DispatchError) -> WireGuardError {
    match error {
        DispatchError::UnknownIndex => WireGuardError::UnknownIndex,
        DispatchError::InvalidPacket => WireGuardError::InvalidPacket,
        DispatchError::PacketTooLarge => WireGuardError::PacketTooLarge,
        _ => WireGuardError::Protocol,
    }
}

struct SourceWindow {
    started: Instant,
    ips: Vec<IpAddr>,
}
impl SourceWindow {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            ips: Vec::with_capacity(MAX_HANDSHAKE_SOURCES),
        }
    }
    fn admit(&mut self, ip: IpAddr) -> Result<(), WireGuardError> {
        let now = Instant::now();
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.ips.clear();
            self.started = now;
        }
        if self.ips.len() == MAX_HANDSHAKE_SOURCES && !self.ips.contains(&ip) {
            return Err(WireGuardError::SourceLimit);
        }
        Ok(())
    }
    fn record(&mut self, ip: IpAddr) {
        if !self.ips.contains(&ip) {
            self.ips.push(ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::RouteHint;
    use wgfeel_core::{DeviceId, NetworkId, NodeId};

    fn tenant() -> ContextId {
        ContextId::Tenant(NetworkId::new("tenant").unwrap())
    }
    fn admin() -> PeerId {
        PeerId::Node(NodeId::new("admin").unwrap())
    }
    fn device() -> PeerId {
        PeerId::Device(DeviceId::new("device").unwrap())
    }
    fn router(service_first: bool) -> Router {
        let mut contexts = vec![
            DispatchContext {
                context: ContextId::Service,
                peers: vec![admin()],
            },
            DispatchContext {
                context: tenant(),
                peers: vec![device()],
            },
        ];
        if !service_first {
            contexts.reverse();
        }
        Router::new(
            contexts
                .into_iter()
                .map(|context| {
                    (
                        context,
                        Arc::new(RateLimiter::new(
                            &gotatun::x25519::PublicKey::from([7; 32]),
                            10,
                        )),
                    )
                })
                .collect(),
        )
        .unwrap()
    }
    fn packet(index: u32) -> Vec<u8> {
        let mut packet = vec![0; 32];
        packet[0] = 4;
        packet[4..8].copy_from_slice(&index.to_le_bytes());
        packet
    }

    #[test]
    fn scoped_receiver_index_requires_both_the_context_and_peer() {
        let mut router = router(true);
        let bytes = packet(42);
        router
            .publish(
                1,
                vec![IndexBinding {
                    index: 42,
                    peer: device(),
                }],
            )
            .unwrap();
        let source = "127.0.0.1:9000".parse().unwrap();
        let route = router.registry.route(&bytes).unwrap();
        for (slot, peer) in [(0, device()), (1, admin())] {
            assert!(
                router
                    .admit_scoped(source, &bytes, Some((slot, &peer)))
                    .is_err()
            );
            assert_eq!(router.registry.route(&bytes).unwrap(), route);
        }
        let admitted = router
            .admit_scoped(source, &bytes, Some((1, &device())))
            .unwrap();
        assert_eq!(admitted.peer, Some(device()));
    }

    #[test]
    fn service_handoff_preserves_indices_and_tenants_across_different_slots_and_leases() {
        let mut previous = router(true);
        previous.restart(0).unwrap();
        previous
            .publish(
                0,
                vec![IndexBinding {
                    index: 100,
                    peer: admin(),
                }],
            )
            .unwrap();
        previous
            .publish(
                1,
                vec![IndexBinding {
                    index: 200,
                    peer: device(),
                }],
            )
            .unwrap();
        let mut next = router(false);
        next.publish(
            0,
            vec![IndexBinding {
                index: 300,
                peer: device(),
            }],
        )
        .unwrap();
        next.prepare_routes(1, &previous, 0).unwrap();
        next.move_admission(1, &mut previous, 0).unwrap();
        for (router, index, context, peer) in [
            (&next, 100, ContextId::Service, admin()),
            (&next, 300, tenant(), device()),
            (&previous, 200, tenant(), device()),
        ] {
            assert_eq!(
                router.registry.route(&packet(index)).unwrap(),
                RouteHint::Receiver {
                    context,
                    peer,
                    generation: 1
                }
            );
        }
        assert_eq!(
            previous.registry.route(&packet(100)),
            Err(DispatchError::UnknownIndex)
        );
        assert!(matches!(
            previous
                .registry
                .context_snapshot(&previous.contexts[0].lease),
            Err(DispatchError::InvalidLease)
        ));
    }

    #[test]
    fn service_handoff_collision_preserves_both_registries_and_admission() {
        let mut previous = router(true);
        previous
            .publish(
                0,
                vec![IndexBinding {
                    index: 100,
                    peer: admin(),
                }],
            )
            .unwrap();
        let mut next = router(false);
        next.publish(
            0,
            vec![IndexBinding {
                index: 100,
                peer: device(),
            }],
        )
        .unwrap();
        assert!(next.prepare_routes(1, &previous, 0).is_err());
        assert_eq!(
            previous.registry.route(&packet(100)).unwrap(),
            RouteHint::Receiver {
                context: ContextId::Service,
                peer: admin(),
                generation: 1
            }
        );
        assert_eq!(
            next.registry.route(&packet(100)).unwrap(),
            RouteHint::Receiver {
                context: tenant(),
                peer: device(),
                generation: 1
            }
        );
        assert!(previous.contexts[0].active);
        assert!(next.contexts[1].active);
    }
}
