//! Ephemeral invitation authority. No token, temporary private key or unfinished
//! claim is written into ManagementStore. A restart intentionally revokes all.
use aws_lc_rs::agreement::{PrivateKey, X25519};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId, ServicePrivateKey, TrafficMode};
use wgfeel_protocol::enrollment::{EnrollmentClaim, Invitation};
use zeroize::Zeroizing;

pub const INVITATION_LIFETIME: Duration = Duration::from_secs(15 * 60);
pub use wgfeel_core::MAX_INVITATIONS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    Unavailable,
    Limit,
    ExpiredOrUnknown,
    AlreadyClaimed,
    InvalidIdentity,
    NotClaimed,
}

struct Entry {
    traffic: TrafficMode,
    temporary_public_key: DevicePublicKey,
    management_public_key: DevicePublicKey,
    deadline: Instant,
    claim: Option<EnrollmentClaim>,
    activated_generation: Option<u64>,
}

#[derive(Default)]
pub(crate) struct Invitations {
    entries: BTreeMap<NodeId, Entry>,
}
impl Invitations {
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now < entry.deadline);
    }
    pub fn issue(
        &mut self,
        management: NodeId,
        management_public_key: DevicePublicKey,
        contact: (Vec<SocketAddr>, u16),
        traffic: TrafficMode,
        now: Instant,
        unix_seconds: u64,
    ) -> Result<Invitation, EnrollmentError> {
        self.expire(now);
        if self.entries.len() >= MAX_INVITATIONS {
            return Err(EnrollmentError::Limit);
        }
        let id = NodeId::new(&format!(
            "invite-{}",
            super::generated_id(None).map_err(|_| EnrollmentError::Unavailable)?
        ))
        .map_err(|_| EnrollmentError::Unavailable)?;
        // Fail closed on the vanishingly unlikely random-ID collision.
        if self.entries.contains_key(&id) {
            return Err(EnrollmentError::Unavailable);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(bytes.as_mut_slice()).map_err(|_| EnrollmentError::Unavailable)?;
        let private = ServicePrivateKey::new(*bytes).map_err(|_| EnrollmentError::Unavailable)?;
        let public = PrivateKey::from_private_key(&X25519, private.expose_bytes())
            .map_err(|_| EnrollmentError::Unavailable)?
            .compute_public_key()
            .map_err(|_| EnrollmentError::Unavailable)?;
        let public = DevicePublicKey::new(
            public
                .as_ref()
                .try_into()
                .map_err(|_| EnrollmentError::Unavailable)?,
        )
        .map_err(|_| EnrollmentError::Unavailable)?;
        if public == management_public_key {
            return Err(EnrollmentError::Unavailable);
        }
        let expires_at = unix_seconds
            .checked_add(INVITATION_LIFETIME.as_secs())
            .ok_or(EnrollmentError::Unavailable)?;
        let deadline = now
            .checked_add(INVITATION_LIFETIME)
            .ok_or(EnrollmentError::Unavailable)?;
        let (endpoints, mesh_port) = contact;
        let invitation = Invitation::new(
            id.clone(),
            management,
            management_public_key.clone(),
            endpoints,
            mesh_port,
            expires_at,
            private,
        )
        .map_err(|_| EnrollmentError::Unavailable)?;
        self.entries.insert(
            id,
            Entry {
                traffic,
                temporary_public_key: public,
                management_public_key,
                deadline,
                claim: None,
                activated_generation: None,
            },
        );
        Ok(invitation)
    }
    /// Only public WG peer metadata is exposed to the transport.
    pub fn peers(&mut self, now: Instant) -> Vec<(NodeId, DevicePublicKey)> {
        self.expire(now);
        self.entries
            .iter()
            .map(|(id, entry)| (id.clone(), entry.temporary_public_key.clone()))
            .collect()
    }
    pub fn pending(&mut self, now: Instant) -> Vec<(NodeId, DevicePublicKey, EnrollmentClaim)> {
        self.expire(now);
        self.entries
            .iter()
            .filter_map(|(id, entry)| {
                if entry.activated_generation.is_some() {
                    return None;
                }
                entry.claim.as_ref().map(|claim| {
                    (
                        id.clone(),
                        entry.temporary_public_key.clone(),
                        claim.clone(),
                    )
                })
            })
            .collect()
    }
    /// `authenticated_key` must come from successful WireGuard authentication,
    /// never from an HTTP header, address or request body.
    pub fn claim(
        &mut self,
        id: &NodeId,
        authenticated_key: &DevicePublicKey,
        claim: EnrollmentClaim,
        now: Instant,
    ) -> Result<&EnrollmentClaim, EnrollmentError> {
        let entry = self.entry(id, authenticated_key, now)?;
        if claim.public_keys().contains(&&entry.temporary_public_key)
            || claim.public_keys().contains(&&entry.management_public_key)
        {
            return Err(EnrollmentError::InvalidIdentity);
        }
        if entry
            .claim
            .as_ref()
            .is_some_and(|existing| existing != &claim)
        {
            return Err(EnrollmentError::AlreadyClaimed);
        }
        Ok(entry.claim.get_or_insert(claim))
    }
    pub fn claimed(
        &mut self,
        id: &NodeId,
        authenticated_key: &DevicePublicKey,
        now: Instant,
    ) -> Result<&EnrollmentClaim, EnrollmentError> {
        self.entry(id, authenticated_key, now)?
            .claim
            .as_ref()
            .ok_or(EnrollmentError::NotClaimed)
    }
    /// Called only after a permanent-key reachability proof and successful
    /// durable registration. This receipt permits safe lost-response retries.
    pub fn activated(
        &mut self,
        id: &NodeId,
        authenticated_key: &DevicePublicKey,
        permanent_key: &DevicePublicKey,
        generation: u64,
        now: Instant,
    ) -> Result<(), EnrollmentError> {
        let entry = self.entry(id, authenticated_key, now)?;
        let claim = entry.claim.as_ref().ok_or(EnrollmentError::NotClaimed)?;
        if claim.public_key() != permanent_key || generation == 0 {
            return Err(EnrollmentError::InvalidIdentity);
        }
        if entry
            .activated_generation
            .is_some_and(|existing| existing != generation)
        {
            return Err(EnrollmentError::AlreadyClaimed);
        }
        entry.activated_generation = Some(generation);
        Ok(())
    }
    pub fn generation(
        &mut self,
        id: &NodeId,
        authenticated_key: &DevicePublicKey,
        now: Instant,
    ) -> Result<Option<u64>, EnrollmentError> {
        Ok(self.entry(id, authenticated_key, now)?.activated_generation)
    }
    pub fn traffic(
        &mut self,
        id: &NodeId,
        key: &DevicePublicKey,
        now: Instant,
    ) -> Result<TrafficMode, EnrollmentError> {
        Ok(self.entry(id, key, now)?.traffic)
    }
    fn entry(
        &mut self,
        id: &NodeId,
        authenticated_key: &DevicePublicKey,
        now: Instant,
    ) -> Result<&mut Entry, EnrollmentError> {
        self.expire(now);
        let entry = self
            .entries
            .get_mut(id)
            .ok_or(EnrollmentError::ExpiredOrUnknown)?;
        if &entry.temporary_public_key != authenticated_key {
            return Err(EnrollmentError::ExpiredOrUnknown);
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public(byte: u8) -> DevicePublicKey {
        DevicePublicKey::new([byte; 32]).unwrap()
    }
    fn issue(registry: &mut Invitations, now: Instant) -> Invitation {
        registry
            .issue(
                NodeId::new("manager").unwrap(),
                public(1),
                (vec!["127.0.0.1:51820".parse().unwrap()], 51820),
                TrafficMode::Entry,
                now,
                1000,
            )
            .unwrap()
    }
    fn claim(byte: u8) -> EnrollmentClaim {
        EnrollmentClaim::new(
            NodeId::new("node-1").unwrap(),
            (public(byte)).clone(),
            wgfeel_test_support::fixture_gateway_public(&(public(byte))),
            "vps1".into(),
            vec![
                "203.0.113.20:51821".parse().unwrap(),
                "[2001:db8::20]:51821".parse().unwrap(),
            ],
            NodeId::new("attempt-1").unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn one_invitation_binds_exactly_one_identity_with_idempotent_retries() {
        let mut registry = Invitations::default();
        let now = Instant::now();
        let invite = issue(&mut registry, now);
        let (_, transport_key) = registry.peers(now).pop().unwrap();
        assert_eq!(
            registry.claim(invite.id(), &public(7), claim(2), now),
            Err(EnrollmentError::ExpiredOrUnknown)
        );
        assert_eq!(
            registry.claim(invite.id(), &transport_key, claim(1), now),
            Err(EnrollmentError::InvalidIdentity)
        );
        assert_eq!(
            registry
                .claim(invite.id(), &transport_key, claim(2), now)
                .unwrap(),
            &claim(2)
        );
        assert_eq!(
            registry.claim(invite.id(), &transport_key, claim(3), now),
            Err(EnrollmentError::AlreadyClaimed)
        );
        let changed = EnrollmentClaim::new(
            NodeId::new("node-1").unwrap(),
            (public(2)).clone(),
            wgfeel_test_support::fixture_gateway_public(&(public(2))),
            "changed".into(),
            claim(2).endpoints().to_vec(),
            NodeId::new("attempt-1").unwrap(),
        )
        .unwrap();
        assert_eq!(
            registry.claim(invite.id(), &transport_key, changed, now),
            Err(EnrollmentError::AlreadyClaimed)
        );
        assert_eq!(
            registry
                .generation(invite.id(), &transport_key, now)
                .unwrap(),
            None
        );
        assert_eq!(
            registry.activated(invite.id(), &transport_key, &public(3), 4, now),
            Err(EnrollmentError::InvalidIdentity)
        );
        registry
            .activated(invite.id(), &transport_key, &public(2), 4, now)
            .unwrap();
        registry
            .activated(invite.id(), &transport_key, &public(2), 4, now)
            .unwrap();
        assert_eq!(
            registry
                .generation(invite.id(), &transport_key, now)
                .unwrap(),
            Some(4)
        );
        assert_eq!(
            registry
                .claim(invite.id(), &transport_key, claim(2), now)
                .unwrap(),
            &claim(2)
        );
        let next_attempt = EnrollmentClaim::new(
            NodeId::new("node-1").unwrap(),
            (public(2)).clone(),
            wgfeel_test_support::fixture_gateway_public(&(public(2))),
            "vps1".into(),
            claim(2).endpoints().to_vec(),
            NodeId::new("attempt-2").unwrap(),
        )
        .unwrap();
        assert_eq!(
            registry.claim(invite.id(), &transport_key, next_attempt, now),
            Err(EnrollmentError::AlreadyClaimed)
        );
    }
    #[test]
    fn expiry_and_restart_invalidate_unfinished_claims_without_persistent_state() {
        let mut registry = Invitations::default();
        let now = Instant::now();
        let invite = issue(&mut registry, now);
        let (_, transport_key) = registry.peers(now).pop().unwrap();
        registry
            .claim(invite.id(), &transport_key, claim(2), now)
            .unwrap();
        assert_eq!(
            registry.claimed(invite.id(), &transport_key, now + INVITATION_LIFETIME),
            Err(EnrollmentError::ExpiredOrUnknown)
        );
        assert!(registry.peers(now + INVITATION_LIFETIME).is_empty());
        let mut restarted = Invitations::default();
        assert_eq!(
            restarted.claim(invite.id(), &transport_key, claim(2), now),
            Err(EnrollmentError::ExpiredOrUnknown)
        );
    }
    #[test]
    fn invitation_pool_is_bounded_and_expiration_frees_capacity() {
        let now = Instant::now();
        let mut registry = Invitations::default();
        for _ in 0..MAX_INVITATIONS {
            issue(&mut registry, now);
        }
        assert_eq!(
            registry
                .issue(
                    NodeId::new("manager").unwrap(),
                    public(1),
                    (vec!["127.0.0.1:51820".parse().unwrap()], 51820),
                    TrafficMode::Entry,
                    now,
                    1000
                )
                .unwrap_err(),
            EnrollmentError::Limit
        );
        issue(&mut registry, now + INVITATION_LIFETIME);
        assert_eq!(registry.peers(now + INVITATION_LIFETIME).len(), 1);
    }
}
