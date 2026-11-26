//! Bounded enrollment messages. The URI is a credential, not a public link.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};
use wgfeel_core::{
    DevicePublicKey, NodeId, ServicePrivateKey, validate_node_endpoints, validate_node_hostname,
};
use zeroize::Zeroizing;

const PREFIX: &str = "wgfeel://join/";
pub const MAX_INVITATION_URI: usize = 4096;
pub const MAX_ENROLLMENT_BODY: usize = 4096;
pub const ENROLLMENT_PATH: &str = "/internal/v1/enroll";
pub const PROBE_PATH: &str = "/internal/v1/enroll/probe";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProbe {
    pub invitation: String,
    pub nonce: [u8; 32],
}

pub struct Invitation {
    id: NodeId,
    management: NodeId,
    management_public_key: DevicePublicKey,
    endpoints: Vec<SocketAddr>,
    mesh_port: u16,
    expires_at: u64,
    temporary_private_key: ServicePrivateKey,
}
impl fmt::Debug for Invitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invitation([REDACTED])")
    }
}
impl Invitation {
    pub fn new(
        id: NodeId,
        management: NodeId,
        management_public_key: DevicePublicKey,
        endpoints: Vec<SocketAddr>,
        mesh_port: u16,
        expires_at: u64,
        temporary_private_key: ServicePrivateKey,
    ) -> Result<Self, &'static str> {
        validate_node_endpoints(&endpoints).map_err(|_| "invalid invitation endpoints")?;
        if endpoints.is_empty() || mesh_port == 0 || expires_at == 0 {
            return Err("invalid invitation");
        }
        Ok(Self {
            id,
            management,
            management_public_key,
            endpoints,
            mesh_port,
            expires_at,
            temporary_private_key,
        })
    }
    pub fn id(&self) -> &NodeId {
        &self.id
    }
    pub fn management(&self) -> &NodeId {
        &self.management
    }
    pub fn management_public_key(&self) -> &DevicePublicKey {
        &self.management_public_key
    }
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }
    pub fn mesh_port(&self) -> u16 {
        self.mesh_port
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn temporary_private_key(&self) -> &ServicePrivateKey {
        &self.temporary_private_key
    }

    /// The caller must print at most once and must not persist or log this URI.
    pub fn encode(&self) -> Result<Zeroizing<String>, &'static str> {
        #[derive(Serialize)]
        struct Wire<'a> {
            version: u32,
            id: &'a NodeId,
            management: &'a NodeId,
            management_public_key: &'a DevicePublicKey,
            endpoints: &'a [SocketAddr],
            mesh_port: u16,
            expires_at: u64,
            temporary_private_key: &'a str,
        }
        let key = Zeroizing::new(STANDARD.encode(self.temporary_private_key.expose_bytes()));
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Wire {
                version: 2,
                id: &self.id,
                management: &self.management,
                management_public_key: &self.management_public_key,
                endpoints: &self.endpoints,
                mesh_port: self.mesh_port,
                expires_at: self.expires_at,
                temporary_private_key: &key,
            })
            .map_err(|_| "cannot encode invitation")?,
        );
        let mut uri = Zeroizing::new(String::from(PREFIX));
        URL_SAFE_NO_PAD.encode_string(&bytes, &mut uri);
        if uri.len() > MAX_INVITATION_URI {
            return Err("invitation too large");
        }
        Ok(uri)
    }
    pub fn decode(uri: &str) -> Result<Self, &'static str> {
        if uri.len() > MAX_INVITATION_URI {
            return Err("invalid invitation");
        }
        let encoded = uri.strip_prefix(PREFIX).ok_or("invalid invitation")?;
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| "invalid invitation")?,
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<'a> {
            version: u32,
            id: &'a str,
            management: &'a str,
            management_public_key: [u8; 32],
            endpoints: Vec<SocketAddr>,
            mesh_port: u16,
            expires_at: u64,
            temporary_private_key: &'a str,
        }
        let wire: Wire<'_> = serde_json::from_slice(&bytes).map_err(|_| "invalid invitation")?;
        if wire.version != 2 {
            return Err("unsupported invitation version");
        }
        let key =
            crate::decode_key(wire.temporary_private_key).map_err(|_| "invalid invitation")?;
        Self::new(
            NodeId::new(wire.id).map_err(|_| "invalid invitation")?,
            NodeId::new(wire.management).map_err(|_| "invalid invitation")?,
            DevicePublicKey::new(wire.management_public_key).map_err(|_| "invalid invitation")?,
            wire.endpoints,
            wire.mesh_port,
            wire.expires_at,
            ServicePrivateKey::new(*key).map_err(|_| "invalid invitation")?,
        )
    }
}

/// Public node identity and contact candidates. Possession of this public key
/// still needs a separate permanent WireGuard handshake before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrollmentClaim {
    node_id: NodeId,
    public_key: DevicePublicKey,
    gateway_public_key: DevicePublicKey,
    hostname: String,
    endpoints: Vec<SocketAddr>,
    // Random, memory-only identifier generated once per local join operation.
    // It separates network retries from a later reuse by the same node.
    attempt: NodeId,
}
impl EnrollmentClaim {
    pub fn new(
        node_id: NodeId,
        public_key: DevicePublicKey,
        gateway_public_key: DevicePublicKey,
        hostname: String,
        endpoints: Vec<SocketAddr>,
        attempt: NodeId,
    ) -> Result<Self, &'static str> {
        validate_node_hostname(&hostname).map_err(|_| "invalid node hostname")?;
        validate_node_endpoints(&endpoints).map_err(|_| "invalid node endpoints")?;
        if public_key == gateway_public_key {
            return Err("node keys must be distinct");
        }
        if endpoints.is_empty() {
            return Err("node endpoint required");
        }
        Ok(Self {
            node_id,
            public_key,
            gateway_public_key,
            hostname,
            endpoints,
            attempt,
        })
    }
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }
    pub fn gateway_public_key(&self) -> &DevicePublicKey {
        &self.gateway_public_key
    }
    pub fn public_keys(&self) -> [&DevicePublicKey; 2] {
        [&self.public_key, &self.gateway_public_key]
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_ENROLLMENT_BODY {
            return Err("enrollment request too large");
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            node_id: String,
            public_key: [u8; 32],
            gateway_public_key: [u8; 32],
            hostname: String,
            endpoints: Vec<SocketAddr>,
            attempt: String,
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| "invalid enrollment request")?;
        Self::new(
            NodeId::new(&wire.node_id).map_err(|_| "invalid node identity")?,
            DevicePublicKey::new(wire.public_key).map_err(|_| "invalid node key")?,
            DevicePublicKey::new(wire.gateway_public_key).map_err(|_| "invalid gateway key")?,
            wire.hostname,
            wire.endpoints,
            NodeId::new(&wire.attempt).map_err(|_| "invalid enrollment attempt")?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn invitation() -> Invitation {
        Invitation::new(
            NodeId::new("invite-1").unwrap(),
            NodeId::new("manager").unwrap(),
            DevicePublicKey::new([3; 32]).unwrap(),
            vec![
                "203.0.113.2:51820".parse().unwrap(),
                "[2001:db8::2]:51820".parse().unwrap(),
            ],
            53001,
            1000,
            ServicePrivateKey::new([7; 32]).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn credential_roundtrip_preserves_pinned_identity_both_families_and_secret() {
        let first = invitation();
        let encoded = first.encode().unwrap();
        assert!(
            encoded
                .strip_prefix(PREFIX)
                .unwrap()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        );
        let second = Invitation::decode(&encoded).unwrap();
        assert_eq!(second.id(), first.id());
        assert_eq!(second.management(), first.management());
        assert_eq!(
            second.management_public_key(),
            first.management_public_key()
        );
        assert_eq!(second.endpoints(), first.endpoints());
        assert_eq!(second.mesh_port(), 53001);
        assert_eq!(second.expires_at(), 1000);
        assert_eq!(second.temporary_private_key().expose_bytes(), &[7; 32]);
        assert_eq!(format!("{second:?}"), "Invitation([REDACTED])");
    }
    #[test]
    fn invitation_parser_is_bounded_strict_and_never_echoes_credentials() {
        for uri in [
            "secret",
            "wgfeel://join/SECRET?query",
            &"x".repeat(MAX_INVITATION_URI + 1),
        ] {
            assert_eq!(Invitation::decode(uri).unwrap_err(), "invalid invitation");
        }
        let encoded = invitation().encode().unwrap();
        let raw = URL_SAFE_NO_PAD
            .decode(encoded.strip_prefix(PREFIX).unwrap())
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for (field, replacement) in [
            ("version", serde_json::json!(1)),
            ("mesh_port", serde_json::json!(0)),
            ("endpoints", serde_json::json!([])),
            ("endpoints", serde_json::json!(["0.0.0.0:1"])),
            ("temporary_private_key", serde_json::json!("invalid")),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            let uri = format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invalid).unwrap())
            );
            assert!(Invitation::decode(&uri).is_err());
        }
        let duplicate = String::from_utf8(raw)
            .unwrap()
            .replacen('{', "{\"version\":1,", 1);
        assert!(
            Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(duplicate))).is_err()
        );
    }
    #[test]
    fn claim_requires_valid_identity_hostname_and_reachable_candidate_addresses() {
        let claim = EnrollmentClaim::new(
            NodeId::new("node-1").unwrap(),
            (DevicePublicKey::new([4; 32]).unwrap()).clone(),
            DevicePublicKey::new([90; 32]).unwrap(),
            "vps1".into(),
            vec!["203.0.113.3:55125".parse().unwrap()],
            NodeId::new("attempt-1").unwrap(),
        )
        .unwrap();
        assert_eq!(
            EnrollmentClaim::decode(&serde_json::to_vec(&claim).unwrap()).unwrap(),
            claim
        );
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!("attempt\nforged"),
        ] {
            let mut raw = serde_json::to_value(&claim).unwrap();
            raw["attempt"] = invalid;
            assert!(EnrollmentClaim::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
        }
        let mut missing = serde_json::to_value(&claim).unwrap();
        missing.as_object_mut().unwrap().remove("attempt");
        assert!(EnrollmentClaim::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut raw = serde_json::to_value(&claim).unwrap();
        raw["hostname"] = serde_json::json!("vps\nforged");
        assert!(EnrollmentClaim::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
        assert!(EnrollmentClaim::decode(&vec![b' '; MAX_ENROLLMENT_BODY + 1]).is_err());
    }
}
