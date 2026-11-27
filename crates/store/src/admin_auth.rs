use crate::StoreError;
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};
use wgfeel_core::AdminCredential;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Algorithm {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

/// The HMAC key is the uniformly random 256-bit administrator credential.
/// Only a public random salt and its authentication tag are persisted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminVerifier {
    algorithm: Algorithm,
    salt: [u8; 32],
    digest: [u8; 32],
}

impl std::fmt::Debug for AdminVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminVerifier")
            .finish_non_exhaustive()
    }
}

impl AdminVerifier {
    pub fn new(token: &AdminCredential) -> Result<Self, StoreError> {
        let mut salt = [0; 32];
        aws_lc_rs::rand::fill(&mut salt).map_err(|_| StoreError::InvalidState)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, token.expose_bytes());
        let mut digest = [0; 32];
        digest.copy_from_slice(hmac::sign(&key, &salt).as_ref());
        Ok(Self {
            algorithm: Algorithm::HmacSha256,
            salt,
            digest,
        })
    }

    pub fn verify(&self, token: &[u8]) -> bool {
        token.len() == 32
            && hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, token),
                &self.salt,
                &self.digest,
            )
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_salted_verifiers_are_not_bearer_tokens() {
        let token = AdminCredential::new([91; 32]).unwrap();
        let first = AdminVerifier::new(&token).unwrap();
        let second = AdminVerifier::new(&token).unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.digest, second.digest);
        assert!(first.verify(token.expose_bytes()));
        assert!(!first.verify(&[92; 32]));
        assert!(!first.verify(&[91; 31]));
        assert!(!first.verify(&first.digest));
        let mut invalid = serde_json::to_value(&first).unwrap();
        invalid["algorithm"] = "unknown".into();
        assert!(serde_json::from_value::<AdminVerifier>(invalid).is_err());
    }
}
