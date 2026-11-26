use crate::StoreError;
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use serde::{Deserialize, Serialize};
use wgfeel_core::AdminCredential;

/// Verifier for a uniformly random 256-bit token, never a human password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminVerifier {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; 32],
    digest: [u8; 32],
}
impl AdminVerifier {
    pub fn new(token: &AdminCredential) -> Result<Self, StoreError> {
        let mut salt = [0; 32];
        aws_lc_rs::rand::fill(&mut salt).map_err(|_| StoreError::InvalidState)?;
        Ok(Self {
            algorithm: "argon2id".into(),
            version: 19,
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
            salt,
            digest: hash(&salt, token.expose_bytes())?,
        })
    }
    pub fn verify(&self, token: &[u8]) -> bool {
        self.valid()
            && token.len() == 32
            && hash(&self.salt, token)
                .is_ok_and(|actual| verify_slices_are_equal(&actual, &self.digest).is_ok())
    }
    pub(crate) fn valid(&self) -> bool {
        self.algorithm == "argon2id"
            && self.version == 19
            && self.memory_kib == 19456
            && self.iterations == 2
            && self.parallelism == 1
    }
}
fn hash(salt: &[u8; 32], token: &[u8]) -> Result<[u8; 32], StoreError> {
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|_| StoreError::InvalidState)?;
    let mut memory = zeroize::Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    let mut output = [0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(token, salt, &mut output, memory.as_mut_slice())
        .map_err(|_| StoreError::InvalidState)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_salts_and_fixed_cost_argon2id_verifiers_are_not_bearer_tokens() {
        let token = AdminCredential::new([91; 32]).unwrap();
        let first = AdminVerifier::new(&token).unwrap();
        let second = AdminVerifier::new(&token).unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.digest, second.digest);
        assert!(first.verify(token.expose_bytes()));
        assert!(!first.verify(&[92; 32]));
        assert!(!first.verify(&first.digest));
        let mut excessive = first.clone();
        excessive.memory_kib = u32::MAX;
        assert!(!excessive.verify(token.expose_bytes()));
        let mut cheap = first;
        cheap.iterations = 1;
        assert!(!cheap.verify(token.expose_bytes()));
    }
}
