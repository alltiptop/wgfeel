//! Shared bounded wire protocol; no authority, host sockets or persistent state.
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};
pub mod enrollment;
pub mod http;
pub mod tcp;
pub const MAX_REQUEST_BODY: usize = 65_536;

/// Secrets are intentionally excluded from Debug and logs.
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub authorization: Option<&'a str>,
    pub if_match: Option<&'a str>,
    pub body: &'a [u8],
}

pub struct Response {
    pub status: u16,
    pub generation: Option<u64>,
    pub body: Vec<u8>,
    pub is_config: bool,
}
impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Response {
    pub fn error(status: u16, code: &'static str) -> Self {
        Self {
            status,
            generation: None,
            body: serde_json::json!({"error": code}).to_string().into_bytes(),
            is_config: false,
        }
    }
}

/// Canonical WireGuard Base64. This helper never echoes or retains rejected input.
pub fn decode_key(text: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    if text.len() != 44 || STANDARD.decode_slice(text, bytes.as_mut_slice()).ok() != Some(32) {
        return Err("invalid key encoding");
    }
    Ok(bytes)
}

pub trait Handler {
    fn handle(&mut self, request: Request<'_>) -> Response;
}
