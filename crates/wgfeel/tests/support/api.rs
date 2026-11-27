use serde_json::Value;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};
use wgfeel_management::{Request, Response, http};

pub fn request(state: &Path, method: &str, path: &str, body: &Value) -> Response {
    let revision = if method == "GET" {
        None
    } else {
        Some(get(state, "/api/v1/users").generation.unwrap())
    };
    let bytes = if matches!(method, "POST" | "PUT") {
        serde_json::to_vec(body).unwrap()
    } else {
        Vec::new()
    };
    exchange(state, method, path, revision, &bytes)
}
pub fn get(state: &Path, path: &str) -> Response {
    exchange(state, "GET", path, None, b"")
}
fn exchange(
    state: &Path,
    method: &str,
    path: &str,
    revision: Option<u64>,
    body: &[u8],
) -> Response {
    let revision = revision.map(|n| format!("\"{n}\""));
    unix_bytes(
        state,
        &http::encode_request(Request {
            method,
            target: path,
            authorization: None,
            if_match: revision.as_deref(),
            body,
        })
        .unwrap(),
    )
}
pub(super) fn unix_bytes(state: &Path, request: &[u8]) -> Response {
    let mut stream = UnixStream::connect(state.join("api.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    loop {
        let mut buffer = zeroize::Zeroizing::new([0; 8192]);
        let size = stream.read(&mut buffer[..]).unwrap();
        assert!(size > 0);
        bytes.extend_from_slice(&buffer[..size]);
        assert!(bytes.len() <= http::MAX_RESPONSE_BYTES);
        if let Some(response) = http::decode_response(&bytes).unwrap() {
            return response;
        }
    }
}
pub fn json(state: &Path, method: &str, path: &str, body: Value) -> Value {
    let response = request(state, method, path, &body);
    assert!(
        (200..300).contains(&response.status),
        "HTTP {}",
        response.status
    );
    serde_json::from_slice(&response.body).unwrap()
}
