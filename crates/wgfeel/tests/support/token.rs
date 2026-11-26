//! Test-only external consumer: explicitly receives a newly issued token and
//! stores it in its own test profile for encrypted remote API coverage.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};
pub fn provision_remote_profile(state: &Path, profile: &Path, generation: u64) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(profile).unwrap()).unwrap();
    if value.get("credential").is_some() {
        return;
    }
    let mut stream = UnixStream::connect(state.join("api.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(stream, "POST /api/v1/token/rotate HTTP/1.1\r\nHost: local\r\nIf-Match: \"{generation}\"\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let response = wgfeel_management::http::decode_response(&bytes)
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    value["credential"] =
        serde_json::json!(STANDARD.decode(body["token"].as_str().unwrap()).unwrap());
    fs::write(profile, serde_json::to_vec(&value).unwrap()).unwrap();
}
