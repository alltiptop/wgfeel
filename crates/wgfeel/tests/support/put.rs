//! Raw HTTP from the local socket and an independently authenticated WG administrator.
use super::{Fixture, WAIT, api, enrollment, stop};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, net::SocketAddr, path::Path, sync::Barrier, thread};
use wgfeel_core::{DevicePublicKey, NodeId, ServicePrivateKey};
use wgfeel_protocol::Response;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
struct Administrator {
    management_id: NodeId,
    endpoint: SocketAddr,
    server_public_key: [u8; 32],
    admin_private_key: [u8; 32],
    credential: [u8; 32],
}
impl Drop for Administrator {
    fn drop(&mut self) {
        self.admin_private_key.zeroize();
        self.credential.zeroize();
    }
}
#[derive(Clone, Copy)]
enum Transport<'a> {
    Unix(&'a Path),
    WireGuard(&'a Administrator),
}
impl Transport<'_> {
    fn send(
        self,
        method: &str,
        path: &str,
        revision: Option<u64>,
        headers: &str,
        body: &[u8],
    ) -> Response {
        use std::fmt::Write;
        let mut header = Zeroizing::new(format!("{method} {path} HTTP/1.1\r\nHost: wgfeel\r\n"));
        if let Some(revision) = revision {
            write!(header, "If-Match: \"{revision}\"\r\n").unwrap();
        }
        if let Self::WireGuard(admin) = self {
            header.push_str("Authorization: Bearer ");
            header.push_str(&Zeroizing::new(STANDARD.encode(admin.credential)));
            header.push_str("\r\n");
        }
        header.push_str(headers);
        header.push_str("Connection: close\r\n\r\n");
        let mut bytes = Zeroizing::new(Vec::with_capacity(header.len() + body.len()));
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(body);
        match self {
            Self::Unix(state) => api::unix_bytes(state, &bytes),
            Self::WireGuard(admin) => enrollment::wire_exchange(
                admin.endpoint,
                &admin.management_id,
                &DevicePublicKey::new(admin.server_public_key).unwrap(),
                ServicePrivateKey::new(admin.admin_private_key).unwrap(),
                bytes,
                WAIT,
            )
            .expect("encrypted administrator response"),
        }
    }
}
fn valid_headers(body: &[u8]) -> String {
    format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    )
}
fn assert_redacted(response: &Response, admin: &Administrator) {
    let body = std::str::from_utf8(&response.body).unwrap();
    for needle in ["PrivateKey =", "PresharedKey =", "[Interface]"] {
        assert!(
            !body.contains(needle),
            "response included provider configuration"
        );
    }
    for key in [
        [41; 32],
        [43; 32],
        admin.admin_private_key,
        admin.credential,
    ] {
        assert!(
            !body.contains(&STANDARD.encode(key)),
            "response included private material"
        );
        let array = serde_json::to_string(&key).unwrap();
        assert!(
            !body.contains(&array),
            "response included private byte array"
        );
    }
}
#[test]
fn put_framing_cas_and_redaction_match_across_unix_and_remote_wireguard() {
    let fixture = Fixture::new();
    fixture.initialize();
    let server = fixture.start(1);
    let profile = Zeroizing::new(fs::read(fixture.profile()).unwrap());
    let admin: Administrator = serde_json::from_slice(&profile).unwrap();
    let config = Zeroizing::new(format!(
        "[Interface]\nPrivateKey = {}\nAddress = 172.16.0.42/24\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\n",
        STANDARD.encode([41; 32]),
        STANDARD.encode([42; 32]),
        STANDARD.encode([43; 32])
    ));
    let collection = "/api/v1/egresses";
    let created = api::request(
        &fixture.state(),
        "POST",
        collection,
        &json!({"config":config.as_str(),"name":"original"}),
    );
    assert_eq!(created.status, 201);
    assert_redacted(&created, &admin);
    let record: Value = serde_json::from_slice(&created.body).unwrap();
    let path = format!("{collection}/{}", record["id"].as_str().unwrap());
    let revision = created.generation.unwrap();
    let replacement = |name| {
        Zeroizing::new(serde_json::to_vec(&json!({"config":config.as_str(),"name":name})).unwrap())
    };
    let changes = [replacement("Unix winner"), replacement("WireGuard winner")];
    let state = fixture.state();
    let transports = [Transport::Unix(&state), Transport::WireGuard(&admin)];

    for transport in transports {
        let body = &changes[0];
        let valid = valid_headers(body);
        let duplicate = format!("{valid}Content-Length: {}\r\n", body.len());
        let wrong_type = format!(
            "Content-Type: text/plain\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (headers, status) in [
            (duplicate.as_str(), 400),
            ("Content-Type: application/json\r\n", 411),
            (wrong_type.as_str(), 415),
        ] {
            let response = transport.send("PUT", &path, Some(revision), headers, body);
            assert_eq!(response.status, status);
            assert_redacted(&response, &admin);
        }
        let missing = br#"{}"#;
        let response = transport.send(
            "PUT",
            &format!("{path}/node"),
            Some(revision),
            &valid_headers(missing),
            missing,
        );
        assert_eq!(response.status, 400);
        assert_redacted(&response, &admin);
    }
    assert_eq!(api::get(&fixture.state(), &path).generation, Some(revision));
    let start = Barrier::new(2);
    let results = thread::scope(|scope| {
        let run = |index: usize| {
            start.wait();
            transports[index].send(
                "PUT",
                &path,
                Some(revision),
                &valid_headers(&changes[index]),
                &changes[index],
            )
        };
        let unix = scope.spawn(move || run(0));
        let remote = run(1);
        [unix.join().unwrap(), remote]
    });
    let mut statuses = results.each_ref().map(|r| r.status);
    statuses.sort();
    assert_eq!(statuses, [200, 412]);
    let winner = results.iter().position(|r| r.status == 200).unwrap();
    assert_eq!(results[winner].generation, Some(revision + 1));
    for r in &results {
        assert_redacted(r, &admin);
    }
    for transport in transports {
        let stale = transport.send(
            "PUT",
            &path,
            Some(revision),
            &valid_headers(&changes[0]),
            &changes[0],
        );
        assert_eq!(stale.status, 412);
        assert_redacted(&stale, &admin);
        let current = transport.send("GET", &path, None, "", &[]);
        assert_eq!(current.status, 200);
        assert_eq!(current.generation, Some(revision + 1));
        assert_redacted(&current, &admin);
        let saved: Value = serde_json::from_slice(&current.body).unwrap();
        assert_eq!(saved["name"], ["Unix winner", "WireGuard winner"][winner]);
    }
    stop(server);
}
