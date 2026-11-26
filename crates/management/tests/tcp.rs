use std::time::Duration;
use wgfeel_management::{ManagementService, Response, tcp::*};
use zeroize::Zeroizing;
const SOCKET_BUFFER_BYTES: usize = 16_384;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use wgfeel_core::{
    AdminCredential, Client as Owner, ClientDevice, ClientId, Config, DeviceId, DeviceMetadata,
    ManagementConfig, ManagementDocument, Network, NetworkId, NodeId, Policy,
};
use wgfeel_store::ManagementStore;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new(large: bool) -> (Self, ManagementService, ManagementDocument) {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-tcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let document = ManagementDocument::new(
            ManagementConfig::new(
                NodeId::new("management").unwrap(),
                Config::new(
                    7,
                    if large {
                        (0..64)
                            .map(|i| {
                                Network::new(NetworkId::new(&format!("owner-{i}")).unwrap(), vec![])
                                    .unwrap()
                            })
                            .collect()
                    } else {
                        vec![]
                    },
                    Policy::new(vec![], vec![], vec![]),
                )
                .unwrap(),
                vec![],
            )
            .unwrap(),
            if large {
                (0..64)
                    .map(|i| {
                        Owner::new(
                            ClientId::new(&format!("owner-{i}")).unwrap(),
                            vec![NetworkId::new(&format!("owner-{i}")).unwrap()],
                            vec![ClientDevice::new(
                                DeviceId::new(&format!("device-{i}")).unwrap(),
                                DeviceMetadata::new(
                                    Some(format!("device-{i}")),
                                    Some("x".repeat(1024)),
                                )
                                .unwrap(),
                            )],
                        )
                        .unwrap()
                    })
                    .collect()
            } else {
                vec![]
            },
        )
        .unwrap();
        let state = path.join("state");
        let mut store = ManagementStore::initialize(&state).unwrap();
        store
            .commit(
                &document,
                &wgfeel_test_support::fixture_node_keys([197; 32]),
                &AdminCredential::new([211; 32]).unwrap(),
                None,
            )
            .unwrap();
        drop(store);
        let service = ManagementService::open(&state).unwrap();
        (Self(path), service, document)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn http(method: &str, target: &str, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let header = format!(
        "{method} {target} HTTP/1.1\r\nHost: management\r\nAuthorization: Bearer {}\r\nIf-Match: \"7\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        STANDARD.encode([211; 32]),
        body.len()
    );
    let mut request = Zeroizing::new(Vec::with_capacity(header.len() + body.len()));
    request.extend_from_slice(header.as_bytes());
    request.extend_from_slice(body);
    request
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn fix_checksum(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let header = usize::from(packet[0] & 15) * 4;
    let ip_sum = checksum(&packet[..header]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[header + 16..header + 18].fill(0);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((packet.len() - header) as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[header..]);
    let tcp_sum = checksum(&pseudo);
    packet[header + 16..header + 18].copy_from_slice(&tcp_sum.to_be_bytes());
}
fn syn(port: u16) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&ADMIN_IP);
    packet[16..20].copy_from_slice(&SERVER_IP);
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet[22..24].copy_from_slice(&80u16.to_be_bytes());
    packet[24..28].copy_from_slice(&1234u32.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 2;
    packet[34..36].copy_from_slice(&16384u16.to_be_bytes());
    fix_checksum(&mut packet);
    packet
}
fn assert_packet(packet: &[u8], from: [u8; 4], to: [u8; 4]) {
    assert!(packet.len() <= 1280);
    assert_eq!(packet[0], 0x45);
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        packet.len()
    );
    assert_eq!(&packet[12..16], &from);
    assert_eq!(&packet[16..20], &to);
    assert_eq!(packet[9], 6);
    assert_eq!(checksum(&packet[..20]), 0);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    assert_eq!(checksum(&pseudo), 0);
}
fn exchange(
    server: &mut Server<'_>,
    client: &mut Client<'_>,
    service: &mut ManagementService,
    start: u64,
    drop_first_syn: bool,
    drop_first_data: bool,
) -> Response {
    let mut dropped_syn = !drop_first_syn;
    let mut dropped_data = !drop_first_data;
    for millis in start..start + 9900 {
        let now = Duration::from_millis(millis);
        client.poll(now).unwrap();
        while let Some(packet) = client.take_packet() {
            assert_packet(&packet, ADMIN_IP, SERVER_IP);
            if !dropped_syn && packet[33] & 2 != 0 {
                dropped_syn = true;
                continue;
            }
            let header = 20 + usize::from(packet[32] >> 4) * 4;
            if !dropped_data && packet.len() > header {
                dropped_data = true;
                continue;
            }
            server.receive(&packet).unwrap();
        }
        server.poll(now, service).unwrap();
        while let Some(packet) = server.take_packet() {
            assert_packet(&packet, SERVER_IP, ADMIN_IP);
            client.receive(&packet).unwrap();
        }
        if let Some(response) = client.take_response() {
            assert!(dropped_syn && dropped_data);
            return response.unwrap();
        }
    }
    panic!("bounded exchange did not finish");
}

#[test]
fn buffer_counts_and_request_bounds_are_explicit() {
    assert!(Buffers::new(0).is_err());
    assert!(Buffers::new(9).is_err());
    let mut one = Buffers::new(1).unwrap();
    assert!(Server::new(&mut one, 1).is_err());
    let mut eight = Buffers::new(8).unwrap();
    assert!(Client::new(&mut eight, 1, http("GET", "/api/v1/config", b"")).is_err());
    let mut one = Buffers::new(1).unwrap();
    assert!(
        Client::new(
            &mut one,
            1,
            Zeroizing::new(vec![
                b'x';
                wgfeel_management::MAX_REQUEST_BODY
                    + wgfeel_management::http::MAX_HEADER_BYTES
                    + 1
            ])
        )
        .is_err()
    );
}
#[test]
fn authentic_http_mutation_survives_segmentation_and_syn_and_data_loss() {
    let (_fixture, mut service, _) = Fixture::new(false);
    let mut server_buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut server_buffers, 7).unwrap();
    let mut body = br#"{"name":"alice"}"#.to_vec();
    body.resize(65536, b' ');
    let mut client_buffers = Buffers::new(1).unwrap();
    let mut client = Client::new(
        &mut client_buffers,
        19,
        http("POST", "/api/v1/users", &body),
    )
    .unwrap();
    let response = exchange(&mut server, &mut client, &mut service, 0, true, true);
    assert_eq!(response.status, 201);
    assert_eq!(response.generation, Some(8));
    let created: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(created["id"].as_str().unwrap().len(), 36);
    assert_eq!(created["generation"], 8);
    assert_eq!(created["distribution"], "pending");
    assert!(client.take_response().is_none());
}
#[test]
fn response_larger_than_socket_buffers_is_delivered_exactly() {
    let (_fixture, mut service, expected) = Fixture::new(true);
    assert!(expected.to_json().unwrap().len() > SOCKET_BUFFER_BYTES * 2);
    let mut server_buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut server_buffers, 7).unwrap();
    let mut client_buffers = Buffers::new(1).unwrap();
    let mut client =
        Client::new(&mut client_buffers, 21, http("GET", "/api/v1/config", b"")).unwrap();
    let response = exchange(&mut server, &mut client, &mut service, 0, false, false);
    assert_eq!(response.status, 200);
    assert_eq!(response.generation, Some(7));
    assert_eq!(
        ManagementDocument::from_json(std::str::from_utf8(&response.body).unwrap()).unwrap(),
        expected
    );
}
#[test]
fn invalid_inner_packets_never_reach_the_http_handler_and_ingress_is_bounded() {
    let (_fixture, mut service, _) = Fixture::new(false);
    let mut buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut buffers, 1).unwrap();
    for mutation in 0..9 {
        let mut packet = syn(50000);
        match mutation {
            0 => packet[12] = 11,
            1 => packet[16] = 11,
            2 => packet[9] = 17,
            3 => packet[6] = 0x20,
            4 => packet[7] = 1,
            5 => packet[6] = 0x80,
            6 => packet[23] = 81,
            7 => packet[8] = 0,
            _ => packet[0] = 0x65,
        }
        fix_checksum(&mut packet);
        assert_eq!(server.receive(&packet), Err(TcpError::InvalidPacket));
    }
    let mut bad = syn(50000);
    bad[10] ^= 1;
    assert_eq!(server.receive(&bad), Err(TcpError::InvalidPacket));
    let mut bad = syn(50000);
    bad[36] ^= 1;
    assert_eq!(server.receive(&bad), Err(TcpError::InvalidPacket));
    assert_eq!(server.receive(&vec![0; 1281]), Err(TcpError::InvalidPacket));
    for _ in 0..16 {
        server.receive(&syn(50000)).unwrap();
    }
    assert_eq!(server.receive(&syn(50000)), Err(TcpError::QueueFull));
    server.poll(Duration::ZERO, &mut service).unwrap();
    server.receive(&syn(50000)).unwrap();
    assert_eq!(server.receive(&syn(50000)), Err(TcpError::QueueFull));
    assert_eq!(service.identity().unwrap().1, 7);
}
#[test]
fn monotonic_clock_and_client_total_timeout_have_exact_boundaries() {
    let mut buffers = Buffers::new(1).unwrap();
    let mut client = Client::new(&mut buffers, 1, http("GET", "/api/v1/config", b"")).unwrap();
    client.poll(Duration::from_secs(20)).unwrap();
    client.poll(Duration::from_secs(29)).unwrap();
    assert!(client.take_response().is_none());
    client.poll(Duration::from_secs(30)).unwrap();
    assert!(matches!(
        client.take_response(),
        Some(Err(TcpError::Timeout))
    ));
    assert!(client.take_response().is_none());
    let mut buffers = Buffers::new(1).unwrap();
    let mut client = Client::new(&mut buffers, 2, http("GET", "/api/v1/config", b"")).unwrap();
    client.poll(Duration::from_secs(2)).unwrap();
    assert_eq!(
        client.poll(Duration::from_secs(1)),
        Err(TcpError::InvalidTime)
    );
    let (_fixture, mut service, _) = Fixture::new(false);
    let mut buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut buffers, 1).unwrap();
    server.poll(Duration::from_secs(2), &mut service).unwrap();
    assert_eq!(
        server.poll(Duration::from_secs(1), &mut service),
        Err(TcpError::InvalidTime)
    );
}
#[test]
fn stalled_partial_requests_expire_and_slots_accept_new_clients() {
    let (_fixture, mut service, _) = Fixture::new(false);
    let mut buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut buffers, 9).unwrap();
    let mut client_buffers = (0..8).map(|_| Buffers::new(1).unwrap()).collect::<Vec<_>>();
    let mut clients = client_buffers
        .iter_mut()
        .enumerate()
        .map(|(i, b)| {
            Client::new(
                b,
                100 + i as u64,
                Zeroizing::new(b"GET /api/v1/config HTTP/1.1\r\nHost: unfinished\r\n".to_vec()),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    for millis in 0..1000 {
        let now = Duration::from_millis(millis);
        for client in &mut clients {
            client.poll(now).unwrap();
            while let Some(packet) = client.take_packet() {
                server.receive(&packet).unwrap();
            }
        }
        server.poll(now, &mut service).unwrap();
        while let Some(packet) = server.take_packet() {
            let destination = u16::from_be_bytes([packet[22], packet[23]]);
            for client in &mut clients {
                if client.receive(&packet).is_ok() {
                    break;
                }
            }
            let _ = destination;
        }
    }
    server.poll(Duration::from_secs(6), &mut service).unwrap();
    while server.take_packet().is_some() {}
    let mut fresh_buffers = Buffers::new(1).unwrap();
    let mut fresh =
        Client::new(&mut fresh_buffers, 999, http("GET", "/api/v1/config", b"")).unwrap();
    let response = exchange(&mut server, &mut fresh, &mut service, 6000, false, false);
    assert_eq!(response.status, 200);
    assert_eq!(response.generation, Some(7));
}
#[test]
fn parallel_clients_have_distinct_streams_and_auth_failures_do_not_block_valid_requests() {
    let (_fixture, mut service, expected) = Fixture::new(false);
    let mut buffers = Buffers::new(8).unwrap();
    let mut server = Server::new(&mut buffers, 9).unwrap();
    let mut one = Buffers::new(1).unwrap();
    let mut two = Buffers::new(1).unwrap();
    let mut good = Client::new(&mut one, 101, http("GET", "/api/v1/config", b"")).unwrap();
    let bad = Zeroizing::new(
        b"GET /api/v1/config HTTP/1.1\r\nHost: management\r\nContent-Length: 0\r\n\r\n".to_vec(),
    );
    let mut bad = Client::new(&mut two, 102, bad).unwrap();
    let mut replies = [None, None];
    for millis in 0..9900 {
        let now = Duration::from_millis(millis);
        for client in [&mut good, &mut bad] {
            client.poll(now).unwrap();
            while let Some(packet) = client.take_packet() {
                server.receive(&packet).unwrap();
            }
        }
        server.poll(now, &mut service).unwrap();
        while let Some(packet) = server.take_packet() {
            if good.receive(&packet).is_err() {
                bad.receive(&packet).unwrap();
            }
        }
        if replies[0].is_none() {
            replies[0] = good.take_response();
        }
        if replies[1].is_none() {
            replies[1] = bad.take_response();
        }
        if replies.iter().all(Option::is_some) {
            break;
        }
    }
    let response = replies[0].take().unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        ManagementDocument::from_json(std::str::from_utf8(&response.body).unwrap()).unwrap(),
        expected
    );
    assert_eq!(replies[1].take().unwrap().unwrap().status, 401);
    assert_eq!(service.identity().unwrap().1, 7);
}
