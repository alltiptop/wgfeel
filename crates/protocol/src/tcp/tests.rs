use super::*;

#[test]
fn abandoned_distribution_stream_releases_its_slot_after_a_bounded_idle_period() {
    let mut buffers = Buffers::new(1).unwrap();
    let mut server = Server::distribution(&mut buffers, 19).unwrap();
    let mut old_buffers = Buffers::new(1).unwrap();
    let mut old = Client::distribution(&mut old_buffers, 20, Zeroizing::new(b"POST /internal/v1/config HTTP/1.1\r\nHost: management\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nobsolete".to_vec())).unwrap();
    for millis in 0..100 {
        let now = Duration::from_millis(millis);
        old.poll(now).unwrap();
        while let Some(packet) = old.take_packet() {
            server.receive(&packet).unwrap();
        }
        server
            .poll_with(now, |_| panic!("partial request was dispatched"))
            .unwrap();
        while let Some(packet) = server.take_packet() {
            old.receive(&packet).unwrap();
        }
    }
    assert!(!server.connections[0].request.is_empty());
    drop(old); // Main changed revision or restarted without completing this stream.
    server
        .poll_with(Duration::from_secs(6), |_| {
            panic!("abandoned request was dispatched")
        })
        .unwrap();
    assert!(
        server.connections[0].request.is_empty(),
        "idle stream retained the only delivery slot"
    );
    assert_eq!(
        server
            .stack
            .sockets
            .get::<tcp::Socket>(server.stack.handles[0])
            .state(),
        tcp::State::Listen
    );
}

#[test]
fn distribution_idle_deadline_allows_a_slow_request_that_keeps_making_progress() {
    let mut server_buffers = Buffers::new(1).unwrap();
    let mut server = Server::distribution(&mut server_buffers, 31).unwrap();
    let mut client_buffers = Buffers::new(1).unwrap();
    let mut client = Client::distribution(&mut client_buffers, 32, Zeroizing::new(b"POST /internal/v1/config HTTP/1.1\r\nHost: management\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\na".to_vec())).unwrap();
    for millis in 0..9000 {
        if millis == 4000 {
            client.request.push(b'b');
        }
        if millis == 8000 {
            client.request.push(b'c');
        }
        let now = Duration::from_millis(millis);
        client.poll(now).unwrap();
        while let Some(packet) = client.take_packet() {
            server.receive(&packet).unwrap();
        }
        server
            .poll_with(now, |request| {
                assert_eq!(request.body, b"abc");
                assert!(millis >= 8000);
                Response::error(200, "complete")
            })
            .unwrap();
        while let Some(packet) = server.take_packet() {
            client.receive(&packet).unwrap();
        }
        if let Some(response) = client.take_response() {
            assert_eq!(response.unwrap().status, 200);
            return;
        }
    }
    panic!("progressing delivery was expired or never completed");
}

#[test]
fn replacing_single_peer_session_discards_abandoned_partial_stream_immediately() {
    let mut buffers = Buffers::new(1).unwrap();
    let mut server = Server::distribution(&mut buffers, 9).unwrap();
    let mut old_buffers = Buffers::new(1).unwrap();
    let mut old = Client::distribution(&mut old_buffers, 10, Zeroizing::new(b"POST /internal/v1/config HTTP/1.1\r\nHost: management\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nobsolete".to_vec())).unwrap();
    for millis in 0..100 {
        let now = Duration::from_millis(millis);
        old.poll(now).unwrap();
        while let Some(packet) = old.take_packet() {
            server.receive(&packet).unwrap();
        }
        server
            .poll_with(now, |_| panic!("partial request must not be dispatched"))
            .unwrap();
        while let Some(packet) = server.take_packet() {
            old.receive(&packet).unwrap();
        }
    }
    assert!(!server.connections[0].request.is_empty());
    server.reset_session().unwrap();
    assert!(server.connections[0].request.is_empty());
    let mut fresh_buffers = Buffers::new(1).unwrap();
    let encoded = http::encode_request(crate::Request {
        method: "POST",
        target: "/internal/v1/config",
        authorization: None,
        if_match: None,
        body: b"latest",
    })
    .unwrap();
    let mut fresh = Client::distribution(&mut fresh_buffers, 11, encoded).unwrap();
    for millis in 100..1000 {
        let now = Duration::from_millis(millis);
        fresh.poll(now).unwrap();
        while let Some(packet) = fresh.take_packet() {
            server.receive(&packet).unwrap();
        }
        server
            .poll_with(now, |request| {
                assert_eq!(request.body, b"latest");
                Response {
                    status: 200,
                    generation: Some(10),
                    body: b"{}".to_vec(),
                    is_config: false,
                }
            })
            .unwrap();
        while let Some(packet) = server.take_packet() {
            fresh.receive(&packet).unwrap();
        }
        if let Some(response) = fresh.take_response() {
            assert_eq!(response.unwrap().status, 200);
            return;
        }
    }
    panic!("superseded stream blocked new authenticated delivery");
}

#[test]
fn internal_distribution_streams_large_snapshots_without_relaxing_admin_limits() {
    let body = vec![b'x'; 200_000];
    assert!(
        crate::http::encode_request(crate::Request {
            method: "POST",
            target: "/internal/v1/config",
            authorization: None,
            if_match: None,
            body: &body
        })
        .is_err()
    );
    let request = crate::http::encode_request_with_limit(
        crate::Request {
            method: "POST",
            target: "/internal/v1/config",
            authorization: None,
            if_match: None,
            body: &body,
        },
        wgfeel_core::MAX_PROJECTION_BYTES,
    )
    .unwrap();
    let mut server_buffers = Buffers::new(1).unwrap();
    let mut server = Server::distribution(&mut server_buffers, 17).unwrap();
    let mut client_buffers = Buffers::new(1).unwrap();
    let mut client = Client::distribution(&mut client_buffers, 18, request).unwrap();
    let mut calls = 0;
    let mut dropped = false;
    for millis in 0..30_000 {
        let now = Duration::from_millis(millis);
        client.poll(now).unwrap();
        while let Some(packet) = client.take_packet() {
            if !dropped && packet.len() > 100 {
                dropped = true;
                continue;
            }
            server.receive(&packet).unwrap();
        }
        server
            .poll_with(now, |request| {
                calls += 1;
                assert_eq!(request.body, body);
                assert_eq!(request.authorization, None);
                Response {
                    status: 200,
                    generation: Some(9),
                    body: b"{\"applied\":true}".to_vec(),
                    is_config: false,
                }
            })
            .unwrap();
        while let Some(packet) = server.take_packet() {
            client.receive(&packet).unwrap();
        }
        if let Some(response) = client.take_response() {
            assert_eq!(response.unwrap().generation, Some(9));
            assert_eq!(calls, 1);
            assert!(dropped);
            return;
        }
    }
    panic!("large distribution request was not delivered");
}
