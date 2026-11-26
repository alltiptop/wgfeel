use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener, net::UnixStream},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId, ServicePrivateKey};
use wgfeel_protocol::{Response, enrollment::Invitation, http};
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

struct Fixture {
    state: PathBuf,
    listener: UnixListener,
    invitation: Invitation,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let state = std::env::temp_dir().join(format!(
            "wgfeel-join-progress-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = state.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            state,
            listener,
            invitation: Invitation::new(
                NodeId::new("private-invitation-id").unwrap(),
                NodeId::new("manager1").unwrap(),
                DevicePublicKey::new([211; 32]).unwrap(),
                vec![
                    "192.0.2.1:51820".parse().unwrap(),
                    "[2001:db8::1]:51820".parse().unwrap(),
                ],
                51820,
                u64::MAX,
                ServicePrivateKey::new([197; 32]).unwrap(),
            )
            .unwrap(),
        }
    }
    fn spawn(&self) -> ManagedChild {
        ManagedChild::spawn(
            ProcessSpec::new(
                env!("CARGO_BIN_EXE_wgfeel").into(),
                vec![
                    "join".into(),
                    self.invitation.encode().unwrap().as_str().into(),
                    "--state-dir".into(),
                    self.state.clone().into(),
                    "--endpoint".into(),
                    "203.0.113.2:51821".into(),
                ],
                vec![],
                None,
            ),
            ProcessLimits {
                max_stdout_bytes: 8192,
                max_stderr_bytes: 8192,
            },
        )
        .unwrap()
    }
    fn request(&self, method: &str) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no local join request");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= 8192);
            if let Some(request) = http::decode_request(&bytes).unwrap() {
                assert_eq!(request.method, method);
                assert_eq!(request.target, "/internal/v1/join");
                return stream;
            }
        }
    }
    fn assert_public_progress(&self, output: &CapturedOutput) {
        let text = String::from_utf8_lossy(&output.stderr);
        for value in ["manager1", "192.0.2.1:51820", "[2001:db8::1]:51820"] {
            assert!(
                text.contains(value),
                "missing public Manager contact: {value}"
            );
        }
        // The --endpoint override advertises this Node, not its Manager.
        assert!(!text.contains("203.0.113.2:51821"));
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for private in [
                "wgfeel://join/",
                "private-invitation-id",
                "temporary_private_key",
                &STANDARD.encode([197; 32]),
                self.invitation.encode().unwrap().as_str(),
            ] {
                assert!(!text.contains(private), "invitation leaked to output");
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.state);
    }
}
fn respond(stream: &mut UnixStream, status: u16, state: &str) {
    stream
        .write_all(&http::encode_response(&Response {
            status,
            generation: None,
            body: serde_json::json!({"operation":1,"management":"manager1","state":state})
                .to_string()
                .into_bytes(),
            is_config: false,
        }))
        .unwrap();
}

#[test]
fn join_prints_manager_addresses_before_the_local_service_replies() {
    let fixture = Fixture::new();
    let child = fixture.spawn();
    let _pending = fixture.request("POST");
    // No response was sent: capture output while join is still waiting for it.
    let output = child.terminate().unwrap();
    assert!(output.stdout.is_empty());
    fixture.assert_public_progress(&output);
}

#[test]
fn join_reports_pending_progress_and_preserves_success_and_failure_results() {
    for (final_state, pending_for) in [
        ("applied", Duration::from_millis(5500)),
        ("failed", Duration::from_millis(1)),
    ] {
        let fixture = Fixture::new();
        let child = fixture.spawn();
        respond(&mut fixture.request("POST"), 202, "pending");
        let started = Instant::now();
        loop {
            assert!(started.elapsed() < Duration::from_secs(10));
            let mut request = fixture.request("GET");
            if started.elapsed() >= pending_for {
                respond(&mut request, 200, final_state);
                break;
            }
            respond(&mut request, 200, "pending");
        }
        let output = child.wait(Duration::from_secs(3)).unwrap();
        fixture.assert_public_progress(&output);
        let progress = String::from_utf8_lossy(&output.stderr);
        assert!(progress.contains("Local Node accepted the join request"));
        assert!(progress.contains("75s"));
        if final_state == "applied" {
            assert!(progress.contains("Still waiting"));
            assert!(progress.contains("5s elapsed"));
            assert!(output.status.success());
            assert_eq!(
                output.stdout,
                b"Node joined Manager manager1. Configuration saved.\n"
            );
        } else {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(progress.contains("join failed"));
        }
    }
}

#[test]
fn join_reports_the_failed_stage_without_disclosing_the_invitation() {
    let fixture = Fixture::new();
    let child = fixture.spawn();
    respond(&mut fixture.request("POST"), 202, "pending");
    let failure = Response {
        status: 200,
        generation: None,
        is_config: false,
        body: serde_json::json!({"operation":1,"state":"failed","failure":"no_probe"})
            .to_string()
            .into_bytes(),
    };
    fixture
        .request("GET")
        .write_all(&http::encode_response(&failure))
        .unwrap();
    let output = child.wait(Duration::from_secs(3)).unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("child received no authenticated WireGuard probe")
    );
    fixture.assert_public_progress(&output);
}
