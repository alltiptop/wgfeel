//! A standalone Cargo test executable: the parent never installs a filter.
//! Every `--worker` invocation is a freshly executed, single-threaded process.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime};

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::process::{Pid, Resource, Signal, dumpable_behavior, getrlimit, kill_process};
use wgfeel_core::{DeviceId, DevicePublicKey, NetworkId, TenantPrivateKey};
use wgfeel_sandbox::{SandboxError, WorkerLimits, enter_worker};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};
use wgfeel_wireguard::{ContextConfig, ContextId, Event, Gateway, Limits, PeerConfig, PeerId};

const ADDRESS_SPACE: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("wgfeel-confinement-{}", std::process::id()));
        fs::create_dir(&path).expect("create unique disposable fixture directory");
        fs::write(path.join("neighbor-key"), b"disposable-public-test-marker").unwrap();
        Self(path)
    }

    fn neighbor(&self) -> PathBuf {
        self.0.join("neighbor-key")
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spawn(mode: &str, arguments: &[OsString]) -> ManagedChild {
    let mut argv = vec!["--worker".into(), mode.into()];
    argv.extend_from_slice(arguments);
    let environment = if mode == "nonempty-environment" {
        vec![("WGFEEL_PUBLIC_FIXTURE".into(), "must-be-rejected".into())]
    } else {
        vec![]
    };
    ManagedChild::spawn(
        ProcessSpec::new(std::env::current_exe().unwrap(), argv, environment, None),
        ProcessLimits {
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
    )
    .expect("spawn isolated probe process group")
}

fn successful_probe(mode: &str, arguments: &[OsString], installed: bool) {
    let mut child = spawn(mode, arguments);
    if installed {
        child
            .wait_for_stdout_line(b"READY", TIMEOUT)
            .expect("child must install policy before probing it");
    }
    let output = child
        .wait(TIMEOUT)
        .expect("probe exits within deadline and is reaped");
    assert!(
        output.status.success(),
        "probe {mode} failed: {}",
        output.status
    );
    assert!(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"PASS"),
        "probe {mode} did not report its complete assertions"
    );
    assert!(
        output.stderr.is_empty(),
        "probe diagnostics must not use stderr"
    );
}

fn permission_denied<T: std::fmt::Debug>(result: io::Result<T>) {
    assert_eq!(
        result.unwrap_err().raw_os_error(),
        Some(Errno::PERM.raw_os_error())
    );
}

fn nonblocking_stdin() {
    let stdin = io::stdin();
    let flags = fcntl_getfl(&stdin).unwrap();
    fcntl_setfl(&stdin, flags | OFlags::NONBLOCK).unwrap();
}

fn install() {
    assert_eq!(
        std::env::vars_os().count(),
        0,
        "probe has no inherited environment"
    );
    if let Err(error) = enter_worker(WorkerLimits {
        address_space_bytes: ADDRESS_SPACE,
    }) {
        println!("INSTALL {error}");
        std::process::exit(1);
    }
    println!("READY");
    io::stdout().flush().unwrap();
}

fn preflight_rejection(expected: SandboxError, bytes: u64, neighbor: &Path) {
    let old_core = getrlimit(Resource::Core);
    let old_space = getrlimit(Resource::As);
    let old_files = getrlimit(Resource::Nofile);
    let old_dumpable = dumpable_behavior().unwrap();
    assert_eq!(
        enter_worker(WorkerLimits {
            address_space_bytes: bytes
        }),
        Err(expected)
    );
    assert_eq!(getrlimit(Resource::Core), old_core);
    assert_eq!(getrlimit(Resource::As), old_space);
    assert_eq!(getrlimit(Resource::Nofile), old_files);
    assert_eq!(dumpable_behavior().unwrap(), old_dumpable);
    assert_eq!(
        fs::read(neighbor).unwrap(),
        b"disposable-public-test-marker"
    );
}

fn hex(value: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

fn wire_bytes(event: Event) -> Vec<u8> {
    match event {
        Event::Network { packet, .. } => packet.as_bytes().to_vec(),
        Event::Plaintext { .. } => panic!("expected encrypted network packet"),
    }
}

fn fresh_wireguard_exchange() {
    // These public RFC 7748 test vectors are decoded only after READY. The
    // production key-delivery protocol is deliberately not claimed here.
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let network = NetworkId::new("confined").unwrap();
    let context = ContextId::Tenant(network.clone());
    let peer = PeerId::Device(DeviceId::new("remote").unwrap());
    let mut left = Gateway::new(
        vec![ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(alice).unwrap(),
            vec![PeerConfig {
                id: peer.clone(),
                public_key: DevicePublicKey::new(bob_public).unwrap(),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let mut right = Gateway::new(
        vec![ContextConfig::tenant(
            network,
            TenantPrivateKey::new(bob).unwrap(),
            vec![PeerConfig {
                id: peer.clone(),
                public_key: DevicePublicKey::new(alice_public).unwrap(),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let source = "198.51.100.1:51820".parse().unwrap();
    let initiation = wire_bytes(left.initiate(&context, &peer).unwrap().unwrap());
    let response = wire_bytes(
        right
            .receive(&context, &peer, source, &initiation)
            .unwrap()
            .unwrap(),
    );
    let confirmation = wire_bytes(
        left.receive(&context, &peer, source, &response)
            .unwrap()
            .unwrap(),
    );
    assert!(
        right
            .receive(&context, &peer, source, &confirmation)
            .unwrap()
            .is_none()
    );
    for ipv6 in [false, true] {
        let mut plaintext = vec![0_u8; if ipv6 { 40 } else { 20 }];
        if ipv6 {
            plaintext[0] = 0x60;
            plaintext[6] = 253;
            plaintext[7] = 64;
        } else {
            plaintext[0] = 0x45;
            plaintext[2..4].copy_from_slice(&20_u16.to_be_bytes());
            plaintext[8] = 64;
            plaintext[9] = 253;
        }
        let ciphertext = wire_bytes(left.send(&context, &peer, &plaintext).unwrap());
        match right
            .receive(&context, &peer, source, &ciphertext)
            .unwrap()
            .unwrap()
        {
            Event::Plaintext {
                context: actual_context,
                peer: actual_peer,
                packet,
            } => {
                assert_eq!(actual_context, context);
                assert_eq!(actual_peer, peer);
                assert_eq!(packet.as_bytes(), plaintext);
            }
            Event::Network { .. } => panic!("expected authenticated plaintext"),
        }
        let reply = wire_bytes(right.send(&context, &peer, &plaintext).unwrap());
        match left
            .receive(&context, &peer, source, &reply)
            .unwrap()
            .unwrap()
        {
            Event::Plaintext {
                context: actual_context,
                peer: actual_peer,
                packet,
            } => {
                assert_eq!(actual_context, context);
                assert_eq!(actual_peer, peer);
                assert_eq!(packet.as_bytes(), plaintext);
            }
            Event::Network { .. } => panic!("expected authenticated return plaintext"),
        }
    }
}

fn worker(mode: &str, arguments: &[OsString]) {
    std::panic::set_hook(Box::new(|_| {}));
    match mode {
        "victim" => {
            println!("VICTIM");
            io::stdout().flush().unwrap();
            let _ = io::stdin().read(&mut [0_u8; 1]);
            return;
        }
        "missing-pipe" => {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    OsString::from("--worker"),
                    OsString::from("missing-pipe-final"),
                    arguments[0].clone(),
                ])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .unwrap();
            assert!(status.success());
        }
        "missing-pipe-final" => preflight_rejection(
            SandboxError::InvalidDescriptors,
            ADDRESS_SPACE,
            Path::new(&arguments[0]),
        ),
        "invalid-limits" => {
            for bytes in [0, 16 * 1024 * 1024 - 1, 1024 * 1024 * 1024 + 1, u64::MAX] {
                preflight_rejection(SandboxError::InvalidLimits, bytes, Path::new(&arguments[0]));
            }
        }
        "nonempty-environment" => {
            assert_eq!(
                std::env::var("WGFEEL_PUBLIC_FIXTURE").unwrap(),
                "must-be-rejected"
            );
            preflight_rejection(
                SandboxError::InvalidProcess,
                ADDRESS_SPACE,
                Path::new(&arguments[0]),
            );
            assert_eq!(
                std::env::var("WGFEEL_PUBLIC_FIXTURE").unwrap(),
                "must-be-rejected"
            );
        }
        "extra-descriptor" => {
            let extra = File::open(&arguments[0]).unwrap();
            preflight_rejection(
                SandboxError::InvalidDescriptors,
                ADDRESS_SPACE,
                Path::new(&arguments[0]),
            );
            std::hint::black_box(&extra);
        }
        "multiple-threads" => {
            let barrier = Arc::new(Barrier::new(2));
            let child_barrier = Arc::clone(&barrier);
            let thread = std::thread::spawn(move || {
                child_barrier.wait();
            });
            preflight_rejection(
                SandboxError::InvalidProcess,
                ADDRESS_SPACE,
                Path::new(&arguments[0]),
            );
            barrier.wait();
            thread.join().unwrap();
        }
        "allowed-runtime" => {
            nonblocking_stdin();
            install();
            assert_eq!(
                io::stdin().read(&mut [0_u8; 1]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let mut allocation = vec![0x5a_u8; 1024 * 1024];
            allocation.resize(2 * 1024 * 1024, 0x6b);
            assert_eq!(allocation[1024 * 1024], 0x6b);
            let before = Instant::now();
            std::thread::sleep(Duration::from_millis(2));
            assert!(before.elapsed() >= Duration::from_millis(2));
            assert!(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .is_ok()
            );
            fresh_wireguard_exchange();
        }
        "hold" => {
            install();
            let _ = io::stdin().read(&mut [0_u8; 1]);
            return;
        }
        "deny-file" => {
            install();
            permission_denied(File::open(&arguments[0]));
        }
        "deny-socket" => {
            install();
            permission_denied(UdpSocket::bind("127.0.0.1:0"));
        }
        "deny-signal" => {
            let pid = arguments[0].to_str().unwrap().parse::<i32>().unwrap();
            install();
            assert_eq!(
                kill_process(Pid::from_raw(pid).unwrap(), Signal::TERM),
                Err(Errno::PERM)
            );
        }
        "deny-thread" => {
            install();
            permission_denied(std::thread::Builder::new().spawn(|| {}));
        }
        "deny-exec" => {
            let executable = std::env::current_exe().unwrap();
            install();
            assert_eq!(
                Command::new(executable)
                    .arg("--escape")
                    .env_clear()
                    .exec()
                    .raw_os_error(),
                Some(Errno::PERM.raw_os_error())
            );
        }
        "deny-stderr" => {
            install();
            permission_denied(io::stderr().write_all(b"must-not-escape"));
        }
        _ => panic!("unknown worker probe mode"),
    }
    println!("PASS");
}

fn limits_are_visible_only_after_ready() {
    let mut child = spawn("hold", &[]);
    child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
    let limits = fs::read_to_string(format!("/proc/{}/limits", child.id())).unwrap();
    for (name, expected) in [
        ("Max core file size", "0"),
        ("Max address space", "67108864"),
    ] {
        let row = limits
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .expect("kernel resource limit row");
        assert_eq!(
            row.split_whitespace().take(2).collect::<Vec<_>>(),
            vec![expected, expected]
        );
    }
    let status = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert!(status.lines().any(|line| line == "Seccomp:\t2"));
    child.terminate().unwrap();
}

fn sibling_signal_is_denied() {
    let mut victim = spawn("victim", &[]);
    victim.wait_for_stdout_line(b"VICTIM", TIMEOUT).unwrap();
    successful_probe("deny-signal", &[victim.id().to_string().into()], true);
    let output = victim.terminate().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        Some(9),
        "victim survived until the harness killed it"
    );
}

fn probe_with_neighbor(mode: &str, installed: bool) {
    let directory = FixtureDirectory::new();
    successful_probe(mode, &[directory.neighbor().into_os_string()], installed);
}

fn main() -> std::process::ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.first().is_some_and(|arg| arg == "--worker") {
        let result =
            std::panic::catch_unwind(|| worker(arguments[1].to_str().unwrap(), &arguments[2..]));
        if result.is_err() {
            println!("FAIL");
            std::process::exit(1);
        }
        return std::process::ExitCode::SUCCESS;
    }
    assert!(
        !arguments.iter().any(|arg| arg == "--escape"),
        "forbidden exec succeeded"
    );
    fn is_error<T: std::error::Error>() {}
    is_error::<SandboxError>();
    let cases: &[(&str, fn())] = &[
        ("allowed_runtime_and_fresh_wireguard", || {
            successful_probe("allowed-runtime", &[], true)
        }),
        (
            "installed_kernel_limits",
            limits_are_visible_only_after_ready,
        ),
        ("neighbor_file_open_is_denied", || {
            probe_with_neighbor("deny-file", true)
        }),
        ("socket_creation_is_denied", || {
            successful_probe("deny-socket", &[], true)
        }),
        ("sibling_signal_is_denied", sibling_signal_is_denied),
        ("thread_creation_is_denied", || {
            successful_probe("deny-thread", &[], true)
        }),
        ("exec_is_denied", || {
            successful_probe("deny-exec", &[], true)
        }),
        ("stderr_is_not_a_data_channel", || {
            successful_probe("deny-stderr", &[], true)
        }),
        ("invalid_limits_leave_process_unchanged", || {
            probe_with_neighbor("invalid-limits", false)
        }),
        ("nonempty_environment_leaves_process_unchanged", || {
            probe_with_neighbor("nonempty-environment", false)
        }),
        ("missing_pipe_leaves_process_unchanged", || {
            probe_with_neighbor("missing-pipe", false)
        }),
        ("extra_descriptor_leaves_process_unchanged", || {
            probe_with_neighbor("extra-descriptor", false)
        }),
        ("multiple_threads_leave_process_unchanged", || {
            probe_with_neighbor("multiple-threads", false)
        }),
    ];
    wgfeel_test_support::runner::run(&arguments, cases)
}
