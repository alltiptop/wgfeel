use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wgfeel_test_support::{ManagedChild, ProcessError, ProcessLimits, ProcessSpec};

const TIMEOUT: Duration = Duration::from_secs(10);
const SECRET: &str = "HARNESS_SECRET_MUST_NOT_APPEAR_IN_DEBUG";
static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "wgfeel-harness-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn arguments() -> Vec<OsString> {
    [
        "--exact",
        "subprocess_fixture",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn spec(mode: &str, fixture: Option<&Fixture>) -> ProcessSpec {
    let mut environment = vec![("WGFEEL_HARNESS_MODE".into(), mode.into())];
    if let Some(fixture) = fixture {
        environment.push(("WGFEEL_HARNESS_DIRECTORY".into(), fixture.0.clone().into()));
    }
    ProcessSpec::new(
        std::env::current_exe().unwrap(),
        arguments(),
        environment,
        None,
    )
}

fn limits() -> ProcessLimits {
    ProcessLimits {
        max_stdout_bytes: 300_000,
        max_stderr_bytes: 300_000,
    }
}

fn spawn(mode: &str) -> ManagedChild {
    ManagedChild::spawn(spec(mode, None), limits()).unwrap()
}

fn direct_child_is_reaped(pid: u32) {
    assert!(
        !PathBuf::from(format!("/proc/{pid}")).exists(),
        "direct child remains present after its cleanup: {pid}"
    );
}

fn wait_until_terminated(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(stat) => {
                // The executable name can contain spaces/parentheses. The state follows its final ')'.
                let state = stat.rsplit_once(')').unwrap().1.split_whitespace().next();
                if state == Some("Z") || state == Some("X") {
                    return;
                }
            }
            Err(error) => panic!("cannot inspect process state: {error}"),
        }
        assert!(Instant::now() < deadline, "process still running: {pid}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn invocation_preserves_arguments_explicit_environment_and_working_directory() {
    let fixture = Fixture::new();
    let literal = "literal spaces ; $() ' \" *";
    let mut argv = arguments();
    argv.extend(["--skip".into(), literal.into()]);
    let spec = ProcessSpec::new(
        std::env::current_exe().unwrap(),
        argv,
        vec![
            ("WGFEEL_HARNESS_MODE".into(), "invocation".into()),
            ("WGFEEL_HARNESS_VALUE".into(), SECRET.into()),
        ],
        Some(fixture.0.clone()),
    );
    assert!(!format!("{spec:?}").contains(SECRET));
    let child = ManagedChild::spawn(spec, limits()).unwrap();
    assert!(!format!("{child:?}").contains(SECRET));
    let output = child.wait(TIMEOUT).unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("ARG={literal}\n")));
    assert!(stdout.contains(&format!("VALUE={SECRET}\n")));
    assert!(stdout.contains(&format!("CWD={}\n", fixture.0.display())));
    assert!(stdout.contains("ENVIRONMENT_COUNT=2\n"));
    assert!(!format!("{output:?}").contains(SECRET));
}

#[test]
fn both_streams_drain_beyond_pipe_capacity_without_deadlock() {
    let child = spawn("both_streams");
    let pid = child.id();
    let output = child.wait(TIMEOUT).unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == 0x91).count(),
        96 * 1024
    );
    assert_eq!(output.stderr, vec![0x92; 128 * 1024]);
    direct_child_is_reaped(pid);
}

#[test]
fn exact_capture_limit_is_allowed_and_one_more_byte_is_rejected() {
    let exact = ManagedChild::spawn(
        spec("stderr_1024", None),
        ProcessLimits {
            max_stdout_bytes: 4096,
            max_stderr_bytes: 1024,
        },
    )
    .unwrap()
    .wait(TIMEOUT)
    .unwrap();
    assert!(exact.status.success());
    assert_eq!(exact.stderr, vec![0x92; 1024]);
    let child = ManagedChild::spawn(
        spec("stderr_1025", None),
        ProcessLimits {
            max_stdout_bytes: 4096,
            max_stderr_bytes: 1024,
        },
    )
    .unwrap();
    let pid = child.id();
    assert_eq!(child.wait(TIMEOUT).unwrap_err(), ProcessError::OutputLimit);
    direct_child_is_reaped(pid);
}

#[test]
fn each_capture_limit_aborts_and_reaps_a_noisy_child() {
    for mode in ["exceed_stdout", "exceed_stderr"] {
        let child = ManagedChild::spawn(
            spec(mode, None),
            ProcessLimits {
                max_stdout_bytes: 1024,
                max_stderr_bytes: 1024,
            },
        )
        .unwrap();
        let pid = child.id();
        assert_eq!(child.wait(TIMEOUT).unwrap_err(), ProcessError::OutputLimit);
        direct_child_is_reaped(pid);
    }
}

#[test]
fn readiness_requires_an_exact_complete_stdout_line_and_preserves_capture() {
    let mut child = spawn("ready");
    child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
    let pid = child.id();
    let output = child.terminate().unwrap();
    assert!(!output.status.success());
    assert!(
        output
            .stdout
            .windows(b"noise\nREADY\n".len())
            .any(|window| window == b"noise\nREADY\n")
    );
    direct_child_is_reaped(pid);
}

#[test]
fn readiness_on_quick_exit_preserves_status_and_both_captures_for_wait() {
    for mode in ["exit_before_readiness", "exit_after_readiness"] {
        let mut child = spawn(mode);
        let pid = child.id();
        if mode == "exit_before_readiness" {
            child
                .wait_for_stdout_line(b"STDERR_WRITTEN", TIMEOUT)
                .unwrap();
            child.write_stdin_line(b"").unwrap();
            wait_until_terminated(pid);
        }
        child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
        if mode == "exit_after_readiness" {
            child.write_stdin_line(b"").unwrap();
        }
        let output = child.wait(TIMEOUT).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(
            output
                .stdout
                .windows(b"\nREADY\n".len())
                .any(|window| window == b"\nREADY\n")
        );
        assert_eq!(output.stderr, vec![0x93; 64 * 1024]);
        direct_child_is_reaped(pid);
    }
}

#[test]
fn readiness_cursor_cannot_reuse_a_previously_matched_or_skipped_line() {
    for marker in [b"READY".as_slice(), b"noise".as_slice()] {
        let mut child = spawn("ready");
        child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
        let pid = child.id();
        assert_eq!(
            child.wait_for_stdout_line(marker, Duration::from_millis(25)),
            Err(ProcessError::Timeout)
        );
        direct_child_is_reaped(pid);
    }
}

#[test]
fn early_exit_without_exact_marker_cleans_up_and_invalidates_handle() {
    let mut child = spawn("wrong_marker");
    let pid = child.id();
    assert_eq!(
        child.wait_for_stdout_line(b"READY", TIMEOUT),
        Err(ProcessError::ExitedBeforeReady)
    );
    direct_child_is_reaped(pid);
    assert_eq!(
        child.wait_for_stdout_line(b"READY", TIMEOUT),
        Err(ProcessError::AlreadyFinished)
    );
}

#[test]
fn partial_line_and_stderr_marker_do_not_satisfy_readiness() {
    for mode in ["partial_marker", "stderr_marker"] {
        let mut child = spawn(mode);
        let pid = child.id();
        assert_eq!(
            child.wait_for_stdout_line(b"READY", Duration::from_millis(100)),
            Err(ProcessError::Timeout)
        );
        direct_child_is_reaped(pid);
    }
}

#[test]
fn timeout_kills_and_reaps_instead_of_only_reporting_failure() {
    let mut child = spawn("ready");
    child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
    let pid = child.id();
    let started = Instant::now();
    assert_eq!(
        child.wait(Duration::from_millis(25)).unwrap_err(),
        ProcessError::Timeout
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    direct_child_is_reaped(pid);
}

#[test]
fn invalid_marker_also_cleans_up_the_started_process() {
    for marker in [vec![], b"one\ntwo".to_vec(), vec![b'x'; 300_001]] {
        let mut child = spawn("ready");
        let pid = child.id();
        assert_eq!(
            child.wait_for_stdout_line(&marker, TIMEOUT),
            Err(ProcessError::InvalidMarker)
        );
        direct_child_is_reaped(pid);
    }
}

#[test]
fn invalid_limits_are_rejected_before_a_process_is_spawned() {
    for (stdout, stderr) in [(0, 1), (1, 0), (1_048_577, 1), (1, 1_048_577)] {
        let spec = ProcessSpec::new(
            PathBuf::from("/no/such/wgfeel-fixture"),
            vec![],
            vec![],
            None,
        );
        assert_eq!(
            ManagedChild::spawn(
                spec,
                ProcessLimits {
                    max_stdout_bytes: stdout,
                    max_stderr_bytes: stderr
                }
            )
            .unwrap_err(),
            ProcessError::InvalidLimits
        );
    }
}

#[test]
fn spawn_error_diagnostics_do_not_include_secrets() {
    let spec = ProcessSpec::new(
        PathBuf::from(format!("/no/such/{SECRET}")),
        vec![SECRET.into()],
        vec![("SECRET".into(), SECRET.into())],
        Some(PathBuf::from(format!("/no/such/{SECRET}"))),
    );
    assert!(!format!("{spec:?}").contains(SECRET));
    let error = ManagedChild::spawn(spec, limits()).unwrap_err();
    assert_eq!(error, ProcessError::Spawn);
    assert!(!format!("{error:?}").contains(SECRET));
    assert!(!error.to_string().contains(SECRET));
}

#[test]
fn leader_exit_cleans_up_descendants_holding_capture_pipes() {
    let fixture = Fixture::new();
    let child =
        ManagedChild::spawn(spec("spawn_descendant_then_exit", Some(&fixture)), limits()).unwrap();
    let leader = child.id();
    let started = Instant::now();
    let output = child.wait(TIMEOUT).unwrap();
    assert!(output.status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
    let descendant = fs::read_to_string(fixture.0.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();
    direct_child_is_reaped(leader);
    wait_until_terminated(descendant);
}

#[test]
fn dropping_ready_leader_cleans_up_its_same_group_descendants() {
    let fixture = Fixture::new();
    let mut child =
        ManagedChild::spawn(spec("spawn_descendant_then_wait", Some(&fixture)), limits()).unwrap();
    child.wait_for_stdout_line(b"READY", TIMEOUT).unwrap();
    let leader = child.id();
    let descendant = fs::read_to_string(fixture.0.join("descendant.pid"))
        .unwrap()
        .parse()
        .unwrap();
    drop(child);
    direct_child_is_reaped(leader);
    wait_until_terminated(descendant);
}

fn block_on_stdin() {
    let mut signal = [0_u8; 1];
    let _ = io::stdin().read_exact(&mut signal);
}

#[test]
fn next_stdout_line_preserves_dynamic_bytes_and_consumes_each_complete_line() {
    let mut child = spawn("dynamic_lines");
    child.wait_for_stdout_line(b"BEGIN", TIMEOUT).unwrap();
    assert_eq!(
        child.next_stdout_line(TIMEOUT).unwrap(),
        b"{\"port\":43210}"
    );
    assert_eq!(child.next_stdout_line(TIMEOUT).unwrap(), b"");
    assert_eq!(child.next_stdout_line(TIMEOUT).unwrap(), [0xff, b'x']);
    let pid = child.id();
    assert_eq!(
        child.next_stdout_line(Duration::from_millis(30)),
        Err(ProcessError::Timeout)
    );
    direct_child_is_reaped(pid);
}

#[test]
fn next_stdout_line_preserves_quick_exit_status_and_final_capture() {
    let mut child = spawn("dynamic_exit");
    child.wait_for_stdout_line(b"BEGIN", TIMEOUT).unwrap();
    assert_eq!(
        child.next_stdout_line(TIMEOUT).unwrap(),
        b"{\"port\":43210}"
    );
    let output = child.wait(TIMEOUT).unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.ends_with(b"{\"port\":43210}\n"));
    assert_eq!(output.stderr, b"final diagnostic");
}

#[test]
fn next_stdout_line_never_accepts_unterminated_output_at_eof() {
    let mut child = spawn("dynamic_partial");
    child.wait_for_stdout_line(b"BEGIN", TIMEOUT).unwrap();
    let pid = child.id();
    assert_eq!(
        child.next_stdout_line(TIMEOUT),
        Err(ProcessError::ExitedBeforeReady)
    );
    direct_child_is_reaped(pid);
}

#[test]
#[ignore = "Rust fixture process; invoked explicitly by parent harness tests"]
fn subprocess_fixture() {
    let mode = std::env::var("WGFEEL_HARNESS_MODE").unwrap();
    match mode.as_str() {
        "dynamic_lines" => {
            io::stdout()
                .write_all(b"\nBEGIN\n{\"port\":43210}\n\n\xffx\n")
                .unwrap();
            io::stdout().flush().unwrap();
            block_on_stdin();
        }
        "dynamic_exit" => {
            io::stderr().write_all(b"final diagnostic").unwrap();
            println!("\nBEGIN\n{{\"port\":43210}}");
            io::stdout().flush().unwrap();
            std::process::exit(7);
        }
        "dynamic_partial" => {
            print!("\nBEGIN\nunterminated");
            io::stdout().flush().unwrap();
            std::process::exit(7);
        }
        "invocation" => {
            let argv: Vec<_> = std::env::args().collect();
            let index = argv.iter().position(|value| value == "--skip").unwrap();
            println!("ARG={}", argv[index + 1]);
            println!("VALUE={}", std::env::var("WGFEEL_HARNESS_VALUE").unwrap());
            println!("CWD={}", std::env::current_dir().unwrap().display());
            println!("ENVIRONMENT_COUNT={}", std::env::vars_os().count());
        }
        "both_streams" => {
            io::stdout().write_all(&vec![0x91; 96 * 1024]).unwrap();
            io::stderr().write_all(&vec![0x92; 128 * 1024]).unwrap();
        }
        "stderr_1024" | "stderr_1025" => {
            let count = if mode == "stderr_1024" { 1024 } else { 1025 };
            io::stderr().write_all(&vec![0x92; count]).unwrap();
        }
        "exceed_stdout" => {
            let _ = io::stdout().write_all(&vec![0x91; 2 * 1024 * 1024]);
        }
        "exceed_stderr" => {
            let _ = io::stderr().write_all(&vec![0x92; 2 * 1024 * 1024]);
        }
        "ready" => {
            println!("\nnoise\nREADY");
            io::stdout().flush().unwrap();
            block_on_stdin();
        }
        "exit_before_readiness" | "exit_after_readiness" => {
            io::stderr().write_all(&vec![0x93; 64 * 1024]).unwrap();
            if mode == "exit_before_readiness" {
                // Drain the large stderr write before waiting for exit on an unread READY.
                println!("\nSTDERR_WRITTEN");
                io::stdout().flush().unwrap();
                block_on_stdin();
            }
            println!("\nREADY");
            io::stdout().flush().unwrap();
            if mode == "exit_after_readiness" {
                block_on_stdin();
            }
            std::process::exit(7);
        }
        "wrong_marker" => println!("NOT_READY"),
        "partial_marker" => {
            print!("READY");
            io::stdout().flush().unwrap();
            block_on_stdin();
        }
        "stderr_marker" => {
            eprintln!("READY");
            block_on_stdin();
        }
        "spawn_descendant_then_exit" | "spawn_descendant_then_wait" => {
            #[expect(
                clippy::zombie_processes,
                reason = "The leader must exit or be killed without waiting to test cleanup of descendants retaining capture pipes; host init reaps the orphan."
            )]
            let descendant = Command::new(std::env::current_exe().unwrap())
                .args(arguments())
                .env("WGFEEL_HARNESS_MODE", "descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let directory = PathBuf::from(std::env::var_os("WGFEEL_HARNESS_DIRECTORY").unwrap());
            fs::write(
                directory.join("descendant.pid"),
                descendant.id().to_string(),
            )
            .unwrap();
            if mode == "spawn_descendant_then_wait" {
                println!("\nREADY");
                io::stdout().flush().unwrap();
                block_on_stdin();
            }
        }
        "descendant" => std::thread::sleep(Duration::from_secs(30)),
        _ => panic!("unknown controlled fixture mode"),
    }
}
