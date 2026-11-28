use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wgfeel_core::{Config, NodeId};
use wgfeel_store::Store;
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "wgfeel-cli-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self(directory)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn state_check(path: &Path) -> CapturedOutput {
    ManagedChild::spawn(
        ProcessSpec::new(
            env!("CARGO_BIN_EXE_wgfeel").into(),
            vec!["state-check".into(), "--state-dir".into(), path.into()],
            vec![],
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
    )
    .expect("start actual wgfeel executable")
    .wait(Duration::from_secs(10))
    .expect("state-check terminated within bounds")
}

const CONFIG: &str = r#"{
  "schema_version": 1,
  "generation": 17,
  "networks": [{"id": "alice", "devices": [{
    "id": "phone",
    "public_key": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
    "addresses": ["10.20.0.2", "fd20::2"]
  }]}],
  "policy": {"global_rules": [], "local_rules": [], "grants": []}
}"#;

fn persisted_fixture(path: &Path) {
    let mut store = Store::open(path).unwrap();
    let node = NodeId::new("gateway-a").unwrap();
    let keys = wgfeel_test_support::fixture_node_keys([37; 32]);
    let projection = wgfeel_test_support::fixture_projection(
        &Config::from_json(CONFIG).unwrap(),
        &node,
        &keys,
        vec![],
    );
    store
        .commit_projection(
            projection.management_id(),
            &projection,
            &node,
            &keys,
            &Default::default(),
        )
        .unwrap();
}

#[test]
fn new_process_recovers_production_state_without_provider_and_emits_only_public_summary() {
    let fixture = Fixture::new();
    persisted_fixture(&fixture.0);
    let before = fs::read(fixture.0.join("state.json")).unwrap();

    let output = state_check(&fixture.0);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Local state\n  Node ID        : gateway-a\n  Generation     : 17\n  Control        : child\n  Devices        : 1\n  Local Contexts : 0\n  Management ID  : main\n  Networks       : 1\n  Scope Networks : 1\n"
    );
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), before);
}

#[test]
fn empty_or_missing_state_is_an_error_and_does_not_create_credentials() {
    let fixture = Fixture::new();
    let output = state_check(&fixture.0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());

    let missing = fixture.0.join("missing");
    let output = state_check(&missing);
    assert!(!output.status.success());
    assert!(!missing.exists());
}

#[test]
fn corrupted_secret_state_fails_without_echoing_private_material() {
    let fixture = Fixture::new();
    let marker = "THIS_PRIVATE_VALUE_MUST_NEVER_APPEAR_IN_DIAGNOSTICS";
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.0.join("state.json"))
        .unwrap();
    writeln!(
        file,
        "{{\"storage_version\":3,\"service_private_key\":\"{marker}\"}}"
    )
    .unwrap();
    drop(file);
    let output = state_check(&fixture.0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !output.stderr.is_empty(),
        "expected a diagnostic for corrupt state"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}

#[test]
fn running_store_lock_is_respected_by_separate_cli_process() {
    let fixture = Fixture::new();
    persisted_fixture(&fixture.0);
    let store = Store::open(&fixture.0).unwrap();
    let output = state_check(&fixture.0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    drop(store);
    assert!(state_check(&fixture.0).status.success());
}

#[test]
fn unsafe_state_permissions_are_rejected_without_chmod_repair() {
    let fixture = Fixture::new();
    persisted_fixture(&fixture.0);
    let state = fixture.0.join("state.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    let output = state_check(&fixture.0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
