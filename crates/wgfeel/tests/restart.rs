#[path = "support/human.rs"]
mod human;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wgfeel_core::{
    Config, Device, DeviceId, DevicePublicKey, GatewayAssignment, ManagementConfig, Network,
    NetworkId, NodeId, Policy, TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_store::{LocalTenants, Store};
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

fn persist_main_snapshot(path: &Path, config: &Config, tenants: LocalTenants) {
    let node = NodeId::new("gateway-a").unwrap();
    let keys = wgfeel_test_support::fixture_node_keys([37; 32]);
    let assignments = tenants
        .network_ids()
        .map(|id| {
            let private = tenants.private_key(id).unwrap();
            TenantKeyAssignment::new(
                id.clone(),
                wgfeel_test_support::fixture_public(private.expose_bytes()),
            )
        })
        .collect();
    let projection = wgfeel_test_support::fixture_projection(config, &node, &keys, assignments);
    Store::open(path)
        .unwrap()
        .commit_projection(
            projection.management_id(),
            &projection,
            &node,
            &keys,
            &tenants,
        )
        .unwrap();
}
fn persisted_fixture(path: &Path) {
    persist_main_snapshot(
        path,
        &Config::from_json(CONFIG).unwrap(),
        LocalTenants::default(),
    );
}
fn tenant_fixture(path: &Path) {
    let network = NetworkId::new("alice").unwrap();
    let config = Config::new(
        17,
        vec![Network::new(network.clone(), vec![]).unwrap()],
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let tenants =
        LocalTenants::new(vec![(network, TenantPrivateKey::new([173; 32]).unwrap())]).unwrap();
    persist_main_snapshot(path, &config, tenants);
}
fn node(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn network(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn key(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}

fn projection_fixture(path: &Path) {
    let device = Device::new(
        DeviceId::new("client").unwrap(),
        key(11),
        vec!["10.1.0.1".parse().unwrap()],
    )
    .unwrap();
    let config = Config::new(
        23,
        vec![
            Network::new(network("alpha"), vec![device]).unwrap(),
            Network::new(network("beta"), vec![]).unwrap(),
        ],
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let assignment = GatewayAssignment::new(
        node("gateway-a"),
        key(101),
        wgfeel_test_support::fixture_gateway_public(&key(101)),
        vec![network("alpha"), network("beta")],
        vec![TenantKeyAssignment::new(network("alpha"), key(102))],
    )
    .unwrap();
    let projection = ManagementConfig::new(node("management"), config, vec![assignment])
        .unwrap()
        .project_for(&node("gateway-a"))
        .unwrap();
    let mut store = Store::open(path).unwrap();
    store
        .commit_projection(
            &node("management"),
            &projection,
            &node("gateway-a"),
            &wgfeel_test_support::fixture_node_keys([47; 32]),
            &LocalTenants::new(vec![(
                network("alpha"),
                TenantPrivateKey::new([48; 32]).unwrap(),
            )])
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn state_check_recovers_public_summaries_without_changing_any_snapshot() {
    for (setup, manager, generation, networks, devices, local_key) in [
        (persisted_fixture as fn(&Path), "main", 17, 1, 1, None),
        (tenant_fixture, "main", 17, 1, 0, Some(("alice", 173))),
        (
            projection_fixture,
            "management",
            23,
            2,
            1,
            Some(("alpha", 48)),
        ),
    ] {
        let fixture = Fixture::new();
        setup(&fixture.0);
        let path = fixture.0.join("state.json");
        let before = fs::read(&path).unwrap();
        let output = state_check(&fixture.0);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            human::summary(&output.stdout),
            serde_json::json!({
                "control": "child", "node_id": "gateway-a", "management_id": manager,
                "generation": generation, "networks": networks, "scope_networks": networks,
                "devices": devices, "local_contexts": usize::from(local_key.is_some()),
            })
        );
        assert!(
            fs::read(&path).unwrap() == before,
            "state-check changed its input"
        );
        if let Some((tenant, value)) = local_key {
            let recovered = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
            assert!(
                recovered
                    .local_tenants()
                    .private_key(&network(tenant))
                    .unwrap()
                    .expose_bytes()
                    == &[value; 32]
            );
        }
    }
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

#[test]
fn fresh_cli_rejects_mismatched_recipient_without_repair_or_secret_diagnostics() {
    let fixture = Fixture::new();
    projection_fixture(&fixture.0);
    let path = fixture.0.join("state.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    envelope["projection"]["assignment"]["recipient"] = "gateway-b".into();
    let altered = serde_json::to_vec(&envelope).unwrap();
    fs::write(&path, &altered).unwrap();
    let output = state_check(&fixture.0);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stderr);
    for value in [47_u8, 48] {
        assert!(!text.contains(&format!("{:?}", [value; 32])));
        assert!(!text.contains(&format!("{:?}", [value; 32]).replace(' ', "")));
    }
    assert!(!text.contains("private_key"));
    assert!(
        fs::read(&path).unwrap() == altered,
        "state-check repaired the invalid snapshot"
    );
}
