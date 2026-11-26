#[path = "support/human.rs"]
mod human;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use wgfeel_core::{Config, Network, NetworkId, NodeId, Policy, TenantPrivateKey};
use wgfeel_store::{LocalTenants, Store};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-tenant-cli-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn fresh_cli_process_loads_tenant_snapshot_and_emits_only_existing_public_summary() {
    let fixture = Fixture::new();
    let network = NetworkId::new("alice").unwrap();
    let config = Config::new(
        17,
        vec![Network::new(network.clone(), vec![]).unwrap()],
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let tenants = LocalTenants::new(vec![(
        network.clone(),
        TenantPrivateKey::new([173; 32]).unwrap(),
    )])
    .unwrap();
    let mut store = Store::open(&fixture.0).unwrap();
    let node = NodeId::new("gateway-a").unwrap();
    let keys = wgfeel_test_support::fixture_node_keys([37; 32]);
    let projection = wgfeel_test_support::fixture_projection(
        &config,
        &node,
        &keys,
        vec![wgfeel_core::TenantKeyAssignment::new(
            network.clone(),
            wgfeel_test_support::fixture_public(&[173; 32]),
        )],
    );
    store
        .commit_projection(
            projection.management_id(),
            &projection,
            &node,
            &keys,
            &tenants,
        )
        .unwrap();
    drop(store);
    let before = fs::read(fixture.0.join("state.json")).unwrap();
    for _ in 0..2 {
        let spec = ProcessSpec::new(
            PathBuf::from(env!("CARGO_BIN_EXE_wgfeel")),
            vec![
                "state-check".into(),
                "--state-dir".into(),
                fixture.0.clone().into(),
            ],
            vec![],
            None,
        );
        let output = ManagedChild::spawn(
            spec,
            ProcessLimits {
                max_stdout_bytes: 16_384,
                max_stderr_bytes: 16_384,
            },
        )
        .unwrap()
        .wait(Duration::from_secs(10))
        .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let actual: serde_json::Value = human::summary(&output.stdout);
        assert_eq!(
            actual,
            serde_json::json!({"control":"child","management_id":"main","scope_networks":1,"local_contexts":1,"generation":17,"node_id":"gateway-a","networks":1,"devices":0})
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("173"));
    }
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), before);
    let recovered = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
    assert_eq!(
        recovered
            .local_tenants()
            .private_key(&network)
            .unwrap()
            .expose_bytes(),
        &[173; 32]
    );
}
