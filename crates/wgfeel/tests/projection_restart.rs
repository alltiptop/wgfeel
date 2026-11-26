#[path = "support/human.rs"]
mod human;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wgfeel_core::{
    Config, Device, DeviceId, DevicePublicKey, GatewayAssignment, ManagementConfig, Network,
    NetworkId, NodeId, Policy, TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_store::{LocalTenants, Store};
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-projection-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn populated() -> Directory {
    let directory = Directory::new();
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
        (key(101)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(key(101))),
        vec![network("alpha"), network("beta")],
        vec![TenantKeyAssignment::new(network("alpha"), key(102))],
    )
    .unwrap();
    let projection = ManagementConfig::new(node("management"), config, vec![assignment])
        .unwrap()
        .project_for(&node("gateway-a"))
        .unwrap();
    let mut store = Store::initialize(&directory.state()).unwrap();
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
    drop(store);
    directory
}

fn state_check(directory: &Directory) -> CapturedOutput {
    ManagedChild::spawn(
        ProcessSpec::new(
            env!("CARGO_BIN_EXE_wgfeel").into(),
            vec![
                "state-check".into(),
                "--state-dir".into(),
                directory.state().into_os_string(),
            ],
            vec![],
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
        },
    )
    .unwrap()
    .wait(Duration::from_secs(5))
    .unwrap()
}
fn no_secrets(output: &CapturedOutput) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for value in [47_u8, 48] {
        assert!(!text.contains(&format!("{:?}", [value; 32])));
        assert!(!text.contains(&format!("{:?}", [value; 32]).replace(' ', "")));
    }
    assert!(!text.contains("private_key"));
}

#[test]
fn fresh_cli_reads_projection_summary_without_secret_output_or_state_mutation() {
    let directory = populated();
    let before = fs::read(directory.state().join("state.json")).unwrap();
    let output = state_check(&directory);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    no_secrets(&output);
    let summary: serde_json::Value = human::summary(&output.stdout);
    assert_eq!(
        summary,
        serde_json::json!({ "generation":23, "node_id":"gateway-a", "networks":2, "devices":1, "control":"child", "management_id":"management", "scope_networks":2, "local_contexts":1 })
    );
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        before
    );
}

#[test]
fn fresh_cli_rejects_mismatched_recipient_without_repair_or_secret_diagnostics() {
    let directory = populated();
    let path = directory.state().join("state.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    envelope["projection"]["assignment"]["recipient"] = "gateway-b".into();
    let altered = serde_json::to_vec(&envelope).unwrap();
    fs::write(&path, &altered).unwrap();
    let output = state_check(&directory);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    no_secrets(&output);
    assert_eq!(fs::read(&path).unwrap(), altered);
}
