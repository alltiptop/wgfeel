use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use wgfeel_core::{
    Action, Config, Device, DeviceId, DevicePublicKey, Endpoint, MAX_DEVICES, MAX_NETWORKS,
    MAX_POLICY_RULES, MAX_PROJECTION_BYTES, Network, NetworkId, NodeId, NodeKeys, Policy, Rule,
    TenantPrivateKey,
};
use wgfeel_store::{CommitStage, LocalTenants, Store, StoreError};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-tenant-store-{}-{}",
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

fn id(name: &str) -> NetworkId {
    NetworkId::new(name).unwrap()
}
fn node() -> NodeId {
    NodeId::new("gateway-a").unwrap()
}
fn node_key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([37; 32])
}
fn config(generation: u64, names: &[&str]) -> Config {
    Config::new(
        generation,
        names
            .iter()
            .map(|name| Network::new(id(name), vec![]).unwrap())
            .collect(),
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap()
}
fn tenants(entries: &[(&str, u8)]) -> LocalTenants {
    LocalTenants::new(
        entries
            .iter()
            .map(|(name, byte)| (id(name), TenantPrivateKey::new([*byte; 32]).unwrap()))
            .collect(),
    )
    .unwrap()
}
fn bytes(byte: u8) -> String {
    vec![byte.to_string(); 32].join(",")
}
fn entry(name: &str, byte: u8) -> String {
    format!(r#"{{"network":"{name}","private_key":[{}]}}"#, bytes(byte))
}
fn assigned(
    config: &Config,
    id: &NodeId,
    keys: &NodeKeys,
    local: &LocalTenants,
) -> wgfeel_core::GatewayProjection {
    let tenants = local
        .network_ids()
        .map(|id| {
            let key = local.private_key(id).unwrap();
            wgfeel_core::TenantKeyAssignment::new(
                id.clone(),
                wgfeel_test_support::fixture_public(key.expose_bytes()),
            )
        })
        .collect();
    wgfeel_test_support::fixture_projection(config, id, keys, tenants)
}
fn publish(
    store: &mut Store,
    config: &Config,
    id: &NodeId,
    keys: &NodeKeys,
    local: &LocalTenants,
) -> Result<(), StoreError> {
    let projection = assigned(config, id, keys, local);
    store.commit_projection(projection.management_id(), &projection, id, keys, local)
}
fn snapshot(field: Option<&str>) -> String {
    let local = tenants(&[("alice", 71)]);
    let projection = assigned(&config(1, &["alice", "bob"]), &node(), &node_key(), &local)
        .to_json()
        .unwrap();
    let field = field
        .map(|value| format!(",\"tenant_private_keys\":{value}"))
        .unwrap_or_default();
    format!(
        r#"{{"storage_version":3,"node_id":"gateway-a","gateway_private_key":{:?},"service_private_key":[{}],"projection":{projection}{field}}}"#,
        node_key().gateway().expose_bytes(),
        bytes(37)
    )
}
fn write_fixture(path: &Path, contents: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("state.json"))
        .unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}
fn invalid_snapshot(contents: &str) {
    let fixture = Fixture::new();
    write_fixture(&fixture.0, contents);
    let before = fs::read(fixture.0.join("state.json")).unwrap();
    let store = Store::open(&fixture.0).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidState)));
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), before);
}
fn assert_key(local: &LocalTenants, name: &str, byte: u8) {
    assert_eq!(
        local.private_key(&id(name)).unwrap().expose_bytes(),
        &[byte; 32]
    );
}

#[test]
fn local_mapping_is_an_explicit_subset_with_exact_key_lookup() {
    let local = tenants(&[("alice", 71)]);
    assert_eq!(local.network_ids().collect::<Vec<_>>(), vec![&id("alice")]);
    assert_key(&local, "alice", 71);
    assert!(local.private_key(&id("bob")).is_none());
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    publish(
        &mut store,
        &config(1, &["alice", "bob"]),
        &node(),
        &node_key(),
        &local,
    )
    .unwrap();
    let loaded = store.load().unwrap().unwrap();
    assert_key(loaded.local_tenants(), "alice", 71);
    assert!(loaded.local_tenants().private_key(&id("bob")).is_none());
}

#[test]
fn duplicate_local_ids_and_raw_keys_are_rejected() {
    for entries in [
        vec![("alice", 71), ("alice", 72)],
        vec![("alice", 71), ("bob", 71)],
    ] {
        let entries = entries
            .into_iter()
            .map(|(name, byte)| (id(name), TenantPrivateKey::new([byte; 32]).unwrap()))
            .collect();
        assert!(matches!(
            LocalTenants::new(entries),
            Err(StoreError::InvalidLocalTenants)
        ));
    }
}

#[test]
fn unconfigured_context_or_raw_node_key_reuse_cannot_be_committed() {
    for local in [tenants(&[("unknown", 71)]), tenants(&[("alice", 37)])] {
        let fixture = Fixture::new();
        let mut store = Store::open(&fixture.0).unwrap();
        let desired = assigned(
            &config(1, &["alice"]),
            &node(),
            &node_key(),
            &tenants(&[("alice", 71)]),
        );
        assert!(matches!(
            store.commit_projection(
                desired.management_id(),
                &desired,
                &node(),
                &node_key(),
                &local
            ),
            Err(StoreError::InvalidLocalTenants)
        ));
        assert!(store.load().unwrap().is_none());
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
    }
}

fn maximum_entries(count: usize) -> Vec<(NetworkId, TenantPrivateKey)> {
    (0..count)
        .map(|index| {
            let name = format!("n{index:03}{}", "x".repeat(60));
            let mut bytes = [255; 32];
            bytes[..2].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            (id(&name), TenantPrivateKey::new(bytes).unwrap())
        })
        .collect()
}

#[test]
fn maximum_local_context_count_round_trips_and_next_entry_is_rejected() {
    assert!(matches!(
        LocalTenants::new(maximum_entries(MAX_NETWORKS + 1)),
        Err(StoreError::InvalidLocalTenants)
    ));
    let local = LocalTenants::new(maximum_entries(MAX_NETWORKS)).unwrap();
    let public = Config::new(
        1,
        local
            .network_ids()
            .map(|id| Network::new(id.clone(), vec![]).unwrap())
            .collect(),
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    publish(&mut store, &public, &node(), &node_key(), &local).unwrap();
    drop(store);
    let reopened = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
    assert_eq!(reopened.local_tenants().network_ids().count(), MAX_NETWORKS);
    for name in local.network_ids() {
        assert_eq!(
            reopened
                .local_tenants()
                .private_key(name)
                .unwrap()
                .expose_bytes(),
            local.private_key(name).unwrap().expose_bytes()
        );
    }
    assert_eq!(
        fs::metadata(fixture.0.join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn dense_maximum_configuration_and_local_keys_fit_the_unchanged_state_bound() {
    let local = LocalTenants::new(maximum_entries(MAX_NETWORKS)).unwrap();
    let networks = local.network_ids().cloned().collect::<Vec<_>>();
    let device_id = |index| DeviceId::new(&format!("d{index:03}{}", "y".repeat(60))).unwrap();
    let source = Endpoint::new(networks[0].clone(), device_id(0));
    let destination = Endpoint::new(networks[0].clone(), device_id(1));
    let public = Config::new(
        1,
        networks
            .iter()
            .enumerate()
            .map(|(network_index, network)| {
                let devices = (0..MAX_DEVICES / MAX_NETWORKS)
                    .map(|within| {
                        let index = network_index * (MAX_DEVICES / MAX_NETWORKS) + within;
                        let mut key = [255; 32];
                        key[..2].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
                        Device::new(
                            device_id(index),
                            DevicePublicKey::new(key).unwrap(),
                            vec![
                                std::net::IpAddr::from([
                                    10,
                                    254,
                                    254,
                                    u8::try_from(within + 2).unwrap(),
                                ]),
                                std::net::Ipv6Addr::new(
                                    0xfdff,
                                    0xffff,
                                    0xffff,
                                    0xffff,
                                    0xffff,
                                    0xffff,
                                    0xffff,
                                    u16::try_from(within + 2).unwrap(),
                                )
                                .into(),
                            ],
                        )
                        .unwrap()
                    })
                    .collect();
                Network::new(network.clone(), devices).unwrap()
            })
            .collect(),
        Policy::new(
            vec![Rule::new(source, destination, Action::Deny); MAX_POLICY_RULES],
            vec![],
            vec![],
        ),
    )
    .unwrap();
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    publish(&mut store, &public, &node(), &node_key(), &local).unwrap();
    drop(store);
    let recovered = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
    assert_eq!(recovered.config(), &public);
    assert_eq!(
        recovered.local_tenants().network_ids().count(),
        MAX_NETWORKS
    );
    for network in local.network_ids() {
        assert_eq!(
            recovered
                .local_tenants()
                .private_key(network)
                .unwrap()
                .expose_bytes(),
            local.private_key(network).unwrap().expose_bytes()
        );
    }
    assert!(
        fs::metadata(fixture.0.join("state.json")).unwrap().len()
            <= (MAX_PROJECTION_BYTES + 65_536) as u64
    );
}

#[test]
fn assigned_snapshot_loads_without_inventing_other_keys() {
    let fixture = Fixture::new();
    write_fixture(
        &fixture.0,
        &snapshot(Some(&format!("[{}]", entry("alice", 71)))),
    );
    let state = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
    assert_eq!(state.service_private_key().expose_bytes(), &[37; 32]);
    assert_eq!(state.config(), &config(1, &["alice", "bob"]));
    assert_key(state.local_tenants(), "alice", 71);
    assert!(state.local_tenants().private_key(&id("bob")).is_none());
}

#[test]
fn assigned_tenant_material_must_be_present() {
    for field in [None, Some("null"), Some("[]")] {
        invalid_snapshot(&snapshot(field));
    }
}

#[test]
fn malformed_or_ambiguous_tenant_entries_fail_closed_on_load() {
    let valid = entry("alice", 71);
    for records in [
        format!("[{valid},{valid}]"),
        format!("[{},{}]", entry("alice", 71), entry("bob", 71)),
        format!("[{}]", entry("unknown", 71)),
        format!("[{}]", entry("alice", 37)),
        format!("[{}]", entry("alice", 0)),
        format!("[{}]", entry("../alice", 71)),
        format!(
            "[{}]",
            valid.replace("\"network\":", "\"unknown\":true,\"network\":")
        ),
        format!(
            "[{}]",
            valid.replace(
                "\"network\":\"alice\"",
                "\"network\":\"alice\",\"network\":\"bob\""
            )
        ),
        format!(
            "[{}]",
            valid.replace(
                "\"private_key\":",
                &format!("\"private_key\":[{}],\"private_key\":", bytes(72))
            )
        ),
        format!(
            "[{}]",
            valid.replace(&format!("[{}]", bytes(71)), "[71,71]")
        ),
        r#"[{"network":"alice"}]"#.to_owned(),
        r#"[{"network":"alice","private_key":null}]"#.to_owned(),
    ] {
        invalid_snapshot(&snapshot(Some(&records)));
    }
    invalid_snapshot(&snapshot(Some("[]")).replace(
        "\"tenant_private_keys\":[]",
        "\"tenant_private_keys\":[],\"tenant_private_keys\":[]",
    ));
}

#[test]
fn incomplete_key_material_cannot_replace_an_applied_projection() {
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    let local = tenants(&[("alice", 71)]);
    publish(
        &mut store,
        &config(1, &["alice", "bob"]),
        &node(),
        &node_key(),
        &local,
    )
    .unwrap();
    let before = fs::read(fixture.0.join("state.json")).unwrap();
    let desired = assigned(&config(2, &["alice", "bob"]), &node(), &node_key(), &local);
    assert!(matches!(
        store.commit_projection(
            desired.management_id(),
            &desired,
            &node(),
            &node_key(),
            &LocalTenants::default()
        ),
        Err(StoreError::InvalidLocalTenants)
    ));
    assert_key(store.load().unwrap().unwrap().local_tenants(), "alice", 71);
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), before);
}

#[test]
fn explicit_replacement_rotates_adds_and_removes_only_at_greater_generation() {
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    publish(
        &mut store,
        &config(1, &["alice", "bob"]),
        &node(),
        &node_key(),
        &tenants(&[("alice", 71)]),
    )
    .unwrap();
    let replacement = tenants(&[("alice", 72), ("bob", 81)]);
    assert!(matches!(
        publish(
            &mut store,
            &config(1, &["alice", "bob"]),
            &node(),
            &node_key(),
            &replacement
        ),
        Err(StoreError::RevisionNotIncreasing)
    ));
    assert_key(store.load().unwrap().unwrap().local_tenants(), "alice", 71);
    publish(
        &mut store,
        &config(2, &["alice", "bob"]),
        &node(),
        &node_key(),
        &replacement,
    )
    .unwrap();
    let state = store.load().unwrap().unwrap();
    assert_key(state.local_tenants(), "alice", 72);
    assert_key(state.local_tenants(), "bob", 81);
    publish(
        &mut store,
        &config(3, &["bob"]),
        &node(),
        &node_key(),
        &tenants(&[]),
    )
    .unwrap();
    assert_eq!(
        store
            .load()
            .unwrap()
            .unwrap()
            .local_tenants()
            .network_ids()
            .count(),
        0
    );
}

#[test]
fn tenant_aware_commit_cannot_replace_node_identity() {
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    publish(
        &mut store,
        &config(1, &["alice"]),
        &node(),
        &node_key(),
        &tenants(&[("alice", 71)]),
    )
    .unwrap();
    let before = fs::read(fixture.0.join("state.json")).unwrap();
    assert!(matches!(
        publish(
            &mut store,
            &config(2, &["alice"]),
            &NodeId::new("gateway-b").unwrap(),
            &node_key(),
            &tenants(&[("alice", 72)])
        ),
        Err(StoreError::IdentityChanged)
    ));
    assert!(matches!(
        publish(
            &mut store,
            &config(2, &["alice"]),
            &node(),
            &wgfeel_test_support::fixture_node_keys([38; 32]),
            &tenants(&[("alice", 72)])
        ),
        Err(StoreError::IdentityChanged)
    ));
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), before);
}

#[test]
fn tenant_debug_does_not_expose_private_bytes() {
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.0).unwrap();
    let local = tenants(&[("alice", 173)]);
    assert!(!format!("{local:?}").contains("173"));
    publish(
        &mut store,
        &config(1, &["alice"]),
        &node(),
        &node_key(),
        &local,
    )
    .unwrap();
    let state = store.load().unwrap().unwrap();
    assert!(!format!("{state:?}").contains("173"));
}

#[test]
fn crash_either_side_of_rename_preserves_whole_configuration_and_tenant_map() {
    for (mode, published) in [("before-rename", false), ("after-rename", true)] {
        let fixture = Fixture::new();
        let mut store = Store::open(&fixture.0).unwrap();
        publish(
            &mut store,
            &config(1, &["alice", "bob"]),
            &node(),
            &node_key(),
            &tenants(&[("alice", 71)]),
        )
        .unwrap();
        drop(store);
        let spec = ProcessSpec::new(
            std::env::current_exe().unwrap(),
            [
                "--exact",
                "subprocess_tenant_writer",
                "--ignored",
                "--nocapture",
            ]
            .map(Into::into)
            .to_vec(),
            vec![
                ("WGFEEL_TENANT_DIRECTORY".into(), fixture.0.clone().into()),
                ("WGFEEL_TENANT_STAGE".into(), mode.into()),
            ],
            None,
        );
        let mut child = ManagedChild::spawn(
            spec,
            ProcessLimits {
                max_stdout_bytes: 16_384,
                max_stderr_bytes: 16_384,
            },
        )
        .unwrap();
        child
            .wait_for_stdout_line(b"TENANT_CHECKPOINT_READY", Duration::from_secs(10))
            .unwrap();
        assert!(matches!(Store::open(&fixture.0), Err(StoreError::Locked)));
        assert!(!child.terminate().unwrap().status.success());
        let recovered = Store::open(&fixture.0).unwrap().load().unwrap().unwrap();
        assert_eq!(recovered.service_private_key().expose_bytes(), &[37; 32]);
        if published {
            assert_eq!(recovered.config(), &config(2, &["bob", "charlie"]));
            assert_eq!(recovered.local_tenants().network_ids().count(), 2);
            assert_key(recovered.local_tenants(), "bob", 81);
            assert_key(recovered.local_tenants(), "charlie", 82);
            assert!(
                recovered
                    .local_tenants()
                    .private_key(&id("alice"))
                    .is_none()
            );
        } else {
            assert_eq!(recovered.config(), &config(1, &["alice", "bob"]));
            assert_eq!(recovered.local_tenants().network_ids().count(), 1);
            assert_key(recovered.local_tenants(), "alice", 71);
            assert!(recovered.local_tenants().private_key(&id("bob")).is_none());
        }
    }
}

#[test]
#[ignore = "Rust checkpoint writer launched only by its parent tenant-storage test"]
fn subprocess_tenant_writer() {
    let path = PathBuf::from(std::env::var_os("WGFEEL_TENANT_DIRECTORY").unwrap());
    let stage = match std::env::var("WGFEEL_TENANT_STAGE").unwrap().as_str() {
        "before-rename" => CommitStage::AfterFileSync,
        "after-rename" => CommitStage::AfterRename,
        _ => panic!("unknown tenant commit stage"),
    };
    let local = tenants(&[("bob", 81), ("charlie", 82)]);
    let projection = assigned(
        &config(2, &["bob", "charlie"]),
        &node(),
        &node_key(),
        &local,
    );
    Store::open(&path)
        .unwrap()
        .commit_projection_with_checkpoint(
            projection.management_id(),
            &projection,
            &node(),
            &node_key(),
            &local,
            |at| {
                if at == stage {
                    println!("\nTENANT_CHECKPOINT_READY");
                    io::stdout().flush()?;
                    io::stdin().read_exact(&mut [0_u8; 1])?;
                }
                Ok(())
            },
        )
        .unwrap();
}
