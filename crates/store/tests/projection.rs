use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use wgfeel_core::{
    Config, DevicePublicKey, GatewayAssignment, GatewayProjection, ManagementConfig, Network,
    NetworkId, NodeId, NodeKeys, Policy, TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_store::{CommitStage, LocalTenants, Store, StoreError};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-projection-{}-{}",
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
fn public(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}
fn config(generation: u64) -> Config {
    Config::new(
        generation,
        vec![
            Network::new(network("alpha"), vec![]).unwrap(),
            Network::new(network("beta"), vec![]).unwrap(),
        ],
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap()
}
fn projection(
    management: &str,
    recipient: &str,
    generation: u64,
    contexts: &[&str],
) -> GatewayProjection {
    let assignment = GatewayAssignment::new(
        node(recipient),
        (public(101)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(public(101))),
        vec![network("alpha"), network("beta")],
        contexts
            .iter()
            .enumerate()
            .map(|(index, name)| TenantKeyAssignment::new(network(name), public(102 + index as u8)))
            .collect(),
    )
    .unwrap();
    ManagementConfig::new(node(management), config(generation), vec![assignment])
        .unwrap()
        .project_for(&node(recipient))
        .unwrap()
}
fn tenants(entries: &[(&str, u8)]) -> LocalTenants {
    LocalTenants::new(
        entries
            .iter()
            .map(|(name, byte)| (network(name), TenantPrivateKey::new([*byte; 32]).unwrap()))
            .collect(),
    )
    .unwrap()
}
fn key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([41; 32])
}

#[test]
fn same_manager_join_keeps_atomic_commit_failure_semantics() {
    let directory = Directory::new();
    let mut store = Store::initialize(&directory.state()).unwrap();
    let old = projection("management", "gateway-a", 1, &["alpha"]);
    let new = projection("management", "gateway-a", 2, &["beta"]);
    store
        .commit_managed_projection(&old, &key(), &tenants(&[("alpha", 42)]), &public(71))
        .unwrap();
    let result = store.accept_manager_with_checkpoint(
        &old,
        Some(&public(71)),
        &new,
        &tenants(&[("beta", 43)]),
        &public(71),
        |stage| {
            if stage == CommitStage::AfterWrite {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(result, Err(StoreError::Io(_))));
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.projection(), &old);
    assert_eq!(state.management_public_key(), Some(&public(71)));
    assert_eq!(
        state.local_tenants().network_ids().collect::<Vec<_>>(),
        vec![&network("alpha")]
    );
}

#[test]
fn explicit_manager_transfer_is_fenced_atomic_and_replaces_all_old_tenant_material() {
    for failure in [
        Some(CommitStage::AfterWrite),
        Some(CommitStage::AfterRename),
        None,
    ] {
        let directory = Directory::new();
        let mut store = Store::initialize(&directory.state()).unwrap();
        let old = projection("old", "gateway-a", 42, &["alpha"]);
        let new = projection("new", "gateway-a", 2, &["beta"]);
        store
            .commit_managed_projection(&old, &key(), &tenants(&[("alpha", 42)]), &public(71))
            .unwrap();
        assert!(matches!(
            store.commit_managed_projection(&new, &key(), &tenants(&[("beta", 43)]), &public(72)),
            Err(StoreError::AuthorityChanged)
        ));
        assert!(
            store
                .accept_manager_with_checkpoint(
                    &old,
                    Some(&public(99)),
                    &new,
                    &tenants(&[("beta", 43)]),
                    &public(72),
                    |_| Ok(())
                )
                .is_err()
        );
        assert!(
            store
                .accept_manager_with_checkpoint(
                    &old,
                    Some(&public(71)),
                    &new,
                    &tenants(&[("alpha", 42), ("beta", 43)]),
                    &public(72),
                    |_| Ok(())
                )
                .is_err()
        );
        let result = store.accept_manager_with_checkpoint(
            &old,
            Some(&public(71)),
            &new,
            &tenants(&[("beta", 43)]),
            &public(72),
            |stage| {
                if failure == Some(stage) {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            },
        );
        let committed = failure != Some(CommitStage::AfterWrite);
        if failure.is_none() {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
        drop(store);
        let mut store = Store::open(&directory.state()).unwrap();
        let state = store.load().unwrap().unwrap();
        assert_eq!(state.projection(), if committed { &new } else { &old });
        assert_eq!(
            state.management_public_key(),
            Some(&public(if committed { 72 } else { 71 }))
        );
        assert_eq!(
            state.service_private_key().expose_bytes(),
            key().service().expose_bytes()
        );
        assert_eq!(
            state
                .local_tenants()
                .network_ids()
                .map(NetworkId::as_str)
                .collect::<Vec<_>>(),
            if committed {
                vec!["beta"]
            } else {
                vec!["alpha"]
            }
        );
        if committed {
            assert!(
                store
                    .accept_manager_with_checkpoint(
                        &old,
                        Some(&public(71)),
                        &new,
                        &tenants(&[("beta", 43)]),
                        &public(72),
                        |_| Ok(())
                    )
                    .is_err()
            );
            assert!(matches!(
                store.commit_managed_projection(
                    &projection("old", "gateway-a", 99, &["alpha"]),
                    &key(),
                    &tenants(&[("alpha", 42)]),
                    &public(71)
                ),
                Err(StoreError::AuthorityChanged)
            ));
        }
    }
}
fn commit(store: &mut Store, generation: u64) {
    store
        .commit_projection(
            &node("management"),
            &projection("management", "gateway-a", generation, &["alpha"]),
            &node("gateway-a"),
            &key(),
            &tenants(&[("alpha", 42)]),
        )
        .unwrap();
}
fn assert_generation(store: &Store, generation: u64) {
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.projection().generation(), generation);
    assert_eq!(state.config(), state.projection().config());
    assert_eq!(state.node_id(), &node("gateway-a"));
    assert_eq!(state.service_private_key().expose_bytes(), &[41; 32]);
}

#[test]
fn accepted_projection_and_only_local_material_survive_close_and_reopen() {
    let directory = Directory::new();
    let mut store = Store::initialize(&directory.state()).unwrap();
    commit(&mut store, 7);
    drop(store);
    let store = Store::open(&directory.state()).unwrap();
    assert_generation(&store, 7);
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.projection().management_id(), &node("management"));
    assert_eq!(
        state.local_tenants().network_ids().collect::<Vec<_>>(),
        vec![&network("alpha")]
    );
    assert_eq!(
        state
            .local_tenants()
            .private_key(&network("alpha"))
            .unwrap()
            .expose_bytes(),
        &[42; 32]
    );
    let disk: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.state().join("state.json")).unwrap()).unwrap();
    assert_eq!(disk["storage_version"], 3);
    assert!(disk.get("config").is_none());
    assert_eq!(
        disk["service_private_key"],
        serde_json::json!(vec![41_u8; 32])
    );
    assert_eq!(
        disk["tenant_private_keys"][0]["private_key"],
        serde_json::json!(vec![42_u8; 32])
    );
    assert_eq!(disk["tenant_private_keys"].as_array().unwrap().len(), 1);
    let public = state.projection().to_json().unwrap();
    assert!(!public.contains("private_key"));
    let debug = format!("{state:?}");
    assert!(!debug.contains(&format!("{:?}", [41_u8; 32])));
    assert!(!debug.contains(&format!("{:?}", [42_u8; 32])));
}

#[test]
fn bound_authority_cannot_be_replaced_by_a_new_caller_supplied_pin() {
    let directory = Directory::new();
    let mut store = Store::initialize(&directory.state()).unwrap();
    commit(&mut store, 7);
    let candidate = projection("other-management", "gateway-a", 8, &["alpha"]);
    assert!(matches!(
        store.commit_projection(
            &node("other-management"),
            &candidate,
            &node("gateway-a"),
            &key(),
            &tenants(&[("alpha", 42)])
        ),
        Err(StoreError::AuthorityChanged)
    ));
    assert_generation(&store, 7);
    let candidate = projection("management", "gateway-b", 8, &["alpha"]);
    assert!(
        store
            .commit_projection(
                &node("management"),
                &candidate,
                &node("gateway-b"),
                &key(),
                &tenants(&[("alpha", 42)])
            )
            .is_err()
    );
    assert_generation(&store, 7);
    assert!(matches!(
        store.commit_projection(
            &node("management"),
            &projection("management", "gateway-a", 8, &["alpha"]),
            &node("gateway-a"),
            &wgfeel_test_support::fixture_node_keys([99; 32]),
            &tenants(&[("alpha", 42)])
        ),
        Err(StoreError::IdentityChanged)
    ));
    assert_generation(&store, 7);
}

#[test]
fn revision_and_exact_local_context_validation_precede_publication() {
    let directory = Directory::new();
    let mut store = Store::initialize(&directory.state()).unwrap();
    commit(&mut store, 7);
    for generation in [6, 7] {
        assert!(matches!(
            store.commit_projection(
                &node("management"),
                &projection("management", "gateway-a", generation, &["alpha"]),
                &node("gateway-a"),
                &key(),
                &tenants(&[("alpha", 42)])
            ),
            Err(StoreError::RevisionNotIncreasing)
        ));
    }
    for local in [
        tenants(&[]),
        tenants(&[("alpha", 42), ("beta", 43)]),
        tenants(&[("beta", 43)]),
    ] {
        assert!(matches!(
            store.commit_projection(
                &node("management"),
                &projection("management", "gateway-a", 8, &["alpha"]),
                &node("gateway-a"),
                &key(),
                &local
            ),
            Err(StoreError::InvalidLocalTenants)
        ));
        assert_generation(&store, 7);
    }
    assert!(
        store
            .commit_projection(
                &node("wrong-pin"),
                &projection("management", "gateway-a", 8, &["alpha"]),
                &node("gateway-a"),
                &key(),
                &tenants(&[("alpha", 42)])
            )
            .is_err()
    );
    assert_generation(&store, 7);
    store
        .commit_projection(
            &node("management"),
            &projection("management", "gateway-a", 8, &["beta"]),
            &node("gateway-a"),
            &key(),
            &tenants(&[("beta", 43)]),
        )
        .unwrap();
    assert_generation(&store, 8);
    let state = store.load().unwrap().unwrap();
    assert!(
        state
            .local_tenants()
            .private_key(&network("alpha"))
            .is_none()
    );
    assert_eq!(
        state
            .local_tenants()
            .private_key(&network("beta"))
            .unwrap()
            .expose_bytes(),
        &[43; 32]
    );
}

#[test]
fn projection_and_keys_recover_together_after_a_publication_error() {
    for (stage, published) in [
        (CommitStage::AfterFileSync, false),
        (CommitStage::AfterRename, true),
    ] {
        let directory = Directory::new();
        let mut store = Store::initialize(&directory.state()).unwrap();
        commit(&mut store, 1);
        let result = store.commit_projection_with_checkpoint(
            &node("management"),
            &projection("management", "gateway-a", 2, &["beta"]),
            &node("gateway-a"),
            &key(),
            &tenants(&[("beta", 43)]),
            |actual| {
                if actual == stage {
                    Err(io::Error::other("public checkpoint fixture"))
                } else {
                    Ok(())
                }
            },
        );
        if published {
            assert!(matches!(result, Err(StoreError::CommitUncertain)));
        } else {
            assert!(matches!(result, Err(StoreError::Io(_))));
        }
        drop(store);
        let store = Store::open(&directory.state()).unwrap();
        let state = store.load().unwrap().unwrap();
        assert_eq!(
            state.projection().generation(),
            if published { 2 } else { 1 }
        );
        let expected_network = network(if published { "beta" } else { "alpha" });
        assert_eq!(
            state.projection().assignment().tenants()[0].network(),
            &expected_network
        );
        assert_eq!(
            state.local_tenants().network_ids().collect::<Vec<_>>(),
            vec![&expected_network]
        );
        assert_eq!(
            state
                .local_tenants()
                .private_key(&expected_network)
                .unwrap()
                .expose_bytes(),
            &[if published { 43 } else { 42 }; 32]
        );
    }
}

fn private_write(path: &Path, contents: &str) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}
fn child_snapshot() -> String {
    format!(
        r#"{{"storage_version":3,"node_id":"gateway-a","gateway_private_key":[99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99],"service_private_key":{:?},"projection":{},"tenant_private_keys":[{{"network":"alpha","private_key":{:?}}}]}}"#,
        [41_u8; 32],
        projection("management", "gateway-a", 3, &["alpha"])
            .to_json()
            .unwrap(),
        [42_u8; 32]
    )
}

#[test]
fn durable_projection_envelope_rejects_version_mixing_ambiguity_and_missing_material() {
    let valid = child_snapshot();
    let mut cases = vec![
        valid.replacen("\"storage_version\":3", "\"storage_version\":99", 1),
        valid.replacen(
            "\"storage_version\":3",
            "\"storage_version\":3,\"config\":null",
            1,
        ),
        valid.replacen(
            "\"node_id\":\"gateway-a\"",
            "\"node_id\":\"gateway-a\",\"node_id\":\"gateway-b\"",
            1,
        ),
        valid.replacen("\"node_id\":\"gateway-a\"", "\"node_id\":\"gateway-b\"", 1),
        valid.replacen(
            "\"tenant_private_keys\":[",
            "\"tenant_private_keys\":null,\"ignored_entries\":[",
            1,
        ),
        valid.replacen(
            "\"network\":\"alpha\",\"private_key\"",
            "\"network\":\"beta\",\"private_key\"",
            1,
        ),
        valid.replacen(
            "\"projection\":",
            "\"projection\":null,\"ignored_projection\":",
            1,
        ),
        valid.replacen("\"projection\":", "\"projection\":null,\"projection\":", 1),
    ];
    for field in [
        "projection",
        "tenant_private_keys",
        "service_private_key",
        "gateway_private_key",
        "node_id",
    ] {
        let mut null: serde_json::Value = serde_json::from_str(&valid).unwrap();
        null[field] = serde_json::Value::Null;
        cases.push(serde_json::to_string(&null).unwrap());
        let mut missing: serde_json::Value = serde_json::from_str(&valid).unwrap();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(serde_json::to_string(&missing).unwrap());
    }
    for case in cases {
        assert_ne!(case, valid);
        let directory = Directory::new();
        drop(Store::initialize(&directory.state()).unwrap());
        private_write(&directory.state().join("state.json"), &case);
        assert!(Store::open(&directory.state()).unwrap().load().is_err());
    }
    let directory = Directory::new();
    drop(Store::initialize(&directory.state()).unwrap());
    private_write(&directory.state().join("state.json"), &valid);
    assert_generation(&Store::open(&directory.state()).unwrap(), 3);
}

#[test]
fn durable_projection_accepts_exact_file_bound_and_rejects_one_more_byte() {
    let maximum = wgfeel_core::MAX_PROJECTION_BYTES + 65536;
    let mut exact = child_snapshot();
    assert!(exact.len() < maximum);
    exact.extend(std::iter::repeat_n(' ', maximum - exact.len()));
    let directory = Directory::new();
    drop(Store::initialize(&directory.state()).unwrap());
    private_write(&directory.state().join("state.json"), &exact);
    assert_generation(&Store::open(&directory.state()).unwrap(), 3);
    let oversized = Directory::new();
    drop(Store::initialize(&oversized.state()).unwrap());
    exact.push(' ');
    private_write(&oversized.state().join("state.json"), &exact);
    assert!(Store::open(&oversized.state()).unwrap().load().is_err());
}
