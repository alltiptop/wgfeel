use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use wgfeel_core::{
    Action, AdminCredential, Client, ClientDevice, ClientId, Config, Device, DeviceId,
    DeviceMetadata, DevicePublicKey, Endpoint, GatewayAssignment, Grant, MAX_MANAGEMENT_BYTES,
    ManagementConfig, ManagementDocument, Network, NetworkId, NodeId, NodeKeys, Policy, Rule,
    TenantKeyAssignment, TenantPrivateKey,
};
use wgfeel_store::{
    CommitStage, LocalTenants, ManagementStore, Store, StoreError, StoredManagement,
};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

const WAIT: Duration = Duration::from_secs(5);
const STAGES: [CommitStage; 5] = [
    CommitStage::AfterCreate,
    CommitStage::AfterWrite,
    CommitStage::AfterFileSync,
    CommitStage::AfterRename,
    CommitStage::AfterDirectorySync,
];
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-management-store-{}-{}",
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
fn device(value: &str) -> DeviceId {
    DeviceId::new(value).unwrap()
}
fn endpoint(net: &str, dev: &str) -> Endpoint {
    Endpoint::new(network(net), device(dev))
}
fn key(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}
fn catalog(id: &str, name: &str) -> ClientDevice {
    ClientDevice::new(
        device(id),
        DeviceMetadata::new(Some(name.into()), Some(format!("description for {name}"))).unwrap(),
    )
}
fn owner(id: &str, net: &str, devices: Vec<ClientDevice>) -> Client {
    Client::new(ClientId::new(id).unwrap(), vec![network(net)], devices).unwrap()
}
fn document(generation: u64, changed: bool, authority: &str) -> ManagementDocument {
    let alpha_device = if changed { "tablet" } else { "laptop" };
    let config = Config::new(
        generation,
        vec![
            Network::new(
                network("alpha"),
                vec![
                    Device::new(
                        device(alpha_device),
                        key(if changed { 41 } else { 11 }),
                        vec!["10.1.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
            Network::new(
                network("beta"),
                vec![
                    Device::new(
                        device("shared"),
                        key(if changed { 42 } else { 12 }),
                        vec!["10.2.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ],
        Policy::new(
            if changed {
                vec![Rule::new(
                    endpoint("alpha", alpha_device),
                    endpoint("beta", "shared"),
                    Action::Deny,
                )]
            } else {
                vec![]
            },
            vec![],
            vec![Grant::new(
                endpoint("alpha", alpha_device),
                endpoint("beta", "shared"),
            )],
        ),
    )
    .unwrap();
    let scope = if changed { "beta" } else { "alpha" };
    let assignment = GatewayAssignment::new(
        node("gateway-a"),
        (key(if changed { 111 } else { 101 })).clone(),
        wgfeel_test_support::fixture_gateway_public(&(key(if changed { 111 } else { 101 }))),
        vec![network(scope)],
        vec![TenantKeyAssignment::new(
            network(scope),
            key(if changed { 112 } else { 102 }),
        )],
    )
    .unwrap();
    let clients = if changed {
        vec![
            owner("bob", "alpha", vec![catalog("tablet", "new tablet")]),
            owner(
                "alice",
                "beta",
                vec![
                    catalog("shared", "renamed device"),
                    catalog("spare", "new unassigned"),
                ],
            ),
        ]
    } else {
        vec![
            owner(
                "alice",
                "alpha",
                vec![
                    catalog("laptop", "old laptop"),
                    catalog("unassigned", "old unassigned"),
                ],
            ),
            owner("bob", "beta", vec![catalog("shared", "old device")]),
        ]
    };
    ManagementDocument::new(
        ManagementConfig::new(node(authority), config, vec![assignment]).unwrap(),
        clients,
    )
    .unwrap()
}
fn old() -> ManagementDocument {
    document(3, false, "management")
}
fn new() -> ManagementDocument {
    document(9, true, "management")
}
fn management_key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([211; 32])
}
fn credential(changed: bool) -> AdminCredential {
    AdminCredential::new([if changed { 227 } else { 223 }; 32]).unwrap()
}

#[test]
fn token_rotation_is_atomic_at_every_commit_boundary_and_never_persists_the_token() {
    for stage in STAGES {
        let directory = Directory::new();
        let mut store = populated(&directory.state());
        let before = store.load().unwrap().unwrap();
        assert!(
            store
                .rotate_admin_credential_with_checkpoint(&credential(true), |current| {
                    if current == stage {
                        Err(io::Error::other("injected failure"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        let next = store.load().unwrap().unwrap();
        let published = matches!(
            stage,
            CommitStage::AfterRename | CommitStage::AfterDirectorySync
        );
        assert_eq!(
            next.admin_verifier()
                .verify(credential(true).expose_bytes()),
            published
        );
        assert_eq!(
            next.admin_verifier()
                .verify(credential(false).expose_bytes()),
            !published
        );
        assert_eq!(next.document(), before.document());
        assert_eq!(
            next.service_private_key().expose_bytes(),
            before.service_private_key().expose_bytes()
        );
        for entry in fs::read_dir(directory.state()).unwrap() {
            let entry = entry.unwrap();
            let bytes = fs::read_to_string(entry.path()).unwrap();
            assert!(!bytes.contains("\"admin_credential\""));
            assert!(!bytes.contains(&serde_json::to_string(&[227; 32]).unwrap()));
        }
        drop(store);
        let reopened = ManagementStore::open(&directory.state())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(reopened.admin_verifier(), next.admin_verifier());
    }
}
fn assert_snapshot(snapshot: &StoredManagement, expected: &ManagementDocument, changed: bool) {
    assert_eq!(snapshot.document(), expected);
    assert!(snapshot.service_private_key().expose_bytes() == &[211; 32]);
    assert!(
        snapshot
            .admin_verifier()
            .verify(&[if changed { 227 } else { 223 }; 32])
    );
}
fn envelope(document: &str, changed: bool) -> String {
    let key = std::iter::repeat_n("211", 32).collect::<Vec<_>>().join(",");
    let verifier =
        serde_json::to_string(&wgfeel_store::AdminVerifier::new(&credential(changed)).unwrap())
            .unwrap();
    format!(
        "{{\"management_storage_version\":6,\"document\":{document},\"service_private_key\":[{key}],\"gateway_private_key\":[212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212],\"admin_verifier\":{verifier}}}"
    )
}
fn populated(path: &Path) -> ManagementStore {
    let mut store = ManagementStore::initialize(path).unwrap();
    store
        .commit(&old(), &management_key(), &credential(false), None)
        .unwrap();
    store
}
fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn fresh_verify(path: &Path, changed: bool) {
    let output = spawn_fixture(
        path,
        if changed { "verify-new" } else { "verify-old" },
        None,
    )
    .wait(WAIT)
    .unwrap();
    assert!(
        output.status.success(),
        "fresh process failed complete snapshot verification"
    );
}
fn spawn_fixture(path: &Path, mode: &str, stage: Option<usize>) -> ManagedChild {
    let mut environment = vec![
        ("WGFEEL_MANAGEMENT_PATH".into(), path.as_os_str().to_owned()),
        ("WGFEEL_MANAGEMENT_MODE".into(), mode.into()),
    ];
    if let Some(stage) = stage {
        environment.push(("WGFEEL_MANAGEMENT_STAGE".into(), stage.to_string().into()));
    }
    ManagedChild::spawn(
        ProcessSpec::new(
            std::env::current_exe().unwrap(),
            [
                "--exact",
                "management_process_fixture",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .map(OsString::from)
            .to_vec(),
            environment,
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
    )
    .unwrap()
}

#[test]
fn initialization_is_private_leaf_only_and_open_never_creates_a_directory() {
    let directory = Directory::new();
    let state = directory.state();
    assert!(matches!(
        ManagementStore::open(&state),
        Err(StoreError::Io(_))
    ));
    assert!(!state.exists());
    let store = ManagementStore::initialize(&state).unwrap();
    assert!(store.load().unwrap().is_none());
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
    drop(store);
    assert!(ManagementStore::initialize(&state).is_ok());
    assert!(ManagementStore::initialize(&directory.0.join("absent/leaf")).is_err());
    assert!(!directory.0.join("absent").exists());
}

#[test]
fn complete_document_and_own_secrets_survive_a_fresh_process_without_public_leakage() {
    let directory = Directory::new();
    let store = populated(&directory.state());
    let loaded = store.load().unwrap().unwrap();
    assert_snapshot(&loaded, &old(), false);
    let bytes = fs::read(directory.state().join("state.json")).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["management_storage_version"], 7);
    assert_eq!(json["document"]["management_version"], 2);
    assert_eq!(json["document"]["management_id"], "management");
    assert_eq!(json.as_object().unwrap().len(), 5);
    assert!(json["service_private_key"] == serde_json::to_value([211; 32]).unwrap());
    assert!(json.get("admin_credential").is_none());
    assert_eq!(json["admin_verifier"]["algorithm"], "hmac-sha256");
    assert!(json.get("storage_version").is_none());
    assert!(json.get("tenant_private_keys").is_none());
    assert_eq!(
        ManagementDocument::from_json(&json["document"].to_string()).unwrap(),
        old()
    );
    let public_document = loaded.document().to_json().unwrap();
    let public_projection = loaded
        .document()
        .project_for(&node("gateway-a"))
        .unwrap()
        .to_json()
        .unwrap();
    let diagnostics = format!("{loaded:?} {store:?}");
    for output in [&public_document, &public_projection, &diagnostics] {
        for secret in [211, 223] {
            assert!(!output.contains(&format!("{secret}, {secret}, {secret}")));
            assert!(!output.contains(&format!("{secret},{secret},{secret}")));
        }
    }
    for output in [&public_document, &public_projection] {
        assert!(!output.contains("service_private_key"));
        assert!(!output.contains("admin_credential"));
    }
    assert!(diagnostics.contains("[REDACTED]"));
    assert_eq!(
        fs::metadata(directory.state().join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(store);
    fresh_verify(&directory.state(), false);
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        bytes
    );
}

#[test]
fn optimistic_revision_and_authority_checks_precede_any_pending_file_change() {
    let directory = Directory::new();
    let mut store = ManagementStore::initialize(&directory.state()).unwrap();
    let pending = directory.state().join(".pending");
    private_write(&pending, b"safe unpublished sentinel");
    let mut reached = false;
    assert!(matches!(
        store.commit_with_checkpoint(
            &old(),
            &management_key(),
            &credential(false),
            Some(3),
            |_| {
                reached = true;
                Ok(())
            }
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert!(!reached);
    assert_eq!(fs::read(&pending).unwrap(), b"safe unpublished sentinel");
    assert!(!directory.state().join("state.json").exists());
    store
        .commit(&old(), &management_key(), &credential(false), None)
        .unwrap();
    private_write(&pending, b"validation must not unlink this");
    let original = fs::read(directory.state().join("state.json")).unwrap();
    for (candidate, expected, category) in [
        (new(), None, 0),
        (new(), Some(2), 0),
        (document(3, true, "management"), Some(3), 1),
        (document(2, true, "management"), Some(3), 1),
        (document(9, true, "foreign"), Some(3), 2),
    ] {
        let mut reached = false;
        let error = store
            .commit_with_checkpoint(
                &candidate,
                &management_key(),
                &credential(true),
                expected,
                |_| {
                    reached = true;
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(match category {
            0 => matches!(error, StoreError::RevisionConflict),
            1 => matches!(error, StoreError::RevisionNotIncreasing),
            _ => matches!(error, StoreError::AuthorityChanged),
        });
        assert!(!reached);
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"validation must not unlink this"
        );
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            original
        );
    }
    let mut reached = false;
    assert!(matches!(
        store.commit_with_checkpoint(
            &new(),
            &wgfeel_test_support::fixture_node_keys([212; 32]),
            &credential(true),
            Some(3),
            |_| {
                reached = true;
                Ok(())
            }
        ),
        Err(StoreError::IdentityChanged)
    ));
    assert!(!reached);
    assert_snapshot(&store.load().unwrap().unwrap(), &old(), false);
    assert_eq!(
        fs::read(&pending).unwrap(),
        b"validation must not unlink this"
    );
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        original
    );
    store
        .commit(&new(), &management_key(), &credential(true), Some(3))
        .unwrap();
    assert_snapshot(&store.load().unwrap().unwrap(), &new(), true);
    store
        .commit(
            &document(u64::MAX, true, "management"),
            &management_key(),
            &credential(true),
            Some(9),
        )
        .unwrap();
    assert!(matches!(
        store.commit(
            &old(),
            &management_key(),
            &credential(false),
            Some(u64::MAX)
        ),
        Err(StoreError::RevisionNotIncreasing)
    ));
}

#[test]
fn stale_editor_cannot_replace_a_new_revision_published_by_another_process() {
    let directory = Directory::new();
    let store = populated(&directory.state());
    let base = store
        .load()
        .unwrap()
        .unwrap()
        .document()
        .routing()
        .generation();
    drop(store);
    let output = spawn_fixture(&directory.state(), "commit-new", None)
        .wait(WAIT)
        .unwrap();
    assert!(output.status.success());
    let mut store = ManagementStore::open(&directory.state()).unwrap();
    let candidate = document(10, false, "management");
    assert!(matches!(
        store.commit(
            &candidate,
            &management_key(),
            &credential(false),
            Some(base)
        ),
        Err(StoreError::RevisionConflict)
    ));
    assert_snapshot(&store.load().unwrap().unwrap(), &new(), true);
    store
        .commit(&candidate, &management_key(), &credential(true), Some(9))
        .unwrap();
    assert_snapshot(&store.load().unwrap().unwrap(), &candidate, true);
}

#[test]
fn role_types_share_one_lifetime_lock_including_across_processes() {
    let directory = Directory::new();
    let store = populated(&directory.state());
    assert!(matches!(
        ManagementStore::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    assert!(matches!(
        Store::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    assert!(
        spawn_fixture(&directory.state(), "expect-locked", None)
            .wait(WAIT)
            .unwrap()
            .status
            .success()
    );
    drop(store);
    let mut holder = spawn_fixture(&directory.state(), "hold", None);
    holder
        .wait_for_stdout_line(b"MANAGEMENT_LOCK_READY", WAIT)
        .unwrap();
    assert!(matches!(
        ManagementStore::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    assert!(matches!(
        Store::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    holder.terminate().unwrap();
    let gateway = Store::open(&directory.state()).unwrap();
    assert!(matches!(
        ManagementStore::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    drop(gateway);
    assert!(ManagementStore::open(&directory.state()).is_ok());
}

fn gateway_projection() -> wgfeel_core::GatewayProjection {
    old().project_for(&node("gateway-a")).unwrap()
}
fn local_keys() -> LocalTenants {
    LocalTenants::new(vec![(
        network("alpha"),
        TenantPrivateKey::new([78; 32]).unwrap(),
    )])
    .unwrap()
}
fn gateway_key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([77; 32])
}

#[test]
fn gateway_and_management_formats_cannot_be_loaded_or_overwritten_by_the_wrong_role() {
    for bound in [false, true] {
        let directory = Directory::new();
        let mut gateway = Store::initialize(&directory.state()).unwrap();
        let projection = gateway_projection();
        if bound {
            gateway
                .commit_managed_projection(&projection, &gateway_key(), &local_keys(), &key(193))
                .unwrap();
        } else {
            gateway
                .commit_projection(
                    &node("management"),
                    &projection,
                    &node("gateway-a"),
                    &gateway_key(),
                    &local_keys(),
                )
                .unwrap();
        }
        drop(gateway);
        let current = fs::read(directory.state().join("state.json")).unwrap();
        private_write(
            &directory.state().join(".pending"),
            b"foreign pending must survive",
        );
        let mut management = ManagementStore::open(&directory.state()).unwrap();
        assert!(matches!(management.load(), Err(StoreError::InvalidState)));
        let mut reached = false;
        assert!(matches!(
            management.commit_with_checkpoint(
                &new(),
                &management_key(),
                &credential(true),
                None,
                |_| {
                    reached = true;
                    Ok(())
                }
            ),
            Err(StoreError::InvalidState)
        ));
        assert!(!reached);
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            current
        );
        assert_eq!(
            fs::read(directory.state().join(".pending")).unwrap(),
            b"foreign pending must survive"
        );
    }
    let directory = Directory::new();
    drop(populated(&directory.state()));
    let current = fs::read(directory.state().join("state.json")).unwrap();
    private_write(
        &directory.state().join(".pending"),
        b"management pending must survive",
    );
    let mut gateway = Store::open(&directory.state()).unwrap();
    assert!(matches!(gateway.load(), Err(StoreError::InvalidState)));
    let mut reached = false;
    assert!(matches!(
        gateway.commit_projection_with_checkpoint(
            &node("management"),
            &gateway_projection(),
            &node("gateway-a"),
            &gateway_key(),
            &local_keys(),
            |_| {
                reached = true;
                Ok(())
            }
        ),
        Err(StoreError::InvalidState)
    ));
    assert!(!reached);
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        current
    );
    assert_eq!(
        fs::read(directory.state().join(".pending")).unwrap(),
        b"management pending must survive"
    );
}

#[test]
fn five_checkpoint_errors_preserve_whole_old_or_new_document_and_force_cas_reload() {
    for (index, stage) in STAGES.into_iter().enumerate() {
        let directory = Directory::new();
        let mut store = populated(&directory.state());
        let mut visited = vec![];
        let result = store.commit_with_checkpoint(
            &new(),
            &management_key(),
            &credential(true),
            Some(3),
            |at| {
                visited.push(at);
                if at == stage {
                    Err(io::Error::other("injected checkpoint failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(visited, STAGES[..=index]);
        if index < 3 {
            assert!(matches!(result, Err(StoreError::Io(_))));
            assert_snapshot(&store.load().unwrap().unwrap(), &old(), false);
        } else {
            assert!(matches!(result, Err(StoreError::CommitUncertain)));
            assert_snapshot(&store.load().unwrap().unwrap(), &new(), true);
            assert!(matches!(
                store.commit(
                    &document(10, false, "management"),
                    &management_key(),
                    &credential(false),
                    Some(3)
                ),
                Err(StoreError::RevisionConflict)
            ));
        }
        drop(store);
        fresh_verify(&directory.state(), index >= 3);
    }
}

#[test]
fn real_process_death_at_all_five_stages_recovers_complete_revision_and_lock() {
    for (index, _) in STAGES.into_iter().enumerate() {
        let directory = Directory::new();
        drop(populated(&directory.state()));
        let mut child = spawn_fixture(&directory.state(), "crash-writer", Some(index));
        child
            .wait_for_stdout_line(b"MANAGEMENT_CHECKPOINT_READY", WAIT)
            .unwrap();
        assert!(matches!(
            ManagementStore::open(&directory.state()),
            Err(StoreError::Locked)
        ));
        assert!(matches!(
            Store::open(&directory.state()),
            Err(StoreError::Locked)
        ));
        assert!(!child.terminate().unwrap().status.success());
        fresh_verify(&directory.state(), index >= 3);
        let store = ManagementStore::open(&directory.state()).unwrap();
        assert_snapshot(
            &store.load().unwrap().unwrap(),
            &if index >= 3 { new() } else { old() },
            index >= 3,
        );
    }
}

#[test]
fn pending_is_never_authoritative_and_corruption_is_not_empty_state() {
    let directory = Directory::new();
    let mut store = ManagementStore::initialize(&directory.state()).unwrap();
    private_write(
        &directory.state().join(".pending"),
        envelope(&new().to_json().unwrap(), true).as_bytes(),
    );
    assert!(store.load().unwrap().is_none());
    store
        .commit(&old(), &management_key(), &credential(false), None)
        .unwrap();
    private_write(
        &directory.state().join(".pending"),
        envelope(&new().to_json().unwrap(), true).as_bytes(),
    );
    assert_snapshot(&store.load().unwrap().unwrap(), &old(), false);
    fs::write(
        directory.state().join("state.json"),
        b"broken committed document",
    )
    .unwrap();
    let pending = fs::read(directory.state().join(".pending")).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidState)));
    assert!(matches!(
        store.commit(&new(), &management_key(), &credential(true), None),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        b"broken committed document"
    );
    assert_eq!(
        fs::read(directory.state().join(".pending")).unwrap(),
        pending
    );
}

const LITERAL: &str = r#"{"management_version":1,"management_id":"management","config":{"schema_version":1,"generation":3,"networks":[],"policy":{"global_rules":[],"local_rules":[],"grants":[]}},"assignments":[],"clients":[]}"#;

#[test]
fn private_envelope_requires_exact_distinct_fields_and_valid_secret_arrays() {
    let valid = envelope(LITERAL, false);
    let parsed: serde_json::Value = serde_json::from_str(&valid).unwrap();
    let mut cases = vec![LITERAL.to_owned()];
    for version in [
        "0",
        "99",
        "4294967296",
        "18446744073709551615",
        "-1",
        "1.0",
        "null",
        "\"1\"",
    ] {
        cases.push(valid.replace(
            "\"management_storage_version\":6",
            &format!("\"management_storage_version\":{version}"),
        ));
    }
    for field in [
        "management_storage_version",
        "document",
        "service_private_key",
        "gateway_private_key",
        "admin_verifier",
    ] {
        let mut missing = parsed.clone();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(missing.to_string());
        let mut null = parsed.clone();
        null[field] = serde_json::Value::Null;
        cases.push(null.to_string());
        let pair = format!("\"{field}\":{}", parsed[field]);
        cases.push(format!("{{{pair},{}", &valid[1..]));
    }
    for field in [
        "service_private_key",
        "gateway_private_key",
        "admin_verifier",
    ] {
        for invalid in [
            serde_json::json!([]),
            serde_json::json!(vec![1; 31]),
            serde_json::json!(vec![1; 33]),
            serde_json::json!(vec![0; 32]),
            serde_json::json!(vec![256; 32]),
            serde_json::json!(vec![-1; 32]),
            serde_json::json!(vec![1.5; 32]),
            serde_json::json!("NEVER_ECHO_SECRET_INPUT"),
            serde_json::json!({"bytes": [1, 2, 3]}),
        ] {
            let mut candidate = parsed.clone();
            candidate[field] = invalid;
            cases.push(candidate.to_string());
        }
    }
    let mut unknown = parsed;
    unknown["foreign_private_key"] = serde_json::json!("NEVER_ECHO_SECRET_INPUT");
    cases.push(unknown.to_string());
    for input in cases {
        let directory = Directory::new();
        let mut store = ManagementStore::initialize(&directory.state()).unwrap();
        private_write(&directory.state().join("state.json"), input.as_bytes());
        private_write(
            &directory.state().join(".pending"),
            b"do not repair corrupt current",
        );
        let error = store.load().unwrap_err();
        assert!(matches!(error, StoreError::InvalidState));
        assert!(!format!("{error} {error:?}").contains("NEVER_ECHO_SECRET_INPUT"));
        assert!(matches!(
            store.commit(&old(), &management_key(), &credential(false), None),
            Err(StoreError::InvalidState)
        ));
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            input.as_bytes()
        );
        assert_eq!(
            fs::read(directory.state().join(".pending")).unwrap(),
            b"do not repair corrupt current"
        );
    }
    let directory = Directory::new();
    let store = ManagementStore::initialize(&directory.state()).unwrap();
    // A valid secret may contain zero bytes; only an entirely zero value is invalid.
    let mut sparse: serde_json::Value = serde_json::from_str(&valid).unwrap();
    let mut secret = [0; 32];
    secret[31] = 1;
    sparse["service_private_key"] = serde_json::to_value(secret).unwrap();
    sparse["admin_verifier"] = serde_json::to_value(
        wgfeel_store::AdminVerifier::new(&AdminCredential::new(secret).unwrap()).unwrap(),
    )
    .unwrap();
    private_write(
        &directory.state().join("state.json"),
        sparse.to_string().as_bytes(),
    );
    let loaded = store.load().unwrap().unwrap();
    assert!(loaded.service_private_key().expose_bytes() == &secret);
    assert!(loaded.admin_verifier().verify(&secret));
}

#[test]
fn independent_malformed_wrong_version_and_invalid_ownership_documents_fail_closed() {
    let cases = vec![
        LITERAL.replace("\"management_version\":1", "\"management_version\":2"),
        LITERAL.replace(
            "\"management_version\":1",
            "\"management_version\":1,\"management_version\":1",
        ),
        LITERAL.replace("\"generation\":3", "\"generation\":3,\"generation\":9"),
        LITERAL.replace(
            "\"clients\":[]",
            "\"clients\":[{\"id\":\"alice\",\"networks\":[\"foreign\"],\"devices\":[]}]",
        ),
        LITERAL.replace("\"clients\":[]", "\"clients\":null"),
        LITERAL.replace(
            "\"clients\":[]",
            "\"clients\":[],\"private_key\":\"NEVER_ECHO_INPUT\"",
        ),
    ];
    for bytes in cases
        .into_iter()
        .map(|document| envelope(&document, false).into_bytes())
        .chain([vec![0xff, 0xfe]])
    {
        let directory = Directory::new();
        let mut store = ManagementStore::initialize(&directory.state()).unwrap();
        private_write(&directory.state().join("state.json"), &bytes);
        let error = store.load().unwrap_err();
        assert!(matches!(error, StoreError::InvalidState));
        assert!(!format!("{error} {error:?}").contains("NEVER_ECHO_INPUT"));
        assert!(matches!(
            store.commit(&old(), &management_key(), &credential(false), None),
            Err(StoreError::InvalidState)
        ));
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            bytes
        );
    }
}

#[test]
fn nested_document_and_complete_private_file_have_independent_exact_byte_bounds() {
    for (size, accepted) in [
        (MAX_MANAGEMENT_BYTES + 4096, true),
        (MAX_MANAGEMENT_BYTES + 4097, false),
    ] {
        let directory = Directory::new();
        let store = ManagementStore::initialize(&directory.state()).unwrap();
        let mut input = envelope(LITERAL, false).into_bytes();
        input.resize(size, b' ');
        private_write(&directory.state().join("state.json"), &input);
        if accepted {
            let expected = ManagementDocument::from_json(LITERAL).unwrap();
            assert_snapshot(&store.load().unwrap().unwrap(), &expected, false);
        } else {
            assert!(matches!(store.load(), Err(StoreError::InvalidState)));
        }
    }
    for (size, accepted) in [
        (MAX_MANAGEMENT_BYTES, true),
        (MAX_MANAGEMENT_BYTES + 1, false),
    ] {
        let directory = Directory::new();
        let store = ManagementStore::initialize(&directory.state()).unwrap();
        let mut document = LITERAL.strip_suffix('}').unwrap().to_owned();
        document.extend(std::iter::repeat_n(' ', size - document.len() - 1));
        document.push('}');
        assert_eq!(document.len(), size);
        let input = envelope(&document, false);
        assert!(input.len() < MAX_MANAGEMENT_BYTES + 4096);
        private_write(&directory.state().join("state.json"), input.as_bytes());
        if accepted {
            let expected = ManagementDocument::from_json(LITERAL).unwrap();
            assert_snapshot(&store.load().unwrap().unwrap(), &expected, false);
        } else {
            assert!(matches!(store.load(), Err(StoreError::InvalidState)));
        }
    }
}

#[test]
fn unsafe_directory_paths_and_permissions_are_rejected_without_repair() {
    let directory = Directory::new();
    let state = directory.state();
    drop(ManagementStore::initialize(&state).unwrap());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ManagementStore::open(&state),
        Err(StoreError::UnsafePath)
    ));
    assert!(matches!(
        ManagementStore::initialize(&state),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o755
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.0.join("link");
    symlink(&state, &link).unwrap();
    assert!(matches!(
        ManagementStore::open(&link),
        Err(StoreError::UnsafePath)
    ));
    assert!(matches!(
        ManagementStore::initialize(&link.join("child")),
        Err(StoreError::UnsafePath)
    ));
    assert!(!state.join("child").exists());
    assert!(matches!(
        ManagementStore::open(&state.join("../state")),
        Err(StoreError::UnsafePath)
    ));
    private_write(
        &state.join("state.json"),
        envelope(LITERAL, false).as_bytes(),
    );
    fs::set_permissions(state.join("state.json"), fs::Permissions::from_mode(0o640)).unwrap();
    let mut store = ManagementStore::open(&state).unwrap();
    assert!(matches!(store.load(), Err(StoreError::UnsafePath)));
    assert!(matches!(
        store.commit(&old(), &management_key(), &credential(false), None),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(
        fs::metadata(state.join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[test]
fn linked_or_special_current_and_pending_files_are_not_followed_unlinked_or_blocking() {
    for pending in [false, true] {
        for kind in ["symlink", "hardlink", "fifo", "directory"] {
            let directory = Directory::new();
            if pending {
                drop(populated(&directory.state()));
            } else {
                drop(ManagementStore::initialize(&directory.state()).unwrap());
            }
            let outside = directory.0.join("outside");
            private_write(&outside, b"must remain untouched");
            let entry = directory
                .state()
                .join(if pending { ".pending" } else { "state.json" });
            match kind {
                "symlink" => symlink(&outside, &entry).unwrap(),
                "hardlink" => fs::hard_link(&outside, &entry).unwrap(),
                "fifo" => rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &entry,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap(),
                _ => {
                    fs::create_dir(&entry).unwrap();
                    fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            let output = spawn_fixture(
                &directory.state(),
                if pending {
                    "unsafe-pending"
                } else {
                    "unsafe-current"
                },
                None,
            )
            .wait(WAIT)
            .unwrap();
            assert!(
                output.status.success(),
                "unsafe entry failed bounded rejection: {kind}"
            );
            assert_eq!(fs::read(&outside).unwrap(), b"must remain untouched");
            let file_type = fs::symlink_metadata(&entry).unwrap().file_type();
            assert_eq!(file_type.is_fifo(), kind == "fifo");
            assert_eq!(file_type.is_dir(), kind == "directory");
            assert_eq!(file_type.is_symlink(), kind == "symlink");
        }
    }
}

#[test]
#[ignore = "Rust child fixture invoked only by management persistence tests"]
fn management_process_fixture() {
    let path = PathBuf::from(std::env::var_os("WGFEEL_MANAGEMENT_PATH").unwrap());
    let mode = std::env::var("WGFEEL_MANAGEMENT_MODE").unwrap();
    if mode == "expect-locked" {
        assert!(matches!(
            ManagementStore::open(&path),
            Err(StoreError::Locked)
        ));
        assert!(matches!(Store::open(&path), Err(StoreError::Locked)));
        return;
    }
    let mut store = ManagementStore::open(&path).unwrap();
    match mode.as_str() {
        "verify-old" => assert_snapshot(&store.load().unwrap().unwrap(), &old(), false),
        "verify-new" => assert_snapshot(&store.load().unwrap().unwrap(), &new(), true),
        "commit-new" => store
            .commit(&new(), &management_key(), &credential(true), Some(3))
            .unwrap(),
        "unsafe-current" => assert!(matches!(store.load(), Err(StoreError::UnsafePath))),
        "unsafe-pending" => assert!(matches!(
            store.commit(&new(), &management_key(), &credential(true), Some(3)),
            Err(StoreError::UnsafePath)
        )),
        "hold" => {
            println!("\nMANAGEMENT_LOCK_READY");
            io::stdout().flush().unwrap();
            let _ = io::stdin().read_exact(&mut [0]);
        }
        "crash-writer" => {
            let stage: usize = std::env::var("WGFEEL_MANAGEMENT_STAGE")
                .unwrap()
                .parse()
                .unwrap();
            store
                .commit_with_checkpoint(
                    &new(),
                    &management_key(),
                    &credential(true),
                    Some(3),
                    |at| {
                        if at == STAGES[stage] {
                            println!("\nMANAGEMENT_CHECKPOINT_READY");
                            io::stdout().flush()?;
                            io::stdin().read_exact(&mut [0])?;
                        }
                        Ok(())
                    },
                )
                .unwrap();
        }
        _ => panic!("unknown private fixture mode"),
    }
}
