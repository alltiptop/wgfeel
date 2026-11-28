use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use wgfeel_core::{
    Action, AdminCredential, Client, ClientDevice, ClientId, Config, Device, DeviceId,
    DeviceMetadata, DevicePublicKey, Endpoint, GatewayAssignment, Grant, MAX_MANAGEMENT_BYTES,
    ManagementChange, ManagementConfig, ManagementDocument, Network, NetworkId, NodeId, NodeKeys,
    Policy, Rule, TenantKeyAssignment,
};
use wgfeel_store::{
    CommitStage, ManagementApi, ManagementStore, Store, StoreError, StoredManagement,
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
            "wgfeel-management-api-store-{}-{}",
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
fn node(id: &str) -> NodeId {
    NodeId::new(id).unwrap()
}
fn network(id: &str) -> NetworkId {
    NetworkId::new(id).unwrap()
}
fn device(id: &str) -> DeviceId {
    DeviceId::new(id).unwrap()
}
fn public(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}
fn key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([197; 32])
}
fn credential(changed: bool) -> AdminCredential {
    AdminCredential::new([if changed { 227 } else { 211 }; 32]).unwrap()
}
fn api() -> ManagementApi {
    ManagementApi::new("0.0.0.0:51820".parse().unwrap(), public(181)).unwrap()
}
fn document(generation: u64, changed: bool) -> ManagementDocument {
    let endpoint = |net: &str| {
        Endpoint::new(
            network(net),
            device(if net == "beta" {
                "shared-beta"
            } else {
                "shared"
            }),
        )
    };
    let config = Config::new(
        generation,
        vec![
            Network::new(
                network("alpha"),
                vec![
                    Device::new(
                        device("shared"),
                        public(11),
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
                        device("shared-beta"),
                        public(21),
                        vec!["10.2.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ],
        Policy::new(
            if changed {
                vec![Rule::new(endpoint("alpha"), endpoint("beta"), Action::Deny)]
            } else {
                vec![]
            },
            vec![],
            vec![Grant::new(endpoint("alpha"), endpoint("beta"))],
        ),
    )
    .unwrap();
    let routing = ManagementConfig::new(
        node("management"),
        config,
        vec![
            GatewayAssignment::new(
                node("gateway"),
                (public(101)).clone(),
                wgfeel_test_support::fixture_gateway_public(&(public(101))),
                vec![network("alpha"), network("beta")],
                vec![TenantKeyAssignment::new(network("alpha"), public(102))],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    ManagementDocument::new(
        routing,
        vec![
            Client::new(
                ClientId::new("alice").unwrap(),
                vec![network("alpha")],
                vec![ClientDevice::new(
                    device("shared"),
                    DeviceMetadata::new(
                        Some(if changed { "renamed" } else { "Alice laptop" }.into()),
                        Some("Alice description".into()),
                    )
                    .unwrap(),
                )],
            )
            .unwrap(),
            Client::new(
                ClientId::new("bob").unwrap(),
                vec![network("beta")],
                vec![ClientDevice::new(
                    device("shared-beta"),
                    DeviceMetadata::new(Some("Bob laptop".into()), None).unwrap(),
                )],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn seed(path: &Path, configured: bool) -> ManagementStore {
    let mut store = ManagementStore::initialize(path).unwrap();
    if configured {
        store
            .commit_with_api(
                &document(3, false),
                &key(),
                &credential(false),
                &api(),
                None,
            )
            .unwrap();
    } else {
        store
            .commit(&document(3, false), &key(), &credential(false), None)
            .unwrap();
    }
    store
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn assert_state(
    state: &StoredManagement,
    expected: &ManagementDocument,
    configured: bool,
    changed_credential: bool,
) {
    assert_eq!(state.document(), expected);
    assert!(state.service_private_key().expose_bytes() == &[197; 32]);
    assert!(
        state
            .admin_verifier()
            .verify(&[if changed_credential { 227 } else { 211 }; 32])
    );
    if configured {
        let actual = state.api().expect("configured API was lost");
        assert_eq!(
            actual.listen(),
            "0.0.0.0:51820".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(actual.admin_public_key(), &public(181));
    } else {
        assert!(state.api().is_none());
    }
}
fn child(path: &Path, mode: &str, stage: usize) -> ManagedChild {
    ManagedChild::spawn(
        ProcessSpec::new(
            std::env::current_exe().unwrap(),
            [
                "--exact",
                "management_api_process_fixture",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .map(OsString::from)
            .to_vec(),
            vec![
                ("WGFEEL_API_STATE".into(), path.as_os_str().to_owned()),
                ("WGFEEL_API_MODE".into(), mode.into()),
                ("WGFEEL_API_STAGE".into(), stage.to_string().into()),
            ],
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 8192,
            max_stderr_bytes: 8192,
        },
    )
    .unwrap()
}
fn fresh_verify(path: &Path, configured: bool) {
    let output = child(
        path,
        if configured {
            "verify-configured"
        } else {
            "verify-unconfigured"
        },
        0,
    )
    .wait(WAIT)
    .unwrap();
    assert!(
        output.status.success(),
        "fresh process rejected expected complete snapshot"
    );
}

#[test]
fn api_listen_validation_accepts_wildcards_but_not_zero_port_multicast_broadcast_or_mapped_ipv6() {
    for address in [
        "0.0.0.0:51820",
        "[::]:51820",
        "127.0.0.1:1",
        "[::1]:65535",
        "192.0.2.1:51820",
        "[2001:db8::1]:51820",
    ] {
        let address: SocketAddr = address.parse().unwrap();
        let settings = ManagementApi::new(address, public(181)).unwrap();
        assert_eq!(settings.listen(), address);
        assert_eq!(settings.admin_public_key(), &public(181));
    }
    for address in [
        "0.0.0.0:0",
        "[::]:0",
        "224.0.0.1:51820",
        "255.255.255.255:51820",
        "[ff02::1]:51820",
        "[::ffff:192.0.2.1]:51820",
    ] {
        assert!(ManagementApi::new(address.parse().unwrap(), public(181)).is_err());
    }
}

#[test]
fn commits_use_hashed_auth_and_explicit_api_configuration_preserves_complete_material() {
    let directory = Directory::new();
    let mut store = seed(&directory.state(), false);
    assert_state(
        &store.load().unwrap().unwrap(),
        &document(3, false),
        false,
        false,
    );
    store
        .commit(&document(4, false), &key(), &credential(false), Some(3))
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.state().join("state.json")).unwrap()).unwrap();
    assert_eq!(json["management_storage_version"], 7);
    assert!(json.get("api").is_none());
    store
        .commit_with_api(
            &document(6, true),
            &key(),
            &credential(true),
            &api(),
            Some(4),
        )
        .unwrap();
    assert_state(
        &store.load().unwrap().unwrap(),
        &document(6, true),
        true,
        true,
    );
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.state().join("state.json")).unwrap()).unwrap();
    assert_eq!(json["management_storage_version"], 7);
    assert_eq!(
        json["api"],
        serde_json::json!({"listen":"0.0.0.0:51820","admin_public_key":vec![181;32]})
    );
    assert_eq!(json.as_object().unwrap().len(), 6);
    drop(store);
    fresh_verify(&directory.state(), true);
}

#[test]
fn configuration_and_settings_pin_failures_do_not_touch_current_or_pending() {
    for configured in [false, true] {
        let directory = Directory::new();
        let mut store = seed(&directory.state(), configured);
        let before = fs::read(directory.state().join("state.json")).unwrap();
        let pending = directory.state().join(".pending");
        private_file(&pending, b"pending must remain unchanged");
        for category in 0..if configured { 7 } else { 5 } {
            let generation = if category == 2 { 3 } else { 6 };
            let candidate = if category == 3 {
                let mut json: serde_json::Value =
                    serde_json::from_str(&document(generation, true).to_json().unwrap()).unwrap();
                json["management_id"] = "foreign".into();
                ManagementDocument::from_json(&json.to_string()).unwrap()
            } else {
                document(generation, true)
            };
            let supplied_key = if category == 4 {
                wgfeel_test_support::fixture_node_keys([198; 32])
            } else {
                key()
            };
            let settings = match category {
                5 => ManagementApi::new("0.0.0.0:51821".parse().unwrap(), public(181)).unwrap(),
                6 => ManagementApi::new("0.0.0.0:51820".parse().unwrap(), public(182)).unwrap(),
                _ => api(),
            };
            let expected = match category {
                0 => None,
                1 => Some(2),
                _ => Some(3),
            };
            let mut reached = false;
            let error = store
                .commit_with_api_and_checkpoint(
                    &candidate,
                    &supplied_key,
                    &credential(true),
                    &settings,
                    expected,
                    |_| {
                        reached = true;
                        Ok(())
                    },
                )
                .unwrap_err();
            assert!(match category {
                0 | 1 => matches!(error, StoreError::RevisionConflict),
                2 => matches!(error, StoreError::RevisionNotIncreasing),
                3 => matches!(error, StoreError::AuthorityChanged),
                4 => matches!(error, StoreError::IdentityChanged),
                _ => matches!(error, StoreError::ApiSettingsChanged),
            });
            assert!(!reached);
            assert_eq!(
                fs::read(directory.state().join("state.json")).unwrap(),
                before
            );
            assert_eq!(
                fs::read(&pending).unwrap(),
                b"pending must remain unchanged"
            );
            assert_state(
                &store.load().unwrap().unwrap(),
                &document(3, false),
                configured,
                false,
            );
        }
    }
}

#[test]
fn all_six_changes_and_credential_rotation_preserve_settings_without_public_projection_leakage() {
    let directory = Directory::new();
    let mut store = seed(&directory.state(), true);
    let changes = [
        ManagementChange::AddClient {
            broadcast: true,
            name: "New user".into(),
            client: ClientId::new("charlie").unwrap(),
            network: network("gamma"),
        },
        ManagementChange::AddDevice {
            client: ClientId::new("charlie").unwrap(),
            network: network("gamma"),
            device: Device::new(
                device("guest"),
                public(31),
                vec!["10.3.0.1".parse().unwrap()],
            )
            .unwrap(),
            metadata: DeviceMetadata::new(Some("new device".into()), None).unwrap(),
        },
        ManagementChange::AddGateway {
            assignment: GatewayAssignment::new(
                node("gateway-new"),
                (public(201)).clone(),
                wgfeel_test_support::fixture_gateway_public(&(public(201))),
                vec![network("gamma")],
                vec![TenantKeyAssignment::new(network("gamma"), public(202))],
            )
            .unwrap(),
        },
        ManagementChange::RemoveDevice {
            client: ClientId::new("charlie").unwrap(),
            device: device("guest"),
        },
        ManagementChange::RemoveClient {
            client: ClientId::new("charlie").unwrap(),
        },
        ManagementChange::RemoveGateway {
            gateway: node("gateway-new"),
        },
    ];
    for change in changes {
        let current = store.load().unwrap().unwrap();
        let generation = current.document().routing().generation();
        let candidate = current
            .document()
            .apply_change(generation, &change)
            .unwrap();
        store
            .commit(
                &candidate,
                current.node_keys(),
                &credential(false),
                Some(generation),
            )
            .unwrap();
        assert_state(&store.load().unwrap().unwrap(), &candidate, true, false);
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.state().join("state.json")).unwrap())
                .unwrap();
        assert_eq!(json["management_storage_version"], 7);
        let public = candidate.to_json().unwrap();
        assert!(!public.contains("\"api\""));
        assert!(!public.contains("admin_public_key"));
        for assignment in candidate.routing().assignments() {
            let projection = candidate
                .project_for(assignment.recipient())
                .unwrap()
                .to_json()
                .unwrap();
            assert!(!projection.contains("\"api\""));
            assert!(!projection.contains("admin_public_key"));
        }
    }
    assert_state(
        &store.load().unwrap().unwrap(),
        &document(9, false),
        true,
        false,
    );
    store
        .commit(&document(10, true), &key(), &credential(true), Some(9))
        .unwrap();
    assert_state(
        &store.load().unwrap().unwrap(),
        &document(10, true),
        true,
        true,
    );
    store
        .commit_with_api(
            &document(11, true),
            &key(),
            &credential(true),
            &api(),
            Some(10),
        )
        .unwrap();
    assert_state(
        &store.load().unwrap().unwrap(),
        &document(11, true),
        true,
        true,
    );
    let debug = format!("{:?}", store.load().unwrap().unwrap());
    for value in [197, 211, 227] {
        assert!(!debug.contains(&format!("{value}, {value}, {value}")));
    }
}

const LITERAL_DOCUMENT: &str = r#"{"management_version":1,"management_id":"management","config":{"schema_version":1,"generation":3,"networks":[],"policy":{"global_rules":[],"local_rules":[],"grants":[]}},"assignments":[],"clients":[]}"#;
fn literal() -> String {
    literal_snapshot(LITERAL_DOCUMENT, true)
}

fn literal_snapshot(document: &str, configured: bool) -> String {
    let api = if configured {
        format!(
            r#","api":{{"listen":"0.0.0.0:51820","admin_public_key":{}}}"#,
            serde_json::to_string(&[181; 32]).unwrap()
        )
    } else {
        String::new()
    };
    format!(
        r#"{{"management_storage_version":6,"document":{document},"gateway_private_key":{},"service_private_key":{},"admin_verifier":{}{api}}}"#,
        serde_json::to_string(&[99; 32]).unwrap(),
        serde_json::to_string(&[197; 32]).unwrap(),
        serde_json::to_string(&wgfeel_store::AdminVerifier::new(&credential(false)).unwrap())
            .unwrap(),
    )
}

#[test]
fn explicit_api_settings_reject_ambiguous_fields_and_invalid_addresses() {
    let valid = literal();
    let parsed: serde_json::Value = serde_json::from_str(&valid).unwrap();
    let mut cases = vec![
        valid.replace(
            "\"management_storage_version\":6",
            "\"management_storage_version\":99",
        ),
        valid.replace("\"listen\":", "\"listen\":\"0.0.0.0:51820\",\"listen\":"),
        valid.replace(
            "\"admin_public_key\":",
            &format!(
                "\"admin_public_key\":{},\"admin_public_key\":",
                serde_json::to_string(&vec![181; 32]).unwrap()
            ),
        ),
        valid.replace("\"api\":", "\"api\":null,\"api\":"),
        valid.replace("\"generation\":3", "\"generation\":3,\"generation\":4"),
    ];
    let mut null = parsed.clone();
    null["api"] = serde_json::Value::Null;
    cases.push(null.to_string());
    for field in ["listen", "admin_public_key"] {
        let mut candidate = parsed.clone();
        candidate["api"].as_object_mut().unwrap().remove(field);
        cases.push(candidate.to_string());
    }
    for (field, value) in [
        ("listen", serde_json::json!("localhost:51820")),
        ("listen", serde_json::json!("0.0.0.0:0")),
        ("listen", serde_json::json!("224.0.0.1:51820")),
        ("listen", serde_json::json!("[::ffff:192.0.2.1]:51820")),
        ("admin_public_key", serde_json::json!(null)),
        ("admin_public_key", serde_json::json!(vec![0; 32])),
        ("admin_public_key", serde_json::json!(vec![1; 31])),
        ("admin_public_key", serde_json::json!(vec![1; 33])),
        ("admin_public_key", serde_json::json!(vec![256; 32])),
        ("unknown", serde_json::json!("NEVER_ECHO_INPUT")),
    ] {
        let mut candidate = parsed.clone();
        candidate["api"][field] = value;
        cases.push(candidate.to_string());
    }
    for input in cases {
        let directory = Directory::new();
        let mut store = ManagementStore::initialize(&directory.state()).unwrap();
        private_file(&directory.state().join("state.json"), input.as_bytes());
        private_file(&directory.state().join(".pending"), b"do not repair input");
        let error = store.load().unwrap_err();
        assert!(matches!(error, StoreError::InvalidState));
        assert!(!format!("{error:?} {error}").contains("NEVER_ECHO_INPUT"));
        assert!(matches!(
            store.commit_with_api(&document(6, true), &key(), &credential(true), &api(), None),
            Err(StoreError::InvalidState)
        ));
        assert_eq!(
            fs::read(directory.state().join("state.json")).unwrap(),
            input.as_bytes()
        );
        assert_eq!(
            fs::read(directory.state().join(".pending")).unwrap(),
            b"do not repair input"
        );
    }
    let directory = Directory::new();
    let store = ManagementStore::initialize(&directory.state()).unwrap();
    private_file(&directory.state().join("state.json"), valid.as_bytes());
    assert_state(
        &store.load().unwrap().unwrap(),
        &ManagementDocument::from_json(LITERAL_DOCUMENT).unwrap(),
        true,
        false,
    );
}

#[test]
fn snapshots_retain_both_nested_document_and_whole_snapshot_byte_bounds() {
    let expected = ManagementDocument::from_json(LITERAL_DOCUMENT).unwrap();
    let envelope_limit = MAX_MANAGEMENT_BYTES + 4096;
    for configured in [false, true] {
        let check = |input: &[u8], accepted| {
            let directory = Directory::new();
            let store = ManagementStore::initialize(&directory.state()).unwrap();
            private_file(&directory.state().join("state.json"), input);
            if accepted {
                assert_state(
                    &store.load().unwrap().unwrap(),
                    &expected,
                    configured,
                    false,
                );
            } else {
                assert!(matches!(store.load(), Err(StoreError::InvalidState)));
            }
        };
        for (extra, accepted) in [(0, true), (1, false)] {
            let mut envelope = literal_snapshot(LITERAL_DOCUMENT, configured).into_bytes();
            envelope.resize(envelope_limit + extra, b' ');
            check(&envelope, accepted);

            let mut document = LITERAL_DOCUMENT.strip_suffix('}').unwrap().to_owned();
            document.extend(std::iter::repeat_n(
                ' ',
                MAX_MANAGEMENT_BYTES + extra - document.len() - 1,
            ));
            document.push('}');
            assert_eq!(document.len(), MAX_MANAGEMENT_BYTES + extra);
            let envelope = literal_snapshot(&document, configured);
            assert!(envelope.len() < envelope_limit);
            check(envelope.as_bytes(), accepted);
        }
    }
}

#[test]
fn explicit_api_publication_respects_existing_lock_wrong_role_and_unsafe_pending_boundaries() {
    let directory = Directory::new();
    let mut store = seed(&directory.state(), false);
    assert!(matches!(
        ManagementStore::open(&directory.state()),
        Err(StoreError::Locked)
    ));
    let before = fs::read(directory.state().join("state.json")).unwrap();
    let outside = directory.0.join("outside");
    private_file(&outside, b"must not be followed");
    symlink(&outside, directory.state().join(".pending")).unwrap();
    assert!(matches!(
        store.commit_with_api(
            &document(6, true),
            &key(),
            &credential(true),
            &api(),
            Some(3)
        ),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(fs::read(&outside).unwrap(), b"must not be followed");
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        before
    );
    let other = directory.0.join("gateway");
    let mut gateway = Store::initialize(&other).unwrap();
    let node = node("gateway");
    let keys = key();
    let projection = wgfeel_test_support::fixture_projection(
        &Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
        &node,
        &keys,
        vec![],
    );
    gateway
        .commit_projection(
            projection.management_id(),
            &projection,
            &node,
            &keys,
            &Default::default(),
        )
        .unwrap();
    drop(gateway);
    let before = fs::read(other.join("state.json")).unwrap();
    private_file(&other.join(".pending"), b"foreign pending");
    let mut wrong_role = ManagementStore::open(&other).unwrap();
    assert!(matches!(
        wrong_role.commit_with_api(&document(6, true), &key(), &credential(true), &api(), None),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(fs::read(other.join("state.json")).unwrap(), before);
    assert_eq!(
        fs::read(other.join(".pending")).unwrap(),
        b"foreign pending"
    );
}

#[test]
fn every_settings_checkpoint_error_recovers_a_whole_snapshot_and_requires_correct_cas() {
    for (index, stage) in STAGES.into_iter().enumerate() {
        let directory = Directory::new();
        let mut store = seed(&directory.state(), false);
        let mut visited = vec![];
        let result = store.commit_with_api_and_checkpoint(
            &document(6, true),
            &key(),
            &credential(true),
            &api(),
            Some(3),
            |at| {
                visited.push(at);
                if at == stage {
                    Err(io::Error::other("injected failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(visited, STAGES[..=index]);
        if index < 3 {
            assert!(matches!(result, Err(StoreError::Io(_))));
        } else {
            assert!(matches!(result, Err(StoreError::CommitUncertain)));
            assert!(matches!(
                store.commit_with_api(
                    &document(7, true),
                    &key(),
                    &credential(true),
                    &api(),
                    Some(3)
                ),
                Err(StoreError::RevisionConflict)
            ));
        }
        assert_state(
            &store.load().unwrap().unwrap(),
            &document(if index < 3 { 3 } else { 6 }, index >= 3),
            index >= 3,
            index >= 3,
        );
        drop(store);
        fresh_verify(&directory.state(), index >= 3);
    }
}

#[test]
fn process_death_at_each_settings_checkpoint_retains_all_fields_and_releases_the_lock() {
    for (index, _) in STAGES.iter().enumerate() {
        let directory = Directory::new();
        drop(seed(&directory.state(), false));
        let mut writer = child(&directory.state(), "crash-writer", index);
        writer
            .wait_for_stdout_line(b"API_CHECKPOINT_READY", WAIT)
            .unwrap();
        assert!(matches!(
            ManagementStore::open(&directory.state()),
            Err(StoreError::Locked)
        ));
        assert!(!writer.terminate().unwrap().status.success());
        fresh_verify(&directory.state(), index >= 3);
    }
}

#[test]
#[ignore = "Rust child fixture invoked only by API persistence tests"]
fn management_api_process_fixture() {
    let path = PathBuf::from(std::env::var_os("WGFEEL_API_STATE").unwrap());
    let mode = std::env::var("WGFEEL_API_MODE").unwrap();
    let mut store = ManagementStore::open(&path).unwrap();
    match mode.as_str() {
        "verify-unconfigured" => assert_state(
            &store.load().unwrap().unwrap(),
            &document(3, false),
            false,
            false,
        ),
        "verify-configured" => assert_state(
            &store.load().unwrap().unwrap(),
            &document(6, true),
            true,
            true,
        ),
        "crash-writer" => {
            let stage: usize = std::env::var("WGFEEL_API_STAGE").unwrap().parse().unwrap();
            store
                .commit_with_api_and_checkpoint(
                    &document(6, true),
                    &key(),
                    &credential(true),
                    &api(),
                    Some(3),
                    |at| {
                        if at == STAGES[stage] {
                            println!("\nAPI_CHECKPOINT_READY");
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
