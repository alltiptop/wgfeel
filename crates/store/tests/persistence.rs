use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wgfeel_core::{Config, NodeId, NodeKeys, Policy};
use wgfeel_store::{CommitStage, Store, StoreError};
use wgfeel_test_support::{ManagedChild, ProcessLimits, ProcessSpec};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-store-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create unique fixture directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(generation: u64) -> Config {
    Config::new(generation, vec![], Policy::new(vec![], vec![], vec![])).unwrap()
}

fn node() -> NodeId {
    NodeId::new("gateway-a").unwrap()
}

fn key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([37; 32])
}

fn publish(
    store: &mut Store,
    config: &Config,
    id: &NodeId,
    keys: &NodeKeys,
) -> Result<(), StoreError> {
    publish_at(store, config, id, keys, |_| Ok(()))
}
fn publish_at(
    store: &mut Store,
    config: &Config,
    id: &NodeId,
    keys: &NodeKeys,
    checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
) -> Result<(), StoreError> {
    let projection = wgfeel_test_support::fixture_projection(config, id, keys, vec![]);
    store.commit_projection_with_checkpoint(
        projection.management_id(),
        &projection,
        id,
        keys,
        &Default::default(),
        checkpoint,
    )
}
fn populated(directory: &Path) -> Store {
    let mut store = Store::open(directory).unwrap();
    publish(&mut store, &config(1), &node(), &key()).unwrap();
    store
}

fn private_write(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
}

fn assert_loaded(directory: &Path, generation: u64) {
    let store = Store::open(directory).expect("reopen protected state");
    let state = store.load().unwrap().expect("committed state exists");
    assert_eq!(state.config().generation(), generation);
    assert_eq!(state.node_id().as_str(), "gateway-a");
    assert_eq!(state.service_private_key().expose_bytes(), &[37; 32]);
}

fn assert_unsafe_state(directory: &Path) {
    match Store::open(directory) {
        Err(StoreError::UnsafePath) => {}
        Ok(store) => assert!(matches!(store.load(), Err(StoreError::UnsafePath))),
        Err(error) => panic!("expected unsafe-path rejection, got {error}"),
    }
}

#[test]
fn initialize_creates_only_private_leaf_and_open_does_not_create() {
    let fixture = TestDirectory::new();
    let missing = fixture.path().join("state");
    assert!(matches!(Store::open(&missing), Err(StoreError::Io(_))));
    assert!(!missing.exists());
    let store = Store::initialize(&missing).unwrap();
    assert!(store.load().unwrap().is_none());
    assert_eq!(
        fs::metadata(&missing).unwrap().permissions().mode() & 0o777,
        0o700
    );
    drop(store);
    assert!(Store::initialize(&missing).is_ok());
    let missing_parent = fixture.path().join("absent").join("state");
    assert!(Store::initialize(&missing_parent).is_err());
    assert!(!fixture.path().join("absent").exists());
}

#[test]
fn commit_and_reopen_preserve_configuration_identity_and_private_mode() {
    let fixture = TestDirectory::new();
    let store = populated(fixture.path());
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.config(), &config(1));
    assert_eq!(state.node_id(), &node());
    assert_eq!(state.service_private_key().expose_bytes(), &[37; 32]);
    assert_eq!(
        fs::metadata(fixture.path().join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(store);
    assert_loaded(fixture.path(), 1);
}

#[test]
fn only_strictly_increasing_generations_can_replace_state() {
    let fixture = TestDirectory::new();
    let mut store = populated(fixture.path());
    assert!(matches!(
        publish(&mut store, &config(1), &node(), &key()),
        Err(StoreError::RevisionNotIncreasing)
    ));
    publish(&mut store, &config(9), &node(), &key()).unwrap();
    assert!(matches!(
        publish(&mut store, &config(2), &node(), &key()),
        Err(StoreError::RevisionNotIncreasing)
    ));
    assert_eq!(store.load().unwrap().unwrap().config().generation(), 9);
    publish(&mut store, &config(u64::MAX), &node(), &key()).unwrap();
    assert!(matches!(
        publish(&mut store, &config(1), &node(), &key()),
        Err(StoreError::RevisionNotIncreasing)
    ));
}

#[test]
fn node_identifier_and_private_key_are_immutable_after_first_commit() {
    let fixture = TestDirectory::new();
    let mut store = populated(fixture.path());
    assert!(matches!(
        publish(
            &mut store,
            &config(2),
            &NodeId::new("gateway-b").unwrap(),
            &key()
        ),
        Err(StoreError::IdentityChanged)
    ));
    assert!(matches!(
        publish(
            &mut store,
            &config(2),
            &node(),
            &wgfeel_test_support::fixture_node_keys([38; 32])
        ),
        Err(StoreError::IdentityChanged)
    ));
    drop(store);
    assert_loaded(fixture.path(), 1);
}

#[test]
fn a_second_store_open_is_nonblocking_and_rejected_until_lock_drop() {
    let fixture = TestDirectory::new();
    let store = Store::open(fixture.path()).unwrap();
    assert!(matches!(
        Store::open(fixture.path()),
        Err(StoreError::Locked)
    ));
    drop(store);
    assert!(Store::open(fixture.path()).is_ok());
}

#[test]
fn insecure_directory_is_rejected_without_chmod_repair() {
    let fixture = TestDirectory::new();
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Store::open(fixture.path()),
        Err(StoreError::UnsafePath)
    ));
    assert!(matches!(
        Store::initialize(fixture.path()),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(
        fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn symlink_components_and_parent_traversal_are_rejected() {
    let fixture = TestDirectory::new();
    let target = fixture.path().join("real");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let link = fixture.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(matches!(Store::open(&link), Err(StoreError::UnsafePath)));
    assert!(matches!(
        Store::initialize(&link.join("child")),
        Err(StoreError::UnsafePath)
    ));
    assert!(!target.join("child").exists());
    let traversal = target.join("..").join("real");
    assert!(matches!(
        Store::open(&traversal),
        Err(StoreError::UnsafePath)
    ));
}

#[test]
fn symlink_or_hardlink_current_state_never_reads_or_replaces_target() {
    for hardlink in [false, true] {
        let fixture = TestDirectory::new();
        let target = fixture.path().join("outside");
        private_write(&target, b"do not read or replace");
        let current = fixture.path().join("state.json");
        if hardlink {
            fs::hard_link(&target, &current).unwrap();
        } else {
            symlink(&target, &current).unwrap();
        }
        assert_unsafe_state(fixture.path());
        assert_eq!(fs::read(&target).unwrap(), b"do not read or replace");
    }
}

#[test]
fn permissive_current_file_is_rejected_without_repair() {
    let fixture = TestDirectory::new();
    drop(populated(fixture.path()));
    let current = fixture.path().join("state.json");
    fs::set_permissions(&current, fs::Permissions::from_mode(0o644)).unwrap();
    assert_unsafe_state(fixture.path());
    assert_eq!(
        fs::metadata(&current).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn suspicious_pending_entries_are_not_unlinked_or_truncated() {
    for hardlink in [false, true] {
        let fixture = TestDirectory::new();
        let mut store = populated(fixture.path());
        let target = fixture.path().join("outside");
        private_write(&target, b"preserve external contents");
        let pending = fixture.path().join(".pending");
        if hardlink {
            fs::hard_link(&target, &pending).unwrap();
        } else {
            symlink(&target, &pending).unwrap();
        }
        assert!(matches!(
            publish(&mut store, &config(2), &node(), &key()),
            Err(StoreError::UnsafePath)
        ));
        assert!(fs::symlink_metadata(&pending).is_ok());
        assert_eq!(fs::read(&target).unwrap(), b"preserve external contents");
        drop(store);
    }
}

#[test]
fn incomplete_pending_is_not_promoted_and_can_be_replaced_by_later_commit() {
    let fixture = TestDirectory::new();
    drop(populated(fixture.path()));
    private_write(&fixture.path().join(".pending"), b"{incomplete");
    assert_loaded(fixture.path(), 1);
    let mut store = Store::open(fixture.path()).unwrap();
    publish(&mut store, &config(2), &node(), &key()).unwrap();
    drop(store);
    assert_loaded(fixture.path(), 2);
}

#[test]
fn failed_initial_commit_does_not_publish_identity_or_configuration() {
    for stage in [
        CommitStage::AfterCreate,
        CommitStage::AfterWrite,
        CommitStage::AfterFileSync,
    ] {
        let fixture = TestDirectory::new();
        let mut store = Store::open(fixture.path()).unwrap();
        assert!(matches!(
            publish_at(&mut store, &config(1), &node(), &key(), |at| {
                if at == stage {
                    Err(io::Error::other("initial commit interrupted"))
                } else {
                    Ok(())
                }
            }),
            Err(StoreError::Io(_))
        ));
        drop(store);
        let mut reopened = Store::open(fixture.path()).unwrap();
        assert!(reopened.load().unwrap().is_none());
        // The failed publication did not permanently claim either identity value.
        publish(
            &mut reopened,
            &config(1),
            &NodeId::new("first-published-node").unwrap(),
            &wgfeel_test_support::fixture_node_keys([38; 32]),
        )
        .unwrap();
        assert_eq!(
            reopened.load().unwrap().unwrap().node_id().as_str(),
            "first-published-node"
        );
    }
}

#[test]
fn malformed_current_fails_closed_instead_of_loading_pending() {
    let fixture = TestDirectory::new();
    drop(populated(fixture.path()));
    let current = fixture.path().join("state.json");
    let complete = fs::read(&current).unwrap();
    fs::write(&current, b"{broken-current").unwrap();
    private_write(&fixture.path().join(".pending"), &complete);
    let store = Store::open(fixture.path()).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidState)));
}

#[test]
fn oversized_regular_state_is_rejected() {
    // Whitespace is valid JSON. Only the byte boundary distinguishes these cases;
    // zeros or a truncated document could be rejected solely for invalid syntax.
    let maximum = wgfeel_core::MAX_PROJECTION_BYTES + 65_536;
    for (size, accepted) in [(maximum, true), (maximum + 1, false)] {
        let fixture = TestDirectory::new();
        let mut input = envelope(VALID_CONFIG, "3").into_bytes();
        input.resize(size, b' ');
        private_write(&fixture.path().join("state.json"), &input);
        let store = Store::open(fixture.path()).unwrap();
        if accepted {
            assert_eq!(store.load().unwrap().unwrap().config().generation(), 1);
        } else {
            assert!(matches!(store.load(), Err(StoreError::InvalidState)));
        }
    }
}

fn envelope(config_text: &str, version: &str) -> String {
    let service_key = vec![37u8; 32];
    let gateway_key = vec![99u8; 32];
    let assignment = serde_json::json!({"recipient":"gateway-a", "service_public_key":vec![31u8;32],
        "gateway_public_key":vec![32u8;32], "networks":[], "tenants":[], "traffic":"entry"});
    format!(
        r#"{{"storage_version":{version},"node_id":"gateway-a","service_private_key":{service_key:?},"gateway_private_key":{gateway_key:?},"projection":{{"projection_version":1,"management_id":"main","assignment":{assignment},"config":{config_text}}},"tenant_private_keys":[]}}"#
    )
}

const VALID_CONFIG: &str = r#"{"schema_version":1,"generation":1,"networks":[],"policy":{"global_rules":[],"local_rules":[],"grants":[]}}"#;

#[test]
fn storage_versions_unknown_fields_and_duplicate_envelope_fields_fail_closed() {
    let inputs = [
        envelope(VALID_CONFIG, "99"),
        envelope(VALID_CONFIG, "\"3\""),
        envelope(VALID_CONFIG, "3,\"storage_version\":3"),
        envelope(VALID_CONFIG, "3,\"unexpected\":true"),
    ];
    for input in inputs {
        let fixture = TestDirectory::new();
        private_write(&fixture.path().join("state.json"), input.as_bytes());
        let store = Store::open(fixture.path()).unwrap();
        assert!(matches!(store.load(), Err(StoreError::InvalidState)));
    }
}

#[test]
fn stored_private_key_requires_exactly_32_valid_bytes_and_nonzero_value() {
    // Coverage added from independent review of the custom secret deserializer.
    // These fixtures do not call its serializer or derive expectations from it.
    let valid = format!("{:?}", vec![37u8; 32]);
    let cases = [
        std::iter::repeat_n("37", 31).collect::<Vec<_>>().join(","),
        std::iter::repeat_n("37", 33).collect::<Vec<_>>().join(","),
        format!(
            "256,{}",
            std::iter::repeat_n("37", 31).collect::<Vec<_>>().join(",")
        ),
        format!(
            "-1,{}",
            std::iter::repeat_n("37", 31).collect::<Vec<_>>().join(",")
        ),
        std::iter::repeat_n("0", 32).collect::<Vec<_>>().join(","),
    ];
    for bytes in cases {
        let fixture = TestDirectory::new();
        let input = envelope(VALID_CONFIG, "3").replace(&valid, &format!("[{bytes}]"));
        private_write(&fixture.path().join("state.json"), input.as_bytes());
        let store = Store::open(fixture.path()).unwrap();
        assert!(matches!(store.load(), Err(StoreError::InvalidState)));
    }
    let fixture = TestDirectory::new();
    let duplicate = envelope(VALID_CONFIG, "3").replace(
        &format!("\"service_private_key\":{valid}"),
        &format!("\"service_private_key\":{valid},\"service_private_key\":{valid}"),
    );
    private_write(&fixture.path().join("state.json"), duplicate.as_bytes());
    let store = Store::open(fixture.path()).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidState)));
}

#[test]
fn nested_config_duplicate_fields_cannot_disappear_in_intermediate_json_value() {
    let fixture = TestDirectory::new();
    let duplicate = r#"{"schema_version":1,"generation":1,"generation":2,"networks":[],"policy":{"global_rules":[],"local_rules":[],"grants":[]}}"#;
    private_write(
        &fixture.path().join("state.json"),
        envelope(duplicate, "3").as_bytes(),
    );
    let store = Store::open(fixture.path()).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidState)));
}

#[test]
fn malformed_state_diagnostics_do_not_echo_private_values() {
    let fixture = TestDirectory::new();
    let secret_marker = "NEVER_LOG_THIS_PRIVATE_MATERIAL";
    let input = format!("{{\"storage_version\":3,\"service_private_key\":\"{secret_marker}\"}}");
    private_write(&fixture.path().join("state.json"), input.as_bytes());
    let store = Store::open(fixture.path()).unwrap();
    let error = match store.load() {
        Err(error) => error,
        Ok(_) => panic!("malformed private state accepted"),
    };
    assert!(!format!("{error} {error:?}").contains(secret_marker));
}

#[test]
fn injected_prepublication_errors_preserve_previous_revision() {
    for stage in [
        CommitStage::AfterCreate,
        CommitStage::AfterWrite,
        CommitStage::AfterFileSync,
    ] {
        let fixture = TestDirectory::new();
        let mut store = populated(fixture.path());
        let result = publish_at(&mut store, &config(2), &node(), &key(), |at| {
            if at == stage {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(StoreError::Io(_))));
        drop(store);
        assert_loaded(fixture.path(), 1);
    }
}

#[test]
fn injected_postpublication_errors_report_uncertainty_and_require_reload() {
    for stage in [CommitStage::AfterRename, CommitStage::AfterDirectorySync] {
        let fixture = TestDirectory::new();
        let mut store = populated(fixture.path());
        let result = publish_at(&mut store, &config(2), &node(), &key(), |at| {
            if at == stage {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(StoreError::CommitUncertain)));
        assert_eq!(store.load().unwrap().unwrap().config().generation(), 2);
        assert!(matches!(
            publish(&mut store, &config(2), &node(), &key()),
            Err(StoreError::RevisionNotIncreasing)
        ));
        drop(store);
        assert_loaded(fixture.path(), 2);
    }
}

fn stage_name(stage: CommitStage) -> &'static str {
    match stage {
        CommitStage::AfterCreate => "created",
        CommitStage::AfterWrite => "written",
        CommitStage::AfterFileSync => "file-synced",
        CommitStage::AfterRename => "renamed",
        CommitStage::AfterDirectorySync => "directory-synced",
    }
}

#[test]
fn special_current_and_pending_entries_are_rejected_without_blocking_or_unlinking() {
    for pending in [false, true] {
        for fifo in [false, true] {
            let fixture = TestDirectory::new();
            if pending {
                drop(populated(fixture.path()));
            }
            let name = if pending { ".pending" } else { "state.json" };
            let entry = fixture.path().join(name);
            if fifo {
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &entry,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            } else {
                fs::create_dir(&entry).unwrap();
                fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let child = spawn_fixture(
                "subprocess_special_file",
                vec![
                    ("WGFEEL_TEST_STATE_DIRECTORY".into(), fixture.path().into()),
                    ("WGFEEL_TEST_SPECIAL_ENTRY".into(), name.into()),
                ],
            );
            let output = child.wait(Duration::from_secs(10)).unwrap();
            assert!(
                output.status.success(),
                "special entry was not rejected safely"
            );
            let file_type = fs::symlink_metadata(&entry).unwrap().file_type();
            assert_eq!(file_type.is_fifo(), fifo);
            assert_eq!(file_type.is_dir(), !fifo);
        }
    }
}

#[test]
#[ignore = "Rust subprocess harness for bounded special-file rejection"]
fn subprocess_special_file() {
    let directory = std::env::var_os("WGFEEL_TEST_STATE_DIRECTORY").expect("parent fixture path");
    let entry = std::env::var("WGFEEL_TEST_SPECIAL_ENTRY").expect("parent fixture entry");
    let mut store = match Store::open(Path::new(&directory)) {
        Ok(store) => store,
        Err(StoreError::UnsafePath) => return,
        Err(error) => panic!("unexpected store-open error: {error}"),
    };
    if entry == "state.json" {
        assert!(matches!(store.load(), Err(StoreError::UnsafePath)));
    } else {
        assert!(matches!(
            publish(&mut store, &config(2), &node(), &key()),
            Err(StoreError::UnsafePath)
        ));
    }
}

fn spawn_fixture(entry: &str, env: Vec<(std::ffi::OsString, std::ffi::OsString)>) -> ManagedChild {
    ManagedChild::spawn(
        ProcessSpec::new(
            std::env::current_exe().unwrap(),
            ["--exact", entry, "--ignored", "--nocapture"]
                .map(Into::into)
                .to_vec(),
            env,
            None,
        ),
        ProcessLimits {
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
    )
    .unwrap()
}

fn spawn_paused_writer(directory: &Path, stage: CommitStage) -> ManagedChild {
    let mut child = spawn_fixture(
        "subprocess_writer",
        vec![
            ("WGFEEL_TEST_STATE_DIRECTORY".into(), directory.into()),
            ("WGFEEL_TEST_COMMIT_STAGE".into(), stage_name(stage).into()),
        ],
    );
    child
        .wait_for_stdout_line(b"WGFEEL_CHECKPOINT_READY", Duration::from_secs(10))
        .expect("child reached production checkpoint");
    child
}

#[test]
fn process_death_at_each_commit_stage_recovers_only_published_state_and_releases_lock() {
    for stage in [
        CommitStage::AfterCreate,
        CommitStage::AfterWrite,
        CommitStage::AfterFileSync,
        CommitStage::AfterRename,
        CommitStage::AfterDirectorySync,
    ] {
        let fixture = TestDirectory::new();
        drop(populated(fixture.path()));
        let child = spawn_paused_writer(fixture.path(), stage);
        assert!(matches!(
            Store::open(fixture.path()),
            Err(StoreError::Locked)
        ));
        let output = child.terminate().unwrap();
        assert!(!output.status.success());
        let generation = match stage {
            CommitStage::AfterRename | CommitStage::AfterDirectorySync => 2,
            _ => 1,
        };
        assert_loaded(fixture.path(), generation);
    }
}

#[test]
#[ignore = "Rust subprocess harness, launched only by its parent integration test"]
fn subprocess_writer() {
    let directory = std::env::var_os("WGFEEL_TEST_STATE_DIRECTORY").expect("parent fixture path");
    let stage = std::env::var("WGFEEL_TEST_COMMIT_STAGE").expect("parent checkpoint");
    let mut store = Store::open(Path::new(&directory)).unwrap();
    publish_at(&mut store, &config(2), &node(), &key(), |at| {
        if stage_name(at) == stage {
            println!("\nWGFEEL_CHECKPOINT_READY");
            io::stdout().flush()?;
            let mut signal = [0_u8; 1];
            io::stdin().read_exact(&mut signal)?;
        }
        Ok(())
    })
    .unwrap();
}
