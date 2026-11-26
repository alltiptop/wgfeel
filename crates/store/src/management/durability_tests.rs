use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use wgfeel_core::{Config, ManagementConfig, Policy};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wgfeel-management-durability-{}-{}",
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

fn document(generation: u64) -> ManagementDocument {
    ManagementDocument::new(
        ManagementConfig::new(
            NodeId::new("management").unwrap(),
            Config::new(generation, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![],
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}

fn key() -> NodeKeys {
    wgfeel_test_support::fixture_node_keys([17; 32])
}

fn credential() -> AdminCredential {
    AdminCredential::new([19; 32]).unwrap()
}

fn populated(directory: &Directory) -> ManagementStore {
    let mut store = ManagementStore::initialize(&directory.state()).unwrap();
    store
        .commit(&document(1), &key(), &credential(), None)
        .unwrap();
    store
}

fn attempts(store: &ManagementStore) -> usize {
    store
        .directory
        .confirmation
        .attempts
        .load(Ordering::Relaxed)
}

fn fail_confirmation(store: &ManagementStore, fail: bool) {
    store
        .directory
        .confirmation
        .fail
        .store(fail, Ordering::Relaxed);
}

fn interrupt_publish(store: &mut ManagementStore, stage: CommitStage) {
    let result =
        store.commit_with_checkpoint(&document(2), &key(), &credential(), Some(1), |current| {
            if current == stage {
                Err(io::Error::other("injected publish interruption"))
            } else {
                Ok(())
            }
        });
    assert!(matches!(result, Err(StoreError::CommitUncertain)));
}

#[test]
fn empty_and_successfully_published_stores_need_no_load_confirmation() {
    let directory = Directory::new();
    let mut store = ManagementStore::initialize(&directory.state()).unwrap();
    fail_confirmation(&store, true);
    assert!(store.load().unwrap().is_none());
    store
        .commit(&document(1), &key(), &credential(), None)
        .unwrap();
    for _ in 0..2 {
        assert_eq!(store.load().unwrap().unwrap().document(), &document(1));
    }
    assert_eq!(attempts(&store), 0);
}

#[test]
fn opening_existing_authority_confirms_once_before_returning_it() {
    let directory = Directory::new();
    drop(populated(&directory));
    for initialize in [false, true] {
        let store = if initialize {
            ManagementStore::initialize(&directory.state())
        } else {
            ManagementStore::open(&directory.state())
        }
        .unwrap();
        assert_eq!(attempts(&store), 0);
        assert_eq!(store.load().unwrap().unwrap().document(), &document(1));
        assert_eq!(attempts(&store), 1);
        fail_confirmation(&store, true);
        assert_eq!(store.load().unwrap().unwrap().document(), &document(1));
        assert_eq!(attempts(&store), 1);
    }
}

#[test]
fn reopened_authority_stays_unavailable_until_confirmation_succeeds() {
    let directory = Directory::new();
    drop(populated(&directory));
    let store = ManagementStore::open(&directory.state()).unwrap();
    fail_confirmation(&store, true);
    for expected_attempts in 1..=2 {
        assert!(matches!(store.load(), Err(StoreError::Io(_))));
        assert_eq!(attempts(&store), expected_attempts);
    }
    fail_confirmation(&store, false);
    assert_eq!(store.load().unwrap().unwrap().document(), &document(1));
    assert_eq!(attempts(&store), 3);
    fail_confirmation(&store, true);
    assert!(store.load().is_ok());
    assert_eq!(attempts(&store), 3);
}

#[test]
fn uncertain_publication_is_confirmed_before_loading_its_generation() {
    for stage in [CommitStage::AfterRename, CommitStage::AfterDirectorySync] {
        let directory = Directory::new();
        let mut store = populated(&directory);
        interrupt_publish(&mut store, stage);
        assert_eq!(store.load().unwrap().unwrap().document(), &document(2));
        assert_eq!(attempts(&store), 1);
        fail_confirmation(&store, true);
        assert_eq!(store.load().unwrap().unwrap().document(), &document(2));
        assert_eq!(attempts(&store), 1);
    }
}

#[test]
fn uncertain_authority_cannot_be_loaded_or_replaced_until_confirmed() {
    let directory = Directory::new();
    let mut store = populated(&directory);
    interrupt_publish(&mut store, CommitStage::AfterRename);
    let visible = fs::read(directory.state().join("state.json")).unwrap();
    fail_confirmation(&store, true);
    for expected_attempts in 1..=2 {
        assert!(matches!(store.load(), Err(StoreError::Io(_))));
        assert_eq!(attempts(&store), expected_attempts);
    }
    // Even a caller using the visible generation cannot publish until the
    // authority that generation represents has been made durable.
    let mut visited = vec![];
    assert!(matches!(
        store.commit_with_checkpoint(&document(3), &key(), &credential(), Some(2), |stage| {
            visited.push(stage);
            Ok(())
        }),
        Err(StoreError::Io(_))
    ));
    assert!(visited.is_empty());
    assert_eq!(
        fs::read(directory.state().join("state.json")).unwrap(),
        visible
    );
    assert!(!directory.state().join(".pending").exists());
    assert_eq!(attempts(&store), 3);

    fail_confirmation(&store, false);
    assert_eq!(store.load().unwrap().unwrap().document(), &document(2));
    assert_eq!(attempts(&store), 4);
    assert!(matches!(
        store.commit(&document(3), &key(), &credential(), Some(1)),
        Err(StoreError::RevisionConflict)
    ));
    store
        .commit(&document(3), &key(), &credential(), Some(2))
        .unwrap();
    assert_eq!(store.load().unwrap().unwrap().document(), &document(3));
    assert_eq!(attempts(&store), 4);
}

#[test]
fn failure_before_rename_keeps_the_previous_confirmation() {
    let directory = Directory::new();
    let mut store = populated(&directory);
    fail_confirmation(&store, true);
    assert!(matches!(
        store.commit_with_checkpoint(&document(2), &key(), &credential(), Some(1), |stage| {
            if stage == CommitStage::AfterFileSync {
                Err(io::Error::other("injected failure before rename"))
            } else {
                Ok(())
            }
        }),
        Err(StoreError::Io(_))
    ));
    assert_eq!(store.load().unwrap().unwrap().document(), &document(1));
    assert_eq!(attempts(&store), 0);
}
