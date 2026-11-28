use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf};
use wgfeel_core::{
    AdminCredential, Config, DevicePublicKey, ManagementConfig, ManagementDocument, NodeId, Policy,
};
use wgfeel_store::{CommitStage, ManagementApi, ManagementStore, RestApi, StoreError};

fn document(generation: u64) -> ManagementDocument {
    ManagementDocument::new(
        ManagementConfig::new(
            NodeId::new("main").unwrap(),
            Config::new(generation, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
            vec![],
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn http_port_publication_is_atomic_and_preserves_mesh_identity_and_revision() {
    for (stage, published) in [
        (CommitStage::AfterFileSync, false),
        (CommitStage::AfterRename, true),
    ] {
        let root = Root(std::env::temp_dir().join(format!(
            "wgfeel-rest-store-{}-{stage:?}",
            std::process::id()
        )));
        fs::create_dir(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagementStore::initialize(&root.0.join("state")).unwrap();
        let mesh = ManagementApi::new(
            "0.0.0.0:51820".parse().unwrap(),
            DevicePublicKey::new([181; 32]).unwrap(),
        )
        .unwrap();
        let key = wgfeel_test_support::fixture_node_keys([197; 32]);
        let credential = AdminCredential::new([211; 32]).unwrap();
        let old = RestApi::new("127.0.0.1:8080".parse().unwrap()).unwrap();
        let next = RestApi::new("127.0.0.1:8081".parse().unwrap()).unwrap();
        store
            .initialize_with_apis(&document(1), &key, &credential, &mesh, Some(&old))
            .unwrap();
        let result = store.set_rest_api_with_checkpoint(&next, |at| {
            if at == stage {
                Err(io::Error::other("injected storage failure"))
            } else {
                Ok(())
            }
        });
        if !published {
            assert!(matches!(result, Err(StoreError::Io(_))));
        } else {
            assert!(matches!(result, Err(StoreError::CommitUncertain)));
        }
        drop(store);
        let mut store = ManagementStore::open(&root.0.join("state")).unwrap();
        let state = store.load().unwrap().unwrap();
        let expected = if published { &next } else { &old };
        assert_eq!(state.rest_api(), Some(expected));
        assert_eq!(state.api(), Some(&mesh));
        assert_eq!(state.document(), &document(1));
        assert_eq!(
            state.service_private_key().expose_bytes(),
            key.service().expose_bytes()
        );
        assert!(state.admin_verifier().verify(credential.expose_bytes()));
        store
            .rotate_admin_credential(&AdminCredential::new([212; 32]).unwrap())
            .unwrap();
        store
            .commit(&document(2), &key, &credential, Some(1))
            .unwrap();
        assert_eq!(store.load().unwrap().unwrap().rest_api(), Some(expected));
    }
}

#[test]
fn http_listener_settings_are_strict_and_allow_ipv4_ipv6_and_wildcards() {
    for address in ["127.0.0.1:8080", "0.0.0.0:8080", "[::1]:8080", "[::]:8080"] {
        let settings = RestApi::new(address.parse().unwrap()).unwrap();
        assert_eq!(
            serde_json::from_value::<RestApi>(serde_json::to_value(&settings).unwrap()).unwrap(),
            settings
        );
    }
    for value in [
        serde_json::json!({"listen":"127.0.0.1:0"}),
        serde_json::json!({"listen":"224.0.0.1:8080"}),
        serde_json::json!({"listen":"[::ffff:127.0.0.1]:8080"}),
        serde_json::json!({"listen":"127.0.0.1:8080", "unknown":true}),
        serde_json::json!({"listen":null}),
    ] {
        assert!(serde_json::from_value::<RestApi>(value).is_err());
    }
}
