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

/// Build fixed-width /128 route rows so a single additional route can cross
/// the production projection ceiling without hard-coding JSON framing sizes.
fn routes_near_move_limit(
    mut extra: usize,
    promoted: bool,
) -> (ManagementDocument, ManagementSecrets) {
    use wgfeel_core::*;
    use wgfeel_test_support::{fixture_gateway_public, fixture_public};
    let b = NodeId::new("destination").unwrap();
    let networks: Vec<_> = (0..MAX_NETWORKS)
        .map(|i| NetworkId::new(&format!("network-{i:03}")).unwrap())
        .collect();
    let clients: Vec<_> = networks
        .iter()
        .enumerate()
        .map(|(i, n)| {
            Client::new(
                ClientId::new(&format!("user-{i:03}")).unwrap(),
                vec![n.clone()],
                vec![],
            )
            .unwrap()
        })
        .collect();
    let config = Config::new(
        1,
        networks
            .iter()
            .map(|n| Network::new(n.clone(), vec![]).unwrap())
            .collect(),
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let mut nodes = Vec::new();
    for (i, id) in ["destination", "source-1", "source-2"]
        .into_iter()
        .enumerate()
    {
        let public = fixture_public(&[70 + i as u8; 32]);
        let scope = if i == 0 { networks.clone() } else { vec![] };
        let tenants = scope
            .iter()
            .enumerate()
            .map(|(index, n)| {
                let mut key = [244; 32];
                key[..2].copy_from_slice(&(index as u16).to_be_bytes());
                TenantKeyAssignment::new(n.clone(), DevicePublicKey::new(key).unwrap())
            })
            .collect();
        nodes.push(
            GatewayAssignment::new(
                NodeId::new(id).unwrap(),
                public.clone(),
                fixture_gateway_public(&public),
                scope,
                tenants,
            )
            .unwrap()
            .with_endpoint(Some(format!("192.0.2.{}:10000", i + 1).parse().unwrap()))
            .unwrap(),
        );
    }
    let mut policy = EgressPolicy::default();
    let mut secrets = ManagementSecrets::default();
    let peer = fixture_public(&[93; 32]);
    for i in 0..MAX_EGRESSES_PER_USER + 2 {
        let id = EgressId::new(&format!("e{i:02}{}", "x".repeat(61))).unwrap();
        let keys = crate::EgressKeys::new(
            EgressPrivateKey::new([33 + i as u8; 32]).unwrap(),
            Some(PresharedKey::new([253; 32]).unwrap()),
        );
        let placement = if i < MAX_EGRESSES_PER_USER || promoted {
            b.clone()
        } else {
            NodeId::new(&format!("source-{}", i - MAX_EGRESSES_PER_USER + 1)).unwrap()
        };
        policy.profiles.push(
            EgressProfileFields {
                id: id.clone(),
                name: "n".repeat(128),
                node: Some(placement),
                pending_node: None,
                secret_revision: 1,
                interface_public_key: keys.interface_public_key(&peer).unwrap(),
                addresses: vec!["fd01::1".parse().unwrap()],
                dns_servers: vec![],
                mtu: None,
                peer_public_key: peer.clone(),
                endpoint: "vpn.example:51820".parse().unwrap(),
                allowed_ips: vec!["::/0".parse().unwrap()],
                persistent_keepalive: None,
                has_preshared_key: true,
            }
            .try_into()
            .unwrap(),
        );
        secrets.insert_egress(id, keys).unwrap();
    }
    for client in &clients {
        let mut grants = Vec::new();
        for (index, p) in policy.profiles[..MAX_EGRESSES_PER_USER].iter().enumerate() {
            let additional = extra.min(MAX_ROUTES_PER_ASSIGNMENT - 1);
            extra -= additional;
            let routes = (0..=additional)
                .map(|n| {
                    format!(
                        "2001:db8:1111:2222:3333:4444:5555:{:04x}/128",
                        0xf000 + index * 32 + n
                    )
                    .parse()
                    .unwrap()
                })
                .collect();
            grants.push(UserEgressAssignment {
                egress_id: p.id.clone(),
                routes,
                dns: EgressDnsSelection::None {},
            });
        }
        policy.users.push(UserEgresses {
            user: client.id().clone(),
            network: client.network().clone(),
            egresses: grants,
        });
    }
    assert_eq!(extra, 0);
    let routing = ManagementConfig::new(NodeId::new("main").unwrap(), config, nodes)
        .unwrap()
        .with_egress_policy(policy)
        .unwrap();
    (ManagementDocument::new(routing, clients).unwrap(), secrets)
}

#[test]
fn combined_pending_moves_reserve_the_real_destination_size_before_detaching() {
    use wgfeel_core::{DomainError, MAX_EGRESSES_PER_USER, MAX_PROJECTION_BYTES, ManagementChange};
    let target = NodeId::new("destination").unwrap();
    let projected_len = |extra| {
        routes_near_move_limit(extra, true)
            .0
            .routing()
            .project_mesh_for(&target)
            .unwrap()
            .to_json()
            .unwrap()
            .len()
    };
    let base = projected_len(0);
    let row = projected_len(1) - base;
    let extra = (MAX_PROJECTION_BYTES - base) / row + 1;
    let (active, secrets) = routes_near_move_limit(extra, false);
    let move_to_target = |doc: &ManagementDocument, i: usize| {
        doc.apply_change(
            doc.routing().generation(),
            &ManagementChange::SetEgressNode {
                egress: active.routing().egresses()[MAX_EGRESSES_PER_USER + i]
                    .id
                    .clone(),
                node: Some(target.clone()),
            },
        )
        .unwrap()
    };
    let first = move_to_target(&active, 0usize);
    let second = move_to_target(&first, 1usize);
    // Both detached placements' actual deliveries fit. With both providers
    // promoted the production projection ceiling is exceeded by at most one row.
    assert!(
        second
            .routing()
            .project_mesh_for(&target)
            .unwrap()
            .to_json()
            .is_ok()
    );
    assert!(matches!(
        routes_near_move_limit(extra, true)
            .0
            .routing()
            .project_mesh_for(&target)
            .unwrap()
            .to_json(),
        Err(DomainError::LimitExceeded)
    ));
    let directory = Directory::new();
    let mut store = ManagementStore::initialize(&directory.state()).unwrap();
    store
        .commit_with_secrets(&active, &key(), &credential(), &secrets, None)
        .unwrap();
    store
        .commit_with_secrets(&first, &key(), &credential(), &secrets, Some(1))
        .unwrap();
    assert!(matches!(
        store.commit_with_secrets(&second, &key(), &credential(), &secrets, Some(2)),
        Err(StoreError::InvalidConfig(DomainError::LimitExceeded))
    ));
    let retained = store.load().unwrap().unwrap();
    assert_eq!(retained.document(), &first);
    // Existing pending status never gives the destination either provider key.
    let deliver = |id: &str| {
        let projection = retained
            .document()
            .routing()
            .project_mesh_for(&NodeId::new(id).unwrap())
            .unwrap();
        GatewayDelivery::decode(&retained.delivery(&projection).unwrap()).unwrap()
    };
    let id = &active.routing().egresses()[MAX_EGRESSES_PER_USER + 1].id;
    assert!(deliver("source-2").egress_keys().get(id).is_some());
    assert!(deliver("destination").egress_keys().get(id).is_none());

    // Removing one route creates the needed space. Once the second move is
    // pending, a later unrelated grant edit cannot consume its reserved bytes.
    let user = &first.routing().egress_policy().users[0];
    let edit_routes = |doc: &ManagementDocument, grants| {
        doc.apply_change(
            doc.routing().generation(),
            &ManagementChange::SetUserEgresses {
                user: user.user.clone(),
                egresses: grants,
            },
        )
        .unwrap()
    };
    let mut reduced_grants = user.egresses.clone();
    assert!(reduced_grants[0].routes.len() > 1);
    reduced_grants[0].routes.pop();
    let reduced = edit_routes(&first, reduced_grants);
    store
        .commit_with_secrets(&reduced, &key(), &credential(), &secrets, Some(2))
        .unwrap();
    let pending = move_to_target(&reduced, 1);
    store
        .commit_with_secrets(&pending, &key(), &credential(), &secrets, Some(3))
        .unwrap();
    let expanded = edit_routes(&pending, user.egresses.clone());
    assert!(matches!(
        store.commit_with_secrets(&expanded, &key(), &credential(), &secrets, Some(4)),
        Err(StoreError::InvalidConfig(DomainError::LimitExceeded))
    ));
    assert_eq!(store.load().unwrap().unwrap().document(), &pending);
    for (revision, source) in [(4, "source-2"), (5, "source-1")] {
        let source = NodeId::new(source).unwrap();
        let assignment = active
            .routing()
            .assignments()
            .iter()
            .find(|a| a.recipient() == &source)
            .unwrap();
        store
            .acknowledge_release(&source, assignment.service_public_key(), revision)
            .unwrap();
    }
    let final_state = store.load().unwrap().unwrap();
    let target_projection = final_state
        .document()
        .routing()
        .project_mesh_for(&target)
        .unwrap();
    let delivered =
        GatewayDelivery::decode(&final_state.delivery(&target_projection).unwrap()).unwrap();
    assert!(
        active
            .routing()
            .egresses()
            .iter()
            .all(|profile| delivered.egress_keys().get(&profile.id).is_some())
    );
}

/// The published descriptor for the first profile shrinks by one byte when its
/// owner changes from null to "x". A second provider is moving to destination.
fn opposing_descriptor_sizes(
    extra: usize,
    mut padding: usize,
) -> (ManagementDocument, ManagementSecrets) {
    use wgfeel_core::{MAX_EGRESSES_PER_USER, ManagementChange, TenantKeyAssignment};
    use wgfeel_test_support::{fixture_gateway_public, fixture_public};
    let (base, secrets) = routes_near_move_limit(extra, false);
    let routing = base.routing();
    let mut nodes = routing.assignments().to_vec();
    let scope = nodes[0].networks().to_vec();
    let tenants = scope
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let mut key = [211; 32];
            key[..2].copy_from_slice(&(i as u16).to_be_bytes());
            TenantKeyAssignment::new(n.clone(), DevicePublicKey::new(key).unwrap())
        })
        .collect();
    let short = NodeId::new("x").unwrap();
    let public = fixture_public(&[177; 32]);
    nodes.push(
        GatewayAssignment::new(
            short.clone(),
            public.clone(),
            fixture_gateway_public(&public),
            scope,
            tenants,
        )
        .unwrap()
        .with_endpoint(Some("192.0.2.4:10000".parse().unwrap()))
        .unwrap(),
    );
    let mut policy = routing.egress_policy().clone();
    for profile in &mut policy.profiles[2..4] {
        let n = padding.min(127);
        padding -= n;
        let mut fields = (**profile).clone();
        fields.name = "n".repeat(1 + n);
        *profile = fields.try_into().unwrap();
    }
    assert_eq!(padding, 0);
    let long = nodes[0].recipient().clone();
    let mut doc = ManagementDocument::new(
        ManagementConfig::new(
            routing.management_id().clone(),
            routing.config().clone(),
            nodes,
        )
        .unwrap()
        .with_egress_policy(policy)
        .unwrap(),
        base.clients().to_vec(),
    )
    .unwrap();
    for (index, destination) in [(0, short), (MAX_EGRESSES_PER_USER, long)] {
        doc = doc
            .apply_change(
                doc.routing().generation(),
                &ManagementChange::SetEgressNode {
                    egress: doc.routing().egresses()[index].id.clone(),
                    node: Some(destination),
                },
            )
            .unwrap();
    }
    (doc, secrets)
}

#[test]
fn an_intermediate_ack_order_cannot_overflow_an_exactly_full_final_projection() {
    use wgfeel_core::{DomainError, MAX_PROJECTION_BYTES, ManagementChange};
    let release = |doc: &ManagementDocument, former: &str| {
        let id = NodeId::new(former).unwrap();
        let node = doc
            .routing()
            .assignments()
            .iter()
            .find(|n| n.recipient() == &id)
            .unwrap();
        doc.apply_change(
            doc.routing().generation(),
            &ManagementChange::ReleaseEgressKeys {
                former: id,
                service_key: node.service_public_key().clone(),
            },
        )
        .unwrap()
    };
    let destination = NodeId::new("destination").unwrap();
    let size = |doc: &ManagementDocument| {
        doc.routing()
            .project_mesh_for(&destination)
            .unwrap()
            .to_json()
            .map(|encoded| encoded.len())
    };
    let final_size = |extra| {
        let (pending, _) = opposing_descriptor_sizes(extra, 0);
        size(&release(&release(&pending, "source-1"), "destination")).unwrap()
    };
    let base = final_size(0);
    let row = final_size(1) - base;
    let remaining = MAX_PROJECTION_BYTES - base;
    let (pending, secrets) = opposing_descriptor_sizes(remaining / row, remaining % row);
    let intermediate = release(&pending, "source-1");
    let final_doc = release(&intermediate, "destination");
    assert!(size(&pending).is_ok());
    assert_eq!(size(&final_doc), Ok(MAX_PROJECTION_BYTES));
    assert_eq!(size(&intermediate), Err(DomainError::LimitExceeded));
    assert!(matches!(
        check_pending_deliveries(&pending, &[], Some(&secrets)),
        Err(StoreError::InvalidConfig(DomainError::LimitExceeded))
    ));
}
