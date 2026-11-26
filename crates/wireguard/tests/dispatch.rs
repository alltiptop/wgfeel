use wgfeel_core::{DeviceId, NetworkId, NodeId};
use wgfeel_wireguard::dispatch::{
    DispatchContext, DispatchError, IndexBinding, MAX_INDICES_PER_PEER, MAX_RECEIVER_INDICES,
    Registry, RouteHint,
};
use wgfeel_wireguard::{ContextId, MAX_DATAGRAM_SIZE, PeerId};

fn tenant(name: &str) -> ContextId {
    ContextId::Tenant(NetworkId::new(name).unwrap())
}

fn device(name: &str) -> PeerId {
    PeerId::Device(DeviceId::new(name).unwrap())
}

fn node(name: &str) -> PeerId {
    PeerId::Node(NodeId::new(name).unwrap())
}

fn config(context: ContextId, peers: Vec<PeerId>) -> DispatchContext {
    DispatchContext { context, peers }
}

fn binding(index: u32, peer: PeerId) -> IndexBinding {
    IndexBinding { index, peer }
}

fn small_registry() -> Registry {
    Registry::new(vec![
        config(tenant("alice"), vec![device("same"), device("second")]),
        config(tenant("bob"), vec![device("same")]),
        config(ContextId::Service, vec![node("same")]),
    ])
    .unwrap()
}

// Public fields are authored directly from the protocol, not from a production
// encoder. Payload/MAC bytes remain zero to prove a route is only a hint.
fn packet(kind: u8, index: u32, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    if length >= 4 {
        bytes[0] = kind;
    }
    let offset = if kind == 2 { 8 } else { 4 };
    if length >= offset + 4 {
        bytes[offset..offset + 4].copy_from_slice(&index.to_le_bytes());
    }
    if kind == 2 && length >= 8 {
        bytes[4..8].copy_from_slice(&0xfedc_ba98_u32.to_le_bytes());
    }
    bytes
}

fn expect_route(
    registry: &Registry,
    index: u32,
    context: ContextId,
    peer: PeerId,
    generation: u64,
) {
    assert_eq!(
        registry.route(&packet(4, index, 32)).unwrap(),
        RouteHint::Receiver {
            context,
            peer,
            generation,
        },
    );
}

fn expect_unknown(registry: &Registry, index: u32) {
    assert_eq!(
        registry.route(&packet(4, index, 32)).unwrap_err(),
        DispatchError::UnknownIndex,
    );
}

#[test]
fn empty_registry_and_peerless_contexts_are_valid() {
    let empty = Registry::new(vec![]).unwrap();
    assert_eq!(
        empty.route(&packet(1, 0, 148)).unwrap(),
        RouteHint::NeedsHandshakeAdmission,
    );
    expect_unknown(&empty, 0);

    let mut registry = Registry::new(vec![config(tenant("alice"), vec![])]).unwrap();
    let lease = registry.restart(&tenant("alice")).unwrap();
    assert_eq!(lease.context(), &tenant("alice"));
    assert_eq!(lease.generation(), 1);
    registry.replace(&lease, vec![]).unwrap();
    assert_eq!(
        registry
            .replace(&lease, vec![binding(1, device("unconfigured"))])
            .unwrap_err(),
        DispatchError::UnknownPeer,
    );
    assert_eq!(
        registry.restart(&tenant("unknown")).unwrap_err(),
        DispatchError::UnknownContext,
    );
}

#[test]
fn duplicate_contexts_peers_and_wrong_identity_kinds_are_rejected() {
    for duplicate in [tenant("alice"), ContextId::Service] {
        assert_eq!(
            Registry::new(vec![
                config(duplicate.clone(), vec![]),
                config(duplicate, vec![]),
            ])
            .unwrap_err(),
            DispatchError::DuplicateContext,
        );
    }
    for (context, peer) in [
        (tenant("alice"), device("same")),
        (ContextId::Service, node("same")),
    ] {
        assert_eq!(
            Registry::new(vec![config(context, vec![peer.clone(), peer])]).unwrap_err(),
            DispatchError::DuplicatePeer,
        );
    }
    for wrong in [
        config(tenant("alice"), vec![node("wrong")]),
        config(ContextId::Service, vec![device("wrong")]),
    ] {
        assert_eq!(
            Registry::new(vec![wrong]).unwrap_err(),
            DispatchError::InvalidConfiguration
        );
    }
}

#[test]
fn configured_context_and_peer_counts_are_bounded_separately() {
    let too_many_tenants = (0..151)
        .map(|number| config(tenant(&format!("tenant-{number}")), vec![]))
        .collect();
    assert_eq!(
        Registry::new(too_many_tenants).unwrap_err(),
        DispatchError::LimitExceeded
    );
    let too_many_devices = (0..751)
        .map(|number| device(&format!("device-{number}")))
        .collect();
    assert_eq!(
        Registry::new(vec![config(tenant("alice"), too_many_devices)]).unwrap_err(),
        DispatchError::LimitExceeded,
    );
    let too_many_nodes = (0..183)
        .map(|number| node(&format!("node-{number}")))
        .collect();
    assert_eq!(
        Registry::new(vec![config(ContextId::Service, too_many_nodes)]).unwrap_err(),
        DispatchError::LimitExceeded,
    );
}

#[test]
fn handwritten_headers_select_exact_receiver_offsets_and_full_width_indices() {
    let mut registry = small_registry();
    let lease = registry.restart(&tenant("alice")).unwrap();
    registry
        .replace(
            &lease,
            vec![
                binding(0, device("same")),
                binding(0x0102_0304, device("second")),
                binding(u32::MAX, device("same")),
            ],
        )
        .unwrap();

    for (index, peer) in [
        (0, device("same")),
        (0x0102_0304, device("second")),
        (u32::MAX, device("same")),
    ] {
        for (kind, length) in [(2, 92), (3, 64), (4, 32), (4, MAX_DATAGRAM_SIZE)] {
            assert_eq!(
                registry.route(&packet(kind, index, length)).unwrap(),
                RouteHint::Receiver {
                    context: tenant("alice"),
                    peer: peer.clone(),
                    generation: 1
                },
            );
        }
    }
    let mut counter_is_not_index = packet(4, 0x0102_0304, 48);
    counter_is_not_index[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        registry.route(&counter_is_not_index).unwrap(),
        RouteHint::Receiver {
            context: tenant("alice"),
            peer: device("second"),
            generation: 1,
        }
    );
    assert_eq!(
        registry.route(&packet(1, u32::MAX, 148)).unwrap(),
        RouteHint::NeedsHandshakeAdmission
    );
    expect_unknown(&registry, 0xfedc_ba98);
}

#[test]
fn malformed_public_headers_are_rejected_before_routing() {
    let mut registry = small_registry();
    let lease = registry.restart(&tenant("alice")).unwrap();
    registry
        .replace(&lease, vec![binding(7, device("same"))])
        .unwrap();
    let mut malformed = vec![
        vec![],
        vec![1],
        vec![1, 0, 0],
        packet(0, 7, 148),
        packet(5, 7, 148),
    ];
    for (kind, length) in [(1, 148), (2, 92), (3, 64), (4, 32)] {
        for reserved in 1..4 {
            let mut bytes = packet(kind, 7, length);
            bytes[reserved] = 1;
            malformed.push(bytes);
        }
    }
    for (kind, length) in [
        (1, 147),
        (1, 149),
        (2, 91),
        (2, 93),
        (3, 63),
        (3, 65),
        (4, 31),
    ] {
        malformed.push(packet(kind, 7, length));
    }
    for bytes in malformed {
        assert_eq!(
            registry.route(&bytes).unwrap_err(),
            DispatchError::InvalidPacket
        );
    }
    assert_eq!(
        registry
            .route(&packet(4, 7, MAX_DATAGRAM_SIZE + 1))
            .unwrap_err(),
        DispatchError::PacketTooLarge,
    );
    for (kind, length) in [(2, 92), (3, 64), (4, 32)] {
        assert_eq!(
            registry.route(&packet(kind, 8, length)).unwrap_err(),
            DispatchError::UnknownIndex
        );
    }
    expect_route(&registry, 7, tenant("alice"), device("same"), 1);
}

#[test]
fn complete_replacement_changes_only_its_context_and_preserves_scoped_identities() {
    let mut registry = small_registry();
    let alice = registry.restart(&tenant("alice")).unwrap();
    let bob = registry.restart(&tenant("bob")).unwrap();
    let system = registry.restart(&ContextId::Service).unwrap();
    registry
        .replace(
            &alice,
            vec![binding(10, device("same")), binding(11, device("second"))],
        )
        .unwrap();
    registry
        .replace(&bob, vec![binding(20, device("same"))])
        .unwrap();
    registry
        .replace(&system, vec![binding(30, node("same"))])
        .unwrap();
    registry
        .replace(
            &alice,
            vec![binding(10, device("second")), binding(12, device("same"))],
        )
        .unwrap();
    expect_route(&registry, 10, tenant("alice"), device("second"), 1);
    expect_unknown(&registry, 11);
    expect_route(&registry, 12, tenant("alice"), device("same"), 1);
    expect_route(&registry, 20, tenant("bob"), device("same"), 1);
    expect_route(&registry, 30, ContextId::Service, node("same"), 1);
    registry.replace(&alice, vec![]).unwrap();
    expect_unknown(&registry, 10);
    expect_unknown(&registry, 12);
    registry
        .replace(&alice, vec![binding(13, device("same"))])
        .unwrap();
    expect_route(&registry, 13, tenant("alice"), device("same"), 1);
}

#[test]
fn invalid_snapshots_leave_every_previous_mapping_unchanged() {
    let mut registry = small_registry();
    let alice = registry.restart(&tenant("alice")).unwrap();
    let bob = registry.restart(&tenant("bob")).unwrap();
    registry
        .replace(&alice, vec![binding(10, device("same"))])
        .unwrap();
    registry
        .replace(&bob, vec![binding(20, device("same"))])
        .unwrap();
    let too_many_for_peer = (100..117)
        .map(|index| binding(index, device("same")))
        .collect();
    let cases = [
        (
            vec![binding(11, device("same")), binding(11, device("second"))],
            DispatchError::DuplicateIndex,
        ),
        (
            vec![binding(11, device("unknown"))],
            DispatchError::UnknownPeer,
        ),
        (vec![binding(11, node("same"))], DispatchError::UnknownPeer),
        (
            vec![binding(11, device("second")), binding(20, device("same"))],
            DispatchError::IndexCollision,
        ),
        (too_many_for_peer, DispatchError::LimitExceeded),
    ];
    for (snapshot, expected) in cases {
        assert_eq!(registry.replace(&alice, snapshot).unwrap_err(), expected);
        expect_route(&registry, 10, tenant("alice"), device("same"), 1);
        expect_route(&registry, 20, tenant("bob"), device("same"), 1);
        expect_unknown(&registry, 11);
        expect_unknown(&registry, 100);
    }
}

#[test]
fn foreign_registry_leases_fail_even_with_equal_context_and_generation() {
    let mut first = small_registry();
    let mut second = small_registry();
    let first_lease = first.restart(&tenant("alice")).unwrap();
    let second_lease = second.restart(&tenant("alice")).unwrap();
    assert_eq!(first_lease.context(), second_lease.context());
    assert_eq!(first_lease.generation(), second_lease.generation());
    second
        .replace(&second_lease, vec![binding(8, device("same"))])
        .unwrap();
    assert_eq!(
        second
            .replace(&first_lease, vec![binding(9, device("second"))])
            .unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        second.retire(&first_lease, 8).unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        second.release(&first_lease).unwrap_err(),
        DispatchError::InvalidLease
    );
    expect_route(&second, 8, tenant("alice"), device("same"), 1);
    expect_unknown(&second, 9);
}

#[test]
fn restarting_revokes_old_lease_before_indices_are_reused() {
    let mut registry = small_registry();
    let old = registry.restart(&tenant("alice")).unwrap();
    let bob = registry.restart(&tenant("bob")).unwrap();
    registry
        .replace(&old, vec![binding(8, device("same"))])
        .unwrap();
    registry
        .replace(&bob, vec![binding(9, device("same"))])
        .unwrap();
    let fresh = registry.restart(&tenant("alice")).unwrap();
    assert_eq!(fresh.generation(), 2);
    expect_unknown(&registry, 8);
    expect_route(&registry, 9, tenant("bob"), device("same"), 1);
    registry
        .replace(&fresh, vec![binding(8, device("second"))])
        .unwrap();
    assert_eq!(
        registry
            .replace(&old, vec![binding(10, device("same"))])
            .unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        registry.retire(&old, 8).unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        registry.retire(&old, 12345).unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        registry.release(&old).unwrap_err(),
        DispatchError::InvalidLease
    );
    expect_route(&registry, 8, tenant("alice"), device("second"), 2);
    expect_unknown(&registry, 10);
}

#[test]
fn retirement_release_and_cross_context_reuse_preserve_current_ownership() {
    let mut registry = small_registry();
    let alice = registry.restart(&tenant("alice")).unwrap();
    let bob = registry.restart(&tenant("bob")).unwrap();
    registry
        .replace(
            &alice,
            vec![binding(8, device("same")), binding(9, device("second"))],
        )
        .unwrap();
    registry
        .replace(&bob, vec![binding(20, device("same"))])
        .unwrap();
    assert_eq!(
        registry.retire(&alice, 20).unwrap_err(),
        DispatchError::IndexOwnership
    );
    assert_eq!(
        registry.retire(&alice, 999).unwrap_err(),
        DispatchError::UnknownIndex
    );
    registry.retire(&alice, 8).unwrap();
    expect_unknown(&registry, 8);
    expect_route(&registry, 9, tenant("alice"), device("second"), 1);
    registry
        .replace(
            &bob,
            vec![binding(8, device("same")), binding(20, device("same"))],
        )
        .unwrap();
    assert_eq!(
        registry.retire(&alice, 8).unwrap_err(),
        DispatchError::IndexOwnership
    );
    registry.release(&alice).unwrap();
    expect_unknown(&registry, 9);
    assert_eq!(
        registry.replace(&alice, vec![]).unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        registry.retire(&alice, 8).unwrap_err(),
        DispatchError::InvalidLease
    );
    assert_eq!(
        registry.release(&alice).unwrap_err(),
        DispatchError::InvalidLease
    );
    expect_route(&registry, 8, tenant("bob"), device("same"), 1);
    expect_route(&registry, 20, tenant("bob"), device("same"), 1);
    let fresh = registry.restart(&tenant("alice")).unwrap();
    assert_eq!(fresh.generation(), 2);
    registry
        .replace(&fresh, vec![binding(9, device("same"))])
        .unwrap();
    expect_route(&registry, 9, tenant("alice"), device("same"), 2);
}

#[test]
fn exact_configured_capacity_and_snapshot_replacement_fit_fixed_bounds() {
    assert_eq!(MAX_INDICES_PER_PEER, 16);
    // Main needs 149 other nodes, one administrator and 32 invitation peers.
    // Gateway has 150 peers; tenant mesh retains 150 peers per tenant.
    assert_eq!(MAX_RECEIVER_INDICES, (750 + 182 + 150 + 150 * 150) * 16);
    let mut configs: Vec<_> = (0..150)
        .map(|network| {
            config(
                tenant(&format!("tenant-{network}")),
                (0..5)
                    .map(|peer| device(&format!("device-{peer}")))
                    .collect(),
            )
        })
        .collect();
    configs.push(config(
        ContextId::Service,
        (0..182).map(|peer| node(&format!("node-{peer}"))).collect(),
    ));
    let mut registry = Registry::new(configs).unwrap();
    let mut next_index = 0_u32;
    for network in 0..150 {
        let context = tenant(&format!("tenant-{network}"));
        let lease = registry.restart(&context).unwrap();
        let mut indices = Vec::new();
        for peer in 0..5 {
            for _ in 0..16 {
                indices.push(binding(next_index, device(&format!("device-{peer}"))));
                next_index += 1;
            }
        }
        registry.replace(&lease, indices).unwrap();
    }
    let system = registry.restart(&ContextId::Service).unwrap();
    let mut service_indices = Vec::new();
    for peer in 0..182 {
        for _ in 0..16 {
            service_indices.push(binding(next_index, node(&format!("node-{peer}"))));
            next_index += 1;
        }
    }
    registry.replace(&system, service_indices).unwrap();
    assert_eq!(next_index, 14_912);
    expect_route(&registry, 0, tenant("tenant-0"), device("device-0"), 1);
    expect_route(
        &registry,
        11_999,
        tenant("tenant-149"),
        device("device-4"),
        1,
    );
    expect_route(&registry, 14_911, ContextId::Service, node("node-181"), 1);

    // Full snapshots replace existing entries; capacity must not double-count
    // both the old and new versions of this context.
    let mut replacements = Vec::new();
    for peer in 0..182 {
        for slot in 0..16 {
            replacements.push(binding(
                20_000 + peer * 16 + slot,
                node(&format!("node-{peer}")),
            ));
        }
    }
    registry.replace(&system, replacements).unwrap();
    expect_unknown(&registry, 14_911);
    expect_route(&registry, 22_911, ContextId::Service, node("node-181"), 1);
    expect_route(&registry, 0, tenant("tenant-0"), device("device-0"), 1);
}

#[test]
fn errors_do_not_embed_packet_contents_and_support_standard_error_reporting() {
    let registry = Registry::new(vec![]).unwrap();
    let bytes = b"PRIVATE_PACKET_SENTINEL";
    let error = registry.route(bytes).unwrap_err();
    let description = format!("{error:?} {error}");
    assert!(!description.contains("PRIVATE_PACKET_SENTINEL"));
    let error: &dyn std::error::Error = &error;
    assert!(!error.to_string().is_empty());
    assert!(error.source().is_none());
}
