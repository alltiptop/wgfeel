use wgfeel_core::{
    Action, Client, ClientDevice, ClientId, Config, Device, DeviceId, DeviceMetadata,
    DevicePublicKey, DomainError, Endpoint, GatewayAssignment, GatewayProjection, Grant,
    MAX_CLIENT_DEVICES, MAX_GATEWAYS, MAX_NETWORKS, ManagementChange, ManagementChangeError,
    ManagementConfig, ManagementDocument, Network, NetworkId, NodeId, Policy, Rule,
    TenantKeyAssignment,
};

fn client(id: &str) -> ClientId {
    ClientId::new(id).unwrap()
}
fn network(id: &str) -> NetworkId {
    NetworkId::new(id).unwrap()
}
fn device_id(id: &str) -> DeviceId {
    DeviceId::new(id).unwrap()
}
fn node(id: &str) -> NodeId {
    NodeId::new(id).unwrap()
}
fn key(value: usize) -> DevicePublicKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&(value as u64).to_le_bytes());
    DevicePublicKey::new(bytes).unwrap()
}
fn metadata(name: &str) -> DeviceMetadata {
    DeviceMetadata::new(Some(name.into()), Some(format!("description {name}"))).unwrap()
}
fn catalog(id: &str, name: &str) -> ClientDevice {
    ClientDevice::new(device_id(id), metadata(name))
}
fn registration(id: &str, public: usize, address: &str) -> Device {
    Device::new(device_id(id), key(public), vec![address.parse().unwrap()]).unwrap()
}
fn net(id: &str, devices: Vec<Device>) -> Network {
    Network::new(network(id), devices).unwrap()
}
fn alpha() -> Network {
    net(
        "alpha",
        vec![
            registration("shared", 11, "10.1.0.1"),
            registration("keep", 12, "10.1.0.2"),
        ],
    )
}
fn alpha_two() -> Network {
    net(
        "alpha-two",
        vec![registration("shared-alpha-two", 21, "10.2.0.1")],
    )
}
fn beta() -> Network {
    net(
        "beta",
        vec![
            registration("shared-beta", 31, "10.3.0.1"),
            registration("peer", 32, "10.3.0.2"),
        ],
    )
}
fn gamma() -> Network {
    net("gamma", vec![registration("guest", 41, "10.4.0.1")])
}
fn endpoint(net: &str, id: &str) -> Endpoint {
    Endpoint::new(network(net), device_id(id))
}
fn rule(src_net: &str, src: &str, dst_net: &str, dst: &str, action: Action) -> Rule {
    Rule::new(endpoint(src_net, src), endpoint(dst_net, dst), action)
}
fn grant(src_net: &str, src: &str, dst_net: &str, dst: &str) -> Grant {
    Grant::new(endpoint(src_net, src), endpoint(dst_net, dst))
}
fn unrelated_global_rules() -> Vec<Rule> {
    vec![
        rule("beta", "shared-beta", "beta", "peer", Action::Deny),
        rule("gamma", "guest", "beta", "shared-beta", Action::Deny),
    ]
}
fn unrelated_local_rules() -> Vec<Rule> {
    vec![
        rule("beta", "shared-beta", "beta", "peer", Action::Allow),
        rule("beta", "peer", "beta", "shared-beta", Action::Allow),
    ]
}
fn unrelated_grants() -> Vec<Grant> {
    vec![
        grant("beta", "peer", "gamma", "guest"),
        grant("gamma", "guest", "beta", "shared-beta"),
    ]
}
fn policy() -> Policy {
    let mut global = vec![
        rule("alpha", "shared", "beta", "shared-beta", Action::Deny),
        rule(
            "beta",
            "shared-beta",
            "alpha-two",
            "shared-alpha-two",
            Action::Allow,
        ),
    ];
    global.extend(unrelated_global_rules());
    let mut local = vec![
        rule("alpha", "shared", "alpha", "keep", Action::Allow),
        rule("alpha", "keep", "alpha", "shared", Action::Deny),
        rule("alpha", "keep", "alpha", "keep", Action::Allow),
    ];
    local.extend(unrelated_local_rules());
    let mut grants = vec![
        grant("alpha", "shared", "beta", "shared-beta"),
        grant("beta", "shared-beta", "alpha-two", "shared-alpha-two"),
        grant("alpha-two", "shared-alpha-two", "gamma", "guest"),
        grant("alpha", "keep", "gamma", "guest"),
    ];
    grants.extend(unrelated_grants());
    Policy::new(global, local, grants)
}
fn assignment(
    id: &str,
    system: usize,
    scope: &[&str],
    tenants: &[(&str, usize)],
) -> GatewayAssignment {
    GatewayAssignment::new(
        node(id),
        (key(system)).clone(),
        fixture_gateway_public(&(key(system))),
        scope.iter().map(|id| network(id)).collect(),
        tenants
            .iter()
            .map(|(id, public)| TenantKeyAssignment::new(network(id), key(*public)))
            .collect(),
    )
    .unwrap()
}
fn assignments() -> Vec<GatewayAssignment> {
    vec![
        assignment(
            "gateway-one",
            101,
            &["alpha", "alpha-two", "beta"],
            &[("alpha", 102), ("alpha-two", 103), ("beta", 104)],
        ),
        assignment(
            "gateway-two",
            111,
            &["alpha", "gamma"],
            &[("alpha", 112), ("gamma", 113)],
        ),
        assignment("gateway-three", 121, &["alpha-two"], &[("alpha-two", 122)]),
    ]
}
fn owner(id: &str, networks: &[&str], devices: Vec<ClientDevice>) -> Client {
    Client::new(
        client(id),
        networks.iter().map(|id| network(id)).collect(),
        devices,
    )
    .unwrap()
}
fn clients() -> Vec<Client> {
    vec![
        owner(
            "alice",
            &["alpha"],
            vec![
                catalog("shared", "Alice laptop"),
                catalog("keep", "Alice retained"),
                catalog("spare", "Alice unassigned"),
            ],
        ),
        owner(
            "bob",
            &["beta"],
            vec![
                catalog("shared-beta", "Bob laptop"),
                catalog("peer", "Bob peer"),
            ],
        ),
        owner("carol", &["gamma"], vec![catalog("guest", "Carol guest")]),
        owner(
            "alice-work",
            &["alpha-two"],
            vec![catalog("shared-alpha-two", "Alice work laptop")],
        ),
    ]
}
fn build(
    generation: u64,
    networks: Vec<Network>,
    policy: Policy,
    assignments: Vec<GatewayAssignment>,
    clients: Vec<Client>,
) -> ManagementDocument {
    ManagementDocument::new(
        ManagementConfig::new(
            node("management"),
            Config::new(generation, networks, policy).unwrap(),
            assignments,
        )
        .unwrap(),
        clients,
    )
    .unwrap()
}
fn fixture(generation: u64) -> ManagementDocument {
    build(
        generation,
        vec![alpha(), alpha_two(), beta(), gamma()],
        policy(),
        assignments(),
        clients(),
    )
}
fn empty_policy() -> Policy {
    Policy::new(vec![], vec![], vec![])
}
fn assert_roundtrips(document: &ManagementDocument) {
    assert_eq!(
        ManagementDocument::from_json(&document.to_json().unwrap()).unwrap(),
        *document
    );
    for assignment in document.routing().assignments() {
        let projection = document.project_for(assignment.recipient()).unwrap();
        assert_eq!(projection.generation(), document.routing().generation());
        assert_eq!(projection.assignment(), assignment);
        assert_eq!(
            GatewayProjection::from_json(&projection.to_json().unwrap()).unwrap(),
            projection
        );
    }
}
fn apply(
    source: &ManagementDocument,
    change: ManagementChange,
    expected: &ManagementDocument,
) -> ManagementDocument {
    let before = source.clone();
    let result = source
        .apply_change(source.routing().generation(), &change)
        .unwrap();
    assert_eq!(result, *expected);
    assert_eq!(*source, before);
    assert_roundtrips(&result);
    result
}
fn reject(source: &ManagementDocument, change: ManagementChange, expected: ManagementChangeError) {
    let before = source.clone();
    assert_eq!(
        source.apply_change(source.routing().generation(), &change),
        Err(expected)
    );
    assert_eq!(*source, before);
    assert_roundtrips(source);
}

#[test]
fn every_change_requires_exact_revision_and_cannot_wrap_generation() {
    let source = fixture(42);
    let changes = [
        ManagementChange::AddClient {
            client: client("dave"),
            name: "dave".into(),
            network: network("delta"),
        },
        ManagementChange::RemoveClient {
            client: client("alice"),
        },
        ManagementChange::AddDevice {
            client: client("alice"),
            network: network("alpha"),
            device: registration("fresh", 51, "10.1.0.3"),
            metadata: metadata("fresh"),
        },
        ManagementChange::RemoveDevice {
            client: client("alice"),
            device: device_id("shared"),
        },
        ManagementChange::AddGateway {
            assignment: assignment("gateway-new", 201, &["beta"], &[("beta", 202)]),
        },
        ManagementChange::RemoveGateway {
            gateway: node("gateway-one"),
        },
    ];
    for change in &changes {
        for revision in [0, 41, 43, u64::MAX] {
            assert_eq!(
                source.apply_change(revision, change),
                Err(ManagementChangeError::RevisionConflict)
            );
            assert_eq!(source, fixture(42));
        }
        let exhausted = fixture(u64::MAX);
        assert_eq!(
            exhausted.apply_change(u64::MAX, change),
            Err(ManagementChangeError::GenerationExhausted)
        );
        assert_eq!(exhausted, fixture(u64::MAX));
    }
    let last = fixture(u64::MAX - 1);
    let expected = build(
        u64::MAX,
        vec![alpha(), alpha_two(), beta(), gamma()],
        policy(),
        assignments().into_iter().skip(1).collect(),
        clients(),
    );
    apply(
        &last,
        ManagementChange::RemoveGateway {
            gateway: node("gateway-one"),
        },
        &expected,
    );
}

#[test]
fn add_client_creates_only_an_empty_owned_network_without_grants_or_gateway_scope() {
    let source = fixture(42);
    let mut expected_clients = clients();
    expected_clients.push(owner("dave", &["delta"], vec![]));
    let expected = build(
        43,
        vec![alpha(), alpha_two(), beta(), gamma(), net("delta", vec![])],
        policy(),
        assignments(),
        expected_clients,
    );
    let changed = apply(
        &source,
        ManagementChange::AddClient {
            client: client("dave"),
            name: "dave".into(),
            network: network("delta"),
        },
        &expected,
    );
    for gateway in changed.routing().assignments() {
        assert!(!gateway.networks().contains(&network("delta")));
        assert!(
            !changed
                .project_for(gateway.recipient())
                .unwrap()
                .config()
                .networks()
                .iter()
                .any(|entry| entry.id() == &network("delta"))
        );
    }
    reject(
        &source,
        ManagementChange::AddClient {
            client: client("alice"),
            name: "alice".into(),
            network: network("delta"),
        },
        ManagementChangeError::DuplicateClient,
    );
    reject(
        &source,
        ManagementChange::AddClient {
            client: client("dave"),
            name: "dave".into(),
            network: network("alpha"),
        },
        ManagementChangeError::Invalid(DomainError::DuplicateNetworkId),
    );
}

#[test]
fn add_device_uses_exact_owner_and_preserves_another_clients_device() {
    let source = fixture(42);
    let added = registration("new-guest", 51, "10.1.0.3");
    let mut expected_clients = clients();
    expected_clients[0] = owner(
        "alice",
        &["alpha"],
        vec![
            catalog("shared", "Alice laptop"),
            catalog("keep", "Alice retained"),
            catalog("spare", "Alice unassigned"),
            catalog("new-guest", "New Alice device"),
        ],
    );
    let expected = build(
        43,
        vec![
            net(
                "alpha",
                vec![
                    registration("shared", 11, "10.1.0.1"),
                    registration("keep", 12, "10.1.0.2"),
                    added.clone(),
                ],
            ),
            alpha_two(),
            beta(),
            gamma(),
        ],
        policy(),
        assignments(),
        expected_clients,
    );
    let result = apply(
        &source,
        ManagementChange::AddDevice {
            client: client("alice"),
            network: network("alpha"),
            device: added,
            metadata: metadata("New Alice device"),
        },
        &expected,
    );
    assert_eq!(
        result
            .select_device(&client("carol"), &device_id("guest"), None)
            .unwrap()
            .device
            .metadata()
            .name(),
        Some("Carol guest")
    );
    assert_eq!(
        result.routing().config().decision(
            &endpoint("alpha", "new-guest"),
            &endpoint("beta", "shared-beta")
        ),
        Action::Deny
    );
}

#[test]
fn device_addition_rejects_unknown_owner_foreign_network_duplicates_and_key_or_address_collision() {
    let source = fixture(42);
    for (owner, net, id, public, address, error) in [
        (
            "missing",
            "alpha",
            "fresh",
            51,
            "10.1.0.3",
            ManagementChangeError::UnknownClient,
        ),
        (
            "alice",
            "beta",
            "fresh",
            51,
            "10.3.0.3",
            ManagementChangeError::NetworkNotOwned,
        ),
        (
            "alice",
            "missing",
            "fresh",
            51,
            "10.1.0.3",
            ManagementChangeError::NetworkNotOwned,
        ),
        (
            "alice",
            "alpha",
            "shared",
            51,
            "10.1.0.3",
            ManagementChangeError::DuplicateDevice,
        ),
        (
            "alice",
            "alpha",
            "spare",
            51,
            "10.1.0.3",
            ManagementChangeError::DuplicateDevice,
        ),
        (
            "alice",
            "alpha",
            "fresh",
            11,
            "10.1.0.3",
            ManagementChangeError::Invalid(DomainError::DuplicateDeviceKey),
        ),
        (
            "alice",
            "alpha",
            "fresh",
            51,
            "10.1.0.1",
            ManagementChangeError::Invalid(DomainError::DuplicateDeviceAddress),
        ),
        (
            "alice",
            "alpha",
            "fresh",
            101,
            "10.1.0.3",
            ManagementChangeError::Invalid(DomainError::DuplicateGatewayKey),
        ),
        (
            "alice",
            "alpha",
            "fresh",
            51,
            "10.3.0.1",
            ManagementChangeError::Invalid(DomainError::AmbiguousGrant),
        ),
    ] {
        reject(
            &source,
            ManagementChange::AddDevice {
                client: client(owner),
                network: network(net),
                device: registration(id, public, address),
                metadata: metadata("fresh"),
            },
            error,
        );
    }
}

#[test]
fn remove_device_revokes_all_owned_registrations_and_both_direction_references_only() {
    let source = fixture(42);
    let mut expected_clients = clients();
    expected_clients[0] = owner(
        "alice",
        &["alpha"],
        vec![
            catalog("keep", "Alice retained"),
            catalog("spare", "Alice unassigned"),
        ],
    );
    let mut global = vec![rule(
        "beta",
        "shared-beta",
        "alpha-two",
        "shared-alpha-two",
        Action::Allow,
    )];
    global.extend(unrelated_global_rules());
    let mut local = vec![rule("alpha", "keep", "alpha", "keep", Action::Allow)];
    local.extend(unrelated_local_rules());
    let mut grants = vec![
        grant("beta", "shared-beta", "alpha-two", "shared-alpha-two"),
        grant("alpha-two", "shared-alpha-two", "gamma", "guest"),
        grant("alpha", "keep", "gamma", "guest"),
    ];
    grants.extend(unrelated_grants());
    let expected = build(
        43,
        vec![
            net("alpha", vec![registration("keep", 12, "10.1.0.2")]),
            alpha_two(),
            beta(),
            gamma(),
        ],
        Policy::new(global, local, grants),
        assignments(),
        expected_clients,
    );
    let result = apply(
        &source,
        ManagementChange::RemoveDevice {
            client: client("alice"),
            device: device_id("shared"),
        },
        &expected,
    );
    assert_eq!(
        result
            .select_device(&client("bob"), &device_id("shared-beta"), None)
            .unwrap()
            .device
            .metadata()
            .name(),
        Some("Bob laptop")
    );
    assert_eq!(
        result
            .routing()
            .config()
            .decision(&endpoint("beta", "shared-beta"), &endpoint("beta", "peer")),
        Action::Deny
    );
    assert_eq!(
        result
            .routing()
            .config()
            .decision(&endpoint("beta", "peer"), &endpoint("gamma", "guest")),
        Action::Allow
    );
    let mut expected_clients = clients();
    expected_clients[0] = owner(
        "alice",
        &["alpha"],
        vec![
            catalog("shared", "Alice laptop"),
            catalog("keep", "Alice retained"),
        ],
    );
    let expected = build(
        43,
        vec![alpha(), alpha_two(), beta(), gamma()],
        policy(),
        assignments(),
        expected_clients,
    );
    apply(
        &source,
        ManagementChange::RemoveDevice {
            client: client("alice"),
            device: device_id("spare"),
        },
        &expected,
    );
}

#[test]
fn remove_client_revokes_its_networks_and_trims_every_assignment_without_removing_gateways() {
    let source = fixture(42);
    let mut global = vec![rule(
        "beta",
        "shared-beta",
        "alpha-two",
        "shared-alpha-two",
        Action::Allow,
    )];
    global.extend(unrelated_global_rules());
    let mut grants = vec![
        grant("beta", "shared-beta", "alpha-two", "shared-alpha-two"),
        grant("alpha-two", "shared-alpha-two", "gamma", "guest"),
    ];
    grants.extend(unrelated_grants());
    let expected = build(
        43,
        vec![alpha_two(), beta(), gamma()],
        Policy::new(global, unrelated_local_rules(), grants),
        vec![
            assignment(
                "gateway-one",
                101,
                &["alpha-two", "beta"],
                &[("alpha-two", 103), ("beta", 104)],
            ),
            assignment("gateway-two", 111, &["gamma"], &[("gamma", 113)]),
            assignment("gateway-three", 121, &["alpha-two"], &[("alpha-two", 122)]),
        ],
        clients().into_iter().skip(1).collect(),
    );
    let result = apply(
        &source,
        ManagementChange::RemoveClient {
            client: client("alice"),
        },
        &expected,
    );
    assert_eq!(
        result
            .project_for(&node("gateway-three"))
            .unwrap()
            .assignment()
            .networks(),
        &[network("alpha-two")]
    );
    assert_eq!(
        result
            .routing()
            .config()
            .decision(&endpoint("beta", "shared-beta"), &endpoint("beta", "peer")),
        Action::Deny
    );
    reject(
        &result,
        ManagementChange::RemoveClient {
            client: client("alice"),
        },
        ManagementChangeError::UnknownClient,
    );
}

#[test]
fn gateway_addition_validates_full_assignment_without_modifying_ownership_or_policy() {
    let source = fixture(42);
    let added = assignment("gateway-new", 201, &["beta"], &[("beta", 202)]);
    let mut expected_assignments = assignments();
    expected_assignments.push(added.clone());
    let expected = build(
        43,
        vec![alpha(), alpha_two(), beta(), gamma()],
        policy(),
        expected_assignments,
        clients(),
    );
    apply(
        &source,
        ManagementChange::AddGateway { assignment: added },
        &expected,
    );
    for (candidate, error) in [
        (
            assignment("gateway-one", 201, &[], &[]),
            DomainError::DuplicateGatewayId,
        ),
        (
            assignment("management", 201, &[], &[]),
            DomainError::InvalidManagementIdentity,
        ),
        (
            assignment("gateway-new", 101, &[], &[]),
            DomainError::DuplicateGatewayKey,
        ),
        (
            assignment("gateway-new", 11, &[], &[]),
            DomainError::DuplicateGatewayKey,
        ),
        (
            assignment("gateway-new", 201, &["beta"], &[("beta", 112)]),
            DomainError::DuplicateGatewayKey,
        ),
        (
            assignment("gateway-new", 201, &["missing"], &[]),
            DomainError::InvalidGatewayAssignment,
        ),
    ] {
        reject(
            &source,
            ManagementChange::AddGateway {
                assignment: candidate,
            },
            ManagementChangeError::Invalid(error),
        );
    }
}

#[test]
fn removals_require_exact_existing_identity_and_cannot_remove_management_authority() {
    let source = fixture(42);
    let expected = build(
        43,
        vec![alpha(), alpha_two(), beta(), gamma()],
        policy(),
        vec![assignments()[0].clone(), assignments()[2].clone()],
        clients(),
    );
    let result = apply(
        &source,
        ManagementChange::RemoveGateway {
            gateway: node("gateway-two"),
        },
        &expected,
    );
    assert_eq!(result.routing().management_id(), &node("management"));
    assert_eq!(
        result.project_for(&node("gateway-two")),
        Err(DomainError::UnknownGateway)
    );
    for (change, error) in [
        (
            ManagementChange::RemoveGateway {
                gateway: node("management"),
            },
            ManagementChangeError::ProtectedManagement,
        ),
        (
            ManagementChange::RemoveGateway {
                gateway: node("missing"),
            },
            ManagementChangeError::UnknownGateway,
        ),
        (
            ManagementChange::RemoveClient {
                client: client("missing"),
            },
            ManagementChangeError::UnknownClient,
        ),
        (
            ManagementChange::RemoveDevice {
                client: client("missing"),
                device: device_id("shared"),
            },
            ManagementChangeError::UnknownClient,
        ),
        (
            ManagementChange::RemoveDevice {
                client: client("alice"),
                device: device_id("guest"),
            },
            ManagementChangeError::UnknownDevice,
        ),
    ] {
        reject(&source, change, error);
    }
}

#[test]
fn change_validation_preserves_existing_client_network_catalog_and_gateway_bounds() {
    let names: Vec<_> = (0..MAX_NETWORKS)
        .map(|index| format!("network-{index}"))
        .collect();
    let source = build(
        1,
        names.iter().map(|id| net(id, vec![])).collect(),
        empty_policy(),
        vec![],
        names
            .iter()
            .map(|name| owner(name, &[name], vec![]))
            .collect(),
    );
    reject(
        &source,
        ManagementChange::AddClient {
            client: client("extra"),
            name: "extra".into(),
            network: network("extra"),
        },
        ManagementChangeError::Invalid(DomainError::LimitExceeded),
    );
    let source = build(
        1,
        vec![net("alpha", vec![])],
        empty_policy(),
        vec![],
        vec![owner(
            "alice",
            &["alpha"],
            (0..MAX_CLIENT_DEVICES)
                .map(|index| catalog(&format!("device-{index}"), "unassigned"))
                .collect(),
        )],
    );
    reject(
        &source,
        ManagementChange::AddDevice {
            client: client("alice"),
            network: network("alpha"),
            device: registration("extra", 51, "10.1.0.1"),
            metadata: metadata("extra"),
        },
        ManagementChangeError::Invalid(DomainError::LimitExceeded),
    );
    let source = build(
        1,
        vec![],
        empty_policy(),
        (0..MAX_GATEWAYS)
            .map(|index| assignment(&format!("gateway-{index}"), index + 1000, &[], &[]))
            .collect(),
        vec![],
    );
    reject(
        &source,
        ManagementChange::AddGateway {
            assignment: assignment("extra", 2000, &[], &[]),
        },
        ManagementChangeError::Invalid(DomainError::LimitExceeded),
    );
}

#[test]
fn user_names_and_device_ids_are_unique_across_the_authoritative_catalog() {
    let source = fixture(42);
    reject(
        &source,
        ManagementChange::AddClient {
            client: client("different-id"),
            network: network("new-context"),
            name: "alice".into(),
        },
        ManagementChangeError::DuplicateClient,
    );
    reject(
        &source,
        ManagementChange::AddDevice {
            client: client("alice"),
            network: network("alpha"),
            device: registration("shared-beta", 88, "10.1.0.88"),
            metadata: metadata("Another name"),
        },
        ManagementChangeError::DuplicateDevice,
    );
    let changed = source
        .apply_change(
            42,
            &ManagementChange::AddClient {
                client: client("generated-id"),
                network: network("generated-id"),
                name: "Display name".into(),
            },
        )
        .unwrap();
    let restored = ManagementDocument::from_json(&changed.to_json().unwrap()).unwrap();
    assert_eq!(restored.clients().last().unwrap().name(), "Display name");
}

#[test]
fn suspension_denies_grants_in_both_directions_and_survives_serialization() {
    let source = fixture(42);
    let a = endpoint("alpha-two", "shared-alpha-two");
    let b = endpoint("gamma", "guest");
    assert_eq!(source.routing().config().decision(&a, &b), Action::Allow);
    for owner in ["alice-work", "carol"] {
        let suspended = source
            .apply_change(
                42,
                &ManagementChange::SetClientSuspended {
                    client: client(owner),
                    suspended: true,
                },
            )
            .unwrap();
        let restored = ManagementDocument::from_json(&suspended.to_json().unwrap()).unwrap();
        assert_eq!(restored.routing().config().decision(&a, &b), Action::Deny);
        assert_eq!(restored.clients(), source.clients());
        let resumed = restored
            .apply_change(
                43,
                &ManagementChange::SetClientSuspended {
                    client: client(owner),
                    suspended: false,
                },
            )
            .unwrap();
        assert_eq!(resumed.routing().config().decision(&a, &b), Action::Allow);
    }
}

fn fixture_gateway_public(service: &wgfeel_core::DevicePublicKey) -> wgfeel_core::DevicePublicKey {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    wgfeel_core::DevicePublicKey::new(bytes).unwrap()
}
