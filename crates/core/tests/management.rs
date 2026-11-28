use wgfeel_core::{
    Action, Client, ClientDevice, ClientId, Config, Device, DeviceId, DeviceLookupError,
    DeviceMetadata, DevicePublicKey, DomainError, Endpoint, GatewayAssignment, Grant,
    MANAGEMENT_VERSION, MAX_CLIENT_DEVICES, MAX_CLIENTS, MAX_DEVICE_DESCRIPTION_BYTES,
    MAX_DEVICE_NAME_BYTES, MAX_MANAGEMENT_BYTES, ManagementConfig, ManagementDocument, Network,
    NetworkId, NodeId, Policy, Rule, TenantKeyAssignment,
};

fn client_id(value: &str) -> ClientId {
    ClientId::new(value).unwrap()
}
fn device_id(value: &str) -> DeviceId {
    DeviceId::new(value).unwrap()
}
fn network_id(value: &str) -> NetworkId {
    NetworkId::new(value).unwrap()
}
fn node_id(value: &str) -> NodeId {
    NodeId::new(value).unwrap()
}
fn key(value: u8) -> DevicePublicKey {
    DevicePublicKey::new([value; 32]).unwrap()
}
fn endpoint(network: &str, device: &str) -> Endpoint {
    Endpoint::new(network_id(network), device_id(device))
}
fn catalog_device(id: &str, name: Option<&str>) -> ClientDevice {
    ClientDevice::new(
        device_id(id),
        DeviceMetadata::new(name.map(str::to_owned), None).unwrap(),
    )
}
fn client(id: &str, networks: &[&str], devices: &[&str]) -> Client {
    Client::new(
        client_id(id),
        networks.iter().map(|id| network_id(id)).collect(),
        devices.iter().map(|id| catalog_device(id, None)).collect(),
    )
    .unwrap()
}
fn routing(generation: u64, laptop_key: u8) -> ManagementConfig {
    let config = Config::new(
        generation,
        vec![
            Network::new(network_id("empty"), vec![]).unwrap(),
            Network::new(
                network_id("alpha"),
                vec![
                    Device::new(
                        device_id("laptop"),
                        key(laptop_key),
                        vec!["10.1.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                    Device::new(
                        device_id("phone"),
                        key(12),
                        vec!["10.1.0.2".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
            Network::new(
                network_id("beta"),
                vec![
                    Device::new(
                        device_id("laptop-beta"),
                        key(21),
                        vec!["10.2.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
            Network::new(
                network_id("gamma"),
                vec![
                    Device::new(
                        device_id("laptop-gamma"),
                        key(31),
                        vec!["10.3.0.1".parse().unwrap()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ],
        Policy::new(
            vec![Rule::new(
                endpoint("alpha", "laptop"),
                endpoint("alpha", "phone"),
                Action::Deny,
            )],
            vec![Rule::new(
                endpoint("alpha", "laptop"),
                endpoint("alpha", "phone"),
                Action::Allow,
            )],
            vec![Grant::new(
                endpoint("alpha", "laptop"),
                endpoint("gamma", "laptop-gamma"),
            )],
        ),
    )
    .unwrap();
    ManagementConfig::new(
        node_id("management"),
        config,
        vec![
            GatewayAssignment::new(
                node_id("gateway"),
                (key(101)).clone(),
                fixture_gateway_public(&(key(101))),
                vec![network_id("alpha"), network_id("beta")],
                vec![
                    TenantKeyAssignment::new(network_id("alpha"), key(102)),
                    TenantKeyAssignment::new(network_id("beta"), key(103)),
                ],
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn clients(name: &str) -> Vec<Client> {
    vec![
        Client::new(
            client_id("alice"),
            vec![network_id("alpha")],
            vec![
                catalog_device("laptop", Some(name)),
                catalog_device("phone", None),
                catalog_device("spare", None),
            ],
        )
        .unwrap(),
        client("alice-work", &["beta"], &["laptop-beta"]),
        client("bob", &["gamma"], &["laptop-gamma"]),
        client("empty", &["empty"], &[]),
    ]
}
fn document() -> ManagementDocument {
    ManagementDocument::new(routing(7, 11), clients("Alice laptop")).unwrap()
}
fn routing_for_clients(count: usize) -> ManagementConfig {
    ManagementConfig::new(
        node_id("management"),
        Config::new(
            1,
            (0..count)
                .map(|i| Network::new(network_id(&format!("c{i}")), vec![]).unwrap())
                .collect(),
            Policy::new(vec![], vec![], vec![]),
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}

#[test]
fn client_identifiers_use_existing_opaque_ascii_syntax() {
    for value in ["a", "_", "-", "Alice_42-Z", &"x".repeat(64)] {
        assert_eq!(ClientId::new(value).unwrap().as_str(), value);
    }
    for value in ["", "a.b", "a b", "\u{e9}", "a/b", "a\n", &"x".repeat(65)] {
        assert_eq!(ClientId::new(value), Err(DomainError::InvalidIdentifier));
    }
    assert_ne!(client_id("Alice"), client_id("alice"));
}

#[test]
fn optional_metadata_preserves_unicode_and_spaces_with_utf8_byte_limits() {
    assert_eq!(MAX_DEVICE_NAME_BYTES, 128);
    assert_eq!(MAX_DEVICE_DESCRIPTION_BYTES, 1024);
    let absent = DeviceMetadata::new(None, None).unwrap();
    assert_eq!(absent.name(), None);
    assert_eq!(absent.description(), None);
    let name = "\u{e9}".repeat(64);
    let description = "🦀".repeat(256);
    let maximum = DeviceMetadata::new(Some(name.clone()), Some(description.clone())).unwrap();
    assert_eq!(maximum.name(), Some(name.as_str()));
    assert_eq!(maximum.description(), Some(description.as_str()));
    assert_eq!(
        DeviceMetadata::new(Some(format!("{name}x")), None),
        Err(DomainError::InvalidMetadata)
    );
    assert_eq!(
        DeviceMetadata::new(None, Some(format!("{description}x"))),
        Err(DomainError::InvalidMetadata)
    );
    let text = "  e\u{301} / name  ";
    let preserved = DeviceMetadata::new(Some(text.into()), Some(" ".into())).unwrap();
    assert_eq!(preserved.name(), Some(text));
    assert_eq!(preserved.description(), Some(" "));
    for invalid in ["", "\0", "a\n", "a\r", "\t", "\u{7f}", "\u{85}"] {
        assert_eq!(
            DeviceMetadata::new(Some(invalid.into()), None),
            Err(DomainError::InvalidMetadata)
        );
        assert_eq!(
            DeviceMetadata::new(None, Some(invalid.into())),
            Err(DomainError::InvalidMetadata)
        );
    }
}

#[test]
fn client_catalog_rejects_duplicate_membership_and_ids_but_allows_empty_registration() {
    let empty = client("empty", &["empty"], &[]);
    assert_eq!(empty.network(), &network_id("empty"));
    assert!(empty.devices().is_empty());
    for networks in [vec![], vec![network_id("alpha"), network_id("beta")]] {
        assert_eq!(
            Client::new(client_id("alice"), networks, vec![]),
            Err(DomainError::InvalidClientOwnership)
        );
    }
    assert_eq!(
        Client::new(
            client_id("alice"),
            vec![network_id("alpha"), network_id("alpha")],
            vec![]
        ),
        Err(DomainError::InvalidClientOwnership)
    );
    assert_eq!(
        Client::new(
            client_id("alice"),
            vec![network_id("alpha")],
            vec![
                catalog_device("laptop", Some("first")),
                catalog_device("laptop", Some("second"))
            ]
        ),
        Err(DomainError::DuplicateDeviceId)
    );
    let same_names = Client::new(
        client_id("alice"),
        vec![network_id("alpha")],
        vec![
            catalog_device("a", Some("same name")),
            catalog_device("b", Some("same name")),
        ],
    )
    .unwrap();
    assert_eq!(
        same_names.devices().len(),
        2,
        "display metadata is not identity"
    );
}

#[test]
fn every_network_has_exactly_one_owner_and_every_registration_belongs_to_its_catalog() {
    let valid = document();
    assert_eq!(valid.clients().len(), 4);
    for invalid in [
        vec![client("alice", &["alpha"], &["laptop", "phone"])],
        vec![
            client("alice", &["alpha"], &["laptop", "phone"]),
            client("bob", &["alpha"], &["laptop", "phone"]),
        ],
        vec![
            client("alice", &["foreign"], &["laptop", "phone"]),
            client("bob", &["gamma"], &["laptop-gamma"]),
        ],
        vec![
            client("alice", &["alpha"], &["laptop"]),
            client("bob", &["gamma"], &["laptop", "phone"]),
        ],
        vec![
            client("same", &["alpha"], &["laptop", "phone"]),
            client("same", &["gamma"], &["laptop"]),
        ],
    ] {
        assert_eq!(
            ManagementDocument::new(routing(7, 11), invalid),
            Err(DomainError::InvalidClientOwnership)
        );
    }
}

#[test]
fn selection_requires_owner_and_membership_without_treating_grants_as_ownership() {
    let doc = document();
    let alice = client_id("alice");
    let laptop = device_id("laptop");
    assert_eq!(
        doc.select_device(&alice, &laptop, None)
            .unwrap()
            .network
            .id(),
        &network_id("alpha")
    );
    assert_eq!(
        doc.select_device(&alice, &device_id("spare"), None)
            .unwrap_err(),
        DeviceLookupError::UnassignedDevice
    );
    for (client, device) in [("absent", "laptop"), ("bob", "phone"), ("empty", "laptop")] {
        assert_eq!(
            doc.select_device(
                &client_id(client),
                &device_id(device),
                Some(&network_id("alpha"))
            )
            .unwrap_err(),
            DeviceLookupError::UnknownDevice
        );
    }
    for (device, net) in [
        ("laptop", "gamma"),
        ("laptop", "absent"),
        ("phone", "beta"),
        ("spare", "alpha"),
    ] {
        assert_eq!(
            doc.select_device(&alice, &device_id(device), Some(&network_id(net)))
                .unwrap_err(),
            DeviceLookupError::InvalidNetwork
        );
    }
    let alpha = doc
        .select_device(&alice, &laptop, Some(&network_id("alpha")))
        .unwrap();
    assert_eq!(alpha.client.id(), &alice);
    assert_eq!(alpha.device.id(), &laptop);
    assert_eq!(alpha.network.id(), &network_id("alpha"));
    assert_eq!(alpha.registration.public_key(), &key(11));
    let beta = doc
        .select_device(&client_id("alice-work"), &device_id("laptop-beta"), None)
        .unwrap();
    assert_eq!(beta.registration.public_key(), &key(21));
    let bob = doc
        .select_device(&client_id("bob"), &device_id("laptop-gamma"), None)
        .unwrap();
    assert_eq!(bob.client.id(), &client_id("bob"));
    assert_eq!(bob.network.id(), &network_id("gamma"));
    assert_eq!(bob.registration.public_key(), &key(31));
    let phone = doc
        .select_device(&alice, &device_id("phone"), None)
        .unwrap();
    assert_eq!(phone.network.id(), &network_id("alpha"));
}

#[test]
fn repeated_keys_and_addresses_do_not_merge_client_or_network_identity() {
    let config = Config::new(
        9,
        ["alpha", "beta", "gamma"]
            .into_iter()
            .map(|name| {
                Network::new(
                    network_id(name),
                    vec![
                        Device::new(
                            device_id(&format!("shared-{name}")),
                            key(11),
                            vec!["10.1.0.1".parse().unwrap()],
                        )
                        .unwrap(),
                    ],
                )
                .unwrap()
            })
            .collect(),
        Policy::new(vec![], vec![], vec![]),
    )
    .unwrap();
    let routing = ManagementConfig::new(node_id("management"), config, vec![]).unwrap();
    let doc = ManagementDocument::new(
        routing,
        vec![
            client("alice", &["alpha"], &["shared-alpha"]),
            client("alice-work", &["beta"], &["shared-beta"]),
            client("bob", &["gamma"], &["shared-gamma"]),
        ],
    )
    .unwrap();
    assert_eq!(
        doc.select_device(&client_id("alice"), &device_id("shared-alpha"), None)
            .unwrap()
            .network
            .id(),
        &network_id("alpha")
    );
    assert_eq!(
        doc.select_device(
            &client_id("alice"),
            &device_id("shared-alpha"),
            Some(&network_id("gamma"))
        )
        .unwrap_err(),
        DeviceLookupError::InvalidNetwork
    );
    let bob = doc
        .select_device(&client_id("bob"), &device_id("shared-gamma"), None)
        .unwrap();
    assert_eq!(bob.client.id(), &client_id("bob"));
    assert_eq!(bob.network.id(), &network_id("gamma"));
    assert_eq!(bob.registration.public_key(), &key(11));
}

#[test]
fn device_selection_uses_stable_ids_across_metadata_and_registration_versions() {
    let before = document();
    let after = ManagementDocument::new(routing(8, 41), clients("Renamed laptop")).unwrap();
    let selected_before = before
        .select_device(
            &client_id("alice"),
            &device_id("laptop"),
            Some(&network_id("alpha")),
        )
        .unwrap();
    let selected_after = after
        .select_device(
            &client_id("alice"),
            &device_id("laptop"),
            Some(&network_id("alpha")),
        )
        .unwrap();
    assert_eq!(selected_before.client.id(), selected_after.client.id());
    assert_eq!(selected_before.device.id(), selected_after.device.id());
    assert_eq!(
        selected_after.device.metadata().name(),
        Some("Renamed laptop")
    );
    assert_eq!(selected_before.registration.public_key(), &key(11));
    assert_eq!(selected_after.registration.public_key(), &key(41));
}

#[test]
fn catalog_is_management_only_and_existing_gateway_projection_policy_is_unchanged() {
    let doc = ManagementDocument::new(routing(7, 11), clients("private display label")).unwrap();
    let actual = doc.project_for(&node_id("gateway")).unwrap();
    assert_eq!(
        actual.decision(&endpoint("alpha", "laptop"), &endpoint("alpha", "phone")),
        Action::Deny
    );
    assert_eq!(
        actual.decision(
            &endpoint("alpha", "laptop"),
            &endpoint("gamma", "laptop-gamma")
        ),
        Action::Allow
    );
    let json = actual.to_json().unwrap();
    assert!(!json.contains("clients"));
    assert!(!json.contains("private display label"));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["projection_version"], 3);
    assert_eq!(value["config"]["schema_version"], 1);
}

// Hand-authored independently of all product serializers. This makes duplicate
// nested fields observable and pins the document's public schema separately.
const LITERAL: &str = r#"{
  "management_version":1,"management_id":"management",
  "config":{"schema_version":1,"generation":7,"networks":[{"id":"alpha","devices":[{"id":"laptop","public_key":[11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"addresses":["10.1.0.1"]}]},{"id":"empty","devices":[]}],"policy":{"global_rules":[],"local_rules":[],"grants":[]}},
  "assignments":[{"recipient":"gateway","traffic":"entry","service_public_key":[101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101,101],"gateway_public_key":[201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201,201],"networks":["alpha"],"tenants":[{"network":"alpha","public_key":[102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102]}]}],
  "clients":[{"id":"alice","networks":["alpha"],"devices":[{"id":"laptop","metadata":{"name":"Sam’s laptop","description":null}}]},{"id":"empty","networks":["empty"],"devices":[]}]
}"#;

#[test]
fn independent_json_fixture_decodes_optional_metadata_and_roundtrips_public_document() {
    let doc = ManagementDocument::from_json(LITERAL).unwrap();
    let selected = doc
        .select_device(&client_id("alice"), &device_id("laptop"), None)
        .unwrap();
    assert_eq!(selected.device.metadata().name(), Some("Sam’s laptop"));
    assert_eq!(selected.device.metadata().description(), None);
    assert_eq!(selected.network.id(), &network_id("alpha"));
    assert_eq!(selected.registration.public_key(), &key(11));
    for metadata in [
        "{}",
        r#"{"name":null}"#,
        r#"{"description":null}"#,
        r#"{"name":null,"description":null}"#,
    ] {
        let json = LITERAL.replace(r#"{"name":"Sam’s laptop","description":null}"#, metadata);
        let parsed = ManagementDocument::from_json(&json).unwrap();
        let selected = parsed
            .select_device(&client_id("alice"), &device_id("laptop"), None)
            .unwrap();
        assert_eq!(
            selected.device.metadata(),
            &DeviceMetadata::new(None, None).unwrap()
        );
    }
    let encoded = doc.to_json().unwrap();
    assert_eq!(ManagementDocument::from_json(&encoded).unwrap(), doc);
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(value["management_version"], 2);
    assert_eq!(value["management_id"], "management");
    assert_eq!(
        value["clients"][0]["devices"][0]["metadata"]["name"],
        "Sam’s laptop"
    );
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("credential"));
}

#[test]
fn json_rejects_unknown_duplicate_missing_and_mistyped_fields_at_each_new_boundary() {
    assert!(ManagementDocument::from_json(LITERAL).is_ok());
    for (old, new) in [
        (
            r#""management_version":1"#,
            r#""extra":true,"management_version":1"#,
        ),
        (
            r#""management_version":1"#,
            r#""management_version":1,"management_version":1"#,
        ),
        (r#""generation":7"#, r#""generation":7,"generation":7"#),
        (r#""id":"alice""#, r#""id":"alice","id":"alice""#),
        (r#""id":"alice""#, r#""id":"alice","owner":"foreign""#),
        (
            r#""id":"laptop","metadata""#,
            r#""id":"laptop","id":"laptop","metadata""#,
        ),
        (
            r#""id":"laptop","metadata""#,
            r#""id":"laptop","owner":"foreign","metadata""#,
        ),
        (
            r#""name":"Sam’s laptop""#,
            r#""name":null,"name":"Sam’s laptop""#,
        ),
        (
            r#""description":null"#,
            r#""description":null,"description":null"#,
        ),
        (
            r#""name":"Sam’s laptop""#,
            r#""alias":"x","name":"Sam’s laptop""#,
        ),
        (
            r#""recipient":"gateway""#,
            r#""recipient":"gateway","recipient":"gateway""#,
        ),
        (
            r#""recipient":"gateway""#,
            r#""recipient":"gateway","extra":1"#,
        ),
        (
            r#""network":"alpha","public_key""#,
            r#""network":"alpha","network":"alpha","public_key""#,
        ),
        (r#""name":"Sam’s laptop""#, r#""name":12"#),
        (
            r#""metadata":{"name":"Sam’s laptop","description":null}"#,
            r#""metadata":null"#,
        ),
    ] {
        assert!(LITERAL.contains(old), "invalid test replacement target");
        assert_eq!(
            ManagementDocument::from_json(&LITERAL.replacen(old, new, 1)),
            Err(DomainError::InvalidJson),
            "accepted malformed field replacement: {old}"
        );
    }
    let valid: serde_json::Value = serde_json::from_str(LITERAL).unwrap();
    for field in [
        "management_version",
        "management_id",
        "config",
        "assignments",
        "clients",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            ManagementDocument::from_json(&missing.to_string()),
            Err(DomainError::InvalidJson)
        );
    }
    let mut missing = valid;
    missing["clients"][0]["devices"][0]
        .as_object_mut()
        .unwrap()
        .remove("metadata");
    assert_eq!(
        ManagementDocument::from_json(&missing.to_string()),
        Err(DomainError::InvalidJson)
    );
}

#[test]
fn structurally_valid_json_cannot_bypass_ownership_or_metadata_validation() {
    assert!(ManagementDocument::from_json(LITERAL).is_ok());
    for (old, new) in [
        (
            r#""id":"alice","networks":["alpha"]"#,
            r#""id":"alice","networks":[]"#,
        ),
        (
            r#""id":"alice","networks":["alpha"]"#,
            r#""id":"alice","networks":["foreign"]"#,
        ),
        (
            r#""id":"empty","networks":["empty"]"#,
            r#""id":"empty","networks":["alpha"]"#,
        ),
        (r#""id":"empty""#, r#""id":"alice""#),
        (
            r#""id":"laptop","metadata""#,
            r#""id":"unregistered","metadata""#,
        ),
    ] {
        assert!(LITERAL.contains(old));
        assert_eq!(
            ManagementDocument::from_json(&LITERAL.replacen(old, new, 1)),
            Err(DomainError::InvalidClientOwnership)
        );
    }
    for invalid in [
        r#""name":"""#.to_owned(),
        r#""name":"escaped\ncontrol""#.to_owned(),
        format!(r#""name":"{}""#, "x".repeat(129)),
    ] {
        assert_eq!(
            ManagementDocument::from_json(&LITERAL.replace(r#""name":"Sam’s laptop""#, &invalid)),
            Err(DomainError::InvalidMetadata)
        );
    }
}

#[test]
fn schema_version_uses_unsigned_integer_and_document_input_has_exact_byte_bound() {
    assert_eq!(MANAGEMENT_VERSION, 2);
    assert_eq!(MAX_MANAGEMENT_BYTES, 16_777_216);
    for version in ["0", "3", "4294967296", "18446744073709551615"] {
        let json = LITERAL.replacen(
            r#""management_version":1"#,
            &format!(r#""management_version":{version}"#),
            1,
        );
        assert_eq!(
            ManagementDocument::from_json(&json),
            Err(DomainError::UnsupportedSchemaVersion)
        );
    }
    for version in ["-1", "1.5", "\"1\"", "null", "true"] {
        let json = LITERAL.replacen(
            r#""management_version":1"#,
            &format!(r#""management_version":{version}"#),
            1,
        );
        assert_eq!(
            ManagementDocument::from_json(&json),
            Err(DomainError::InvalidJson)
        );
    }
    let mut padded = LITERAL.to_owned();
    padded.extend(std::iter::repeat_n(
        ' ',
        MAX_MANAGEMENT_BYTES - padded.len(),
    ));
    assert_eq!(padded.len(), MAX_MANAGEMENT_BYTES);
    assert!(ManagementDocument::from_json(&padded).is_ok());
    padded.push(' ');
    assert_eq!(
        ManagementDocument::from_json(&padded),
        Err(DomainError::LimitExceeded)
    );
}

#[test]
fn client_and_catalog_limits_count_unassigned_devices_across_all_clients() {
    assert_eq!(MAX_CLIENTS, 750);
    assert_eq!(MAX_CLIENT_DEVICES, 750);
    let make = |count: usize, devices: bool| {
        (0..count)
            .map(|i| {
                Client::new(
                    client_id(&format!("c{i}")),
                    vec![network_id(&format!("c{i}"))],
                    if devices {
                        vec![ClientDevice::new(
                            device_id(&format!("unassigned-{i}")),
                            DeviceMetadata::new(Some("\"".repeat(128)), Some("\\".repeat(1024)))
                                .unwrap(),
                        )]
                    } else {
                        vec![]
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let full = ManagementDocument::new(
        routing_for_clients(wgfeel_core::MAX_NETWORKS),
        make(wgfeel_core::MAX_NETWORKS, true),
    )
    .unwrap();
    assert_eq!(full.clients().len(), wgfeel_core::MAX_NETWORKS);
    assert_eq!(
        full.select_device(&client_id("c149"), &device_id("unassigned-149"), None)
            .unwrap_err(),
        DeviceLookupError::UnassignedDevice
    );
    let encoded = full.to_json().unwrap();
    assert!(encoded.len() <= MAX_MANAGEMENT_BYTES);
    assert_eq!(ManagementDocument::from_json(&encoded).unwrap(), full);
    assert_eq!(
        ManagementDocument::new(routing_for_clients(0), make(751, false)),
        Err(DomainError::LimitExceeded)
    );
    let catalog = |prefix: &str, count| {
        (0..count)
            .map(|i| catalog_device(&format!("{prefix}{i}"), None))
            .collect()
    };
    assert_eq!(
        Client::new(
            client_id("alice"),
            vec![network_id("alpha")],
            catalog("d", 751)
        ),
        Err(DomainError::LimitExceeded)
    );
    let too_many = vec![
        Client::new(
            client_id("alice"),
            vec![network_id("alpha")],
            catalog("a", 375),
        )
        .unwrap(),
        Client::new(
            client_id("bob"),
            vec![network_id("beta")],
            catalog("b", 376),
        )
        .unwrap(),
    ];
    assert_eq!(
        ManagementDocument::new(routing_for_clients(0), too_many),
        Err(DomainError::LimitExceeded)
    );
}

fn fixture_gateway_public(service: &wgfeel_core::DevicePublicKey) -> wgfeel_core::DevicePublicKey {
    let mut bytes = *service.as_bytes();
    bytes[10] ^= 0xa5;
    wgfeel_core::DevicePublicKey::new(bytes).unwrap()
}
