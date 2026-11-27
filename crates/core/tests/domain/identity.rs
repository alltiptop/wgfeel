use super::network_id;
use wgfeel_core::{
    AdminCredential, DeviceId, DevicePublicKey, DomainError, InvitationToken, NetworkId, NodeId,
    ServicePrivateKey, TenantPrivateKey,
};

#[test]
fn identifiers_accept_bounded_ascii_without_normalization() {
    for value in ["a", "A_9-", &"z".repeat(64)] {
        assert_eq!(NetworkId::new(value).unwrap().as_str(), value);
        assert_eq!(DeviceId::new(value).unwrap().as_str(), value);
        assert_eq!(NodeId::new(value).unwrap().as_str(), value);
    }
    assert_ne!(network_id("Alice"), network_id("alice"));
}

#[test]
fn identifiers_reject_empty_oversized_and_ambiguous_input() {
    for value in [
        "",
        " alice",
        "alice ",
        "a/b",
        "a.b",
        "a:b",
        "a\n",
        "сеть",
        &"a".repeat(65),
    ] {
        assert_eq!(
            NetworkId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
        assert_eq!(
            DeviceId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
        assert_eq!(
            NodeId::new(value).unwrap_err(),
            DomainError::InvalidIdentifier
        );
    }
}

#[test]
fn public_key_preserves_bytes_and_rejects_zero() {
    assert_eq!(
        DevicePublicKey::new([42; 32]).unwrap().as_bytes(),
        &[42; 32]
    );
    assert_eq!(
        DevicePublicKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
}

#[test]
fn secret_types_preserve_explicit_access_and_redact_debug() {
    let bytes = [83; 32];
    let admin = AdminCredential::new(bytes).unwrap();
    let invitation = InvitationToken::new(bytes).unwrap();
    let node = ServicePrivateKey::new(bytes).unwrap();
    let tenant = TenantPrivateKey::new(bytes).unwrap();
    assert_eq!(admin.expose_bytes(), &bytes);
    assert_eq!(invitation.expose_bytes(), &bytes);
    assert_eq!(node.expose_bytes(), &bytes);
    assert_eq!(tenant.expose_bytes(), &bytes);
    for (name, debug) in [
        ("AdminCredential", format!("{admin:?}")),
        ("InvitationToken", format!("{invitation:?}")),
        ("ServicePrivateKey", format!("{node:?}")),
        ("TenantPrivateKey", format!("{tenant:?}")),
    ] {
        assert!(debug.contains(name), "missing type name: {debug}");
        assert!(
            debug.contains("[REDACTED]"),
            "missing redaction marker: {debug}"
        );
        assert!(!debug.contains("83"), "secret bytes in Debug: {debug}");
        assert!(
            !debug.contains("5353"),
            "hex secret bytes in Debug: {debug}"
        );
    }
    assert_eq!(
        AdminCredential::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        InvitationToken::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        ServicePrivateKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
    assert_eq!(
        TenantPrivateKey::new([0; 32]).unwrap_err(),
        DomainError::InvalidKey
    );
}

#[test]
fn errors_have_standard_error_contract_without_input_echo() {
    fn standard_error(error: &dyn std::error::Error) {
        assert!(!error.to_string().is_empty());
    }
    standard_error(&DomainError::InvalidIdentifier);
    standard_error(&DomainError::InvalidJson);
}
