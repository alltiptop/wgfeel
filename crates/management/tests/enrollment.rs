use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use wgfeel_core::*;
use wgfeel_management::{ManagementService, Request, Response};
use wgfeel_protocol::enrollment::{ENROLLMENT_PATH, EnrollmentClaim, Invitation};
use wgfeel_store::{ManagementApi, ManagementStore};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-enrollment-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagementStore::initialize(&root.join("state")).unwrap();
        let document = ManagementDocument::new(
            ManagementConfig::new(
                node("manager"),
                Config::new(1, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
                vec![],
            )
            .unwrap(),
            vec![],
        )
        .unwrap();
        let api = ManagementApi::new("0.0.0.0:51820".parse().unwrap(), key(9))
            .unwrap()
            .with_endpoints(vec![
                "203.0.113.2:51820".parse().unwrap(),
                "[2001:db8::2]:51820".parse().unwrap(),
            ])
            .unwrap();
        store
            .commit_with_api(
                &document,
                &wgfeel_test_support::fixture_node_keys([197; 32]),
                &AdminCredential::new([211; 32]).unwrap(),
                &api,
                None,
            )
            .unwrap();
        Self(root)
    }
    fn open(&self) -> ManagementService {
        ManagementService::open(&self.0.join("state")).unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.0.join("state/state.json")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn node(id: &str) -> NodeId {
    NodeId::new(id).unwrap()
}
fn key(byte: u8) -> DevicePublicKey {
    DevicePublicKey::new([byte; 32]).unwrap()
}
fn request<'a>(target: &'a str, body: &'a [u8]) -> Request<'a> {
    Request {
        method: "POST",
        target,
        authorization: None,
        if_match: None,
        body,
    }
}
fn issue(service: &mut ManagementService) -> (Invitation, DevicePublicKey) {
    issue_with_body(service, b"")
}
fn issue_with_body(service: &mut ManagementService, body: &[u8]) -> (Invitation, DevicePublicKey) {
    let response = service.handle_local(request("/api/v1/node-invitations", body));
    assert_eq!(
        response.status,
        201,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    #[derive(serde::Deserialize)]
    struct Issued<'a> {
        invitation: &'a str,
    }
    let wire: Issued<'_> = serde_json::from_slice(&response.body).unwrap();
    let invitation = Invitation::decode(wire.invitation).unwrap();
    let peer = service
        .invitation_peers()
        .into_iter()
        .find(|(id, _)| id == invitation.id())
        .unwrap()
        .1;
    (invitation, peer)
}
fn claim() -> EnrollmentClaim {
    EnrollmentClaim::new(
        node("node-1"),
        (key(3)).clone(),
        wgfeel_test_support::fixture_gateway_public(&(key(3))),
        "vps1".into(),
        vec![
            "203.0.113.20:55125".parse().unwrap(),
            "[2001:db8::20]:55125".parse().unwrap(),
        ],
        node("attempt-1"),
    )
    .unwrap()
}
fn submit(
    service: &mut ManagementService,
    invitation: &Invitation,
    peer: &DevicePublicKey,
) -> Response {
    service.handle_enrollment(
        invitation.id(),
        peer,
        request(ENROLLMENT_PATH, &serde_json::to_vec(&claim()).unwrap()),
    )
}

#[test]
fn invitation_revision_is_optional_but_a_supplied_condition_must_match() {
    let fixture = Fixture::new();
    let mut service = fixture.open();
    let before = fixture.bytes();
    for (condition, expected) in [
        (Some("\"2\""), 412),
        (Some("invalid"), 400),
        (Some("\"1\""), 201),
        (None, 201),
    ] {
        let peers = service.invitation_peers().len();
        let response = service.handle_local(Request {
            if_match: condition,
            ..request("/api/v1/node-invitations", b"")
        });
        assert_eq!(response.status, expected);
        assert_eq!(
            service.invitation_peers().len(),
            peers + usize::from(expected == 201)
        );
        assert_eq!(
            fixture.bytes(),
            before,
            "issuing an invitation must not publish a configuration revision"
        );
    }
}

#[test]
fn invitation_traffic_is_chosen_by_main_and_cannot_be_overridden_by_the_child() {
    for mode in [TrafficMode::Entry, TrafficMode::Relay, TrafficMode::Off] {
        let fixture = Fixture::new();
        let mut service = fixture.open();
        let body = serde_json::to_vec(&serde_json::json!({"traffic":mode})).unwrap();
        let (invitation, peer) = issue_with_body(&mut service, &body);
        let mut forged = serde_json::to_value(claim()).unwrap();
        forged["traffic"] = "entry".into();
        assert_eq!(
            service
                .handle_enrollment(
                    invitation.id(),
                    &peer,
                    request(ENROLLMENT_PATH, &serde_json::to_vec(&forged).unwrap())
                )
                .status,
            400
        );
        assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
        let claim = claim();
        assert_eq!(
            service
                .complete_enrollment(
                    invitation.id(),
                    &peer,
                    claim.public_key(),
                    claim.endpoints()[0]
                )
                .status,
            200
        );
        drop(service);
        let state = fixture.open().delivery_snapshot().unwrap();
        assert_eq!(state.document().routing().assignments()[0].traffic(), mode);
    }
    let fixture = Fixture::new();
    let mut service = fixture.open();
    for invalid in [
        br#"{"traffic":"gateway"}"#.as_slice(),
        br#"{"traffic":null}"#,
        br#"{"control":"main"}"#,
    ] {
        assert_eq!(
            service
                .handle_local(request("/api/v1/node-invitations", invalid))
                .status,
            400
        );
    }
    assert!(service.invitation_peers().is_empty());
}

#[test]
fn verified_address_becomes_primary_for_native_configs_and_remains_durable() {
    let fixture = Fixture::new();
    let mut service = fixture.open();
    let (invitation, peer) = issue(&mut service);
    assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
    let claim = claim();
    let ipv6 = claim.endpoints()[1];
    let response = service.complete_enrollment(invitation.id(), &peer, claim.public_key(), ipv6);
    assert_eq!(response.status, 200);
    let check = |service: &mut ManagementService| {
        let state = service.delivery_snapshot().unwrap();
        let assignment = &state.document().routing().assignments()[0];
        assert_eq!(assignment.endpoint(), Some(ipv6));
        assert_eq!(assignment.endpoints(), &[ipv6, claim.endpoints()[0]]);
    };
    check(&mut service);
    assert_eq!(
        submit(&mut service, &invitation, &peer).generation,
        response.generation
    );
    drop(service);
    check(&mut fixture.open());
}

#[test]
fn invitations_and_unfinished_claims_never_touch_durable_state_and_restart_revokes_them() {
    let fixture = Fixture::new();
    let mut service = fixture.open();
    let before = fixture.bytes();
    assert_eq!(
        service
            .handle(request("/api/v1/node-invitations", b""))
            .status,
        401
    );
    let (invitation, peer) = issue(&mut service);
    assert_eq!(invitation.endpoints().len(), 2);
    assert_eq!(fixture.bytes(), before);
    assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
    assert_eq!(fixture.bytes(), before);
    assert_eq!(service.pending_enrollments().len(), 1);
    drop(service);
    let mut service = fixture.open();
    assert!(service.invitation_peers().is_empty());
    assert!(service.pending_enrollments().is_empty());
    assert_eq!(submit(&mut service, &invitation, &peer).status, 410);
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn invitation_channel_cannot_read_config_rotate_admin_token_or_register_without_key_proof() {
    let fixture = Fixture::new();
    let mut service = fixture.open();
    let (invitation, peer) = issue(&mut service);
    let before = fixture.bytes();
    for target in [
        "/api/v1/config",
        "/api/v1/token/rotate",
        "/api/v1/gateways",
        "/api/v1/node-invitations",
        "/internal/v1/config",
    ] {
        assert_eq!(
            service
                .handle_enrollment(invitation.id(), &peer, request(target, b""))
                .status,
            403
        );
    }
    assert_eq!(submit(&mut service, &invitation, &key(99)).status, 410);
    assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
    let claim = claim();
    assert_eq!(
        service
            .complete_enrollment(invitation.id(), &peer, &key(99), claim.endpoints()[0])
            .status,
        403
    );
    assert_eq!(
        service
            .complete_enrollment(
                invitation.id(),
                &peer,
                claim.public_key(),
                "203.0.113.21:55125".parse().unwrap()
            )
            .status,
        403
    );
    assert_eq!(fixture.bytes(), before);
    let pending = submit(&mut service, &invitation, &peer);
    assert!(!String::from_utf8_lossy(&pending.body).contains("private"));
    assert_eq!(pending.status, 202);
}

#[test]
fn verified_activation_is_durable_and_repeat_join_has_one_membership_and_stable_keys() {
    let fixture = Fixture::new();
    let mut service = fixture.open();
    let (invitation, peer) = issue(&mut service);
    assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
    let claim = claim();
    let response = service.complete_enrollment(
        invitation.id(),
        &peer,
        claim.public_key(),
        claim.endpoints()[1],
    );
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.generation, Some(2));
    let registered = fixture.bytes();
    assert_eq!(submit(&mut service, &invitation, &peer).status, 200);
    assert_eq!(
        service
            .complete_enrollment(
                invitation.id(),
                &peer,
                claim.public_key(),
                claim.endpoints()[0]
            )
            .status,
        200
    );
    assert_eq!(fixture.bytes(), registered);
    drop(service);
    let mut service = fixture.open();
    let state = service.delivery_snapshot().unwrap();
    assert_eq!(state.document().routing().assignments().len(), 1);
    let node = &state.document().routing().assignments()[0];
    assert_eq!(node.hostname(), Some("vps1"));
    assert_eq!(
        node.endpoints(),
        &[claim.endpoints()[1], claim.endpoints()[0]]
    );
    let (invitation, peer) = issue(&mut service);
    assert_eq!(submit(&mut service, &invitation, &peer).status, 202);
    assert_eq!(
        service
            .complete_enrollment(
                invitation.id(),
                &peer,
                claim.public_key(),
                claim.endpoints()[1]
            )
            .status,
        200
    );
    assert_eq!(fixture.bytes(), registered);
}
