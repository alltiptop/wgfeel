//! Private fault-path coverage. No production fault-injection API is exposed.

use super::*;
use crate::PeerConfig;
use wgfeel_core::{DeviceId, NetworkId, TenantPrivateKey};

fn seed(value: u8) -> [u8; 32] {
    let mut bytes = [43; 32];
    bytes[8] = value;
    bytes
}

fn fixture() -> (Gateway, ContextId, PeerId, PeerId) {
    let context = ContextId::Tenant(NetworkId::new("publication-test").unwrap());
    let first = PeerId::Device(DeviceId::new("first").unwrap());
    let second = PeerId::Device(DeviceId::new("second").unwrap());
    let peers = [(&first, 2), (&second, 3)]
        .into_iter()
        .map(|(id, key)| PeerConfig {
            id: id.clone(),
            public_key: DevicePublicKey::new(
                PublicKey::from(&StaticSecret::from(seed(key))).to_bytes(),
            )
            .unwrap(),
        })
        .collect();
    let ContextId::Tenant(network) = &context else {
        unreachable!()
    };
    let gateway = Gateway::new(
        vec![ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(seed(1)).unwrap(),
            peers,
        )],
        Limits::default(),
    )
    .unwrap();
    (gateway, context, first, second)
}

fn pending_index(gateway: &mut Gateway, context: &ContextId, peer: &PeerId) -> u32 {
    let Event::Network { packet, .. } = gateway.initiate(context, peer).unwrap().unwrap() else {
        panic!("expected an initiation");
    };
    assert_eq!(packet.as_bytes().len(), 148);
    assert_eq!(&packet.as_bytes()[..4], &[1, 0, 0, 0]);
    u32::from_le_bytes(packet.as_bytes()[4..8].try_into().unwrap())
}

fn transport_for(index: u32) -> [u8; 32] {
    let mut packet = [0; 32];
    packet[0] = 4;
    packet[4..8].copy_from_slice(&index.to_le_bytes());
    packet
}

#[test]
fn service_capacity_covers_transfer_and_main_invitations_without_unbounded_growth() {
    let peer = |index: u8| PeerConfig {
        id: PeerId::Node(NodeId::new(&format!("node-{index}")).unwrap()),
        public_key: DevicePublicKey::new(
            PublicKey::from(&StaticSecret::from(seed(index))).to_bytes(),
        )
        .unwrap(),
    };
    // 149 mesh neighbors + the current Manager.
    let mut peers: Vec<_> = (2..=151).map(peer).collect();
    let mut gateway = Gateway::new(
        vec![ContextConfig::service(
            ServicePrivateKey::new(seed(1)).unwrap(),
            peers.clone(),
        )],
        Limits::default(),
    )
    .unwrap();
    peers.push(peer(152));
    gateway.set_service_peers(peers.clone()).unwrap();
    // The unified main additionally owns the invitation transport. Its bound is
    // 149 neighbors + one administrator + 32 pending enrollment identities.
    peers.extend((153..=183).map(peer));
    gateway.set_service_peers(peers.clone()).unwrap();
    peers.push(peer(184));
    assert!(gateway.set_service_peers(peers).is_err());
    assert_eq!(gateway.contexts[0].peers.len(), 182);
    assert_eq!(crate::MAX_MESH_PEERS, 150 * 150);
}

#[test]
fn publication_failure_suppresses_output_and_drops_all_engine_owners() {
    let (mut gateway, context, first, second) = fixture();
    let live_index = pending_index(&mut gateway, &context, &first);
    let allocator = gateway.indices.clone();
    assert!(allocator.in_use(live_index));

    // Corrupt only internal ownership metadata, keeping the real engine's
    // allocation alive. The next real handshake must fail registry publication
    // after it allocates, rather than releasing an unregistered packet.
    gateway.contexts[0].peers[1].indices.push(live_index);
    assert_eq!(
        gateway.initiate(&context, &second).unwrap_err(),
        WireGuardError::Protocol
    );
    assert!(
        gateway.router.is_none(),
        "routing capabilities must be revoked"
    );
    assert!(
        gateway.contexts.is_empty(),
        "secret-owning engines must be dropped"
    );
    assert!(
        !allocator.in_use(live_index),
        "the old engine index must be freed"
    );
    assert!(gateway.public_key(&context).is_none());

    let source = "127.0.0.1:51820".parse().unwrap();
    let packet = transport_for(live_index);
    assert_eq!(
        gateway.receive_datagram(source, &packet).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.endpoint(&context, &first).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.initiate(&context, &first).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.tick(&context, &first).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.reset(&context, &first).unwrap_err(),
        WireGuardError::Protocol
    );
    assert_eq!(
        gateway.send(&context, &first, &[]).unwrap_err(),
        WireGuardError::Protocol
    );
}

#[test]
fn index_retirement_is_published_after_error_and_no_event_outcomes() {
    for return_error in [true, false] {
        let (mut gateway, context, first, _) = fixture();
        let live_index = pending_index(&mut gateway, &context, &first);
        let (slot, peer) = gateway.select(&context, &first).unwrap();
        let result = gateway.operate(slot, peer, true, |tunnel| {
            // Timer expiry can drop indices before returning either an error
            // or no packet. Exercise both wrapper outcomes deterministically.
            tunnel.reset();
            if return_error {
                Err(WireGuardError::Protocol)
            } else {
                Ok(TunnResult::Done)
            }
        });
        if return_error {
            assert_eq!(result.unwrap_err(), WireGuardError::Protocol);
        } else {
            assert!(matches!(result.unwrap(), TunnResult::Done));
        }
        assert!(
            gateway.router.is_some(),
            "a normal engine error must not poison routing"
        );
        assert!(!gateway.indices.in_use(live_index));
        assert_eq!(
            gateway
                .receive_datagram(
                    "127.0.0.1:51820".parse().unwrap(),
                    &transport_for(live_index)
                )
                .unwrap_err(),
            WireGuardError::UnknownIndex
        );
        assert!(gateway.initiate(&context, &first).unwrap().is_some());
    }
}

#[test]
fn consumed_plaintext_allocation_is_retained_and_erased_after_success_and_no_session() {
    let (mut gateway, context, first, _) = fixture();
    let original_allocation = gateway.plaintext_pool.get().as_ptr();
    let mut plaintext = [0x71; 61];
    plaintext[..20].copy_from_slice(&[
        0x45, 0, 0, 61, 0, 0, 0, 0, 64, 6, 0, 0, 10, 253, 0, 2, 10, 253, 0, 1,
    ]);
    assert_eq!(
        gateway.send(&context, &first, &plaintext).unwrap_err(),
        WireGuardError::NoSession
    );
    {
        let returned = gateway.plaintext_pool.get();
        assert_eq!(
            returned.as_ptr(),
            original_allocation,
            "must inspect original allocation"
        );
        assert!(returned.iter().all(|byte| *byte == 0));
    }
    let ContextId::Tenant(network) = &context else {
        unreachable!()
    };
    let mut peer = Gateway::new(
        vec![ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(seed(2)).unwrap(),
            vec![PeerConfig {
                id: first.clone(),
                public_key: gateway.public_key(&context).unwrap().clone(),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let source = "127.0.0.1:51820".parse().unwrap();
    let Event::Network { packet, .. } = gateway.initiate(&context, &first).unwrap().unwrap() else {
        panic!("initiation");
    };
    let Event::Network { packet, .. } = peer
        .receive(&context, &first, source, packet.as_bytes())
        .unwrap()
        .unwrap()
    else {
        panic!("response");
    };
    gateway
        .receive(&context, &first, source, packet.as_bytes())
        .unwrap();
    assert!(matches!(
        gateway.send(&context, &first, &plaintext),
        Ok(Event::Network { .. })
    ));
    let returned = gateway.plaintext_pool.get();
    assert_eq!(
        returned.as_ptr(),
        original_allocation,
        "must inspect original allocation"
    );
    assert!(returned.iter().all(|byte| *byte == 0));
}

#[test]
fn mesh_handshake_identity_is_bound_to_the_expected_peer_before_session_changes() {
    let (mut receiver, context, first, second) = fixture();
    let ContextId::Tenant(network) = &context else {
        unreachable!()
    };
    let mut sender = Gateway::new(
        vec![ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(seed(2)).unwrap(),
            vec![PeerConfig {
                id: first.clone(),
                public_key: receiver.public_key(&context).unwrap().clone(),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let Event::Network { packet, .. } = sender.initiate(&context, &first).unwrap().unwrap() else {
        panic!("expected initiation")
    };
    let source = "127.0.0.1:51820".parse().unwrap();
    let admission = receiver
        .router
        .as_mut()
        .unwrap()
        .admit(source, packet.as_bytes())
        .unwrap();
    let Verification::Packet(verified) = admission.verified else {
        panic!("expected admitted handshake")
    };
    assert!(receiver.live_indices().unwrap().is_empty());
    assert!(matches!(
        receiver.admitted_peer(0, Some(&second), &verified),
        Err(WireGuardError::UnknownPeer)
    ));
    assert!(receiver.live_indices().unwrap().is_empty());
    assert_eq!(
        receiver.admitted_peer(0, Some(&first), &verified).unwrap(),
        0
    );
}
