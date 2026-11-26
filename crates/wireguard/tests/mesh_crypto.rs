use wgfeel_core::{DevicePublicKey, NetworkId, NodeId, TenantPrivateKey};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Gateway, Limits, PeerConfig, PeerId,
};
fn key(id: u8) -> [u8; 32] {
    let mut key = [61; 32];
    key[10] = id;
    key
}
fn public(id: u8) -> DevicePublicKey {
    DevicePublicKey::new(
        gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from(key(id))).to_bytes(),
    )
    .unwrap()
}
#[test]
fn gateway_peers_use_tenant_keys_and_cannot_decrypt_another_tenant() {
    let network = NetworkId::new("alice").unwrap();
    let context = ContextId::Tenant(network.clone());
    let mut a = Gateway::new(
        vec![ContextConfig::tenant(
            network.clone(),
            TenantPrivateKey::new(key(1)).unwrap(),
            vec![PeerConfig {
                id: PeerId::Gateway(NodeId::new("b").unwrap()),
                public_key: public(2),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let mut b = Gateway::new(
        vec![ContextConfig::tenant(
            network,
            TenantPrivateKey::new(key(2)).unwrap(),
            vec![PeerConfig {
                id: PeerId::Gateway(NodeId::new("a").unwrap()),
                public_key: public(1),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let mut other = Gateway::new(
        vec![ContextConfig::tenant(
            NetworkId::new("bob").unwrap(),
            TenantPrivateKey::new(key(3)).unwrap(),
            vec![PeerConfig {
                id: PeerId::Gateway(NodeId::new("a").unwrap()),
                public_key: public(4),
            }],
        )],
        Limits::default(),
    )
    .unwrap();
    let a_addr = "127.0.0.1:10001".parse().unwrap();
    let b_addr = "127.0.0.1:10002".parse().unwrap();
    let Some(DatagramEvent::Network { packet, .. }) = a
        .initiate_at(
            &context,
            &PeerId::Gateway(NodeId::new("b").unwrap()),
            b_addr,
        )
        .unwrap()
    else {
        panic!("initiation")
    };
    assert!(other.receive_datagram(a_addr, packet.as_bytes()).is_err());
    let Some(DatagramEvent::Network { packet, .. }) =
        b.receive_datagram(a_addr, packet.as_bytes()).unwrap()
    else {
        panic!("response")
    };
    let Some(DatagramEvent::Network { packet, .. }) =
        a.receive_datagram(b_addr, packet.as_bytes()).unwrap()
    else {
        panic!("confirmation")
    };
    b.receive_datagram(a_addr, packet.as_bytes()).unwrap();
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 0, 2, 10, 77, 0, 3,
    ];
    let DatagramEvent::Network {
        packet: encrypted, ..
    } = a
        .send_datagram(
            &context,
            &PeerId::Gateway(NodeId::new("b").unwrap()),
            &packet,
        )
        .unwrap()
    else {
        panic!("encrypted")
    };
    assert!(
        other
            .receive_datagram(a_addr, encrypted.as_bytes())
            .is_err()
    );
    let Some(DatagramEvent::Plaintext {
        context: actual,
        peer,
        packet: clear,
    }) = b.receive_datagram(a_addr, encrypted.as_bytes()).unwrap()
    else {
        panic!("plaintext")
    };
    assert_eq!(actual, context);
    assert_eq!(peer, PeerId::Gateway(NodeId::new("a").unwrap()));
    assert_eq!(clear.as_bytes(), packet);
}
