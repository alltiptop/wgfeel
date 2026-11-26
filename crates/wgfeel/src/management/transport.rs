//! One embedded service WireGuard peer. Only authenticated inner packets escape.
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId, ServicePrivateKey};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Gateway, Limits, PeerConfig, PeerId, TransportError,
    UdpEvent, UdpTransport, WireGuardError,
};

pub(super) struct Tunnel {
    gateway: Gateway,
    udp: UdpTransport,
    peer: PeerId,
    peers: Vec<PeerConfig>,
    tick: Instant,
}
impl Tunnel {
    pub(super) fn bind(
        listen: SocketAddr,
        key: ServicePrivateKey,
        peer: NodeId,
        public: DevicePublicKey,
    ) -> Result<Self, &'static str> {
        let udp = UdpTransport::bind(listen).map_err(|_| "cannot bind service WireGuard socket")?;
        Self::new(udp, key, peer, public)
    }
    pub(super) fn new(
        udp: UdpTransport,
        key: ServicePrivateKey,
        peer: NodeId,
        public: DevicePublicKey,
    ) -> Result<Self, &'static str> {
        let peer = PeerId::Node(peer);
        let gateway = Gateway::new(
            vec![ContextConfig::service(
                key,
                vec![PeerConfig {
                    id: peer.clone(),
                    public_key: public.clone(),
                }],
            )],
            Limits::default(),
        )
        .map_err(|_| "invalid service WireGuard identity")?;
        Ok(Self {
            gateway,
            udp,
            peers: vec![PeerConfig {
                id: peer.clone(),
                public_key: public,
            }],
            peer,
            tick: Instant::now(),
        })
    }
    pub(super) fn reset(&mut self) -> Result<(), &'static str> {
        self.gateway
            .reset(&ContextId::Service, &self.peer)
            .map_err(|_| "cannot reset service WireGuard session")
    }
    #[cfg(test)]
    pub(super) fn local_addr(&self) -> Result<SocketAddr, &'static str> {
        self.udp
            .local_addr()
            .map_err(|_| "cannot inspect service WireGuard socket")
    }
    pub(super) fn initiate(&mut self, endpoint: SocketAddr) -> Result<(), &'static str> {
        if let Some(event) = self
            .gateway
            .initiate_at(&ContextId::Service, &self.peer, endpoint)
            .map_err(|_| "cannot initiate service WireGuard session")?
        {
            self.udp
                .transmit(event)
                .map_err(|_| "cannot send service WireGuard handshake")?;
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, mut receive: impl FnMut(&[u8])) -> Result<(), &'static str> {
        let expected = self.peer.clone();
        self.poll_peers(|peer, packet| {
            if peer == &expected {
                receive(packet);
            }
        })
    }
    pub(super) fn poll_peers(
        &mut self,
        mut receive: impl FnMut(&PeerId, &[u8]),
    ) -> Result<(), &'static str> {
        // Fixed per-turn ingress budget; unauthenticated noise cannot prevent
        // signal processing, local API work or protocol timers.
        for _ in 0..32 {
            match self.udp.poll(&mut self.gateway) {
                Ok(Some(UdpEvent::Plaintext {
                    context: ContextId::Service,
                    peer,
                    packet,
                })) => receive(&peer, packet.as_bytes()),
                Ok(_) | Err(TransportError::WireGuard(_)) => (),
                Err(_) => return Err("service WireGuard receive failed"),
            }
        }
        if self.tick.elapsed() >= Duration::from_millis(100) {
            self.tick = Instant::now();
            for index in 0..self.peers.len() {
                let peer = self.peers[index].id.clone();
                let result = self.gateway.tick_datagram(&ContextId::Service, &peer);
                self.peer_timer_result(&peer, result)?;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn timer_result(
        &mut self,
        result: Result<Option<DatagramEvent>, WireGuardError>,
    ) -> Result<(), &'static str> {
        self.peer_timer_result(&self.peer.clone(), result)
    }
    fn peer_timer_result(
        &mut self,
        peer: &PeerId,
        result: Result<Option<DatagramEvent>, WireGuardError>,
    ) -> Result<(), &'static str> {
        match result {
            Ok(Some(event)) => self
                .udp
                .transmit(event)
                .map_err(|_| "service WireGuard timer send failed"),
            Ok(None) | Err(WireGuardError::NoEndpoint | WireGuardError::NoSession) => Ok(()),
            // The engine reports expired idle/rekey sessions as Protocol.
            // Reset only this peer; invalid internal routing still makes reset
            // fail, while a normal disconnect leaves Management available.
            Err(WireGuardError::Protocol) => self
                .gateway
                .reset(&ContextId::Service, peer)
                .map_err(|_| "service WireGuard state invalid"),
            Err(_) => Err("service WireGuard timer failed"),
        }
    }
    pub(super) fn send(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        self.send_peer(&self.peer.clone(), packet)
    }
    pub(super) fn send_peer(&mut self, peer: &PeerId, packet: &[u8]) -> Result<(), &'static str> {
        match self
            .gateway
            .send_datagram(&ContextId::Service, peer, packet)
        {
            Ok(event) => self
                .udp
                .transmit(event)
                .map_err(|_| "service WireGuard send failed"),
            // TCP retains and retransmits bytes after handshake completion.
            Err(WireGuardError::NoEndpoint | WireGuardError::NoSession) => Ok(()),
            Err(_) => Err("service WireGuard encryption failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    use wgfeel_wireguard::{ContextConfig, ContextId, Gateway, Limits};

    fn key(byte: u8) -> ServicePrivateKey {
        ServicePrivateKey::new([byte; 32]).unwrap()
    }
    fn public(byte: u8) -> DevicePublicKey {
        Gateway::new(
            vec![ContextConfig::service(key(byte), vec![])],
            Limits::default(),
        )
        .unwrap()
        .public_key(&ContextId::Service)
        .unwrap()
        .clone()
    }
    fn tunnel(own: u8, peer: u8) -> Tunnel {
        Tunnel::bind(
            "127.0.0.1:0".parse().unwrap(),
            key(own),
            NodeId::new("peer").unwrap(),
            public(peer),
        )
        .unwrap()
    }
    fn packet() -> [u8; 20] {
        [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 253, 0, 2, 10, 253, 0, 1,
        ]
    }

    #[test]
    fn only_pinned_peer_can_deliver_inner_packets_over_service_wireguard() {
        let mut server = tunnel(31, 32);
        let mut wrong = tunnel(33, 31);
        let address = server.local_addr().unwrap();
        wrong.initiate(address).unwrap();
        for _ in 0..30 {
            server
                .poll(|_| panic!("untrusted peer delivered plaintext"))
                .unwrap();
            wrong.poll(|_| panic!("unexpected inner packet")).unwrap();
            wrong.send(&packet()).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        let mut client = tunnel(32, 31);
        client.initiate(address).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let mut received = false;
        while Instant::now() < end && !received {
            client.poll(|_| panic!("unexpected inner packet")).unwrap();
            client.send(&packet()).unwrap();
            server
                .poll(|bytes| {
                    assert_eq!(bytes, packet());
                    received = true;
                })
                .unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            received,
            "authenticated tunnel did not recover after wrong-key handshake"
        );
        server
            .timer_result(Err(WireGuardError::Protocol))
            .expect("expired admin session must not stop Management");
        assert!(
            server
                .gateway
                .endpoint(&ContextId::Service, &server.peer)
                .unwrap()
                .is_none()
        );
        client.initiate(address).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let mut recovered = false;
        while Instant::now() < end && !recovered {
            server
                .poll(|bytes| {
                    assert_eq!(bytes, packet());
                    recovered = true;
                })
                .unwrap();
            client.poll(|_| ()).unwrap();
            client.send(&packet()).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        assert!(recovered, "admin could not reconnect after session expiry");
    }
}
