//! Main uses the same forwarding runtime and UDP listener as child participants.
use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};
use wgfeel_core::{DevicePublicKey, NodeId};
use wgfeel_management::ManagementService;
use wgfeel_node::{MainEvent, MainForwarder};
use wgfeel_store::{GatewayDelivery, StoredManagement};
use wgfeel_wireguard::{PeerConfig, PeerId};

pub(super) struct Transport {
    forwarding: MainForwarder,
    admin: PeerConfig,
    own: NodeId,
    public: DevicePublicKey,
    next_config: Instant,
    acknowledged: u64,
    diagnostics: VecDeque<&'static str>,
}
fn delivery(state: &StoredManagement) -> Result<GatewayDelivery, &'static str> {
    let projection = state
        .document()
        .routing()
        .project_mesh_for(state.document().routing().management_id())
        .map_err(|_| "main has no local forwarding projection")?;
    let bytes = state
        .delivery(&projection)
        .map_err(|_| "cannot select main forwarding keys")?;
    GatewayDelivery::decode(&bytes).map_err(|_| "invalid main forwarding material")
}
impl Transport {
    pub(super) fn control_transport(&mut self) -> std::io::Result<wgfeel_wireguard::UdpTransport> {
        self.forwarding.control_transport()
    }
    pub(super) fn bind(
        listen: SocketAddr,
        admin: NodeId,
        admin_key: DevicePublicKey,
        service: &ManagementService,
    ) -> Result<Self, &'static str> {
        let state = service
            .delivery_snapshot()
            .map_err(|_| "cannot load main forwarding state")?;
        let own = state.document().routing().management_id();
        let assignment = state
            .document()
            .routing()
            .assignments()
            .iter()
            .find(|node| node.recipient() == own)
            .ok_or("main state has no local forwarding assignment")?;
        let selected = delivery(&state)?;
        let forwarding = MainForwarder::bind(
            listen,
            selected.projection(),
            state.node_keys(),
            selected.keys(),
            selected.egress_keys(),
        )?;
        Ok(Self {
            forwarding,
            admin: PeerConfig {
                id: PeerId::Node(admin),
                public_key: admin_key,
            },
            own: own.clone(),
            public: assignment.service_public_key().clone(),
            next_config: Instant::now(),
            acknowledged: 0,
            diagnostics: VecDeque::with_capacity(16),
        })
    }
    pub(super) fn applied_generation(&self) -> u64 {
        self.forwarding.generation()
    }
    pub(super) fn peer_identity(&self, id: &NodeId) -> Option<&DevicePublicKey> {
        self.forwarding.peer_identity(id)
    }
    pub(super) fn ready(&self) -> bool {
        self.forwarding.ready()
    }
    pub(super) fn synchronize(
        &mut self,
        service: &mut ManagementService,
    ) -> Result<(), &'static str> {
        if Instant::now() < self.next_config {
            return Ok(());
        }
        self.next_config = Instant::now() + Duration::from_millis(250);
        let state = service
            .delivery_snapshot()
            .map_err(|_| "cannot load main forwarding state")?;
        let generation = state.document().routing().generation();
        if generation != self.forwarding.generation() {
            let selected = delivery(&state)?;
            if self
                .forwarding
                .configure(
                    selected.projection(),
                    state.node_keys(),
                    selected.keys(),
                    selected.egress_keys(),
                )
                .is_err()
            {
                self.record_diagnostic("main forwarding configuration could not be prepared");
            }
        }
        if self.forwarding.ready()
            && self.forwarding.generation() == generation
            && self.acknowledged != generation
        {
            service
                .acknowledge(self.own.clone(), &self.public, generation)
                .map_err(|_| "cannot confirm main forwarding generation")?;
            self.acknowledged = generation;
        }
        Ok(())
    }
    pub(super) fn set_invitation_peers(
        &mut self,
        peers: &[(NodeId, DevicePublicKey)],
    ) -> Result<(), &'static str> {
        let mut controls = vec![self.admin.clone()];
        controls.extend(peers.iter().map(|(id, key)| PeerConfig {
            id: PeerId::Node(id.clone()),
            public_key: key.clone(),
        }));
        self.forwarding.control_peers(controls);
        Ok(())
    }
    pub(super) fn poll_peers(
        &mut self,
        mut receive: impl FnMut(&PeerId, &[u8]),
    ) -> Result<(), &'static str> {
        for event in self.forwarding.poll()? {
            match event {
                MainEvent::Control { peer, packet } => {
                    receive(&PeerId::Node(peer), packet.as_bytes())
                }
                MainEvent::Applied { .. } => (),
                MainEvent::WorkerFailed { .. } => {
                    self.record_diagnostic("main forwarding worker failed; its context is disabled")
                }
                MainEvent::ConfigurationRejected => self.record_diagnostic(
                    "main forwarding configuration was rejected; previous runtime retained",
                ),
            }
        }
        Ok(())
    }
    pub(super) fn diagnostic(&mut self) -> Option<&'static str> {
        self.diagnostics.pop_front()
    }
    pub(super) fn endpoint(&self) -> Option<SocketAddr> {
        match &self.admin.id {
            PeerId::Node(id) => self.forwarding.endpoint(id),
            _ => None,
        }
    }
    pub(super) fn send(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        let PeerId::Node(id) = &self.admin.id else {
            return Err("invalid main administrator peer");
        };
        self.forwarding.send_control(id, packet);
        Ok(())
    }
    pub(super) fn send_peer(&mut self, peer: &PeerId, packet: &[u8]) -> Result<(), &'static str> {
        let PeerId::Node(id) = peer else {
            return Err("invalid main API peer");
        };
        self.forwarding.send_control(id, packet);
        Ok(())
    }
    pub(super) fn send_distribution(&mut self, peer: &NodeId, packet: &[u8]) {
        self.forwarding.send_control(peer, packet);
    }
    fn record_diagnostic(&mut self, message: &'static str) {
        if self.diagnostics.len() < 16 {
            self.diagnostics.push_back(message);
        }
    }
}
