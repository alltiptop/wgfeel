//! Connected provider sockets belong to the trusted node, outside the workers.
use rustix::net::sockopt;
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    os::fd::{AsFd, BorrowedFd},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};
use wgfeel_core::{EgressId, EgressProfile, MAX_EGRESSES_PER_NODE, validate_external_endpoint};
use wgfeel_wireguard::{
    ContextId, PeerId,
    worker::{EncryptedDatagram, LocalGateway, same_provider_session},
};

type Lookup = (String, SyncSender<Vec<SocketAddr>>);

// Detached lookups outlive revoked assignments only until libc returns. Their
// reply channels are per incarnation. A fixed process-wide pool bounds both
// threads and queued jobs, including across rapid configuration replacement.
fn resolver() -> Option<SyncSender<Lookup>> {
    static LOOKUPS: Mutex<Option<SyncSender<Lookup>>> = Mutex::new(None);
    let mut pool = LOOKUPS.lock().ok()?;
    if pool.is_none() {
        let (sender, receiver) = mpsc::sync_channel::<Lookup>(MAX_EGRESSES_PER_NODE);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = 0;
        for _ in 0..2 {
            let receiver = Arc::clone(&receiver);
            if std::thread::Builder::new()
                .name("provider-dns".into())
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(lock) => lock.recv(),
                            Err(_) => return,
                        };
                        let Ok((name, reply)) = job else { return };
                        let candidates = name
                            .to_socket_addrs()
                            .into_iter()
                            .flatten()
                            .filter(|a| validate_external_endpoint(*a).is_ok())
                            .take(16)
                            .collect();
                        let _ = reply.try_send(candidates);
                    }
                })
                .is_ok()
            {
                workers += 1
            }
        }
        *pool = (workers > 0).then_some(sender);
    }
    pool.clone()
}

// Let WireGuard retransmit before moving to another resolved endpoint.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(15);
#[derive(Default)]
struct Handshakes {
    next_candidate: usize,
    unanswered: Option<Instant>,
}
impl Handshakes {
    fn next_address(&mut self, addresses: &[SocketAddr]) -> SocketAddr {
        let addr = addresses[self.next_candidate % addresses.len()];
        self.next_candidate = (self.next_candidate + 1) % addresses.len();
        addr
    }
    fn sent(&mut self, now: Instant) {
        self.unanswered.get_or_insert(now);
    }
    fn expired(&mut self, now: Instant, authenticated: Option<Instant>) -> bool {
        let Some(sent) = self.unanswered else {
            return false;
        };
        if authenticated.is_some_and(|time| time >= sent) {
            self.unanswered = None;
            return false;
        }
        if now.saturating_duration_since(sent) >= HANDSHAKE_WAIT {
            self.unanswered = None;
            return true;
        }
        false
    }
}
struct Provider {
    profile: EgressProfile,
    worker_pid: u32,
    handshakes: Handshakes,
    reset: bool,
    socket: Option<(UdpSocket, SocketAddr)>,
    lookup: Option<Receiver<Vec<SocketAddr>>>,
    retry: Instant,
    backoff: Duration,
    tick: Instant,
}
impl Provider {
    fn new(profile: &EgressProfile, worker_pid: u32, now: Instant) -> Self {
        Self {
            profile: profile.clone(),
            worker_pid,
            handshakes: Handshakes::default(),
            reset: false,
            socket: None,
            lookup: None,
            retry: now,
            backoff: Duration::from_secs(1),
            tick: now,
        }
    }
    fn retry(&mut self, now: Instant) {
        self.reset |= self.socket.take().is_some();
        self.handshakes.unanswered = None;
        self.lookup = None;
        self.retry = now + self.backoff;
        self.backoff = (self.backoff * 2).min(Duration::from_secs(60));
    }
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        validate_external_endpoint(addr).map_err(|_| io::ErrorKind::InvalidInput)?;
        let socket = UdpSocket::bind(if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_nonblocking(true)?;
        socket.connect(addr)?;
        if addr.is_ipv4() {
            sockopt::set_ip_mtu_discover(&socket, sockopt::Ipv4PathMtuDiscovery::DO)?;
        } else {
            sockopt::set_ipv6_mtu_discover(&socket, sockopt::Ipv6PathMtuDiscovery::DO)?;
        }
        self.socket = Some((socket, addr));
        Ok(())
    }
    fn connect_resolved(&mut self, mut candidates: Vec<SocketAddr>) -> bool {
        candidates.sort_unstable();
        candidates.dedup();
        for _ in 0..candidates.len() {
            let addr = self.handshakes.next_address(&candidates);
            if self.connect(addr).is_ok() {
                return true;
            }
        }
        false
    }
    fn poll(&mut self, gateway: &mut LocalGateway, now: Instant) {
        if now >= self.tick
            && self.handshakes.unanswered.is_some()
            && self
                .handshakes
                .expired(now, gateway.provider_authenticated(&self.profile.id))
        {
            self.retry(now);
        }
        if self.socket.is_none() && now >= self.retry {
            let endpoint = self.profile.endpoint.to_string();
            if let Some(rx) = &self.lookup {
                let candidates = match rx.try_recv() {
                    Ok(candidates) => candidates,
                    Err(mpsc::TryRecvError::Empty) => return,
                    Err(mpsc::TryRecvError::Disconnected) => vec![],
                };
                self.lookup = None;
                if !self.connect_resolved(candidates) {
                    self.retry(now);
                    return;
                }
            } else if let Ok(addr) = endpoint.parse() {
                if self.connect(addr).is_err() {
                    self.retry(now);
                    return;
                }
            } else {
                let (reply, receive) = mpsc::sync_channel(1);
                if resolver().is_some_and(|pool| pool.try_send((endpoint, reply)).is_ok()) {
                    self.lookup = Some(receive)
                } else {
                    self.retry(now)
                }
                return;
            }
            gateway.clear_path_mtu(&self.profile.id);
        }
        if let Some((_, addr)) = &self.socket
            && now >= self.tick
        {
            let context = ContextId::External(self.profile.id.clone());
            if self.reset {
                if gateway.reset(&context, &PeerId::Provider).is_ok() {
                    self.reset = false
                }
                return;
            }
            let result =
                if gateway.endpoint(&context, &PeerId::Provider).ok().flatten() != Some(*addr) {
                    gateway.initiate_at(&context, &PeerId::Provider, *addr)
                } else {
                    gateway.tick(&context, &PeerId::Provider)
                };
            if result.is_ok() {
                self.tick = now + Duration::from_millis(250)
            }
        }
    }
    fn send(&mut self, gateway: &mut LocalGateway, output: &EncryptedDatagram) {
        let Some((socket, addr)) = &self.socket else {
            return;
        };
        if *addr != output.destination {
            return;
        }
        let bytes = output.packet.as_bytes();
        let Err(error) = socket.send(bytes) else {
            if bytes.starts_with(&[1, 0, 0, 0]) {
                self.handshakes.sent(Instant::now());
            }
            return;
        };
        self.socket_error(error, Instant::now(), |id, mtu| {
            gateway.set_path_mtu(id, mtu)
        });
    }
    // Linux can report an earlier UDP send's PMTU error on either send or recv.
    fn socket_error(
        &mut self,
        error: io::Error,
        now: Instant,
        set_path_mtu: impl FnOnce(&EgressId, u16),
    ) {
        if error.raw_os_error() == Some(rustix::io::Errno::MSGSIZE.raw_os_error()) {
            let Some((socket, addr)) = &self.socket else {
                return;
            };
            let mtu = if addr.is_ipv4() {
                sockopt::ip_mtu(socket)
            } else {
                sockopt::ipv6_mtu(socket)
            };
            // Account for outer IP, UDP, WireGuard and sixteen-byte padding.
            if let Ok(mtu) = mtu {
                let inner = mtu.saturating_sub(if addr.is_ipv4() { 60 } else { 80 }) / 16 * 16;
                set_path_mtu(&self.profile.id, inner.min(1280) as u16);
            }
        } else if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            self.retry(now);
        }
    }
}
pub(super) struct Runtime {
    providers: Vec<Provider>,
    cursor: usize,
    buffer: Box<[u8]>,
    expiry: Instant,
}
impl Runtime {
    pub fn new(gateway: &LocalGateway) -> Self {
        let mut runtime = Self {
            providers: vec![],
            cursor: 0,
            buffer: vec![0; wgfeel_wireguard::MAX_PROVIDER_DATAGRAM_SIZE + 1].into_boxed_slice(),
            expiry: Instant::now(),
        };
        runtime.configure(gateway);
        runtime
    }
    pub fn configure(&mut self, gateway: &LocalGateway) {
        let workers = gateway.workers();
        let projection = gateway.projection();
        let now = Instant::now();
        let mut old = std::mem::take(&mut self.providers);
        self.providers = projection
            .owned_egresses()
            .iter()
            .filter_map(|profile| {
                let worker = workers
                    .iter()
                    .find(|w| matches!(&w.context,ContextId::External(id) if id==&profile.id))?;
                Some(
                    old.iter()
                        .position(|p| {
                            p.worker_pid == worker.pid && same_provider_session(&p.profile, profile)
                        })
                        .map_or_else(
                            || Provider::new(profile, worker.pid, now),
                            |index| old.swap_remove(index),
                        ),
                )
            })
            .collect();
        self.cursor = 0;
    }
    pub fn append_fds<'a>(&'a self, fds: &mut Vec<BorrowedFd<'a>>) {
        fds.extend(
            self.providers
                .iter()
                .filter_map(|p| p.socket.as_ref().map(|(s, _)| s.as_fd())),
        );
    }
    pub fn failed(&mut self, context: &ContextId) {
        if let ContextId::External(id) = context {
            self.providers.retain(|p| p.profile.id != *id);
            self.cursor = 0;
        }
    }
    pub fn send(&mut self, gateway: &mut LocalGateway, output: EncryptedDatagram) {
        if let ContextId::External(id) = &output.context
            && let Some(p) = self.providers.iter_mut().find(|p| p.profile.id == *id)
        {
            p.send(gateway, &output)
        }
    }
    pub fn poll(&mut self, gateway: &mut LocalGateway) {
        let now = Instant::now();
        if now >= self.expiry {
            gateway.expire_translations(now);
            self.expiry = now + Duration::from_secs(1)
        }
        for p in &mut self.providers {
            p.poll(gateway, now)
        }
        let mut quiet = 0;
        let mut received = 0;
        while quiet < self.providers.len() && received < 32 {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % self.providers.len();
            let p = &mut self.providers[index];
            let Some((socket, source)) = &p.socket else {
                quiet += 1;
                continue;
            };
            match socket.recv(&mut self.buffer) {
                Ok(n) => {
                    p.backoff = Duration::from_secs(1);
                    received += 1;
                    quiet = 0;
                    if n <= wgfeel_wireguard::MAX_PROVIDER_DATAGRAM_SIZE
                        && let Ok(Some(output)) =
                            gateway.receive_provider(&p.profile.id, *source, &self.buffer[..n])
                    {
                        p.send(gateway, &output)
                    }
                }
                Err(err) => {
                    quiet += 1;
                    p.socket_error(err, now, |id, mtu| gateway.set_path_mtu(id, mtu));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> EgressProfile {
        use wgfeel_core::{DevicePublicKey, EgressId, EgressProfileFields};
        EgressProfileFields {
            id: EgressId::new("office").unwrap(),
            name: "Office".into(),
            node: None,
            pending_node: None,
            secret_revision: 1,
            interface_public_key: DevicePublicKey::new([41; 32]).unwrap(),
            addresses: vec!["172.16.0.6".parse().unwrap()],
            dns_servers: vec![],
            mtu: None,
            peer_public_key: DevicePublicKey::new([42; 32]).unwrap(),
            endpoint: "192.0.2.1:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
            has_preshared_key: false,
        }
        .try_into()
        .unwrap()
    }
    #[test]
    fn fresh_dns_answers_are_validated_again_after_an_existing_socket_is_retired() {
        let now = Instant::now();
        let mut provider = Provider::new(&test_profile(), 1, now);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(addr).unwrap();
        provider.socket = Some((socket, addr));
        provider.retry(now);
        // Inject a fresh reply for the same hostname after the original path failed.
        let reply = [
            "169.254.169.254:80",
            "127.0.0.2:51820",
            "[fe80::1]:51820",
            "[::ffff:169.254.169.254]:80",
        ];
        assert!(!provider.connect_resolved(reply.map(|s| s.parse().unwrap()).to_vec()));
        assert!(provider.socket.is_none());
    }
    #[test]
    fn asynchronous_message_size_error_updates_mtu_and_preserves_the_connection() {
        let profile = test_profile();
        let now = Instant::now();
        let mut provider = Provider::new(&profile, 1, now);
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let peer = UdpSocket::bind(bind).unwrap();
            let remote = peer.local_addr().unwrap();
            let socket = UdpSocket::bind(bind).unwrap();
            socket.connect(remote).unwrap();
            let local = socket.local_addr().unwrap();
            provider.socket = Some((socket, remote));
            provider.handshakes.sent(now);

            // Inject the pending error that Linux can surface on a later recv.
            let mut learned = None;
            provider.socket_error(rustix::io::Errno::MSGSIZE.into(), now, |id, mtu| {
                assert_eq!(id, &profile.id);
                learned = Some(mtu);
            });
            assert_eq!(learned, Some(1280)); // Loopback exceeds the inner cap.
            assert!(provider.handshakes.unanswered == Some(now) && !provider.reset);
            assert_eq!(provider.backoff, Duration::from_secs(1));
            let (socket, _) = provider.socket.as_ref().unwrap();
            socket.send(b"next").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut data = [0; 8];
            let (n, source) = peer.recv_from(&mut data).unwrap();
            assert_eq!(source, local);
            assert_eq!(&data[..n], b"next");
        }
    }

    #[test]
    fn silent_first_dns_candidate_yields_to_an_authenticated_second_candidate() {
        let addresses = [
            "192.0.2.1:51820".parse().unwrap(),
            "192.0.2.2:51820".parse().unwrap(),
        ];
        let now = Instant::now();
        let mut attempts = Handshakes::default();
        assert_eq!(attempts.next_address(&addresses), addresses[0]);
        attempts.sent(now);
        attempts.sent(now + Duration::from_secs(5));
        assert!(!attempts.expired(now + Duration::from_secs(5), None));
        assert!(attempts.expired(now + HANDSHAKE_WAIT, Some(now - Duration::from_millis(1))));
        assert_eq!(attempts.next_address(&addresses), addresses[1]);
        let retry = now + HANDSHAKE_WAIT + Duration::from_secs(1);
        attempts.sent(retry);
        assert!(!attempts.expired(retry + HANDSHAKE_WAIT, Some(retry + Duration::from_secs(1))));
        assert!(!attempts.expired(retry + Duration::from_secs(600), None));
    }
}
