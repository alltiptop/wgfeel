//! One nonblocking UDP port for both outer IP families. Mapped IPv4 addresses
//! are a socket implementation detail and never enter authentication/routing.
use std::{
    collections::VecDeque,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::{AsFd, BorrowedFd},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

type Datagram = (SocketAddr, Vec<u8>);
#[derive(Debug)]
struct ControlInbox {
    index: AtomicU64,
    packets: Mutex<VecDeque<Datagram>>,
}
// Two enrollment proofs and four withdrawal workers may use the shared port.
const MAX_CONTROL_EXCHANGES: usize = 6;
const CONTROL_QUEUE: usize = 32;

#[derive(Debug)]
pub struct UdpListener {
    socket: UdpSocket,
    ipv4: bool,
    ipv6: bool,
    report_ipv4: bool,
    routes: Vec<Weak<ControlInbox>>,
    inbox: Option<Arc<ControlInbox>>,
}
impl UdpListener {
    /// Wildcards accept both families, independently of the host v6only default.
    /// A concrete bind address deliberately restricts reception to that address.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        if !address.ip().is_unspecified() {
            return Self::from_socket(UdpSocket::bind(address)?);
        }
        use rustix::net::{self, AddressFamily, SocketFlags, SocketType, ipproto, sockopt};
        let socket = match net::socket_with(
            AddressFamily::INET6,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(ipproto::UDP),
        ) {
            Ok(socket) => socket,
            // IPv4-only hosts still run; other bind/configuration failures must
            // remain visible rather than silently reducing listener scope.
            Err(rustix::io::Errno::AFNOSUPPORT) if address.is_ipv4() => {
                return Self::from_socket(UdpSocket::bind(address)?);
            }
            Err(error) => return Err(error.into()),
        };
        sockopt::set_ipv6_v6only(&socket, false)?;
        net::bind(
            &socket,
            &SocketAddr::from((Ipv6Addr::UNSPECIFIED, address.port())),
        )?;
        Ok(Self {
            socket: socket.into(),
            ipv4: true,
            ipv6: true,
            report_ipv4: address.is_ipv4(),
            routes: vec![],
            inbox: None,
        })
    }
    pub fn from_socket(socket: UdpSocket) -> io::Result<Self> {
        let local = socket.local_addr()?;
        let ipv6 = local.is_ipv6();
        let ipv4 =
            !ipv6 || (local.ip().is_unspecified() && !rustix::net::sockopt::ipv6_v6only(&socket)?);
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            ipv4,
            ipv6,
            report_ipv4: false,
            routes: vec![],
            inbox: None,
        })
    }
    /// The main event loop remains the only kernel socket reader. A short-lived
    /// control initiator sends through the same bound socket and gets copies
    /// of replies addressed to its handshake index. Both engines still perform
    /// full authentication, including if their independently chosen indices collide.
    pub fn control_transport(&mut self) -> io::Result<crate::UdpTransport> {
        self.routes.retain(|route| route.strong_count() != 0);
        if self.inbox.is_some() || self.routes.len() >= MAX_CONTROL_EXCHANGES {
            return Err(io::Error::other("control transport capacity reached"));
        }
        let socket = self.socket.try_clone()?;
        let inbox = Arc::new(ControlInbox {
            index: AtomicU64::new(u64::MAX),
            packets: Mutex::new(VecDeque::with_capacity(CONTROL_QUEUE)),
        });
        self.routes.push(Arc::downgrade(&inbox));
        Ok(crate::UdpTransport::from_listener(Self {
            socket,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            report_ipv4: self.report_ipv4,
            routes: vec![],
            inbox: Some(inbox),
        }))
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let address = self.socket.local_addr()?;
        Ok(if self.report_ipv4 {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, address.port()))
        } else {
            address
        })
    }
    pub fn supports_endpoint(&self, endpoint: SocketAddr) -> bool {
        if endpoint.is_ipv4() {
            self.ipv4
        } else {
            self.ipv6
        }
    }
    pub fn recv_from(&self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if let Some(inbox) = &self.inbox {
            let (source, packet) = inbox
                .packets
                .lock()
                .map_err(|_| io::Error::other("control queue unavailable"))?
                .pop_front()
                .ok_or(io::ErrorKind::WouldBlock)?;
            let len = bytes.len().min(packet.len());
            bytes[..len].copy_from_slice(&packet[..len]);
            return Ok((len, source));
        }
        let (length, mut source) = self.socket.recv_from(bytes)?;
        if let SocketAddr::V6(address) = source
            && let Some(ip) = address.ip().to_ipv4_mapped()
        {
            source = SocketAddr::from((ip, address.port()));
        }
        if !self.routes.is_empty()
            && let Ok(Some(index)) = crate::framing::receiver_index(&bytes[..length])
        {
            for inbox in self.routes.iter().filter_map(Weak::upgrade) {
                if inbox.index.load(Ordering::Acquire) == u64::from(index)
                    && let Ok(mut queue) = inbox.packets.try_lock()
                    && queue.len() < CONTROL_QUEUE
                {
                    queue.push_back((source, bytes[..length].to_vec()));
                }
            }
        }
        Ok((length, source))
    }
    pub fn send_to(&self, bytes: &[u8], mut destination: SocketAddr) -> io::Result<usize> {
        if let Some(inbox) = &self.inbox
            && bytes.len() == 148
            && bytes.starts_with(&[1, 0, 0, 0])
        {
            let index = u32::from_le_bytes(bytes[4..8].try_into().expect("handshake sender index"));
            inbox.index.store(u64::from(index), Ordering::Release);
        }
        if self.ipv6
            && let SocketAddr::V4(address) = destination
        {
            destination = SocketAddr::from((address.ip().to_ipv6_mapped(), address.port()));
        }
        self.socket.send_to(bytes, destination)
    }
}
impl AsFd for UdpListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}
