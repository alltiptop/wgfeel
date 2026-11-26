//! Bounded in-memory IPv4/TCP transport for the encrypted Management API.
//!
//! These endpoints accept only the fixed administrator/server IP pair. The
//! caller must authenticate WireGuard before supplying packets here. They do
//! not open host sockets, and a successful TCP exchange is not authentication.
use crate::{Handler, Response, http};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket},
};
use std::{collections::VecDeque, fmt, time::Duration};
use zeroize::{Zeroize, Zeroizing};

pub const SERVER_IP: [u8; 4] = [10, 253, 0, 1];
pub const ADMIN_IP: [u8; 4] = [10, 253, 0, 2];
pub const API_PORT: u16 = 80;
pub const MTU: usize = 1280;
pub const SERVER_SOCKETS: usize = 8;
pub const MAX_PACKET_QUEUE: usize = 16;
/// The sender and pinned-authority receiver use the same inactivity budget.
pub const DISTRIBUTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_BUFFER_BYTES: usize = 16_384;
const MAX_REQUEST_BYTES: usize = crate::MAX_REQUEST_BODY + http::MAX_HEADER_BYTES;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    InvalidConfiguration,
    InvalidPacket,
    QueueFull,
    InvalidTime,
    Timeout,
    Closed,
    Http(u16),
}
impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Management TCP error: {self:?}")
    }
}
impl std::error::Error for TcpError {}

struct SocketBuffers {
    rx: Zeroizing<Vec<u8>>,
    tx: Zeroizing<Vec<u8>>,
}
/// Storage outlives the borrowed smoltcp sockets, and is erased on drop.
/// Construct eight slots for a server or one for a client.
pub struct Buffers {
    sockets: Vec<SocketBuffers>,
}
impl Buffers {
    pub fn new(socket_count: usize) -> Result<Self, TcpError> {
        if !(1..=SERVER_SOCKETS).contains(&socket_count) {
            return Err(TcpError::InvalidConfiguration);
        }
        Ok(Self {
            sockets: (0..socket_count)
                .map(|_| SocketBuffers {
                    rx: Zeroizing::new(vec![0; SOCKET_BUFFER_BYTES]),
                    tx: Zeroizing::new(vec![0; SOCKET_BUFFER_BYTES]),
                })
                .collect(),
        })
    }
}

struct PacketDevice {
    ingress: VecDeque<Zeroizing<Vec<u8>>>,
    egress: VecDeque<Zeroizing<Vec<u8>>>,
}
impl PacketDevice {
    fn new() -> Self {
        Self {
            ingress: VecDeque::with_capacity(MAX_PACKET_QUEUE),
            egress: VecDeque::with_capacity(MAX_PACKET_QUEUE),
        }
    }
    fn receive_packet(&mut self, frame: &[u8]) -> Result<(), TcpError> {
        if self.ingress.len() == MAX_PACKET_QUEUE {
            return Err(TcpError::QueueFull);
        }
        // Allocate once before copying any plaintext or credential bytes.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MTU));
        bytes.extend_from_slice(frame);
        self.ingress.push_back(bytes);
        Ok(())
    }
}
struct RxToken(Zeroizing<Vec<u8>>);
struct TxToken<'a>(&'a mut VecDeque<Zeroizing<Vec<u8>>>);
impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp derives outgoing segment sizes from this device's MTU.
        let mut packet = Zeroizing::new(Vec::with_capacity(MTU));
        packet.resize(len, 0);
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl phy::Device for PacketDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;
    fn receive(&mut self, _now: Instant) -> Option<(RxToken, TxToken<'_>)> {
        if self.egress.len() == MAX_PACKET_QUEUE {
            return None;
        }
        let packet = self.ingress.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.egress)))
    }
    fn transmit(&mut self, _now: Instant) -> Option<TxToken<'_>> {
        (self.egress.len() < MAX_PACKET_QUEUE).then_some(TxToken(&mut self.egress))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(MAX_PACKET_QUEUE);
        caps
    }
}

struct Stack<'a> {
    interface: Interface,
    sockets: SocketSet<'a>,
    handles: Vec<SocketHandle>,
    device: PacketDevice,
    last_time: Option<Duration>,
}
impl<'a> Stack<'a> {
    fn new(buffers: &'a mut Buffers, seed: u64, local: [u8; 4]) -> Self {
        let mut device = PacketDevice::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(local)), 24))
                .expect("one fixed IP fits the interface");
        });
        let mut sockets = SocketSet::new(Vec::with_capacity(buffers.sockets.len()));
        let mut handles = Vec::with_capacity(buffers.sockets.len());
        for storage in &mut buffers.sockets {
            // Reusing Buffers after dropping a prior endpoint erases its rings.
            storage.rx.as_mut_slice().zeroize();
            storage.tx.as_mut_slice().zeroize();
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(&mut storage.rx[..]),
                tcp::SocketBuffer::new(&mut storage.tx[..]),
            );
            socket.set_ack_delay(None);
            handles.push(sockets.add(socket));
        }
        Self {
            interface,
            sockets,
            handles,
            device,
            last_time: None,
        }
    }
    fn clock(&mut self, now: Duration) -> Result<Instant, TcpError> {
        // Leave headroom for smoltcp's signed timer arithmetic.
        let micros = i64::try_from(now.as_micros()).map_err(|_| TcpError::InvalidTime)?;
        if micros > i64::MAX - 3_600_000_000 || self.last_time.is_some_and(|last| now < last) {
            return Err(TcpError::InvalidTime);
        }
        self.last_time = Some(now);
        Ok(Instant::from_micros(micros))
    }
    fn ingress(&mut self, time: Instant) {
        self.interface.poll_maintenance(time);
        self.interface
            .poll_ingress_single(time, &mut self.device, &mut self.sockets);
    }
    fn egress(&mut self, time: Instant) {
        self.interface
            .poll_egress(time, &mut self.device, &mut self.sockets);
    }
}

fn validate_packet(
    frame: &[u8],
    source: [u8; 4],
    destination: [u8; 4],
    source_port: Option<u16>,
    destination_port: u16,
) -> Result<(), TcpError> {
    if frame.len() > MTU {
        return Err(TcpError::InvalidPacket);
    }
    let ip = Ipv4Packet::new_checked(frame).map_err(|_| TcpError::InvalidPacket)?;
    if ip.version() != 4
        || ip.header_len() != 20
        || usize::from(ip.total_len()) != frame.len()
        || ip.next_header() != IpProtocol::Tcp
        || ip.hop_limit() == 0
        || ip.more_frags()
        || ip.frag_offset() != 0
        || frame[6] & 0x80 != 0
        || ip.src_addr() != Ipv4Address::from(source)
        || ip.dst_addr() != Ipv4Address::from(destination)
        || !ip.verify_checksum()
    {
        return Err(TcpError::InvalidPacket);
    }
    let tcp = TcpPacket::new_checked(ip.payload()).map_err(|_| TcpError::InvalidPacket)?;
    if tcp.src_port() == 0
        || source_port.is_some_and(|port| tcp.src_port() != port)
        || tcp.dst_port() != destination_port
        || !tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into())
    {
        return Err(TcpError::InvalidPacket);
    }
    Ok(())
}

fn erase(bytes: &mut Zeroizing<Vec<u8>>) {
    // Clear only after erasing: a Vec's dropped length otherwise hides bytes.
    bytes.as_mut_slice().zeroize();
    bytes.clear();
}

struct Connection {
    started: Option<Duration>,
    last_received: Option<Duration>,
    request: Zeroizing<Vec<u8>>,
    response: Option<Zeroizing<Vec<u8>>>,
    sent: usize,
}
impl Connection {
    fn new(maximum: usize) -> Self {
        Self {
            started: None,
            last_received: None,
            request: Zeroizing::new(Vec::with_capacity(maximum)),
            response: None,
            sent: 0,
        }
    }
    fn reset(&mut self) {
        self.started = None;
        self.last_received = None;
        erase(&mut self.request);
        self.response = None;
        self.sent = 0;
    }
    fn respond(&mut self, response: Response) {
        let encoded = http::encode_response(&response);
        self.response = Some(if encoded.len() <= http::MAX_RESPONSE_BYTES {
            encoded
        } else {
            http::encode_response(&Response::error(500, "response_too_large"))
        });
        erase(&mut self.request);
    }
}

pub struct Server<'a> {
    stack: Stack<'a>,
    connections: Vec<Connection>,
    maximum: usize,
    request_timeout: Duration,
    total_timeout: Duration,
    idle_timeout: Option<Duration>,
}
impl<'a> Server<'a> {
    pub fn new(buffers: &'a mut Buffers, seed: u64) -> Result<Self, TcpError> {
        if buffers.sockets.len() != SERVER_SOCKETS {
            return Err(TcpError::InvalidConfiguration);
        }
        Self::configured(
            buffers,
            seed,
            MAX_REQUEST_BYTES,
            REQUEST_TIMEOUT,
            TOTAL_TIMEOUT,
        )
    }
    pub fn distribution(buffers: &'a mut Buffers, seed: u64) -> Result<Self, TcpError> {
        if buffers.sockets.len() != 1 {
            return Err(TcpError::InvalidConfiguration);
        }
        let mut server = Self::configured(
            buffers,
            seed,
            wgfeel_core::MAX_DELIVERY_BYTES + http::MAX_HEADER_BYTES,
            Duration::from_secs(60),
            Duration::from_secs(90),
        )?;
        server.idle_timeout = Some(DISTRIBUTION_IDLE_TIMEOUT);
        Ok(server)
    }
    /// One isolated, small HTTP stream for a temporary enrollment capability.
    pub fn enrollment(buffers: &'a mut Buffers, seed: u64) -> Result<Self, TcpError> {
        if buffers.sockets.len() != 1 {
            return Err(TcpError::InvalidConfiguration);
        }
        Self::configured(
            buffers,
            seed,
            crate::enrollment::MAX_ENROLLMENT_BODY + http::MAX_HEADER_BYTES,
            REQUEST_TIMEOUT,
            TOTAL_TIMEOUT,
        )
    }
    fn configured(
        buffers: &'a mut Buffers,
        seed: u64,
        maximum: usize,
        request_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, TcpError> {
        let count = buffers.sockets.len();
        let mut stack = Stack::new(buffers, seed, SERVER_IP);
        for handle in &stack.handles {
            stack
                .sockets
                .get_mut::<tcp::Socket>(*handle)
                .listen(API_PORT)
                .map_err(|_| TcpError::InvalidConfiguration)?;
        }
        Ok(Self {
            stack,
            connections: (0..count).map(|_| Connection::new(maximum)).collect(),
            maximum,
            request_timeout,
            total_timeout,
            idle_timeout: None,
        })
    }
    pub fn receive(&mut self, frame: &[u8]) -> Result<(), TcpError> {
        validate_packet(frame, ADMIN_IP, SERVER_IP, None, API_PORT)?;
        self.stack.device.receive_packet(frame)
    }
    /// Erase a single-peer stream before reassigning its storage to another
    /// authenticated peer. No queued request or response crosses identities.
    pub fn reset_session(&mut self) -> Result<(), TcpError> {
        if self.stack.handles.len() != 1 {
            return Err(TcpError::InvalidConfiguration);
        }
        self.reset_connections()
    }
    /// Retire every stream when the underlying WireGuard context is replaced.
    pub fn reset_connections(&mut self) -> Result<(), TcpError> {
        self.stack.device.ingress.clear();
        self.stack.device.egress.clear();
        for (connection, handle) in self.connections.iter_mut().zip(&self.stack.handles) {
            connection.reset();
            let socket = self.stack.sockets.get_mut::<tcp::Socket>(*handle);
            socket.abort();
            socket.listen(API_PORT).map_err(|_| TcpError::Closed)?;
        }
        Ok(())
    }
    /// Process at most one received IP packet, each of eight bounded HTTP
    /// streams once, and bounded socket egress. Time must never move backwards.
    pub fn poll(&mut self, now: Duration, service: &mut impl Handler) -> Result<(), TcpError> {
        self.poll_with(now, |request| service.handle(request))
    }
    pub fn poll_with(
        &mut self,
        now: Duration,
        mut handler: impl FnMut(crate::Request<'_>) -> Response,
    ) -> Result<(), TcpError> {
        let time = self.stack.clock(now)?;
        self.stack.ingress(time);
        for (handle, connection) in self.stack.handles.iter().zip(&mut self.connections) {
            let socket = self.stack.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.is_active() {
                connection.started.get_or_insert(now);
            }
            let expired = connection.started.is_some_and(|started| {
                now - started >= self.total_timeout
                    || (connection.response.is_none() && now - started >= self.request_timeout)
                    || self.idle_timeout.is_some_and(|limit| {
                        now - connection.last_received.unwrap_or(started) >= limit
                    })
            });
            if expired {
                socket.abort();
            }
            if !socket.is_open() {
                connection.reset();
                socket.listen(API_PORT).map_err(|_| TcpError::Closed)?;
                continue;
            }
            if connection.response.is_none() && socket.can_recv() {
                connection.last_received = Some(now);
                // At most one ring slice (<=16KiB) per connection per poll.
                let overflow = socket
                    .recv(|bytes| {
                        if bytes.len() > self.maximum - connection.request.len() {
                            (bytes.len(), true)
                        } else {
                            connection.request.extend_from_slice(bytes);
                            (bytes.len(), false)
                        }
                    })
                    .map_err(|_| TcpError::Closed)?;
                if overflow {
                    connection.respond(Response::error(413, "request_too_large"));
                } else {
                    match http::decode_request_with_limit(
                        &connection.request,
                        self.maximum - http::MAX_HEADER_BYTES,
                    ) {
                        Ok(Some(request)) => {
                            let response = handler(request);
                            connection.respond(response);
                        }
                        Ok(None) => {}
                        Err(http::HttpError(status)) => {
                            connection.respond(Response::error(status, "invalid_http"));
                        }
                    }
                }
            }
            if let Some(response) = &connection.response {
                if socket.can_send() && connection.sent < response.len() {
                    connection.sent += socket
                        .send_slice(&response[connection.sent..])
                        .map_err(|_| TcpError::Closed)?;
                }
                if connection.sent == response.len() {
                    socket.close();
                }
            } else if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                socket.abort();
            }
        }
        self.stack.egress(time);
        Ok(())
    }
    pub fn take_packet(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.stack.device.egress.pop_front()
    }
}

pub struct Client<'a> {
    stack: Stack<'a>,
    port: u16,
    started: Option<Duration>,
    request: Zeroizing<Vec<u8>>,
    sent: usize,
    response: Zeroizing<Vec<u8>>,
    result: Option<Result<Response, TcpError>>,
    finished: bool,
    timeout: Duration,
}
impl<'a> Client<'a> {
    pub fn new(
        buffers: &'a mut Buffers,
        seed: u64,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Self, TcpError> {
        Self::configured(buffers, seed, request, MAX_REQUEST_BYTES, TOTAL_TIMEOUT)
    }
    pub fn distribution(
        buffers: &'a mut Buffers,
        seed: u64,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Self, TcpError> {
        Self::configured(
            buffers,
            seed,
            request,
            wgfeel_core::MAX_DELIVERY_BYTES + http::MAX_HEADER_BYTES,
            Duration::from_secs(90),
        )
    }
    fn configured(
        buffers: &'a mut Buffers,
        seed: u64,
        request: Zeroizing<Vec<u8>>,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Self, TcpError> {
        if buffers.sockets.len() != 1 || request.is_empty() || request.len() > maximum {
            return Err(TcpError::InvalidConfiguration);
        }
        Ok(Self {
            stack: Stack::new(buffers, seed, ADMIN_IP),
            port: 49_152 + (seed % 16_384) as u16,
            started: None,
            request,
            sent: 0,
            response: Zeroizing::new(Vec::with_capacity(http::MAX_RESPONSE_BYTES)),
            result: None,
            finished: false,
            timeout,
        })
    }
    pub fn receive(&mut self, frame: &[u8]) -> Result<(), TcpError> {
        validate_packet(frame, SERVER_IP, ADMIN_IP, Some(API_PORT), self.port)?;
        self.stack.device.receive_packet(frame)
    }
    pub fn poll(&mut self, now: Duration) -> Result<(), TcpError> {
        let time = self.stack.clock(now)?;
        let handle = self.stack.handles[0];
        if self.started.is_none() {
            // Set the interface clock before connect initializes TCP timers.
            self.stack.interface.poll_maintenance(time);
            self.stack
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(
                    self.stack.interface.context(),
                    (IpAddress::Ipv4(Ipv4Address::from(SERVER_IP)), API_PORT),
                    self.port,
                )
                .map_err(|_| TcpError::InvalidConfiguration)?;
            self.started = Some(now);
        }
        self.stack.ingress(time);
        let socket = self.stack.sockets.get_mut::<tcp::Socket>(handle);
        if !self.finished && now - self.started.expect("initialized above") >= self.timeout {
            self.result = Some(Err(TcpError::Timeout));
            self.finished = true;
            socket.abort();
        }
        if !self.finished {
            if socket.can_send() && self.sent < self.request.len() {
                self.sent += socket
                    .send_slice(&self.request[self.sent..])
                    .map_err(|_| TcpError::Closed)?;
            }
            if socket.can_recv() {
                let overflow = socket
                    .recv(|bytes| {
                        if bytes.len() > http::MAX_RESPONSE_BYTES - self.response.len() {
                            (bytes.len(), true)
                        } else {
                            self.response.extend_from_slice(bytes);
                            (bytes.len(), false)
                        }
                    })
                    .map_err(|_| TcpError::Closed)?;
                match if overflow {
                    Err(http::HttpError(413))
                } else {
                    http::decode_response(&self.response)
                } {
                    Ok(Some(response)) => {
                        self.result = Some(Ok(response));
                        self.finished = true;
                        socket.close();
                    }
                    Ok(None) => {}
                    Err(http::HttpError(status)) => {
                        self.result = Some(Err(TcpError::Http(status)));
                        self.finished = true;
                        socket.abort();
                    }
                }
            }
            if !self.finished
                && matches!(socket.state(), tcp::State::Closed | tcp::State::CloseWait)
                && !socket.can_recv()
            {
                self.result = Some(Err(TcpError::Closed));
                self.finished = true;
                socket.abort();
            }
        }
        if self.finished {
            erase(&mut self.request);
            erase(&mut self.response);
        }
        self.stack.egress(time);
        Ok(())
    }
    pub fn take_packet(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.stack.device.egress.pop_front()
    }
    pub fn take_response(&mut self) -> Option<Result<Response, TcpError>> {
        self.result.take()
    }
}

#[cfg(test)]
mod tests;
