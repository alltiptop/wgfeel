//! Per-tenant IP stack. Its only listening sockets are virtual UDP/TCP 53.
use super::resolver::MAX_MESSAGE;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::{tcp, udp},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{collections::VecDeque, time::Duration};
use wgfeel_core::{DNS_IPV4, DNS_IPV6};
use zeroize::Zeroizing;

const QUEUE: usize = 16;
const TCP_SOCKETS: usize = 4;
const MTU: usize = 1280;

pub(super) struct Packets {
    pub ingress: VecDeque<Zeroizing<Vec<u8>>>,
    pub egress: VecDeque<Zeroizing<Vec<u8>>>,
}
pub(super) struct Rx(Zeroizing<Vec<u8>>);
pub(super) struct Tx<'a>(&'a mut VecDeque<Zeroizing<Vec<u8>>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = Zeroizing::new(vec![0; len]);
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl phy::Device for Packets {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.egress.len() >= QUEUE {
            return None;
        }
        Some((Rx(self.ingress.pop_front()?), Tx(&mut self.egress)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        (self.egress.len() < QUEUE).then_some(Tx(&mut self.egress))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(QUEUE);
        caps
    }
}

#[derive(Clone, Copy)]
pub(super) enum Target {
    Udp {
        remote: IpEndpoint,
        local: IpAddress,
    },
    Tcp {
        slot: usize,
        session: u64,
    },
}
pub(super) struct Request {
    pub target: Target,
    pub source: IpAddress,
    pub bytes: Vec<u8>,
}
struct Stream {
    handle: SocketHandle,
    session: u64,
    waiting: bool,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    touched: Duration,
}
pub(super) struct Stack {
    interface: Interface,
    sockets: SocketSet<'static>,
    udp: SocketHandle,
    streams: Vec<Stream>,
    pub packets: Packets,
}
fn clock(now: Duration) -> Instant {
    Instant::from_micros(now.as_micros().min((i64::MAX / 2) as u128) as i64)
}
impl Stack {
    pub fn new(seed: u64) -> Self {
        let mut packets = Packets {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut interface = Interface::new(config, &mut packets, Instant::ZERO);
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(DNS_IPV4.into(), 32))
                .expect("two IPs fit");
            ips.push(IpCidr::new(DNS_IPV6.into(), 128))
                .expect("two IPs fit");
        });
        // Medium::Ip needs no neighbor resolution. Source-bound admission and
        // output validation enforce exact client routes, including custom IPs.
        interface
            .routes_mut()
            .add_default_ipv4_route(DNS_IPV4)
            .expect("route capacity");
        interface
            .routes_mut()
            .add_default_ipv6_route(DNS_IPV6)
            .expect("route capacity");
        let mut sockets = SocketSet::new(Vec::new());
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE],
                vec![0; QUEUE * MTU],
            )
        };
        let mut udp = udp::Socket::new(buffer(), buffer());
        udp.bind(53).expect("fresh socket");
        let udp = sockets.add(udp);
        let streams = (0..TCP_SOCKETS)
            .map(|_| {
                let mut tcp = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; MAX_MESSAGE + 2]),
                    tcp::SocketBuffer::new(vec![0; MAX_MESSAGE + 2]),
                );
                tcp.set_ack_delay(None);
                tcp.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
                Stream {
                    handle: sockets.add(tcp),
                    session: 0,
                    waiting: false,
                    input: Vec::new(),
                    output: Vec::new(),
                    written: 0,
                    touched: Duration::ZERO,
                }
            })
            .collect();
        Self {
            interface,
            sockets,
            udp,
            streams,
            packets,
        }
    }
    pub fn receive(&mut self, bytes: &[u8]) {
        if bytes.len() <= MTU && self.packets.ingress.len() < QUEUE {
            self.packets
                .ingress
                .push_back(Zeroizing::new(bytes.to_vec()));
        }
    }
    pub fn poll(&mut self, now: Duration) -> Vec<Request> {
        let time = clock(now);
        for stream in &mut self.streams {
            let socket = self.sockets.get_mut::<tcp::Socket>(stream.handle);
            if socket.is_open()
                && !socket.is_listening()
                && now.saturating_sub(stream.touched) > Duration::from_secs(10)
            {
                socket.abort();
            }
            if !socket.is_open() {
                stream.session = stream.session.wrapping_add(1);
                stream.waiting = false;
                stream.input.clear();
                stream.output.clear();
                stream.written = 0;
                let _ = socket.listen(53);
            }
            if socket.is_listening() {
                stream.touched = now;
            }
        }
        self.interface.poll_maintenance(time);
        for _ in 0..QUEUE {
            self.interface
                .poll_ingress_single(time, &mut self.packets, &mut self.sockets);
        }
        let mut requests = Vec::new();
        let udp = self.sockets.get_mut::<udp::Socket>(self.udp);
        for _ in 0..8 {
            let Ok((bytes, meta)) = udp.recv() else {
                break;
            };
            if let Some(local) = meta.local_address {
                requests.push(Request {
                    source: meta.endpoint.addr,
                    target: Target::Udp {
                        remote: meta.endpoint,
                        local,
                    },
                    bytes: bytes.to_vec(),
                });
            }
        }
        for (slot, stream) in self.streams.iter_mut().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(stream.handle);
            if socket.can_send() && stream.written < stream.output.len() {
                if let Ok(count) = socket.send_slice(&stream.output[stream.written..]) {
                    stream.written += count;
                    stream.touched = now;
                }
                if stream.written == stream.output.len() {
                    stream.output.clear();
                    stream.written = 0;
                    stream.waiting = false;
                }
            }
            if stream.waiting {
                continue;
            }
            if socket.can_recv() {
                let _ = socket.recv(|bytes| {
                    let count = bytes.len().min(MAX_MESSAGE + 2 - stream.input.len());
                    stream.input.extend_from_slice(&bytes[..count]);
                    (count, ())
                });
            }
            if stream.input.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([stream.input[0], stream.input[1]]));
                if !(12..=MAX_MESSAGE).contains(&len) {
                    socket.abort();
                    continue;
                }
                if stream.input.len() >= len + 2 {
                    let bytes = stream.input[2..len + 2].to_vec();
                    stream.input.drain(..len + 2);
                    if let Some(remote) = socket.remote_endpoint() {
                        stream.waiting = true;
                        stream.touched = now;
                        requests.push(Request {
                            target: Target::Tcp {
                                slot,
                                session: stream.session,
                            },
                            source: remote.addr,
                            bytes,
                        });
                    }
                }
            }
            if socket.state() == tcp::State::CloseWait && !stream.waiting && stream.input.is_empty()
            {
                socket.close();
            }
        }
        self.interface
            .poll_egress(time, &mut self.packets, &mut self.sockets);
        requests
    }
    pub fn discard(&mut self, target: Target) {
        if let Target::Tcp { slot, session } = target {
            let stream = &self.streams[slot];
            if stream.session == session && stream.waiting {
                self.sockets.get_mut::<tcp::Socket>(stream.handle).abort();
            }
        }
    }
    pub fn reply(&mut self, target: Target, bytes: &[u8]) {
        match target {
            Target::Udp { remote, local } => {
                let meta = udp::UdpMetadata {
                    endpoint: remote,
                    local_address: Some(local),
                    meta: Default::default(),
                };
                let _ = self
                    .sockets
                    .get_mut::<udp::Socket>(self.udp)
                    .send_slice(bytes, meta);
            }
            Target::Tcp { slot, session } => {
                let stream = &mut self.streams[slot];
                if stream.session != session || !stream.waiting || !stream.output.is_empty() {
                    return;
                }
                stream
                    .output
                    .extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                stream.output.extend_from_slice(bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discarded_tcp_request_releases_its_own_session_on_the_next_poll() {
        let mut stack = Stack::new(42);
        stack.poll(Duration::ZERO);
        let stream = &mut stack.streams[0];
        stream.waiting = true;
        let session = stream.session;
        let handle = stream.handle;
        stack.discard(Target::Tcp {
            slot: 0,
            session: session.wrapping_sub(1),
        });
        assert!(stack.sockets.get::<tcp::Socket>(handle).is_open());
        stack.discard(Target::Tcp { slot: 0, session });
        assert!(!stack.sockets.get::<tcp::Socket>(handle).is_open());
        stack.poll(Duration::from_millis(1));
        assert!(stack.sockets.get::<tcp::Socket>(handle).is_listening());
        assert!(!stack.streams[0].waiting);
        assert_ne!(stack.streams[0].session, session);
    }
}
