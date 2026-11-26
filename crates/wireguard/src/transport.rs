use crate::{
    ContextId, DatagramEvent, ForwardError, Gateway, MAX_DATAGRAM_SIZE, PacketBytes, PeerId,
    UdpListener, WireGuardError,
};
use std::{
    fmt, io,
    net::{SocketAddr, UdpSocket},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Io,
    NotNetwork,
    WireGuard(WireGuardError),
    Forward(ForwardError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireGuard transport rejected: {self:?}")
    }
}
impl std::error::Error for TransportError {}

#[derive(Debug)]
pub enum UdpEvent {
    Sent {
        destination: SocketAddr,
        context: ContextId,
        peer: Option<PeerId>,
    },
    Plaintext {
        context: ContextId,
        peer: PeerId,
        packet: PacketBytes,
    },
}

#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpListener,
}

impl UdpTransport {
    pub(crate) fn from_listener(socket: UdpListener) -> Self {
        Self { socket }
    }
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpListener::bind(address)?,
        })
    }
    /// Take ownership of a bound socket and enable nonblocking I/O. Its clones,
    /// if any remain with the caller, share the nonblocking file status flag.
    pub fn from_socket(socket: UdpSocket) -> io::Result<Self> {
        Ok(Self {
            socket: UdpListener::from_socket(socket)?,
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    /// Consume at most one encrypted datagram through local forwarding policy.
    /// Successful output is encrypted; this path never emits plaintext to callers.
    pub fn poll_local(&self, gateway: &mut Gateway) -> Result<Option<UdpEvent>, TransportError> {
        if gateway.projection().is_none() {
            return Err(TransportError::Forward(ForwardError::MissingProjection));
        }
        self.poll_with(|source, bytes| {
            match gateway
                .receive_local_datagram(source, bytes)
                .map_err(TransportError::Forward)?
            {
                // Keep the public transport boundary encrypted-only even if a
                // future forwarding change accidentally returns a raw event.
                Some(DatagramEvent::Plaintext { .. }) => {
                    Err(TransportError::Forward(ForwardError::Denied))
                }
                event => Ok(event),
            }
        })
    }
    /// Consume at most one datagram. Encrypted responses use this same socket;
    /// authenticated inner bytes go only to the caller. None can mean either
    /// an empty socket or a consumed packet with no output (e.g. a keepalive).
    pub fn poll(&self, gateway: &mut Gateway) -> Result<Option<UdpEvent>, TransportError> {
        self.poll_with(|source, bytes| {
            gateway
                .receive_datagram(source, bytes)
                .map_err(TransportError::WireGuard)
        })
    }

    fn poll_with(
        &self,
        receive: impl FnOnce(SocketAddr, &[u8]) -> Result<Option<DatagramEvent>, TransportError>,
    ) -> Result<Option<UdpEvent>, TransportError> {
        // A truncated oversized UDP datagram still fills MAX+1, making it
        // distinguishable from any permitted packet before engine admission.
        let mut buffer = [0; MAX_DATAGRAM_SIZE + 1];
        let (length, source) = match self.socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(_) => return Err(TransportError::Io),
        };
        if length > MAX_DATAGRAM_SIZE {
            return Err(TransportError::WireGuard(WireGuardError::PacketTooLarge));
        }
        match receive(source, &buffer[..length])? {
            None => Ok(None),
            Some(DatagramEvent::Plaintext {
                context,
                peer,
                packet,
            }) => Ok(Some(UdpEvent::Plaintext {
                context,
                peer,
                packet,
            })),
            Some(DatagramEvent::Network {
                destination,
                context,
                peer,
                packet,
            }) => {
                self.send(destination, &packet)?;
                Ok(Some(UdpEvent::Sent {
                    destination,
                    context,
                    peer,
                }))
            }
        }
    }
    /// Send one encrypted event immediately, without a retry or payload queue.
    /// A send error may follow an already-accepted handshake; protocol timers
    /// remain the caller's responsibility and drive any required retransmission.
    pub fn transmit(&self, event: DatagramEvent) -> Result<(), TransportError> {
        match event {
            DatagramEvent::Network {
                destination,
                packet,
                ..
            } => self.send(destination, &packet),
            DatagramEvent::Plaintext { .. } => Err(TransportError::NotNetwork),
        }
    }

    fn send(&self, destination: SocketAddr, packet: &PacketBytes) -> Result<(), TransportError> {
        match self.socket.send_to(packet.as_bytes(), destination) {
            Ok(length) if length == packet.as_bytes().len() => Ok(()),
            _ => Err(TransportError::Io),
        }
    }
}
