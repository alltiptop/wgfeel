use super::{BATCH, Timer, dns, egress, mesh, send};
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};
use wgfeel_wireguard::{
    ContextId, MAX_DATAGRAM_SIZE, UdpListener,
    worker::{LocalError, LocalGateway, WorkerError},
};

pub(super) struct Forwarding {
    pub(super) mesh: mesh::Runtime,
    pub(super) egress: egress::Runtime,
    pub(super) dns: dns::Runtime,
    incoming: VecDeque<(SocketAddr, Vec<u8>, Instant)>,
    buffer: Box<[u8; MAX_DATAGRAM_SIZE + 1]>,
    ingress_first: bool,
}

impl Forwarding {
    pub(super) fn new(gateway: &LocalGateway) -> Result<Self, &'static str> {
        Ok(Self {
            mesh: mesh::Runtime::new(gateway.projection())?,
            egress: egress::Runtime::new(gateway),
            dns: dns::Runtime::default(),
            incoming: VecDeque::with_capacity(64),
            buffer: Box::new([0; MAX_DATAGRAM_SIZE + 1]),
            ingress_first: false,
        })
    }

    pub(super) fn clear_ingress(&mut self) {
        self.incoming.clear();
    }

    pub(super) fn worker_failed<'a>(
        &mut self,
        context: &ContextId,
        timers: impl IntoIterator<Item = &'a mut Timer>,
    ) {
        if *context == ContextId::Gateway {
            self.mesh.clear_broadcast_assemblies();
        }
        self.egress.failed(context);
        for timer in timers {
            if timer.context == *context {
                timer.failed = true;
            }
        }
    }

    // Alternate which source can claim the worker before control traffic.
    pub(super) fn begin_turn(
        &mut self,
        socket: &UdpListener,
        gateway: &mut LocalGateway,
    ) -> Result<(), &'static str> {
        self.ingress_first = !self.ingress_first;
        self.admit(self.ingress_first, socket, gateway)
    }

    pub(super) fn finish_turn<'a>(
        &mut self,
        socket: &UdpListener,
        gateway: &mut LocalGateway,
        started: Instant,
        timers: impl IntoIterator<Item = &'a mut Timer>,
    ) -> Result<(), &'static str> {
        self.egress.poll(gateway);
        self.mesh.poll(gateway, socket, started.elapsed());
        self.dns.poll(gateway, started.elapsed());
        let now = Instant::now();
        for timer in timers {
            timer.tick(gateway, now);
        }
        self.admit(!self.ingress_first, socket, gateway)
    }

    fn admit(
        &mut self,
        ingress: bool,
        socket: &UdpListener,
        gateway: &mut LocalGateway,
    ) -> Result<(), &'static str> {
        if ingress {
            receive(socket, gateway, self.buffer.as_mut(), &mut self.incoming)
        } else {
            gateway.advance_broadcast();
            Ok(())
        }
    }
}

fn receive(
    socket: &UdpListener,
    gateway: &mut LocalGateway,
    buffer: &mut [u8],
    incoming: &mut VecDeque<(SocketAddr, Vec<u8>, Instant)>,
) -> Result<(), &'static str> {
    // A worker accepts one operation at a time. Preserve bounded encrypted
    // bursts (notably two relay fragments) rather than deterministically losing
    // every second datagram. Authentication and current policy are checked when
    // processing each entry; no plaintext or prior authorization is queued.
    for _ in 0..incoming.len().min(BATCH) {
        let (source, packet, deadline) = incoming.pop_front().expect("bounded ingress");
        if Instant::now() >= deadline {
            continue;
        }
        match gateway.receive_datagram(source, &packet) {
            Ok(Some(datagram)) => send(socket, datagram),
            Err(LocalError::Worker(WorkerError::Busy)) => {
                incoming.push_back((source, packet, deadline))
            }
            _ => (),
        }
    }
    for _ in 0..BATCH {
        match socket.recv_from(buffer) {
            Ok((length, source)) if length <= MAX_DATAGRAM_SIZE => {
                match gateway.receive_datagram(source, &buffer[..length]) {
                    Ok(Some(datagram)) => send(socket, datagram),
                    Err(LocalError::Worker(WorkerError::Busy)) if incoming.len() < 64 => {
                        incoming.push_back((
                            source,
                            buffer[..length].to_vec(),
                            Instant::now() + Duration::from_millis(250),
                        ));
                    }
                    _ => (),
                }
            }
            Ok(_) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                break;
            }
            Err(_) => return Err("cannot receive node UDP packet"),
        }
    }
    Ok(())
}
