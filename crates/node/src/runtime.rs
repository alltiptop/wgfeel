//! Process-owned foreground runtime. No host network configuration.
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, SigmaskHow, Signal, sigprocmask},
        signalfd::{SfdFlags, SignalFd},
    },
};
use std::{
    ffi::OsString,
    io::{self, Write},
    net::SocketAddr,
    os::fd::AsFd,
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{SyncSender, sync_channel},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wgfeel_store::Store;
use wgfeel_wireguard::{
    ContextId, MAX_DATAGRAM_SIZE, PeerId,
    worker::{EncryptedDatagram, LocalError, LocalEvent, LocalGateway, WorkerError, WorkerOptions},
};

mod control;
mod dns;
mod enrollment;
mod main;
mod mesh;
pub use main::{MainEvent, MainForwarder};

const TICK_INTERVAL: Duration = Duration::from_millis(250);
const BATCH: usize = 32;
const USAGE: &str =
    "usage: wgfeel serve --control child --state-dir PATH (--listen IP:PORT | --listen-ip IP)";

// Only bounded public lifecycle metadata crosses this queue. Blocking log sinks
// must not hold the packet loop, state lock or worker cleanup hostage.
enum Log {
    Error(&'static str),
    Ready {
        listen: SocketAddr,
        node_id: String,
        management_id: String,
        generation: u64,
        local_contexts: usize,
    },
    Failed {
        context: ContextId,
        generation: u64,
    },
}
struct Logger {
    sender: SyncSender<Log>,
    thread: JoinHandle<()>,
}
impl Logger {
    fn new() -> io::Result<Self> {
        let (sender, receiver) = sync_channel(16);
        let thread = thread::Builder::new()
            .name("node-log".into())
            .spawn(move || {
                for event in receiver {
                    match event {
                        Log::Error(error) => {
                            let _ = writeln!(io::stderr().lock(), "wgfeel: {error}");
                        }
                        Log::Ready {
                            listen,
                            node_id,
                            management_id,
                            generation,
                            local_contexts,
                        } => {
                            let value = serde_json::json!({
                                "event": "ready", "control": "child", "listen": listen.to_string(),
                                "node_id": node_id, "management_id": management_id,
                                "generation": generation, "local_contexts": local_contexts,
                            });
                            let _ = writeln!(io::stdout().lock(), "{value}");
                        }
                        Log::Failed {
                            context,
                            generation,
                        } => {
                            let context = match context {
                                ContextId::Tenant(id) => format!("tenant:{}", id.as_str()),
                                ContextId::Service => "service".into(),
                                ContextId::Gateway => "gateway".into(),
                            };
                            let value = serde_json::json!({
                                "event": "worker_failed", "context": context,
                                "generation": generation,
                            });
                            let _ = writeln!(io::stderr().lock(), "{value}");
                        }
                    }
                }
            })?;
        Ok(Self { sender, thread })
    }
    fn emit(&self, event: Log) {
        let _ = self.sender.try_send(event);
    }
    fn finish(self) {
        drop(self.sender);
        let deadline = Instant::now() + Duration::from_millis(100);
        while !self.thread.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if self.thread.is_finished() {
            let _ = self.thread.join();
        }
        // A blocked logger may remain until main returns ExitCode, ending this
        // process. All service resources have already been dropped by serve.
    }
}

pub(super) fn run(args: &[OsString]) -> ExitCode {
    match foreground(args, None) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

pub(super) fn foreground(
    args: &[OsString],
    join: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<(), &'static str> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGTERM);
    let mut previous = SigSet::empty();
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous))
        .map_err(|_| "cannot mask shutdown signals")?;
    let result = (|| {
        let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
            .map_err(|_| "cannot watch shutdown signals")?;
        let logger = Logger::new().map_err(|_| "cannot start node logger")?;
        let standalone = join.is_none();
        let result = serve(args, &signals, &logger, join);
        if standalone && let Err(error) = &result {
            logger.emit(Log::Error(error));
        }
        logger.finish();
        result
    })();
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&previous), None)
        .map_err(|_| "cannot restore signal mask")?;
    result
}

fn stopping(signals: &SignalFd, joining: bool) -> Result<bool, &'static str> {
    match signals.read_signal() {
        Ok(Some(_)) if joining => Err("join interrupted"),
        Ok(signal) => Ok(signal.is_some()),
        Err(Errno::EINTR) => Ok(false),
        Err(_) => Err("cannot read shutdown signal"),
    }
}

fn serve(
    args: &[OsString],
    signals: &SignalFd,
    logger: &Logger,
    bootstrap: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<(), &'static str> {
    let enrolling = bootstrap.is_some();
    if args.len() != 4 || args[0] != "--state-dir" {
        return Err(USAGE);
    }

    // Only this process accepts authenticated updates under the lifetime lock.
    let mut store = Store::open(&PathBuf::from(&args[1])).map_err(|_| "cannot open node state")?;
    let state = store
        .load()
        .map_err(|_| "invalid node state")?
        .ok_or("no committed state")?;
    let managed_port = args[2] == "--listen-ip";
    let listen = if managed_port {
        let ip = args[3].to_str().ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
        let port = state
            .projection()
            .assignment()
            .endpoint()
            .filter(|_| state.management_public_key().is_some())
            .ok_or("child is awaiting enrollment; run the join command issued by main")?
            .port();
        SocketAddr::new(ip, port)
    } else if args[2] == "--listen" {
        args[3].to_str().ok_or(USAGE)?.parse().map_err(|_| USAGE)?
    } else {
        return Err(USAGE);
    };
    let mut socket =
        wgfeel_wireguard::UdpListener::bind(listen).map_err(|_| "cannot bind node UDP socket")?;
    let listen = socket
        .local_addr()
        .map_err(|_| "cannot read node UDP address")?;
    let mut managed = state.management_public_key().is_some();
    let mut gateway = control::spawn(&state)?;
    // The workers own bootstrap buffers and keys; do not retain another static
    // key copy in the runtime after assembly.
    drop(state);
    let projection = gateway.projection();
    let contexts = projection.assignment().tenants().len();
    let ready = Log::Ready {
        listen,
        node_id: projection.assignment().recipient().as_str().into(),
        management_id: projection.management_id().as_str().into(),
        generation: projection.config().generation(),
        local_contexts: contexts,
    };
    let mut timers = timers(&gateway, managed);
    let mut remaining = gateway.workers().len();
    while remaining != 0 {
        if stopping(signals, enrolling)? {
            return Ok(());
        }
        for _ in 0..BATCH {
            match gateway.poll() {
                Some(LocalEvent::Ready { .. }) => {
                    remaining = remaining
                        .checked_sub(1)
                        .ok_or("unexpected worker readiness")?;
                }
                Some(LocalEvent::Failed { .. }) => return Err("node worker startup failed"),
                Some(_) => return Err("unexpected node startup event"),
                None => break,
            }
        }
        if remaining != 0 {
            gateway
                .wait_for_activity(&[signals.as_fd()], TICK_INTERVAL)
                .map_err(|_| "cannot wait for node workers")?;
        }
    }
    if stopping(signals, enrolling)? {
        return Ok(());
    }
    let start = Instant::now();
    let mut tcp_buffers =
        wgfeel_protocol::tcp::Buffers::new(1).map_err(|_| "cannot allocate control transport")?;
    let mut control = Some(
        wgfeel_protocol::tcp::Server::distribution(&mut tcp_buffers, wgfeel_host::random_seed()?)
            .map_err(|_| "cannot create control transport")?,
    );
    let state_dir = PathBuf::from(&args[1]);
    let mut local = if !enrolling {
        Some(crate::local::Server::bind(&state_dir.join("api.sock"))?)
    } else {
        None
    };
    let mut joining = enrollment::Runtime::default();
    let mut enrollment_buffers = wgfeel_protocol::tcp::Buffers::new(1)
        .map_err(|_| "cannot allocate enrollment transport")?;
    let mut enrollment_tcp = wgfeel_protocol::tcp::Server::distribution(
        &mut enrollment_buffers,
        wgfeel_host::random_seed()?,
    )
    .map_err(|_| "cannot create enrollment transport")?;
    let mut enrollment_outgoing = std::collections::VecDeque::new();
    let mut outgoing = std::collections::VecDeque::new();
    let mut mesh = mesh::Runtime::new(gateway.projection())?;
    let mut dns = dns::Runtime::default();
    let mut updates = control::Updates::default();
    let mut buffer = [0; MAX_DATAGRAM_SIZE + 1];
    let mut incoming = std::collections::VecDeque::new();
    let mut ingress_first = false;
    if let Some(body) = bootstrap {
        let response = joining.local(
            &store,
            &gateway,
            &state_dir,
            listen,
            true,
            wgfeel_protocol::Request {
                method: "POST",
                target: crate::join::PATH,
                authorization: None,
                if_match: None,
                body: &body,
            },
        );
        if response.status != 202 {
            return Err("cannot begin enrollment with these addresses and invitation");
        }
    } else {
        logger.emit(ready);
    }
    let mut progress = Instant::now();
    loop {
        if stopping(signals, enrolling)? {
            return Ok(());
        }
        let was_joining = joining.active();
        if let Some(local) = &mut local {
            local.poll(|request| {
                joining.local(&store, &gateway, &state_dir, listen, managed_port, request)
            })?;
        }
        if enrolling {
            if let Some(result) = joining.result() {
                return result;
            }
            if progress.elapsed() >= Duration::from_secs(5) {
                eprintln!(
                    "{} ({}s elapsed).",
                    joining.progress().waiting(),
                    start.elapsed().as_secs()
                );
                progress = Instant::now();
            }
        }
        if !was_joining && joining.active() {
            updates.cancel_pending();
        }
        joining.poll(&store, &mut gateway, &mut socket);
        if !joining.active() {
            updates.cancel_join();
        }
        // Alternate admission order: mesh/control output and timers must not
        // monopolize a worker before every queued inbound handshake is read.
        for _ in 0..BATCH {
            match gateway.poll() {
                Some(LocalEvent::Network(datagram)) => {
                    if datagram.context == ContextId::Service
                        && gateway
                            .enrollment_peer()
                            .is_some_and(|id| datagram.peer == Some(PeerId::Node(id.clone())))
                        && datagram.packet.as_bytes().starts_with(&[2, 0, 0, 0])
                    {
                        enrollment_tcp
                            .reset_session()
                            .map_err(|_| "cannot reset enrollment transport")?;
                        enrollment_outgoing.clear();
                    }
                    // WireGuard rekeying does not end a configuration TCP stream.
                    // Abandoned deliveries have their own bounded idle deadline.
                    send(&socket, datagram);
                }
                Some(event @ (LocalEvent::Mesh { .. } | LocalEvent::MeshOutput { .. })) => {
                    mesh.event(event, start.elapsed(), &gateway)
                }
                Some(LocalEvent::Failed {
                    context,
                    generation,
                    ..
                }) => {
                    if let Some(timer) = timers.iter_mut().find(|timer| timer.context == context) {
                        timer.failed = true;
                    }
                    logger.emit(Log::Failed {
                        context,
                        generation,
                    });
                }
                Some(LocalEvent::Management { packet }) => {
                    if let Some(control) = &mut control {
                        let _ = control.receive(packet.as_bytes());
                    }
                }
                Some(LocalEvent::Dns { source, packet }) => dns.receive(source, packet.as_bytes()),
                Some(LocalEvent::Enrollment { packet }) => {
                    let _ = enrollment_tcp.receive(packet.as_bytes());
                }
                Some(LocalEvent::EnrollmentConfigured { result }) => joining.configured(result),
                Some(LocalEvent::Control { .. } | LocalEvent::ControlConfigured { .. }) => {
                    return Err("unexpected main control event in child runtime");
                }
                Some(LocalEvent::Dropped { .. } | LocalEvent::Ready { .. }) => {}
                None => break,
            }
        }
        ingress_first = !ingress_first;
        if ingress_first {
            receive(&socket, &mut gateway, &mut buffer, &mut incoming)?;
        }
        if let Some(control) = &mut control {
            control
                .poll_with(start.elapsed(), |request| {
                    if joining.same_manager(&store, &gateway) {
                        joining.handle(&mut updates, &mut store, &mut gateway, request)
                    } else if joining.active() {
                        wgfeel_protocol::Response::error(409, "join_in_progress")
                    } else {
                        updates.handle(&mut store, &mut gateway, request)
                    }
                })
                .map_err(|_| "control transport failed")?;
            while outgoing.len() < wgfeel_protocol::tcp::MAX_PACKET_QUEUE {
                let Some(packet) = control.take_packet() else {
                    break;
                };
                outgoing.push_back(packet);
            }
            while let Some(packet) = outgoing.front() {
                if matches!(
                    gateway.send_management(packet),
                    Err(LocalError::Worker(WorkerError::Busy))
                ) {
                    break;
                }
                outgoing.pop_front();
            }
        }
        enrollment_tcp
            .poll_with(start.elapsed(), |request| {
                joining.handle(&mut updates, &mut store, &mut gateway, request)
            })
            .map_err(|_| "enrollment transport failed")?;
        while enrollment_outgoing.len() < wgfeel_protocol::tcp::MAX_PACKET_QUEUE {
            let Some(packet) = enrollment_tcp.take_packet() else {
                break;
            };
            enrollment_outgoing.push_back(packet);
        }
        while let Some(packet) = enrollment_outgoing.front() {
            if matches!(
                gateway.send_enrollment(packet),
                Err(LocalError::Worker(WorkerError::Busy))
            ) {
                break;
            }
            enrollment_outgoing.pop_front();
        }
        if let Some(activation) = updates.poll(&mut store, &mut gateway)? {
            managed = store
                .load()
                .map_err(|_| "cannot inspect committed node authority")?
                .is_some_and(|state| state.management_public_key().is_some());
            timers = self::timers(&gateway, managed);
            incoming.clear();
            enrollment_outgoing.clear();
            if matches!(activation, control::Activation::NewAuthority) {
                outgoing.clear();
                if let Some(control) = &mut control {
                    control
                        .reset_session()
                        .map_err(|_| "cannot reset committed control transport")?;
                }
            }
            enrollment_tcp
                .reset_session()
                .map_err(|_| "cannot reset committed enrollment transport")?;
            mesh = match activation {
                control::Activation::SameAuthority => mesh.replacement(gateway.projection())?,
                control::Activation::NewAuthority => mesh::Runtime::new(gateway.projection())?,
            };
            dns.reset();
        }
        let now = Instant::now();
        mesh.poll(&mut gateway, &socket, start.elapsed());
        dns.poll(&mut gateway, start.elapsed());
        for timer in &mut timers {
            timer.tick(&mut gateway, now);
        }
        if !ingress_first {
            receive(&socket, &mut gateway, &mut buffer, &mut incoming)?;
        }
        let now = Instant::now();
        let wait = timers
            .iter()
            .filter(|timer| !timer.failed && !timer.blocked)
            .flat_map(|timer| {
                timer
                    .peers
                    .iter()
                    .map(|(_, due)| due.saturating_duration_since(now))
            })
            .fold(Duration::from_millis(2), Duration::min);
        gateway
            .wait_for_activity(&[socket.as_fd(), signals.as_fd()], wait)
            .map_err(|_| "cannot wait for node activity")?;
    }
}

fn receive(
    socket: &wgfeel_wireguard::UdpListener,
    gateway: &mut LocalGateway,
    buffer: &mut [u8],
    incoming: &mut std::collections::VecDeque<(SocketAddr, Vec<u8>, Instant)>,
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

fn send(socket: &wgfeel_wireguard::UdpListener, datagram: EncryptedDatagram) {
    // UDP and worker backpressure are loss, never a plaintext/retry queue or a
    // reason to tear down healthy contexts. Protocol timers handle recovery.
    let _ = socket.send_to(datagram.packet.as_bytes(), datagram.destination);
}

struct Timer {
    context: ContextId,
    peers: Vec<(PeerId, Instant)>,
    cursor: usize,
    blocked: bool,
    failed: bool,
}
fn timers(gateway: &LocalGateway, managed: bool) -> Vec<Timer> {
    let projection = gateway.projection();
    let mut timers: Vec<_> = projection
        .config()
        .networks()
        .iter()
        .filter(|network| {
            projection
                .assignment()
                .tenants()
                .iter()
                .any(|tenant| tenant.network() == network.id())
        })
        .map(|network| Timer {
            context: ContextId::Tenant(network.id().clone()),
            peers: network
                .devices()
                .iter()
                .filter(|device| {
                    device
                        .gateway()
                        .is_none_or(|node| node == projection.recipient())
                })
                .map(|device| (PeerId::Device(device.id().clone()), Instant::now()))
                .chain(
                    projection
                        .mesh()
                        .iter()
                        .filter(|node| {
                            node.recipient() != projection.recipient()
                                && node
                                    .tenants()
                                    .iter()
                                    .any(|tenant| tenant.network() == network.id())
                        })
                        .map(|node| (PeerId::Gateway(node.recipient().clone()), Instant::now())),
                )
                .collect(),
            cursor: 0,
            blocked: false,
            failed: false,
        })
        .collect();
    // Gateway handshakes and rekeys have their own engine timers. Mesh probes
    // alone cannot retry an initiation that the underlying WG engine considers
    // pending, nor retire an expired receiver index after a long outage.
    timers.push(Timer {
        context: ContextId::Gateway,
        peers: projection
            .mesh()
            .iter()
            .filter(|node| node.recipient() != projection.recipient() && !projection.is_revoked())
            .map(|node| (PeerId::Node(node.recipient().clone()), Instant::now()))
            .collect(),
        cursor: 0,
        blocked: false,
        failed: false,
    });
    if managed {
        timers.push(Timer {
            context: ContextId::Service,
            peers: std::iter::once(projection.management_id())
                .filter(|id| *id != projection.recipient())
                .chain(
                    projection
                        .mesh()
                        .iter()
                        .filter(|node| {
                            node.recipient() != projection.recipient()
                                && node.recipient() != projection.management_id()
                                && !projection.is_revoked()
                                && projection.control_mode() == wgfeel_core::ControlMode::Main
                        })
                        .map(|node| node.recipient()),
                )
                .map(|id| (PeerId::Node(id.clone()), Instant::now()))
                .collect(),
            cursor: 0,
            blocked: false,
            failed: false,
        });
    }
    timers
}
impl Timer {
    fn tick(&mut self, gateway: &mut LocalGateway, now: Instant) {
        self.blocked = false;
        if self.failed {
            return;
        }
        for _ in 0..self.peers.len() {
            let (peer, due) = &mut self.peers[self.cursor];
            if *due <= now {
                if matches!(gateway.endpoint(&self.context, peer), Ok(Some(_))) {
                    match gateway.tick(&self.context, peer) {
                        Err(LocalError::Worker(WorkerError::Busy)) => {
                            // Retry this peer after I/O, without a zero-timeout
                            // spin or counting a refused submission as a tick.
                            self.blocked = true;
                            return;
                        }
                        _ => {
                            *due = now + TICK_INTERVAL;
                            self.cursor = (self.cursor + 1) % self.peers.len();
                            return;
                        }
                    }
                }
                *due = now + TICK_INTERVAL;
            }
            self.cursor = (self.cursor + 1) % self.peers.len();
        }
    }
}
