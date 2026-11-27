use super::{distribution::Distributor, main_transport::Transport, paths, remote};
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, SigmaskHow, Signal, sigprocmask},
        signalfd::{SfdFlags, SignalFd},
    },
};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::ExitCode,
    sync::mpsc::{SyncSender, sync_channel},
    thread,
    time::{Duration, Instant},
};
use wgfeel_management::{ManagementService, Response, http, tcp};
use zeroize::Zeroizing;

const MAX_CONNECTIONS: usize = 16;
const REQUEST_CAPACITY: usize = http::MAX_HEADER_BYTES + wgfeel_management::MAX_REQUEST_BODY;
const DEADLINE: Duration = Duration::from_secs(5);

/// A shortage in one listener must not stall the shared forwarding loop.
#[derive(Default)]
pub(super) struct AcceptLoop {
    retry_at: Option<Instant>,
    backed_off: bool,
}

impl AcceptLoop {
    pub(super) fn poll<S, A>(
        &mut self,
        mut accept: impl FnMut() -> io::Result<(S, A)>,
        mut connected: impl FnMut(S),
        mut on_backoff: impl FnMut(Errno),
    ) -> io::Result<()> {
        if self.retry_at.is_some_and(|due| Instant::now() < due) {
            return Ok(());
        }
        self.retry_at = None;
        for _ in 0..MAX_CONNECTIONS {
            match accept() {
                Ok((stream, _)) => {
                    self.backed_off = false;
                    connected(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.backed_off = false;
                    break;
                }
                Err(error) => match error.raw_os_error().map(Errno::from_raw) {
                    Some(
                        errno @ (Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM),
                    ) => {
                        self.retry_at = Some(Instant::now() + Duration::from_millis(100));
                        if !self.backed_off {
                            self.backed_off = true;
                            on_backoff(errno);
                        }
                        break;
                    }
                    Some(
                        Errno::EINTR
                        | Errno::ECONNABORTED
                        | Errno::ECONNRESET
                        | Errno::ENETDOWN
                        | Errno::EPROTO
                        | Errno::ENOPROTOOPT
                        | Errno::EHOSTDOWN
                        | Errno::ENONET
                        | Errno::EHOSTUNREACH
                        | Errno::EOPNOTSUPP
                        | Errno::EPERM
                        | Errno::ENETUNREACH,
                    ) => continue,
                    _ => return Err(error),
                },
            }
        }
        Ok(())
    }
}

struct Logger {
    sender: SyncSender<(bool, String)>,
    thread: thread::JoinHandle<()>,
}
impl Logger {
    fn new() -> io::Result<Self> {
        let (sender, receiver) = sync_channel::<(bool, String)>(2);
        let thread = thread::Builder::new()
            .name("management-log".into())
            .spawn(move || {
                for (error, line) in receiver {
                    if error {
                        let _ = writeln!(io::stderr().lock(), "wgfeel: {line}");
                    } else {
                        let _ = writeln!(io::stdout().lock(), "{line}");
                    }
                }
            })?;
        Ok(Self { sender, thread })
    }
    fn emit(&self, error: bool, line: String) {
        let _ = self.sender.try_send((error, line));
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
        // Main returns ExitCode after all service resources have been dropped;
        // a blocked log writer must not retain the service or delay process exit.
    }
}

struct SocketPath {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.dev() == self.dev && meta.ino() == self.ino && meta.file_type().is_socket()
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn bind(path: &Path) -> Result<(UnixListener, SocketPath), &'static str> {
    paths::parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            paths::socket(path)?;
            match paths::connect(path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path).map_err(|_| "cannot remove stale Management socket")?;
                }
                _ => return Err("Management socket is already in use"),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(_) => return Err("cannot inspect Management socket"),
    }
    let listener = UnixListener::bind(path).map_err(|_| "cannot bind Management socket")?;
    let meta = fs::symlink_metadata(path).map_err(|_| "cannot inspect Management socket")?;
    let guard = SocketPath {
        path: path.to_owned(),
        dev: meta.dev(),
        ino: meta.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect Management socket")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "cannot configure Management socket")?;
    Ok((listener, guard))
}

pub(super) struct Connection<S = UnixStream> {
    stream: S,
    input: Zeroizing<Vec<u8>>,
    output: Option<Zeroizing<Vec<u8>>>,
    sent: usize,
    deadline: Instant,
}
impl Connection {
    fn new(stream: UnixStream) -> io::Result<Self> {
        if rustix::net::sockopt::socket_peercred(&stream)?.uid != rustix::process::geteuid() {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        stream.set_nonblocking(true)?;
        Ok(Self::framed(stream))
    }
}
impl Connection<std::net::TcpStream> {
    pub(super) fn remote(stream: std::net::TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self::framed(stream))
    }
}
impl<S: Read + Write> Connection<S> {
    fn framed(stream: S) -> Self {
        Self {
            stream,
            input: Zeroizing::new(Vec::with_capacity(REQUEST_CAPACITY)),
            output: None,
            sent: 0,
            deadline: Instant::now() + DEADLINE,
        }
    }
    pub(super) fn progress(
        &mut self,
        mut dispatch: impl FnMut(wgfeel_protocol::Request<'_>) -> Response,
    ) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        if self.output.is_none() {
            let mut chunk = Zeroizing::new([0u8; 4096]);
            match self.stream.read(chunk.as_mut_slice()) {
                Ok(0) => return false,
                Ok(count) => {
                    if self.input.len() + count > REQUEST_CAPACITY {
                        self.output = Some(http::encode_response(&Response::error(
                            413,
                            "body_too_large",
                        )));
                    } else {
                        self.input.extend_from_slice(&chunk[..count]);
                        match http::decode_request(&self.input) {
                            Ok(Some(request)) => {
                                self.output = Some(http::encode_response(&dispatch(request)))
                            }
                            Ok(None) => (),
                            Err(error) => {
                                self.output = Some(http::encode_response(&Response::error(
                                    error.0,
                                    "invalid_http",
                                )))
                            }
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return false,
            }
        }
        if let Some(output) = &self.output {
            let end = (self.sent + 16_384).min(output.len());
            match self.stream.write(&output[self.sent..end]) {
                Ok(0) => return false,
                Ok(count) => self.sent += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return false,
            }
            if self.sent == output.len() {
                return false;
            }
        }
        true
    }
}

pub(super) fn run(args: &[OsString]) -> ExitCode {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGTERM);
    if sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None).is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(signals) = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
    else {
        return ExitCode::FAILURE;
    };
    let Ok(logger) = Logger::new() else {
        return ExitCode::FAILURE;
    };
    let exit = match serve(args, &signals, &logger) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            logger.emit(true, error.into());
            ExitCode::FAILURE
        }
    };
    logger.finish();
    exit
}

fn serve(args: &[OsString], signals: &SignalFd, logger: &Logger) -> Result<(), &'static str> {
    if args.len() != 2 || args[0] != "--state-dir" {
        return Err("usage: wgfeel serve --control main --state-dir PATH");
    }
    let directory = PathBuf::from(&args[1]);
    if !directory.is_absolute() {
        return Err("Management state path must be absolute");
    }
    let mut service =
        ManagementService::open(&directory).map_err(|_| "cannot open Management state")?;
    let mut distributor = Distributor::new()?;
    let mut enrollment = super::enrollment::Verifier::new()?;
    let (listener, _path_guard) = bind(&directory.join("api.sock"))?;
    let mut buffers = tcp::Buffers::new(tcp::SERVER_SOCKETS)
        .map_err(|_| "cannot allocate service API buffers")?;
    let mut invitation_buffers = (0..wgfeel_management::MAX_INVITATIONS)
        .map(|_| tcp::Buffers::new(1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "cannot allocate enrollment buffers")?;
    let mut invitations = invitation_buffers
        .iter_mut()
        .map(|buffers| {
            Ok(InvitationSession {
                peer: None,
                tcp: tcp::Server::enrollment(buffers, remote::seed()?)
                    .map_err(|_| "cannot initialize enrollment server")?,
            })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    let mut system = if let Some((api, _key)) = service
        .service_api()
        .map_err(|_| "cannot load service API identity")?
    {
        let tunnel = Transport::bind(
            api.listen(),
            wgfeel_core::NodeId::new("administrator-api")
                .map_err(|_| "invalid service API peer")?,
            api.admin_public_key().clone(),
            &service,
        )?;
        let tcp = tcp::Server::new(&mut buffers, remote::seed()?)
            .map_err(|_| "cannot initialize service API server")?;
        Some((tunnel, tcp))
    } else {
        None
    };
    let started = Instant::now();
    let mut api_budget = ApiBudget::new(started);
    let mut rest = super::rest::Listener::new(&service)?;
    let (management_id, generation) = service
        .identity()
        .map_err(|_| "cannot read Management identity")?;
    let ready = serde_json::json!({"event":"ready", "control":"main", "management_id":management_id.as_str(), "generation":generation});
    let mut announced = false;
    let mut accept = AcceptLoop::default();
    let mut connections: Vec<Connection> = Vec::with_capacity(MAX_CONNECTIONS);
    loop {
        match signals.read_signal() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(Errno::EINTR) => (),
            Err(_) => return Err("cannot read Management shutdown signal"),
        }
        accept
            .poll(
                || listener.accept(),
                |stream| {
                    if connections.len() < MAX_CONNECTIONS
                        && let Ok(connection) = Connection::new(stream)
                    {
                        connections.push(connection);
                    }
                },
                |_| {
                    logger.emit(
                        true,
                        "Management local listener backing off after temporary accept error".into(),
                    );
                },
            )
            .map_err(|_| "cannot accept Management request")?;
        connections.retain_mut(|connection| {
            connection.progress(|request| {
                if request.target == super::rest::LOCAL_PATH {
                    rest.configure(&mut service, request)
                } else {
                    service.handle_local(request)
                }
            })
        });
        rest.poll(&mut service, |message| logger.emit(true, message))?;
        if let Some((tunnel, tcp)) = &mut system {
            distributor.poll(&mut service, tunnel);
            enrollment.poll(&mut service, tunnel, |message| logger.emit(true, message));
            tunnel.synchronize(&mut service)?;
            let peers = service.invitation_peers();
            tunnel.set_invitation_peers(&peers)?;
            for slot in &mut invitations {
                if slot.peer.as_ref().is_some_and(|old| !peers.contains(old)) {
                    slot.tcp
                        .reset_session()
                        .map_err(|_| "cannot clear enrollment stream")?;
                    slot.peer = None;
                }
            }
            for peer in peers {
                if !invitations
                    .iter()
                    .any(|slot| slot.peer.as_ref() == Some(&peer))
                {
                    let slot = invitations
                        .iter_mut()
                        .find(|slot| slot.peer.is_none())
                        .ok_or("enrollment capacity invariant failed")?;
                    slot.peer = Some(peer);
                }
            }
            tunnel.poll_peers(|peer, packet| {
                if let wgfeel_wireguard::PeerId::Node(id) = peer {
                    if id.as_str() == "administrator-api" {
                        let _ = tcp.receive(packet);
                    } else if let Some(slot) = invitations.iter_mut().find(|slot| {
                        slot.peer
                            .as_ref()
                            .is_some_and(|(candidate, _)| candidate == id)
                    }) {
                        let _ = slot.tcp.receive(packet);
                    } else {
                        distributor.receive(id, packet);
                    }
                }
            })?;
            while let Some(message) = tunnel.diagnostic() {
                logger.emit(true, message.into());
            }
            distributor.flush(tunnel);
            tcp.poll_with(started.elapsed(), |request| {
                if !api_budget.allow(Instant::now()) {
                    return Response::error(429, "api_rate_limited");
                }
                let response = service.handle(request);
                if response.status == 401
                    && let Some(endpoint) = tunnel.endpoint()
                {
                    logger.emit(true, format!("auth-rejected source={}", endpoint.ip()));
                }
                response
            })
            .map_err(|_| "service API processing failed")?;
            while let Some(packet) = tcp.take_packet() {
                tunnel.send(&packet)?;
            }
            for slot in &mut invitations {
                if let Some((id, key)) = &slot.peer {
                    slot.tcp
                        .poll_with(started.elapsed(), |request| {
                            service.handle_enrollment(id, key, request)
                        })
                        .map_err(|_| "enrollment API processing failed")?;
                    while let Some(packet) = slot.tcp.take_packet() {
                        tunnel.send_peer(&wgfeel_wireguard::PeerId::Node(id.clone()), &packet)?;
                    }
                }
            }
        }
        if !announced && system.as_ref().is_none_or(|(tunnel, _)| tunnel.ready()) {
            logger.emit(false, ready.to_string());
            announced = true;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

struct InvitationSession<'a> {
    peer: Option<(wgfeel_core::NodeId, wgfeel_core::DevicePublicKey)>,
    tcp: tcp::Server<'a>,
}

// Bound each remote administrative transport before loading or changing state.
pub(super) struct ApiBudget {
    tokens: u32,
    refill: Instant,
}
impl ApiBudget {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            tokens: 4,
            refill: now,
        }
    }
    pub(super) fn allow(&mut self, now: Instant) -> bool {
        let steps = now.saturating_duration_since(self.refill).as_millis() / 250;
        if steps > 0 {
            self.tokens = self.tokens.saturating_add(steps.min(4) as u32).min(4);
            self.refill = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accept_recovers_per_connection_and_resource_backoff_is_local() {
        let mut first = AcceptLoop::default();
        let mut second = AcceptLoop::default();
        let mut events = [
            Err(Errno::ECONNABORTED),
            Err(Errno::EPERM),
            Err(Errno::EOPNOTSUPP),
            Ok((1, ())),
            Err(Errno::EMFILE),
        ]
        .into_iter();
        let mut accepted = vec![];
        let mut backoffs = vec![];
        first
            .poll(
                || events.next().unwrap().map_err(io::Error::from),
                |stream| accepted.push(stream),
                |errno| backoffs.push(errno),
            )
            .unwrap();
        assert_eq!(accepted, [1]);
        assert_eq!(backoffs, [Errno::EMFILE]);
        first
            .poll::<(), ()>(
                || panic!("listener is backing off"),
                |_| unreachable!(),
                |_| unreachable!(),
            )
            .unwrap();
        let mut healthy = [Ok((2, ())), Err(io::ErrorKind::WouldBlock.into())].into_iter();
        second
            .poll(
                || healthy.next().unwrap(),
                |stream| accepted.push(stream),
                |_| unreachable!(),
            )
            .unwrap();
        first.retry_at = Some(Instant::now());
        // Repeated backoff before any recovery does not spam diagnostics.
        first
            .poll::<(), ()>(
                || Err(Errno::ENOBUFS.into()),
                |_| unreachable!(),
                |errno| backoffs.push(errno),
            )
            .unwrap();
        assert_eq!(backoffs, [Errno::EMFILE]);
        first.retry_at = Some(Instant::now());
        let mut recovered = [Ok((3, ())), Err(io::ErrorKind::WouldBlock.into())].into_iter();
        first
            .poll(
                || recovered.next().unwrap(),
                |stream| accepted.push(stream),
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(accepted, [1, 2, 3]);
        assert!(
            first
                .poll::<(), ()>(
                    || Err(Errno::EBADF.into()),
                    |_| unreachable!(),
                    |_| unreachable!(),
                )
                .is_err()
        );
    }

    #[test]
    fn remote_api_budget_bounds_bursts_and_refills_without_unbounded_credit() {
        let now = Instant::now();
        let mut budget = ApiBudget::new(now);
        for _ in 0..4 {
            assert!(budget.allow(now));
        }
        assert!(!budget.allow(now));
        assert!(!budget.allow(now + Duration::from_millis(249)));
        assert!(budget.allow(now + Duration::from_millis(250)));
        assert!(!budget.allow(now + Duration::from_millis(250)));
        for _ in 0..4 {
            assert!(budget.allow(now + Duration::from_secs(60)));
        }
        assert!(!budget.allow(now + Duration::from_secs(60)));
    }
}
