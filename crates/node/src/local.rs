//! Owner-only local control. No host TCP listener and no persisted join token.
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use wgfeel_protocol::{Request, Response, http};
use zeroize::Zeroizing;

const CAPACITY: usize = http::MAX_HEADER_BYTES + 8192;
pub(crate) fn connect(path: &Path) -> Result<UnixStream, &'static str> {
    wgfeel_host::validate_private_parent(path)?;
    let meta = fs::symlink_metadata(path).map_err(|_| "node service is not running")?;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
    {
        return Err("unsafe node control socket");
    }
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let address = SocketAddrUnix::new(path).map_err(|_| "invalid node control path")?;
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| "cannot create node control socket")?;
    rustix::net::connect(&fd, &address).map_err(|_| "node service is unavailable")?;
    let stream = UnixStream::from(fd);
    owner(&stream)?;
    Ok(stream)
}
fn owner(stream: &UnixStream) -> Result<(), &'static str> {
    if rustix::net::sockopt::socket_peercred(stream)
        .map_err(|_| "cannot verify local peer")?
        .uid
        != rustix::process::geteuid()
    {
        return Err("untrusted local peer");
    }
    Ok(())
}
pub(crate) fn exchange(path: &Path, request: Request<'_>) -> Result<Response, &'static str> {
    let mut stream = connect(path)?;
    let encoded = http::encode_request(request).map_err(|_| "invalid local request")?;
    let mut sent = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut received = Zeroizing::new(Vec::with_capacity(CAPACITY));
    loop {
        if Instant::now() >= deadline {
            return Err("node control request timed out");
        }
        if sent < encoded.len() {
            match stream.write(&encoded[sent..]) {
                Ok(0) => return Err("node control connection closed"),
                Ok(count) => sent += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err("node control send failed"),
            }
        } else {
            let mut chunk = Zeroizing::new([0; 4096]);
            match stream.read(chunk.as_mut_slice()) {
                Ok(0) => return Err("node control connection closed"),
                Ok(count) => {
                    if received.len() + count > CAPACITY {
                        return Err("node response too large");
                    }
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(response) =
                        http::decode_response(&received).map_err(|_| "invalid node response")?
                    {
                        return Ok(response);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err("node control receive failed"),
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
pub(super) struct Server {
    listener: UnixListener,
    path: PathBuf,
    dev: u64,
    ino: u64,
    connections: Vec<Connection>,
}
impl Server {
    pub fn bind(path: &Path) -> Result<Self, &'static str> {
        wgfeel_host::validate_private_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.file_type().is_socket()
                    || meta.uid() != rustix::process::geteuid().as_raw()
                    || meta.mode() & 0o7777 != 0o600
                {
                    return Err("unsafe node control socket");
                }
                // The service holds the state lock. Only an actual refused
                // connection proves this is a stale socket from a prior run.
                use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
                let fd = rustix::net::socket_with(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                    None,
                )
                .map_err(|_| "cannot inspect node socket")?;
                match rustix::net::connect(
                    &fd,
                    &SocketAddrUnix::new(path).map_err(|_| "invalid node socket")?,
                ) {
                    Err(rustix::io::Errno::CONNREFUSED) => {
                        fs::remove_file(path).map_err(|_| "cannot remove stale node socket")?
                    }
                    _ => return Err("node control socket is in use"),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(_) => return Err("cannot inspect node control socket"),
        }
        let listener = UnixListener::bind(path).map_err(|_| "cannot bind node control socket")?;
        let meta = fs::symlink_metadata(path).map_err(|_| "cannot inspect node control socket")?;
        let server = Self {
            listener,
            path: path.into(),
            dev: meta.dev(),
            ino: meta.ino(),
            connections: vec![],
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot protect node control socket")?;
        server
            .listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure node control socket")?;
        Ok(server)
    }
    pub fn poll(
        &mut self,
        mut handler: impl FnMut(Request<'_>) -> Response,
    ) -> Result<(), &'static str> {
        for _ in 0..4 {
            match self.listener.accept() {
                Ok((stream, _)) if self.connections.len() < 4 => {
                    if owner(&stream).is_ok() && stream.set_nonblocking(true).is_ok() {
                        self.connections.push(Connection {
                            stream,
                            input: Zeroizing::new(Vec::with_capacity(CAPACITY)),
                            output: None,
                            sent: 0,
                            deadline: Instant::now() + Duration::from_secs(3),
                        });
                    }
                }
                Ok(_) => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("node control accept failed"),
            }
        }
        self.connections
            .retain_mut(|connection| connection.poll(&mut handler));
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && meta.dev() == self.dev && meta.ino() == self.ino
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
struct Connection {
    stream: UnixStream,
    input: Zeroizing<Vec<u8>>,
    output: Option<Zeroizing<Vec<u8>>>,
    sent: usize,
    deadline: Instant,
}
impl Connection {
    fn poll(&mut self, handler: &mut impl FnMut(Request<'_>) -> Response) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        if self.output.is_none() {
            let mut chunk = Zeroizing::new([0; 4096]);
            match self.stream.read(chunk.as_mut_slice()) {
                Ok(0) => return false,
                Ok(count) => {
                    if self.input.len() + count > CAPACITY {
                        return false;
                    }
                    self.input.extend_from_slice(&chunk[..count]);
                    match http::decode_request(&self.input) {
                        Ok(Some(request)) => {
                            self.output = Some(http::encode_response(&handler(request)))
                        }
                        Ok(None) => (),
                        Err(_) => return false,
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
            match self.stream.write(&output[self.sent..]) {
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
