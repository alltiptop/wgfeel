//! Local control paths must be owned, private and traversed without symlinks.
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::net::UnixStream,
    path::Path,
};
use zeroize::Zeroizing;

pub(super) use wgfeel_host::private_paths::parent;

pub(super) fn connect(path: &Path) -> io::Result<UnixStream> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    let address = SocketAddrUnix::new(path)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    // AF_UNIX may return EAGAIN when the listener backlog is full. Fail without
    // sending a credential; a pending/full probe never proves a stale socket.
    connect(&socket, &address)?;
    Ok(UnixStream::from(socket))
}

pub(super) fn socket(path: &Path) -> Result<(), &'static str> {
    let (parent, name) = parent(path)?;
    let stat = fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "Management unavailable")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err("unsafe Management socket");
    }
    Ok(())
}

pub(super) fn credential(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let (parent, name) = parent(path)?;
    let fd = fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "cannot read credential file")?;
    let stat = fs::fstat(&fd).map_err(|_| "cannot inspect credential file")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || !(44..=45).contains(&stat.st_size)
    {
        return Err("credential file requires a single owned regular file with mode 0600");
    }
    let mut buffer = Zeroizing::new([0u8; 46]);
    let mut file = File::from(fd);
    let mut length = 0;
    while length < buffer.len() {
        let count = file
            .read(&mut buffer[length..])
            .map_err(|_| "cannot read credential file")?;
        if count == 0 {
            break;
        }
        length += count;
    }
    let text = std::str::from_utf8(&buffer[..length]).map_err(|_| "invalid credential file")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    wgfeel_management::decode_key(text).map_err(|_| "invalid credential file")?;
    let mut authorization = Zeroizing::new(String::with_capacity(51));
    authorization.push_str("Bearer ");
    authorization.push_str(text);
    Ok(authorization)
}
