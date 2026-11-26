//! Local control paths must be owned, private and traversed without symlinks.
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags},
    process::geteuid,
};
use std::{
    ffi::OsString,
    path::{Component, Path},
};

const FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub fn parent(path: &Path) -> Result<(OwnedFd, OsString), &'static str> {
    if !path.is_absolute() {
        return Err("control paths must be absolute");
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(value) => parts.push(value),
            _ => return Err("unsafe control path"),
        }
    }
    let name = parts.pop().ok_or("unsafe control path")?.to_owned();
    let mut directory = fs::openat(fs::CWD, "/", FLAGS, Mode::empty())
        .map_err(|_| "cannot open control directory")?;
    for part in parts {
        let stat = fs::fstat(&directory).map_err(|_| "cannot inspect control ancestor")?;
        if (stat.st_uid != 0 && stat.st_uid != geteuid().as_raw())
            || (stat.st_mode & 0o022 != 0 && !(stat.st_uid == 0 && stat.st_mode & 0o1000 != 0))
        {
            return Err("unsafe control ancestor");
        }
        directory = fs::openat(&directory, part, FLAGS, Mode::empty())
            .map_err(|_| "unsafe control directory")?;
    }
    let stat = fs::fstat(&directory).map_err(|_| "cannot inspect control directory")?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err("control directory requires owner-only mode 0700");
    }
    Ok((directory, name))
}
