use crate::StoreError;
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    fs::File,
    path::{Component, Path},
};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn path_error(error: rustix::io::Errno) -> StoreError {
    match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => StoreError::UnsafePath,
        _ => StoreError::Io(error.into()),
    }
}

pub(crate) fn directory(path: &Path, initialize: bool) -> Result<OwnedFd, StoreError> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::UnsafePath);
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value),
            Component::RootDir | Component::CurDir => (),
            Component::ParentDir | Component::Prefix(_) => return Err(StoreError::UnsafePath),
        }
    }
    let mut dir = fs::openat(
        fs::CWD,
        if path.is_absolute() { "/" } else { "." },
        DIRECTORY_FLAGS,
        Mode::empty(),
    )
    .map_err(path_error)?;
    for (i, part) in parts.iter().enumerate() {
        dir = match fs::openat(&dir, *part, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) if initialize && i + 1 == parts.len() => {
                fs::mkdirat(&dir, *part, Mode::RWXU).map_err(path_error)?;
                // Persist the new leaf entry before it can contain acknowledged state.
                fs::fsync(&dir).map_err(path_error)?;
                fs::openat(&dir, *part, DIRECTORY_FLAGS, Mode::empty()).map_err(path_error)?
            }
            Err(error) => return Err(path_error(error)),
        };
    }
    check_directory(&dir)?;
    Ok(dir)
}

pub(crate) fn check_directory(dir: &OwnedFd) -> Result<(), StoreError> {
    let stat = fs::fstat(dir).map_err(path_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_uid != geteuid().as_raw()
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

pub(crate) fn check_file(file: &File) -> Result<(), StoreError> {
    let stat = fs::fstat(file).map_err(path_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

pub(crate) fn existing(dir: &OwnedFd, name: &str) -> Result<Option<File>, StoreError> {
    // NONBLOCK prevents a malicious FIFO from blocking before we can reject its type.
    match fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            check_file(&file)?;
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(path_error(error)),
    }
}

pub(crate) fn stage(dir: &OwnedFd) -> Result<File, StoreError> {
    if existing(dir, ".pending")?.is_some() {
        // The retained private directory and lifetime lock constrain replacement.
        // A hostile process with this same UID is outside this storage boundary.
        fs::unlinkat(dir, ".pending", AtFlags::empty()).map_err(path_error)?;
    }
    let file = File::from(
        fs::openat(
            dir,
            ".pending",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(path_error)?,
    );
    check_file(&file)?;
    Ok(file)
}
