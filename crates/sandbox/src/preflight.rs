use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd};

use rustix::fs::{Dir, FileType, Mode, OFlags, fcntl_getfl, fstat, major, minor, open, readlink};
use rustix::process::{Resource, getrlimit};

use crate::{SandboxError, WorkerLimits};

// These files describe only this process. Reads are capped before allocation;
// malformed, unavailable or unexpectedly large proc records fail closed.
fn proc_text(path: &str, maximum: u64) -> Result<String, SandboxError> {
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_string(&mut text))
        .map_err(|_| SandboxError::InvalidProcess)?;
    if text.len() as u64 > maximum {
        return Err(SandboxError::InvalidProcess);
    }
    Ok(text)
}

pub(super) fn check(limits: WorkerLimits) -> Result<(), SandboxError> {
    if !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&limits.address_space_bytes) {
        return Err(SandboxError::InvalidLimits);
    }
    if std::env::vars_os().next().is_some() || !single_thread()? {
        return Err(SandboxError::InvalidProcess);
    }
    if !native_personality(&proc_text("/proc/self/personality", 32)?)
        || !private_mappings(&proc_text("/proc/self/maps", 1024 * 1024)?)
    {
        return Err(SandboxError::InvalidProcess);
    }
    descriptors()?;
    // Never raise an existing hard limit, even when launched with privilege.
    for (resource, ceiling) in [
        (Resource::As, limits.address_space_bytes),
        (Resource::Nofile, 3),
    ] {
        if getrlimit(resource)
            .maximum
            .is_some_and(|maximum| ceiling > maximum)
        {
            return Err(SandboxError::ResourceLimit);
        }
    }
    Ok(())
}

fn directory(path: &str) -> rustix::io::Result<Dir> {
    Dir::new(open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn single_thread() -> Result<bool, SandboxError> {
    let mut directory = directory("/proc/self/task").map_err(|_| SandboxError::InvalidProcess)?;
    let expected = std::process::id().to_string();
    let mut found = false;
    // The normal directory has dot, dot-dot and exactly one TID. Stop on the
    // first extra entry rather than enumerating an unbounded hostile process.
    while let Some(entry) = directory.read() {
        let entry = entry.map_err(|_| SandboxError::InvalidProcess)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if found || name != expected.as_bytes() {
            return Ok(false);
        }
        found = true;
    }
    Ok(found)
}

fn descriptors() -> Result<(), SandboxError> {
    let invalid = || SandboxError::InvalidDescriptors;
    let mut directory = directory("/proc/self/fd").map_err(|_| invalid())?;
    let inspector = directory
        .fd()
        .map_err(|_| invalid())?
        .as_raw_fd()
        .to_string();
    let mut seen = [false; 3];
    while let Some(entry) = directory.read() {
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name().to_bytes();
        match name {
            b"." | b".." => (),
            b"0" => seen[0] = true,
            b"1" => seen[1] = true,
            b"2" => seen[2] = true,
            _ if name == inspector.as_bytes() => (),
            _ => return Err(invalid()),
        }
    }
    drop(directory);
    if !seen.into_iter().all(|present| present) {
        return Err(invalid());
    }
    pipe(io::stdin(), "/proc/self/fd/0", OFlags::RDONLY)?;
    pipe(io::stdout(), "/proc/self/fd/1", OFlags::WRONLY)?;
    let stderr = io::stderr();
    let stat = fstat(&stderr).map_err(|_| invalid())?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::Fifo {
        pipe(&stderr, "/proc/self/fd/2", OFlags::WRONLY)?;
    } else if FileType::from_raw_mode(stat.st_mode) != FileType::CharacterDevice
        || major(stat.st_rdev) != 1
        || minor(stat.st_rdev) != 3
        || readlink("/proc/self/fd/2", Vec::new())
            .map_err(|_| invalid())?
            .to_bytes()
            != b"/dev/null"
    {
        return Err(invalid());
    }
    Ok(())
}

fn pipe(fd: impl AsFd, path: &str, mode: OFlags) -> Result<(), SandboxError> {
    let invalid = || SandboxError::InvalidDescriptors;
    let stat = fstat(&fd).map_err(|_| invalid())?;
    let flags = fcntl_getfl(&fd).map_err(|_| invalid())?;
    let link = readlink(path, Vec::new()).map_err(|_| invalid())?;
    let inode = link
        .to_bytes()
        .strip_prefix(b"pipe:[")
        .and_then(|tail| tail.strip_suffix(b"]"));
    if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo
        || flags & OFlags::ACCMODE != mode
        || !inode.is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
    {
        return Err(invalid());
    }
    Ok(())
}

fn hexadecimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

fn mapping(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_ascii_whitespace();
    let (start, end) = fields.next()?.split_once('-')?;
    let range = (hexadecimal(start)?, hexadecimal(end)?);
    let permissions = fields.next()?.as_bytes();
    if !matches!(permissions, [b'r' | b'-', b'w' | b'-', b'x' | b'-', b'p'])
        || permissions[1] == b'w' && permissions[2] == b'x'
    {
        return None;
    }
    hexadecimal(fields.next()?)?;
    let (major, minor) = fields.next()?.split_once(':')?;
    hexadecimal(major)?;
    hexadecimal(minor)?;
    let inode = fields.next()?;
    if !inode.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    inode.parse::<u64>().ok()?;
    // Remaining text is an optional pathname, which may contain spaces.
    Some(range)
}

pub(super) fn private_mappings(text: &str) -> bool {
    if text.contains(['\0', '\r']) {
        return false;
    }
    let mut previous_end = 0;
    for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
        let Some((start, end)) = mapping(line) else {
            return false;
        };
        if start >= end || start < previous_end {
            return false;
        }
        previous_end = end;
    }
    true
}

pub(super) fn native_personality(text: &str) -> bool {
    // In particular, READ_IMPLIES_EXEC must not turn allowed readable maps
    // into executable ones. Other inherited personality flags are unsupported.
    matches!(text, "00000000" | "00000000\n")
}
