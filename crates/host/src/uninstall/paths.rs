use super::{Artifact, Result};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    cell::Cell,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn io_error(error: impl Into<std::io::Error>) -> String {
    format!("installation I/O error ({:?})", error.into().kind())
}
pub(super) fn validate_path(path: &Path) -> Result<()> {
    let rebuilt: PathBuf = path.components().collect();
    if !path.is_absolute()
        || path.parent().is_none()
        || rebuilt.as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(
            "installation paths must be absolute, normalized and below the filesystem root".into(),
        );
    }
    Ok(())
}
pub(super) fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn identity(stat: &fs::Stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}
fn stat_entry(dir: &OwnedFd, name: &OsStr) -> Result<Option<fs::Stat>> {
    match fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

pub(super) struct Directory {
    fd: OwnedFd,
    parent: OwnedFd,
    name: OsString,
    id: (u64, u64),
    uid: u32,
    locked: Cell<bool>,
}
impl Directory {
    pub(super) fn open(path: &Path, private: bool, service_user: bool) -> Result<Option<Self>> {
        validate_path(path)?;
        let mut fd = fs::open("/", DIR_FLAGS, Mode::empty()).map_err(io_error)?;
        let parts = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect::<Vec<_>>();
        for (index, part) in parts.iter().enumerate() {
            let next = match fs::openat(&fd, *part, DIR_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(error) => return Err(io_error(error)),
            };
            let stat = fs::fstat(&next).map_err(io_error)?;
            let current = geteuid().as_raw();
            let last = index + 1 == parts.len();
            if last {
                let owner_ok = stat.st_uid == current || (service_user && current == 0);
                let mode_ok = if private {
                    stat.st_mode & 0o7777 == 0o700
                } else {
                    stat.st_mode & 0o7022 == 0
                };
                if !owner_ok || !mode_ok {
                    return Err("unsafe installation directory owner or permissions".into());
                }
                return Ok(Some(Self {
                    fd: next,
                    parent: fd,
                    name: (*part).into(),
                    id: identity(&stat),
                    uid: stat.st_uid,
                    locked: Cell::new(false),
                }));
            }
            // Root-owned sticky /tmp is a supported fixture/custom-path ancestor.
            if (stat.st_uid != 0 && stat.st_uid != current)
                || (stat.st_mode & 0o022 != 0 && !(stat.st_uid == 0 && stat.st_mode & 0o1000 != 0))
            {
                return Err("unsafe installation path ancestor".into());
            }
            fd = next;
        }
        Err("invalid installation directory".into())
    }
    pub(super) fn lock(&self) -> Result<()> {
        if !self.locked.get() {
            fs::flock(&self.fd, fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| "installation or state directory is locked".to_string())?;
            self.locked.set(true);
        }
        Ok(())
    }
    pub(super) fn check_file(&self, name: &str, private: bool) -> Result<Option<fs::Stat>> {
        let Some(stat) = stat_entry(&self.fd, name.as_ref())? else {
            return Ok(None);
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_uid != self.uid
            || if private {
                stat.st_mode & 0o7777 != 0o600
            } else {
                stat.st_mode & 0o7022 != 0
            }
        {
            return Err("unsafe installation file type, owner, links or permissions".into());
        }
        Ok(Some(stat))
    }
    fn read(&self, name: &str, maximum: usize, private: bool) -> Result<Option<Vec<u8>>> {
        let Some(stat) = self.check_file(name, private)? else {
            return Ok(None);
        };
        if stat.st_size < 0 || stat.st_size as u64 > maximum as u64 {
            return Err("installation file exceeds size limit".into());
        }
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io_error)?;
        if identity(&fs::fstat(&fd).map_err(io_error)?) != identity(&stat) {
            return Err("installation file changed".into());
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > maximum {
            return Err("installation file exceeds size limit".into());
        }
        Ok(Some(bytes))
    }
    pub(super) fn read_private(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        self.read(name, maximum, true)
    }
    pub(super) fn check_alias(&self, name: &str, target: &Path) -> Result<()> {
        let stat =
            stat_entry(&self.fd, name.as_ref())?.ok_or("installed command alias is missing")?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Symlink
            || stat.st_uid != self.uid
            || fs::readlinkat(&self.fd, name, Vec::new())
                .map_err(io_error)?
                .as_bytes()
                != target.as_os_str().as_bytes()
        {
            return Err("installed command alias does not match the installation".into());
        }
        Ok(())
    }
    fn still_present(&self) -> Result<()> {
        if stat_entry(&self.parent, &self.name)?.as_ref().map(identity) != Some(self.id) {
            return Err("installation directory changed".into());
        }
        Ok(())
    }
    fn unlink(&self, name: &str, expected: (u64, u64), private: bool) -> Result<()> {
        self.still_present()?;
        if self.check_file(name, private)?.as_ref().map(identity) != Some(expected) {
            return Err("installation file changed".into());
        }
        fs::unlinkat(&self.fd, name, AtFlags::empty()).map_err(io_error)?;
        fs::fsync(&self.fd).map_err(io_error)
    }
    pub(super) fn remove_empty(&self) -> Result<()> {
        self.still_present()?;
        fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR).map_err(io_error)?;
        fs::fsync(&self.parent).map_err(io_error)
    }
    pub(super) fn check_names(&self, allowed: &[&str]) -> Result<()> {
        for name in self.names()? {
            if !allowed.contains(&name.as_str()) {
                return Err(
                    "unrecognized installation entry; removal requires manual review".into(),
                );
            }
        }
        Ok(())
    }
    fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(&self.fd).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| "invalid installation filename")?;
            if name != "." && name != ".." {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }
    pub(super) fn remove_private(&self, name: &str) -> Result<()> {
        if let Some(stat) = self.check_file(name, true)? {
            self.unlink(name, identity(&stat), true)?;
        }
        Ok(())
    }
    pub(super) fn replace_private(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.still_present()?;
        self.check_file(name, true)?
            .ok_or("installation receipt disappeared")?;
        let temporary = format!(".receipt-{:016x}", crate::random_seed()?);
        let fd = fs::openat(
            &self.fd,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(io_error)?;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            fs::renameat(&self.fd, &temporary, &self.fd, name).map_err(io_error)?;
            fs::fsync(&self.fd).map_err(io_error)
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.fd, &temporary, AtFlags::empty());
        }
        result
    }
    /// Replace only a receipt-owned public resource, or exclusively create one.
    pub(super) fn replace_public(
        &self,
        name: &str,
        expected: Option<&[u8]>,
        bytes: &[u8],
    ) -> Result<()> {
        self.still_present()?;
        if self.read(name, super::MAX_RECEIPT, false)?.as_deref() != expected {
            return Err("installed resource changed".into());
        }
        let original = self.check_file(name, false)?.as_ref().map(identity);
        let temporary = format!(".resource-{:016x}", crate::random_seed()?);
        let fd = fs::openat(
            &self.fd,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io_error)?;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(io_error)?;
            fs::fchmod(&file, Mode::from_raw_mode(0o644)).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            self.still_present()?;
            if self.check_file(name, false)?.as_ref().map(identity) != original
                || self.read(name, super::MAX_RECEIPT, false)?.as_deref() != expected
            {
                return Err("installed resource changed".into());
            }
            fs::renameat_with(
                &self.fd,
                &temporary,
                &self.fd,
                name,
                if expected.is_some() {
                    fs::RenameFlags::empty()
                } else {
                    fs::RenameFlags::NOREPLACE
                },
            )
            .map_err(io_error)?;
            fs::fsync(&self.fd).map_err(io_error)
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.fd, &temporary, AtFlags::empty());
        }
        result
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.locked.get() {
            let _ = fs::flock(&self.fd, fs::FlockOperation::Unlock);
        }
    }
}

/// Only installed executable files in the receipt-owned bin directory are removed.
/// Never follows aliases or compares the caller's downloaded executable path.
pub(super) struct OwnedExecutable {
    spec: super::Executable,
    name: String,
    directory: Option<Directory>,
    files: Vec<(String, (u64, u64))>,
    aliases: Option<Directory>,
    alias_id: Option<(u64, u64)>,
}
impl OwnedExecutable {
    pub(super) fn check(spec: &super::Executable, name: &str) -> Result<Self> {
        let directory = Directory::open(&spec.directory, false, false)?;
        let mut files = Vec::new();
        if let Some(directory) = &directory {
            let prefix = format!("{name}.previous-");
            for entry in directory.names()? {
                let backup = entry.strip_prefix(&prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                });
                if entry != name && !backup {
                    return Err(
                        "unrecognized executable entry; removal requires manual review".into(),
                    );
                }
                let stat = directory
                    .check_file(&entry, false)?
                    .ok_or("executable disappeared")?;
                files.push((entry, identity(&stat)));
            }
        }
        let aliases = Directory::open(
            spec.alias.parent().ok_or("invalid alias path")?,
            false,
            false,
        )?;
        let mut alias_id = None;
        if let Some(aliases) = &aliases
            && let Some(stat) = stat_entry(&aliases.fd, name.as_ref())?
        {
            aliases.check_alias(name, &spec.directory.join(name))?;
            alias_id = Some(identity(&stat));
        }
        Ok(Self {
            spec: super::Executable {
                directory: spec.directory.clone(),
                alias: spec.alias.clone(),
            },
            name: name.into(),
            directory,
            files,
            aliases,
            alias_id,
        })
    }
    pub(super) fn recheck(&self) -> Result<()> {
        let current = Self::check(&self.spec, &self.name)?;
        if current.files != self.files
            || current.alias_id != self.alias_id
            || current.directory.as_ref().map(|d| d.id) != self.directory.as_ref().map(|d| d.id)
            || current.aliases.as_ref().map(|d| d.id) != self.aliases.as_ref().map(|d| d.id)
        {
            return Err("installed executable or alias changed".into());
        }
        Ok(())
    }
    pub(super) fn remove(&self) -> Result<()> {
        self.recheck()?;
        if let (Some(aliases), Some(id)) = (&self.aliases, self.alias_id) {
            aliases.still_present()?;
            aliases.check_alias(&self.name, &self.spec.directory.join(&self.name))?;
            if stat_entry(&aliases.fd, self.name.as_ref())?
                .as_ref()
                .map(identity)
                != Some(id)
            {
                return Err("installed alias changed".into());
            }
            fs::unlinkat(&aliases.fd, &self.name, AtFlags::empty()).map_err(io_error)?;
            fs::fsync(&aliases.fd).map_err(io_error)?;
        }
        if let Some(directory) = &self.directory {
            for (name, id) in &self.files {
                directory.unlink(name, *id, false)?;
            }
            directory.remove_empty()?;
        }
        Ok(())
    }
}

pub(super) struct OwnedArtifact {
    directory: Option<Directory>,
    artifact: Artifact,
    id: Option<(u64, u64)>,
}
impl OwnedArtifact {
    pub(super) fn check(artifact: &Artifact) -> Result<Self> {
        let directory = Directory::open(
            artifact.path.parent().ok_or("invalid artifact path")?,
            false,
            false,
        )?;
        let mut id = None;
        if let Some(directory) = &directory {
            let name = artifact
                .path
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or("invalid artifact name")?;
            if let Some(bytes) = directory.read(name, super::MAX_RECEIPT, false)? {
                if bytes != artifact.contents.as_bytes() {
                    return Err("installed artifact was modified; refusing removal".into());
                }
                id = directory.check_file(name, false)?.as_ref().map(identity);
            }
        }
        Ok(Self {
            directory,
            artifact: Artifact {
                path: artifact.path.clone(),
                contents: artifact.contents.clone(),
            },
            id,
        })
    }
    pub(super) fn present(&self) -> bool {
        self.id.is_some()
    }
    pub(super) fn recheck(&self) -> Result<()> {
        if Self::check(&self.artifact)?.id != self.id {
            return Err("installed artifact changed".into());
        }
        Ok(())
    }
    pub(super) fn remove(&self) -> Result<()> {
        if let (Some(directory), Some(id)) = (&self.directory, self.id) {
            self.recheck()?;
            directory.unlink(
                self.artifact
                    .path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .ok_or("invalid artifact name")?,
                id,
                false,
            )?;
        }
        Ok(())
    }
}

pub(super) struct DataDirectory {
    directory: Option<Directory>,
    path: PathBuf,
    names: Vec<String>,
    files: Vec<(String, (u64, u64))>,
}
impl DataDirectory {
    pub(super) fn check(path: &Path, names: &[&str], purge: bool) -> Result<Self> {
        let directory = Directory::open(path, true, true)?;
        let mut files = Vec::new();
        if let Some(directory) = &directory {
            if purge {
                for entry in fs::Dir::read_from(&directory.fd).map_err(io_error)? {
                    let entry = entry.map_err(io_error)?;
                    let name = entry.file_name().to_bytes();
                    // The running Management owns this transient socket. Stop
                    // its recorded service before purge; never unlink a live
                    // socket or treat it as a durable private state file.
                    if name == b"api.sock" && names.contains(&"state.json") {
                        let socket =
                            fs::statat(&directory.fd, "api.sock", AtFlags::SYMLINK_NOFOLLOW)
                                .map_err(io_error)?;
                        if FileType::from_raw_mode(socket.st_mode) != FileType::Socket
                            || socket.st_uid != directory.uid
                            || socket.st_mode & 0o7777 != 0o600
                        {
                            return Err("unsafe runtime socket".into());
                        }
                        continue;
                    }
                    if name != b"."
                        && name != b".."
                        && !names.iter().any(|allowed| allowed.as_bytes() == name)
                    {
                        return Err("unrecognized data entry; purge requires manual review".into());
                    }
                }
            }
            for name in names {
                if let Some(stat) = directory.check_file(name, true)? {
                    files.push(((*name).into(), identity(&stat)));
                }
            }
        }
        Ok(Self {
            directory,
            path: path.into(),
            names: names.iter().map(|s| (*s).into()).collect(),
            files,
        })
    }
    pub(super) fn same_directory(&self, other: &Self) -> bool {
        matches!((&self.directory, &other.directory), (Some(a), Some(b)) if a.id == b.id)
    }
    pub(super) fn lock(&self) -> Result<()> {
        if let Some(directory) = &self.directory {
            directory.lock()?;
        }
        Ok(())
    }
    pub(super) fn recheck(&self) -> Result<()> {
        let current = Self::check(
            &self.path,
            &self.names.iter().map(String::as_str).collect::<Vec<_>>(),
            true,
        )?;
        if self.files != current.files
            || self.directory.as_ref().map(|d| d.id) != current.directory.as_ref().map(|d| d.id)
        {
            return Err("data directory changed".into());
        }
        Ok(())
    }
    pub(super) fn refresh_after_stop(&mut self) -> Result<()> {
        // Shutdown may atomically publish a final snapshot. Once the retained
        // directory is locked, accept its current protected, known files.
        let current = Self::check(
            &self.path,
            &self.names.iter().map(String::as_str).collect::<Vec<_>>(),
            true,
        )?;
        if self.directory.as_ref().map(|d| d.id) != current.directory.as_ref().map(|d| d.id) {
            return Err("data directory changed".into());
        }
        self.files = current.files;
        Ok(())
    }
    pub(super) fn remove(&self) -> Result<()> {
        self.recheck()?;
        if let Some(directory) = &self.directory {
            for (name, id) in &self.files {
                directory.unlink(name, *id, true)?;
            }
            // The state lock is held and the service has stopped. A killed
            // Manager may leave its Unix socket behind; never follow it.
            if self.names.iter().any(|name| name == "state.json")
                && let Some(stat) = stat_entry(&directory.fd, "api.sock".as_ref())?
            {
                if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
                    || stat.st_uid != directory.uid
                    || stat.st_mode & 0o7777 != 0o600
                {
                    return Err("unsafe runtime socket".into());
                }
                if !directory.locked.get() {
                    return Err("runtime socket removal requires the state lock".into());
                }
                fs::unlinkat(&directory.fd, "api.sock", AtFlags::empty()).map_err(io_error)?;
                fs::fsync(&directory.fd).map_err(io_error)?;
            }
            directory.remove_empty()?;
        }
        Ok(())
    }
}
