//! Installation paths are walked by directory descriptors, without symlinks.
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};
type Result<T> = std::result::Result<T, String>;
const FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
pub(crate) struct Directory(OwnedFd);

#[must_use]
pub(super) struct DirectoryLock<'a>(&'a OwnedFd);

impl Drop for DirectoryLock<'_> {
    fn drop(&mut self) {
        // A forked child can retain the open file description until exec.
        let _ = fs::flock(self.0, fs::FlockOperation::Unlock);
    }
}
impl Directory {
    pub fn create(path: &Path, private: bool) -> Result<Self> {
        Self::walk(path, private, true)?.ok_or("installation directory is missing".into())
    }
    pub fn open(path: &Path, private: bool) -> Result<Option<Self>> {
        Self::walk(path, private, false)
    }
    fn walk(path: &Path, private: bool, create: bool) -> Result<Option<Self>> {
        let mut directory =
            fs::open("/", FLAGS, Mode::empty()).map_err(|_| "cannot open installation root")?;
        let parts: Vec<_> = path
            .components()
            .filter_map(|part| {
                if let Component::Normal(name) = part {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        if !path.is_absolute()
            || parts.is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err("invalid installation path".into());
        }
        for (index, name) in parts.iter().enumerate() {
            let parent = fs::fstat(&directory).map_err(|_| "cannot inspect installation parent")?;
            if (parent.st_uid != 0 && parent.st_uid != geteuid().as_raw())
                || (parent.st_mode & 0o022 != 0
                    && !(parent.st_uid == 0 && parent.st_mode & 0o1000 != 0))
            {
                return Err("unsafe installation ancestor".into());
            }
            let last = index + 1 == parts.len();
            let mode = Mode::from_raw_mode(if last && private { 0o700 } else { 0o755 });
            let next = match fs::openat(&directory, *name, FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if create => {
                    fs::mkdirat(&directory, *name, mode)
                        .map_err(|_| "cannot create installation directory")?;
                    fs::fsync(&directory).map_err(|_| "cannot sync installation parent")?;
                    let created = fs::openat(&directory, *name, FLAGS, Mode::empty())
                        .map_err(|_| "cannot open created directory")?;
                    fs::fchmod(&created, mode)
                        .map_err(|_| "cannot set created directory permissions")?;
                    created
                }
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(_) => return Err("unsafe installation directory".into()),
            };
            if last {
                let stat = fs::fstat(&next).map_err(|_| "cannot inspect installation directory")?;
                if stat.st_uid != geteuid().as_raw()
                    || (private && stat.st_mode & 0o7777 != 0o700)
                    || stat.st_mode & 0o7022 != 0
                {
                    return Err("unsafe installation directory permissions".into());
                }
            }
            directory = next;
        }
        Ok(Some(Self(directory)))
    }
    pub fn absent(&self, name: &str) -> Result<()> {
        match fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err(format!(
                "installation artifact already exists or is inaccessible: {name}"
            )),
        }
    }
    pub(super) fn lock(&self) -> Result<DirectoryLock<'_>> {
        fs::flock(&self.0, fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "another installation operation is active")?;
        Ok(DirectoryLock(&self.0))
    }
    pub fn write(&self, name: &str, bytes: &[u8], executable: bool) -> Result<()> {
        let mut file = self.new_file(name, executable)?;
        file.write_all(bytes)
            .map_err(|_| "cannot write installation artifact")?;
        file.sync_all()
            .map_err(|_| "cannot sync installation artifact")?;
        fs::fsync(&self.0).map_err(|_| "cannot sync installation directory".into())
    }
    pub fn write_public(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = self.new_file(name, false)?;
        file.write_all(bytes)
            .map_err(|_| "cannot write installed resource")?;
        fs::fchmod(&file, Mode::from_raw_mode(0o644))
            .map_err(|_| "cannot set installed resource permissions")?;
        file.sync_all()
            .map_err(|_| "cannot sync installed resource")?;
        fs::fsync(&self.0).map_err(|_| "cannot sync installed resource directory".into())
    }
    fn new_file(&self, name: &str, executable: bool) -> Result<File> {
        let fd = fs::openat(
            &self.0,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(if executable { 0o755 } else { 0o600 }),
        )
        .map_err(|_| "cannot exclusively create installation artifact")?;
        Ok(File::from(fd))
    }
    pub fn binary(&self, name: &str, source: &mut File) -> Result<()> {
        match fs::openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let stat = fs::fstat(&fd).map_err(|_| "cannot inspect installed executable")?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || stat.st_nlink != 1
                    || stat.st_uid != geteuid().as_raw()
                    || stat.st_mode & 0o7777 != 0o755
                {
                    return Err("unsafe installed executable".into());
                }
                let mut installed = File::from(fd);
                let mut first = [0; 8192];
                let mut second = [0; 8192];
                loop {
                    let a = source
                        .read(&mut first)
                        .map_err(|_| "cannot compare executable")?;
                    installed
                        .read_exact(&mut second[..a])
                        .map_err(|_| "installed executable differs; upgrade separately")?;
                    if first[..a] != second[..a] {
                        return Err("installed executable differs; upgrade separately".into());
                    }
                    if a == 0 {
                        if installed
                            .read(&mut second[..1])
                            .map_err(|_| "cannot compare executable")?
                            != 0
                        {
                            return Err("installed executable differs".into());
                        }
                        return Ok(());
                    }
                }
            }
            Err(rustix::io::Errno::NOENT) => (),
            Err(_) => return Err("cannot inspect installed executable".into()),
        }
        let mut target = self.new_file(name, true)?;
        std::io::copy(source, &mut target).map_err(|_| "cannot copy executable")?;
        fs::fchmod(&target, Mode::from_raw_mode(0o755))
            .map_err(|_| "cannot set installed executable permissions")?;
        target.sync_all().map_err(|_| "cannot sync executable")?;
        fs::fsync(&self.0).map_err(|_| "cannot sync binary directory".into())
    }
    pub fn alias(&self, name: &str, target: &Path) -> Result<()> {
        match fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink
                    && stat.st_uid == geteuid().as_raw() =>
            {
                let existing = fs::readlinkat(&self.0, name, Vec::new())
                    .map_err(|_| "cannot read existing alias")?;
                if OsStr::new(existing.to_str().map_err(|_| "invalid alias")?) != target.as_os_str()
                {
                    return Err("existing command alias differs".into());
                }
            }
            Err(rustix::io::Errno::NOENT) => {
                fs::symlinkat(target, &self.0, name).map_err(|_| "cannot create command alias")?;
            }
            _ => return Err("existing command path is not an owned alias".into()),
        }
        fs::fsync(&self.0).map_err(|_| "cannot sync command directory".into())
    }
}

pub(super) struct BinaryUpdate {
    name: &'static str,
    directory: Directory,
    old: File,
    source: File,
    staged: Option<String>,
    committed: bool,
}
impl BinaryUpdate {
    pub fn inspect(path: &Path, name: &'static str, source: File) -> Result<Self> {
        let directory =
            Directory::open(path, false)?.ok_or("installed binary directory is missing")?;
        let fd = fs::openat(
            &directory.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "installed binary is missing or unsafe")?;
        let stat = fs::fstat(&fd).map_err(|_| "cannot inspect installed binary")?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_uid != geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o755
        {
            return Err("unsafe installed binary owner, type or permissions".into());
        }
        Ok(Self {
            name,
            directory,
            old: File::from(fd),
            source,
            staged: None,
            committed: false,
        })
    }
    pub fn unchanged(&mut self) -> Result<bool> {
        self.old
            .rewind()
            .map_err(|_| "cannot rewind installed binary")?;
        self.source
            .rewind()
            .map_err(|_| "cannot rewind update executable")?;
        let mut left = [0; 8192];
        let mut right = [0; 8192];
        loop {
            let count = self
                .source
                .read(&mut left)
                .map_err(|_| "cannot read update executable")?;
            match self.old.read_exact(&mut right[..count]) {
                Ok(()) if left[..count] == right[..count] => (),
                Ok(()) => return Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(false);
                }
                Err(_) => return Err("cannot compare installed binary".into()),
            }
            if count == 0 {
                return self
                    .old
                    .read(&mut right[..1])
                    .map(|count| count == 0)
                    .map_err(|_| "cannot compare installed binary".into());
            }
        }
    }
    pub fn stage(&mut self) -> Result<()> {
        let mut random = [0u8; 16];
        aws_lc_rs::rand::fill(&mut random).map_err(|_| "cannot generate update filename")?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = format!("{}.previous-{suffix}", self.name);
        let mut file = self.directory.new_file(&name, false)?;
        self.staged = Some(name);
        self.source
            .seek(SeekFrom::Start(0))
            .map_err(|_| "cannot rewind update executable")?;
        std::io::copy(&mut self.source, &mut file).map_err(|_| "cannot stage update executable")?;
        fs::fchmod(&file, Mode::from_raw_mode(0o755))
            .map_err(|_| "cannot set update executable permissions")?;
        file.sync_all()
            .map_err(|_| "cannot sync staged update executable")?;
        fs::fsync(&self.directory.0).map_err(|_| "cannot sync staged update directory".into())
    }
    pub fn commit(&mut self) -> Result<()> {
        let old = fs::fstat(&self.old).map_err(|_| "cannot inspect original binary")?;
        let current = fs::statat(&self.directory.0, self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "installed binary disappeared")?;
        if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino) {
            return Err("installed binary changed during update".into());
        }
        let name = self.staged.as_ref().ok_or("update binary was not staged")?;
        fs::renameat_with(
            &self.directory.0,
            name.as_str(),
            &self.directory.0,
            self.name,
            fs::RenameFlags::EXCHANGE,
        )
        .map_err(|_| "cannot atomically replace installed binary")?;
        self.committed = true;
        fs::fsync(&self.directory.0).map_err(|_| {
            "binary replaced but syncing the directory failed; previous binary retained".into()
        })
    }
    pub fn backup_name(&self) -> Option<&str> {
        self.committed.then_some(self.staged.as_deref()).flatten()
    }
}
impl Drop for BinaryUpdate {
    fn drop(&mut self) {
        if !self.committed
            && let Some(name) = &self.staged
        {
            let _ = fs::unlinkat(&self.directory.0, name.as_str(), AtFlags::empty());
            let _ = fs::fsync(&self.directory.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_releases_its_lock_even_if_a_child_inherited_the_descriptor() {
        let path = std::env::temp_dir().join(format!("wgfeel-install-lock-{}", std::process::id()));
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let inherited = {
            let directory = Directory::open(&path, true).unwrap().unwrap();
            let _lock = directory.lock().unwrap();
            rustix::io::dup(&directory.0).unwrap()
        };
        let directory = Directory::open(&path, true).unwrap().unwrap();
        let result = directory.lock();
        drop(inherited);
        std::fs::remove_dir(path).unwrap();
        assert!(result.is_ok());
    }
}
