use crate::{CommitStage, StoreError, path};
use rustix::{fd::OwnedFd, fs};
use std::{
    io::{self, Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

/// Private filesystem mechanics shared by the two typed stores.
#[derive(Debug)]
pub(crate) struct LockedDirectory {
    directory: OwnedFd,
    // A reopened directory may contain a rename whose fsync never completed.
    confirmed: AtomicBool,
    #[cfg(test)]
    pub(crate) confirmation: ConfirmationProbe,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct ConfirmationProbe {
    pub(crate) fail: std::sync::atomic::AtomicBool,
    pub(crate) attempts: std::sync::atomic::AtomicUsize,
}

impl Drop for LockedDirectory {
    fn drop(&mut self) {
        // Concurrent fork/exec can briefly inherit this open file description.
        // Release the lock without waiting for those CLOEXEC copies to close.
        let _ = fs::flock(&self.directory, fs::FlockOperation::Unlock);
    }
}

impl LockedDirectory {
    pub(crate) fn confirm_if_needed(&self) -> Result<(), StoreError> {
        // Publish requires exclusive ownership through the typed stores. Shared
        // readers may reuse a completed confirmation; they never publish state.
        if !self.confirmed.load(Ordering::Acquire) {
            self.confirm()?;
        }
        Ok(())
    }

    pub(crate) fn confirm(&self) -> Result<(), StoreError> {
        #[cfg(test)]
        {
            self.confirmation.attempts.fetch_add(1, Ordering::Relaxed);
            if self.confirmation.fail.load(Ordering::Relaxed) {
                return Err(io::Error::other("injected confirmation failure").into());
            }
        }
        path::check_directory(&self.directory)?;
        path::existing(&self.directory, "state.json")?
            .ok_or(StoreError::InvalidState)?
            .sync_all()?;
        fs::fsync(&self.directory)?;
        self.confirmed.store(true, Ordering::Release);
        Ok(())
    }
    pub(crate) fn acquire(path: &Path, initialize: bool) -> Result<Self, StoreError> {
        let directory = path::directory(path, initialize)?;
        match fs::flock(&directory, fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self {
                directory,
                confirmed: AtomicBool::new(false),
                #[cfg(test)]
                confirmation: ConfirmationProbe::default(),
            }),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(StoreError::Locked),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn read(&self, maximum: usize) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        path::check_directory(&self.directory)?;
        let Some(mut file) = path::existing(&self.directory, "state.json")? else {
            return Ok(None);
        };
        let length =
            usize::try_from(file.metadata()?.len()).map_err(|_| StoreError::InvalidState)?;
        if length > maximum {
            return Err(StoreError::InvalidState);
        }
        // Even a wrong-role load can read Gateway secrets before decoding fails.
        // Allocate once before reading; never grow a secret-bearing allocation.
        let capacity = length.checked_add(1).ok_or(StoreError::InvalidState)?;
        let mut bytes = Zeroizing::new(vec![0u8; capacity]);
        let mut filled = 0;
        while filled < bytes.len() {
            match file.read(&mut bytes[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        if filled != length {
            return Err(StoreError::InvalidState);
        }
        // The unused tail contains only its initial zeros; capacity never changes.
        bytes.truncate(filled);
        Ok(Some(bytes))
    }

    pub(crate) fn publish(
        &self,
        bytes: &[u8],
        mut checkpoint: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let mut staged = path::stage(&self.directory)?;
        checkpoint(CommitStage::AfterCreate)?;
        staged.write_all(bytes)?;
        checkpoint(CommitStage::AfterWrite)?;
        staged.sync_all()?;
        checkpoint(CommitStage::AfterFileSync)?;
        fs::renameat(&self.directory, ".pending", &self.directory, "state.json")?;
        // The visible revision must not become authoritative until its directory
        // entry is durable. Leave it unconfirmed on every post-rename failure.
        self.confirmed.store(false, Ordering::Release);
        checkpoint(CommitStage::AfterRename).map_err(|_| StoreError::CommitUncertain)?;
        fs::fsync(&self.directory).map_err(|_| StoreError::CommitUncertain)?;
        checkpoint(CommitStage::AfterDirectorySync).map_err(|_| StoreError::CommitUncertain)?;
        self.confirmed.store(true, Ordering::Release);
        Ok(())
    }
}
