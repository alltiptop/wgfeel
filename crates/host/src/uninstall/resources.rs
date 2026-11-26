//! Receipt-owned manuals and shell adapters. No shell is executed by installation.
use super::{Artifact, Directory, OwnedArtifact, Receipt, Result};
use std::path::Path;

pub(super) fn artifacts(root: &Path) -> Vec<Artifact> {
    crate::help::resources()
        .into_iter()
        .map(|(relative, contents)| Artifact {
            path: root.join("usr/local/share").join(relative),
            contents,
        })
        .collect()
}

struct Change {
    previous: Option<Artifact>,
    next: Artifact,
}

pub(crate) struct Update<'a> {
    directory: &'a Directory,
    name: String,
    previous: Vec<u8>,
    next: Vec<u8>,
    changes: Vec<Change>,
}
impl<'a> Update<'a> {
    pub(super) fn inspect(
        root: &Path,
        directory: &'a Directory,
        receipt: &Receipt,
    ) -> Result<Self> {
        let name = super::RECEIPT.to_owned();
        let previous = directory
            .read_private(&name, super::MAX_RECEIPT)?
            .ok_or("installation receipt disappeared")?;
        let mut updated: Receipt =
            serde_json::from_slice(&previous).map_err(|_| "invalid installation receipt")?;
        let mut changes = Vec::new();
        for next in artifacts(root) {
            let old = receipt.resources.iter().find(|item| item.path == next.path);
            if let Some(old) = old {
                if !OwnedArtifact::check(old)?.present() {
                    return Err("installed resource is missing".into());
                }
                if old.contents == next.contents {
                    continue;
                }
            } else {
                let parent = crate::install::paths::Directory::open(
                    next.path.parent().ok_or("invalid resource path")?,
                    false,
                )?;
                if let Some(parent) = parent {
                    parent.absent(
                        next.path
                            .file_name()
                            .and_then(|value| value.to_str())
                            .ok_or("invalid resource name")?,
                    )?;
                }
            }
            changes.push(Change {
                previous: old.map(|old| Artifact {
                    path: old.path.clone(),
                    contents: old.contents.clone(),
                }),
                next,
            });
        }
        updated.resources = artifacts(root);
        let next =
            serde_json::to_vec(&updated).map_err(|_| "cannot encode installation receipt")?;
        if next.len() > super::MAX_RECEIPT {
            return Err("installation receipt exceeds size limit".into());
        }
        Ok(Self {
            directory,
            name,
            previous,
            next,
            changes,
        })
    }
    pub fn unchanged(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn apply(&self) -> Result<()> {
        if self.unchanged() {
            return Ok(());
        }
        let result = (|| {
            for change in &self.changes {
                write(&change.next, change.previous.as_ref())?;
            }
            self.directory.replace_private(&self.name, &self.next)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => match self.rollback() {
                Ok(()) => Err(error),
                Err(recovery) => Err(format!("{error}; resource recovery failed: {recovery}")),
            },
        }
    }

    pub fn rollback(&self) -> Result<()> {
        let mut failures = Vec::new();
        for change in self.changes.iter().rev() {
            let restore = || {
                if let Some(previous) = &change.previous {
                    // A failure may have happened either before or after rename.
                    if OwnedArtifact::check(previous).is_ok_and(|item| item.present()) {
                        return Ok(());
                    }
                    write(previous, Some(&change.next))
                } else {
                    OwnedArtifact::check(&change.next)?.remove()
                }
            };
            if let Err(error) = restore() {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            self.directory.replace_private(&self.name, &self.previous)
        } else {
            Err(failures.join("; "))
        }
    }
}

fn write(next: &Artifact, previous: Option<&Artifact>) -> Result<()> {
    let parent = next.path.parent().ok_or("invalid resource path")?;
    crate::install::paths::Directory::create(parent, false)?;
    let directory =
        Directory::open(parent, false, false)?.ok_or("resource directory disappeared")?;
    let name = next
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("invalid resource name")?;
    directory.replace_public(
        name,
        previous.map(|item| item.contents.as_bytes()),
        next.contents.as_bytes(),
    )
}
