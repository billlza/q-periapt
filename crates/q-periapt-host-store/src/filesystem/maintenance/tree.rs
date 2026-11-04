use super::{PublicationCleanupLimits, PublicationMaintenanceError as Error};
use crate::filesystem::{publication_ops as ops, LockedFileBackend, OwnedPrivateDirectory};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
};

#[derive(Clone, Copy, Default)]
pub(super) struct Usage {
    pub entries: u64,
    pub bytes: u64,
}
pub(super) enum Tree {
    File {
        file: File,
        _owner: LockedFileBackend,
    },
    Directory {
        directory: OwnedPrivateDirectory,
        children: Vec<(OsString, Tree)>,
    },
}
pub(super) fn lock(file: File) -> Result<LockedFileBackend, Error> {
    LockedFileBackend::new(file).map_err(|error| match error {
        redb::DatabaseError::DatabaseAlreadyOpen => Error::Busy,
        other => Error::Io(io::Error::other(other)),
    })
}
fn same_volume(identity: [u8; 16], volume: [u8; 16]) -> Result<(), Error> {
    if identity.get(..8) != volume.get(..8) {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(super) fn file(
    file: File,
    volume: [u8; 16],
    budget: PublicationCleanupLimits,
    used: &mut Usage,
) -> Result<Tree, Error> {
    let owner = lock(file.try_clone()?)?;
    same_volume(ops::file_identity(&file)?, volume)?;
    used.entries = used.entries.checked_add(1).ok_or(Error::Limit)?;
    used.bytes = used
        .bytes
        .checked_add(file.metadata()?.len())
        .ok_or(Error::Limit)?;
    if used.entries > u64::try_from(budget.entries).map_err(|_| Error::Limit)?
        || used.bytes > budget.bytes
    {
        return Err(Error::Limit);
    }
    Ok(Tree::File {
        file,
        _owner: owner,
    })
}
pub(super) fn directory(
    directory: OwnedPrivateDirectory,
    volume: [u8; 16],
    budget: PublicationCleanupLimits,
    depth: usize,
    used: &mut Usage,
) -> Result<Tree, Error> {
    if depth > budget.depth {
        return Err(Error::Limit);
    }
    same_volume(ops::directory_identity(&directory)?, volume)?;
    used.entries = used.entries.checked_add(1).ok_or(Error::Limit)?;
    let remaining = u64::try_from(budget.entries)
        .map_err(|_| Error::Limit)?
        .checked_sub(used.entries)
        .ok_or(Error::Limit)?;
    let names = ops::directory_entries(
        &directory,
        usize::try_from(remaining)
            .map_err(|_| Error::Limit)?
            .checked_add(1)
            .ok_or(Error::Limit)?,
    )?;
    if u64::try_from(names.len()).map_err(|_| Error::Limit)? > remaining {
        return Err(Error::Limit);
    }
    // Every child, including a regular file, occupies the next payload depth.
    // Refuse before opening or locking any entry outside the admitted depth.
    if !names.is_empty() && depth >= budget.depth {
        return Err(Error::Limit);
    }
    let mut children = Vec::with_capacity(names.len());
    for name in names {
        let child = match ops::open_directory(&directory, &name) {
            Ok(child) => self::directory(
                child,
                volume,
                budget,
                depth.checked_add(1).ok_or(Error::Limit)?,
                used,
            )?,
            Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
                file(ops::open_file(&directory, &name)?, volume, budget, used)?
            }
            Err(error) => return Err(error.into()),
        };
        children.push((name, child));
    }
    Ok(Tree::Directory {
        directory,
        children,
    })
}
impl Tree {
    pub(super) fn identity(&self) -> io::Result<[u8; 16]> {
        match self {
            Self::File { file, .. } => ops::file_identity(file),
            Self::Directory { directory, .. } => ops::directory_identity(directory),
        }
    }
    pub(super) fn remove(
        &self,
        parent: &OwnedPrivateDirectory,
        name: &OsStr,
        on_remove: &mut impl FnMut() -> io::Result<()>,
    ) -> Result<(), Error> {
        match self {
            Self::File { file, .. } => ops::remove_file(parent, name, file)?,
            Self::Directory {
                directory,
                children,
            } => {
                ops::same_directory(parent, name, directory)?;
                // Every child was admitted and all file leases were acquired in
                // the completed preflight. Never discover new names while deleting.
                for (name, child) in children {
                    child.remove(directory, name, on_remove)?;
                }
                ops::sync_directory(directory)?;
                ops::remove_directory(parent, name, directory)?;
            }
        }
        on_remove()?;
        Ok(())
    }
}
