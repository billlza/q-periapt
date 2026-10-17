//! Private file admission on local Windows NTFS. Directory-tree publication is
//! deliberately separate: open children prevent its current live-owner contract.

use super::{windows_native as native, PrivateFileError};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    path::{Component, Path, Prefix},
};

/// File identity on admitted local NTFS. This is correlation metadata, not an
/// authorization or permanent identity: file IDs can be reused after deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsFileIdentity {
    volume: u32,
    index: u64,
}
impl WindowsFileIdentity {
    /// Volume serial number reported by the open file handle.
    pub fn volume_serial(self) -> u32 {
        self.volume
    }
    /// Opaque 64-bit NTFS file index reported by the open file handle.
    pub fn file_index(self) -> u64 {
        self.index
    }
}

/// Read identity only after verifying local NTFS, regular single-link shape and
/// the current-user private DACL. The caller must separately authenticate its
/// retained expectation, contents, parent namespace and lifetime lock.
pub fn private_file_identity(file: &File) -> Result<WindowsFileIdentity, PrivateFileError> {
    native::check_local_ntfs(file).map_err(|_| PrivateFileError)?;
    let (volume, index) = native::file_identity(file).map_err(|_| PrivateFileError)?;
    crate::windows_acl::validate(file).map_err(|_| PrivateFileError)?;
    Ok(WindowsFileIdentity { volume, index })
}

/// An authenticated current-user-owned private directory on local Windows NTFS.
/// File operations and synchronization retain this original directory handle.
pub struct OwnedPrivateDirectory {
    pub(super) descriptor: File,
}

impl OwnedPrivateDirectory {
    /// Open an absolute private directory through non-reparse drive-relative traversal.
    pub fn open(path: &Path) -> Result<Self, PrivateFileError> {
        Self::open_admitted(path).map_err(|_| PrivateFileError)
    }

    fn open_admitted(path: &Path) -> io::Result<Self> {
        let mut components = path.components().peekable();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(native::denied());
        };
        let letter = match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(native::denied()),
        };
        if components.next() != Some(Component::RootDir) || components.peek().is_none() {
            return Err(native::denied());
        }
        let mut descriptor = native::drive_root(letter)?;
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(native::denied());
            };
            descriptor = native::open(
                &descriptor,
                name,
                if components.peek().is_some() {
                    native::OpenKind::TraverseDirectory
                } else {
                    native::OpenKind::PrivateDirectory
                },
            )?;
            native::check_directory(&descriptor)?;
        }
        crate::windows_acl::validate(&descriptor)?;
        Ok(Self { descriptor })
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        native::check_directory(&self.descriptor)?;
        crate::windows_acl::validate(&self.descriptor)
    }

    /// Open a fixed-name, nonempty private configuration file for reading only.
    /// The maximum bounds the admitted length; callers must also bound their reads.
    pub fn open_config_file(&self, name: &str, maximum: usize) -> Result<File, PrivateFileError> {
        let operation = || -> io::Result<File> {
            self.validate()?;
            let file = native::open(
                &self.descriptor,
                OsStr::new(name),
                native::OpenKind::Configuration,
            )?;
            let length = validate_file(&file)?;
            let maximum = u64::try_from(maximum).map_err(|_| native::denied())?;
            if length == 0 || length > maximum {
                return Err(native::denied());
            }
            Ok(file)
        };
        operation().map_err(|_| PrivateFileError)
    }

    /// Open a nonempty private state leaf beneath this pinned directory.
    pub fn open_state_file(&self, name: &OsStr) -> Result<File, PrivateFileError> {
        open_private_leaf(self, name, false)
    }

    /// Recheck ownership and DACL, then flush this same pinned directory.
    pub fn sync_entries(&self) -> Result<(), PrivateFileError> {
        self.validate().map_err(|_| PrivateFileError)?;
        self.descriptor.sync_all().map_err(|_| PrivateFileError)
    }
}

/// Authenticate a private parent and return its validated single leaf name.
pub fn open_private_parent(
    path: &Path,
) -> Result<(OwnedPrivateDirectory, &OsStr), PrivateFileError> {
    let parent = path.parent().ok_or(PrivateFileError)?;
    let name = path.file_name().ok_or(PrivateFileError)?;
    native::leaf(name).map_err(|_| PrivateFileError)?;
    Ok((OwnedPrivateDirectory::open(parent)?, name))
}

pub(super) fn validate_file(file: &File) -> io::Result<u64> {
    let length = native::file_length(file)?;
    crate::windows_acl::validate(file)?;
    Ok(length)
}

pub(super) fn open_private_leaf(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    create: bool,
) -> Result<File, PrivateFileError> {
    let operation = || -> io::Result<File> {
        parent.validate()?;
        let file = if create {
            native::create(&parent.descriptor, name, false)?
        } else {
            native::open(&parent.descriptor, name, native::OpenKind::State)?
        };
        let length = validate_file(&file)?;
        if !create && length == 0 {
            return Err(native::denied());
        }
        if create {
            file.sync_all()?;
            parent.validate()?;
            parent.descriptor.sync_all()?;
        }
        Ok(file)
    };
    operation().map_err(|_| PrivateFileError)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod configuration_tests;
