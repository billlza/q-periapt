//! Private file admission on local Windows NTFS. Directory-tree publication is
//! deliberately separate: open children prevent its current live-owner contract.

use super::{windows_native as native, PrivateFileError};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    path::{Component, Path, Prefix},
};

pub(super) struct OwnedPrivateDirectory {
    pub(super) descriptor: File,
}

impl OwnedPrivateDirectory {
    fn open(path: &Path) -> io::Result<Self> {
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
}

pub(super) fn open_private_parent(
    path: &Path,
) -> Result<(OwnedPrivateDirectory, &OsStr), PrivateFileError> {
    let parent = path.parent().ok_or(PrivateFileError)?;
    let name = path.file_name().ok_or(PrivateFileError)?;
    native::leaf(name).map_err(|_| PrivateFileError)?;
    Ok((
        OwnedPrivateDirectory::open(parent).map_err(|_| PrivateFileError)?,
        name,
    ))
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
