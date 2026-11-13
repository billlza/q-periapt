//! Windows file operations for the shared file-publication state machine.
use super::{
    windows::{validate_file, OwnedPrivateDirectory},
    windows_native as native,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
};

pub(super) type Descriptor = native::StagingFile;

pub(super) fn require_absent(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<()> {
    parent.validate()?;
    match native::open(&parent.descriptor, name, native::OpenKind::Metadata) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "private destination already exists",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn create_file(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<Descriptor> {
    parent.validate()?;
    native::create_staging(&parent.descriptor, name)
}

pub(super) fn clone_file(descriptor: &Descriptor) -> io::Result<File> {
    descriptor.file().try_clone()
}

/// Open an existing disposable attempt file, including an empty lease or payload.
/// Normal state admission keeps its separate nonempty-file requirement.
pub(super) fn open_file(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<File> {
    parent.validate()?;
    let file = native::open(&parent.descriptor, name, native::OpenKind::State)?;
    validate_file(&file)?;
    Ok(file)
}

pub(super) fn open_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
) -> io::Result<OwnedPrivateDirectory> {
    parent.validate()?;
    let directory = OwnedPrivateDirectory {
        descriptor: native::open(&parent.descriptor, name, native::OpenKind::PrivateDirectory)?,
    };
    directory.validate()?;
    Ok(directory)
}

fn encoded_identity((volume, index): (u32, u64)) -> [u8; 16] {
    let mut identity = [0; 16];
    identity[..4].copy_from_slice(&volume.to_le_bytes());
    identity[8..].copy_from_slice(&index.to_le_bytes());
    identity
}

pub(super) fn file_identity(file: &File) -> io::Result<[u8; 16]> {
    native::check_local_ntfs(file)?;
    validate_file(file)?;
    Ok(encoded_identity(native::file_identity(file)?))
}

pub(super) fn directory_identity(directory: &OwnedPrivateDirectory) -> io::Result<[u8; 16]> {
    native::check_local_ntfs(&directory.descriptor)?;
    directory.validate()?;
    Ok(encoded_identity(native::directory_identity(
        &directory.descriptor,
    )?))
}

pub(super) fn same_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    same_plain_file(parent, name, original.file())
}

pub(super) fn same_plain_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &File,
) -> io::Result<()> {
    parent.validate()?;
    validate_file(original)?;
    let named = native::open(&parent.descriptor, name, native::OpenKind::Metadata)?;
    validate_file(&named)?;
    native::same_file(original, &named)
}

pub(super) fn rename_file_to(
    source_parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination_parent: &OwnedPrivateDirectory,
    destination: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    same_file(source_parent, name, original)?;
    destination_parent.validate()?;
    native::rename_file(original, &destination_parent.descriptor, destination)
}

/// Publish an existing maintenance control field while its attempt lease is held.
/// The original file pin remains open; native deletion access is acquired only now.
pub(super) fn rename_plain_file_to(
    source_parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination_parent: &OwnedPrivateDirectory,
    destination: &OsStr,
    original: &File,
) -> io::Result<()> {
    same_plain_file(source_parent, name, original)?;
    destination_parent.validate()?;
    native::rename_plain_file_to(
        &source_parent.descriptor,
        name,
        &destination_parent.descriptor,
        destination,
        original,
    )
}

pub(super) fn sync_directory(parent: &OwnedPrivateDirectory) -> io::Result<()> {
    parent.validate()?;
    parent.descriptor.sync_all()
}

pub(super) fn create_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
) -> io::Result<OwnedPrivateDirectory> {
    parent.validate()?;
    let directory = OwnedPrivateDirectory {
        descriptor: native::create(&parent.descriptor, name, true)?,
    };
    directory.validate()?;
    Ok(directory)
}

pub(super) fn same_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    directory: &OwnedPrivateDirectory,
) -> io::Result<()> {
    parent.validate()?;
    directory.validate()?;
    let named = OwnedPrivateDirectory {
        descriptor: native::open(&parent.descriptor, name, native::OpenKind::PrivateDirectory)?,
    };
    named.validate()?;
    native::same_directory(&directory.descriptor, &named.descriptor)
}

pub(super) fn rename_directory_to(
    source_parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination_parent: &OwnedPrivateDirectory,
    destination: &OsStr,
    directory: &OwnedPrivateDirectory,
) -> io::Result<()> {
    same_directory(source_parent, name, directory)?;
    destination_parent.validate()?;
    native::rename_directory(
        directory,
        &source_parent.descriptor,
        name,
        &destination_parent.descriptor,
        destination,
    )
}

/// The caller must retain its independent attempt lease and admitted metadata.
/// Only the separately opened deletion handle is closed by this operation.
pub(super) fn remove_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &File,
) -> io::Result<()> {
    same_plain_file(parent, name, original)?;
    native::remove_file(&parent.descriptor, name, original)?;
    require_absent(parent, name)
}

/// Remove only this admitted empty directory; never traverse or delete children.
pub(super) fn remove_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &OwnedPrivateDirectory,
) -> io::Result<()> {
    same_directory(parent, name, original)?;
    native::remove_directory(&parent.descriptor, name, &original.descriptor)?;
    require_absent(parent, name)
}

pub(super) fn directory_entries(
    parent: &OwnedPrivateDirectory,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    parent.validate()?;
    native::directory_entries(&parent.descriptor, limit)
}
