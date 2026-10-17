//! Windows file operations for the shared file-publication state machine.
use super::{
    windows::{validate_file, OwnedPrivateDirectory},
    windows_native as native,
};
use std::{ffi::OsStr, fs::File, io};

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

pub(super) fn same_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    parent.validate()?;
    validate_file(original.file())?;
    let named = native::open(&parent.descriptor, name, native::OpenKind::Metadata)?;
    validate_file(&named)?;
    native::same_file(original.file(), &named)
}

pub(super) fn rename_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    same_file(parent, name, original)?;
    native::rename_file(original, &parent.descriptor, destination)
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

pub(super) fn rename_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination: &OsStr,
    directory: &OwnedPrivateDirectory,
) -> io::Result<()> {
    same_directory(parent, name, directory)?;
    native::rename_directory(directory, &parent.descriptor, destination)
}
