//! Platform operations used by the shared publication state machines.
//!
//! These helpers do not remove names, retry operations, or decide whether an
//! uncertain publication committed. Those decisions stay with the caller.

use super::{validate_private_directory, validate_regular_file, OwnedPrivateDirectory};
use std::{ffi::OsStr, fs::File, io, os::fd::OwnedFd};

pub(super) type Descriptor = OwnedFd;

fn admission() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private publication admission failed",
    )
}

pub(super) fn require_absent(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<()> {
    use rustix::fs::{statat, AtFlags};
    match statat(&parent.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "private destination already exists",
        )),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn create_file(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<Descriptor> {
    use rustix::fs::{openat, Mode, OFlags};
    Ok(openat(
        &parent.descriptor,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?)
}

pub(super) fn clone_file(descriptor: &Descriptor) -> io::Result<File> {
    descriptor.try_clone().map(File::from)
}

pub(super) fn same_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    use rustix::fs::{fstat, openat, Mode, OFlags};
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    validate_regular_file(original).map_err(|_| admission())?;
    let named = openat(
        &parent.descriptor,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    validate_regular_file(&named).map_err(|_| admission())?;
    let original = fstat(original)?;
    let named = fstat(&named)?;
    if original.st_nlink != 1
        || named.st_nlink != 1
        || original.st_dev != named.st_dev
        || original.st_ino != named.st_ino
    {
        return Err(admission());
    }
    Ok(())
}

pub(super) fn create_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
) -> io::Result<OwnedPrivateDirectory> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};
    mkdirat(&parent.descriptor, name, Mode::RWXU)?;
    let descriptor = openat(
        &parent.descriptor,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_private_directory(&descriptor).map_err(|_| admission())?;
    Ok(OwnedPrivateDirectory { descriptor })
}

pub(super) fn same_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    directory: &OwnedPrivateDirectory,
) -> io::Result<()> {
    use rustix::fs::{fstat, openat, Mode, OFlags};
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    validate_private_directory(&directory.descriptor).map_err(|_| admission())?;
    let named = openat(
        &parent.descriptor,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_private_directory(&named).map_err(|_| admission())?;
    let original = fstat(&directory.descriptor)?;
    let observed = fstat(&named)?;
    if (original.st_dev, original.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(admission());
    }
    Ok(())
}

pub(super) fn rename_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    let _ = original;
    rename_name(parent, name, destination)
}

pub(super) fn rename_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination: &OsStr,
    original: &OwnedPrivateDirectory,
) -> io::Result<()> {
    let _ = original;
    rename_name(parent, name, destination)
}

fn rename_name(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    destination: &OsStr,
) -> io::Result<()> {
    Ok(rustix::fs::renameat_with(
        &parent.descriptor,
        name,
        &parent.descriptor,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

pub(super) fn sync_directory(directory: &OwnedPrivateDirectory) -> io::Result<()> {
    Ok(rustix::fs::fsync(&directory.descriptor)?)
}
