//! Platform operations used by the shared publication state machines.
//!
//! Callers own the continuous publication/maintenance lease and the decision to
//! remove a validated original entry. These helpers do not retry operations or
//! decide whether an uncertain publication committed.

use super::{validate_private_directory, validate_regular_file, OwnedPrivateDirectory};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::fd::OwnedFd,
};

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

pub(super) fn rename_file_to(
    source: &OwnedPrivateDirectory,
    name: &OsStr,
    target: &OwnedPrivateDirectory,
    destination: &OsStr,
    original: &Descriptor,
) -> io::Result<()> {
    same_file(source, name, original)?;
    validate_private_directory(&target.descriptor).map_err(|_| admission())?;
    Ok(rustix::fs::renameat_with(
        &source.descriptor,
        name,
        &target.descriptor,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

pub(super) fn rename_directory_to(
    source: &OwnedPrivateDirectory,
    name: &OsStr,
    target: &OwnedPrivateDirectory,
    destination: &OsStr,
    original: &OwnedPrivateDirectory,
) -> io::Result<()> {
    same_directory(source, name, original)?;
    validate_private_directory(&target.descriptor).map_err(|_| admission())?;
    Ok(rustix::fs::renameat_with(
        &source.descriptor,
        name,
        &target.descriptor,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

/// Internal disposable-file admission. Zero bytes are valid here; normal
/// operational/configuration opens retain their existing nonempty requirement.
pub(super) fn open_file(parent: &OwnedPrivateDirectory, name: &OsStr) -> io::Result<File> {
    use rustix::fs::{fstat, openat, Mode, OFlags};
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    let descriptor = openat(
        &parent.descriptor,
        name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    validate_regular_file(&descriptor).map_err(|_| admission())?;
    if fstat(&descriptor)?.st_nlink != 1 {
        return Err(admission());
    }
    Ok(File::from(descriptor))
}

pub(super) fn open_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
) -> io::Result<OwnedPrivateDirectory> {
    use rustix::fs::{openat, Mode, OFlags};
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    let descriptor = openat(
        &parent.descriptor,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    validate_private_directory(&descriptor).map_err(|_| admission())?;
    Ok(OwnedPrivateDirectory { descriptor })
}

fn identity(file: &File) -> io::Result<[u8; 16]> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let mut result = [0; 16];
    let (device, inode) = result.split_at_mut(8);
    device.copy_from_slice(&metadata.dev().to_le_bytes());
    inode.copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(result)
}

pub(super) fn file_identity(file: &File) -> io::Result<[u8; 16]> {
    let probe: OwnedFd = file.try_clone()?.into();
    validate_regular_file(&probe).map_err(|_| admission())?;
    if rustix::fs::fstat(&probe)?.st_nlink != 1 {
        return Err(admission());
    }
    identity(file)
}

pub(super) fn directory_identity(directory: &OwnedPrivateDirectory) -> io::Result<[u8; 16]> {
    validate_private_directory(&directory.descriptor).map_err(|_| admission())?;
    identity(&File::from(directory.descriptor.try_clone()?))
}

pub(super) fn same_plain_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &File,
) -> io::Result<()> {
    if file_identity(original)? != file_identity(&open_file(parent, name)?)? {
        return Err(admission());
    }
    Ok(())
}

pub(super) fn rename_plain_file_to(
    source: &OwnedPrivateDirectory,
    name: &OsStr,
    target: &OwnedPrivateDirectory,
    destination: &OsStr,
    original: &File,
) -> io::Result<()> {
    same_plain_file(source, name, original)?;
    validate_private_directory(&target.descriptor).map_err(|_| admission())?;
    Ok(rustix::fs::renameat_with(
        &source.descriptor,
        name,
        &target.descriptor,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

/// The managed attempt owner must retain its independent lease across this
/// identity check and namespace mutation. This does not isolate hostile same-UID code.
pub(super) fn remove_file(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &File,
) -> io::Result<()> {
    same_plain_file(parent, name, original)?;
    Ok(rustix::fs::unlinkat(
        &parent.descriptor,
        name,
        rustix::fs::AtFlags::empty(),
    )?)
}

pub(super) fn remove_directory(
    parent: &OwnedPrivateDirectory,
    name: &OsStr,
    original: &OwnedPrivateDirectory,
) -> io::Result<()> {
    same_directory(parent, name, original)?;
    Ok(rustix::fs::unlinkat(
        &parent.descriptor,
        name,
        rustix::fs::AtFlags::REMOVEDIR,
    )?)
}

/// Return at most `limit` names. Callers pass budget + 1 and must refuse overflow;
/// a full returned limit must never be treated as a complete bounded inventory.
pub(super) fn directory_entries(
    parent: &OwnedPrivateDirectory,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStringExt;
    if limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero directory inventory limit",
        ));
    }
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    let mut directory = rustix::fs::Dir::read_from(&parent.descriptor)?;
    directory.rewind();
    let mut names = Vec::new();
    for entry in directory {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
        if names.len() == limit {
            break;
        }
    }
    Ok(names)
}

pub(super) fn sync_directory(directory: &OwnedPrivateDirectory) -> io::Result<()> {
    Ok(rustix::fs::fsync(&directory.descriptor)?)
}
