//! Atomic, non-replacing publication beneath a pinned private parent.
use std::{io, path::Path};

/// Publication failed; the destination may already contain the complete image.
/// Never interpret this error as permission to replace or remove the destination.
#[derive(Debug)]
pub struct PrivatePublicationError {
    operation: io::Error,
    staging_name: Option<std::ffi::OsString>,
}
impl PrivatePublicationError {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn staged(operation: io::Error, name: std::ffi::OsString) -> Self {
        Self {
            operation,
            staging_name: Some(name),
        }
    }
    /// Original admission, write, sync, or non-replacing rename error.
    pub fn operation(&self) -> &io::Error {
        &self.operation
    }
    /// Name reserved by this attempt, if creation reached a private staging inode.
    /// It may no longer exist after rename. This is diagnostic correlation data,
    /// never proof of current inode ownership or permission to delete by name.
    pub fn staging_name(&self) -> Option<&std::ffi::OsStr> {
        self.staging_name.as_deref()
    }
}
impl std::fmt::Display for PrivatePublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "private image publication failed: {}", self.operation)?;
        if self.staging_name.is_some() {
            f.write_str("; publication may have committed or retained unpublished staging")?;
        }
        Ok(())
    }
}
impl std::error::Error for PrivatePublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.operation)
    }
}
impl From<io::Error> for PrivatePublicationError {
    fn from(operation: io::Error) -> Self {
        Self {
            operation,
            staging_name: None,
        }
    }
}

/// Publish an immutable image beneath one authenticated, pinned private parent.
///
/// Writes a fresh exclusive `0600` staging inode, syncs its complete contents,
/// renames with NOREPLACE, authenticates the published inode, then syncs the
/// parent. No owner or public identity may be released before this returns.
/// Existing destinations, including partial files and symlinks, are never changed.
/// There is no fallback when the filesystem lacks non-replacing rename support.
///
/// Neither returned errors nor process crashes remove staging or destination
/// names. A check-then-unlink cannot atomically authenticate the inode being
/// removed. Failures can therefore leave private `.private-publication-*` orphans;
/// the error retains the original I/O failure and the attempted staging name.
/// Orphans are never selected for recovery, swept or treated as authority.
/// Callers must bound first-use retries; an exclusive maintenance/erasure protocol
/// is a separate host responsibility, not implemented by this helper.
///
/// An explicitly authorized first provisioning retry may generate fresh unpublished
/// material only while the destination is absent. After publication, recover the
/// exact destination with independently retained scope and identity; absence after
/// prior successful use is data loss, never permission for initial provisioning.
/// The host and other same-UID code must respect immutable-file ownership; these
/// checks are not isolation from malicious same-UID processes. They make no claim
/// about cryptographic erasure of filesystem pages or backups.
pub fn publish_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), PrivatePublicationError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        publish_with(path, bytes, |_, _, _, _| Ok(()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (path, bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private publication adapter unavailable",
        )
        .into())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::{
    open_locked_database, open_private_parent, validate_private_directory, validate_regular_file,
    DatabaseOpenMode, OwnedPrivateDirectory, PrivateDatabaseError,
};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::{ffi::OsStr, fs::File, io::Write, os::fd::OwnedFd};

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Created,
    Written,
    BeforeFileSync,
    FileSynced,
    BeforeRename,
    Published,
    BeforeDirectorySync,
    DirectorySynced,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn admission() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private publication inode admission failed",
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn same_leaf(parent: &OwnedPrivateDirectory, leaf: &OsStr, original: &OwnedFd) -> io::Result<()> {
    use rustix::fs::{fstat, openat, Mode, OFlags};
    validate_private_directory(&parent.descriptor).map_err(|_| admission())?;
    validate_regular_file(original).map_err(|_| admission())?;
    let named = openat(
        &parent.descriptor,
        leaf,
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

/// Internal publication capability. The descriptor is a plain probe only: never
/// wrap a duplicate in a second lock-managing backend or explicitly unlock it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) struct StagedFile {
    parent: OwnedPrivateDirectory,
    destination: std::ffi::OsString,
    name: std::ffi::OsString,
    descriptor: OwnedFd,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl StagedFile {
    pub(super) fn new(path: &Path) -> Result<Self, PrivatePublicationError> {
        use rustix::fs::{openat, statat, AtFlags, Mode, OFlags};
        let (parent, destination) = open_private_parent(path).map_err(|_| admission())?;
        // This avoids staging for known-existing destinations; NOREPLACE below
        // still decides concurrent winners.
        match statat(&parent.descriptor, destination, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private destination already exists",
                )
                .into())
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        let mut token = [0u8; 16];
        getrandom::fill(&mut token).map_err(io::Error::other)?;
        let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
        let name = std::ffi::OsString::from(format!(".private-publication-{token}"));
        let descriptor = openat(
            &parent.descriptor,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)?;
        let staged = Self {
            parent,
            destination: destination.to_owned(),
            name,
            descriptor,
        };
        same_leaf(&staged.parent, &staged.name, &staged.descriptor).map_err(|e| staged.error(e))?;
        Ok(staged)
    }
    fn error(&self, operation: io::Error) -> PrivatePublicationError {
        PrivatePublicationError {
            operation,
            staging_name: Some(self.name.clone()),
        }
    }
    pub(super) fn file(&self) -> Result<File, PrivatePublicationError> {
        self.descriptor
            .try_clone()
            .map(File::from)
            .map_err(|e| self.error(e))
    }
    pub(super) fn publish(&self) -> Result<(), PrivatePublicationError> {
        let file = self.file()?;
        self.publish_with(&file, &mut |_, _, _, _| Ok(()))
    }
    fn publish_with(
        &self,
        file: &File,
        hook: &mut impl FnMut(Step, &OwnedPrivateDirectory, &OsStr, &File) -> io::Result<()>,
    ) -> Result<(), PrivatePublicationError> {
        let operation = (|| -> io::Result<()> {
            same_leaf(&self.parent, &self.name, &self.descriptor)?;
            hook(Step::BeforeFileSync, &self.parent, &self.name, file)?;
            file.sync_all()?;
            hook(Step::FileSynced, &self.parent, &self.name, file)?;
            hook(Step::BeforeRename, &self.parent, &self.name, file)?;
            same_leaf(&self.parent, &self.name, &self.descriptor)?;
            rustix::fs::renameat_with(
                &self.parent.descriptor,
                &self.name,
                &self.parent.descriptor,
                &self.destination,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            hook(Step::Published, &self.parent, &self.name, file)?;
            same_leaf(&self.parent, &self.destination, &self.descriptor)?;
            hook(Step::BeforeDirectorySync, &self.parent, &self.name, file)?;
            rustix::fs::fsync(&self.parent.descriptor)?;
            hook(Step::DirectorySynced, &self.parent, &self.name, file)?;
            same_leaf(&self.parent, &self.destination, &self.descriptor)?;
            Ok(())
        })();
        operation.map_err(|e| self.error(e))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn publish_with(
    path: &Path,
    bytes: &[u8],
    mut hook: impl FnMut(Step, &OwnedPrivateDirectory, &OsStr, &File) -> io::Result<()>,
) -> Result<(), PrivatePublicationError> {
    let staged = StagedFile::new(path)?;
    let mut file = staged.file()?;
    let write = (|| -> io::Result<()> {
        hook(Step::Created, &staged.parent, &staged.name, &file)?;
        file.write_all(bytes)?;
        hook(Step::Written, &staged.parent, &staged.name, &file)?;
        if file.metadata()?.len() != bytes.len() as u64 {
            return Err(admission());
        }
        Ok(())
    })();
    write.map_err(|e| staged.error(e))?;
    staged.publish_with(&file, &mut hook)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn provision_database<E>(
    path: &Path,
    initialize: impl FnOnce(&redb::Database) -> Result<(), E>,
) -> Result<redb::Database, E>
where
    E: From<PrivateDatabaseError>,
{
    provision_database_with(path, initialize, StagedFile::publish)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn provision_database_with<E>(
    path: &Path,
    initialize: impl FnOnce(&redb::Database) -> Result<(), E>,
    publish: impl FnOnce(&StagedFile) -> Result<(), PrivatePublicationError>,
) -> Result<redb::Database, E>
where
    E: From<PrivateDatabaseError>,
{
    let staged = StagedFile::new(path)
        .map_err(PrivateDatabaseError::from)
        .map_err(E::from)?;
    let file = staged
        .file()
        .map_err(PrivateDatabaseError::from)
        .map_err(E::from)?;
    // Exactly one backend manages this open description's lock. Plain staging
    // probes may be dropped, but a second backend's close could explicitly unlock it.
    let database = open_locked_database(file, DatabaseOpenMode::New).map_err(E::from)?;
    initialize(&database)?;
    publish(&staged)
        .map_err(PrivateDatabaseError::from)
        .map_err(E::from)?;
    Ok(database)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(super) mod database_tests;
