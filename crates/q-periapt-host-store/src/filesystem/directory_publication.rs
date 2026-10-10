//! Non-replacing publication of a fully prepared first-install directory.
use super::PrivatePublicationError;
use std::{io, path::Path};

/// Build first-use state privately and publish its directory in one rename.
///
/// The destination must be absent. Existing directories, files and symlinks are
/// never replaced. The initializer receives an exclusive private staging path;
/// it must finish and sync every child before returning and must not retain
/// concurrent writers. The helper syncs that directory and its pinned parent.
/// It does not verify application configuration or make child writes durable.
///
/// Errors and unwinds preserve staging. An error after rename may have published
/// the complete directory. Reconcile its exact original inputs; never delete or
/// recreate a destination after an uncertain result. Unpublished staging is not
/// recovery authority and is not automatically selected or removed. Explicit
/// first-use retries must be bounded by the caller. Same-UID hostile code and
/// physical power-loss durability remain outside this helper's guarantees.
pub fn publish_private_directory<T, E>(
    path: &Path,
    initialize: impl FnOnce(&Path) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<PrivatePublicationError>,
{
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        publish_with(path, initialize, |_, _| Ok(()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (path, initialize);
        Err(E::from(PrivatePublicationError::from(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory publication adapter unavailable",
        ))))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::{open_private_parent, validate_private_directory, OwnedPrivateDirectory};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::{ffi::OsStr, path::PathBuf};

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Created,
    Initialized,
    BeforeStagingSync,
    StagingSynced,
    BeforeRename,
    Published,
    BeforeParentSync,
    ParentSynced,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn admission() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private directory publication admission failed",
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct Staging {
    parent: OwnedPrivateDirectory,
    directory: OwnedPrivateDirectory,
    name: std::ffi::OsString,
    destination: std::ffi::OsString,
    path: PathBuf,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Staging {
    fn new(path: &Path) -> Result<Self, PrivatePublicationError> {
        use rustix::fs::{mkdirat, openat, statat, AtFlags, Mode, OFlags};
        let (parent, destination) = open_private_parent(path).map_err(|_| admission())?;
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
        let token: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = std::ffi::OsString::from(format!(".private-tree-{token}"));
        let staged_error = |error: io::Error| PrivatePublicationError::staged(error, name.clone());
        mkdirat(&parent.descriptor, &name, Mode::RWXU)
            .map_err(io::Error::from)
            .map_err(staged_error)?;
        let descriptor = openat(
            &parent.descriptor,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)
        .map_err(staged_error)?;
        validate_private_directory(&descriptor).map_err(|_| staged_error(admission()))?;
        let staged_path = path.parent().ok_or_else(admission)?.join(&name);
        Ok(Self {
            parent,
            directory: OwnedPrivateDirectory { descriptor },
            name,
            destination: destination.into(),
            path: staged_path,
        })
    }

    fn same(&self, name: &OsStr) -> io::Result<()> {
        use rustix::fs::{fstat, openat, Mode, OFlags};
        validate_private_directory(&self.parent.descriptor).map_err(|_| admission())?;
        validate_private_directory(&self.directory.descriptor).map_err(|_| admission())?;
        let named = openat(
            &self.parent.descriptor,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        validate_private_directory(&named).map_err(|_| admission())?;
        let original = fstat(&self.directory.descriptor)?;
        let observed = fstat(&named)?;
        if (original.st_dev, original.st_ino) != (observed.st_dev, observed.st_ino) {
            return Err(admission());
        }
        Ok(())
    }

    fn error(&self, error: io::Error) -> PrivatePublicationError {
        PrivatePublicationError::staged(error, self.name.clone())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn publish_with<T, E>(
    path: &Path,
    initialize: impl FnOnce(&Path) -> Result<T, E>,
    mut hook: impl FnMut(Step, &Staging) -> io::Result<()>,
) -> Result<T, E>
where
    E: From<PrivatePublicationError>,
{
    let staging = Staging::new(path).map_err(E::from)?;
    hook(Step::Created, &staging).map_err(|e| E::from(staging.error(e)))?;
    staging
        .same(&staging.name)
        .map_err(|e| E::from(staging.error(e)))?;
    let value = initialize(&staging.path)?;
    let publish = (|| -> io::Result<()> {
        hook(Step::Initialized, &staging)?;
        staging.same(&staging.name)?;
        hook(Step::BeforeStagingSync, &staging)?;
        rustix::fs::fsync(&staging.directory.descriptor)?;
        hook(Step::StagingSynced, &staging)?;
        hook(Step::BeforeRename, &staging)?;
        staging.same(&staging.name)?;
        rustix::fs::renameat_with(
            &staging.parent.descriptor,
            &staging.name,
            &staging.parent.descriptor,
            &staging.destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        hook(Step::Published, &staging)?;
        staging.same(&staging.destination)?;
        hook(Step::BeforeParentSync, &staging)?;
        rustix::fs::fsync(&staging.parent.descriptor)?;
        hook(Step::ParentSynced, &staging)?;
        staging.same(&staging.destination)
    })();
    publish.map_err(|e| E::from(staging.error(e)))?;
    Ok(value)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;
