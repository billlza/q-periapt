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
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    ))]
    pub(super) fn staged(operation: io::Error, name: std::ffi::OsString) -> Self {
        Self {
            operation,
            staging_name: Some(name),
        }
    }
    /// Original admission, write, sync, non-replacing rename or control-retirement error.
    pub fn operation(&self) -> &io::Error {
        &self.operation
    }
    /// Versioned control-directory name selected when attempt creation began.
    /// Creation may have failed, or successful retirement may have removed it.
    /// This is diagnostic correlation data,
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
/// Holds a separate control lease before exposing a fresh owner-only payload,
/// syncs its complete contents, renames with NOREPLACE, authenticates the published
/// inode and syncs both rename parents. It then retires its own control fields.
/// No owner or public identity may be released before this returns.
/// Existing destinations, including partial files and symlinks, are never changed.
/// There is no fallback when the filesystem lacks non-replacing rename support.
///
/// Publication errors never delete the payload or formal destination. They can
/// leave an unpublished payload in `.private-attempt-v2-*/payload`, or a complete
/// published target and partially retired control directory. The error preserves
/// the original failure and control-name correlation. A valid abandoned v2
/// attempt can be explicitly reclaimed with `reclaim_private_publication`; old
/// prefix-only residues and incomplete controls are refused. No automatic sweep
/// or recovery from a staging payload occurs. Callers must bound first-use retries.
///
/// An explicitly authorized first provisioning retry may generate fresh unpublished
/// material only while the destination is absent. After publication, recover the
/// exact destination with independently retained scope and identity; absence after
/// prior successful use is data loss, never permission for initial provisioning.
/// The host and other same-UID code must respect immutable-file ownership; these
/// checks are not isolation from malicious same-UID processes. They make no claim
/// about cryptographic erasure of filesystem pages or backups.
pub fn publish_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), PrivatePublicationError> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    ))]
    {
        publish_with(path, bytes, |_, _, _, _| Ok(()))
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = (path, bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private publication adapter unavailable",
        )
        .into())
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
use super::{
    maintenance::ManagedAttempt, open_locked_database, DatabaseOpenMode, OwnedPrivateDirectory,
    PrivateDatabaseError,
};
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
use std::{ffi::OsStr, fs::File, io::Write};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
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

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
fn admission() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private publication inode admission failed",
    )
}

/// Internal publication capability. The data descriptor is a plain probe;
/// the independent control lease spans preparation, publication and retirement.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
pub(super) struct StagedFile {
    attempt: ManagedAttempt,
    name: std::ffi::OsString,
}
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
impl StagedFile {
    pub(super) fn new(path: &Path) -> Result<Self, PrivatePublicationError> {
        let attempt = ManagedAttempt::file(path)?;
        let name = Path::new(attempt.correlation_name())
            .join("payload")
            .into_os_string();
        Ok(Self { attempt, name })
    }
    fn error(&self, operation: io::Error) -> PrivatePublicationError {
        PrivatePublicationError::staged(operation, self.attempt.correlation_name().to_owned())
    }
    pub(super) fn file(&self) -> Result<File, PrivatePublicationError> {
        self.attempt.data_file().map_err(|e| self.error(e))
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
            self.attempt.validate_unpublished()?;
            hook(
                Step::BeforeFileSync,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            file.sync_all()?;
            hook(
                Step::FileSynced,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            hook(
                Step::BeforeRename,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            self.attempt.rename()?;
            hook(
                Step::Published,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            self.attempt.same_target()?;
            hook(
                Step::BeforeDirectorySync,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            self.attempt.sync_publication()?;
            hook(
                Step::DirectorySynced,
                self.attempt.target_parent(),
                &self.name,
                file,
            )?;
            self.attempt.finish()
        })();
        operation.map_err(|e| self.error(e))
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
fn publish_with(
    path: &Path,
    bytes: &[u8],
    mut hook: impl FnMut(Step, &OwnedPrivateDirectory, &OsStr, &File) -> io::Result<()>,
) -> Result<(), PrivatePublicationError> {
    let staged = StagedFile::new(path)?;
    let mut file = staged.file()?;
    let write = (|| -> io::Result<()> {
        hook(
            Step::Created,
            staged.attempt.target_parent(),
            &staged.name,
            &file,
        )?;
        file.write_all(bytes)?;
        hook(
            Step::Written,
            staged.attempt.target_parent(),
            &staged.name,
            &file,
        )?;
        if file.metadata()?.len() != bytes.len() as u64 {
            return Err(admission());
        }
        Ok(())
    })();
    write.map_err(|e| staged.error(e))?;
    staged.publish_with(&file, &mut hook)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
pub(super) fn provision_database<E>(
    path: &Path,
    initialize: impl FnOnce(&redb::Database) -> Result<(), E>,
) -> Result<redb::Database, E>
where
    E: From<PrivateDatabaseError>,
{
    provision_database_with(path, initialize, StagedFile::publish)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    target_os = "windows"
))]
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

#[cfg(all(
    test,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )
))]
mod tests;

#[cfg(all(
    test,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )
))]
pub(super) mod database_tests;
