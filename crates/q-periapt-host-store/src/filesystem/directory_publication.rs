//! Non-replacing publication of a fully prepared first-install directory.
use super::PrivatePublicationError;
use std::{io, path::Path};

/// Build first-use state privately and publish its directory in one rename.
///
/// The destination must be absent. Existing directories, files and symlinks are
/// never replaced. The initializer receives an exclusive private staging path;
/// it must finish and sync every child before returning and must not retain
/// concurrent writers. A separate attempt lease is held before the initializer
/// runs, through publication, both rename-parent syncs and control retirement.
/// The helper also syncs the payload directory before publication.
/// It does not verify application configuration or make child writes durable.
/// On Windows, child file handles must be closed before the directory rename.
/// The helper never closes caller-owned handles: a retained live database causes
/// native publication refusal, preserving the original prepared tree. Separate
/// state preparation and subsequent authenticated admission at the caller when
/// that caller's contract permits it; this helper never reopens an owner.
///
/// Errors and unwinds preserve the payload. An error after rename may have published
/// the complete directory. Reconcile its exact original inputs; never delete or
/// recreate a destination after an uncertain result. Unpublished staging is not
/// recovery authority and is not automatically selected or removed. A valid v2
/// attempt can be explicitly reclaimed after its publisher releases the lease;
/// a partially retired or incomplete control is refused. Explicit
/// first-use retries must be bounded by the caller. Same-UID hostile code and
/// physical power-loss durability remain outside this helper's guarantees.
pub fn publish_private_directory<T, E>(
    path: &Path,
    initialize: impl FnOnce(&Path) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<PrivatePublicationError>,
{
    #[cfg(any(
        windows,
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    ))]
    {
        publish_with(path, initialize, |_, _| Ok(()))
    }
    #[cfg(not(any(
        windows,
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        let _ = (path, initialize);
        Err(E::from(PrivatePublicationError::from(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory publication adapter unavailable",
        ))))
    }
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
use super::{maintenance::ManagedAttempt, publication_ops as ops};
#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
use std::path::PathBuf;

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
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

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
struct Staging {
    attempt: ManagedAttempt,
    path: PathBuf,
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
impl Staging {
    fn new(path: &Path) -> Result<Self, PrivatePublicationError> {
        let attempt = ManagedAttempt::directory(path)?;
        let path = attempt.path().to_owned();
        Ok(Self { attempt, path })
    }

    fn error(&self, error: io::Error) -> PrivatePublicationError {
        PrivatePublicationError::staged(error, self.attempt.correlation_name().to_owned())
    }
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
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
        .attempt
        .validate_unpublished()
        .map_err(|e| E::from(staging.error(e)))?;
    let value = initialize(&staging.path)?;
    let publish = (|| -> io::Result<()> {
        hook(Step::Initialized, &staging)?;
        staging.attempt.validate_unpublished()?;
        hook(Step::BeforeStagingSync, &staging)?;
        ops::sync_directory(staging.attempt.data_directory()?)?;
        hook(Step::StagingSynced, &staging)?;
        hook(Step::BeforeRename, &staging)?;
        staging.attempt.rename()?;
        hook(Step::Published, &staging)?;
        staging.attempt.same_target()?;
        hook(Step::BeforeParentSync, &staging)?;
        staging.attempt.sync_publication()?;
        hook(Step::ParentSynced, &staging)?;
        staging.attempt.finish()
    })();
    publish.map_err(|e| E::from(staging.error(e)))?;
    Ok(value)
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

#[cfg(all(test, windows))]
mod windows_tests;
