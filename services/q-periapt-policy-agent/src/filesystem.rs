//! Owner-only durable-file boundary for security-critical agent state.

use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateFileError;

/// Validate an existing private file, or atomically reserve a new one.
///
/// The immediate parent must be a real owner-only directory. That directory is
/// the race-control boundary: an actor already able to mutate it runs with the
/// same authority as the service and is outside this reference adapter's threat
/// model.
#[cfg(unix)]
pub(crate) fn prepare_private_file(path: &Path, create: bool) -> Result<(), PrivateFileError> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().ok_or(PrivateFileError)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| PrivateFileError)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PrivateFileError);
    }
    if create {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| PrivateFileError)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| PrivateFileError)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PrivateFileError);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn prepare_private_file(_: &Path, _: bool) -> Result<(), PrivateFileError> {
    // Unix owner-only mode bits are part of this reference implementation's
    // reviewed boundary. A platform-specific protected-store adapter is required.
    Err(PrivateFileError)
}
