//! Private test I/O on the same reviewed storage boundary as the native runtime.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{fs, io, path::Path};

#[cfg(unix)]
pub(super) type FixtureDirectory = tempfile::TempDir;
#[cfg(windows)]
pub(super) struct FixtureDirectory(std::path::PathBuf);
#[cfg(windows)]
impl FixtureDirectory {
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}
#[cfg(windows)]
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0)
            .expect("remove owned private fixture directory after closing owners");
    }
}

pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        q_periapt_host_store::filesystem::publish_private_directory(path, |_| {
            Ok::<_, q_periapt_host_store::filesystem::PrivatePublicationError>(())
        })
        .map_err(|error| io::Error::new(error.operation().kind(), error))
    }
}

pub(super) fn create_private_file(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        q_periapt_host_store::filesystem::provision_private_file(path, io::Error::other, Ok)
    }
}

#[cfg(windows)]
pub(super) fn publish_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // This fixture needs the publisher's AlreadyExists result to distinguish
    // immutable observation replay from private-file admission failure. The
    // lower-level provisioning API intentionally returns opaque PrivateFileError.
    q_periapt_host_store::filesystem::publish_private_bytes(path, bytes)
        .map_err(|error| io::Error::new(error.operation().kind(), error))
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

pub(super) fn temporary_directory(prefix: &str) -> io::Result<FixtureDirectory> {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix(prefix)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
    }
    #[cfg(windows)]
    {
        use q_periapt_host_store::filesystem::OwnedPrivateDirectory;
        // Create through the reviewed explicit owner/DACL publisher. Inherited
        // permissions and an administrator's default object owner are insufficient.
        // Require an owned parent; never alter an existing directory's ACL.
        let parent = std::env::var_os("QPERIAPT_PRIVATE_FIXTURE_ROOT")
            .ok_or_else(|| io::Error::other("private Windows fixture parent is required"))?;
        let parent = std::path::PathBuf::from(parent);
        OwnedPrivateDirectory::open(&parent).map_err(io::Error::other)?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| io::Error::other(format!("fixture directory entropy: {error}")))?;
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!("{prefix}{suffix}"));
        create_private_directory(&path)?;
        Ok(FixtureDirectory(path))
    }
}

/// Keep the real unpublished-file writer barrier used by the readiness tests.
pub(super) fn finish_observation(
    pending: tempfile::NamedTempFile,
    path: &Path,
    name: &str,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        pending
            .persist_noclobber(path.join(name))
            .map_err(|error| error.error)?;
        sync_directory(path)
    }
    #[cfg(windows)]
    {
        use std::io::{Read, Seek};
        // Marker/address bytes are public and bounded. Publish the completed image
        // with the SDK's explicit owner/DACL, rather than an inherited temp-file owner.
        let mut pending = pending;
        pending.as_file_mut().rewind()?;
        let mut bytes = Vec::new();
        pending.as_file_mut().take(129).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "readiness observation width",
            ));
        }
        publish_bytes(&path.join(name), &bytes)
    }
}
