//! Owner-only directory capabilities for security-critical agent files.

use std::fs::File;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateFileError;

/// An already-open, owner-owned exact-`0700` directory.
///
/// Construction walks every absolute path component descriptor-relative with
/// `O_NOFOLLOW`. File operations therefore remain beneath this pinned directory
/// and never re-resolve a caller-provided path.
#[cfg(unix)]
pub(crate) struct OwnedPrivateDirectory {
    descriptor: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl OwnedPrivateDirectory {
    /// Open and authenticate one absolute private directory path.
    pub(crate) fn open(path: &Path) -> Result<Self, PrivateFileError> {
        let descriptor = open_directory(path)?;
        validate_private_directory(&descriptor)?;
        Ok(Self { descriptor })
    }

    /// Open a fixed-name, nonempty owner-only configuration file.
    pub(crate) fn open_config_file(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<File, PrivateFileError> {
        use rustix::fs::{openat, Mode, OFlags};

        validate_private_directory(&self.descriptor)?;
        let name = private_leaf(Path::new(name))?;
        let descriptor = openat(
            &self.descriptor,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| PrivateFileError)?;
        let length = validate_regular_file(&descriptor)?;
        let maximum = u64::try_from(maximum).map_err(|_| PrivateFileError)?;
        if length == 0 || length > maximum {
            return Err(PrivateFileError);
        }
        Ok(File::from(descriptor))
    }

    /// Verify that a leaf is absent before a Unix socket bind.
    pub(crate) fn require_absent(&self, name: &std::ffi::OsStr) -> Result<(), PrivateFileError> {
        use rustix::fs::{statat, AtFlags};
        use rustix::io::Errno;

        validate_private_directory(&self.descriptor)?;
        let name = private_leaf(Path::new(name))?;
        match statat(&self.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            _ => Err(PrivateFileError),
        }
    }

    /// Set and verify the exact owner-only mode of a newly bound socket leaf.
    pub(crate) fn protect_socket(&self, name: &std::ffi::OsStr) -> Result<(), PrivateFileError> {
        use rustix::fs::{chmodat, AtFlags, Mode};

        validate_private_directory(&self.descriptor)?;
        let name = private_leaf(Path::new(name))?;
        chmodat(
            &self.descriptor,
            name,
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )
        .map_err(|_| PrivateFileError)?;
        self.validate_socket(name)
    }

    /// Pin this directory as the process working directory before server startup.
    pub(crate) fn set_as_process_directory(&self) -> Result<(), PrivateFileError> {
        validate_private_directory(&self.descriptor)?;
        rustix::process::fchdir(&self.descriptor).map_err(|_| PrivateFileError)
    }

    /// Remove one fixed leaf during failed socket setup.
    pub(crate) fn remove_leaf(&self, name: &std::ffi::OsStr) -> Result<(), PrivateFileError> {
        use rustix::fs::{unlinkat, AtFlags};

        let name = private_leaf(Path::new(name))?;
        unlinkat(&self.descriptor, name, AtFlags::empty()).map_err(|_| PrivateFileError)
    }

    fn validate_socket(&self, name: &std::ffi::OsStr) -> Result<(), PrivateFileError> {
        use rustix::fs::{statat, AtFlags, FileType, Mode};
        use rustix::process::geteuid;

        let name = private_leaf(Path::new(name))?;
        let status = statat(&self.descriptor, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| PrivateFileError)?;
        if !FileType::from_raw_mode(status.st_mode).is_socket()
            || Mode::from_raw_mode(status.st_mode) != (Mode::RUSR | Mode::WUSR)
            || status.st_uid != geteuid().as_raw()
        {
            return Err(PrivateFileError);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn socket_is_protected(&self, name: &std::ffi::OsStr) -> bool {
        self.validate_socket(name).is_ok()
    }
}

/// Open an existing private state file, or atomically reserve a new one.
///
/// The path must name a single leaf beneath an absolute [`OwnedPrivateDirectory`].
/// The returned regular file is exact `0600`, owned by the effective user, and
/// can be passed directly to a storage adapter without reopening by path.
#[cfg(unix)]
pub(crate) fn open_private_file(path: &Path, create: bool) -> Result<File, PrivateFileError> {
    use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
    use rustix::process::geteuid;

    let (parent, filename) = open_private_parent(path)?;
    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    let descriptor = openat(&parent.descriptor, filename, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|_| PrivateFileError)?;
    let status = fstat(&descriptor).map_err(|_| PrivateFileError)?;
    if !FileType::from_raw_mode(status.st_mode).is_file()
        || Mode::from_raw_mode(status.st_mode) != (Mode::RUSR | Mode::WUSR)
        || status.st_uid != geteuid().as_raw()
        || (!create && status.st_size == 0)
    {
        return Err(PrivateFileError);
    }
    require_no_extended_acl(&descriptor)?;

    let file = File::from(descriptor);
    if create {
        file.sync_all().map_err(|_| PrivateFileError)?;
        rustix::fs::fsync(&parent.descriptor).map_err(|_| PrivateFileError)?;
    }
    Ok(file)
}

/// Open the authenticated parent capability and return its single leaf name.
#[cfg(unix)]
pub(crate) fn open_private_parent(
    path: &Path,
) -> Result<(OwnedPrivateDirectory, &std::ffi::OsStr), PrivateFileError> {
    let parent = path.parent().ok_or(PrivateFileError)?;
    let filename = path.file_name().ok_or(PrivateFileError)?;
    private_leaf(Path::new(filename))?;
    Ok((OwnedPrivateDirectory::open(parent)?, filename))
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<std::os::fd::OwnedFd, PrivateFileError> {
    use std::path::Component;

    use rustix::fs::{open, openat, Mode, OFlags};

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(PrivateFileError);
    }
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory = open("/", directory_flags, Mode::empty()).map_err(|_| PrivateFileError)?;
    for component in components {
        let Component::Normal(component) = component else {
            return Err(PrivateFileError);
        };
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| PrivateFileError)?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn private_leaf(path: &Path) -> Result<&std::ffi::OsStr, PrivateFileError> {
    use std::path::Component;

    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name),
        _ => Err(PrivateFileError),
    }
}

#[cfg(unix)]
fn validate_regular_file(descriptor: &std::os::fd::OwnedFd) -> Result<u64, PrivateFileError> {
    use rustix::fs::{fstat, FileType, Mode};
    use rustix::process::geteuid;

    let status = fstat(descriptor).map_err(|_| PrivateFileError)?;
    if !FileType::from_raw_mode(status.st_mode).is_file()
        || Mode::from_raw_mode(status.st_mode) != (Mode::RUSR | Mode::WUSR)
        || status.st_uid != geteuid().as_raw()
    {
        return Err(PrivateFileError);
    }
    require_no_extended_acl(descriptor)?;
    u64::try_from(status.st_size).map_err(|_| PrivateFileError)
}

#[cfg(unix)]
fn validate_private_directory(descriptor: &std::os::fd::OwnedFd) -> Result<(), PrivateFileError> {
    use rustix::fs::{fstat, FileType, Mode};
    use rustix::process::geteuid;

    let status = fstat(descriptor).map_err(|_| PrivateFileError)?;
    if !FileType::from_raw_mode(status.st_mode).is_dir()
        || Mode::from_raw_mode(status.st_mode) != Mode::RWXU
        || status.st_uid != geteuid().as_raw()
    {
        return Err(PrivateFileError);
    }
    require_no_extended_acl(descriptor)
}

#[cfg(target_os = "macos")]
fn require_no_extended_acl(descriptor: &std::os::fd::OwnedFd) -> Result<(), PrivateFileError> {
    use std::os::fd::AsFd;

    match crate::macos_acl::extended_acl_present(descriptor.as_fd()) {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(PrivateFileError),
    }
}

#[cfg(target_os = "linux")]
fn require_no_extended_acl(_: &std::os::fd::OwnedFd) -> Result<(), PrivateFileError> {
    // Linux POSIX access-ACL grants are reflected through the group-class mask
    // bits, which the exact mode checks reject.
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn require_no_extended_acl(_: &std::os::fd::OwnedFd) -> Result<(), PrivateFileError> {
    // Other Unix ACL models have not been reviewed for an exact correspondence
    // with mode bits, so this reference boundary fails closed.
    Err(PrivateFileError)
}

#[cfg(not(unix))]
pub(crate) fn open_private_file(_: &Path, _: bool) -> Result<File, PrivateFileError> {
    // Unix descriptor-relative traversal, owner identity, and mode bits are part
    // of this reference implementation's reviewed boundary. A platform-specific
    // protected-store adapter is required.
    Err(PrivateFileError)
}
