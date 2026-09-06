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

    /// Open an existing state leaf without losing this pinned parent capability.
    pub(crate) fn open_state_file(&self, name: &std::ffi::OsStr) -> Result<File, PrivateFileError> {
        validate_private_directory(&self.descriptor)?;
        let name = private_leaf(Path::new(name))?;
        open_private_leaf(self, name, false)
    }

    /// Create an owner-only scratch inode and remove its name before it can hold data.
    pub(crate) fn create_anonymous_scratch(&self) -> Result<File, PrivateFileError> {
        self.create_anonymous_scratch_with(|parent, name| {
            rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty())
        })
    }

    fn create_anonymous_scratch_with(
        &self,
        unlink: impl FnOnce(&std::os::fd::OwnedFd, &std::ffi::OsStr) -> Result<(), rustix::io::Errno>,
    ) -> Result<File, PrivateFileError> {
        use rustix::fs::{openat, Mode, OFlags};

        validate_private_directory(&self.descriptor)?;
        // Randomness avoids stale-name collisions; O_EXCL and the private directory
        // establish ownership. This name is not an authentication mechanism.
        let mut token = [0u8; 16];
        getrandom::fill(&mut token).map_err(|_| PrivateFileError)?;
        let token: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = format!(".witness-admission-{token}");
        let name = std::ffi::OsStr::new(&name);
        let descriptor = openat(
            &self.descriptor,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| PrivateFileError)?;
        // Never return a linked scratch file or copy any database bytes when unlink
        // fails. The only possible leftover on this path is the newly-created empty leaf.
        unlink(&self.descriptor, name).map_err(|_| PrivateFileError)?;
        validate_regular_file(&descriptor)?;
        Ok(File::from(descriptor))
    }
}

/// Copy a locked source into an already-anonymous scratch file with bounded memory.
///
/// The caller retains the original redb FileBackend lock for this entire operation.
/// File lengths remain u64; the buffer size is not a limit on accepted database size.
#[cfg(unix)]
pub(crate) fn copy_to_anonymous_scratch(
    source: &mut File,
    scratch: &mut File,
) -> Result<(), PrivateFileError> {
    use std::io::Seek;

    let length = source.metadata().map_err(|_| PrivateFileError)?.len();
    source.rewind().map_err(|_| PrivateFileError)?;
    copy_exact_stream(source, scratch, length).map_err(|_| PrivateFileError)?;
    if source.metadata().map_err(|_| PrivateFileError)?.len() != length
        || scratch.metadata().map_err(|_| PrivateFileError)?.len() != length
    {
        return Err(PrivateFileError);
    }
    scratch.sync_data().map_err(|_| PrivateFileError)
}

#[cfg(unix)]
fn copy_exact_stream(
    source: &mut impl std::io::Read,
    destination: &mut impl std::io::Write,
    length: u64,
) -> Result<(), std::io::Error> {
    let mut buffer = [0u8; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| std::io::Error::other("scratch copy chunk is not representable"))?;
        let chunk_buffer = buffer
            .get_mut(..chunk)
            .ok_or_else(|| std::io::Error::other("scratch copy chunk exceeds its buffer"))?;
        source.read_exact(chunk_buffer)?;
        destination.write_all(chunk_buffer)?;
        remaining -= chunk as u64;
    }
    Ok(())
}

/// Open an existing private state file, or atomically reserve a new one.
///
/// The path must name a single leaf beneath an absolute [`OwnedPrivateDirectory`].
/// The returned regular file is exact `0600`, owned by the effective user, and
/// can be passed directly to a storage adapter without reopening by path.
#[cfg(unix)]
pub(crate) fn open_private_file(path: &Path, create: bool) -> Result<File, PrivateFileError> {
    let (parent, filename) = open_private_parent(path)?;
    open_private_leaf(&parent, filename, create)
}

/// Open (or atomically create) one leaf beneath an already-pinned parent.
///
/// Every filesystem action -- the `openat`, the validation, and the failure
/// unlink -- goes through `parent`'s descriptor, so nothing here ever
/// re-resolves the path by name. Splitting this out of [`open_private_file`]
/// lets [`provision_private_file`] reuse the *same* pinned parent for its own
/// post-initialization cleanup.
#[cfg(unix)]
fn open_private_leaf(
    parent: &OwnedPrivateDirectory,
    filename: &std::ffi::OsStr,
    create: bool,
) -> Result<File, PrivateFileError> {
    use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
    use rustix::process::geteuid;

    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    let descriptor = openat(&parent.descriptor, filename, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|_| PrivateFileError)?;

    let opened = (|| -> Result<File, PrivateFileError> {
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
    })();

    match opened {
        Ok(file) => Ok(file),
        Err(error) => {
            if create {
                // O_CREAT|O_EXCL already made the leaf, so a failure after this
                // point must not leave it behind: the next attempt would get
                // EEXIST, and the `create = false` path rejects the zero-length
                // leftover, so one transient failure (a restrictive umask
                // yielding the wrong mode, ENOSPC or EIO on the syncs) would
                // brick provisioning permanently. Best-effort by design -- the
                // original error is what the caller needs to see.
                let _ = rustix::fs::unlinkat(
                    &parent.descriptor,
                    filename,
                    rustix::fs::AtFlags::empty(),
                );
            }
            Err(error)
        }
    }
}

/// Refuse a redb store file that was left unclean by a writer other than this
/// crate's stores, before the file is handed to redb at all.
///
/// Every commit the three stores make is two-phase, and that is the premise
/// of letting redb finish crash recovery on open: with two-phase commit redb
/// never falls back to the older commit slot. A file whose recovery flag is
/// set but whose two-phase flag is clear was last written by something else
/// -- a stock redb writer, or a regression that dropped `set_two_phase_commit`
/// -- and redb would recover it through the slot-picking branch that this
/// crate's safety argument excludes. It is refused untouched instead. A file
/// too short to carry the header is left for redb to reject.
///
/// Layout (redb 2.6 file format v2): nine magic bytes, then the god byte at
/// offset 9 with bit 2 = recovery required and bit 4 = two-phase commit.
#[cfg(unix)]
pub(crate) fn refuse_unclean_foreign_redb(file: &File) -> Result<(), PrivateFileError> {
    use std::os::unix::fs::FileExt;

    const GOD_BYTE_OFFSET: u64 = 9;
    const RECOVERY_REQUIRED: u8 = 2;
    const TWO_PHASE_COMMIT: u8 = 4;

    let mut god = [0u8; 1];
    match file.read_at(&mut god, GOD_BYTE_OFFSET) {
        Ok(1) => {}
        Ok(_) => return Ok(()),
        Err(_) => return Err(PrivateFileError),
    }
    let unclean = god[0] & RECOVERY_REQUIRED != 0;
    let two_phase = god[0] & TWO_PHASE_COMMIT != 0;
    if unclean && !two_phase {
        return Err(PrivateFileError);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn refuse_unclean_foreign_redb(_: &File) -> Result<(), PrivateFileError> {
    // No store file can be opened on this platform (see `open_private_file`),
    // so there is nothing to inspect.
    Ok(())
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

/// Create a private store file and initialize it, removing the file again if the
/// initialization does not complete.
///
/// Creation uses `O_CREAT|O_EXCL`, so a leftover from a failed attempt makes
/// every later provision fail with `EEXIST`, while the open path rejects the
/// half-written store it finds. One transient failure -- unavailable entropy, a
/// clock before the epoch, `ENOSPC` or `EIO` partway through the first commit --
/// would therefore brick the path permanently instead of leaving it retryable.
///
/// The removal is best effort and the caller still receives the original error,
/// which is the one that explains what actually went wrong.
///
/// The parent is pinned once and both the create and the cleanup unlink go
/// through that single descriptor. The cleanup therefore removes the exact leaf
/// this call created, never a same-named file reached by re-resolving `path`:
/// an initialization closure that (or an adversary who) replaces an ancestor of
/// the leaf after it is created cannot redirect the removal onto an unrelated
/// file. `std::fs::remove_file(path)` re-resolved every component by name and
/// could do exactly that.
#[cfg(unix)]
pub(crate) fn provision_private_file<T, E>(
    path: &Path,
    on_open_failure: impl FnOnce(PrivateFileError) -> E,
    initialize: impl FnOnce(File) -> Result<T, E>,
) -> Result<T, E> {
    let (parent, filename) = match open_private_parent(path) {
        Ok(pair) => pair,
        Err(error) => return Err(on_open_failure(error)),
    };
    let file = match open_private_leaf(&parent, filename, true) {
        Ok(file) => file,
        Err(error) => return Err(on_open_failure(error)),
    };
    match initialize(file) {
        Ok(provisioned) => Ok(provisioned),
        Err(error) => {
            let _ =
                rustix::fs::unlinkat(&parent.descriptor, filename, rustix::fs::AtFlags::empty());
            Err(error)
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn provision_private_file<T, E>(
    path: &Path,
    on_open_failure: impl FnOnce(PrivateFileError) -> E,
    _initialize: impl FnOnce(File) -> Result<T, E>,
) -> Result<T, E> {
    // Provisioning depends on the Unix descriptor-relative boundary; a
    // platform adapter is required before any leaf can be created safely.
    let _ = path;
    Err(on_open_failure(PrivateFileError))
}

#[cfg(all(test, unix))]
mod cleanup_boundary {
    use super::*;
    use std::io::{self, Read, Seek, Write};
    use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};

    fn scratch_directory() -> Result<tempfile::TempDir, io::Error> {
        tempfile::Builder::new()
            .prefix("private-scratch-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    #[test]
    fn anonymous_scratch_has_no_name_before_or_after_copy() -> Result<(), io::Error> {
        let temporary = scratch_directory()?;
        let root = temporary.path().canonicalize()?;
        let directory = OwnedPrivateDirectory::open(&root)
            .map_err(|_| io::Error::other("private directory open failed"))?;
        let source_path = root.join("source.bin");
        let mut source = open_private_file(&source_path, true)
            .map_err(|_| io::Error::other("source creation failed"))?;
        source.write_all(b"bounded scratch copy")?;
        let mut scratch = directory
            .create_anonymous_scratch()
            .map_err(|_| io::Error::other("anonymous scratch creation failed"))?;
        assert_eq!(scratch.metadata()?.nlink(), 0);
        assert_eq!(scratch.metadata()?.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&root)?.count(), 1);
        copy_to_anonymous_scratch(&mut source, &mut scratch)
            .map_err(|_| io::Error::other("scratch copy failed"))?;
        scratch.rewind()?;
        let mut copied = String::new();
        scratch.read_to_string(&mut copied)?;
        assert_eq!(copied, "bounded scratch copy");
        assert_eq!(std::fs::read(&source_path)?, b"bounded scratch copy");
        drop(scratch);
        assert_eq!(std::fs::read_dir(&root)?.count(), 1);
        Ok(())
    }

    #[test]
    fn scratch_unlink_failure_is_explicit_and_never_returns_a_copy_destination(
    ) -> Result<(), io::Error> {
        let temporary = scratch_directory()?;
        let root = temporary.path().canonicalize()?;
        let directory = OwnedPrivateDirectory::open(&root)
            .map_err(|_| io::Error::other("private directory open failed"))?;
        let outcome = directory.create_anonymous_scratch_with(|_, _| Err(rustix::io::Errno::IO));
        assert!(matches!(outcome, Err(PrivateFileError)));
        let entries: Vec<_> = std::fs::read_dir(&root)?.collect::<Result<_, _>>()?;
        assert_eq!(entries.len(), 1);
        for entry in entries {
            assert_eq!(
                entry.metadata()?.len(),
                0,
                "unlink failure allowed content to be copied"
            );
        }
        Ok(())
    }

    #[test]
    fn scratch_copy_preserves_write_failure_and_stops_without_retry() -> Result<(), io::Error> {
        struct NoSpaceWriter {
            calls: usize,
        }
        impl Write for NoSpaceWriter {
            fn write(&mut self, _: &[u8]) -> Result<usize, io::Error> {
                self.calls += 1;
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::NOSPC.raw_os_error(),
                ))
            }
            fn flush(&mut self) -> Result<(), io::Error> {
                Ok(())
            }
        }
        let bytes = b"copy input remains intact";
        let mut input = io::Cursor::new(bytes.as_slice());
        let mut output = NoSpaceWriter { calls: 0 };
        let outcome = copy_exact_stream(&mut input, &mut output, bytes.len() as u64);
        assert_eq!(
            outcome.expect_err("ENOSPC must fail").raw_os_error(),
            Some(rustix::io::Errno::NOSPC.raw_os_error())
        );
        assert_eq!(output.calls, 1);
        assert_eq!(input.into_inner(), bytes);
        Ok(())
    }

    #[test]
    fn scratch_copy_rejects_short_input() {
        let mut input = io::Cursor::new(b"short".as_slice());
        let mut output = Vec::new();
        let outcome = copy_exact_stream(&mut input, &mut output, 6);
        assert_eq!(
            outcome.expect_err("short copy must fail").kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(output.is_empty());
    }

    #[test]
    fn scratch_copy_supports_lengths_above_u32_without_a_full_file_allocation(
    ) -> Result<(), io::Error> {
        struct CountingReader {
            remaining: u64,
            largest_request: usize,
        }
        impl Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> Result<usize, io::Error> {
                self.largest_request = self.largest_request.max(buffer.len());
                let length = usize::try_from(self.remaining.min(buffer.len() as u64))
                    .map_err(|_| io::Error::other("test chunk overflow"))?;
                // copy_exact_stream supplies an initialized zeroed buffer, and this
                // virtual all-zero input does not retain or allocate the logical file.
                self.remaining -= length as u64;
                Ok(length)
            }
        }
        struct CountingWriter(u64);
        impl Write for CountingWriter {
            fn write(&mut self, buffer: &[u8]) -> Result<usize, io::Error> {
                self.0 += buffer.len() as u64;
                Ok(buffer.len())
            }
            fn flush(&mut self) -> Result<(), io::Error> {
                Ok(())
            }
        }
        let length = u64::from(u32::MAX) + 17;
        let mut input = CountingReader {
            remaining: length,
            largest_request: 0,
        };
        let mut output = CountingWriter(0);
        copy_exact_stream(&mut input, &mut output, length)?;
        assert_eq!(input.remaining, 0);
        assert_eq!(output.0, length);
        assert!(input.largest_request <= 64 * 1024);
        Ok(())
    }

    /// A failed initialization must unlink the exact leaf it created, even when
    /// the initialization replaced the leaf's parent with a symlink to an
    /// unrelated directory holding a same-named file. The unrelated file must
    /// survive, and the created leaf must be gone.
    #[test]
    fn failed_provision_cleanup_keeps_the_pinned_parent() -> Result<(), io::Error> {
        let temporary = tempfile::Builder::new()
            .prefix("private-file-cleanup-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let root = temporary.path().canonicalize()?;
        let original_parent = root.join("service");
        let moved_parent = root.join("moved-service");
        let replacement_parent = root.join("unrelated");
        for directory in [&original_parent, &replacement_parent] {
            std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        let original_path = original_parent.join("state.redb");
        let unrelated_file = replacement_parent.join("state.redb");
        std::fs::write(&unrelated_file, b"unrelated existing file")?;
        let outcome: Result<(), io::Error> = provision_private_file(
            &original_path,
            |_| io::Error::other("open failed before the probe could run"),
            |created| {
                // Swap the pinned parent out from under the path name after the
                // leaf is created, then fail. A by-name cleanup would follow the
                // symlink into `replacement_parent`.
                std::fs::rename(&original_parent, &moved_parent)?;
                symlink(&replacement_parent, &original_parent)?;
                drop(created);
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected initialization failure after path replacement",
                ))
            },
        );
        assert_eq!(
            outcome.expect_err("initialization must fail").kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            unrelated_file.exists(),
            "cleanup followed the swapped path and deleted the unrelated file"
        );
        assert!(
            !moved_parent.join("state.redb").exists(),
            "cleanup did not remove the leaf it actually created"
        );
        Ok(())
    }
}
