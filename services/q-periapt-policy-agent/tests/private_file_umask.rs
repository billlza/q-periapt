//! Keep the process-global umask case in its own single-test Cargo executable.
//!
//! Cargo runs integration-test executables separately from the parallel library
//! suite, so this case needs neither self-execution nor an environment-supplied
//! filesystem path. Keep this executable limited to the umask boundary test.

#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use q_periapt_host_store::filesystem::{open_private_file, PrivateFileError};
use rustix::fs::Mode;
use rustix::process::umask;

#[test]
fn failed_private_file_admission_preserves_reserved_leaf() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("q-periapt-private-file-umask-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root = directory.path().canonicalize()?;
    let path = root.join("reserved.redb");
    // umask 0o200 strips the owner-write bit, so O_CREAT yields mode 0400 and
    // the exact-mode check rejects it after the leaf already exists.
    let previous = umask(Mode::WUSR);
    let outcome = open_private_file(&path, true);
    umask(previous);
    assert!(
        matches!(outcome, Err(PrivateFileError)),
        "expected the exact-mode check to reject a 0400 leaf"
    );
    let original = fs::symlink_metadata(&path)?;
    assert!(original.file_type().is_file());
    assert_eq!(original.permissions().mode() & 0o7777, 0o400);
    assert_eq!(original.len(), 0);
    for create in [false, true] {
        assert!(matches!(
            open_private_file(&path, create),
            Err(PrivateFileError)
        ));
        let retained = fs::symlink_metadata(&path)?;
        assert_eq!(
            (
                retained.dev(),
                retained.ino(),
                retained.mode(),
                retained.len()
            ),
            (
                original.dev(),
                original.ino(),
                original.mode(),
                original.len()
            )
        );
    }
    // A fresh name remains usable after restoring this process's original mask.
    drop(
        open_private_file(&root.join("fresh.redb"), true)
            .map_err(|_| io::Error::other("fresh private-file admission must succeed"))?,
    );
    Ok(())
}
