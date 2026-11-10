//! Private temporary roots shared by platform admission and publication tests.
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) struct PrivateTestDirectory {
    // Keep the containing temporary directory alive until all fixture operations finish.
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl PrivateTestDirectory {
    pub(super) fn path(&self) -> &Path {
        &self.root
    }
}

pub(super) fn directory() -> io::Result<PrivateTestDirectory> {
    #[cfg(unix)]
    let temporary = {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?
    };
    #[cfg(windows)]
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    #[cfg(windows)]
    let root = {
        use std::{ffi::OsStr, os::windows::fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&root)?;
        let private = super::windows_native::create(&parent, OsStr::new("private"), true)?;
        crate::windows_acl::validate(&private)?;
        private.sync_all()?;
        parent.sync_all()?;
        root.join("private")
    };
    Ok(PrivateTestDirectory {
        _temporary: temporary,
        root,
    })
}
