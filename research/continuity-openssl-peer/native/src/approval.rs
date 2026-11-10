// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Publish complete public controller metadata before selecting an in-memory peer.
//! The original journal/witness provide exclusive controller access. Staging
//! directories are never authority and are retained as evidence after SIGKILL.
use crate::{restart, Result};
use std::{fs, io::Write, path::Path};

pub(super) const UNACTIVATED: &[u8] = b"QPERIAPT-UNACTIVATED-PREDECESSOR/1";

#[derive(Clone, Copy)]
pub(super) enum Kind {
    First,
    Later,
    Unactivated,
}

impl Kind {
    fn directory(self) -> &'static str {
        match self {
            Self::First | Self::Unactivated => "root-successor",
            Self::Later => "root-successor-later",
        }
    }
}

fn matches(directory: &Path, rows: &[(&str, &[u8])]) -> Result<()> {
    if !fs::symlink_metadata(directory)?.file_type().is_dir() {
        return Err("successor approval directory is not a regular directory".into());
    }
    for (name, expected) in rows {
        let path = directory.join(name);
        if !fs::symlink_metadata(&path)?.file_type().is_file()
            || restart::read(&path, expected.len())? != *expected
        {
            return Err("successor approval cannot replace retained metadata".into());
        }
    }
    let unactivated = rows.iter().any(|(name, _)| *name == "unactivated");
    if directory.join("unactivated").try_exists()? != unactivated {
        return Err("successor approval cannot change activation authority".into());
    }
    Ok(())
}

/// The caller must first verify the signed approval and its committed retirement.
/// Once the final directory exists it is immutable: incomplete or changed records
/// fail closed, including records left by the previous publication implementation.
pub(super) fn publish(
    public: &Path,
    kind: Kind,
    control: &[u8],
    publication_started: &mut bool,
) -> Result<()> {
    if control.is_empty() || control.len() > 32768 {
        return Err("successor approval capacity".into());
    }
    // An I/O error can follow the atomic rename. The controller must terminate
    // on any later error rather than keep serving with its old in-memory peer.
    *publication_started = true;
    let original = restart::private_path(public, "private-fixture-path")?;
    let path = original.as_os_str().as_encoded_bytes();
    let mut rows = vec![("control", control), ("private-fixture-path", path)];
    if matches!(kind, Kind::Unactivated) {
        rows.push(("unactivated", UNACTIVATED));
    }
    let destination = public.join(kind.directory());
    if destination.try_exists()? {
        matches(&destination, &rows)?;
        fs::File::open(&destination)?.sync_all()?;
        fs::File::open(public)?.sync_all()?;
        return Ok(());
    }
    let staging = tempfile::Builder::new()
        .prefix(".successor-approval-")
        .tempdir_in(public)?;
    for (name, bytes) in &rows {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staging.path().join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    matches(staging.path(), &rows)?;
    fs::File::open(staging.path())?.sync_all()?;
    // The test controller holds the original store, and no other controller may
    // publish concurrently. Never intentionally replace an existing directory.
    if destination.try_exists()? {
        return Err("successor approval appeared during publication".into());
    }
    fs::rename(staging.path(), &destination)?;
    fs::File::open(public)?.sync_all()?;
    matches(&destination, &rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish(public: &Path, kind: Kind, control: &[u8]) -> Result<()> {
        let mut started = false;
        super::publish(public, kind, control, &mut started)
    }

    fn fixture() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("private"))?;
        fs::write(
            root.path().join("private-fixture-path"),
            root.path()
                .join("private")
                .canonicalize()?
                .as_os_str()
                .as_encoded_bytes(),
        )?;
        Ok(root)
    }

    #[test]
    fn exact_retry_preserves_complete_approval() -> Result<()> {
        let root = fixture()?;
        publish(root.path(), Kind::First, b"signed approval")?;
        publish(root.path(), Kind::First, b"signed approval")?;
        assert!(publish(root.path(), Kind::First, b"another approval").is_err());
        assert_eq!(
            fs::read(root.path().join("root-successor/control"))?,
            b"signed approval"
        );
        Ok(())
    }

    #[test]
    fn committed_missing_or_corrupt_metadata_is_not_repaired() -> Result<()> {
        for missing in [false, true] {
            let root = fixture()?;
            publish(root.path(), Kind::Later, b"signed approval")?;
            let control = root.path().join("root-successor-later/control");
            if missing {
                fs::remove_file(&control)?;
            } else {
                fs::write(&control, b"broken")?;
            }
            assert!(publish(root.path(), Kind::Later, b"signed approval").is_err());
            assert_eq!(control.try_exists()?, !missing);
        }
        Ok(())
    }

    #[test]
    fn unactivated_record_never_becomes_an_active_approval() -> Result<()> {
        let root = fixture()?;
        publish(root.path(), Kind::Unactivated, b"signed approval")?;
        publish(root.path(), Kind::Unactivated, b"signed approval")?;
        assert!(publish(root.path(), Kind::First, b"signed approval").is_err());
        Ok(())
    }

    #[test]
    fn partial_legacy_directory_and_symlink_are_rejected() -> Result<()> {
        let root = fixture()?;
        fs::create_dir(root.path().join("root-successor"))?;
        assert!(publish(root.path(), Kind::First, b"signed approval").is_err());
        std::os::unix::fs::symlink(
            root.path().join("root-successor"),
            root.path().join("root-successor-later"),
        )?;
        assert!(publish(root.path(), Kind::Later, b"signed approval").is_err());
        Ok(())
    }
}
