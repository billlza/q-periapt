// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public path admission is lexical; private filesystem admission remains required.
#![cfg(any(unix, windows))]

use q_periapt_continuity_identity_candidate::{DurableError, EnrollmentPaths, InstallationPaths};
use std::path::{Path, PathBuf};

fn paths(root: &Path) -> [PathBuf; 6] {
    [
        "installation",
        "journal",
        "archives",
        "wrapping",
        "signer",
        "enrollment",
    ]
    .map(|name| root.join(name))
}

fn admit(files: &[PathBuf; 6]) -> Result<EnrollmentPaths, DurableError> {
    let [installation, journal, archives, wrapping, signer, enrollment] = files;
    EnrollmentPaths::new(
        wrapping,
        signer,
        enrollment,
        InstallationPaths::new(installation, journal, archives)?,
    )
}

fn root() -> &'static Path {
    #[cfg(unix)]
    {
        Path::new("/private/configured")
    }
    #[cfg(windows)]
    {
        Path::new(r"C:\private\configured")
    }
}

#[test]
fn local_absolute_paths_are_admitted() {
    assert!(admit(&paths(root())).is_ok());
    #[cfg(windows)]
    {
        assert!(admit(&paths(Path::new(r"\\?\C:\private\configured"))).is_ok());
    }
}

#[test]
fn noncanonical_or_nonlocal_paths_are_rejected_at_every_position() {
    #[cfg(unix)]
    let invalid = [
        "relative",
        "/",
        "/private/../file",
        "/private/./file",
        "/private//file",
        "/private/file/",
    ];
    #[cfg(windows)]
    let invalid = [
        r"relative",
        r"C:relative",
        r"\private\file",
        r"C:\",
        r"C:\private\..\file",
        r"C:\private\.\file",
        r"C:\private\\file",
        r"C:\private\file\",
        r"\\server\share\file",
        r"\\?\UNC\server\share\file",
        r"\\.\C:\private\file",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\file",
        r"\\?\C:\private\..\file",
        r"\\?\C:\private\.\file",
    ];
    for value in invalid {
        for index in 0..6 {
            let mut files = paths(root());
            *files.get_mut(index).expect("six configured paths") = value.into();
            assert!(
                matches!(admit(&files), Err(DurableError::PrivateFile)),
                "unexpected admission of {value:?} at position {index}"
            );
        }
    }
}

#[test]
fn every_duplicate_pair_is_rejected() {
    for left in 0..6 {
        for right in left + 1..6 {
            let mut files = paths(root());
            let duplicate = files.get(left).expect("original path").clone();
            *files.get_mut(right).expect("duplicate position") = duplicate;
            assert!(matches!(admit(&files), Err(DurableError::Conflict)));
        }
    }
}

#[test]
fn non_utf8_paths_are_rejected() {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0xff])
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xd800])
    };
    let mut files = paths(root());
    *files.first_mut().expect("configuration path") = root().join(name);
    assert!(matches!(admit(&files), Err(DurableError::PrivateFile)));
}
