//! Narrow descriptor-based adapter for the macOS extended-ACL boundary.
//!
//! macOS can grant access through an extended ACL without changing the POSIX
//! mode reported by `fstat`. The platform has no safe standard-library or
//! rustix wrapper for `acl_get_fd_np`, so the native calls are quarantined here.

#![allow(unsafe_code)]

use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

const ACL_TYPE_EXTENDED: c_uint = 256;

#[repr(C)]
struct Acl {
    _private: [u8; 0],
}

type AclHandle = *mut Acl;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_uint) -> AclHandle;
    fn acl_free(object: *mut c_void) -> c_int;
}

/// Report whether an already-open file or directory has a macOS extended ACL.
pub(crate) fn extended_acl_present(file: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: `file` remains live for the call and `ACL_TYPE_EXTENDED` is the
    // value defined by macOS `<sys/acl.h>`.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }

    // A non-null extended ACL is rejected even if it has no effective grant.
    // This keeps the boundary closed under unfamiliar or future ACL semantics.
    // SAFETY: `acl` is the unique non-null allocation returned by the preceding
    // `acl_get_fd_np` call and is consumed exactly once here.
    if unsafe { acl_free(acl.cast()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}
