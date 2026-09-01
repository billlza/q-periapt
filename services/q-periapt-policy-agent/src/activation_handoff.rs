//! Narrow adapter that adopts a service-manager listening socket.
//!
//! A service manager creates the IPC listener and hands it to this process as an
//! inherited descriptor number. The standard library deliberately offers no safe
//! conversion from an integer to an owning handle — treating a caller-supplied
//! integer as a descriptor is unsound — so the two adoptions, the systemd
//! `LISTEN_FDS` descriptor and the launchd `launch_activate_socket` array, are
//! quarantined here. Nothing but `OwnedFd` leaves this module; no raw descriptor
//! number crosses its boundary, and it performs no validation of its own.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use super::activation::ActivationError;

/// First descriptor systemd passes, after stdin/stdout/stderr.
#[cfg(target_os = "linux")]
const SD_LISTEN_FDS_START: i32 = 3;

/// Adopt the single descriptor systemd passed to this process.
///
/// The caller has already established that the activation is addressed to this
/// process and carries exactly one descriptor.
#[cfg(target_os = "linux")]
pub(crate) fn adopt_systemd_listener() -> Result<OwnedFd, ActivationError> {
    // SAFETY: systemd passes its listening sockets as descriptors numbered from
    // SD_LISTEN_FDS_START. The caller established that LISTEN_PID names this
    // process and that LISTEN_FDS is exactly one, so this descriptor is open,
    // is owned by this process, and needs no cleanup beyond `close`. The
    // caller's claim guard admits one call per process, so it is adopted once.
    Ok(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) })
}

#[cfg(target_os = "macos")]
mod launchd {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::fd::{FromRawFd, OwnedFd};

    use super::ActivationError;

    unsafe extern "C" {
        /// `int launch_activate_socket(const char *name, int **fds, size_t *cnt)`
        /// declared by `<launch.h>`. On success the callee allocates `fds` with
        /// `malloc` and the caller must `free` it.
        fn launch_activate_socket(
            name: *const c_char,
            fds: *mut *mut c_int,
            cnt: *mut usize,
        ) -> c_int;
        fn free(ptr: *mut c_void);
    }

    /// Adopt the single descriptor launchd published under `name`.
    pub(crate) fn adopt(name: &str) -> Result<OwnedFd, ActivationError> {
        let name = CString::new(name).map_err(|_| ActivationError::Mismatch)?;
        let mut descriptors: *mut c_int = core::ptr::null_mut();
        let mut count: usize = 0;
        // SAFETY: `name` is a live NUL-terminated string for the duration of the
        // call, and the two out-parameters are distinct live locals of the exact
        // types the declaration requires. launchd either leaves them untouched
        // and returns non-zero, or writes one malloc'd array and its length.
        let status = unsafe { launch_activate_socket(name.as_ptr(), &mut descriptors, &mut count) };
        if status != 0 {
            return Err(ActivationError::NotActivated);
        }
        if descriptors.is_null() {
            return Err(ActivationError::Mismatch);
        }
        // Exactly one descriptor, or the configuration is not the one this
        // daemon expects. Every path below frees the array launchd allocated.
        if count != 1 {
            // SAFETY: `descriptors` is the non-null array launchd allocated with
            // `malloc` on the success path above, freed exactly once here and
            // not used afterwards.
            unsafe { free(descriptors.cast::<c_void>()) };
            return Err(ActivationError::Mismatch);
        }
        // SAFETY: launchd reported one descriptor, so index 0 is initialized and
        // within the allocation.
        let raw = unsafe { *descriptors };
        // SAFETY: as above; the array is freed exactly once and the descriptor
        // value has already been copied out.
        unsafe { free(descriptors.cast::<c_void>()) };
        if raw < 0 {
            return Err(ActivationError::Descriptor);
        }
        // SAFETY: launchd returned this descriptor as an open socket it created
        // for the named entry and transferred ownership to this process; the
        // caller's claim guard admits one adoption per process.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

/// Adopt the single descriptor launchd published under `name`.
#[cfg(target_os = "macos")]
pub(crate) fn adopt_launchd_listener(name: &str) -> Result<OwnedFd, ActivationError> {
    launchd::adopt(name)
}
