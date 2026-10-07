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
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::net::addr::SocketAddrStorage;
use rustix::net::AddressFamily;

use super::activation::ActivationError;

/// `sun_path` begins two bytes into `struct sockaddr_un` on every platform this
/// daemon targets: `sun_len` plus `sun_family` on the BSDs, and a two-byte
/// `sun_family` on Linux. A wrong offset yields a wrong name and so a refused
/// listener, which `a_listener_bound_to_the_expected_path_is_adopted` catches
/// on every platform the tests run on.
const SUN_PATH_OFFSET: usize = 2;

/// Read the pathname an `AF_UNIX` descriptor is bound to.
///
/// `getsockname` reports back whatever `addrlen` the binder passed, and rustix's
/// safe `SocketAddrUnix` conversion only accepts the exactly-sized prefix that
/// `std` and `rustix` produce themselves. Handed the whole `struct sockaddr_un`
/// — which is what launchd passes — it derives a path length of
/// `addrlen - 1 - offsetof(sun_path)`, debug-asserts that against the real
/// string length, and otherwise builds a slice full of interior NULs that it
/// then rejects. It does scan for the NUL instead, but only under
/// `cfg(solarish or freebsd)`; macOS behaves the same way and is not in that
/// set. So the address is decoded here, where reading it is permitted.
///
/// The returned name is the bytes before the first NUL, which is correct for
/// both conventions: an exactly-sized address ends at its terminator, and a
/// whole-structure one is padded past it. A pathname can never contain a NUL,
/// and an unnamed or Linux-abstract address yields an empty name that no
/// absolute configured path can equal.
pub(crate) fn bound_unix_path(descriptor: BorrowedFd<'_>) -> Result<Vec<u8>, ActivationError> {
    let address = rustix::net::getsockname(descriptor).map_err(|_| ActivationError::Descriptor)?;
    if address.address_family() != AddressFamily::UNIX {
        return Err(ActivationError::Mismatch);
    }
    let reported = usize::try_from(address.addr_len()).map_err(|_| ActivationError::Descriptor)?;
    if reported <= SUN_PATH_OFFSET || reported > size_of::<SocketAddrStorage>() {
        return Err(ActivationError::Mismatch);
    }
    // SAFETY: `address` owns a `SocketAddrStorage`, and `reported` is the length
    // the kernel wrote into it, bounded above by that storage's size just above.
    // So `reported - SUN_PATH_OFFSET` bytes starting `SUN_PATH_OFFSET` in are
    // initialized and within the allocation. The slice borrows `address`, which
    // outlives it here, and is only read.
    let stored = unsafe {
        core::slice::from_raw_parts(
            address.as_ptr().cast::<u8>().add(SUN_PATH_OFFSET),
            reported - SUN_PATH_OFFSET,
        )
    };
    let end = stored
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(stored.len());
    Ok(stored.get(..end).unwrap_or_default().to_vec())
}

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
            // Ownership of every descriptor was transferred to this process, so
            // discarding only the array would leave open listening sockets
            // behind. Startup fails on this path and the process exits today,
            // but a function that returns an error should not rely on that.
            for index in 0..count {
                // SAFETY: launchd reported `count` descriptors, so every index
                // below it is initialized and within the allocation. Each value
                // is an open descriptor this process owns; it is adopted once,
                // solely so that dropping it closes it.
                let raw = unsafe { *descriptors.add(index) };
                if raw >= 0 {
                    drop(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
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

/// Bind a listener the way launchd does, with `addrlen` set to the whole
/// `struct sockaddr_un` rather than to the exactly-sized prefix.
///
/// `std` and `rustix` both bind with the exact prefix, so nothing else in the
/// tree produces the address shape a service manager actually hands over.
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod test_support {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::Path;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrUn {
        sun_len: u8,
        sun_family: u8,
        sun_path: [u8; 104],
    }

    unsafe extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn bind(fd: i32, addr: *const SockaddrUn, len: u32) -> i32;
        fn listen(fd: i32, backlog: i32) -> i32;
    }

    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;

    /// Returns a listening descriptor bound to `path` in the launchd shape.
    pub(crate) fn launchd_shaped_listener(path: &Path) -> OwnedFd {
        let bytes = path.as_os_str().as_encoded_bytes();
        let mut address = SockaddrUn {
            sun_len: u8::try_from(size_of::<SockaddrUn>()).expect("sockaddr_un fits in u8"),
            sun_family: u8::try_from(AF_UNIX).expect("AF_UNIX fits in u8"),
            sun_path: [0u8; 104],
        };
        address
            .sun_path
            .get_mut(..bytes.len())
            .expect("path fits in sun_path")
            .copy_from_slice(bytes);

        // SAFETY: each call receives the exact argument types its C declaration
        // requires; `address` is a live local for the duration of `bind`, and
        // the length passed is this struct's own size, which is what makes the
        // address take the padded shape under test.
        unsafe {
            let raw = socket(AF_UNIX, SOCK_STREAM, 0);
            assert!(raw >= 0, "socket failed");
            let length = u32::try_from(size_of::<SockaddrUn>()).expect("length fits in u32");
            assert_eq!(bind(raw, &address, length), 0, "bind failed");
            assert_eq!(listen(raw, 8), 0, "listen failed");
            OwnedFd::from_raw_fd(raw)
        }
    }
}
