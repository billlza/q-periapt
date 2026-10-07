//! Service-manager socket activation for the Unix IPC boundary.
//!
//! The listening socket is created by the service manager — a systemd `.socket`
//! unit or a launchd `Sockets` entry — and handed to this process. The daemon
//! never binds, chmods, chowns, or unlinks it. It adopts exactly one inherited
//! descriptor, proves what it can about it, and fails startup otherwise. There
//! is no self-bind fallback, so a deployment that starts the binary without
//! activation gets a refusal rather than a socket with different properties than
//! the ones the deployment believes it configured.
//!
//! # What the daemon can and cannot prove
//!
//! Two limits are load-bearing for the security argument and are stated here
//! rather than left implicit:
//!
//! * **The socket's owner, group, and mode are not verifiable from the
//!   descriptor.** An `AF_UNIX` descriptor describes a socket object, not the
//!   filesystem node that names it: `fstat` on the descriptor reports a
//!   different inode and a different mode than `stat` on the path, and `fchmod`
//!   fails outright. Re-resolving the path to `stat` it would be worse than
//!   useless — it would reach outside every owned-directory capability this
//!   crate maintains, and the mode it read would not be the mode that governed a
//!   `connect` that already happened. The enforced admission boundary is
//!   therefore the **parent directory's mode**, provisioned by the deployment;
//!   the socket's own mode is defense in depth that the service manager sets and
//!   the daemon cannot attest to.
//! * **On macOS the listening state cannot be checked.** `SO_ACCEPTCONN` is
//!   declared by the platform but not implemented, so a socket that was bound
//!   and never listened is indistinguishable here from one that was. On Linux
//!   that check is real and is performed. The macOS assurance rests instead on
//!   provenance: `launch_activate_socket` returns only descriptors launchd
//!   created for that named entry. This asymmetry is deliberate and is not
//!   hidden behind a `cfg` that would imply parity.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::net::SocketType;

/// Longest `sun_path` this daemon accepts, one byte below the smaller platform
/// limit so a single constant is portable. A longer path could never match what
/// `getsockname` reports, so it is refused while it is still a configuration
/// error rather than an unexplainable mismatch.
pub(crate) const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Adopted at most once per process; a second adoption of the same descriptor
/// number would be undefined behaviour that no amount of validation can detect.
static ACTIVATION_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Why socket activation did not yield the expected listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActivationError {
    /// No service-manager activation was presented to this process.
    NotActivated,
    /// Activation was already claimed once in this process.
    AlreadyClaimed,
    /// The inherited descriptor could not be configured or interrogated.
    Descriptor,
    /// Activation was presented but is not the expected listener.
    Mismatch,
}

/// Reject an activation name that could not survive the transport that carries
/// it, before any descriptor is touched.
pub(crate) fn validate_activation_name(name: &str) -> Result<(), ActivationError> {
    let usable = !name.is_empty()
        && name.len() <= 255
        // ':' separates entries in LISTEN_FDNAMES, '/' means a path was passed
        // where a name belongs, and control bytes cannot round-trip.
        && !name.contains(':')
        && !name.contains('/')
        && !name.bytes().any(|byte| byte.is_ascii_control());
    if usable {
        Ok(())
    } else {
        Err(ActivationError::Mismatch)
    }
}

/// Reject a socket path that could never match what `getsockname` reports.
pub(crate) fn validate_socket_path(path: &Path) -> Result<(), ActivationError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let usable = path.is_absolute()
        && !bytes.is_empty()
        && bytes.len() <= MAX_SOCKET_PATH_BYTES
        && !bytes.contains(&0);
    if usable {
        Ok(())
    } else {
        Err(ActivationError::Mismatch)
    }
}

/// Claim the single service-manager listener and prove it is the expected one.
pub(crate) fn activated_listener(
    name: &str,
    expected_path: &Path,
) -> Result<UnixListener, ActivationError> {
    validate_activation_name(name)?;
    validate_socket_path(expected_path)?;
    if ACTIVATION_CLAIMED.swap(true, Ordering::SeqCst) {
        return Err(ActivationError::AlreadyClaimed);
    }
    let descriptor = adopt(name)?;
    adopted_listener(descriptor, expected_path)
}

#[cfg(target_os = "linux")]
fn adopt(name: &str) -> Result<OwnedFd, ActivationError> {
    linux_activation_environment(name)?;
    super::activation_handoff::adopt_systemd_listener()
}

#[cfg(target_os = "macos")]
fn adopt(name: &str) -> Result<OwnedFd, ActivationError> {
    super::activation_handoff::adopt_launchd_listener(name)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn adopt(_name: &str) -> Result<OwnedFd, ActivationError> {
    Err(ActivationError::NotActivated)
}

/// Read and clear the systemd activation environment, and require that it names
/// this process and carries exactly the expected single listener.
#[cfg(target_os = "linux")]
fn linux_activation_environment(name: &str) -> Result<(), ActivationError> {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let listen_names = std::env::var("LISTEN_FDNAMES").ok();

    // Clear before anything in this process can fork and exec. The descriptor
    // table is per-process but the environment is inherited, so a child that
    // still saw these would conclude it had been activated and adopt whatever
    // occupied descriptor 3 in its own table.
    clear_activation_environment();

    let (Some(listen_pid), Some(listen_fds)) = (listen_pid, listen_fds) else {
        return Err(ActivationError::NotActivated);
    };
    let listen_pid: i32 = listen_pid
        .parse()
        .map_err(|_| ActivationError::NotActivated)?;
    if listen_pid != rustix::process::getpid().as_raw_nonzero().get() {
        return Err(ActivationError::NotActivated);
    }
    let listen_fds: usize = listen_fds.parse().map_err(|_| ActivationError::Mismatch)?;
    if listen_fds != 1 {
        return Err(ActivationError::Mismatch);
    }
    // The name is how the deployment says which socket this is; without it the
    // daemon would accept any single listener systemd happened to pass.
    let listen_names = listen_names.ok_or(ActivationError::Mismatch)?;
    let mut names = listen_names.split(':');
    match (names.next(), names.next()) {
        (Some(only), None) if only == name => Ok(()),
        _ => Err(ActivationError::Mismatch),
    }
}

#[cfg(target_os = "linux")]
fn clear_activation_environment() {
    // Safe on this edition, and this runs before the process starts a second
    // thread, which is the condition that makes clearing the environment sound.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    std::env::remove_var("LISTEN_PIDFDID");
}

/// Validate an already-owned descriptor and convert it into a listener.
pub(crate) fn adopted_listener(
    descriptor: OwnedFd,
    expected_path: &Path,
) -> Result<UnixListener, ActivationError> {
    let borrowed = descriptor.as_fd();

    // The service manager passes the descriptor without FD_CLOEXEC, because it
    // has to survive the exec into this daemon. Setting it now keeps any child
    // this process later execs from inheriting the control socket and being
    // able to accept on it, which would hand a subprocess a pre-authorized seat
    // past the transport-group gate.
    rustix::io::fcntl_setfd(borrowed, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| ActivationError::Descriptor)?;

    if rustix::net::sockopt::socket_type(borrowed).map_err(|_| ActivationError::Descriptor)?
        != SocketType::STREAM
    {
        return Err(ActivationError::Mismatch);
    }

    // Linux can prove the socket was listened on; macOS declares SO_ACCEPTCONN
    // without implementing it, so there the property rests on launchd
    // provenance. See the module documentation.
    #[cfg(target_os = "linux")]
    {
        if !rustix::net::sockopt::socket_acceptconn(borrowed)
            .map_err(|_| ActivationError::Descriptor)?
        {
            return Err(ActivationError::Mismatch);
        }
    }

    // The bound name is the only identity the descriptor itself carries; the
    // owner, group, and mode of the filesystem node are not observable here.
    // Decoding it needs to read the raw address, so it lives in the quarantine
    // module -- see `bound_unix_path` for why the safe conversion cannot be used
    // on an address a service manager produced.
    let bound = super::activation_handoff::bound_unix_path(borrowed)?;
    if bound != expected_path.as_os_str().as_encoded_bytes() {
        return Err(ActivationError::Mismatch);
    }

    Ok(UnixListener::from(descriptor))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn activation_names_that_cannot_round_trip_are_refused() {
        assert!(validate_activation_name("agent").is_ok());
        for rejected in ["", "a:b", "/run/agent.sock", "bad\nname", "nul\0name"] {
            assert_eq!(
                validate_activation_name(rejected),
                Err(ActivationError::Mismatch),
                "{rejected:?} must be refused"
            );
        }
        let too_long = "a".repeat(256);
        assert_eq!(
            validate_activation_name(&too_long),
            Err(ActivationError::Mismatch)
        );
    }

    /// A listener the test owns, standing in for the one a service manager
    /// would hand over. Production has no path that creates one.
    fn scratch_listener(name: &str) -> (UnixListener, std::path::PathBuf) {
        // Short, absolute, and inside sun_path's budget; a temp directory path
        // can exceed it on macOS.
        let path =
            std::path::PathBuf::from(format!("/tmp/qp-act-{}-{name}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind scratch listener");
        // Present the descriptor state a service manager presents, not the one
        // `std` produces: every socket `std` creates is already close-on-exec,
        // which made the adoption's own `fcntl_setfd` deletable with the
        // assertion below still passing. A handed-over descriptor cannot carry
        // the flag -- it has to survive the exec into this daemon.
        rustix::io::fcntl_setfd(listener.as_fd(), rustix::io::FdFlags::empty())
            .expect("clear close-on-exec on the scratch listener");
        (listener, path)
    }

    #[test]
    fn a_listener_bound_to_the_expected_path_is_adopted() {
        use std::os::fd::AsRawFd;

        let (listener, path) = scratch_listener("ok");
        let descriptor = OwnedFd::from(listener);
        let raw = descriptor.as_raw_fd();
        let adopted = adopted_listener(descriptor, &path).expect("expected listener is adopted");
        // The descriptor must have been marked close-on-exec, so a child this
        // process later execs cannot inherit the control socket and accept on it.
        let flags = rustix::io::fcntl_getfd(adopted.as_fd()).expect("read descriptor flags");
        assert!(
            flags.contains(rustix::io::FdFlags::CLOEXEC),
            "the adopted listener must be close-on-exec"
        );
        assert_eq!(
            adopted.as_raw_fd(),
            raw,
            "the same descriptor is carried through"
        );
        drop(adopted);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_listener_bound_elsewhere_is_refused() {
        let (listener, path) = scratch_listener("elsewhere");
        let descriptor = OwnedFd::from(listener);
        let outcome = adopted_listener(descriptor, Path::new("/tmp/qp-act-not-this.sock"));
        assert_eq!(
            outcome.err(),
            Some(ActivationError::Mismatch),
            "the bound name is the only identity the descriptor carries, so it must be checked"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The address shape a service manager actually produces, which neither
    /// `std` nor `rustix` generates when binding.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_launchd_shaped_listener_is_adopted() {
        let path = std::env::temp_dir().join(format!("qp-launchd-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let descriptor = crate::activation_handoff::test_support::launchd_shaped_listener(&path);
        // This fixture is built with a raw `socket(2)` and no SOCK_CLOEXEC, so
        // it already presents what launchd presents; asserting the flag here is
        // what makes the adoption's `fcntl_setfd` load-bearing on this platform.
        assert!(
            !rustix::io::fcntl_getfd(descriptor.as_fd())
                .expect("read descriptor flags")
                .contains(rustix::io::FdFlags::CLOEXEC),
            "the fixture must present a descriptor a service manager could hand over"
        );
        let outcome = adopted_listener(descriptor, &path);
        let _ = std::fs::remove_file(&path);
        assert!(
            outcome.is_ok(),
            "a launchd-bound listener must be adopted, got {outcome:?}"
        );
        let adopted = outcome.expect("adopted above");
        let flags = rustix::io::fcntl_getfd(adopted.as_fd()).expect("read descriptor flags");
        assert!(
            flags.contains(rustix::io::FdFlags::CLOEXEC),
            "the adopted listener must be close-on-exec"
        );
    }

    #[test]
    fn socket_paths_that_could_never_match_are_refused() {
        assert!(validate_socket_path(Path::new("/run/qperiapt-agent/agent.sock")).is_ok());
        assert_eq!(
            validate_socket_path(Path::new("relative.sock")),
            Err(ActivationError::Mismatch)
        );
        let too_long = format!("/{}", "a".repeat(MAX_SOCKET_PATH_BYTES));
        assert_eq!(
            validate_socket_path(Path::new(&too_long)),
            Err(ActivationError::Mismatch),
            "a path longer than sun_path could never match getsockname"
        );
    }
}
