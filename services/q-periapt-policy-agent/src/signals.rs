//! Quarantined installation of the daemon's termination-signal handlers.
//!
//! The service manager stops a daemon with `SIGTERM`; an operator running one
//! by hand stops it with `SIGINT`. With no handler installed either signal ends
//! the process on the spot: the instance lease is never released, so a restart
//! inside the lease TTL is fenced at construction and the service stays down,
//! and no store is closed cleanly. The handler installed here does exactly one
//! thing -- it stores `true` into a process-wide flag. The serving loops read
//! that flag once per wait and return, which is what lets `serve_agent` hand
//! the lease back and lets every store close through its destructor.
//!
//! Installing a handler is `unsafe` by nature: the kernel will call whatever
//! address is registered, on whichever thread it chooses, between any two
//! instructions. `rustix` deliberately does not wrap `sigaction`, so the call
//! is made through `libc` and quarantined here, the same way
//! `activation_handoff` quarantines descriptor adoption. The `unsafe` is
//! confined to the installation itself; nothing but the `&'static AtomicBool`
//! leaves this module.
//!
//! # Contract
//!
//! * The handler is async-signal-safe: one atomic store and nothing else. It
//!   does not allocate, lock, format, or call back into the runtime.
//! * `SA_RESTART` is deliberately **not** set. A blocking `poll` that the
//!   signal interrupts returns `EINTR` instead of being transparently resumed,
//!   so a serving loop parked in its wait observes the flag within one
//!   iteration. `ipc::wait_for_connection` already reports `EINTR` as "nothing
//!   waiting", and the loop re-reads the flag on every pass.
//! * Which thread receives a process-directed signal is not specified. The
//!   loops therefore never rely on `EINTR` alone: every wait is bounded and the
//!   flag is read at the top of every iteration, so a stop is observed within
//!   one maintenance interval even when a thread that was not waiting took
//!   the signal.
//! * The flag is process-wide and is never cleared. A process that has been
//!   asked to stop stays asked; the only correct response is to exit.
//! * Installation is idempotent: a second call re-registers the same handler
//!   and returns the same flag.

#![allow(unsafe_code)]

use core::ffi::c_int;
use core::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the handler and read by the serving loops. Never cleared.
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The termination handlers could not be installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignalError {
    /// `sigaction` refused the installation for `SIGTERM` or `SIGINT`.
    Install,
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Install => "termination signal handlers could not be installed",
        })
    }
}

impl std::error::Error for SignalError {}

/// The handler. It runs in signal context and may do nothing but the store.
extern "C" fn record_termination(_signal: c_int) {
    TERMINATION_REQUESTED.store(true, Ordering::Release);
}

/// Install `SIGTERM` and `SIGINT` handlers whose only action is to set the
/// returned flag, and return that flag.
///
/// See the module documentation for the contract. The flag is `'static`
/// because the handler stores into it for the rest of the process's life. A
/// signal is latched, never delivered twice: once the flag is set, the process
/// is expected to finish what it is doing and exit.
pub(crate) fn install_termination_handlers() -> Result<&'static AtomicBool, SignalError> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        install(signal)?;
    }
    Ok(&TERMINATION_REQUESTED)
}

/// Register `record_termination` for one signal, without `SA_RESTART`.
fn install(signal: c_int) -> Result<(), SignalError> {
    // SAFETY: `sigaction` is a plain C structure for which all-zero bytes are a
    // valid value, so `zeroed` is a sound starting point; `sigemptyset` then
    // writes a valid empty mask into the live local it is handed. The handler
    // registered is an `extern "C" fn(c_int)` -- the exact signature the kernel
    // calls when `SA_SIGINFO` is not set -- and it performs one atomic store,
    // which is async-signal-safe. `action` is a live local for the whole
    // `sigaction` call, which only reads it, and no previous disposition is
    // requested back (null `oldact`).
    let status = unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err(SignalError::Install);
        }
        // `sighandler_t` is an integer holding the handler's address; the
        // cast goes through a pointer because that is what it is.
        action.sa_sigaction = record_termination as *const () as libc::sighandler_t;
        // No SA_RESTART: a blocking wait must return EINTR so the loop parked
        // in it re-reads the flag now rather than at its next timeout.
        action.sa_flags = 0;
        libc::sigaction(signal, &action, core::ptr::null_mut())
    };
    if status == 0 {
        Ok(())
    } else {
        Err(SignalError::Install)
    }
}
