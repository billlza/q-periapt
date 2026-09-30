// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared native TLS I/O, cancellation and invocation bounds. Carrier grammars
//! and journal transitions remain the responsibility of each protocol endpoint.
use crate::{BootstrapContext, DurableError};
use q_periapt_rustls::connection;
use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
mod socket;
pub(crate) use socket::Channel;
#[cfg(feature = "control-tls")]
pub(crate) use socket::Request;

/// Shared one-way cancellation signal. Cancellation cannot undo a journal commit.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}
impl Cancellation {
    /// Stop further dispatch; the owner and exact pending operation remain available.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether cancellation has been requested; there is no reset operation.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Explicit per-invocation bounds; reconnecting never refreshes the total deadline.
#[derive(Clone, Copy)]
pub struct RunLimits {
    /// Total request exchanges, including failed attempts, from 1 through 128.
    pub exchanges: u16,
    /// Entire run/accepted-connection duration, nonzero and at most 120 seconds.
    pub timeout: Duration,
    /// Each TCP connect bound, nonzero and at most five seconds. Cancellation
    /// during connect is observed by the end of this bound; later I/O polls at 25 ms.
    pub connect_timeout: Duration,
}
impl RunLimits {
    pub(crate) fn deadline(self) -> Result<Instant, Error> {
        if !(1..=128).contains(&self.exchanges)
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(120)
            || self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(5)
        {
            return Err(Error::InvalidOptions);
        }
        Instant::now()
            .checked_add(self.timeout)
            .ok_or(Error::InvalidOptions)
    }
}

/// Transport outcomes retain the distinction between local state and peer delivery.
#[derive(Debug)]
pub enum Error {
    /// Invalid capacity, deadline, address or endpoint role.
    InvalidOptions,
    /// Cancellation observed before further dispatch; local work may have committed.
    Cancelled,
    /// One unchanged absolute run deadline elapsed; local work may have committed.
    Deadline,
    /// Finite exchange allowance exhausted; exact work remains in the journal.
    AttemptsExhausted,
    /// The endpoint is bound to another protocol context or session.
    Binding,
    /// Malformed carrier bytes or a no-output reply without local completion.
    Protocol,
    /// Current Continuity authority or trusted-time admission failed.
    Authority(crate::Error),
    /// Trusted time could not be obtained; no timestamp is substituted or retried.
    Clock(io::Error),
    /// External application transaction failed; no consumption ACK is produced.
    Application(io::Error),
    /// Cleanup archive persistence or authentication failed; no activation or
    /// delivery success is inferred. Reopen/reconcile the original archive index.
    Archive(DurableError),
    /// Original durable failure; the caller must reopen/reconcile when required.
    Durable(DurableError),
    /// Original SDK TLS/identity/policy/framing failure.
    Connection(connection::Error),
    /// Original network failure; no peer commit/absence is inferred.
    Io(io::Error),
    /// Transient network failure exhausted the finite exchange allowance.
    RetryExhausted {
        /// Actual number of attempted exchanges.
        attempts: u16,
        /// Last observed network error; earlier attempts did not reset the journal.
        last: Box<Error>,
    },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOptions => "invalid Continuity transport options",
            Self::Cancelled => "Continuity dispatch cancelled; reconcile local target",
            Self::Deadline => "Continuity deadline expired; reconcile local target",
            Self::AttemptsExhausted => "Continuity exchange allowance exhausted",
            Self::Binding => "Continuity transport context or session differs",
            Self::Protocol => "invalid Continuity carrier reply",
            Self::Authority(_) => "Continuity authority rejected dispatch",
            Self::Clock(_) => "trusted Continuity time is unavailable",
            Self::Application(_) => "application consumption was not confirmed",
            Self::Archive(_) => "Continuity cleanup archive operation failed",
            Self::Durable(_) => "Continuity journal operation failed",
            Self::Connection(_) => "Continuity TLS connection failed",
            Self::Io(_) => "Continuity network outcome unavailable",
            Self::RetryExhausted { .. } => {
                "Continuity network retries exhausted; reconcile local target"
            }
        })
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(e) => Some(e),
            Self::Clock(e) => Some(e),
            Self::Application(e) => Some(e),
            Self::Archive(e) => Some(e),
            Self::Durable(e) => Some(e),
            Self::Connection(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::RetryExhausted { last, .. } => Some(last.as_ref()),
            _ => None,
        }
    }
}
impl From<DurableError> for Error {
    fn from(e: DurableError) -> Self {
        Self::Durable(e)
    }
}
impl From<connection::Error> for Error {
    fn from(e: connection::Error) -> Self {
        Self::Connection(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub(crate) fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Deadline)
}
pub(crate) fn check(
    context: &BootstrapContext,
    cancel: &Cancellation,
    deadline: Instant,
    clock: &mut impl FnMut() -> io::Result<u64>,
) -> Result<(), Error> {
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    remaining(deadline)?;
    context
        .check_session_identity(clock().map_err(Error::Clock)?)
        .map_err(Error::Authority)
}
pub(crate) fn retryable(error: &Error) -> bool {
    let io = match error {
        Error::Io(e) | Error::Connection(connection::Error::Io(e)) => e,
        _ => return false,
    };
    matches!(
        io.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotConnected
    )
}

pub(crate) fn address(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(Error::InvalidOptions);
    }
    Ok(())
}
