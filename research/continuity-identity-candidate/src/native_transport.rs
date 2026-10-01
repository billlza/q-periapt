// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared native TLS I/O, cancellation and invocation bounds. Carrier grammars
//! and journal transitions remain the responsibility of each protocol endpoint.
pub use crate::Cancellation;
use crate::{BootstrapContext, DurableError};
use q_periapt_rustls::connection;
use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
mod socket;
pub(crate) use socket::Channel;
#[cfg(feature = "control-tls")]
pub(crate) use socket::Request;

/// Explicit per-invocation bounds; reconnecting never refreshes the total deadline.
#[derive(Clone, Copy)]
pub struct RunLimits {
    /// Total request exchanges, including failed attempts, from 1 through 128.
    pub exchanges: u16,
    /// Entire run/accepted-connection duration, nonzero and at most 120 seconds.
    pub timeout: Duration,
    /// Each TCP connect bound, nonzero and at most five seconds. Pending connects
    /// and later I/O poll cancellation at intervals of at most 25 ms.
    pub connect_timeout: Duration,
    /// Optional caller-wide absolute deadline. A run can shorten this bound but
    /// never extend it, including after listener admission or a witness exchange.
    pub outer_deadline: Option<Instant>,
}
impl RunLimits {
    pub(crate) fn deadline(self) -> Result<Instant, Error> {
        if !(1..=crate::contract::MAX_NETWORK_EXCHANGES).contains(&self.exchanges)
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(crate::contract::MAX_RUN_TIMEOUT_SECONDS)
            || self.connect_timeout.is_zero()
            || self.connect_timeout
                > Duration::from_secs(crate::contract::MAX_CONNECT_TIMEOUT_SECONDS)
        {
            return Err(Error::InvalidOptions);
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(Error::InvalidOptions)?;
        let deadline = self
            .outer_deadline
            .map_or(deadline, |outer| outer.min(deadline));
        remaining(deadline)?;
        Ok(deadline)
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
pub(crate) fn connect(
    address: SocketAddr,
    cancel: &Cancellation,
    deadline: Instant,
    timeout: Duration,
) -> Result<TcpStream, Error> {
    let phase = Instant::now()
        .checked_add(timeout)
        .ok_or(Error::InvalidOptions)?
        .min(deadline);
    let result = crate::connect::tcp(address, phase, cancel);
    // Preserve the public cancellation/whole-run-deadline distinctions. Only a
    // per-connect timeout remains a retryable I/O error under the original run.
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    remaining(deadline)?;
    result.map_err(Error::Io)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(outer_deadline: Option<Instant>) -> RunLimits {
        RunLimits {
            exchanges: 1,
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(1),
            outer_deadline,
        }
    }

    #[test]
    fn enclosing_deadline_is_preserved_across_multiple_run_admissions() {
        let outer = Instant::now() + Duration::from_secs(2);
        assert_eq!(limits(Some(outer)).deadline().expect("first run"), outer);
        assert_eq!(limits(Some(outer)).deadline().expect("later run"), outer);
        assert!(matches!(
            limits(Some(Instant::now())).deadline(),
            Err(Error::Deadline)
        ));
    }

    #[test]
    fn enclosing_deadline_cannot_extend_phase_or_relax_invalid_limits() {
        let outer = Instant::now() + Duration::from_secs(100);
        let deadline = limits(Some(outer)).deadline().expect("bounded phase");
        assert!(deadline <= Instant::now() + Duration::from_secs(10));
        assert!(deadline < outer);
        let mut invalid = limits(Some(Instant::now()));
        invalid.exchanges = 0;
        assert!(matches!(invalid.deadline(), Err(Error::InvalidOptions)));
    }
}
