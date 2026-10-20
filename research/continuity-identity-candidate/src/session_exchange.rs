// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Owned, replayable session operations over an untrusted request/reply carrier.
//!
//! QPCXCH01 is distinct from the TLS-bound QPCNET01 carrier. Its establishment
//! result requires an authenticated epoch-zero acknowledgement, not a public
//! session ID. The proof attests original peer key possession, not fresh liveness
//! or remote business effects. The existing bootstrap, journal and message
//! cryptography are unchanged. An error or dropped polled operation closes the
//! enrolled owner; reopen the original installation and retry the original ID.
use crate::{
    BootstrapContext, BootstrapPeer, BootstrapRole, Cancellation, CommittedPlaintext, DurableError,
    EnrolledDevice, InitiationId, MessageId, MessageStatus, MonotonicInstant as Instant,
    ReopenedPeer,
};
use std::{io, sync::Arc, time::Duration};

pub(crate) mod account;
mod client;
mod codec;
mod control;
mod server;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod tcp;
pub use account::{AccountDelivered, AccountDeliveryOutcome, AccountSubmission};
pub use client::PreparedMessage;
use codec::{frame, payload, ACK, FINAL, INITIAL, MESSAGE, READY, REPLY};
pub use control::{PreparedRekey, RekeyCompleted, RekeyDeliveryStep};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tcp::TcpTransport;

/// Failure retains its responsible boundary; no variant establishes rollback.
#[derive(Debug)]
pub enum Error {
    /// Original authority, storage, cryptographic or protocol rejection.
    Durable(DurableError),
    /// Trusted wall-clock callback failed.
    Clock(io::Error),
    /// Untrusted carrier failed; a peer commit can already have happened.
    Transport(io::Error),
    /// The host did not confirm durable application consumption.
    Application(io::Error),
    /// One-way cancellation was observed.
    Cancelled,
    /// The original monotonic invocation deadline expired.
    Deadline,
    /// The explicit request allowance was exhausted; retain this same target.
    ExchangeLimit,
}
impl From<DurableError> for Error {
    fn from(value: DurableError) -> Self {
        Self::Durable(value)
    }
}
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::Durable(value.into())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Durable(_) => "session operation rejected; reconcile original state",
            Self::Clock(_) => "session trusted clock failed",
            Self::Transport(_) => "session transport outcome unavailable",
            Self::Application(_) => "application consumption unconfirmed",
            Self::Cancelled => "session operation cancelled",
            Self::Deadline => "session operation deadline expired",
            Self::ExchangeLimit => "session exchange allowance exhausted",
        })
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Durable(e) => Some(e),
            Self::Clock(e) | Self::Transport(e) | Self::Application(e) => Some(e),
            Self::Cancelled | Self::Deadline | Self::ExchangeLimit => None,
        }
    }
}

/// One finite invocation; retries must not extend this deadline.
pub struct Run<'a> {
    cancel: &'a Cancellation,
    deadline: Instant,
}
impl<'a> Run<'a> {
    /// Original absolute deadline, for bounded host callbacks; it cannot be extended.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Create a nonzero invocation of at most 120 seconds.
    pub fn new(cancel: &'a Cancellation, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(crate::contract::MAX_RUN_TIMEOUT_SECONDS)
        {
            return Err(crate::Error::Encoding.into());
        }
        Ok(Self {
            cancel,
            deadline: Instant::now().checked_add(timeout).ok_or(Error::Deadline)?,
        })
    }
    /// Preserve an enclosing absolute deadline after admission or request I/O.
    /// The remaining interval must be nonzero and at most 120 seconds.
    pub fn until(cancel: &'a Cancellation, deadline: Instant) -> Result<Self, Error> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Deadline)?;
        if remaining.is_zero()
            || remaining > Duration::from_secs(crate::contract::MAX_RUN_TIMEOUT_SECONDS)
        {
            return Err(crate::Error::Encoding.into());
        }
        Ok(Self { cancel, deadline })
    }
    /// Check only cancellation and time bounds. This grants no identity, policy
    /// or storage authority; owned protocol operations still admit those inputs.
    pub fn check(&self) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn time(
        &self,
        context: &BootstrapContext,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<u64, Error> {
        self.check()?;
        let now = clock().map_err(Error::Clock)?;
        context.check_session_identity(now)?;
        self.check()?;
        Ok(now)
    }
}

/// Unauthenticated request routing metadata. It selects no trust root and grants
/// no authority; the owner must still authenticate/admit the original operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRoute {
    /// An initial/final flight under separately configured peer expectations.
    Bootstrap,
    /// Application input naming an original session.
    Message([u8; 32]),
    /// Signed control input naming an original session.
    Control([u8; 32]),
}
impl RequestRoute {
    /// Bound and inspect the existing QPCXCH01 frame; this does not authenticate it.
    pub fn inspect(request: &[u8]) -> Result<Self, Error> {
        let (kind, body) = codec::open(request)?;
        match kind {
            INITIAL | FINAL => Ok(Self::Bootstrap),
            MESSAGE => {
                let (_, message) = codec::split(body)?;
                Ok(Self::Message(crate::durable::message_route(message)?.0))
            }
            codec::CONTROL => Ok(Self::Control(crate::RekeyControlMessage::inspect_session(
                body,
            )?)),
            _ => Err(crate::Error::Encoding.into()),
        }
    }
}

/// Bounded opaque carrier. It supplies no authentication or commit evidence.
/// Implementations must honor the absolute deadline and one-way cancellation.
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), async_trait::async_trait(?Send))]
pub trait Transport {
    /// Exchange one frame, without inventing replies or implicitly changing its ID.
    async fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>>;
}

/// Host effects and deduplication must commit durably together before success.
/// An unknown effect must return an error. Replay can call the same ID again.
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), async_trait::async_trait(?Send))]
pub trait Consumer {
    /// Commit the exact authenticated delivery; retained host copies are outside SDK erasure.
    async fn commit(&mut self, session: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()>;
}

/// Public context for an existing session, with no independent storage lease.
#[derive(Clone)]
pub struct Session {
    context: Arc<BootstrapContext>,
    role: BootstrapRole,
    id: [u8; 32],
}
impl Session {
    /// Retain the same already authenticated native reopen descriptor.
    pub fn from_reopened(peer: &ReopenedPeer) -> Self {
        Self {
            context: Arc::clone(peer.context()),
            role: peer.role(),
            id: peer.session_id(),
        }
    }
    /// Original session identity, not a remote consumption receipt.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Bootstrap direction, independent of application traffic direction.
    pub fn role(&self) -> BootstrapRole {
        self.role
    }
}

/// Exact original application operation. The ID must come from this journal.
pub struct Submission<'a> {
    /// Original correlation ID retained across unknown outcomes.
    pub message: MessageId,
    /// Original plaintext, at most 16 KiB.
    pub plaintext: &'a [u8],
    /// Original associated data, at most 1 KiB.
    pub associated_data: &'a [u8],
}
/// Authenticated cumulative peer consumption, never inferred from a response alone.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Consumption {
    /// The authenticated prefix includes this exact original message.
    Confirmed,
    /// The authenticated prefix does not yet include this message.
    PrefixPending,
}

struct Operation<'a> {
    owner: &'a mut EnrolledDevice,
    armed: bool,
}
impl<'a> Operation<'a> {
    fn new(owner: &'a mut EnrolledDevice) -> Self {
        Self { owner, armed: true }
    }
    fn finish<T>(mut self, value: Result<T, Error>) -> Result<T, Error> {
        if value.is_ok() {
            self.armed = false;
        }
        value
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.close();
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
