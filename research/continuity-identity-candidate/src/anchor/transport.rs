// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::MonotonicInstant as Instant;
use std::{io, time::Duration};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod tcp;
#[cfg(feature = "anchor-tls")]
pub(super) use tcp::checked_remaining;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tcp::AnchorTcpTransport;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod fetch;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use fetch::AnchorFetchTransport;

/// Untrusted byte carrier. Implementations must honor the absolute deadline;
/// journal authority comes only from verification of the complete signed reply.
/// On `wasm32-unknown-unknown`, exchange is asynchronous. Native carriers retain
/// their synchronous API. Suspending a request never establishes non-commit.
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), async_trait::async_trait(?Send))]
pub trait AnchorTransport: Send {
    /// Optionally narrow an attempt to an enclosing caller's absolute deadline.
    /// The client never accepts an extension of its own attempt budget. Failure
    /// is checked before signing or dispatch; it does not imply rollback of any
    /// earlier command in the enclosing invocation.
    fn constrain_deadline(&self, deadline: Instant) -> io::Result<Instant> {
        Ok(deadline)
    }
    /// Exchange one bounded signed request. Transport failure says nothing about
    /// whether the witness committed; never report a fabricated reply or absence.
    async fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>>;
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "anchor attempt deadline expired"))
}

/// Missing or invalid witness evidence, never a successful unanchored fallback.
#[derive(Debug)]
pub enum AnchorClientError {
    /// I/O, deadline or malformed transport frame; the command may have committed.
    Transport(io::Error),
    /// The response or configured signing owner failed exact cryptographic admission.
    Verification(Error),
    /// The authenticated witness head/command conflicts with the local state.
    Conflict,
    /// A verified reply refuses the exact requested current enrollment authority.
    /// Head queries and local roster updates cannot replace this confirmation.
    AuthorityDenied,
}
impl std::fmt::Display for AnchorClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Transport(_) => "witness outcome unavailable; reconcile exact command",
            Self::Verification(_) => "witness response verification failed",
            Self::Conflict => "witness state or writer fence differs",
            Self::AuthorityDenied => "witness enrollment authority is not current or valid",
        })
    }
}
impl std::error::Error for AnchorClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Conflict | Self::AuthorityDenied => None,
        }
    }
}
impl From<Error> for AnchorClientError {
    fn from(error: Error) -> Self {
        Self::Verification(error)
    }
}

/// Owned pinned witness connection and device signer. The journal consumes this
/// owner; byte transports cannot manufacture authenticated advancement evidence.
/// A failed exchange, or dropping an exchange future after its first poll, closes
/// its signing owner. Reopen the original journal and reconcile its retained
/// intent with a fresh owner; do not substitute a new command. An unpolled future
/// has not dispatched or moved the signing owner.
pub struct AnchorClient {
    pin: AnchorPin,
    signer: Option<DeviceSigningKey>,
    transport: Box<dyn AnchorTransport>,
    timeout: Duration,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AnchorClient {
    /// Require a finite nonzero attempt budget of at most 60 seconds.
    pub fn new(
        pin: AnchorPin,
        signer: DeviceSigningKey,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<Self, AnchorClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(AnchorClientError::Transport(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        if signer.public_key()?.shares_component(pin.public_key()) {
            return Err(Error::Scope.into());
        }
        Ok(Self {
            pin,
            signer: Some(signer),
            transport,
            timeout,
        })
    }
    pub(crate) fn pin(&self) -> &AnchorPin {
        &self.pin
    }
    pub(crate) fn check_device(&self, device: &VerifiedDevice) -> Result<(), Error> {
        self.signer
            .as_ref()
            .ok_or(Error::Closed)?
            .check_device(device)
    }
    pub(crate) fn signer_public_key(&self) -> Result<PublicKey, Error> {
        self.signer.as_ref().ok_or(Error::Closed)?.public_key()
    }
    pub(crate) async fn exchange(
        &mut self,
        subject: AnchorSubject,
        operation: AnchorOperation,
    ) -> Result<AnchorReply, AnchorClientError> {
        // A dropped asynchronous exchange must not leave its signer usable.
        // The in-flight future owns it; only a fully verified, timely reply
        // returns it to this client. Error or future drop erases that owner.
        let signer = self.signer.take().ok_or(Error::Closed)?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| AnchorClientError::Transport(io::ErrorKind::InvalidInput.into()))?;
        let deadline = self
            .transport
            .constrain_deadline(deadline)
            .map_err(AnchorClientError::Transport)?
            .min(deadline);
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let request = AnchorRequest::new(&self.pin, subject, operation, &signer)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let wire = self
            .transport
            .exchange(request.as_bytes(), deadline)
            .await
            .map_err(AnchorClientError::Transport)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        let reply = self.pin.verify_reply(&request, &wire)?;
        remaining(deadline).map_err(AnchorClientError::Transport)?;
        self.signer = Some(signer);
        Ok(reply)
    }
}
