// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded native bootstrap and durable application delivery over standard TLS.
//! A successful application result requires the original session's authenticated
//! consumption prefix, never just a TLS response or a committed inbox.
use crate::native_transport::{self, check, remaining, retryable, Channel};
pub use crate::native_transport::{Cancellation, Error, RunLimits};
use crate::{
    BootstrapContext, CommittedPlaintext, DeviceJournal, DeviceSigningKey, InitiationId, MessageId,
    MessageStatus, SessionArchiveStore,
};
use q_periapt_rustls::connection::{Credentials, Endpoint, Limits};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Instant,
};

mod client;
mod codec;
mod server;
use codec::{frame, payload, ACK, BOOTSTRAP, INITIAL, MESSAGE, READY, REPLY};

/// Exclusive actor; callers retain the journal and controlled signing owner.
pub struct Actor<'a> {
    /// Exact store, independently provisioned before transport use.
    pub journal: &'a mut DeviceJournal,
    /// Exact durable cleanup index. Bootstrap must commit its archive here before
    /// activation; data delivery requires the original authenticated archive.
    pub archives: &'a mut SessionArchiveStore,
    /// Independently verified account, roster, policy and manifest selection.
    pub context: &'a Arc<BootstrapContext>,
    /// Matching device owner; bootstrap may sign, application delivery does not.
    pub signer: &'a DeviceSigningKey,
}
/// Explicit network peer and one finite invocation's resource bounds.
pub struct Run<'a> {
    /// Selected address; the carrier does not discover peers or follow redirects.
    pub address: SocketAddr,
    /// Name checked in addition to the exact TLS certificate pin.
    pub server_name: &'a str,
    /// Every network attempt consumes this allowance; reconnects retain the deadline.
    pub limits: RunLimits,
    /// One-way cancellation, which cannot roll back external or journal commits.
    pub cancel: &'a Cancellation,
}
/// New application input with a journal-issued ID retained across uncertain results.
pub struct Submission<'a> {
    /// Previously established session.
    pub session: [u8; 32],
    /// Original message ID; changed input under a reserved/committed ID conflicts.
    pub message: MessageId,
    /// At most the journal's 16-KiB message bound.
    pub plaintext: &'a [u8],
    /// At most the journal's 1-KiB associated-data bound.
    pub associated_data: &'a [u8],
}
/// Locally activated bootstrap after the peer reported its matching activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Established {
    /// Exact transcript-bound session; this is not a secrecy-recovery claim.
    pub session: [u8; 32],
    /// Attempted exchanges, including failed network attempts.
    pub exchanges: u16,
}
/// Authenticated cumulative consumption outcome for the original message ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Consumption {
    /// The peer's authenticated consumption prefix includes this exact ID.
    Confirmed,
    /// A valid prefix does not yet include this ID. Earlier out-of-order work may
    /// still need delivery; the caller must not treat this as completed consumption.
    PrefixPending,
}
/// Client result after accepting a real session/epoch-specific consumption proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivered {
    /// Original application correlation ID.
    pub message: MessageId,
    /// Exact proof-based outcome; a response alone never means Confirmed.
    pub consumption: Consumption,
    /// Attempted exchanges including failures, without resetting on reconnect.
    pub exchanges: u16,
}
/// The host owns its external transaction and must deduplicate by session/message.
/// Return success only after the application effect and deduplication record are
/// durable together. Failure (including an unknown external commit) leaves the
/// journal inbox unconsumed; a retry may call this handler with the same ID again.
/// No method may acknowledge an effect merely because it was queued or started.
pub trait Consumer {
    /// Durably account for this exact authenticated, committed inbox delivery.
    /// Copies retained by the host are outside the plaintext owner's erasure scope.
    fn commit(&mut self, session: [u8; 32], delivery: &CommittedPlaintext) -> io::Result<()>;
}
/// Result of one accepted connection, after flushing its final reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Served {
    /// The confirmed bootstrap root was transferred into durable message state.
    Established([u8; 32]),
    /// The host confirmed consumption, or this ID was already consumed earlier.
    /// This does not certify new bytes for an ID below the erased receive prefix.
    Consumed {
        /// Original pairwise session.
        session: [u8; 32],
        /// Original message correlation ID.
        message: MessageId,
        /// True means the handler was not called because prior consumption exists.
        duplicate: bool,
    },
}
/// Endpoint bound to one authenticated context before a session ID exists.
/// TLS certificate pins and exporter policy confirmation remain SDK-owned.
pub struct ConnectionEndpoint {
    endpoint: Endpoint,
    context: [u8; 32],
    client: bool,
}
impl ConnectionEndpoint {
    fn new(
        context: &BootstrapContext,
        credentials: Credentials<'_>,
        limits: Limits,
        client: bool,
    ) -> Result<Self, Error> {
        let mut binding = b"Q-PERIAPT-CONTINUITY-CONNECTION-TLS/v1/".to_vec();
        binding.extend_from_slice(&context.digest());
        let runtime = Arc::clone(&context.policy().runtime);
        let endpoint = if client {
            Endpoint::client(runtime, credentials, &binding, limits)?
        } else {
            Endpoint::server(runtime, credentials, &binding, limits)?
        };
        Ok(Self {
            endpoint,
            context: context.digest(),
            client,
        })
    }
    /// Active endpoint; application direction is independent of bootstrap role.
    pub fn client(
        context: &BootstrapContext,
        credentials: Credentials<'_>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(context, credentials, limits, true)
    }
    /// Passive endpoint; every bootstrap or data frame still has journal admission.
    pub fn server(
        context: &BootstrapContext,
        credentials: Credentials<'_>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(context, credentials, limits, false)
    }
    /// Revoke this endpoint and all SDK connections. Also signal cancellation to
    /// wake its socket loops; already committed work is not undone.
    pub fn close(&self) {
        self.endpoint.close();
    }
    fn binding(&self, context: &BootstrapContext, client: bool) -> Result<(), Error> {
        if self.context != context.digest() {
            return Err(Error::Binding);
        }
        if self.client != client {
            return Err(Error::InvalidOptions);
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod test_support {
    use std::{
        fs,
        io::{self, Write},
        path::Path,
        time::Duration,
    };
    pub(super) fn response(kind: u8, expected: Vec<u8>) -> io::Result<Vec<u8>> {
        if kind == super::MESSAGE
            && std::env::var("QPERIAPT_CONNECTION_TLS_CUT").ok().as_deref() == Some("old-ack")
        {
            let path = std::env::var_os("QPERIAPT_CONNECTION_TLS_DIR")
                .ok_or(io::ErrorKind::InvalidInput)?;
            return super::frame(super::ACK, &fs::read(Path::new(&path).join("old-ack"))?)
                .map_err(io::Error::other);
        }
        Ok(expected)
    }
    pub(super) fn archive_boundary(
        stage: &str,
        session: &[u8],
        cancel: &super::Cancellation,
        deadline: std::time::Instant,
    ) -> io::Result<()> {
        after_stage(stage, session)?;
        let mode = std::env::var("QPERIAPT_CONNECTION_TLS_CUT").ok();
        if stage == "server-archive"
            && matches!(
                mode.as_deref(),
                Some("cancel-server-archive" | "deadline-server-archive")
            )
        {
            let path = std::env::var_os("QPERIAPT_CONNECTION_TLS_DIR")
                .ok_or(io::ErrorKind::InvalidInput)?;
            let mut file = fs::File::create_new(Path::new(&path).join("archive-boundary"))?;
            file.write_all(session)?;
            file.sync_all()?;
            if mode.as_deref() == Some("cancel-server-archive") {
                cancel.cancel();
            } else {
                std::thread::sleep(
                    deadline.saturating_duration_since(std::time::Instant::now())
                        + Duration::from_millis(5),
                );
            }
        }
        Ok(())
    }
    pub(super) fn after_reply(kind: u8, bytes: &[u8]) -> io::Result<()> {
        let stage = match kind {
            super::INITIAL => "reply",
            super::BOOTSTRAP => "activation",
            super::MESSAGE => "ack",
            _ => return Ok(()),
        };
        after_stage(stage, bytes)
    }
    pub(super) fn after_stage(stage: &str, bytes: &[u8]) -> io::Result<()> {
        if std::env::var("QPERIAPT_CONNECTION_TLS_CUT").ok().as_deref() != Some(stage) {
            return Ok(());
        }
        let path =
            std::env::var_os("QPERIAPT_CONNECTION_TLS_DIR").ok_or(io::ErrorKind::InvalidInput)?;
        let path = Path::new(&path);
        let mut file = fs::File::create_new(path.join("cut-wire"))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let pending = path.join("cut-ready-pending");
        let mut file = fs::File::create_new(&pending)?;
        file.write_all(stage.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(pending, path.join("cut-ready"))?;
        loop {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
