// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit standard mutual TLS for the existing signed witness protocol.
//!
//! TLS protects transport bytes under its authentication assumptions. Classical
//! certificate authentication is not PQ identity authentication; the unchanged
//! dual signatures still authorize every witness command and reply. Witnesses
//! retain visibility of subjects/heads. No plaintext or classic-KX fallback occurs.
use super::{incoming, transport::checked_remaining, AnchorStore, AnchorSubject, AnchorTransport};
use crate::Cancellation;
use q_periapt_rustls::standard::{MutualTlsClient, MutualTlsServer};
use rustls::{
    pki_types::ServerName, Connection, HandshakeKind, NamedGroup, ProtocolVersion, RootCertStore,
};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, TryLockError},
    thread,
    time::{Duration, Instant},
};

mod channel;
use channel::Channel;

/// Separate ALPN for one length-framed signed witness request/reply per connection.
pub const APPLICATION_PROTOCOL: &[u8] = b"q-periapt-anchor/1";
/// Maximum exact DER leaf pin, checked before retained configuration is allocated.
pub const MAX_CERTIFICATE_BYTES: usize = 65_536;
/// Finite certificate-to-subject authorization table; no wildcard/default entry.
pub const MAX_PEER_BINDINGS: usize = 256;
/// Maximum whole connection/exchange deadline, including the handshake.
pub const MAX_EXCHANGE_SECONDS: u64 = 60;
const REQUEST_BYTES: usize = 3674;
const REPLY_BYTES: usize = 3659;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn attempt_budget(deadline: Instant, cancel: &Cancellation) -> io::Result<Duration> {
    let remaining = checked_remaining(deadline, cancel)?;
    if remaining > Duration::from_secs(MAX_EXCHANGE_SECONDS) {
        return Err(invalid("witness TLS deadline exceeds bound"));
    }
    Ok(remaining)
}
fn pin(certificate: &[u8]) -> io::Result<()> {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid("invalid witness TLS certificate pin length"));
    }
    // Parse the certificate with the maintained TLS parser. This temporary store
    // grants no trust: the caller's immutable TLS config owns the actual roots.
    RootCertStore::empty()
        .add(certificate.to_vec().into())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

/// Explicit encrypted witness endpoint and immutable standard TLS credentials.
/// Each exchange opens a fresh full handshake; it never retries or changes carrier.
pub struct AnchorTlsTransport {
    address: SocketAddr,
    name: ServerName<'static>,
    peer: Vec<u8>,
    config: MutualTlsClient,
    cancel: Cancellation,
}
impl AnchorTlsTransport {
    /// Independently pin the server's DER leaf in addition to CA/name validation.
    /// The witness signing pin remains independently enforced by `AnchorClient`.
    pub fn new(
        address: SocketAddr,
        name: ServerName<'static>,
        peer: Vec<u8>,
        config: MutualTlsClient,
        cancel: Cancellation,
    ) -> io::Result<Self> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(invalid("invalid witness TLS endpoint"));
        }
        pin(&peer)?;
        let config = config
            .with_application_protocol(APPLICATION_PROTOCOL)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            address,
            name,
            peer,
            config,
            cancel,
        })
    }
}
impl AnchorTransport for AnchorTlsTransport {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if request.len() != REQUEST_BYTES {
            return Err(invalid("invalid witness request width"));
        }
        attempt_budget(deadline, &self.cancel)?;
        let stream = crate::connect::tcp(self.address, deadline, &self.cancel)?;
        checked_remaining(deadline, &self.cancel)?;
        let connection = self
            .config
            .connect(self.name.clone())
            .map_err(io::Error::other)?;
        let mut channel = Channel::new(
            stream,
            Connection::Client(connection),
            deadline,
            self.cancel.clone(),
        )?;
        channel.handshake()?;
        if channel.peer()? != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "witness TLS server pin differs",
            ));
        }
        channel.send_frame(request)?;
        channel.close()?;
        let reply = channel.receive_frame(REPLY_BYTES)?;
        // Require the exact one-response stream boundary. Truncation, trailing
        // data or cancellation withholds the reply; no commit outcome is inferred.
        channel.receive_close()?;
        Ok(reply)
    }
}

/// Operator-provisioned exact TLS leaf and enrolled journal/owner/policy subject.
/// Certificate membership alone never authorizes another subject's metadata.
pub struct PeerBinding {
    certificate: Vec<u8>,
    subject: AnchorSubject,
}
impl PeerBinding {
    /// Bind independently retained enrollment metadata, never request-selected scope.
    pub fn new(certificate: Vec<u8>, subject: AnchorSubject) -> io::Result<Self> {
        pin(&certificate)?;
        Ok(Self {
            certificate,
            subject,
        })
    }
}

/// Reusable standard TLS configuration plus an immutable bounded access table.
/// The host owns listening/concurrency and credential/enrollment lifecycle. Calls
/// hold the witness mutex only for canonical admission and durable handling.
#[derive(Clone)]
pub struct AnchorTlsServer {
    config: MutualTlsServer,
    peers: Arc<Vec<PeerBinding>>,
}
impl AnchorTlsServer {
    /// Every accepted certificate must match an explicit leaf/subject pair.
    /// Duplicate pairs, empty tables and excessive retained pins are refused.
    pub fn new(config: MutualTlsServer, peers: Vec<PeerBinding>) -> io::Result<Self> {
        if peers.is_empty() || peers.len() > MAX_PEER_BINDINGS {
            return Err(invalid("invalid witness TLS authorization capacity"));
        }
        for (index, peer) in peers.iter().enumerate() {
            if peers
                .iter()
                .take(index)
                .any(|prior| prior.certificate == peer.certificate && prior.subject == peer.subject)
            {
                return Err(invalid("duplicate witness TLS authorization"));
            }
        }
        let config = config
            .with_application_protocol(APPLICATION_PROTOCOL)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            config,
            peers: Arc::new(peers),
        })
    }

    /// Serve one accepted connection within one unchanged absolute deadline.
    /// Waiting for store ownership observes cancellation; the admitted synchronous
    /// clock/database/crypto operation cannot be preempted or rolled back. Its reply is
    /// withheld if the deadline/cancellation wins after commit. Errors are local;
    /// no detailed storage or authentication diagnostic is emitted to the peer.
    pub fn serve(
        &self,
        stream: TcpStream,
        store: &Mutex<AnchorStore>,
        deadline: Instant,
        cancel: Cancellation,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> io::Result<()> {
        self.serve_observing_wait(stream, store, deadline, cancel, clock, &mut || {})
    }

    // One shared driver. The private observer supplies a deterministic test
    // barrier after a real failed lock attempt, without replacing TLS or storage.
    fn serve_observing_wait(
        &self,
        stream: TcpStream,
        store: &Mutex<AnchorStore>,
        deadline: Instant,
        cancel: Cancellation,
        clock: &mut impl FnMut() -> io::Result<u64>,
        waiting: &mut impl FnMut(),
    ) -> io::Result<()> {
        attempt_budget(deadline, &cancel)?;
        let connection = self.config.accept().map_err(io::Error::other)?;
        let mut channel = Channel::new(
            stream,
            Connection::Server(connection),
            deadline,
            cancel.clone(),
        )?;
        channel.handshake()?;
        let peer = channel.peer()?.to_vec();
        if !self.peers.iter().any(|binding| binding.certificate == peer) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unconfigured witness TLS client",
            ));
        }
        let request = channel.receive_frame(REQUEST_BYTES)?;
        channel.receive_close()?;
        // A complete frame is required before taking the shared store. The same
        // canonical decoder checks the requested authority/subject before any I/O
        // on its durable image; handle then verifies both device signatures.
        let mut owner = loop {
            checked_remaining(deadline, &cancel)?;
            match store.try_lock() {
                Ok(owner) => break owner,
                Err(TryLockError::WouldBlock) => {
                    waiting();
                    thread::sleep(Duration::from_millis(2));
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("witness store owner poisoned"))
                }
            }
        };
        let pin = owner.pin().map_err(io::Error::other)?;
        let subject = incoming(&pin, &request).map_err(io::Error::other)?.subject;
        if !self
            .peers
            .iter()
            .any(|binding| binding.certificate == peer && binding.subject == subject)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "witness TLS subject is not authorized",
            ));
        }
        let now = clock()?;
        checked_remaining(deadline, &cancel)?;
        let reply = owner.handle(&request, now).map_err(io::Error::other)?;
        drop(owner);
        checked_remaining(deadline, &cancel)?;
        if reply.len() != REPLY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid witness reply width",
            ));
        }
        channel.send_frame(&reply)?;
        channel.close()
    }
}

#[cfg(all(test, unix))]
mod tests;
