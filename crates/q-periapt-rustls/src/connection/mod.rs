// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
//! Bounded, transport-independent reference connection over standard mutual TLS.
//!
//! The application explicitly selects standard TLS. A separate confirmation
//! binds the SDK's signed application-policy identity and application context to
//! the fresh TLS exporter and both pinned leaf certificates. It does not convert
//! RFC 10024 into ContextBound or attest to a remote process enforcing its policy.
//! The host supplies durable policy state, network I/O and deadline wakeups.
//! One request may be outstanding; no retry or durable RPC execution is implied.

mod frame;
use crate::standard::{ConfigurationError, MutualTlsClient, MutualTlsServer};
use frame::{Decoder, Outgoing, WipingBytes, CLIENT_CONFIRM, REQUEST, RESPONSE, SERVER_CONFIRM};
use q_periapt_core::{ct_eq, ZeroizingBytes};
use q_periapt_sdk::Runtime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{NamedGroup, RootCertStore};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

/// Versioned application protocol; standard-only peers do not implement it.
pub const APPLICATION_PROTOCOL: &[u8] = b"qperiapt-sdk/1";
/// Maximum request or response payload, independently bounded in both directions.
pub const MAX_PAYLOAD_BYTES: usize = 65_536;
/// Maximum encrypted bytes admitted or drained by one synchronous engine call.
pub const MAX_TLS_IO_BYTES: usize = 16_384;
/// Certificate/anchor bound before native parsing or copying.
pub const MAX_CERTIFICATE_BYTES: usize = 65_536;
/// Borrowed private identity material bound before parsing/copying.
pub const MAX_PRIVATE_KEY_BYTES: usize = 16_384;
// RFC 9266's registered tls-exporter channel binding, used once by this protocol
// instance. Public context/identity commitments travel inside authenticated TLS.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Explicit connection/configuration failure. Errors contain no key/payload bytes.
#[derive(Debug)]
pub enum Error {
    /// Runtime, endpoint or connection has been closed.
    Closed,
    /// Invalid caller buffer length.
    InvalidLength,
    /// Endpoint limits or role/name are invalid.
    InvalidOptions,
    /// Endpoint live-connection capacity or controlled allocation exhausted.
    ResourceLimit,
    /// Operation is not valid in the current live state; state is retained.
    NotReady,
    /// Handshake, confirmation, request or idle deadline elapsed.
    Timeout,
    /// Upstream platform cryptographic randomness failed; there is no fallback.
    Entropy,
    /// Authenticated TLS peer differs from the explicitly pinned leaf certificate.
    PeerIdentity,
    /// Peer claims a different application-policy root/version/digest.
    PolicyMismatch,
    /// Peer context/session/certificate binding differs.
    BindingMismatch,
    /// Invalid ALPN, message kind, frame length, sequence or orderly-close position.
    Protocol,
    /// The local SDK policy was disabled/revoked or otherwise rejected use.
    Policy(q_periapt_sdk::Error),
    /// Upstream certificate/configuration validation failed.
    Configuration(ConfigurationError),
    /// Upstream TLS authentication or record validation failed.
    Tls(rustls::Error),
    /// Unexpected TLS input EOF or underlying in-memory reader/writer failure.
    Io(std::io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("connection owner is closed"),
            Self::InvalidLength => f.write_str("invalid connection input length"),
            Self::InvalidOptions => f.write_str("invalid connection options or endpoint role"),
            Self::ResourceLimit => f.write_str("connection resource limit reached"),
            Self::NotReady => f.write_str("connection is not ready for this operation"),
            Self::Timeout => f.write_str("connection deadline elapsed"),
            Self::Entropy => f.write_str("connection platform entropy unavailable"),
            Self::PeerIdentity => f.write_str("TLS peer certificate does not match its pin"),
            Self::PolicyMismatch => f.write_str("peer application policy differs"),
            Self::BindingMismatch => f.write_str("peer application context or TLS binding differs"),
            Self::Protocol => f.write_str("invalid reference connection protocol state or frame"),
            Self::Policy(error) => write!(f, "connection policy: {error}"),
            Self::Configuration(error) => write!(f, "connection configuration: {error}"),
            Self::Tls(error) => write!(f, "connection TLS: {error}"),
            Self::Io(error) => write!(f, "connection input/output: {error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<rustls::Error> for Error {
    fn from(error: rustls::Error) -> Self {
        if matches!(error, rustls::Error::FailedToGetRandomBytes) {
            Self::Entropy
        } else {
            Self::Tls(error)
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<ConfigurationError> for Error {
    fn from(error: ConfigurationError) -> Self {
        Self::Configuration(error)
    }
}
impl From<q_periapt_sdk::Error> for Error {
    fn from(error: q_periapt_sdk::Error) -> Self {
        if error == q_periapt_sdk::Error::Closed {
            Self::Closed
        } else {
            Self::Policy(error)
        }
    }
}

/// Each endpoint requires an explicit peer leaf pin, alongside normal TLS
/// certificate validity/name checks. Input copies remain the caller's responsibility.
pub struct Credentials<'a> {
    /// This endpoint's one leaf certificate, DER encoded.
    pub certificate: &'a [u8],
    /// Corresponding private key in a rustls-supported DER representation.
    pub private_key: &'a [u8],
    /// Exact trusted peer leaf certificate, DER encoded; no TOFU occurs here.
    pub peer_certificate: &'a [u8],
}

/// Endpoint capacity and absolute per-phase deadlines. Network adapters must
/// wake at `Progress::remaining_ms`; absence of I/O never extends a deadline.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous live connections, 1..=64.
    pub max_connections: usize,
    /// Entire TLS + policy-confirmation deadline, 1..=120000 milliseconds.
    pub handshake_ms: u32,
    /// One outstanding request/response deadline, 1..=120000 milliseconds.
    pub request_ms: u32,
    /// Idle deadline after confirmation/response, 1..=300000 milliseconds.
    pub idle_ms: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            handshake_ms: 10_000,
            request_ms: 5_000,
            idle_ms: 30_000,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}
enum TlsEndpoint {
    Client(MutualTlsClient),
    Server(MutualTlsServer),
}
struct Shared {
    policy: Arc<Runtime>,
    context_digest: [u8; 32],
    own_certificate: [u8; 32],
    peer_certificate: [u8; 32],
    closed: AtomicBool,
    live: AtomicUsize,
    limits: Limits,
}
impl Shared {
    fn check(&self) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if !self.policy.is_enabled()? {
            return Err(Error::Policy(q_periapt_sdk::Error::PolicyDenied));
        }
        Ok(())
    }
}
struct Lease(Arc<Shared>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Immutable TLS identity/configuration tied to one verified application policy.
/// Closing/dropping it revokes its connections. It retains the supplied runtime
/// owner; explicit runtime close or policy activation also revokes those sessions.
pub struct Endpoint {
    tls: TlsEndpoint,
    shared: Arc<Shared>,
}
impl Endpoint {
    fn new(
        policy: Arc<Runtime>,
        credentials: Credentials<'_>,
        context: &[u8],
        limits: Limits,
        role: Role,
    ) -> Result<Self, Error> {
        if !(1..=MAX_CERTIFICATE_BYTES).contains(&credentials.certificate.len())
            || !(1..=MAX_CERTIFICATE_BYTES).contains(&credentials.peer_certificate.len())
            || !(1..=MAX_PRIVATE_KEY_BYTES).contains(&credentials.private_key.len())
            || context.len() > q_periapt_core::MAX_APPLICATION_CONTEXT_BYTES
        {
            return Err(Error::InvalidLength);
        }
        if !(1..=64).contains(&limits.max_connections)
            || !(1..=120_000).contains(&limits.handshake_ms)
            || !(1..=120_000).contains(&limits.request_ms)
            || !(1..=300_000).contains(&limits.idle_ms)
        {
            return Err(Error::InvalidOptions);
        }
        if !policy.is_enabled()? {
            return Err(Error::Policy(q_periapt_sdk::Error::PolicyDenied));
        }
        let certificates = vec![CertificateDer::from(credentials.certificate.to_vec())];
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(credentials.peer_certificate))?;
        // Parse borrowed DER first. The standard constructors immediately hand
        // the sole owned copy to AWS-LC's zeroizing key loader on every path.
        let key = PrivateKeyDer::try_from(credentials.private_key)
            .map_err(|_| Error::InvalidOptions)?
            .clone_key();
        let tls = match role {
            Role::Client => TlsEndpoint::Client(
                MutualTlsClient::new(roots, certificates, key)?
                    .with_application_protocol(APPLICATION_PROTOCOL)?,
            ),
            Role::Server => TlsEndpoint::Server(
                MutualTlsServer::new(roots, certificates, key)?
                    .with_application_protocol(APPLICATION_PROTOCOL)?,
            ),
        };
        let mut context_hash = Sha256::new();
        context_hash.update(b"QPeriapt-SDK-Connection-v1");
        context_hash.update([1]); // explicit standard TLS transport
        context_hash.update((context.len() as u32).to_be_bytes());
        context_hash.update(context);
        let endpoint = Self {
            tls,
            shared: Arc::new(Shared {
                policy,
                context_digest: context_hash.finalize().into(),
                own_certificate: Sha256::digest(credentials.certificate).into(),
                peer_certificate: Sha256::digest(credentials.peer_certificate).into(),
                closed: AtomicBool::new(false),
                live: AtomicUsize::new(0),
                limits,
            }),
        };
        endpoint.shared.check()?;
        Ok(endpoint)
    }
    /// Create a client endpoint with an explicit standard-TLS transport choice.
    pub fn client(
        policy: Arc<Runtime>,
        credentials: Credentials<'_>,
        context: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(policy, credentials, context, limits, Role::Client)
    }
    /// Create a server endpoint requiring the explicitly pinned client identity.
    pub fn server(
        policy: Arc<Runtime>,
        credentials: Credentials<'_>,
        context: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(policy, credentials, context, limits, Role::Server)
    }
    fn lease(&self) -> Result<Lease, Error> {
        self.shared.check()?;
        let mut current = self.shared.live.load(Ordering::Acquire);
        loop {
            if current >= self.shared.limits.max_connections {
                return Err(Error::ResourceLimit);
            }
            match self.shared.live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let lease = Lease(Arc::clone(&self.shared));
        self.shared.check()?;
        Ok(lease)
    }
    /// Start a fresh client connection; no DNS resolution or socket I/O occurs.
    pub fn connect(&self, server_name: &str) -> Result<Connection, Error> {
        if !(1..=253).contains(&server_name.len()) {
            return Err(Error::InvalidLength);
        }
        let name =
            ServerName::try_from(server_name.to_owned()).map_err(|_| Error::InvalidOptions)?;
        let TlsEndpoint::Client(client) = &self.tls else {
            return Err(Error::InvalidOptions);
        };
        let lease = self.lease()?;
        Connection::new(
            rustls::Connection::Client(client.connect(name)?),
            lease,
            Role::Client,
        )
    }
    /// Start a fresh server connection; no socket accept/read occurs.
    pub fn accept(&self) -> Result<Connection, Error> {
        let TlsEndpoint::Server(server) = &self.tls else {
            return Err(Error::InvalidOptions);
        };
        let lease = self.lease()?;
        Connection::new(
            rustls::Connection::Server(server.accept()?),
            lease,
            Role::Server,
        )
    }
    /// Revoke all new operations; adapters must cancel outstanding network I/O.
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.close();
    }
}

/// Observable protocol state. Success requires application-policy confirmation,
/// not merely TLS handshake completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Phase {
    /// TLS 1.3 authentication in progress.
    Handshaking = 1,
    /// Waiting for the peer's bound application-policy confirmation.
    Confirming = 2,
    /// Confirmed and ready for one request.
    Ready = 3,
    /// Client waits for the matching response.
    RequestPending = 4,
    /// Server has an authenticated request available to take.
    RequestReady = 5,
    /// Server application owns a request and must respond within its deadline.
    HandlingRequest = 6,
    /// Client has the matching authenticated response available to take.
    ResponseReady = 7,
    /// An orderly local close is queued; drain encrypted output, then release I/O.
    Closing = 8,
}
/// Snapshot used by an external network adapter to drive encrypted I/O.
#[derive(Clone, Copy, Debug)]
pub struct Progress {
    /// Current protocol phase.
    pub phase: Phase,
    /// Pending encrypted output or framed plaintext waiting for TLS buffer space.
    pub wants_write: bool,
    /// Upper bound until the next mandatory deadline check, rounded up in ms.
    pub remaining_ms: u32,
}
/// One plaintext application message. Drop erases this owner's buffer; external
/// copies, TLS library internal buffers and registers have separate lifetimes.
pub struct Message {
    id: u64,
    // Constructed only by parse_message after validating the fixed 9-byte
    // kind/sequence prefix. Owning the whole frame avoids another payload copy.
    body: WipingBytes,
}
impl Message {
    /// Connection-local sequence; it is not a durable transaction identifier.
    pub fn request_id(&self) -> u64 {
        self.id
    }
    /// Borrow authenticated payload bytes without an implicit copy.
    pub fn bytes(&self) -> &[u8] {
        self.body.0.split_at(9).1
    }
}

struct Live {
    tls: rustls::Connection,
    lease: Lease,
    role: Role,
    phase: Phase,
    deadline: Instant,
    policy: [u8; 68],
    confirmation_context: [u8; 96],
    binding: Option<ZeroizingBytes<32>>,
    decoder: Decoder,
    outgoing: Option<Outgoing>,
    message: Option<Message>,
    next_id: u64,
    pending_id: Option<u64>,
    peer_closed: bool,
}
impl Live {
    fn check(&self) -> Result<(), Error> {
        self.lease.0.check()?;
        if Instant::now() >= self.deadline {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    fn idle(&mut self) {
        self.deadline = Instant::now() + Duration::from_millis(self.lease.0.limits.idle_ms.into());
    }
    fn request_deadline(&mut self) {
        self.deadline =
            Instant::now() + Duration::from_millis(self.lease.0.limits.request_ms.into());
    }
    fn flush_plaintext(&mut self) -> Result<(), Error> {
        if let Some(frame) = self.outgoing.as_mut() {
            while frame.offset < frame.bytes.0.len() {
                let rest = frame.bytes.0.get(frame.offset..).ok_or(Error::Protocol)?;
                match self.tls.writer().write(rest) {
                    Ok(0) => break,
                    Ok(written) => frame.offset += written,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if frame.offset == frame.bytes.0.len() {
                self.outgoing = None;
            }
        }
        Ok(())
    }
    fn tls_completed(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Handshaking || self.tls.is_handshaking() {
            return Ok(());
        }
        if self.tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || self
                .tls
                .negotiated_key_exchange_group()
                .map(|group| group.name())
                != Some(NamedGroup::X25519MLKEM768)
            || self.tls.handshake_kind() != Some(rustls::HandshakeKind::Full)
            || self.tls.alpn_protocol() != Some(APPLICATION_PROTOCOL)
        {
            return Err(Error::Protocol);
        }
        let peer = self
            .tls
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(Error::PeerIdentity)?;
        let peer_digest: [u8; 32] = Sha256::digest(peer.as_ref()).into();
        if peer_digest != self.lease.0.peer_certificate {
            return Err(Error::PeerIdentity);
        }
        let (client, server) = match self.role {
            Role::Client => (&self.lease.0.own_certificate, &peer_digest),
            Role::Server => (&peer_digest, &self.lease.0.own_certificate),
        };
        let (context, identities) = self.confirmation_context.split_at_mut(32);
        context.copy_from_slice(&self.lease.0.context_digest);
        let (client_out, server_out) = identities.split_at_mut(32);
        client_out.copy_from_slice(client);
        server_out.copy_from_slice(server);
        let mut binding = ZeroizingBytes::<32>::zeroed();
        self.tls
            .export_keying_material(binding.as_mut_bytes(), EXPORTER_LABEL, Some(&[]))?;
        if self.role == Role::Client {
            self.outgoing = Some(Outgoing::confirmation(
                CLIENT_CONFIRM,
                &self.policy,
                &self.confirmation_context,
                binding.as_bytes(),
            )?);
        }
        self.binding = Some(binding);
        self.phase = Phase::Confirming;
        Ok(())
    }
    fn frame(&mut self, body: WipingBytes) -> Result<(), Error> {
        let (&kind, payload) = body.0.split_first().ok_or(Error::Protocol)?;
        match (self.role, self.phase, kind) {
            (Role::Server, Phase::Confirming, CLIENT_CONFIRM)
            | (Role::Client, Phase::Confirming, SERVER_CONFIRM) => {
                if payload.len() != 196 {
                    return Err(Error::Protocol);
                }
                let (policy, remaining) = payload.split_at(68);
                if policy != self.policy {
                    return Err(Error::PolicyMismatch);
                }
                let (context, binding) = remaining.split_at(96);
                if context != self.confirmation_context {
                    return Err(Error::BindingMismatch);
                }
                let expected = self.binding.as_ref().ok_or(Error::Protocol)?;
                if ct_eq(binding, expected.as_bytes()) != 0xff {
                    return Err(Error::BindingMismatch);
                }
                if self.role == Role::Server {
                    self.outgoing = Some(Outgoing::confirmation(
                        SERVER_CONFIRM,
                        &self.policy,
                        &self.confirmation_context,
                        expected.as_bytes(),
                    )?);
                }
                self.binding = None;
                self.phase = Phase::Ready;
                self.idle();
            }
            (Role::Server, Phase::Ready, REQUEST) if !self.peer_closed => {
                let message = frame::parse_message(body)?;
                if message.id != self.next_id || self.message.is_some() {
                    return Err(Error::Protocol);
                }
                self.pending_id = Some(message.id);
                self.message = Some(message);
                self.phase = Phase::RequestReady;
                self.request_deadline();
            }
            (Role::Client, Phase::RequestPending, RESPONSE) => {
                let message = frame::parse_message(body)?;
                if self.pending_id != Some(message.id) || self.message.is_some() {
                    return Err(Error::Protocol);
                }
                self.message = Some(message);
                self.phase = Phase::ResponseReady;
            }
            _ => return Err(Error::Protocol),
        }
        Ok(())
    }
    fn process(&mut self) -> Result<(), Error> {
        self.peer_closed = self.tls.process_new_packets()?.peer_has_closed();
        self.tls_completed()?;
        let mut buffer = ZeroizingBytes::<4096>::zeroed();
        loop {
            match self.tls.reader().read(buffer.as_mut_bytes()) {
                Ok(0) => break,
                Ok(read) => {
                    let mut input = buffer.as_bytes().get(..read).ok_or(Error::Protocol)?;
                    while !input.is_empty() {
                        if let Some(body) = self.decoder.push(&mut input)? {
                            self.frame(body)?;
                        }
                    }
                    buffer.clear();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        if self.peer_closed
            && (!self.decoder.is_empty()
                || !matches!(
                    self.phase,
                    Phase::Ready | Phase::ResponseReady | Phase::Closing
                ))
        {
            return Err(Error::Protocol);
        }
        self.flush_plaintext()
    }
}

/// Synchronous bounded TLS/framing engine. Exclusive mutable access serializes
/// state changes; external I/O retains its owner until each call finishes.
pub struct Connection {
    live: Option<Live>,
}

#[cfg(test)]
mod tests;
impl Connection {
    fn new(mut tls: rustls::Connection, lease: Lease, role: Role) -> Result<Self, Error> {
        lease.0.check()?;
        let policy = lease.0.policy.policy_binding()?;
        let deadline = Instant::now() + Duration::from_millis(lease.0.limits.handshake_ms.into());
        tls.set_buffer_limit(Some(frame::MAX_FRAME));
        Ok(Self {
            live: Some(Live {
                tls,
                lease,
                role,
                phase: Phase::Handshaking,
                deadline,
                policy,
                confirmation_context: [0; 96],
                binding: None,
                decoder: Decoder::new(),
                outgoing: None,
                message: None,
                next_id: 1,
                pending_id: None,
                peer_closed: false,
            }),
        })
    }
    fn live(&mut self) -> Result<&mut Live, Error> {
        let checked = self
            .live
            .as_ref()
            .ok_or(Error::Closed)
            .and_then(Live::check);
        if let Err(error) = checked {
            self.close();
            return Err(error);
        }
        self.live.as_mut().ok_or(Error::Closed)
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        let result = result.and_then(|value| {
            self.live()?.check()?;
            Ok(value)
        });
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Admit up to 16 KiB of immutable encrypted input. Returns actual consumed
    /// bytes; adapters retain/reoffer an unconsumed suffix. Wire/TLS errors close
    /// the engine, so a failing call must never be retried on the same session.
    pub fn feed_tls(&mut self, input: &[u8]) -> Result<usize, Error> {
        if input.is_empty() || input.len() > MAX_TLS_IO_BYTES {
            return Err(Error::InvalidLength);
        }
        let result = (|| {
            let live = self.live()?;
            let read = live.tls.read_tls(&mut Cursor::new(input))?;
            live.process()?;
            Ok(read)
        })();
        self.finish(result)
    }
    /// Drain at most 16 KiB of encrypted output; no network I/O occurs. Errors
    /// clear the caller's entire output and terminate this engine.
    pub fn drain_tls(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if output.is_empty() || output.len() > MAX_TLS_IO_BYTES {
            return Err(Error::InvalidLength);
        }
        let result = (|| {
            let live = self.live()?;
            live.flush_plaintext()?;
            let written = live.tls.write_tls(&mut Cursor::new(&mut *output))?;
            live.flush_plaintext()?;
            Ok(written)
        })();
        let result = self.finish(result);
        if result.is_err() {
            output.fill(0);
        }
        result
    }
    /// Signal transport EOF; TLS truncation is an error, never an empty response.
    pub fn end_of_input(&mut self) -> Result<(), Error> {
        let result = (|| {
            let live = self.live()?;
            live.tls.read_tls(&mut std::io::empty())?;
            live.process()
        })();
        self.finish(result)
    }
    /// Snapshot progress and enforce the current absolute deadline/revocation.
    pub fn progress(&mut self) -> Result<Progress, Error> {
        let live = self.live()?;
        if (live.peer_closed && live.phase == Phase::Ready)
            || (live.phase == Phase::Closing && !live.tls.wants_write() && live.outgoing.is_none())
        {
            self.close();
            return Err(Error::Closed);
        }
        Ok(Progress {
            phase: live.phase,
            wants_write: live.tls.wants_write() || live.outgoing.is_some(),
            remaining_ms: u32::try_from(
                live.deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|_| Error::InvalidOptions)?
            .saturating_add(1),
        })
    }
    /// Inspect the pending request/response size without consuming it. This is
    /// only a snapshot; callers must serialize use of the same connection.
    pub fn pending_message_size(&mut self) -> Result<usize, Error> {
        let live = self.live()?;
        if !matches!(live.phase, Phase::RequestReady | Phase::ResponseReady) {
            return Err(Error::NotReady);
        }
        Ok(live.message.as_ref().ok_or(Error::Protocol)?.bytes().len())
    }
    /// Queue TLS close_notify after a completed exchange. Drain all ciphertext
    /// until progress reports Closed. Cancellation instead uses immediate close.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let live = self.live()?;
        if live.phase != Phase::Ready || live.outgoing.is_some() {
            return Err(Error::NotReady);
        }
        live.tls.send_close_notify();
        live.phase = Phase::Closing;
        Ok(())
    }
    /// Whether this engine's resources have been released (not a liveness lease).
    pub fn is_closed(&self) -> bool {
        self.live.is_none()
    }
    /// Queue one client request. No automatic retry occurs, including reconnect.
    pub fn send_request(&mut self, payload: &[u8]) -> Result<u64, Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidLength);
        }
        let live = self.live()?;
        if live.role != Role::Client
            || live.phase != Phase::Ready
            || live.outgoing.is_some()
            || live.peer_closed
        {
            return Err(Error::NotReady);
        }
        let id = live.next_id;
        let next = id.checked_add(1).ok_or(Error::ResourceLimit)?;
        let frame = Outgoing::message(REQUEST, id, payload)?;
        live.outgoing = Some(frame);
        live.next_id = next;
        live.pending_id = Some(id);
        live.phase = Phase::RequestPending;
        live.request_deadline();
        Ok(id)
    }
    /// Take one authenticated server request. The application must respond with
    /// its exact ID; handling is not a durable or exactly-once execution guarantee.
    pub fn take_request(&mut self) -> Result<Message, Error> {
        let live = self.live()?;
        if live.role != Role::Server || live.phase != Phase::RequestReady {
            return Err(Error::NotReady);
        }
        let message = live.message.take().ok_or(Error::Protocol)?;
        live.phase = Phase::HandlingRequest;
        Ok(message)
    }
    /// Queue the response to the single in-flight server request.
    pub fn send_response(&mut self, request_id: u64, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidLength);
        }
        let live = self.live()?;
        if live.role != Role::Server
            || live.phase != Phase::HandlingRequest
            || live.pending_id != Some(request_id)
            || live.outgoing.is_some()
            || live.peer_closed
        {
            return Err(Error::NotReady);
        }
        let next = live.next_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        live.outgoing = Some(Outgoing::message(RESPONSE, request_id, payload)?);
        live.next_id = next;
        live.pending_id = None;
        live.phase = Phase::Ready;
        live.idle();
        Ok(())
    }
    /// Take one matching authenticated response; subsequent use of an old ID is
    /// rejected on the wire. A transport failure never becomes an empty success.
    pub fn take_response(&mut self) -> Result<Message, Error> {
        let live = self.live()?;
        if live.role != Role::Client || live.phase != Phase::ResponseReady {
            return Err(Error::NotReady);
        }
        let message = live.message.take().ok_or(Error::Protocol)?;
        live.pending_id = None;
        live.phase = Phase::Ready;
        live.idle();
        Ok(message)
    }
    /// Erase owned framing/confirmation buffers, release the upstream TLS owner
    /// and return its capacity. External adapters separately cancel socket I/O.
    pub fn close(&mut self) {
        self.live = None;
    }
}
