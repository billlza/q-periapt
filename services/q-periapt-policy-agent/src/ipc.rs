//! Strict authenticated Unix IPC and executable configuration boundary.

use core::fmt;
use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_ffi_abi2::{
    Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_MLKEM768_PK_LEN, Q_PERIAPT_X25519_LEN,
};
use q_periapt_migration::{
    EndpointRole, InitiatorFinishedV1, MigrationAuthorityKeyId, MigrationIdentityKeyId,
    ResponderFinishedV1,
};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::io::Errno;

use crate::activation::{activated_listener, ActivationError};
use crate::authentication::{sign_envelope, verify_envelope, AuthenticationError};
use crate::authority::{
    AuthorityEpochV2, DeploymentConfigRevisionV2, StateFenceV2, StateHeadV2, StateRevisionV2,
};
use crate::authority_codec::HARD_MAX_LEASE_TTL_MILLIS;
use crate::authority_protocol::{
    AuthorityClientIdV2, AuthorityServerIdV2, AuthorityWireIdentityV2,
};
use crate::authority_transport::{AuthenticatedTcpAuthorityV2, InstanceAuthorityPort};
use crate::codec::{
    accept_error_is_transient, encode_domain, hash_fields, read_frame_until, require_domain,
    write_frame_until, CodecError, DeadlineStream, Decoder, Encoder, MAX_FRAME_BYTES,
};
use crate::crypto::{EncapsulationCiphertexts, EncapsulationPublicKeys};
use crate::filesystem::OwnedPrivateDirectory;
use crate::repository::{MigrationTrustRoots, StateRepository};
use crate::service::{
    AgentConfig, AgentError, AgentLimits, BeginDecapsulation, BeginDecapsulationResult,
    BeginEncapsulation, BeginEncapsulationResult, ConfirmedKeyHandle, EndpointIdentity,
    PendingSessionHandle, PolicyAgent, SessionAuthorization, SignedPolicyBundle,
};
use crate::signals::install_termination_handlers;
use crate::witness::{AuthenticatedTcpWitness, ReferenceWitnessServer};

const IPC_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2";
const IPC_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2";
const IPC_REQUEST_DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-DIGEST/v2";
const IPC_SCHEMA_VERSION: u16 = 2;
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(5);
const WITNESS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORITY_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The one end-to-end deadline every connection gets, from accept to the last
/// response byte: the client-paced read (`IPC_IO_TIMEOUT`), the least plan of
/// the largest guarded command -- Begin and Accept need three authority round
/// trips and one witness read, Reconcile two authority round trips and two
/// witness calls, twenty seconds either way at the transport bounds above --
/// the client-paced write (`IPC_IO_TIMEOUT`), and five seconds of slack for
/// one renew retry or one reconciling query. The agent admits each round
/// trip against it and refuses, with status 24, a guarded operation whose
/// least plan no longer fits.
const IPC_REQUEST_DEADLINE: Duration = Duration::from_secs(35);
/// How long the lease release at stop may take. Against an authority that
/// accepts the connection and never answers it is up to six bounded round
/// trips -- the two drains, each stopping at its first unanswered call, the
/// release, two reconciling queries and the snapshot proof -- each admitted
/// only while it can end strictly within what is left of this budget. So
/// the budget must exceed five full bounds for the release and its queries
/// to be reached behind two unanswered drains, and a round trip that no
/// longer fits is refused rather than started: the stop is bounded by this
/// budget whatever the authority does.
const LEASE_RELEASE_BUDGET: Duration = Duration::from_secs(30);
const NONCE_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_RECENT_NONCES: usize = 4096;
const MAX_SIGNED_OFFER_BYTES: usize = 8 * 1024;
const MAX_POLICY_BYTES: usize = q_periapt_ffi_abi2::Q_PERIAPT_MAX_SIGNED_POLICY_BYTES;
/// Name the service manager publishes the listener under. Both deployment
/// templates must use this exact value: systemd `FileDescriptorName=` and the
/// launchd `Sockets` dictionary key.
const IPC_ACTIVATION_NAME: &str = "agent";
/// Margin added to the longest lease TTL the authority can grant, giving how
/// long `serve-agent` waits at startup for a predecessor's lease to lapse. The
/// TTL bounds how long a lease left behind by a killed process outlives it;
/// the margin covers the wait's own pauses and the authority's clock
/// granularity.
const STARTUP_LEASE_WAIT_MARGIN_MILLIS: u64 = 5_000;
/// How long `serve-agent` waits for a predecessor's lease to lapse before it
/// gives up fenced. See `PolicyAgent::new_with_lease_wait`.
const STARTUP_LEASE_WAIT: Duration =
    Duration::from_millis(HARD_MAX_LEASE_TTL_MILLIS + STARTUP_LEASE_WAIT_MARGIN_MILLIS);

/// IPC configuration, authentication, framing, or fatal service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IpcError {
    /// The executable command or protected configuration was invalid.
    InvalidConfiguration,
    /// The service manager did not present a socket-activation listener.
    ActivationMissing,
    /// Socket activation did not supply the expected listener.
    ActivationRejected,
    /// A message was malformed, unknown, oversized, truncated, or had trailing bytes.
    InvalidMessage,
    /// Request authentication or nonce replay protection failed.
    AuthenticationFailed,
    /// A listener or connection operation failed.
    Unavailable,
    /// The agent entered a fail-closed poisoned state.
    AgentFatal,
    /// The serving loop stopped cleanly but the instance lease could not be
    /// released: the transport refused the release, its outcome stayed
    /// unknown, or the agent was poisoned. The lease lapses at the
    /// authority's TTL, which the next start waits out.
    LeaseReleaseFailed,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "IPC configuration invalid",
            Self::ActivationMissing => {
                "IPC socket activation was not provided by the service manager"
            }
            Self::ActivationRejected => {
                "IPC socket activation did not supply the expected listener"
            }
            Self::InvalidMessage => "IPC message invalid",
            Self::AuthenticationFailed => "IPC request authentication failed",
            Self::Unavailable => "IPC transport unavailable",
            Self::AgentFatal => "policy agent entered a fail-closed state",
            Self::LeaseReleaseFailed => {
                "instance lease was not released at stop; it lapses at the authority TTL"
            }
        })
    }
}

impl std::error::Error for IpcError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Command {
    PublicKeys = 1,
    BeginEncapsulation = 2,
    BeginDecapsulation = 3,
    AcceptInitiatorFinished = 4,
    AcceptResponderFinished = 5,
    Cancel = 6,
    DestroyKey = 7,
    Advance = 8,
    Reset = 9,
    Reconcile = 10,
}

impl Command {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublicKeys),
            2 => Some(Self::BeginEncapsulation),
            3 => Some(Self::BeginDecapsulation),
            4 => Some(Self::AcceptInitiatorFinished),
            5 => Some(Self::AcceptResponderFinished),
            6 => Some(Self::Cancel),
            7 => Some(Self::DestroyKey),
            8 => Some(Self::Advance),
            9 => Some(Self::Reset),
            10 => Some(Self::Reconcile),
            _ => None,
        }
    }
}

enum RequestPayload {
    PublicKeys,
    BeginEncapsulation(BeginEncapsulation),
    BeginDecapsulation(BeginDecapsulation),
    AcceptInitiatorFinished(PendingSessionHandle, InitiatorFinishedV1),
    AcceptResponderFinished(PendingSessionHandle, ResponderFinishedV1),
    Cancel(PendingSessionHandle),
    DestroyKey(ConfirmedKeyHandle),
    Advance(Vec<u8>),
    Reset(Vec<u8>),
    Reconcile,
}

struct Request {
    nonce: [u8; 32],
    payload: RequestPayload,
}

impl Request {
    fn decode(body: &[u8]) -> Result<Self, IpcError> {
        let mut decoder = Decoder::new(body);
        require_domain(&mut decoder, IPC_REQUEST_DOMAIN, IPC_SCHEMA_VERSION).map_err(map_codec)?;
        let nonce: [u8; 32] = decoder.array().map_err(map_codec)?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(IpcError::InvalidMessage);
        }
        let command =
            Command::from_u8(decoder.byte().map_err(map_codec)?).ok_or(IpcError::InvalidMessage)?;
        let payload = match command {
            Command::PublicKeys => RequestPayload::PublicKeys,
            Command::BeginEncapsulation => {
                let authorization = decode_authorization(&mut decoder)?;
                let pq = decoder
                    .fixed(Q_PERIAPT_MLKEM768_PK_LEN)
                    .map_err(map_codec)?;
                let traditional = decoder.fixed(Q_PERIAPT_X25519_LEN).map_err(map_codec)?;
                let peer = EncapsulationPublicKeys::from_slices(pq, traditional)
                    .map_err(|_| IpcError::InvalidMessage)?;
                RequestPayload::BeginEncapsulation(BeginEncapsulation::new(authorization, peer))
            }
            Command::BeginDecapsulation => {
                let authorization = decode_authorization(&mut decoder)?;
                let pq = decoder
                    .fixed(Q_PERIAPT_MLKEM768_CT_LEN)
                    .map_err(map_codec)?;
                let traditional = decoder.fixed(Q_PERIAPT_X25519_LEN).map_err(map_codec)?;
                let ciphertexts = EncapsulationCiphertexts::from_slices(pq, traditional)
                    .map_err(|_| IpcError::InvalidMessage)?;
                RequestPayload::BeginDecapsulation(BeginDecapsulation::new(
                    authorization,
                    ciphertexts,
                ))
            }
            Command::AcceptInitiatorFinished => RequestPayload::AcceptInitiatorFinished(
                PendingSessionHandle::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| IpcError::InvalidMessage)?,
                InitiatorFinishedV1::from_bytes(decoder.array().map_err(map_codec)?),
            ),
            Command::AcceptResponderFinished => RequestPayload::AcceptResponderFinished(
                PendingSessionHandle::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| IpcError::InvalidMessage)?,
                ResponderFinishedV1::from_bytes(decoder.array().map_err(map_codec)?),
            ),
            Command::Cancel => RequestPayload::Cancel(
                PendingSessionHandle::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| IpcError::InvalidMessage)?,
            ),
            Command::DestroyKey => RequestPayload::DestroyKey(
                ConfirmedKeyHandle::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| IpcError::InvalidMessage)?,
            ),
            Command::Advance => {
                RequestPayload::Advance(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?.to_vec())
            }
            Command::Reset => {
                RequestPayload::Reset(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?.to_vec())
            }
            Command::Reconcile => RequestPayload::Reconcile,
        };
        decoder.finish().map_err(map_codec)?;
        Ok(Self { nonce, payload })
    }
}

enum ResponsePayload {
    Empty,
    PublicKeys(EncapsulationPublicKeys),
    InitiatorEncapsulation {
        handle: PendingSessionHandle,
        ciphertexts: EncapsulationCiphertexts,
        initiator_finished: InitiatorFinishedV1,
    },
    ResponderEncapsulation {
        handle: PendingSessionHandle,
        ciphertexts: EncapsulationCiphertexts,
    },
    InitiatorDecapsulation {
        handle: PendingSessionHandle,
        initiator_finished: InitiatorFinishedV1,
    },
    ResponderDecapsulation {
        handle: PendingSessionHandle,
    },
    InitiatorAccepted(ConfirmedKeyHandle),
    ResponderAccepted {
        key_handle: ConfirmedKeyHandle,
        responder_finished: ResponderFinishedV1,
    },
}

struct RecentNonces {
    ordered: VecDeque<([u8; 32], Instant)>,
    values: HashSet<[u8; 32]>,
}

impl RecentNonces {
    fn new() -> Self {
        Self {
            ordered: VecDeque::new(),
            values: HashSet::new(),
        }
    }

    fn insert(&mut self, nonce: [u8; 32]) -> Result<(), IpcError> {
        let now = Instant::now();
        while matches!(self.ordered.front(), Some((_, seen)) if now.duration_since(*seen) >= NONCE_WINDOW)
        {
            if let Some((expired, _)) = self.ordered.pop_front() {
                self.values.remove(&expired);
            }
        }
        if self.values.contains(&nonce) || self.values.len() >= MAX_RECENT_NONCES {
            return Err(IpcError::AuthenticationFailed);
        }
        self.values.insert(nonce);
        self.ordered.push_back((nonce, now));
        Ok(())
    }
}

/// Sequential, deadline-bounded authenticated Unix server.
///
/// Sequential handling deliberately caps active clients at one. One
/// end-to-end deadline per connection (`IPC_REQUEST_DEADLINE`) covers the
/// read, the execution and the write. The two client-paced phases are
/// additionally capped at `io_timeout` each, from which every framed read and
/// write derives its remaining budget, so a client trickling one byte per
/// interval cannot occupy the slot. Execution admits each authority and
/// witness round trip only when it can end before the deadline, and refuses a
/// lease-guarded operation whose least plan does not fit before it dispatches
/// anything. A response that cannot be written by the deadline is not
/// written: the connection closes with nothing sent, which the client sees as
/// a lost response and recovers by exact retry. No unbounded worker or thread
/// creation is possible.
pub(crate) struct UnixIpcServer<W: crate::witness::WitnessPort, A: InstanceAuthorityPort> {
    agent: PolicyAgent<W, A>,
    client_verification_key: [u8; ML_DSA_65_VK_LEN],
    server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    io_timeout: Duration,
    recent_nonces: RecentNonces,
}

impl<W: crate::witness::WitnessPort, A: InstanceAuthorityPort> fmt::Debug for UnixIpcServer<W, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnixIpcServer([redacted])")
    }
}

/// Domain-separated probe used only to prove, at startup, that the two
/// directions of this protocol are carried by different key pairs.
const IPC_DIRECTION_ISOLATION_PROBE: &[u8] = b"Q-PERIAPT-IPC-DIRECTION-PROBE/v1";

/// How often the serving loop runs maintenance. This is the granularity of the
/// session TTL, not a poll interval in the busy-wait sense: the wait is a real
/// blocking `poll`, so a connection is still accepted the moment it arrives.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

/// The same interval as the `poll` timeout. `maintenance_interval_agrees_with_
/// the_poll_timeout` pins the two together.
const MAINTENANCE_TIMEOUT: Timespec = Timespec {
    tv_sec: 1,
    tv_nsec: 0,
};

/// Wait for a connection to accept, or for the maintenance interval to elapse.
///
/// `false` means nothing is waiting. A signal that interrupts the wait reports
/// the same thing, which keeps a routine `EINTR` from being mistaken for a dead
/// listener; the caller loops and waits again.
fn wait_for_connection(listener: &UnixListener) -> Result<bool, IpcError> {
    let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
    match poll(&mut descriptors, Some(&MAINTENANCE_TIMEOUT)) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(Errno::INTR) => Ok(false),
        Err(_) => Err(IpcError::Unavailable),
    }
}

/// Reject a configuration whose request and response directions share one key
/// pair, and prove the server signing key can actually produce a signature.
///
/// Requests are verified under `client_verification_key`; responses are signed
/// under `server_signing_key`. If those are one key pair, any client authorized
/// to send requests could also forge responses. The signing step additionally
/// surfaces an unusable server key at startup rather than after a state change
/// has already been committed and only the response can no longer be produced.
fn validate_ipc_direction_isolation(
    client_verification_key: &[u8],
    server_signing_key: &[u8],
    server_verification_key: &[u8],
) -> Result<(), IpcError> {
    if server_signing_key.iter().all(|byte| *byte == 0)
        || server_verification_key.iter().all(|byte| *byte == 0)
    {
        return Err(IpcError::InvalidConfiguration);
    }
    let probe = sign_envelope(IPC_DIRECTION_ISOLATION_PROBE, server_signing_key)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    // The response key pair has to be a pair. Signing proves only that the key
    // is well-formed; without this, a deployment that installs a valid but wrong
    // signing key starts cleanly, commits state, and only then produces
    // responses every client rejects -- the exact outcome startup validation
    // exists to prevent. This proves a signature this daemon produces verifies
    // under the key its clients were told to pin. It cannot prove the clients
    // actually pinned that key, which is established out of band.
    if verify_envelope(&probe, server_verification_key).is_err() {
        return Err(IpcError::InvalidConfiguration);
    }
    // And the two directions must remain distinct pairs.
    if verify_envelope(&probe, client_verification_key).is_ok() {
        return Err(IpcError::InvalidConfiguration);
    }
    Ok(())
}

impl<W: crate::witness::WitnessPort, A: InstanceAuthorityPort> UnixIpcServer<W, A> {
    /// Configure pinned request/response keys. The listener is supplied
    /// separately by the service manager; this server never creates one.
    fn new(
        agent: PolicyAgent<W, A>,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        server_verification_key: [u8; ML_DSA_65_VK_LEN],
        io_timeout: Duration,
    ) -> Result<Self, IpcError> {
        if client_verification_key.iter().all(|byte| *byte == 0) || io_timeout.is_zero() {
            return Err(IpcError::InvalidConfiguration);
        }
        validate_ipc_direction_isolation(
            &client_verification_key,
            server_signing_key.as_bytes(),
            &server_verification_key,
        )?;
        Ok(Self {
            agent,
            client_verification_key,
            server_signing_key,
            io_timeout,
            recent_nonces: RecentNonces::new(),
        })
    }

    /// Serve one request per accepted connection with bounded sequential
    /// resources, until `shutdown` is set.
    ///
    /// `serve_agent` points `shutdown` at the flag the termination handlers
    /// set, so in production the service manager's stop is what sets it; a
    /// test sets it directly. It is read once per accept wait, so a shutdown is
    /// observed within one maintenance interval, and sooner when the signal
    /// interrupts the wait itself (`wait_for_connection` reports that `EINTR`
    /// as an idle pass). Returning is the whole response: the caller releases
    /// the lease and lets every store close through its destructor.
    fn serve(&mut self, listener: UnixListener, shutdown: &AtomicBool) -> Result<(), IpcError> {
        // Wait in `poll` rather than in `accept`, for two reasons. A daemon
        // nobody is talking to still has to run its session TTL sweep, and only
        // a bounded wait gives it the chance. And a blocking `accept` can still
        // block after a readiness report, if the queued peer resets in between;
        // on this single-threaded loop that stalls the daemon until some other
        // client happens to connect. A non-blocking listener turns that case
        // into a `WouldBlock` the loop can simply retry.
        listener
            .set_nonblocking(true)
            .map_err(|_| IpcError::Unavailable)?;
        let mut swept = Instant::now();
        while !shutdown.load(Ordering::Acquire) {
            let waiting = wait_for_connection(&listener)?;
            // Maintenance runs on a schedule, not on idleness. Tying it to a
            // timed-out wait meant any client that keeps the listener readable
            // -- a loop of cheap requests, or a loop of connections that fail
            // authentication -- starved the session sweep indefinitely, and a
            // busy daemon is precisely the one holding the most expired key
            // material. The sweep is cheap and takes the same lock the request
            // path already takes, so running it between connections costs a
            // bounded scan of at most `max_pending_sessions` entries.
            if swept.elapsed() >= MAINTENANCE_INTERVAL {
                self.agent.expire_idle_sessions();
                swept = Instant::now();
            }
            if !waiting {
                continue;
            }
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                // Reported readable, but the connection is already gone. `poll`
                // did the waiting, so go straight back to it without a pause.
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                // A transient accept failure (descriptor pressure, a signal, a
                // peer that reset before we got here) must not end the daemon;
                // only a listener that is genuinely unusable is fatal. Resource
                // exhaustion returns immediately, and retrying without pause
                // would spin at full CPU until the condition clears and worsen
                // an already degraded host. Back off the same 5ms the TCP loops
                // use.
                Err(error) if accept_error_is_transient(&error) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => return Err(IpcError::Unavailable),
            };
            // An accepted socket inherits the listener's non-blocking mode on
            // the BSDs but not on Linux. Set it explicitly so the request
            // handler's deadline reads block identically on both. A failure here
            // belongs to this one connection, exactly like a malformed request
            // below, and must not tear down the listener for everyone else --
            // the witness and authority loops already skip on the same failure.
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            match self.handle(&mut stream) {
                Ok(())
                | Err(IpcError::InvalidMessage)
                | Err(IpcError::AuthenticationFailed)
                | Err(IpcError::Unavailable) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn handle(&mut self, stream: &mut UnixStream) -> Result<(), IpcError> {
        let (read_deadline, request_deadline) = self.deadlines_from(Instant::now())?;
        self.handle_io(stream, read_deadline, request_deadline)
    }

    /// The two deadlines of a connection accepted at `accepted`: the request
    /// deadline, `IPC_REQUEST_DEADLINE` from the accept, and the read
    /// deadline, one `io_timeout` from the accept and never past the former.
    fn deadlines_from(&self, accepted: Instant) -> Result<(Instant, Instant), IpcError> {
        let request_deadline = accepted
            .checked_add(IPC_REQUEST_DEADLINE)
            .ok_or(IpcError::Unavailable)?;
        let read_deadline = accepted
            .checked_add(self.io_timeout)
            .ok_or(IpcError::Unavailable)?
            .min(request_deadline);
        Ok((read_deadline, request_deadline))
    }

    fn handle_io<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
        read_deadline: Instant,
        request_deadline: Instant,
    ) -> Result<(), IpcError> {
        let envelope = read_frame_until(stream, read_deadline).map_err(map_codec)?;
        let request_body = verify_envelope(&envelope, &self.client_verification_key)
            .map_err(map_authentication)?;
        let request = Request::decode(request_body)?;
        self.recent_nonces.insert(request.nonce)?;
        let request_digest =
            hash_fields(IPC_REQUEST_DIGEST_DOMAIN, &[request_body]).map_err(map_codec)?;
        let result = self.execute(request.payload, request_deadline);
        if matches!(result, Err(AgentError::InternalPoisoned)) {
            return Err(IpcError::AgentFatal);
        }
        let (status, payload) = match result {
            Ok(payload) => (0u8, payload),
            Err(error) => (agent_status(error), ResponsePayload::Empty),
        };
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut encoder, IPC_RESPONSE_DOMAIN, IPC_SCHEMA_VERSION).map_err(map_codec)?;
        encoder.fixed(&request.nonce).map_err(map_codec)?;
        encoder.fixed(&request_digest).map_err(map_codec)?;
        encoder.byte(status).map_err(map_codec)?;
        encode_response_payload(&mut encoder, payload)?;
        let response = sign_envelope(&encoder.finish(), self.server_signing_key.as_bytes())
            .map_err(map_authentication)?;
        // The write gets what is left of the request deadline, capped at one
        // I/O timeout because the client paces this phase too. A request
        // deadline already reached fails `write_frame_until` on its budget
        // before the first byte, so the connection closes with nothing
        // written: a committed operation whose response missed the deadline
        // is reported as a lost response -- which the client recovers by
        // exact retry under a fresh nonce -- rather than answered on a budget
        // the caller never granted.
        let write_deadline = Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(IpcError::Unavailable)?
            .min(request_deadline);
        write_frame_until(stream, &response, write_deadline).map_err(|_| IpcError::Unavailable)
    }

    /// Run the serving loop, then hand the instance lease back.
    ///
    /// This is what `serve_agent` runs. The release is attempted on every
    /// exit, the orderly stop and a fatal listener error alike, and it is what
    /// lets the next process acquire at once instead of waiting out the lease
    /// TTL; it also erases every in-process secret first. A serving failure
    /// keeps precedence: it is what caused the exit and what this returns,
    /// whatever the release did. An orderly stop returns the release's
    /// outcome: `Ok` only once the authority has confirmed the release or a
    /// snapshot has proved the lease gone, and
    /// [`IpcError::LeaseReleaseFailed`] otherwise -- the authority
    /// unreachable, the outcome unknown, or the agent poisoned, which refuses
    /// the release outright (`release_instance_lease` checks liveness first).
    /// In that case the lease lapses at its TTL exactly as it would after a
    /// crash, and the process exits 1 with that one-line reason rather than
    /// report a stop that left the lease held as clean. The release runs
    /// under `LEASE_RELEASE_BUDGET`, so a stop is bounded whatever the
    /// authority does.
    fn serve_and_release(
        &mut self,
        listener: UnixListener,
        shutdown: &AtomicBool,
    ) -> Result<(), IpcError> {
        let outcome = self.serve(listener, shutdown);
        let released = Instant::now()
            .checked_add(LEASE_RELEASE_BUDGET)
            .ok_or(AgentError::InvalidConfiguration)
            .and_then(|deadline| self.agent.release_instance_lease_until(deadline));
        match (outcome, released) {
            (Err(error), _) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(_)) => Err(IpcError::LeaseReleaseFailed),
        }
    }

    /// Run the serving loop against a caller-supplied listener.
    ///
    /// The module is already `cfg(unix)`, so `cfg(test)` is enough here.
    #[cfg(test)]
    pub(crate) fn serve_for_test(
        &mut self,
        listener: UnixListener,
        shutdown: &AtomicBool,
    ) -> Result<(), IpcError> {
        self.serve(listener, shutdown)
    }

    /// Run the serving loop and the release that follows it, exactly as
    /// `serve_agent` does.
    #[cfg(test)]
    pub(crate) fn serve_and_release_for_test(
        &mut self,
        listener: UnixListener,
        shutdown: &AtomicBool,
    ) -> Result<(), IpcError> {
        self.serve_and_release(listener, shutdown)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        agent: PolicyAgent<W, A>,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        server_verification_key: [u8; ML_DSA_65_VK_LEN],
    ) -> Result<Self, IpcError> {
        if client_verification_key.iter().all(|byte| *byte == 0) {
            return Err(IpcError::InvalidConfiguration);
        }
        validate_ipc_direction_isolation(
            &client_verification_key,
            server_signing_key.as_bytes(),
            &server_verification_key,
        )?;
        Ok(Self {
            agent,
            client_verification_key,
            server_signing_key,
            io_timeout: IPC_IO_TIMEOUT,
            recent_nonces: RecentNonces::new(),
        })
    }

    /// Serve one request with both deadlines derived exactly as `handle`
    /// derives them from the accept.
    #[cfg(test)]
    pub(crate) fn handle_io_for_test<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
    ) -> Result<(), IpcError> {
        let (read_deadline, request_deadline) = self.deadlines_from(Instant::now())?;
        self.handle_io(stream, read_deadline, request_deadline)
    }

    /// Serve one request with `deadline` as both the read deadline and the
    /// request deadline.
    #[cfg(test)]
    pub(crate) fn handle_io_with_deadline_for_test<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
        deadline: Instant,
    ) -> Result<(), IpcError> {
        self.handle_io(stream, deadline, deadline)
    }

    /// Serve one request with the read deadline and the request deadline
    /// given separately.
    #[cfg(test)]
    pub(crate) fn handle_io_with_deadlines_for_test<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
        read_deadline: Instant,
        request_deadline: Instant,
    ) -> Result<(), IpcError> {
        self.handle_io(stream, read_deadline, request_deadline)
    }

    #[cfg(test)]
    pub(crate) const fn agent_for_test(&self) -> &PolicyAgent<W, A> {
        &self.agent
    }

    /// Run one decoded request under the connection's `deadline`. The
    /// commands that make no port call take the agent's default budget.
    fn execute(
        &self,
        payload: RequestPayload,
        deadline: Instant,
    ) -> Result<ResponsePayload, AgentError> {
        match payload {
            RequestPayload::PublicKeys => self.agent.public_keys().map(ResponsePayload::PublicKeys),
            RequestPayload::BeginEncapsulation(request) => {
                let result = self.agent.begin_encapsulation_until(request, deadline)?;
                Ok(match result {
                    BeginEncapsulationResult::Initiator(result) => {
                        ResponsePayload::InitiatorEncapsulation {
                            handle: result.handle,
                            ciphertexts: result.ciphertexts,
                            initiator_finished: result.initiator_finished,
                        }
                    }
                    BeginEncapsulationResult::Responder(result) => {
                        ResponsePayload::ResponderEncapsulation {
                            handle: result.handle,
                            ciphertexts: result.ciphertexts,
                        }
                    }
                })
            }
            RequestPayload::BeginDecapsulation(request) => {
                let result = self.agent.begin_decapsulation_until(request, deadline)?;
                Ok(match result {
                    BeginDecapsulationResult::Initiator(result) => {
                        ResponsePayload::InitiatorDecapsulation {
                            handle: result.handle,
                            initiator_finished: result.initiator_finished,
                        }
                    }
                    BeginDecapsulationResult::Responder(result) => {
                        ResponsePayload::ResponderDecapsulation {
                            handle: result.handle,
                        }
                    }
                })
            }
            RequestPayload::AcceptInitiatorFinished(handle, finished) => self
                .agent
                .accept_initiator_finished_until(handle, finished, deadline)
                .map(|result| ResponsePayload::ResponderAccepted {
                    key_handle: result.key_handle,
                    responder_finished: result.responder_finished,
                }),
            RequestPayload::AcceptResponderFinished(handle, finished) => self
                .agent
                .accept_responder_finished_until(handle, finished, deadline)
                .map(ResponsePayload::InitiatorAccepted),
            RequestPayload::Cancel(handle) => {
                self.agent.cancel(handle)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::DestroyKey(handle) => {
                self.agent.destroy_key(handle)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::Advance(certificate) => {
                self.agent.apply_advance_until(&certificate, deadline)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::Reset(certificate) => {
                self.agent.apply_reset_until(&certificate, deadline)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::Reconcile => {
                self.agent.reconcile_transition_until(deadline)?;
                Ok(ResponsePayload::Empty)
            }
        }
    }
}

fn decode_authorization(decoder: &mut Decoder<'_>) -> Result<SessionAuthorization, IpcError> {
    let local = decoder
        .lp16(MAX_SIGNED_OFFER_BYTES)
        .map_err(map_codec)?
        .to_vec();
    let peer = decoder
        .lp16(MAX_SIGNED_OFFER_BYTES)
        .map_err(map_codec)?
        .to_vec();
    SessionAuthorization::new(local, peer).map_err(|_| IpcError::InvalidMessage)
}

fn encode_response_payload(
    encoder: &mut Encoder,
    payload: ResponsePayload,
) -> Result<(), IpcError> {
    match payload {
        ResponsePayload::Empty => encoder.byte(0).map_err(map_codec),
        ResponsePayload::PublicKeys(keys) => {
            encoder.byte(1).map_err(map_codec)?;
            encoder.fixed(keys.pq()).map_err(map_codec)?;
            encoder.fixed(keys.traditional()).map_err(map_codec)
        }
        ResponsePayload::InitiatorEncapsulation {
            handle,
            ciphertexts,
            initiator_finished,
        } => {
            encoder.byte(2).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)?;
            encoder.fixed(ciphertexts.pq()).map_err(map_codec)?;
            encoder
                .fixed(ciphertexts.traditional())
                .map_err(map_codec)?;
            encoder
                .fixed(initiator_finished.as_bytes())
                .map_err(map_codec)
        }
        ResponsePayload::ResponderEncapsulation {
            handle,
            ciphertexts,
        } => {
            encoder.byte(3).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)?;
            encoder.fixed(ciphertexts.pq()).map_err(map_codec)?;
            encoder.fixed(ciphertexts.traditional()).map_err(map_codec)
        }
        ResponsePayload::InitiatorDecapsulation {
            handle,
            initiator_finished,
        } => {
            encoder.byte(4).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)?;
            encoder
                .fixed(initiator_finished.as_bytes())
                .map_err(map_codec)
        }
        ResponsePayload::ResponderDecapsulation { handle } => {
            encoder.byte(5).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)
        }
        ResponsePayload::InitiatorAccepted(handle) => {
            encoder.byte(6).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)
        }
        ResponsePayload::ResponderAccepted {
            key_handle,
            responder_finished,
        } => {
            encoder.byte(7).map_err(map_codec)?;
            encoder.fixed(key_handle.as_bytes()).map_err(map_codec)?;
            encoder
                .fixed(responder_finished.as_bytes())
                .map_err(map_codec)
        }
    }
}

fn agent_status(error: AgentError) -> u8 {
    match error {
        AgentError::InvalidConfiguration => 1,
        AgentError::Repository(_) => 2,
        AgentError::Witness(_) => 3,
        AgentError::RollbackOrFork => 4,
        AgentError::TransitionIndeterminate => 5,
        AgentError::TransitionPending => 6,
        AgentError::AuthorizationRejected => 7,
        AgentError::PublicInputRejected => 8,
        AgentError::CapacityExceeded => 9,
        AgentError::SessionExpired => 10,
        AgentError::UnknownHandle => 11,
        AgentError::StaleSession => 12,
        AgentError::UnexpectedFlight => 13,
        AgentError::ConflictingAcceptanceReplay => 14,
        AgentError::FinishedRejected => 15,
        AgentError::LocalResourceFailure => 16,
        AgentError::LocalCryptoFailure => 17,
        AgentError::ExecutionUnavailable => 18,
        AgentError::InstanceFenced => 20,
        AgentError::InstanceLeaseUnavailable => 21,
        AgentError::InstanceLeaseIndeterminate => 22,
        AgentError::InstanceLeaseCoverageElapsed => 23,
        AgentError::OperationDeadlineExceeded => 24,
        AgentError::InternalPoisoned => 19,
    }
}

/// Run the Unix executable from one of two exact command shapes:
///
/// `serve-agent SOCKET_PATH REPOSITORY WITNESS_ADDRESS AUTHORITY_ADDRESS CONFIG_DIRECTORY`
/// `serve-witness LISTEN_ADDRESS WITNESS_DATABASE CONFIG_DIRECTORY`
///
/// `SOCKET_PATH` is not a path this process binds. The service manager creates
/// the listening socket and passes it in; the argument states which path that
/// inherited listener must already be bound to, and startup fails if it is bound
/// somewhere else or if no activation was presented at all. There is no
/// self-bind fallback, so a socket whose owner, group and mode nobody
/// configured cannot come into existence by starting the daemon by hand.
///
/// This entry point is for the dedicated executable process: it claims the
/// activation once per process and a second call fails.
pub fn run_from_arguments<I>(arguments: I) -> Result<(), IpcError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next().ok_or(IpcError::InvalidConfiguration)?;
    let mode = arguments.next().ok_or(IpcError::InvalidConfiguration)?;
    if mode == "serve-agent" {
        let socket_path = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        let repository = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        let witness_address =
            parse_socket_address(arguments.next().ok_or(IpcError::InvalidConfiguration)?)?;
        let authority_address =
            parse_socket_address(arguments.next().ok_or(IpcError::InvalidConfiguration)?)?;
        let configuration = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        if arguments.next().is_some() {
            return Err(IpcError::InvalidConfiguration);
        }
        return serve_agent(
            &socket_path,
            &repository,
            witness_address,
            authority_address,
            &configuration,
        );
    }
    if mode == "serve-witness" {
        let listen = parse_socket_address(arguments.next().ok_or(IpcError::InvalidConfiguration)?)?;
        let database = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        let configuration = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        if arguments.next().is_some() {
            return Err(IpcError::InvalidConfiguration);
        }
        return serve_witness(listen, &database, &configuration);
    }
    Err(IpcError::InvalidConfiguration)
}

fn serve_agent(
    socket_path: &Path,
    repository_path: &Path,
    witness_address: SocketAddr,
    authority_address: SocketAddr,
    configuration: &Path,
) -> Result<(), IpcError> {
    // Claim the service-manager listener first. The daemon never binds, so a
    // deployment that started this process without activation is refused here,
    // before any key material is read, rather than silently serving a socket
    // with properties nobody configured.
    let listener =
        activated_listener(IPC_ACTIVATION_NAME, socket_path).map_err(|error| match error {
            ActivationError::NotActivated => IpcError::ActivationMissing,
            _ => IpcError::ActivationRejected,
        })?;
    let configuration =
        OwnedPrivateDirectory::open(configuration).map_err(|_| IpcError::InvalidConfiguration)?;
    let roots = load_migration_roots(&configuration)?;
    let repository = StateRepository::open_existing(repository_path, roots)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    let witness = AuthenticatedTcpWitness::new(
        witness_address,
        read_secret(&configuration, "witness-client-sk.bin")?,
        read_array(&configuration, "witness-server-vk.bin")?,
        WITNESS_IO_TIMEOUT,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let authority = AuthenticatedTcpAuthorityV2::new(
        authority_address,
        load_authority_identity(&configuration)?,
        read_secret(&configuration, "authority-client-sk.bin")?,
        read_array(&configuration, "authority-server-vk.bin")?,
        AUTHORITY_IO_TIMEOUT,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let config = load_agent_config(&configuration)?;
    // A predecessor that was killed rather than stopped never released its
    // lease, and the authority lets that lease lapse only at the TTL it
    // granted. Wait that out rather than failing: with `Restart=no` a failure
    // here leaves the service down until an operator restarts it, when the
    // whole point of socket activation is that the next connection brings it
    // back. The bound is the longest lease the authority can grant plus a
    // margin, so a holder that is genuinely alive -- which keeps renewing --
    // still fences this process, exactly as a fail-fast start would.
    let agent = PolicyAgent::new_with_lease_wait(
        repository,
        witness,
        authority,
        config,
        STARTUP_LEASE_WAIT,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let mut server = UnixIpcServer::new(
        agent,
        read_array(&configuration, "ipc-client-vk.bin")?,
        read_secret(&configuration, "ipc-server-sk.bin")?,
        read_array(&configuration, "ipc-server-vk.bin")?,
        IPC_IO_TIMEOUT,
    )?;
    // Only now is there something to release, so only now are the handlers
    // installed. A stop that arrives earlier -- during the lease wait above in
    // particular, which can last minutes -- keeps the default disposition and
    // ends the process at once, holding no lease. Latching it instead would
    // have the daemon sit out the whole wait and only then exit, which is
    // longer than the service manager's stop timeout. One that lands between
    // the acquire above and this install ends the process holding the lease
    // with no release, and the next start waits that lease out. From here on
    // the orderly stop and a fatal listener error alike attempt the release;
    // one the authority does not confirm -- a poisoned agent refuses it
    // outright -- leaves the lease to lapse at its TTL instead, and an
    // orderly stop reports that by exiting 1. A stop that lands during a
    // request is observed once that request is answered or refused, within
    // `IPC_REQUEST_DEADLINE`, and the release then runs under
    // `LEASE_RELEASE_BUDGET`; the service managers' stop timeouts cover both.
    let shutdown = install_termination_handlers().map_err(|_| IpcError::Unavailable)?;
    server.serve_and_release(listener, shutdown)
}

fn serve_witness(
    listen: SocketAddr,
    database: &Path,
    configuration: &Path,
) -> Result<(), IpcError> {
    let configuration =
        OwnedPrivateDirectory::open(configuration).map_err(|_| IpcError::InvalidConfiguration)?;
    let server = ReferenceWitnessServer::open(
        database,
        read_array(&configuration, "witness-client-vk.bin")?,
        read_secret(&configuration, "witness-server-sk.bin")?,
        read_array(&configuration, "witness-server-vk.bin")?,
        WITNESS_IO_TIMEOUT,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let listener = TcpListener::bind(listen).map_err(|_| IpcError::Unavailable)?;
    // The witness holds no lease. Observing the stop is what lets its store
    // close through its destructor instead of being cut off and recovered at
    // the next open.
    let shutdown = install_termination_handlers().map_err(|_| IpcError::Unavailable)?;
    server
        .serve(listener, shutdown)
        .map_err(|_| IpcError::Unavailable)
}

fn load_migration_roots(
    configuration: &OwnedPrivateDirectory,
) -> Result<MigrationTrustRoots, IpcError> {
    MigrationTrustRoots::new(
        MigrationAuthorityKeyId::from_bytes(read_array(
            configuration,
            "migration-authority-id.bin",
        )?),
        read_array(configuration, "migration-authority-vk.bin")?,
        MigrationAuthorityKeyId::from_bytes(read_array(
            configuration,
            "recovery-authority-id.bin",
        )?),
        read_array(configuration, "recovery-authority-vk.bin")?,
    )
    .map_err(|_| IpcError::InvalidConfiguration)
}

/// Load the exact pinned Authority Wire V2 endpoint identity.
///
/// The state head and configuration are pinned deployment facts read from the
/// protected configuration directory, exactly like the pinned keys: the client
/// accepts only an authority whose provisioned head/config equal these bytes.
fn load_authority_identity(
    configuration: &OwnedPrivateDirectory,
) -> Result<AuthorityWireIdentityV2, IpcError> {
    let head = read_array::<112>(configuration, "authority-state-head.bin")?;
    let mut global_generation = [0u8; 8];
    global_generation.copy_from_slice(&head[0..8]);
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&head[8..40]);
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&head[40..48]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&head[48..80]);
    let mut fence = [0u8; 32];
    fence.copy_from_slice(&head[80..112]);
    let revision = StateRevisionV2::new(
        u64::from_be_bytes(global_generation),
        chain_id,
        u64::from_be_bytes(epoch),
        digest,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let state_head = StateHeadV2::new(
        revision,
        StateFenceV2::from_bytes(fence).map_err(|_| IpcError::InvalidConfiguration)?,
    );
    let config = read_array::<40>(configuration, "authority-config.bin")?;
    let mut config_generation = [0u8; 8];
    config_generation.copy_from_slice(&config[0..8]);
    let mut config_digest = [0u8; 32];
    config_digest.copy_from_slice(&config[8..40]);
    let config =
        DeploymentConfigRevisionV2::new(u64::from_be_bytes(config_generation), config_digest)
            .map_err(|_| IpcError::InvalidConfiguration)?;
    AuthorityWireIdentityV2::new(
        AuthorityClientIdV2::from_bytes(read_array(configuration, "authority-client-id.bin")?)
            .map_err(|_| IpcError::InvalidConfiguration)?,
        AuthorityServerIdV2::from_bytes(read_array(configuration, "authority-server-id.bin")?)
            .map_err(|_| IpcError::InvalidConfiguration)?,
        AuthorityEpochV2::from_bytes(read_array(configuration, "authority-epoch.bin")?)
            .map_err(|_| IpcError::InvalidConfiguration)?,
        state_head,
        config,
    )
    .map_err(|_| IpcError::InvalidConfiguration)
}

fn load_agent_config(configuration: &OwnedPrivateDirectory) -> Result<AgentConfig, IpcError> {
    let role = match read_array::<1>(configuration, "local-role.bin")? {
        [1] => EndpointRole::Initiator,
        [2] => EndpointRole::Responder,
        _ => return Err(IpcError::InvalidConfiguration),
    };
    let local_identity = EndpointIdentity::new(
        MigrationIdentityKeyId::from_bytes(read_array(configuration, "local-identity-id.bin")?),
        read_array(configuration, "local-identity-vk.bin")?,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let peer_identity = EndpointIdentity::new(
        MigrationIdentityKeyId::from_bytes(read_array(configuration, "peer-identity-id.bin")?),
        read_array(configuration, "peer-identity-vk.bin")?,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    AgentConfig::new(
        AgentLimits::new(256, 256, Duration::from_secs(5 * 60))
            .map_err(|_| IpcError::InvalidConfiguration)?,
        role,
        local_identity,
        peer_identity,
        read_policy_bundle(configuration, "execution")?,
        read_policy_bundle(configuration, "local-endpoint")?,
        read_policy_bundle(configuration, "peer-endpoint")?,
    )
    .map_err(|_| IpcError::InvalidConfiguration)
}

fn read_policy_bundle(
    configuration: &OwnedPrivateDirectory,
    prefix: &str,
) -> Result<SignedPolicyBundle, IpcError> {
    let document = read_bounded(
        configuration,
        &format!("{prefix}-policy.toml"),
        MAX_POLICY_BYTES,
    )?;
    let signature = read_bounded(
        configuration,
        &format!("{prefix}-policy.sig"),
        ML_DSA_65_SIG_LEN,
    )?;
    SignedPolicyBundle::new(
        document,
        signature,
        read_array(configuration, &format!("{prefix}-policy-vk.bin"))?,
    )
    .map_err(|_| IpcError::InvalidConfiguration)
}

fn read_array<const N: usize>(
    directory: &OwnedPrivateDirectory,
    name: &str,
) -> Result<[u8; N], IpcError> {
    let mut file = open_private_config(directory, name, N)?;
    let mut value = [0u8; N];
    file.read_exact(&mut value)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    ensure_eof(&mut file)?;
    Ok(value)
}

fn read_secret<const N: usize>(
    directory: &OwnedPrivateDirectory,
    name: &str,
) -> Result<ZeroizingBytes<N>, IpcError> {
    let mut file = open_private_config(directory, name, N)?;
    let mut value = ZeroizingBytes::<N>::zeroed();
    file.read_exact(value.as_mut_bytes())
        .map_err(|_| IpcError::InvalidConfiguration)?;
    ensure_eof(&mut file)?;
    Ok(value)
}

fn read_bounded(
    directory: &OwnedPrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, IpcError> {
    let file = open_private_config(directory, name, maximum)?;
    let limit = u64::try_from(maximum)
        .map_err(|_| IpcError::InvalidConfiguration)?
        .checked_add(1)
        .ok_or(IpcError::InvalidConfiguration)?;
    let mut value = Vec::new();
    file.take(limit)
        .read_to_end(&mut value)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    if value.is_empty() || value.len() > maximum {
        return Err(IpcError::InvalidConfiguration);
    }
    Ok(value)
}

fn open_private_config(
    directory: &OwnedPrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<File, IpcError> {
    directory
        .open_config_file(name, maximum)
        .map_err(|_| IpcError::InvalidConfiguration)
}

fn ensure_eof(file: &mut File) -> Result<(), IpcError> {
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(()),
        _ => Err(IpcError::InvalidConfiguration),
    }
}

fn parse_socket_address(value: OsString) -> Result<SocketAddr, IpcError> {
    value
        .into_string()
        .map_err(|_| IpcError::InvalidConfiguration)?
        .parse()
        .map_err(|_| IpcError::InvalidConfiguration)
}

fn map_codec(_: CodecError) -> IpcError {
    IpcError::InvalidMessage
}

fn map_authentication(error: AuthenticationError) -> IpcError {
    match error {
        AuthenticationError::Authentication => IpcError::AuthenticationFailed,
        AuthenticationError::Entropy => IpcError::Unavailable,
        AuthenticationError::InvalidEnvelope => IpcError::InvalidMessage,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use q_periapt_backends::MlDsa65;

    use super::*;
    use crate::codec::read_frame;
    use crate::witness::WitnessPort;

    fn deploy_file(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deploy")
            .join(name);
        assert!(path.is_file(), "missing deployment template: {name}");
        std::fs::read_to_string(&path).expect("a shipped deployment template must be readable")
    }

    /// The unquoted value of `NAME=value` in a shell script's parameter block.
    fn shell_parameter<'a>(script: &'a str, name: &str) -> &'a str {
        script
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .map(|value| value.trim().trim_matches('"'))
            .unwrap_or_else(|| unreachable!("the run-directory script must set {name}"))
    }

    /// The line after `<key>KEY</key>` in a plist, trimmed.
    fn plist_value<'a>(plist: &'a str, key: &str) -> &'a str {
        let key = format!("<key>{key}</key>");
        let mut lines = plist.lines().map(str::trim);
        lines
            .find(|line| *line == key.as_str())
            .and_then(|_| lines.next())
            .unwrap_or_else(|| unreachable!("the plist must set {key}"))
    }

    /// The `<string>` value under `<key>KEY</key>` in a plist.
    fn plist_string<'a>(plist: &'a str, key: &str) -> &'a str {
        plist_value(plist, key)
            .trim_start_matches("<string>")
            .trim_end_matches("</string>")
    }

    /// The `<string>` values of a plist's `ProgramArguments` array, in order.
    fn plist_program_arguments(plist: &str) -> Vec<&str> {
        let mut lines = plist.lines().map(str::trim);
        lines
            .find(|line| *line == "<key>ProgramArguments</key>")
            .unwrap_or_else(|| unreachable!("the plist must set ProgramArguments"));
        assert_eq!(lines.next(), Some("<array>"));
        lines
            .take_while(|line| *line != "</array>")
            .filter_map(|line| line.strip_prefix("<string>")?.strip_suffix("</string>"))
            .collect()
    }

    /// The shipped templates encode contracts this code enforces, and nothing
    /// else checked them. Two defects reached this branch that way: endpoints
    /// written as DNS names, which `parse_socket_address` cannot accept, and an
    /// `EnvironmentFile` whose optional marker was put on the directive instead
    /// of the path, which systemd discards as an unknown key.
    #[test]
    fn the_deployment_templates_agree_with_this_code() {
        let service = deploy_file("q-periapt-policy-agent.service");
        let socket = deploy_file("q-periapt-policy-agent.socket");
        let dropin = deploy_file("q-periapt-policy-agent.service.d/10-endpoints.conf.example");
        let plist = deploy_file("com.qperiapt.policy-agent.plist");

        // A leading '-' marks an optional VALUE. On the directive it is simply
        // an unknown key, which systemd logs and ignores -- failing silently.
        for (name, body) in [
            ("service", &service),
            ("socket", &socket),
            ("drop-in", &dropin),
        ] {
            for line in body.lines() {
                assert!(
                    !line.starts_with('-'),
                    "{name}: '{line}' puts the optional marker on the directive, not the value"
                );
            }
        }

        // The activation name is the daemon's; both templates must use it.
        assert!(
            socket.contains(&format!("FileDescriptorName={IPC_ACTIVATION_NAME}")),
            "the socket unit must publish the listener as {IPC_ACTIVATION_NAME}"
        );
        assert!(
            plist.contains(&format!("<key>{IPC_ACTIVATION_NAME}</key>")),
            "the plist Sockets entry must be keyed {IPC_ACTIVATION_NAME}"
        );

        // The daemon compares its first argument against getsockname, so the
        // path the manager binds and the path it passes must be the same one.
        let listen = socket
            .lines()
            .find_map(|line| line.strip_prefix("ListenStream="))
            .expect("the socket unit must declare ListenStream");
        assert!(
            service.contains(listen),
            "ExecStart must be given the same socket path the socket unit binds ({listen})"
        );
        let plist_socket = plist
            .lines()
            .find(|line| line.contains("agent.sock"))
            .expect("the plist must name a socket path");
        let plist_socket = plist_socket
            .trim()
            .trim_start_matches("<string>")
            .trim_end_matches("</string>");
        assert_eq!(
            plist.matches(plist_socket).count(),
            2,
            "the plist socket path must appear as both SockPathName and the first argument"
        );

        // Every endpoint any template suggests has to be one this code accepts.
        for body in [&service, &dropin, &plist] {
            for candidate in body
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .filter_map(|line| line.split_once("ENDPOINT=").map(|(_, value)| value))
                .chain(
                    body.lines()
                        .filter(|line| line.contains("<string>") && line.contains(":784"))
                        .map(|line| {
                            line.trim()
                                .trim_start_matches("<string>")
                                .trim_end_matches("</string>")
                        }),
                )
            {
                let candidate = candidate.trim();
                assert!(
                    parse_socket_address(OsString::from(candidate)).is_ok(),
                    "template endpoint {candidate:?} is not a numeric address this code accepts"
                );
            }
        }

        // The optional-endpoints-file path the drop-in advertises must exist.
        assert!(
            service.contains("EnvironmentFile=-/"),
            "EnvironmentFile must tolerate a missing file, or the drop-in's Environment= path fails"
        );

        // PartOf= propagates stop and restart from the service to the socket, so
        // a service restart would unlink and recreate the node that both READMEs
        // promise survives one.
        assert!(
            !socket
                .lines()
                .any(|line| line.trim_start().starts_with("PartOf=")),
            "the socket unit must not be PartOf= the service, or a restart destroys the socket"
        );

        // /run is a tmpfs, so the socket's parent is recreated every boot. Left
        // to systemd it is 0755 root:root; the daemon's only enforced admission
        // boundary is that directory's mode, so the entry must be shipped.
        let tmpfiles = deploy_file("q-periapt-agent.tmpfiles.conf");
        let parent = listen
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .expect("the listener path must have a parent directory");
        let entry = tmpfiles
            .lines()
            .find(|line| line.starts_with('d') && line.contains(parent));
        let entry = entry.unwrap_or_else(|| unreachable!("tmpfiles.d must provision {parent}"));
        assert!(
            entry.contains("0710"),
            "the socket's parent must be 0710 so only the transport group can traverse: {entry}"
        );

        // launchd creates the SockPathName node but never its parent. The
        // shipped RunAtLoad job verifies that parent and is the only thing
        // that loads the agent, so the script, its plist and the agent plist
        // have to agree on the directory, the mode, the script path and the
        // label -- and on the ordering the whole arrangement exists for.
        let script = deploy_file("qperiapt-agent-rundir.sh");
        let rundir = deploy_file("com.qperiapt.policy-agent-rundir.plist");
        let plist_parent = plist_socket
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .expect("the plist socket path must have a parent directory");
        let run_dir = shell_parameter(&script, "RUN_DIR");
        assert_eq!(
            run_dir, plist_parent,
            "the run-directory script must own the parent of the plist's SockPathName"
        );

        // On macOS /private/var/run is root:daemon 0775 with no sticky bit, and
        // rename(2) in a writable directory needs no ownership of the entry: a
        // gid-1 process could rename the verified directory away and put its
        // own, or a symlink, at the path, and launchd would bind inside it. So
        // the directory has to sit where only root can rename it, and the
        // script has to refuse any ancestor that is not a root-owned real
        // directory group and other cannot write -- before it creates or
        // adopts anything below.
        for (name, path) in [
            ("RUN_DIR", run_dir),
            ("SockPathName's parent", plist_parent),
        ] {
            assert!(
                !path.starts_with("/private/var/run/") && !path.starts_with("/var/run/"),
                "{name} {path} sits under /var/run, where a gid-1 process can rename it away"
            );
        }
        let ancestors_verified = script
            .find("verify_ancestor \"$ancestor\"")
            .expect("the script must verify every ancestor of RUN_DIR");
        assert!(
            script.contains("Directory:root:[0-7][0-7][0145][0145])"),
            "the ancestor check must accept only a root-owned directory without group or other write"
        );
        let inspected = script
            .find("if [ -L \"$RUN_DIR\" ]")
            .expect("the script must refuse a symlink at RUN_DIR");
        assert!(
            ancestors_verified < inspected,
            "the script must verify the ancestors before it so much as looks at RUN_DIR"
        );
        assert_eq!(
            shell_parameter(&script, "RUN_DIR_MODE"),
            "0710",
            "the run directory must be 0710 so only the transport group can traverse"
        );
        assert_eq!(
            shell_parameter(&script, "RUN_DIR_OWNER"),
            plist_string(&plist, "UserName"),
            "the run directory's owner must be the account the agent plist runs the daemon as"
        );

        let label = plist_string(&plist, "Label");
        assert_eq!(label, "com.qperiapt.policy-agent");
        assert_eq!(
            shell_parameter(&script, "AGENT_LABEL"),
            label,
            "the script must bootstrap the agent plist's label"
        );
        let agent_plist = shell_parameter(&script, "AGENT_PLIST");
        assert_eq!(
            agent_plist.rsplit_once('/').map(|(_, name)| name),
            Some("com.qperiapt.policy-agent.plist"),
            "the script must bootstrap the shipped agent plist"
        );
        // launchd loads everything under /Library/LaunchDaemons at boot with no
        // ordering among RunAtLoad jobs, which is the whole reason the agent is
        // loaded by the script rather than by launchd's scan.
        assert!(
            !agent_plist.starts_with("/Library/LaunchDaemons/")
                && !agent_plist.starts_with("/System/Library/LaunchDaemons/"),
            "the agent plist must live where launchd does not scan at boot: {agent_plist}"
        );
        let verified = script
            .find("\nverified=1\n")
            .expect("the script must record that the directory verified");
        let bootstrapped = script
            .find("launchctl bootstrap system \"$AGENT_PLIST\"")
            .expect("the script must bootstrap the agent plist");
        assert!(
            verified < bootstrapped,
            "the script must bootstrap the agent only after the directory verified"
        );

        // stat has no ACL format on macOS and chmod 0710 removes no ACL
        // entry, so type, owner, group and mode alone accept a directory whose
        // ACL grants what its mode denies -- and a socket bound inside such a
        // directory inherits its inheritable entries, which would defeat the
        // plist's SockPathMode the same way. The script has to read ls -e's
        // entry lines, on every ancestor and on the directory itself, and to
        // strip the directory's ACL between the chown and the verification.
        assert!(
            script.contains("ls -lde -- \"$1\""),
            "stat has no ACL format on macOS; the check must read ls -e entries"
        );
        let ancestor_check = script
            .find("verify_ancestor() {")
            .expect("the script must define verify_ancestor");
        let ancestor_check_end = script
            .get(ancestor_check..)
            .and_then(|body| body.find("\n}\n"))
            .map(|end| ancestor_check + end)
            .expect("verify_ancestor must close");
        let ancestor_acl = script
            .find("verify_no_acl \"$1\"")
            .expect("the script must check every ancestor for an ACL");
        assert!(
            ancestor_check < ancestor_acl && ancestor_acl < ancestor_check_end,
            "every ancestor must be refused on an ACL: verify_no_acl belongs inside verify_ancestor"
        );
        let owned = script
            .find("chown -h \"$RUN_DIR_OWNER:$RUN_DIR_GROUP\"")
            .expect("the script must chown the run directory");
        let stripped = script
            .find("chmod -h -N \"$RUN_DIR\"")
            .expect("the script must remove any ACL from the run directory");
        assert!(
            owned < stripped && stripped < verified,
            "the run directory's ACL must be removed after the chown and before the verification"
        );
        let mode_verified = script
            .find("stat -f '%HT:%Su:%Sg:%Mp%Lp' \"$RUN_DIR\"")
            .expect("the script must verify the run directory's type, owner, group and mode");
        let acl_verified = script
            .find("verify_no_acl \"$RUN_DIR\"")
            .expect("the script must verify the run directory carries no ACL");
        assert!(
            mode_verified < acl_verified && acl_verified < verified,
            "the run directory must be verified ACL-free after the stat and before it counts as verified"
        );
        let deploy_readme = deploy_file("README.md");
        assert!(
            deploy_readme.contains("ls -lde") && deploy_readme.contains("chmod -N"),
            "the deploy README must document the ACL check and the strip the script performs"
        );

        // The job that runs the script must run the shipped script through
        // /bin/sh (it is installed 0644, with no execute bit), at boot, once,
        // as root, and the script's install instructions must name the path
        // the job runs it from.
        assert_eq!(
            plist_string(&rundir, "Label"),
            "com.qperiapt.policy-agent-rundir"
        );
        let arguments = plist_program_arguments(&rundir);
        assert_eq!(
            arguments.first().copied(),
            Some("/bin/sh"),
            "the run-directory job must run the script through /bin/sh"
        );
        let script_path = arguments
            .get(1)
            .copied()
            .unwrap_or_else(|| unreachable!("the run-directory plist must run the shipped script"));
        assert_eq!(
            script_path.rsplit_once('/').map(|(_, name)| name),
            Some("qperiapt-agent-rundir.sh"),
            "the run-directory job must run the shipped script: {script_path}"
        );
        assert_eq!(
            arguments.len(),
            2,
            "the run-directory job runs the script and nothing else: {arguments:?}"
        );
        assert!(
            script.contains(script_path),
            "the script must document the path the plist runs it from ({script_path})"
        );
        assert_eq!(
            plist_value(&rundir, "RunAtLoad"),
            "<true/>",
            "the run-directory job must run at boot"
        );
        assert_eq!(
            plist_value(&rundir, "KeepAlive"),
            "<false/>",
            "the run-directory job runs once per boot and is not restarted"
        );
        assert!(
            !rundir.contains("<key>UserName</key>"),
            "the run-directory job must run as root: chown and launchctl bootstrap system require it"
        );
        assert!(
            script.contains("system/com.qperiapt.policy-agent-rundir"),
            "the script's re-run instructions must name the job's own label"
        );

        // launchd's default ExitTimeOut is 20 seconds. A stop that lands
        // during a request is observed once that request is answered or
        // refused -- at most IPC_REQUEST_DEADLINE -- or within one
        // maintenance interval when the daemon is idle, and the lease release
        // that follows runs under LEASE_RELEASE_BUDGET: 66 seconds worst
        // case, past the default and past the 60 the plist used to give. 90
        // is systemd's default stop timeout, which the deploy README already
        // relies on.
        assert_eq!(
            plist_value(&plist, "ExitTimeOut"),
            "<integer>90</integer>",
            "the agent plist must give a stop that lands during a request room to finish"
        );
        assert!(
            Duration::from_secs(90)
                > MAINTENANCE_INTERVAL + IPC_REQUEST_DEADLINE + LEASE_RELEASE_BUDGET,
            "ExitTimeOut must cover observing the stop after a request plus the release budget"
        );
    }

    /// The shipped ACL check, run as shipped: the `verify_no_acl` text is cut
    /// out of the script and executed under `/bin/sh` against real ACLs on
    /// real directories. Every setup step is asserted, never skipped -- a
    /// filesystem that cannot hold an ACL is not a reason to pass.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_run_directory_job_refuses_the_acl_stat_cannot_see() {
        use std::path::Path;
        use std::process::Command;

        let script = deploy_file("qperiapt-agent-rundir.sh");
        let start = script
            .find("NL=$(printf")
            .expect("the script must define its newline constant");
        let check = script
            .get(start..)
            .and_then(|rest| {
                let end = rest.find("\n}\n")?;
                rest.get(..end + 3)
            })
            .expect("the newline constant must be followed by a closed function");
        assert!(
            check.contains("verify_no_acl() {"),
            "the first function after the newline constant must be verify_no_acl: {check}"
        );
        let harness = format!(
            "set -eu\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\nAGENT_LABEL=test\n\
             fail() {{ printf '%s\\n' \"$1\" >&2; exit 1; }}\n{check}\nverify_no_acl \"$1\"\n"
        );
        let root = tempfile::Builder::new()
            .prefix("qperiapt-rundir-acl-")
            .tempdir()
            .expect("a temporary directory for the ACL cases");
        let harness_path = root.path().join("harness.sh");
        std::fs::write(&harness_path, harness).expect("the harness must be writable");

        let run = |program: &str, arguments: &[&str]| -> String {
            let output = Command::new(program)
                .args(arguments)
                .current_dir(root.path())
                .output()
                .unwrap_or_else(|error| unreachable!("{program} must run: {error}"));
            assert!(
                output.status.success(),
                "{program} {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let verify = |path: &Path| -> (bool, String) {
            let output = Command::new("/bin/sh")
                .arg(&harness_path)
                .arg(path)
                .output()
                .expect("/bin/sh must run the harness");
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        };

        // A plain 0710 directory is accepted.
        let plain = root.path().join("plain");
        run("/bin/mkdir", &["plain"]);
        run("/bin/chmod", &["0710", "plain"]);
        assert!(verify(&plain).0, "a plain 0710 directory must pass");

        // The counterexample: an ACL granting everyone write and search that
        // the stat format the script relies on for owner and mode cannot see.
        let acl = root.path().join("acl");
        run("/bin/mkdir", &["acl"]);
        run(
            "/bin/chmod",
            &[
                "+a",
                "everyone allow list,add_file,search,add_subdirectory,delete_child",
                "acl",
            ],
        );
        run("/bin/chmod", &["0710", "acl"]);
        let stat = run("/usr/bin/stat", &["-f", "%HT:%Su:%Sg:%Mp%Lp", "acl"]);
        assert!(
            stat.trim_end().ends_with(":0710"),
            "the stat format reports the mode as if nothing were wrong: {stat}"
        );
        let (accepted, stderr) = verify(&acl);
        assert!(
            !accepted,
            "an ACL that grants what 0710 denies must be refused"
        );
        assert!(
            stderr.contains("carries an ACL") && stderr.contains(" 0: "),
            "the refusal must name the ACL and print its entries: {stderr}"
        );

        // With an extended attribute beside the ACL the mode field ends in
        // '@', not '+', which is why the check counts ls -e's lines instead.
        run("/usr/bin/xattr", &["-w", "com.qperiapt.test", "x", "acl"]);
        let listing = run("/bin/ls", &["-ld", "acl"]);
        let mode_field = listing.split_whitespace().next().unwrap_or_default();
        assert!(
            mode_field.ends_with('@'),
            "an extended attribute hides the ACL marker in the mode field: {listing}"
        );
        let (accepted, stderr) = verify(&acl);
        assert!(
            !accepted && stderr.contains("carries an ACL"),
            "the ACL must still be refused behind the extended attribute: {stderr}"
        );

        // An inheritable entry on a parent lands on a child that plain mkdir
        // creates, exactly as the script's own mkdir would; the parent is
        // refused as an ancestor and the child until its entry is removed.
        let parent = root.path().join("parent");
        let child = parent.join("child");
        run("/bin/mkdir", &["parent"]);
        run(
            "/bin/chmod",
            &[
                "+a",
                "everyone allow search,file_inherit,directory_inherit",
                "parent",
            ],
        );
        run("/bin/mkdir", &["parent/child"]);
        run("/bin/chmod", &["0710", "parent/child"]);
        let (accepted, stderr) = verify(&child);
        assert!(
            !accepted && stderr.contains("inherited"),
            "a child must be refused on the entry it inherited: {stderr}"
        );
        assert!(
            !verify(&parent).0,
            "the parent carrying the inheritable entry must be refused"
        );
        run("/bin/chmod", &["-h", "-N", "parent/child"]);
        assert!(
            verify(&child).0,
            "the child must pass once its inherited entry is removed"
        );
        assert!(
            !verify(&parent).0,
            "removing the child's entry leaves the parent refused"
        );

        // The strip the script applies to the run directory removes the
        // counterexample's ACL; the extended attribute stays and does not
        // matter.
        run("/bin/chmod", &["-h", "-N", "acl"]);
        let (accepted, stderr) = verify(&acl);
        assert!(
            accepted,
            "chmod -N must leave a directory the check accepts: {stderr}"
        );
    }

    #[test]
    fn the_request_deadline_covers_the_minimum_guarded_plan() {
        // The request deadline has to admit the least plan of every guarded
        // command after a full read phase and before a full write phase, or
        // a healthy request against slow-but-answering ports would be refused
        // with status 24 as a matter of course.
        assert!(
            IPC_REQUEST_DEADLINE
                >= IPC_IO_TIMEOUT + 3 * AUTHORITY_IO_TIMEOUT + WITNESS_IO_TIMEOUT + IPC_IO_TIMEOUT,
            "the request deadline must cover Begin and Accept: 3 authority + 1 witness round trips"
        );
        assert!(
            IPC_REQUEST_DEADLINE
                >= IPC_IO_TIMEOUT
                    + 2 * AUTHORITY_IO_TIMEOUT
                    + 2 * WITNESS_IO_TIMEOUT
                    + IPC_IO_TIMEOUT,
            "the request deadline must cover Reconcile: 2 authority + 2 witness round trips"
        );
        // Admission is strict, so five round trips need strictly more than
        // five timeouts.
        assert!(
            LEASE_RELEASE_BUDGET > 5 * AUTHORITY_IO_TIMEOUT,
            "the release budget must admit five bounded authority round trips"
        );
    }

    #[test]
    fn the_port_round_trip_bounds_are_the_transport_deadlines(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The agent admits a port call only while at least `round_trip_bound`
        // of its deadline remains, so each bound must be the very deadline
        // the transport gives one exchange: the timeout `serve_agent` builds
        // that client with.
        let address = SocketAddr::from(([127, 0, 0, 1], 1));
        let (witness_client_sk, _) = MlDsa65::generate([0x71u8; 32]);
        let (_, witness_server_vk) = MlDsa65::generate([0x72u8; 32]);
        let witness = AuthenticatedTcpWitness::new(
            address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            WITNESS_IO_TIMEOUT,
        )?;
        assert_eq!(witness.round_trip_bound(), WITNESS_IO_TIMEOUT);

        let (authority_client_sk, _) = MlDsa65::generate([0x73u8; 32]);
        let (_, authority_server_vk) = MlDsa65::generate([0x74u8; 32]);
        let identity = AuthorityWireIdentityV2::new(
            AuthorityClientIdV2::from_bytes([0x11; 32])?,
            AuthorityServerIdV2::from_bytes([0x12; 32])?,
            AuthorityEpochV2::from_bytes([0x13; 32])?,
            StateHeadV2::new(
                StateRevisionV2::new(1, [0x21; 32], 1, [0x22; 32])?,
                StateFenceV2::from_bytes([0x23; 32])?,
            ),
            DeploymentConfigRevisionV2::new(1, [0x31; 32])?,
        )?;
        let authority = AuthenticatedTcpAuthorityV2::new(
            address,
            identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            AUTHORITY_IO_TIMEOUT,
        )?;
        assert_eq!(authority.round_trip_bound(), AUTHORITY_IO_TIMEOUT);
        Ok(())
    }

    #[test]
    fn endpoint_addresses_are_numeric_only() {
        // Both deployment templates and README.md state this, because the Linux
        // template pairs each endpoint with an IPAddressAllow entry that systemd
        // resolves once at unit load and never re-checks. A name would be the
        // wrong thing on both sides of that pairing, so it is refused at start
        // rather than resolved.
        assert!(parse_socket_address(OsString::from("203.0.113.10:7841")).is_ok());
        assert!(parse_socket_address(OsString::from("[2001:db8::1]:7841")).is_ok());
        assert_eq!(
            parse_socket_address(OsString::from("witness.example.internal:7841")),
            Err(IpcError::InvalidConfiguration)
        );
        assert_eq!(
            parse_socket_address(OsString::from("localhost:7841")),
            Err(IpcError::InvalidConfiguration)
        );
        assert_eq!(
            parse_socket_address(OsString::from("203.0.113.10")),
            Err(IpcError::InvalidConfiguration)
        );
    }

    #[test]
    fn the_maintenance_interval_agrees_with_the_poll_timeout() {
        // The loop waits for one and schedules on the other; if they drift, the
        // sweep either runs twice per wait or skips a wait entirely.
        assert_eq!(
            u64::try_from(MAINTENANCE_TIMEOUT.tv_sec).expect("timeout seconds fit in u64"),
            MAINTENANCE_INTERVAL.as_secs()
        );
        assert_eq!(MAINTENANCE_TIMEOUT.tv_nsec, 0);
        assert_eq!(MAINTENANCE_INTERVAL.subsec_nanos(), 0);
    }

    #[test]
    fn the_accept_wait_times_out_when_idle_and_reports_a_waiting_client() {
        let directory =
            std::env::temp_dir().join(format!("qperiapt-accept-wait-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temporary directory");
        let path = directory.join("accept-wait.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("listener");
        listener.set_nonblocking(true).expect("non-blocking");

        // Nothing is connected, so the wait must return control rather than
        // parking until a client shows up. This is what gives an idle daemon
        // the chance to sweep expired sessions.
        let waited = Instant::now();
        assert_eq!(wait_for_connection(&listener), Ok(false));
        assert!(waited.elapsed() >= Duration::from_millis(500));

        // A waiting client is reported, and the accept that follows does not
        // block -- the listener is non-blocking, so a report that turned out to
        // be stale would surface as `WouldBlock` instead of stalling the loop.
        let client = UnixStream::connect(&path).expect("client");
        assert_eq!(wait_for_connection(&listener), Ok(true));
        assert!(listener.accept().is_ok());

        drop(client);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
    }

    fn request_body(command: u8) -> Result<Vec<u8>, IpcError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut encoder, IPC_REQUEST_DOMAIN, IPC_SCHEMA_VERSION).map_err(map_codec)?;
        encoder.fixed(&[7u8; 32]).map_err(map_codec)?;
        encoder.byte(command).map_err(map_codec)?;
        Ok(encoder.finish())
    }

    fn finished_request_body(command: Command, finished: [u8; 32]) -> Result<Vec<u8>, IpcError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut encoder, IPC_REQUEST_DOMAIN, IPC_SCHEMA_VERSION).map_err(map_codec)?;
        encoder.fixed(&[7u8; 32]).map_err(map_codec)?;
        encoder.byte(command as u8).map_err(map_codec)?;
        encoder.fixed(&[8u8; 32]).map_err(map_codec)?;
        encoder.fixed(&finished).map_err(map_codec)?;
        Ok(encoder.finish())
    }

    fn encoded_payload(payload: ResponsePayload) -> Result<Vec<u8>, IpcError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_response_payload(&mut encoder, payload)?;
        Ok(encoder.finish())
    }

    #[test]
    fn strict_request_decoder_rejects_unknown_and_trailing_bytes() -> Result<(), IpcError> {
        let valid = request_body(Command::PublicKeys as u8)?;
        assert!(Request::decode(&valid).is_ok());

        let unknown = request_body(0xff)?;
        assert_eq!(
            Request::decode(&unknown).err(),
            Some(IpcError::InvalidMessage)
        );

        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            Request::decode(&trailing).err(),
            Some(IpcError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn v1_domain_and_schema_are_rejected_without_compatibility_fallback() -> Result<(), IpcError> {
        let mut old_domain = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut old_domain, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v1", 1)
            .map_err(map_codec)?;
        old_domain.fixed(&[7u8; 32]).map_err(map_codec)?;
        old_domain
            .byte(Command::PublicKeys as u8)
            .map_err(map_codec)?;
        assert_eq!(
            Request::decode(&old_domain.finish()).err(),
            Some(IpcError::InvalidMessage)
        );

        let mut old_schema = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut old_schema, IPC_REQUEST_DOMAIN, 1).map_err(map_codec)?;
        old_schema.fixed(&[7u8; 32]).map_err(map_codec)?;
        old_schema
            .byte(Command::PublicKeys as u8)
            .map_err(map_codec)?;
        assert_eq!(
            Request::decode(&old_schema.finish()).err(),
            Some(IpcError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn finished_commands_decode_to_distinct_typed_flights() -> Result<(), IpcError> {
        let initiator = Request::decode(&finished_request_body(
            Command::AcceptInitiatorFinished,
            [11u8; 32],
        )?)?;
        assert!(matches!(
            initiator.payload,
            RequestPayload::AcceptInitiatorFinished(_, finished)
                if finished == InitiatorFinishedV1::from_bytes([11u8; 32])
        ));

        let responder = Request::decode(&finished_request_body(
            Command::AcceptResponderFinished,
            [12u8; 32],
        )?)?;
        assert!(matches!(
            responder.payload,
            RequestPayload::AcceptResponderFinished(_, finished)
                if finished == ResponderFinishedV1::from_bytes([12u8; 32])
        ));
        Ok(())
    }

    #[test]
    fn response_tags_encode_role_and_flight_without_implicit_responder_finished(
    ) -> Result<(), IpcError> {
        let pending =
            PendingSessionHandle::decode([1u8; 32]).map_err(|_| IpcError::InvalidConfiguration)?;
        let key =
            ConfirmedKeyHandle::decode([2u8; 32]).map_err(|_| IpcError::InvalidConfiguration)?;
        let initiator_finished = InitiatorFinishedV1::from_bytes([3u8; 32]);
        let responder_finished = ResponderFinishedV1::from_bytes([4u8; 32]);
        let ciphertexts = EncapsulationCiphertexts::from_slices(
            &[5u8; Q_PERIAPT_MLKEM768_CT_LEN],
            &[6u8; Q_PERIAPT_X25519_LEN],
        )
        .map_err(|_| IpcError::InvalidConfiguration)?;

        let mut expected_initiator_encapsulation = vec![2];
        expected_initiator_encapsulation.extend_from_slice(pending.as_bytes());
        expected_initiator_encapsulation.extend_from_slice(ciphertexts.pq());
        expected_initiator_encapsulation.extend_from_slice(ciphertexts.traditional());
        expected_initiator_encapsulation.extend_from_slice(initiator_finished.as_bytes());
        assert_eq!(
            encoded_payload(ResponsePayload::InitiatorEncapsulation {
                handle: pending,
                ciphertexts: ciphertexts.clone(),
                initiator_finished,
            })?,
            expected_initiator_encapsulation
        );

        let mut expected_responder_encapsulation = vec![3];
        expected_responder_encapsulation.extend_from_slice(pending.as_bytes());
        expected_responder_encapsulation.extend_from_slice(ciphertexts.pq());
        expected_responder_encapsulation.extend_from_slice(ciphertexts.traditional());
        assert_eq!(
            encoded_payload(ResponsePayload::ResponderEncapsulation {
                handle: pending,
                ciphertexts,
            })?,
            expected_responder_encapsulation
        );

        let mut expected_initiator_decapsulation = vec![4];
        expected_initiator_decapsulation.extend_from_slice(pending.as_bytes());
        expected_initiator_decapsulation.extend_from_slice(initiator_finished.as_bytes());
        assert_eq!(
            encoded_payload(ResponsePayload::InitiatorDecapsulation {
                handle: pending,
                initiator_finished,
            })?,
            expected_initiator_decapsulation
        );

        let mut expected_responder_decapsulation = vec![5];
        expected_responder_decapsulation.extend_from_slice(pending.as_bytes());
        assert_eq!(
            encoded_payload(ResponsePayload::ResponderDecapsulation { handle: pending })?,
            expected_responder_decapsulation
        );

        let mut expected_initiator_accepted = vec![6];
        expected_initiator_accepted.extend_from_slice(key.as_bytes());
        assert_eq!(
            encoded_payload(ResponsePayload::InitiatorAccepted(key))?,
            expected_initiator_accepted
        );

        let mut expected_responder_accepted = vec![7];
        expected_responder_accepted.extend_from_slice(key.as_bytes());
        expected_responder_accepted.extend_from_slice(responder_finished.as_bytes());
        assert_eq!(
            encoded_payload(ResponsePayload::ResponderAccepted {
                key_handle: key,
                responder_finished,
            })?,
            expected_responder_accepted
        );
        Ok(())
    }

    #[test]
    fn v2_agent_statuses_keep_flight_and_resource_failures_distinct() {
        assert_eq!(agent_status(AgentError::UnexpectedFlight), 13);
        assert_eq!(agent_status(AgentError::ConflictingAcceptanceReplay), 14);
        assert_eq!(agent_status(AgentError::FinishedRejected), 15);
        assert_eq!(agent_status(AgentError::LocalResourceFailure), 16);
        assert_eq!(agent_status(AgentError::LocalCryptoFailure), 17);
        assert_eq!(agent_status(AgentError::OperationDeadlineExceeded), 24);
    }

    #[test]
    fn length_delimited_reader_rejects_oversized_frame_before_allocation() -> Result<(), IpcError> {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .map_err(|_| IpcError::InvalidConfiguration)?
            .to_be_bytes();
        let mut cursor = Cursor::new(oversized);
        assert_eq!(read_frame(&mut cursor), Err(CodecError::Oversized));
        Ok(())
    }
}
