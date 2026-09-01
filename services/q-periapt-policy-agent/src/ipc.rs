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
use crate::witness::{AuthenticatedTcpWitness, ReferenceWitnessServer};

const IPC_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2";
const IPC_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2";
const IPC_REQUEST_DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-DIGEST/v2";
const IPC_SCHEMA_VERSION: u16 = 2;
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(5);
const WITNESS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORITY_IO_TIMEOUT: Duration = Duration::from_secs(5);
const NONCE_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_RECENT_NONCES: usize = 4096;
const MAX_SIGNED_OFFER_BYTES: usize = 8 * 1024;
const MAX_POLICY_BYTES: usize = q_periapt_ffi_abi2::Q_PERIAPT_MAX_SIGNED_POLICY_BYTES;
/// Name the service manager publishes the listener under. Both deployment
/// templates must use this exact value: systemd `FileDescriptorName=` and the
/// launchd `Sockets` dictionary key.
const IPC_ACTIVATION_NAME: &str = "agent";

/// IPC configuration, authentication, framing, or fatal service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IpcError {
    /// The executable command or protected configuration was invalid.
    InvalidConfiguration,
    /// The socket path or mode was not an owner-only Unix boundary.
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
/// Sequential handling deliberately caps active clients at one. Each accepted
/// connection is bounded by one absolute deadline of `io_timeout` computed at
/// accept: every framed read and write derives its remaining budget from that
/// deadline, so even a client trickling one byte per interval cannot occupy
/// the slot for longer. No unbounded worker/thread creation is possible.
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

/// How long the serving loop waits for a connection before sweeping expired
/// sessions. This is the granularity of the session TTL on an idle daemon, not
/// a poll interval in the busy-wait sense: the wait is a real blocking `poll`,
/// so a connection is still accepted the moment it arrives.
const IDLE_MAINTENANCE_INTERVAL: Timespec = Timespec {
    tv_sec: 1,
    tv_nsec: 0,
};

/// Wait for a connection to accept, or for the maintenance interval to elapse.
///
/// `false` means the wait timed out and the caller should run one maintenance
/// pass. A signal that interrupts the wait reports the same thing: sweeping and
/// waiting again is both correct and cheap, and it keeps a routine `EINTR` from
/// being mistaken for a dead listener.
fn wait_for_connection(listener: &UnixListener) -> Result<bool, IpcError> {
    let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
    match poll(&mut descriptors, Some(&IDLE_MAINTENANCE_INTERVAL)) {
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
) -> Result<(), IpcError> {
    if server_signing_key.iter().all(|byte| *byte == 0) {
        return Err(IpcError::InvalidConfiguration);
    }
    let probe = sign_envelope(IPC_DIRECTION_ISOLATION_PROBE, server_signing_key)
        .map_err(|_| IpcError::InvalidConfiguration)?;
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
        io_timeout: Duration,
    ) -> Result<Self, IpcError> {
        if client_verification_key.iter().all(|byte| *byte == 0) || io_timeout.is_zero() {
            return Err(IpcError::InvalidConfiguration);
        }
        validate_ipc_direction_isolation(&client_verification_key, server_signing_key.as_bytes())?;
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
    /// The daemon never sets the flag; it exists so the loop is reachable from a
    /// test, matching the witness and authority servers. It is read once per
    /// accept wait, so a shutdown is observed within one maintenance interval.
    fn serve(mut self, listener: UnixListener, shutdown: &AtomicBool) -> Result<(), IpcError> {
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
        while !shutdown.load(Ordering::Acquire) {
            if !wait_for_connection(&listener)? {
                self.agent.expire_idle_sessions();
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
            // handler's deadline reads block identically on both.
            stream
                .set_nonblocking(false)
                .map_err(|_| IpcError::Unavailable)?;
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
        let deadline = Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(IpcError::Unavailable)?;
        self.handle_io(stream, deadline)
    }

    fn handle_io<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
        read_deadline: Instant,
    ) -> Result<(), IpcError> {
        let envelope = read_frame_until(stream, read_deadline).map_err(map_codec)?;
        let request_body = verify_envelope(&envelope, &self.client_verification_key)
            .map_err(map_authentication)?;
        let request = Request::decode(request_body)?;
        self.recent_nonces.insert(request.nonce)?;
        let request_digest =
            hash_fields(IPC_REQUEST_DIGEST_DOMAIN, &[request_body]).map_err(map_codec)?;
        let result = self.execute(request.payload);
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
        // The response gets its own budget rather than whatever is left of the
        // request's. Reading is paced by the client, so it must be bounded to
        // keep a slow one from holding this single-threaded loop. Execution is
        // not: it is bounded by the witness and authority timeouts, and those
        // together already exceed one IPC timeout, so a state advance would
        // routinely exhaust a shared deadline before it produced a response.
        // The client would then be told nothing about an operation that had
        // already committed -- the one outcome this protocol most needs to
        // avoid. Both phases stay separately bounded, so the connection as a
        // whole is still bounded.
        let write_deadline = Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(IpcError::Unavailable)?;
        write_frame_until(stream, &response, write_deadline).map_err(|_| IpcError::Unavailable)
    }

    /// Run the serving loop against a caller-supplied listener.
    ///
    /// The module is already `cfg(unix)`, so `cfg(test)` is enough here.
    #[cfg(test)]
    pub(crate) fn serve_for_test(
        self,
        listener: UnixListener,
        shutdown: &AtomicBool,
    ) -> Result<(), IpcError> {
        self.serve(listener, shutdown)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        agent: PolicyAgent<W, A>,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    ) -> Result<Self, IpcError> {
        if client_verification_key.iter().all(|byte| *byte == 0) {
            return Err(IpcError::InvalidConfiguration);
        }
        validate_ipc_direction_isolation(&client_verification_key, server_signing_key.as_bytes())?;
        Ok(Self {
            agent,
            client_verification_key,
            server_signing_key,
            io_timeout: IPC_IO_TIMEOUT,
            recent_nonces: RecentNonces::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn handle_io_for_test<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
    ) -> Result<(), IpcError> {
        let deadline = Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(IpcError::Unavailable)?;
        self.handle_io(stream, deadline)
    }

    #[cfg(test)]
    pub(crate) fn handle_io_with_deadline_for_test<T: DeadlineStream>(
        &mut self,
        stream: &mut T,
        deadline: Instant,
    ) -> Result<(), IpcError> {
        self.handle_io(stream, deadline)
    }

    #[cfg(test)]
    pub(crate) const fn agent_for_test(&self) -> &PolicyAgent<W, A> {
        &self.agent
    }

    fn execute(&self, payload: RequestPayload) -> Result<ResponsePayload, AgentError> {
        match payload {
            RequestPayload::PublicKeys => self.agent.public_keys().map(ResponsePayload::PublicKeys),
            RequestPayload::BeginEncapsulation(request) => {
                let result = self.agent.begin_encapsulation(request)?;
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
                let result = self.agent.begin_decapsulation(request)?;
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
                .accept_initiator_finished(handle, finished)
                .map(|result| ResponsePayload::ResponderAccepted {
                    key_handle: result.key_handle,
                    responder_finished: result.responder_finished,
                }),
            RequestPayload::AcceptResponderFinished(handle, finished) => self
                .agent
                .accept_responder_finished(handle, finished)
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
                self.agent.apply_advance(&certificate)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::Reset(certificate) => {
                self.agent.apply_reset(&certificate)?;
                Ok(ResponsePayload::Empty)
            }
            RequestPayload::Reconcile => {
                self.agent.reconcile_transition()?;
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
    let agent = PolicyAgent::new(repository, witness, authority, config)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    let server = UnixIpcServer::new(
        agent,
        read_array(&configuration, "ipc-client-vk.bin")?,
        read_secret(&configuration, "ipc-server-sk.bin")?,
        IPC_IO_TIMEOUT,
    )?;
    // The daemon runs until the service manager stops it; nothing sets this.
    let shutdown = AtomicBool::new(false);
    server.serve(listener, &shutdown)
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
        WITNESS_IO_TIMEOUT,
    )
    .map_err(|_| IpcError::InvalidConfiguration)?;
    let listener = TcpListener::bind(listen).map_err(|_| IpcError::Unavailable)?;
    let shutdown = AtomicBool::new(false);
    server
        .serve(listener, &shutdown)
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

    use super::*;
    use crate::codec::read_frame;

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
