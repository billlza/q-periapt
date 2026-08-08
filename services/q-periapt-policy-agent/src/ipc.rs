//! Strict authenticated Unix IPC and executable configuration boundary.

use core::fmt;
use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_ffi_abi2::{
    Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_MLKEM768_PK_LEN, Q_PERIAPT_X25519_LEN,
};
use q_periapt_migration::{EndpointRole, MigrationAuthorityKeyId, MigrationIdentityKeyId};

use crate::authentication::{sign_envelope, verify_envelope, AuthenticationError};
use crate::codec::{
    encode_domain, hash_fields, read_frame, require_domain, write_frame, CodecError, Decoder,
    Encoder, MAX_FRAME_BYTES,
};
use crate::crypto::{EncapsulationCiphertexts, EncapsulationPublicKeys};
use crate::filesystem::OwnedPrivateDirectory;
use crate::repository::{MigrationTrustRoots, StateRepository};
use crate::service::{
    AgentConfig, AgentError, AgentLimits, BeginDecapsulation, BeginEncapsulation,
    ConfirmedKeyHandle, EndpointIdentity, PendingSessionHandle, PolicyAgent, SessionAuthorization,
    SignedPolicyBundle,
};
use crate::witness::{AuthenticatedTcpWitness, ReferenceWitnessServer};

const IPC_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v1";
const IPC_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v1";
const IPC_REQUEST_DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-IPC-DIGEST/v1";
const IPC_SCHEMA_VERSION: u16 = 1;
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(5);
const WITNESS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const NONCE_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_RECENT_NONCES: usize = 4096;
const MAX_SIGNED_OFFER_BYTES: usize = 8 * 1024;
const MAX_POLICY_BYTES: usize = q_periapt_ffi_abi2::Q_PERIAPT_MAX_SIGNED_POLICY_BYTES;
const IPC_SOCKET_NAME: &str = "agent.sock";

/// IPC configuration, authentication, framing, or fatal service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IpcError {
    /// The executable command or protected configuration was invalid.
    InvalidConfiguration,
    /// The socket path or mode was not an owner-only Unix boundary.
    InsecureSocket,
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
            Self::InsecureSocket => "IPC socket boundary is not owner protected",
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
    Confirm = 4,
    Cancel = 5,
    DestroyKey = 6,
    Advance = 7,
    Reset = 8,
    Reconcile = 9,
}

impl Command {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublicKeys),
            2 => Some(Self::BeginEncapsulation),
            3 => Some(Self::BeginDecapsulation),
            4 => Some(Self::Confirm),
            5 => Some(Self::Cancel),
            6 => Some(Self::DestroyKey),
            7 => Some(Self::Advance),
            8 => Some(Self::Reset),
            9 => Some(Self::Reconcile),
            _ => None,
        }
    }
}

enum RequestPayload {
    PublicKeys,
    BeginEncapsulation(BeginEncapsulation),
    BeginDecapsulation(BeginDecapsulation),
    Confirm(PendingSessionHandle, [u8; 32]),
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
            Command::Confirm => RequestPayload::Confirm(
                PendingSessionHandle::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| IpcError::InvalidMessage)?,
                decoder.array().map_err(map_codec)?,
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
    Encapsulation {
        handle: PendingSessionHandle,
        ciphertexts: EncapsulationCiphertexts,
        finished: [u8; 32],
    },
    Decapsulation {
        handle: PendingSessionHandle,
        finished: [u8; 32],
    },
    Confirmed(ConfirmedKeyHandle),
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

/// Sequential, timeout-bounded authenticated Unix server.
///
/// Sequential handling deliberately caps active clients at one. A slow client
/// can occupy that slot for at most `io_timeout`; no unbounded worker/thread
/// creation is possible.
struct UnixIpcServer<W: crate::witness::WitnessPort> {
    agent: PolicyAgent<W>,
    client_verification_key: [u8; ML_DSA_65_VK_LEN],
    server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    io_timeout: Duration,
    recent_nonces: RecentNonces,
}

impl<W: crate::witness::WitnessPort> fmt::Debug for UnixIpcServer<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnixIpcServer([redacted])")
    }
}

impl<W: crate::witness::WitnessPort> UnixIpcServer<W> {
    /// Bind an owner-only socket and configure pinned request/response keys.
    fn bind(
        service_directory: &OwnedPrivateDirectory,
        agent: PolicyAgent<W>,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        io_timeout: Duration,
    ) -> Result<(Self, UnixListener), IpcError> {
        if client_verification_key.iter().all(|byte| *byte == 0) || io_timeout.is_zero() {
            return Err(IpcError::InvalidConfiguration);
        }
        let listener = bind_private_socket(service_directory)?;
        Ok((
            Self {
                agent,
                client_verification_key,
                server_signing_key,
                io_timeout,
                recent_nonces: RecentNonces::new(),
            },
            listener,
        ))
    }

    /// Serve one request per accepted connection with bounded sequential resources.
    fn serve(mut self, listener: UnixListener) -> Result<(), IpcError> {
        for accepted in listener.incoming() {
            let mut stream = accepted.map_err(|_| IpcError::Unavailable)?;
            match self.handle(&mut stream) {
                Ok(())
                | Err(IpcError::InvalidMessage)
                | Err(IpcError::AuthenticationFailed)
                | Err(IpcError::Unavailable) => {}
                Err(error) => return Err(error),
            }
        }
        Err(IpcError::Unavailable)
    }

    fn handle(&mut self, stream: &mut UnixStream) -> Result<(), IpcError> {
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(|_| IpcError::Unavailable)?;
        let envelope = read_frame(stream).map_err(map_codec)?;
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
        write_frame(stream, &response).map_err(map_codec)
    }

    fn execute(&self, payload: RequestPayload) -> Result<ResponsePayload, AgentError> {
        match payload {
            RequestPayload::PublicKeys => self.agent.public_keys().map(ResponsePayload::PublicKeys),
            RequestPayload::BeginEncapsulation(request) => {
                let result = self.agent.begin_encapsulation(request)?;
                Ok(ResponsePayload::Encapsulation {
                    handle: result.handle,
                    ciphertexts: result.ciphertexts,
                    finished: *result.local_finished.as_bytes(),
                })
            }
            RequestPayload::BeginDecapsulation(request) => {
                let result = self.agent.begin_decapsulation(request)?;
                Ok(ResponsePayload::Decapsulation {
                    handle: result.handle,
                    finished: *result.local_finished.as_bytes(),
                })
            }
            RequestPayload::Confirm(handle, finished) => self
                .agent
                .confirm(handle, finished)
                .map(ResponsePayload::Confirmed),
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
        ResponsePayload::Encapsulation {
            handle,
            ciphertexts,
            finished,
        } => {
            encoder.byte(2).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)?;
            encoder.fixed(ciphertexts.pq()).map_err(map_codec)?;
            encoder
                .fixed(ciphertexts.traditional())
                .map_err(map_codec)?;
            encoder.fixed(&finished).map_err(map_codec)
        }
        ResponsePayload::Decapsulation { handle, finished } => {
            encoder.byte(3).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)?;
            encoder.fixed(&finished).map_err(map_codec)
        }
        ResponsePayload::Confirmed(handle) => {
            encoder.byte(4).map_err(map_codec)?;
            encoder.fixed(handle.as_bytes()).map_err(map_codec)
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
        AgentError::FinishedRejected => 13,
        AgentError::LocalCryptoFailure => 14,
        AgentError::ExecutionUnavailable => 15,
        AgentError::InternalPoisoned => 16,
    }
}

pub(crate) fn bind_private_socket(
    directory: &OwnedPrivateDirectory,
) -> Result<UnixListener, IpcError> {
    let name = std::ffi::OsStr::new(IPC_SOCKET_NAME);
    directory
        .require_absent(name)
        .map_err(|_| IpcError::InsecureSocket)?;
    directory
        .set_as_process_directory()
        .map_err(|_| IpcError::InsecureSocket)?;
    let listener = UnixListener::bind(IPC_SOCKET_NAME).map_err(|_| IpcError::Unavailable)?;
    if directory.protect_socket(name).is_err() {
        drop(listener);
        directory
            .remove_leaf(name)
            .map_err(|_| IpcError::InsecureSocket)?;
        return Err(IpcError::InsecureSocket);
    }
    Ok(listener)
}

/// Run the Unix executable from one of two exact command shapes:
///
/// `serve-agent SERVICE_DIRECTORY REPOSITORY WITNESS_ADDRESS CONFIG_DIRECTORY`
/// `serve-witness LISTEN_ADDRESS WITNESS_DATABASE CONFIG_DIRECTORY`
///
/// A successful `serve-agent` startup permanently pins `SERVICE_DIRECTORY` as
/// the process working directory before entering the server loop. This entry
/// point is therefore intended for the dedicated executable process, not for
/// embedding in a host process with unrelated working-directory users. Call it
/// before starting any other threads or relative-path I/O in that process.
pub fn run_from_arguments<I>(arguments: I) -> Result<(), IpcError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next().ok_or(IpcError::InvalidConfiguration)?;
    let mode = arguments.next().ok_or(IpcError::InvalidConfiguration)?;
    if mode == "serve-agent" {
        let service_directory =
            PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        let repository = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        let witness_address =
            parse_socket_address(arguments.next().ok_or(IpcError::InvalidConfiguration)?)?;
        let configuration = PathBuf::from(arguments.next().ok_or(IpcError::InvalidConfiguration)?);
        if arguments.next().is_some() {
            return Err(IpcError::InvalidConfiguration);
        }
        return serve_agent(
            &service_directory,
            &repository,
            witness_address,
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
    service_directory: &Path,
    repository_path: &Path,
    witness_address: SocketAddr,
    configuration: &Path,
) -> Result<(), IpcError> {
    let service_directory =
        OwnedPrivateDirectory::open(service_directory).map_err(|_| IpcError::InsecureSocket)?;
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
    let config = load_agent_config(&configuration)?;
    let agent = PolicyAgent::new(repository, witness, config)
        .map_err(|_| IpcError::InvalidConfiguration)?;
    let (server, listener) = UnixIpcServer::bind(
        &service_directory,
        agent,
        read_array(&configuration, "ipc-client-vk.bin")?,
        read_secret(&configuration, "ipc-server-sk.bin")?,
        IPC_IO_TIMEOUT,
    )?;
    server.serve(listener)
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

    fn request_body(command: u8) -> Result<Vec<u8>, IpcError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut encoder, IPC_REQUEST_DOMAIN, IPC_SCHEMA_VERSION).map_err(map_codec)?;
        encoder.fixed(&[7u8; 32]).map_err(map_codec)?;
        encoder.byte(command).map_err(map_codec)?;
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
    fn length_delimited_reader_rejects_oversized_frame_before_allocation() -> Result<(), IpcError> {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .map_err(|_| IpcError::InvalidConfiguration)?
            .to_be_bytes();
        let mut cursor = Cursor::new(oversized);
        assert_eq!(read_frame(&mut cursor), Err(CodecError::Oversized));
        Ok(())
    }
}
