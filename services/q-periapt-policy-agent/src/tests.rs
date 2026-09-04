use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_ffi_abi2::{Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_X25519_LEN};
use q_periapt_migration::{
    CapabilityOfferInputV1, CapabilityOfferV1, CommittedMigrationStateV1, ComponentMode,
    EndpointKeyShareV1, EndpointRole, InitiatorFinishedV1, MigrationAuthorityKeyId,
    MigrationChainId, MigrationIdentityKeyId, MigrationNonce, MigrationProtocolId,
    MigrationResetNonce, MigrationResetV1, MigrationSecurityPosture, MigrationSessionId,
    MigrationStateDigest, MigrationStateDraftV1, MigrationStateV1, MigrationSuiteSet,
    ResponderFinishedV1, SecurityFloor, SignedCapabilityOfferV1, SignedMigrationResetV1,
    SignedMigrationStateV1, StateCertificateKind,
};
use q_periapt_policy::{
    policy_signature_message, AuthenticatedPolicy, HybridSuite, Policy, TrustedPolicyState,
};
use q_periapt_sig::Signer;

use crate::authentication::{sign_envelope, verify_envelope};
use crate::authority::{
    AuthorityDispositionV2, AuthorityErrorV2, AuthorityIntentV2, AuthorityLimitsV2,
    AuthorityMutationV2, AuthorityQueryResultV2, AuthorityReceiptV2, AuthoritySnapshotV2,
    AuthorityStateV2, DeploymentConfigRevisionV2, InstanceLeaseV2, OperationIdV2,
    ProcessInstanceIdV2, StateFenceV2, StateHeadV2, StateRevisionV2, TrustedClockErrorV2,
    TrustedClockV2,
};
use crate::authority_protocol::{
    AuthorityCommandV2, AuthorityKnownFailureV2, AuthorityOutcomeV2, AuthorityUnknownV2,
    DurablyRetainedAuthorityReceiptV2,
};
use crate::authority_transport::{AuthorityTransportErrorV2, InstanceAuthorityPort};
use crate::codec::{
    encode_domain, read_frame, require_domain, write_frame, DeadlineStream, Decoder, Encoder,
    MAX_FRAME_BYTES,
};
use crate::crypto::{EncapsulationCiphertexts, EncapsulationPublicKeys};
use crate::filesystem::{open_private_file, OwnedPrivateDirectory, PrivateFileError};
use crate::repository::{
    MigrationTrustRoots, RepositoryError, StateRepository, MAX_JOURNALED_LEASE_INTENTS,
};
use crate::service::{
    AgentConfig, AgentError, AgentLimits, BeginDecapsulation, BeginDecapsulationResult,
    BeginEncapsulation, BeginEncapsulationResult, EndpointIdentity, InitiatorDecapsulationResult,
    InitiatorEncapsulationResult, LeaseReleaseOutcome, PolicyAgent, ResponderDecapsulationResult,
    ResponderEncapsulationResult, SessionAuthorization, SignedPolicyBundle,
};
use crate::types::{
    FenceToken, OperationId, StateAdvance, StateHead, StateRevision, TransitionKind,
};
use crate::witness::{
    AuthenticatedTcpWitness, ReferenceWitnessServer, WitnessError, WitnessIntent, WitnessOutcome,
    WitnessPort, WitnessReceipt,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

mod durable_store;
mod ipc;
mod lease;
mod lease_journal;
mod session;
mod transition;
mod witness_protocol;

const POLICY: &str = "schema_version = 1\n\
    policy_version = 1\n\
    min_nist_level = 3\n\
    default_profile = \"ContextBound\"\n\
    allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
    allowed_sigs = [\"ML-DSA-65\"]\n\
    deprecated = []\n";

struct TestDirectory {
    _temporary: tempfile::TempDir,
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> TestResult<Self> {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::Builder::new()
            .prefix("q-periapt-policy-agent-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = temporary.path().canonicalize()?;
        Ok(Self {
            _temporary: temporary,
            path,
        })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
fn install_macos_test_acl(path: &Path, entry: &str) -> TestResult {
    let status = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("failed to install macOS test ACL").into());
    }
    Ok(())
}

/// redb 2.6 file-format-v2 header layout, as far as these tests inspect it:
/// nine magic bytes, then the god byte at offset 9 (bit 1: primary commit slot
/// index, bit 2: recovery required, bit 4: two-phase commit), then two 128-byte
/// commit slots at offsets 64 and 192, each ending in a 16-byte xxh3 checksum.
const GOD_BYTE_OFFSET: u64 = 9;
const PRIMARY_BIT: u8 = 1;
const RECOVERY_REQUIRED: u8 = 2;
const TWO_PHASE_COMMIT: u8 = 4;
const SLOT_0_OFFSET: u64 = 64;
const SLOT_SIZE: u64 = 128;

/// Leave a cleanly closed redb 2.6 file looking as a *stock* redb writer would
/// after a crash: recovery required, and no two-phase flag. This crate's
/// stores never produce this state -- every commit they make is two-phase --
/// which is exactly why they refuse to recover it.
fn mark_redb_file_unclean_without_two_phase(path: &Path) -> TestResult {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(GOD_BYTE_OFFSET))?;
    let mut god = [0u8; 1];
    file.read_exact(&mut god)?;
    god[0] |= RECOVERY_REQUIRED;
    god[0] &= !TWO_PHASE_COMMIT;
    file.seek(SeekFrom::Start(GOD_BYTE_OFFSET))?;
    file.write_all(&god)?;
    file.sync_all()?;
    Ok(())
}

/// Prove a redb 2.6 file was left by a process that died with the store open:
/// the recovery-required flag is set (only a clean `Drop` clears it) and the
/// two-phase flag is set (every commit here is two-phase). A crash test whose
/// child had quietly dropped the store before exiting would be a clean-close
/// test that still passes; this is what stops that.
fn assert_redb_file_left_unclean(path: &Path) -> TestResult {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(GOD_BYTE_OFFSET))?;
    let mut god = [0u8; 1];
    file.read_exact(&mut god)?;
    assert!(
        god[0] & RECOVERY_REQUIRED != 0,
        "the child closed the store cleanly; this is not a crash"
    );
    assert!(
        god[0] & TWO_PHASE_COMMIT != 0,
        "the store's last commit was not two-phase"
    );
    Ok(())
}

/// Corrupt the checksum of the primary commit slot of a cleanly closed redb 2.6
/// file and mark the file not cleanly shut down, so that redb's recovery has to
/// decide whether to trust that slot. The header is nine magic bytes; the god
/// byte at offset 9 (bit 1: primary slot index, bit 2: recovery required, bit 4:
/// two-phase commit); then two 128-byte commit slots at offsets 64 and 192, each
/// ending in a 16-byte xxh3 checksum of the slot.
fn mark_redb_primary_slot_corrupted(path: &Path) -> TestResult {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(GOD_BYTE_OFFSET))?;
    let mut god = [0u8; 1];
    file.read_exact(&mut god)?;
    let primary = u64::from(god[0] & PRIMARY_BIT);
    god[0] |= RECOVERY_REQUIRED;
    file.seek(SeekFrom::Start(GOD_BYTE_OFFSET))?;
    file.write_all(&god)?;
    let checksum_last_byte = SLOT_0_OFFSET + primary * SLOT_SIZE + SLOT_SIZE - 1;
    file.seek(SeekFrom::Start(checksum_last_byte))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(checksum_last_byte))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    Ok(())
}

fn join<T>(handle: thread::JoinHandle<T>) -> TestResult<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("test worker panicked").into())
}

struct FailingWriteTransport {
    input: Cursor<Vec<u8>>,
}

impl Read for FailingWriteTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for FailingWriteTransport {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "intentional response write failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "intentional response flush failure",
        ))
    }
}

impl DeadlineStream for FailingWriteTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

struct CaptureTransport {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for CaptureTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for CaptureTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for CaptureTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

/// Records the write timeout the framing layer asks for, so a test can see
/// which budget the response was actually given.
struct WriteBudgetTransport {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    write_timeout: std::cell::Cell<Option<Duration>>,
}

impl Read for WriteBudgetTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for WriteBudgetTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for WriteBudgetTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout.set(timeout);
        Ok(())
    }
}

/// Yields one buffered byte per read after a short pause, mimicking a client
/// that stays inside any per-syscall timeout while never completing a frame.
struct TricklingTransport {
    input: Cursor<Vec<u8>>,
    step: Duration,
    output: Vec<u8>,
}

impl Read for TricklingTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        thread::sleep(self.step);
        let mut byte = [0u8; 1];
        if self.input.read(&mut byte)? == 0 {
            return Ok(0);
        }
        let Some(first) = output.first_mut() else {
            return Ok(0);
        };
        *first = byte[0];
        Ok(1)
    }
}

impl Write for TricklingTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for TricklingTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

fn framed_accept_initiator_request(
    signing_key: &[u8],
    nonce: [u8; 32],
    handle: crate::PendingSessionHandle,
    finished: InitiatorFinishedV1,
) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(4))
        .and_then(|()| body.fixed(handle.as_bytes()))
        .and_then(|()| body.fixed(finished.as_bytes()))
        .map_err(|error| io::Error::other(format!("IPC request encoding failed: {error:?}")))?;
    let envelope = sign_envelope(&body.finish(), signing_key)
        .map_err(|error| io::Error::other(format!("IPC request signing failed: {error:?}")))?;
    let mut framed = Vec::new();
    write_frame(&mut framed, &envelope)
        .map_err(|error| io::Error::other(format!("IPC framing failed: {error:?}")))?;
    Ok(framed)
}

/// Frame one initiator-role Begin (command 2) over the signed offers
/// `initiator_authorization` was built from, and the peer's public keys.
fn framed_begin(
    signing_key: &[u8],
    nonce: [u8; 32],
    offers: &(Vec<u8>, Vec<u8>),
    peer_public_keys: &EncapsulationPublicKeys,
) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(2))
        .and_then(|()| body.lp16(&offers.0))
        .and_then(|()| body.lp16(&offers.1))
        .and_then(|()| body.fixed(peer_public_keys.pq()))
        .and_then(|()| body.fixed(peer_public_keys.traditional()))
        .map_err(|error| io::Error::other(format!("IPC request encoding failed: {error:?}")))?;
    let envelope = sign_envelope(&body.finish(), signing_key)
        .map_err(|error| io::Error::other(format!("IPC request signing failed: {error:?}")))?;
    let mut framed = Vec::new();
    write_frame(&mut framed, &envelope)
        .map_err(|error| io::Error::other(format!("IPC framing failed: {error:?}")))?;
    Ok(framed)
}

/// The nonce and request digest a response must carry, recomputed from the
/// exact framed request the way a conformant external client would.
///
/// The digest is over the signed request body, which is the envelope's first
/// length-prefixed field, so recovering it needs no key. There is no IPC
/// client in this workspace -- the witness and authority protocols have one,
/// and both of those verify this same binding -- so without this the server's
/// only tie between a response and the request *body* was emitted and checked
/// by nothing: a constant, a wrongly-domained digest, or a digest over the
/// wrong bytes would ship either silently or unverifiably.
fn expected_response_binding(framed_request: &[u8]) -> TestResult<([u8; 32], [u8; 32])> {
    let envelope = read_frame(&mut Cursor::new(framed_request))
        .map_err(|error| io::Error::other(format!("IPC request framing failed: {error:?}")))?;
    let mut envelope_fields = Decoder::new(&envelope);
    let body = envelope_fields
        .lp16(MAX_FRAME_BYTES)
        .map_err(|error| io::Error::other(format!("IPC request body failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC request domain failed: {error:?}")))?;
    let nonce: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC request nonce failed: {error:?}")))?;
    // The domain is spelled out rather than imported, so a change to the
    // constant has to be made here too and cannot pass unnoticed.
    let digest = crate::codec::hash_fields(b"Q-PERIAPT-POLICY-AGENT-IPC-DIGEST/v2", &[body])
        .map_err(|error| io::Error::other(format!("IPC request digest failed: {error:?}")))?;
    Ok((nonce, digest))
}

/// Read a response's nonce and request-digest binding and assert both against
/// the request that produced it.
fn assert_response_binding(decoder: &mut Decoder<'_>, framed_request: &[u8]) -> TestResult {
    let (expected_nonce, expected_digest) = expected_response_binding(framed_request)?;
    let nonce: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response nonce failed: {error:?}")))?;
    assert_eq!(nonce, expected_nonce);
    let digest: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response digest failed: {error:?}")))?;
    assert_eq!(
        digest, expected_digest,
        "the response must bind the exact request body it answered"
    );
    Ok(())
}

fn decode_responder_acceptance_response(
    framed: &[u8],
    verification_key: &[u8],
    framed_request: &[u8],
) -> TestResult<([u8; 32], [u8; 32])> {
    let envelope = read_frame(&mut Cursor::new(framed))
        .map_err(|error| io::Error::other(format!("IPC response framing failed: {error:?}")))?;
    let body = verify_envelope(&envelope, verification_key)
        .map_err(|error| io::Error::other(format!("IPC response signature failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC response domain failed: {error:?}")))?;
    assert_response_binding(&mut decoder, framed_request)?;
    let status = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response status failed: {error:?}")))?;
    assert_eq!(status, 0);
    let tag = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response tag failed: {error:?}")))?;
    assert_eq!(tag, 7);
    let key_handle = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC key handle failed: {error:?}")))?;
    let responder_finished = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC Finished failed: {error:?}")))?;
    decoder
        .finish()
        .map_err(|error| io::Error::other(format!("IPC trailing bytes: {error:?}")))?;
    Ok((key_handle, responder_finished))
}

/// The fields of a status-0 initiator-role Begin response, as decoded from
/// the wire.
struct DecodedBeginEncapsulation {
    handle: [u8; 32],
    pq_ciphertext: Vec<u8>,
    traditional_ciphertext: Vec<u8>,
    initiator_finished: [u8; 32],
}

/// Decode a status-0 initiator-role Begin response (tag 2) exactly as
/// `encode_response_payload` lays it out: pending-session handle, ML-KEM-768
/// ciphertext, X25519 ciphertext, Initiator Finished.
fn decode_begin_encapsulation_response(
    framed: &[u8],
    verification_key: &[u8],
    framed_request: &[u8],
) -> TestResult<DecodedBeginEncapsulation> {
    let envelope = read_frame(&mut Cursor::new(framed))
        .map_err(|error| io::Error::other(format!("IPC response framing failed: {error:?}")))?;
    let body = verify_envelope(&envelope, verification_key)
        .map_err(|error| io::Error::other(format!("IPC response signature failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC response domain failed: {error:?}")))?;
    assert_response_binding(&mut decoder, framed_request)?;
    let status = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response status failed: {error:?}")))?;
    assert_eq!(status, 0);
    let tag = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response tag failed: {error:?}")))?;
    assert_eq!(tag, 2);
    let handle = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC session handle failed: {error:?}")))?;
    let pq_ciphertext = decoder
        .fixed(Q_PERIAPT_MLKEM768_CT_LEN)
        .map_err(|error| io::Error::other(format!("IPC ML-KEM ciphertext failed: {error:?}")))?
        .to_vec();
    let traditional_ciphertext = decoder
        .fixed(Q_PERIAPT_X25519_LEN)
        .map_err(|error| io::Error::other(format!("IPC X25519 ciphertext failed: {error:?}")))?
        .to_vec();
    let initiator_finished = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC Finished failed: {error:?}")))?;
    decoder
        .finish()
        .map_err(|error| io::Error::other(format!("IPC trailing bytes: {error:?}")))?;
    Ok(DecodedBeginEncapsulation {
        handle,
        pq_ciphertext,
        traditional_ciphertext,
        initiator_finished,
    })
}

#[derive(Clone)]
struct MemoryWitness {
    state: Arc<Mutex<MemoryWitnessState>>,
    unknown_after_apply: Arc<AtomicBool>,
    /// Once, at the next `query`: answer with an `Applied` receipt filed under
    /// the queried operation id whose stored intent is a *different* one --
    /// same successor head, a different attested predecessor. The wire admits
    /// such a receipt (its shape is valid and the client transport checks only
    /// the operation id), and a tampered witness store opens with one, so
    /// `WitnessReceipt::is_exact_applied` is the only thing that rejects it.
    foreign_intent_on_next_query: Arc<AtomicBool>,
    /// Answer every `read_head` with `Unavailable` while set, as a witness
    /// that cannot be reached would.
    fail_reads: Arc<AtomicBool>,
    /// Once, at the next `read_head`: let this authority's active lease run
    /// out before the head is returned. A witness read is the I/O between the
    /// agent's coverage snapshot and its durable write, so this is where an
    /// authority clock step lands inside a real operation.
    advance_authority_on_read: Arc<Mutex<Option<MemoryAuthority>>>,
    /// What `round_trip_bound` reports. In-memory calls are instantaneous, so
    /// this is zero unless a test says otherwise.
    round_trip_bound: Arc<Mutex<Duration>>,
    /// Sleep this long at the top of the next `compare_and_advance`, the way
    /// a slow network round trip would.
    delay_next_compare_and_advance: Arc<Mutex<Duration>>,
    /// Sleep this long at the top of the next `read_head`. That read is the
    /// I/O between an operation's coverage proof and the checks that guard
    /// what it may retain or return, so this is where a slow witness spends
    /// a budget the operation was admitted under.
    delay_next_read_head: Arc<Mutex<Duration>>,
}

struct MemoryWitnessState {
    head: StateHead,
    operations: HashMap<OperationId, WitnessReceipt>,
}

impl MemoryWitness {
    fn new(head: StateHead) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryWitnessState {
                head,
                operations: HashMap::new(),
            })),
            unknown_after_apply: Arc::new(AtomicBool::new(false)),
            foreign_intent_on_next_query: Arc::new(AtomicBool::new(false)),
            fail_reads: Arc::new(AtomicBool::new(false)),
            advance_authority_on_read: Arc::new(Mutex::new(None)),
            round_trip_bound: Arc::new(Mutex::new(Duration::ZERO)),
            delay_next_compare_and_advance: Arc::new(Mutex::new(Duration::ZERO)),
            delay_next_read_head: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }

    fn make_next_unknown(&self) {
        self.unknown_after_apply.store(true, Ordering::Release);
    }

    /// Arm the receipt described on `foreign_intent_on_next_query`.
    fn answer_next_query_with_a_foreign_intent(&self) {
        self.foreign_intent_on_next_query
            .store(true, Ordering::Release);
    }

    /// What `round_trip_bound` reports from now on.
    fn set_round_trip_bound(&self, bound: Duration) {
        *self
            .round_trip_bound
            .lock()
            .expect("memory witness hook poisoned") = bound;
    }

    /// Make the next `compare_and_advance` take this long before it acts.
    fn delay_next_compare_and_advance(&self, delay: Duration) {
        *self
            .delay_next_compare_and_advance
            .lock()
            .expect("memory witness hook poisoned") = delay;
    }

    /// Whether the delay above is still armed. `compare_and_advance` takes it
    /// with `mem::take`, so this doubles as "no compare has run since the
    /// delay was armed".
    fn compare_delay_armed(&self) -> bool {
        !self
            .delay_next_compare_and_advance
            .lock()
            .expect("memory witness hook poisoned")
            .is_zero()
    }

    /// Make the next `read_head` take this long before it answers.
    fn delay_next_read_head(&self, delay: Duration) {
        *self
            .delay_next_read_head
            .lock()
            .expect("memory witness hook poisoned") = delay;
    }

    /// Whether the read delay above is still armed. `read_head` takes it with
    /// `mem::take`, so this doubles as "no head read has run since the delay
    /// was armed" -- which is how a test tells a refusal that came *after*
    /// the witness read from one that came before it.
    fn read_head_delay_armed(&self) -> bool {
        !self
            .delay_next_read_head
            .lock()
            .expect("memory witness hook poisoned")
            .is_zero()
    }

    /// Arm the next `read_head` to let `authority`'s active lease run out before
    /// it answers -- an authority clock step landing inside the witness round
    /// trip a guarded operation makes between its coverage proof and the gate
    /// that guards what it may return, with this host's clock unmoved.
    fn advance_authority_on_next_read(&self, authority: MemoryAuthority) {
        *self
            .advance_authority_on_read
            .lock()
            .expect("memory witness hook poisoned") = Some(authority);
    }

    fn replace_head(&self, head: StateHead) -> Result<(), WitnessError> {
        self.state
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .head = head;
        Ok(())
    }
}

impl WitnessPort for MemoryWitness {
    fn read_head(&self) -> Result<StateHead, WitnessError> {
        if self.fail_reads.load(Ordering::Acquire) {
            return Err(WitnessError::Unavailable);
        }
        let delay = core::mem::take(
            &mut *self
                .delay_next_read_head
                .lock()
                .map_err(|_| WitnessError::Persistence)?,
        );
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        if let Some(authority) = self
            .advance_authority_on_read
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .take()
        {
            authority.expire_active_lease();
        }
        Ok(self
            .state
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .head)
    }

    fn compare_and_advance(&self, intent: WitnessIntent) -> Result<WitnessOutcome, WitnessError> {
        let delay = core::mem::take(
            &mut *self
                .delay_next_compare_and_advance
                .lock()
                .map_err(|_| WitnessError::Persistence)?,
        );
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let mut state = self.state.lock().map_err(|_| WitnessError::Persistence)?;
        if let Some(receipt) = state.operations.get(&intent.operation_id()).copied() {
            if receipt.intent() != Some(intent) {
                return Err(WitnessError::InvalidIntent);
            }
            return Ok(WitnessOutcome::Known(Box::new(receipt)));
        }
        let receipt = if state.head == intent.expected() {
            state.head = intent.next();
            WitnessReceipt::applied(intent)
        } else {
            WitnessReceipt::conflict(intent, state.head)
        };
        state.operations.insert(intent.operation_id(), receipt);
        if self.unknown_after_apply.swap(false, Ordering::AcqRel) {
            Ok(WitnessOutcome::Unknown)
        } else {
            Ok(WitnessOutcome::Known(Box::new(receipt)))
        }
    }

    fn query(&self, operation_id: OperationId) -> Result<WitnessOutcome, WitnessError> {
        let state = self.state.lock().map_err(|_| WitnessError::Persistence)?;
        let stored = state.operations.get(&operation_id).copied();
        if self
            .foreign_intent_on_next_query
            .swap(false, Ordering::AcqRel)
        {
            let filed = stored
                .and_then(WitnessReceipt::intent)
                .ok_or(WitnessError::InvalidIntent)?;
            // Same operation id, same successor head, a different attested
            // predecessor. `FenceToken::generate` cannot collide with the one
            // it replaces in any run that matters.
            let foreign = WitnessIntent::new(
                operation_id,
                filed.advance(),
                FenceToken::generate().map_err(|_| WitnessError::InvalidIntent)?,
                filed.next().fence(),
            )?;
            return Ok(WitnessOutcome::Known(Box::new(WitnessReceipt::applied(
                foreign,
            ))));
        }
        Ok(WitnessOutcome::Known(Box::new(stored.unwrap_or_else(
            || WitnessReceipt::not_applied(state.head),
        ))))
    }

    fn round_trip_bound(&self) -> Duration {
        *self
            .round_trip_bound
            .lock()
            .expect("memory witness hook poisoned")
    }
}

const MEMORY_AUTHORITY_LEASE_TTL_MILLIS: u64 = 10_000;
const MEMORY_AUTHORITY_EPOCH_MILLIS: u64 = 1_000_000;

struct FixedClock(u64);

impl TrustedClockV2 for FixedClock {
    fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
        Ok(self.0)
    }
}

/// In-process instance-lease authority sharing one Stage 1 state per deployment.
///
/// Cloning shares the same authority, so two agents built over one clone pair
/// model a recovery clone or concurrent second instance against one deployment.
#[derive(Clone)]
struct MemoryAuthority {
    state: Arc<Mutex<MemoryAuthorityState>>,
}

struct MemoryAuthorityState {
    authority: AuthorityStateV2,
    config: DeploymentConfigRevisionV2,
    now_millis: u64,
    unknown_after_apply: bool,
    /// Before the next acquire: lose its response and refuse every query
    /// after it, so the acquire applies but the agent cannot learn that it
    /// did.
    lose_next_acquire_and_queries: bool,
    /// Before the next acquire: lose its response alone, leaving queries
    /// answered, so the reconciliation inside the very same call is what
    /// learns the outcome.
    lose_next_acquire_response: bool,
    /// Before the next receipt query is answered: acknowledge away the receipt
    /// it would have found. That is a recovery copy sharing this journal
    /// landing between the dispatch and the reconciling query, so the query
    /// reports absent for an operation that did apply.
    acknowledge_before_next_query: bool,
    /// Lose the next `n` lease calls this filter selects on the wire, before
    /// the authority applies them. The calls are not counted; the operation
    /// id each carried is kept in `lost_operation`.
    lose_lease_calls_before_apply: Option<(LeaseCallFilter, u32)>,
    /// The operation id of the last lease call lost before apply.
    lost_operation: Option<OperationIdV2>,
    /// Fail the next lease call this filter selects before it is sent. The
    /// call is not counted.
    fail_next_lease_call_before_send: Option<LeaseCallFilter>,
    /// Answer the next `n` lease calls with this closed failure instead of
    /// applying them. The calls are not counted: the authority never saw
    /// them.
    refuse_lease_calls_with: Option<(AuthorityKnownFailureV2, u32)>,
    /// Answer the next receipt query with this closed failure. The query is
    /// counted.
    refuse_next_query_with: Option<AuthorityKnownFailureV2>,
    /// Arm the locator of the next acknowledgement seen for the set below.
    arm_mismatch_next_acknowledgement: bool,
    /// Answer every acknowledgement of one of these operation ids with
    /// `ReceiptAcknowledgementMismatch`, keeping the receipt retained: the
    /// authority holds a receipt under this operation id whose resulting
    /// authority version the locator cannot discharge
    /// (`ResultingVersionMismatch`). Absence is not this answer; a vacant
    /// entry acknowledges as `AlreadyAbsent`, a `Known` outcome. The real
    /// authority answers this way on every attempt, so this set is sticky.
    mismatching_receipts: HashSet<OperationIdV2>,
    /// Lose the next acknowledgement's response; the receipt stays retained.
    lose_next_acknowledgement: bool,
    /// Clock steps to apply just before the next snapshots, one per snapshot
    /// in order; an empty queue is no step.
    advance_before_snapshot: VecDeque<u64>,
    snapshot_delay: Duration,
    /// Snapshots to let pass before this fires: let the current lease expire,
    /// have a fresh instance acquire the next generation, and let that lease
    /// expire too. The snapshot then reports no active lease *and* an
    /// advanced generation.
    successor_before_snapshot: Option<u32>,
    /// Before the next snapshot: replace the authority with one provisioned
    /// fresh, as a restore from before this instance's acquire would leave it.
    /// The snapshot then reports no lease and a generation *behind* ours.
    rollback_before_snapshot: bool,
    /// Answer every snapshot as indeterminate, as an authority that cannot be
    /// reached would. The queued snapshot hooks stay queued.
    refuse_snapshots: bool,
    /// Snapshots to let pass before one is answered as indeterminate.
    lose_snapshot_after: Option<u32>,
    /// Snapshots this authority has been asked for, answered or not.
    snapshot_calls: u64,
    /// What `round_trip_bound` reports. In-memory calls are instantaneous,
    /// so this is zero unless a test says otherwise.
    round_trip_bound: Duration,
    /// Report this bound from the *next* `round_trip_bound` read and then go
    /// back to the field above. Armed by the hook below once a lease call has
    /// been made, which is how a test makes exactly the reconciling round
    /// trip after a lost dispatch too large for what the budget has left.
    round_trip_bound_once: Option<Duration>,
    /// Arms `round_trip_bound_once` after the next lease call.
    round_trip_bound_once_after_next_lease_call: Option<Duration>,
    /// Answer every acknowledgement with a retryable failure, so receipts stay
    /// retained on both sides -- the authority's table and the agent's queue.
    refuse_acknowledgements: bool,
    /// Answer every receipt query as indeterminate, as an authority that
    /// cannot be reached would.
    refuse_queries: bool,
    /// Lease mutations this authority has been asked to apply, whatever the
    /// answer. A refusal made *before* dispatch leaves this untouched.
    lease_calls: u64,
    /// Receipt queries this authority has been asked, answered or not.
    query_calls: u64,
}

/// Which lease mutations a one-shot transport hook fires for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseCallFilter {
    Any,
    Acquire,
    Release,
}

impl LeaseCallFilter {
    fn selects(self, command: AuthorityCommandV2) -> bool {
        match self {
            Self::Any => true,
            Self::Acquire => command == AuthorityCommandV2::Acquire,
            Self::Release => command == AuthorityCommandV2::Release,
        }
    }
}

fn map_memory_authority_failure(error: AuthorityErrorV2) -> AuthorityKnownFailureV2 {
    match error {
        AuthorityErrorV2::ClockUnavailable => AuthorityKnownFailureV2::ClockUnavailable,
        AuthorityErrorV2::OperationConflict => AuthorityKnownFailureV2::OperationConflict,
        AuthorityErrorV2::AuthorityVersionMismatch => {
            AuthorityKnownFailureV2::AuthorityVersionMismatch
        }
        AuthorityErrorV2::AuthorityVersionExhausted => {
            AuthorityKnownFailureV2::AuthorityVersionExhausted
        }
        AuthorityErrorV2::ReceiptCapacityExceeded => {
            AuthorityKnownFailureV2::ReceiptCapacityExceeded
        }
        _ => AuthorityKnownFailureV2::AllocationFailed,
    }
}

impl MemoryAuthority {
    /// The deployment this fixture models, provisioned fresh at `now_millis`:
    /// no lease, lease generation at its floor.
    fn fresh_authority(
        now_millis: u64,
    ) -> TestResult<(AuthorityStateV2, DeploymentConfigRevisionV2)> {
        let head = StateHeadV2::new(
            StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
            StateFenceV2::from_bytes([44u8; 32])?,
        );
        let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
        let authority = AuthorityStateV2::provision(
            head,
            config,
            AuthorityLimitsV2::new(64, 16, 16, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
            &FixedClock(now_millis),
        )?;
        Ok((authority, config))
    }

    fn new() -> TestResult<Self> {
        let (authority, config) = Self::fresh_authority(MEMORY_AUTHORITY_EPOCH_MILLIS)?;
        Ok(Self {
            state: Arc::new(Mutex::new(MemoryAuthorityState {
                authority,
                config,
                now_millis: MEMORY_AUTHORITY_EPOCH_MILLIS,
                unknown_after_apply: false,
                lose_next_acquire_and_queries: false,
                lose_next_acquire_response: false,
                acknowledge_before_next_query: false,
                lose_lease_calls_before_apply: None,
                lost_operation: None,
                fail_next_lease_call_before_send: None,
                refuse_lease_calls_with: None,
                refuse_next_query_with: None,
                arm_mismatch_next_acknowledgement: false,
                mismatching_receipts: HashSet::new(),
                lose_next_acknowledgement: false,
                advance_before_snapshot: VecDeque::new(),
                snapshot_delay: Duration::ZERO,
                successor_before_snapshot: None,
                rollback_before_snapshot: false,
                refuse_snapshots: false,
                lose_snapshot_after: None,
                snapshot_calls: 0,
                round_trip_bound: Duration::ZERO,
                round_trip_bound_once: None,
                round_trip_bound_once_after_next_lease_call: None,
                refuse_acknowledgements: false,
                refuse_queries: false,
                lease_calls: 0,
                query_calls: 0,
            })),
        })
    }

    /// Refuse (or accept again) every acknowledgement with a retryable failure.
    fn refuse_acknowledgements(&self, refuse: bool) {
        self.lock().refuse_acknowledgements = refuse;
    }

    /// Answer (or stop answering) every receipt query as indeterminate.
    fn refuse_queries(&self, refuse: bool) {
        self.lock().refuse_queries = refuse;
    }

    /// Answer (or stop answering) every snapshot as indeterminate. The queued
    /// snapshot hooks stay queued for the first snapshot answered again.
    fn refuse_snapshots(&self, refuse: bool) {
        self.lock().refuse_snapshots = refuse;
    }

    /// Let `passes` snapshots through, then answer one as indeterminate.
    fn lose_snapshot_after(&self, passes: u32) {
        self.lock().lose_snapshot_after = Some(passes);
    }

    /// Before the next acquire: lose its response and refuse every query
    /// after it, so the acquire applies but the agent cannot learn that it
    /// did.
    fn lose_next_acquire_and_queries(&self) {
        self.lock().lose_next_acquire_and_queries = true;
    }

    /// Before the next acquire: lose its response alone. Queries keep
    /// answering, so the reconciliation inside the same call learns the
    /// outcome -- the commoner shape of a lost response, and the one
    /// `lease_exchange` reconciles inline rather than deferring.
    fn lose_next_acquire_response(&self) {
        self.lock().lose_next_acquire_response = true;
    }

    /// Acknowledge away the receipt the next receipt query would find, just
    /// before that query is answered: a recovery copy sharing this journal
    /// landing between a dispatch and its reconciling query.
    fn acknowledge_before_next_query(&self) {
        self.lock().acknowledge_before_next_query = true;
    }

    /// Lose the next lease call `filter` selects on the wire, before the
    /// authority applies it. The call is not counted; its operation id is
    /// kept for `lost_operation`.
    fn lose_next_lease_call_before_apply(&self, filter: LeaseCallFilter) {
        self.lose_lease_calls_before_apply(filter, 1);
    }

    /// The same, for the next `count` calls `filter` selects, so a resync
    /// loop can be run out with every dispatch's outcome unknown.
    fn lose_lease_calls_before_apply(&self, filter: LeaseCallFilter, count: u32) {
        self.lock().lose_lease_calls_before_apply = Some((filter, count));
    }

    /// The operation id of the last lease call lost before apply, if any.
    fn lost_operation(&self) -> Option<OperationIdV2> {
        self.lock().lost_operation
    }

    /// Fail the next lease call `filter` selects before it is sent. The call
    /// is not counted.
    fn fail_next_lease_call_before_send(&self, filter: LeaseCallFilter) {
        self.lock().fail_next_lease_call_before_send = Some(filter);
    }

    /// Answer the next lease call with `failure` instead of applying it. The
    /// call is not counted: the authority never saw it.
    fn refuse_next_lease_call_with(&self, failure: AuthorityKnownFailureV2) {
        self.refuse_lease_calls_with(failure, 1);
    }

    /// The same, for the next `count` lease calls, so a resync loop can be
    /// run out with every attempt refused on its precondition.
    fn refuse_lease_calls_with(&self, failure: AuthorityKnownFailureV2, count: u32) {
        self.lock().refuse_lease_calls_with = Some((failure, count));
    }

    /// Answer the next receipt query with `failure`. The query is counted.
    fn refuse_next_query_with(&self, failure: AuthorityKnownFailureV2) {
        self.lock().refuse_next_query_with = Some(failure);
    }

    /// Answer every acknowledgement of the next locator seen -- and of that
    /// locator thereafter -- with `ReceiptAcknowledgementMismatch`, keeping
    /// the receipt retained: the authority holds a receipt under this
    /// operation id whose resulting authority version the locator cannot
    /// discharge. Absence is not this answer; a vacant entry acknowledges as
    /// `AlreadyAbsent`, a `Known` outcome.
    fn mismatch_next_acknowledgement(&self) {
        self.lock().arm_mismatch_next_acknowledgement = true;
    }

    /// Lose the next acknowledgement's response; the receipt stays retained.
    fn lose_next_acknowledgement(&self) {
        self.lock().lose_next_acknowledgement = true;
    }

    /// Advertise a deployment config revision the authority does not hold, so
    /// every lease intent built from `wire_config` comes back
    /// `Rejected(ConfigurationMismatch)` -- the shape of a deployment config
    /// that advanced under a running process. `false` restores the revision
    /// the authority actually holds.
    ///
    /// Only the advertised revision drifts: `apply` checks the expected
    /// authority version before it plans, so that has to stay in step or the
    /// intent is refused on the version instead of ever reaching the config.
    fn drift_wire_config(&self, drifted: bool) -> TestResult {
        let mut state = self.lock();
        state.config = if drifted {
            DeploymentConfigRevisionV2::new(2, [46u8; 32])?
        } else {
            state.authority.persistent_meta().config
        };
        Ok(())
    }

    /// What `round_trip_bound` reports from now on.
    fn set_round_trip_bound(&self, bound: Duration) {
        self.lock().round_trip_bound = bound;
    }

    /// Report `bound` from the one `round_trip_bound` read that follows the
    /// next lease call, and the usual bound from every other read. The read
    /// after a dispatch is the reconciliation's own admission, so this is how
    /// a test makes exactly that round trip miss the budget.
    fn report_bound_once_after_next_lease_call(&self, bound: Duration) {
        self.lock().round_trip_bound_once_after_next_lease_call = Some(bound);
    }

    /// Lease mutations this authority has been asked to apply so far.
    fn lease_call_count(&self) -> u64 {
        self.lock().lease_calls
    }

    /// Receipt queries this authority has been asked so far.
    fn query_call_count(&self) -> u64 {
        self.lock().query_calls
    }

    /// Snapshots this authority has been asked for so far. `active_lease`
    /// reads through `snapshot` too, so tests take deltas around the call
    /// under test.
    fn snapshot_call_count(&self) -> u64 {
        self.lock().snapshot_calls
    }

    /// Receipts the authority is still retaining, awaiting acknowledgement.
    fn receipt_count(&self) -> TestResult<usize> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(state.authority.snapshot(&clock)?.receipt_count())
    }

    /// Model a recovery copy sharing this deployment: for each operation the
    /// live instance journaled, find its retained receipt and acknowledge it
    /// away -- exactly what a second instance's start-up journal pass does,
    /// before it finds the lease already held and exits. After this, the live
    /// instance's own exact query reports the receipt absent for an operation
    /// that did execute.
    fn acknowledge_journaled_receipts(&self, operations: &[OperationIdV2]) -> TestResult {
        let mut state = self.lock();
        for operation_id in operations {
            if let Some(receipt) = state.authority.receipt(*operation_id) {
                state
                    .authority
                    .acknowledge_receipt(receipt.locator())
                    .map_err(|error| io::Error::other(format!("{error:?}")))?;
            }
        }
        Ok(())
    }

    /// A foreign instance acquires the lease from the authority's current
    /// generation and then lets it lapse -- a successor that held key-use
    /// authority and is now gone, leaving the snapshot showing no active lease at
    /// an advanced generation. Unlike `install_successor` this needs no live
    /// incumbent, so it models a takeover during a lapse this instance never
    /// recovered from.
    fn foreign_successor_acquires_and_lapses(&self) -> TestResult {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        let current = state.authority.snapshot(&clock)?;
        let intent = AuthorityIntentV2::new(
            OperationIdV2::new(current.authority_version(), [0xC3u8; 32])?,
            current.authority_version(),
            state.config,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: current.lease_generation(),
                instance_id: ProcessInstanceIdV2::from_bytes([0x3Cu8; 32])?,
            },
        )?;
        let receipt = state.authority.apply(&clock, intent)?;
        assert!(
            matches!(receipt.disposition(), AuthorityDispositionV2::Applied),
            "the foreign successor's acquire must apply"
        );
        state
            .authority
            .acknowledge_receipt(receipt.locator())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        state.now_millis += MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1;
        Ok(())
    }

    /// Between the agent's renew and its coverage snapshot, let its lease
    /// expire and have another instance acquire -- and lapse -- the next
    /// generation. This is what a real takeover looks like from the snapshot:
    /// no active lease, but a generation that has moved past the agent's.
    fn successor_acquires_before_next_snapshot(&self) {
        self.successor_acquires_before_snapshot_after(0);
    }

    /// Let `passes` snapshots through, then stage the takeover above before
    /// the next one: `1` leaves the post-renew snapshot clean and lets the
    /// retention snapshot after the durable write see the generation move.
    fn successor_acquires_before_snapshot_after(&self, passes: u32) {
        self.lock().successor_before_snapshot = Some(passes);
    }

    /// Between the agent's renew and its coverage snapshot, replace the
    /// authority with one restored from before the agent ever acquired.
    fn authority_rolls_back_before_next_snapshot(&self) {
        self.lock().rollback_before_snapshot = true;
    }

    fn install_successor(state: &mut MemoryAuthorityState) -> TestResult {
        let clock = FixedClock(state.now_millis);
        let current = state.authority.snapshot(&clock)?;
        let lease = current.active_lease().ok_or_else(|| {
            io::Error::other("the successor hook needs a live lease to supersede")
        })?;
        // Let the incumbent's lease run out, then acquire at the generation
        // the authority reports, exactly as a fresh process would.
        state.now_millis = lease.expires_at_millis() + 1;
        let clock = FixedClock(state.now_millis);
        let intent = AuthorityIntentV2::new(
            OperationIdV2::new(current.authority_version(), [0xA5u8; 32])?,
            current.authority_version(),
            state.config,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: current.lease_generation(),
                instance_id: ProcessInstanceIdV2::from_bytes([0x5Au8; 32])?,
            },
        )?;
        let receipt = state.authority.apply(&clock, intent)?;
        assert!(
            matches!(receipt.disposition(), AuthorityDispositionV2::Applied),
            "the successor's acquire must apply"
        );
        // A real successor drains its own receipt before serving; leave the
        // authority's receipt table as it would.
        state
            .authority
            .acknowledge_receipt(receipt.locator())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        // And let the successor lapse as well, so the snapshot shows no
        // active lease at all -- the shape that used to be mistaken for a
        // lapse of the incumbent's own lease.
        state.now_millis += MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryAuthorityState> {
        self.state.lock().expect("memory authority poisoned")
    }

    fn advance_clock(&self, delta_millis: u64) {
        let mut state = self.lock();
        state.now_millis += delta_millis;
    }

    /// Advance the authority clock once, just before the next snapshot not
    /// yet targeted is computed, so that snapshot reports a lease with
    /// almost no life left. Calls queue: a second call targets the snapshot
    /// after the first call's.
    ///
    /// This is the real sequence, not a contrived one: the renew succeeds and
    /// then time passes before the agent learns the expiry. Advancing the clock
    /// up front cannot reproduce it, because the renew itself resets the expiry
    /// to `now + ttl`.
    fn advance_clock_before_next_snapshot(&self, delta_millis: u64) {
        self.lock().advance_before_snapshot.push_back(delta_millis);
    }

    /// Make the next snapshot take real time, the way a network round trip
    /// does. The coverage anchor is captured before the request is sent, so a
    /// slow snapshot spends the budget it is being asked to report -- which is
    /// the conservative behaviour the anchor exists to produce.
    fn delay_next_snapshot(&self, delay: Duration) {
        self.lock().snapshot_delay = delay;
    }

    /// Whether the delay above is still armed. It is paid only by a snapshot
    /// that is actually computed, so this doubles as "no snapshot has been
    /// computed since the delay was armed".
    fn snapshot_delay_armed(&self) -> bool {
        !self.lock().snapshot_delay.is_zero()
    }

    fn expire_active_lease(&self) {
        self.advance_clock(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    }

    /// The lease the authority currently reports, read the way an agent reads
    /// it: through the port, at the fixture's current clock.
    fn active_lease(&self) -> TestResult<Option<InstanceLeaseV2>> {
        match self.snapshot()? {
            AuthorityOutcomeV2::Known(snapshot) => Ok(snapshot.active_lease()),
            AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_) => {
                Err("the memory authority could not produce a snapshot".into())
            }
        }
    }

    fn make_next_unknown(&self) {
        self.lock().unknown_after_apply = true;
    }

    fn lease_call(
        &self,
        command: AuthorityCommandV2,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        // The one-shot transport hooks come first: none of them reaches the
        // authority, so none of them counts as a call it was asked to apply.
        if state
            .lose_lease_calls_before_apply
            .is_some_and(|(filter, _)| filter.selects(command))
        {
            state.lose_lease_calls_before_apply =
                state
                    .lose_lease_calls_before_apply
                    .and_then(|(filter, remaining)| {
                        remaining
                            .checked_sub(1)
                            .filter(|left| *left > 0)
                            .map(|left| (filter, left))
                    });
            state.lost_operation = Some(intent.operation_id());
            return Ok(AuthorityOutcomeV2::Unknown(
                AuthorityUnknownV2::RequestWriteIndeterminate,
            ));
        }
        if state
            .fail_next_lease_call_before_send
            .is_some_and(|filter| filter.selects(command))
        {
            state.fail_next_lease_call_before_send = None;
            return Err(AuthorityTransportErrorV2::NotSent);
        }
        if let Some((failure, remaining)) = state.refuse_lease_calls_with {
            state.refuse_lease_calls_with = remaining
                .checked_sub(1)
                .filter(|left| *left > 0)
                .map(|left| (failure, left));
            return Ok(AuthorityOutcomeV2::KnownFailure(failure));
        }
        state.lease_calls += 1;
        state.round_trip_bound_once = state.round_trip_bound_once_after_next_lease_call.take();
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.apply(&clock, intent) {
            Ok(receipt) => {
                if state.unknown_after_apply {
                    state.unknown_after_apply = false;
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
                } else {
                    AuthorityOutcomeV2::Known(receipt)
                }
            }
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }
}

impl InstanceAuthorityPort for MemoryAuthority {
    fn wire_config(&self) -> DeploymentConfigRevisionV2 {
        self.lock().config
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        state.snapshot_calls += 1;
        // A snapshot that never reaches the authority consumes none of the
        // queued hooks: they wait for the first one that does.
        if state.refuse_snapshots {
            return Ok(AuthorityOutcomeV2::Unknown(
                AuthorityUnknownV2::ResponseUnavailable,
            ));
        }
        if let Some(passes) = state.lose_snapshot_after {
            state.lose_snapshot_after = passes.checked_sub(1);
            if passes == 0 {
                return Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ResponseUnavailable,
                ));
            }
        }
        let pending = state.advance_before_snapshot.pop_front().unwrap_or(0);
        state.now_millis = state.now_millis.saturating_add(pending);
        if let Some(passes) = state.successor_before_snapshot {
            state.successor_before_snapshot = passes.checked_sub(1);
            if passes == 0 {
                Self::install_successor(&mut state).expect("successor hook failed");
            }
        }
        if core::mem::take(&mut state.rollback_before_snapshot) {
            let (authority, _) =
                Self::fresh_authority(state.now_millis).expect("rollback hook failed");
            state.authority = authority;
        }
        let delay = core::mem::take(&mut state.snapshot_delay);
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV2::Known(snapshot),
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        {
            let mut state = self.lock();
            if core::mem::take(&mut state.lose_next_acquire_and_queries) {
                state.unknown_after_apply = true;
                state.refuse_queries = true;
            }
            if core::mem::take(&mut state.lose_next_acquire_response) {
                state.unknown_after_apply = true;
            }
        }
        self.lease_call(AuthorityCommandV2::Acquire, intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(AuthorityCommandV2::Renew, intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(AuthorityCommandV2::Release, intent)
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        state.query_calls += 1;
        // A recovery copy sharing this journal, landing between the dispatch
        // and this query: it finds the receipt and acknowledges it away, so
        // what follows reports absent for an operation that did apply.
        if core::mem::take(&mut state.acknowledge_before_next_query) {
            if let Some(receipt) = state.authority.receipt(operation_id) {
                let locator = receipt.locator();
                let _ = state.authority.acknowledge_receipt(locator);
            }
        }
        if let Some(failure) = state.refuse_next_query_with.take() {
            return Ok(AuthorityOutcomeV2::KnownFailure(failure));
        }
        if state.refuse_queries {
            return Ok(AuthorityOutcomeV2::Unknown(
                AuthorityUnknownV2::ResponseUnavailable,
            ));
        }
        if let Some(receipt) = state.authority.receipt(operation_id) {
            return Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(
                Box::new(receipt),
            )));
        }
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: snapshot.authority_version(),
            }),
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<
        AuthorityOutcomeV2<crate::authority::ReceiptAckDispositionV2>,
        AuthorityTransportErrorV2,
    > {
        let mut state = self.lock();
        if state.refuse_acknowledgements {
            return Ok(AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::AllocationFailed,
            ));
        }
        if core::mem::take(&mut state.arm_mismatch_next_acknowledgement) {
            state
                .mismatching_receipts
                .insert(retained.locator().operation_id());
        }
        if state
            .mismatching_receipts
            .contains(&retained.locator().operation_id())
        {
            // The receipt stays retained: what the authority holds under this
            // id is not what this locator can discharge, and no retry of the
            // agent's changes that. Pruning it here would make the mismatch
            // transient, which no authority produces.
            return Ok(AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
            ));
        }
        if core::mem::take(&mut state.lose_next_acknowledgement) {
            return Ok(AuthorityOutcomeV2::Unknown(
                AuthorityUnknownV2::ResponseUnavailable,
            ));
        }
        Ok(
            match state.authority.acknowledge_receipt(retained.locator()) {
                Ok(disposition) => AuthorityOutcomeV2::Known(disposition),
                Err(_) => AuthorityOutcomeV2::KnownFailure(
                    AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
                ),
            },
        )
    }

    fn round_trip_bound(&self) -> Duration {
        let mut state = self.lock();
        match state.round_trip_bound_once.take() {
            Some(once) => once,
            None => state.round_trip_bound,
        }
    }
}

/// A port that kills the process -- `std::process::exit(86)` -- the instant a
/// release it forwarded comes back `Known`, before the agent can record the
/// receipt. That is the crash between the dispatch and the acknowledgement:
/// the journal row is written, the authority retains the receipt, and the
/// repository is still open when the process dies.
struct CrashAfterDispatchAuthority<A> {
    inner: A,
}

impl<A> CrashAfterDispatchAuthority<A> {
    const fn new(inner: A) -> Self {
        Self { inner }
    }
}

impl<A: InstanceAuthorityPort> InstanceAuthorityPort for CrashAfterDispatchAuthority<A> {
    fn wire_config(&self) -> DeploymentConfigRevisionV2 {
        self.inner.wire_config()
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        self.inner.snapshot()
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.inner.acquire(intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.inner.renew(intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        let outcome = self.inner.release(intent);
        if matches!(outcome, Ok(AuthorityOutcomeV2::Known(_))) {
            std::process::exit(86);
        }
        outcome
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        self.inner.query(operation_id)
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<
        AuthorityOutcomeV2<crate::authority::ReceiptAckDispositionV2>,
        AuthorityTransportErrorV2,
    > {
        self.inner.acknowledge(retained)
    }

    fn round_trip_bound(&self) -> Duration {
        self.inner.round_trip_bound()
    }
}

/// A port that records the operation id of every acknowledgement it forwards,
/// answered or not, so a test can count how often one obligation was
/// discharged.
struct CountingAuthority<A> {
    inner: A,
    acknowledged: Arc<Mutex<Vec<OperationIdV2>>>,
}

impl<A> CountingAuthority<A> {
    const fn new(inner: A, acknowledged: Arc<Mutex<Vec<OperationIdV2>>>) -> Self {
        Self {
            inner,
            acknowledged,
        }
    }
}

impl<A: InstanceAuthorityPort> InstanceAuthorityPort for CountingAuthority<A> {
    fn wire_config(&self) -> DeploymentConfigRevisionV2 {
        self.inner.wire_config()
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        self.inner.snapshot()
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.inner.acquire(intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.inner.renew(intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.inner.release(intent)
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        self.inner.query(operation_id)
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<
        AuthorityOutcomeV2<crate::authority::ReceiptAckDispositionV2>,
        AuthorityTransportErrorV2,
    > {
        self.acknowledged
            .lock()
            .expect("acknowledgement log poisoned")
            .push(retained.locator().operation_id());
        self.inner.acknowledge(retained)
    }

    fn round_trip_bound(&self) -> Duration {
        self.inner.round_trip_bound()
    }
}

struct PolicyMaterial {
    bundle: SignedPolicyBundle,
    authenticated: AuthenticatedPolicy,
}

fn policy_material(seed: u8) -> TestResult<PolicyMaterial> {
    policy_material_from_text(seed, POLICY)
}

fn policy_material_from_text(seed: u8, document: &str) -> TestResult<PolicyMaterial> {
    let (signing_key, verification_key) = MlDsa65::generate([seed; 32]);
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let written = MlDsa65
        .sign(
            &signing_key,
            &policy_signature_message(document.as_bytes()),
            &[0u8; 32],
            &mut signature,
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if written != ML_DSA_65_SIG_LEN {
        return Err(io::Error::other("unexpected policy signature length").into());
    }
    let authenticated =
        Policy::load_signed(&MlDsa65, &verification_key, document.as_bytes(), &signature)
            .map_err(|error| io::Error::other(error.to_string()))?;
    let bundle = SignedPolicyBundle::new(
        document.as_bytes().to_vec(),
        signature.to_vec(),
        verification_key,
    )?;
    Ok(PolicyMaterial {
        bundle,
        authenticated,
    })
}

struct MigrationMaterial {
    roots: MigrationTrustRoots,
    authority_signing_key: Vec<u8>,
    recovery_signing_key: Vec<u8>,
    genesis: Vec<u8>,
}

fn migration_material(policy: &AuthenticatedPolicy) -> TestResult<MigrationMaterial> {
    let (authority_sk, authority_vk) = MlDsa65::generate([21u8; 32]);
    let (recovery_sk, recovery_vk) = MlDsa65::generate([22u8; 32]);
    let authority_id = MigrationAuthorityKeyId::from_bytes([31u8; 32]);
    let recovery_id = MigrationAuthorityKeyId::from_bytes([32u8; 32]);
    let state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 1,
        chain_id: MigrationChainId::from_bytes([41u8; 32]),
        protocol_id: MigrationProtocolId::from_bytes([42u8; 16]),
        epoch: 1,
        previous_state_digest: MigrationStateDigest::from_bytes([0u8; 32]),
        authority_key_id: authority_id,
        execution_policy_state: policy.trusted_state(),
        posture: MigrationSecurityPosture::new(
            SecurityFloor::Level3,
            ComponentMode::HybridRequired,
        ),
        allowed_suites: MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
    })?;
    let mut signature_output = [0u8; ML_DSA_65_SIG_LEN];
    let certificate = SignedMigrationStateV1::sign(
        StateCertificateKind::Genesis,
        state,
        &MlDsa65,
        &authority_sk,
        &[0u8; 32],
        &mut signature_output,
    )?;
    Ok(MigrationMaterial {
        roots: MigrationTrustRoots::new(authority_id, authority_vk, recovery_id, recovery_vk)?,
        authority_signing_key: authority_sk.to_vec(),
        recovery_signing_key: recovery_sk.to_vec(),
        genesis: certificate.encode()?,
    })
}

struct AgentPair {
    initiator: PolicyAgent<MemoryWitness, MemoryAuthority>,
    responder: PolicyAgent<MemoryWitness, MemoryAuthority>,
    witness: MemoryWitness,
    initiator_authority: MemoryAuthority,
    /// The responder agent's own authority, so a test can drive the responder
    /// side's lease clock exactly as it drives the initiator's.
    responder_authority: MemoryAuthority,
    committed: CommittedMigrationStateV1,
    migration: MigrationMaterial,
    initiator_config: AgentConfig,
    endpoint_policy_bundle: SignedPolicyBundle,
    initiator_repository_path: PathBuf,
    old_snapshot_path: PathBuf,
    initiator_authorization: SessionAuthorization,
    /// The initiator's own signed offer and the responder's, exactly as
    /// `initiator_authorization` was built from them, for tests that frame a
    /// Begin over IPC themselves.
    initiator_signed_offers: (Vec<u8>, Vec<u8>),
    responder_authorization: SessionAuthorization,
    /// A second, independently identified session, for tests that need two
    /// live sessions on one agent.
    second_initiator_authorization: SessionAuthorization,
    second_responder_authorization: SessionAuthorization,
    initiator_public_keys: EncapsulationPublicKeys,
    responder_public_keys: EncapsulationPublicKeys,
}

fn agent_pair(directory: &TestDirectory, session_byte: u8) -> TestResult<AgentPair> {
    agent_pair_with_session_ttl(directory, session_byte, Duration::from_secs(60))
}

fn agent_pair_with_session_ttl(
    directory: &TestDirectory,
    session_byte: u8,
    session_ttl: Duration,
) -> TestResult<AgentPair> {
    agent_pair_with_limits(
        directory,
        session_byte,
        AgentLimits::new(16, 16, session_ttl)?,
    )
}

fn agent_pair_with_limits(
    directory: &TestDirectory,
    session_byte: u8,
    limits: AgentLimits,
) -> TestResult<AgentPair> {
    use std::os::unix::fs::PermissionsExt;

    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let initiator_repository_path = directory.join("initiator.redb");
    let responder_repository_path = directory.join("responder.redb");
    let old_snapshot_path = directory.join("old-snapshot.redb");
    let (initial_repository, head) = StateRepository::provision_new(
        &initiator_repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let committed = initial_repository.committed_state();
    drop(initial_repository);
    for destination in [&responder_repository_path, &old_snapshot_path] {
        fs::copy(&initiator_repository_path, destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    }
    let initiator_repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let responder_repository =
        StateRepository::open_existing(&responder_repository_path, migration.roots.clone())?;
    let witness = MemoryWitness::new(head);
    let (initiator_identity_sk, initiator_identity_vk) = MlDsa65::generate([51u8; 32]);
    let (responder_identity_sk, responder_identity_vk) = MlDsa65::generate([52u8; 32]);
    let initiator_identity_id = MigrationIdentityKeyId::from_bytes([61u8; 32]);
    let responder_identity_id = MigrationIdentityKeyId::from_bytes([62u8; 32]);
    let initiator_config = AgentConfig::new(
        limits,
        EndpointRole::Initiator,
        EndpointIdentity::new(initiator_identity_id, initiator_identity_vk)?,
        EndpointIdentity::new(responder_identity_id, responder_identity_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle.clone(),
    )?;
    let responder_config = AgentConfig::new(
        limits,
        EndpointRole::Responder,
        EndpointIdentity::new(responder_identity_id, responder_identity_vk)?,
        EndpointIdentity::new(initiator_identity_id, initiator_identity_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle.clone(),
    )?;
    let initiator_authority = MemoryAuthority::new()?;
    let responder_authority = MemoryAuthority::new()?;
    let initiator = PolicyAgent::new(
        initiator_repository,
        witness.clone(),
        initiator_authority.clone(),
        initiator_config.clone(),
    )?;
    let responder = PolicyAgent::new(
        responder_repository,
        witness.clone(),
        responder_authority.clone(),
        responder_config,
    )?;
    let initiator_public_keys = initiator.public_keys()?;
    let responder_public_keys = responder.public_keys()?;
    let session_id = MigrationSessionId::from_bytes([session_byte; 32]);
    let initiator_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Initiator,
        sender_identity: initiator_identity_id,
        receiver_identity: responder_identity_id,
        nonce: MigrationNonce::from_bytes([71u8.wrapping_add(session_byte); 32]),
        session_id,
        policy: &policy.authenticated,
        committed,
        keys: &initiator_public_keys,
        signing_key: &initiator_identity_sk,
    })?;
    let responder_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Responder,
        sender_identity: responder_identity_id,
        receiver_identity: initiator_identity_id,
        nonce: MigrationNonce::from_bytes([81u8.wrapping_add(session_byte); 32]),
        session_id,
        policy: &policy.authenticated,
        committed,
        keys: &responder_public_keys,
        signing_key: &responder_identity_sk,
    })?;
    let second_session_id = MigrationSessionId::from_bytes([session_byte.wrapping_add(128); 32]);
    let second_initiator_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Initiator,
        sender_identity: initiator_identity_id,
        receiver_identity: responder_identity_id,
        nonce: MigrationNonce::from_bytes([91u8.wrapping_add(session_byte); 32]),
        session_id: second_session_id,
        policy: &policy.authenticated,
        committed,
        keys: &initiator_public_keys,
        signing_key: &initiator_identity_sk,
    })?;
    let second_responder_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Responder,
        sender_identity: responder_identity_id,
        receiver_identity: initiator_identity_id,
        nonce: MigrationNonce::from_bytes([101u8.wrapping_add(session_byte); 32]),
        session_id: second_session_id,
        policy: &policy.authenticated,
        committed,
        keys: &responder_public_keys,
        signing_key: &responder_identity_sk,
    })?;
    Ok(AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        responder_authority,
        committed,
        migration,
        initiator_config,
        endpoint_policy_bundle: policy.bundle,
        initiator_repository_path,
        old_snapshot_path,
        initiator_authorization: SessionAuthorization::new(
            initiator_offer.clone(),
            responder_offer.clone(),
        )?,
        initiator_signed_offers: (initiator_offer.clone(), responder_offer.clone()),
        responder_authorization: SessionAuthorization::new(responder_offer, initiator_offer)?,
        second_initiator_authorization: SessionAuthorization::new(
            second_initiator_offer.clone(),
            second_responder_offer.clone(),
        )?,
        second_responder_authorization: SessionAuthorization::new(
            second_responder_offer,
            second_initiator_offer,
        )?,
        initiator_public_keys,
        responder_public_keys,
    })
}

struct SignedOfferInput<'a> {
    role: EndpointRole,
    sender_identity: MigrationIdentityKeyId,
    receiver_identity: MigrationIdentityKeyId,
    nonce: MigrationNonce,
    session_id: MigrationSessionId,
    policy: &'a AuthenticatedPolicy,
    committed: CommittedMigrationStateV1,
    keys: &'a EncapsulationPublicKeys,
    signing_key: &'a [u8],
}

fn signed_offer(input: SignedOfferInput<'_>) -> TestResult<Vec<u8>> {
    let SignedOfferInput {
        role,
        sender_identity,
        receiver_identity,
        nonce,
        session_id,
        policy,
        committed,
        keys,
        signing_key,
    } = input;
    let key_share = EndpointKeyShareV1::new(keys.pq(), keys.traditional())?;
    let offer = CapabilityOfferV1::from_authenticated_state(CapabilityOfferInputV1 {
        protocol_id: committed.state().protocol_id(),
        session_id,
        sender_role: role,
        sender_identity,
        receiver_identity,
        sender_nonce: nonce,
        sender_policy: policy,
        committed_state: committed,
        offered_suites: MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
        sender_key_share: &key_share,
    })?;
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed =
        SignedCapabilityOfferV1::sign(offer, &MlDsa65, signing_key, &[0u8; 32], &mut signature)?;
    Ok(signed.encode()?)
}

fn initiator_encapsulation(
    result: BeginEncapsulationResult,
) -> TestResult<InitiatorEncapsulationResult> {
    match result {
        BeginEncapsulationResult::Initiator(result) => Ok(result),
        BeginEncapsulationResult::Responder(_) => {
            Err(io::Error::other("initiator returned responder begin state").into())
        }
    }
}

/// The cheapest lease-guarded operation: it renews, journals, and then fails
/// on the absence of a pending transition before touching anything else.
fn drive_one_lease_renew(agent: &PolicyAgent<MemoryWitness, MemoryAuthority>) -> TestResult {
    assert_eq!(
        agent.reconcile_transition().err(),
        Some(AgentError::Repository(RepositoryError::NoPendingTransition))
    );
    Ok(())
}

fn responder_encapsulation(
    result: BeginEncapsulationResult,
) -> TestResult<ResponderEncapsulationResult> {
    match result {
        BeginEncapsulationResult::Responder(result) => Ok(result),
        BeginEncapsulationResult::Initiator(_) => {
            Err(io::Error::other("responder returned initiator begin state").into())
        }
    }
}

fn initiator_decapsulation(
    result: BeginDecapsulationResult,
) -> TestResult<InitiatorDecapsulationResult> {
    match result {
        BeginDecapsulationResult::Initiator(result) => Ok(result),
        BeginDecapsulationResult::Responder(_) => {
            Err(io::Error::other("initiator returned responder begin state").into())
        }
    }
}

fn responder_decapsulation(
    result: BeginDecapsulationResult,
) -> TestResult<ResponderDecapsulationResult> {
    match result {
        BeginDecapsulationResult::Responder(result) => Ok(result),
        BeginDecapsulationResult::Initiator(_) => {
            Err(io::Error::other("responder returned initiator begin state").into())
        }
    }
}

fn signed_advance(
    current: MigrationStateV1,
    migration: &MigrationMaterial,
    posture: MigrationSecurityPosture,
    allowed_suites: MigrationSuiteSet,
) -> TestResult<(MigrationStateV1, Vec<u8>)> {
    signed_advance_with_execution(
        current,
        migration,
        current.execution_policy_state(),
        posture,
        allowed_suites,
    )
}

fn signed_advance_with_execution(
    current: MigrationStateV1,
    migration: &MigrationMaterial,
    execution_policy_state: TrustedPolicyState,
    posture: MigrationSecurityPosture,
    allowed_suites: MigrationSuiteSet,
) -> TestResult<(MigrationStateV1, Vec<u8>)> {
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: current
            .global_generation()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("generation overflow"))?,
        chain_id: current.chain_id(),
        protocol_id: current.protocol_id(),
        epoch: current
            .epoch()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("epoch overflow"))?,
        previous_state_digest: current.digest()?,
        authority_key_id: current.authority_key_id(),
        execution_policy_state,
        posture,
        allowed_suites,
    })?;
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let certificate = SignedMigrationStateV1::sign(
        StateCertificateKind::Advance,
        next,
        &MlDsa65,
        &migration.authority_signing_key,
        &[0u8; 32],
        &mut signature,
    )?;
    Ok((next, certificate.encode()?))
}

impl AgentPair {
    fn committed_head(&self) -> TestResult<StateHead> {
        let repository =
            StateRepository::open_existing(&self.old_snapshot_path, self.migration.roots.clone())?;
        repository.head().map_err(Into::into)
    }
}

/// Self-checks of the fixture hooks above. Each pins the exact semantics the
/// lifecycle tests rely on -- what a hook consumes, what it counts, and what
/// it leaves for the next call -- against the fixture alone.
mod fixture_hooks {
    use super::*;

    /// The authority's current version and configuration, read without going
    /// through the port, so the read itself trips no snapshot hook.
    fn authority_version(
        authority: &MemoryAuthority,
    ) -> TestResult<(u64, u64, DeploymentConfigRevisionV2)> {
        let mut state = authority.lock();
        let clock = FixedClock(state.now_millis);
        let snapshot = state.authority.snapshot(&clock)?;
        Ok((
            snapshot.authority_version(),
            snapshot.lease_generation(),
            state.config,
        ))
    }

    /// An acquire at the authority's current version and generation, as a
    /// fresh process identified by `byte` would build one.
    fn acquire_intent(authority: &MemoryAuthority, byte: u8) -> TestResult<AuthorityIntentV2> {
        let (version, generation, config) = authority_version(authority)?;
        Ok(AuthorityIntentV2::new(
            OperationIdV2::new(version, [byte; 32])?,
            version,
            config,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: generation,
                instance_id: ProcessInstanceIdV2::from_bytes([byte; 32])?,
            },
        )?)
    }

    /// A mutation under the fence of the lease the authority holds now.
    fn fenced_intent(
        authority: &MemoryAuthority,
        byte: u8,
        mutation: impl FnOnce(InstanceLeaseV2) -> AuthorityMutationV2,
    ) -> TestResult<AuthorityIntentV2> {
        let lease = authority
            .active_lease()?
            .ok_or_else(|| io::Error::other("no active lease to act on"))?;
        let (version, _, config) = authority_version(authority)?;
        Ok(AuthorityIntentV2::new(
            OperationIdV2::new(version, [byte; 32])?,
            version,
            config,
            mutation(lease),
        )?)
    }

    fn applied(
        outcome: Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2>,
    ) -> TestResult<AuthorityReceiptV2> {
        match outcome? {
            AuthorityOutcomeV2::Known(receipt)
                if receipt.disposition() == AuthorityDispositionV2::Applied =>
            {
                Ok(receipt)
            }
            other => {
                Err(io::Error::other(format!("expected an applied receipt, got {other:?}")).into())
            }
        }
    }

    fn known_snapshot(
        outcome: Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2>,
    ) -> TestResult<AuthoritySnapshotV2> {
        match outcome? {
            AuthorityOutcomeV2::Known(snapshot) => Ok(snapshot),
            other => {
                Err(io::Error::other(format!("expected a known snapshot, got {other:?}")).into())
            }
        }
    }

    #[test]
    fn lease_call_hooks_fire_once_and_only_for_the_calls_they_select() -> TestResult {
        let authority = MemoryAuthority::new()?;

        // A `Release` filter lets an acquire through untouched and stays armed.
        authority.lose_next_lease_call_before_apply(LeaseCallFilter::Release);
        applied(authority.acquire(acquire_intent(&authority, 1)?))?;
        assert_eq!(authority.lease_call_count(), 1);
        assert_eq!(authority.lost_operation(), None);

        // The release it selects is lost before apply: not applied, not
        // counted, its id kept; the same call goes through once the hook is
        // spent.
        let release = fenced_intent(&authority, 2, |lease| AuthorityMutationV2::ReleaseLease {
            fence: lease.fence(),
        })?;
        assert_eq!(
            authority.release(release)?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::RequestWriteIndeterminate)
        );
        assert_eq!(authority.lost_operation(), Some(release.operation_id()));
        assert_eq!(authority.lease_call_count(), 1);
        assert!(
            authority.active_lease()?.is_some(),
            "a call lost before apply must not have been applied"
        );
        applied(authority.release(release))?;
        assert_eq!(authority.lease_call_count(), 2);
        assert!(authority.active_lease()?.is_none());

        // Not sent: a transport error, not counted, spent by the one call.
        authority.fail_next_lease_call_before_send(LeaseCallFilter::Acquire);
        let acquire = acquire_intent(&authority, 3)?;
        assert_eq!(
            authority.acquire(acquire),
            Err(AuthorityTransportErrorV2::NotSent)
        );
        assert_eq!(authority.lease_call_count(), 2);
        applied(authority.acquire(acquire))?;
        assert_eq!(authority.lease_call_count(), 3);

        // Refused closed: the failure named, nothing applied, not counted.
        authority.refuse_next_lease_call_with(AuthorityKnownFailureV2::RateLimited);
        let release = fenced_intent(&authority, 4, |lease| AuthorityMutationV2::ReleaseLease {
            fence: lease.fence(),
        })?;
        assert_eq!(
            authority.release(release)?,
            AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::RateLimited)
        );
        assert_eq!(authority.lease_call_count(), 3);
        assert!(authority.active_lease()?.is_some());

        // `Any` selects a renew as well.
        authority.lose_next_lease_call_before_apply(LeaseCallFilter::Any);
        let renew = fenced_intent(&authority, 5, |lease| AuthorityMutationV2::RenewLease {
            fence: lease.fence(),
        })?;
        assert_eq!(
            authority.renew(renew)?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::RequestWriteIndeterminate)
        );
        assert_eq!(authority.lost_operation(), Some(renew.operation_id()));
        assert_eq!(authority.lease_call_count(), 3);
        authority.advance_clock(1);
        applied(authority.renew(renew))?;
        assert_eq!(authority.lease_call_count(), 4);
        Ok(())
    }

    #[test]
    fn a_lost_acquire_applies_and_leaves_the_queries_refused() -> TestResult {
        let authority = MemoryAuthority::new()?;
        authority.lose_next_acquire_and_queries();
        let acquire = acquire_intent(&authority, 9)?;
        assert!(matches!(
            authority.acquire(acquire)?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        ));
        // Applied and counted: only the answer was lost.
        assert_eq!(authority.lease_call_count(), 1);
        assert_eq!(
            authority
                .active_lease()?
                .map(|lease| lease.fence().instance_id()),
            Some(ProcessInstanceIdV2::from_bytes([9u8; 32])?)
        );
        // And every query after it stays refused until a test says otherwise.
        assert!(matches!(
            authority.query(acquire.operation_id())?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        ));
        authority.refuse_queries(false);
        assert!(matches!(
            authority.query(acquire.operation_id())?,
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(_))
        ));
        assert_eq!(authority.query_call_count(), 2);
        Ok(())
    }

    #[test]
    fn query_and_acknowledgement_hooks_answer_exactly_once() -> TestResult {
        let authority = MemoryAuthority::new()?;
        let acquire = acquire_intent(&authority, 6)?;
        let receipt = applied(authority.acquire(acquire))?;
        let retained = DurablyRetainedAuthorityReceiptV2::after_durable_commit(receipt)?;

        // A refused query is counted and answered with the failure named;
        // the next one is answered from the table again.
        authority.refuse_next_query_with(AuthorityKnownFailureV2::RateLimited);
        assert_eq!(
            authority.query(acquire.operation_id())?,
            AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::RateLimited)
        );
        assert_eq!(authority.query_call_count(), 1);
        assert!(matches!(
            authority.query(acquire.operation_id())?,
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(_))
        ));
        assert_eq!(authority.query_call_count(), 2);

        // A lost acknowledgement leaves the receipt retained.
        authority.lose_next_acknowledgement();
        assert!(matches!(
            authority.acknowledge(&retained)?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        ));
        assert_eq!(authority.receipt_count()?, 1);

        // A mismatched acknowledgement does not prune: the receipt stays
        // retained, exactly as an authority holding a receipt this locator
        // cannot discharge leaves it.
        authority.mismatch_next_acknowledgement();
        assert!(matches!(
            authority.acknowledge(&retained)?,
            AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch
            )
        ));
        assert_eq!(authority.receipt_count()?, 1);

        // And the condition is persistent: this locator can never discharge
        // what the authority holds, so every later attempt answers the same.
        assert!(matches!(
            authority.acknowledge(&retained)?,
            AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch
            )
        ));
        assert_eq!(authority.receipt_count()?, 1);

        // A receipt that was never armed acknowledges cleanly, so the hook
        // refuses one locator rather than every acknowledgement. The clock has
        // to move first, or the renew extends nothing and is rejected.
        authority.advance_clock(1_000);
        let renew = fenced_intent(&authority, 9, |lease| AuthorityMutationV2::RenewLease {
            fence: lease.fence(),
        })?;
        let other_retained = DurablyRetainedAuthorityReceiptV2::after_durable_commit(applied(
            authority.renew(renew),
        )?)?;
        assert!(matches!(
            authority.acknowledge(&other_retained)?,
            AuthorityOutcomeV2::Known(_)
        ));
        Ok(())
    }

    #[test]
    fn snapshot_hooks_count_every_request_and_consume_in_order() -> TestResult {
        let authority = MemoryAuthority::new()?;
        applied(authority.acquire(acquire_intent(&authority, 7)?))?;
        let epoch = authority.lock().now_millis;

        // Refused snapshots are counted, and consume none of the queue.
        authority.advance_clock_before_next_snapshot(10);
        authority.advance_clock_before_next_snapshot(20);
        authority.delay_next_snapshot(Duration::from_millis(1));
        authority.refuse_snapshots(true);
        assert!(matches!(
            authority.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        ));
        assert_eq!(authority.snapshot_call_count(), 1);
        assert_eq!(authority.lock().now_millis, epoch);
        assert!(authority.snapshot_delay_armed());

        // The queue is paid one step per computed snapshot, in order, and
        // the delay by the first of them.
        authority.refuse_snapshots(false);
        let first = known_snapshot(authority.snapshot())?;
        assert_eq!(authority.lock().now_millis, epoch + 10);
        assert!(!authority.snapshot_delay_armed());
        known_snapshot(authority.snapshot())?;
        assert_eq!(authority.lock().now_millis, epoch + 30);
        known_snapshot(authority.snapshot())?;
        assert_eq!(authority.lock().now_millis, epoch + 30);
        assert_eq!(authority.snapshot_call_count(), 4);

        // One passes, the next is lost, then answers resume.
        authority.lose_snapshot_after(1);
        known_snapshot(authority.snapshot())?;
        assert!(matches!(
            authority.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        ));
        known_snapshot(authority.snapshot())?;

        // One passes with our lease intact, the next sees the takeover.
        authority.successor_acquires_before_snapshot_after(1);
        let intact = known_snapshot(authority.snapshot())?;
        assert!(intact.active_lease().is_some());
        assert_eq!(intact.lease_generation(), first.lease_generation());
        let taken = known_snapshot(authority.snapshot())?;
        assert!(taken.active_lease().is_none());
        assert_eq!(taken.lease_generation(), first.lease_generation() + 1);

        assert_eq!(authority.round_trip_bound(), Duration::ZERO);
        authority.set_round_trip_bound(Duration::from_secs(5));
        assert_eq!(authority.round_trip_bound(), Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn witness_hooks_fail_reads_step_the_authority_and_delay_the_compare() -> TestResult {
        let head = StateHead::new(
            StateRevision::new(1, 1, [7u8; 32])?,
            FenceToken::generate()?,
        );
        let witness = MemoryWitness::new(head);
        witness.fail_reads.store(true, Ordering::Release);
        assert_eq!(witness.read_head(), Err(WitnessError::Unavailable));
        witness.fail_reads.store(false, Ordering::Release);
        assert_eq!(witness.read_head()?, head);

        // The authority step lands inside the read, once.
        let authority = MemoryAuthority::new()?;
        applied(authority.acquire(acquire_intent(&authority, 8)?))?;
        *witness
            .advance_authority_on_read
            .lock()
            .expect("memory witness hook poisoned") = Some(authority.clone());
        assert_eq!(witness.read_head()?, head);
        assert!(
            authority.active_lease()?.is_none(),
            "the read must let the authority's lease run out"
        );
        assert_eq!(witness.read_head()?, head);

        assert_eq!(witness.round_trip_bound(), Duration::ZERO);
        witness.set_round_trip_bound(Duration::from_secs(5));
        assert_eq!(witness.round_trip_bound(), Duration::from_secs(5));

        // The delay is paid by the next compare, and only by that one.
        let intent = WitnessIntent::new(
            OperationId::generate()?,
            StateAdvance::new(
                TransitionKind::Advance,
                head.revision(),
                StateRevision::new(2, 2, [8u8; 32])?,
            )?,
            head.fence(),
            FenceToken::generate()?,
        )?;
        witness.delay_next_compare_and_advance(Duration::from_millis(50));
        assert!(witness.compare_delay_armed());
        let started = Instant::now();
        assert!(matches!(
            witness.compare_and_advance(intent)?,
            WitnessOutcome::Known(_)
        ));
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(matches!(
            witness.compare_and_advance(intent)?,
            WitnessOutcome::Known(_)
        ));
        // "Paid once" is a fact about the hook's state, not about how fast the
        // second call returned: an in-memory compare that lost the CPU for
        // fifty milliseconds is not a re-armed delay.
        assert!(
            !witness.compare_delay_armed(),
            "the first compare must consume the delay, so the second pays nothing"
        );
        Ok(())
    }

    #[test]
    fn the_lease_journal_write_hook_fails_the_next_write_once() -> TestResult {
        let directory = TestDirectory::new()?;
        let pair = agent_pair(&directory, 203)?;

        // At the repository: refused before anything is committed, once.
        let repository =
            StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
        repository.fail_next_lease_journal_write_for_test();
        let row = OperationIdV2::new(1, [0x66u8; 32])?;
        assert_eq!(
            repository.journal_lease_intent(row, &[]),
            Err(RepositoryError::CorruptStore)
        );
        assert!(repository.journaled_lease_intents()?.is_empty());
        repository.journal_lease_intent(row, &[])?;
        assert_eq!(repository.journaled_lease_intents()?, vec![row]);

        // Through the agent: the next lease operation's journal write fails
        // the same way, and the hook is spent by it.
        pair.initiator.fail_next_lease_journal_write_for_test()?;
        assert_eq!(
            pair.initiator.reconcile_transition().err(),
            Some(AgentError::Repository(RepositoryError::CorruptStore))
        );
        drive_one_lease_renew(&pair.initiator)?;
        Ok(())
    }

    #[test]
    fn a_framed_begin_decodes_as_the_ipc_server_encodes_it() -> TestResult {
        let directory = TestDirectory::new()?;
        let pair = agent_pair(&directory, 204)?;
        let (client_signing_key, client_verification_key) = MlDsa65::generate([0x61u8; 32]);
        let (server_signing_key, server_verification_key) = MlDsa65::generate([0x62u8; 32]);
        let mut server = crate::ipc::UnixIpcServer::new_for_test(
            pair.initiator,
            client_verification_key,
            ZeroizingBytes::from_bytes(server_signing_key),
            server_verification_key,
        )?;
        let nonce = [0x63u8; 32];
        let mut transport = CaptureTransport {
            input: Cursor::new(framed_begin(
                &client_signing_key,
                nonce,
                &pair.initiator_signed_offers,
                &pair.responder_public_keys,
            )?),
            output: Vec::new(),
        };
        server.handle_io_for_test(&mut transport)?;
        assert_eq!(server.agent_for_test().pending_session_count(), 1);
        let DecodedBeginEncapsulation {
            handle,
            pq_ciphertext,
            traditional_ciphertext,
            initiator_finished,
        } = decode_begin_encapsulation_response(
            &transport.output,
            &server_verification_key,
            transport.input.get_ref(),
        )?;

        // The decoded fields are the real ones, not merely the right sizes:
        // the responder confirms the session from them, and the initiator
        // accepts under the decoded handle.
        let ciphertexts =
            EncapsulationCiphertexts::from_slices(&pq_ciphertext, &traditional_ciphertext)
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
            BeginDecapsulation::new(pair.responder_authorization, ciphertexts),
        )?)?;
        let accepted = pair.responder.accept_initiator_finished(
            decapsulated.handle,
            InitiatorFinishedV1::from_bytes(initiator_finished),
        )?;
        server.agent_for_test().accept_responder_finished(
            crate::PendingSessionHandle::decode(handle)?,
            accepted.responder_finished,
        )?;
        assert_eq!(server.agent_for_test().pending_session_count(), 0);
        assert_eq!(server.agent_for_test().confirmed_key_count(), 1);
        Ok(())
    }
}
