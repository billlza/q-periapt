use std::collections::HashMap;
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
    AuthorityErrorV2, AuthorityIntentV2, AuthorityLimitsV2, AuthorityQueryResultV2,
    AuthorityReceiptV2, AuthoritySnapshotV2, AuthorityStateV2, DeploymentConfigRevisionV2,
    InstanceLeaseV2, OperationIdV2, StateFenceV2, StateHeadV2, StateRevisionV2,
    TrustedClockErrorV2, TrustedClockV2,
};
use crate::authority_protocol::{
    AuthorityKnownFailureV2, AuthorityOutcomeV2, AuthorityUnknownV2,
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
    InitiatorEncapsulationResult, PolicyAgent, ResponderDecapsulationResult,
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

fn decode_responder_acceptance_response(
    framed: &[u8],
    verification_key: &[u8],
    expected_nonce: [u8; 32],
) -> TestResult<([u8; 32], [u8; 32])> {
    let envelope = read_frame(&mut Cursor::new(framed))
        .map_err(|error| io::Error::other(format!("IPC response framing failed: {error:?}")))?;
    let body = verify_envelope(&envelope, verification_key)
        .map_err(|error| io::Error::other(format!("IPC response signature failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC response domain failed: {error:?}")))?;
    let nonce: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response nonce failed: {error:?}")))?;
    assert_eq!(nonce, expected_nonce);
    let _: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response digest failed: {error:?}")))?;
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

#[derive(Clone)]
struct MemoryWitness {
    state: Arc<Mutex<MemoryWitnessState>>,
    unknown_after_apply: Arc<AtomicBool>,
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
        }
    }

    fn make_next_unknown(&self) {
        self.unknown_after_apply.store(true, Ordering::Release);
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
        Ok(self
            .state
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .head)
    }

    fn compare_and_advance(&self, intent: WitnessIntent) -> Result<WitnessOutcome, WitnessError> {
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
        Ok(WitnessOutcome::Known(Box::new(
            state
                .operations
                .get(&operation_id)
                .copied()
                .unwrap_or_else(|| WitnessReceipt::not_applied(state.head)),
        )))
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
    advance_before_snapshot: u64,
    snapshot_delay: Duration,
    /// Before the next snapshot: let the current lease expire, have a fresh
    /// instance acquire the next generation, and let that lease expire too.
    /// The snapshot then reports no active lease *and* an advanced generation.
    successor_before_snapshot: bool,
    /// Before the next snapshot: replace the authority with one provisioned
    /// fresh, as a restore from before this instance's acquire would leave it.
    /// The snapshot then reports no lease and a generation *behind* ours.
    rollback_before_snapshot: bool,
    /// Answer every acknowledgement with a retryable failure, so receipts stay
    /// retained on both sides -- the authority's table and the agent's queue.
    refuse_acknowledgements: bool,
    /// Answer every receipt query as indeterminate, as an authority that
    /// cannot be reached would.
    refuse_queries: bool,
    /// Lease mutations this authority has been asked to apply, whatever the
    /// answer. A refusal made *before* dispatch leaves this untouched.
    lease_calls: u64,
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
                advance_before_snapshot: 0,
                snapshot_delay: Duration::ZERO,
                successor_before_snapshot: false,
                rollback_before_snapshot: false,
                refuse_acknowledgements: false,
                refuse_queries: false,
                lease_calls: 0,
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

    /// Lease mutations this authority has been asked to apply so far.
    fn lease_call_count(&self) -> u64 {
        self.lock().lease_calls
    }

    /// Receipts the authority is still retaining, awaiting acknowledgement.
    fn receipt_count(&self) -> TestResult<usize> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(state.authority.snapshot(&clock)?.receipt_count())
    }

    /// Between the agent's renew and its coverage snapshot, let its lease
    /// expire and have another instance acquire -- and lapse -- the next
    /// generation. This is what a real takeover looks like from the snapshot:
    /// no active lease, but a generation that has moved past the agent's.
    fn successor_acquires_before_next_snapshot(&self) {
        self.lock().successor_before_snapshot = true;
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
            crate::authority::AuthorityMutationV2::AcquireLease {
                expected_lease_generation: current.lease_generation(),
                instance_id: crate::authority::ProcessInstanceIdV2::from_bytes([0x5Au8; 32])?,
            },
        )?;
        let receipt = state.authority.apply(&clock, intent)?;
        assert!(
            matches!(
                receipt.disposition(),
                crate::authority::AuthorityDispositionV2::Applied
            ),
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

    /// Advance the authority clock once, just before the next snapshot is
    /// computed, so the snapshot reports a lease with almost no life left.
    ///
    /// This is the real sequence, not a contrived one: the renew succeeds and
    /// then time passes before the agent learns the expiry. Advancing the clock
    /// up front cannot reproduce it, because the renew itself resets the expiry
    /// to `now + ttl`.
    fn advance_clock_before_next_snapshot(&self, delta_millis: u64) {
        self.lock().advance_before_snapshot = delta_millis;
    }

    /// Make the next snapshot take real time, the way a network round trip
    /// does. The coverage anchor is captured before the request is sent, so a
    /// slow snapshot spends the budget it is being asked to report -- which is
    /// the conservative behaviour the anchor exists to produce.
    fn delay_next_snapshot(&self, delay: Duration) {
        self.lock().snapshot_delay = delay;
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
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        state.lease_calls += 1;
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
        let pending = core::mem::take(&mut state.advance_before_snapshot);
        state.now_millis = state.now_millis.saturating_add(pending);
        if core::mem::take(&mut state.successor_before_snapshot) {
            Self::install_successor(&mut state).expect("successor hook failed");
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
        self.lease_call(intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(intent)
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
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
        Ok(
            match state.authority.acknowledge_receipt(retained.locator()) {
                Ok(disposition) => AuthorityOutcomeV2::Known(disposition),
                Err(_) => AuthorityOutcomeV2::KnownFailure(
                    AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
                ),
            },
        )
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
    committed: CommittedMigrationStateV1,
    migration: MigrationMaterial,
    initiator_config: AgentConfig,
    endpoint_policy_bundle: SignedPolicyBundle,
    initiator_repository_path: PathBuf,
    old_snapshot_path: PathBuf,
    initiator_authorization: SessionAuthorization,
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
    let limits = AgentLimits::new(16, 16, session_ttl)?;
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
