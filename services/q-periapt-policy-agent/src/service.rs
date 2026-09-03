//! Single-linearizer policy, transition, KEM, and mutual-confirmation service.

use core::fmt;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use q_periapt_backends::{MlDsa65, Sha3_256Xof, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::Profile;
use q_periapt_migration::{
    Abi2MigrationApplicationContextV2, AcceptedSessionKeyV1, AuthenticatedMigrationContextV2Input,
    AuthenticatedNegotiationInputV1, AuthenticatedNegotiationV1, EndpointKeyShareV1, EndpointRole,
    InitiatorAwaitingResponderFinishedV1, InitiatorConfirmationV1, InitiatorFinishedV1,
    MigrationContextV2, MigrationIdentityKeyId, PostKemTranscriptV1, PreKemTranscriptV1,
    ResponderAwaitingInitiatorFinishedV1, ResponderFinishedV1, SignedCapabilityOfferV1,
};
use q_periapt_policy::{AuthenticatedPolicy, HybridSuite, KeyFormat, Policy};

use crate::authority::{
    AuthorityDispositionV2, AuthorityIntentV2, AuthorityMutationV2, AuthorityQueryResultV2,
    AuthorityReceiptV2, AuthorityRejectionV2, AuthoritySnapshotV2, DeploymentConfigRevisionV2,
    InstanceFenceV2, OperationIdV2, ProcessInstanceIdV2,
};
use crate::authority_protocol::{
    AuthorityKnownFailureV2, AuthorityOutcomeV2, DurablyRetainedAuthorityReceiptV2,
};
use crate::authority_transport::InstanceAuthorityPort;
use crate::crypto::{
    Abi2Engine, Abi2EngineError, EncapsulationCiphertexts, EncapsulationPublicKeys,
};
use crate::repository::{RepositoryError, StateRepository, DURABLE_COMMIT_RESERVE};
use crate::types::{SessionId, StateHead};
use crate::witness::{
    WitnessDisposition, WitnessError, WitnessOutcome, WitnessPort, WitnessReceipt,
};

pub(crate) mod lease;

use self::lease::{
    acquire_instance_lease, acquire_instance_lease_within, ensure_instance_lease,
    ensure_may_retain, erase_all_secrets, forget_settled, prove_lease_covers_retention,
    release_lease_state, InstanceLeaseState, LeasePhase, OperationPlan,
};

const MAX_SIGNED_OFFER_BYTES: usize = 16 * 1024;
const HARD_MAX_SESSIONS: usize = 1024;
const HARD_MAX_CONFIRMED_KEYS: usize = 1024;
const MAX_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Domain of the nonce-free digest that identifies an exact Begin retry. The
/// tags are the IPC command bytes of the two Begin commands, so a record left
/// by one command can never answer the other under the same offers. Every
/// caller-supplied input that shapes a Begin response is in the digest; a new
/// one must be added there, or an exact retry could answer a different
/// request.
const BEGIN_REPLAY_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-BEGIN-REPLAY/v1";
const BEGIN_ENCAPSULATION_TAG: [u8; 1] = [2];
const BEGIN_DECAPSULATION_TAG: [u8; 1] = [3];
/// The end-to-end budget an operation gets when its caller gives it no
/// deadline of its own: the plain (non-`_until`) methods, and the
/// constructor's own lease work. The IPC server never relies on it; every
/// request it serves carries the request's deadline.
const DEFAULT_OPERATION_BUDGET: Duration = Duration::from_secs(60);
/// How long `lock_until` sleeps between two attempts to take the agent's
/// linearizer while another operation holds it.
///
/// `std::sync::Mutex` has no timed acquisition and this workspace pins and
/// justifies every dependency, so the bounded wait is built from `try_lock`
/// and this pause. It bounds only how late a waiter notices the lock is free,
/// never the total wait, which the caller's own deadline clamps. One
/// millisecond is the order of the shortest critical section this lock has --
/// one `Durability::Immediate` two-phase commit -- so a waiter behind one
/// durable write is not made to wait several times the work it waits for, and
/// it is three orders of magnitude below the five-second port bounds every
/// `OperationPlan` reserve is built from, so it perturbs no admission. The
/// cost is at most one wake-up per millisecond of contention, on a lock the
/// single-threaded serving loop never contends at all.
const LINEARIZER_POLL_PAUSE: Duration = Duration::from_millis(1);

/// The one end-to-end deadline of the operation currently holding the
/// agent's lock.
///
/// Every wait the operation performs is admitted against it first: the
/// acquisition of the agent's one linearizer, each authority and witness
/// round trip, and the retention gate before a secret becomes reachable. A
/// call starts only if the port's own bound on that call ends before the
/// deadline, so an admitted call always finishes in time and a refusal costs
/// nothing. Local work is not admitted, with one exception: where a durable
/// commit stands between the admission and the call -- the lease-intent
/// journal before a lease mutation, the prepared intent before a transition's
/// CAS -- that commit is admitted with the call at `DURABLE_COMMIT_RESERVE`,
/// so the guarantee holds under that stated commit-latency model and not
/// otherwise. The refusal is [`AgentError::OperationDeadlineExceeded`].
///
/// So this bounds the waits an operation enters, not the wall clock it takes.
/// Besides the modelled reserve above, the erase of expired sessions is
/// charged to no deadline whatever: it is one durable commit per session and
/// nothing about it may be skipped to fit a budget, so both the idle sweep
/// ([`PolicyAgent::expire_idle_sessions`], which installs a deadline already
/// reached) and the purge the heaviest request paths run on entry sit outside
/// this. The service manager's stop timeout is what carries that work.
///
/// `std::sync::Mutex` has no timed acquisition, so the lock is polled rather
/// than blocked on; the door is `admit(Duration::ZERO)` and the wait ends at
/// the deadline whatever the holder is doing.
#[derive(Clone, Copy)]
struct OperationDeadline {
    at: Instant,
}

impl OperationDeadline {
    /// A deadline `budget` from now.
    fn fresh(budget: Duration) -> Result<Self, AgentError> {
        Instant::now()
            .checked_add(budget)
            .map(|at| Self { at })
            .ok_or(AgentError::InvalidConfiguration)
    }

    /// What is left of the deadline, or `None` once it is reached.
    ///
    /// A `Some` is never zero, so a caller that waits for what this reports
    /// always makes progress.
    fn remaining(self) -> Option<Duration> {
        self.at
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// Admit work that blocks for at most `bound`: `Ok` only if it can end
    /// strictly before the deadline. A zero bound against a deadline already
    /// reached is refused too, which is what makes this usable as the final
    /// gate before retention and as the gate on the lock itself.
    fn admit(self, bound: Duration) -> Result<(), AgentError> {
        if self.remaining().is_some_and(|left| bound < left) {
            Ok(())
        } else {
            Err(AgentError::OperationDeadlineExceeded)
        }
    }
}

/// One exact signed policy document and its pinned ML-DSA-65 root.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedPolicyBundle {
    document: Vec<u8>,
    signature: Vec<u8>,
    verification_key: [u8; ML_DSA_65_VK_LEN],
}

impl fmt::Debug for SignedPolicyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedPolicyBundle([redacted])")
    }
}

impl SignedPolicyBundle {
    /// Validate bounded exact policy material. Authentication occurs at agent construction.
    pub fn new(
        document: Vec<u8>,
        signature: Vec<u8>,
        verification_key: [u8; ML_DSA_65_VK_LEN],
    ) -> Result<Self, AgentError> {
        if document.is_empty()
            || document.len() > q_periapt_ffi_abi2::Q_PERIAPT_MAX_SIGNED_POLICY_BYTES
            || signature.len() != ML_DSA_65_SIG_LEN
            || verification_key.iter().all(|byte| *byte == 0)
        {
            return Err(AgentError::InvalidConfiguration);
        }
        Ok(Self {
            document,
            signature,
            verification_key,
        })
    }

    fn authenticate(&self) -> Result<AuthenticatedPolicy, AgentError> {
        Policy::load_signed(
            &MlDsa65,
            &self.verification_key,
            &self.document,
            &self.signature,
        )
        .map_err(|_| AgentError::InvalidConfiguration)
    }
}

/// One pinned endpoint identity used only to verify capability envelopes.
#[derive(Clone, Eq, PartialEq)]
pub struct EndpointIdentity {
    key_id: MigrationIdentityKeyId,
    verification_key: [u8; ML_DSA_65_VK_LEN],
}

impl fmt::Debug for EndpointIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointIdentity([redacted])")
    }
}

impl EndpointIdentity {
    /// Pin a nonzero identity identifier and ML-DSA-65 verification key.
    pub fn new(
        key_id: MigrationIdentityKeyId,
        verification_key: [u8; ML_DSA_65_VK_LEN],
    ) -> Result<Self, AgentError> {
        if key_id.as_bytes().iter().all(|byte| *byte == 0)
            || verification_key.iter().all(|byte| *byte == 0)
        {
            return Err(AgentError::InvalidConfiguration);
        }
        Ok(Self {
            key_id,
            verification_key,
        })
    }
}

/// Explicit in-memory resource and lifetime bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentLimits {
    max_pending_sessions: usize,
    max_confirmed_keys: usize,
    session_ttl: Duration,
}

impl AgentLimits {
    /// Construct nonzero bounds no larger than the reference hard limits.
    pub fn new(
        max_pending_sessions: usize,
        max_confirmed_keys: usize,
        session_ttl: Duration,
    ) -> Result<Self, AgentError> {
        if max_pending_sessions == 0
            || max_pending_sessions > HARD_MAX_SESSIONS
            || max_confirmed_keys == 0
            || max_confirmed_keys > HARD_MAX_CONFIRMED_KEYS
            || session_ttl.is_zero()
            || session_ttl > MAX_SESSION_TTL
        {
            return Err(AgentError::InvalidConfiguration);
        }
        Ok(Self {
            max_pending_sessions,
            max_confirmed_keys,
            session_ttl,
        })
    }
}

/// Immutable agent authentication and resource configuration.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    limits: AgentLimits,
    local_role: EndpointRole,
    local_identity: EndpointIdentity,
    peer_identity: EndpointIdentity,
    execution_policy: SignedPolicyBundle,
    local_endpoint_policy: SignedPolicyBundle,
    peer_endpoint_policy: SignedPolicyBundle,
}

impl AgentConfig {
    /// Construct a role-fixed configuration with distinct endpoint identities.
    pub fn new(
        limits: AgentLimits,
        local_role: EndpointRole,
        local_identity: EndpointIdentity,
        peer_identity: EndpointIdentity,
        execution_policy: SignedPolicyBundle,
        local_endpoint_policy: SignedPolicyBundle,
        peer_endpoint_policy: SignedPolicyBundle,
    ) -> Result<Self, AgentError> {
        if local_identity.key_id == peer_identity.key_id
            || local_identity.verification_key == peer_identity.verification_key
        {
            return Err(AgentError::InvalidConfiguration);
        }
        Ok(Self {
            limits,
            local_role,
            local_identity,
            peer_identity,
            execution_policy,
            local_endpoint_policy,
            peer_endpoint_policy,
        })
    }
}

/// Two strict signed capability envelopes. Raw caller-built context is never accepted.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionAuthorization {
    local_offer: Vec<u8>,
    peer_offer: Vec<u8>,
}

impl fmt::Debug for SessionAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionAuthorization([redacted])")
    }
}

impl SessionAuthorization {
    /// Own bounded canonical-envelope candidates for later in-agent verification.
    pub fn new(local_offer: Vec<u8>, peer_offer: Vec<u8>) -> Result<Self, AgentError> {
        if local_offer.is_empty()
            || local_offer.len() > MAX_SIGNED_OFFER_BYTES
            || peer_offer.is_empty()
            || peer_offer.len() > MAX_SIGNED_OFFER_BYTES
        {
            return Err(AgentError::AuthorizationRejected);
        }
        Ok(Self {
            local_offer,
            peer_offer,
        })
    }
}

/// Authenticated encapsulation request containing only signed offers and exact peer public bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginEncapsulation {
    authorization: SessionAuthorization,
    peer_public_keys: EncapsulationPublicKeys,
}

impl BeginEncapsulation {
    /// Construct a request; all authentication and contract derivation remains inside the agent.
    #[must_use]
    pub const fn new(
        authorization: SessionAuthorization,
        peer_public_keys: EncapsulationPublicKeys,
    ) -> Self {
        Self {
            authorization,
            peer_public_keys,
        }
    }
}

/// Authenticated decapsulation request containing no caller-supplied context or decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginDecapsulation {
    authorization: SessionAuthorization,
    ciphertexts: EncapsulationCiphertexts,
}

impl BeginDecapsulation {
    /// Construct a request; the agent derives the receiver keys and context internally.
    #[must_use]
    pub const fn new(
        authorization: SessionAuthorization,
        ciphertexts: EncapsulationCiphertexts,
    ) -> Self {
        Self {
            authorization,
            ciphertexts,
        }
    }
}

/// Opaque handle to one pending confirmation session.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PendingSessionHandle(SessionId);

impl fmt::Debug for PendingSessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingSessionHandle([redacted])")
    }
}

impl PendingSessionHandle {
    /// Borrow opaque bytes for an authenticated IPC response/request.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[cfg(unix)]
    pub(crate) fn decode(bytes: [u8; 32]) -> Result<Self, AgentError> {
        SessionId::decode(bytes)
            .map(Self)
            .map_err(|_| AgentError::UnknownHandle)
    }
}

/// Opaque handle to one mutually confirmed application key retained by the agent.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ConfirmedKeyHandle(SessionId);

impl fmt::Debug for ConfirmedKeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmedKeyHandle([redacted])")
    }
}

impl ConfirmedKeyHandle {
    /// Borrow opaque bytes for future authenticated agent operations.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[cfg(unix)]
    pub(crate) fn decode(bytes: [u8; 32]) -> Result<Self, AgentError> {
        SessionId::decode(bytes)
            .map(Self)
            .map_err(|_| AgentError::UnknownHandle)
    }
}

/// Initiator-role encapsulation output, including the first protocol Finished flight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiatorEncapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
    /// Public component ciphertexts.
    pub ciphertexts: EncapsulationCiphertexts,
    /// Initiator Finished to deliver as the first confirmation flight.
    pub initiator_finished: InitiatorFinishedV1,
}

/// Responder-role encapsulation output; no Finished may exist before peer acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponderEncapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
    /// Public component ciphertexts.
    pub ciphertexts: EncapsulationCiphertexts,
}

/// Encapsulation output explicitly separated by authenticated protocol role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginEncapsulationResult {
    /// The local endpoint is the protocol initiator and issued the first Finished.
    Initiator(InitiatorEncapsulationResult),
    /// The local endpoint is the protocol responder and is awaiting the first Finished.
    Responder(ResponderEncapsulationResult),
}

/// Initiator-role decapsulation output, including the first protocol Finished flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiatorDecapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
    /// Initiator Finished to deliver as the first confirmation flight.
    pub initiator_finished: InitiatorFinishedV1,
}

/// Responder-role decapsulation output; no Finished may exist before peer acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponderDecapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
}

/// Decapsulation output explicitly separated by authenticated protocol role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginDecapsulationResult {
    /// The local endpoint is the protocol initiator and issued the first Finished.
    Initiator(InitiatorDecapsulationResult),
    /// The local endpoint is the protocol responder and is awaiting the first Finished.
    Responder(ResponderDecapsulationResult),
}

/// Responder acceptance result returned only after key retention and durable release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponderAcceptanceResult {
    /// Opaque handle to the retained accepted key.
    pub key_handle: ConfirmedKeyHandle,
    /// Responder Finished to deliver as the second confirmation flight.
    pub responder_finished: ResponderFinishedV1,
}

/// Transition/session error with retry-relevant states kept distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AgentError {
    /// Static roots, policies, identity, limits, or execution policy were invalid.
    InvalidConfiguration,
    /// Durable local state failed closed.
    Repository(RepositoryError),
    /// The mandatory authenticated witness failed.
    Witness(WitnessError),
    /// Local and witness heads diverged, indicating rollback, fork, or another writer.
    RollbackOrFork,
    /// The exact operation may have applied; only reconciliation of that operation is allowed.
    TransitionIndeterminate,
    /// An unresolved transition blocks new sessions and transitions.
    TransitionPending,
    /// Signed capability offers, identities, policies, roles, or agreement were rejected,
    /// or a live capability was retried with different public input.
    AuthorizationRejected,
    /// Peer public keys or ciphertexts were malformed or rejected.
    PublicInputRejected,
    /// A configured bounded table is full.
    CapacityExceeded,
    /// The pending session exceeded its TTL and its secret was erased.
    SessionExpired,
    /// The supplied opaque handle was absent or invalid.
    UnknownHandle,
    /// The exact state/fence changed before acceptance.
    StaleSession,
    /// The command carried a Finished flight not accepted by this pending role state.
    UnexpectedFlight,
    /// A completed handle was replayed with different bytes for its original Finished flight.
    ConflictingAcceptanceReplay,
    /// Peer Finished failed constant-time verification; the pending secret was erased.
    FinishedRejected,
    /// A bounded local allocation could not be reserved before mutating acceptance state.
    LocalResourceFailure,
    /// ABI version, entropy, or a local cryptographic provider failed.
    LocalCryptoFailure,
    /// The committed state is valid but this process has no exact compatible ABI 2 executor.
    ExecutionUnavailable,
    /// Another process instance holds or took the exclusive key-use lease, the
    /// authority's lease generation was observed behind the one it issued this
    /// instance, or this instance has begun releasing its lease; every
    /// in-process pending and accepted secret of this instance was erased, and
    /// it permanently refuses lease-guarded operations. An active lease under
    /// this instance's own id at the generation its own re-acquire would
    /// produce is never a fence: it is that re-acquire's result, adopted once
    /// the authority confirms it.
    InstanceFenced,
    /// The mandatory instance-lease authority failed closed, or the durable
    /// lease-intent journal is full and could not take the row every lease
    /// mutation needs before dispatch; the operation did not run -- or, when
    /// the authority could not be observed immediately before a secret would
    /// have been retained, it was aborted with nothing retained and, for a
    /// Begin or an Accept whose offer was already consumed, its reservation
    /// released. It also covers a lease mutation the authority refused on its
    /// authority-version precondition on every resync attempt: the version
    /// moved under each dispatch, nothing executed, and the call may be
    /// repeated. From [`PolicyAgent::release_instance_lease`] it means the
    /// lease is still held by this instance and the call may be repeated.
    InstanceLeaseUnavailable,
    /// A lease operation outcome stayed unknown after exact-operation
    /// reconciliation. For a re-acquire after a lapse, the fence it would have
    /// produced is remembered and resolved -- by the exact receipt query, or
    /// by that fence appearing in a snapshot -- before the next guarded
    /// operation dispatches anything; no renew is sent with the pre-acquire
    /// fence while that outcome is unknown. From
    /// [`PolicyAgent::release_instance_lease`] the fence is kept and the call
    /// may be repeated; from construction, a release of the fence the
    /// unconfirmed acquire would have granted was attempted, under its own
    /// fresh budget, before this was returned. That release is best-effort:
    /// if it could not be settled -- the authority still unreachable -- the
    /// lease lapses only at its TTL, and a restart before then is refused
    /// with [`Self::InstanceFenced`], exactly as after a crash. Use
    /// [`PolicyAgent::new_with_lease_wait`] to wait that TTL out.
    InstanceLeaseIndeterminate,
    /// This instance could not prove lease coverage for the operation, and
    /// nothing was retained or returned. Either the authority's own snapshot,
    /// taken right after a successful renew, reported the lease lapsed at this
    /// instance's generation with no successor, or still held with no more
    /// than the clock-divergence budget left -- the operation never started,
    /// and the next guarded operation re-acquires -- or the coverage that
    /// snapshot proved ran out during the operation, or the fresh snapshot
    /// taken after the operation's durable write, immediately before a secret
    /// would have been retained, reported the lease lapsed or within the
    /// budget of lapsing; in those cases every secret the operation produced
    /// was erased and its reservation released. The budget is
    /// `LEASE_CLOCK_DIVERGENCE_BUDGET_MILLIS` (one second) of authority clock
    /// advance beyond this host's elapsed time.
    ///
    /// What such an abort had already consumed is not undone, and it is the
    /// same set as for [`Self::OperationDeadlineExceeded`], which enumerates
    /// it: the Begin's offer stays consumed by its tombstone, an acceptance
    /// aborted after its witness read has lost its handle, and a lapse
    /// reported on the coverage snapshot after a re-acquire follows the
    /// erasure of every in-process secret, not only this operation's.
    ///
    /// Distinct from [`Self::InstanceFenced`], which is permanent. A coverage
    /// lapse is no evidence that any successor exists.
    InstanceLeaseCoverageElapsed,
    /// The caller's end-to-end deadline could not be met. Either the operation
    /// was refused before its first blocking exchange, because what remained
    /// of the deadline could not cover the least authority and witness round
    /// trips it needs, and the durable commits it cannot abandon
    /// (`DURABLE_COMMIT_RESERVE` each: the journal row before every lease
    /// dispatch, and a transition's own intent) -- nothing was dispatched,
    /// journaled, erased or fenced
    /// -- or the deadline ran out during the operation, in which case every
    /// secret it produced was erased, its reservation released, and nothing
    /// retained or returned. A transition the witness had already applied is
    /// the one exception: it is committed and reported `Ok` whatever the
    /// clock says. Not a fence, and distinct from
    /// [`Self::InstanceLeaseCoverageElapsed`]: a local deadline says nothing
    /// about the lease or about any successor.
    ///
    /// The earliest refusal is at the agent's one linearizer, and it is the
    /// most benign: a caller that could not take the lock inside its deadline
    /// never set a deadline on the agent, never reached the lease phase
    /// guard, and consumed nothing at all. The list below does not apply to
    /// it; its retry is the same request with a longer deadline.
    ///
    /// An abort does not undo what the operation had already consumed, and
    /// that is what the retry has to account for:
    ///
    /// * Begin: the reservation is released, but the capability tombstone it
    ///   wrote stays -- the offer was consumed the moment it was reserved --
    ///   so that offer now answers [`Self::AuthorizationRejected`] and the
    ///   retry needs a fresh one.
    /// * Acceptance: an abort after the witness read has already consumed the
    ///   pending session and durably cancelled it, so the handle is gone: a
    ///   retry answers [`Self::UnknownHandle`] and the flight must be re-run
    ///   from Begin; the peer's Finished for that handle can never be
    ///   accepted. A refusal before that read leaves the session in place.
    /// * Re-acquire after a lapse: when the deadline is reached on the
    ///   coverage snapshot that follows a successful re-acquire, the
    ///   re-acquire has already erased every in-process secret -- every
    ///   pending session and every confirmed key, not only this operation's
    ///   -- so a longer deadline recovers the agent, not the keys.
    ///
    /// Retry with a longer deadline, then: with a fresh offer where the offer
    /// was consumed, and from the start of the handshake where the handle was.
    OperationDeadlineExceeded,
    /// The process linearizer was poisoned; no operation continued.
    InternalPoisoned,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy agent rejected operation: {self:?}")
    }
}

impl std::error::Error for AgentError {}

/// What a settled lease release left behind.
///
/// Only produced where the lease is provably gone: the authority confirmed
/// the release, a snapshot proved no lease of this instance remains, or the
/// lease was already retired. A release that did not settle is an
/// [`AgentError`], never one of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseReleaseOutcome {
    /// The lease is released and the bookkeeping that follows it succeeded.
    Released,
    /// The lease is released -- a successor acquires at once -- but a durable
    /// session cancellation during the erase, or the journal forget after the
    /// release, failed. The carried error is the first failure; every
    /// in-process secret is gone either way, and the agent is poisoned.
    ReleasedWithFailure(AgentError),
}

impl From<RepositoryError> for AgentError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::TransitionPending => Self::TransitionPending,
            RepositoryError::CapacityExceeded => Self::CapacityExceeded,
            RepositoryError::SessionNotFound => Self::UnknownHandle,
            RepositoryError::CapabilityReplay => Self::AuthorizationRejected,
            RepositoryError::StaleReservation => Self::StaleSession,
            other => Self::Repository(other),
        }
    }
}

impl From<WitnessError> for AgentError {
    fn from(error: WitnessError) -> Self {
        match error {
            WitnessError::InvalidConfiguration => Self::InvalidConfiguration,
            other => Self::Witness(other),
        }
    }
}

impl From<Abi2EngineError> for AgentError {
    fn from(error: Abi2EngineError) -> Self {
        match error {
            Abi2EngineError::InvalidPublicInput => Self::PublicInputRejected,
            Abi2EngineError::ContextMismatch | Abi2EngineError::PolicyRejected => {
                Self::AuthorizationRejected
            }
            Abi2EngineError::AbiVersionMismatch | Abi2EngineError::LocalCryptoFailure => {
                Self::LocalCryptoFailure
            }
        }
    }
}

/// Public outputs of one Begin, kept so an exact retry under a fresh IPC
/// nonce can be answered with the same handle. It holds no secret: the handle
/// is opaque, and the ciphertexts and Initiator Finished have already left the
/// process once.
#[derive(Clone)]
enum BeginReplay {
    Encapsulation(Box<BeginEncapsulationResult>),
    Decapsulation(BeginDecapsulationResult),
}

/// What identifies the Begin that created a pending session, and what that
/// Begin answered. It lives with the pending secret and dies with it.
struct BegunRequest {
    /// The authenticated capability session id: the durable tombstone's key.
    capability_session_id: [u8; 32],
    /// Nonce-free digest of everything else that shaped the response.
    request_digest: [u8; 32],
    replay: BeginReplay,
}

enum PendingSession {
    Initiator {
        confirmation: InitiatorAwaitingResponderFinishedV1<Sha3_256Xof>,
        expected_head: StateHead,
        deadline: Instant,
        begun: BegunRequest,
    },
    Responder {
        confirmation: ResponderAwaitingInitiatorFinishedV1<Sha3_256Xof>,
        expected_head: StateHead,
        deadline: Instant,
        begun: BegunRequest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletedAcceptance {
    Initiator {
        received_finished: ResponderFinishedV1,
        key_handle: ConfirmedKeyHandle,
    },
    Responder {
        received_finished: InitiatorFinishedV1,
        result: ResponderAcceptanceResult,
    },
}

impl PendingSession {
    const fn begun(&self) -> &BegunRequest {
        match self {
            Self::Initiator { begun, .. } | Self::Responder { begun, .. } => begun,
        }
    }

    const fn expected_head(&self) -> StateHead {
        match self {
            Self::Initiator { expected_head, .. } | Self::Responder { expected_head, .. } => {
                *expected_head
            }
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        match self {
            Self::Initiator { deadline, .. } | Self::Responder { deadline, .. } => *deadline <= now,
        }
    }
}

enum ExecutorState {
    Available(Box<Abi2Engine>),
    Blocked,
}

impl ExecutorState {
    fn available(&self) -> Result<&Abi2Engine, AgentError> {
        match self {
            Self::Available(engine) => Ok(engine),
            Self::Blocked => Err(AgentError::ExecutionUnavailable),
        }
    }
}

struct Inner<W: WitnessPort, A: InstanceAuthorityPort> {
    repository: StateRepository,
    witness: W,
    authority: A,
    lease: InstanceLeaseState,
    config: AgentConfig,
    local_policy: AuthenticatedPolicy,
    peer_policy: AuthenticatedPolicy,
    engine: ExecutorState,
    pending_engine: Option<ExecutorState>,
    pending_sessions: HashMap<PendingSessionHandle, PendingSession>,
    /// The capability each live pending session's Begin consumed, so an exact
    /// retry finds the handle it created. An entry exists iff its handle is
    /// in `pending_sessions` and that session's `begun` record carries the
    /// key, so the index never exceeds `max_pending_sessions`: `reserve_pending`
    /// is the only insert, `take_pending` the only removal (with
    /// `restore_unexpected` putting back what an accept took).
    begun_capabilities: HashMap<[u8; 32], PendingSessionHandle>,
    confirmed_keys: HashMap<ConfirmedKeyHandle, AcceptedSessionKeyV1>,
    completed_acceptances: HashMap<PendingSessionHandle, CompletedAcceptance>,
    poisoned: bool,
    /// The deadline of the operation holding the lock; `lock_until` sets it
    /// before the operation reads it, and the idle sweep -- which admits
    /// nothing -- installs one already reached.
    deadline: OperationDeadline,
}

/// Process-local façade whose one mutex is the transition/session linearization point.
///
/// Every operation runs under one end-to-end deadline. The `_until` variants
/// (`begin_encapsulation_until`, `accept_initiator_finished_until`,
/// `apply_advance_until`, `release_instance_lease_until`, and the rest) take
/// it from the caller, and admit each authority and witness round trip only
/// while the port's own bound on that call ends before it -- so an operation
/// whose least plan does not fit is refused before its first exchange, and
/// one whose deadline runs out mid-way retains nothing. The plain forms give
/// themselves `DEFAULT_OPERATION_BUDGET` (60 seconds) from the call, for
/// callers with no deadline of their own.
///
/// The deadline reaches the lock itself. A caller waits for the linearizer
/// only while its own deadline lasts, and one that never reaches it is
/// refused with [`AgentError::OperationDeadlineExceeded`] having consumed
/// nothing at all -- the earliest and most benign refusal the agent makes.
pub struct PolicyAgent<W: WitnessPort, A: InstanceAuthorityPort> {
    inner: Mutex<Inner<W, A>>,
}

impl<W: WitnessPort, A: InstanceAuthorityPort> fmt::Debug for PolicyAgent<W, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyAgent([redacted])")
    }
}

impl<W: WitnessPort, A: InstanceAuthorityPort> PolicyAgent<W, A> {
    /// Authenticate configured policy material, acquire the exclusive instance
    /// lease, and align local state with the mandatory witness.
    ///
    /// Construction fails closed with [`AgentError::InstanceFenced`] while
    /// another unexpired process instance holds the lease, so a recovery clone
    /// or duplicate deployment cannot start using keys next to the live holder.
    ///
    /// Before the acquire, the lease-intent journal a previous process left in
    /// the repository is settled: each journaled operation is queried, a
    /// receipt the authority still holds is acknowledged, and settled rows are
    /// forgotten. That pass runs inside the acquire's own budget, admitted a
    /// row at a time with what the acquire itself needs kept in reserve, so
    /// rows the authority cannot yet answer for -- and rows the budget can no
    /// longer cover -- are kept and retried before each guarded operation
    /// instead of starving the acquire they precede. If all
    /// `MAX_JOURNALED_LEASE_INTENTS` rows remain unresolved, construction
    /// fails closed with [`AgentError::InstanceLeaseUnavailable`] rather than
    /// dispatch an acquire it could not journal.
    ///
    /// It does not wait for that lease to lapse; [`Self::new_with_lease_wait`]
    /// is the constructor for a daemon restarting after its predecessor was
    /// killed.
    ///
    /// A failure after the acquire -- the witness read, the executor, or the
    /// policy authentication -- releases the lease before returning, so a
    /// healthy retry acquires at once instead of waiting out the TTL. The
    /// failure itself is what is returned; a release that cannot be settled
    /// leaves the lease to lapse at its TTL, with its journal row for the next
    /// start to settle, exactly as after a crash. An acquire whose own outcome
    /// stayed unknown is handled the same way, whichever error carries that
    /// state out: the fence it would have granted is released before the
    /// acquire's own error -- [`AgentError::InstanceLeaseIndeterminate`],
    /// [`AgentError::InstanceLeaseUnavailable`] or
    /// [`AgentError::OperationDeadlineExceeded`] -- is returned.
    pub fn new(
        repository: StateRepository,
        witness: W,
        authority: A,
        config: AgentConfig,
    ) -> Result<Self, AgentError> {
        let lease = acquire_instance_lease(&repository, &authority)?;
        Self::with_lease(repository, witness, authority, config, lease)
    }

    /// Like [`Self::new`], but wait up to `max_wait` for a predecessor's lease
    /// to lapse before giving up.
    ///
    /// A process that was killed rather than stopped never released its lease,
    /// and the authority lets that lease lapse only at the TTL it granted.
    /// Failing fast on it is right for a duplicate deployment or a recovery
    /// clone, but wrong for the daemon's own restart, which would then stay
    /// down until an operator noticed. So while the authority reports an
    /// active lease held by another instance -- whether the pre-acquire
    /// snapshot shows it or the acquire itself is rejected as held -- this
    /// constructor pauses for the shorter of that lease's remaining life and
    /// one second, then tries the same fail-closed acquire again, until
    /// `max_wait` has elapsed; it then fails with
    /// [`AgentError::InstanceFenced`] exactly as [`Self::new`] would have.
    /// Exclusivity is never loosened: every attempt is the same acquire, which
    /// the authority refuses while any lease is active, so a holder that keeps
    /// renewing wins. Every other failure is returned at once.
    pub fn new_with_lease_wait(
        repository: StateRepository,
        witness: W,
        authority: A,
        config: AgentConfig,
        max_wait: Duration,
    ) -> Result<Self, AgentError> {
        let lease = acquire_instance_lease_within(&repository, &authority, max_wait)?;
        Self::with_lease(repository, witness, authority, config, lease)
    }

    /// Finish construction once the lease is held: align local state with the
    /// mandatory witness and authenticate the configured policy material.
    ///
    /// Everything fallible happens in `prepare_execution`, before the lease is
    /// committed to an `Inner`, so that a failure can hand the lease back
    /// first: left held, it would fence every retry until its TTL. The
    /// constructor's own error is what is returned, because this process
    /// holds no usable lease either way; a release that could not itself be
    /// settled -- the authority unreachable -- leaves the lease to lapse at
    /// its TTL with its journal row for the next start, exactly as after a
    /// crash. That release runs under its own fresh default budget, not
    /// under whatever the failed attempt had left.
    fn with_lease(
        mut repository: StateRepository,
        witness: W,
        authority: A,
        config: AgentConfig,
        mut lease: InstanceLeaseState,
    ) -> Result<Self, AgentError> {
        let prepared = match prepare_execution(&mut repository, &witness, &config) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Ok(deadline) = OperationDeadline::fresh(DEFAULT_OPERATION_BUDGET) {
                    let _ = release_lease_state(&repository, &authority, &mut lease, deadline);
                }
                let _ = forget_settled(&repository, &mut lease);
                return Err(error);
            }
        };
        let PreparedExecution {
            engine,
            pending_engine,
            local_policy,
            peer_policy,
        } = prepared;
        Ok(Self {
            inner: Mutex::new(Inner {
                repository,
                witness,
                authority,
                lease,
                config,
                local_policy,
                peer_policy,
                engine,
                pending_engine,
                pending_sessions: HashMap::new(),
                begun_capabilities: HashMap::new(),
                confirmed_keys: HashMap::new(),
                completed_acceptances: HashMap::new(),
                poisoned: false,
                // Already reached, so nothing is admitted until the first
                // `lock_until` sets the real one; every lock does.
                deadline: OperationDeadline { at: Instant::now() },
            }),
        })
    }

    /// Return only the public encapsulation keys owned by the agent, under
    /// the default budget.
    pub fn public_keys(&self) -> Result<EncapsulationPublicKeys, AgentError> {
        self.public_keys_until(default_deadline()?)
    }

    /// Return only the public encapsulation keys owned by the agent, waiting
    /// for the linearizer no longer than `deadline`.
    ///
    /// This makes no port call, so the linearizer is the only thing it waits
    /// for; a refusal with [`AgentError::OperationDeadlineExceeded`] read
    /// nothing and changed nothing.
    pub fn public_keys_until(
        &self,
        deadline: Instant,
    ) -> Result<EncapsulationPublicKeys, AgentError> {
        let inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        if inner.repository.pending_intent().is_some() {
            return Err(AgentError::TransitionPending);
        }
        Ok(inner.engine.available()?.public_keys().clone())
    }

    /// Authenticate and execute a normal migration state advance, under the
    /// default budget.
    pub fn apply_advance(&self, canonical_signed_state: &[u8]) -> Result<(), AgentError> {
        self.apply_advance_until(canonical_signed_state, default_deadline()?)
    }

    /// Authenticate and execute a normal migration state advance, admitting
    /// each round trip only while it ends before `deadline`.
    ///
    /// Refused with [`AgentError::OperationDeadlineExceeded`] before any
    /// durable intent is written: the least plan does not fit, or what is
    /// left after the lease work cannot cover both the durable intent and the
    /// witness CAS. The certificate is authenticated and the replacement
    /// executor built before that admission, so a certificate this agent
    /// rejects is reported as rejected whatever the clock says, and no engine
    /// failure can strand an intent. A lease renew, and the journal row every
    /// dispatch writes first, may already have been made by then; both are
    /// the lease's own bookkeeping, which the next operation's drains settle,
    /// and no transition is pending and no Reconcile is owed. Past the
    /// durable intent the clock no longer decides: the CAS is dispatched and
    /// its outcome reported truthfully, and a CAS the witness has applied is
    /// committed and reported `Ok` whatever the deadline says. A durable
    /// commit that blocks longer than the second reserved for it
    /// (`DURABLE_COMMIT_RESERVE`) is the one way the CAS can start after the
    /// deadline; the store bounds that, not this deadline.
    pub fn apply_advance_until(
        &self,
        canonical_signed_state: &[u8],
        deadline: Instant,
    ) -> Result<(), AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::TRANSITION)?;
        purge_expired(&mut inner)?;
        // Authenticated and provisioned before the admission below, not after
        // it: neither has any durable or external effect, so paying for them
        // here keeps the un-admitted stretch to the durable commit alone --
        // and an executor that cannot be built now fails while there is still
        // nothing on disk to strand.
        let prepared = inner
            .repository
            .authenticate_advance(canonical_signed_state)?;
        let replacement = executor_for(&inner.config.execution_policy, prepared.next_state())?;
        // Admitted here, before the durable intent, and not at the dispatch:
        // a refusal after the intent is on disk would strand a pending
        // transition that only Reconcile clears, and this agent does not
        // abandon one. So the admission covers everything from here to the
        // end of the CAS: the intent's own commit, charged at
        // DURABLE_COMMIT_RESERVE, and the CAS at the witness's bound. Past
        // the commit the clock no longer decides.
        inner
            .deadline
            .admit(DURABLE_COMMIT_RESERVE.saturating_add(inner.witness.round_trip_bound()))?;
        let intent = inner.repository.persist_transition(prepared)?;
        // Only now: an executor published for a transition that then failed
        // to persist would be reused by a later `reconcile_transition_until`,
        // which rebuilds only when this field is `None` -- an executor for
        // the wrong next state.
        inner.pending_engine = Some(replacement);
        dispatch_transition(&mut inner, intent)
    }

    /// Authenticate and execute a separately authorized lineage reset, under
    /// the default budget.
    pub fn apply_reset(&self, canonical_signed_reset: &[u8]) -> Result<(), AgentError> {
        self.apply_reset_until(canonical_signed_reset, default_deadline()?)
    }

    /// Authenticate and execute a separately authorized lineage reset,
    /// admitting each round trip only while it ends before `deadline`; see
    /// [`Self::apply_advance_until`].
    pub fn apply_reset_until(
        &self,
        canonical_signed_reset: &[u8],
        deadline: Instant,
    ) -> Result<(), AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::TRANSITION)?;
        purge_expired(&mut inner)?;
        let prepared = inner
            .repository
            .authenticate_reset(canonical_signed_reset)?;
        let replacement = executor_for(&inner.config.execution_policy, prepared.next_state())?;
        // Admitted before the durable intent, and covering it, for the reason
        // given on `apply_advance_until`; the authentication and the executor
        // above are paid for before it for the same reason.
        inner
            .deadline
            .admit(DURABLE_COMMIT_RESERVE.saturating_add(inner.witness.round_trip_bound()))?;
        let intent = inner.repository.persist_transition(prepared)?;
        // After the persist, never before it; see `apply_advance_until`.
        inner.pending_engine = Some(replacement);
        dispatch_transition(&mut inner, intent)
    }

    /// Reconcile only the durable operation ID retained after an unknown
    /// outcome, under the default budget.
    pub fn reconcile_transition(&self) -> Result<(), AgentError> {
        self.reconcile_transition_until(default_deadline()?)
    }

    /// Reconcile only the durable operation ID retained after an unknown
    /// outcome, admitting each round trip only while it ends before
    /// `deadline`; see [`Self::apply_advance_until`].
    pub fn reconcile_transition_until(&self, deadline: Instant) -> Result<(), AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::RECONCILE)?;
        let intent = inner
            .repository
            .pending_intent()
            .ok_or(RepositoryError::NoPendingTransition)?;
        if inner.pending_engine.is_none() {
            inner.pending_engine = Some(executor_for(
                &inner.config.execution_policy,
                inner
                    .repository
                    .pending_next_state()
                    .ok_or(AgentError::InternalPoisoned)?,
            )?);
        }
        inner.deadline.admit(inner.witness.round_trip_bound())?;
        match inner.witness.query(intent.operation_id())? {
            WitnessOutcome::Unknown => Err(AgentError::TransitionIndeterminate),
            WitnessOutcome::Known(receipt) if receipt.is_exact_applied(intent) => {
                finish_transition(&mut inner, *receipt)
            }
            WitnessOutcome::Known(receipt) => {
                let same_intent = inner.repository.validate_unapplied(*receipt)?;
                execute_transition(&mut inner, same_intent)
            }
        }
    }

    /// Begin encapsulation from signed capability envelopes, under the default
    /// budget; no raw context is accepted.
    ///
    /// While the pending session it created remains live, an exact retry --
    /// the same signed offers and the same peer public keys, under any IPC
    /// nonce -- returns the same handle, ciphertexts and Initiator Finished
    /// and reserves nothing, so a Begin whose response was lost is recovered
    /// rather than stranded. Different public input under the same capability
    /// fails with [`AgentError::AuthorizationRejected`] and erases nothing.
    /// Cancel, expiry, acceptance, Finished rejection, a lease lapse recovered
    /// by re-acquire, restart, a committed transition and fencing end that
    /// window. After the first six the durable capability tombstone answers
    /// with [`AgentError::AuthorizationRejected`]. After a committed
    /// transition the tombstone table is already cleared, and the old offers
    /// fail the current-state checks instead -- the same
    /// [`AgentError::AuthorizationRejected`]. After fencing the instance is
    /// retired and every operation, this retry included, is refused with
    /// [`AgentError::InstanceFenced`] at the lease phase guard, before the
    /// retry index or the tombstone is consulted.
    pub fn begin_encapsulation(
        &self,
        request: BeginEncapsulation,
    ) -> Result<BeginEncapsulationResult, AgentError> {
        self.begin_encapsulation_until(request, default_deadline()?)
    }

    /// Begin encapsulation from signed capability envelopes, admitting each
    /// round trip only while it ends before `deadline`; no raw context is
    /// accepted. See [`Self::begin_encapsulation`] for the exact-retry
    /// contract.
    ///
    /// Refused with [`AgentError::OperationDeadlineExceeded`] before anything
    /// is dispatched when the least plan does not fit, and aborted with the
    /// same error, its reservation released and nothing retained, when the
    /// deadline is reached before the secret becomes reachable.
    ///
    /// An exact retry reserves nothing durably, but it is not free: it
    /// dispatches the renew, the coverage snapshot that follows it, the
    /// witness head read, and the retention snapshot that gates the
    /// disclosure -- the same `OperationPlan::RETAINING` budget of three
    /// authority round trips and one witness round trip the fresh path is
    /// admitted against. It is refused rather than answered when that budget
    /// does not fit the caller's remaining deadline
    /// ([`AgentError::OperationDeadlineExceeded`]), when the authority cannot
    /// be reached for either snapshot ([`AgentError::InstanceLeaseUnavailable`]),
    /// or when the coverage it re-proves has elapsed
    /// ([`AgentError::InstanceLeaseCoverageElapsed`]). And it can fence: the
    /// retention snapshot fences exactly as it does on the fresh path when it
    /// shows a successor, a rolled-back authority or a foreign fence, erasing
    /// the retried session along with every other secret and answering
    /// [`AgentError::InstanceFenced`].
    pub fn begin_encapsulation_until(
        &self,
        request: BeginEncapsulation,
        deadline: Instant,
    ) -> Result<BeginEncapsulationResult, AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::RETAINING)?;
        purge_expired(&mut inner)?;
        let head = verify_current_head(&inner)?;
        // Digested before `build_contract` consumes the authorization, and
        // the index is consulted only for a capability that authenticated:
        // it is never asked about a forged offer.
        let request_digest = begin_request_digest(
            &BEGIN_ENCAPSULATION_TAG,
            &request.authorization,
            (
                request.peer_public_keys.pq(),
                request.peer_public_keys.traditional(),
            ),
        )?;
        let (context, abi_context, capability_session_id) = build_contract(
            &inner,
            request.authorization,
            inner.config.local_role,
            request.peer_public_keys.clone(),
        )?;
        if let Some(replay) =
            lookup_begun_capability(&mut inner, capability_session_id, request_digest)?
        {
            return match replay {
                BeginReplay::Encapsulation(result) => Ok(*result),
                BeginReplay::Decapsulation(_) => Err(AgentError::AuthorizationRejected),
            };
        }
        // After the replay check, so a retry never needs a free slot: it adds
        // none, and the sessions it is recovering must not be what refuses it.
        ensure_session_capacity(&inner)?;
        let engine = inner.engine.available()?;
        let (ciphertexts, secret) = engine.encapsulate(&request.peer_public_keys, &abi_context)?;
        let post = PostKemTranscriptV1::from_context(
            &context,
            ciphertexts.pq(),
            ciphertexts.traditional(),
        )
        .map_err(|_| AgentError::AuthorizationRejected)?;
        let deadline = pending_deadline(&inner)?;
        match inner.config.local_role {
            EndpointRole::Initiator => {
                let confirmation =
                    InitiatorConfirmationV1::<Sha3_256Xof>::new(secret, &context, &post)
                        .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                let (confirmation, initiator_finished) = confirmation.issue_finished();
                ensure_may_retain(&inner)?;
                reserve_pending(&mut inner, head, |handle| {
                    let result =
                        BeginEncapsulationResult::Initiator(InitiatorEncapsulationResult {
                            handle,
                            ciphertexts,
                            initiator_finished,
                        });
                    let begun = BegunRequest {
                        capability_session_id,
                        request_digest,
                        replay: BeginReplay::Encapsulation(Box::new(result.clone())),
                    };
                    (
                        PendingSession::Initiator {
                            confirmation,
                            expected_head: head,
                            deadline,
                            begun,
                        },
                        result,
                    )
                })
            }
            EndpointRole::Responder => {
                let confirmation = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
                    secret, &context, &post,
                )
                .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                ensure_may_retain(&inner)?;
                reserve_pending(&mut inner, head, |handle| {
                    let result =
                        BeginEncapsulationResult::Responder(ResponderEncapsulationResult {
                            handle,
                            ciphertexts,
                        });
                    let begun = BegunRequest {
                        capability_session_id,
                        request_digest,
                        replay: BeginReplay::Encapsulation(Box::new(result.clone())),
                    };
                    (
                        PendingSession::Responder {
                            confirmation,
                            expected_head: head,
                            deadline,
                            begun,
                        },
                        result,
                    )
                })
            }
        }
    }

    /// Begin decapsulation from signed capability envelopes and exact
    /// ciphertexts, under the default budget.
    ///
    /// While the pending session it created remains live, an exact retry --
    /// the same signed offers and the same ciphertexts, under any IPC nonce
    /// -- returns the same handle and, for the initiator, the same Initiator
    /// Finished, and reserves nothing. Different ciphertexts under the same
    /// capability fail with [`AgentError::AuthorizationRejected`] and erase
    /// nothing. Cancel, expiry, acceptance, Finished rejection, a lease lapse
    /// recovered by re-acquire, restart, a committed transition and fencing
    /// end that window. After the first six the durable capability tombstone
    /// answers with [`AgentError::AuthorizationRejected`]. After a committed
    /// transition the tombstone table is already cleared, and the old offers
    /// fail the current-state checks instead -- the same
    /// [`AgentError::AuthorizationRejected`]. After fencing the instance is
    /// retired and every operation, this retry included, is refused with
    /// [`AgentError::InstanceFenced`] at the lease phase guard, before the
    /// retry index or the tombstone is consulted.
    pub fn begin_decapsulation(
        &self,
        request: BeginDecapsulation,
    ) -> Result<BeginDecapsulationResult, AgentError> {
        self.begin_decapsulation_until(request, default_deadline()?)
    }

    /// Begin decapsulation from signed capability envelopes and exact
    /// ciphertexts, admitting each round trip only while it ends before
    /// `deadline`; see [`Self::begin_encapsulation_until`] for the deadline's
    /// contract and [`Self::begin_decapsulation`] for the exact retry's.
    pub fn begin_decapsulation_until(
        &self,
        request: BeginDecapsulation,
        deadline: Instant,
    ) -> Result<BeginDecapsulationResult, AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::RETAINING)?;
        purge_expired(&mut inner)?;
        let head = verify_current_head(&inner)?;
        // Digested before `build_contract` consumes the authorization, and
        // the index is consulted only for a capability that authenticated:
        // it is never asked about a forged offer.
        let request_digest = begin_request_digest(
            &BEGIN_DECAPSULATION_TAG,
            &request.authorization,
            (request.ciphertexts.pq(), request.ciphertexts.traditional()),
        )?;
        let encapsulator_role = opposite(inner.config.local_role);
        let local_keys = inner.engine.available()?.public_keys().clone();
        let (context, abi_context, capability_session_id) =
            build_contract(&inner, request.authorization, encapsulator_role, local_keys)?;
        if let Some(replay) =
            lookup_begun_capability(&mut inner, capability_session_id, request_digest)?
        {
            return match replay {
                BeginReplay::Decapsulation(result) => Ok(result),
                BeginReplay::Encapsulation(_) => Err(AgentError::AuthorizationRejected),
            };
        }
        // After the replay check, so a retry never needs a free slot: it adds
        // none, and the sessions it is recovering must not be what refuses it.
        ensure_session_capacity(&inner)?;
        let engine = inner.engine.available()?;
        let secret = engine.decapsulate(&request.ciphertexts, &abi_context)?;
        let post = PostKemTranscriptV1::from_context(
            &context,
            request.ciphertexts.pq(),
            request.ciphertexts.traditional(),
        )
        .map_err(|_| AgentError::AuthorizationRejected)?;
        let deadline = pending_deadline(&inner)?;
        match inner.config.local_role {
            EndpointRole::Initiator => {
                let confirmation =
                    InitiatorConfirmationV1::<Sha3_256Xof>::new(secret, &context, &post)
                        .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                let (confirmation, initiator_finished) = confirmation.issue_finished();
                ensure_may_retain(&inner)?;
                reserve_pending(&mut inner, head, |handle| {
                    let result =
                        BeginDecapsulationResult::Initiator(InitiatorDecapsulationResult {
                            handle,
                            initiator_finished,
                        });
                    let begun = BegunRequest {
                        capability_session_id,
                        request_digest,
                        replay: BeginReplay::Decapsulation(result),
                    };
                    (
                        PendingSession::Initiator {
                            confirmation,
                            expected_head: head,
                            deadline,
                            begun,
                        },
                        result,
                    )
                })
            }
            EndpointRole::Responder => {
                let confirmation = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
                    secret, &context, &post,
                )
                .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                ensure_may_retain(&inner)?;
                reserve_pending(&mut inner, head, |handle| {
                    let result =
                        BeginDecapsulationResult::Responder(ResponderDecapsulationResult {
                            handle,
                        });
                    let begun = BegunRequest {
                        capability_session_id,
                        request_digest,
                        replay: BeginReplay::Decapsulation(result),
                    };
                    (
                        PendingSession::Responder {
                            confirmation,
                            expected_head: head,
                            deadline,
                            begun,
                        },
                        result,
                    )
                })
            }
        }
    }

    /// Accept I, durably release its reservation, retain K and retry state, then return R,
    /// under the default budget.
    ///
    /// While the retained key remains live, an exact same-handle/same-Finished retry returns the
    /// same handle and R. Different bytes for that completed flight fail closed without replacing
    /// the result. Destroy, migration transition, or process restart clears this retry cache.
    pub fn accept_initiator_finished(
        &self,
        handle: PendingSessionHandle,
        initiator_finished: InitiatorFinishedV1,
    ) -> Result<ResponderAcceptanceResult, AgentError> {
        self.accept_initiator_finished_until(handle, initiator_finished, default_deadline()?)
    }

    /// Accept I under the caller's `deadline`; see
    /// [`Self::accept_initiator_finished`] for the retry contract and
    /// [`Self::begin_encapsulation_until`] for what a refused or lapsed
    /// deadline leaves behind. A refusal before the witness read leaves the
    /// pending session in place.
    pub fn accept_initiator_finished_until(
        &self,
        handle: PendingSessionHandle,
        initiator_finished: InitiatorFinishedV1,
        deadline: Instant,
    ) -> Result<ResponderAcceptanceResult, AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::RETAINING)?;
        if let Some(completed) = inner.completed_acceptances.get(&handle) {
            return match completed {
                CompletedAcceptance::Responder {
                    received_finished,
                    result,
                } if *received_finished == initiator_finished => {
                    // Returning the retained result is a lease-guarded
                    // disclosure, the same as retaining it was. The renew and
                    // its coverage proof ran just above with no I/O since, so
                    // the budgeted rule against that proof is the exact gate the
                    // fresh path applies before it discloses. Without it a
                    // completed acceptance is answered even once the coverage
                    // the proof recorded has already elapsed by the time the
                    // cached result is returned. It is not a fence.
                    ensure_may_retain(&inner)?;
                    Ok(*result)
                }
                CompletedAcceptance::Responder { .. } => {
                    Err(AgentError::ConflictingAcceptanceReplay)
                }
                CompletedAcceptance::Initiator { .. } => Err(AgentError::UnexpectedFlight),
            };
        }
        let (expected_head, key_handle) =
            prepare_acceptance(&mut inner, handle, PendingFlight::Initiator)?;
        let confirmation = match take_pending(&mut inner, handle) {
            Some(PendingSession::Responder { confirmation, .. }) => confirmation,
            Some(unexpected) => return restore_unexpected(&mut inner, handle, unexpected),
            None => return Err(AgentError::UnknownHandle),
        };
        let (accepted, responder_finished) = match confirmation
            .verify_accept_and_issue_finished(inner.repository.state_machine(), &initiator_finished)
        {
            Ok(accepted) => accepted,
            Err(error) => {
                cancel_consumed_session(&mut inner, handle)?;
                return Err(map_confirmation_error(&mut inner, error));
            }
        };
        let result = ResponderAcceptanceResult {
            key_handle,
            responder_finished,
        };
        if let Err(error) = ensure_may_retain(&inner) {
            // The session has already left the map and its confirmation is
            // consumed, but its durable reservation is still held. Returning
            // here without releasing it would orphan the row: `erase_pending`
            // can no longer find the handle and `fence_out` iterates the map,
            // so the bounded SESSION_TABLE slot would be burned permanently and
            // survive restart. The confirmation-failure path just above releases
            // it the same way, for the same reason.
            cancel_consumed_session(&mut inner, handle)?;
            return Err(error);
        }
        retain_accepted_key(
            &mut inner,
            handle,
            expected_head,
            key_handle,
            accepted,
            CompletedAcceptance::Responder {
                received_finished: initiator_finished,
                result,
            },
        )?;
        Ok(result)
    }

    /// Accept the responder Finished only from an initiator pending state and retain K, under
    /// the default budget.
    ///
    /// While the retained key remains live, an exact same-handle/same-Finished retry returns the
    /// same handle. Different bytes for that completed flight fail closed without replacing the
    /// result. Destroy, migration transition, or process restart clears this retry cache.
    pub fn accept_responder_finished(
        &self,
        handle: PendingSessionHandle,
        responder_finished: ResponderFinishedV1,
    ) -> Result<ConfirmedKeyHandle, AgentError> {
        self.accept_responder_finished_until(handle, responder_finished, default_deadline()?)
    }

    /// Accept the responder Finished under the caller's `deadline`; see
    /// [`Self::accept_responder_finished`] for the retry contract and
    /// [`Self::accept_initiator_finished_until`] for the deadline's.
    pub fn accept_responder_finished_until(
        &self,
        handle: PendingSessionHandle,
        responder_finished: ResponderFinishedV1,
        deadline: Instant,
    ) -> Result<ConfirmedKeyHandle, AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner, OperationPlan::RETAINING)?;
        if let Some(completed) = inner.completed_acceptances.get(&handle) {
            return match completed {
                CompletedAcceptance::Initiator {
                    received_finished,
                    key_handle,
                } if *received_finished == responder_finished => {
                    // Returning the retained handle is a lease-guarded
                    // disclosure, the same as retaining it was. The renew and
                    // its coverage proof ran just above with no I/O since, so
                    // the budgeted rule against that proof is the exact gate the
                    // fresh path applies before it discloses. Without it a
                    // completed acceptance is answered even once the coverage
                    // the proof recorded has already elapsed by the time the
                    // cached handle is returned. It is not a fence.
                    ensure_may_retain(&inner)?;
                    Ok(*key_handle)
                }
                CompletedAcceptance::Initiator { .. } => {
                    Err(AgentError::ConflictingAcceptanceReplay)
                }
                CompletedAcceptance::Responder { .. } => Err(AgentError::UnexpectedFlight),
            };
        }
        let (expected_head, key_handle) =
            prepare_acceptance(&mut inner, handle, PendingFlight::Responder)?;
        let confirmation = match take_pending(&mut inner, handle) {
            Some(PendingSession::Initiator { confirmation, .. }) => confirmation,
            Some(unexpected) => return restore_unexpected(&mut inner, handle, unexpected),
            None => return Err(AgentError::UnknownHandle),
        };
        let accepted = match confirmation
            .verify_and_accept(inner.repository.state_machine(), &responder_finished)
        {
            Ok(accepted) => accepted,
            Err(error) => {
                cancel_consumed_session(&mut inner, handle)?;
                return Err(map_confirmation_error(&mut inner, error));
            }
        };
        if let Err(error) = ensure_may_retain(&inner) {
            // The session has already left the map and its confirmation is
            // consumed, but its durable reservation is still held. Returning
            // here without releasing it would orphan the row: `erase_pending`
            // can no longer find the handle and `fence_out` iterates the map,
            // so the bounded SESSION_TABLE slot would be burned permanently and
            // survive restart. The confirmation-failure path just above releases
            // it the same way, for the same reason.
            cancel_consumed_session(&mut inner, handle)?;
            return Err(error);
        }
        retain_accepted_key(
            &mut inner,
            handle,
            expected_head,
            key_handle,
            accepted,
            CompletedAcceptance::Initiator {
                received_finished: responder_finished,
                key_handle,
            },
        )?;
        Ok(key_handle)
    }

    /// Cancel a pending session and wipe its unconfirmed secret immediately,
    /// under the default budget.
    pub fn cancel(&self, handle: PendingSessionHandle) -> Result<(), AgentError> {
        self.cancel_until(handle, default_deadline()?)
    }

    /// Cancel a pending session and wipe its unconfirmed secret immediately,
    /// waiting for the linearizer no longer than `deadline`.
    ///
    /// This makes no port call, so the linearizer is the only thing it waits
    /// for. A refusal with [`AgentError::OperationDeadlineExceeded`] happens
    /// at the door, before anything is erased: the pending session and its
    /// durable reservation are intact, the call may be repeated, and the
    /// session-TTL sweep remains the backstop.
    pub fn cancel_until(
        &self,
        handle: PendingSessionHandle,
        deadline: Instant,
    ) -> Result<(), AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        erase_pending(&mut inner, handle)
    }

    /// Destroy a retained confirmed key, under the default budget. No
    /// secret-export API exists.
    pub fn destroy_key(&self, handle: ConfirmedKeyHandle) -> Result<(), AgentError> {
        self.destroy_key_until(handle, default_deadline()?)
    }

    /// Destroy a retained confirmed key, waiting for the linearizer no longer
    /// than `deadline`.
    ///
    /// This makes no port call, so the linearizer is the only thing it waits
    /// for; a refusal with [`AgentError::OperationDeadlineExceeded`] leaves
    /// the key retained for the retry.
    pub fn destroy_key_until(
        &self,
        handle: ConfirmedKeyHandle,
        deadline: Instant,
    ) -> Result<(), AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        ensure_live(&inner)?;
        let destroyed = inner
            .confirmed_keys
            .remove(&handle)
            .ok_or(AgentError::UnknownHandle)?;
        drop(destroyed);
        inner.completed_acceptances.retain(|_, completed| {
            let completed_handle = match completed {
                CompletedAcceptance::Initiator { key_handle, .. } => *key_handle,
                CompletedAcceptance::Responder { result, .. } => result.key_handle,
            };
            completed_handle != handle
        });
        Ok(())
    }

    /// Release the exclusive instance lease for graceful shutdown.
    ///
    /// Every in-process pending and accepted secret is erased first, so key use
    /// stops before the release is dispatched and before another instance can
    /// acquire the next lease generation. From the first attempt on, whatever
    /// its outcome, this agent refuses lease-guarded operations with
    /// [`AgentError::InstanceFenced`]; a successor process must construct a
    /// new agent to acquire authority.
    ///
    /// It succeeds only once the authority has confirmed the release --
    /// applied, or rejected because no lease of this instance remains -- or a
    /// snapshot has shown that no lease of this instance remains. Until then
    /// the fence is kept and the call may be repeated:
    /// [`AgentError::InstanceLeaseUnavailable`] when the release could not be
    /// sent, could not be journaled, or was declined on a condition that can
    /// clear, and [`AgentError::InstanceLeaseIndeterminate`] when its outcome
    /// stayed unknown and no snapshot could prove it either way. In both cases
    /// the lease is still held by this instance. A durable cancellation that
    /// fails during the erase, or a journal forget that fails after the
    /// release, is reported by [`Self::release_instance_lease_until`] as
    /// [`LeaseReleaseOutcome::ReleasedWithFailure`] -- the lease really is
    /// gone -- which this flattening form returns as
    /// [`AgentError::InternalPoisoned`]; the agent is poisoned and refuses a
    /// repeat. Once the lease is retired, repeating the call succeeds
    /// idempotently without dispatching anything.
    ///
    /// A re-acquire whose outcome is still unknown is resolved first, by the
    /// same exact query and snapshot the guarded operations use; when the
    /// resolution cannot complete -- the authority answers neither, or the
    /// deadline has no room for it on top of the release it keeps in reserve
    /// -- the release is dispatched with the fence that re-acquire would have
    /// produced, so whichever lease this instance may hold is the one
    /// released.
    ///
    /// This is the clean shutdown path, so it also forgets, durably, every
    /// journaled lease intent this process has settled -- the release's own
    /// included. A clean shutdown therefore leaves the journal empty whenever
    /// every row could be settled: a crash, a release the authority never
    /// confirmed, and a re-acquire adopted from a snapshot while the authority
    /// was still refusing queries each leave a row for the next start to
    /// settle. That last one is the confirmed-release case -- the adoption
    /// proves the fence but not the receipt, so the acquire's row and the
    /// receipt it owes stay until a query can be answered.
    ///
    /// Runs under the default budget; [`Self::release_instance_lease_until`]
    /// takes the caller's deadline and [`Self::release_instance_lease_within`]
    /// a budget the erase is not charged to.
    pub fn release_instance_lease(&self) -> Result<(), AgentError> {
        match self.release_instance_lease_until(default_deadline()?)? {
            LeaseReleaseOutcome::Released => Ok(()),
            LeaseReleaseOutcome::ReleasedWithFailure(error) => Err(error),
        }
    }

    /// [`Self::release_instance_lease`] under the caller's `deadline`.
    ///
    /// One authority round trip -- the release dispatch -- and the durable
    /// journal commit `lease_exchange` admits with it
    /// (`DURABLE_COMMIT_RESERVE`) are the least it needs, and that pair is
    /// admitted first, before anything is erased: a refusal,
    /// [`AgentError::OperationDeadlineExceeded`], changes nothing, the lease
    /// still serves, and the call may be repeated with a longer deadline.
    /// Every round trip after that is admitted the same way; a refusal once
    /// the release is under way keeps the fence for a later call exactly as
    /// an unreachable authority does, and is never reported as released.
    ///
    /// `Err` never means this call released the lease: it is still held by
    /// this instance, or -- when a fence or an earlier release had already
    /// given it up and this call was refused before dispatching anything --
    /// there was nothing left to release. The erase and the journal forget
    /// are bookkeeping around a release that did settle, so their failure is
    /// [`LeaseReleaseOutcome::ReleasedWithFailure`] rather than an `Err`.
    ///
    /// The erase between the admission and the release is **not** admitted
    /// against `deadline`: it costs one `Durability::Immediate` two-phase
    /// commit per pending session, up to `HARD_MAX_SESSIONS` of them, and
    /// nothing may be skipped. A caller that owns the wall clock rather than
    /// an instant -- the stop path -- should use
    /// [`Self::release_instance_lease_within`], which gives the release its
    /// budget afresh once the erase is done.
    pub fn release_instance_lease_until(
        &self,
        deadline: Instant,
    ) -> Result<LeaseReleaseOutcome, AgentError> {
        let mut inner = self.lock_until(OperationDeadline { at: deadline })?;
        release_under_lock(&mut inner, None)
    }

    /// [`Self::release_instance_lease`] with `budget` for the release itself,
    /// measured from after the erase.
    ///
    /// The difference from [`Self::release_instance_lease_until`] is the
    /// accounting, not the order: the pre-erase admission of one authority
    /// round trip and the release dispatch's own journal commit still comes
    /// first, so a budget too short to release erases nothing. What follows
    /// it -- one durable `cancel_session` per pending session, up to
    /// `HARD_MAX_SESSIONS` of them, two fsyncs each -- is charged to the
    /// caller's stop timeout rather than to `budget`, and the release then
    /// runs under a deadline `budget` from the moment the last secret is
    /// gone. Charging the erase to the release budget instead would
    /// let a large session table on a slow store spend it before the release
    /// is dispatched, leaving the lease to lapse at its TTL.
    pub fn release_instance_lease_within(
        &self,
        budget: Duration,
    ) -> Result<LeaseReleaseOutcome, AgentError> {
        let mut inner = self.lock_until(OperationDeadline::fresh(budget)?)?;
        release_under_lock(&mut inner, Some(budget))
    }

    /// Every lease intent still journaled in the repository.
    #[cfg(all(test, unix))]
    pub(crate) fn journaled_lease_intents_for_test(
        &self,
    ) -> Result<Vec<OperationIdV2>, AgentError> {
        let inner = self.lock()?;
        Ok(inner.repository.journaled_lease_intents()?)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn remove_durable_reservation_for_test(
        &self,
        handle: PendingSessionHandle,
    ) -> Result<(), AgentError> {
        let inner = self.lock()?;
        ensure_live(&inner)?;
        if !inner.pending_sessions.contains_key(&handle) {
            return Err(AgentError::UnknownHandle);
        }
        inner.repository.cancel_session(handle.0)?;
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn acceptance_counts_for_test(&self) -> Result<(usize, usize), AgentError> {
        let inner = self.lock()?;
        ensure_live(&inner)?;
        Ok((
            inner.confirmed_keys.len(),
            inner.completed_acceptances.len(),
        ))
    }

    /// Erase every pending session whose TTL has already elapsed.
    ///
    /// Every request path purges before it acts, so this covers only the idle
    /// case. Without it the TTL means "erased when the agent is next used"
    /// rather than "erased on time", and a daemon that stops receiving requests
    /// keeps expired session key material in memory for as long as it stays
    /// quiet. The serving loop calls this whenever its accept wait times out.
    ///
    /// This is cleanup, so it requires nothing and reports nothing. It takes no
    /// instance lease, because releasing a secret must not depend on holding
    /// one, and it does not check liveness, because a poisoned agent is
    /// precisely when the secrets should still go. `erase_pending` drops the
    /// key material before it touches the repository, so a session whose
    /// durable reservation fails to release has still lost its secret and the
    /// sweep continues rather than stranding every session behind it.
    ///
    /// It also never waits. It takes the lock only if it is free, and a pass
    /// that finds the agent busy is skipped: the four heaviest request paths
    /// purge expired sessions themselves on entry, and the serving loop runs
    /// this again one maintenance interval later. Waiting would only delay the
    /// next accept by however long the holder takes -- and that is not always
    /// its deadline, because the durable work no deadline admits runs on top
    /// of it: the stop's erase, one `Durability::Immediate` commit per pending
    /// session and charged to the stop timeout alone, is the unbounded case,
    /// and the purge those four request paths run on entry is the same
    /// unadmitted work.
    pub fn expire_idle_sessions(&self) {
        let Some(mut inner) = self.try_lock_now() else {
            return;
        };
        for handle in expired_handles(&inner, Instant::now()) {
            let _ = erase_pending(&mut inner, handle);
        }
    }

    /// Number of pending sessions currently held, expired or not.
    ///
    /// Every request path purges before it acts, so the idle sweep cannot be
    /// observed through the public API: by the time a caller could ask, the
    /// question has already answered itself. This exists so the tests can see
    /// that an expired session really does survive until something sweeps it,
    /// and really does go when the sweep runs.
    // Gated exactly like its only caller: `mod tests` is `cfg(all(test, unix))`,
    // so a plain `cfg(test)` here is dead code in a Windows test build.
    #[cfg(all(test, unix))]
    pub(crate) fn pending_session_count(&self) -> usize {
        self.lock().map_or(0, |inner| inner.pending_sessions.len())
    }

    /// Number of confirmed application keys currently retained.
    #[cfg(all(test, unix))]
    pub(crate) fn confirmed_key_count(&self) -> usize {
        self.lock().map_or(0, |inner| inner.confirmed_keys.len())
    }

    /// Drop one session's durable reservation while leaving it in memory, so a
    /// later erase of it fails the way a corrupt or diverged store would.
    #[cfg(all(test, unix))]
    pub(crate) fn desynchronize_session_for_test(
        &self,
        handle: PendingSessionHandle,
    ) -> Result<(), AgentError> {
        let inner = self.lock()?;
        inner.repository.cancel_session(handle.0)?;
        Ok(())
    }

    /// Fence this instance out directly, without waiting for the authority to
    /// reject a lease.
    #[cfg(all(test, unix))]
    pub(crate) fn fence_out_for_test(&self) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        lease::fence_out(&mut inner)
    }

    /// Make the next durable session reserve or release take this long after
    /// it commits, so a test can lapse the lease coverage *inside* the durable
    /// write rather than before it.
    #[cfg(all(test, unix))]
    pub(crate) fn delay_next_durable_write_for_test(
        &self,
        delay: Duration,
    ) -> Result<(), AgentError> {
        let inner = self.lock()?;
        inner
            .repository
            .delay_after_next_durable_write_for_test(delay);
        Ok(())
    }

    /// Test-only: whether the durable-write delay armed above is still
    /// unpaid, i.e. no durable session reserve or release has run since. A
    /// test that expects a refusal *before* the write asserts this rather
    /// than timing the refusal.
    #[cfg(all(test, unix))]
    pub(crate) fn durable_write_delay_armed_for_test(&self) -> Result<bool, AgentError> {
        let inner = self.lock()?;
        Ok(inner.repository.durable_write_delay_armed_for_test())
    }

    /// Make every durable session cancellation take this long after it
    /// commits, so a test can make the stop's unbounded erase outlast a
    /// release budget the way a large session table on a slow store does.
    #[cfg(all(test, unix))]
    pub(crate) fn delay_each_session_cancel_for_test(
        &self,
        delay: Duration,
    ) -> Result<(), AgentError> {
        let inner = self.lock()?;
        inner
            .repository
            .delay_after_each_session_cancel_for_test(delay);
        Ok(())
    }

    /// Fail the next lease-journal write as a corrupt store would, before
    /// anything is committed, so a test can see what a lease operation does
    /// when its intent cannot be journaled for storage reasons.
    #[cfg(all(test, unix))]
    pub(crate) fn fail_next_lease_journal_write_for_test(&self) -> Result<(), AgentError> {
        let inner = self.lock()?;
        inner.repository.fail_next_lease_journal_write_for_test();
        Ok(())
    }

    /// Poison the linearizer the way a panic under it would, so a test can
    /// see that a poisoned lock is reported at once rather than waited on.
    #[cfg(all(test, unix))]
    #[allow(clippy::panic)]
    pub(crate) fn poison_linearizer_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = self.inner.lock();
            panic!("poisoning the linearizer for a test");
        }));
    }

    /// Take the linearizer and never give it back, so a test can drive an
    /// agent whose lock is held past every deadline a caller could give it --
    /// the stop's erase is the real holder of that shape, bounded by no
    /// deadline at all.
    ///
    /// The guard is leaked deliberately: the hold has to outlive every borrow
    /// of this agent, including the move into the IPC server, which no scoped
    /// thread can survive. Nothing else may use this agent afterwards; every
    /// call on it waits out its own deadline and is refused. Dropping a locked
    /// `Mutex` is well defined, so the agent still drops normally at the end
    /// of the test.
    #[cfg(all(test, unix))]
    pub(crate) fn hold_linearizer_for_test(&self) {
        match self.inner.lock() {
            Ok(held) => std::mem::forget(held),
            Err(poisoned) => std::mem::forget(poisoned.into_inner()),
        }
    }

    /// Number of durable session reservations the repository currently holds.
    #[cfg(all(test, unix))]
    pub(crate) fn durable_session_count_for_test(&self) -> Result<u64, AgentError> {
        let inner = self.lock()?;
        Ok(inner.repository.durable_session_count_for_test()?)
    }

    /// Take the lock under the default budget. Every production path carries
    /// a deadline of its own; this is what the test hooks use.
    #[cfg(all(test, unix))]
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner<W, A>>, AgentError> {
        self.lock_until(OperationDeadline::fresh(DEFAULT_OPERATION_BUDGET)?)
    }

    /// Take the lock within `deadline`, and set it as the deadline every
    /// admission inside it reads.
    ///
    /// `std::sync::Mutex` offers no timed acquisition, so this polls
    /// `try_lock` and sleeps `LINEARIZER_POLL_PAUSE` between attempts, the
    /// last sleep clamped so the wait ends exactly at the deadline. A
    /// deadline already reached is refused without an attempt, which is
    /// `admit(Duration::ZERO)` at the door. `try_lock` is not queued, so a
    /// waiter can be barged past by other threads; the deadline is what
    /// bounds that, and the refusal is the same.
    ///
    /// Poisoning is decided on the first attempt and never waited on: no
    /// amount of waiting clears it, and the IPC face turns
    /// [`AgentError::InternalPoisoned`] into a fatal stop rather than into a
    /// status-24 response.
    fn lock_until(
        &self,
        deadline: OperationDeadline,
    ) -> Result<std::sync::MutexGuard<'_, Inner<W, A>>, AgentError> {
        loop {
            // The door is `admit(Duration::ZERO)`: a deadline already reached
            // admits nothing, not even an acquisition that would not block.
            let Some(remaining) = deadline.remaining() else {
                return Err(AgentError::OperationDeadlineExceeded);
            };
            match self.inner.try_lock() {
                Ok(mut inner) => {
                    inner.deadline = deadline;
                    return Ok(inner);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(AgentError::InternalPoisoned)
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining.min(LINEARIZER_POLL_PAUSE));
                }
            }
        }
    }

    /// Take the lock only if it is free right now.
    ///
    /// The one caller is the idle sweep, which must never wait: see
    /// [`Self::expire_idle_sessions`].
    fn try_lock_now(&self) -> Option<std::sync::MutexGuard<'_, Inner<W, A>>> {
        let mut inner = self.inner.try_lock().ok()?;
        // The sweep admits nothing: it makes no port call, and a future edit
        // that added one must be refused here rather than run on a budget
        // nobody granted. The same already-reached value the constructor
        // installs.
        inner.deadline = OperationDeadline { at: Instant::now() };
        Some(inner)
    }
}

/// The deadline a plain (non-`_until`) operation gives itself.
fn default_deadline() -> Result<Instant, AgentError> {
    OperationDeadline::fresh(DEFAULT_OPERATION_BUDGET).map(|deadline| deadline.at)
}

/// The body of every release: erase, release, forget, with `Err` reserved for
/// a lease this instance still holds.
///
/// `budget_after_erase` is `Some` for the callers that own a budget rather
/// than an instant: the release deadline is then re-derived once the erase is
/// done, so the unadmitted durable cancellations do not spend it.
fn release_under_lock<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    budget_after_erase: Option<Duration>,
) -> Result<LeaseReleaseOutcome, AgentError> {
    ensure_live(inner)?;
    if inner.lease.phase == LeasePhase::Retired {
        // Nothing is held, so a failed forget is bookkeeping around a release
        // that already settled, never a lease left behind.
        return Ok(match forget_settled(&inner.repository, &mut inner.lease) {
            Ok(()) => LeaseReleaseOutcome::Released,
            Err(error) => LeaseReleaseOutcome::ReleasedWithFailure(error),
        });
    }
    // Admitted before the erase, so a deadline too short to release the lease
    // leaves every secret where it is and the lease serving. What the release
    // really needs is its round trip and the journal commit `lease_exchange`
    // admits with it, so the gate covers both.
    inner.deadline.admit(
        inner
            .authority
            .round_trip_bound()
            .saturating_add(DURABLE_COMMIT_RESERVE),
    )?;
    // Erase first, and report a failure only once the release has been
    // settled: `erase_pending` drops each secret before it touches the
    // repository, so a failed durable cancellation still erases, and a
    // lease released with its secrets gone is what a stop must leave
    // behind whether or not the bookkeeping succeeded.
    let erase_failure = erase_all_secrets(inner);
    if let Some(budget) = budget_after_erase {
        inner.deadline = OperationDeadline::fresh(budget)?;
    }
    let released = release_lease_state(
        &inner.repository,
        &inner.authority,
        &mut inner.lease,
        inner.deadline,
    );
    // No journal write follows a release, so the rows this process settled
    // would otherwise wait for the next start to find them absent. Forget
    // them now, whatever the release's outcome.
    let forgotten = forget_settled(&inner.repository, &mut inner.lease);
    released?;
    Ok(match erase_failure.map_or(Ok(()), Err).and(forgotten) {
        Ok(()) => LeaseReleaseOutcome::Released,
        Err(error) => LeaseReleaseOutcome::ReleasedWithFailure(error),
    })
}

/// What construction derives from the repository and the configuration once
/// the lease is held, gathered before any of it is committed to an `Inner`.
struct PreparedExecution {
    engine: ExecutorState,
    pending_engine: Option<ExecutorState>,
    local_policy: AuthenticatedPolicy,
    peer_policy: AuthenticatedPolicy,
}

/// Every fallible step of construction after the acquire: align local state
/// with the mandatory witness, build the executor for the committed state and
/// for a pending one, and authenticate the configured policy material. Kept
/// apart from `with_lease` so that a failure here can release the lease.
fn prepare_execution<W: WitnessPort>(
    repository: &mut StateRepository,
    witness: &W,
    config: &AgentConfig,
) -> Result<PreparedExecution, AgentError> {
    align_repository(repository, witness)?;
    let committed = repository.committed_state();
    let engine = executor_for(&config.execution_policy, committed.state())?;
    let local_policy = config.local_endpoint_policy.authenticate()?;
    let peer_policy = config.peer_endpoint_policy.authenticate()?;
    let pending_engine = if repository.pending_intent().is_some() {
        Some(executor_for(
            &config.execution_policy,
            repository
                .pending_next_state()
                .ok_or(AgentError::InternalPoisoned)?,
        )?)
    } else {
        None
    };
    Ok(PreparedExecution {
        engine,
        pending_engine,
        local_policy,
        peer_policy,
    })
}

fn align_repository<W: WitnessPort>(
    repository: &mut StateRepository,
    witness: &W,
) -> Result<(), AgentError> {
    let Some(intent) = repository.pending_intent() else {
        return (witness.read_head()? == repository.head()?)
            .then_some(())
            .ok_or(AgentError::RollbackOrFork);
    };
    match witness.query(intent.operation_id())? {
        WitnessOutcome::Unknown => Ok(()),
        WitnessOutcome::Known(receipt) if receipt.is_exact_applied(intent) => {
            repository.commit_applied(*receipt)?;
            Ok(())
        }
        WitnessOutcome::Known(receipt)
            if receipt.disposition() == WitnessDisposition::NotApplied =>
        {
            repository.validate_unapplied(*receipt)?;
            Ok(())
        }
        WitnessOutcome::Known(_) => Err(AgentError::RollbackOrFork),
    }
}

fn executor_for(
    policy: &SignedPolicyBundle,
    state: q_periapt_migration::MigrationStateV1,
) -> Result<ExecutorState, AgentError> {
    let authenticated = policy.authenticate()?;
    let execution = authenticated.resolve_suite(&[HybridSuite::MlKem768X25519]);
    if authenticated.trusted_state() != state.execution_policy_state()
        || state.posture().component_mode() != q_periapt_migration::ComponentMode::HybridRequired
        || !state.allowed_suites().contains(HybridSuite::MlKem768X25519)
        || state.posture().minimum_pq_level().to_u8() > 3
    {
        return Ok(ExecutorState::Blocked);
    }
    let Ok(execution) = execution else {
        return Ok(ExecutorState::Blocked);
    };
    if execution.resolved().profile() != Profile::ContextBound
        || execution.resolved().key_format() != KeyFormat::Expanded
    {
        return Ok(ExecutorState::Blocked);
    }
    Abi2Engine::provision(
        &policy.document,
        &policy.signature,
        &policy.verification_key,
        state.execution_policy_state(),
    )
    .map(Box::new)
    .map(ExecutorState::Available)
    .map_err(AgentError::from)
}

/// Admit the witness round trip, then dispatch the CAS.
///
/// Used where the CAS follows a round trip of its own that the operation's
/// plan did not reserve -- Reconcile's conditional CAS after its query -- so
/// the bound has to be admitted here. The bare bound is right for it:
/// Reconcile's intent is already on disk, so nothing durable stands between
/// this admission and its CAS. Advance and Reset admit the witness bound
/// together with the reserve for the durable intent they are about to write,
/// then call [`dispatch_transition`] directly.
fn execute_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    intent: crate::witness::WitnessIntent,
) -> Result<(), AgentError> {
    inner.deadline.admit(inner.witness.round_trip_bound())?;
    dispatch_transition(inner, intent)
}

/// Dispatch one witness CAS and account for what it answered.
///
/// Deliberately takes no admission of its own: past the durable intent the
/// clock no longer decides. Refusing here would strand a pending transition
/// the witness never saw, which only Reconcile clears; the caller is
/// responsible for admitting the round trip, and any durable commit that
/// precedes it, while nothing is committed.
fn dispatch_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    intent: crate::witness::WitnessIntent,
) -> Result<(), AgentError> {
    match inner.witness.compare_and_advance(intent)? {
        WitnessOutcome::Unknown => Err(AgentError::TransitionIndeterminate),
        WitnessOutcome::Known(receipt) if receipt.is_exact_applied(intent) => {
            finish_transition(inner, *receipt)
        }
        WitnessOutcome::Known(_) => Err(AgentError::RollbackOrFork),
    }
}

/// Commit a transition the witness reports applied.
///
/// Deliberately not gated by the operation deadline: past the witness's
/// `Known(applied)` the transition is committed externally, the commit here is
/// a local fsync, and the truthful answer is `Ok` whatever the clock says. A
/// response that then misses its deadline is a lost response, which the
/// caller reconciles.
fn finish_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    receipt: WitnessReceipt,
) -> Result<(), AgentError> {
    if inner.repository.commit_applied(receipt).is_err() {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    // The durable commit already erased all reservations and tombstones.
    // Dropping these maps erases every in-process pending/accepted secret, and
    // the Begin retry records that pointed at them, before any new request.
    inner.pending_sessions.clear();
    inner.begun_capabilities.clear();
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    inner.engine = inner.pending_engine.take().ok_or_else(|| {
        inner.poisoned = true;
        AgentError::InternalPoisoned
    })?;
    Ok(())
}

fn build_contract<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
    authorization: SessionAuthorization,
    encapsulator_role: EndpointRole,
    receiver_keys: EncapsulationPublicKeys,
) -> Result<
    (
        MigrationContextV2,
        Abi2MigrationApplicationContextV2,
        [u8; 32],
    ),
    AgentError,
> {
    let local_signed = decode_canonical_offer(&authorization.local_offer)?;
    let peer_signed = decode_canonical_offer(&authorization.peer_offer)?;
    let local = local_signed
        .authenticate(
            &MlDsa65,
            &inner.config.local_identity.verification_key,
            inner.config.local_identity.key_id,
        )
        .map_err(|_| AgentError::AuthorizationRejected)?;
    let peer = peer_signed
        .authenticate(
            &MlDsa65,
            &inner.config.peer_identity.verification_key,
            inner.config.peer_identity.key_id,
        )
        .map_err(|_| AgentError::AuthorizationRejected)?;
    let committed = inner.repository.committed_state();
    let execution = inner.engine.available()?.execution();
    let negotiation =
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: inner.config.local_role,
            local_offer: local,
            peer_offer: peer,
            local_policy: &inner.local_policy,
            peer_policy: &inner.peer_policy,
            committed_state: committed,
            execution,
        })
        .map_err(|_| AgentError::AuthorizationRejected)?;
    let receiver_key_share =
        EndpointKeyShareV1::new(receiver_keys.pq(), receiver_keys.traditional())
            .map_err(|_| AgentError::PublicInputRejected)?;
    let pre_kem = PreKemTranscriptV1::from_authenticated_contract(
        negotiation,
        committed,
        execution,
        encapsulator_role,
        receiver_key_share,
    )
    .map_err(|_| AgentError::AuthorizationRejected)?;
    let context =
        MigrationContextV2::from_authenticated_contract(AuthenticatedMigrationContextV2Input {
            local_role: inner.config.local_role,
            encapsulator_role,
            execution,
            local_policy: &inner.local_policy,
            peer_policy: &inner.peer_policy,
            committed_state: committed,
            negotiation,
            pre_kem: &pre_kem,
        })
        .map_err(|_| AgentError::AuthorizationRejected)?;
    let abi_context = Abi2MigrationApplicationContextV2::try_from(&context)
        .map_err(|_| AgentError::AuthorizationRejected)?;
    Ok((context, abi_context, *negotiation.session_id().as_bytes()))
}

fn decode_canonical_offer(bytes: &[u8]) -> Result<SignedCapabilityOfferV1, AgentError> {
    let value =
        SignedCapabilityOfferV1::decode(bytes).map_err(|_| AgentError::AuthorizationRejected)?;
    if value
        .encode()
        .map_err(|_| AgentError::AuthorizationRejected)?
        != bytes
    {
        return Err(AgentError::AuthorizationRejected);
    }
    Ok(value)
}

fn verify_current_head<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<StateHead, AgentError> {
    if inner.repository.pending_intent().is_some() {
        return Err(AgentError::TransitionPending);
    }
    let local = inner.repository.head()?;
    inner.deadline.admit(inner.witness.round_trip_bound())?;
    if inner.witness.read_head()? != local {
        return Err(AgentError::RollbackOrFork);
    }
    Ok(local)
}

fn pending_deadline<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<Instant, AgentError> {
    Instant::now()
        .checked_add(inner.config.limits.session_ttl)
        .ok_or(AgentError::InvalidConfiguration)
}

/// Draw a pending-session handle that collides with nothing still live.
fn generate_pending_handle<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<PendingSessionHandle, AgentError> {
    for _ in 0..4 {
        let handle = PendingSessionHandle(
            SessionId::generate().map_err(|_| AgentError::LocalCryptoFailure)?,
        );
        if !inner.pending_sessions.contains_key(&handle)
            && !inner.completed_acceptances.contains_key(&handle)
        {
            return Ok(handle);
        }
    }
    Err(AgentError::LocalCryptoFailure)
}

/// The nonce-free identity of one Begin: what, besides the capability itself,
/// shaped its response. The IPC nonce is left out on purpose -- that is what
/// makes a retry under a fresh nonce exact -- and the command tag is put in,
/// so the two Begin commands never answer for each other.
fn begin_request_digest(
    tag: &[u8; 1],
    authorization: &SessionAuthorization,
    public_input: (&[u8], &[u8]),
) -> Result<[u8; 32], AgentError> {
    crate::codec::hash_fields(
        BEGIN_REPLAY_DOMAIN,
        &[
            tag,
            &authorization.local_offer,
            &authorization.peer_offer,
            public_input.0,
            public_input.1,
        ],
    )
    .map_err(|_| AgentError::LocalCryptoFailure)
}

/// Answer an exact Begin retry from the pending session its capability
/// created.
///
/// `Ok(Some(replay))`: the same request, and its session is still live --
/// return it. `Ok(None)`: nothing live under this capability; take the fresh
/// path, which ends in the durable tombstone check and, for a consumed
/// capability, in [`AgentError::AuthorizationRejected`].
/// `Err(AuthorizationRejected)`: the capability is live under a different
/// request; the original handle stays acceptable and nothing is erased.
fn lookup_begun_capability<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    capability_session_id: [u8; 32],
    request_digest: [u8; 32],
) -> Result<Option<BeginReplay>, AgentError> {
    let Some(handle) = inner
        .begun_capabilities
        .get(&capability_session_id)
        .copied()
    else {
        return Ok(None);
    };
    let Some(pending) = inner.pending_sessions.get(&handle) else {
        // Defensive only: `take_pending` keeps the two maps in step.
        inner.begun_capabilities.remove(&capability_session_id);
        return Ok(None);
    };
    let begun = pending.begun();
    if begun.capability_session_id != capability_session_id {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    if begun.request_digest != request_digest {
        // Same signed capability, different public input or command: the
        // capability is consumed, and this is not the request that consumed
        // it. Both digests are over public values, so a plain comparison is
        // enough; the tombstone on the fresh path fails closed regardless.
        return Err(AgentError::AuthorizationRejected);
    }
    // Clone the replay before the coverage proof so the borrow of the pending
    // session ends: `prove_lease_covers_retention` needs `&mut inner`.
    let replay = begun.replay.clone();
    // Returning a handle to a retained secret is a lease-guarded disclosure,
    // exactly as retaining it was, so it is gated exactly as the fresh path
    // gates the secret it retains. The post-renew proof is consulted first as
    // the budgeted early-out. But a witness round trip (`verify_current_head`)
    // has run since that proof was taken, and authority time can step past the
    // lease's expiry during that round trip without this host's clock
    // moving -- which the recorded deadline, being local, cannot see. So a
    // fresh authority observation is taken after that last I/O, then the
    // budgeted rule against it and the operation's own deadline
    // (`prove_lease_covers_retention`), exactly as `reserve_pending` does before
    // it retains a fresh secret.
    //
    // The budgeted early-out is not a fence: a local deadline running out is no
    // evidence that a successor exists. The fresh proof is, exactly as it is on
    // the fresh path -- a snapshot showing a successor, a rolled-back authority
    // or a foreign fence retires this instance and erases every secret, this
    // retry's own session included, and the retry answers `InstanceFenced`
    // instead of the replay.
    ensure_may_retain(inner)?;
    prove_lease_covers_retention(inner)?;
    Ok(Some(replay))
}

/// The one place a pending session leaves the map, so the Begin retry index
/// can never outlive the session it points at.
fn take_pending<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    handle: PendingSessionHandle,
) -> Option<PendingSession> {
    let pending = inner.pending_sessions.remove(&handle)?;
    let capability = pending.begun().capability_session_id;
    if inner.begun_capabilities.get(&capability) == Some(&handle) {
        inner.begun_capabilities.remove(&capability);
    }
    Some(pending)
}

/// Reserve one pending session durably and retain it, with the record an
/// exact retry of its Begin is answered from.
///
/// `build` receives the handle drawn for the session and returns the session
/// -- whose `begun` record names the capability the reservation is keyed by
/// and holds the replay -- together with the result the caller returns. The
/// session, its retry record and the index entry are therefore written as
/// one, so "a retry record exists iff its session does" holds by
/// construction.
fn reserve_pending<W: WitnessPort, A: InstanceAuthorityPort, R, F>(
    inner: &mut Inner<W, A>,
    head: StateHead,
    build: F,
) -> Result<R, AgentError>
where
    F: FnOnce(PendingSessionHandle) -> (PendingSession, R),
{
    let handle = generate_pending_handle(inner)?;
    inner
        .pending_sessions
        .try_reserve(1)
        .map_err(|_| AgentError::LocalResourceFailure)?;
    inner
        .begun_capabilities
        .try_reserve(1)
        .map_err(|_| AgentError::LocalResourceFailure)?;
    let (pending, result) = build(handle);
    let capability_session_id = pending.begun().capability_session_id;
    inner
        .repository
        .reserve_session(handle.0, capability_session_id, head)?;
    // The durable reservation is a real fsync, and authority time may have
    // stepped past the lease's expiry during the witness round trip, the
    // KEM or that fsync without this host's clock moving. This is the last
    // step before the secret becomes retained, so the check that counts
    // consults the authority: a fresh snapshot after the write, then the
    // budgeted local rule against it and the operation's own deadline
    // (`prove_lease_covers_retention`); the check before the write only
    // saves a wasted fsync. Whatever it reports -- coverage elapsed, the
    // deadline reached, the authority unreachable, or a successor that
    // fenced this instance -- the reservation must not be left behind:
    // `erase_pending` could never find it, and `fence_out`
    // iterates a map this handle is not in yet. So release it here and
    // drop the secret with `pending`. The capability tombstone the
    // reservation wrote stays, exactly as it does for any cancelled
    // session: the offer was consumed the moment it was reserved, and the
    // caller needs a fresh offer to try again. The retry index is written
    // only after this proof succeeds, together with the session it points
    // at, so an exact retry is never answered with a handle that was never
    // retained.
    if let Err(error) = prove_lease_covers_retention(inner) {
        if inner.repository.cancel_session(handle.0).is_err() {
            inner.poisoned = true;
            return Err(AgentError::InternalPoisoned);
        }
        return Err(error);
    }
    if inner.pending_sessions.insert(handle, pending).is_some() {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    // A second live entry under one capability is impossible: the durable
    // tombstone just written would already have refused the reservation.
    if inner
        .begun_capabilities
        .insert(capability_session_id, handle)
        .is_some()
    {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingFlight {
    Initiator,
    Responder,
}

fn prepare_acceptance<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    handle: PendingSessionHandle,
    flight: PendingFlight,
) -> Result<(StateHead, ConfirmedKeyHandle), AgentError> {
    ensure_live(inner)?;
    if matches!(inner.pending_sessions.get(&handle), Some(pending) if pending.is_expired(Instant::now()))
    {
        erase_pending(inner, handle)?;
        return Err(AgentError::SessionExpired);
    }
    purge_expired(inner)?;
    let pending = inner
        .pending_sessions
        .get(&handle)
        .ok_or(AgentError::UnknownHandle)?;
    let expected_variant = matches!(
        (flight, pending),
        (PendingFlight::Initiator, PendingSession::Responder { .. })
            | (PendingFlight::Responder, PendingSession::Initiator { .. })
    );
    if !expected_variant {
        return Err(AgentError::UnexpectedFlight);
    }
    if inner.repository.pending_intent().is_some() {
        return Err(AgentError::TransitionPending);
    }
    if inner.confirmed_keys.len() >= inner.config.limits.max_confirmed_keys
        || inner.completed_acceptances.len() >= inner.config.limits.max_confirmed_keys
    {
        return Err(AgentError::CapacityExceeded);
    }
    let expected_head = pending.expected_head();
    if inner.repository.head()? != expected_head {
        erase_pending(inner, handle)?;
        return Err(AgentError::StaleSession);
    }
    // Admitted before the read, so a refused request leaves the pending
    // session exactly as it found it.
    inner.deadline.admit(inner.witness.round_trip_bound())?;
    if inner.witness.read_head()? != expected_head {
        erase_pending(inner, handle)?;
        return Err(AgentError::StaleSession);
    }
    inner
        .confirmed_keys
        .try_reserve(1)
        .map_err(|_| AgentError::LocalResourceFailure)?;
    inner
        .completed_acceptances
        .try_reserve(1)
        .map_err(|_| AgentError::LocalResourceFailure)?;
    let key_handle = generate_key_handle(&inner.confirmed_keys)?;
    Ok((expected_head, key_handle))
}

fn cancel_consumed_session<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    handle: PendingSessionHandle,
) -> Result<(), AgentError> {
    if inner.repository.cancel_session(handle.0).is_err() {
        inner.poisoned = true;
        Err(AgentError::InternalPoisoned)
    } else {
        Ok(())
    }
}

fn map_confirmation_setup_error<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    _error: q_periapt_migration::ConfirmationError,
) -> AgentError {
    // The role, context, and post-KEM transcript were all derived inside this
    // locked service operation. Constructor rejection therefore denotes an
    // internal invariant failure, not caller authorization failure.
    inner.poisoned = true;
    AgentError::InternalPoisoned
}

fn map_confirmation_error<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    error: q_periapt_migration::ConfirmationError,
) -> AgentError {
    match error {
        q_periapt_migration::ConfirmationError::StaleState => AgentError::StaleSession,
        q_periapt_migration::ConfirmationError::PeerFinishedMismatch => {
            AgentError::FinishedRejected
        }
        _ => {
            inner.poisoned = true;
            AgentError::InternalPoisoned
        }
    }
}

fn restore_unexpected<W: WitnessPort, A: InstanceAuthorityPort, T>(
    inner: &mut Inner<W, A>,
    handle: PendingSessionHandle,
    pending: PendingSession,
) -> Result<T, AgentError> {
    // Unreachable in practice, since `prepare_acceptance` checked the variant
    // before the session was taken. Put back both the session and the retry
    // index entry that `take_pending` removed with it.
    let capability_session_id = pending.begun().capability_session_id;
    if inner.pending_sessions.insert(handle, pending).is_some()
        || inner
            .begun_capabilities
            .insert(capability_session_id, handle)
            .is_some()
    {
        inner.poisoned = true;
        Err(AgentError::InternalPoisoned)
    } else {
        Err(AgentError::UnexpectedFlight)
    }
}

fn retain_accepted_key<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    pending_handle: PendingSessionHandle,
    expected_head: StateHead,
    key_handle: ConfirmedKeyHandle,
    accepted: AcceptedSessionKeyV1,
    completed: CompletedAcceptance,
) -> Result<(), AgentError> {
    if inner
        .repository
        .release_session(pending_handle.0, expected_head)
        .is_err()
    {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    // The durable release is a real fsync, and authority time may have stepped
    // past the lease's expiry during the witness round trip or that fsync
    // without this host's clock moving. This is the last step before the
    // accepted key becomes retained, so the check that counts consults the
    // authority: a fresh snapshot after the write, then the budgeted local
    // rule against it and the operation's own deadline
    // (`prove_lease_covers_retention`); the caller's check before the write
    // only saves a wasted fsync. Nothing needs undoing on any of its errors:
    // the reservation is gone, which is where an accepted session ends up
    // either way, and `accepted` is dropped here without ever being
    // reachable. A coverage lapse, a reached deadline or an unreachable
    // authority is not a fence and not a poison; a successor seen by that
    // snapshot fences, and `fence_out` has erased every other secret by then.
    prove_lease_covers_retention(inner)?;
    if inner.confirmed_keys.insert(key_handle, accepted).is_some() {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    if inner
        .completed_acceptances
        .insert(pending_handle, completed)
        .is_some()
    {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    Ok(())
}

fn erase_pending<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    handle: PendingSessionHandle,
) -> Result<(), AgentError> {
    let removed = take_pending(inner, handle).ok_or(AgentError::UnknownHandle)?;
    drop(removed);
    if inner.repository.cancel_session(handle.0).is_err() {
        inner.poisoned = true;
        Err(AgentError::InternalPoisoned)
    } else {
        Ok(())
    }
}

fn expired_handles<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
    now: Instant,
) -> Vec<PendingSessionHandle> {
    inner
        .pending_sessions
        .iter()
        .filter_map(|(handle, pending)| pending.is_expired(now).then_some(*handle))
        .collect()
}

fn purge_expired<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    for handle in expired_handles(inner, Instant::now()) {
        erase_pending(inner, handle)?;
    }
    Ok(())
}

fn ensure_session_capacity<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.pending_sessions.len() >= inner.config.limits.max_pending_sessions {
        Err(AgentError::CapacityExceeded)
    } else {
        Ok(())
    }
}

fn generate_key_handle(
    keys: &HashMap<ConfirmedKeyHandle, AcceptedSessionKeyV1>,
) -> Result<ConfirmedKeyHandle, AgentError> {
    for _ in 0..4 {
        let handle =
            ConfirmedKeyHandle(SessionId::generate().map_err(|_| AgentError::LocalCryptoFailure)?);
        if !keys.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(AgentError::LocalCryptoFailure)
}

fn ensure_live<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.poisoned {
        Err(AgentError::InternalPoisoned)
    } else {
        Ok(())
    }
}

/// Closed lease-mutation dispatch selector for one authority exchange.
const fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}
