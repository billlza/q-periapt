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
use crate::repository::{RepositoryError, StateRepository};
use crate::types::{SessionId, StateHead};
use crate::witness::{
    WitnessDisposition, WitnessError, WitnessOutcome, WitnessPort, WitnessReceipt,
};

const MAX_SIGNED_OFFER_BYTES: usize = 16 * 1024;
const HARD_MAX_SESSIONS: usize = 1024;
const HARD_MAX_CONFIRMED_KEYS: usize = 1024;
const MAX_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_UNACKNOWLEDGED_LEASE_RECEIPTS: usize = 64;
const LEASE_VERSION_RESYNC_ATTEMPTS: usize = 2;

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
    /// Signed capability offers, identities, policies, roles, or agreement were rejected.
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
    /// Another process instance holds or took the exclusive key-use lease; every
    /// in-process pending and accepted secret of this instance was erased.
    InstanceFenced,
    /// The mandatory instance-lease authority failed closed; the operation did not run.
    InstanceLeaseUnavailable,
    /// A lease operation outcome stayed unknown after exact-operation reconciliation.
    InstanceLeaseIndeterminate,
    /// The process linearizer was poisoned; no operation continued.
    InternalPoisoned,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy agent rejected operation: {self:?}")
    }
}

impl std::error::Error for AgentError {}

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

enum PendingSession {
    Initiator {
        confirmation: InitiatorAwaitingResponderFinishedV1<Sha3_256Xof>,
        expected_head: StateHead,
        deadline: Instant,
    },
    Responder {
        confirmation: ResponderAwaitingInitiatorFinishedV1<Sha3_256Xof>,
        expected_head: StateHead,
        deadline: Instant,
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

/// RAM-only client view of this process's exclusive instance lease.
///
/// The fence (lease generation plus fresh process identity) deliberately never
/// touches disk: a restored clone of this host must not be able to replay the
/// live fence, so a process restart always starts a new acquire cycle.
struct InstanceLeaseState {
    instance_id: ProcessInstanceIdV2,
    fence: Option<InstanceFenceV2>,
    authority_version: u64,
    fenced: bool,
    unacknowledged: VecDeque<DurablyRetainedAuthorityReceiptV2>,
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
    confirmed_keys: HashMap<ConfirmedKeyHandle, AcceptedSessionKeyV1>,
    completed_acceptances: HashMap<PendingSessionHandle, CompletedAcceptance>,
    poisoned: bool,
}

/// Process-local façade whose one mutex is the transition/session linearization point.
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
    pub fn new(
        mut repository: StateRepository,
        witness: W,
        authority: A,
        config: AgentConfig,
    ) -> Result<Self, AgentError> {
        let lease = acquire_instance_lease(&authority)?;
        align_repository(&mut repository, &witness)?;
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
                confirmed_keys: HashMap::new(),
                completed_acceptances: HashMap::new(),
                poisoned: false,
            }),
        })
    }

    /// Return only the public encapsulation keys owned by the agent.
    pub fn public_keys(&self) -> Result<EncapsulationPublicKeys, AgentError> {
        let inner = self.lock()?;
        ensure_live(&inner)?;
        if inner.repository.pending_intent().is_some() {
            return Err(AgentError::TransitionPending);
        }
        Ok(inner.engine.available()?.public_keys().clone())
    }

    /// Authenticate and execute a normal migration state advance.
    pub fn apply_advance(&self, canonical_signed_state: &[u8]) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        let intent = inner.repository.prepare_advance(canonical_signed_state)?;
        let replacement = executor_for(
            &inner.config.execution_policy,
            inner
                .repository
                .pending_next_state()
                .ok_or(AgentError::InternalPoisoned)?,
        )?;
        inner.pending_engine = Some(replacement);
        execute_transition(&mut inner, intent)
    }

    /// Authenticate and execute a separately authorized lineage reset.
    pub fn apply_reset(&self, canonical_signed_reset: &[u8]) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        let intent = inner.repository.prepare_reset(canonical_signed_reset)?;
        let replacement = executor_for(
            &inner.config.execution_policy,
            inner
                .repository
                .pending_next_state()
                .ok_or(AgentError::InternalPoisoned)?,
        )?;
        inner.pending_engine = Some(replacement);
        execute_transition(&mut inner, intent)
    }

    /// Reconcile only the durable operation ID retained after an unknown outcome.
    pub fn reconcile_transition(&self) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
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

    /// Begin encapsulation from signed capability envelopes; no raw context is accepted.
    pub fn begin_encapsulation(
        &self,
        request: BeginEncapsulation,
    ) -> Result<BeginEncapsulationResult, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        ensure_session_capacity(&inner)?;
        let head = verify_current_head(&inner)?;
        let (context, abi_context, capability_session_id) = build_contract(
            &inner,
            request.authorization,
            inner.config.local_role,
            request.peer_public_keys.clone(),
        )?;
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
                let handle = reserve_pending(
                    &mut inner,
                    head,
                    capability_session_id,
                    PendingSession::Initiator {
                        confirmation,
                        expected_head: head,
                        deadline,
                    },
                )?;
                Ok(BeginEncapsulationResult::Initiator(
                    InitiatorEncapsulationResult {
                        handle,
                        ciphertexts,
                        initiator_finished,
                    },
                ))
            }
            EndpointRole::Responder => {
                let confirmation = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
                    secret, &context, &post,
                )
                .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                let handle = reserve_pending(
                    &mut inner,
                    head,
                    capability_session_id,
                    PendingSession::Responder {
                        confirmation,
                        expected_head: head,
                        deadline,
                    },
                )?;
                Ok(BeginEncapsulationResult::Responder(
                    ResponderEncapsulationResult {
                        handle,
                        ciphertexts,
                    },
                ))
            }
        }
    }

    /// Begin decapsulation from signed capability envelopes and exact ciphertexts.
    pub fn begin_decapsulation(
        &self,
        request: BeginDecapsulation,
    ) -> Result<BeginDecapsulationResult, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        ensure_session_capacity(&inner)?;
        let head = verify_current_head(&inner)?;
        let encapsulator_role = opposite(inner.config.local_role);
        let engine = inner.engine.available()?;
        let local_keys = engine.public_keys().clone();
        let (context, abi_context, capability_session_id) =
            build_contract(&inner, request.authorization, encapsulator_role, local_keys)?;
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
                let handle = reserve_pending(
                    &mut inner,
                    head,
                    capability_session_id,
                    PendingSession::Initiator {
                        confirmation,
                        expected_head: head,
                        deadline,
                    },
                )?;
                Ok(BeginDecapsulationResult::Initiator(
                    InitiatorDecapsulationResult {
                        handle,
                        initiator_finished,
                    },
                ))
            }
            EndpointRole::Responder => {
                let confirmation = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
                    secret, &context, &post,
                )
                .map_err(|error| map_confirmation_setup_error(&mut inner, error))?;
                let handle = reserve_pending(
                    &mut inner,
                    head,
                    capability_session_id,
                    PendingSession::Responder {
                        confirmation,
                        expected_head: head,
                        deadline,
                    },
                )?;
                Ok(BeginDecapsulationResult::Responder(
                    ResponderDecapsulationResult { handle },
                ))
            }
        }
    }

    /// Accept I, durably release its reservation, retain K and retry state, then return R.
    ///
    /// While the retained key remains live, an exact same-handle/same-Finished retry returns the
    /// same handle and R. Different bytes for that completed flight fail closed without replacing
    /// the result. Destroy, migration transition, or process restart clears this retry cache.
    pub fn accept_initiator_finished(
        &self,
        handle: PendingSessionHandle,
        initiator_finished: InitiatorFinishedV1,
    ) -> Result<ResponderAcceptanceResult, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        if let Some(completed) = inner.completed_acceptances.get(&handle) {
            return match completed {
                CompletedAcceptance::Responder {
                    received_finished,
                    result,
                } if *received_finished == initiator_finished => Ok(*result),
                CompletedAcceptance::Responder { .. } => {
                    Err(AgentError::ConflictingAcceptanceReplay)
                }
                CompletedAcceptance::Initiator { .. } => Err(AgentError::UnexpectedFlight),
            };
        }
        let (expected_head, key_handle) =
            prepare_acceptance(&mut inner, handle, PendingFlight::Initiator)?;
        let confirmation = match inner.pending_sessions.remove(&handle) {
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

    /// Accept the responder Finished only from an initiator pending state and retain K.
    ///
    /// While the retained key remains live, an exact same-handle/same-Finished retry returns the
    /// same handle. Different bytes for that completed flight fail closed without replacing the
    /// result. Destroy, migration transition, or process restart clears this retry cache.
    pub fn accept_responder_finished(
        &self,
        handle: PendingSessionHandle,
        responder_finished: ResponderFinishedV1,
    ) -> Result<ConfirmedKeyHandle, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_instance_lease(&mut inner)?;
        if let Some(completed) = inner.completed_acceptances.get(&handle) {
            return match completed {
                CompletedAcceptance::Initiator {
                    received_finished,
                    key_handle,
                } if *received_finished == responder_finished => Ok(*key_handle),
                CompletedAcceptance::Initiator { .. } => {
                    Err(AgentError::ConflictingAcceptanceReplay)
                }
                CompletedAcceptance::Responder { .. } => Err(AgentError::UnexpectedFlight),
            };
        }
        let (expected_head, key_handle) =
            prepare_acceptance(&mut inner, handle, PendingFlight::Responder)?;
        let confirmation = match inner.pending_sessions.remove(&handle) {
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

    /// Cancel a pending session and wipe its unconfirmed secret immediately.
    pub fn cancel(&self, handle: PendingSessionHandle) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        erase_pending(&mut inner, handle)
    }

    /// Destroy a retained confirmed key. No secret-export API exists.
    pub fn destroy_key(&self, handle: ConfirmedKeyHandle) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
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
    /// stops before another instance can acquire the next lease generation.
    /// After release this agent permanently refuses lease-guarded operations;
    /// a successor process must construct a new agent to acquire authority.
    /// Repeating the call after the fence is already gone succeeds idempotently.
    pub fn release_instance_lease(&self) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        let inner = &mut *inner;
        ensure_live(inner)?;
        let Some(fence) = inner.lease.fence else {
            return Ok(());
        };
        fence_out(inner)?;
        drain_acknowledgements(&inner.authority, &mut inner.lease);
        for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
            let intent = lease_intent(
                &inner.lease,
                inner.authority.wire_config(),
                AuthorityMutationV2::ReleaseLease { fence },
            )?;
            match lease_exchange(
                &inner.authority,
                &mut inner.lease,
                LeaseCall::Release,
                intent,
            )? {
                LeaseExchange::Receipt(receipt) => {
                    drain_acknowledgements(&inner.authority, &mut inner.lease);
                    return match receipt.disposition() {
                        AuthorityDispositionV2::Applied
                        | AuthorityDispositionV2::Rejected(
                            AuthorityRejectionV2::LeaseAbsent
                            | AuthorityRejectionV2::LeaseExpired
                            | AuthorityRejectionV2::FenceMismatch,
                        ) => Ok(()),
                        AuthorityDispositionV2::Rejected(_) => {
                            Err(AgentError::InstanceLeaseUnavailable)
                        }
                    };
                }
                LeaseExchange::Retry => {}
            }
        }
        Err(AgentError::InstanceLeaseIndeterminate)
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
    pub fn expire_idle_sessions(&self) {
        let Ok(mut inner) = self.lock() else {
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
        fence_out(&mut inner)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner<W, A>>, AgentError> {
        self.inner.lock().map_err(|_| AgentError::InternalPoisoned)
    }
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

fn execute_transition<W: WitnessPort, A: InstanceAuthorityPort>(
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

fn finish_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    receipt: WitnessReceipt,
) -> Result<(), AgentError> {
    if inner.repository.commit_applied(receipt).is_err() {
        inner.poisoned = true;
        return Err(AgentError::InternalPoisoned);
    }
    // The durable commit already erased all reservations. Dropping these maps
    // erases every in-process pending/accepted secret before any new request.
    inner.pending_sessions.clear();
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

fn reserve_pending<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
    head: StateHead,
    capability_session_id: [u8; 32],
    pending: PendingSession,
) -> Result<PendingSessionHandle, AgentError> {
    for _ in 0..4 {
        let handle = PendingSessionHandle(
            SessionId::generate().map_err(|_| AgentError::LocalCryptoFailure)?,
        );
        if inner.pending_sessions.contains_key(&handle)
            || inner.completed_acceptances.contains_key(&handle)
        {
            continue;
        }
        inner
            .repository
            .reserve_session(handle.0, capability_session_id, head)?;
        if inner.pending_sessions.insert(handle, pending).is_some() {
            inner.poisoned = true;
            return Err(AgentError::InternalPoisoned);
        }
        return Ok(handle);
    }
    Err(AgentError::LocalCryptoFailure)
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
    if inner.pending_sessions.insert(handle, pending).is_some() {
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
    let removed = inner
        .pending_sessions
        .remove(&handle)
        .ok_or(AgentError::UnknownHandle)?;
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
enum LeaseCall {
    Acquire,
    Renew,
    Release,
}

// The receipt stays `Copy` so one short-lived stack value can be compared and
// recorded without heap allocation, matching the wire payload discipline.
#[allow(clippy::large_enum_variant)]
/// Outcome of one lease exchange after exact-operation reconciliation.
enum LeaseExchange {
    /// The authority returned this operation's exact authenticated receipt.
    Receipt(AuthorityReceiptV2),
    /// The operation provably never dispatched; rebuild the intent and retry.
    Retry,
}

fn fresh_lease_random() -> Result<[u8; 32], AgentError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AgentError::LocalCryptoFailure)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(AgentError::LocalCryptoFailure);
    }
    Ok(bytes)
}

fn authority_snapshot<A: InstanceAuthorityPort>(
    authority: &A,
) -> Result<AuthoritySnapshotV2, AgentError> {
    match authority.snapshot() {
        Ok(AuthorityOutcomeV2::Known(snapshot)) => Ok(snapshot),
        Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
            Err(AgentError::InstanceLeaseUnavailable)
        }
    }
}

fn lease_intent(
    lease: &InstanceLeaseState,
    config: DeploymentConfigRevisionV2,
    mutation: AuthorityMutationV2,
) -> Result<AuthorityIntentV2, AgentError> {
    let operation_id = OperationIdV2::new(lease.authority_version, fresh_lease_random()?)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)?;
    AuthorityIntentV2::new(operation_id, lease.authority_version, config, mutation)
        .map_err(|_| AgentError::InstanceLeaseUnavailable)
}

fn record_lease_receipt(
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
    receipt: AuthorityReceiptV2,
) -> Result<LeaseExchange, AgentError> {
    if receipt.intent() != intent {
        return Err(AgentError::InstanceLeaseUnavailable);
    }
    lease.authority_version = receipt.resulting_authority_version();
    // The lease view is deliberately RAM-only: after a crash the successor
    // process starts a fresh acquire cycle and never queries this operation ID
    // again, so the receipt needs no further durability before the bounded
    // acknowledgement queue lets the authority prune it.
    if lease.unacknowledged.len() < MAX_UNACKNOWLEDGED_LEASE_RECEIPTS
        && lease.unacknowledged.try_reserve(1).is_ok()
    {
        if let Ok(retained) = DurablyRetainedAuthorityReceiptV2::after_durable_commit(receipt) {
            lease.unacknowledged.push_back(retained);
        }
    }
    Ok(LeaseExchange::Receipt(receipt))
}

fn drain_acknowledgements<A: InstanceAuthorityPort>(authority: &A, lease: &mut InstanceLeaseState) {
    while let Some(retained) = lease.unacknowledged.front() {
        match authority.acknowledge(retained) {
            Ok(AuthorityOutcomeV2::Known(_)) => {
                lease.unacknowledged.pop_front();
            }
            // The authority holds no retained state matching this locator, so
            // there is nothing left to reclaim and no retry can change that:
            // its receipt table only ever shrinks. Keeping the entry would
            // block every acknowledgement behind it permanently -- the queue
            // drains strictly in order, this failure does not poison the store,
            // and acknowledgement is the only thing that ever removes a receipt
            // on either side. One unmatchable receipt would fill this bounded
            // queue and then leave the authority's own table to fill too, which
            // ends with the daemon unable to acquire a lease at all. Discard it
            // and carry on.
            Ok(AuthorityOutcomeV2::KnownFailure(
                AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
            )) => {
                lease.unacknowledged.pop_front();
            }
            // Everything else is a server-side condition that can clear: a full
            // nonce table, a failed allocation, an unavailable clock, or an
            // indeterminate response. Stop and retry on the next drain rather
            // than discarding an obligation that can still be honoured.
            Ok(AuthorityOutcomeV2::KnownFailure(_) | AuthorityOutcomeV2::Unknown(_)) | Err(_) => {
                return;
            }
        }
    }
}

fn reconcile_lease_operation<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        match authority.query(intent.operation_id()) {
            Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt))) => {
                return record_lease_receipt(lease, intent, *receipt);
            }
            Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version,
            })) => {
                lease.authority_version = authority_version;
                return Ok(LeaseExchange::Retry);
            }
            Ok(AuthorityOutcomeV2::KnownFailure(_)) => {
                return Err(AgentError::InstanceLeaseUnavailable);
            }
            Ok(AuthorityOutcomeV2::Unknown(_)) | Err(_) => {}
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

fn lease_exchange<A: InstanceAuthorityPort>(
    authority: &A,
    lease: &mut InstanceLeaseState,
    call: LeaseCall,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    let outcome = match call {
        LeaseCall::Acquire => authority.acquire(intent),
        LeaseCall::Renew => authority.renew(intent),
        LeaseCall::Release => authority.release(intent),
    };
    match outcome {
        Ok(AuthorityOutcomeV2::Known(receipt)) => record_lease_receipt(lease, intent, receipt),
        Ok(AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::AuthorityVersionMismatch)) => {
            let snapshot = authority_snapshot(authority)?;
            lease.authority_version = snapshot.authority_version();
            Ok(LeaseExchange::Retry)
        }
        Ok(AuthorityOutcomeV2::KnownFailure(_)) => Err(AgentError::InstanceLeaseUnavailable),
        Ok(AuthorityOutcomeV2::Unknown(_)) => reconcile_lease_operation(authority, lease, intent),
        Err(_) => Err(AgentError::InstanceLeaseUnavailable),
    }
}

/// Adopt the authority's current lease when a lost response already acquired
/// it for this exact fresh process identity; fail closed on any other holder.
fn adopt_or_reject_active_lease(
    lease: &mut InstanceLeaseState,
    snapshot: &AuthoritySnapshotV2,
    expected_lease_generation: &mut u64,
) -> Result<bool, AgentError> {
    lease.authority_version = snapshot.authority_version();
    match snapshot.active_lease() {
        Some(active) if active.fence().instance_id() == lease.instance_id => {
            lease.fence = Some(active.fence());
            Ok(true)
        }
        Some(_) => Err(AgentError::InstanceFenced),
        None => {
            *expected_lease_generation = snapshot.lease_generation();
            Ok(false)
        }
    }
}

fn acquire_instance_lease<A: InstanceAuthorityPort>(
    authority: &A,
) -> Result<InstanceLeaseState, AgentError> {
    let instance_id = ProcessInstanceIdV2::from_bytes(fresh_lease_random()?)
        .map_err(|_| AgentError::LocalCryptoFailure)?;
    let mut lease = InstanceLeaseState {
        instance_id,
        fence: None,
        authority_version: 1,
        fenced: false,
        unacknowledged: VecDeque::new(),
    };
    let snapshot = authority_snapshot(authority)?;
    lease.authority_version = snapshot.authority_version();
    if snapshot.active_lease().is_some() {
        return Err(AgentError::InstanceFenced);
    }
    let mut expected_lease_generation = snapshot.lease_generation();
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &lease,
            authority.wire_config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id,
            },
        )?;
        match lease_exchange(authority, &mut lease, LeaseCall::Acquire, intent)? {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(authority, &mut lease);
                match receipt.disposition() {
                    AuthorityDispositionV2::Applied => {
                        let generation = expected_lease_generation
                            .checked_add(1)
                            .ok_or(AgentError::InstanceLeaseUnavailable)?;
                        lease.fence = Some(
                            InstanceFenceV2::new(generation, instance_id)
                                .map_err(|_| AgentError::InstanceLeaseUnavailable)?,
                        );
                        return Ok(lease);
                    }
                    AuthorityDispositionV2::Rejected(
                        AuthorityRejectionV2::LeaseHeld
                        | AuthorityRejectionV2::LeaseGenerationMismatch,
                    ) => {
                        let snapshot = authority_snapshot(authority)?;
                        if adopt_or_reject_active_lease(
                            &mut lease,
                            &snapshot,
                            &mut expected_lease_generation,
                        )? {
                            return Ok(lease);
                        }
                    }
                    AuthorityDispositionV2::Rejected(_) => {
                        return Err(AgentError::InstanceLeaseUnavailable);
                    }
                }
            }
            LeaseExchange::Retry => {
                let snapshot = authority_snapshot(authority)?;
                if adopt_or_reject_active_lease(
                    &mut lease,
                    &snapshot,
                    &mut expected_lease_generation,
                )? {
                    return Ok(lease);
                }
            }
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Re-authorize key use behind the exclusive lease before every guarded operation.
///
/// Every guarded operation renews against the authority's trusted clock, so a
/// fenced, expired, or superseded instance is rejected before it can touch a
/// pending or accepted secret, and this instance erases all of them first.
fn ensure_instance_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.lease.fenced {
        return Err(AgentError::InstanceFenced);
    }
    let Some(fence) = inner.lease.fence else {
        return Err(AgentError::InstanceFenced);
    };
    drain_acknowledgements(&inner.authority, &mut inner.lease);
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &inner.lease,
            inner.authority.wire_config(),
            AuthorityMutationV2::RenewLease { fence },
        )?;
        match lease_exchange(&inner.authority, &mut inner.lease, LeaseCall::Renew, intent)? {
            LeaseExchange::Receipt(receipt) => {
                drain_acknowledgements(&inner.authority, &mut inner.lease);
                return match receipt.disposition() {
                    AuthorityDispositionV2::Applied
                    | AuthorityDispositionV2::Rejected(
                        // The fence was verified live; only the expiry could
                        // not strictly extend within this clock-floor instant.
                        AuthorityRejectionV2::LeaseRenewalNotExtended,
                    ) => Ok(()),
                    AuthorityDispositionV2::Rejected(
                        AuthorityRejectionV2::LeaseAbsent
                        | AuthorityRejectionV2::LeaseExpired
                        | AuthorityRejectionV2::FenceMismatch,
                    ) => {
                        fence_out(inner)?;
                        Err(AgentError::InstanceFenced)
                    }
                    AuthorityDispositionV2::Rejected(_) => {
                        Err(AgentError::InstanceLeaseUnavailable)
                    }
                };
            }
            LeaseExchange::Retry => {}
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

/// Erase every in-process pending and accepted secret and retire this fence.
///
/// After this returns, the agent permanently refuses lease-guarded operations
/// and holds no pending or accepted secret.
///
/// It does **not** establish that key use stopped before a successor acquired
/// the next generation, and an earlier version of this comment claimed that it
/// did. Nothing gives this process that guarantee: a successor's acquire is
/// gated purely on wall-clock expiry (`plan_acquire`), with no interaction with
/// the incumbent and no revocation, and this process learns it has been fenced
/// only by making a further authority call and being rejected. Between the
/// lease lapsing and that rejection arriving, both instances hold live key
/// material, and neither the guarded entry points nor `expire_idle_sessions`
/// closes that window: the entry points check the lease once, on the way in,
/// and are handed no expiry with which to bound the work that follows.
///
/// What this function does guarantee is the erasure, and that it happens before
/// the rejected call returns. Narrowing the window itself needs the lease to
/// carry a deadline the agent can check again before it retains a secret, which
/// is a separate change.
///
/// See `docs/policy/` for the intended end state.
fn fence_out<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    // Erase everything first, and report a failure only afterwards. This runs
    // when another instance holds the lease, which is precisely when this
    // process must not be left holding key material. Abandoning the sweep on the
    // first failed durable cancellation would skip both clears below and leave
    // every accepted application key live -- the opposite of what fencing out
    // exists to guarantee. `erase_pending` drops each secret before it touches
    // the repository, so continuing past a failure still erases.
    let handles: Vec<_> = inner.pending_sessions.keys().copied().collect();
    let mut first_failure = None;
    for handle in handles {
        if let Err(error) = erase_pending(inner, handle) {
            first_failure = first_failure.or(Some(error));
        }
    }
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    inner.lease.fence = None;
    // The process is fenced whether or not the durable bookkeeping succeeded;
    // that is a fact about the lease, not about the erasure.
    inner.lease.fenced = true;
    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

const fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}
