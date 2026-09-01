//! Single-linearizer policy, transition, KEM, and mutual-confirmation service.

use core::fmt;
use std::collections::HashMap;
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
    InstanceFenceV2, OperationIdV2, ProcessInstanceIdV2, ReceiptAckDispositionV2,
};
use crate::authority_journal::DurableAuthorityOperation;
use crate::authority_protocol::{AuthorityKnownFailureV3, AuthorityOutcomeV3};
use crate::authority_transport::{AuthorityTransportErrorV3, InstanceAuthorityPort};
use crate::crypto::{
    Abi2Engine, Abi2EngineError, EncapsulationCiphertexts, EncapsulationPublicKeys,
};
use crate::repository::{
    CommittedTransition, CoordinatedTransition, RepositoryError, StateRepository,
};
use crate::types::{SessionId, StateHead};
use crate::witness::{
    WitnessDisposition, WitnessError, WitnessOutcome, WitnessPort, WitnessReceipt,
};

const MAX_SIGNED_OFFER_BYTES: usize = 16 * 1024;
const HARD_MAX_SESSIONS: usize = 1024;
const HARD_MAX_CONFIRMED_KEYS: usize = 1024;
const MAX_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
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
            RepositoryError::CommitUncertain | RepositoryError::RepositoryPoisoned => {
                Self::InternalPoisoned
            }
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

impl From<AuthorityTransportErrorV3> for AgentError {
    fn from(error: AuthorityTransportErrorV3) -> Self {
        match error {
            AuthorityTransportErrorV3::InvalidConfiguration => Self::InvalidConfiguration,
            AuthorityTransportErrorV3::InvalidRequest
            | AuthorityTransportErrorV3::EntropyUnavailable
            | AuthorityTransportErrorV3::EncodingFailed
            | AuthorityTransportErrorV3::NotSent => Self::InstanceLeaseUnavailable,
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
        if repository.authority_identity()? != authority.wire_identity()? {
            return Err(AgentError::InvalidConfiguration);
        }
        if repository.coordinated_transition().is_some() {
            drive_coordinated_transition(&mut repository, &witness, &authority)?;
        }
        align_repository(&mut repository, &witness, &authority)?;
        recover_durable_lease_operation(&mut repository, &authority)?;
        let lease = acquire_instance_lease(&mut repository, &authority)?;
        align_repository(&mut repository, &witness, &authority)?;
        let committed = repository.committed_state();
        let engine = executor_for(&config.execution_policy, committed.state())?;
        let local_policy = config.local_endpoint_policy.authenticate()?;
        let peer_policy = config.peer_endpoint_policy.authenticate()?;
        let pending_engine = None;
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
        ensure_no_transition(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        let fence = inner.lease.fence.ok_or(AgentError::InstanceFenced)?;
        let authority_version = inner.lease.authority_version;
        let prepared =
            inner
                .repository
                .prepare_advance(canonical_signed_state, authority_version, fence);
        let transition = repository_result_or_fatal(&mut inner, prepared)?;
        let Some(next_state) = inner.repository.pending_next_state() else {
            return fatalize(&mut inner);
        };
        let replacement = executor_for(&inner.config.execution_policy, next_state)?;
        inner.pending_engine = Some(replacement);
        execute_transition(&mut inner, transition)
    }

    /// Authenticate and execute a separately authorized lineage reset.
    pub fn apply_reset(&self, canonical_signed_reset: &[u8]) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_no_transition(&inner)?;
        ensure_instance_lease(&mut inner)?;
        purge_expired(&mut inner)?;
        let fence = inner.lease.fence.ok_or(AgentError::InstanceFenced)?;
        let authority_version = inner.lease.authority_version;
        let prepared =
            inner
                .repository
                .prepare_reset(canonical_signed_reset, authority_version, fence);
        let transition = repository_result_or_fatal(&mut inner, prepared)?;
        let Some(next_state) = inner.repository.pending_next_state() else {
            return fatalize(&mut inner);
        };
        let replacement = executor_for(&inner.config.execution_policy, next_state)?;
        inner.pending_engine = Some(replacement);
        execute_transition(&mut inner, transition)
    }

    /// Reconcile only the durable operation ID retained after an unknown outcome.
    pub fn reconcile_transition(&self) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        let transition = inner
            .repository
            .coordinated_transition()
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
        execute_transition(&mut inner, transition)
    }

    /// Begin encapsulation from signed capability envelopes; no raw context is accepted.
    pub fn begin_encapsulation(
        &self,
        request: BeginEncapsulation,
    ) -> Result<BeginEncapsulationResult, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        ensure_no_transition(&inner)?;
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
        ensure_no_transition(&inner)?;
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
        ensure_no_transition(&inner)?;
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
        ensure_no_transition(&inner)?;
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
        ensure_no_transition(inner)?;
        let recovery = recover_durable_lease_operation(&mut inner.repository, &inner.authority);
        repository_agent_result_or_fatal(inner, recovery)?;
        let Some(fence) = inner.lease.fence else {
            return Ok(());
        };
        fence_out(inner)?;
        for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
            let intent = lease_intent(
                &inner.lease,
                inner.authority.wire_config()?,
                AuthorityMutationV2::ReleaseLease { fence },
            )?;
            let exchange = lease_exchange(
                &mut inner.repository,
                &inner.authority,
                &mut inner.lease,
                LeaseCall::Release,
                intent,
            );
            match repository_agent_result_or_fatal(inner, exchange)? {
                LeaseExchange::Receipt(receipt) => {
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

    #[cfg(all(test, unix))]
    pub(crate) fn fatal_state_for_test(&self) -> Result<(bool, usize, usize, bool), AgentError> {
        let inner = self.lock()?;
        Ok((
            inner.poisoned,
            inner.pending_sessions.len(),
            inner.confirmed_keys.len(),
            matches!(inner.engine, ExecutorState::Blocked)
                && inner.pending_engine.is_none()
                && inner.lease.fence.is_none()
                && inner.lease.fenced,
        ))
    }

    #[cfg(all(test, unix))]
    pub(crate) fn fail_after_next_authority_journal_commit_for_test(
        &self,
    ) -> Result<(), AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        inner
            .repository
            .fail_after_next_authority_journal_commit_for_test();
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn fail_after_authority_journal_commits_for_test(
        &self,
        commits: usize,
    ) -> Result<(), AgentError> {
        if commits == 0 {
            return Err(AgentError::InvalidConfiguration);
        }
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        inner
            .repository
            .fail_after_authority_journal_commits_for_test(commits);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner<W, A>>, AgentError> {
        self.inner.lock().map_err(|_| AgentError::InternalPoisoned)
    }
}

fn align_repository<W: WitnessPort, A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    witness: &W,
    authority: &A,
) -> Result<(), AgentError> {
    if repository.coordinated_transition().is_some() {
        return Err(AgentError::TransitionPending);
    }
    let local = repository.head()?;
    let identity = repository.authority_identity()?;
    if witness.read_head()? != local || authority.wire_identity()? != identity {
        return Err(AgentError::RollbackOrFork);
    }
    let snapshot = authority_snapshot(authority)?;
    if snapshot.state_head() != identity.state_head() || snapshot.config() != identity.config() {
        return Err(AgentError::RollbackOrFork);
    }
    Ok(())
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
    transition: CoordinatedTransition,
) -> Result<(), AgentError> {
    if inner.repository.coordinated_transition() != Some(transition) {
        return Err(AgentError::RollbackOrFork);
    }
    if let Err(error) =
        drive_coordinated_transition(&mut inner.repository, &inner.witness, &inner.authority)
    {
        if matches!(
            error,
            AgentError::Repository(_) | AgentError::InternalPoisoned
        ) {
            return fatalize(inner);
        }
        return Err(error);
    }
    // The durable commit already erased all reservations. Dropping these maps
    // erases every in-process pending/accepted secret before any new request.
    inner.pending_sessions.clear();
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    let Some(replacement) = inner.pending_engine.take() else {
        return fatalize(inner);
    };
    inner.engine = replacement;
    inner.lease = match acquire_instance_lease(&mut inner.repository, &inner.authority) {
        Ok(lease) => lease,
        Err(_) => return fatalize(inner),
    };
    Ok(())
}

fn drive_coordinated_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    witness: &W,
    authority: &A,
) -> Result<CommittedTransition, AgentError> {
    let mut transition = repository
        .coordinated_transition()
        .ok_or(RepositoryError::NoPendingTransition)?;
    let mut authority_applied = false;
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let authority_receipt = reconcile_transition_authority(repository, authority, transition)?;
        match authority_receipt.disposition() {
            AuthorityDispositionV2::Applied => {
                authority_applied = true;
                break;
            }
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::StateMismatch) => {
                return Err(AgentError::RollbackOrFork);
            }
            AuthorityDispositionV2::Rejected(
                AuthorityRejectionV2::LeaseAbsent
                | AuthorityRejectionV2::LeaseExpired
                | AuthorityRejectionV2::FenceMismatch,
            ) => {
                // A previous attempt may have crashed at the replacement
                // lease's Prepared or Resolved cut. The transition receipt is
                // already durably ACK-terminal here, so the active journal
                // slot can only belong to that non-AdvanceState lease attempt.
                recover_durable_lease_operation(repository, authority)?;
                let replacement_lease = acquire_instance_lease(repository, authority)?;
                let replacement_fence = replacement_lease
                    .fence
                    .ok_or(AgentError::InstanceLeaseUnavailable)?;
                transition = repository.replace_rejected_transition_authority_attempt(
                    authority_receipt,
                    replacement_lease.authority_version,
                    replacement_fence,
                )?;
            }
            AuthorityDispositionV2::Rejected(_) => {
                return Err(AgentError::InstanceLeaseUnavailable);
            }
        }
    }
    if !authority_applied {
        return Err(AgentError::InstanceLeaseIndeterminate);
    }
    let witness_intent = transition.witness_intent();
    let witness_receipt = match witness.query(witness_intent.operation_id())? {
        WitnessOutcome::Known(receipt) if receipt.is_exact_applied(witness_intent) => *receipt,
        WitnessOutcome::Known(receipt)
            if receipt.disposition() == WitnessDisposition::NotApplied
                && receipt.authoritative_head() == witness_intent.expected() =>
        {
            dispatch_witness_transition(witness, witness_intent)?
        }
        WitnessOutcome::Unknown => dispatch_witness_transition(witness, witness_intent)?,
        WitnessOutcome::Known(_) => return Err(AgentError::RollbackOrFork),
    };
    let committed = repository.commit_applied(witness_receipt)?;
    authority
        .advance_wire_identity(committed.expected_identity, committed.next_identity)
        .map_err(|_| AgentError::InternalPoisoned)?;
    Ok(committed)
}

fn dispatch_witness_transition<W: WitnessPort>(
    witness: &W,
    intent: crate::witness::WitnessIntent,
) -> Result<WitnessReceipt, AgentError> {
    match witness.compare_and_advance(intent)? {
        WitnessOutcome::Known(receipt) if receipt.is_exact_applied(intent) => Ok(*receipt),
        WitnessOutcome::Unknown => Err(AgentError::TransitionIndeterminate),
        WitnessOutcome::Known(_) => Err(AgentError::RollbackOrFork),
    }
}

fn reconcile_transition_authority<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
    transition: CoordinatedTransition,
) -> Result<AuthorityReceiptV2, AgentError> {
    let identity = repository.authority_identity()?;
    if authority.wire_identity()? != identity {
        return Err(AgentError::RollbackOrFork);
    }
    if let Some(receipt) = transition.authority_receipt() {
        if transition.authority_acknowledged() {
            return Ok(receipt);
        }
        match repository.durable_lease_operation(identity)? {
            Some(DurableAuthorityOperation::Resolved(durable)) if durable == receipt => {
                let retained = DurableAuthorityOperation::Resolved(durable)
                    .retained()
                    .map_err(RepositoryError::from)?;
                acknowledge_transition_authority_receipt(repository, authority, retained)?;
            }
            _ => return Err(AgentError::RollbackOrFork),
        }
        return Ok(receipt);
    }
    let intent = transition.authority_intent();
    if repository.durable_lease_operation(identity)?
        != Some(DurableAuthorityOperation::Prepared(intent))
    {
        return Err(AgentError::RollbackOrFork);
    }
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        match authority.advance_state(intent) {
            Ok(AuthorityOutcomeV3::Known(receipt)) => {
                let retained = repository.record_transition_authority_result(intent, receipt)?;
                acknowledge_transition_authority_receipt(repository, authority, retained)?;
                return Ok(receipt);
            }
            Ok(AuthorityOutcomeV3::KnownFailure(
                AuthorityKnownFailureV3::OperationConflict
                | AuthorityKnownFailureV3::ReceiptAcknowledgementMismatch,
            )) => return Err(AgentError::RollbackOrFork),
            Ok(AuthorityOutcomeV3::KnownFailure(_))
            | Ok(AuthorityOutcomeV3::Unknown(_))
            | Err(_) => match authority.query(intent.operation_id()) {
                Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::Found(receipt)))
                    if receipt.intent() == intent =>
                {
                    let receipt = *receipt;
                    let retained =
                        repository.record_transition_authority_result(intent, receipt)?;
                    acknowledge_transition_authority_receipt(repository, authority, retained)?;
                    return Ok(receipt);
                }
                Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                    authority_version,
                })) if authority_version == intent.expected_authority_version() => {}
                Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                    ..
                }))
                | Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::Found(_))) => {
                    return Err(AgentError::RollbackOrFork);
                }
                Ok(AuthorityOutcomeV3::KnownFailure(_))
                | Ok(AuthorityOutcomeV3::Unknown(_))
                | Err(_) => {}
            },
        }
    }
    Err(AgentError::TransitionIndeterminate)
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

fn purge_expired<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    let now = Instant::now();
    let expired: Vec<_> = inner
        .pending_sessions
        .iter()
        .filter_map(|(handle, pending)| pending.is_expired(now).then_some(*handle))
        .collect();
    for handle in expired {
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

fn ensure_no_transition<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.repository.coordinated_transition().is_some() {
        Err(AgentError::TransitionPending)
    } else {
        Ok(())
    }
}

fn fatalize<W: WitnessPort, A: InstanceAuthorityPort, T>(
    inner: &mut Inner<W, A>,
) -> Result<T, AgentError> {
    inner.pending_sessions.clear();
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    inner.pending_engine = None;
    inner.engine = ExecutorState::Blocked;
    inner.lease.fence = None;
    inner.lease.fenced = true;
    inner.poisoned = true;
    Err(AgentError::InternalPoisoned)
}

fn repository_result_or_fatal<W: WitnessPort, A: InstanceAuthorityPort, T>(
    inner: &mut Inner<W, A>,
    result: Result<T, RepositoryError>,
) -> Result<T, AgentError> {
    match result {
        Ok(value) => Ok(value),
        Err(RepositoryError::CommitUncertain | RepositoryError::RepositoryPoisoned) => {
            fatalize(inner)
        }
        Err(error) => Err(error.into()),
    }
}

fn repository_agent_result_or_fatal<W: WitnessPort, A: InstanceAuthorityPort, T>(
    inner: &mut Inner<W, A>,
    result: Result<T, AgentError>,
) -> Result<T, AgentError> {
    match result {
        Err(AgentError::Repository(_) | AgentError::InternalPoisoned) => fatalize(inner),
        other => other,
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
        Ok(AuthorityOutcomeV3::Known(snapshot)) => Ok(snapshot),
        Ok(AuthorityOutcomeV3::KnownFailure(_) | AuthorityOutcomeV3::Unknown(_)) | Err(_) => {
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
    repository: &mut StateRepository,
    authority: &impl InstanceAuthorityPort,
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
    receipt: AuthorityReceiptV2,
) -> Result<LeaseExchange, AgentError> {
    if receipt.intent() != intent {
        return Err(AgentError::InstanceLeaseUnavailable);
    }
    let identity = authority.wire_identity()?;
    let retained = repository.resolve_lease_operation(identity, intent, receipt)?;
    lease.authority_version = receipt.resulting_authority_version();
    acknowledge_resolved_receipt(repository, authority, retained)?;
    Ok(LeaseExchange::Receipt(receipt))
}

fn acknowledge_resolved_receipt<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
    retained: crate::authority_protocol::DurablyRetainedAuthorityReceiptV3,
) -> Result<(), AgentError> {
    let disposition = acknowledge_authority_receipt(authority, retained)?;
    repository.complete_lease_acknowledgement(authority.wire_identity()?, retained, disposition)?;
    Ok(())
}

fn acknowledge_transition_authority_receipt<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
    retained: crate::authority_protocol::DurablyRetainedAuthorityReceiptV3,
) -> Result<(), AgentError> {
    let disposition = acknowledge_authority_receipt(authority, retained)?;
    repository.complete_transition_authority_acknowledgement(
        authority.wire_identity()?,
        retained,
        disposition,
    )?;
    Ok(())
}

fn acknowledge_authority_receipt<A: InstanceAuthorityPort>(
    authority: &A,
    retained: crate::authority_protocol::DurablyRetainedAuthorityReceiptV3,
) -> Result<ReceiptAckDispositionV2, AgentError> {
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        match authority.acknowledge(&retained) {
            Ok(AuthorityOutcomeV3::Known(
                disposition @ (ReceiptAckDispositionV2::Removed
                | ReceiptAckDispositionV2::AlreadyAbsent),
            )) => return Ok(disposition),
            Ok(AuthorityOutcomeV3::KnownFailure(
                AuthorityKnownFailureV3::RateLimited | AuthorityKnownFailureV3::AllocationFailed,
            ))
            | Ok(AuthorityOutcomeV3::Unknown(_))
            | Err(_) => {}
            Ok(AuthorityOutcomeV3::KnownFailure(_)) => {
                return Err(AgentError::InstanceLeaseUnavailable)
            }
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

fn recover_durable_lease_operation<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
) -> Result<(), AgentError> {
    let identity = authority.wire_identity()?;
    let Some(operation) = repository.durable_lease_operation(identity)? else {
        return Ok(());
    };
    if matches!(
        operation.intent().mutation(),
        AuthorityMutationV2::AdvanceState { .. }
    ) {
        return Err(AgentError::TransitionPending);
    }
    match operation {
        DurableAuthorityOperation::Resolved(_) => {
            let retained = operation.retained().map_err(RepositoryError::from)?;
            acknowledge_resolved_receipt(repository, authority, retained)
        }
        DurableAuthorityOperation::Prepared(intent) => {
            for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
                match authority.query(intent.operation_id()) {
                    Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::Found(receipt))) => {
                        let retained =
                            repository.resolve_lease_operation(identity, intent, *receipt)?;
                        return acknowledge_resolved_receipt(repository, authority, retained);
                    }
                    Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                        authority_version,
                    })) if authority_version >= intent.expected_authority_version() => {
                        repository.cancel_prepared_lease_operation(identity, intent)?;
                        return Ok(());
                    }
                    Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                        ..
                    })) => return Err(AgentError::InstanceLeaseUnavailable),
                    Ok(AuthorityOutcomeV3::KnownFailure(
                        AuthorityKnownFailureV3::RateLimited
                        | AuthorityKnownFailureV3::AllocationFailed,
                    ))
                    | Ok(AuthorityOutcomeV3::Unknown(_))
                    | Err(_) => {}
                    Ok(AuthorityOutcomeV3::KnownFailure(_)) => {
                        return Err(AgentError::InstanceLeaseUnavailable)
                    }
                }
            }
            Err(AgentError::InstanceLeaseIndeterminate)
        }
    }
}

fn reconcile_lease_operation<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        match authority.query(intent.operation_id()) {
            Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::Found(receipt))) => {
                return record_lease_receipt(repository, authority, lease, intent, *receipt);
            }
            Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version,
            })) if authority_version >= intent.expected_authority_version() => {
                repository.cancel_prepared_lease_operation(authority.wire_identity()?, intent)?;
                lease.authority_version = authority_version;
                return Ok(LeaseExchange::Retry);
            }
            Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion { .. })) => {
                return Err(AgentError::InstanceLeaseUnavailable)
            }
            Ok(AuthorityOutcomeV3::KnownFailure(
                AuthorityKnownFailureV3::RateLimited | AuthorityKnownFailureV3::AllocationFailed,
            ))
            | Ok(AuthorityOutcomeV3::Unknown(_))
            | Err(_) => {}
            Ok(AuthorityOutcomeV3::KnownFailure(_)) => {
                return Err(AgentError::InstanceLeaseUnavailable)
            }
        }
    }
    Err(AgentError::InstanceLeaseIndeterminate)
}

fn lease_exchange<A: InstanceAuthorityPort>(
    repository: &mut StateRepository,
    authority: &A,
    lease: &mut InstanceLeaseState,
    call: LeaseCall,
    intent: AuthorityIntentV2,
) -> Result<LeaseExchange, AgentError> {
    let identity = authority.wire_identity()?;
    repository.prepare_lease_operation(identity, intent)?;
    let outcome = match call {
        LeaseCall::Acquire => authority.acquire(intent),
        LeaseCall::Renew => authority.renew(intent),
        LeaseCall::Release => authority.release(intent),
    };
    match outcome {
        Ok(AuthorityOutcomeV3::Known(receipt)) => {
            record_lease_receipt(repository, authority, lease, intent, receipt)
        }
        Ok(AuthorityOutcomeV3::KnownFailure(AuthorityKnownFailureV3::AuthorityVersionMismatch)) => {
            repository.cancel_prepared_lease_operation(identity, intent)?;
            let snapshot = authority_snapshot(authority)?;
            lease.authority_version = snapshot.authority_version();
            Ok(LeaseExchange::Retry)
        }
        Ok(AuthorityOutcomeV3::KnownFailure(_)) => {
            repository.cancel_prepared_lease_operation(identity, intent)?;
            Err(AgentError::InstanceLeaseUnavailable)
        }
        Ok(AuthorityOutcomeV3::Unknown(_)) => {
            reconcile_lease_operation(repository, authority, lease, intent)
        }
        Err(_) => {
            repository.cancel_prepared_lease_operation(identity, intent)?;
            Err(AgentError::InstanceLeaseUnavailable)
        }
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
    repository: &mut StateRepository,
    authority: &A,
) -> Result<InstanceLeaseState, AgentError> {
    let instance_id = ProcessInstanceIdV2::from_bytes(fresh_lease_random()?)
        .map_err(|_| AgentError::LocalCryptoFailure)?;
    let mut lease = InstanceLeaseState {
        instance_id,
        fence: None,
        authority_version: 1,
        fenced: false,
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
            authority.wire_config()?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id,
            },
        )?;
        match lease_exchange(
            repository,
            authority,
            &mut lease,
            LeaseCall::Acquire,
            intent,
        )? {
            LeaseExchange::Receipt(receipt) => match receipt.disposition() {
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
                    AuthorityRejectionV2::LeaseHeld | AuthorityRejectionV2::LeaseGenerationMismatch,
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
            },
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
    let result = renew_instance_lease(inner);
    if matches!(result, Err(AgentError::InternalPoisoned)) {
        fatalize(inner)
    } else {
        result
    }
}

fn renew_instance_lease<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    if inner.lease.fenced {
        return Err(AgentError::InstanceFenced);
    }
    recover_durable_lease_operation(&mut inner.repository, &inner.authority)?;
    let Some(fence) = inner.lease.fence else {
        return Err(AgentError::InstanceFenced);
    };
    for _ in 0..LEASE_VERSION_RESYNC_ATTEMPTS {
        let intent = lease_intent(
            &inner.lease,
            inner.authority.wire_config()?,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        match lease_exchange(
            &mut inner.repository,
            &inner.authority,
            &mut inner.lease,
            LeaseCall::Renew,
            intent,
        )? {
            LeaseExchange::Receipt(receipt) => {
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
/// After this returns, the agent permanently refuses lease-guarded operations;
/// key use has provably stopped before any successor instance can acquire the
/// next lease generation.
fn fence_out<W: WitnessPort, A: InstanceAuthorityPort>(
    inner: &mut Inner<W, A>,
) -> Result<(), AgentError> {
    let handles: Vec<_> = inner.pending_sessions.keys().copied().collect();
    for handle in handles {
        erase_pending(inner, handle)?;
    }
    inner.confirmed_keys.clear();
    inner.completed_acceptances.clear();
    inner.lease.fence = None;
    inner.lease.fenced = true;
    Ok(())
}

const fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}
