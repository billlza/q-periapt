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
    IssuedLocalFinishedV1, MigrationContextV2, MigrationFinishedV1, MigrationIdentityKeyId,
    PendingMutualConfirmationV1, PostKemTranscriptV1, PreKemTranscriptV1, SignedCapabilityOfferV1,
};
use q_periapt_policy::{AuthenticatedPolicy, HybridSuite, KeyFormat, Policy};

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

    pub(crate) fn decode(bytes: [u8; 32]) -> Result<Self, AgentError> {
        SessionId::decode(bytes)
            .map(Self)
            .map_err(|_| AgentError::UnknownHandle)
    }
}

/// Encapsulation output: public ciphertexts plus a handle and local Finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginEncapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
    /// Public component ciphertexts.
    pub ciphertexts: EncapsulationCiphertexts,
    /// Role-separated local Finished; no application key is released.
    pub local_finished: MigrationFinishedV1,
}

/// Decapsulation output: only a handle and local Finished, never a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginDecapsulationResult {
    /// Opaque pending-session handle.
    pub handle: PendingSessionHandle,
    /// Role-separated local Finished; no application key is released.
    pub local_finished: MigrationFinishedV1,
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
    /// Peer Finished failed constant-time verification; the pending secret was erased.
    FinishedRejected,
    /// ABI version, entropy, or a local cryptographic provider failed.
    LocalCryptoFailure,
    /// The committed state is valid but this process has no exact compatible ABI 2 executor.
    ExecutionUnavailable,
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

struct PendingSession {
    confirmation: IssuedLocalFinishedV1<Sha3_256Xof>,
    expected_head: StateHead,
    deadline: Instant,
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

struct Inner<W: WitnessPort> {
    repository: StateRepository,
    witness: W,
    config: AgentConfig,
    local_policy: AuthenticatedPolicy,
    peer_policy: AuthenticatedPolicy,
    engine: ExecutorState,
    pending_engine: Option<ExecutorState>,
    pending_sessions: HashMap<PendingSessionHandle, PendingSession>,
    confirmed_keys: HashMap<ConfirmedKeyHandle, AcceptedSessionKeyV1>,
    poisoned: bool,
}

/// Process-local façade whose one mutex is the transition/session linearization point.
pub struct PolicyAgent<W: WitnessPort> {
    inner: Mutex<Inner<W>>,
}

impl<W: WitnessPort> fmt::Debug for PolicyAgent<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyAgent([redacted])")
    }
}

impl<W: WitnessPort> PolicyAgent<W> {
    /// Authenticate configured policy material and align local state with the mandatory witness.
    pub fn new(
        mut repository: StateRepository,
        witness: W,
        config: AgentConfig,
    ) -> Result<Self, AgentError> {
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
                config,
                local_policy,
                peer_policy,
                engine,
                pending_engine,
                pending_sessions: HashMap::new(),
                confirmed_keys: HashMap::new(),
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
        let confirmation = PendingMutualConfirmationV1::<Sha3_256Xof>::new(secret, &context, &post)
            .map_err(|_| AgentError::AuthorizationRejected)?;
        let (confirmation, local_finished) = confirmation.issue_local_finished();
        let handle = reserve_pending(&mut inner, head, capability_session_id, confirmation)?;
        Ok(BeginEncapsulationResult {
            handle,
            ciphertexts,
            local_finished,
        })
    }

    /// Begin decapsulation from signed capability envelopes and exact ciphertexts.
    pub fn begin_decapsulation(
        &self,
        request: BeginDecapsulation,
    ) -> Result<BeginDecapsulationResult, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
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
        let confirmation = PendingMutualConfirmationV1::<Sha3_256Xof>::new(secret, &context, &post)
            .map_err(|_| AgentError::AuthorizationRejected)?;
        let (confirmation, local_finished) = confirmation.issue_local_finished();
        let handle = reserve_pending(&mut inner, head, capability_session_id, confirmation)?;
        Ok(BeginDecapsulationResult {
            handle,
            local_finished,
        })
    }

    /// Verify peer Finished, exact local head, exact witness fence, and only then retain K.
    pub fn confirm(
        &self,
        handle: PendingSessionHandle,
        peer_finished: [u8; 32],
    ) -> Result<ConfirmedKeyHandle, AgentError> {
        let mut inner = self.lock()?;
        ensure_live(&inner)?;
        if matches!(inner.pending_sessions.get(&handle), Some(pending) if pending.deadline <= Instant::now())
        {
            erase_pending(&mut inner, handle)?;
            return Err(AgentError::SessionExpired);
        }
        purge_expired(&mut inner)?;
        if inner.repository.pending_intent().is_some() {
            return Err(AgentError::TransitionPending);
        }
        if inner.confirmed_keys.len() >= inner.config.limits.max_confirmed_keys {
            return Err(AgentError::CapacityExceeded);
        }
        let pending = inner
            .pending_sessions
            .get(&handle)
            .ok_or(AgentError::UnknownHandle)?;
        let expected_head = pending.expected_head;
        if inner.repository.head()? != expected_head {
            erase_pending(&mut inner, handle)?;
            return Err(AgentError::StaleSession);
        }
        let witness_head = inner.witness.read_head()?;
        if witness_head != expected_head {
            erase_pending(&mut inner, handle)?;
            return Err(AgentError::StaleSession);
        }
        let key_handle = generate_key_handle(&inner.confirmed_keys)?;
        let pending = inner
            .pending_sessions
            .remove(&handle)
            .ok_or(AgentError::UnknownHandle)?;
        let accepted = match pending.confirmation.verify_peer_and_accept(
            inner.repository.state_machine(),
            &MigrationFinishedV1::from_bytes(peer_finished),
        ) {
            Ok(accepted) => accepted,
            Err(error) => {
                if inner.repository.cancel_session(handle.0).is_err() {
                    inner.poisoned = true;
                    return Err(AgentError::InternalPoisoned);
                }
                return Err(match error {
                    q_periapt_migration::ConfirmationError::StaleState => AgentError::StaleSession,
                    _ => AgentError::FinishedRejected,
                });
            }
        };
        if inner
            .repository
            .release_session(handle.0, expected_head)
            .is_err()
        {
            inner.poisoned = true;
            return Err(AgentError::InternalPoisoned);
        }
        inner.confirmed_keys.insert(key_handle, accepted);
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
        inner
            .confirmed_keys
            .remove(&handle)
            .map(|_| ())
            .ok_or(AgentError::UnknownHandle)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner<W>>, AgentError> {
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

fn execute_transition<W: WitnessPort>(
    inner: &mut Inner<W>,
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

fn finish_transition<W: WitnessPort>(
    inner: &mut Inner<W>,
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
    inner.engine = inner.pending_engine.take().ok_or_else(|| {
        inner.poisoned = true;
        AgentError::InternalPoisoned
    })?;
    Ok(())
}

fn build_contract<W: WitnessPort>(
    inner: &Inner<W>,
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

fn verify_current_head<W: WitnessPort>(inner: &Inner<W>) -> Result<StateHead, AgentError> {
    if inner.repository.pending_intent().is_some() {
        return Err(AgentError::TransitionPending);
    }
    let local = inner.repository.head()?;
    if inner.witness.read_head()? != local {
        return Err(AgentError::RollbackOrFork);
    }
    Ok(local)
}

fn reserve_pending<W: WitnessPort>(
    inner: &mut Inner<W>,
    head: StateHead,
    capability_session_id: [u8; 32],
    confirmation: IssuedLocalFinishedV1<Sha3_256Xof>,
) -> Result<PendingSessionHandle, AgentError> {
    let deadline = Instant::now()
        .checked_add(inner.config.limits.session_ttl)
        .ok_or(AgentError::InvalidConfiguration)?;
    for _ in 0..4 {
        let handle = PendingSessionHandle(
            SessionId::generate().map_err(|_| AgentError::LocalCryptoFailure)?,
        );
        if inner.pending_sessions.contains_key(&handle) {
            continue;
        }
        inner
            .repository
            .reserve_session(handle.0, capability_session_id, head)?;
        inner.pending_sessions.insert(
            handle,
            PendingSession {
                confirmation,
                expected_head: head,
                deadline,
            },
        );
        return Ok(handle);
    }
    Err(AgentError::LocalCryptoFailure)
}

fn erase_pending<W: WitnessPort>(
    inner: &mut Inner<W>,
    handle: PendingSessionHandle,
) -> Result<(), AgentError> {
    let removed = inner
        .pending_sessions
        .remove(&handle)
        .ok_or(AgentError::UnknownHandle)?;
    drop(removed);
    inner.repository.cancel_session(handle.0)?;
    Ok(())
}

fn purge_expired<W: WitnessPort>(inner: &mut Inner<W>) -> Result<(), AgentError> {
    let now = Instant::now();
    let expired: Vec<_> = inner
        .pending_sessions
        .iter()
        .filter_map(|(handle, pending)| (pending.deadline <= now).then_some(*handle))
        .collect();
    for handle in expired {
        erase_pending(inner, handle)?;
    }
    Ok(())
}

fn ensure_session_capacity<W: WitnessPort>(inner: &Inner<W>) -> Result<(), AgentError> {
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

fn ensure_live<W: WitnessPort>(inner: &Inner<W>) -> Result<(), AgentError> {
    if inner.poisoned {
        Err(AgentError::InternalPoisoned)
    } else {
        Ok(())
    }
}

const fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}
