//! Explicit effect, persistence, anchor, delivery, and recovery lifecycle.

use crate::context::AuthenticatedContext;
use crate::types::{
    AnchorId, AnchorProfile, AnchorValue, CryptoCommand, CryptoCompletion, CryptoPurpose,
    CryptoResult, FenceToken, OperationBinding, OperationDraft, OperationId, ProtocolScope,
    RecordCommitment, RetryContract, SessionIdentity, StateDigest, StateVersion, TransitionId,
};

/// Current non-canonical durable-snapshot shape for the test-only model.
pub const DURABLE_SNAPSHOT_SCHEMA_VERSION: u16 = 3;

/// Durable record kind requested by the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersistStage {
    /// Install the effect reservation before exposing an execution permit.
    Reservation = 1,
    /// Pin the first complete provider result.
    ResultPin = 2,
    /// Persist an exact finalization and anchor plan before touching the anchor.
    AnchorReservation = 3,
    /// Atomically make the next state and release record committed.
    FinalCommit = 4,
    /// Durably acknowledge one exact idempotent release permission.
    ReleaseAck = 5,
    /// Close the operation as cancelled.
    Cancellation = 6,
    /// Close the operation as superseded.
    Supersession = 7,
}

/// Structured subject that an exact repository record must commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistSubject {
    /// Effect reservation for the complete operation binding.
    Reservation,
    /// Service-created pin for one validated provider result commitment.
    ResultPin {
        /// Closed result shape derived from the operation variant.
        result_kind: crate::types::ResultKind,
        /// Exact validated provider result commitment.
        result_commitment: crate::types::ResultCommitment,
    },
    /// Exact finalization and anchor intent persisted before the anchor effect.
    AnchorReservation(AnchorIntent),
    /// Final state commit, including the reconciled anchor intent when required.
    FinalCommit {
        /// Exact per-transition anchor intent, or none for non-anchor profiles.
        anchor_intent: Option<AnchorIntent>,
    },
    /// Exact idempotent release permission being acknowledged.
    ReleaseAck(ReleasePermit),
    /// Durable cancellation tombstone.
    Cancellation,
    /// Durable supersession tombstone.
    Supersession,
}

impl PersistSubject {
    const fn matches_stage(self, stage: PersistStage) -> bool {
        matches!(
            (stage, self),
            (PersistStage::Reservation, Self::Reservation)
                | (PersistStage::ResultPin, Self::ResultPin { .. })
                | (PersistStage::AnchorReservation, Self::AnchorReservation(_))
                | (PersistStage::FinalCommit, Self::FinalCommit { .. })
                | (PersistStage::ReleaseAck, Self::ReleaseAck(_))
                | (PersistStage::Cancellation, Self::Cancellation)
                | (PersistStage::Supersession, Self::Supersession)
        )
    }
}

/// One exact aggregate-state revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateRevision {
    version: StateVersion,
    digest: StateDigest,
}

impl StateRevision {
    /// Construct an indivisible version-and-digest revision.
    #[must_use]
    pub const fn new(version: StateVersion, digest: StateDigest) -> Self {
        Self { version, digest }
    }

    /// Return the monotonic state version.
    #[must_use]
    pub const fn version(self) -> StateVersion {
        self.version
    }

    /// Return the exact state commitment at that version.
    #[must_use]
    pub const fn digest(self) -> StateDigest {
        self.digest
    }
}

/// Exact compare-and-swap predecessor and successor revisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateAdvance {
    expected: StateRevision,
    next: StateRevision,
}

impl StateAdvance {
    /// Construct an exact state advance.
    #[must_use]
    pub const fn new(expected: StateRevision, next: StateRevision) -> Self {
        Self { expected, next }
    }

    /// Return the required predecessor revision.
    #[must_use]
    pub const fn expected(self) -> StateRevision {
        self.expected
    }

    /// Return the installed successor revision.
    #[must_use]
    pub const fn next(self) -> StateRevision {
        self.next
    }
}

/// Exact aggregate write intent used for commit and unknown-outcome reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistIntent {
    stage: PersistStage,
    subject: PersistSubject,
    transition_id: TransitionId,
    operation_id: OperationId,
    binding: OperationBinding,
    state_advance: StateAdvance,
    record_commitment: RecordCommitment,
    fence_token: FenceToken,
}

impl PersistIntent {
    /// Return the durable stage.
    #[must_use]
    pub const fn stage(self) -> PersistStage {
        self.stage
    }

    /// Return the structured record subject.
    #[must_use]
    pub const fn subject(self) -> PersistSubject {
        self.subject
    }

    /// Return the transition identifier.
    #[must_use]
    pub const fn transition_id(self) -> TransitionId {
        self.transition_id
    }

    /// Return the operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete operation binding covered by this write.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the required prior version.
    #[must_use]
    pub const fn expected_state_version(self) -> StateVersion {
        self.state_advance.expected.version
    }

    /// Return the exact required predecessor-state commitment.
    #[must_use]
    pub const fn expected_state_digest(self) -> StateDigest {
        self.state_advance.expected.digest
    }

    /// Return the version installed by an exact commit.
    #[must_use]
    pub const fn next_state_version(self) -> StateVersion {
        self.state_advance.next.version
    }

    /// Return the exact record commitment.
    #[must_use]
    pub const fn record_commitment(self) -> RecordCommitment {
        self.record_commitment
    }

    /// Return the exact next-state digest.
    #[must_use]
    pub const fn next_state_digest(self) -> StateDigest {
        self.state_advance.next.digest
    }

    /// Return the indivisible compare-and-swap state advance.
    #[must_use]
    pub const fn state_advance(self) -> StateAdvance {
        self.state_advance
    }

    /// Return the writer fence required at commit.
    #[must_use]
    pub const fn fence_token(self) -> FenceToken {
        self.fence_token
    }

    /// Construct the only receipt accepted for this exact intent.
    #[must_use]
    pub const fn exact_receipt(self) -> CommitReceipt {
        CommitReceipt {
            stage: self.stage,
            subject: self.subject,
            transition_id: self.transition_id,
            operation_id: self.operation_id,
            binding: self.binding,
            state_advance: self.state_advance,
            record_commitment: self.record_commitment,
            fence_token: self.fence_token,
        }
    }
}

/// Authenticated repository receipt for one exact aggregate write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    stage: PersistStage,
    subject: PersistSubject,
    transition_id: TransitionId,
    operation_id: OperationId,
    binding: OperationBinding,
    state_advance: StateAdvance,
    record_commitment: RecordCommitment,
    fence_token: FenceToken,
}

impl CommitReceipt {
    /// Construct a receipt. Every field must match the pending intent exactly.
    #[must_use]
    pub const fn new(
        identity: CommitIdentity,
        subject: PersistSubject,
        binding: OperationBinding,
        state_advance: StateAdvance,
        record_commitment: RecordCommitment,
        fence_token: FenceToken,
    ) -> Self {
        Self {
            stage: identity.stage,
            subject,
            transition_id: identity.transition_id,
            operation_id: identity.operation_id,
            binding,
            state_advance,
            record_commitment,
            fence_token,
        }
    }
}

/// Identity fields of a repository commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitIdentity {
    stage: PersistStage,
    transition_id: TransitionId,
    operation_id: OperationId,
}

impl CommitIdentity {
    /// Construct commit identity fields.
    #[must_use]
    pub const fn new(
        stage: PersistStage,
        transition_id: TransitionId,
        operation_id: OperationId,
    ) -> Self {
        Self {
            stage,
            transition_id,
            operation_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryOutcomeKind {
    Applied,
    NotApplied,
    Conflict,
    Unknown,
}

/// Repository result envelope. Unknown never aliases failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryOutcome {
    kind: RepositoryOutcomeKind,
    receipt: Option<CommitReceipt>,
    observed_fence: Option<FenceToken>,
}

impl RepositoryOutcome {
    /// Report that the exact aggregate write committed with this receipt.
    #[must_use]
    pub const fn applied(receipt: CommitReceipt) -> Self {
        Self {
            kind: RepositoryOutcomeKind::Applied,
            receipt: Some(receipt),
            observed_fence: None,
        }
    }

    /// Report that a linearizable read proves the exact write absent.
    #[must_use]
    pub const fn not_applied() -> Self {
        Self {
            kind: RepositoryOutcomeKind::NotApplied,
            receipt: None,
            observed_fence: None,
        }
    }

    /// Report that another writer or state won the compare-and-swap.
    #[must_use]
    pub const fn conflict(observed_fence: FenceToken) -> Self {
        Self {
            kind: RepositoryOutcomeKind::Conflict,
            receipt: None,
            observed_fence: Some(observed_fence),
        }
    }

    /// Report that the repository outcome remains unknown.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            kind: RepositoryOutcomeKind::Unknown,
            receipt: None,
            observed_fence: None,
        }
    }

    /// Return the observed conflicting fence, if this is a conflict result.
    #[must_use]
    pub const fn observed_fence(&self) -> Option<FenceToken> {
        self.observed_fence
    }
}

/// Structured evidence retained with a fail-closed suspension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionEvidence {
    /// The suspension has no additional typed evidence.
    None,
    /// An authoritative lease observation advanced beyond this writer.
    FenceLoss {
        /// Strictly newer authoritative fence observed by the caller.
        observed_fence: FenceToken,
    },
    /// The aggregate repository reported a conflicting writer or state.
    RepositoryConflict {
        /// Fence reported by the repository; it need not be newer than this writer.
        observed_fence: FenceToken,
    },
}

impl SuspensionEvidence {
    const fn matches_reason(self, reason: SuspensionReason) -> bool {
        matches!(
            (reason, self),
            (SuspensionReason::FenceLost, Self::FenceLoss { .. })
                | (
                    SuspensionReason::RepositoryConflict,
                    Self::RepositoryConflict { .. }
                )
                | (
                    SuspensionReason::ResultBindingMismatch
                        | SuspensionReason::ResultShapeMismatch
                        | SuspensionReason::ConflictingProviderResult
                        | SuspensionReason::ProviderOutcomeContradiction
                        | SuspensionReason::ResultBeforeDispatch
                        | SuspensionReason::IndeterminateProviderOperation
                        | SuspensionReason::ProviderDefinitiveFailure
                        | SuspensionReason::RepositoryReceiptMismatch
                        | SuspensionReason::AnchorBindingMismatch
                        | SuspensionReason::AnchorAheadOrConflict
                        | SuspensionReason::AnchorEquivocation
                        | SuspensionReason::AnchorUnauthenticated
                        | SuspensionReason::AnchorUnavailable
                        | SuspensionReason::ReleaseBindingMismatch,
                    Self::None
                )
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SuspensionCause {
    reason: SuspensionReason,
    evidence: SuspensionEvidence,
}

impl SuspensionCause {
    const fn new(reason: SuspensionReason, evidence: SuspensionEvidence) -> Self {
        Self { reason, evidence }
    }
}

/// Exact append-only tombstone requested for a fail-closed suspension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionIntent {
    operation_id: OperationId,
    binding: OperationBinding,
    reason: SuspensionReason,
    record_commitment: RecordCommitment,
    fence_token: FenceToken,
    evidence: SuspensionEvidence,
}

impl SuspensionIntent {
    /// Return the suspended operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete suspended operation binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the exact suspension reason.
    #[must_use]
    pub const fn reason(self) -> SuspensionReason {
        self.reason
    }

    /// Return the append-only record commitment fixed before execution.
    #[must_use]
    pub const fn record_commitment(self) -> RecordCommitment {
        self.record_commitment
    }

    /// Return the writer fence observed by the suspended operation.
    #[must_use]
    pub const fn fence_token(self) -> FenceToken {
        self.fence_token
    }

    /// Return the typed evidence retained for this suspension.
    #[must_use]
    pub const fn evidence(self) -> SuspensionEvidence {
        self.evidence
    }

    /// Construct the only receipt accepted for this exact suspension.
    #[must_use]
    pub const fn exact_receipt(self) -> SuspensionReceipt {
        SuspensionReceipt { intent: self }
    }
}

/// Authenticated receipt for an exact append-only suspension tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionReceipt {
    intent: SuspensionIntent,
}

impl SuspensionReceipt {
    /// Construct a receipt that will be accepted only if the complete intent matches.
    #[must_use]
    pub const fn new(intent: SuspensionIntent) -> Self {
        Self { intent }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuspensionOutcomeKind {
    Applied,
    NotApplied,
    Unknown,
    Conflict,
}

/// Result from the append-only suspension journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionOutcome {
    kind: SuspensionOutcomeKind,
    receipt: Option<SuspensionReceipt>,
}

impl SuspensionOutcome {
    /// Report that the exact suspension tombstone committed.
    #[must_use]
    pub const fn applied(receipt: SuspensionReceipt) -> Self {
        Self {
            kind: SuspensionOutcomeKind::Applied,
            receipt: Some(receipt),
        }
    }

    /// Report that the exact suspension tombstone is absent.
    #[must_use]
    pub const fn not_applied() -> Self {
        Self {
            kind: SuspensionOutcomeKind::NotApplied,
            receipt: None,
        }
    }

    /// Report that the suspension-journal outcome remains unknown.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            kind: SuspensionOutcomeKind::Unknown,
            receipt: None,
        }
    }

    /// Report a conflicting suspension-journal record.
    #[must_use]
    pub const fn conflict() -> Self {
        Self {
            kind: SuspensionOutcomeKind::Conflict,
            receipt: None,
        }
    }
}

/// Service-created state transition used to pin a validated provider result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultPinPlan {
    record_commitment: RecordCommitment,
    next_state_digest: StateDigest,
}

impl ResultPinPlan {
    /// Construct a result-pin plan outside the provider completion envelope.
    #[must_use]
    pub const fn new(record_commitment: RecordCommitment, next_state_digest: StateDigest) -> Self {
        Self {
            record_commitment,
            next_state_digest,
        }
    }
}

/// Caller-supplied anchor values and durable preparation record.
///
/// The model binds these values to the exact operation and final state. It does not
/// claim to implement the future canonical hash that derives the next anchor value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorPlan {
    anchor_id: AnchorId,
    exact_prior: AnchorValue,
    exact_next: AnchorValue,
    preparation_record_commitment: RecordCommitment,
    preparation_state_digest: StateDigest,
}

impl AnchorPlan {
    /// Construct a per-transition anchor preparation plan.
    #[must_use]
    pub const fn new(
        anchor_id: AnchorId,
        exact_prior: AnchorValue,
        exact_next: AnchorValue,
        preparation_record_commitment: RecordCommitment,
        preparation_state_digest: StateDigest,
    ) -> Self {
        Self {
            anchor_id,
            exact_prior,
            exact_next,
            preparation_record_commitment,
            preparation_state_digest,
        }
    }
}

/// Exact authenticated anchor operation built by the lifecycle model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorIntent {
    operation_id: OperationId,
    binding: OperationBinding,
    anchor_id: AnchorId,
    exact_prior: AnchorValue,
    exact_next: AnchorValue,
    final_record_commitment: RecordCommitment,
    final_state_digest: StateDigest,
}

impl AnchorIntent {
    const fn from_plan(
        operation_id: OperationId,
        binding: OperationBinding,
        final_record_commitment: RecordCommitment,
        final_state_digest: StateDigest,
        plan: AnchorPlan,
    ) -> Self {
        Self {
            operation_id,
            binding,
            anchor_id: plan.anchor_id,
            exact_prior: plan.exact_prior,
            exact_next: plan.exact_next,
            final_record_commitment,
            final_state_digest,
        }
    }

    /// Return the complete operation binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the anchor identifier.
    #[must_use]
    pub const fn anchor_id(self) -> AnchorId {
        self.anchor_id
    }

    /// Return the transition identifier.
    #[must_use]
    pub const fn transition_id(self) -> TransitionId {
        self.binding.session().transition_id()
    }

    /// Return the operation identifier indirectly bound by an anchor response.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the exact prior anchor value.
    #[must_use]
    pub const fn exact_prior(self) -> AnchorValue {
        self.exact_prior
    }

    /// Return the exact next anchor value.
    #[must_use]
    pub const fn exact_next(self) -> AnchorValue {
        self.exact_next
    }

    /// Return the final record commitment bound by the anchor operation.
    #[must_use]
    pub const fn final_record_commitment(self) -> RecordCommitment {
        self.final_record_commitment
    }

    /// Return the final state digest bound by the anchor operation.
    #[must_use]
    pub const fn final_state_digest(self) -> StateDigest {
        self.final_state_digest
    }

    /// Return the writer fence.
    #[must_use]
    pub const fn fence_token(self) -> FenceToken {
        self.binding.session().fence_token()
    }
}

/// Authenticated result of an anchor operation or reconciliation query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorOutcome {
    /// The exact transition was newly applied.
    AppliedExact(AnchorIntent),
    /// A query proves the exact transition was already applied.
    AlreadyAppliedExact(AnchorIntent),
    /// A query proves the anchor still equals the exact prior value.
    NotAppliedExactPrior(AnchorIntent),
    /// The caller cannot determine whether the anchor advanced.
    Unknown,
    /// The authenticated anchor is ahead of the expected transition.
    Ahead,
    /// The authenticated anchor conflicts with both exact values.
    Conflict,
    /// Two authenticated views equivocate.
    Equivocation,
    /// The anchor is temporarily unavailable.
    Unavailable,
    /// The response is not authenticated and must not be interpreted.
    Unauthenticated,
}

/// Rollback-assurance boundary attached to a release permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceLevel {
    /// Commit ordering only; no external rollback-detection claim.
    CommitOrderingOnly,
    /// The exact final state was bound to an authenticated per-transition anchor.
    PerTransitionAnchored,
}

/// Exact idempotent delivery permission installed by the final aggregate commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePermit {
    operation_id: OperationId,
    binding: OperationBinding,
    final_record_commitment: RecordCommitment,
    final_state_digest: StateDigest,
    assurance: AssuranceLevel,
}

impl ReleasePermit {
    /// Return the transition identifier.
    #[must_use]
    pub const fn transition_id(self) -> TransitionId {
        self.binding.session().transition_id()
    }

    /// Return the operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete operation binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the exact committed release or outbox record commitment.
    #[must_use]
    pub const fn final_record_commitment(self) -> RecordCommitment {
        self.final_record_commitment
    }

    /// Return the exact committed state digest.
    #[must_use]
    pub const fn final_state_digest(self) -> StateDigest {
        self.final_state_digest
    }

    /// Return the precise rollback-assurance boundary.
    #[must_use]
    pub const fn assurance(self) -> AssuranceLevel {
        self.assurance
    }
}

/// External effect requested by one model step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// No external effect is permitted or required.
    None,
    /// Atomically persist the exact aggregate intent.
    Persist(PersistIntent),
    /// Execute the provider command after its reservation is durable.
    Execute(CryptoCommand),
    /// Re-execute the byte-identical deterministic command.
    RetryExact(CryptoCommand),
    /// Query the exact stable provider operation; do not create a new command.
    QueryProvider(CryptoCommand),
    /// Query whether an unknown repository write committed.
    QueryRepository(PersistIntent),
    /// Compare-and-advance the authenticated anchor.
    AdvanceAnchor(AnchorIntent),
    /// Retry the same exact anchor compare-and-advance.
    RetryAnchor(AnchorIntent),
    /// Query the outcome of the same exact anchor operation.
    QueryAnchor(AnchorIntent),
    /// Release the same committed delivery until its exact acknowledgement is durable.
    Release(ReleasePermit),
    /// Append the exact fail-closed suspension tombstone.
    PersistSuspension(SuspensionIntent),
    /// Retry the same exact append-only suspension tombstone.
    RetrySuspension(SuspensionIntent),
    /// Query the exact suspension tombstone after an unknown outcome.
    QuerySuspension(SuspensionIntent),
    /// Re-emit durable quarantine or cleanup for a suspended operation.
    Quarantine(SuspensionIntent),
}

impl Effect {
    /// Return the persist intent carried by this effect, if any.
    #[must_use]
    pub const fn persist_intent(self) -> Option<PersistIntent> {
        match self {
            Self::Persist(intent) => Some(intent),
            _ => None,
        }
    }

    /// Return the provider command carried by an execute, retry, or query effect.
    #[must_use]
    pub const fn crypto_command(self) -> Option<CryptoCommand> {
        match self {
            Self::Execute(command) | Self::RetryExact(command) | Self::QueryProvider(command) => {
                Some(command)
            }
            _ => None,
        }
    }

    /// Return the anchor intent carried by an advance, retry, or query effect.
    #[must_use]
    pub const fn anchor_intent(self) -> Option<AnchorIntent> {
        match self {
            Self::AdvanceAnchor(intent) | Self::RetryAnchor(intent) | Self::QueryAnchor(intent) => {
                Some(intent)
            }
            _ => None,
        }
    }

    /// Return the release permission carried by this effect, if any.
    #[must_use]
    pub const fn release_permit(self) -> Option<ReleasePermit> {
        match self {
            Self::Release(permit) => Some(permit),
            _ => None,
        }
    }

    /// Return the suspension intent carried by this effect, if any.
    #[must_use]
    pub const fn suspension_intent(self) -> Option<SuspensionIntent> {
        match self {
            Self::PersistSuspension(intent)
            | Self::RetrySuspension(intent)
            | Self::QuerySuspension(intent)
            | Self::Quarantine(intent) => Some(intent),
            _ => None,
        }
    }
}

/// Observable lifecycle phase. It is not a production persistence encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseTag {
    /// No transition is active.
    Idle,
    /// The effect reservation write is in flight.
    AwaitingReservation,
    /// The effect reservation is durable; provider execution is now permitted.
    Reserved,
    /// The provider command has been dispatched.
    Dispatched,
    /// A complete result is validated but not yet durable.
    ResultReceived,
    /// The first complete result is being pinned.
    AwaitingResultPin,
    /// The first complete result is durable.
    ResultPinned,
    /// The exact finalization and anchor plan are being persisted.
    AwaitingAnchorReservation,
    /// The exact anchor plan is durable but has not been reconciled.
    AnchorReserved,
    /// A per-transition anchor operation is in flight.
    AwaitingAnchor,
    /// The anchor outcome is unknown and must be queried.
    AnchorUnknown,
    /// The final aggregate commit is in flight.
    AwaitingFinalCommit,
    /// A cancellation or supersession tombstone is in flight.
    AwaitingClosure,
    /// A repository outcome is unknown and must be queried.
    CommitUnknown,
    /// The final commit is durable and the exact release awaits acknowledgement.
    CommittedPendingRelease,
    /// The release acknowledgement is being persisted.
    AwaitingReleaseAck,
    /// An append-only fail-closed suspension tombstone is being persisted.
    AwaitingSuspension,
    /// The suspension-journal outcome is unknown and must be queried.
    SuspensionUnknown,
    /// The transition and release acknowledgement are durable.
    Committed,
    /// A cancellation tombstone committed.
    Cancelled,
    /// A supersession tombstone committed.
    Superseded,
    /// The transition failed closed and requires reconciliation or recovery.
    Suspended,
}

/// Reasons a modeled transition must stop rather than retry or fall back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionReason {
    /// A provider returned the wrong operation or structured binding.
    ResultBindingMismatch,
    /// A provider returned a result shape not allowed by the closed operation.
    ResultShapeMismatch,
    /// Two different successful results were returned for one operation.
    ConflictingProviderResult,
    /// A provider contradicted an already accepted successful result.
    ProviderOutcomeContradiction,
    /// A provider result arrived before durable reservation and dispatch.
    ResultBeforeDispatch,
    /// A non-repeatable provider outcome is unknown.
    IndeterminateProviderOperation,
    /// A provider reported a definitive failure.
    ProviderDefinitiveFailure,
    /// A repository receipt did not match the exact pending write.
    RepositoryReceiptMismatch,
    /// Another writer or state won the repository compare-and-swap.
    RepositoryConflict,
    /// An authoritative lease observation proved that this writer lost its fence.
    FenceLost,
    /// The anchor response did not match the exact operation.
    AnchorBindingMismatch,
    /// The anchor is ahead or conflicts with the expected transition.
    AnchorAheadOrConflict,
    /// Authenticated anchor views equivocate.
    AnchorEquivocation,
    /// An anchor result was unauthenticated.
    AnchorUnauthenticated,
    /// The anchor is unavailable and policy forbids progress without it.
    AnchorUnavailable,
    /// A release acknowledgement did not match the exact committed permission.
    ReleaseBindingMismatch,
}

/// Typed rejection from an invalid model transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The requested event is not valid in the current phase.
    InvalidPhase,
    /// An executable command was requested before durable reservation.
    EffectReservationRequired,
    /// A state version, command ordinal, or dispatch counter overflowed.
    CounterOverflow,
    /// A fence-loss event did not carry a strictly newer authoritative fence.
    FenceNotAdvanced,
    /// The draft does not bind the current state, next reserved state, ordinal, or fence.
    DraftBindingMismatch,
    /// The draft targets a different session or pair of devices than the trusted state.
    SessionIdentityMismatch,
    /// The draft's exact prior authentication context is not the trusted current context.
    AuthenticatedContextMismatch,
    /// The closed operation purpose is incompatible with the lifecycle-context variant.
    ContextOperationMismatch,
    /// The provider completion does not equal the complete active operation binding.
    ResultBindingMismatch,
    /// The provider result shape differs from the operation's closed expectation.
    ResultShapeMismatch,
    /// A provider result arrived before dispatch.
    ResultBeforeDispatch,
    /// The exact result was already accepted and cannot be applied twice.
    DuplicateResult,
    /// A conflicting result was returned for the same active operation.
    ConflictingResult,
    /// A repository receipt does not equal the pending aggregate write.
    RepositoryReceiptMismatch,
    /// A per-transition anchor profile requires an exact anchor plan.
    AnchorRequired,
    /// An anchor plan is not allowed for this profile.
    UnexpectedAnchor,
    /// A per-transition anchor plan did not change the authenticated anchor value.
    AnchorDidNotAdvance,
    /// An anchor response did not equal the exact pending intent.
    AnchorBindingMismatch,
    /// A release acknowledgement did not equal the committed permission.
    ReleaseBindingMismatch,
    /// The requested cut is not a model-known durable state.
    DurableSnapshotUnavailable,
    /// The transition is already committed.
    AlreadyCompleted,
    /// The operation is durably cancelled.
    AlreadyCancelled,
    /// The operation is durably superseded.
    AlreadySuperseded,
    /// A closure commit is already in flight.
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    AwaitingReservation,
    Reserved,
    Dispatched,
    ResultReceived,
    AwaitingResultPin,
    ResultPinned,
    AwaitingAnchorReservation,
    AnchorReserved,
    AwaitingAnchor,
    AnchorUnknown,
    AwaitingFinalCommit,
    AwaitingClosure(PersistStage),
    CommitUnknown,
    CommittedPendingRelease,
    AwaitingReleaseAck,
    AwaitingSuspension,
    SuspensionUnknown,
    Committed,
    Cancelled,
    Superseded,
    Suspended(SuspensionReason),
}

impl Phase {
    const fn tag(self) -> PhaseTag {
        match self {
            Self::Idle => PhaseTag::Idle,
            Self::AwaitingReservation => PhaseTag::AwaitingReservation,
            Self::Reserved => PhaseTag::Reserved,
            Self::Dispatched => PhaseTag::Dispatched,
            Self::ResultReceived => PhaseTag::ResultReceived,
            Self::AwaitingResultPin => PhaseTag::AwaitingResultPin,
            Self::ResultPinned => PhaseTag::ResultPinned,
            Self::AwaitingAnchorReservation => PhaseTag::AwaitingAnchorReservation,
            Self::AnchorReserved => PhaseTag::AnchorReserved,
            Self::AwaitingAnchor => PhaseTag::AwaitingAnchor,
            Self::AnchorUnknown => PhaseTag::AnchorUnknown,
            Self::AwaitingFinalCommit => PhaseTag::AwaitingFinalCommit,
            Self::AwaitingClosure(_) => PhaseTag::AwaitingClosure,
            Self::CommitUnknown => PhaseTag::CommitUnknown,
            Self::CommittedPendingRelease => PhaseTag::CommittedPendingRelease,
            Self::AwaitingReleaseAck => PhaseTag::AwaitingReleaseAck,
            Self::AwaitingSuspension => PhaseTag::AwaitingSuspension,
            Self::SuspensionUnknown => PhaseTag::SuspensionUnknown,
            Self::Committed => PhaseTag::Committed,
            Self::Cancelled => PhaseTag::Cancelled,
            Self::Superseded => PhaseTag::Superseded,
            Self::Suspended(_) => PhaseTag::Suspended,
        }
    }

    const fn is_snapshotable(self) -> bool {
        matches!(
            self,
            Self::Idle
                | Self::AwaitingReservation
                | Self::Reserved
                | Self::AwaitingResultPin
                | Self::ResultPinned
                | Self::AwaitingAnchorReservation
                | Self::AnchorReserved
                | Self::AwaitingFinalCommit
                | Self::AwaitingClosure(_)
                | Self::CommitUnknown
                | Self::CommittedPendingRelease
                | Self::AwaitingReleaseAck
                | Self::AwaitingSuspension
                | Self::SuspensionUnknown
                | Self::Committed
                | Self::Cancelled
                | Self::Superseded
                | Self::Suspended(_)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveOperation {
    command: CryptoCommand,
    result: Option<AcceptedResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptedResult {
    Volatile(CryptoResult),
    Pinned(CryptoResult),
}

impl AcceptedResult {
    const fn result(self) -> CryptoResult {
        match self {
            Self::Volatile(result) | Self::Pinned(result) => result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Finalization {
    final_record_commitment: RecordCommitment,
    final_state_digest: StateDigest,
    anchor_intent: Option<AnchorIntent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptApplication {
    Reservation,
    ResultPin(CryptoResult),
    AnchorReservation,
    FinalCommit(ReleasePermit),
    ReleaseAck(u8),
    Cancellation,
    Supersession,
}

/// Abstract model-known durable state used to destroy and reconstruct process state.
///
/// This is not a canonical byte encoding and does not prove fsync, WAL, migration,
/// corruption detection, or backup behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableSnapshot {
    schema_version: u16,
    protocol_scope: ProtocolScope,
    session_identity: SessionIdentity,
    authenticated_context: AuthenticatedContext,
    phase: Phase,
    state_version: StateVersion,
    state_digest: StateDigest,
    fence_token: FenceToken,
    next_ordinal: crate::types::CommandOrdinal,
    active: Option<ActiveOperation>,
    pending_persist: Option<PersistIntent>,
    finalization: Option<Finalization>,
    release_permit: Option<ReleasePermit>,
    pending_suspension: Option<SuspensionIntent>,
    post_reconcile_suspension: Option<SuspensionCause>,
    durable_release_ack_count: u8,
}

impl DurableSnapshot {
    /// Return the non-canonical snapshot schema version.
    #[must_use]
    pub const fn schema_version(self) -> u16 {
        self.schema_version
    }

    /// Return the stable phase represented by this snapshot.
    #[must_use]
    pub const fn phase(self) -> PhaseTag {
        self.phase.tag()
    }

    /// Return the trusted pairwise session identity retained by this snapshot.
    #[must_use]
    pub const fn session_identity(self) -> SessionIdentity {
        self.session_identity
    }

    /// Return the trusted current authentication context retained by this snapshot.
    #[must_use]
    pub const fn authenticated_context(self) -> AuthenticatedContext {
        self.authenticated_context
    }

    /// Report whether an invalid volatile provider result survived in this snapshot.
    ///
    /// A snapshot returned by [`TransitionModel::durable_snapshot`] must always
    /// return `false`; this accessor exists so crash-cut tests can enforce that
    /// persistence boundary without inspecting private model fields.
    #[must_use]
    pub const fn contains_volatile_provider_result(self) -> bool {
        matches!(
            self.active,
            Some(ActiveOperation {
                result: Some(AcceptedResult::Volatile(_)),
                ..
            })
        )
    }
}

/// One-transition executable model. It owns no secret or plaintext bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionModel {
    protocol_scope: ProtocolScope,
    session_identity: SessionIdentity,
    authenticated_context: AuthenticatedContext,
    phase: Phase,
    state_version: StateVersion,
    state_digest: StateDigest,
    fence_token: FenceToken,
    next_ordinal: crate::types::CommandOrdinal,
    active: Option<ActiveOperation>,
    pending_persist: Option<PersistIntent>,
    finalization: Option<Finalization>,
    release_permit: Option<ReleasePermit>,
    pending_suspension: Option<SuspensionIntent>,
    post_reconcile_suspension: Option<SuspensionCause>,
    durable_release_ack_count: u8,
    provider_dispatch_count: u32,
}

impl TransitionModel {
    /// Construct an idle lifecycle model at an exact durable state.
    #[must_use]
    pub const fn new(
        protocol_scope: ProtocolScope,
        session_identity: SessionIdentity,
        authenticated_context: AuthenticatedContext,
        state_version: StateVersion,
        state_digest: StateDigest,
        fence_token: FenceToken,
        next_ordinal: crate::types::CommandOrdinal,
    ) -> Self {
        Self {
            protocol_scope,
            session_identity,
            authenticated_context,
            phase: Phase::Idle,
            state_version,
            state_digest,
            fence_token,
            next_ordinal,
            active: None,
            pending_persist: None,
            finalization: None,
            release_permit: None,
            pending_suspension: None,
            post_reconcile_suspension: None,
            durable_release_ack_count: 0,
            provider_dispatch_count: 0,
        }
    }

    /// Reconstruct a fresh process model from one model-known durable snapshot.
    #[must_use]
    pub const fn reconstruct(snapshot: DurableSnapshot) -> Self {
        Self {
            protocol_scope: snapshot.protocol_scope,
            session_identity: snapshot.session_identity,
            authenticated_context: snapshot.authenticated_context,
            phase: snapshot.phase,
            state_version: snapshot.state_version,
            state_digest: snapshot.state_digest,
            fence_token: snapshot.fence_token,
            next_ordinal: snapshot.next_ordinal,
            active: snapshot.active,
            pending_persist: snapshot.pending_persist,
            finalization: snapshot.finalization,
            release_permit: snapshot.release_permit,
            pending_suspension: snapshot.pending_suspension,
            post_reconcile_suspension: snapshot.post_reconcile_suspension,
            durable_release_ack_count: snapshot.durable_release_ack_count,
            provider_dispatch_count: 0,
        }
    }

    /// Return a snapshot only at a state the model treats as durably committed.
    pub fn durable_snapshot(&self) -> Result<DurableSnapshot, LifecycleError> {
        if !self.phase.is_snapshotable() || !self.snapshot_shape_is_valid() {
            return Err(LifecycleError::DurableSnapshotUnavailable);
        }
        let mut active = self.active;
        if let Some(operation) = active.as_mut() {
            if matches!(operation.result, Some(AcceptedResult::Volatile(_))) {
                operation.result = None;
            }
        }
        Ok(DurableSnapshot {
            schema_version: DURABLE_SNAPSHOT_SCHEMA_VERSION,
            protocol_scope: self.protocol_scope,
            session_identity: self.session_identity,
            authenticated_context: self.authenticated_context,
            phase: self.phase,
            state_version: self.state_version,
            state_digest: self.state_digest,
            fence_token: self.fence_token,
            next_ordinal: self.next_ordinal,
            active,
            pending_persist: self.pending_persist,
            finalization: self.finalization,
            release_permit: self.release_permit,
            pending_suspension: self.pending_suspension,
            post_reconcile_suspension: self.post_reconcile_suspension,
            durable_release_ack_count: self.durable_release_ack_count,
        })
    }

    /// Return the observable model phase.
    #[must_use]
    pub const fn phase(&self) -> PhaseTag {
        self.phase.tag()
    }

    /// Return the exact durable state version known by the model.
    #[must_use]
    pub const fn state_version(&self) -> StateVersion {
        self.state_version
    }

    /// Return the exact durable state digest known by the model.
    #[must_use]
    pub const fn state_digest(&self) -> StateDigest {
        self.state_digest
    }

    /// Return the trusted pairwise session identity for this model instance.
    #[must_use]
    pub const fn session_identity(&self) -> SessionIdentity {
        self.session_identity
    }

    /// Return the trusted current authentication context for this model instance.
    #[must_use]
    pub const fn authenticated_context(&self) -> AuthenticatedContext {
        self.authenticated_context
    }

    /// Return provider execution permissions emitted by this process instance.
    #[must_use]
    pub const fn provider_dispatch_count(&self) -> u32 {
        self.provider_dispatch_count
    }

    /// Return the number of exact release acknowledgements committed by the model.
    #[must_use]
    pub const fn release_count(&self) -> u8 {
        self.durable_release_ack_count
    }

    /// Return the suspension reason, if the model is suspended.
    #[must_use]
    pub const fn suspension_reason(&self) -> Option<SuspensionReason> {
        match self.phase {
            Phase::Suspended(reason) => Some(reason),
            _ => None,
        }
    }

    /// Prepare and request durable installation of an effect reservation.
    pub fn prepare(
        &mut self,
        draft: OperationDraft,
        reservation_record_commitment: RecordCommitment,
    ) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::Idle {
            return Err(LifecycleError::InvalidPhase);
        }
        let next_version = self
            .state_version
            .checked_next()
            .ok_or(LifecycleError::CounterOverflow)?;
        let session = draft.binding().session();
        if draft.binding().protocol() != self.protocol_scope {
            return Err(LifecycleError::DraftBindingMismatch);
        }
        let lifecycle_context = self.authenticated_context.lifecycle_context();
        if self.authenticated_context.policy_digest() != self.protocol_scope.policy_digest()
            || lifecycle_context.protocol_id() != self.protocol_scope.protocol_id()
            || lifecycle_context.wire_version() != self.protocol_scope.wire_version()
            || lifecycle_context.session_id() != self.session_identity.session_id()
            || !lifecycle_context.contains_device_pair(
                self.session_identity.local_device_id(),
                self.session_identity.peer_device_id(),
            )
        {
            return Err(LifecycleError::AuthenticatedContextMismatch);
        }
        let context_operation_matches = matches!(
            (lifecycle_context, draft.binding().purpose()),
            (
                crate::context::LifecycleContextV1::Bootstrap(_),
                CryptoPurpose::Bootstrap | CryptoPurpose::MessageProtection
            ) | (
                crate::context::LifecycleContextV1::RootTransition(_),
                CryptoPurpose::RootTransition | CryptoPurpose::MessageProtection
            )
        );
        if !context_operation_matches {
            return Err(LifecycleError::ContextOperationMismatch);
        }
        if session.identity() != self.session_identity {
            return Err(LifecycleError::SessionIdentityMismatch);
        }
        if draft.binding().context() != self.authenticated_context {
            return Err(LifecycleError::AuthenticatedContextMismatch);
        }
        if session.prior_state_version() != self.state_version
            || session.reserved_state_version() != next_version
            || session.prior_state_digest() != self.state_digest
            || session.command_ordinal() != self.next_ordinal
            || session.fence_token() != self.fence_token
        {
            return Err(LifecycleError::DraftBindingMismatch);
        }
        let intent = PersistIntent {
            stage: PersistStage::Reservation,
            subject: PersistSubject::Reservation,
            transition_id: session.transition_id(),
            operation_id: draft.operation_id(),
            binding: draft.binding(),
            state_advance: StateAdvance::new(
                StateRevision::new(self.state_version, self.state_digest),
                StateRevision::new(next_version, session.reserved_state_digest()),
            ),
            record_commitment: reservation_record_commitment,
            fence_token: self.fence_token,
        };
        self.active = Some(ActiveOperation {
            command: draft.command(),
            result: None,
        });
        self.pending_persist = Some(intent);
        self.phase = Phase::AwaitingReservation;
        Ok(Effect::Persist(intent))
    }

    /// Resolve the direct outcome of the current aggregate repository write.
    pub fn repository_outcome(
        &mut self,
        outcome: &RepositoryOutcome,
    ) -> Result<Effect, LifecycleError> {
        if !matches!(
            self.phase,
            Phase::AwaitingReservation
                | Phase::AwaitingResultPin
                | Phase::AwaitingAnchorReservation
                | Phase::AwaitingFinalCommit
                | Phase::AwaitingReleaseAck
                | Phase::AwaitingClosure(_)
        ) {
            return Err(LifecycleError::InvalidPhase);
        }
        self.apply_repository_outcome(outcome, false)
    }

    /// Reconcile a repository write whose earlier outcome was unknown.
    pub fn reconcile_repository(
        &mut self,
        outcome: &RepositoryOutcome,
    ) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::CommitUnknown {
            return Err(LifecycleError::InvalidPhase);
        }
        self.apply_repository_outcome(outcome, true)
    }

    /// Expose an execution effect only after reservation is known durable.
    pub fn dispatch(&mut self) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::Reserved {
            return Err(if self.phase == Phase::AwaitingReservation {
                LifecycleError::EffectReservationRequired
            } else {
                LifecycleError::InvalidPhase
            });
        }
        let command = self.active_command()?;
        self.provider_dispatch_count = self
            .provider_dispatch_count
            .checked_add(1)
            .ok_or(LifecycleError::CounterOverflow)?;
        self.phase = Phase::Dispatched;
        Ok(Effect::Execute(command))
    }

    /// Fail closed when an authoritative lease observation advances beyond this writer.
    pub fn fence_lost(&mut self, observed_fence: FenceToken) -> Result<Effect, LifecycleError> {
        if observed_fence <= self.fence_token {
            return Err(LifecycleError::FenceNotAdvanced);
        }
        match self.phase {
            Phase::Idle
            | Phase::Committed
            | Phase::Cancelled
            | Phase::Superseded
            | Phase::AwaitingSuspension
            | Phase::SuspensionUnknown
            | Phase::Suspended(_) => return Err(LifecycleError::InvalidPhase),
            _ => {}
        }
        self.request_suspension_with_evidence(
            SuspensionReason::FenceLost,
            SuspensionEvidence::FenceLoss { observed_fence },
        )
    }

    /// Accept one provider outcome after dispatch.
    pub fn provider_completion(
        &mut self,
        completion: CryptoCompletion,
    ) -> Result<Effect, LifecycleError> {
        match self.phase {
            Phase::Committed => return Err(LifecycleError::AlreadyCompleted),
            Phase::Cancelled => return Err(LifecycleError::AlreadyCancelled),
            Phase::Superseded => return Err(LifecycleError::AlreadySuperseded),
            Phase::AwaitingClosure(_) => return Err(LifecycleError::Closing),
            Phase::AwaitingReservation | Phase::Reserved => {
                return self.request_suspension(SuspensionReason::ResultBeforeDispatch);
            }
            Phase::CommitUnknown
                if matches!(
                    self.pending_persist,
                    Some(PersistIntent {
                        stage: PersistStage::Reservation,
                        ..
                    })
                ) =>
            {
                return self.request_suspension(SuspensionReason::ResultBeforeDispatch);
            }
            Phase::ResultReceived
            | Phase::AwaitingResultPin
            | Phase::ResultPinned
            | Phase::AwaitingAnchorReservation
            | Phase::AnchorReserved
            | Phase::AwaitingAnchor
            | Phase::AnchorUnknown
            | Phase::AwaitingFinalCommit
            | Phase::CommitUnknown
            | Phase::CommittedPendingRelease
            | Phase::AwaitingReleaseAck => return self.classify_duplicate(completion),
            Phase::Dispatched => {}
            Phase::Idle
            | Phase::AwaitingSuspension
            | Phase::SuspensionUnknown
            | Phase::Suspended(_) => return Err(LifecycleError::InvalidPhase),
        }

        let command = self.active_command()?;
        if completion.operation_id() != command.operation_id()
            || completion.binding() != command.binding()
        {
            return self.request_suspension(SuspensionReason::ResultBindingMismatch);
        }

        match completion {
            CryptoCompletion::Succeeded(result) => {
                if result.result_kind() != command.expected_result_kind() {
                    return self.request_suspension(SuspensionReason::ResultShapeMismatch);
                }
                if let Some(active) = self.active.as_mut() {
                    active.result = Some(AcceptedResult::Volatile(result));
                }
                self.phase = Phase::ResultReceived;
                Ok(Effect::None)
            }
            CryptoCompletion::DefinitiveFailure { .. } => {
                self.request_suspension(SuspensionReason::ProviderDefinitiveFailure)
            }
            CryptoCompletion::OutcomeUnknown { .. } => self.recover_provider_unknown(command),
        }
    }

    /// Persist a service-created state transition for the validated provider result.
    pub fn pin_result(&mut self, plan: ResultPinPlan) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::ResultReceived {
            return Err(LifecycleError::InvalidPhase);
        }
        let command = self.active_command()?;
        let result = self
            .active
            .and_then(|active| active.result)
            .map(AcceptedResult::result)
            .ok_or(LifecycleError::InvalidPhase)?;
        let intent = self.make_persist_intent(
            PersistStage::ResultPin,
            PersistSubject::ResultPin {
                result_kind: result.result_kind(),
                result_commitment: result.result_commitment(),
            },
            command,
            plan.record_commitment,
            plan.next_state_digest,
        )?;
        self.pending_persist = Some(intent);
        self.phase = Phase::AwaitingResultPin;
        Ok(Effect::Persist(intent))
    }

    /// Persist the exact finalization plan before any external anchor effect.
    pub fn begin_finalize(
        &mut self,
        final_record_commitment: RecordCommitment,
        final_state_digest: StateDigest,
        anchor_plan: Option<AnchorPlan>,
    ) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::ResultPinned {
            return Err(LifecycleError::InvalidPhase);
        }
        let command = self.active_command()?;
        match command.binding().protocol().anchor_profile() {
            AnchorProfile::PerTransitionDigest => {
                let plan = anchor_plan.ok_or(LifecycleError::AnchorRequired)?;
                if plan.exact_prior == plan.exact_next {
                    return Err(LifecycleError::AnchorDidNotAdvance);
                }
                let anchor_intent = AnchorIntent::from_plan(
                    command.operation_id(),
                    command.binding(),
                    final_record_commitment,
                    final_state_digest,
                    plan,
                );
                let finalization = Finalization {
                    final_record_commitment,
                    final_state_digest,
                    anchor_intent: Some(anchor_intent),
                };
                let persist = self.make_persist_intent(
                    PersistStage::AnchorReservation,
                    PersistSubject::AnchorReservation(anchor_intent),
                    command,
                    plan.preparation_record_commitment,
                    plan.preparation_state_digest,
                )?;
                self.finalization = Some(finalization);
                self.pending_persist = Some(persist);
                self.phase = Phase::AwaitingAnchorReservation;
                Ok(Effect::Persist(persist))
            }
            AnchorProfile::None | AnchorProfile::EpochOnly => {
                if anchor_plan.is_some() {
                    return Err(LifecycleError::UnexpectedAnchor);
                }
                let finalization = Finalization {
                    final_record_commitment,
                    final_state_digest,
                    anchor_intent: None,
                };
                let persist = self.make_final_commit_intent(command, finalization)?;
                self.finalization = Some(finalization);
                self.pending_persist = Some(persist);
                self.phase = Phase::AwaitingFinalCommit;
                Ok(Effect::Persist(persist))
            }
        }
    }

    /// Expose an anchor effect only after the exact anchor plan is durable.
    pub fn advance_anchor(&mut self) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::AnchorReserved {
            return Err(LifecycleError::InvalidPhase);
        }
        let intent = self.expected_anchor()?;
        self.phase = Phase::AwaitingAnchor;
        Ok(Effect::AdvanceAnchor(intent))
    }

    /// Resolve or reconcile the exact per-transition anchor operation.
    pub fn anchor_outcome(&mut self, outcome: AnchorOutcome) -> Result<Effect, LifecycleError> {
        if !matches!(self.phase, Phase::AwaitingAnchor | Phase::AnchorUnknown) {
            return Err(LifecycleError::InvalidPhase);
        }
        let expected = self.expected_anchor()?;
        match outcome {
            AnchorOutcome::AppliedExact(actual) | AnchorOutcome::AlreadyAppliedExact(actual) => {
                if actual != expected {
                    return self.request_suspension(SuspensionReason::AnchorBindingMismatch);
                }
                self.install_final_commit()
            }
            AnchorOutcome::NotAppliedExactPrior(actual) => {
                if actual != expected {
                    return self.request_suspension(SuspensionReason::AnchorBindingMismatch);
                }
                self.phase = Phase::AwaitingAnchor;
                Ok(Effect::RetryAnchor(expected))
            }
            AnchorOutcome::Unknown => {
                self.phase = Phase::AnchorUnknown;
                Ok(Effect::QueryAnchor(expected))
            }
            AnchorOutcome::Ahead | AnchorOutcome::Conflict => {
                self.request_suspension(SuspensionReason::AnchorAheadOrConflict)
            }
            AnchorOutcome::Equivocation => {
                self.request_suspension(SuspensionReason::AnchorEquivocation)
            }
            AnchorOutcome::Unavailable => {
                self.request_suspension(SuspensionReason::AnchorUnavailable)
            }
            AnchorOutcome::Unauthenticated => {
                self.request_suspension(SuspensionReason::AnchorUnauthenticated)
            }
        }
    }

    /// Persist an acknowledgement for the exact idempotent release permission.
    pub fn acknowledge_release(
        &mut self,
        permit: ReleasePermit,
        acknowledgement_record_commitment: RecordCommitment,
        acknowledgement_state_digest: StateDigest,
    ) -> Result<Effect, LifecycleError> {
        if self.phase != Phase::CommittedPendingRelease {
            return Err(LifecycleError::InvalidPhase);
        }
        if self.release_permit != Some(permit) {
            return self.request_suspension(SuspensionReason::ReleaseBindingMismatch);
        }
        let command = self.active_command()?;
        let intent = self.make_persist_intent(
            PersistStage::ReleaseAck,
            PersistSubject::ReleaseAck(permit),
            command,
            acknowledgement_record_commitment,
            acknowledgement_state_digest,
        )?;
        self.pending_persist = Some(intent);
        self.phase = Phase::AwaitingReleaseAck;
        Ok(Effect::Persist(intent))
    }

    /// Atomically request a durable cancellation tombstone.
    pub fn cancel(
        &mut self,
        record_commitment: RecordCommitment,
        next_state_digest: StateDigest,
    ) -> Result<Effect, LifecycleError> {
        self.begin_closure(
            PersistStage::Cancellation,
            record_commitment,
            next_state_digest,
        )
    }

    /// Atomically request a durable supersession tombstone.
    pub fn supersede(
        &mut self,
        record_commitment: RecordCommitment,
        next_state_digest: StateDigest,
    ) -> Result<Effect, LifecycleError> {
        self.begin_closure(
            PersistStage::Supersession,
            record_commitment,
            next_state_digest,
        )
    }

    /// Resolve or query the append-only suspension tombstone.
    pub fn suspension_outcome(
        &mut self,
        outcome: &SuspensionOutcome,
    ) -> Result<Effect, LifecycleError> {
        if !matches!(
            self.phase,
            Phase::AwaitingSuspension | Phase::SuspensionUnknown
        ) {
            return Err(LifecycleError::InvalidPhase);
        }
        let expected = self
            .pending_suspension
            .ok_or(LifecycleError::InvalidPhase)?;
        match outcome.kind {
            SuspensionOutcomeKind::Applied => {
                let receipt = outcome.receipt.ok_or(LifecycleError::InvalidPhase)?;
                if receipt != expected.exact_receipt() {
                    self.phase = Phase::SuspensionUnknown;
                    return Ok(Effect::QuerySuspension(expected));
                }
                self.phase = Phase::Suspended(expected.reason());
                Ok(Effect::Quarantine(expected))
            }
            SuspensionOutcomeKind::NotApplied => {
                self.phase = Phase::AwaitingSuspension;
                Ok(Effect::RetrySuspension(expected))
            }
            SuspensionOutcomeKind::Unknown | SuspensionOutcomeKind::Conflict => {
                self.phase = Phase::SuspensionUnknown;
                Ok(Effect::QuerySuspension(expected))
            }
        }
    }

    /// Derive the next exact effect from a freshly reconstructed durable state.
    pub fn resume_from_durable(&mut self) -> Result<Effect, LifecycleError> {
        if !self.phase.is_snapshotable() || !self.snapshot_shape_is_valid() {
            return Err(LifecycleError::DurableSnapshotUnavailable);
        }
        if let Some(intent) = self.pending_persist {
            self.phase = Phase::CommitUnknown;
            return Ok(Effect::QueryRepository(intent));
        }
        if matches!(
            self.phase,
            Phase::AwaitingSuspension | Phase::SuspensionUnknown
        ) {
            let intent = self
                .pending_suspension
                .ok_or(LifecycleError::InvalidPhase)?;
            self.phase = Phase::SuspensionUnknown;
            return Ok(Effect::QuerySuspension(intent));
        }
        match self.phase {
            Phase::Reserved => {
                let command = self.active_command()?;
                self.recover_provider_unknown(command)
            }
            Phase::AnchorReserved => {
                let intent = self.expected_anchor()?;
                self.phase = Phase::AnchorUnknown;
                Ok(Effect::QueryAnchor(intent))
            }
            Phase::CommittedPendingRelease => Ok(Effect::Release(
                self.release_permit.ok_or(LifecycleError::InvalidPhase)?,
            )),
            Phase::Suspended(_) => Ok(Effect::Quarantine(
                self.pending_suspension
                    .ok_or(LifecycleError::InvalidPhase)?,
            )),
            Phase::Idle
            | Phase::ResultPinned
            | Phase::Committed
            | Phase::Cancelled
            | Phase::Superseded => Ok(Effect::None),
            _ => Err(LifecycleError::DurableSnapshotUnavailable),
        }
    }

    fn apply_repository_outcome(
        &mut self,
        outcome: &RepositoryOutcome,
        reconciling: bool,
    ) -> Result<Effect, LifecycleError> {
        let intent = self.pending_persist.ok_or(LifecycleError::InvalidPhase)?;
        match outcome.kind {
            RepositoryOutcomeKind::Applied => {
                let receipt = outcome.receipt.ok_or(LifecycleError::InvalidPhase)?;
                if receipt != intent.exact_receipt() {
                    return self.request_suspension(SuspensionReason::RepositoryReceiptMismatch);
                }
                let suspension = self
                    .post_reconcile_suspension
                    .map(|cause| self.make_suspension_intent(cause))
                    .transpose()?;
                let effect = self.apply_receipt(intent)?;
                if let Some(suspension) = suspension {
                    Ok(self.install_suspension(suspension))
                } else {
                    Ok(effect)
                }
            }
            RepositoryOutcomeKind::NotApplied => {
                if let Some(cause) = self.post_reconcile_suspension {
                    let suspension = self.make_suspension_intent(cause)?;
                    self.discard_unapplied_subject(intent);
                    Ok(self.install_suspension(suspension))
                } else if reconciling || intent.stage != PersistStage::Reservation {
                    self.phase = awaiting_phase(intent.stage);
                    Ok(Effect::Persist(intent))
                } else {
                    self.phase = Phase::Idle;
                    self.active = None;
                    self.pending_persist = None;
                    Ok(Effect::None)
                }
            }
            RepositoryOutcomeKind::Conflict => {
                let cause = match self.post_reconcile_suspension {
                    Some(cause) => cause,
                    None => SuspensionCause::new(
                        SuspensionReason::RepositoryConflict,
                        SuspensionEvidence::RepositoryConflict {
                            observed_fence: outcome
                                .observed_fence()
                                .ok_or(LifecycleError::InvalidPhase)?,
                        },
                    ),
                };
                let suspension = self.make_suspension_intent(cause)?;
                self.discard_unapplied_subject(intent);
                Ok(self.install_suspension(suspension))
            }
            RepositoryOutcomeKind::Unknown => {
                self.phase = Phase::CommitUnknown;
                Ok(Effect::QueryRepository(intent))
            }
        }
    }

    fn apply_receipt(&mut self, intent: PersistIntent) -> Result<Effect, LifecycleError> {
        if !intent.subject.matches_stage(intent.stage) {
            return Err(LifecycleError::InvalidPhase);
        }
        let application = match intent.stage {
            PersistStage::Reservation => ReceiptApplication::Reservation,
            PersistStage::ResultPin => {
                let (result_kind, result_commitment) = match intent.subject {
                    PersistSubject::ResultPin {
                        result_kind,
                        result_commitment,
                    } => (result_kind, result_commitment),
                    _ => return Err(LifecycleError::InvalidPhase),
                };
                if self.active.is_none() {
                    return Err(LifecycleError::InvalidPhase);
                }
                ReceiptApplication::ResultPin(CryptoResult::new(
                    intent.operation_id,
                    intent.binding,
                    result_kind,
                    result_commitment,
                ))
            }
            PersistStage::AnchorReservation => ReceiptApplication::AnchorReservation,
            PersistStage::FinalCommit => {
                let active = self.active.ok_or(LifecycleError::InvalidPhase)?;
                let finalization = self.finalization.ok_or(LifecycleError::InvalidPhase)?;
                let subject_anchor = match intent.subject {
                    PersistSubject::FinalCommit { anchor_intent } => anchor_intent,
                    _ => return Err(LifecycleError::InvalidPhase),
                };
                if subject_anchor != finalization.anchor_intent {
                    return Err(LifecycleError::InvalidPhase);
                }
                let assurance = match active.command.binding().protocol().anchor_profile() {
                    AnchorProfile::None | AnchorProfile::EpochOnly => {
                        AssuranceLevel::CommitOrderingOnly
                    }
                    AnchorProfile::PerTransitionDigest => AssuranceLevel::PerTransitionAnchored,
                };
                ReceiptApplication::FinalCommit(ReleasePermit {
                    operation_id: active.command.operation_id(),
                    binding: active.command.binding(),
                    final_record_commitment: finalization.final_record_commitment,
                    final_state_digest: finalization.final_state_digest,
                    assurance,
                })
            }
            PersistStage::ReleaseAck => {
                let acknowledged = match intent.subject {
                    PersistSubject::ReleaseAck(permit) => permit,
                    _ => return Err(LifecycleError::InvalidPhase),
                };
                if self.release_permit != Some(acknowledged) {
                    return Err(LifecycleError::InvalidPhase);
                }
                ReceiptApplication::ReleaseAck(
                    self.durable_release_ack_count
                        .checked_add(1)
                        .ok_or(LifecycleError::CounterOverflow)?,
                )
            }
            PersistStage::Cancellation => ReceiptApplication::Cancellation,
            PersistStage::Supersession => ReceiptApplication::Supersession,
        };

        if let ReceiptApplication::ResultPin(result) = application {
            let active = self.active.as_mut().ok_or(LifecycleError::InvalidPhase)?;
            active.result = Some(AcceptedResult::Pinned(result));
        }
        self.state_version = intent.state_advance.next.version;
        self.state_digest = intent.state_advance.next.digest;
        self.pending_persist = None;
        match application {
            ReceiptApplication::Reservation => {
                self.phase = Phase::Reserved;
                Ok(Effect::None)
            }
            ReceiptApplication::ResultPin(_) => {
                self.phase = Phase::ResultPinned;
                Ok(Effect::None)
            }
            ReceiptApplication::AnchorReservation => {
                self.phase = Phase::AnchorReserved;
                Ok(Effect::None)
            }
            ReceiptApplication::FinalCommit(permit) => {
                self.release_permit = Some(permit);
                self.phase = Phase::CommittedPendingRelease;
                Ok(Effect::Release(permit))
            }
            ReceiptApplication::ReleaseAck(count) => {
                self.durable_release_ack_count = count;
                self.phase = Phase::Committed;
                Ok(Effect::None)
            }
            ReceiptApplication::Cancellation => {
                self.phase = Phase::Cancelled;
                Ok(Effect::None)
            }
            ReceiptApplication::Supersession => {
                self.phase = Phase::Superseded;
                Ok(Effect::None)
            }
        }
    }

    fn classify_duplicate(
        &mut self,
        completion: CryptoCompletion,
    ) -> Result<Effect, LifecycleError> {
        let active = self.active.ok_or(LifecycleError::InvalidPhase)?;
        if completion.operation_id() != active.command.operation_id()
            || completion.binding() != active.command.binding()
        {
            return self.request_suspension(SuspensionReason::ResultBindingMismatch);
        }
        let accepted_result = active.result.map(AcceptedResult::result).or_else(|| {
            self.pending_persist
                .and_then(|intent| match intent.subject {
                    PersistSubject::ResultPin {
                        result_kind,
                        result_commitment,
                    } => Some(CryptoResult::new(
                        intent.operation_id,
                        intent.binding,
                        result_kind,
                        result_commitment,
                    )),
                    _ => None,
                })
        });
        match (accepted_result, completion) {
            (Some(first), CryptoCompletion::Succeeded(second)) if first == second => {
                Err(LifecycleError::DuplicateResult)
            }
            (Some(_), CryptoCompletion::Succeeded(_)) => {
                self.request_suspension(SuspensionReason::ConflictingProviderResult)
            }
            (
                Some(_),
                CryptoCompletion::DefinitiveFailure { .. }
                | CryptoCompletion::OutcomeUnknown { .. },
            ) => self.request_suspension(SuspensionReason::ProviderOutcomeContradiction),
            _ => Err(LifecycleError::DuplicateResult),
        }
    }

    fn recover_provider_unknown(
        &mut self,
        command: CryptoCommand,
    ) -> Result<Effect, LifecycleError> {
        match command.retry_contract() {
            RetryContract::RetryExactBytes => {
                self.provider_dispatch_count = self
                    .provider_dispatch_count
                    .checked_add(1)
                    .ok_or(LifecycleError::CounterOverflow)?;
                self.phase = Phase::Dispatched;
                Ok(Effect::RetryExact(command))
            }
            RetryContract::QueryExactStableHandle => {
                self.phase = Phase::Dispatched;
                Ok(Effect::QueryProvider(command))
            }
            RetryContract::SuspendOnUnknown => {
                self.request_suspension(SuspensionReason::IndeterminateProviderOperation)
            }
        }
    }

    fn begin_closure(
        &mut self,
        stage: PersistStage,
        record_commitment: RecordCommitment,
        next_state_digest: StateDigest,
    ) -> Result<Effect, LifecycleError> {
        match self.phase {
            Phase::Committed | Phase::CommittedPendingRelease | Phase::AwaitingReleaseAck => {
                return Err(LifecycleError::AlreadyCompleted);
            }
            Phase::Cancelled => return Err(LifecycleError::AlreadyCancelled),
            Phase::Superseded => return Err(LifecycleError::AlreadySuperseded),
            Phase::AwaitingClosure(_) => return Err(LifecycleError::Closing),
            Phase::Reserved | Phase::Dispatched | Phase::ResultReceived | Phase::ResultPinned => {}
            _ => return Err(LifecycleError::InvalidPhase),
        }
        let command = self.active_command()?;
        let subject = match stage {
            PersistStage::Cancellation => PersistSubject::Cancellation,
            PersistStage::Supersession => PersistSubject::Supersession,
            _ => return Err(LifecycleError::InvalidPhase),
        };
        let intent = self.make_persist_intent(
            stage,
            subject,
            command,
            record_commitment,
            next_state_digest,
        )?;
        self.pending_persist = Some(intent);
        self.phase = Phase::AwaitingClosure(stage);
        Ok(Effect::Persist(intent))
    }

    fn install_final_commit(&mut self) -> Result<Effect, LifecycleError> {
        let command = self.active_command()?;
        let finalization = self.finalization.ok_or(LifecycleError::InvalidPhase)?;
        let intent = self.make_final_commit_intent(command, finalization)?;
        self.pending_persist = Some(intent);
        self.phase = Phase::AwaitingFinalCommit;
        Ok(Effect::Persist(intent))
    }

    fn make_final_commit_intent(
        &self,
        command: CryptoCommand,
        finalization: Finalization,
    ) -> Result<PersistIntent, LifecycleError> {
        self.make_persist_intent(
            PersistStage::FinalCommit,
            PersistSubject::FinalCommit {
                anchor_intent: finalization.anchor_intent,
            },
            command,
            finalization.final_record_commitment,
            finalization.final_state_digest,
        )
    }

    fn make_persist_intent(
        &self,
        stage: PersistStage,
        subject: PersistSubject,
        command: CryptoCommand,
        record_commitment: RecordCommitment,
        next_state_digest: StateDigest,
    ) -> Result<PersistIntent, LifecycleError> {
        if !subject.matches_stage(stage) {
            return Err(LifecycleError::InvalidPhase);
        }
        let next_version = self
            .state_version
            .checked_next()
            .ok_or(LifecycleError::CounterOverflow)?;
        Ok(PersistIntent {
            stage,
            subject,
            transition_id: command.binding().session().transition_id(),
            operation_id: command.operation_id(),
            binding: command.binding(),
            state_advance: StateAdvance::new(
                StateRevision::new(self.state_version, self.state_digest),
                StateRevision::new(next_version, next_state_digest),
            ),
            record_commitment,
            fence_token: self.fence_token,
        })
    }

    fn expected_anchor(&self) -> Result<AnchorIntent, LifecycleError> {
        self.finalization
            .and_then(|finalization| finalization.anchor_intent)
            .ok_or(LifecycleError::AnchorRequired)
    }

    fn active_command(&self) -> Result<CryptoCommand, LifecycleError> {
        self.active
            .map(|active| active.command)
            .ok_or(LifecycleError::InvalidPhase)
    }

    fn discard_unapplied_subject(&mut self, intent: PersistIntent) {
        if intent.stage == PersistStage::ResultPin {
            if let Some(active) = self.active.as_mut() {
                active.result = None;
            }
        }
    }

    fn snapshot_shape_is_valid(&self) -> bool {
        if matches!(self.active, Some(active) if !self.binding_matches_authority(active.command.binding()))
            || matches!(self.pending_persist, Some(intent) if !self.binding_matches_authority(intent.binding()))
            || matches!(self.release_permit, Some(permit) if !self.binding_matches_authority(permit.binding()))
            || matches!(self.pending_suspension, Some(intent) if !self.binding_matches_authority(intent.binding()))
            || matches!(
                self.finalization,
                Some(Finalization {
                    anchor_intent: Some(intent),
                    ..
                }) if !self.binding_matches_authority(intent.binding())
            )
        {
            return false;
        }
        if matches!(
            self.pending_persist,
            Some(intent) if !intent.subject.matches_stage(intent.stage)
        ) || (self.post_reconcile_suspension.is_some() && self.pending_persist.is_none())
            || matches!(
                self.post_reconcile_suspension,
                Some(cause) if !cause.evidence.matches_reason(cause.reason)
            )
            || matches!(
                self.pending_suspension,
                Some(intent) if !intent.evidence.matches_reason(intent.reason)
            )
        {
            return false;
        }
        match self.phase {
            Phase::AwaitingReservation
            | Phase::AwaitingResultPin
            | Phase::AwaitingAnchorReservation
            | Phase::AwaitingFinalCommit
            | Phase::AwaitingReleaseAck
            | Phase::AwaitingClosure(_)
            | Phase::CommitUnknown => self.pending_persist.is_some(),
            Phase::AwaitingSuspension | Phase::SuspensionUnknown | Phase::Suspended(_) => {
                self.pending_suspension.is_some()
            }
            Phase::Idle
            | Phase::Reserved
            | Phase::ResultPinned
            | Phase::AnchorReserved
            | Phase::CommittedPendingRelease
            | Phase::Committed
            | Phase::Cancelled
            | Phase::Superseded => {
                self.pending_persist.is_none() && self.pending_suspension.is_none()
            }
            Phase::Dispatched
            | Phase::ResultReceived
            | Phase::AwaitingAnchor
            | Phase::AnchorUnknown => false,
        }
    }

    fn binding_matches_authority(&self, binding: OperationBinding) -> bool {
        if binding.protocol() != self.protocol_scope
            || binding.session().identity() != self.session_identity
        {
            return false;
        }
        binding.context() == self.authenticated_context
    }

    fn request_suspension(&mut self, reason: SuspensionReason) -> Result<Effect, LifecycleError> {
        self.request_suspension_with_evidence(reason, SuspensionEvidence::None)
    }

    fn request_suspension_with_evidence(
        &mut self,
        reason: SuspensionReason,
        evidence: SuspensionEvidence,
    ) -> Result<Effect, LifecycleError> {
        if !evidence.matches_reason(reason) {
            return Err(LifecycleError::InvalidPhase);
        }
        let cause = SuspensionCause::new(reason, evidence);
        if let Some(intent) = self.pending_persist {
            if self.post_reconcile_suspension.is_none() {
                self.post_reconcile_suspension = Some(cause);
            }
            self.phase = Phase::CommitUnknown;
            return Ok(Effect::QueryRepository(intent));
        }
        self.begin_suspension(cause)
    }

    fn begin_suspension(&mut self, cause: SuspensionCause) -> Result<Effect, LifecycleError> {
        let intent = self.make_suspension_intent(cause)?;
        Ok(self.install_suspension(intent))
    }

    fn make_suspension_intent(
        &self,
        cause: SuspensionCause,
    ) -> Result<SuspensionIntent, LifecycleError> {
        let command = self.active_command()?;
        Ok(SuspensionIntent {
            operation_id: command.operation_id(),
            binding: command.binding(),
            reason: cause.reason,
            record_commitment: command.binding().suspension_plan().record_commitment(),
            fence_token: self.fence_token,
            evidence: cause.evidence,
        })
    }

    fn install_suspension(&mut self, intent: SuspensionIntent) -> Effect {
        self.pending_persist = None;
        self.post_reconcile_suspension = None;
        self.pending_suspension = Some(intent);
        self.phase = Phase::AwaitingSuspension;
        Effect::PersistSuspension(intent)
    }
}

const fn awaiting_phase(stage: PersistStage) -> Phase {
    match stage {
        PersistStage::Reservation => Phase::AwaitingReservation,
        PersistStage::ResultPin => Phase::AwaitingResultPin,
        PersistStage::AnchorReservation => Phase::AwaitingAnchorReservation,
        PersistStage::FinalCommit => Phase::AwaitingFinalCommit,
        PersistStage::ReleaseAck => Phase::AwaitingReleaseAck,
        PersistStage::Cancellation | PersistStage::Supersession => Phase::AwaitingClosure(stage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{
        AuthenticationStage, BootstrapContext, CommonContext, ContextParty, ContextProtocol,
        ContextRoles, Direction, DirectoryContext, IdentityMode, LifecycleContextV1,
    };
    use crate::types::{
        CommandCommitment, CommandOrdinal, ModeledOperation, ProviderBinding, ProviderEpoch,
        ProviderProfileDigest, ResultCommitment, SessionScope, StateReservation, SuspensionPlan,
        TransitionScope,
    };
    use crate::{
        AccountId, ClassicalPrekeySelection, DeviceEpoch, DeviceId, DirectoryCheckpointDigest,
        IdentityCredentialDigest, PolicyDigest, PostQuantumPrekeySelection, PrekeyBundleEpoch,
        PrekeyId, PrekeyResponder, PrekeySelectionV1, ProtocolId, RosterDigest, RosterVersion,
        SessionId, SignedPrekeyManifestDigest, SuiteDigest, TranscriptDigest, WireVersion,
    };

    fn bytes<const N: usize>(tag: u8) -> [u8; N] {
        [tag; N]
    }

    fn test_authenticated_context() -> AuthenticatedContext {
        let canonical_prekey = PrekeySelectionV1::new(
            SuiteDigest::from_bytes(bytes(10)),
            PrekeyResponder::new(
                AccountId::from_bytes(bytes(25)),
                DeviceId::from_bytes(bytes(5)),
                DeviceEpoch::new(2),
                IdentityCredentialDigest::from_bytes(bytes(45)),
            ),
            PrekeyBundleEpoch::new(3),
            DirectoryCheckpointDigest::from_bytes(bytes(61)),
            SignedPrekeyManifestDigest::from_bytes(bytes(62)),
            ClassicalPrekeySelection::one_time(
                PrekeyId::from_bytes(bytes(64)),
                PrekeyId::from_bytes(bytes(65)),
            )
            .expect("valid classical selection"),
            PostQuantumPrekeySelection::one_time(
                PrekeyId::from_bytes(bytes(66)),
                PrekeyId::from_bytes(bytes(67)),
            )
            .expect("valid PQ selection"),
        )
        .expect("valid prekey record")
        .derive_with(|_| Ok::<_, ()>(bytes(63)))
        .expect("valid prekey digest");
        let lifecycle = LifecycleContextV1::Bootstrap(
            BootstrapContext::new(
                CommonContext::new(
                    ContextProtocol::new(
                        ProtocolId::from_bytes(bytes(1)),
                        WireVersion::new(1),
                        SuiteDigest::from_bytes(bytes(10)),
                        SessionId::from_bytes(bytes(3)),
                    ),
                    ContextRoles::new(
                        ContextParty::new(
                            AccountId::from_bytes(bytes(24)),
                            DeviceId::from_bytes(bytes(4)),
                            DeviceEpoch::new(1),
                            IdentityCredentialDigest::from_bytes(bytes(44)),
                        ),
                        ContextParty::new(
                            AccountId::from_bytes(bytes(25)),
                            DeviceId::from_bytes(bytes(5)),
                            DeviceEpoch::new(2),
                            IdentityCredentialDigest::from_bytes(bytes(45)),
                        ),
                        IdentityMode::Accountable,
                        Direction::InitiatorToResponder,
                        AuthenticationStage::PrekeyAuthenticated,
                    ),
                ),
                DirectoryContext::new(
                    RosterVersion::new(1),
                    RosterDigest::from_bytes(bytes(60)),
                    DirectoryCheckpointDigest::from_bytes(bytes(61)),
                ),
                canonical_prekey,
                TranscriptDigest::from_bytes(bytes(9)),
            )
            .expect("matching bootstrap prekey scope"),
        );
        lifecycle
            .derive_authenticated_context_with(PolicyDigest::from_bytes(bytes(2)), |_| {
                Ok::<_, ()>(bytes(9))
            })
            .expect("valid synthetic canonical context")
    }

    fn test_model_and_draft() -> (TransitionModel, OperationDraft) {
        let protocol = ProtocolScope::new(
            ProtocolId::from_bytes(bytes(1)),
            WireVersion::new(1),
            PolicyDigest::from_bytes(bytes(2)),
            AnchorProfile::None,
        );
        let identity = SessionIdentity::new(
            SessionId::from_bytes(bytes(3)),
            DeviceId::from_bytes(bytes(4)),
            DeviceId::from_bytes(bytes(5)),
        );
        let context = test_authenticated_context();
        let binding = OperationBinding::new(
            protocol,
            SessionScope::new(
                identity,
                StateReservation::new(
                    StateVersion::new(7),
                    StateVersion::new(8),
                    StateDigest::from_bytes(bytes(6)),
                    StateDigest::from_bytes(bytes(7)),
                ),
                TransitionScope::new(
                    TransitionId::from_bytes(bytes(8)),
                    CommandOrdinal::new(9),
                    FenceToken::new(11),
                ),
            ),
            context,
            ProviderBinding::new(
                ProviderProfileDigest::from_bytes(bytes(10)),
                ProviderEpoch::new(12),
            ),
            ModeledOperation::DeterministicBootstrap {
                command_commitment: CommandCommitment::from_bytes(bytes(11)),
            },
            SuspensionPlan::new(RecordCommitment::from_bytes(bytes(99))),
        );
        (
            TransitionModel::new(
                protocol,
                identity,
                context,
                StateVersion::new(7),
                StateDigest::from_bytes(bytes(6)),
                FenceToken::new(11),
                CommandOrdinal::new(9),
            ),
            OperationDraft::new(OperationId::from_bytes(bytes(12)), binding),
        )
    }

    fn awaiting_result_pin() -> (TransitionModel, PersistIntent) {
        let (mut model, draft) = test_model_and_draft();
        let reservation = model
            .prepare(draft, RecordCommitment::from_bytes(bytes(13)))
            .expect("reservation");
        let reservation_intent = reservation.persist_intent().expect("reservation intent");
        model
            .apply_receipt(reservation_intent)
            .expect("apply reservation");
        let command = model
            .dispatch()
            .expect("dispatch")
            .crypto_command()
            .expect("command");
        model
            .provider_completion(CryptoCompletion::Succeeded(CryptoResult::new(
                command.operation_id(),
                command.binding(),
                command.expected_result_kind(),
                ResultCommitment::from_bytes(bytes(20)),
            )))
            .expect("provider completion");
        let pin = model
            .pin_result(ResultPinPlan::new(
                RecordCommitment::from_bytes(bytes(21)),
                StateDigest::from_bytes(bytes(22)),
            ))
            .expect("result pin");
        (model, pin.persist_intent().expect("result-pin intent"))
    }

    #[test]
    fn receipt_preflight_failures_leave_the_entire_model_unchanged() {
        let (mut missing_active, result_pin) = awaiting_result_pin();
        missing_active.active = None;
        let before = missing_active.clone();
        assert_eq!(
            missing_active.apply_receipt(result_pin),
            Err(LifecycleError::InvalidPhase)
        );
        assert_eq!(missing_active, before);

        let (mut missing_finalization, result_pin) = awaiting_result_pin();
        missing_finalization
            .apply_receipt(result_pin)
            .expect("apply result pin");
        let final_commit = missing_finalization
            .begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                None,
            )
            .expect("final commit")
            .persist_intent()
            .expect("final-commit intent");
        missing_finalization.finalization = None;
        let before = missing_finalization.clone();
        assert_eq!(
            missing_finalization.apply_receipt(final_commit),
            Err(LifecycleError::InvalidPhase)
        );
        assert_eq!(missing_finalization, before);

        let (mut overflowing_ack, result_pin) = awaiting_result_pin();
        overflowing_ack
            .apply_receipt(result_pin)
            .expect("apply result pin");
        let final_commit = overflowing_ack
            .begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                None,
            )
            .expect("final commit")
            .persist_intent()
            .expect("final-commit intent");
        let release = overflowing_ack
            .apply_receipt(final_commit)
            .expect("apply final commit")
            .release_permit()
            .expect("release permit");
        let release_ack = overflowing_ack
            .acknowledge_release(
                release,
                RecordCommitment::from_bytes(bytes(50)),
                StateDigest::from_bytes(bytes(51)),
            )
            .expect("release ack")
            .persist_intent()
            .expect("release-ack intent");
        overflowing_ack.durable_release_ack_count = u8::MAX;
        let before = overflowing_ack.clone();
        assert_eq!(
            overflowing_ack.apply_receipt(release_ack),
            Err(LifecycleError::CounterOverflow)
        );
        assert_eq!(overflowing_ack, before);
    }
}
