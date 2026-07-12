//! Closed identifiers and effect envelopes used by the lifecycle model.

use crate::commitments::{DeviceId, PolicyDigest, ProtocolId, SessionId, WireVersion};
use crate::context::AuthenticatedContext;

macro_rules! fixed_bytes_type {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Construct the value from its exact fixed-width representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact fixed-width representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

macro_rules! integer_type {
    ($name:ident, $raw:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($raw);

        impl $name {
            /// Construct a typed integer.
            #[must_use]
            pub const fn new(value: $raw) -> Self {
                Self(value)
            }

            /// Return the underlying integer.
            #[must_use]
            pub const fn get(self) -> $raw {
                self.0
            }
        }
    };
}

fixed_bytes_type!(TransitionId, 32, "A unique durable transition identifier.");
fixed_bytes_type!(
    OperationId,
    32,
    "An operation correlation identifier, never an authorization token."
);
fixed_bytes_type!(
    StateDigest,
    32,
    "A commitment to an exact modeled aggregate state."
);
fixed_bytes_type!(
    ProviderProfileDigest,
    32,
    "A commitment to the provider and algorithm profile."
);
fixed_bytes_type!(
    CommandCommitment,
    32,
    "A commitment to the complete provider command intent."
);
fixed_bytes_type!(
    RecordCommitment,
    32,
    "A commitment to exact persisted record bytes."
);
fixed_bytes_type!(
    ResultCommitment,
    32,
    "A commitment to one complete provider result."
);
fixed_bytes_type!(
    AnchorId,
    16,
    "An identifier for an authenticated external anchor."
);
fixed_bytes_type!(AnchorValue, 32, "An authenticated external anchor value.");

integer_type!(StateVersion, u64, "A monotonic aggregate-state version.");
integer_type!(
    CommandOrdinal,
    u32,
    "The command ordinal within one transition."
);
integer_type!(
    FenceToken,
    u64,
    "A monotonically increasing single-writer fencing token."
);
integer_type!(
    ProviderEpoch,
    u64,
    "A provider-instance epoch that changes across incompatible restarts."
);

impl StateVersion {
    /// Return the next version, or `None` on overflow.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl CommandOrdinal {
    /// Return the next ordinal, or `None` on overflow.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// External rollback-anchor requirement fixed by the resolved protocol policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorProfile {
    /// No external anchor is required; only commit ordering may be claimed.
    None = 1,
    /// An epoch-level anchor is required, but evidence is outside this model.
    EpochOnly = 2,
    /// Every transition must bind and reconcile an authenticated anchor advance.
    PerTransitionDigest = 3,
}

/// Closed purpose namespace for the non-normative effect model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CryptoPurpose {
    /// Bootstrap identity or key-establishment work.
    Bootstrap = 1,
    /// A root or sparse-PQ transition.
    RootTransition = 2,
    /// Ordinary message protection.
    MessageProtection = 3,
    /// Reserved for a future role/profile-bound confirmation operation.
    /// No current `ModeledOperation` produces this purpose.
    Confirmation = 4,
}

/// Closed provider-result shape expected by a modeled operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResultKind {
    /// Opaque output bytes whose meaning is fixed by the operation variant.
    OpaqueOutput = 1,
    /// A stable provider handle that can be queried after restart.
    StableHandle = 2,
    /// A closed verification decision.
    VerificationDecision = 3,
}

/// Abstract command category used to derive retry behavior in the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommandKind {
    /// Exact bytes and reserved entropy make re-execution deterministic.
    Deterministic = 1,
    /// A provider exposes an exact-operation stable handle that must be queried.
    StableHandle = 2,
    /// The external effect cannot be safely repeated after an uncertain outcome.
    NonRepeatable = 3,
}

impl CommandKind {
    /// Return the retry contract fixed by this command kind.
    #[must_use]
    pub const fn retry_contract(self) -> RetryContract {
        match self {
            Self::Deterministic => RetryContract::RetryExactBytes,
            Self::StableHandle => RetryContract::QueryExactStableHandle,
            Self::NonRepeatable => RetryContract::SuspendOnUnknown,
        }
    }
}

/// Closed operation variants used by the executable model.
///
/// A caller selects a protocol operation, not an independent retry boolean. Each
/// variant fixes its purpose, execution semantics, and expected result shape.
/// The current set contains no confirmation operation and cannot advance an
/// [`AuthenticatedContext`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeledOperation {
    /// Deterministic bootstrap derived from an exact sealed entropy reservation.
    DeterministicBootstrap {
        /// Commitment to the complete command intent.
        command_commitment: CommandCommitment,
    },
    /// Root transition represented by one exact provider stable handle.
    StableHandleRootTransition {
        /// Commitment to the complete command intent and stable handle.
        command_commitment: CommandCommitment,
    },
    /// Non-repeatable message-protection operation.
    NonRepeatableMessageProtection {
        /// Commitment to the complete command intent.
        command_commitment: CommandCommitment,
    },
}

impl ModeledOperation {
    /// Return the operation purpose fixed by this variant.
    #[must_use]
    pub const fn purpose(self) -> CryptoPurpose {
        match self {
            Self::DeterministicBootstrap { .. } => CryptoPurpose::Bootstrap,
            Self::StableHandleRootTransition { .. } => CryptoPurpose::RootTransition,
            Self::NonRepeatableMessageProtection { .. } => CryptoPurpose::MessageProtection,
        }
    }

    /// Return the execution semantics fixed by this variant.
    #[must_use]
    pub const fn command_kind(self) -> CommandKind {
        match self {
            Self::DeterministicBootstrap { .. } => CommandKind::Deterministic,
            Self::StableHandleRootTransition { .. } => CommandKind::StableHandle,
            Self::NonRepeatableMessageProtection { .. } => CommandKind::NonRepeatable,
        }
    }

    /// Return the exact result shape fixed by this variant.
    #[must_use]
    pub const fn expected_result_kind(self) -> ResultKind {
        match self {
            Self::DeterministicBootstrap { .. } => ResultKind::OpaqueOutput,
            Self::StableHandleRootTransition { .. } => ResultKind::StableHandle,
            Self::NonRepeatableMessageProtection { .. } => ResultKind::VerificationDecision,
        }
    }

    /// Return the complete command commitment carried by this variant.
    #[must_use]
    pub const fn command_commitment(self) -> CommandCommitment {
        match self {
            Self::DeterministicBootstrap { command_commitment }
            | Self::StableHandleRootTransition { command_commitment }
            | Self::NonRepeatableMessageProtection { command_commitment } => command_commitment,
        }
    }
}

/// Fail-closed recovery behavior derived from a command kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryContract {
    /// Reissue the same command, operation identifier, and reserved entropy.
    RetryExactBytes,
    /// Query the same provider epoch and stable handle; do not create a new operation.
    QueryExactStableHandle,
    /// Suspend when the provider outcome is uncertain.
    SuspendOnUnknown,
}

/// Protocol-wide fields committed by every modeled operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolScope {
    protocol_id: ProtocolId,
    wire_version: WireVersion,
    policy_digest: PolicyDigest,
    anchor_profile: AnchorProfile,
}

impl ProtocolScope {
    /// Construct a closed protocol scope.
    #[must_use]
    pub const fn new(
        protocol_id: ProtocolId,
        wire_version: WireVersion,
        policy_digest: PolicyDigest,
        anchor_profile: AnchorProfile,
    ) -> Self {
        Self {
            protocol_id,
            wire_version,
            policy_digest,
            anchor_profile,
        }
    }

    /// Return the protocol identifier.
    #[must_use]
    pub const fn protocol_id(self) -> ProtocolId {
        self.protocol_id
    }

    /// Return the wire version.
    #[must_use]
    pub const fn wire_version(self) -> WireVersion {
        self.wire_version
    }

    /// Return the exact policy digest.
    #[must_use]
    pub const fn policy_digest(self) -> PolicyDigest {
        self.policy_digest
    }

    /// Return the anchor requirement fixed by the resolved policy.
    #[must_use]
    pub const fn anchor_profile(self) -> AnchorProfile {
        self.anchor_profile
    }
}

/// Session and repository fields committed by every modeled operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionScope {
    session_id: SessionId,
    local_device_id: DeviceId,
    peer_device_id: DeviceId,
    prior_state_version: StateVersion,
    reserved_state_version: StateVersion,
    prior_state_digest: StateDigest,
    reserved_state_digest: StateDigest,
    transition_id: TransitionId,
    command_ordinal: CommandOrdinal,
    fence_token: FenceToken,
}

impl SessionScope {
    /// Construct an exact per-transition session scope.
    #[must_use]
    pub const fn new(
        identity: SessionIdentity,
        state: StateReservation,
        operation: TransitionScope,
    ) -> Self {
        Self {
            session_id: identity.session_id,
            local_device_id: identity.local_device_id,
            peer_device_id: identity.peer_device_id,
            prior_state_version: state.prior_state_version,
            reserved_state_version: state.reserved_state_version,
            prior_state_digest: state.prior_state_digest,
            reserved_state_digest: state.reserved_state_digest,
            transition_id: operation.transition_id,
            command_ordinal: operation.command_ordinal,
            fence_token: operation.fence_token,
        }
    }

    /// Return the session identifier.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Return the local device identifier.
    #[must_use]
    pub const fn local_device_id(self) -> DeviceId {
        self.local_device_id
    }

    /// Return the peer device identifier.
    #[must_use]
    pub const fn peer_device_id(self) -> DeviceId {
        self.peer_device_id
    }

    /// Return the version on which the operation was prepared.
    #[must_use]
    pub const fn prior_state_version(self) -> StateVersion {
        self.prior_state_version
    }

    /// Return the version installed by the durable effect reservation.
    #[must_use]
    pub const fn reserved_state_version(self) -> StateVersion {
        self.reserved_state_version
    }

    /// Return the prior state digest.
    #[must_use]
    pub const fn prior_state_digest(self) -> StateDigest {
        self.prior_state_digest
    }

    /// Return the reserved-state digest.
    #[must_use]
    pub const fn reserved_state_digest(self) -> StateDigest {
        self.reserved_state_digest
    }

    /// Return the transition identifier.
    #[must_use]
    pub const fn transition_id(self) -> TransitionId {
        self.transition_id
    }

    /// Return the command ordinal.
    #[must_use]
    pub const fn command_ordinal(self) -> CommandOrdinal {
        self.command_ordinal
    }

    /// Return the writer fence.
    #[must_use]
    pub const fn fence_token(self) -> FenceToken {
        self.fence_token
    }

    /// Return the stable pairwise identity bound by this transition.
    #[must_use]
    pub const fn identity(self) -> SessionIdentity {
        SessionIdentity::new(self.session_id, self.local_device_id, self.peer_device_id)
    }
}

/// Stable session/device identity fields for a modeled transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    session_id: SessionId,
    local_device_id: DeviceId,
    peer_device_id: DeviceId,
}

impl SessionIdentity {
    /// Construct a pairwise device identity scope.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        local_device_id: DeviceId,
        peer_device_id: DeviceId,
    ) -> Self {
        Self {
            session_id,
            local_device_id,
            peer_device_id,
        }
    }

    /// Return the pairwise session identifier.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Return the local device identifier.
    #[must_use]
    pub const fn local_device_id(self) -> DeviceId {
        self.local_device_id
    }

    /// Return the peer device identifier.
    #[must_use]
    pub const fn peer_device_id(self) -> DeviceId {
        self.peer_device_id
    }
}

/// Prior and reserved state commitments for a modeled transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateReservation {
    prior_state_version: StateVersion,
    reserved_state_version: StateVersion,
    prior_state_digest: StateDigest,
    reserved_state_digest: StateDigest,
}

impl StateReservation {
    /// Construct exact prior and reserved state commitments.
    #[must_use]
    pub const fn new(
        prior_state_version: StateVersion,
        reserved_state_version: StateVersion,
        prior_state_digest: StateDigest,
        reserved_state_digest: StateDigest,
    ) -> Self {
        Self {
            prior_state_version,
            reserved_state_version,
            prior_state_digest,
            reserved_state_digest,
        }
    }
}

/// Transition-local ordering and fencing fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionScope {
    transition_id: TransitionId,
    command_ordinal: CommandOrdinal,
    fence_token: FenceToken,
}

impl TransitionScope {
    /// Construct transition-local ordering fields.
    #[must_use]
    pub const fn new(
        transition_id: TransitionId,
        command_ordinal: CommandOrdinal,
        fence_token: FenceToken,
    ) -> Self {
        Self {
            transition_id,
            command_ordinal,
            fence_token,
        }
    }
}

/// Caller-selected provider profile and instance epoch committed by an operation.
///
/// Full echo equality prevents an in-flight binding swap. This value is not a
/// trusted policy authorization, downgrade proof, provider identity credential,
/// or epoch attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderBinding {
    profile_digest: ProviderProfileDigest,
    instance_epoch: ProviderEpoch,
}

/// Pre-bound append-only record slot used when an operation must durably suspend.
///
/// The final suspension intent separately binds the runtime reason and evidence.
/// Canonical byte derivation for that complete record remains an adapter concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionPlan {
    record_commitment: RecordCommitment,
}

impl SuspensionPlan {
    /// Construct the suspension-record slot commitment bound before execution.
    #[must_use]
    pub const fn new(record_commitment: RecordCommitment) -> Self {
        Self { record_commitment }
    }

    /// Return the pre-bound suspension-record slot commitment.
    #[must_use]
    pub const fn record_commitment(self) -> RecordCommitment {
        self.record_commitment
    }
}

impl ProviderBinding {
    /// Construct a provider binding.
    #[must_use]
    pub const fn new(profile_digest: ProviderProfileDigest, instance_epoch: ProviderEpoch) -> Self {
        Self {
            profile_digest,
            instance_epoch,
        }
    }

    /// Return the provider profile digest.
    #[must_use]
    pub const fn profile_digest(self) -> ProviderProfileDigest {
        self.profile_digest
    }

    /// Return the provider instance epoch.
    #[must_use]
    pub const fn instance_epoch(self) -> ProviderEpoch {
        self.instance_epoch
    }
}

/// Complete structured binding echoed by a provider completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBinding {
    protocol: ProtocolScope,
    session: SessionScope,
    context: AuthenticatedContext,
    provider: ProviderBinding,
    operation: ModeledOperation,
    suspension_plan: SuspensionPlan,
}

impl OperationBinding {
    /// Construct the complete operation binding.
    #[must_use]
    pub const fn new(
        protocol: ProtocolScope,
        session: SessionScope,
        context: AuthenticatedContext,
        provider: ProviderBinding,
        operation: ModeledOperation,
        suspension_plan: SuspensionPlan,
    ) -> Self {
        Self {
            protocol,
            session,
            context,
            provider,
            operation,
            suspension_plan,
        }
    }

    /// Return the protocol scope.
    #[must_use]
    pub const fn protocol(self) -> ProtocolScope {
        self.protocol
    }

    /// Return the session scope.
    #[must_use]
    pub const fn session(self) -> SessionScope {
        self.session
    }

    /// Return the authenticated context.
    #[must_use]
    pub const fn context(self) -> AuthenticatedContext {
        self.context
    }

    /// Return the provider binding.
    #[must_use]
    pub const fn provider(self) -> ProviderBinding {
        self.provider
    }

    /// Return the command purpose.
    #[must_use]
    pub const fn purpose(self) -> CryptoPurpose {
        self.operation.purpose()
    }

    /// Return the abstract command kind.
    #[must_use]
    pub const fn command_kind(self) -> CommandKind {
        self.operation.command_kind()
    }

    /// Return the exact expected result shape.
    #[must_use]
    pub const fn expected_result_kind(self) -> ResultKind {
        self.operation.expected_result_kind()
    }

    /// Return the complete command commitment.
    #[must_use]
    pub const fn command_commitment(self) -> CommandCommitment {
        self.operation.command_commitment()
    }

    /// Return the closed modeled operation.
    #[must_use]
    pub const fn operation(self) -> ModeledOperation {
        self.operation
    }

    /// Return the append-only suspension plan fixed before execution.
    #[must_use]
    pub const fn suspension_plan(self) -> SuspensionPlan {
        self.suspension_plan
    }
}

/// Opaque modeled provider command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoCommand {
    operation_id: OperationId,
    binding: OperationBinding,
}

impl CryptoCommand {
    pub(crate) const fn new(operation_id: OperationId, binding: OperationBinding) -> Self {
        Self {
            operation_id,
            binding,
        }
    }

    /// Return the operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete structured binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the retry contract derived from the command kind.
    #[must_use]
    pub const fn retry_contract(self) -> RetryContract {
        self.binding.command_kind().retry_contract()
    }

    /// Return the exact result shape fixed by the operation variant.
    #[must_use]
    pub const fn expected_result_kind(self) -> ResultKind {
        self.binding.expected_result_kind()
    }
}

/// Draft for one effect reservation. It exposes no executable command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDraft {
    operation_id: OperationId,
    binding: OperationBinding,
}

impl OperationDraft {
    /// Construct an operation draft for reservation.
    #[must_use]
    pub const fn new(operation_id: OperationId, binding: OperationBinding) -> Self {
        Self {
            operation_id,
            binding,
        }
    }

    pub(crate) const fn command(self) -> CryptoCommand {
        CryptoCommand::new(self.operation_id, self.binding)
    }

    /// Return the operation identifier without exposing an execution permission.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete proposed binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }
}

/// Complete successful provider result represented only by public commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoResult {
    operation_id: OperationId,
    binding: OperationBinding,
    result_kind: ResultKind,
    result_commitment: ResultCommitment,
}

impl CryptoResult {
    /// Construct a complete modeled result envelope.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        binding: OperationBinding,
        result_kind: ResultKind,
        result_commitment: ResultCommitment,
    ) -> Self {
        Self {
            operation_id,
            binding,
            result_kind,
            result_commitment,
        }
    }

    /// Return the operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the complete echoed binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        self.binding
    }

    /// Return the closed result shape.
    #[must_use]
    pub const fn result_kind(self) -> ResultKind {
        self.result_kind
    }

    /// Return the result commitment.
    #[must_use]
    pub const fn result_commitment(self) -> ResultCommitment {
        self.result_commitment
    }
}

/// Authoritative terminal provider completion with no arbitrary string or secret payload.
///
/// An adapter emits one linearizable terminal outcome for an operation. A later
/// different terminal report for an already accepted success is an integrity
/// contradiction, not a timeout notification or retry hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoCompletion {
    /// The provider returned one complete result envelope.
    Succeeded(CryptoResult),
    /// The provider proves the operation failed definitively.
    DefinitiveFailure {
        /// Operation identifier echoed by the provider.
        operation_id: OperationId,
        /// Complete structured binding echoed by the provider.
        binding: OperationBinding,
    },
    /// The service cannot determine whether the external operation ran.
    OutcomeUnknown {
        /// Operation identifier echoed by the provider.
        operation_id: OperationId,
        /// Complete structured binding echoed by the provider.
        binding: OperationBinding,
    },
}

impl CryptoCompletion {
    /// Return the echoed operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        match self {
            Self::Succeeded(result) => result.operation_id,
            Self::DefinitiveFailure { operation_id, .. }
            | Self::OutcomeUnknown { operation_id, .. } => operation_id,
        }
    }

    /// Return the echoed complete binding.
    #[must_use]
    pub const fn binding(self) -> OperationBinding {
        match self {
            Self::Succeeded(result) => result.binding,
            Self::DefinitiveFailure { binding, .. } | Self::OutcomeUnknown { binding, .. } => {
                binding
            }
        }
    }
}
