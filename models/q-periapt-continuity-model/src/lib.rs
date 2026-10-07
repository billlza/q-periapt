#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Non-normative executable lifecycle model for Q-Periapt Continuity research.
//!
//! The crate models ordering, binding, reconciliation, and release permission with
//! public commitments only. It intentionally has no production codec, cryptography,
//! secret material, plaintext, storage adapter, or platform effect.

mod codec;
mod commitments;
mod context;
mod model;
mod prekey;
mod types;

pub use commitments::{
    AccountId, ContextDigest, DeviceEpoch, DeviceId, DirectoryCheckpointDigest,
    IdentityCredentialDigest, PolicyDigest, ProtocolId, RatchetEpoch, RosterDigest, RosterVersion,
    SessionId, SuiteDigest, TranscriptDigest, WireVersion,
};
pub use context::{
    AuthenticatedContext, AuthenticationStage, BootstrapContext, CommonContext, ContextDigestError,
    ContextEncodingError, ContextParty, ContextProtocol, ContextRoles, Direction, DirectoryContext,
    IdentityMode, LifecycleContextV1, RootEpochs, RootTransitionContext, RootTransitionKind,
    BOOTSTRAP_BODY_LEN, BOOTSTRAP_DIGEST_PREIMAGE_LEN, BOOTSTRAP_POLICY_BOUND_KCTX_LEN,
    CONTEXT_DIGEST_DOMAIN, LIFECYCLE_CONTEXT_DOMAIN, LIFECYCLE_CONTEXT_SCHEMA_VERSION,
    POLICY_CONTEXT_DOMAIN, ROOT_TRANSITION_BODY_LEN, ROOT_TRANSITION_DIGEST_PREIMAGE_LEN,
    ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN,
};

pub use prekey::{
    CanonicalPrekeySelection, ClassicalPrekeyMode, ClassicalPrekeySelection, PostQuantumPrekeyMode,
    PostQuantumPrekeySelection, PrekeyBundleEpoch, PrekeyId, PrekeyLeg, PrekeyQuality,
    PrekeyResponder, PrekeySelectionCodecError, PrekeySelectionDigest, PrekeySelectionDigestError,
    PrekeySelectionError, PrekeySelectionField, PrekeySelectionV1, SignedPrekeyManifestDigest,
    PREKEY_SELECTION_DIGEST_DOMAIN, PREKEY_SELECTION_DIGEST_PREIMAGE_LEN, PREKEY_SELECTION_DOMAIN,
    PREKEY_SELECTION_ENCODED_LEN, PREKEY_SELECTION_SCHEMA_VERSION,
};

pub use model::{
    AnchorIntent, AnchorOutcome, AnchorPlan, AssuranceLevel, CommitIdentity, CommitReceipt,
    DurableSnapshot, Effect, LifecycleError, PersistIntent, PersistStage, PersistSubject, PhaseTag,
    ReleasePermit, RepositoryOutcome, ResultPinPlan, StateAdvance, StateRevision,
    SuspensionEvidence, SuspensionIntent, SuspensionOutcome, SuspensionReason, SuspensionReceipt,
    TransitionModel, DURABLE_SNAPSHOT_SCHEMA_VERSION,
};
pub use types::{
    AnchorId, AnchorProfile, AnchorValue, CommandCommitment, CommandKind, CommandOrdinal,
    CryptoCommand, CryptoCompletion, CryptoPurpose, CryptoResult, FenceToken, ModeledOperation,
    OperationBinding, OperationDraft, OperationId, ProtocolScope, ProviderBinding, ProviderEpoch,
    ProviderProfileDigest, RecordCommitment, ResultCommitment, ResultKind, RetryContract,
    SessionIdentity, SessionScope, StateDigest, StateReservation, StateVersion, SuspensionPlan,
    TransitionId, TransitionScope,
};
