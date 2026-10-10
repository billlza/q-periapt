// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
//! Candidate accountable identity, prekey selection and confirmed bootstrap.
//!
//! This isolated, unpublished component uses actual ML-DSA-65 and P-256 signatures.
//! The volatile handshake is not a ratchet or permission to consume prekeys.
//! Account enrollment must independently pin the intended account and roster head.
//! No production crate, C ABI, or language binding depends on this candidate.

mod account_authority;
mod anchor;
mod bootstrap;
mod bootstrap_bundle;
mod cancellation;
mod codec;
mod connect;
#[cfg(feature = "connection-tls")]
pub mod connection_transport;
pub mod contract;
#[cfg(feature = "control-tls")]
pub mod control_transport;
mod crypto;
pub use account_authority::{
    AccountAuthorityAccess, AccountAuthorityCheckpoint, AccountAuthorityIdentity,
    AccountAuthorityLease, AccountAuthorityReplacementState, AccountAuthorityStore,
    ApplicationAccountId,
};
mod durable;
mod enrollment;
mod identity;
mod installation;
mod manifest;
mod merkle;
#[cfg(any(feature = "control-tls", feature = "connection-tls"))]
mod native_transport;
mod selection;
mod session_archives;
mod session_policy;
#[cfg(feature = "anchor-tls")]
pub use anchor::tls as anchor_tls;
pub use cancellation::Cancellation;
pub use durable::retired_report as retired_device;
pub use enrollment::{
    AccountRootEnrollmentRecovery, AccountRootEnrollmentState, CredentialRenewalRequest,
    CredentialRenewalStatus, DeviceEnrollment, EnrolledDevice, EnrollmentIntent, EnrollmentPaths,
    EnrollmentStatus, PolicyRenewalAbandonment, PolicyRenewalRequest, PolicyRenewalStatus,
    RetiredDeviceEnrollment, RosterRefreshOutcome, RosterRefreshResolution,
    SigningFileErasureState, VerifiedEnrollmentRequest, WitnessedPolicyRenewalDisposition,
    WitnessedPolicyRenewalProgress, WitnessedRosterRefreshDisposition,
    WitnessedRosterRefreshProgress,
};
pub use installation::{
    BootstrapPeer, DeviceInstallation, DeviceService, InstallationAdmission, InstallationPaths,
    InstallationPreparation, InstallationRecovery, InstallationStatus, InstalledAccountRecovery,
    InstalledSessionRecovery, ReopenedPeer, ReopenedSession, RetiredInstallationRecovery,
};
pub use session_archives::SessionArchiveStore;

// Retained installation metadata shared by cleanup admission layers. It is not
// an operational capability and cannot be supplied by a public caller.
pub(crate) struct RetainedInstallationAuthority {
    owner: [u8; 32],
    policy: [u8; 32],
    witness: Option<[u8; 32]>,
}
impl RetainedInstallationAuthority {
    fn active_installation(
        device: &VerifiedDevice,
        policy: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Self {
        let policy = policy.as_ref();
        Self {
            owner: bootstrap::storage_owner(device),
            policy: policy.checkpoint().digest(),
            witness: policy.anchor_requirement().binding(),
        }
    }
    fn check(
        &self,
        owner: [u8; 32],
        required: Option<([u8; 32], [u8; 32])>,
    ) -> Result<(), DurableError> {
        if owner != self.owner {
            return Err(DurableError::Conflict);
        }
        match (required, self.witness) {
            (None, None) => Ok(()),
            (Some((policy, witness)), Some(expected))
                if policy == self.policy && witness == expected =>
            {
                Ok(())
            }
            _ => Err(DurableError::Conflict),
        }
    }
}
#[cfg(test)]
mod tests;

pub use anchor::{
    AnchorAccountFreezeId, AnchorAccountFreezeRequest, AnchorAccountReplacementId,
    AnchorAccountReplacementPlan, AnchorAccountReplacementProposal, AnchorAccountReplacementState,
    AnchorClient, AnchorClientError, AnchorClosedAccountPreparation,
    AnchorClosedAccountReplacement, AnchorCredentialCancellationState,
    AnchorCredentialRenewalCancellation, AnchorCredentialRenewalProposal,
    AnchorCredentialRenewalState, AnchorDeviceReplacementProposal, AnchorDeviceReplacementState,
    AnchorError, AnchorFrozenAccount, AnchorGenesis, AnchorHead, AnchorIdentity, AnchorOperation,
    AnchorOutcome, AnchorPin, AnchorPolicyRenewalProposal, AnchorPolicyRenewalState, AnchorReply,
    AnchorRequest, AnchorRetiredAccount, AnchorRetiredAccountSubject, AnchorRetiredCleanup,
    AnchorRetiredCleanupProposal, AnchorRetiredCleanupState, AnchorRetiredReport,
    AnchorRetiredReportAcknowledgement, AnchorRetiredReportAcknowledgementState,
    AnchorRetiredReportProposal, AnchorRetiredReportState, AnchorRetiredSubject,
    AnchorRosterRefreshProposal, AnchorRosterRefreshState, AnchorStore, AnchorSubject,
    AnchorTcpTransport, AnchorTransport, RosterRefreshId, RosterRefreshScope,
};
pub use bootstrap::{
    BootstrapContext, BootstrapRole, DirectoryExpectation, InitiatorOperation, InitiatorOutcome,
    PendingSession, ResponderOperation,
};
pub use bootstrap_bundle::{
    BootstrapBundle, BootstrapMaterials, BootstrapRequirements, ExpectedDevice,
    SessionReopenRequest, MAX_BOOTSTRAP_BUNDLE_BYTES,
};
pub use crypto::{
    AnchorSigningKey, DeviceSigningKey, PolicySigningKey, PublicKey, RootSigningKey, SigningKeyId,
    PUBLIC_KEY_BYTES,
};
pub use durable::{
    AbandonedDelivery, AbandonedEpoch, AbandonedSession, AccountRootJournalRecovery,
    AccountRootJournalState, AccountRootJournalTransition, BootstrapCancellation,
    BootstrapCancellationJournal, BootstrapEntry, BootstrapOperationId, BootstrapPrekeyDisposition,
    BootstrapPrekeyUse, ClosedEpochResolution, CommittedInitiation, CommittedPlaintext,
    DeviceJournal, DurableError, DurableStatus, EpochResolutionId, EpochResolutionStatus,
    FanoutAbandonment, FanoutAbandonmentId, FanoutAbandonmentJournal, FanoutId, FanoutInput,
    FanoutMember, FanoutMemberState, FanoutMemberStatus, FanoutOutput, FanoutReconciliation,
    FanoutStatus, FanoutTarget, InitiationId, JournalAccountAuthority, JournalIdentity, JournalKey,
    MessageId, MessageStatus, PrekeyId, PrekeyPublicationError, PrekeyPublicationId,
    PrekeyPublicationKey, PrekeyPublicationPlan, PrekeyPublicationRequest, PrekeyPublicationRun,
    PrekeyPublicationStatus, PrekeyStatus, PreparedPrekeyPublication, RekeyControlMessage,
    RekeyControlStep, RekeyFlight, RekeyOfferStatus, RekeyProgress, RekeyRequestStatus,
    RekeyResponseStatus, ReservedAbandonment, RosterRefreshMaterials, SendProgress, SessionClosure,
    SessionClosureArchive, SessionClosureId, SessionClosureJournal, SessionClosureStatus,
    UnconfirmedMessage, UnconsumedDelivery, MAX_PREKEY_PUBLICATIONS,
};
pub use identity::{
    AccountPin, CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    DeviceDescription, HistoricalCredentialRenewal, IssuedCredentialRenewal, IssuedRoster,
    RosterCheckpoint, RosterEntry, Validity, VerifiedCredentialRenewal, VerifiedDevice,
    VerifiedRoster, MAX_CREDENTIAL_RENEWAL_BYTES, MAX_DEVICES,
};
pub use manifest::{
    AuthenticatedLeaf, IssuedManifest, LeafKind, LeafProof, ManifestContext, PrekeyLeaf,
    VerifiedManifest, MAX_PREKEYS,
};
pub use selection::{
    AuthenticatedPrekeySelection, ClassicalChoice, PqChoice, PrekeyQuality, PREKEY_SELECTION_BYTES,
};
pub use session_policy::{
    bootstrap_suite_digest, AllowedPrekeyModes, AnchorRequirement, ApplicationSendBudget,
    HistoricalPolicyContinuation, HistoricalPolicyContinuationMaterials, HistoricalPolicyRenewal,
    HistoricalPolicyRenewalMaterials, HistoricalSessionPolicy, IssuedSessionPolicy,
    PolicyCheckpoint, PolicyContinuationApproval, PolicyContinuationMaterials,
    PolicyContinuationScope, PolicyContinuationStatement, PolicyPin, PolicyRenewalApproval,
    PolicyRenewalId, PolicyRenewalMaterials, PolicyRenewalScope, PolicyRenewalStatement,
    SessionPolicyParameters, VerifiedPolicyContinuation, VerifiedPolicyRenewal,
    VerifiedSessionPolicy, MAX_POLICY_CONTINUATION_BYTES, MAX_POLICY_RENEWAL_BYTES,
};

use std::fmt;

/// Candidate validation and ownership failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Truncated, noncanonical, excessive, or unsupported public encoding.
    Encoding,
    /// At least one required signature or its context is invalid.
    Authentication,
    /// Signed account/device/generation or other required binding differs.
    Scope,
    /// The signed interval does not admit the supplied trusted time.
    Validity,
    /// A retained checkpoint disagrees with the signed revision or digest.
    Checkpoint,
    /// An authenticated protocol policy does not permit the requested operation.
    PolicyDenied,
    /// Different bytes attempted to replace a successfully pinned handshake result.
    Conflict,
    /// The operation has not reached the phase required by this action.
    State,
    /// The separately verified SDK runtime rejected a key or lifecycle operation.
    Runtime(q_periapt_sdk::Error),
    /// A per-record or per-operation resource bound was exceeded.
    Capacity,
    /// The signed application-send budget requires locally completed rekey progress.
    RekeyRequired,
    /// This message lies below the retained acknowledgement/delivery boundary.
    Retired,
    /// The signing owner, policy or operation has been closed.
    Closed,
    /// The operating-system CSPRNG failed.
    Entropy,
    /// The bounded secret-scalar generation or signing provider failed.
    Provider,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid candidate encoding",
            Self::Authentication => "candidate authentication failed",
            Self::Scope => "candidate scope differs",
            Self::Validity => "candidate validity interval denied",
            Self::Checkpoint => "candidate checkpoint differs",
            Self::PolicyDenied => "candidate protocol policy denied",
            Self::Conflict => "candidate operation already pins different bytes",
            Self::State => "candidate operation phase does not permit this action",
            Self::Runtime(_) => "candidate SDK runtime operation failed",
            Self::Capacity => "candidate resource limit",
            Self::RekeyRequired => "candidate application-send budget requires rekey completion",
            Self::Retired => "candidate message has been retired",
            Self::Closed => "candidate owner is closed",
            Self::Entropy => "platform entropy unavailable",
            Self::Provider => "candidate signing provider failed",
        })
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<q_periapt_sdk::Error> for Error {
    fn from(error: q_periapt_sdk::Error) -> Self {
        Self::Runtime(error)
    }
}
