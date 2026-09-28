// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
//! Candidate accountable identity, prekey selection and confirmed bootstrap.
//!
//! This isolated, unpublished component uses actual ML-DSA-65 and P-256 signatures.
//! The volatile handshake is not a ratchet or permission to consume prekeys.
//! Account enrollment must independently pin the intended account and roster head.
//! No production crate, C ABI, or language binding depends on this candidate.

mod bootstrap;
mod codec;
mod crypto;
mod durable;
mod identity;
mod manifest;
mod merkle;
mod selection;
mod session_policy;
#[cfg(test)]
mod tests;

pub use bootstrap::{
    BootstrapContext, BootstrapRole, DirectoryExpectation, InitiatorOperation, InitiatorOutcome,
    PendingSession, ResponderOperation,
};
pub use crypto::{
    DeviceSigningKey, PolicySigningKey, PublicKey, RootSigningKey, SigningKeyId, PUBLIC_KEY_BYTES,
};
pub use durable::{
    CommittedInitiation, DeviceJournal, DurableError, DurableStatus, InitiationId, JournalIdentity,
    JournalKey, PrekeyId, PrekeyStatus,
};
pub use identity::{
    AccountPin, DeviceDescription, IssuedRoster, RosterCheckpoint, RosterEntry, Validity,
    VerifiedDevice, MAX_DEVICES,
};
pub use manifest::{
    AuthenticatedLeaf, IssuedManifest, LeafKind, LeafProof, ManifestContext, PrekeyLeaf,
    VerifiedManifest, MAX_PREKEYS,
};
pub use selection::{
    AuthenticatedPrekeySelection, ClassicalChoice, PqChoice, PrekeyQuality, PREKEY_SELECTION_BYTES,
};
pub use session_policy::{
    bootstrap_suite_digest, AllowedPrekeyModes, IssuedSessionPolicy, PolicyCheckpoint, PolicyPin,
    SessionPolicyParameters, VerifiedSessionPolicy,
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
