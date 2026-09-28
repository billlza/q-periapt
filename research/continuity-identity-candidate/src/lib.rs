// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
//! Candidate accountable identity and prekey-manifest verification.
//!
//! This isolated, unpublished component uses actual ML-DSA-65 and P-256 signatures.
//! It is not a ratchet, a bootstrap confirmation, or permission to consume prekeys.
//! Account enrollment must independently pin the intended account and roster head.
//! No production crate, C ABI, or language binding depends on this candidate.

mod codec;
mod crypto;
mod identity;
mod manifest;
mod merkle;
mod selection;
#[cfg(test)]
mod tests;

pub use crypto::{DeviceSigningKey, PublicKey, RootSigningKey, PUBLIC_KEY_BYTES};
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
    /// A per-record or per-operation resource bound was exceeded.
    Capacity,
    /// The signing owner has been closed.
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
            Self::Capacity => "candidate resource limit",
            Self::Closed => "candidate signing owner is closed",
            Self::Entropy => "platform entropy unavailable",
            Self::Provider => "candidate signing provider failed",
        })
    }
}
impl std::error::Error for Error {}
