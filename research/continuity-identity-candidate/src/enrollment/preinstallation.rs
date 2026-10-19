// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh admission before any installation context is selected. This is not G.
use super::*;
use crate::{PolicyCheckpoint, Validity};

/// Independently approved, exact same-key validity extension for fresh admission.
/// Retain the operation before submission. Possession of this value is not user
/// authentication; the target certificate/rosters and live policy are verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentExtensionApproval {
    operation: [u8; 32],
    previous: Option<[u8; 32]>,
    predecessor: RosterCheckpoint,
    until: u64,
}
impl EnrollmentExtensionApproval {
    /// Reconstruct one explicit host approval, never infer it from a response.
    pub fn from_trusted_state(
        operation: [u8; 32],
        previous: Option<[u8; 32]>,
        predecessor: RosterCheckpoint,
        until: u64,
    ) -> Result<Self, Error> {
        crate::codec::nonzero(&operation)?;
        if let Some(previous) = previous {
            crate::codec::nonzero(&previous)?;
            if previous == operation {
                return Err(Error::Scope);
            }
        }
        Validity::new(0, until)?;
        Ok(Self {
            operation,
            previous,
            predecessor,
            until,
        })
    }
    /// Exact caller-retained operation identity.
    pub fn operation(&self) -> [u8; 32] {
        self.operation
    }
    /// Exact last adopted extension, or none for the original accepted credential.
    pub fn previous(&self) -> Option<[u8; 32]> {
        self.previous
    }
    /// Independently approved roster before host issuance.
    pub fn predecessor(&self) -> RosterCheckpoint {
        self.predecessor
    }
    /// Explicit finite end of the extended credential interval.
    pub fn valid_until(&self) -> u64 {
        self.until
    }
}

/// Public issuance materials, separate from the independently current account pin.
pub struct EnrollmentExtensionInputs<'a> {
    /// Exact independent approval.
    pub approval: &'a EnrollmentExtensionApproval,
    /// Root-signed same-key target certificate.
    pub certificate: &'a [u8],
    /// Signed roster from the original committed issuance.
    pub issued_roster: &'a [u8],
    /// Checkpoint of that signed issuance, not a current trust anchor.
    pub issued_checkpoint: RosterCheckpoint,
    /// Signed current roster matching the separate current account pin.
    pub current_roster: &'a [u8],
}

/// Historical preparation progress, never operational authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentPreparationStatus {
    /// No credential has been accepted yet.
    NotAccepted,
    /// Older Accepted storage cannot prove whether preparation ever began.
    Untracked,
    /// Acceptance recorded that no installation context has been selected.
    Unprepared,
    /// An installation context is fixed, even if dependent files are missing.
    Selected,
}

/// Last retained extension result. Current policy, membership and time remain separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentExtensionStatus {
    /// Exact last adopted approval.
    pub approval: EnrollmentExtensionApproval,
    /// Original future journal, preserved throughout adoption.
    pub journal: JournalIdentity,
    /// Signed historical issuance checkpoint.
    pub issued_checkpoint: RosterCheckpoint,
    /// Policy chosen for the first installation after adoption.
    pub policy: PolicyCheckpoint,
}

pub(super) struct Preparation {
    pub(super) selected: bool,
    policy: PolicyCheckpoint,
    pub(super) extension: Option<Box<Extension>>,
}
pub(super) struct Extension {
    approval: EnrollmentExtensionApproval,
    origin: Admission,
    origin_policy: PolicyCheckpoint,
    previous_until: u64,
    previous_checkpoint: RosterCheckpoint,
    previous_policy: PolicyCheckpoint,
    issued_checkpoint: RosterCheckpoint,
    issued_roster: Vec<u8>,
    target: [u8; 32],
}

fn monotonic(target: RosterCheckpoint, prior: RosterCheckpoint) -> Result<(), DurableError> {
    if target.version() < prior.version()
        || (target.version() == prior.version() && target != prior)
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
fn policy_monotonic(target: PolicyCheckpoint, prior: PolicyCheckpoint) -> Result<(), DurableError> {
    if target.version() < prior.version()
        || (target.version() == prior.version() && target != prior)
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

mod adoption;
mod codec;
mod history;
