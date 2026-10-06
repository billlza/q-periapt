// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Separately typed witness metadata for a policy-only journal transaction.
use super::*;

/// Exact public policy-only proposal. Parsing grants no witness authority.
/// The sealed target must come from the original journal, never a replacement.
///
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorPolicyRenewalProposal, AnchorCredentialRenewalProposal};
/// fn substitute(proposal: AnchorPolicyRenewalProposal) {
///     let _: AnchorCredentialRenewalProposal = proposal;
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorPolicyRenewalProposal {
    pub(super) witness: [u8; 32],
    pub(super) subject: AnchorSubject,
    pub(super) operation: crate::PolicyRenewalId,
    pub(super) statement: [u8; 32],
    pub(super) expected: AnchorHead,
    pub(super) target: AnchorHead,
}
impl AnchorPolicyRenewalProposal {
    pub(crate) fn from_journal(
        witness: [u8; 32],
        subject: AnchorSubject,
        operation: crate::PolicyRenewalId,
        statement: [u8; 32],
        expected: AnchorHead,
        target: AnchorHead,
    ) -> Result<Self, Error> {
        Self::from_trusted_state(
            &Self {
                witness,
                subject,
                operation,
                statement,
                expected,
                target,
            }
            .to_bytes(),
        )
    }
    /// Restore bounded, canonical public expectations retained by the caller.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPPWNP01" {
            return Err(Error::Encoding);
        }
        let value = Self {
            witness: d.array()?,
            subject: AnchorSubject::decode(&mut d)?,
            operation: crate::PolicyRenewalId::from_trusted_state(d.array()?)?,
            statement: d.array()?,
            expected: AnchorHead::decode(&mut d)?,
            target: AnchorHead::decode(&mut d)?,
        };
        d.finish()?;
        nonzero(&value.witness)?;
        nonzero(&value.statement)?;
        if value.expected.fence != value.target.fence
            || increment(value.expected.revision)? != value.target.revision
            || value.expected.digest == value.target.digest
        {
            return Err(Error::Conflict);
        }
        Ok(value)
    }
    /// Canonical public descriptor, distinct from all credential proposals.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = b"QPPWNP01".to_vec();
        out.extend_from_slice(&self.witness);
        self.subject.encode(&mut out);
        out.extend_from_slice(self.operation.as_bytes());
        out.extend_from_slice(&self.statement);
        self.expected.encode(&mut out);
        self.target.encode(&mut out);
        out
    }
    /// Exact independently pinned witness binding.
    pub fn witness_binding(self) -> [u8; 32] {
        self.witness
    }
    /// Stable original journal subject.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Original policy-only operation, never a credential-renewal ID.
    pub fn operation(self) -> crate::PolicyRenewalId {
        self.operation
    }
    /// Exact two-root policy statement commitment.
    pub fn statement(self) -> [u8; 32] {
        self.statement
    }
    /// Independently retained predecessor head.
    pub fn expected_head(self) -> AnchorHead {
        self.expected
    }
    /// Sealed original-journal target head.
    pub fn target_head(self) -> AnchorHead {
        self.target
    }
    /// Commitment under the independent policy-proposal domain.
    pub fn binding(self) -> [u8; 32] {
        digest(b"Q-PERIAPT-ANCHOR-POLICY-RENEWAL/v1", &self.to_bytes())
    }
}

/// Exact policy transaction history. None of these states grants a traffic lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorPolicyRenewalState {
    /// Independently approved original target is prepared, not applied.
    Prepared,
    /// Original head and policy authority were committed together.
    Applied,
    /// Original target is permanently closed without application.
    Closed,
    /// Exact retained terminal was acknowledged; retain its local disposition.
    Acknowledged,
    /// No exact retained disposition. This never proves non-commit.
    Unavailable,
}
impl AnchorOperation {
    /// Commit only the independently prepared original policy transaction.
    pub fn commit_policy_renewal(p: &AnchorPolicyRenewalProposal) -> Self {
        Self(Command::PolicyCommit(p.binding()))
    }
    /// Inspect one exact policy transaction; absence never means no-commit.
    pub fn policy_renewal_status(p: &AnchorPolicyRenewalProposal) -> Self {
        Self(Command::PolicyStatus(p.binding()))
    }
    /// Close an exact prepared target mutually exclusively with application.
    pub fn close_policy_renewal(p: &AnchorPolicyRenewalProposal) -> Self {
        Self(Command::PolicyClose(p.binding()))
    }
    /// Retire only after durably retaining this exact original terminal outcome.
    pub fn acknowledge_policy_renewal(p: &AnchorPolicyRenewalProposal) -> Self {
        Self(Command::PolicyAcknowledge(p.binding()))
    }
    /// Freshly check the unchanged account authority and independent P statement.
    /// Callers must also admit their current policy and exact observed journal head.
    pub fn admit_policy_renewal(authority: [u8; 32], statement: [u8; 32]) -> Result<Self, Error> {
        nonzero(&authority)?;
        nonzero(&statement)?;
        Ok(Self(Command::AdmitPolicy(authority, statement)))
    }
    pub(super) fn policy_binding(self) -> Option<[u8; 32]> {
        match self.0 {
            Command::PolicyCommit(b)
            | Command::PolicyStatus(b)
            | Command::PolicyClose(b)
            | Command::PolicyAcknowledge(b) => Some(b),
            _ => None,
        }
    }
}
impl AnchorReply {
    /// Interpret only a fresh authenticated reply for the exact original P proposal.
    pub fn policy_renewal_state(
        &self,
        p: &AnchorPolicyRenewalProposal,
    ) -> Result<AnchorPolicyRenewalState, Error> {
        if self.authority != p.witness
            || self.subject != p.subject
            || self.operation.policy_binding() != Some(p.binding())
        {
            return Err(Error::Scope);
        }
        match self.outcome {
            AnchorOutcome::PolicyPrepared if self.head == p.expected => {
                Ok(AnchorPolicyRenewalState::Prepared)
            }
            AnchorOutcome::PolicyClosed if self.head == p.expected => {
                Ok(AnchorPolicyRenewalState::Closed)
            }
            AnchorOutcome::PolicyApplied
                if self.head == p.target
                    && self.last
                        == Some(command_id(
                            &p.witness,
                            p.subject,
                            AnchorOperation::commit_policy_renewal(p),
                        )) =>
            {
                Ok(AnchorPolicyRenewalState::Applied)
            }
            AnchorOutcome::PolicyAcknowledged => Ok(AnchorPolicyRenewalState::Acknowledged),
            AnchorOutcome::PolicyUnavailable => Ok(AnchorPolicyRenewalState::Unavailable),
            _ => Err(Error::State),
        }
    }
}
