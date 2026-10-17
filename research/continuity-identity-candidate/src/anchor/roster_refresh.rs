// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact roster/head transaction metadata, distinct from credential and policy grants.
use super::*;
use crate::{PolicyCheckpoint, RosterCheckpoint};
pub(crate) const ROSTER_REFRESH_PROPOSAL_BYTES: usize = 417;

/// Retained identity of one original roster/head update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterRefreshId([u8; 32]);
impl RosterRefreshId {
    /// Generate once before retaining or dispatching this update.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore independently retained operation metadata.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public correlation bytes, never authority.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Exact expectations derived from the original journal and independently approved R.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterRefreshScope {
    /// Original operation to retain across unknown results.
    pub operation: RosterRefreshId,
    /// Exact actual predecessor roster.
    pub previous: RosterCheckpoint,
    /// Independently root-approved target roster.
    pub target: RosterCheckpoint,
    /// Exact unchanged current policy, not necessarily original P0.
    pub policy: PolicyCheckpoint,
    /// Exact adopted independent-P statement, absent only for original P0.
    pub policy_authorization: Option<[u8; 32]>,
}
impl RosterRefreshScope {
    pub(crate) const ENCODED_BYTES: usize = 185;
    pub(crate) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.operation.as_bytes());
        for (version, digest) in [
            (self.previous.version(), self.previous.digest()),
            (self.target.version(), self.target.digest()),
            (self.policy.version(), self.policy.digest()),
        ] {
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&digest);
        }
        out.push(u8::from(self.policy_authorization.is_some()));
        out.extend_from_slice(&self.policy_authorization.unwrap_or([0; 32]));
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let operation = RosterRefreshId::from_trusted_state(d.array()?)?;
        let previous = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let target_roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let flag = d.array::<1>()?;
        let statement = d.array()?;
        let policy_authorization = match flag {
            [0] if statement == [0; 32] => None,
            [1] => {
                nonzero(&statement)?;
                Some(statement)
            }
            _ => return Err(Error::Encoding),
        };
        if target_roster.version() <= previous.version() {
            return Err(Error::Conflict);
        }
        Ok(Self {
            operation,
            previous,
            target: target_roster,
            policy,
            policy_authorization,
        })
    }
}
/// Public descriptor of one sealed original journal target. Parsing is not proof.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorRosterRefreshProposal, AnchorPolicyRenewalProposal};
/// fn substitute(p: AnchorRosterRefreshProposal) { let _: AnchorPolicyRenewalProposal = p; }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorRosterRefreshProposal {
    witness: [u8; 32],
    subject: AnchorSubject,
    scope: RosterRefreshScope,
    expected: AnchorHead,
    target: AnchorHead,
}
impl AnchorRosterRefreshProposal {
    pub(crate) fn from_journal(
        witness: [u8; 32],
        subject: AnchorSubject,
        scope: RosterRefreshScope,
        expected: AnchorHead,
        target: AnchorHead,
    ) -> Result<Self, Error> {
        nonzero(&witness)?;
        if let Some(statement) = scope.policy_authorization {
            nonzero(&statement)?;
        }
        if scope.target.version() <= scope.previous.version()
            || expected.fence != target.fence
            || increment(expected.revision)? != target.revision
            || expected.digest == target.digest
            || (scope.policy_authorization.is_none() != (scope.policy.digest() == subject.policy))
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            witness,
            subject,
            scope,
            expected,
            target,
        })
    }
    /// Parse only canonical bounded expectations retained by the application.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPRWNP01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        nonzero(&witness)?;
        let subject = AnchorSubject::decode(&mut d)?;
        let scope = RosterRefreshScope::decode(&mut d)?;
        let expected = AnchorHead::decode(&mut d)?;
        let target = AnchorHead::decode(&mut d)?;
        d.finish()?;
        Self::from_journal(witness, subject, scope, expected, target)
    }
    /// Canonical 417-byte proposal under its own domain and tag.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = b"QPRWNP01".to_vec();
        out.extend_from_slice(&self.witness);
        self.subject.encode(&mut out);
        self.scope.encode(&mut out);
        self.expected.encode(&mut out);
        self.target.encode(&mut out);
        out
    }
    /// Original pinned witness binding.
    pub fn witness_binding(self) -> [u8; 32] {
        self.witness
    }
    /// Original immutable journal subject.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Exact operation/roster/policy scope, never current permission.
    pub fn scope(&self) -> &RosterRefreshScope {
        &self.scope
    }
    /// Original expected head.
    pub fn expected_head(self) -> AnchorHead {
        self.expected
    }
    /// Exact sealed target head.
    pub fn target_head(self) -> AnchorHead {
        self.target
    }
    /// Domain-separated commitment to the complete original proposal.
    pub fn binding(self) -> [u8; 32] {
        digest(b"Q-PERIAPT-ANCHOR-ROSTER-REFRESH/v1", &self.to_bytes())
    }
}
/// Exact retained roster/head outcome, never an operational lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorRosterRefreshState {
    /// Root-approved target retained, current roster/head unchanged.
    Prepared,
    /// Exact head and roster authority committed in one witness transaction.
    Applied,
    /// Original target closed without application.
    Closed,
    /// Original terminal retired; preserve its local disposition.
    Acknowledged,
    /// No exact retained disposition. This never proves non-commit.
    Unavailable,
}
impl AnchorOperation {
    /// Commit the exact independently prepared roster/head target.
    pub fn commit_roster_refresh(p: &AnchorRosterRefreshProposal) -> Self {
        Self(Command::RosterCommit(p.binding()))
    }
    /// Query exact roster/head history without granting current permission.
    pub fn roster_refresh_status(p: &AnchorRosterRefreshProposal) -> Self {
        Self(Command::RosterStatus(p.binding()))
    }
    /// Close an existing exact preparation, mutually exclusively with application.
    pub fn close_roster_refresh(p: &AnchorRosterRefreshProposal) -> Self {
        Self(Command::RosterClose(p.binding()))
    }
    /// Retire only after the original enrollment durably retains this terminal.
    pub fn acknowledge_roster_refresh(p: &AnchorRosterRefreshProposal) -> Self {
        Self(Command::RosterAcknowledge(p.binding()))
    }
    pub(super) fn roster_binding(self) -> Option<[u8; 32]> {
        match self.0 {
            Command::RosterCommit(b)
            | Command::RosterStatus(b)
            | Command::RosterClose(b)
            | Command::RosterAcknowledge(b) => Some(b),
            _ => None,
        }
    }
}
impl AnchorReply {
    /// Interpret only a fresh authenticated reply bound to this entire proposal.
    pub fn roster_refresh_state(
        &self,
        p: &AnchorRosterRefreshProposal,
    ) -> Result<AnchorRosterRefreshState, Error> {
        if self.authority != p.witness
            || self.subject != p.subject
            || self.operation.roster_binding() != Some(p.binding())
        {
            return Err(Error::Scope);
        }
        match self.outcome {
            AnchorOutcome::RosterPrepared if self.head == p.expected => {
                Ok(AnchorRosterRefreshState::Prepared)
            }
            AnchorOutcome::RosterClosed if self.head == p.expected => {
                Ok(AnchorRosterRefreshState::Closed)
            }
            AnchorOutcome::RosterApplied
                if self.head == p.target
                    && self.last
                        == Some(command_id(
                            &p.witness,
                            p.subject,
                            AnchorOperation::commit_roster_refresh(p),
                        )) =>
            {
                Ok(AnchorRosterRefreshState::Applied)
            }
            AnchorOutcome::RosterAcknowledged => Ok(AnchorRosterRefreshState::Acknowledged),
            AnchorOutcome::RosterUnavailable => Ok(AnchorRosterRefreshState::Unavailable),
            _ => Err(Error::State),
        }
    }
}
