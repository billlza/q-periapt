// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Trusted account-root replacement with a permanent account-wide witness fence.
use super::*;
use crate::{PolicyCheckpoint, RosterCheckpoint};
use std::collections::BTreeSet;

mod codec;
mod receipt;
pub(super) use codec::{decode_records, encode_records};

const MAX_PROPOSAL_BYTES: usize = 65_536;

/// Original independently approved account replacement operation, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorAccountReplacementId([u8; 32]);
impl AnchorAccountReplacementId {
    /// Generate once and retain before asking the independent operator to approve.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Reconstruct the exact original operation; incoming bytes cannot select it.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Stable public correlation bytes, not a proof of authorization or commitment.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Frozen public metadata within an authenticated account retirement.
/// This observation alone is not a signed receipt or an operating capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorRetiredAccountSubject {
    subject: AnchorSubject,
    head: AnchorHead,
    last: Option<[u8; 32]>,
    state: [u8; 32],
}
impl AnchorRetiredAccountSubject {
    /// Original journal, owner and policy scope.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Exact frozen witness head.
    pub fn observed_head(self) -> AnchorHead {
        self.head
    }
    /// Last original command retained at the witness, not a delivery decision.
    pub fn last_command_id(self) -> Option<[u8; 32]> {
        self.last
    }
    /// Commitment to the complete frozen entry, including unresolved lifecycle state.
    pub fn state_commitment(self) -> [u8; 32] {
        self.state
    }
}

/// Complete original expectation for one independently approved root replacement.
/// Parsing this descriptor does not authorize a trusted-control-plane mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorAccountReplacementProposal {
    witness: [u8; 32],
    operation: AnchorAccountReplacementId,
    previous_root: PublicKey,
    successor_root: PublicKey,
    identity: OriginalIdentity,
    target: AnchorSubject,
    genesis: [u8; 32],
    key: [u8; 32],
    authority: [u8; 32],
    validity: Validity,
    roster: RosterCheckpoint,
    policy: PolicyCheckpoint,
    policy_validity: Validity,
    frozen: Vec<AnchorRetiredAccountSubject>,
}
impl AnchorAccountReplacementProposal {
    /// Original host-approved operation identity.
    pub fn operation(&self) -> AnchorAccountReplacementId {
        self.operation
    }
    /// Cryptographic account permanently retired by this transition.
    pub fn previous_account(&self) -> [u8; 32] {
        crate::identity::account_id(&self.previous_root)
    }
    /// Distinct target account; this is not current operating permission.
    pub fn successor_account(&self) -> [u8; 32] {
        self.identity.account
    }
    /// Exact prepared target journal; commitment does not promise current validity.
    pub fn successor(&self) -> AnchorSubject {
        self.target
    }
    /// All original-account subjects, including previously retired generations.
    pub fn predecessors(&self) -> impl Iterator<Item = AnchorSubject> + '_ {
        self.frozen.iter().map(|entry| entry.subject)
    }
    pub(crate) fn witness_binding(&self) -> [u8; 32] {
        self.witness
    }
    pub(crate) fn predecessor_observation(
        &self,
        subject: AnchorSubject,
    ) -> Result<AnchorRetiredAccountSubject, Error> {
        self.frozen
            .iter()
            .find(|entry| entry.subject == subject)
            .copied()
            .ok_or(Error::Scope)
    }
    /// Canonical statement commitment, independent of receipt signature randomness.
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-REPLACEMENT/v1",
            &self.to_bytes()?,
        ))
    }
    fn check_shape(&self) -> Result<(), Error> {
        nonzero(&self.witness)?;
        nonzero(&self.genesis)?;
        nonzero(&self.key)?;
        nonzero(&self.target.journal)?;
        nonzero(&self.target.owner)?;
        nonzero(&self.target.policy)?;
        if self.previous_root.shares_component(&self.successor_root)
            || self.identity.account != crate::identity::account_id(&self.successor_root)
            || self.target.policy != self.policy.digest()
            || self.authority
                != crate::identity::authority_binding(
                    self.identity.account,
                    self.roster,
                    self.identity.description.family,
                )
            || !self.identity.description.validity.contains(self.validity)
            || !self.policy_validity.contains(self.validity)
            || self.frozen.len() > MAX_ENTRIES
        {
            return Err(Error::Scope);
        }
        let mut last = None;
        for old in &self.frozen {
            nonzero(&old.subject.journal)?;
            nonzero(&old.subject.owner)?;
            nonzero(&old.subject.policy)?;
            nonzero(&old.state)?;
            let bytes = old.subject.to_bytes();
            if old.subject == self.target || last.is_some_and(|previous| previous >= bytes) {
                return Err(Error::Scope);
            }
            last = Some(bytes);
        }
        Ok(())
    }
    fn check_target(
        &self,
        previous_root: &PublicKey,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        self.check_shape()?;
        if self.witness != pin.binding
            || &self.previous_root != previous_root
            || self.successor_root != next.authority_key
            || previous_root.shares_component(&pin.key)
            || policy.anchor_requirement().binding() != Some(pin.binding)
            || self.target != genesis.subject
            || self.genesis != genesis.digest
            || self.identity != OriginalIdentity::from_verified(next)
            || self.key != replacement::key_commitment(&next.key)
            || self.authority != next.authority_binding()
            || self.validity != enrollment_validity(next, policy)?
            || self.roster != next.roster().checkpoint()
            || self.policy != policy.checkpoint()
            || self.policy_validity != policy.validity()
            || self.target.owner != storage_owner(next)
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
}

/// Historical local decision, never permission to release an operational owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorAccountReplacementState {
    /// No exact decision; this does not authorize fallback to the previous root.
    Unavailable,
    /// The original complete transition is permanently retained.
    Committed,
}

/// Authenticated permanent account retirement, not an operating witness reply.
/// Witness key and storage continuity remain independent trust assumptions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredAccount {
    proposal: AnchorAccountReplacementProposal,
}
impl AnchorRetiredAccount {
    /// Exact historical statement, including its frozen original subjects.
    pub fn proposal(&self) -> &AnchorAccountReplacementProposal {
        &self.proposal
    }
    /// Frozen witness head and last command; neither establishes message delivery.
    pub fn subject_observation(
        &self,
        subject: AnchorSubject,
    ) -> Result<AnchorRetiredAccountSubject, Error> {
        self.proposal.predecessor_observation(subject)
    }
}

impl Image {
    pub(super) fn require_account_live(&self, account: [u8; 32]) -> Result<(), DurableError> {
        if self.account_replacements.contains_key(&account) {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
    pub(super) fn account_retirement(&self, subject: AnchorSubject) -> bool {
        self.account_replacements
            .values()
            .any(|p| p.frozen.iter().any(|entry| entry.subject == subject))
    }
    fn account_snapshot(
        &self,
        account: [u8; 32],
        pin: &AnchorPin,
    ) -> Result<Vec<AnchorRetiredAccountSubject>, DurableError> {
        let mut result = Vec::new();
        for entry in self.entries.values() {
            // An unclassified legacy entry could belong to the retiring account.
            let identity = entry
                .original_identity
                .as_ref()
                .ok_or(DurableError::Suspended)?;
            if identity.account == account {
                result.push(AnchorRetiredAccountSubject {
                    subject: entry.subject,
                    head: entry.head,
                    last: entry.last,
                    state: replacement::state_commitment(entry, pin)?,
                });
            }
        }
        result.sort_by_key(|entry| entry.subject.to_bytes());
        Ok(result)
    }
    fn check_new_account_replacement(
        &self,
        p: &AnchorAccountReplacementProposal,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        self.require_account_live(p.previous_account())?;
        self.require_account_live(p.successor_account())?;
        if self
            .account_replacements
            .values()
            .any(|saved| saved.operation == p.operation)
            || self.entries.values().any(|entry| {
                entry
                    .original_identity
                    .as_ref()
                    .is_some_and(|identity| identity.account == p.successor_account())
            })
            || self.entries.contains_key(&p.target.id(&pin.binding))
            || self.account_snapshot(p.previous_account(), pin)? != p.frozen
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn check_account_replacements(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if self.account_replacements.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut operations = BTreeSet::new();
        for (account, p) in &self.account_replacements {
            p.check_shape()?;
            let target = self
                .entries
                .get(&p.target.id(&pin.binding))
                .ok_or(DurableError::Corrupt)?;
            if account != &p.previous_account()
                || p.witness != pin.binding
                || p.previous_root.shares_component(&pin.key)
                || p.successor_root.shares_component(&pin.key)
                || !operations.insert(p.operation.0)
                || target.subject != p.target
                || target.genesis != p.genesis
                || target.original_identity.as_ref() != Some(&p.identity)
                || replacement::key_commitment(&target.device) != p.key
                || self.account_snapshot(*account, pin)? != p.frozen
            {
                return Err(DurableError::Corrupt);
            }
            let mut visited = BTreeSet::new();
            let mut current = *account;
            while let Some(next) = self.account_replacements.get(&current) {
                if !visited.insert(current) {
                    return Err(DurableError::Corrupt);
                }
                current = next.successor_account();
            }
        }
        Ok(())
    }
}

impl AnchorStore {
    /// Prepare the complete original-root fence and one fresh target journal.
    ///
    /// This is a trusted-control-plane operation. The operator must independently
    /// authenticate application-account recovery and pin both roots; the old root
    /// signature or an incoming descriptor is insufficient. Every old-account
    /// subject is included, even if its device generation was already retired.
    /// Legacy entries need original identity classification before preparation.
    /// Preparation is read-only and grants no successor authority.
    pub fn account_root_replacement_proposal(
        &mut self,
        operation: AnchorAccountReplacementId,
        previous_root: &PublicKey,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorAccountReplacementProposal, DurableError> {
        let validity = self.admit_enrollment(genesis.subject, next, policy, now)?;
        let pin = self.pin()?;
        let image = self.image()?;
        let p = AnchorAccountReplacementProposal {
            witness: pin.binding,
            operation,
            previous_root: previous_root.clone(),
            successor_root: next.authority_key.clone(),
            identity: OriginalIdentity::from_verified(next),
            target: genesis.subject,
            genesis: genesis.digest,
            key: replacement::key_commitment(&next.key),
            authority: next.authority_binding(),
            validity,
            roster: next.roster().checkpoint(),
            policy: policy.checkpoint(),
            policy_validity: policy.validity(),
            frozen: image.account_snapshot(crate::identity::account_id(previous_root), &pin)?,
        };
        p.check_target(previous_root, genesis, next, policy, &pin)?;
        image.check_new_account_replacement(&p, &pin)?;
        Ok(p)
    }
    /// Atomically retire the complete previous account and enroll the exact target.
    ///
    /// Future unseen old-root devices are fenced too. Existing old heads and
    /// unresolved commands remain frozen; no delivery, erasure or safe witness-key
    /// transfer is inferred. Requests already served before this commit may still
    /// arrive over a delayed transport. The host's local authority fence is separate.
    /// Exact committed retries are historical after expiry; they grant no current
    /// owner. I/O failure may follow commit: reopen and reconcile this descriptor.
    pub fn replace_account_root(
        &mut self,
        p: &AnchorAccountReplacementProposal,
        previous_root: &PublicKey,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorAccountReplacementState, DurableError> {
        let pin = self.pin()?;
        p.check_target(previous_root, genesis, next, policy, &pin)?;
        let mut image = self.image()?;
        if let Some(saved) = image.account_replacements.get(&p.previous_account()) {
            return if saved == p {
                Ok(AnchorAccountReplacementState::Committed)
            } else {
                Err(DurableError::Conflict)
            };
        }
        self.admit_enrollment(genesis.subject, next, policy, now)?;
        image.check_new_account_replacement(p, &pin)?;
        if image.entries.len() >= MAX_ENTRIES || image.account_replacements.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image.entries.insert(
            p.target.id(&pin.binding),
            Entry::at_genesis(p.target, p.genesis, next, p.validity)?,
        );
        image
            .account_replacements
            .insert(p.previous_account(), p.clone());
        self.persist(&mut image)?;
        Ok(AnchorAccountReplacementState::Committed)
    }
    /// Observe only the exact original local decision. Unavailable is not a
    /// rollback permission, a fresh network reply or proof that old traffic is safe.
    pub fn account_root_replacement_status(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<AnchorAccountReplacementState, DurableError> {
        p.check_shape()?;
        if p.witness != self.pin()?.binding {
            return Err(Error::Scope.into());
        }
        let image = self.image()?;
        match image.account_replacements.get(&p.previous_account()) {
            Some(saved) if saved == p => Ok(AnchorAccountReplacementState::Committed),
            Some(_) => Err(DurableError::Conflict),
            None if image
                .account_replacements
                .values()
                .any(|saved| saved.operation == p.operation) =>
            {
                Err(DurableError::Conflict)
            }
            None => Ok(AnchorAccountReplacementState::Unavailable),
        }
    }
    /// Read immutable retirement metadata, including original unresolved heads.
    pub fn retired_account_observation(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<AnchorRetiredAccount, DurableError> {
        if self.account_root_replacement_status(p)? != AnchorAccountReplacementState::Committed {
            return Err(DurableError::Absent);
        }
        Ok(AnchorRetiredAccount {
            proposal: p.clone(),
        })
    }
}
