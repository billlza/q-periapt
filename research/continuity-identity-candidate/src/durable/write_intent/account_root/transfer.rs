// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A verified terminal decision permits an explicit transition, never an in-place reset.
use super::*;
use crate::{
    AnchorAccountReplacementId, AnchorClosedAccountPreparation, AnchorClosedAccountReplacement,
};
mod codec;
pub(super) use codec::{decode_history, encode_history};
pub(super) const MAX_TRANSFERS: usize = 256;
pub(super) const TRANSFER_BYTES: usize = 129;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Transfer {
    operation: AnchorAccountReplacementId,
    previous: [u8; 32],
    next: [u8; 32],
    kind: u8,
    closure: [u8; 32],
}
#[derive(Clone)]
enum Closed {
    Exact(Box<AnchorClosedAccountReplacement>),
    Plan(Box<AnchorClosedAccountPreparation>),
}
/// An independently approved next proposal plus authenticated original non-commit.
/// This object grants no operating owner. Retain both original expectations in the
/// application controller; recreate the proof under the same witness on recovery.
#[derive(Clone)]
pub struct AccountRootJournalTransition {
    closed: Closed,
    next: Proposal,
}
impl AccountRootJournalTransition {
    /// Approve a next target only after exact original proposal non-commit.
    pub fn from_closed_replacement(
        closed: AnchorClosedAccountReplacement,
        next: Proposal,
    ) -> Result<Self, Error> {
        let result = Self {
            closed: Closed::Exact(Box::new(closed)),
            next,
        };
        result.check_scope()?;
        Ok(result)
    }
    /// Approve a next target only after exact original plan non-commit.
    pub fn from_closed_preparation(
        closed: AnchorClosedAccountPreparation,
        next: Proposal,
    ) -> Result<Self, Error> {
        let result = Self {
            closed: Closed::Plan(Box::new(closed)),
            next,
        };
        result.check_scope()?;
        Ok(result)
    }
    /// Exact independently approved successor expectation, not current permission.
    pub fn next_proposal(&self) -> &Proposal {
        &self.next
    }
    fn origin(&self) -> &Proposal {
        match &self.closed {
            Closed::Exact(c) => c.proposal(),
            Closed::Plan(c) => c.plan().target(),
        }
    }
    fn check_scope(&self) -> Result<(), Error> {
        let old = self.origin();
        if old.operation() == self.next.operation()
            || old.previous_account() != self.next.previous_account()
            || old.witness_binding() != self.next.witness_binding()
            || old.authority_transition().2 != self.next.authority_transition().2
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    fn closure_binding(&self) -> Result<(u8, [u8; 32]), Error> {
        match &self.closed {
            Closed::Exact(c) => Ok((0, c.proposal().binding()?)),
            Closed::Plan(c) => Ok((1, c.plan().binding()?)),
        }
    }
    fn marker(&self, old: &Proposal) -> Result<Transfer, DurableError> {
        self.check_scope()?;
        let matches = match &self.closed {
            Closed::Exact(c) => c.proposal() == old,
            Closed::Plan(c) => c.plan().check_retained(old)?,
        };
        if !matches {
            return Err(DurableError::Conflict);
        }
        let (kind, closure) = self.closure_binding()?;
        Ok(Transfer {
            operation: old.operation(),
            previous: old.binding()?,
            next: self.next.binding()?,
            kind,
            closure,
        })
    }
    fn is_original_retry(&self, marker: &Transfer) -> Result<bool, Error> {
        let (kind, closure) = self.closure_binding()?;
        Ok(marker.operation == self.origin().operation()
            && marker.next == self.next.binding()?
            && marker.kind == kind
            && marker.closure == closure)
    }
}
pub(super) fn check_history(history: &[Transfer], current: &Proposal) -> Result<(), DurableError> {
    if history.len() > MAX_TRANSFERS {
        return Err(DurableError::Capacity);
    }
    let mut operations = std::collections::BTreeSet::new();
    let mut previous = None;
    for record in history {
        if !operations.insert(*record.operation.as_bytes())
            || record.previous == record.next
            || previous.is_some_and(|binding| binding != record.previous)
            || record.kind > 1
            || (record.kind == 0 && record.closure != record.previous)
        {
            return Err(DurableError::Corrupt);
        }
        previous = Some(record.next);
    }
    let current_binding = current.binding()?;
    if operations.contains(current.operation().as_bytes())
        || previous.is_some_and(|binding| binding != current_binding)
    {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
impl Owners {
    fn transfer(&mut self, transition: &AccountRootJournalTransition) -> Result<(), DurableError> {
        transition.check_scope()?;
        let original = self.read_snapshot()?;
        if original.proposal == transition.next {
            if !original
                .history
                .last()
                .map(|h| transition.is_original_retry(h))
                .transpose()?
                .unwrap_or(false)
            {
                return Err(DurableError::Conflict);
            }
            self.proposal = transition.next.clone();
            return Ok(());
        }
        if original.receipt.is_some() {
            return Err(DurableError::Conflict);
        }
        let marker = transition.marker(&original.proposal)?;
        let (image, pending) = load_pending_snapshot(
            &self.db,
            &self.key,
            self.owner,
            SnapshotAdmission::AccountRootReplacement,
        )?;
        let mut next = original.clone();
        next.proposal = transition.next.clone();
        next.history.push(marker);
        next.check(&self.key, &image, pending.as_ref())?;
        self.save(Some(&original), &next, "handoff")?;
        self.proposal = transition.next.clone();
        self.read()?;
        Ok(())
    }
}
impl AccountRootJournalRecovery {
    /// Durably replace only the original fence descriptor after authenticated
    /// non-commit. Ciphertext, image, pending intent and witnessed head never change.
    /// Errors consume this owner and may follow commit; resume the same transition.
    pub fn transition_after_noncommit(
        &mut self,
        transition: &AccountRootJournalTransition,
    ) -> Result<AccountRootJournalState, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| owners.transfer(transition));
        if let Err(error) = result {
            self.close();
            return Err(error);
        }
        self.status()
    }
    /// Reconcile this exact transition on the original journal after a lost return.
    /// Neither absence nor a different saved proposal creates a replacement journal.
    pub fn resume_transition(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        pin: AnchorPin,
        transition: &AccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin,
            proposal: transition.next.clone(),
        };
        owners.transfer(transition)?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
