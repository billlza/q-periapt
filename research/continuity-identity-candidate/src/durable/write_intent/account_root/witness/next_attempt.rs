// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A new target keeps the complete original freeze and exact signed non-commit.
use super::*;

/// An independently approved next attempt after a purpose-37 Closed result.
/// Recreate this value from the original trusted plans and exact signed result
/// after restart. It never unfreezes the account or grants an operating owner.
#[derive(Clone)]
pub struct TransferredAccountRootJournalTransition {
    previous: TransferredAccountRootJournalPlan,
    next: TransferredAccountRootJournalPlan,
    closed: Vec<u8>,
}
impl TransferredAccountRootJournalTransition {
    /// Authenticate the old permanent non-commit before selecting the separately
    /// approved target. Every frozen subject, pending state and original logical
    /// Witness remains identical; the accounting history may only extend.
    pub fn verify(
        previous: TransferredAccountRootJournalPlan,
        mut next: TransferredAccountRootJournalPlan,
        closed: &[u8],
    ) -> Result<Self, DurableError> {
        previous.verify(closed)?.closure()?;
        let old = previous.proposal();
        let new = next.proposal();
        if !next.attempts.is_empty()
            || previous.logical.binding() != next.logical.binding()
            || old.operation() == new.operation()
            || old.previous_account() != new.previous_account()
            || old.authority_transition().0 != new.authority_transition().0
            || old.authority_transition().2 != new.authority_transition().2
            || old.preparation_binding().is_none()
            || old.preparation_binding() != new.preparation_binding()
            || !old.predecessors().eq(new.predecessors())
            || previous
                .selection
                .as_ref()
                .map(|p| p.retirement_binding())
                .transpose()?
                != next
                    .selection
                    .as_ref()
                    .map(|p| p.retirement_binding())
                    .transpose()?
        {
            return Err(Error::Scope.into());
        }
        for subject in old.predecessors() {
            if old.predecessor_observation(subject)? != new.predecessor_observation(subject)? {
                return Err(DurableError::Conflict);
            }
        }
        if previous.history.checkpoint() != next.history.checkpoint() {
            next.history.require_extension_of(&previous.history)?;
        }
        next.history.require_current(new.witness_binding())?;
        next.attempts = previous.attempts.append(&previous, &next, closed)?;
        Ok(Self {
            previous,
            next,
            closed: closed.to_vec(),
        })
    }
    /// Exact successor expectation, including the authenticated closed-attempt history.
    pub fn next_plan(&self) -> &TransferredAccountRootJournalPlan {
        &self.next
    }
    pub(crate) fn previous_plan(&self) -> &TransferredAccountRootJournalPlan {
        &self.previous
    }
    pub(crate) fn closed(&self) -> &[u8] {
        &self.closed
    }
}

// Hold the original child lease across the independent parent commit. Preflight
// cannot publish; commit performs an exact old-or-already-new comparison.
pub(crate) struct AttemptPreparation {
    owners: Owners,
    saved: Fence,
    next: Fence,
    previous_checkpoint: [u8; 32],
    checkpoint: [u8; 32],
    already_next: bool,
}
impl AttemptPreparation {
    #[cfg(all(test, unix))]
    pub(crate) fn fault_sync(
        mut self,
        path: &Path,
        after: bool,
    ) -> (
        Self,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        // Replace only the owned test backend, before the measured transaction.
        // The original lease is released and reacquired without changing bytes.
        let owners = self.owners;
        drop(owners.db);
        let (db, remaining, count, _) = crate::durable::tests::fault_database_path(path, after);
        self.owners = Owners { db, ..owners };
        (self, remaining, count)
    }
    pub(crate) fn previous_checkpoint(&self) -> [u8; 32] {
        self.previous_checkpoint
    }
    pub(crate) fn checkpoint(&self) -> [u8; 32] {
        self.checkpoint
    }
    pub(crate) fn already_next(&self) -> bool {
        self.already_next
    }
    pub(crate) fn commit(self) -> Result<AccountRootJournalRecovery, DurableError> {
        if self.saved != self.next {
            self.owners
                .save(Some(&self.saved), &self.next, "transferred-handoff")?;
        }
        self.owners.read()?;
        Ok(AccountRootJournalRecovery {
            active: Some(Box::new(self.owners)),
        })
    }
}
impl AccountRootJournalRecovery {
    pub(crate) fn prepare_transferred_transition(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<AttemptPreparation, DurableError> {
        let plan = &transition.previous;
        let mut owners = Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin: plan.witness_pin()?.clone(),
            proposal: plan.proposal().clone(),
            transferred: Some(Box::new(plan.clone())),
        };
        let (image, pending) =
            load_pending_snapshot(&owners.db, &owners.key, owners.owner, owners.admission())?;
        if image.id != *identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let mut previous = owners.new_fence(&image, pending.as_ref())?;
        let previous_checkpoint = previous.preparation_checkpoint(&owners.key)?;
        previous.receipt = Some(transition.closed.clone());
        let saved = {
            let tx = owners.db.begin_read().map_err(storage)?;
            let table = image_table(&tx)?;
            let row = table
                .get(ROW)
                .map_err(storage)?
                .ok_or(DurableError::Absent)?;
            Fence::decode(&owners.key, row.value())?
        };
        saved.check(&owners.key, &image, pending.as_ref())?;
        owners.pin = transition.next.witness_pin()?.clone();
        owners.proposal = transition.next.proposal().clone();
        owners.transferred = Some(Box::new(transition.next.clone()));
        let mut next = owners.new_fence(&image, pending.as_ref())?;
        // Reserve the full terminal proof before publishing a new attempt.
        if next.encode(&owners.key)?.len() + WITNESS_RECEIPT_BYTES > MAX_FENCE_BYTES {
            return Err(DurableError::Capacity);
        }
        let checkpoint = next.preparation_checkpoint(&owners.key)?;
        let already_next = saved.proposal == next.proposal;
        if already_next {
            next.receipt = saved.receipt.clone();
            if saved != next {
                return Err(DurableError::Conflict);
            }
            if let Some(wire) = &next.receipt {
                transition.next.verify(wire)?;
            }
        } else {
            // The authenticated supplied closure may precede its local receipt
            // commit, but must never replace a different retained terminal proof.
            if saved.receipt.is_none() {
                previous.receipt = None;
            }
            if saved != previous {
                return Err(DurableError::Conflict);
            }
        }
        Ok(AttemptPreparation {
            owners,
            saved,
            next,
            previous_checkpoint,
            checkpoint,
            already_next,
        })
    }
    /// Resume one exact child transition. A missing fence or foreign snapshot is
    /// an error, never evidence that the old authority can be used again.
    /// Enrollment-managed callers must use the parent transition API instead.
    pub fn resume_transferred_transition(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        transition: &TransferredAccountRootJournalTransition,
    ) -> Result<Self, DurableError> {
        Self::prepare_transferred_transition(path, key, original, identity, transition)?.commit()
    }
}
