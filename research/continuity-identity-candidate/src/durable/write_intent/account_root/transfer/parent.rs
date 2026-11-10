// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reconstruct a child fence only from the original authenticated enrollment parent.
use super::*;

pub(crate) struct ParentCheckpoint<'a> {
    pub(crate) proposal: &'a Proposal,
    pub(crate) history: &'a [Transfer],
    pub(crate) child: Option<[u8; 32]>,
}
impl ParentCheckpoint<'_> {
    fn admits(&self, child: &Fence) -> Result<(), DurableError> {
        if self.history == child.history && self.proposal == &child.proposal {
            return Ok(());
        }
        let length = child.history.len();
        if child.receipt.is_some() || self.history.get(..length) != Some(child.history.as_slice()) {
            return Err(DurableError::Conflict);
        }
        let next = self.history.get(length).ok_or(DurableError::Conflict)?;
        if next.operation != child.proposal.operation()
            || next.previous != child.proposal.binding()?
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
impl Owners {
    fn planned_parent(
        &self,
        parent: &ParentCheckpoint<'_>,
    ) -> Result<(Option<Fence>, Fence), DurableError> {
        check_history(parent.history, parent.proposal)?;
        if self.pin.binding() != parent.proposal.witness_binding() {
            return Err(Error::Scope.into());
        }
        let (image, pending) = load_pending_snapshot(
            &self.db,
            &self.key,
            self.owner,
            SnapshotAdmission::AccountRootReplacement,
        )?;
        if image.id != *self.identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let original = {
            let tx = self.db.begin_read().map_err(storage)?;
            let table = image_table(&tx)?;
            let row = table.get(ROW).map_err(storage)?;
            row.map(|r| Fence::decode(&self.key, r.value()))
                .transpose()?
        };
        if let Some(fence) = &original {
            fence.check(&self.key, &image, pending.as_ref())?;
            if let Some(receipt) = &fence.receipt {
                self.pin.verify_retired_account(&fence.proposal, receipt)?;
            }
            parent.admits(fence)?;
        }
        let mut next = Fence::new(&self.key, &image, pending.as_ref(), parent.proposal.clone())?;
        next.history = parent.history.to_vec();
        next.receipt = original.as_ref().and_then(|f| f.receipt.clone());
        next.check(&self.key, &image, pending.as_ref())?;
        let checkpoint = next.preparation_checkpoint(&self.key)?;
        if parent.child.is_some_and(|expected| checkpoint != expected) {
            return Err(DurableError::Conflict);
        }
        Ok((original, next))
    }
    fn reconcile_parent(&mut self, parent: &ParentCheckpoint<'_>) -> Result<(), DurableError> {
        let (original, next) = self.planned_parent(parent)?;
        if original.as_ref() != Some(&next) {
            self.save(original.as_ref(), &next, "parent-handoff")?;
        }
        self.read()?;
        Ok(())
    }
}
// Retain the exact child lease while the independent parent publishes its intent.
// Preflight is read-only; only commit() may retain/reconstruct the original fence.
pub(crate) struct ParentPreparation<'a> {
    owners: Owners,
    parent: Option<ParentCheckpoint<'a>>,
    checkpoint: [u8; 32],
    selection: Option<crate::durable::WitnessSelectionProgress>,
}
impl ParentPreparation<'_> {
    pub(crate) fn checkpoint(&self) -> [u8; 32] {
        self.checkpoint
    }
    pub(crate) fn selection(&self) -> Option<&crate::durable::WitnessSelectionProgress> {
        self.selection.as_ref()
    }
    pub(crate) fn commit(mut self) -> Result<AccountRootJournalRecovery, DurableError> {
        if let Some(mut parent) = self.parent {
            parent.child = Some(self.checkpoint);
            self.owners.reconcile_parent(&parent)?;
            Ok(AccountRootJournalRecovery {
                active: Some(Box::new(self.owners)),
            })
        } else {
            let (next, _) = self.owners.transferred_preparation()?;
            if next.preparation_checkpoint(&self.owners.key)? != self.checkpoint {
                return Err(DurableError::Conflict);
            }
            self.owners.prepare()
        }
    }
}
impl AccountRootJournalRecovery {
    pub(crate) fn prepare_parent<'a>(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        pin: AnchorPin,
        parent: ParentCheckpoint<'a>,
    ) -> Result<ParentPreparation<'a>, DurableError> {
        let owners = Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin,
            proposal: parent.proposal.clone(),
            transferred: None,
        };
        let (_, next) = owners.planned_parent(&parent)?;
        let checkpoint = next.preparation_checkpoint(&owners.key)?;
        Ok(ParentPreparation {
            owners,
            parent: Some(parent),
            checkpoint,
            selection: None,
        })
    }
    pub(crate) fn prepare_transferred_parent(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        plan: TransferredAccountRootJournalPlan,
        expected_child: Option<[u8; 32]>,
    ) -> Result<ParentPreparation<'static>, DurableError> {
        let pin = plan.witness_pin()?.clone();
        let owners = Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin,
            proposal: plan.proposal().clone(),
            transferred: Some(Box::new(plan)),
        };
        let (next, selection) = owners.transferred_preparation()?;
        let checkpoint = next.preparation_checkpoint(&owners.key)?;
        if expected_child.is_some_and(|expected| expected != checkpoint) {
            return Err(DurableError::Conflict);
        }
        Ok(ParentPreparation {
            owners,
            parent: None,
            checkpoint,
            selection,
        })
    }
    // The caller holds and authenticates the independent enrollment parent. This
    // is deliberately not an external journal API accepting arbitrary history.
    pub(crate) fn resume_parent(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        pin: AnchorPin,
        parent: ParentCheckpoint<'_>,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin,
            proposal: parent.proposal.clone(),
            transferred: None,
        };
        owners.reconcile_parent(&parent)?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
