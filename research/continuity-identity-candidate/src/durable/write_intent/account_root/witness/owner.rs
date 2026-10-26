// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Match the exact approved authority and retained selection on every read.
use super::*;
impl Owners {
    pub(in crate::durable::write_intent::account_root) fn transferred_preparation(
        &self,
    ) -> Result<(Fence, Option<crate::durable::WitnessSelectionProgress>), DurableError> {
        let plan = self.transferred.as_ref().ok_or(DurableError::Suspended)?;
        let (image, pending) =
            load_pending_snapshot(&self.db, &self.key, self.owner, self.admission())?;
        if image.id != *self.identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let next = self.new_fence(&image, pending.as_ref())?;
        let read = self.db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        if table.get(ROW).map_err(storage)?.is_some() {
            self.read()?;
        }
        let progress = match plan.selection() {
            Some(selected) => {
                let row = table
                    .get(witness_handoff::ROW)
                    .map_err(storage)?
                    .ok_or(DurableError::Suspended)?;
                Some(witness_handoff::check_account_root_selection(
                    &self.key,
                    &image,
                    pending.as_ref(),
                    row.value(),
                    selected,
                )?)
            }
            None => None,
        };
        Ok((next, progress))
    }
    pub(in crate::durable::write_intent::account_root) fn admission(
        &self,
    ) -> SnapshotAdmission<'_> {
        if self.transferred.is_some() {
            SnapshotAdmission::TransferredAccountRootReplacement
        } else {
            SnapshotAdmission::AccountRootReplacement
        }
    }
    fn selection(
        &self,
        plan: &TransferredAccountRootJournalPlan,
        image: &Image,
        pending: Option<&PendingIntent>,
    ) -> Result<Option<[u8; 32]>, DurableError> {
        let read = self.db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let wire = table.get(witness_handoff::ROW).map_err(storage)?;
        match (&plan.selection, wire) {
            (None, None) => Ok(None),
            (Some(selected), Some(wire)) => {
                witness_handoff::check_account_root_selection(
                    &self.key,
                    image,
                    pending,
                    wire.value(),
                    selected,
                )?;
                Ok(Some(selection_digest(wire.value())))
            }
            _ => Err(DurableError::Suspended),
        }
    }
    pub(in crate::durable::write_intent::account_root) fn new_fence(
        &self,
        image: &Image,
        pending: Option<&PendingIntent>,
    ) -> Result<Fence, DurableError> {
        let Some(plan) = &self.transferred else {
            return Fence::new(&self.key, image, pending, self.proposal.clone());
        };
        Ok(Fence {
            subject: subject(
                &self.key,
                image,
                pending,
                &self.proposal,
                Some(plan.logical.binding()),
            )?,
            image: image.digest,
            pending: pending.map(|p| pending_digest(p.wire())),
            proposal: self.proposal.clone(),
            receipt: None,
            history: Vec::new(),
            authority: Some(plan.binding()?),
            selection: self.selection(plan, image, pending)?,
        })
    }
    pub(in crate::durable::write_intent::account_root) fn check_authority(
        &self,
        fence: &Fence,
    ) -> Result<(), DurableError> {
        match &self.transferred {
            None if fence.authority.is_none() && fence.selection.is_none() => Ok(()),
            Some(plan)
                if fence.authority.as_ref() == Some(&plan.binding()?)
                    && fence.proposal == *plan.proposal() =>
            {
                let (image, pending) =
                    load_pending_snapshot(&self.db, &self.key, self.owner, self.admission())?;
                if self.selection(plan, &image, pending.as_ref())? != fence.selection {
                    return Err(DurableError::Conflict);
                }
                Ok(())
            }
            _ => Err(DurableError::Suspended),
        }
    }
    pub(in crate::durable::write_intent::account_root) fn verify_outcome(
        &self,
        wire: &[u8],
    ) -> Result<AccountRootJournalState, DurableError> {
        if let Some(plan) = &self.transferred {
            match plan.verify(wire)?.state() {
                crate::AnchorAccountReplacementState::Committed => {
                    Ok(AccountRootJournalState::WitnessCommitted)
                }
                crate::AnchorAccountReplacementState::Closed => {
                    Ok(AccountRootJournalState::WitnessClosed)
                }
                crate::AnchorAccountReplacementState::Unavailable => Err(DurableError::Corrupt),
            }
        } else {
            self.pin.verify_retired_account(&self.proposal, wire)?;
            Ok(AccountRootJournalState::WitnessCommitted)
        }
    }
    pub(in crate::durable::write_intent::account_root) fn verified_retirement(
        &self,
        wire: &[u8],
    ) -> Result<AnchorRetiredAccount, DurableError> {
        if let Some(plan) = &self.transferred {
            Ok(plan.verify(wire)?.retirement()?)
        } else {
            Ok(self.pin.verify_retired_account(&self.proposal, wire)?)
        }
    }
}
