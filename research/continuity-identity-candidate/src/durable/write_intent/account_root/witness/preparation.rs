// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently retained context before a transferred account is frozen.
use super::*;
use crate::{AccountAuthorityCheckpoint, AnchorTransferredAccountReplacementPlan};
mod next_attempt;

/// Exact pre-freeze target, original logical Witness and independently retained
/// selection/history. Reconstruct the same value after restart; neither a network
/// response nor the current registry contents may choose these trust inputs.
/// This plan grants no traffic and does not approve the later complete freeze.
#[derive(Clone)]
pub struct TransferredAccountRootPreparation {
    pub(crate) target: AnchorTransferredAccountReplacementPlan,
    pub(crate) logical: AnchorPin,
    pub(crate) history: AnchorHandoffHistory,
    pub(crate) selection: Option<WitnessJournalAdoptionPlan>,
    transition: Option<Box<TransferredAccountRootJournalTransition>>,
}
impl TransferredAccountRootPreparation {
    pub(crate) fn original_checkpoint(
        &self,
        parent: [u8; 32],
        child: [u8; 32],
    ) -> Result<[u8; 32], DurableError> {
        let mut bytes = [
            parent,
            child,
            self.target.binding()?,
            self.history.checkpoint(),
            self.logical.binding(),
        ]
        .concat();
        if let Some(transition) = &self.transition {
            transition.next_plan().attempts().encode(&mut bytes)?;
        }
        Ok(digest(b"Q-PERIAPT-MANAGED-ROOT-ORIGINAL/v1", &bytes))
    }
    /// Bind an independently approved target to original local trust. A missing
    /// selection requires that the original journal has no Witness-selection row.
    /// An existing selection must be supplied exactly, including its lineage.
    pub fn new(
        target: AnchorTransferredAccountReplacementPlan,
        logical: AnchorPin,
        history: AnchorHandoffHistory,
        selection: Option<WitnessJournalAdoptionPlan>,
    ) -> Result<Self, DurableError> {
        target.check(&history)?;
        history.historical_pin(logical.binding())?;
        if let Some(selected) = &selection {
            selected.check_account_root_history(&logical, &history)?;
        }
        Ok(Self {
            target,
            logical,
            history,
            selection,
            transition: None,
        })
    }
    /// The original approved target and freeze request; never a fresh operation.
    pub fn target(&self) -> &AnchorTransferredAccountReplacementPlan {
        &self.target
    }
    pub(crate) fn current_pin(&self) -> Result<&AnchorPin, Error> {
        self.history
            .historical_pin(self.target.target().witness_binding())
    }
    pub(crate) fn bind(
        &self,
        approval: AnchorTransferredAccountReplacementApproval,
    ) -> Result<TransferredAccountRootJournalPlan, DurableError> {
        if let Some(transition) = &self.transition {
            self.check_approval(&approval)?;
            return Ok(transition.next_plan().clone());
        }
        TransferredAccountRootJournalPlan::new(
            self.logical.clone(),
            approval,
            self.history.clone(),
            self.selection.clone(),
        )
    }
    // Read only; this cannot create an authority descriptor or recover pending
    // work. The existing parent lease excludes a concurrent managed activation.
    pub(crate) fn check_original(
        &self,
        path: &Path,
        key: &JournalKey,
        original: &VerifiedDevice,
        journal: (JournalIdentity, [u8; 32]),
        registry: ([u8; 32], AccountAuthorityCheckpoint),
        fenced: bool,
    ) -> Result<[u8; 32], DurableError> {
        if original.account_id() != self.target.target().previous_account() {
            return Err(DurableError::Conflict);
        }
        if let Some(selected) = &self.selection {
            selected.check_original_enrollment_binding(
                original,
                journal.0,
                journal.1,
                self.logical.binding(),
            )?;
        }
        let db = open_private_database(path)?;
        let (image, pending) = load_pending_snapshot(
            &db,
            key,
            bootstrap::storage_owner(original),
            SnapshotAdmission::TransferredAccountRootReplacement,
        )?;
        if image.id != *journal.0.as_bytes()
            || !matches!(image.protection, Protection::Required { policy, .. } if policy == journal.1)
        {
            return Err(DurableError::Conflict);
        }
        crate::durable::account_authority::check_root_preparation(
            &image,
            match pending.as_ref() {
                Some(PendingIntent::Write(pending)) => Some(pending),
                Some(PendingIntent::Cancellation(_)) | None => None,
            },
            key,
            registry,
            self.target.target().authority_transition().2,
            self.logical.binding(),
        )?;
        let read = db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        if !fenced && table.get(ROW).map_err(storage)?.is_some() {
            return Err(DurableError::Conflict);
        }
        let wire = table.get(witness_handoff::ROW).map_err(storage)?;
        match (&self.selection, wire.as_ref()) {
            (None, None) => Ok(()),
            (Some(selected), Some(wire)) => {
                witness_handoff::check_account_root_selection(
                    key,
                    &image,
                    pending.as_ref(),
                    wire.value(),
                    selected,
                )?;
                Ok(())
            }
            _ => Err(DurableError::Conflict),
        }?;
        Ok(Self::original_child_checkpoint(
            &image.id,
            &image.owner,
            &image.digest,
            pending.as_ref().map(|p| p.wire()),
            wire.as_ref().map(|w| w.value()),
        ))
    }
    pub(in crate::durable::write_intent) fn original_child_checkpoint(
        id: &[u8; 32],
        owner: &[u8; 32],
        image: &[u8; 32],
        pending: Option<&[u8]>,
        selection: Option<&[u8]>,
    ) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(owner);
        bytes.extend_from_slice(image);
        for retained in [pending, selection] {
            bytes.push(u8::from(retained.is_some()));
            if let Some(value) = retained {
                bytes.extend_from_slice(&digest(
                    b"Q-PERIAPT-MANAGED-ROOT-ORIGINAL-RECORD/v1",
                    value,
                ));
            }
        }
        digest(b"Q-PERIAPT-MANAGED-ROOT-ORIGINAL-CHILD/v1", &bytes)
    }
}
