// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Current account authority never rewrites the original logical Witness binding.
use super::*;
mod owner;
mod preparation;
pub use preparation::TransferredAccountRootPreparation;
mod transaction;
use crate::{
    AnchorHandoffHistory, AnchorTransferredAccountDecision,
    AnchorTransferredAccountReplacementApproval, WitnessJournalAdoptionPlan,
};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Binding {
    pub(crate) logical: [u8; 32],
    approval: [u8; 32],
    history: [u8; 32],
}
impl Binding {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        for value in [self.logical, self.approval, self.history] {
            crate::codec::nonzero(&value)?;
            out.extend_from_slice(&value);
        }
        Ok(())
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let value = Self {
            logical: d.array()?,
            approval: d.array()?,
            history: d.array()?,
        };
        for field in [value.logical, value.approval, value.history] {
            crate::codec::nonzero(&field)?;
        }
        Ok(value)
    }
}
pub(super) fn selection_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-ACCOUNT-ROOT-WITNESS-SELECTION/v1", wire)
}

/// Independently retained account recovery approval and original Witness context.
/// `selection: None` explicitly requires that no Witness-selection row exists.
/// A supplied selection must match its exact prepared/adopted lineage. Neither
/// case admits traffic, resolves pending work or supplies account authentication.
#[derive(Clone)]
pub struct TransferredAccountRootJournalPlan {
    logical: AnchorPin,
    approval: AnchorTransferredAccountReplacementApproval,
    history: AnchorHandoffHistory,
    selection: Option<WitnessJournalAdoptionPlan>,
}
impl TransferredAccountRootJournalPlan {
    /// The host supplies authenticated original trust, the exact approved full
    /// account transition and independently verified history. Retain this same
    /// context for restart; a later history is not an interchangeable expectation.
    pub fn new(
        logical: AnchorPin,
        approval: AnchorTransferredAccountReplacementApproval,
        history: AnchorHandoffHistory,
        selection: Option<WitnessJournalAdoptionPlan>,
    ) -> Result<Self, DurableError> {
        approval.check_retained_history(&history)?;
        history.historical_pin(logical.binding())?;
        if let Some(selected) = &selection {
            selected.check_account_root_history(&logical, &history)?;
        }
        Ok(Self {
            logical,
            approval,
            history,
            selection,
        })
    }
    /// Exact approved successor and complete frozen account; not a decision.
    pub fn proposal(&self) -> &Proposal {
        self.approval.proposal()
    }
    pub(crate) fn binding(&self) -> Result<Binding, DurableError> {
        Ok(Binding {
            logical: self.logical.binding(),
            approval: digest(
                b"Q-PERIAPT-ACCOUNT-ROOT-CURRENT-APPROVAL/v1",
                &self.approval.to_bytes()?,
            ),
            history: self.history.checkpoint(),
        })
    }
    pub(crate) fn verify(
        &self,
        wire: &[u8],
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        self.approval.verify_decision(&self.history, wire)
    }
    pub(crate) fn selection(&self) -> Option<&WitnessJournalAdoptionPlan> {
        self.selection.as_ref()
    }
    pub(crate) fn witness_pin(&self) -> Result<&AnchorPin, Error> {
        self.history
            .historical_pin(self.proposal().witness_binding())
    }
    pub(crate) fn check_parent(
        &self,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        policy: [u8; 32],
    ) -> Result<(), DurableError> {
        if self.proposal().previous_account() != original.account_id()
            || !self.proposal().predecessors().any(|s| {
                s.journal_parts()
                    == (
                        *identity.as_bytes(),
                        bootstrap::storage_owner(original),
                        policy,
                    )
            })
        {
            return Err(Error::Scope.into());
        }
        if let Some(selected) = &self.selection {
            selected.check_original_enrollment_binding(
                original,
                identity,
                policy,
                self.logical.binding(),
            )?;
        }
        Ok(())
    }
}
