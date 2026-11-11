// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit next preparation, carrying its complete independently approved history.
use super::*;

impl TransferredAccountRootPreparation {
    /// Select this separately approved target after an authenticated permanent
    /// non-commit of the previous preparation. Both full approvals must bind the
    /// same original signed freeze. Retain these exact inputs for restart; neither
    /// the old closure nor this value admits traffic or creates storage.
    pub fn after_closed(
        mut self,
        previous: &Self,
        previous_approval: AnchorTransferredAccountReplacementApproval,
        approval: AnchorTransferredAccountReplacementApproval,
        frozen: &crate::AnchorFrozenAccount,
        closed: &[u8],
    ) -> Result<Self, DurableError> {
        if self.transition.is_some()
            || previous.target.bind(frozen, &previous.history)? != *previous_approval.proposal()
            || self.target.bind(frozen, &self.history)? != *approval.proposal()
        {
            return Err(DurableError::Conflict);
        }
        let old = previous.bind(previous_approval)?;
        let next = self.bind(approval)?;
        self.transition = Some(Box::new(TransferredAccountRootJournalTransition::verify(
            old, next, closed,
        )?));
        Ok(self)
    }
    pub(crate) fn check_approval(
        &self,
        approval: &AnchorTransferredAccountReplacementApproval,
    ) -> Result<(), DurableError> {
        if self
            .transition
            .as_ref()
            .is_some_and(|transition| transition.next_plan().approval() != approval)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn transition(&self) -> Option<&TransferredAccountRootJournalTransition> {
        self.transition.as_deref()
    }
}
