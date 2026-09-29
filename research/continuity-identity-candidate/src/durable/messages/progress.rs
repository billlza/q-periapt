// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed progress accounting, separate from message delivery or key secrecy.
use super::*;
use crate::ApplicationSendBudget;

/// Authenticated local accounting, not a grant to send or a recovery claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendProgress {
    /// Highest locally completed rekey exchange, anchoring the current window.
    pub confirmed_epoch: u64,
    /// Traffic epoch used for a new or already reserved outgoing message.
    pub sending_epoch: u64,
    /// Immutable policy-authority-selected allowance.
    pub limit: u16,
    /// Committed sends across the completed and any unconfirmed sending epoch.
    pub committed: u16,
    /// Whether the current immutable input reservation occupies one more slot.
    pub reserved: bool,
    /// Slots available for new input; existing exact work keeps its admitted slot.
    pub remaining: u16,
}

impl State {
    pub(super) fn send_progress(
        &self,
        budget: ApplicationSendBudget,
    ) -> Result<SendProgress, Error> {
        let limit = u64::from(budget.messages());
        self.control.validate_budget(budget.messages())?;
        let confirmed = self.control.confirmed_epoch();
        if confirmed > self.send_epoch
            || self.send_epoch.checked_sub(confirmed).ok_or(Error::State)? > 1
        {
            return Err(Error::State);
        }
        // Old receipts and signed peer close counts remain bounded too. Removing
        // an outbox or resolving an old epoch must not make an invalid count valid.
        for traffic in self.epochs.values() {
            if traffic.sent > limit
                || traffic.received > limit
                || traffic.receive_limit.is_some_and(|count| count > limit)
                || (traffic.pending.is_some() && traffic.sent == limit)
            {
                return Err(Error::State);
            }
        }
        let mut spent = 0_u64;
        for epoch in confirmed..=self.send_epoch {
            spent = spent
                .checked_add(self.traffic(epoch)?.sent)
                .ok_or(Error::State)?;
        }
        let reserved = self.traffic(self.send_epoch)?.pending.is_some();
        let allocated = spent.checked_add(u64::from(reserved)).ok_or(Error::State)?;
        let remaining = limit.checked_sub(allocated).ok_or(Error::State)?;
        Ok(SendProgress {
            confirmed_epoch: confirmed,
            sending_epoch: self.send_epoch,
            limit: budget.messages(),
            committed: spent.try_into().map_err(|_| Error::State)?,
            reserved,
            remaining: remaining.try_into().map_err(|_| Error::State)?,
        })
    }
}

impl DeviceJournal {
    /// Inspect the exact send window without releasing data or granting authority.
    /// Reconciliation remains possible after policy expiry/close or roster removal.
    pub fn application_send_progress(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<SendProgress, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(state.send_progress(context.policy().application_send_budget())?)
    }
}
