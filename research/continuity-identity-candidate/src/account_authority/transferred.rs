// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transferred account intent in the original registry, with per-account scope.
use super::*;
use crate::{
    AnchorAccountFreezeRequest, AnchorAccountReplacementState as WitnessState, AnchorFrozenAccount,
    AnchorHandoffHistory, AnchorTransferredAccountDecision,
    AnchorTransferredAccountReplacementApproval as Approval,
    AnchorTransferredAccountReplacementPlan as Plan,
};
pub(super) mod codec;
mod operations;

#[derive(Clone)]
pub(super) struct Record {
    pub(super) logical: [u8; 32],
    pub(super) plan: Plan,
    pub(super) frozen: Option<AnchorFrozenAccount>,
    pub(super) approval: Option<Approval>,
    pub(super) receipt: Option<Vec<u8>>,
}
impl Replacement {
    pub(super) fn preparation_request(&self) -> Option<&AnchorAccountFreezeRequest> {
        match (&self.preparation, &self.transferred) {
            (Some(plan), None) => Some(plan.request()),
            (None, Some(record)) => Some(record.plan.request()),
            _ => None,
        }
    }
}
impl Record {
    fn check(
        &self,
        record: &Replacement,
        history: &AnchorHandoffHistory,
    ) -> Result<(), DurableError> {
        self.plan.check(history)?;
        history.historical_pin(self.logical)?;
        if record.preparation.is_some() {
            return Err(DurableError::Corrupt);
        }
        match (&self.frozen, &self.approval, &self.receipt) {
            (None, None, None)
                if record.decision == Decision::Pending
                    && &record.proposal == self.plan.target() =>
            {
                Ok(())
            }
            (Some(frozen), Some(approval), receipt) => {
                if self.plan.bind(frozen, history)? != record.proposal
                    || approval.proposal() != &record.proposal
                {
                    return Err(DurableError::Corrupt);
                }
                approval.check_retained_history(history)?;
                match receipt {
                    None if record.decision == Decision::Pending => Ok(()),
                    Some(bytes) => {
                        let decision = approval.verify_decision(history, bytes)?;
                        if state(decision.state())? != record.decision {
                            return Err(DurableError::Corrupt);
                        }
                        Ok(())
                    }
                    _ => Err(DurableError::Corrupt),
                }
            }
            _ => Err(DurableError::Corrupt),
        }
    }
}
fn state(value: WitnessState) -> Result<Decision, DurableError> {
    match value {
        WitnessState::Committed => Ok(Decision::Committed),
        WitnessState::Closed => Ok(Decision::ClosedExact),
        WitnessState::Unavailable => Err(DurableError::Corrupt),
    }
}
impl Image {
    pub(super) fn check_history(&self, original: &AnchorPin) -> Result<(), DurableError> {
        let transferred = self.replacements.iter().any(|r| r.transferred.is_some());
        match &self.history {
            None if !transferred => Ok(()),
            Some(history) if transferred && history.sequence() > 0 => {
                let pin = history.historical_pin(original.binding())?;
                if pin.identity() != original.identity()
                    || pin.public_key() != original.public_key()
                {
                    return Err(DurableError::Conflict);
                }
                Ok(())
            }
            _ => Err(DurableError::Corrupt),
        }
    }
    pub(super) fn resolve_witness<'a>(
        &'a self,
        binding: [u8; 32],
        original: &'a AnchorPin,
    ) -> Result<&'a AnchorPin, DurableError> {
        if binding == original.binding() {
            return Ok(original);
        }
        Ok(self
            .history
            .as_ref()
            .ok_or(DurableError::Corrupt)?
            .historical_pin(binding)?)
    }
    pub(super) fn record_witness<'a>(
        &'a self,
        record: &Replacement,
        selected: &Current,
        original: &'a AnchorPin,
    ) -> Result<&'a AnchorPin, DurableError> {
        match &record.transferred {
            None => self.resolve_witness(selected.witness, original),
            Some(transfer) => {
                let history = self.history.as_ref().ok_or(DurableError::Corrupt)?;
                if transfer.logical != selected.witness {
                    return Err(DurableError::Corrupt);
                }
                transfer.check(record, history)?;
                Ok(history.historical_pin(record.proposal.witness_binding())?)
            }
        }
    }
    // Only fresh operations use the current endpoint. Historical records retain
    // the original signer and are validated by record_witness above.
    pub(super) fn require_current_witness(&self, witness: [u8; 32]) -> Result<(), DurableError> {
        if let Some(history) = &self.history {
            history.require_current(witness)?;
        }
        Ok(())
    }
    fn retain_history(
        &mut self,
        history: &AnchorHandoffHistory,
        original: &AnchorPin,
    ) -> Result<(), DurableError> {
        let pin = history.historical_pin(original.binding())?;
        if pin.identity() != original.identity()
            || pin.public_key() != original.public_key()
            || history.sequence() == 0
        {
            return Err(DurableError::Conflict);
        }
        if let Some(prior) = &self.history {
            if prior.to_bytes()? == history.to_bytes()? {
                return Ok(());
            }
            history.require_extension_of(prior)?;
        }
        self.history = Some(history.clone());
        Ok(())
    }
}
