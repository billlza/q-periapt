// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The same original parent retains current account authority and exact child scope.
use super::*;
use crate::{
    AnchorAccountReplacementState, AnchorTransferredAccountDecision,
    TransferredAccountRootJournalPlan,
};
mod next_attempt;
mod transaction;

fn selected_binding(enrollment: &DeviceEnrollment) -> Result<Option<[u8; 32]>, DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let tx = active.database.begin_read().map_err(storage)?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    Ok(table
        .get(witness_handoff::ROW)
        .map_err(storage)?
        .map(|row| selection_binding(row.value())))
}
fn check_selection(
    plan: &TransferredAccountRootJournalPlan,
    selected: Option<&witness_handoff::State>,
) -> Result<(), DurableError> {
    match (plan.selection(), selected) {
        (None, None) => Ok(()),
        (Some(expected), Some(selected)) => selected.check_plan(expected),
        _ => Err(DurableError::Suspended),
    }
}
impl Owners {
    pub(super) fn check_authority(
        &self,
        snapshot: &EnrollmentSnapshot,
        original: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        match (&self.transferred, &self.state.authority) {
            (None, None) if self.state.selection.is_none() => Ok(()),
            (Some(plan), Some(binding))
                if binding == &plan.binding()?
                    && self.state.proposal == *plan.proposal()
                    && &self.state.attempts == plan.attempts() =>
            {
                let Phase::Accepted { admission, .. } = &snapshot.image.phase else {
                    return Err(DurableError::Suspended);
                };
                plan.check_parent(original, admission.journal, admission.policy)?;
                check_selection(plan, snapshot.witness_handoff.as_ref())
            }
            _ => Err(DurableError::Suspended),
        }
    }
    pub(super) fn outcome(
        &self,
        receipt: &[u8],
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        if let Some(plan) = &self.transferred {
            match plan.verify(receipt)?.state() {
                AnchorAccountReplacementState::Committed => {
                    Ok(AccountRootEnrollmentState::WitnessCommitted)
                }
                AnchorAccountReplacementState::Closed => {
                    Ok(AccountRootEnrollmentState::WitnessClosed)
                }
                AnchorAccountReplacementState::Unavailable => Err(DurableError::Corrupt),
            }
        } else {
            self.pin
                .verify_retired_account(&self.state.proposal, receipt)?;
            Ok(AccountRootEnrollmentState::WitnessCommitted)
        }
    }
    fn retain_current(&mut self, wire: &[u8]) -> Result<AccountRootEnrollmentState, DurableError> {
        self.read()?;
        self.transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .verify(wire)?;
        if self
            .state
            .receipt
            .as_deref()
            .is_some_and(|saved| saved != wire)
        {
            return Err(DurableError::Conflict);
        }
        self.journal
            .as_mut()
            .ok_or(DurableError::Closed)?
            .retain_account_decision(wire)?;
        if self.state.receipt.is_none() {
            let mut next = self.state.clone();
            next.receipt = Some(wire.to_vec());
            save(&self.enrollment, Some(&self.state), &next, "receipt")?;
            self.state = next;
        }
        self.read()?;
        self.outcome(wire)
    }
    fn reconcile_current_outcome(&mut self) -> Result<(), DurableError> {
        if let Some(wire) = self.state.receipt.clone() {
            self.retain_current(&wire)?;
        } else {
            let child = self.journal.as_mut().ok_or(DurableError::Closed)?;
            match child.status()? {
                crate::AccountRootJournalState::LocalFenced => {}
                crate::AccountRootJournalState::WitnessCommitted
                | crate::AccountRootJournalState::WitnessClosed => {
                    let wire = child.account_decision()?.as_bytes().to_vec();
                    self.retain_current(&wire)?;
                }
            }
        }
        Ok(())
    }
}
impl AccountRootEnrollmentRecovery {
    /// Authenticate and retain the exact purpose-37 outcome in child then parent.
    /// An error may follow either commit and closes both leases; resume this same
    /// original plan. Closed is permanent non-commit, never old-account permission.
    pub fn retain_account_decision(
        &mut self,
        wire: &[u8],
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)
            .and_then(|owners| owners.retain_current(wire));
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read only the exact retained historical decision. No signer or live owner.
    pub fn account_decision(&mut self) -> Result<AnchorTransferredAccountDecision, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            owners.read()?;
            let plan = owners.transferred.as_ref().ok_or(DurableError::Suspended)?;
            plan.verify(
                owners
                    .state
                    .receipt
                    .as_deref()
                    .ok_or(DurableError::Absent)?,
            )
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
