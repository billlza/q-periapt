// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original local intent precedes witness freezing and revokes cached authority.
use super::*;
use crate::AnchorFrozenAccount;
impl Replacement {
    pub(super) fn state(&self) -> AccountAuthorityReplacementState {
        if self.decision.closed() {
            AccountAuthorityReplacementState::Closed
        } else if self.decision.committed() {
            AccountAuthorityReplacementState::Committed
        } else if self
            .preparation
            .as_ref()
            .is_some_and(|plan| plan.target() == &self.proposal)
        {
            AccountAuthorityReplacementState::Preparing
        } else {
            AccountAuthorityReplacementState::Pending
        }
    }
}
impl AccountAuthorityStore {
    pub(super) fn begin_operation(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        proposal: Proposal,
        preparation: Option<AnchorAccountReplacementPlan>,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        if let Some(old) = image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == proposal.operation())
        {
            if old.application != expected.application
                || old.revision != expected.revision
                || match &preparation {
                    Some(plan) => old.preparation.as_ref() != Some(plan),
                    None => old.preparation.is_some() || old.proposal != proposal,
                }
                || proposal.previous_account() != expected.account
            {
                return Err(DurableError::Conflict);
            }
            return Ok(old.state());
        }
        let current = image.current(self.family, &self.pin)?;
        let selected = current
            .get(&expected.application)
            .ok_or(DurableError::Absent)?;
        if selected.checkpoint != expected || proposal.previous_account() != expected.account {
            return Err(DurableError::Conflict);
        }
        selected.admit_next(&proposal, preparation.as_ref(), false)?;
        let (_, successor, family, _) = proposal.authority_transition();
        if family != self.family
            || proposal.witness_binding() != self.pin.binding()
            || successor.shares_component(self.pin.public_key())
            || image.root_seen(proposal.successor_account())
        {
            return Err(DurableError::Conflict);
        }
        if image.replacements.len() == MAX_REPLACEMENTS {
            return Err(DurableError::Capacity);
        }
        let record = Replacement {
            application: expected.application,
            revision: expected.revision,
            proposal,
            preparation,
            decision: Decision::Pending,
        };
        let state = record.state();
        image.replacements.push(record);
        image.current(self.family, &self.pin)?;
        self.save(image, expected.application)?;
        Ok(state)
    }

    /// Persist the original independent target approval and freeze request BEFORE
    /// contacting the witness. All old leases are revoked before persistence.
    /// Errors may follow commit: reopen this registry and retry this exact plan.
    /// No journal fence, witness commitment or successor enrollment is implied.
    pub fn begin_preparation(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        plan: AnchorAccountReplacementPlan,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        self.begin_operation(expected, plan.target().clone(), Some(plan))
    }
    /// Recover the same original plan, including after binding or commitment.
    /// The reported state is history; it never grants current traffic permission.
    pub fn preparation(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<
        (
            ApplicationAccountId,
            AccountAuthorityReplacementState,
            &AnchorAccountReplacementPlan,
        ),
        DurableError,
    > {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let record = active
            .image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let plan = record.preparation.as_ref().ok_or(DurableError::Conflict)?;
        Ok((record.application, record.state(), plan))
    }
    /// Bind the exact authenticated witness freeze to the retained target. This
    /// produces a pending exact proposal, while both roots remain fenced locally.
    /// Reopen and retry this same proof on uncertain persistence; another snapshot,
    /// request or target cannot silently replace the original operation.
    pub fn bind_preparation(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let record = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let plan = record.preparation.as_ref().ok_or(DurableError::Conflict)?;
        let bound = plan.bind(frozen)?;
        if record.state() != AccountAuthorityReplacementState::Preparing {
            return if record.proposal == bound {
                Ok(record.state())
            } else {
                Err(DurableError::Conflict)
            };
        }
        record.proposal = bound;
        let application = record.application;
        self.save(image, application)?;
        Ok(AccountAuthorityReplacementState::Pending)
    }
}
