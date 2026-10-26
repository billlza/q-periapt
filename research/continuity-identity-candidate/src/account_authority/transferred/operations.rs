// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl AccountAuthorityStore {
    /// Persist the exact independently approved current-Witness target before
    /// freezing its previous account. The original registry binding and logical
    /// journal Witness are retained; this application alone is revoked before I/O.
    /// An error may follow commit: reopen the same registry and retry the same plan.
    pub fn begin_transferred_preparation(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        history: &AnchorHandoffHistory,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        self.prepare_transferred(expected, plan, history, None)
    }
    pub(crate) fn begin_managed_transferred_preparation(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        history: &AnchorHandoffHistory,
        checkpoint: [u8; 32],
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        crate::codec::nonzero(&checkpoint)?;
        self.prepare_transferred(expected, plan, history, Some(checkpoint))
    }
    pub(crate) fn managed_transferred_checkpoint(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<[u8; 32], DurableError> {
        self.active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Conflict)?
            .managed
            .ok_or(DurableError::Suspended)
    }
    fn prepare_transferred(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        plan: Plan,
        history: &AnchorHandoffHistory,
        managed: Option<[u8; 32]>,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        plan.check(history)?;
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        if let Some(old) = image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == plan.operation())
        {
            let transfer = old.transferred.as_ref().ok_or(DurableError::Conflict)?;
            if old.application != expected.application
                || old.revision != expected.revision
                || old.proposal.previous_account() != expected.account
                || transfer.plan != plan
                || transfer.managed != managed
            {
                return Err(DurableError::Conflict);
            }
            // Check the exact historical prefix against retained history as well;
            // a different incoming branch cannot replace the original intent.
            transfer
                .plan
                .check(image.history.as_ref().ok_or(DurableError::Corrupt)?)?;
            return Ok(old.state());
        }
        history.require_current(plan.target().witness_binding())?;
        let current = image.current(self.family, &self.pin)?;
        let selected = current
            .get(&expected.application)
            .ok_or(DurableError::Absent)?;
        if selected.checkpoint != expected
            || plan.target().previous_account() != expected.account
            || plan.target().authority_transition().2 != self.family
            || image.root_seen(plan.target().successor_account())
        {
            return Err(DurableError::Conflict);
        }
        selected.admit_next(plan.target(), Some(plan.request()), false)?;
        let logical = selected.witness;
        history.historical_pin(logical)?;
        if image.replacements.len() == MAX_REPLACEMENTS {
            return Err(DurableError::Capacity);
        }
        image.retain_history(history, &self.pin)?;
        image.replacements.push(Replacement {
            application: expected.application,
            revision: expected.revision,
            proposal: plan.target().clone(),
            preparation: None,
            decision: Decision::Pending,
            transferred: Some(Box::new(Record {
                logical,
                plan,
                frozen: None,
                approval: None,
                receipt: None,
                managed,
            })),
        });
        self.save(image, expected.application)?;
        Ok(AccountAuthorityReplacementState::Preparing)
    }
    /// Recover only the original retained transferred target and request. This
    /// historical observation does not approve a different target or release traffic.
    pub fn transferred_preparation(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<
        (
            ApplicationAccountId,
            AccountAuthorityReplacementState,
            &Plan,
        ),
        DurableError,
    > {
        let image = &self.active.as_ref().ok_or(DurableError::Closed)?.image;
        let record = image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let transfer = record.transferred.as_ref().ok_or(DurableError::Conflict)?;
        Ok((record.application, record.state(), &transfer.plan))
    }
    /// Bind the actual signed full freeze and separately approved exact root
    /// transition to the original preparation. Both accounts stay fenced. Wrong
    /// proofs fail before I/O; uncertain writes require exact original recovery.
    pub fn bind_transferred_preparation(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
        approval: Approval,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let history = image.history.as_ref().ok_or(DurableError::Conflict)?;
        let record = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let transfer = record.transferred.as_mut().ok_or(DurableError::Conflict)?;
        let proposal = transfer.plan.bind(frozen, history)?;
        approval.check_retained_history(history)?;
        if approval.proposal() != &proposal {
            return Err(DurableError::Conflict);
        }
        if let Some(saved) = &transfer.approval {
            if saved != &approval
                || transfer.frozen.as_ref() != Some(frozen)
                || record.proposal != proposal
            {
                return Err(DurableError::Conflict);
            }
            return Ok(record.state());
        }
        record.proposal = proposal;
        transfer.frozen = Some(frozen.clone());
        transfer.approval = Some(approval);
        let application = record.application;
        self.save(image, application)?;
        Ok(AccountAuthorityReplacementState::Pending)
    }
    /// Original independently retained exact approval, never a fresh account grant.
    pub fn transferred_approval(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<&Approval, DurableError> {
        let image = &self.active.as_ref().ok_or(DurableError::Closed)?.image;
        image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Conflict)?
            .approval
            .as_ref()
            .ok_or(DurableError::Suspended)
    }
    /// Retain exact purpose-37 decision bytes before publishing a new mapping.
    /// Committed advances this application once and selects its target Witness;
    /// Closed permanently fences both roots. This does not activate a device.
    pub fn retain_transferred_account_decision(
        &mut self,
        operation: AnchorAccountReplacementId,
        bytes: &[u8],
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let history = image.history.as_ref().ok_or(DurableError::Conflict)?;
        let record = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let transfer = record.transferred.as_mut().ok_or(DurableError::Conflict)?;
        let approval = transfer.approval.as_ref().ok_or(DurableError::Suspended)?;
        let decision = approval.verify_decision(history, bytes)?;
        if let Some(saved) = &transfer.receipt {
            if saved != bytes {
                return Err(DurableError::Conflict);
            }
            return Ok(record.state());
        }
        record.decision = state(decision.state())?;
        transfer.receipt = Some(bytes.to_vec());
        let result = record.state();
        let application = record.application;
        self.save(image, application)?;
        Ok(result)
    }
    /// Reverify the exact retained historical decision without a private signer or
    /// live credential clock. Absence never authorizes fallback or a new operation.
    pub fn transferred_account_decision(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        let image = &self.active.as_ref().ok_or(DurableError::Closed)?.image;
        let record = image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        let transfer = record.transferred.as_ref().ok_or(DurableError::Conflict)?;
        transfer
            .approval
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .verify_decision(
                image.history.as_ref().ok_or(DurableError::Corrupt)?,
                transfer.receipt.as_deref().ok_or(DurableError::Suspended)?,
            )
    }
}
