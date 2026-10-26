// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Atomic complete-account retirement or permanent closure, with exact proof retention.
use super::*;
impl AnchorStore {
    fn account_decision_history(&self) -> Result<&AnchorHandoffHistory, DurableError> {
        Ok(self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .history())
    }
    /// Observe a fresh exact successor against the original committed full freeze.
    /// This is not account recovery approval or a retirement. The host independently
    /// authenticates recovery authority and pins both roots and the target policy.
    pub fn transferred_account_replacement_proposal(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
        now: u64,
    ) -> Result<AnchorAccountReplacementProposal, DurableError> {
        let current = self.pin()?;
        let history = self.account_decision_history()?;
        if history.checkpoint() != m.history.checkpoint()
            || history.namespace_binding() != m.history.namespace_binding()
        {
            return Err(Error::Scope.into());
        }
        let validity = self.admit_enrollment(m.genesis.subject, m.device, m.policy, now)?;
        let image = self.image()?;
        if image
            .account_freezes
            .get(&crate::identity::account_id(m.previous_root))
            != Some(frozen)
        {
            return Err(Error::Scope.into());
        }
        let p = Target {
            genesis: m.genesis,
            device: m.device,
            policy: m.policy,
            pin: &current,
        }
        .proposal(
            operation,
            (m.previous_root, Some(frozen.binding()?)),
            validity,
            frozen.subjects().collect(),
        )?;
        image.check_new_account_replacement_at(&p, m.history)?;
        Ok(p)
    }

    /// Permanently retire every previous-account subject and enroll only the
    /// independently approved target, with the original signed decision in the same
    /// transaction. Check target runtime/policy/credential and trusted time again
    /// at commit. Unknown commit requires reopening this exact store and approval.
    /// Exact retries, including an already Closed attempt, are historical and do
    /// not consult the clock, re-sign, rewrite state or release an operating owner.
    pub fn replace_transferred_account_root(
        &mut self,
        a: &AnchorTransferredAccountReplacementApproval,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
        mut trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        a.check_materials(m)?;
        let mut image = self.image()?;
        let history = self.account_decision_history()?;
        a.check(history)?;
        if let Some(r) = image.account_decisions.get(a.proposal.operation.as_bytes()) {
            return r.decision(a);
        }
        history.require_current(a.proposal.witness)?;
        image.check_new_account_replacement_at(&a.proposal, history)?;
        check_capacity(&image, a, true)?;
        let admitted = trusted_time()?;
        a.scope.validity.check(admitted)?;
        let validity = self.admit_enrollment(m.genesis.subject, m.device, m.policy, admitted)?;
        if validity != a.proposal.validity {
            return Err(Error::Scope.into());
        }
        let pin = self.pin()?;
        let signer = &self.active.as_ref().ok_or(DurableError::Closed)?.signer;
        let record = Record::sign(a, Some(admitted), signer)?;
        let decision = a.verify_decision(self.account_decision_history()?, record.as_bytes())?;
        image.entries.insert(
            a.proposal.target.id(&image.namespace),
            Entry::at_genesis(
                a.proposal.target,
                a.proposal.genesis,
                m.device,
                a.proposal.validity,
            )?,
        );
        image
            .account_replacements
            .insert(a.proposal.previous_account(), a.proposal.clone());
        image
            .account_decisions
            .insert(*a.proposal.operation.as_bytes(), record);
        self.persist_image_checked(&mut image, true, || {
            let now = trusted_time()?;
            if now < admitted {
                return Err(Error::Scope.into());
            }
            a.scope.validity.check(now)?;
            if admit_device_at(&pin, m.device, m.policy, now, pin.binding)? != a.proposal.validity {
                return Err(Error::Scope.into());
            }
            Ok(())
        })?;
        Ok(decision)
    }

    /// Permanently close exactly this approved attempt, even after target expiry.
    /// This never unfreezes the account or changes a previously committed outcome.
    /// Fresh closure requires its approved current Witness; a later Witness may
    /// only return an already retained decision under this original approval.
    pub fn close_transferred_account_replacement(
        &mut self,
        a: &AnchorTransferredAccountReplacementApproval,
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        let mut image = self.image()?;
        let history = self.account_decision_history()?;
        a.check(history)?;
        if let Some(r) = image.account_decisions.get(a.proposal.operation.as_bytes()) {
            return r.decision(a);
        }
        history.require_current(a.proposal.witness)?;
        image.check_preparation(&a.proposal)?;
        if image
            .account_closures
            .contains_key(a.proposal.operation.as_bytes())
            || image
                .account_replacements
                .values()
                .any(|p| p.operation == a.proposal.operation)
        {
            return Err(DurableError::Conflict);
        }
        check_capacity(&image, a, false)?;
        let signer = &self.active.as_ref().ok_or(DurableError::Closed)?.signer;
        let record = Record::sign(a, None, signer)?;
        let decision = a.verify_decision(history, record.as_bytes())?;
        image
            .account_decisions
            .insert(*a.proposal.operation.as_bytes(), record);
        self.persist(&mut image)?;
        Ok(decision)
    }
    /// Recover only this exact committed/closed decision. Absence is not authority
    /// to reset state or fall back to the old account. No private re-signing occurs.
    pub fn transferred_account_decision(
        &mut self,
        a: &AnchorTransferredAccountReplacementApproval,
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        let image = self.image()?;
        a.check(self.account_decision_history()?)?;
        image
            .account_decisions
            .get(a.proposal.operation.as_bytes())
            .ok_or(DurableError::Absent)?
            .decision(a)
    }
}
fn check_capacity(
    image: &Image,
    a: &AnchorTransferredAccountReplacementApproval,
    commit: bool,
) -> Result<(), DurableError> {
    if image.account_decisions.len() >= MAX_ENTRIES
        || (commit
            && (image.entries.len() >= MAX_ENTRIES
                || image.account_replacements.len() >= MAX_ENTRIES))
    {
        return Err(DurableError::Capacity);
    }
    if image
        .account_decisions
        .values()
        .any(|r| r.decision_id() == a.scope.decision)
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
