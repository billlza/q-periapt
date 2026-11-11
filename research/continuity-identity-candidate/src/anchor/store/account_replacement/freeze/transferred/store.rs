// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Commit the exact approved account freeze and original proof in one image.
use super::*;
impl AnchorStore {
    fn transferred_freeze_history(&self) -> Result<&AnchorHandoffHistory, DurableError> {
        Ok(self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .history())
    }
    /// Observe every account subject under independently retained current history.
    /// No client adoption is required: recovery must include lost/offline devices.
    /// This read-only proposal is not approval, a freeze or a signed receipt.
    pub fn transferred_account_freeze_proposal(
        &mut self,
        request: &AnchorAccountFreezeRequest,
        history: &AnchorHandoffHistory,
    ) -> Result<AnchorTransferredAccountFreezeProposal, DurableError> {
        request.check_pin(&self.pin()?)?;
        let actual = self.transferred_freeze_history()?;
        if actual.checkpoint() != history.checkpoint()
            || actual.namespace_binding() != history.namespace_binding()
        {
            return Err(Error::Scope.into());
        }
        let image = self.image()?;
        image.require_account_live(request.account())?;
        let frozen = AnchorFrozenAccount {
            request: request.clone(),
            subjects: image.account_snapshot_at(request.account(), request.witness, history)?,
            transfer: None,
        };
        let proposal = AnchorTransferredAccountFreezeProposal {
            frozen,
            namespace: history.namespace_binding(),
            history: history.checkpoint(),
        };
        proposal.check(history)?;
        Ok(proposal)
    }
    /// Atomically freeze the independently approved exact full account snapshot
    /// and retain its original current-Witness proof. New commitment checks trusted
    /// time before signing and immediately before commit. Storage/commit failure
    /// closes the owner and may follow commit; recover the original exact approval.
    /// Committed retries preserve signature bytes and never consult the clock.
    pub fn freeze_transferred_account(
        &mut self,
        approval: &AnchorTransferredAccountFreezeApproval,
        mut trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let history = self.transferred_freeze_history()?;
        approval.proposal.check(history)?;
        let request = approval.proposal.request();
        if let Some(saved) = image.account_freezes.get(&request.account()) {
            let wire = saved.to_bytes()?;
            approval.verify_receipt(history, &wire)?;
            return Ok(wire);
        }
        history.require_current(request.witness)?;
        image.require_account_live(request.account())?;
        if image.account_freezes.values().any(|f| {
            f.request.operation == request.operation
                || f.transfer
                    .as_ref()
                    .is_some_and(|p| p.scope.decision == approval.decision)
        }) {
            return Err(DurableError::Conflict);
        }
        if image.account_freezes.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        if image.account_snapshot_at(request.account(), request.witness, history)?
            != approval.proposal.frozen.subjects
        {
            return Err(DurableError::Conflict);
        }
        let admitted = trusted_time()?;
        approval.validity.check(admitted)?;
        let mut frozen = approval.proposal.frozen.clone();
        let mut proof = Proof {
            scope: approval.scope(),
            admitted,
            wire: Vec::new(),
        };
        let body = proof.body(&frozen)?;
        let signer = &self.active.as_ref().ok_or(DurableError::Closed)?.signer;
        let signature = signer.sign(Purpose::AnchorTransferredAccountFreeze, &body)?;
        proof.wire = envelope(&body, &signature)?;
        frozen.transfer = Some(Box::new(proof));
        let wire = frozen.to_bytes()?;
        approval.verify_receipt(history, &wire)?;
        image.account_freezes.insert(request.account(), frozen);
        self.persist_image_checked(&mut image, true, || {
            let now = trusted_time()?;
            if now < admitted {
                return Err(Error::Scope.into());
            }
            approval.validity.check(now)?;
            Ok(())
        })?;
        Ok(wire)
    }
    /// Observe only the exact already committed freeze, including after another
    /// Witness transfer or approval expiry. Absence never permits old traffic.
    pub fn transferred_account_freeze_receipt(
        &mut self,
        approval: &AnchorTransferredAccountFreezeApproval,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let frozen = image
            .account_freezes
            .get(&approval.proposal.request().account())
            .ok_or(DurableError::Absent)?;
        let wire = frozen.to_bytes()?;
        approval.verify_receipt(self.transferred_freeze_history()?, &wire)?;
        Ok(wire)
    }
}
