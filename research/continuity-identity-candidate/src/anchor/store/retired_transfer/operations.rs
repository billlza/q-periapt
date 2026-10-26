// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl AnchorStore {
    fn cleanup_history(&self) -> Result<&AnchorHandoffHistory, DurableError> {
        Ok(self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .history())
    }
    /// Commit exactly one independently authorized accounting stage and its
    /// original signature atomically. ACK requires the host to durably account
    /// for this report first; this method neither performs nor retries effects.
    /// Exact retries return retained bytes without consulting the clock or signer.
    /// A later Witness can execute a separately approved next stage while keeping
    /// every previous receipt. Storage failure may follow commit: reopen the same
    /// store and reconcile this same approval, never infer absence from an error.
    pub fn retain_transferred_cleanup(
        &mut self,
        approval: &AnchorTransferredCleanupApproval,
        mut trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
        let mut image = self.image()?;
        let history = self.cleanup_history()?;
        let retired_at = image.check_retired_transfer_retirement(approval, history)?;
        let id = approval.inventory.subject().id(&image.namespace);
        if let Some(record) = image.retired_transfers.get(&id) {
            if let Some(receipt) = record.exact(approval)? {
                return Ok(receipt);
            }
        }
        history.require_current(approval.signer)?;
        if approval.history != history.checkpoint() {
            return Err(Error::Scope.into());
        }
        if image
            .retired_transfers
            .values()
            .flat_map(|r| &r.receipts)
            .any(|r| r.approval.decision == approval.decision)
        {
            return Err(DurableError::Conflict);
        }
        match (approval.stage.index(), image.retired_transfers.get(&id)) {
            (0, None)
                if !image.retired_cleanup.contains_key(&id)
                    && !image.retired_reports.contains_key(&id) => {}
            (index, Some(record)) if index > 0 && record.receipts.len() == index => {
                let previous = record.receipts.last().ok_or(DurableError::Corrupt)?;
                if approval.previous != fingerprint(previous.as_bytes())
                    || approval.inventory != previous.approval.inventory
                    || approval.retirement != previous.approval.retirement
                    || (index == 2 && approval.report != previous.approval.report)
                {
                    return Err(Error::Scope.into());
                }
            }
            _ => return Err(DurableError::Conflict),
        }
        let admitted = trusted_time()?;
        approval.validity.check(admitted)?;
        if admitted < retired_at {
            return Err(Error::Scope.into());
        }
        if image
            .retired_transfers
            .get(&id)
            .and_then(|r| r.receipts.last())
            .is_some_and(|r| admitted < r.at)
        {
            return Err(Error::Scope.into());
        }
        let signer = &self.active.as_ref().ok_or(DurableError::Closed)?.signer;
        let receipt = AnchorTransferredCleanupReceipt::sign(approval, admitted, signer)?;
        approval.verify_receipt(history, receipt.as_bytes())?;
        match approval.stage {
            AnchorTransferredCleanupStage::Inventory => {
                image.retired_cleanup.insert(id, approval.inventory.clone());
            }
            AnchorTransferredCleanupStage::Report => {
                image.retired_reports.insert(
                    id,
                    retired_report::ReportRecord {
                        proposal: approval.report_proposal()?,
                        acknowledged: false,
                    },
                );
            }
            AnchorTransferredCleanupStage::Acknowledged => {
                image
                    .retired_reports
                    .get_mut(&id)
                    .ok_or(DurableError::Absent)?
                    .acknowledged = true;
            }
        }
        image
            .retired_transfers
            .entry(id)
            .or_insert_with(|| Record {
                receipts: Vec::new(),
            })
            .receipts
            .push(receipt.clone());
        self.persist_image_checked(&mut image, true, || {
            let now = trusted_time()?;
            if now < admitted {
                return Err(Error::Scope.into());
            }
            approval.validity.check(now)?;
            Ok(())
        })?;
        Ok(receipt)
    }
    /// Read only an exact historical stage; no new signature, live policy or
    /// host effect is needed. Absent never resolves an unknown external commit.
    pub fn transferred_cleanup_receipt(
        &mut self,
        approval: &AnchorTransferredCleanupApproval,
    ) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
        record::observe(&self.image()?, self.cleanup_history()?, approval)
    }
}
