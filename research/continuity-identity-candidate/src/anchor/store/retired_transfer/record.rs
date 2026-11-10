// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(in crate::anchor::store) struct Record {
    pub(super) receipts: Vec<AnchorTransferredCleanupReceipt>,
}
impl Record {
    pub(super) fn exact(
        &self,
        a: &AnchorTransferredCleanupApproval,
    ) -> Result<Option<AnchorTransferredCleanupReceipt>, DurableError> {
        match self.receipts.get(a.stage.index()) {
            Some(r) if &r.approval == a => Ok(Some(r.clone())),
            Some(_) => Err(DurableError::Conflict),
            None => Ok(None),
        }
    }
    pub(in crate::anchor::store) fn preserves(&self, old: &Self) -> bool {
        self.receipts.starts_with(&old.receipts)
    }
}
impl Image {
    pub(in crate::anchor::store) fn check_retired_transfer_retirement(
        &self,
        a: &AnchorTransferredCleanupApproval,
        authority: &impl ImageAuthority,
    ) -> Result<u64, DurableError> {
        a.check(authority)?;
        self.admit_cleanup(&a.inventory, authority)?;
        let account = self
            .entries
            .get(&a.inventory.subject().id(&self.namespace))
            .and_then(|e| e.original_identity.as_ref())
            .ok_or(DurableError::Absent)?
            .account;
        let proposal = self
            .account_replacements
            .get(&account)
            .ok_or(DurableError::Absent)?;
        a.inventory.check_account_proposal(proposal)?;
        self.require_account_decision(proposal, authority)?;
        let decision = self
            .account_decisions
            .get(proposal.operation().as_bytes())
            .ok_or(DurableError::Absent)?;
        if fingerprint(decision.as_bytes()) != a.retirement {
            return Err(Error::Scope.into());
        }
        decision.committed_at()
    }
    pub(in crate::anchor::store) fn check_retired_transfers(
        &self,
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        if self.retired_transfers.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut decisions = std::collections::BTreeSet::new();
        for (id, record) in &self.retired_transfers {
            if !(1..=3).contains(&record.receipts.len()) {
                return Err(DurableError::Corrupt);
            }
            let first = &record
                .receipts
                .first()
                .ok_or(DurableError::Corrupt)?
                .approval;
            if *id != first.inventory.subject().id(&self.namespace)
                || self.retired_cleanup.get(id) != Some(&first.inventory)
            {
                return Err(DurableError::Corrupt);
            }
            for (index, receipt) in record.receipts.iter().enumerate() {
                receipt.check(authority)?;
                let a = &receipt.approval;
                let retired_at = self.check_retired_transfer_retirement(a, authority)?;
                if receipt.at < retired_at {
                    return Err(DurableError::Corrupt);
                }
                if a.stage.index() != index
                    || a.inventory != first.inventory
                    || a.retirement != first.retirement
                    || !decisions.insert(a.decision)
                {
                    return Err(DurableError::Corrupt);
                }
                if index > 0 {
                    let previous = record
                        .receipts
                        .get(index - 1)
                        .ok_or(DurableError::Corrupt)?;
                    if a.previous != fingerprint(previous.as_bytes())
                        || (index == 2 && a.report != previous.approval.report)
                        || receipt.at < previous.at
                    {
                        return Err(DurableError::Corrupt);
                    }
                }
            }
            match (record.receipts.get(1), self.retired_reports.get(id)) {
                (None, None) => {}
                (Some(r), Some(saved))
                    if r.approval.report_proposal()? == saved.proposal
                        && saved.acknowledged == (record.receipts.len() == 3) => {}
                _ => return Err(DurableError::Corrupt),
            }
        }
        Ok(())
    }
    // Reserve every remaining signed stage and the report row at inventory
    // admission. Subsequent ordinary writes cannot consume this completion space.
    pub(in crate::anchor::store) fn retired_transfer_reserve(&self) -> Result<usize, DurableError> {
        self.retired_transfers
            .values()
            .try_fold(0usize, |total, r| {
                let remaining = 3usize
                    .checked_sub(r.receipts.len())
                    .ok_or(DurableError::Corrupt)?;
                total
                    .checked_add(
                        remaining * codec::WIRE_BYTES
                            + if r.receipts.len() < 2 { 32 + 353 } else { 0 },
                    )
                    .ok_or(DurableError::Capacity)
            })
    }
}
pub(in crate::anchor::store) fn observe(
    image: &Image,
    history: &AnchorHandoffHistory,
    a: &AnchorTransferredCleanupApproval,
) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
    a.check(history)?;
    image.check_retired_transfers(history)?;
    image.check_retired_transfer_retirement(a, history)?;
    image
        .retired_transfers
        .get(&a.inventory.subject().id(&image.namespace))
        .ok_or(DurableError::Absent)?
        .exact(a)?
        .ok_or(DurableError::Absent)
}
