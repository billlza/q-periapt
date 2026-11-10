// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Existing restricted root owners consume and retain current-authority results.
use super::*;
impl AccountRootJournalRecovery {
    pub(in crate::durable::write_intent) fn prepare_transferred_database(
        db: Database,
        key: JournalKey,
        owner: [u8; 32],
        identity: JournalIdentity,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<Self, DurableError> {
        let pin = plan
            .history
            .historical_pin(plan.proposal().witness_binding())?
            .clone();
        Owners {
            db,
            key,
            owner,
            identity,
            pin,
            proposal: plan.proposal().clone(),
            transferred: Some(Box::new(plan)),
        }
        .prepare()
    }
    /// Recover only this exact original journal and independently retained plan.
    /// Missing selection, changed lineage or an incompatible existing root fence
    /// closes recovery; none permits provisioning or reopening the old account.
    pub fn resume_transferred_original(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<Self, DurableError> {
        Self::prepare_transferred_database(
            open_private_database(path)?,
            key,
            bootstrap::storage_owner(original),
            identity,
            plan,
        )
    }
    /// Retain either exact purpose-37 terminal result without granting an owner.
    /// The first proof is immutable, including after an uncertain I/O outcome.
    /// A Closed observation preserves the complete original image and pending work.
    pub fn retain_account_decision(
        &mut self,
        wire: &[u8],
    ) -> Result<AccountRootJournalState, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let plan = owners.transferred.as_ref().ok_or(DurableError::Suspended)?;
            plan.verify(wire)?;
            let original = owners.read()?;
            if let Some(saved) = &original.receipt {
                if saved != wire {
                    return Err(DurableError::Conflict);
                }
            } else {
                let mut next = original.clone();
                next.receipt = Some(wire.to_vec());
                owners.save(Some(&original), &next, "receipt")?;
            }
            let retained = owners.read()?.receipt.ok_or(DurableError::Corrupt)?;
            owners.verify_outcome(&retained)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Exact retained historical terminal proof; absence closes the restricted owner.
    pub fn account_decision(&mut self) -> Result<AnchorTransferredAccountDecision, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let plan = owners.transferred.as_ref().ok_or(DurableError::Suspended)?;
            let wire = owners.read()?.receipt.ok_or(DurableError::Absent)?;
            plan.verify(&wire)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl DeviceJournal {
    /// Consume the live journal into the existing restricted root recovery type.
    /// Preserves its original sealed image, pending intent and Witness selection.
    pub fn begin_transferred_account_root_replacement(
        &mut self,
        plan: TransferredAccountRootJournalPlan,
    ) -> Result<AccountRootJournalRecovery, DurableError> {
        let owners = self.active.take().ok_or(DurableError::Closed)?;
        AccountRootJournalRecovery::prepare_transferred_database(
            owners.db,
            owners.key,
            owners.owner,
            JournalIdentity(owners.id),
            plan,
        )
    }
}
