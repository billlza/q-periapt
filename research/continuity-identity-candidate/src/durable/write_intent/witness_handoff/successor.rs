// SPDX-License-Identifier: Apache-2.0 OR MIT
//! An exact predecessor is trusted input, never inferred from damaged storage.
use super::*;
#[derive(Clone)]
pub(super) struct Predecessor {
    plan: WitnessJournalAdoptionPlan,
    receipt: Vec<u8>,
}
impl WitnessJournalAdoptionPlan {
    pub(crate) fn retirement_binding(&self) -> Result<[u8; 32], DurableError> {
        let mut bytes = Vec::new();
        let mut current = self;
        let mut count = 0;
        loop {
            count += 1;
            if count > AnchorHandoffHistory::MAX_TRANSITIONS {
                return Err(DurableError::Capacity);
            }
            bytes.extend_from_slice(&digest(
                b"Q-PERIAPT-RETIRED-SELECTION-REQUEST/v1",
                &current.request,
            ));
            bytes.extend_from_slice(&current.history.checkpoint());
            match current.predecessor.as_deref() {
                None => {
                    bytes.push(0);
                    break;
                }
                Some(previous) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&digest(
                        b"Q-PERIAPT-RETIRED-SELECTION-RECEIPT/v1",
                        &previous.receipt,
                    ));
                    current = &previous.plan;
                }
            }
        }
        Ok(digest(b"Q-PERIAPT-RETIRED-SELECTION-PLAN/v1", &bytes))
    }
    /// Approve a later selection for this same original journal. Retain the
    /// previously selected plan and its exact verified target receipt as trusted
    /// input. A complete strict history extension may skip intermediate retired
    /// witnesses; it cannot replace a Prepared or unknown local selection.
    /// Storage preparation still requires fresh admission and an exact durable
    /// predecessor. This constructor does not change either journal or parent.
    pub fn continue_from(
        mut self,
        previous: &Self,
        receipt: &AnchorHandoffClientAuthorizationReceipt,
    ) -> Result<Self, Error> {
        if self.predecessor.is_some() {
            return Err(Error::State);
        }
        previous.verify_receipt(receipt.as_bytes())?;
        self.history.require_extension_of(&previous.history)?;
        let scope = self.scope();
        let old = previous.scope();
        if scope.subject != old.subject
            || scope.logical != old.logical
            || scope.namespace != old.namespace
            || self.account != previous.account
            || self.device != previous.device
            || scope.policy.version() < old.policy.version()
            || (scope.policy.version() == old.policy.version() && scope.policy != old.policy)
        {
            return Err(Error::Scope);
        }
        let mut cursor = Some(previous);
        let mut count = 1;
        while let Some(prior) = cursor {
            if scope.operation == prior.scope().operation {
                return Err(Error::Scope);
            }
            count += 1;
            if count > AnchorHandoffHistory::MAX_TRANSITIONS {
                return Err(Error::Capacity);
            }
            cursor = prior.predecessor.as_deref().map(|p| &p.plan);
        }
        self.predecessor = Some(Box::new(Predecessor {
            plan: previous.clone(),
            receipt: receipt.as_bytes().to_vec(),
        }));
        Ok(self)
    }
    pub(crate) fn has_predecessor(&self) -> bool {
        self.predecessor.is_some()
    }
    pub(crate) fn lineage_reservation(&self) -> Result<usize, DurableError> {
        let mut total = usize::from(self.has_predecessor());
        let mut cursor = self.predecessor.as_deref();
        let mut count = 0;
        while let Some(previous) = cursor {
            count += 1;
            if count >= AnchorHandoffHistory::MAX_TRANSITIONS {
                return Err(DurableError::Capacity);
            }
            total = total
                .checked_add(14 + previous.plan.request.len() + previous.receipt.len())
                .ok_or(DurableError::Capacity)?;
            cursor = previous.plan.predecessor.as_deref();
        }
        Ok(total)
    }
    fn check_lineage(&self, lineage: &WitnessAdoptionLineage) -> Result<(), DurableError> {
        let mut expected = self.predecessor.as_deref();
        for saved in lineage.decisions.iter().rev() {
            let previous = expected.ok_or(DurableError::Conflict)?;
            if previous.plan.request != saved.request || previous.receipt != saved.receipt {
                return Err(DurableError::Conflict);
            }
            previous.plan.scope().validity().check(saved.prepared_at)?;
            previous.plan.verify_receipt(&saved.receipt)?;
            expected = previous.plan.predecessor.as_deref();
        }
        if expected.is_some() {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn check_selection(
        &self,
        request: &[u8],
        prepared_at: u64,
        receipt: Option<&[u8]>,
        lineage: &WitnessAdoptionLineage,
    ) -> Result<(), DurableError> {
        if request != self.request {
            return Err(DurableError::Conflict);
        }
        lineage.check(request, prepared_at)?;
        self.check_lineage(lineage)?;
        if let Some(receipt) = receipt {
            self.verify_receipt(receipt)?;
        }
        Ok(())
    }
    pub(crate) fn check_predecessor(
        &self,
        request: &[u8],
        prepared_at: u64,
        receipt: Option<&[u8]>,
        lineage: &WitnessAdoptionLineage,
    ) -> Result<(), DurableError> {
        let previous = self.predecessor.as_deref().ok_or(DurableError::Conflict)?;
        previous
            .plan
            .check_selection(request, prepared_at, receipt, lineage)?;
        if receipt != Some(previous.receipt.as_slice()) {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
}
