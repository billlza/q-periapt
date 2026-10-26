// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete independent retirement context; never current journal authority.
use super::*;
use crate::{
    AnchorHandoffHistory, AnchorPin, AnchorRetiredSubject, AnchorSubject,
    AnchorTransferredCleanupMaterials, AnchorTransferredCleanupReceipt,
    TransferredAccountRootJournalPlan,
};
pub(crate) mod authority;
pub(crate) mod control;

/// Original approved root retirement and an independently verified accounting
/// history. The logical storage Witness, historical retirement signer and current
/// accounting signer may differ. None of them authorizes ordinary traffic here.
#[derive(Clone)]
pub struct TransferredRetirementContext {
    plan: TransferredAccountRootJournalPlan,
    decision: Vec<u8>,
    retired: AnchorRetiredSubject,
    history: AnchorHandoffHistory,
    binding: [u8; 32],
}
impl TransferredRetirementContext {
    /// Bind the original full plan and exact Committed decision to one original
    /// subject. An accounting history must equal or extend the plan's independently
    /// retained history. A network reply must not select these trust inputs.
    pub fn new(
        plan: TransferredAccountRootJournalPlan,
        decision: &[u8],
        subject: AnchorSubject,
        history: AnchorHandoffHistory,
    ) -> Result<Self, DurableError> {
        if history.checkpoint() != plan.history().checkpoint() {
            history.require_extension_of(plan.history())?;
        }
        let retired = plan
            .verify(decision)?
            .retirement()?
            .retired_subject(subject)?;
        let mut bytes = Vec::new();
        plan.binding()?.encode(&mut bytes)?;
        bytes.extend_from_slice(&digest(
            b"Q-PERIAPT-TRANSFERRED-RETIREMENT-DECISION/v1",
            decision,
        ));
        bytes.extend_from_slice(&subject.to_bytes());
        match plan.selection() {
            None => bytes.push(0),
            Some(selection) => {
                bytes.push(1);
                bytes.extend_from_slice(&selection.retirement_binding()?);
            }
        }
        let binding = digest(b"Q-PERIAPT-TRANSFERRED-RETIREMENT-CONTEXT/v1", &bytes);
        Ok(Self {
            plan,
            decision: decision.to_vec(),
            retired,
            history,
            binding,
        })
    }
    /// Accounting trust selected independently of incoming cleanup receipts.
    pub fn accounting_pin(&self) -> &AnchorPin {
        self.history.current_pin()
    }
    /// Original permanently retired subject; this alone omits the transferred context.
    pub fn retired_subject(&self) -> AnchorRetiredSubject {
        self.retired
    }
    pub(crate) fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub(crate) fn logical(&self) -> [u8; 32] {
        self.plan.logical_pin().binding()
    }
    pub(crate) fn plan(&self) -> &TransferredAccountRootJournalPlan {
        &self.plan
    }
    pub(crate) fn decision(&self) -> &[u8] {
        &self.decision
    }
    pub(crate) fn history(&self) -> &AnchorHandoffHistory {
        &self.history
    }
    pub(crate) fn materials<'a>(
        &'a self,
        inventory: &'a AnchorRetiredCleanupProposal,
        report: Option<&'a AnchorRetiredReportProposal>,
        previous: Option<&'a AnchorTransferredCleanupReceipt>,
    ) -> AnchorTransferredCleanupMaterials<'a> {
        AnchorTransferredCleanupMaterials {
            history: &self.history,
            replacement: self.plan.approval(),
            decision: &self.decision,
            inventory,
            report,
            previous,
        }
    }
    pub(crate) fn check_pin(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if pin.binding() != self.accounting_pin().binding() {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
