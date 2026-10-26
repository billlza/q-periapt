// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated local expectations precede every dispatched accounting stage.
use super::*;
use crate::{AnchorTransferredCleanupApproval as Approval, AnchorTransferredCleanupStage as Stage};
mod codec;

#[derive(Clone, Eq, PartialEq)]
struct Step {
    approval: Approval,
    receipt: Option<AnchorTransferredCleanupReceipt>,
}
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Control {
    context: [u8; 32],
    inventory: [u8; 32],
    report: Option<[u8; 32]>,
    accounted: bool,
    steps: Vec<Step>,
}
fn index(stage: Stage) -> usize {
    match stage {
        Stage::Inventory => 0,
        Stage::Report => 1,
        Stage::Acknowledged => 2,
    }
}
impl Control {
    pub(crate) fn acknowledgement(
        &self,
        ctx: &TransferredRetirementContext,
        report: &AnchorRetiredReportProposal,
        wire: &[u8],
    ) -> Result<crate::AnchorRetiredReportAcknowledgement, DurableError> {
        self.check_metadata(ctx, report.inventory(), Some(report), Some(report))?;
        let saved = self.verified(Stage::Acknowledged)?;
        let incoming = self
            .prepared(Stage::Acknowledged)?
            .verify_receipt(ctx.history(), wire)?;
        if incoming != *saved {
            return Err(DurableError::Conflict);
        }
        crate::AnchorRetiredReportAcknowledgement::from_transferred(&incoming, report)
    }
    pub(crate) const MAX_BYTES: usize = 8
        + 32
        + 32
        + 1
        + 32
        + 1
        + 1
        + 3 * (Approval::BYTES + 1 + AnchorTransferredCleanupReceipt::BYTES)
        + 32;
    pub(crate) fn new(
        context: &TransferredRetirementContext,
        inventory: &AnchorRetiredCleanupProposal,
    ) -> Result<Self, DurableError> {
        inventory.check_retirement(context.retired)?;
        Ok(Self {
            context: context.binding(),
            inventory: inventory.binding(),
            report: None,
            accounted: false,
            steps: Vec::new(),
        })
    }
    fn check_metadata(
        &self,
        ctx: &TransferredRetirementContext,
        inventory: &AnchorRetiredCleanupProposal,
        report: Option<&AnchorRetiredReportProposal>,
        ack: Option<&AnchorRetiredReportProposal>,
    ) -> Result<(), DurableError> {
        inventory.check_retirement(ctx.retired)?;
        if self.context != ctx.binding()
            || self.inventory != inventory.binding()
            || self.report != report.map(|p| *p.report_id())
            || self.accounted != ack.is_some()
            || report.is_some_and(|r| r.inventory() != inventory)
            || ack.is_some_and(|a| Some(a) != report)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn prepared(&self, stage: Stage) -> Result<&Approval, DurableError> {
        self.steps
            .get(index(stage))
            .map(|s| &s.approval)
            .ok_or(DurableError::Absent)
    }
    pub(crate) fn verified(
        &self,
        stage: Stage,
    ) -> Result<&AnchorTransferredCleanupReceipt, DurableError> {
        self.steps
            .get(index(stage))
            .and_then(|s| s.receipt.as_ref())
            .ok_or(DurableError::Suspended)
    }
    pub(crate) fn with_report(
        &self,
        report: &AnchorRetiredReportProposal,
    ) -> Result<Self, DurableError> {
        self.verified(Stage::Inventory)?;
        if report.inventory().binding() != self.inventory
            || self.report.is_some_and(|id| id != *report.report_id())
        {
            return Err(DurableError::Conflict);
        }
        let mut next = self.clone();
        next.report = Some(*report.report_id());
        Ok(next)
    }
    pub(crate) fn with_accounted(
        &self,
        report: &AnchorRetiredReportProposal,
    ) -> Result<Self, DurableError> {
        self.verified(Stage::Report)?;
        if report.inventory().binding() != self.inventory
            || self.report != Some(*report.report_id())
        {
            return Err(DurableError::Conflict);
        }
        let mut next = self.clone();
        next.accounted = true;
        Ok(next)
    }
    pub(crate) fn prepare(
        &self,
        ctx: &TransferredRetirementContext,
        inventory: &AnchorRetiredCleanupProposal,
        report: Option<&AnchorRetiredReportProposal>,
        approval: &Approval,
    ) -> Result<Self, DurableError> {
        let n = index(approval.stage());
        if let Some(old) = self.steps.get(n) {
            return if &old.approval == approval {
                Ok(self.clone())
            } else {
                Err(DurableError::Conflict)
            };
        }
        if self.steps.len() != n
            || (n == 2 && !self.accounted)
            || self
                .steps
                .iter()
                .any(|s| s.approval.operator_decision() == approval.operator_decision())
        {
            return Err(DurableError::Conflict);
        }
        let previous = if n == 0 {
            None
        } else {
            Some(
                self.verified(
                    [Stage::Inventory, Stage::Report]
                        .get(n - 1)
                        .copied()
                        .ok_or(DurableError::Corrupt)?,
                )?,
            )
        };
        let raw = approval.to_bytes();
        let restored = Approval::restore_trusted_state(
            &raw,
            &ctx.materials(inventory, if n == 0 { None } else { report }, previous),
        )?;
        // Only retained historical requests may select a prior authority.
        let fresh = Approval::from_trusted_state(
            &ctx.materials(inventory, if n == 0 { None } else { report }, previous),
            restored.stage(),
            restored.validity(),
            restored.operator_decision(),
        )?;
        if fresh != restored
            || self.context != ctx.binding()
            || self.inventory != inventory.binding()
        {
            return Err(DurableError::Conflict);
        }
        let mut next = self.clone();
        next.steps.push(Step {
            approval: restored,
            receipt: None,
        });
        Ok(next)
    }
    pub(crate) fn retain(
        &self,
        ctx: &TransferredRetirementContext,
        stage: Stage,
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        let receipt = self.prepared(stage)?.verify_receipt(ctx.history(), wire)?;
        let mut next = self.clone();
        let step = next
            .steps
            .get_mut(index(stage))
            .ok_or(DurableError::Absent)?;
        if step.receipt.as_ref().is_some_and(|old| old != &receipt) {
            return Err(DurableError::Conflict);
        }
        step.receipt = Some(receipt);
        Ok(next)
    }
}
