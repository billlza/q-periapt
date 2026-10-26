// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact historical accounting, independently approved at each durable stage.
use super::*;
pub(super) mod codec;
mod record;
pub(super) use record::{observe, Record};
mod operations;

/// Separate historical facts. Only the final stage records a host ACK; none
/// grants traffic, proves remote delivery or proves physical erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorTransferredCleanupStage {
    /// Exact local inventory retained independently; no report or ACK follows.
    Inventory,
    /// Exact host report retained; its accounting effects are not acknowledged.
    Report,
    /// Host explicitly acknowledged this exact previously retained report.
    Acknowledged,
}
impl AnchorTransferredCleanupStage {
    fn index(self) -> usize {
        match self {
            Self::Inventory => 0,
            Self::Report => 1,
            Self::Acknowledged => 2,
        }
    }
}
/// Complete independent inputs. The previous receipt is required for Report
/// and Acknowledged; it is not a host approval for either next action.
pub struct AnchorTransferredCleanupMaterials<'a> {
    /// Independently verified complete history through the current authority.
    pub history: &'a AnchorHandoffHistory,
    /// Independently retained full account replacement approval.
    pub replacement: &'a AnchorTransferredAccountReplacementApproval,
    /// Original purpose-37 committed account retirement, not a closure.
    pub decision: &'a [u8],
    /// Independently retained original local inventory; not a fresh replacement.
    pub inventory: &'a AnchorRetiredCleanupProposal,
    /// Exact report for the final two stages; absent for inventory retention.
    pub report: Option<&'a AnchorRetiredReportProposal>,
    /// Verified immediately preceding stage; absent only for inventory retention.
    pub previous: Option<&'a AnchorTransferredCleanupReceipt>,
}
/// A caller-authenticated operator decision for one exact stage. Persist these
/// bytes independently before dispatch. Public parsing cannot authenticate an
/// operator; possession of these bytes is not controller authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredCleanupApproval {
    namespace: [u8; 32],
    history: [u8; 32],
    signer: [u8; 32],
    decision: [u8; 32],
    validity: Validity,
    retirement: [u8; 32],
    inventory: AnchorRetiredCleanupProposal,
    report: Option<[u8; 32]>,
    previous: [u8; 32],
    stage: AnchorTransferredCleanupStage,
}
impl AnchorTransferredCleanupApproval {
    /// Authenticate account retirement, exact inventory and previous stage before
    /// retaining an independent decision. ACK creation must follow durable host
    /// accounting deduplicated by the original report ID. It does not perform it.
    pub fn from_trusted_state(
        materials: &AnchorTransferredCleanupMaterials<'_>,
        stage: AnchorTransferredCleanupStage,
        validity: Validity,
        decision: [u8; 32],
    ) -> Result<Self, DurableError> {
        let retired = materials
            .replacement
            .verify_decision(materials.history, materials.decision)?
            .retirement()?;
        materials
            .inventory
            .check_account_proposal(retired.proposal())?;
        let report = match (stage, materials.report) {
            (AnchorTransferredCleanupStage::Inventory, None) => None,
            (
                AnchorTransferredCleanupStage::Report | AnchorTransferredCleanupStage::Acknowledged,
                Some(report),
            ) if report.inventory() == materials.inventory => Some(*report.report_id()),
            _ => return Err(Error::Scope.into()),
        };
        let retirement = fingerprint(materials.decision);
        let previous = match (stage.index(), materials.previous) {
            (0, None) => retirement,
            (index, Some(prior)) if index > 0 => {
                prior.check(materials.history)?;
                let old = &prior.approval;
                if old.stage.index() + 1 != index
                    || old.inventory != *materials.inventory
                    || old.retirement != retirement
                    || (index == 2 && old.report != report)
                {
                    return Err(Error::Scope.into());
                }
                fingerprint(prior.as_bytes())
            }
            _ => return Err(Error::Scope.into()),
        };
        let approval = Self {
            namespace: materials.history.namespace_binding(),
            history: materials.history.checkpoint(),
            signer: materials.history.current_pin().binding(),
            decision,
            validity,
            retirement,
            inventory: materials.inventory.clone(),
            report,
            previous,
            stage,
        };
        approval.check(materials.history)?;
        Ok(approval)
    }
    fn check(&self, authority: &impl ImageAuthority) -> Result<(), DurableError> {
        for value in [
            self.namespace,
            self.history,
            self.signer,
            self.decision,
            self.retirement,
            self.previous,
        ] {
            nonzero(&value)?;
        }
        if self.namespace != authority.namespace()
            || self.history != authority.history_checkpoint(self.signer)?
            || (self.stage == AnchorTransferredCleanupStage::Inventory) != self.report.is_none()
            || (self.stage == AnchorTransferredCleanupStage::Inventory
                && self.previous != self.retirement)
        {
            return Err(Error::Scope.into());
        }
        if let Some(report) = self.report {
            nonzero(&report)?;
        }
        Ok(())
    }
    fn report_proposal(&self) -> Result<AnchorRetiredReportProposal, DurableError> {
        Ok(AnchorRetiredReportProposal::from_report(
            self.inventory.clone(),
            self.report.ok_or(Error::Scope)?,
        )?)
    }
    /// Exact stage selected by the independent operator, never inferred from a reply.
    pub fn stage(&self) -> AnchorTransferredCleanupStage {
        self.stage
    }
    /// Verify the exact saved approval against a historical signed result.
    pub fn verify_receipt(
        &self,
        history: &AnchorHandoffHistory,
        wire: &[u8],
    ) -> Result<AnchorTransferredCleanupReceipt, DurableError> {
        self.check(history)?;
        let receipt = AnchorTransferredCleanupReceipt::decode(wire, history)?;
        if receipt.approval != *self {
            return Err(Error::Scope.into());
        }
        Ok(receipt)
    }
}
fn fingerprint(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-TRANSFERRED-CLEANUP-RECEIPT/v1", wire)
}
/// Exact retained proof of one stage, not an ordinary reply or a legacy ACK.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorTransferredCleanupReceipt, AnchorReply};
/// fn traffic(receipt: AnchorTransferredCleanupReceipt) -> AnchorReply { receipt }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredCleanupReceipt {
    approval: AnchorTransferredCleanupApproval,
    at: u64,
    wire: Vec<u8>,
}
impl AnchorTransferredCleanupReceipt {
    /// Original retained signature bytes, never reconstructed with another signer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Historical fact established by these bytes, without traffic authority.
    pub fn stage(&self) -> AnchorTransferredCleanupStage {
        self.approval.stage
    }
    /// Exact operator approval bound into the signature.
    pub fn approval(&self) -> &AnchorTransferredCleanupApproval {
        &self.approval
    }
}
