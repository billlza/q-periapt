// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorRetiredReportAcknowledgement;
use control::Control;
#[derive(Clone, Copy)]
pub(crate) enum ReceiptAuthority<'a> {
    Legacy(&'a AnchorPin),
    Transferred(&'a TransferredRetirementContext, &'a Control),
}
impl<'a> ReceiptAuthority<'a> {
    pub(crate) fn context(self) -> Option<&'a TransferredRetirementContext> {
        match self {
            Self::Legacy(_) => None,
            Self::Transferred(context, _) => Some(context),
        }
    }
    pub(crate) fn check_scope(self, retired: AnchorRetiredSubject) -> Result<(), DurableError> {
        match self {
            Self::Legacy(pin) if pin.binding() == retired.witness_binding() => Ok(()),
            Self::Transferred(context, _) if context.retired_subject() == retired => Ok(()),
            _ => Err(DurableError::Conflict),
        }
    }
    pub(crate) fn verify_ack(
        self,
        retired: AnchorRetiredSubject,
        report: &AnchorRetiredReportProposal,
        wire: &[u8],
    ) -> Result<AnchorRetiredReportAcknowledgement, DurableError> {
        self.check_scope(retired)?;
        report.inventory().check_retirement(retired)?;
        match self {
            Self::Legacy(pin) => {
                Ok(pin.verify_retired_report_acknowledgement(retired, report, wire)?)
            }
            Self::Transferred(context, control) => control.acknowledgement(context, report, wire),
        }
    }
}
