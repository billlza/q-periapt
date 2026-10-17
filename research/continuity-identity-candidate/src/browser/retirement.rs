// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared permanent retirement under the original browser root and operation lease.
use super::*;
use crate::{AnchorRetiredCleanupProposal, AnchorRetiredReportProposal, RetiredDeviceEnrollment};

pub(super) struct Retired {
    pub(super) owner: RetiredDeviceEnrollment,
    pub(super) pin: AnchorPin,
}
impl Operation<'_> {
    fn retired(&mut self) -> Result<&mut Retired, DurableError> {
        match self.state.as_mut() {
            Some(State::Retired(owner)) => Ok(owner),
            _ => Err(Error::State.into()),
        }
    }
}
impl BrowserDevice {
    /// Recover the original complete inventory expectation; never select a backup.
    pub async fn retirement_inventory(&self) -> Result<AnchorRetiredCleanupProposal, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.retired()?.owner.installation().await?.proposal() }.await;
        op.finish(result).await
    }
    /// Retain the original complete report request after independent inventory retention.
    pub async fn prepare_retired_report(
        &self,
        inventory_receipt: &[u8],
    ) -> Result<AnchorRetiredReportProposal, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let state = op.retired()?;
            let child = state.owner.installation().await?;
            let retained = child.verify_retained(&state.pin, inventory_receipt)?;
            child.prepare_report(&retained).await
        }
        .await;
        op.finish(result).await
    }
    /// Genuine local absence or the original saved request; neither is witness NoCommit.
    pub async fn retired_report_request(
        &self,
    ) -> Result<Option<AnchorRetiredReportProposal>, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.retired()?.owner.installation().await?.report_proposal() }.await;
        op.finish(result).await
    }
    /// Release the complete original public loss report after both independent receipts.
    pub async fn retired_report(
        &self,
        inventory_receipt: &[u8],
        report_receipt: &[u8],
    ) -> Result<crate::retired_device::Report, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let state = op.retired()?;
            let child = state.owner.installation().await?;
            let retained = child.verify_retained(&state.pin, inventory_receipt)?;
            child.report(&retained, &state.pin, report_receipt).await
        }
        .await;
        op.finish(result).await
    }
    /// Call only after the host durably accounts the complete report. Exact bytes
    /// and independent retention are verified; this is not the witness ACK or erasure.
    pub async fn prepare_retired_host_acknowledgement(
        &self,
        recorded_report: &[u8],
        inventory_receipt: &[u8],
        report_receipt: &[u8],
    ) -> Result<AnchorRetiredReportProposal, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let state = op.retired()?;
            let child = state.owner.installation().await?;
            let inventory = child.verify_retained(&state.pin, inventory_receipt)?;
            let report = child.report_proposal()?.ok_or(DurableError::Suspended)?;
            let retained = state
                .pin
                .verify_retired_report(&inventory, &report, report_receipt)?;
            child.prepare_host_acknowledgement(recorded_report, &retained)
        }
        .await;
        op.finish(result).await
    }
    /// Recover the original locally committed host-accounting expectation.
    pub async fn retired_host_acknowledgement_request(
        &self,
    ) -> Result<Option<AnchorRetiredReportProposal>, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.retired()?
                .owner
                .installation()
                .await?
                .host_acknowledgement_proposal()
        }
        .await;
        op.finish(result).await
    }
    /// Observe original journal rows or their authenticated erasure terminal.
    pub async fn retired_journal_erasure_status(
        &self,
    ) -> Result<crate::retired_device::JournalErasureState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let state = op.retired()?;
            state
                .owner
                .installation()
                .await?
                .journal_erasure_status(&state.pin)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Erase exact original logical rows only after independent purpose-21 acknowledgement.
    pub async fn erase_retired_journal(&self, receipt: &[u8]) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let state = op.retired()?;
            state
                .owner
                .installation()
                .await?
                .erase_journal(&state.pin, receipt)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Retain the original catalogue signer identity after authenticated journal erasure.
    pub async fn prepare_retired_signer_erasure(&self, receipt: &[u8]) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.retired()?.owner.prepare_signer_erasure(receipt).await }.await;
        op.finish(result).await
    }
    /// Observe the same signer object, rejecting missing, foreign or changed records.
    pub async fn retired_signer_erasure_status(
        &self,
    ) -> Result<crate::SigningFileErasureState, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.retired()?.owner.signer_erasure_status().await }.await;
        op.finish(result).await
    }
    /// Replace the authenticated original signer ciphertext with its retirement
    /// marker, then close and await actual root release. Backups remain out of scope.
    pub async fn erase_retired_signer(&self) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.retired()?.owner.erase_signer().await }.await;
        op.finish(result).await?;
        self.close().await
    }
}
