// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Permanent original-device accounting under independent witness receipts.
use super::*;
pub(super) mod reports;

/// Verified permanent retirement against an independently retained replacement.
/// The expected proposal must come from the approved control-plane operation,
/// never be inferred from the incoming receipt. This grants no operating authority.
#[wasm_bindgen(js_name = QPeriaptContinuityRetirement)]
pub struct Retirement {
    pin: engine::AnchorPin,
    inner: engine::AnchorRetiredSubject,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRetirement)]
impl Retirement {
    #[wasm_bindgen(constructor)]
    pub fn new(
        witness: &Witness,
        approved: &Uint8Array,
        subject: &Uint8Array,
        receipt: &Uint8Array,
    ) -> Result<Retirement, JsValue> {
        let proposal = engine::AnchorDeviceReplacementProposal::from_trusted_state(&read_input(
            approved, 1, 65536,
        )?)
        .map_err(protocol)?;
        let subject = engine::AnchorSubject::from_trusted_state(&read_input(subject, 96, 96)?)
            .map_err(protocol)?;
        Ok(Self {
            pin: witness.pin.clone(),
            inner: witness
                .pin
                .verify_retired_subject(&proposal, subject, &read_input(receipt, 1, 8192)?)
                .map_err(protocol)?,
        })
    }
}
/// Original complete inventory expectation. Persist before independent retention.
#[wasm_bindgen(js_name = QPeriaptContinuityRetiredInventory)]
pub struct Inventory {
    inner: engine::AnchorRetiredCleanupProposal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRetiredInventory)]
impl Inventory {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    pub fn binding(&self) -> Vec<u8> {
        self.inner.binding().to_vec()
    }
    pub fn stored_image_digest(&self) -> Vec<u8> {
        self.inner.stored_image_digest().to_vec()
    }
    pub fn pending_intent_digest(&self) -> Option<Vec<u8>> {
        self.inner.pending_intent_digest().map(|id| id.to_vec())
    }
}
/// Original report expectation; neither possession nor parsing acknowledges loss.
#[wasm_bindgen(js_name = QPeriaptContinuityRetiredReportRequest)]
pub struct ReportRequest {
    inner: engine::AnchorRetiredReportProposal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRetiredReportRequest)]
impl ReportRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    pub fn report_id(&self) -> Vec<u8> {
        self.inner.report_id().to_vec()
    }
    pub fn inventory_binding(&self) -> Vec<u8> {
        self.inner.inventory().binding().to_vec()
    }
}
/// Complete original public metadata, including every source/target view. Treat
/// account/device linkage as private host data. Unknown delivery remains unknown.
#[wasm_bindgen(js_name = QPeriaptContinuityRetiredReport)]
pub struct Report {
    inner: engine::retired_device::Report,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRetiredReport)]
impl Report {
    pub fn report_id(&self) -> Vec<u8> {
        self.inner.proposal().report_id().to_vec()
    }
    /// Persist all canonical bytes and the proposal before host acknowledgement.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
    /// Complete schema-1 inspection with hex bytes and decimal-string u64 values.
    /// JSON aids host accounting; canonical bytes remain the acknowledgement input.
    pub fn to_json(&self) -> String {
        reports::describe(&self.inner)
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityErasureState)]
pub enum ErasureState {
    Retained = 0,
    Erased = 1,
}

#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Open only original existing retired storage. Missing state is never first use.
    pub async fn open_retired(
        #[wasm_bindgen(unchecked_param_type = "string")] name: JsValue,
        id: &Uint8Array,
        intent: &Enrollment,
        retirement: &Retirement,
    ) -> Result<Device, JsValue> {
        let (name, id) = location(&name, id)?;
        Ok(Self {
            inner: BrowserDevice::open_retired(
                name,
                id,
                intent.root.clone(),
                intent.description.clone(),
                retirement.pin.clone(),
                retirement.inner,
            )
            .await?,
        })
    }
    pub async fn retirement_inventory(&self) -> Result<Inventory, JsValue> {
        Ok(Inventory {
            inner: self.inner.retirement_inventory().await?,
        })
    }
    pub async fn prepare_retired_report(
        &self,
        inventory_receipt: &Uint8Array,
    ) -> Result<ReportRequest, JsValue> {
        Ok(ReportRequest {
            inner: self
                .inner
                .prepare_retired_report(&read_input(inventory_receipt, 1, 8192)?)
                .await?,
        })
    }
    pub async fn retired_report_request(&self) -> Result<Option<ReportRequest>, JsValue> {
        Ok(self
            .inner
            .retired_report_request()
            .await?
            .map(|inner| ReportRequest { inner }))
    }
    pub async fn retired_report(
        &self,
        inventory_receipt: &Uint8Array,
        report_receipt: &Uint8Array,
    ) -> Result<Report, JsValue> {
        Ok(Report {
            inner: self
                .inner
                .retired_report(
                    &read_input(inventory_receipt, 1, 8192)?,
                    &read_input(report_receipt, 1, 8192)?,
                )
                .await?,
        })
    }
    /// Supply the exact full report read back from durable host accounting.
    pub async fn prepare_retired_host_acknowledgement(
        &self,
        recorded_report: &Uint8Array,
        inventory_receipt: &Uint8Array,
        report_receipt: &Uint8Array,
    ) -> Result<ReportRequest, JsValue> {
        Ok(ReportRequest {
            inner: self
                .inner
                .prepare_retired_host_acknowledgement(
                    &read_input(
                        recorded_report,
                        1,
                        4 * engine::contract::MAX_JOURNAL_IMAGE_BYTES,
                    )?,
                    &read_input(inventory_receipt, 1, 8192)?,
                    &read_input(report_receipt, 1, 8192)?,
                )
                .await?,
        })
    }
    pub async fn retired_host_acknowledgement_request(
        &self,
    ) -> Result<Option<ReportRequest>, JsValue> {
        Ok(self
            .inner
            .retired_host_acknowledgement_request()
            .await?
            .map(|inner| ReportRequest { inner }))
    }
    pub async fn retired_journal_erasure_status(&self) -> Result<ErasureState, JsValue> {
        Ok(match self.inner.retired_journal_erasure_status().await? {
            engine::retired_device::JournalErasureState::Retained => ErasureState::Retained,
            engine::retired_device::JournalErasureState::Erased => ErasureState::Erased,
        })
    }
    pub async fn erase_retired_journal(&self, receipt: &Uint8Array) -> Result<(), JsValue> {
        self.inner
            .erase_retired_journal(&read_input(receipt, 1, 8192)?)
            .await
    }
    pub async fn prepare_retired_signer_erasure(
        &self,
        receipt: &Uint8Array,
    ) -> Result<(), JsValue> {
        self.inner
            .prepare_retired_signer_erasure(&read_input(receipt, 1, 8192)?)
            .await
    }
    pub async fn retired_signer_erasure_status(&self) -> Result<ErasureState, JsValue> {
        Ok(match self.inner.retired_signer_erasure_status().await? {
            engine::SigningFileErasureState::Retained => ErasureState::Retained,
            engine::SigningFileErasureState::Erased => ErasureState::Erased,
        })
    }
    /// Retire the exact prepared signer object and await actual root release.
    pub async fn erase_retired_signer(&self) -> Result<(), JsValue> {
        self.inner.erase_retired_signer().await
    }
}
