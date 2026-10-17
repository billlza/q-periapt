// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete ordinary-intent metadata and exact historical confirmation.
use super::history::HistoricalPolicy;
use super::recovery::reports::{hex, object};
use super::retirement::reports::describe_image;
use super::*;

/// Original ordinary-write request. Historical device signatures are not
/// independent approval. Retain all bytes before privileged witness completion.
#[wasm_bindgen(js_name = QPeriaptContinuityPendingWriteRequest)]
pub struct Request {
    inner: engine::PendingWriteRecoveryRequest,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPendingWriteRequest)]
impl Request {
    /// Exact 393-byte QPWRPL01 expectation; parsing does not authorize it.
    pub fn proposal(&self) -> Vec<u8> {
        self.inner.proposal().to_bytes()
    }
    pub fn binding(&self) -> Vec<u8> {
        self.inner.proposal().binding().to_vec()
    }
    /// Complete canonical QPWRMD01 source/target metadata, not plaintext.
    pub fn metadata(&self) -> Vec<u8> {
        self.inner.metadata().to_vec()
    }
    /// Original purpose-26 request, for a separately authenticated controller.
    pub fn signed_request(&self) -> Vec<u8> {
        self.inner.signed_request().to_vec()
    }
    /// Complete schema-1 inspection. Bytes use hex, u64 values decimal strings.
    /// Neither source nor target is described as committed without witness proof.
    pub fn to_json(&self) -> String {
        let view = |value: &engine::PendingWriteRecoveryView| {
            describe_image(
                value.head,
                &value.local_account,
                value.next_fanout_ordinal,
                &value.records,
            )
        };
        object(&[
            ("schema", "1".into()),
            ("proposal", hex(&self.inner.proposal().to_bytes())),
            ("binding", hex(&self.inner.proposal().binding())),
            ("source", view(self.inner.source())),
            ("target", view(self.inner.target())),
        ])
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// No request is sent to the witness by preparation. The witness pin is an
    /// independent original input, never learned from the old device's response.
    pub async fn pending_write_recovery_request(
        &self,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<Request, JsValue> {
        Ok(Request {
            inner: self
                .inner
                .pending_write_recovery_request(&original.inner, &witness.pin)
                .await?,
        })
    }
    /// Success confirms only the exact retained proposal target. There is no
    /// fresh Advance, runtime or implied host acknowledgement. Keep the same
    /// approved proposal and complete metadata after any missing result.
    pub async fn confirm_pending_write_recovery(
        &self,
        approved: &Uint8Array,
        recorded_metadata: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<(), JsValue> {
        let size = engine::AnchorPendingWriteRecoveryProposal::ENCODED_BYTES;
        let approved = engine::AnchorPendingWriteRecoveryProposal::from_trusted_state(&read_input(
            approved, size, size,
        )?)
        .map_err(protocol)?;
        let metadata = read_input(
            recorded_metadata,
            1,
            4 * engine::contract::MAX_JOURNAL_IMAGE_BYTES,
        )?;
        self.inner
            .confirm_pending_write_recovery(
                &approved,
                &metadata,
                &original.inner,
                (
                    witness.pin.clone(),
                    Box::new(witness.carrier(self.inner.cancellation())?),
                    witness.timeout,
                ),
            )
            .await
    }
}
