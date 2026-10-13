// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Independently authenticated historical policy metadata. It cannot activate a
/// device or authorize new traffic; the original store must match it for recovery.
#[wasm_bindgen(js_name = QPeriaptContinuityHistoricalPolicy)]
pub struct HistoricalPolicy {
    pub(super) inner: engine::HistoricalSessionPolicy,
}
#[wasm_bindgen(js_class = QPeriaptContinuityHistoricalPolicy)]
impl HistoricalPolicy {
    /// Verify both signatures and the exact retained policy pin without a live
    /// runtime or a fabricated current-time claim.
    #[wasm_bindgen(constructor)]
    pub fn new(
        root: &Uint8Array,
        family: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] version: JsValue,
        digest: &Uint8Array,
        statement: &Uint8Array,
    ) -> Result<HistoricalPolicy, JsValue> {
        let public = engine::PublicKey::decode(&read_input(
            root,
            engine::PUBLIC_KEY_BYTES,
            engine::PUBLIC_KEY_BYTES,
        )?)
        .map_err(protocol)?;
        let checkpoint =
            engine::PolicyCheckpoint::from_trusted_state(read_time(version)?, array(digest)?)
                .map_err(protocol)?;
        let pin = engine::PolicyPin::new(array(family)?, public, checkpoint).map_err(protocol)?;
        Ok(Self {
            inner: pin
                .verify_historical(&read_input(statement, 1, 8192)?)
                .map_err(protocol)?,
        })
    }
    pub fn version(&self) -> u64 {
        self.inner.checkpoint().version()
    }
    pub fn digest(&self) -> Vec<u8> {
        self.inner.checkpoint().digest().to_vec()
    }
}
