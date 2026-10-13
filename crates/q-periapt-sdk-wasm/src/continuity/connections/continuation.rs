// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical session input remains separate from current operational authority.
use super::super::history::HistoricalPolicy;
use super::*;

/// Independently authenticated original public session history. This immutable
/// descriptor owns no runtime, signer, journal or traffic permission. It can be
/// reused after an error; the original installation rechecks current authority.
#[wasm_bindgen(js_name = QPeriaptContinuitySessionReopenRequest)]
pub struct ReopenRequest {
    inner: engine::SessionReopenRequest,
}
#[wasm_bindgen(js_class = QPeriaptContinuitySessionReopenRequest)]
impl ReopenRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        wire: &Uint8Array,
        original: &HistoricalPolicy,
        trust: &Trust,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityRole")] local_role: JsValue,
        session: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<ReopenRequest, JsValue> {
        Ok(Self {
            inner: peers::bundle(wire)?
                .request_historical_reopen(
                    Arc::new(original.inner.clone()),
                    trust.required()?,
                    peers::role(&local_role)?,
                    array(session)?,
                    read_time(now)?,
                )
                .map_err(protocol)?,
        })
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Reopen only the selected original session after policy activation. Its
    /// durable current authorization, archive, identity and witness must match;
    /// historical metadata or a live target policy alone cannot grant access.
    pub async fn reopen_continued_session(
        &self,
        request: &ReopenRequest,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Session, JsValue> {
        Ok(Session {
            inner: self
                .inner
                .reopen_continued_session(
                    &request.inner,
                    Arc::clone(&target.inner),
                    read_time(now)?,
                )
                .await?,
        })
    }
}
