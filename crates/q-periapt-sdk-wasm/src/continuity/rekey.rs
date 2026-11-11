// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::connections::{callable, timeout, Session};
use super::peers::Endpoint;
use super::*;

/// Authenticated local journal progress; no assertion about an attacker's knowledge.
#[wasm_bindgen(js_name = QPeriaptContinuityRekeyProgress)]
pub struct RekeyProgress {
    inner: engine::RekeyProgress,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRekeyProgress)]
impl RekeyProgress {
    pub fn confirmed_epoch(&self) -> u64 {
        self.inner.confirmed_epoch
    }
    pub fn sending_epoch(&self) -> u64 {
        self.inner.sending_epoch
    }
    pub fn receiving_epoch(&self) -> u64 {
        self.inner.receiving_epoch
    }
    pub fn pending_epoch(&self) -> Option<u64> {
        self.inner.pending_epoch
    }
}
/// One explicit target completed locally; neither remote receipt nor secrecy recovery.
#[wasm_bindgen(js_name = QPeriaptContinuityRekeyCompletion)]
pub struct RekeyCompletion {
    inner: engine::session_exchange::RekeyCompleted,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRekeyCompletion)]
impl RekeyCompletion {
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }
    pub fn exchanges(&self) -> u16 {
        self.inner.exchanges
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    pub async fn session_rekey_progress(
        &self,
        session: &Session,
    ) -> Result<RekeyProgress, JsValue> {
        Ok(RekeyProgress {
            inner: self.inner.session_rekey_progress(&session.inner).await?,
        })
    }
    /// Use the same target after failure. At most 128 requests share the original
    /// deadline; failed I/O is returned directly and is not retried automatically.
    pub async fn drive_session_rekey(
        &self,
        session: &Session,
        #[wasm_bindgen(unchecked_param_type = "bigint")] target: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number")] exchanges: JsValue,
        endpoint: &Endpoint,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<RekeyCompletion, JsValue> {
        callable(clock)?;
        let exchanges = u16::try_from(read_limit(
            &exchanges,
            usize::from(engine::contract::MAX_NETWORK_EXCHANGES),
        )?)
        .map_err(|_| protocol(engine::Error::Encoding))?;
        Ok(RekeyCompletion {
            inner: self
                .inner
                .drive_session_rekey(
                    &session.inner,
                    read_time(target)?,
                    exchanges,
                    &endpoint.inner,
                    timeout(&timeout_ms)?,
                    clock,
                )
                .await?,
        })
    }
    pub async fn serve_session_control(
        &self,
        session: &Session,
        wire: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        clock: &js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        callable(clock)?;
        let wire = read_input(wire, 10, engine::contract::MAX_CONNECTION_FRAME_BYTES)?;
        self.inner
            .serve_session_control(&session.inner, &wire, timeout(&timeout_ms)?, clock)
            .await
    }
}
