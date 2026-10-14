// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-state cleanup without a current runtime or operational policy.
use super::history::HistoricalPolicy;
use super::*;

mod reports;
use reports::{AccountReport, SessionReport};

fn operation(id: &Uint8Array) -> Result<engine::FanoutId, JsValue> {
    engine::FanoutId::from_trusted_state(array(id)?).map_err(protocol)
}
#[wasm_bindgen(js_name = QPeriaptContinuityClosurePhase)]
pub enum ClosurePhase {
    Open = 0,
    Pending = 1,
    Closed = 2,
}
/// Retained loss-accounting phase. Closed never asserts remote consumption.
#[wasm_bindgen(js_name = QPeriaptContinuityClosureStatus)]
pub struct ClosureStatus {
    inner: engine::SessionClosureStatus,
}
#[wasm_bindgen(js_class = QPeriaptContinuityClosureStatus)]
impl ClosureStatus {
    pub fn phase(&self) -> ClosurePhase {
        match self.inner {
            engine::SessionClosureStatus::Open => ClosurePhase::Open,
            engine::SessionClosureStatus::Pending(_) => ClosurePhase::Pending,
            engine::SessionClosureStatus::Closed(_) => ClosurePhase::Closed,
        }
    }
    pub fn report_id(&self) -> Option<Vec<u8>> {
        match self.inner {
            engine::SessionClosureStatus::Open => None,
            engine::SessionClosureStatus::Pending(id)
            | engine::SessionClosureStatus::Closed(id) => Some(id.as_bytes().to_vec()),
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Select one complete original local-protection batch for cleanup only.
    /// A required witness is never inferred or replaced with local protection.
    pub async fn recover_account_local(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<(), JsValue> {
        self.inner
            .recover_account(operation(id)?, &original.inner, None)
            .await
    }
    /// Select the original batch under its independent original witness pin.
    pub async fn recover_account(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<(), JsValue> {
        self.inner
            .recover_account(
                operation(id)?,
                &original.inner,
                Some((
                    witness.pin.clone(),
                    Box::new(witness.carrier(self.inner.cancellation())?),
                    witness.timeout,
                )),
            )
            .await
    }
    /// Select one independently closable local-protection session for accounting.
    pub async fn recover_session_local(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<(), JsValue> {
        self.inner
            .recover_session(array(id)?, &original.inner, None)
            .await
    }
    /// Select an original session without current validity, retaining required protection.
    pub async fn recover_session(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<(), JsValue> {
        self.inner
            .recover_session(
                array(id)?,
                &original.inner,
                Some((
                    witness.pin.clone(),
                    Box::new(witness.carrier(self.inner.cancellation())?),
                    witness.timeout,
                )),
            )
            .await
    }
    pub async fn recovered_account_status(&self) -> Result<account::Status, JsValue> {
        let (id, status) = self.inner.recovered_account_status().await?;
        Ok(account::status(id, status))
    }
    pub async fn recovered_account_members(&self) -> Result<account::Members, JsValue> {
        Ok(account::members(
            self.inner.recovered_account_members().await?,
        ))
    }
    /// Irreversibly freeze the complete reserved batch; save the whole report before ACK.
    pub async fn begin_account_abandonment(&self) -> Result<AccountReport, JsValue> {
        Ok(AccountReport::new(
            self.inner.begin_account_abandonment().await?,
        ))
    }
    /// Call only after durable host accounting of every loss/unknown outcome in the report.
    pub async fn acknowledge_account_abandonment(
        &self,
        report: &Uint8Array,
    ) -> Result<(), JsValue> {
        let id =
            engine::FanoutAbandonmentId::from_trusted_state(array(report)?).map_err(protocol)?;
        self.inner.acknowledge_account_abandonment(id).await
    }
    /// Retire aggregate metadata only after all original members are accounted.
    pub async fn retire_recovered_account(&self) -> Result<(), JsValue> {
        self.inner.retire_recovered_account().await
    }
    pub async fn recovered_session_status(&self) -> Result<ClosureStatus, JsValue> {
        Ok(ClosureStatus {
            inner: self.inner.recovered_session_status().await?,
        })
    }
    /// Freeze the independent session and return its complete retained loss metadata.
    pub async fn begin_session_closure(&self) -> Result<SessionReport, JsValue> {
        Ok(SessionReport::new(
            self.inner.begin_session_closure().await?,
        ))
    }
    /// Acknowledge only the original report durably recorded by the host.
    pub async fn acknowledge_session_closure(&self, report: &Uint8Array) -> Result<(), JsValue> {
        let id = engine::SessionClosureId::from_trusted_state(array(report)?).map_err(protocol)?;
        self.inner.acknowledge_session_closure(id).await
    }
}
