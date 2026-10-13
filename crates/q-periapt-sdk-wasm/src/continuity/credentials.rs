// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::history::HistoricalPolicy;
use super::*;
mod types;
use types::{CancellationRequest, Grant, Proposal, Status};
fn witness_config(
    owner: &Device,
    witness: &Witness,
) -> Result<
    (
        engine::AnchorPin,
        Box<dyn engine::AnchorTransport>,
        Duration,
    ),
    JsValue,
> {
    Ok((
        witness.pin.clone(),
        Box::new(witness.carrier(owner.inner.cancellation())?),
        witness.timeout,
    ))
}
fn operation(value: &Uint8Array) -> Result<engine::CredentialRenewalId, JsValue> {
    engine::CredentialRenewalId::from_trusted_state(array(value)?).map_err(protocol)
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Explicit peer approval; never renews this local device or bootstraps a session.
    /// Keep the original operation ID through retries and unknown outcomes.
    pub async fn admit_peer_credential_renewal(
        &self,
        grant: &Grant,
        id: &Uint8Array,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<super::status::Checkpoint, JsValue> {
        Ok(super::status::Checkpoint {
            inner: self
                .inner
                .admit_peer_credential_renewal(
                    &grant.inner,
                    operation(id)?,
                    &policy.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    pub async fn credential_renewal_status(&self) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self.inner.credential_renewal_status().await?,
        })
    }
    /// Close the active owner and reopen its original registration for maintenance.
    pub async fn stage_credential_renewal(
        &self,
        grant: &Grant,
        id: &Uint8Array,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .stage_credential_renewal(
                    &grant.inner,
                    operation(id)?,
                    &policy.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    pub async fn prepare_witnessed_credential_renewal(
        &self,
        original: &HistoricalPolicy,
        policy: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Proposal, JsValue> {
        Ok(Proposal {
            inner: self
                .inner
                .prepare_witnessed_credential_renewal(
                    &original.inner,
                    &policy.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
    /// Local protection only; required-witness targets need exact witnessed recovery.
    pub async fn reconcile_expired_credential_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .reconcile_expired_credential_renewal(
                    operation(id)?,
                    array(statement)?,
                    &policy.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Recover original metadata without requiring a live runtime or grant.
    pub async fn recover_witnessed_credential_renewal_preparation(
        &self,
        original: &HistoricalPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Option<Proposal>, JsValue> {
        Ok(self
            .inner
            .recover_witnessed_credential_renewal_preparation(&original.inner, read_time(now)?)
            .await?
            .map(|inner| Proposal { inner }))
    }
    pub async fn prepare_witnessed_credential_cancellation(
        &self,
        original: &HistoricalPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<CancellationRequest, JsValue> {
        Ok(CancellationRequest {
            inner: self
                .inner
                .prepare_witnessed_credential_cancellation(&original.inner, read_time(now)?)
                .await?,
        })
    }
    pub async fn commit_witnessed_credential_renewal(
        &self,
        proposal: &Proposal,
        original: &HistoricalPolicy,
        policy: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .commit_witnessed_credential_renewal(
                    &proposal.inner,
                    &original.inner,
                    &policy.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
    pub async fn reconcile_witnessed_credential_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .reconcile_witnessed_credential_renewal(
                    operation(id)?,
                    array(statement)?,
                    &original.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
    pub async fn close_witnessed_credential_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .close_witnessed_credential_renewal(
                    operation(id)?,
                    array(statement)?,
                    &original.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
}
