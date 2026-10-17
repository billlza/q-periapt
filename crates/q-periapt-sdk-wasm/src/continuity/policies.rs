// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Browser binding for independently approved policy maintenance and recovery.
use super::history::HistoricalPolicy;
use super::*;
mod types;
use types::{Grant, Progress, Proposal, Status, WitnessState};
fn operation(value: &Uint8Array) -> Result<engine::PolicyRenewalId, JsValue> {
    engine::PolicyRenewalId::from_trusted_state(array(value)?).map_err(protocol)
}
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
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Read historical outcome; activate separately for current traffic.
    pub async fn policy_renewal_status(&self) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self.inner.policy_renewal_status().await?,
        })
    }
    /// Read original local terminal/cleanup, independent of remote availability.
    pub async fn witnessed_policy_renewal_progress(&self) -> Result<Option<Progress>, JsValue> {
        Ok(self
            .inner
            .witnessed_policy_renewal_progress()
            .await?
            .map(|inner| Progress { inner }))
    }
    /// Close and reopen the original registration before maintenance. Stage both approvals exactly.
    pub async fn stage_policy_renewal(
        &self,
        grant: &Grant,
        id: &Uint8Array,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .stage_policy_renewal(
                    &grant.inner,
                    operation(id)?,
                    &original.inner,
                    &target.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Local protection only; completion does not grant current traffic.
    pub async fn reconcile_policy_renewal(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .reconcile_policy_renewal(&original.inner, &target.inner, read_time(now)?)
                .await?,
        })
    }
    /// Recover only an exact already-committed local operation without a runtime.
    pub async fn recover_historical_policy_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .recover_historical_policy_renewal(
                    operation(id)?,
                    array(statement)?,
                    &original.inner,
                )
                .await?,
        })
    }
    /// Resolve an unusable local target against original retained journal history.
    pub async fn resolve_policy_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
        target: &HistoricalPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .resolve_policy_renewal(
                    operation(id)?,
                    array(statement)?,
                    &original.inner,
                    &target.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Recover exact retained public approval bytes; never re-sign after an unknown result.
    pub async fn pending_policy_renewal_approval(
        &self,
        id: &Uint8Array,
    ) -> Result<Vec<u8>, JsValue> {
        self.inner
            .pending_policy_renewal_approval(operation(id)?)
            .await
    }
    /// Seal the exact staged target. Independent witness preparation is still required.
    pub async fn prepare_witnessed_policy_renewal(
        &self,
        original: &HistoricalPolicy,
        previous: &HistoricalPolicy,
        target: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Proposal, JsValue> {
        Ok(Proposal {
            inner: self
                .inner
                .prepare_witnessed_policy_renewal(
                    &original.inner,
                    &previous.inner,
                    &target.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
    /// No local proposal does not mean the witness did not commit.
    pub async fn recover_witnessed_policy_renewal_preparation(
        &self,
        original: &HistoricalPolicy,
    ) -> Result<Option<Proposal>, JsValue> {
        Ok(self
            .inner
            .recover_witnessed_policy_renewal_preparation(&original.inner)
            .await?
            .map(|inner| Proposal { inner }))
    }
    /// Commit the original independently prepared target; recover exact identity after errors.
    pub async fn commit_witnessed_policy_renewal(
        &self,
        proposal: &Proposal,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .commit_witnessed_policy_renewal(
                &proposal.inner,
                &original.inner,
                &target.inner,
                read_time(now)?,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
    /// Retain the historical terminal before ACK and cleanup; no current runtime required.
    pub async fn reconcile_witnessed_policy_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .reconcile_witnessed_policy_renewal(
                operation(id)?,
                array(statement)?,
                &original.inner,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
    /// Close preserves Applied when the original commit won the race.
    pub async fn close_witnessed_policy_renewal(
        &self,
        id: &Uint8Array,
        statement: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .close_witnessed_policy_renewal(
                operation(id)?,
                array(statement)?,
                &original.inner,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
    /// Activate the original installation under current target authority, not a new bootstrap.
    pub async fn activate_local_policy_renewal(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,

        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .activate_policy_renewal(&original.inner, &target.inner, read_time(now)?, None)
            .await?
            .as_bytes()
            .to_vec())
    }
    /// Activate the original installation under current target authority, not a new bootstrap.
    pub async fn activate_witnessed_policy_renewal(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .activate_policy_renewal(
                &original.inner,
                &target.inner,
                read_time(now)?,
                Some(witness_config(self, witness)?),
            )
            .await?
            .as_bytes()
            .to_vec())
    }
}
