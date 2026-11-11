// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use super::{
    history::HistoricalPolicy,
    status::{Checkpoint, Refresh},
};
mod types;
use types::{Progress, Proposal, Target, WitnessState};

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
fn operation(value: &Uint8Array) -> Result<engine::RosterRefreshId, JsValue> {
    engine::RosterRefreshId::from_trusted_state(array(value)?).map_err(protocol)
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Accept the independently authenticated head of a known remote account.
    /// Exact retry rechecks current authority; local-account changes require R.
    pub async fn admit_peer_roster(
        &self,
        roster: &Uint8Array,
        trust: &AccountTrust,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Checkpoint, JsValue> {
        Ok(Checkpoint {
            inner: self
                .inner
                .admit_peer_roster(
                    &read_input(roster, 1, 8192)?,
                    &trust.inner,
                    &policy.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Local-policy path only. Close the operational owner and open the original
    /// registration for maintenance; activate again after the target is reconciled.
    pub async fn refresh_local_roster(
        &self,
        previous: &Checkpoint,
        roster: &Uint8Array,
        trust: &AccountTrust,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .refresh_local_roster(
                    previous.inner,
                    &read_input(roster, 1, 8192)?,
                    &trust.inner,
                    &policy.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    pub async fn resolve_local_roster_refresh(
        &self,
        previous: &Checkpoint,
        target: &Checkpoint,
        original: &HistoricalPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Refresh, JsValue> {
        Ok(self
            .inner
            .resolve_local_roster_refresh(
                previous.inner,
                target.inner,
                &original.inner,
                read_time(now)?,
            )
            .await?
            .into())
    }
    /// None is local absence, not proof of a remote uncommitted operation.
    pub async fn witnessed_roster_refresh_progress(&self) -> Result<Option<Progress>, JsValue> {
        Ok(self
            .inner
            .witnessed_roster_refresh_progress()
            .await?
            .map(|inner| Progress { inner }))
    }
    /// Retain the operation ID before dispatch. Returned public bytes still
    /// require independent root-authorized witness preparation.
    pub async fn prepare_witnessed_roster_refresh(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
        policy: &SessionPolicy,
        target: &Target,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Proposal, JsValue> {
        Ok(Proposal {
            inner: self
                .inner
                .prepare_witnessed_roster_refresh(
                    operation(id)?,
                    &original.inner,
                    &policy.inner,
                    &target.inner,
                    read_time(now)?,
                    witness_config(self, witness)?,
                )
                .await?,
        })
    }
    pub async fn recover_witnessed_roster_refresh_preparation(
        &self,
        original: &HistoricalPolicy,
    ) -> Result<Option<Proposal>, JsValue> {
        Ok(self
            .inner
            .recover_witnessed_roster_refresh_preparation(&original.inner)
            .await?
            .map(|inner| Proposal { inner }))
    }
    pub async fn abandon_unprepared_roster_refresh(
        &self,
        id: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<Progress, JsValue> {
        Ok(Progress {
            inner: self
                .inner
                .abandon_unprepared_roster_refresh(operation(id)?, &original.inner)
                .await?,
        })
    }
    /// Finish original terminal/ACK/cleanup after an unknown result or expiry.
    pub async fn reconcile_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .reconcile_witnessed_roster_refresh(
                &proposal.inner,
                &original.inner,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
    pub async fn commit_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalPolicy,
        policy: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .commit_witnessed_roster_refresh(
                &proposal.inner,
                &original.inner,
                &policy.inner,
                read_time(now)?,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
    /// Close the original target; an already committed outcome remains Applied.
    pub async fn close_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<WitnessState, JsValue> {
        Ok(self
            .inner
            .close_witnessed_roster_refresh(
                &proposal.inner,
                &original.inner,
                witness_config(self, witness)?,
            )
            .await?
            .into())
    }
}
