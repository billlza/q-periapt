// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Logical inventory state, not proof of physical/backup erasure or fresh authorization.
#[wasm_bindgen(js_name = QPeriaptContinuityPrekeyStatus)]
pub enum Status {
    Absent = 0,
    Reserved = 1,
    Available = 2,
    Consumed = 3,
    Abandoned = 4,
    Retired = 5,
}
impl From<engine::PrekeyStatus> for Status {
    fn from(value: engine::PrekeyStatus) -> Self {
        match value {
            engine::PrekeyStatus::Absent => Self::Absent,
            engine::PrekeyStatus::Reserved => Self::Reserved,
            engine::PrekeyStatus::Available => Self::Available,
            engine::PrekeyStatus::Consumed => Self::Consumed,
            engine::PrekeyStatus::Abandoned => Self::Abandoned,
            engine::PrekeyStatus::Retired => Self::Retired,
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Generate/recover an original public prekey; this does not publish it remotely.
    pub async fn generate_prekey(
        &self,
        policy: &SessionPolicy,
        id: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityPrekeyKind")] kind: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] from: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] until: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let id = engine::PrekeyId::from_trusted_state(array(id)?).map_err(protocol)?;
        let kind = read_kind(&kind)?;
        let validity =
            engine::Validity::new(read_time(from)?, read_time(until)?).map_err(protocol)?;
        self.inner
            .generate_prekey(&policy.inner, id, kind.into(), validity, read_time(now)?)
            .await
    }
    /// Observe the original request, including after runtime close. No public key is released.
    pub async fn prekey_status(
        &self,
        policy: &SessionPolicy,
        id: &Uint8Array,
    ) -> Result<Status, JsValue> {
        let id = engine::PrekeyId::from_trusted_state(array(id)?).map_err(protocol)?;
        Ok(self.inner.prekey_status(&policy.inner, id).await?.into())
    }
    /// Remove the logical key-recovery command; keep consumed/abandoned states and pending-response checks.
    /// This does not retract distributed advertisements or erase historical backups.
    pub async fn retire_prekey(
        &self,
        policy: &SessionPolicy,
        id: &Uint8Array,
    ) -> Result<Status, JsValue> {
        let id = engine::PrekeyId::from_trusted_state(array(id)?).map_err(protocol)?;
        Ok(self.inner.retire_prekey(&policy.inner, id).await?.into())
    }
}
