// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn identity(id: &Uint8Array) -> Result<engine::PrekeyPublicationId, JsValue> {
    engine::PrekeyPublicationId::from_trusted_state(array(id)?).map_err(protocol)
}

/// Ordered public advertisement intent. The complete plan is copied at dispatch.
#[wasm_bindgen(js_name = QPeriaptContinuityPublicationPlan)]
pub struct Plan {
    directory: [u8; 32],
    validity: engine::Validity,
    keys: Vec<engine::PrekeyPublicationKey>,
}
impl Plan {
    fn complete(&self) -> Result<engine::PrekeyPublicationPlan, JsValue> {
        engine::PrekeyPublicationPlan::new(self.directory, self.validity, &self.keys)
            .map_err(protocol)
    }
    fn push(&mut self, key: engine::PrekeyPublicationKey) -> Result<(), JsValue> {
        if self.keys.len() >= engine::MAX_PREKEYS {
            return Err(protocol(engine::Error::Capacity));
        }
        if key.validity().from() < self.validity.from()
            || key.validity().until() > self.validity.until()
        {
            return Err(protocol(engine::Error::Validity));
        }
        self.keys.push(key);
        Ok(())
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityPublicationPlan)]
impl Plan {
    #[wasm_bindgen(constructor)]
    pub fn new(
        directory: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] from: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] until: JsValue,
    ) -> Result<Plan, JsValue> {
        let directory = array(directory)?;
        if directory == [0; 32] {
            return Err(protocol(engine::Error::Encoding));
        }
        Ok(Self {
            directory,
            validity: engine::Validity::new(read_time(from)?, read_time(until)?)
                .map_err(protocol)?,
            keys: Vec::new(),
        })
    }
    /// Add an original publication-owned key in this exact member order.
    pub fn generate(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityPrekeyKind")] kind: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] from: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] until: JsValue,
    ) -> Result<(), JsValue> {
        self.push(engine::PrekeyPublicationKey::generate(
            read_kind(&kind)?.into(),
            engine::Validity::new(read_time(from)?, read_time(until)?).map_err(protocol)?,
        ))
    }
    /// Reuse an available inventory request with its original role and validity.
    pub fn reuse(
        &mut self,
        id: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityPrekeyKind")] kind: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] from: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] until: JsValue,
    ) -> Result<(), JsValue> {
        let id = engine::PrekeyId::from_trusted_state(array(id)?).map_err(protocol)?;
        self.push(engine::PrekeyPublicationKey::reuse(
            id,
            read_kind(&kind)?.into(),
            engine::Validity::new(read_time(from)?, read_time(until)?).map_err(protocol)?,
        ))
    }
    /// Validate the complete bootstrap membership and bound the public output.
    pub fn artifact_size_bound(&self) -> Result<usize, JsValue> {
        self.complete()?.artifact_size_bound().map_err(protocol)
    }
}

/// Local original history; Prepared does not imply remote distribution.
#[wasm_bindgen(js_name = QPeriaptContinuityPublicationPhase)]
pub enum Phase {
    Absent = 0,
    Reserved = 1,
    Prepared = 2,
    Retired = 3,
}
/// Immutable publication observation, carrying no permission to use its keys.
#[wasm_bindgen(js_name = QPeriaptContinuityPublicationStatus)]
pub struct Status {
    inner: engine::PrekeyPublicationStatus,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPublicationStatus)]
impl Status {
    pub fn phase(&self) -> Phase {
        use engine::PrekeyPublicationStatus as E;
        match self.inner {
            E::Absent => Phase::Absent,
            E::Reserved { .. } => Phase::Reserved,
            E::Prepared { .. } => Phase::Prepared,
            E::Retired => Phase::Retired,
        }
    }
    pub fn intent_digest(&self) -> Option<Vec<u8>> {
        use engine::PrekeyPublicationStatus as E;
        match self.inner {
            E::Reserved { intent } | E::Prepared { intent, .. } => Some(intent.to_vec()),
            _ => None,
        }
    }
    pub fn artifact_digest(&self) -> Option<Vec<u8>> {
        match self.inner {
            engine::PrekeyPublicationStatus::Prepared { artifact, .. } => Some(artifact.to_vec()),
            _ => None,
        }
    }
    pub fn manifest_digest(&self) -> Option<Vec<u8>> {
        match self.inner {
            engine::PrekeyPublicationStatus::Prepared { manifest, .. } => Some(manifest.to_vec()),
            _ => None,
        }
    }
}
/// Exact locally committed signed advertisement; contains only public material.
#[wasm_bindgen(js_name = QPeriaptContinuityPreparedPublication)]
pub struct Prepared {
    inner: engine::PreparedPrekeyPublication,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPreparedPublication)]
impl Prepared {
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
    pub fn id(&self) -> Vec<u8> {
        self.inner.id().as_bytes().to_vec()
    }
    pub fn intent_digest(&self) -> Vec<u8> {
        self.inner.intent_digest().to_vec()
    }
    pub fn artifact_digest(&self) -> Vec<u8> {
        self.inner.artifact_digest().to_vec()
    }
    #[wasm_bindgen(unchecked_return_type = "Uint8Array[]")]
    pub fn inventory_requests(&self) -> js_sys::Array {
        self.inner
            .inventory_requests()
            .iter()
            .map(|id| JsValue::from(Uint8Array::from(id.as_bytes().as_slice())))
            .collect()
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Observe the next identity before dispatch; retain it with the complete plan.
    pub async fn next_publication_id(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.next_publication_id().await?.as_bytes().to_vec())
    }
    pub async fn publication_status(&self, id: &Uint8Array) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self.inner.publication_status(identity(id)?).await?,
        })
    }
    /// Prepare/recover the original advertisement. `clock` must return current
    /// trusted Unix seconds as a bigint. Success is local preparation, not delivery.
    pub async fn prepare_publication(
        &self,
        id: &Uint8Array,
        plan: &Plan,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
        #[wasm_bindgen(unchecked_param_type = "() => bigint")] clock: js_sys::Function,
    ) -> Result<Prepared, JsValue> {
        let id = identity(id)?;
        let plan = plan.complete()?;
        let timeout = Duration::from_millis(read_limit(&timeout_ms, 60000)? as u64);
        Ok(Prepared {
            inner: self
                .inner
                .prepare_publication(id, &plan, &policy.inner, timeout, &clock)
                .await?,
        })
    }
    /// Retire exact local artifact history, independently of inventory retirement.
    pub async fn retire_publication(
        &self,
        id: &Uint8Array,
        artifact: &Uint8Array,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .retire_publication(identity(id)?, array(artifact)?)
                .await?,
        })
    }
    /// Abandon the original Reserved intent only; this does not revoke reused keys.
    pub async fn abandon_publication(
        &self,
        id: &Uint8Array,
        intent: &Uint8Array,
        policy: &SessionPolicy,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .abandon_publication(identity(id)?, array(intent)?, &policy.inner)
                .await?,
        })
    }
}
