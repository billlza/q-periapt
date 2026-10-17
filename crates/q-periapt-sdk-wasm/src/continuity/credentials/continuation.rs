// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::credential_requests::Request;
use super::*;

/// Both root approvals verified against the exact observed request and target.
/// This is not a commit, a reservation or permission to use an active device.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyContinuation)]
pub struct Continuation {
    inner: engine::VerifiedPolicyContinuation,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicyContinuation)]
impl Continuation {
    #[wasm_bindgen(constructor)]
    pub fn new(
        approvals: &Uint8Array,
        request: &Request,
        grant: &Grant,
        original: &HistoricalPolicy,
        previous: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: engine::VerifiedPolicyContinuation::from_bytes(
                &read_input(
                    approvals,
                    engine::MAX_POLICY_CONTINUATION_BYTES,
                    engine::MAX_POLICY_CONTINUATION_BYTES,
                )?,
                &request.inner.policy_continuation_scope(),
                &engine::PolicyContinuationMaterials {
                    original: &original.inner,
                    previous: &previous.inner,
                    target: &target.inner,
                    credential: &grant.inner,
                },
                read_time(now)?,
            )
            .map_err(protocol)?,
        })
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.scope().operation.as_bytes().to_vec()
    }
    /// The T transaction statement, distinct from the account credential G.
    pub fn statement(&self) -> Vec<u8> {
        self.inner.statement_digest().to_vec()
    }
    pub fn credential_statement(&self) -> Vec<u8> {
        self.inner.credential_statement().to_vec()
    }
    pub fn previous_statement(&self) -> Option<Vec<u8>> {
        self.inner
            .scope()
            .previous_authorization
            .map(|v| v.to_vec())
    }
    pub fn target_version(&self) -> u64 {
        self.inner.target_policy().version()
    }
    pub fn target_digest(&self) -> Vec<u8> {
        self.inner.target_policy().digest().to_vec()
    }
}

#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Stage G and T together in the original enrollment, before any activation.
    pub async fn stage_policy_continuation(
        &self,
        grant: &Grant,
        continuation: &Continuation,
        id: &Uint8Array,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .stage_policy_continuation(
                    &grant.inner,
                    &continuation.inner,
                    operation(id)?,
                    &target.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Local-only coordination. Required witness never falls back to this route.
    pub async fn reconcile_policy_continuation(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self
                .inner
                .reconcile_policy_continuation(&original.inner, &target.inner, read_time(now)?)
                .await?,
        })
    }
    /// Historical local reconciliation grants no current traffic authority.
    pub async fn recover_historical_policy_continuation(
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
                .recover_historical_policy_continuation(
                    operation(id)?,
                    array(statement)?,
                    &original.inner,
                    &target.inner,
                    read_time(now)?,
                )
                .await?,
        })
    }
    /// Reopen original sessions only after successful current target admission.
    pub async fn activate_local_policy_continuation(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .activate_policy_continuation(&original.inner, &target.inner, read_time(now)?, None)
            .await?
            .as_bytes()
            .to_vec())
    }
    /// Explicit required-witness admission, after its original terminal is retained.
    pub async fn activate_witnessed_policy_continuation(
        &self,
        original: &HistoricalPolicy,
        target: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .activate_policy_continuation(
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
