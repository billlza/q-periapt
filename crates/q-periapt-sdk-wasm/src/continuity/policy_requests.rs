// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::history::HistoricalPolicy;
use super::*;

/// Exact original policy-only issuer scope. Public metadata is not independent
/// issuer approval, user authentication, a durable reservation or traffic authority.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicyRequest)]
pub struct Request {
    pub(super) inner: engine::PolicyRenewalRequest,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicyRequest)]
impl Request {
    pub fn new_operation_id() -> Result<Vec<u8>, JsValue> {
        Ok(engine::PolicyRenewalId::generate()
            .map_err(protocol)?
            .as_bytes()
            .to_vec())
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.scope().operation.as_bytes().to_vec()
    }
    pub fn journal(&self) -> Vec<u8> {
        self.inner.scope().journal.as_bytes().to_vec()
    }
    pub fn original_owner(&self) -> Vec<u8> {
        self.inner.scope().original_owner.to_vec()
    }
    pub fn original_credential_digest(&self) -> Vec<u8> {
        self.inner.scope().original_credential.to_vec()
    }
    pub fn current_credential_digest(&self) -> Vec<u8> {
        self.inner.scope().current_credential.to_vec()
    }
    pub fn current_roster_version(&self) -> u64 {
        self.inner.scope().current_roster.version()
    }
    pub fn current_roster_digest(&self) -> Vec<u8> {
        self.inner.scope().current_roster.digest().to_vec()
    }
    pub fn original_policy_version(&self) -> u64 {
        self.inner.scope().original_policy.version()
    }
    pub fn original_policy_digest(&self) -> Vec<u8> {
        self.inner.scope().original_policy.digest().to_vec()
    }
    pub fn previous_policy_version(&self) -> u64 {
        self.inner.scope().previous_policy.version()
    }
    pub fn previous_policy_digest(&self) -> Vec<u8> {
        self.inner.scope().previous_policy.digest().to_vec()
    }
    pub fn previous_policy_authorization(&self) -> Option<Vec<u8>> {
        self.inner
            .scope()
            .previous_authorization
            .map(|v| v.to_vec())
    }
    pub fn original_credential(&self) -> Vec<u8> {
        self.inner.original_credential().to_vec()
    }
    pub fn original_roster(&self) -> Vec<u8> {
        self.inner.original_roster().to_vec()
    }
    pub fn current_credential(&self) -> Vec<u8> {
        self.inner.current_credential().to_vec()
    }
    pub fn current_roster(&self) -> Vec<u8> {
        self.inner.current_roster().to_vec()
    }
}

fn id(value: &Uint8Array) -> Result<engine::PolicyRenewalId, JsValue> {
    engine::PolicyRenewalId::from_trusted_state(array(value)?).map_err(protocol)
}

#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    pub async fn policy_renewal_request(
        &self,
        operation: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<Request, JsValue> {
        Ok(Request {
            inner: self
                .inner
                .policy_renewal_request(id(operation)?, &original.inner)
                .await?,
        })
    }
    pub async fn witnessed_policy_renewal_request(
        &self,
        operation: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<Request, JsValue> {
        Ok(Request {
            inner: self
                .inner
                .witnessed_policy_renewal_request(
                    id(operation)?,
                    &original.inner,
                    (
                        witness.pin.clone(),
                        Box::new(witness.carrier(self.inner.cancellation())?),
                        witness.timeout,
                    ),
                )
                .await?,
        })
    }
}
