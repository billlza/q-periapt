// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::history::HistoricalPolicy;
use super::*;

/// Public original issuer materials, not a reservation, user authentication or
/// current traffic permission. Keep the exact request and ID across retries.
#[wasm_bindgen(js_name = QPeriaptContinuityCredentialRequest)]
pub struct Request {
    inner: engine::CredentialRenewalRequest,
}
#[wasm_bindgen(js_class = QPeriaptContinuityCredentialRequest)]
impl Request {
    pub fn new_operation_id() -> Result<Vec<u8>, JsValue> {
        Ok(engine::CredentialRenewalId::generate()
            .map_err(protocol)?
            .as_bytes()
            .to_vec())
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.operation().as_bytes().to_vec()
    }
    pub fn journal(&self) -> Vec<u8> {
        self.inner.journal().as_bytes().to_vec()
    }
    pub fn original_owner(&self) -> Vec<u8> {
        self.inner.original_owner().to_vec()
    }
    pub fn original_policy_digest(&self) -> Vec<u8> {
        self.inner.authorization().policy_digest.to_vec()
    }
    pub fn current_policy_version(&self) -> u64 {
        self.inner.current_policy().version()
    }
    pub fn current_policy_digest(&self) -> Vec<u8> {
        self.inner.current_policy().digest().to_vec()
    }
    pub fn current_policy_authorization(&self) -> Option<Vec<u8>> {
        self.inner
            .current_policy_authorization()
            .map(|v| v.to_vec())
    }
    pub fn original_roster_version(&self) -> u64 {
        self.inner.original_device().roster().checkpoint().version()
    }
    pub fn original_roster_digest(&self) -> Vec<u8> {
        self.inner
            .original_device()
            .roster()
            .checkpoint()
            .digest()
            .to_vec()
    }
    pub fn previous_roster_version(&self) -> u64 {
        self.inner.authorization().previous.version()
    }
    pub fn previous_roster_digest(&self) -> Vec<u8> {
        self.inner.authorization().previous.digest().to_vec()
    }
    pub fn previous_valid_from(&self) -> u64 {
        self.inner.previous_validity().from()
    }
    pub fn previous_valid_until(&self) -> u64 {
        self.inner.previous_validity().until()
    }
    pub fn original_credential(&self) -> Vec<u8> {
        self.inner.original_credential().to_vec()
    }
    pub fn original_roster(&self) -> Vec<u8> {
        self.inner.original_roster().to_vec()
    }
    pub fn previous_credential(&self) -> Vec<u8> {
        self.inner.previous_credential().to_vec()
    }
    pub fn previous_roster(&self) -> Vec<u8> {
        self.inner.previous_roster().to_vec()
    }
}
fn id(value: &Uint8Array) -> Result<engine::CredentialRenewalId, JsValue> {
    engine::CredentialRenewalId::from_trusted_state(array(value)?).map_err(protocol)
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    pub async fn credential_renewal_request(
        &self,
        operation: &Uint8Array,
        original: &HistoricalPolicy,
    ) -> Result<Request, JsValue> {
        Ok(Request {
            inner: self
                .inner
                .credential_renewal_request(id(operation)?, &original.inner)
                .await?,
        })
    }
    pub async fn witnessed_credential_renewal_request(
        &self,
        operation: &Uint8Array,
        original: &HistoricalPolicy,
        witness: &Witness,
    ) -> Result<Request, JsValue> {
        Ok(Request {
            inner: self
                .inner
                .witnessed_credential_renewal_request(
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
