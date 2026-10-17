// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::Arc;

/// An exact device and generation under an independently retained account pin.
#[wasm_bindgen(js_name = QPeriaptContinuityParticipant)]
#[derive(Clone)]
pub struct Participant {
    pin: Arc<engine::AccountPin>,
    device: [u8; 16],
    generation: u64,
}
impl Participant {
    fn expected(&self) -> Result<engine::ExpectedDevice<'_>, JsValue> {
        engine::ExpectedDevice::new(&self.pin, self.device, self.generation).map_err(protocol)
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityParticipant)]
impl Participant {
    #[wasm_bindgen(constructor)]
    pub fn new(
        account: &AccountTrust,
        device: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] generation: JsValue,
    ) -> Result<Participant, JsValue> {
        let owner = Self {
            pin: Arc::clone(&account.inner),
            device: read_input(device, 16, 16)?
                .try_into()
                .map_err(|_| protocol(engine::Error::Encoding))?,
            generation: read_time(generation)?,
        };
        owner.expected()?;
        Ok(owner)
    }
}
/// Independent admission expectations. Incoming bytes cannot select these values.
#[wasm_bindgen(js_name = QPeriaptContinuityPeerTrust)]
pub struct Trust {
    initiator: Participant,
    responder: Participant,
    quality: engine::PrekeyQuality,
    directory: engine::DirectoryExpectation,
}
impl Trust {
    pub(super) fn required(&self) -> Result<engine::BootstrapRequirements<'_>, JsValue> {
        Ok(engine::BootstrapRequirements {
            initiator: self.initiator.expected()?,
            responder: self.responder.expected()?,
            quality: self.quality,
            directory: self.directory,
        })
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityPeerTrust)]
impl Trust {
    #[wasm_bindgen(constructor)]
    pub fn new(
        initiator: &Participant,
        responder: &Participant,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityQuality")] quality: JsValue,
        directory: &Uint8Array,
    ) -> Result<Trust, JsValue> {
        let quality = match read_limit(&quality, 4)? {
            1 => engine::PrekeyQuality::OneTimeBoth,
            2 => engine::PrekeyQuality::ReusableBoth,
            3 => engine::PrekeyQuality::SignedClassicalOneTimePq,
            4 => engine::PrekeyQuality::OneTimeClassicalLastResortPq,
            _ => return Err(protocol(engine::Error::Encoding)),
        };
        Ok(Self {
            initiator: initiator.clone(),
            responder: responder.clone(),
            quality,
            directory: engine::DirectoryExpectation::from_trusted_state(array(directory)?)
                .map_err(protocol)?,
        })
    }
}
#[wasm_bindgen(js_name = QPeriaptContinuityQuality)]
pub enum Quality {
    OneTimeBoth = 1,
    ReusableBoth = 2,
    SignedClassicalOneTimePq = 3,
    OneTimeClassicalLastResortPq = 4,
}
#[wasm_bindgen(js_name = QPeriaptContinuityRole)]
pub enum Role {
    Initiator = 1,
    Responder = 2,
}
pub(super) fn role(value: &JsValue) -> Result<engine::BootstrapRole, JsValue> {
    match read_limit(value, 2)? {
        1 => Ok(engine::BootstrapRole::Initiator),
        2 => Ok(engine::BootstrapRole::Responder),
        _ => Err(protocol(engine::Error::Encoding)),
    }
}
pub(super) fn public_role(value: engine::BootstrapRole) -> Role {
    match value {
        engine::BootstrapRole::Initiator => Role::Initiator,
        engine::BootstrapRole::Responder => Role::Responder,
    }
}
/// Authenticated public peer preview checked against one original device owner.
#[wasm_bindgen(js_name = QPeriaptContinuityPeer)]
pub struct Peer {
    pub(super) inner: engine::BootstrapPeer,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPeer)]
impl Peer {
    pub fn role(&self) -> Role {
        public_role(self.inner.role())
    }
    /// Generate once and retain for every retry. This reserves no authority or state.
    pub fn new_request_id() -> Result<Vec<u8>, JsValue> {
        Ok(engine::InitiationId::generate()
            .map_err(protocol)?
            .as_bytes()
            .to_vec())
    }
}
/// Explicit bounded HTTP endpoint. The protocol authenticates independent peer pins.
#[wasm_bindgen(js_name = QPeriaptContinuityEndpoint)]
pub struct Endpoint {
    pub(super) inner: engine::browser::PeerEndpoint,
}
#[wasm_bindgen(js_class = QPeriaptContinuityEndpoint)]
impl Endpoint {
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "string")] value: JsValue,
    ) -> Result<Endpoint, JsValue> {
        Ok(Self {
            inner: engine::browser::PeerEndpoint::new(&text(&value, 4096)?)
                .map_err(|e| failure(&engine::DurableError::Io(e)))?,
        })
    }
    pub fn for_loopback(
        #[wasm_bindgen(unchecked_param_type = "string")] value: JsValue,
    ) -> Result<Endpoint, JsValue> {
        Ok(Self {
            inner: engine::browser::PeerEndpoint::for_loopback(&text(&value, 4096)?)
                .map_err(|e| failure(&engine::DurableError::Io(e)))?,
        })
    }
}
pub(super) fn bundle(value: &Uint8Array) -> Result<engine::BootstrapBundle, JsValue> {
    engine::BootstrapBundle::from_bytes(&read_input(value, 1, engine::MAX_BOOTSTRAP_BUNDLE_BYTES)?)
        .map_err(protocol)
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Admit an untrusted public bundle under independently retained expectations.
    pub async fn admit_peer(
        &self,
        wire: &Uint8Array,
        policy: &SessionPolicy,
        trust: &Trust,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptContinuityRole")] local_role: JsValue,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Peer, JsValue> {
        Ok(Peer {
            inner: self
                .inner
                .admit_peer(
                    &bundle(wire)?,
                    Arc::clone(&policy.inner),
                    trust.required()?,
                    role(&local_role)?,
                    read_time(now)?,
                )
                .await?,
        })
    }
}
