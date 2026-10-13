// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
/// Independently pinned signed protocol policy using the real SDK runtime owner.
#[wasm_bindgen(js_name = QPeriaptContinuityPolicy)]
pub struct SessionPolicy {
    pub(super) inner: engine::VerifiedSessionPolicy,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPolicy)]
impl SessionPolicy {
    /// Verify the protocol statement against independent signer/family/checkpoint inputs.
    #[wasm_bindgen(constructor)]
    pub fn new(
        runtime: &Runtime,
        root: &Uint8Array,
        family: &Uint8Array,
        version: u64,
        digest: &Uint8Array,
        statement: &Uint8Array,
        now: u64,
    ) -> Result<SessionPolicy, JsValue> {
        let public = engine::PublicKey::decode(&read_input(
            root,
            engine::PUBLIC_KEY_BYTES,
            engine::PUBLIC_KEY_BYTES,
        )?)
        .map_err(protocol)?;
        let checkpoint = engine::PolicyCheckpoint::from_trusted_state(version, array(digest)?)
            .map_err(protocol)?;
        let pin = engine::PolicyPin::new(array(family)?, public, checkpoint).map_err(protocol)?;
        let statement = read_input(statement, 1, 8192)?;
        Ok(Self {
            inner: pin
                .verify(&statement, runtime.inner.clone(), now)
                .map_err(protocol)?,
        })
    }
    /// Close protocol-policy authority for subsequent operations.
    pub fn close(&self) {
        self.inner.close();
    }
}
/// Independent account-root and roster checkpoint expected for this enrollment.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountTrust)]
pub struct AccountTrust {
    pub(super) inner: engine::AccountPin,
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountTrust)]
impl AccountTrust {
    /// Pin externally approved account, root, roster head and policy family.
    #[wasm_bindgen(constructor)]
    pub fn new(
        account: &Uint8Array,
        root: &Uint8Array,
        version: u64,
        digest: &Uint8Array,
        family: &Uint8Array,
    ) -> Result<AccountTrust, JsValue> {
        let public = engine::PublicKey::decode(&read_input(
            root,
            engine::PUBLIC_KEY_BYTES,
            engine::PUBLIC_KEY_BYTES,
        )?)
        .map_err(protocol)?;
        let checkpoint = engine::RosterCheckpoint::from_trusted_state(version, array(digest)?)
            .map_err(protocol)?;
        Ok(Self {
            inner: engine::AccountPin::new(array(account)?, public, checkpoint, array(family)?)
                .map_err(protocol)?,
        })
    }
}
/// Reusable independent witness pin and endpoint configuration; not an enrollment receipt.
#[wasm_bindgen(js_name = QPeriaptContinuityWitness)]
pub struct Witness {
    pub(super) pin: engine::AnchorPin,
    endpoint: String,
    pub(super) timeout: Duration,
    loopback: bool,
}
#[wasm_bindgen(js_class = QPeriaptContinuityWitness)]
impl Witness {
    /// Admit an HTTPS endpoint. Timeout must be a number integer in 1..=60000 ms.
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity: &Uint8Array,
        public: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "string")] endpoint: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
    ) -> Result<Witness, JsValue> {
        Self::checked(identity, public, text(&endpoint, 4096)?, timeout_ms, false)
    }
    /// Explicit HTTP loopback diagnostics. Remote HTTP and HTTPS fallback are refused.
    pub fn for_loopback(
        identity: &Uint8Array,
        public: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "string")] endpoint: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number")] timeout_ms: JsValue,
    ) -> Result<Witness, JsValue> {
        Self::checked(identity, public, text(&endpoint, 4096)?, timeout_ms, true)
    }
}
impl Witness {
    fn checked(
        identity: &Uint8Array,
        public: &Uint8Array,
        endpoint: String,
        timeout_ms: JsValue,
        loopback: bool,
    ) -> Result<Self, JsValue> {
        let identity =
            engine::AnchorIdentity::from_trusted_state(array(identity)?).map_err(protocol)?;
        let public = engine::PublicKey::decode(&read_input(
            public,
            engine::PUBLIC_KEY_BYTES,
            engine::PUBLIC_KEY_BYTES,
        )?)
        .map_err(protocol)?;
        let owner = Self {
            pin: engine::AnchorPin::new(identity, public),
            endpoint,
            timeout: Duration::from_millis(read_limit(&timeout_ms, 60000)? as u64),
            loopback,
        };
        owner.carrier(engine::Cancellation::default())?;
        Ok(owner)
    }
    pub(super) fn carrier(
        &self,
        cancel: engine::Cancellation,
    ) -> Result<engine::AnchorFetchTransport, JsValue> {
        let carrier = if self.loopback {
            engine::AnchorFetchTransport::for_loopback(&self.endpoint, cancel)
        } else {
            engine::AnchorFetchTransport::with_cancellation(&self.endpoint, cancel)
        };
        carrier.map_err(|error| failure(&engine::DurableError::Io(error)))
    }
}

/// Independently approved enrollment intent; contains no private key or fixture state.
#[wasm_bindgen(js_name = QPeriaptContinuityEnrollment)]
pub struct Enrollment {
    pub(super) root: Vec<u8>,
    pub(super) description: Vec<u8>,
}
#[wasm_bindgen(js_class = QPeriaptContinuityEnrollment)]
impl Enrollment {
    /// Bind the account root, distinct device generation, policy family and validity.
    #[wasm_bindgen(constructor)]
    pub fn new(
        root: &Uint8Array,
        device: &Uint8Array,
        generation: u64,
        family: &Uint8Array,
        from: u64,
        until: u64,
    ) -> Result<Enrollment, JsValue> {
        let root = read_input(root, engine::PUBLIC_KEY_BYTES, engine::PUBLIC_KEY_BYTES)?;
        engine::PublicKey::decode(&root).map_err(protocol)?;
        let device: [u8; 16] = read_input(device, 16, 16)?
            .try_into()
            .map_err(|_| protocol(engine::Error::Encoding))?;
        let family = array(family)?;
        let validity = engine::Validity::new(from, until).map_err(protocol)?;
        engine::DeviceDescription::new(device, generation, family, validity).map_err(protocol)?;
        let mut description = Vec::with_capacity(72);
        description.extend_from_slice(&device);
        description.extend_from_slice(&generation.to_be_bytes());
        description.extend_from_slice(&family);
        description.extend_from_slice(&from.to_be_bytes());
        description.extend_from_slice(&until.to_be_bytes());
        Ok(Self { root, description })
    }
}
