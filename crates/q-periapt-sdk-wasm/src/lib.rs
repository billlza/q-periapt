// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Product WASM surface. The separate `q-periapt-wasm` module retains expert/KAT
//! operations; this module has no caller coins or raw combiner. Plaintext private
//! key transfer is isolated in the explicitly named `QPeriaptExpert` API.
//! Objects are ownership controls, not isolation from malicious same-realm JS.
use js_sys::Uint8Array;
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{self as sdk, Ciphertext, PublicKey};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

/// Named global protocol directions for the version-1 SDK key schedule.
#[wasm_bindgen(js_name = QPeriaptKeyPurpose)]
pub enum KeyPurpose {
    /// Initiator-to-responder application traffic.
    InitiatorTraffic = 1,
    /// Responder-to-initiator application traffic.
    ResponderTraffic = 2,
    /// Initiator key-confirmation computation.
    InitiatorConfirmation = 3,
    /// Responder key-confirmation computation.
    ResponderConfirmation = 4,
    /// Application-specific exporter (separate labels for separate uses).
    Exporter = 5,
}

fn error(e: sdk::Error) -> JsError {
    JsError::new(&e.to_string())
}

fn read_limit(value: &JsValue, maximum: usize) -> Result<usize, JsError> {
    let number = value
        .as_f64()
        .ok_or_else(|| error(sdk::Error::InvalidLimits))?;
    // Validate the original JS value before any integer conversion. wasm-bindgen's
    // u32 ABI would otherwise wrap large values and coerce strings/booleans.
    if !number.is_finite() || number.fract() != 0.0 || !(1.0..=maximum as f64).contains(&number) {
        return Err(error(sdk::Error::InvalidLimits));
    }
    Ok(number as usize)
}

struct WipingInput(Vec<u8>);
impl Drop for WipingInput {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.0);
    }
}

fn read_input(input: &Uint8Array, min: usize, max: usize) -> Result<Vec<u8>, JsError> {
    if !JsValue::from(input.clone()).is_instance_of::<Uint8Array>() {
        return Err(JsError::new("expected Uint8Array"));
    }
    let len = input.length() as usize;
    if len < min || len > max {
        return Err(error(sdk::Error::InvalidLength));
    }
    // Check JS length before wasm-bindgen copies bytes into linear memory.
    Ok(input.to_vec())
}

/// An immutable signed-policy runtime, with WebCrypto-backed randomness.
#[wasm_bindgen(js_name = QPeriaptRuntime)]
pub struct Runtime {
    inner: Arc<sdk::Runtime>,
}
#[wasm_bindgen(js_class = QPeriaptRuntime)]
impl Runtime {
    /// Verify the signed policy; the host supplies the pinned root and trusted state.
    /// Empty previous state is first installation, not a rollback recovery mode.
    /// Limits must be JavaScript numbers: integers in 1..=1024 and 1..=64.
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy: &Uint8Array,
        signature: &Uint8Array,
        trust_root: &Uint8Array,
        previous_state: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "number")] max_keys: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number")] max_in_flight: JsValue,
    ) -> Result<Runtime, JsError> {
        let limits = sdk::Limits {
            max_live_keys: read_limit(&max_keys, 1024)?,
            max_in_flight: read_limit(&max_in_flight, 64)?,
        };
        let policy = read_input(policy, 1, 65_536)?;
        let signature = read_input(signature, 3309, 3309)?;
        let trust_root = read_input(trust_root, 1952, 1952)?;
        let previous_state = read_input(previous_state, 0, TrustedPolicyState::ENCODED_LEN)?;
        let previous = if previous_state.is_empty() {
            None
        } else {
            if previous_state.len() != TrustedPolicyState::ENCODED_LEN {
                return Err(error(sdk::Error::InvalidLength));
            }
            Some(
                TrustedPolicyState::decode(&previous_state)
                    .map_err(|_| error(sdk::Error::PolicyDenied))?,
            )
        };
        let inner = sdk::Runtime::from_signed_policy(
            &policy,
            &signature,
            &trust_root,
            previous.as_ref(),
            limits,
        )
        .map_err(error)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
    /// Persist atomically before using the runtime; no persistent store is provided.
    pub fn trusted_state(&self) -> Result<Vec<u8>, JsError> {
        self.inner.is_enabled().map_err(error)?;
        Ok(self.inner.trusted_state().encode().to_vec())
    }
    /// A valid policy can disable the fixed suite while preserving trusted state
    /// and the ability to accept future signed updates. Key operations then fail.
    pub fn is_enabled(&self) -> Result<bool, JsError> {
        self.inner.is_enabled().map_err(error)
    }
    /// Prepare a strictly newer policy using this runtime's pinned root.
    pub fn prepare_policy_update(
        &self,
        policy: &Uint8Array,
        signature: &Uint8Array,
    ) -> Result<PolicyUpdate, JsError> {
        let policy = read_input(policy, 1, 65_536)?;
        let signature = read_input(signature, 3309, 3309)?;
        self.inner
            .prepare_policy_update(&policy, &signature)
            .map(|inner| PolicyUpdate { inner: Some(inner) })
            .map_err(error)
    }
    /// Generate a hybrid key. Entropy failure rejects instead of using a fallback.
    pub fn generate_key(&self) -> Result<Key, JsError> {
        self.inner
            .generate_key()
            .map(|inner| Key { inner })
            .map_err(error)
    }
    /// Encapsulate using fresh platform coins under this runtime's policy.
    pub fn encapsulate(
        &self,
        public_key: &Uint8Array,
        context: &Uint8Array,
    ) -> Result<Encapsulation, JsError> {
        let public_key = read_input(public_key, sdk::PUBLIC_KEY_LEN, sdk::PUBLIC_KEY_LEN)?;
        let context = WipingInput(read_input(context, 0, 65_536)?);
        let peer = PublicKey::from_bytes(&public_key).map_err(error)?;
        let result = self.inner.encapsulate(&peer, &context.0).map_err(error)?;
        Ok(Encapsulation {
            ciphertext: result.ciphertext,
            secret: Some(result.secret),
        })
    }
    /// Revoke new runtime/key operations. Already exported secrets cannot be revoked.
    pub fn close(&self) {
        self.inner.close();
    }
}

/// Hybrid private-key owner. No secret-key getter or import constructor.
#[wasm_bindgen(js_name = QPeriaptKey)]
pub struct Key {
    inner: sdk::HybridKey,
}
#[wasm_bindgen(js_class = QPeriaptKey)]
impl Key {
    /// Export public bytes only.
    pub fn public_key(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .public_key()
            .map(|key| key.to_bytes().to_vec())
            .map_err(error)
    }
    /// Decapsulate with this key's paired public key and verified runtime.
    pub fn decapsulate(
        &self,
        ciphertext: &Uint8Array,
        context: &Uint8Array,
    ) -> Result<SharedSecret, JsError> {
        let ciphertext = read_input(ciphertext, sdk::CIPHERTEXT_LEN, sdk::CIPHERTEXT_LEN)?;
        let context = WipingInput(read_input(context, 0, 65_536)?);
        let ciphertext = Ciphertext::from_bytes(&ciphertext).map_err(error)?;
        self.inner
            .decapsulate(&ciphertext, &context.0)
            .map(|inner| SharedSecret { inner })
            .map_err(error)
    }
    /// Erase the key and return its runtime slot. Further use fails.
    pub fn close(&mut self) {
        self.inner.close();
    }
}

/// Ciphertext and a movable secret owner; there is no automatic secret getter.
#[wasm_bindgen(js_name = QPeriaptEncapsulation)]
pub struct Encapsulation {
    ciphertext: Ciphertext,
    secret: Option<sdk::SharedSecret>,
}
#[wasm_bindgen(js_class = QPeriaptEncapsulation)]
impl Encapsulation {
    /// Public ciphertext to transmit.
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.to_bytes().to_vec()
    }
    /// Transfer ownership once. Calling twice returns a deterministic error.
    pub fn take_secret(&mut self) -> Result<SharedSecret, JsError> {
        self.secret
            .take()
            .map(|inner| SharedSecret { inner })
            .ok_or_else(|| error(sdk::Error::Closed))
    }
    /// Erase a secret not yet transferred. Ciphertext is public and retained.
    pub fn close(&mut self) {
        self.secret = None;
    }
}

/// Combined-secret owner. Export is an explicit interoperability operation.
#[wasm_bindgen(js_name = QPeriaptSecret)]
pub struct SharedSecret {
    inner: sdk::SharedSecret,
}
#[wasm_bindgen(js_class = QPeriaptSecret)]
impl SharedSecret {
    /// Derive an owned application key. Purpose codes 1..5 use global protocol
    /// directions; labels are 1..=255 printable ASCII bytes, context <=64 KiB.
    pub fn derive_key(
        &self,
        #[wasm_bindgen(unchecked_param_type = "QPeriaptKeyPurpose")] purpose: JsValue,
        protocol_label: &Uint8Array,
        context: &Uint8Array,
    ) -> Result<DerivedKey, JsError> {
        // JS numbers must not silently truncate or wrap into another purpose.
        let purpose = match purpose.as_f64() {
            Some(1.0) => sdk::KeyPurpose::InitiatorTraffic,
            Some(2.0) => sdk::KeyPurpose::ResponderTraffic,
            Some(3.0) => sdk::KeyPurpose::InitiatorConfirmation,
            Some(4.0) => sdk::KeyPurpose::ResponderConfirmation,
            Some(5.0) => sdk::KeyPurpose::Exporter,
            _ => return Err(error(sdk::Error::InvalidPurpose)),
        };
        let label = read_input(protocol_label, 1, sdk::MAX_PROTOCOL_LABEL_BYTES)?;
        let context = WipingInput(read_input(context, 0, 65_536)?);
        self.inner
            .derive_key(purpose, &label, &context.0)
            .map(|inner| DerivedKey { inner })
            .map_err(error)
    }
    /// Copy into JS for an external protocol/KDF. JS copies cannot be erased by
    /// Rust Drop. No authentication, KDF or session-key confirmation is implied.
    pub fn export_for_protocol(&self) -> Result<Uint8Array, JsError> {
        self.inner
            .export_for_protocol()
            // Copy directly into a JS-owned array, then drop/wipe the Rust
            // temporary. Returning Vec would leave wasm-bindgen's exported
            // intermediate allocation outside this owner's erasure control.
            .map(|bytes| Uint8Array::from(bytes.as_bytes().as_slice()))
            .map_err(error)
    }
    /// Erase this WASM owner; future exports fail.
    pub fn close(&mut self) {
        self.inner.close();
    }
}

/// Explicit plaintext private-key transfer; no encryption or storage authority.
#[wasm_bindgen(js_name = QPeriaptExpert)]
pub struct Expert;
#[wasm_bindgen(js_class = QPeriaptExpert)]
impl Expert {
    /// Import exactly 2440 bytes and validate with fresh platform randomness.
    /// The caller retains and must erase the JS input copy.
    pub fn import_expanded(runtime: &Runtime, bytes: &Uint8Array) -> Result<Key, JsError> {
        let bytes = WipingInput(read_input(
            bytes,
            sdk::expert::EXPANDED_KEY_LEN,
            sdk::expert::EXPANDED_KEY_LEN,
        )?);
        sdk::expert::import_expanded(&runtime.inner, &bytes.0)
            .map(|inner| Key { inner })
            .map_err(error)
    }
    /// Copy directly into caller-owned JS memory and erase the native temporary.
    pub fn export_expanded(key: &Key) -> Result<Uint8Array, JsError> {
        sdk::expert::export_expanded(&key.inner)
            .map(|bytes| Uint8Array::from(bytes.as_bytes().as_slice()))
            .map_err(error)
    }
}

/// A prepared policy; no new-policy key operations before activation.
#[wasm_bindgen(js_name = QPeriaptPolicyUpdate)]
pub struct PolicyUpdate {
    inner: Option<sdk::PolicyUpdate>,
}
#[wasm_bindgen(js_class = QPeriaptPolicyUpdate)]
impl PolicyUpdate {
    /// Previous || next trusted states, 36 bytes each, for root-scoped host CAS.
    pub fn states(&self) -> Result<Vec<u8>, JsError> {
        let (previous, next) = self
            .inner
            .as_ref()
            .ok_or_else(|| error(sdk::Error::Closed))?
            .states()
            .map_err(error)?;
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&previous.encode());
        bytes.extend_from_slice(&next.encode());
        Ok(bytes)
    }
    /// Call only after atomic host persistence. Revokes the old runtime and
    /// returns an independent (possibly disabled) runtime. On failure after
    /// persistence, stop old-runtime use and recover from signed policy + state.
    pub fn activate_after_persist(&mut self) -> Result<Runtime, JsError> {
        self.inner
            .take()
            .ok_or_else(|| error(sdk::Error::Closed))?
            .activate_after_persist()
            .map(|inner| Runtime { inner })
            .map_err(error)
    }
    /// Cancel without revoking the old runtime. Does not undo host persistence.
    pub fn close(&mut self) {
        self.inner = None;
    }
}

/// Purpose-derived application-key owner; it cannot be used as a KEM secret.
#[wasm_bindgen(js_name = QPeriaptDerivedKey)]
pub struct DerivedKey {
    inner: sdk::DerivedKey,
}
#[wasm_bindgen(js_class = QPeriaptDerivedKey)]
impl DerivedKey {
    /// Explicit copy into JS-owned storage for a cipher/MAC. The application
    /// owns this copy; closing the native owner cannot revoke it.
    pub fn export_for_protocol(&self) -> Result<Uint8Array, JsError> {
        self.inner
            .export_for_protocol()
            .map(|bytes| Uint8Array::from(bytes.as_bytes().as_slice()))
            .map_err(error)
    }
    /// Erase this owner. Runtime close also revokes further export.
    pub fn close(&mut self) {
        self.inner.close();
    }
}
