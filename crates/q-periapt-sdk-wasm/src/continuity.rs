// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Browser lifecycle binding over the same shared engine and SDK runtime.
use super::{read_input as sdk_input, read_limit as sdk_limit, Runtime};
use engine::browser::{failure, BrowserDevice};
use js_sys::Uint8Array;
use q_periapt_continuity_identity_candidate as engine;
use std::time::Duration;
use wasm_bindgen::prelude::*;
mod connections;
mod credential_requests;
mod credentials;
mod history;
mod inventory;
mod peers;
mod publication;
mod rekey;
mod roster;
mod status;
mod trust;
use status::Status;
use trust::{AccountTrust, Enrollment, SessionPolicy, Witness};
fn read_input(value: &Uint8Array, min: usize, max: usize) -> Result<Vec<u8>, JsValue> {
    sdk_input(value, min, max).map_err(|error| engine::browser::input_failure(error.into()))
}
fn read_limit(value: &JsValue, maximum: usize) -> Result<usize, JsValue> {
    sdk_limit(value, maximum).map_err(|error| engine::browser::input_failure(error.into()))
}
fn read_time(value: JsValue) -> Result<u64, JsValue> {
    u64::try_from(value).map_err(engine::browser::input_failure)
}
fn read_kind(value: &JsValue) -> Result<PrekeyKind, JsValue> {
    match read_limit(value, 4)? {
        1 => Ok(PrekeyKind::SignedClassical),
        2 => Ok(PrekeyKind::OneTimeClassical),
        3 => Ok(PrekeyKind::OneTimePq),
        4 => Ok(PrekeyKind::LastResortPq),
        _ => Err(protocol(engine::Error::Encoding)),
    }
}
fn protocol(error: engine::Error) -> JsValue {
    failure(&error.into())
}
fn array(value: &Uint8Array) -> Result<[u8; 32], JsValue> {
    read_input(value, 32, 32)?
        .try_into()
        .map_err(|_| protocol(engine::Error::Encoding))
}

fn text(value: &JsValue, maximum: u32) -> Result<String, JsValue> {
    let text = value
        .dyn_ref::<js_sys::JsString>()
        .ok_or_else(|| protocol(engine::Error::Encoding))?;
    if text.length() == 0 || text.length() > maximum {
        return Err(protocol(engine::Error::Encoding));
    }
    text.as_string()
        .ok_or_else(|| protocol(engine::Error::Encoding))
}
fn location(name: &JsValue, id: &Uint8Array) -> Result<(String, String), JsValue> {
    let name = text(name, 96)?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(protocol(engine::Error::Encoding));
    }
    let id = array(id)?;
    if id.iter().all(|byte| *byte == 0) {
        return Err(protocol(engine::Error::Encoding));
    }
    let id = id.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((name, id))
}

/// Browser device owner. Secrets and raw signer/store handles are never returned.
#[wasm_bindgen(js_name = QPeriaptContinuityDevice)]
pub struct Device {
    inner: BrowserDevice,
}
#[wasm_bindgen(js_class = QPeriaptContinuityDevice)]
impl Device {
    /// Permanently closed handle, independently of pending cleanup or commit outcome.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    /// Read durable recovery progress; does not renew authority or authorize traffic.
    pub async fn status(&self) -> Result<Status, JsValue> {
        Ok(Status {
            inner: self.inner.status().await?,
        })
    }
    /// Create a fresh identity bound to independently approved account inputs.
    pub async fn create(
        #[wasm_bindgen(unchecked_param_type = "string")] name: JsValue,
        id: &Uint8Array,
        intent: &Enrollment,
    ) -> Result<Device, JsValue> {
        let (name, id) = location(&name, id)?;
        Ok(Self {
            inner: BrowserDevice::create(name, id, intent.root.clone(), intent.description.clone())
                .await?,
        })
    }
    /// Open completed original enrollment, including an already activated device.
    pub async fn open(
        #[wasm_bindgen(unchecked_param_type = "string")] name: JsValue,
        id: &Uint8Array,
        intent: &Enrollment,
    ) -> Result<Device, JsValue> {
        let (name, id) = location(&name, id)?;
        Ok(Self {
            inner: BrowserDevice::open(name, id, intent.root.clone(), intent.description.clone())
                .await?,
        })
    }
    /// Resume the original authenticated initialization after interruption.
    pub async fn resume(
        #[wasm_bindgen(unchecked_param_type = "string")] name: JsValue,
        id: &Uint8Array,
        intent: &Enrollment,
    ) -> Result<Device, JsValue> {
        let (name, id) = location(&name, id)?;
        Ok(Self {
            inner: BrowserDevice::resume(name, id, intent.root.clone(), intent.description.clone())
                .await?,
        })
    }
    /// Return the original signed enrollment request for the account authority.
    pub async fn request(
        &self,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let now = read_time(now)?;
        self.inner.request(now).await
    }
    /// Accept a signed grant under independent account/roster and policy pins.
    pub async fn accept(
        &self,
        certificate: &Uint8Array,
        roster: &Uint8Array,
        trust: &AccountTrust,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let now = read_time(now)?;
        let certificate = read_input(certificate, 1, 8192)?;
        let roster = read_input(roster, 1, 8192)?;
        Ok(self
            .inner
            .accept(&certificate, &roster, &trust.inner, &policy.inner, now)
            .await?
            .as_bytes()
            .to_vec())
    }
    /// Prepare original children; any returned genesis requires independent enrollment.
    pub async fn prepare(
        &self,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Preparation, JsValue> {
        let now = read_time(now)?;
        Ok(Preparation {
            inner: self.inner.prepare(&policy.inner, now).await?,
        })
    }
    /// Activate only a locally protected policy. A required witness is never omitted.
    pub async fn activate_local(
        &self,
        policy: &SessionPolicy,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let now = read_time(now)?;
        Ok(self
            .inner
            .activate(&policy.inner, now, None)
            .await?
            .as_bytes()
            .to_vec())
    }
    /// Activate/reopen using the exact independently pinned, enrolled witness.
    pub async fn activate(
        &self,
        policy: &SessionPolicy,
        witness: &Witness,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let now = read_time(now)?;
        let carrier = witness.carrier(self.inner.cancellation())?;
        Ok(self
            .inner
            .activate(
                &policy.inner,
                now,
                Some((witness.pin.clone(), Box::new(carrier), witness.timeout)),
            )
            .await?
            .as_bytes()
            .to_vec())
    }
    /// Cancel pending work, close all descendants and await actual storage release.
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close().await
    }
}

/// Result of original installation preparation, before operational activation.
#[wasm_bindgen(js_name = QPeriaptContinuityPreparation)]
pub struct Preparation {
    inner: engine::InstallationPreparation,
}
#[wasm_bindgen(js_class = QPeriaptContinuityPreparation)]
impl Preparation {
    /// Whether an independent witness must explicitly admit the original genesis.
    pub fn requires_witness(&self) -> bool {
        matches!(
            self.inner,
            engine::InstallationPreparation::RequiresEnrollment(_)
        )
    }
    /// Public original witness subject; local-only preparation has no subject.
    pub fn subject(&self) -> Result<Vec<u8>, JsValue> {
        match &self.inner {
            engine::InstallationPreparation::RequiresEnrollment(g) => Ok(g.subject().to_bytes()),
            _ => Err(protocol(engine::Error::State)),
        }
    }
    /// Public original journal-image digest; this is not a witness receipt.
    pub fn image_digest(&self) -> Result<Vec<u8>, JsValue> {
        match &self.inner {
            engine::InstallationPreparation::RequiresEnrollment(g) => Ok(g.image_digest().to_vec()),
            _ => Err(protocol(engine::Error::State)),
        }
    }
}
/// Supported prekey roles; the signed policy still decides admissibility.
#[wasm_bindgen(js_name = QPeriaptContinuityPrekeyKind)]
pub enum PrekeyKind {
    /// Reusable classical signed key.
    SignedClassical = 1,
    /// One-time classical key.
    OneTimeClassical = 2,
    /// One-time post-quantum key.
    OneTimePq = 3,
    /// Reusable post-quantum fallback key.
    LastResortPq = 4,
}
impl From<PrekeyKind> for engine::LeafKind {
    fn from(value: PrekeyKind) -> Self {
        match value {
            PrekeyKind::SignedClassical => Self::SignedClassical,
            PrekeyKind::OneTimeClassical => Self::OneTimeClassical,
            PrekeyKind::OneTimePq => Self::OneTimePq,
            PrekeyKind::LastResortPq => Self::LastResortPq,
        }
    }
}
