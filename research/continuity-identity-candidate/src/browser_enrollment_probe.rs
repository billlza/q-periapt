//! Compatibility adapter for retained first-use experiments; uses the shared owner.
use crate::browser::BrowserDevice;
use wasm_bindgen::prelude::*;
/// Retained experiment surface; product bindings use the same BrowserDevice owner.
#[wasm_bindgen]
pub struct BrowserEnrollmentProbe {
    inner: BrowserDevice,
}
#[wasm_bindgen]
impl BrowserEnrollmentProbe {
    /// Create a fresh original identity.
    pub async fn create(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: BrowserDevice::create(name, id, root, description).await?,
        })
    }
    /// Reopen the original completed identity.
    pub async fn open(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: BrowserDevice::open(name, id, root, description).await?,
        })
    }
    /// Resume only the original authenticated creation.
    pub async fn resume(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: BrowserDevice::resume(name, id, root, description).await?,
        })
    }
    /// Return the exact original signed request.
    pub async fn request(&self, now: u64) -> Result<Vec<u8>, JsValue> {
        self.inner.request(now).await
    }
    /// Close and await resource-release receipts.
    pub async fn close(&self) -> Result<(), JsValue> {
        self.inner.close().await
    }
}
