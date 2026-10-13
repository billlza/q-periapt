//! Isolated first-use storage experiment; not the admitted product browser entry.
use crate::{
    codec::Decoder, storage::Storage, DeviceDescription, DeviceEnrollment, DurableError,
    EnrollmentIntent, EnrollmentPaths, InstallationPaths, PublicKey, Validity,
};
use std::{
    cell::{Cell, RefCell},
    path::Path,
};
use wasm_bindgen::prelude::*;

fn js(error: DurableError) -> JsValue {
    Storage::failure_value(&error)
}
fn intent(root: &[u8], description: &[u8]) -> Result<(EnrollmentIntent, Vec<u8>), DurableError> {
    let mut decoder = Decoder::new(description);
    let device = decoder.array()?;
    let generation = u64::from_be_bytes(decoder.array()?);
    let family = decoder.array()?;
    let from = u64::from_be_bytes(decoder.array()?);
    let until = u64::from_be_bytes(decoder.array()?);
    decoder.finish()?;
    let public = PublicKey::decode(root)?;
    let mut binding = b"QPC-BROWSER-ENROLLMENT-INITIAL/v2".to_vec();
    binding.extend_from_slice(&public.encode());
    binding.extend_from_slice(description);
    Ok((
        EnrollmentIntent::new(
            public,
            DeviceDescription::new(device, generation, family, Validity::new(from, until)?)?,
        ),
        binding,
    ))
}
fn paths(storage: &Storage) -> Result<EnrollmentPaths, DurableError> {
    let prefix = storage.prefix()?;
    EnrollmentPaths::new(
        Path::new(&(prefix.clone() + "wrap.key")),
        Path::new(&(prefix.clone() + "signer.key")),
        Path::new(&(prefix.clone() + "enrollment.redb")),
        InstallationPaths::new(
            Path::new(&(prefix.clone() + "installation.redb")),
            Path::new(&(prefix.clone() + "journal.redb")),
            Path::new(&(prefix + "archives.redb")),
        )?,
    )
}

enum Opening {
    Create,
    Open,
    Resume,
}

/// Experiment owner with explicit creation versus exact original reopening.
#[wasm_bindgen]
pub struct BrowserEnrollmentProbe {
    enrollment: RefCell<Option<DeviceEnrollment>>,
    storage: Storage,
    closed: Cell<bool>,
}
#[wasm_bindgen]
impl BrowserEnrollmentProbe {
    /// Create a fresh vault with atomically published wrapping key and exact intent.
    pub async fn create(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Create).await
    }
    /// Open a completed original initialization without repairing missing objects.
    pub async fn open(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Open).await
    }
    /// Resume only the authenticated original first-use intent. Published files cannot be replaced.
    pub async fn resume(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Resume).await
    }
    /// Return the exact committed original request; concurrent use is refused.
    pub async fn request(&self, now: u64) -> Result<Vec<u8>, JsValue> {
        if self.closed.get() {
            return Err(js(DurableError::Closed));
        }
        let mut owner = self
            .enrollment
            .borrow_mut()
            .take()
            .ok_or_else(|| js(DurableError::Io(std::io::ErrorKind::WouldBlock.into())))?;
        let result = owner.request(now).await;
        match result {
            Ok(bytes) if !self.closed.get() => {
                *self.enrollment.borrow_mut() = Some(owner);
                Ok(bytes)
            }
            other => {
                self.closed.set(true);
                owner.close();
                let cleanup = self.storage.close().await;
                Err(js_with_cleanup(
                    other.err().unwrap_or(DurableError::Closed),
                    cleanup,
                ))
            }
        }
    }
    /// Close all descendants and await actual release of the browser storage lease.
    pub async fn close(&self) -> Result<(), JsValue> {
        self.closed.set(true);
        self.enrollment.borrow_mut().take();
        self.storage.close().await.map_err(js)
    }
}
impl BrowserEnrollmentProbe {
    async fn acquire(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
        mode: Opening,
    ) -> Result<Self, JsValue> {
        let (intent, binding) = intent(&root, &description).map_err(js)?;
        let storage = match mode {
            Opening::Create => Storage::create(&name, &id, &binding).await,
            Opening::Open => Storage::open(&name, &id, &binding).await,
            Opening::Resume => Storage::resume(&name, &id, &binding).await,
        }
        .map_err(js)?;
        let result = Self::initialize_or_open(&storage, intent, mode).await;
        match result {
            Ok(owner) => Ok(Self {
                enrollment: RefCell::new(Some(owner)),
                storage,
                closed: Cell::new(false),
            }),
            Err(primary) => {
                let cleanup = storage.close().await;
                Err(js_with_cleanup(primary, cleanup))
            }
        }
    }
    async fn initialize_or_open(
        storage: &Storage,
        intent: EnrollmentIntent,
        mode: Opening,
    ) -> Result<DeviceEnrollment, DurableError> {
        if matches!(mode, Opening::Open) || storage.creation_ready()? {
            return DeviceEnrollment::open_with_storage(storage.clone(), paths(storage)?, intent)
                .await;
        }
        let configuration = storage.prefix()? + "enrollment.redb";
        let owner = if storage.missing(Path::new(&configuration)).await? {
            // The authenticated catalogue proves this original intent never published
            // an enrollment database. An absent *published* row is rejected in storage.
            DeviceEnrollment::provision_with_storage(storage.clone(), paths(storage)?, intent)
                .await?
        } else {
            DeviceEnrollment::open_with_storage(storage.clone(), paths(storage)?, intent).await?
        };
        storage.finish_creation().await?;
        Ok(owner)
    }
}
impl Drop for BrowserEnrollmentProbe {
    fn drop(&mut self) {
        self.closed.set(true);
        self.enrollment.get_mut().take();
        self.storage.begin_close();
    }
}
fn js_with_cleanup(primary: DurableError, cleanup: Result<(), DurableError>) -> JsValue {
    match cleanup {
        Ok(()) => js(primary),
        Err(cleanup) => Storage::combine_failures(&js(primary), &js(cleanup)),
    }
}
