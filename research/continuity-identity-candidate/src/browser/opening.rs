// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    codec::Decoder, DeviceDescription, EnrollmentIntent, EnrollmentPaths, InstallationPaths,
    PublicKey,
};
use std::path::Path;
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

struct OpeningLease {
    storage: Storage,
    armed: bool,
}
impl Drop for OpeningLease {
    fn drop(&mut self) {
        if self.armed {
            self.storage.begin_close();
        }
    }
}
impl BrowserDevice {
    /// Create a fresh browser identity bound to exact independently approved inputs.
    pub async fn create(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Create).await
    }
    /// Reopen a completed original identity; missing published objects are refused.
    pub async fn open(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Open).await
    }
    /// Recover the exact authenticated original creation intent without regeneration.
    pub async fn resume(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
    ) -> Result<Self, JsValue> {
        Self::acquire(name, id, root, description, Opening::Resume).await
    }
    async fn acquire(
        name: String,
        id: String,
        root: Vec<u8>,
        description: Vec<u8>,
        mode: Opening,
    ) -> Result<Self, JsValue> {
        let (intent, binding) = intent(&root, &description).map_err(|e| failure(&e))?;
        let storage = match mode {
            Opening::Create => Storage::create(&name, &id, &binding).await,
            Opening::Open => Storage::open(&name, &id, &binding).await,
            Opening::Resume => Storage::resume(&name, &id, &binding).await,
        }
        .map_err(|e| failure(&e))?;
        let mut guard = OpeningLease {
            storage,
            armed: true,
        };
        let result = Self::initialize_or_open(&guard.storage, intent, mode).await;
        match result {
            Ok(owner) => {
                let owner = Self {
                    state: RefCell::new(Some(State::Enrollment(Box::new(owner)))),
                    storage: guard.storage.clone(),
                    closed: Cell::new(false),
                    cancellation: Cancellation::default(),
                };
                guard.armed = false;
                Ok(owner)
            }
            Err(primary) => {
                let cleanup = guard.storage.close().await;
                Err(cleanup_error(primary, cleanup))
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
