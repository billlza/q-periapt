// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{DeviceSigningKey, DurableError, JournalKey, SigningKeyId};
use js_sys::{Reflect, Uint8Array};
use q_periapt_host_store::database_format;
use redb::{Database, StorageBackend};
use std::{
    fmt, io,
    ops::Bound,
    path::Path,
    sync::{Arc, Mutex},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(raw_module = "./storage-root.js")]
extern "C" {
    #[wasm_bindgen(js_name=continuityFailure)]
    fn continuity_failure(code: &str, original: &JsValue, owner_closed: JsValue) -> JsValue;
    #[wasm_bindgen(js_name=combineFailures)]
    fn combine_failures(primary: &JsValue, cleanup: &JsValue) -> JsValue;
    #[wasm_bindgen(js_name=StorageRoot)]
    #[derive(Clone)]
    type StorageRoot;
    #[wasm_bindgen(js_name=StorageOpening)]
    type StorageOpening;
    #[wasm_bindgen(static_method_of=StorageRoot,js_name=beginCreate,catch)]
    fn begin_create_root(
        name: &str,
        id: &str,
        binding: &[u8],
        wrapping: &[u8],
    ) -> Result<StorageOpening, JsValue>;
    #[wasm_bindgen(static_method_of=StorageRoot,js_name=beginOpen,catch)]
    fn begin_open_root(name: &str, id: &str, binding: &[u8]) -> Result<StorageOpening, JsValue>;
    #[wasm_bindgen(static_method_of=StorageRoot,js_name=beginResume,catch)]
    fn begin_resume_root(name: &str, id: &str, binding: &[u8]) -> Result<StorageOpening, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn ready(this: &StorageOpening) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    fn take(this: &StorageOpening) -> Result<StorageRoot, JsValue>;
    #[wasm_bindgen(method)]
    fn abandon(this: &StorageOpening);
    #[wasm_bindgen(method,js_name=creationReady,catch)]
    fn creation_ready(this: &StorageRoot) -> Result<bool, JsValue>;
    #[wasm_bindgen(method,js_name=finishCreation,catch)]
    async fn finish_creation(this: &StorageRoot) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=missing,catch)]
    async fn missing_file(this: &StorageRoot, path: &str) -> Result<bool, JsValue>;
    #[wasm_bindgen(method,js_name=readSecret,catch)]
    async fn read_secret(this: &StorageRoot, path: &str) -> Result<HostSecret, JsValue>;
    #[wasm_bindgen(method,js_name=publishSecret,catch)]
    async fn publish_secret(this: &StorageRoot, path: &str, bytes: &[u8]) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=openDatabase,catch)]
    async fn open_database(this: &StorageRoot, path: &str) -> Result<HostFile, JsValue>;
    #[wasm_bindgen(method,js_name=stageDatabase,catch)]
    async fn stage_database(this: &StorageRoot, path: &str) -> Result<HostFile, JsValue>;
    #[wasm_bindgen(method,js_name=publishDatabase,catch)]
    async fn publish_database(
        this: &StorageRoot,
        path: &str,
        file: &HostFile,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=close,catch)]
    async fn close_root(this: &StorageRoot) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=beginClose)]
    fn begin_close_root(this: &StorageRoot);
    #[wasm_bindgen(method,js_name=prefix,catch)]
    fn root_prefix(this: &StorageRoot) -> Result<String, JsValue>;
    #[wasm_bindgen(js_name=SecretLease)]
    type HostSecret;
    #[wasm_bindgen(method,js_name=bytes,catch)]
    fn secret_bytes(this: &HostSecret) -> Result<Uint8Array, JsValue>;
    #[wasm_bindgen(method,js_name=close,catch)]
    fn close_secret(this: &HostSecret) -> Result<(), JsValue>;
    #[wasm_bindgen(js_name=DatabaseLease)]
    #[derive(Clone)]
    type HostFile;
    #[wasm_bindgen(method,js_name=getSize,catch)]
    fn file_size(this: &HostFile) -> Result<f64, JsValue>;
    #[wasm_bindgen(method,js_name=read,catch)]
    fn file_read(this: &HostFile, offset: f64, out: &Uint8Array) -> Result<f64, JsValue>;
    #[wasm_bindgen(method,js_name=write,catch)]
    fn file_write(this: &HostFile, offset: f64, bytes: &Uint8Array) -> Result<f64, JsValue>;
    #[wasm_bindgen(method,js_name=resize,catch)]
    fn file_resize(this: &HostFile, size: f64) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=flush,catch)]
    fn file_sync(this: &HostFile) -> Result<(), JsValue>;
    #[wasm_bindgen(method,js_name=close,catch)]
    fn file_close(this: &HostFile) -> Result<(), JsValue>;
}
// Installed synchronously before the first await. JS owns any late root until
// take() transfers it; Drop cannot confuse cancellation with native completion.
struct PendingOpening(StorageOpening);
impl Drop for PendingOpening {
    fn drop(&mut self) {
        self.0.abandon();
    }
}
struct HostFailure {
    code: String,
    cause: JsValue,
}
impl fmt::Debug for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserStorage")
            .field("code", &self.code)
            .field("cause", &self.cause)
            .finish()
    }
}
impl fmt::Display for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "browser storage: {}", self.code)
    }
}
impl std::error::Error for HostFailure {}
#[derive(Debug)]
struct CleanupFailure {
    primary: DurableError,
    cleanup: DurableError,
}
impl fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; cleanup: {}", self.primary, self.cleanup)
    }
}
impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn after_cleanup<T>(
    result: Result<T, DurableError>,
    cleanup: Result<(), DurableError>,
) -> Result<T, DurableError> {
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => Err(DurableError::Io(io::Error::other(CleanupFailure {
            primary,
            cleanup,
        }))),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Ok(value), Ok(())) => Ok(value),
    }
}
fn host(cause: JsValue) -> io::Error {
    let code = Reflect::get(&cause, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "Storage".into());
    let kind = match code.as_str() {
        "Absent" => io::ErrorKind::NotFound,
        "Exists" => io::ErrorKind::AlreadyExists,
        "Busy" => io::ErrorKind::WouldBlock,
        "QuotaExceeded" => io::ErrorKind::StorageFull,
        "Unavailable" => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, HostFailure { code, cause })
}
fn error(value: JsValue) -> DurableError {
    DurableError::Io(host(value))
}
fn path(value: &Path) -> Result<&str, DurableError> {
    value.to_str().ok_or(DurableError::PrivateFile)
}
const MAX: u64 = 64 * 1024 * 1024;
fn width(value: f64, max: u64) -> io::Result<u64> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= max as f64 {
        Ok(value as u64)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}
fn extent(offset: u64, length: usize) -> io::Result<()> {
    if offset.checked_add(length as u64).is_some_and(|n| n <= MAX) {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidInput.into())
    }
}
struct Backend {
    file: HostFile,
    close_error: Arc<Mutex<Option<io::Error>>>,
}
impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedOpfsBackend").finish_non_exhaustive()
    }
}
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        width(self.file.file_size().map_err(host)?, MAX)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        extent(offset, out.len())?;
        let data = Uint8Array::new_with_length(out.len() as u32);
        if width(
            self.file.file_read(offset as f64, &data).map_err(host)?,
            out.len() as u64,
        )? != out.len() as u64
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.copy_to(out);
        Ok(())
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        extent(offset, bytes.len())?;
        if width(
            self.file
                .file_write(offset as f64, &Uint8Array::from(bytes))
                .map_err(host)?,
            bytes.len() as u64,
        )? != bytes.len() as u64
        {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        extent(len, 0)?;
        self.file.file_resize(len as f64).map_err(host)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file.file_sync().map_err(host)
    }
    fn try_lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> Result<bool, redb::BackendError> {
        if start != Bound::Unbounded || end != Bound::Unbounded {
            return Err(redb::BackendError::Unsupported);
        }
        self.len()?;
        Ok(true)
    }
    fn close(&self) -> io::Result<()> {
        match self.file.file_close().map_err(host) {
            Ok(()) => Ok(()),
            Err(e) => {
                let kind = e.kind();
                *self
                    .close_error
                    .lock()
                    .map_err(|_| io::Error::other("OPFS cleanup lock"))? = Some(e);
                Err(io::Error::new(kind, "OPFS close failed"))
            }
        }
    }
}
#[derive(Clone)]
pub(crate) struct Storage {
    root: StorageRoot,
    close_error: Arc<Mutex<Option<io::Error>>>,
}
impl Storage {
    pub(crate) fn continuity_failure(
        code: &str,
        original: &JsValue,
        owner_closed: Option<bool>,
    ) -> JsValue {
        continuity_failure(
            code,
            original,
            owner_closed
                .map(JsValue::from_bool)
                .unwrap_or(JsValue::UNDEFINED),
        )
    }
    pub(crate) fn failure_value(error: &DurableError) -> JsValue {
        if let DurableError::Io(error) = error {
            if let Some(source) = error.get_ref() {
                if let Some(host) = source.downcast_ref::<HostFailure>() {
                    return host.cause.clone();
                }
                if let Some(cleanup) = source.downcast_ref::<CleanupFailure>() {
                    return combine_failures(
                        &Self::failure_value(&cleanup.primary),
                        &Self::failure_value(&cleanup.cleanup),
                    );
                }
            }
        }
        js_sys::Error::new(&format!("{error:?}")).into()
    }
    pub(crate) fn combine_failures(primary: &JsValue, cleanup: &JsValue) -> JsValue {
        combine_failures(primary, cleanup)
    }
    pub(crate) fn prefix(&self) -> Result<String, DurableError> {
        self.root.root_prefix().map_err(error)
    }
    pub(crate) fn begin_close(&self) {
        self.root.begin_close_root()
    }
    pub(crate) fn native() -> Result<Self, DurableError> {
        Err(DurableError::PrivateFile)
    }
    async fn acquire(opening: StorageOpening) -> Result<Self, DurableError> {
        let opening = PendingOpening(opening);
        opening.0.ready().await.map_err(error)?;
        let root = opening.0.take().map_err(error)?;
        Ok(Self {
            root,
            close_error: Arc::new(Mutex::new(None)),
        })
    }
    pub(crate) async fn create(name: &str, id: &str, binding: &[u8]) -> Result<Self, DurableError> {
        let (_, bytes) = JournalKey::prepare_file()?;
        Self::acquire(StorageRoot::begin_create_root(name, id, binding, &bytes).map_err(error)?)
            .await
    }
    pub(crate) async fn open(name: &str, id: &str, binding: &[u8]) -> Result<Self, DurableError> {
        Self::acquire(StorageRoot::begin_open_root(name, id, binding).map_err(error)?).await
    }
    pub(crate) async fn resume(name: &str, id: &str, binding: &[u8]) -> Result<Self, DurableError> {
        Self::acquire(StorageRoot::begin_resume_root(name, id, binding).map_err(error)?).await
    }
    pub(crate) fn creation_ready(&self) -> Result<bool, DurableError> {
        self.root.creation_ready().map_err(error)
    }
    pub(crate) async fn finish_creation(&self) -> Result<(), DurableError> {
        self.root.finish_creation().await.map_err(error)
    }
    pub(crate) async fn close(&self) -> Result<(), DurableError> {
        self.root.close_root().await.map_err(error)?;
        match self
            .close_error
            .lock()
            .map_err(|_| io::Error::other("OPFS cleanup lock"))?
            .take()
        {
            Some(e) => Err(e.into()),
            None => Ok(()),
        }
    }
    pub(crate) async fn missing(&self, value: &Path) -> Result<bool, DurableError> {
        self.root.missing_file(path(value)?).await.map_err(error)
    }
    pub(crate) async fn read_bytes(
        &self,
        value: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, DurableError> {
        let lease = self.root.read_secret(path(value)?).await.map_err(error)?;
        let result = lease
            .secret_bytes()
            .map(|b| Zeroizing::new(b.to_vec()))
            .map_err(error);
        after_cleanup(result, lease.close_secret().map_err(error))
    }
    pub(crate) async fn publish_bytes(
        &self,
        value: &Path,
        bytes: &[u8],
    ) -> Result<(), DurableError> {
        self.root
            .publish_secret(path(value)?, bytes)
            .await
            .map_err(error)
    }
    pub(crate) async fn open_key(&self, value: &Path) -> Result<JournalKey, DurableError> {
        JournalKey::decode_file(&self.read_bytes(value).await?)
    }
    pub(crate) async fn open_signer(
        &self,
        value: &Path,
        key: &JournalKey,
        id: SigningKeyId,
    ) -> Result<DeviceSigningKey, DurableError> {
        crate::crypto::open_browser_device(key, id, &self.read_bytes(value).await?)
    }
    pub(crate) async fn provision_signer(
        &self,
        value: &Path,
        key: &JournalKey,
        id: SigningKeyId,
    ) -> Result<DeviceSigningKey, DurableError> {
        let (signer, bytes) = crate::crypto::prepare_browser_device(key, id)?;
        self.publish_bytes(value, &bytes).await?;
        Ok(signer)
    }
    fn database(&self, file: HostFile, new: bool) -> Result<Database, DurableError> {
        let backend = Backend {
            file,
            close_error: Arc::clone(&self.close_error),
        };
        let admission = (|| {
            let length = backend.len()?;
            if (new && length != 0) || (!new && length < 16) {
                return Err(DurableError::Corrupt);
            }
            if !new {
                database_format::refuse_unclean_foreign_redb(&backend)?
            }
            Ok(())
        })();
        if let Err(primary) = admission {
            return after_cleanup(Err(primary), backend.close().map_err(Into::into));
        }
        let mut builder = Database::builder();
        builder.set_cache_size(2 * 1024 * 1024);
        builder
            .create_with_backend(backend)
            .map_err(|e| DurableError::Storage(Box::new(e.into())))
    }
    pub(crate) async fn open_database(&self, value: &Path) -> Result<Database, DurableError> {
        let file = self.root.open_database(path(value)?).await.map_err(error)?;
        self.database(file, false)
    }
    pub(crate) async fn provision_database(
        &self,
        value: &Path,
        initialize: impl FnOnce(&Database) -> Result<(), DurableError>,
    ) -> Result<Database, DurableError> {
        let file = self
            .root
            .stage_database(path(value)?)
            .await
            .map_err(error)?;
        let db = self.database(file.clone(), true)?;
        initialize(&db)?;
        self.root
            .publish_database(path(value)?, &file)
            .await
            .map_err(error)?;
        Ok(db)
    }
}
