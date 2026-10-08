//! Offline policy-image maintenance. No deployment state enters the SDK until
//! independently pinned root/state and the exact stored image have been checked.
#![forbid(unsafe_code)]

use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_host_store::filesystem::{
    open_private_file, refuse_unclean_foreign_redb, LockedFileBackend, MAX_PRIVATE_DATABASE_BYTES,
};
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{Limits, Runtime};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, StorageBackend, TableHandle};
use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    fs::File,
    io::{self, Read},
    ops::Bound,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

type Result<T> = std::result::Result<T, Error>;
type Image = BTreeMap<String, Vec<u8>>;
#[cfg(test)]
mod tests;
const TABLE: &str = "sdk_host_policy_v1";
const SCHEMA: &[u8] = b"QPeriapt-Host-Policy-v1";
const MAX_POLICY_BYTES: usize = 65_536;

#[derive(Debug)]
pub(super) struct Error {
    stage: &'static str,
    source: Box<dyn StdError + Send + Sync>,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.source)
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}
fn at(stage: &'static str, error: impl StdError + Send + Sync + 'static) -> Error {
    Error {
        stage,
        source: Box::new(error),
    }
}
fn refuse(message: &'static str) -> Error {
    at(
        "admission",
        io::Error::new(io::ErrorKind::InvalidData, message),
    )
}

#[derive(Debug)]
struct AttemptFailure {
    io: io::Error,
    operation: Option<Error>,
}
impl fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.io.fmt(f)?;
        if let Some(operation) = &self.operation {
            write!(f, " (operation also reported {operation})")?;
        }
        Ok(())
    }
}
impl StdError for AttemptFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.io)
    }
}

/// A shared original error, including its typed source. Database destructors
/// sometimes discard an I/O result; the attempt must still fail after they run.
#[derive(Clone, Debug)]
struct SharedIo(Arc<io::Error>);
impl fmt::Display for SharedIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl StdError for SharedIo {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}
#[derive(Debug)]
struct Attempt {
    backend: Box<dyn StorageBackend>,
    failure: Mutex<Option<SharedIo>>,
}

/// Linux's legacy flock and current OFD range locks have separate namespaces.
/// Acquire both on the same admitted open file description before content reads.
/// Neither provider may create/drop an independent lock-managing legacy backend.
#[derive(Debug)]
struct MigrationBackend {
    current: LockedFileBackend,
    #[cfg(target_os = "linux")]
    legacy_lock: File,
}
impl StorageBackend for MigrationBackend {
    fn len(&self) -> io::Result<u64> {
        self.current.len()
    }
    fn read(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.current.read(offset, bytes)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.current.write(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.current.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.current.sync_data()
    }
    fn try_lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.current.try_lock_range(start, end)
    }
    fn close(&self) -> io::Result<()> {
        let current = self.current.close();
        #[cfg(target_os = "linux")]
        {
            // Attempt both unlocks, and do not turn one successful unlock into
            // success when the other failed. Final descriptor drop is still owned.
            let legacy = self.legacy_lock.unlock();
            current.and(legacy)
        }
        #[cfg(not(target_os = "linux"))]
        current
    }
}
impl Attempt {
    fn record<T>(&self, result: io::Result<T>) -> io::Result<T> {
        result.map_err(|error| {
            let kind = error.kind();
            let shared = SharedIo(Arc::new(error));
            match self.failure.lock() {
                Ok(mut first) => {
                    if first.is_none() {
                        *first = Some(shared.clone());
                    }
                    io::Error::new(kind, shared)
                }
                Err(_) => io::Error::other("migration I/O error tracker is poisoned"),
            }
        })
    }
    fn check(&self) -> io::Result<()> {
        match self.failure.lock() {
            Ok(first) => match first.as_ref() {
                Some(error) => Err(io::Error::new(error.0.kind(), error.clone())),
                None => Ok(()),
            },
            Err(_) => Err(io::Error::other("migration I/O error tracker is poisoned")),
        }
    }
    fn extent(&self, offset: u64, length: usize) -> io::Result<()> {
        self.check()?;
        self.record(
            if u64::try_from(length)
                .ok()
                .and_then(|n| offset.checked_add(n))
                .is_some_and(|end| end <= MAX_PRIVATE_DATABASE_BYTES)
            {
                Ok(())
            } else {
                Err(io::Error::other(
                    "migration database extent exceeds its bound",
                ))
            },
        )
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.extent(offset, out.len())?;
        self.record(self.backend.read(offset, out))
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.extent(offset, bytes.len())?;
        self.record(self.backend.write(offset, bytes))
    }
    fn len(&self) -> io::Result<u64> {
        self.check()?;
        self.record(self.backend.len())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.check()?;
        if len > MAX_PRIVATE_DATABASE_BYTES {
            return self.record(Err(io::Error::other(
                "migration database extent exceeds its bound",
            )));
        }
        self.record(self.backend.set_len(len))
    }
    fn sync(&self) -> io::Result<()> {
        self.check()?;
        self.record(self.backend.sync_data())
    }
}
#[derive(Debug)]
struct Legacy(Arc<Attempt>);
impl redb_legacy::StorageBackend for Legacy {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.0.extent(offset, len)?;
        let mut bytes = vec![0; len];
        self.0.read(offset, &mut bytes)?;
        Ok(bytes)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }
    fn sync_data(&self, _eventual: bool) -> io::Result<()> {
        self.0.sync()
    }
}
#[derive(Debug)]
struct Current(Arc<Attempt>);
impl StorageBackend for Current {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read(offset, out)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.0.sync()
    }
    fn try_lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.0.check()?;
        self.0.backend.try_lock_range(start, end)
    }
    fn close(&self) -> io::Result<()> {
        // Close still releases the lease when sync fails. Preserve that first
        // error; never turn successful unlock into successful migration.
        let synced = self.0.sync();
        let closed = self.0.record(self.0.backend.close());
        synced.and(closed)
    }
}

fn exact_file(path: &Path, size: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| at("trust input open", e))?;
    let mut bytes = Vec::new();
    file.take((size + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| at("trust input read", e))?;
    if bytes.len() != size {
        return Err(refuse("independent trust input has the wrong length"));
    }
    Ok(bytes)
}

fn slots(attempt: &Attempt) -> Result<[u8; 2]> {
    let mut header = [0; 320];
    attempt
        .read(0, &mut header)
        .map_err(|e| at("format preflight read", e))?;
    if header.get(..9) != Some(&[b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a]) {
        return Err(refuse("database magic differs"));
    }
    let god = *header
        .get(9)
        .ok_or_else(|| refuse("short database header"))?;
    if god & !7 != 0 || (god & 2 != 0 && god & 4 == 0) {
        return Err(refuse(
            "database recovery flags are not an admitted two-phase state",
        ));
    }
    // These checks detect corruption; independent root/state checks below are
    // the authentication boundary. No surviving-slot rollback is authorized.
    let mut versions = Vec::with_capacity(2);
    for start in [64, 192] {
        let slot = header
            .get(start..start + 128)
            .ok_or_else(|| refuse("short commit slot"))?;
        let checksum = u128::from_le_bytes(
            slot.get(112..128)
                .ok_or_else(|| refuse("short checksum"))?
                .try_into()
                .map_err(|_| refuse("short checksum"))?,
        );
        let body = slot.get(..112).ok_or_else(|| refuse("short slot body"))?;
        if checksum != twox_hash::XxHash3_128::oneshot_with_seed(0, body) {
            return Err(refuse("slot checksum mismatch before provider dispatch"));
        }
        versions.push(*slot.first().ok_or_else(|| refuse("short slot"))?);
    }
    let versions: [u8; 2] = versions
        .try_into()
        .map_err(|_| refuse("slot inventory differs"))?;
    match versions {
        [2, 2] | [2, 3] | [3, 2] | [3, 3] => Ok(versions),
        _ => Err(refuse("database file format is unsupported")),
    }
}
fn value<'a>(image: &'a Image, name: &str, min: usize, max: usize) -> Result<&'a [u8]> {
    let value = image
        .get(name)
        .ok_or_else(|| refuse("policy image is incomplete"))?;
    if !(min..=max).contains(&value.len()) {
        return Err(refuse("policy field length differs"));
    }
    Ok(value)
}
fn authenticate(image: &Image, root: &[u8], state: TrustedPolicyState) -> Result<bool> {
    if image.len() != 5 || value(image, "schema", SCHEMA.len(), SCHEMA.len())? != SCHEMA {
        return Err(refuse(
            "only the original five-field policy schema is supported",
        ));
    }
    if value(image, "root", ML_DSA_65_VK_LEN, ML_DSA_65_VK_LEN)? != root {
        return Err(refuse("stored root differs from the independent root"));
    }
    if value(image, "state", 36, 36)? != state.encode() {
        return Err(refuse(
            "stored state differs from the independent expected state",
        ));
    }
    let runtime = Runtime::from_signed_policy(
        value(image, "policy", 1, MAX_POLICY_BYTES)?,
        value(image, "signature", ML_DSA_65_SIG_LEN, ML_DSA_65_SIG_LEN)?,
        root,
        Some(&state),
        Limits::default(),
    )
    .map_err(|e| at("signed policy authentication", e))?;
    if runtime.trusted_state() != state {
        return Err(refuse("authenticated state differs"));
    }
    runtime
        .is_enabled()
        .map_err(|e| at("authenticated policy status", e))
}
fn put(image: &mut Image, name: &str, bytes: &[u8]) -> Result<()> {
    let limit = match name {
        "schema" => SCHEMA.len(),
        "root" => ML_DSA_65_VK_LEN,
        "signature" => ML_DSA_65_SIG_LEN,
        "policy" => MAX_POLICY_BYTES,
        "state" => 36,
        _ => return Err(refuse("unexpected policy image field")),
    };
    if bytes.len() > limit || image.insert(name.to_owned(), bytes.to_vec()).is_some() {
        return Err(refuse("policy field is oversized or duplicated"));
    }
    Ok(())
}
fn legacy_image(db: &redb_legacy::Database) -> Result<Image> {
    use redb_legacy::{ReadableTable, ReadableTableMetadata, TableHandle};
    let read = db
        .begin_read()
        .map_err(|e| at("legacy read transaction", e))?;
    let mut tables = read
        .list_tables()
        .map_err(|e| at("legacy table inventory", e))?;
    if tables.next().is_none_or(|t| t.name() != TABLE)
        || tables.next().is_some()
        || read
            .list_multimap_tables()
            .map_err(|e| at("legacy multimap inventory", e))?
            .next()
            .is_some()
    {
        return Err(refuse("unexpected table inventory"));
    }
    let table = read
        .open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(TABLE))
        .map_err(|e| at("legacy policy table", e))?;
    if table.len().map_err(|e| at("legacy field count", e))? != 5 {
        return Err(refuse("policy field count differs"));
    }
    let mut image = Image::new();
    for entry in table.iter().map_err(|e| at("legacy fields", e))? {
        let (k, v) = entry.map_err(|e| at("legacy field", e))?;
        put(&mut image, k.value(), v.value())?;
    }
    Ok(image)
}
fn current_image(db: &redb::Database) -> Result<Image> {
    let read = db
        .begin_read()
        .map_err(|e| at("current read transaction", e))?;
    let mut tables = read
        .list_tables()
        .map_err(|e| at("current table inventory", e))?;
    if tables.next().is_none_or(|t| t.name() != TABLE)
        || tables.next().is_some()
        || read
            .list_multimap_tables()
            .map_err(|e| at("current multimap inventory", e))?
            .next()
            .is_some()
    {
        return Err(refuse("unexpected table inventory"));
    }
    let table = read
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(TABLE))
        .map_err(|e| at("current policy table", e))?;
    if table.len().map_err(|e| at("current field count", e))? != 5 {
        return Err(refuse("policy field count differs"));
    }
    let mut image = Image::new();
    for entry in table.iter().map_err(|e| at("current fields", e))? {
        let (k, v) = entry.map_err(|e| at("current field", e))?;
        put(&mut image, k.value(), v.value())?;
    }
    Ok(image)
}
fn convert(
    attempt: Arc<Attempt>,
    root: &[u8],
    state: TrustedPolicyState,
) -> Result<serde_json::Value> {
    let result = convert_inner(&attempt, root, state);
    // Some provider errors flatten their source chain; some destructors discard
    // errors entirely. Retain the original backend error across both paths,
    // without losing the independently reported operation context.
    match attempt.check() {
        Ok(()) => result,
        Err(io) => Err(at(
            "migration backend I/O",
            AttemptFailure {
                io,
                operation: result.err(),
            },
        )),
    }
}

fn convert_inner(
    attempt: &Arc<Attempt>,
    root: &[u8],
    state: TrustedPolicyState,
) -> Result<serde_json::Value> {
    let versions = slots(attempt)?;
    let legacy = versions != [3, 3];
    let before = if legacy {
        let mut builder = redb_legacy::Database::builder();
        builder.set_cache_size(2 * 1024 * 1024);
        let mut db = builder
            .create_with_backend(Legacy(Arc::clone(attempt)))
            .map_err(|e| at("legacy database open", e))?;
        let image = legacy_image(&db)?;
        authenticate(&image, root, state)?;
        db.upgrade()
            .map_err(|e| at("legacy format conversion", e))?;
        if legacy_image(&db)? != image {
            return Err(refuse("format conversion changed the policy image"));
        }
        drop(db);
        attempt
            .check()
            .map_err(|e| at("legacy database close", e))?;
        if Arc::strong_count(attempt) != 1 {
            return Err(refuse("legacy provider retained the file lease"));
        }
        Some(image)
    } else {
        None
    };
    let mut builder = redb::Database::builder();
    builder.set_cache_size(2 * 1024 * 1024);
    let db = builder
        .create_with_backend(Current(Arc::clone(attempt)))
        .map_err(|e| at("current database open", e))?;
    let image = current_image(&db)?;
    let enabled = authenticate(&image, root, state)?;
    if before.as_ref().is_some_and(|before| before != &image) {
        return Err(refuse("provider handoff changed the policy image"));
    }
    drop(db);
    attempt
        .check()
        .map_err(|e| at("current database close", e))?;
    Ok(serde_json::json!({
        "schema":"q-periapt-policy-store-upgrade/1", "status":"verified-format-3",
        "initial_slots":versions, "legacy_provider_used":legacy, "policy_enabled":enabled,
        "trusted_state":state.encode().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }))
}
pub(super) fn run(path: &Path, root_path: &Path, state_path: &Path) -> Result<serde_json::Value> {
    let root = exact_file(root_path, ML_DSA_65_VK_LEN)?;
    let expected = exact_file(state_path, TrustedPolicyState::ENCODED_LEN)?;
    let state = TrustedPolicyState::decode(&expected)
        .map_err(|_| refuse("independent trusted state is invalid"))?;
    let backend = admit(path)?;
    let attempt = Arc::new(Attempt {
        backend: Box::new(backend),
        failure: Mutex::new(None),
    });
    convert(attempt, &root, state)
}

fn admit(path: &Path) -> Result<MigrationBackend> {
    let file = open_private_file(path, false).map_err(|e| at("private-file admission", e))?;
    let probe = file.try_clone().map_err(|e| at("inode probe", e))?;
    let backend = LockedFileBackend::new(file).map_err(|e| at("exclusive file lease", e))?;
    #[cfg(target_os = "linux")]
    probe
        .try_lock()
        .map_err(|e| at("legacy exclusive file lease", e))?;
    let metadata = probe
        .metadata()
        .map_err(|e| at("locked inode metadata", e))?;
    if metadata.nlink() != 1 || !(320..=MAX_PRIVATE_DATABASE_BYTES).contains(&metadata.len()) {
        return Err(refuse("locked file has an invalid link count or extent"));
    }
    refuse_unclean_foreign_redb(&backend).map_err(|e| at("two-phase recovery admission", e))?;
    Ok(MigrationBackend {
        current: backend,
        #[cfg(target_os = "linux")]
        legacy_lock: probe,
    })
}
