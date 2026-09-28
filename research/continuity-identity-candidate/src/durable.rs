// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real local device journal. Encrypted aggregate writes bind the initial
//! operation, private result, one-time claims and immutable response together.
use crate::{
    bootstrap, codec::Decoder, crypto::digest, BootstrapContext, DeviceSigningKey, Error,
    ResponderOperation, VerifiedDevice,
};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use q_periapt_core::ZeroizingBytes;
use q_periapt_host_store::filesystem::{
    open_private_database, open_private_file, provision_private_database, provision_private_file,
    PrivateDatabaseError,
};
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use redb::{
    Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_device_candidate_v2");
const MAX_RECORDS: usize = 128;
const MAX_IMAGE: usize = 2 * 1024 * 1024;
const HEADER: usize = 8 + 32 + 32 + 8 + 24;
const PENDING_CHECKPOINT: usize = 40 + 5817 + 4633 + 32 + 1 + 32;
const COMPLETE_CHECKPOINT: usize = PENDING_CHECKPOINT - 32 + 136;

mod initiator;
pub use initiator::{CommittedInitiation, InitiationId};

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum RecordKind {
    Responder = 1,
    Initiator = 2,
}

/// Explicit local persistence failures. No storage error is reported as absence.
#[derive(Debug)]
pub enum DurableError {
    /// Authenticated lookup found no record for this exact operation.
    Absent,
    /// Closed store, including one revoked after any storage write failure.
    Closed,
    /// Required private path or exact key-file shape was refused.
    PrivateFile,
    /// Original protected database admission failure.
    Database(PrivateDatabaseError),
    /// Original filesystem failure.
    Io(io::Error),
    /// Original storage operation failure.
    Storage(Box<redb::Error>),
    /// Commit did not acknowledge success. Reopen and query the exact operation.
    CommitUncertain(redb::CommitError),
    /// Sealed image authentication failed; a wrong key is not first use.
    Authentication,
    /// Unknown schema, malformed authenticated state or inconsistent record relationships.
    Corrupt,
    /// Authenticated local checkpoint failed its protocol-structure/signature checks.
    InvalidCheckpoint(Error),
    /// The expected owner, context or current aggregate differs.
    Conflict,
    /// A one-time public key is reserved or consumed by another operation.
    PrekeyClaimed,
    /// Bounded journal capacity or revision counter is exhausted.
    Capacity,
    /// A prior non-repeatable computation may have run; it cannot be rerun.
    Suspended,
    /// This exact input already has a durable definitive-failure record.
    Rejected,
    /// Original cryptographic, policy, expiry or runtime failure.
    Protocol(Error),
}
impl fmt::Display for DurableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Absent => "exact journal operation is absent",
            Self::Closed => "device journal is closed",
            Self::PrivateFile => "private journal path or key file rejected",
            Self::Database(_) => "protected database admission failed",
            Self::Io(_) => "journal I/O failed",
            Self::Storage(_) => "journal storage failed",
            Self::CommitUncertain(_) => "journal commit outcome is uncertain",
            Self::Authentication => "sealed journal authentication failed",
            Self::Corrupt => "journal image is inconsistent",
            Self::InvalidCheckpoint(_) => "stored bootstrap checkpoint is invalid",
            Self::Conflict => "journal scope or expected image differs",
            Self::PrekeyClaimed => "one-time prekey already claimed",
            Self::Capacity => "journal capacity exhausted",
            Self::Suspended => "reserved computation requires reconciliation",
            Self::Rejected => "operation has a durable failure record",
            Self::Protocol(_) => "authenticated bootstrap failed",
        })
    }
}
impl std::error::Error for DurableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Storage(e) => Some(e),
            Self::CommitUncertain(e) => Some(e),
            Self::Protocol(e) | Self::InvalidCheckpoint(e) => Some(e),
            _ => None,
        }
    }
}
impl From<Error> for DurableError {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for DurableError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<PrivateDatabaseError> for DurableError {
    fn from(e: PrivateDatabaseError) -> Self {
        Self::Database(e)
    }
}
fn storage(e: impl Into<redb::Error>) -> DurableError {
    DurableError::Storage(Box::new(e.into()))
}

/// Non-cloneable local wrapping key. The protected key file must be kept outside
/// database backups; this file backend assumes a trusted same-UID host. It is
/// neither a hardware key store nor an anti-rollback anchor.
pub struct JournalKey(Box<ZeroizingBytes<32>>);
impl JournalKey {
    /// Generate and durably provision a fresh key without replacing an existing file.
    pub fn provision(path: &Path) -> Result<Self, DurableError> {
        let mut key = Box::new(ZeroizingBytes::zeroed());
        getrandom::fill(key.as_mut_bytes()).map_err(|_| Error::Entropy)?;
        provision_private_file(
            path,
            |_| DurableError::PrivateFile,
            |mut file| {
                file.write_all(b"QPVKEY01")?;
                file.write_all(key.as_bytes())?;
                file.sync_all()?;
                Ok(Self(key))
            },
        )
    }
    /// Load only an existing exact private key file. No raw-key export is provided.
    pub fn open(path: &Path) -> Result<Self, DurableError> {
        let mut file = open_private_file(path, false).map_err(|_| DurableError::PrivateFile)?;
        if file.metadata()?.len() != 40 {
            return Err(DurableError::PrivateFile);
        }
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        if header != *b"QPVKEY01" {
            return Err(DurableError::PrivateFile);
        }
        let mut key = Box::new(ZeroizingBytes::zeroed());
        file.read_exact(key.as_mut_bytes())?;
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(DurableError::PrivateFile);
        }
        Ok(Self(key))
    }
}

/// Independent expected store identity. It distinguishes journals for the same
/// device/key; it is not a monotonic head or a rollback-detection capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalIdentity([u8; 32]);
impl JournalIdentity {
    /// Load trusted configuration, not the header of the database being opened.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public identity to provision independently of the database image.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact durable phase observed after authenticated readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableStatus {
    /// A successful read proves this exact operation is absent.
    Absent = 0,
    /// Reservation is durable; a non-repeatable computation may have executed.
    Executing = 1,
    /// The exact encrypted response/root is pinned; final commit can resume without crypto.
    Prepared = 2,
    /// One-time consumption and exact response/outbox are committed together.
    AwaitingFinal = 3,
    /// Final confirmation and private root are durably installed.
    Complete = 4,
    /// A definitive failure is retained, without consuming a prekey.
    Rejected = 5,
    /// Initiator initial wire and its private reply state are committed.
    AwaitingReply = 6,
    /// Initiator root/final outbox are committed; responder receipt is not implied.
    FinalCommitted = 7,
    /// Initiator accepted result is pinned before final outbox commit.
    FinalPrepared = 8,
    /// One exact signed reply is reserved for deterministic confirmation processing.
    ProcessingReply = 9,
}
impl DurableStatus {
    fn decode(byte: u8) -> Result<Self, DurableError> {
        match byte {
            1 => Ok(Self::Executing),
            2 => Ok(Self::Prepared),
            3 => Ok(Self::AwaitingFinal),
            4 => Ok(Self::Complete),
            5 => Ok(Self::Rejected),
            6 => Ok(Self::AwaitingReply),
            7 => Ok(Self::FinalCommitted),
            8 => Ok(Self::FinalPrepared),
            9 => Ok(Self::ProcessingReply),
            _ => Err(DurableError::Corrupt),
        }
    }
}

struct Record {
    kind: RecordKind,
    context: [u8; 32],
    phase: DurableStatus,
    keys: Vec<[u8; 32]>,
    payload: Zeroizing<Vec<u8>>,
}
impl Record {
    fn check_request(
        &self,
        context: &BootstrapContext,
        initial: &[u8],
    ) -> Result<(), DurableError> {
        if self.kind != RecordKind::Responder {
            return Err(DurableError::Conflict);
        }
        let expected_keys = if self.phase == DurableStatus::Rejected {
            Vec::new()
        } else {
            context.one_time_fingerprints()
        };
        let saved_initial = if matches!(
            self.phase,
            DurableStatus::Executing | DurableStatus::Rejected
        ) {
            self.payload.as_slice()
        } else {
            self.payload
                .get(40..40 + 5817)
                .ok_or(DurableError::Corrupt)?
        };
        if self.context != context.digest()
            || self.keys != expected_keys
            || saved_initial != initial
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
struct Image {
    id: [u8; 32],
    owner: [u8; 32],
    revision: u64,
    digest: [u8; 32],
    records: BTreeMap<[u8; 32], Record>,
}
struct Active {
    db: Database,
    key: JournalKey,
    owner: [u8; 32],
    id: [u8; 32],
}

/// Owned, encrypted macOS/Linux device journal with an exclusive database
/// lifetime lock. Every successful response is persisted before bytes are returned.
/// It enforces local commit ordering and claims across all contexts for one device;
/// it does not establish freshness after restoring an entire older database.
pub struct DeviceJournal {
    active: Option<Active>,
}
impl DeviceJournal {
    /// Explicitly provision a new empty journal for the independently verified local device.
    pub fn provision(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
    ) -> Result<Self, DurableError> {
        let owner = bootstrap::storage_owner(device);
        let mut id = [0u8; 32];
        getrandom::fill(&mut id).map_err(|_| Error::Entropy)?;
        JournalIdentity::from_trusted_state(id)?;
        let image = Image {
            id,
            owner,
            revision: 1,
            digest: [0; 32],
            records: BTreeMap::new(),
        };
        let sealed = seal(&key, &image)?;
        provision_private_database(path, |db| {
            let transaction = transaction(&db)?;
            {
                transaction
                    .open_table(TABLE)
                    .map_err(storage)?
                    .insert("image", sealed.as_slice())
                    .map_err(storage)?;
            }
            transaction
                .commit()
                .map_err(DurableError::CommitUncertain)?;
            Ok(Self {
                active: Some(Active { db, key, owner, id }),
            })
        })
    }
    /// Authenticate and reopen existing storage; missing, wrong-key and malformed stores fail.
    pub fn open(
        path: &Path,
        key: JournalKey,
        device: &VerifiedDevice,
        expected_id: JournalIdentity,
    ) -> Result<Self, DurableError> {
        let db = open_private_database(path)?;
        let owner = bootstrap::storage_owner(device);
        let image = load(&db, &key, owner)?;
        if image.id != expected_id.0 {
            return Err(DurableError::Conflict);
        }
        Ok(Self {
            active: Some(Active {
                db,
                key,
                owner,
                id: image.id,
            }),
        })
    }
    /// Drop the database lease and erase this wrapping-key owner.
    pub fn close(&mut self) {
        self.active = None;
    }
    /// Public identity for independent provisioning after successful creation.
    pub fn identity(&self) -> Result<JournalIdentity, DurableError> {
        Ok(JournalIdentity(
            self.active.as_ref().ok_or(DurableError::Closed)?.id,
        ))
    }

    fn image(&mut self) -> Result<Image, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let result = load(&active.db, &active.key, active.owner).and_then(|image| {
            if image.id == active.id {
                Ok(image)
            } else {
                Err(DurableError::Conflict)
            }
        });
        if result.is_err() {
            self.close();
        }
        result
    }
    fn persist(&mut self, image: &mut Image) -> Result<(), DurableError> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            image.revision = image
                .revision
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(DurableError::Capacity)?;
            let sealed = seal(&active.key, image)?;
            let tx = transaction(&active.db)?;
            {
                let mut table = tx.open_table(TABLE).map_err(storage)?;
                let current = table
                    .get("image")
                    .map_err(storage)?
                    .ok_or(DurableError::Corrupt)?;
                if image_hash(current.value()) != image.digest {
                    return Err(DurableError::Conflict);
                }
                drop(current);
                table.insert("image", sealed.as_slice()).map_err(storage)?;
            }
            tx.commit().map_err(DurableError::CommitUncertain)?;
            image.digest = image_hash(&sealed);
            #[cfg(all(test, unix))]
            tests::after_commit(image);
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn admission(
        &self,
        context: &BootstrapContext,
        initial: &[u8],
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        context.check(now)?;
        self.query_id(context, initial)
    }
    fn query_id(
        &self,
        context: &BootstrapContext,
        initial: &[u8],
    ) -> Result<[u8; 32], DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        if context.storage_owner() != active.owner {
            return Err(DurableError::Conflict);
        }
        context.validate_initial_signature(initial)?;
        Ok(operation_id(&context.digest(), initial))
    }
    /// Linearizable exact-input query after authenticated database readback.
    pub fn status(
        &mut self,
        context: &BootstrapContext,
        initial: &[u8],
    ) -> Result<DurableStatus, DurableError> {
        // Read-only reconciliation remains possible after policy close/expiry.
        // This reports no permission to execute, dispatch or release a secret.
        let id = self.query_id(context, initial)?;
        let image = self.image()?;
        if let Some(record) = image.records.get(&id) {
            record.check_request(context, initial)?;
        }
        Ok(image
            .records
            .get(&id)
            .map_or(DurableStatus::Absent, |r| r.phase))
    }
    /// Reserve before real cryptography, pin its exact private result, atomically
    /// consume one-time claims with the immutable response, then return wire bytes.
    /// Exact committed inputs replay the same bytes without touching supplied keys.
    pub fn respond(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        signer: &DeviceSigningKey,
        pq: PqKeySource<'_>,
        classical: TraditionalKeySource<'_>,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let id = self.admission(&context, initial, now)?;
        let mut image = self.image()?;
        if let Some(record) = image.records.get(&id) {
            record.check_request(&context, initial)?;
            return self.release_prepared(&mut image, id, context, now);
        }
        if image.records.len() >= MAX_RECORDS {
            return Err(DurableError::Capacity);
        }
        let keys = context.one_time_fingerprints();
        for record in image.records.values() {
            if record.keys.iter().any(|key| keys.contains(key)) {
                return Err(DurableError::PrekeyClaimed);
            }
        }
        image.records.insert(
            id,
            Record {
                kind: RecordKind::Responder,
                context: context.digest(),
                phase: DurableStatus::Executing,
                keys,
                payload: Zeroizing::new(initial.to_vec()),
            },
        );
        self.persist(&mut image)?; // The sole execution admission barrier.
        let mut operation = ResponderOperation::new(Arc::clone(&context));
        if let Err(error) = operation.respond(initial, signer, pq, classical, now) {
            let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
            record.phase = DurableStatus::Rejected;
            record.keys.clear();
            self.persist(&mut image)?;
            return Err(DurableError::Protocol(error));
        }
        context.check(now)?;
        let checkpoint = operation.checkpoint()?;
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        record.payload = checkpoint;
        record.phase = DurableStatus::Prepared;
        self.persist(&mut image)?; // Exact result survives before final commit.
        self.release_prepared(&mut image, id, context, now)
    }

    fn release_prepared(
        &mut self,
        image: &mut Image,
        id: [u8; 32],
        context: Arc<BootstrapContext>,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let record = image.records.get(&id).ok_or(DurableError::Absent)?;
        match record.phase {
            DurableStatus::Executing => return Err(DurableError::Suspended),
            DurableStatus::Rejected => return Err(DurableError::Rejected),
            DurableStatus::Absent => return Err(DurableError::Corrupt),
            _ => {}
        }
        let operation = self.restore_record(Arc::clone(&context), &record.payload)?;
        let reply = operation.stored_reply()?.to_vec();
        if record.phase == DurableStatus::Prepared {
            context.check(now)?;
            image
                .records
                .get_mut(&id)
                .ok_or(DurableError::Corrupt)?
                .phase = DurableStatus::AwaitingFinal;
            self.persist(image)?;
        }
        context.check(now)?;
        Ok(reply)
    }
    fn restore_record(
        &mut self,
        context: Arc<BootstrapContext>,
        payload: &[u8],
    ) -> Result<ResponderOperation, DurableError> {
        match ResponderOperation::restore_checkpoint(context, payload) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                self.close();
                Err(DurableError::InvalidCheckpoint(error))
            }
        }
    }
    /// Resume a pinned/committed response without a signing owner or prekey secret.
    /// An executing reservation is suspended, never regenerated after a restart.
    pub fn resume(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let id = self.admission(&context, initial, now)?;
        let mut image = self.image()?;
        if let Some(record) = image.records.get(&id) {
            record.check_request(&context, initial)?;
        }
        self.release_prepared(&mut image, id, context, now)
    }
    /// Authenticate final confirmation and durably install completion before
    /// returning the public session identity. Replays must use the exact final bytes.
    pub fn finish(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        final_wire: &[u8],
        now: u64,
    ) -> Result<[u8; 32], DurableError> {
        let id = self.admission(&context, initial, now)?;
        let mut image = self.image()?;
        let record = image.records.get_mut(&id).ok_or(DurableError::Absent)?;
        record.check_request(&context, initial)?;
        if !matches!(
            record.phase,
            DurableStatus::AwaitingFinal | DurableStatus::Complete
        ) {
            return Err(DurableError::Suspended);
        }
        let mut operation = self.restore_record(Arc::clone(&context), &record.payload)?;
        let session = operation.finish(final_wire, now)?.id();
        if record.phase != DurableStatus::Complete {
            record.payload = operation.checkpoint()?;
            record.phase = DurableStatus::Complete;
            self.persist(&mut image)?;
        }
        context.check(now)?;
        Ok(session)
    }
}

fn transaction(db: &Database) -> Result<redb::WriteTransaction, DurableError> {
    let mut tx = db.begin_write().map_err(storage)?;
    tx.set_durability(Durability::Immediate);
    tx.set_two_phase_commit(true);
    Ok(tx)
}
fn operation_id(context: &[u8; 32], initial: &[u8]) -> [u8; 32] {
    let mut bytes = context.to_vec();
    bytes.extend_from_slice(initial);
    digest(b"Q-PERIAPT-CONTINUITY-VAULT-OP-CANDIDATE/v1", &bytes)
}
fn image_hash(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", wire)
}
fn load(db: &Database, key: &JournalKey, owner: [u8; 32]) -> Result<Image, DurableError> {
    let read = db.begin_read().map_err(storage)?;
    let names: Vec<_> = read
        .list_tables()
        .map_err(storage)?
        .map(|t| t.name().to_owned())
        .collect();
    if names != [TABLE.name()]
        || read
            .list_multimap_tables()
            .map_err(storage)?
            .next()
            .is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = read.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let value = table
        .get("image")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    unseal(key, owner, value.value())
}
fn seal(key: &JournalKey, image: &Image) -> Result<Vec<u8>, DurableError> {
    let mut plaintext = Zeroizing::new(b"QPVIMG02".to_vec());
    plaintext.extend_from_slice(&(image.records.len() as u16).to_be_bytes());
    for (id, record) in &image.records {
        plaintext.extend_from_slice(id);
        plaintext.extend_from_slice(&record.context);
        plaintext.push(record.kind as u8);
        plaintext.push(record.phase as u8);
        plaintext.push(record.keys.len() as u8);
        for key in &record.keys {
            plaintext.extend_from_slice(key);
        }
        plaintext.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&record.payload);
    }
    if image.records.len() > MAX_RECORDS || plaintext.len() > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    let mut wire = b"QPVLT002".to_vec();
    wire.extend_from_slice(&image.id);
    wire.extend_from_slice(&image.owner);
    wire.extend_from_slice(&image.revision.to_be_bytes());
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
    wire.extend_from_slice(&nonce);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.0.as_bytes()).map_err(|_| DurableError::Corrupt)?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &wire, plaintext.as_mut_slice().into())
        .map_err(|_| DurableError::Authentication)?;
    wire.extend_from_slice(&plaintext);
    wire.extend_from_slice(&tag);
    Ok(wire)
}
fn unseal(key: &JournalKey, owner: [u8; 32], wire: &[u8]) -> Result<Image, DurableError> {
    match unseal_image(key, owner, wire) {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        result => result,
    }
}
fn unseal_image(key: &JournalKey, owner: [u8; 32], wire: &[u8]) -> Result<Image, DurableError> {
    if !(HEADER + 16 + 10..=HEADER + 16 + MAX_IMAGE).contains(&wire.len()) {
        return Err(DurableError::Corrupt);
    }
    let mut outer = Decoder::new(wire);
    if outer.array::<8>()? != *b"QPVLT002" {
        return Err(DurableError::Corrupt);
    }
    let id = outer.array::<32>()?;
    if outer.array::<32>()? != owner {
        return Err(DurableError::Conflict);
    }
    let revision = outer.u64()?;
    if revision == 0 || revision == u64::MAX {
        return Err(DurableError::Corrupt);
    }
    let nonce = outer.array::<24>()?;
    let mut bytes = Zeroizing::new(outer.take(wire.len() - HEADER - 16)?.to_vec());
    let tag = Tag::from(outer.array::<16>()?);
    outer.finish()?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.0.as_bytes()).map_err(|_| DurableError::Corrupt)?;
    cipher
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            wire.get(..HEADER).ok_or(DurableError::Corrupt)?,
            bytes.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| DurableError::Authentication)?;
    let mut inner = Decoder::new(&bytes);
    if inner.array::<8>()? != *b"QPVIMG02" {
        return Err(DurableError::Corrupt);
    }
    let count = usize::from(inner.u16()?);
    if count > MAX_RECORDS {
        return Err(DurableError::Capacity);
    }
    let mut records = BTreeMap::new();
    let mut claims = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let op = inner.array::<32>()?;
        if previous.is_some_and(|p| p >= op) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(op);
        let context = inner.array::<32>()?;
        let [kind, phase, count] = inner.array::<3>()?;
        let kind = match kind {
            1 => RecordKind::Responder,
            2 => RecordKind::Initiator,
            _ => return Err(DurableError::Corrupt),
        };
        let phase = DurableStatus::decode(phase)?;
        if count > 2
            || ((phase == DurableStatus::Rejected || kind == RecordKind::Initiator) && count != 0)
        {
            return Err(DurableError::Corrupt);
        }
        let mut keys = Vec::new();
        for _ in 0..count {
            let key = inner.array::<32>()?;
            if keys.last().is_some_and(|p| *p >= key) || !claims.insert(key) {
                return Err(DurableError::Corrupt);
            }
            keys.push(key);
        }
        let length = u32::from_be_bytes(inner.array()?) as usize;
        let payload = Zeroizing::new(inner.take(length)?.to_vec());
        if kind == RecordKind::Initiator {
            initiator::validate_record(&op, &context, phase, &payload)?;
        } else {
            let initial = match phase {
                DurableStatus::Executing | DurableStatus::Rejected if payload.len() == 5817 => {
                    payload.as_slice()
                }
                DurableStatus::Prepared
                | DurableStatus::AwaitingFinal
                | DurableStatus::Complete => {
                    let expected = if phase == DurableStatus::Complete {
                        COMPLETE_CHECKPOINT
                    } else {
                        PENDING_CHECKPOINT
                    };
                    let marker = if phase == DurableStatus::Complete {
                        2
                    } else {
                        1
                    };
                    if payload.len() != expected
                        || payload.get(..8) != Some(b"QPRCHK01")
                        || payload.get(8..40) != Some(context.as_slice())
                        || payload.get(PENDING_CHECKPOINT - 33) != Some(&marker)
                    {
                        return Err(DurableError::Corrupt);
                    }
                    payload.get(40..40 + 5817).ok_or(DurableError::Corrupt)?
                }
                _ => return Err(DurableError::Corrupt),
            };
            if operation_id(&context, initial) != op {
                return Err(DurableError::Corrupt);
            }
        }
        records.insert(
            op,
            Record {
                kind,
                context,
                phase,
                keys,
                payload,
            },
        );
    }
    inner.finish()?;
    Ok(Image {
        id,
        owner,
        revision,
        digest: image_hash(wire),
        records,
    })
}

#[cfg(all(test, unix))]
mod tests;
