// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable, bounded archive index committed before connection activation.
use crate::{
    durable::{storage, transaction},
    BootstrapContext, DeviceJournal, DurableError, JournalIdentity, SessionClosureArchive,
    SessionClosureId, SessionClosureJournal,
};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use std::{collections::BTreeMap, path::Path};

const TABLE: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("continuity_session_archives_v1");
const HEADER: [u8; 32] = [0; 32];
const MAX_ARCHIVES: usize = 128;
fn header(journal: JournalIdentity) -> Vec<u8> {
    let mut value = b"QPCSIX01".to_vec();
    value.extend_from_slice(journal.as_bytes());
    value
}
fn table(
    read: &redb::ReadTransaction,
    journal: JournalIdentity,
) -> Result<redb::ReadOnlyTable<&'static [u8; 32], &'static [u8]>, DurableError> {
    let names: Vec<_> = read.list_tables().map_err(storage)?.collect();
    if names.len() != 1
        || names.first().ok_or(DurableError::Corrupt)?.name() != TABLE.name()
        || read
            .list_multimap_tables()
            .map_err(storage)?
            .next()
            .is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = read.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? > (MAX_ARCHIVES + 1) as u64 {
        return Err(DurableError::Capacity);
    }
    let saved = table
        .get(&HEADER)
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    if saved.value() != header(journal) {
        return Err(DurableError::Conflict);
    }
    drop(saved);
    Ok(table)
}
fn load(
    db: &Database,
    journal: JournalIdentity,
) -> Result<BTreeMap<[u8; 32], SessionClosureArchive>, DurableError> {
    let read = db.begin_read().map_err(storage)?;
    let table = table(&read, journal)?;
    let mut result = BTreeMap::new();
    for entry in table.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        let session = *key.value();
        if session == HEADER {
            continue;
        }
        let archive = SessionClosureArchive::from_bytes(value.value())?;
        archive.check_index(journal, session)?;
        result.insert(session, archive);
    }
    Ok(result)
}

/// Owner-only, exclusively locked index of up to 128 immutable cleanup archives
/// for one independently pinned device journal. No wrapping/signing key is owned.
/// Each record retains its own QPCSCA01 MAC; opening this index does not authenticate
/// that MAC or grant cleanup authority. The journal verifies it before use.
/// Missing/corrupt storage is never interpreted as a new empty index. Restoring an
/// older index may lose discovery/availability; it cannot reset the protected journal.
pub struct SessionArchiveStore {
    active: Option<Database>,
    journal: JournalIdentity,
}
impl SessionArchiveStore {
    /// Explicitly create and sync a new empty index for an independently retained
    /// journal identity. Existing paths are never replaced or treated as first use.
    pub fn provision(path: &Path, journal: JournalIdentity) -> Result<Self, DurableError> {
        provision_private_database(path, |db| {
            let tx = transaction(&db)?;
            tx.open_table(TABLE)
                .map_err(storage)?
                .insert(&HEADER, header(journal).as_slice())
                .map_err(storage)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            load(&db, journal)?;
            Ok(Self {
                active: Some(db),
                journal,
            })
        })
    }
    /// Acquire the existing exclusive lease and validate exact schema, pinned
    /// journal identity and every bounded index/record scope. No repair/reset occurs.
    pub fn open(path: &Path, journal: JournalIdentity) -> Result<Self, DurableError> {
        let db = open_private_database(path)?;
        load(&db, journal)?;
        Ok(Self {
            active: Some(db),
            journal,
        })
    }
    /// Release the exclusive index lease. Its public archival data is retained.
    pub fn close(&mut self) {
        self.active = None;
    }
    pub(crate) fn check_journal(&self, journal: &DeviceJournal) -> Result<(), DurableError> {
        self.check_identity(journal.identity()?)
    }
    pub(crate) fn check_identity(&self, journal: JournalIdentity) -> Result<(), DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        if self.journal != journal {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Read the exact public archive for this session, including its MAC. Parsing
    /// and index scope do not replace authentication by SessionClosureJournal.
    /// Absent is returned only after a successful authoritative lookup.
    pub fn get(&mut self, session: [u8; 32]) -> Result<SessionClosureArchive, DurableError> {
        let result = (|| {
            let db = self.active.as_ref().ok_or(DurableError::Closed)?;
            let read = db.begin_read().map_err(storage)?;
            let table = table(&read, self.journal)?;
            if session == HEADER {
                return Err(DurableError::Absent);
            }
            let bytes = table
                .get(&session)
                .map_err(storage)?
                .ok_or(DurableError::Absent)?;
            let archive = SessionClosureArchive::from_bytes(bytes.value())?;
            archive.check_index(self.journal, session)?;
            Ok(archive)
        })();
        if result.is_err() && !matches!(&result, Err(DurableError::Absent)) {
            self.close();
        }
        result
    }
    /// Enumerate at most 128 indexed IDs in canonical order. These are discovery
    /// hints from the public index, not authenticated session membership or state.
    /// Each archive still requires original journal/key/witness admission. An empty
    /// result follows a successful schema-checked read, never a storage failure.
    pub fn session_ids(&mut self) -> Result<Vec<[u8; 32]>, DurableError> {
        let result = (|| {
            let db = self.active.as_ref().ok_or(DurableError::Closed)?;
            Ok(load(db, self.journal)?.into_keys().collect())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Restore the exact archive admitted by an existing cleanup-only owner.
    /// Original session and fresh required-witness checks precede the write; no
    /// live policy/context or new operational authority is reconstructed. Open the
    /// cleanup owner from independently retained archive bytes first. Conflicting
    /// rows are never overwritten, and unknown commits require exact reopen/retry.
    pub fn restore(&mut self, owner: &mut SessionClosureJournal) -> Result<(), DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        let (session, archive) = owner.index_material(self.journal, None)?;
        self.retain_exact(session, &archive)
    }
    /// Retire only the exact index row for a session whose complete host loss
    /// report has already been acknowledged in its protected journal. The caller
    /// supplies that independently retained report ID. True means a row was removed;
    /// false means a fresh validated lookup found it already absent. Both require
    /// current original-witness admission. Journal tombstones, claims, counters and
    /// capacity are unchanged; this cannot retire reserved aggregate members.
    pub fn retire_closed(
        &mut self,
        owner: &mut SessionClosureJournal,
        report: SessionClosureId,
    ) -> Result<bool, DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        let (session, archive) = owner.index_material(self.journal, Some(report))?;
        let result = (|| {
            let db = self.active.as_ref().ok_or(DurableError::Closed)?;
            let records = load(db, self.journal)?;
            let Some(saved) = records.get(&session) else {
                return Ok(false);
            };
            if saved.as_bytes() != archive.as_bytes() {
                return Err(DurableError::Conflict);
            }
            let tx = transaction(db)?;
            tx.open_table(TABLE)
                .map_err(storage)?
                .remove(&session)
                .map_err(storage)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            if load(db, self.journal)?.contains_key(&session) {
                return Err(DurableError::Conflict);
            }
            Ok(true)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Authenticate and durably index an exact archive before session activation.
    /// Exact repeats are idempotent; changed bytes under a retained ID conflict.
    /// Commit errors close this index owner. Reopen and retry the same archive;
    /// successful readback may prove either the original record or genuine absence.
    /// Never replace the ID or infer that a missing acknowledgement meant no commit.
    pub fn retain(
        &mut self,
        journal: &DeviceJournal,
        context: &BootstrapContext,
        session: [u8; 32],
        archive: &SessionClosureArchive,
    ) -> Result<(), DurableError> {
        self.check_journal(journal)?;
        journal.verify_closure_archive(session, context.digest(), archive)?;
        self.retain_exact(session, archive)
    }
    fn retain_exact(
        &mut self,
        session: [u8; 32],
        archive: &SessionClosureArchive,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let db = self.active.as_ref().ok_or(DurableError::Closed)?;
            let records = load(db, self.journal)?;
            if let Some(saved) = records.get(&session) {
                if saved.as_bytes() != archive.as_bytes() {
                    return Err(DurableError::Conflict);
                }
                return Ok(());
            }
            if records.len() >= MAX_ARCHIVES {
                return Err(DurableError::Capacity);
            }
            let tx = transaction(db)?;
            {
                let mut table = tx.open_table(TABLE).map_err(storage)?;
                if table.get(&session).map_err(storage)?.is_some() {
                    return Err(DurableError::Conflict);
                }
                table
                    .insert(&session, archive.as_bytes())
                    .map_err(storage)?;
            }
            tx.commit().map_err(DurableError::CommitUncertain)?;
            let records = load(db, self.journal)?;
            if records
                .get(&session)
                .ok_or(DurableError::Corrupt)?
                .as_bytes()
                != archive.as_bytes()
            {
                return Err(DurableError::Conflict);
            }
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    #[cfg(feature = "connection-tls")]
    pub(crate) fn require(
        &mut self,
        journal: &DeviceJournal,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<(), DurableError> {
        self.check_journal(journal)?;
        let archive = self.get(session)?;
        journal.verify_closure_archive(session, context.digest(), &archive)
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests;
