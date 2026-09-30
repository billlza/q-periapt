// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable, bounded archive index committed before connection activation.
use crate::{
    durable::{storage, transaction},
    BootstrapContext, DeviceJournal, DurableError, JournalIdentity, SessionClosureArchive,
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
