// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The reference application's durable effect is one stored plaintext delivery.
//! This private host database is outside SDK encryption and erasure guarantees.
use super::*;
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::io;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("reference_inbox_metadata");
const INBOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("reference_inbox_messages");
const SCHEMA: &[u8] = b"qperiapt-reference-inbox/1";
const MAX_DELIVERIES: u64 = 1024;

fn transaction(database: &redb::Database) -> Result<redb::WriteTransaction> {
    let mut tx = database.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    // The shared protected-file opener only admits unclean two-phase images.
    // Immediate alone leaves crash recovery using a different slot-selection rule.
    tx.set_two_phase_commit(true);
    Ok(tx)
}

pub struct Mailbox {
    database: redb::Database,
    journal: [u8; 32],
}
impl Mailbox {
    pub fn provision(path: &Path, journal: [u8; 32]) -> Result<Self> {
        if journal == [0; 32] {
            return Err("Inbox requires the original journal identity".into());
        }
        let database = provision_private_database(path, |database| -> Result<()> {
            let tx = transaction(database)?;
            {
                let mut meta = tx.open_table(META)?;
                meta.insert("schema", SCHEMA)?;
                meta.insert("journal", journal.as_slice())?;
                tx.open_table(INBOX)?;
            }
            tx.commit()?;
            Ok(())
        })?;
        let result = Self { database, journal };
        result.check()?;
        Ok(result)
    }
    pub fn open(path: &Path, journal: [u8; 32]) -> Result<Self> {
        let result = Self {
            database: open_private_database(path)?,
            journal,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        let tx = self.database.begin_read()?;
        let meta = tx.open_table(META)?;
        if self.journal == [0; 32]
            || meta.len()? != 2
            || meta.get("schema")?.as_ref().map(|v| v.value()) != Some(SCHEMA)
            || meta.get("journal")?.as_ref().map(|v| v.value()) != Some(self.journal.as_slice())
            || tx.open_table(INBOX)?.len()? > MAX_DELIVERIES
        {
            return Err("Inbox schema, original journal or capacity differs".into());
        }
        Ok(())
    }
    /// Read a real committed host effect. Absence is explicit failure, not an
    /// empty successful delivery. This API supplies no protocol acknowledgement.
    pub fn delivery(&self, session: [u8; 32], message: [u8; 32]) -> Result<Vec<u8>> {
        self.check()?;
        if session == [0; 32] || message == [0; 32] {
            return Err("Invalid inbox correlation".into());
        }
        let key = [session.as_slice(), message.as_slice()].concat();
        let tx = self.database.begin_read()?;
        let table = tx.open_table(INBOX)?;
        let record = table
            .get(key.as_slice())?
            .ok_or("Original delivery is not committed in this inbox")?;
        if record.value().len() > 16 * 1024 {
            return Err("Inbox delivery capacity".into());
        }
        Ok(record.value().to_vec())
    }
    fn store(&mut self, session: [u8; 32], delivery: &sdk::CommittedPlaintext) -> Result<()> {
        self.check()?;
        if session == [0; 32] || delivery.as_bytes().len() > 16 * 1024 {
            return Err("Inbox delivery bounds".into());
        }
        let key = [session.as_slice(), delivery.message_id().as_bytes()].concat();
        let tx = transaction(&self.database)?;
        {
            let mut inbox = tx.open_table(INBOX)?;
            let old = inbox.get(key.as_slice())?.map(|v| v.value().to_vec());
            match old {
                Some(value) if value == delivery.as_bytes() => {}
                Some(_) => return Err("Conflicting original inbox delivery".into()),
                None => {
                    if inbox.len()? >= MAX_DELIVERIES {
                        return Err("Inbox capacity reached".into());
                    }
                }
            }
            // Repeat the durable write even for an exact retry: the previous
            // caller may have observed an unknown sync/commit outcome.
            inbox.insert(key.as_slice(), delivery.as_bytes())?;
        }
        tx.commit()?;
        Ok(())
    }
}
impl sdk::session_exchange::Consumer for Mailbox {
    fn commit(&mut self, session: [u8; 32], delivery: &sdk::CommittedPlaintext) -> io::Result<()> {
        self.store(session, delivery)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
