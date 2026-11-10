// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

pub(super) const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("sdk_authority");
pub(super) const OPERATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("sdk_publications");
const MAX_RECORD: usize = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub schema: u32,
    pub identity: [u8; 32],
    pub signing_id: [u8; 32],
    pub phase: Phase,
    pub version: u32,
    pub cursor: Cursor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum Phase {
    Wrapping {},
    Signing {},
    Ready {
        #[serde(with = "wire")]
        root: Vec<u8>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum Cursor {
    Idle {},
    Pending { operation: [u8; 32] },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub operation: [u8; 32],
    pub version: u32,
    #[serde(with = "wire")]
    pub document: Vec<u8>,
    pub state: State,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum State {
    Pending {},
    Issued {
        #[serde(with = "wire")]
        signature: Vec<u8>,
        #[serde(with = "wire")]
        trusted_state: Vec<u8>,
    },
    Cancelled {},
}
pub struct AuthorityStore {
    pub(super) db: Database,
    pub(super) path: PathBuf,
    identity: [u8; 32],
    failed: bool,
}
impl AuthorityStore {
    /// Create only a new authority ledger; keys are prepared after its identity commits.
    pub fn provision(path: &Path, identity: [u8; 32]) -> Result<Self, Error> {
        if identity == [0; 32] {
            return Err(Error::Invalid("SDK authority identity must be nonzero"));
        }
        let config = Config {
            schema: 1,
            identity,
            signing_id: *native::SigningKeyId::generate().map_err(fail)?.as_bytes(),
            phase: Phase::Wrapping {},
            version: 0,
            cursor: Cursor::Idle {},
        };
        let db = provision_private_database(path, |db| {
            let tx = transaction(db)?;
            put_config(&tx, &config)?;
            tx.open_table(OPERATIONS).map_err(fail)?;
            tx.commit().map_err(fail)
        })?;
        Ok(Self {
            db,
            path: path.into(),
            identity,
            failed: false,
        })
    }
    /// Open the original protected ledger. Missing files or tables are never initialized.
    pub fn open(path: &Path, identity: [u8; 32]) -> Result<Self, Error> {
        let owner = Self {
            db: open_private_database(path)?,
            path: path.into(),
            identity,
            failed: false,
        };
        let tx = owner.db.begin_read().map_err(fail)?;
        let mut names: Vec<_> = tx
            .list_tables()
            .map_err(fail)?
            .map(|t| t.name().to_owned())
            .collect();
        names.sort();
        if names != [CONFIG.name(), OPERATIONS.name()]
            || tx.list_multimap_tables().map_err(fail)?.next().is_some()
        {
            return Err(Error::Conflict("SDK authority table schema differs"));
        }
        drop(tx);
        owner.config()?;
        Ok(owner)
    }
    pub(super) fn alive(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Internal)
        } else {
            Ok(())
        }
    }
    pub(super) fn action<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.alive()?;
        let result = action(self);
        if matches!(result, Err(Error::Internal | Error::IssuerUnavailable)) {
            self.failed = true;
        }
        result
    }
    pub(super) fn config(&self) -> Result<Config, Error> {
        self.alive()?;
        let tx = self.db.begin_read().map_err(fail)?;
        let table = tx.open_table(CONFIG).map_err(fail)?;
        if table.len().map_err(fail)? != 1 {
            return Err(Error::Internal);
        }
        let value = table.get("state").map_err(fail)?.ok_or(Error::Internal)?;
        let config: Config = decode(value.value())?;
        let operations = tx.open_table(OPERATIONS).map_err(fail)?;
        if config.schema != 1
            || config.identity != self.identity
            || config.identity == [0; 32]
            || config.signing_id == [0; 32]
            || operations.len().map_err(fail)? != u64::from(config.version)
        {
            return Err(Error::Conflict(
                "SDK authority identity, schema or version inventory differs",
            ));
        }
        if let Phase::Ready { root } = &config.phase {
            if root.len() != 1952 || root.iter().all(|v| *v == 0) {
                return Err(Error::Internal);
            }
        } else if config.version != 0 || !matches!(config.cursor, Cursor::Idle {}) {
            return Err(Error::Internal);
        }
        if let Cursor::Pending { operation } = config.cursor {
            let value = operations
                .get(operation.as_slice())
                .map_err(fail)?
                .ok_or(Error::Internal)?;
            let record: Record = decode(value.value())?;
            if operation == [0; 32]
                || record.operation != operation
                || record.version != config.version
                || !matches!(record.state, State::Pending {})
            {
                return Err(Error::Internal);
            }
        }
        Ok(config)
    }
    pub(super) fn record(&self, operation: [u8; 32]) -> Result<Option<Record>, Error> {
        self.alive()?;
        let tx = self.db.begin_read().map_err(fail)?;
        let table = tx.open_table(OPERATIONS).map_err(fail)?;
        let record = table
            .get(operation.as_slice())
            .map_err(fail)?
            .map(|v| decode::<Record>(v.value()))
            .transpose()?;
        if record
            .as_ref()
            .is_some_and(|r| r.operation != operation || operation == [0; 32] || r.version == 0)
        {
            return Err(Error::Internal);
        }
        Ok(record)
    }
}
pub(super) fn transaction(db: &Database) -> Result<redb::WriteTransaction, Error> {
    let mut tx = db.begin_write().map_err(fail)?;
    tx.set_durability(redb::Durability::Immediate)
        .map_err(fail)?;
    tx.set_two_phase_commit(true);
    Ok(tx)
}
pub(super) fn put_config(tx: &redb::WriteTransaction, config: &Config) -> Result<(), Error> {
    tx.open_table(CONFIG)
        .map_err(fail)?
        .insert("state", encode(config)?.as_slice())
        .map_err(fail)?;
    Ok(())
}
pub(super) fn put_record(tx: &redb::WriteTransaction, record: &Record) -> Result<(), Error> {
    tx.open_table(OPERATIONS)
        .map_err(fail)?
        .insert(record.operation.as_slice(), encode(record)?.as_slice())
        .map_err(fail)?;
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(fail)?;
    if bytes.len() > MAX_RECORD {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD {
        return Err(Error::Internal);
    }
    serde_json::from_slice(bytes).map_err(fail)
}
