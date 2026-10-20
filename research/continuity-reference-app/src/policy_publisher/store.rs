// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

pub(super) const CONFIG: TableDefinition<&str, &[u8]> =
    TableDefinition::new("policy_configuration");
pub(super) const OPERATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("policy_publications");
pub(super) const MAX_RECORD: usize = 128 * 1024;
pub(super) const MAX_OPERATIONS: u64 = 512;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub schema: u32,
    pub publisher: [u8; 32],
    pub signing_id: [u8; 32],
    pub sdk: SdkInput,
    pub signer: SignerPhase,
    pub version: u64,
    pub cursor: Cursor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum SignerPhase {
    Wrapping {},
    Signing {},
    Ready {
        #[serde(with = "wire")]
        public: Vec<u8>,
        family: [u8; 32],
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
    pub version: u64,
    pub request: Request,
    pub state: State,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(super) enum State {
    Pending {},
    Issued {
        digest: [u8; 32],
        #[serde(with = "wire")]
        policy: Vec<u8>,
    },
    Cancelled {},
}

pub struct Publisher {
    pub(super) db: Database,
    pub(super) path: PathBuf,
    pub(super) identity: [u8; 32],
    pub(super) failed: bool,
}
impl Publisher {
    /// Explicit first use, independently provisioned SDK trust and stable host identity.
    pub fn provision(path: &Path, identity: [u8; 32], sdk: SdkInput) -> Result<Self, Error> {
        if identity == [0; 32] {
            return Err(Error::Invalid("Publisher identity must be nonzero"));
        }
        sdk.verify()?;
        let signing_id = *sdk::SigningKeyId::generate().map_err(fail)?.as_bytes();
        let config = Config {
            schema: 1,
            publisher: identity,
            signing_id,
            sdk,
            signer: SignerPhase::Wrapping {},
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

    /// Open the same protected publisher; never construct missing files or tables.
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
        let config = owner.config()?;
        let mut expected = vec![CONFIG.name(), OPERATIONS.name()];
        if config.schema == 2 {
            expected.push(super::renewal_store::RENEWALS.name());
            if tx
                .open_table(super::renewal_store::RENEWALS)
                .map_err(fail)?
                .len()
                .map_err(fail)?
                > MAX_OPERATIONS
            {
                return Err(Error::Capacity);
            }
        }
        expected.sort();
        if names != expected || tx.list_multimap_tables().map_err(fail)?.next().is_some() {
            return Err(Error::Conflict("Publisher table schema differs"));
        }
        drop(tx);
        config.sdk.verify()?;
        if let SignerPhase::Ready { public, family } = &config.signer {
            sdk::PublicKey::decode(public).map_err(fail)?;
            if *family == [0; 32] {
                return Err(Error::Internal);
            }
        }
        Ok(owner)
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
    pub(super) fn alive(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Internal)
        } else {
            Ok(())
        }
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
        if !matches!(config.schema, 1 | 2)
            || config.publisher != self.identity
            || config.publisher == [0; 32]
            || config.signing_id == [0; 32]
            || config.version == u64::MAX
            || operations.len().map_err(fail)? != config.version
            || config.version > MAX_OPERATIONS
        {
            return Err(Error::Conflict(
                "Publisher identity, schema or version inventory differs",
            ));
        }
        if let Cursor::Pending { operation } = config.cursor {
            let record: Record = decode(
                operations
                    .get(operation.as_slice())
                    .map_err(fail)?
                    .ok_or(Error::Internal)?
                    .value(),
            )?;
            if record.operation != operation
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
        if record.as_ref().is_some_and(|r| {
            r.operation != operation
                || operation == [0; 32]
                || r.version == 0
                || r.version == u64::MAX
        }) {
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
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(fail)?;
    if bytes.len() > MAX_RECORD {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD {
        return Err(Error::Internal);
    }
    serde_json::from_slice(bytes).map_err(fail)
}
