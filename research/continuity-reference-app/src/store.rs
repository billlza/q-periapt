// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable host accounts. Provisioning is explicit; open never creates state.
use crate::error::Error;
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use webauthn_rs::prelude::{Passkey, Uuid};

const CONFIG: TableDefinition<&str, &str> = TableDefinition::new("configuration");
const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const OWNERS: TableDefinition<&[u8], &str> = TableDefinition::new("credential_owners");
const MAX_ACCOUNTS: u64 = 1024;
const MAX_ACCOUNT_BYTES: usize = 64 * 1024;
mod enrollment;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub user_handle: Uuid,
    pub application_id: [u8; 32],
    pub passkeys: Vec<Passkey>,
}

pub struct Store {
    db: Database,
    failed: bool,
    path: PathBuf,
    enrollment_family: Option<[u8; 32]>,
    enrollment_reapproval: bool,
    enrollment_extensions: bool,
    credential_grants: bool,
    policy_approvals: bool,
}
impl Store {
    pub fn provision(path: &Path, origin: &str) -> Result<Self, Error> {
        let db = provision_private_database(path, |db| {
            let mut tx = db
                .begin_write()
                .map_err(|e| Error::internal("initialize account transaction", e))?;
            tx.set_durability(redb::Durability::Immediate)
                .map_err(|e| Error::internal("set initialization durability", e))?;
            tx.set_two_phase_commit(true);
            {
                let mut config = tx
                    .open_table(CONFIG)
                    .map_err(|e| Error::internal("initialize configuration", e))?;
                config
                    .insert("schema", "1")
                    .map_err(|e| Error::internal("write schema", e))?;
                config
                    .insert("origin", origin)
                    .map_err(|e| Error::internal("write origin", e))?;
                tx.open_table(ACCOUNTS)
                    .map_err(|e| Error::internal("initialize accounts", e))?;
                tx.open_table(OWNERS)
                    .map_err(|e| Error::internal("initialize credential owners", e))?;
            }
            tx.commit()
                .map_err(|e| Error::internal("commit account initialization", e))
        })?;
        Ok(Self {
            db,
            failed: false,
            path: path.into(),
            enrollment_family: None,
            enrollment_reapproval: false,
            enrollment_extensions: false,
            credential_grants: false,
            policy_approvals: false,
        })
    }
    pub fn open(path: &Path, origin: &str) -> Result<Self, Error> {
        let db = open_private_database(path)?;
        let schema = {
            let tx = db
                .begin_read()
                .map_err(|e| Error::internal("read account database", e))?;
            let config = tx
                .open_table(CONFIG)
                .map_err(|e| Error::internal("read configuration", e))?;
            if config
                .get("origin")
                .map_err(|e| Error::internal("read account binding", e))?
                .is_none_or(|saved| saved.value() != origin)
            {
                return Err(Error::Conflict("Account store schema or origin differs"));
            }
            tx.open_table(ACCOUNTS)
                .map_err(|e| Error::internal("open accounts", e))?;
            tx.open_table(OWNERS)
                .map_err(|e| Error::internal("open credential owners", e))?;
            enrollment::admit_schema(&tx, &config)?
        };
        Ok(Self {
            db,
            failed: false,
            path: path.into(),
            enrollment_family: schema.family,
            enrollment_reapproval: schema.reapproval,
            enrollment_extensions: schema.extensions,
            credential_grants: schema.grants,
            policy_approvals: schema.policy_approvals,
        })
    }
    fn alive(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Internal)
        } else {
            Ok(())
        }
    }
    pub fn account(&self, name: &str) -> Result<Option<Account>, Error> {
        self.alive()?;
        let tx = self
            .db
            .begin_read()
            .map_err(|e| Error::internal("read account", e))?;
        let table = tx
            .open_table(ACCOUNTS)
            .map_err(|e| Error::internal("open accounts", e))?;
        let value = table
            .get(name)
            .map_err(|e| Error::internal("find account", e))?;
        let account = value.map(|bytes| decode(bytes.value())).transpose()?;
        if let Some(account) = &account {
            if account.name != name {
                return Err(Error::Internal);
            }
            let owners = tx
                .open_table(OWNERS)
                .map_err(|e| Error::internal("read credential index", e))?;
            for passkey in &account.passkeys {
                let id: &[u8] = passkey.cred_id().as_ref();
                if owners
                    .get(id)
                    .map_err(|e| Error::internal("read credential owner", e))?
                    .is_none_or(|owner| owner.value() != name)
                {
                    return Err(Error::Internal);
                }
            }
        }
        Ok(account)
    }
    pub fn save(&mut self, account: &Account, creating: bool) -> Result<(), Error> {
        self.alive()?;
        let result = self.save_transaction(account, creating);
        // Storage/commit errors can have unknown durable outcomes. No new login
        // or enrollment permission may escape this instance until explicit reopen.
        if matches!(result, Err(Error::Internal)) {
            self.failed = true;
        }
        result
    }
    fn save_transaction(&self, account: &Account, creating: bool) -> Result<(), Error> {
        if account.passkeys.is_empty()
            || account.passkeys.len() > 8
            || account.application_id == [0; 32]
        {
            return Err(Error::Invalid("Invalid account credential inventory"));
        }
        let body = serde_json::to_vec(account).map_err(|e| Error::internal("encode account", e))?;
        if body.len() > MAX_ACCOUNT_BYTES {
            return Err(Error::Capacity);
        }
        let mut tx = self
            .db
            .begin_write()
            .map_err(|e| Error::internal("begin account update", e))?;
        tx.set_durability(redb::Durability::Immediate)
            .map_err(|e| Error::internal("set account durability", e))?;
        tx.set_two_phase_commit(true);
        {
            let mut accounts = tx
                .open_table(ACCOUNTS)
                .map_err(|e| Error::internal("open accounts", e))?;
            let previous = accounts
                .get(account.name.as_str())
                .map_err(|e| Error::internal("find account", e))?
                .map(|v| decode(v.value()))
                .transpose()?;
            match (creating, previous) {
                (true, Some(_)) => return Err(Error::Conflict("Account name already registered")),
                (false, None) => return Err(Error::Conflict("Original account is missing")),
                (false, Some(old))
                    if old.application_id != account.application_id
                        || old.user_handle != account.user_handle =>
                {
                    return Err(Error::Conflict("Original account identity differs"))
                }
                _ => {}
            }
            if creating
                && accounts
                    .len()
                    .map_err(|e| Error::internal("count accounts", e))?
                    >= MAX_ACCOUNTS
            {
                return Err(Error::Capacity);
            }
            let mut owners = tx
                .open_table(OWNERS)
                .map_err(|e| Error::internal("open credential index", e))?;
            for passkey in &account.passkeys {
                let id: &[u8] = passkey.cred_id().as_ref();
                if owners
                    .get(id)
                    .map_err(|e| Error::internal("find credential owner", e))?
                    .is_some_and(|v| v.value() != account.name)
                {
                    return Err(Error::Conflict("Credential belongs to another account"));
                }
                owners
                    .insert(id, account.name.as_str())
                    .map_err(|e| Error::internal("retain credential owner", e))?;
            }
            accounts
                .insert(account.name.as_str(), body.as_slice())
                .map_err(|e| Error::internal("retain account", e))?;
        }
        tx.commit()
            .map_err(|e| Error::internal("commit account update", e))
    }
}
fn decode(body: &[u8]) -> Result<Account, Error> {
    if body.len() > MAX_ACCOUNT_BYTES {
        return Err(Error::Internal);
    }
    let account: Account =
        serde_json::from_slice(body).map_err(|e| Error::internal("decode original account", e))?;
    let ids: std::collections::HashSet<_> = account.passkeys.iter().map(|p| p.cred_id()).collect();
    if account.application_id == [0; 32]
        || account.user_handle.is_nil()
        || account.passkeys.is_empty()
        || account.passkeys.len() > 8
        || ids.len() != account.passkeys.len()
    {
        return Err(Error::Internal);
    }
    Ok(account)
}
