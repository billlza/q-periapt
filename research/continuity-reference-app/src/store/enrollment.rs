// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{Account, Store, CONFIG};
use crate::{enrollment::*, error::Error};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod extension;
mod grant;
mod history;
mod policy_approval;
use history::CredentialHistory;
mod operations;
mod reapproval;
mod replacement;
mod root;
const ROOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_roots");
const OPERATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_operations");
const SIGNERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_signers");
const REQUESTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_requests");
const REAPPROVALS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_reapprovals");
const EXTENSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_extensions");
const GRANTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("credential_grants");
const POLICY_APPROVALS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("policy_approvals");
const MAX_OPERATIONS: u64 = 512;
const MAX_RECORD: usize = 128 * 1024;
const MAX_ROOT: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    application: [u8; 32],
    signing_id: [u8; 32],
    revision: u64,
    phase: RootPhase,
    members: Vec<Member>,
    roster: Option<RosterSnapshot>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum RootPhase {
    Wrapping,
    Signing,
    Ready {
        #[serde(with = "wire")]
        public: Vec<u8>,
        account: [u8; 32],
        suspended: bool,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    device: [u8; 16],
    #[serde(with = "wire")]
    certificate: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    invitation: Invitation,
    phase: Phase,
    // Absence is the legacy/ordinary first-use kind, valid only for generation1.
    // Schema7 explicitly admits the replacement kind; old records stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<replacement::Intent>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum Phase {
    Invited,
    Approved {
        #[serde(with = "wire")]
        request: Vec<u8>,
    },
    Issued {
        #[serde(with = "wire")]
        request: Vec<u8>,
        #[serde(with = "wire")]
        response: Vec<u8>,
    },
    Closed,
}

pub(super) struct EnrollmentSchema {
    pub(super) family: Option<[u8; 32]>,
    pub(super) reapproval: bool,
    pub(super) extensions: bool,
    pub(super) grants: bool,
    pub(super) policy_approvals: bool,
    pub(super) replacements: bool,
}
pub(super) fn admit_schema(
    tx: &redb::ReadTransaction,
    config: &redb::ReadOnlyTable<&str, &str>,
) -> Result<EnrollmentSchema, Error> {
    let schema = config
        .get("schema")
        .map_err(db_error)?
        .ok_or(Error::Internal)?;
    let mut names: Vec<_> = tx
        .list_tables()
        .map_err(db_error)?
        .map(|t| t.name().to_owned())
        .collect();
    names.sort();
    let mut expected = vec!["accounts", "configuration", "credential_owners"];
    let replacements = schema.value() == "7";
    let policy_approvals = matches!(schema.value(), "6" | "7");
    let grants = matches!(schema.value(), "5" | "6" | "7");
    let extensions = matches!(schema.value(), "4" | "5" | "6" | "7");
    let reapproval = matches!(schema.value(), "3" | "4" | "5" | "6" | "7");
    let family = match schema.value() {
        "1" => {
            if config.len().map_err(db_error)? != 2 {
                return Err(Error::Internal);
            }
            None
        }
        "2" | "3" | "4" | "5" | "6" | "7" => {
            if config.len().map_err(db_error)? != 3 {
                return Err(Error::Internal);
            }
            expected.extend([
                ROOTS.name(),
                OPERATIONS.name(),
                SIGNERS.name(),
                REQUESTS.name(),
            ]);
            if reapproval {
                expected.push(REAPPROVALS.name());
            }
            if extensions {
                expected.push(EXTENSIONS.name());
            }
            if grants {
                expected.push(GRANTS.name());
            }
            if policy_approvals {
                expected.push(POLICY_APPROVALS.name());
            }
            let saved = config
                .get("enrollment_family")
                .map_err(db_error)?
                .ok_or(Error::Internal)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(saved.value())
                .map_err(|e| Error::internal("retained policy family", e))?;
            let family: [u8; 32] = bytes.try_into().map_err(|_| Error::Internal)?;
            if family == [0; 32] {
                return Err(Error::Internal);
            }
            Some(family)
        }
        _ => {
            return Err(Error::Conflict(
                "Unsupported account schema; explicit upgrade required",
            ))
        }
    };
    expected.sort();
    if names != expected
        || tx
            .list_multimap_tables()
            .map_err(db_error)?
            .next()
            .is_some()
    {
        return Err(Error::Internal);
    }
    Ok(EnrollmentSchema {
        family,
        reapproval,
        extensions,
        grants,
        policy_approvals,
        replacements,
    })
}

impl Store {
    /// Explicit schema-1 upgrade. The host administrator supplies the policy family.
    /// Reopening does not enable enrollment, change families or recreate accounts.
    pub fn enable_enrollment(&mut self, family: [u8; 32]) -> Result<(), Error> {
        self.alive()?;
        if family == [0; 32] {
            return Err(Error::Invalid("Policy family must be nonzero"));
        }
        if let Some(saved) = self.enrollment_family {
            return if saved == family {
                Ok(())
            } else {
                Err(Error::Conflict("Original policy family differs"))
            };
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "1")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(ROOTS).map_err(db_error)?;
                tx.open_table(OPERATIONS).map_err(db_error)?;
                tx.open_table(SIGNERS).map_err(db_error)?;
                tx.open_table(REQUESTS).map_err(db_error)?;
                config
                    .insert("enrollment_family", URL_SAFE_NO_PAD.encode(family).as_str())
                    .map_err(db_error)?;
                config.insert("schema", "2").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("upgrade-before-commit", &family)?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("upgrade-after-commit", &family)?;
            Ok(())
        })?;
        self.enrollment_family = Some(family);
        Ok(())
    }
    fn action<T>(&mut self, f: impl FnOnce(&Self) -> Result<T, Error>) -> Result<T, Error> {
        self.alive()?;
        let result = f(self);
        if matches!(result, Err(Error::Internal)) {
            self.failed = true;
        }
        result
    }
    fn family(&self) -> Result<[u8; 32], Error> {
        self.enrollment_family.ok_or(Error::Conflict(
            "Enrollment requires explicit schema upgrade",
        ))
    }
    fn authorized(&self, account: &Account) -> Result<(), Error> {
        let current = self.account(&account.name)?.ok_or(Error::Unauthorized)?;
        if current.application_id != account.application_id
            || current.user_handle != account.user_handle
        {
            return Err(Error::Unauthorized);
        }
        self.family()?;
        Ok(())
    }
    fn root(&self, account: &Account) -> Result<Root, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(ROOTS).map_err(db_error)?;
        let row = table
            .get(account.application_id.as_slice())
            .map_err(db_error)?
            .ok_or(Error::Conflict("Original account root is not provisioned"))?;
        let root: Root = decode(row.value(), MAX_ROOT)?;
        if root.application != account.application_id
            || root.signing_id == [0; 32]
            || root.revision == 0
            || root.members.len() > sdk::MAX_DEVICES
        {
            return Err(Error::Internal);
        }
        Ok(root)
    }
    fn operation(&self, account: &Account, id: [u8; 32]) -> Result<Operation, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(OPERATIONS).map_err(db_error)?;
        let row = table
            .get(id.as_slice())
            .map_err(db_error)?
            .ok_or(Error::Conflict("Original enrollment operation is absent"))?;
        let operation: Operation = decode(row.value(), MAX_RECORD)?;
        if operation.invitation.operation != id {
            return Err(Error::Internal);
        }
        if operation.invitation.application != account.application_id {
            return Err(Error::Unauthorized);
        }
        match &operation.replacement {
            Some(replacement) if self.enrollment_replacements => {
                replacement.previous(&operation.invitation)?;
            }
            None if operation.invitation.generation == 1 => {}
            _ => return Err(Error::Internal),
        }
        Ok(operation)
    }
}
impl Root {
    fn info(&self, family: [u8; 32]) -> Result<RootInfo, Error> {
        match &self.phase {
            RootPhase::Ready {
                public,
                account,
                suspended,
            } => {
                sdk::PublicKey::decode(public)
                    .map_err(|e| Error::internal("retained root public key", e))?;
                Ok(RootInfo {
                    revision: self.revision,
                    account: *account,
                    public_key: public.clone(),
                    family,
                    suspended: *suspended,
                    roster: self.roster.clone(),
                })
            }
            _ => Err(Error::Conflict(
                "Original root provisioning must be reconciled",
            )),
        }
    }
    fn admits(&self, invitation: &Invitation, family: [u8; 32]) -> Result<(), Error> {
        self.admits_authority(invitation, family)?;
        let info = self.info(family)?;
        if info.roster.as_ref().map(|r| r.checkpoint) != invitation.predecessor {
            return Err(Error::Conflict("Original roster predecessor changed"));
        }
        Ok(())
    }
    fn admits_authority(&self, invitation: &Invitation, family: [u8; 32]) -> Result<(), Error> {
        let info = self.info(family)?;
        if info.suspended
            || info.revision != invitation.root_revision
            || info.public_key != invitation.root
            || family != invitation.family
            || self.application != invitation.application
        {
            return Err(Error::Conflict("Original root authorization changed"));
        }
        Ok(())
    }
}
fn signer_scope(
    account: &Account,
    root: &Root,
    request: &sdk::VerifiedEnrollmentRequest,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&account.application_id);
    key.extend_from_slice(&root.signing_id);
    key.extend_from_slice(request.identity().as_bytes());
    key
}
fn transaction(db: &redb::Database) -> Result<redb::WriteTransaction, Error> {
    let mut tx = db.begin_write().map_err(db_error)?;
    tx.set_durability(redb::Durability::Immediate)
        .map_err(db_error)?;
    tx.set_two_phase_commit(true);
    Ok(tx)
}
fn db_error(e: impl std::fmt::Display) -> Error {
    Error::internal("enrollment transaction", e)
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(db_error)?;
    if bytes.len() > limit {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, Error> {
    if bytes.len() > limit {
        return Err(Error::Internal);
    }
    serde_json::from_slice(bytes).map_err(db_error)
}
fn save_root(tx: &redb::WriteTransaction, root: &Root) -> Result<(), Error> {
    let bytes = encode(root, MAX_ROOT)?;
    tx.open_table(ROOTS)
        .map_err(db_error)?
        .insert(root.application.as_slice(), bytes.as_slice())
        .map_err(db_error)?;
    Ok(())
}
fn save_operation(tx: &redb::WriteTransaction, op: &Operation) -> Result<(), Error> {
    let bytes = encode(op, MAX_RECORD)?;
    tx.open_table(OPERATIONS)
        .map_err(db_error)?
        .insert(op.invitation.operation.as_slice(), bytes.as_slice())
        .map_err(db_error)?;
    Ok(())
}
