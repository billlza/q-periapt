// SPDX-License-Identifier: Apache-2.0 OR MIT
#[cfg(all(test, unix))]
use crate::filesystem::MAX_PRIVATE_DATABASE_BYTES as MAX_DATABASE_BYTES;
use crate::filesystem::{
    open_locked_database, open_private_file, provision_private_database, DatabaseOpenMode,
    PrivateDatabaseError,
};
use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{Limits, PolicyOwner, Runtime};
use redb::ReadableDatabase;
use redb::{
    Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use std::{error::Error as StdError, fmt, fs::File, io, path::Path, sync::Arc};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("sdk_host_policy_v1");
const SCHEMA: &[u8] = b"QPeriapt-Host-Policy-v1";
const MAX_POLICY_BYTES: usize = 65_536;
mod recovery;
pub use recovery::{
    PolicyRecoveryAuthorization, PolicyRecoveryOutcome, PolicyRecoveryRequest, PolicyRecoveryTrust,
    MAX_POLICY_AUTHORITY_RECOVERIES, POLICY_RECOVERY_AUTHORIZATION_BYTES,
};
use recovery::{RecoveryImage, SCHEMA_RECOVERY};

#[cfg(all(test, unix))]
mod tests;

/// Host persistence failures are distinct from ordinary signed-policy rejection.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Closed or failed store; reopen through the explicit recovery boundary.
    Closed,
    /// Missing/insecure path, ownership, mode, ACL, or unsupported host platform.
    PrivateFile,
    /// A second process or owner already holds the store's exclusive lease.
    Busy,
    /// Malformed, incomplete, oversized or inconsistent stored policy image.
    Corrupt,
    /// The supplied independent root differs from the provisioned root.
    RootMismatch,
    /// The caller's expected state no longer matches the current runtime.
    Stale,
    /// This store requires its original independent recovery trust configuration.
    RecoveryRequired,
    /// Recovery grammar, role signatures, key independence or root reuse was rejected.
    RecoveryDenied,
    /// The explicitly bounded lifetime recovery history is full.
    RecoveryLimit,
    /// Policy verification, revocation, quota or closed-runtime error.
    Policy(q_periapt_sdk::Error),
    /// A filesystem operation failed; original I/O context is retained.
    Io(io::Error),
    /// Database read/write failure; an update closes its previous runtime.
    Storage(Box<redb::Error>),
    /// Commit did not report success. Stop use and reconcile the requested policy.
    CommitUncertain(redb::CommitError),
    /// Persistence succeeded, but the runtime was concurrently closed before activation.
    ActivationAfterCommit(q_periapt_sdk::Error),
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "host policy store is closed",
            Self::PrivateFile => "host policy path is missing, unprotected or unsupported",
            Self::Busy => "host policy store already has an exclusive owner",
            Self::Corrupt => "host policy store is malformed or inconsistent",
            Self::RootMismatch => "host policy store has a different pinned root",
            Self::Stale => "host policy update expected a different state",
            Self::RecoveryRequired => "host policy recovery trust configuration is required",
            Self::RecoveryDenied => "host policy authority recovery was rejected",
            Self::RecoveryLimit => "host policy authority recovery history is full",
            Self::Policy(_) => "host policy verification or runtime operation failed",
            Self::Io(_) => "host policy filesystem operation failed",
            Self::Storage(_) => "host policy database operation failed",
            Self::CommitUncertain(_) => {
                "host policy commit outcome is uncertain; old runtime closed"
            }
            Self::ActivationAfterCommit(_) => "host policy persisted but runtime activation failed",
        })
    }
}
impl StdError for StoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Policy(e) | Self::ActivationAfterCommit(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Storage(e) => Some(e),
            Self::CommitUncertain(e) => Some(e),
            _ => None,
        }
    }
}
impl From<q_periapt_sdk::Error> for StoreError {
    fn from(error: q_periapt_sdk::Error) -> Self {
        Self::Policy(error)
    }
}
impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
fn storage(error: impl Into<redb::Error>) -> StoreError {
    StoreError::Storage(Box::new(error.into()))
}
fn database(file: File, create: bool) -> Result<Database, StoreError> {
    let mode = if create {
        DatabaseOpenMode::New
    } else {
        DatabaseOpenMode::Existing
    };
    open_locked_database(file, mode).map_err(StoreError::from)
}
impl From<PrivateDatabaseError> for StoreError {
    fn from(error: PrivateDatabaseError) -> Self {
        match error {
            PrivateDatabaseError::File => Self::PrivateFile,
            PrivateDatabaseError::Busy => Self::Busy,
            PrivateDatabaseError::Corrupt => Self::Corrupt,
            PrivateDatabaseError::Io(error) => Self::Io(error),
            PrivateDatabaseError::Storage(error) => Self::Storage(error),
        }
    }
}

struct Active {
    database: Database,
    owner: PolicyOwner,
    root: Vec<u8>,
    recovery: Option<RecoveryImage>,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.owner.close();
    }
}

/// One private macOS/Linux host store with an exclusive lifetime owner.
///
/// Explicit provisioning never overwrites an existing path. Opening never
/// treats missing/corrupt storage as first use. A signed image and its exact
/// trusted state commit together before a runtime can be returned. Keep this
/// owner alive while using its runtimes: close/drop revokes every retained alias.
///
/// This is local protected-file durability, not an authenticated IPC authority,
/// a hardware rollback counter, or protection against restoring an older disk
/// image. Filesystem sync/atomicity guarantees are required. After an uncertain
/// update, reconcile the attempted policy before serving again; do not silently
/// resume the old policy merely because an old-or-new commit was interrupted.
pub struct PolicyStore {
    active: Option<Active>,
}
impl PolicyStore {
    /// Explicit first provisioning beneath an existing private absolute directory.
    pub fn provision(
        path: &Path,
        policy: &[u8],
        signature: &[u8],
        root: &[u8],
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let owner = PolicyOwner::from_signed_policy(policy, signature, root, None, limits)?;
        let database = provision_private_database(path, |database| {
            let transaction = write_transaction(database)?;
            if let Err(error) = write_image(
                &transaction,
                None,
                root,
                policy,
                signature,
                owner.trusted_state(),
                None,
            ) {
                transaction.abort().map_err(storage)?;
                return Err(error);
            }
            transaction.commit().map_err(StoreError::CommitUncertain)?;
            Ok::<_, StoreError>(())
        })?;
        #[cfg(all(test, unix))]
        tests::after_provision_commit()?;
        Ok(Self {
            active: Some(Active {
                database,
                owner,
                root: root.to_vec(),
                recovery: None,
            }),
        })
    }

    /// Reopen the exact committed signed image under an independently pinned root.
    /// The application must separately reconcile any previously uncertain update.
    pub fn open(path: &Path, root: &[u8], limits: Limits) -> Result<Self, StoreError> {
        Self::open_inner(path, root, None, limits)
    }

    fn open_inner(
        path: &Path,
        root: &[u8],
        recovery_trust: Option<&PolicyRecoveryTrust>,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        if root.len() != ML_DSA_65_VK_LEN {
            return Err(StoreError::RootMismatch);
        }
        let file = open_private_file(path, false).map_err(|_| StoreError::PrivateFile)?;
        let database = database(file, false)?;
        let read = database.begin_read().map_err(storage)?;
        let mut tables = read.list_tables().map_err(storage)?;
        if tables
            .next()
            .is_none_or(|table| table.name() != TABLE.name())
            || tables.next().is_some()
            || read
                .list_multimap_tables()
                .map_err(storage)?
                .next()
                .is_some()
        {
            return Err(StoreError::Corrupt);
        }
        let table = read.open_table(TABLE).map_err(storage)?;
        let image = read_image(
            &table,
            if recovery_trust.is_none() {
                Some(root)
            } else {
                None
            },
        )?;
        match (&image.recovery, recovery_trust) {
            (None, None) => {}
            (Some(recovery), Some(trust)) => recovery.verify(trust, &image.root, image.state)?,
            _ => return Err(StoreError::RecoveryRequired),
        }
        let owner = PolicyOwner::from_signed_policy(
            &image.policy,
            &image.signature,
            &image.root,
            Some(&image.state),
            limits,
        )?;
        if owner.trusted_state() != image.state {
            return Err(StoreError::Corrupt);
        }
        drop(table);
        drop(tables);
        drop(read);
        Ok(Self {
            active: Some(Active {
                database,
                owner,
                root: image.root,
                recovery: image.recovery,
            }),
        })
    }

    /// Open existing storage and reconcile the host's configured signed policy
    /// before exposing a runtime. Same exact policy is idempotent; newer policy
    /// is persisted first. Older/invalid configuration fails without a runtime.
    /// Use this startup boundary after an update with an uncertain result.
    pub fn open_configured(
        path: &Path,
        policy: &[u8],
        signature: &[u8],
        root: &[u8],
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let mut store = Self::open(path, root, limits)?;
        let current = store.runtime()?;
        let requested = Runtime::from_signed_policy(
            policy,
            signature,
            root,
            Some(&current.trusted_state()),
            limits,
        )?;
        if requested.trusted_state() != current.trusted_state() {
            store.replace_policy(current.trusted_state(), policy, signature)?;
        }
        Ok(store)
    }

    /// Borrow an operational runtime without policy-update authority. Update
    /// through [`Self::replace_policy`]; store close/drop revokes every alias.
    pub fn runtime(&self) -> Result<Arc<Runtime>, StoreError> {
        let active = self.active.as_ref().ok_or(StoreError::Closed)?;
        Ok(active.owner.runtime()?)
    }

    /// Verify a strictly newer policy, compare expected state inside the write
    /// transaction, commit its complete signed image, then revoke/replace runtime.
    /// Valid revocations persist a disabled runtime and survive process restart.
    /// Signature/rollback/stale-caller errors leave the current runtime usable.
    /// Storage/commit/activation failures revoke it and close this store.
    pub fn replace_policy(
        &mut self,
        expected: TrustedPolicyState,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<Arc<Runtime>, StoreError> {
        let active = self.active.as_mut().ok_or(StoreError::Closed)?;
        if active.owner.trusted_state() != expected {
            return Err(StoreError::Stale);
        }
        let update = active.owner.prepare_policy_update(policy, signature)?;
        let (_, next) = update.states()?;
        // The mutation owns its epoch on the stack. Result errors AND unwinds
        // drop it and revoke aliases; only complete activation restores the store.
        let mut active = self.active.take().ok_or(StoreError::Closed)?;
        let outcome: Result<Arc<Runtime>, StoreError> = (|| {
            let transaction = write_transaction(&active.database)?;
            if let Err(error) = write_image(
                &transaction,
                Some(expected),
                &active.root,
                policy,
                signature,
                next,
                active.recovery.as_ref(),
            ) {
                transaction.abort().map_err(storage)?;
                return Err(error);
            }
            transaction.commit().map_err(StoreError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            tests::after_policy_commit();
            let owner = update
                .activate_after_persist()
                .map_err(StoreError::ActivationAfterCommit)?;
            active.owner = owner;
            Ok(active.owner.runtime()?)
        })();
        let runtime = outcome?;
        self.active = Some(active);
        Ok(runtime)
    }

    /// Revoke retained runtime aliases and release the lifetime filesystem lock.
    /// Already admitted native operations may finish with their existing leases.
    pub fn close(&mut self) {
        self.active = None;
    }
}
impl Drop for PolicyStore {
    fn drop(&mut self) {
        self.close();
    }
}

struct Image {
    root: Vec<u8>,
    policy: Vec<u8>,
    signature: Vec<u8>,
    state: TrustedPolicyState,
    recovery: Option<RecoveryImage>,
}
fn field(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, StoreError> {
    let value = table
        .get(key)
        .map_err(storage)?
        .ok_or(StoreError::Corrupt)?;
    if !(min..=max).contains(&value.value().len()) {
        return Err(StoreError::Corrupt);
    }
    Ok(value.value().to_vec())
}
fn read_image(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    root: Option<&[u8]>,
) -> Result<Image, StoreError> {
    let schema = field(table, "schema", SCHEMA.len(), SCHEMA.len())?;
    let recovery = if schema == SCHEMA && table.len().map_err(storage)? == 5 {
        None
    } else if schema == SCHEMA_RECOVERY && table.len().map_err(storage)? == 9 {
        Some(RecoveryImage::read(table).map_err(|error| match error {
            StoreError::RecoveryDenied => StoreError::Corrupt,
            error => error,
        })?)
    } else {
        return Err(StoreError::Corrupt);
    };
    let stored_root = field(table, "root", ML_DSA_65_VK_LEN, ML_DSA_65_VK_LEN)?;
    if root.is_some_and(|root| stored_root != root) {
        return Err(StoreError::RootMismatch);
    }
    let state = TrustedPolicyState::decode(&field(table, "state", 36, 36)?)
        .map_err(|_| StoreError::Corrupt)?;
    Ok(Image {
        root: stored_root,
        policy: field(table, "policy", 1, MAX_POLICY_BYTES)?,
        signature: field(table, "signature", ML_DSA_65_SIG_LEN, ML_DSA_65_SIG_LEN)?,
        state,
        recovery,
    })
}
fn write_transaction(database: &Database) -> Result<redb::WriteTransaction, StoreError> {
    let mut transaction = database.begin_write().map_err(storage)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(storage)?;
    transaction.set_two_phase_commit(true);
    Ok(transaction)
}
fn write_image(
    transaction: &redb::WriteTransaction,
    expected: Option<TrustedPolicyState>,
    root: &[u8],
    policy: &[u8],
    signature: &[u8],
    next: TrustedPolicyState,
    recovery: Option<&RecoveryImage>,
) -> Result<(), StoreError> {
    let mut table = transaction.open_table(TABLE).map_err(storage)?;
    if let Some(expected) = expected {
        let image = read_image(&table, Some(root))?;
        if image.state != expected || image.recovery.as_ref() != recovery {
            return Err(StoreError::Corrupt);
        }
    } else if !table.is_empty().map_err(storage)? {
        return Err(StoreError::Corrupt);
    }
    write_fields(&mut table, root, policy, signature, next, recovery)
}
fn write_fields(
    table: &mut redb::Table<&str, &[u8]>,
    root: &[u8],
    policy: &[u8],
    signature: &[u8],
    next: TrustedPolicyState,
    recovery: Option<&RecoveryImage>,
) -> Result<(), StoreError> {
    for (name, bytes) in [
        (
            "schema",
            if recovery.is_some() {
                SCHEMA_RECOVERY
            } else {
                SCHEMA
            },
        ),
        ("root", root),
        ("policy", policy),
        ("signature", signature),
        ("state", &next.encode()),
    ] {
        table.insert(name, bytes).map_err(storage)?;
    }
    if let Some(recovery) = recovery {
        recovery.write(table)?;
    }
    Ok(())
}
