//! Durable normalized storage for the pure Witness V2 authority state.
//!
//! This Stage 2A1 adapter accepts already authenticated typed state and deployment
//! revisions. It deliberately does not provide a wire protocol, authenticate those
//! revisions, integrate the product service, or by itself close disk-clone, process-clone,
//! key-use fencing, rollback-proof time, or commit-uncertainty recovery claims. Schema V2 has
//! no V1 decoder, migration, or fallback path. Any [`AuthorityStoreErrorV2::CommitUncertain`]
//! places the whole database path in an unresolved quarantine which this stage cannot clear.

use core::fmt;
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{
    Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};

use crate::authority::{
    reachable_lease_receipt_kind, AcceptedKeyIdV2, AcceptedKeyRecordV2, AuthorityEpochV2,
    AuthorityErrorV2, AuthorityIntentV2, AuthorityLimitsV2, AuthorityPersistentMetaV2,
    AuthorityQueryResultV2, AuthorityReceiptV2, AuthorityRestoreErrorV2, AuthorityRestoreV2,
    AuthoritySnapshotV2, AuthorityStateV2, CapabilityIdV2, CapabilityRecordV2,
    DeploymentConfigRevisionV2, OperationIdV2, ReceiptAckDispositionV2, ReceiptAckErrorV2,
    ReceiptLocatorV2, StateHeadV2, TrustedClockErrorV2, TrustedClockV2,
};
use crate::authority_codec::{
    decode_accepted_key_id, decode_capability_record, decode_config, decode_key_record,
    decode_lease, decode_limits, decode_operation_id, decode_receipt, decode_state_head,
    encode_accepted_key_id, encode_capability_record, encode_config, encode_key_record,
    encode_lease, encode_limits, encode_operation_id, encode_receipt, encode_state_head,
    AuthorityCodecError, STORE_SCHEMA_VERSION,
};
use crate::filesystem::{open_private_file, provision_private_file, refuse_unclean_foreign_redb};

#[cfg(test)]
use crate::authority::{
    AuthorityDispositionV2, AuthorityMutationV2, AuthorityRejectionV2, ConfigAdvanceV2,
    InstanceFenceV2, InstanceLeaseV2, ProcessInstanceIdV2, ReservationPointV2, StateAdvanceV2,
    StateFenceV2, StateRevisionV2, StateTransitionKindV2,
};
#[cfg(test)]
use crate::authority_codec::{decode_rejection, encode_intent, encode_rejection, RECEIPT_DOMAIN};
#[cfg(test)]
use crate::codec::{encode_domain, CodecError, Encoder, MAX_FRAME_BYTES};

const STORE_SCHEMA: [u8; 2] = STORE_SCHEMA_VERSION.to_be_bytes();
const STORE_CACHE_BYTES: usize = 64 * 1024 * 1024;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("authority_meta_v2");
const RECEIPT_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("authority_receipts_v2");
const CAPABILITY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("authority_capabilities_v2");
const KEY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("authority_keys_v2");

const META_SCHEMA: &str = "schema";
const META_AUTHORITY_EPOCH: &str = "authority_epoch";
const META_AUTHORITY_VERSION: &str = "authority_version";
const META_CLOCK_FLOOR: &str = "clock_floor_millis";
const META_CONFIG: &str = "config";
const META_STATE_HEAD: &str = "state_head";
const META_LEASE_GENERATION: &str = "lease_generation";
const META_LEASE: &str = "lease";
const META_LIMITS: &str = "limits";
const META_ENTRY_COUNT: u64 = 9;

/// System wall-clock adapter used only on the independently operated authority host.
///
/// Its persisted nondecreasing floor prevents a backward observation from reviving a lease.
/// Deployments must still treat the authority host and its clock-administration boundary as
/// trusted; this adapter is not a Byzantine or hardware-backed time source. The floor guarantee
/// applies only after a successful commit or clean recovery. A commit-uncertain database path
/// cannot safely rely on its stored floor without external non-rollback evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTimeClockV2;

impl TrustedClockV2 for SystemTimeClockV2 {
    fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TrustedClockErrorV2)?;
        u64::try_from(duration.as_millis()).map_err(|_| TrustedClockErrorV2)
    }
}

/// Authority-store persistence, schema, resource, or semantic operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorityStoreErrorV2 {
    /// The protected store path was missing, insecure, or unavailable.
    InsecureOrMissingStore,
    /// Another process or store instance already holds the exclusive database lock.
    AlreadyOpen,
    /// The file is not an exact Authority Store V2 database.
    UnsupportedSchema,
    /// Normalized records were corrupt, incomplete, duplicated, or inconsistent.
    CorruptStore,
    /// A bounded allocation failed before a transaction could be committed.
    AllocationFailed,
    /// Cryptographic randomness for a fresh authority epoch was unavailable.
    EntropyUnavailable,
    /// The pure authority rejected the requested operation without a receipt.
    Authority(AuthorityErrorV2),
    /// Receipt acknowledgement did not match the retained exact receipt.
    ReceiptAcknowledgement(ReceiptAckErrorV2),
    /// A durable commit or explicit abort may have completed with an unknown outcome.
    ///
    /// The current instance is permanently poisoned and the entire database path must remain in
    /// unresolved quarantine. Stage 2A1 provides no safe reopen-and-serve recovery for this state.
    CommitUncertain,
    /// A prior uncertain or fatal persistence result forbids further use of this instance.
    Poisoned,
}

impl fmt::Display for AuthorityStoreErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InsecureOrMissingStore => "authority store path missing or insecure",
            Self::AlreadyOpen => "authority store is already open",
            Self::UnsupportedSchema => "authority store schema is not exact V2",
            Self::CorruptStore => "authority store records are corrupt or inconsistent",
            Self::AllocationFailed => "authority store bounded allocation failed",
            Self::EntropyUnavailable => "authority store epoch randomness unavailable",
            Self::Authority(_) => "pure authority rejected the operation",
            Self::ReceiptAcknowledgement(_) => "authority receipt acknowledgement failed",
            Self::CommitUncertain => "authority store commit or abort outcome is uncertain",
            Self::Poisoned => "authority store instance is poisoned",
        })
    }
}

impl std::error::Error for AuthorityStoreErrorV2 {}

impl AuthorityStoreErrorV2 {
    /// Whether a failure observed before commit must poison this instance once
    /// the transaction is aborted. A bounded allocation failure is the one
    /// error that leaves the store exactly as it was, so it is retried rather
    /// than quarantined; every other pre-commit failure means the in-memory
    /// image can no longer be trusted.
    const fn poisons_after_abort(self) -> bool {
        !matches!(self, Self::AllocationFailed)
    }
}

/// Single-writer normalized redb persistence for [`AuthorityStateV2`].
///
/// The database is the sole truth. The normal path reconstructs and validates a temporary pure
/// state inside one transaction, applies the existing Stage 1 transition logic, writes a generic
/// normalized old/new diff, and commits before returning a known result. If bounded export or
/// serialization allocation fails after trusted time was observed, the business transaction is
/// aborted and a fresh compare-and-set transaction persists only the fixed-width clock floor.
/// Failure of either commit or explicit-abort path poisons this object because durability may be
/// uncertain. [`AuthorityStoreErrorV2::CommitUncertain`] also quarantines the backing path beyond
/// this object's lifetime; schema validation on a later open cannot resolve that uncertainty.
pub struct AuthorityStoreV2 {
    database: Database,
    authority_epoch: AuthorityEpochV2,
    poisoned: bool,
    #[cfg(test)]
    faults: StoreFaults,
}

/// Test-only fault injection. Every point fires once and is then cleared, so a
/// test arms exactly the failure it wants to observe and nothing else.
#[cfg(test)]
#[derive(Default)]
struct StoreFaults {
    next_reservation: Option<ReservationPointV2>,
    before_next_commit: bool,
    after_next_commit: bool,
    next_export_allocation: bool,
    next_encode_allocation: bool,
    next_internal_invariant: bool,
    report_next_abort_failure: bool,
    next_persist_allocation_after_meta: bool,
}

impl fmt::Debug for AuthorityStoreV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityStoreV2")
            .field("authority_epoch", &self.authority_epoch)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl AuthorityStoreV2 {
    /// Provision a new V2 store from already authenticated typed inputs.
    ///
    /// This is not an authentication boundary: a later adapter must verify the signed migration
    /// genesis and signed deployment configuration before calling it.
    pub fn provision(
        path: &Path,
        state_head: StateHeadV2,
        config: DeploymentConfigRevisionV2,
        limits: AuthorityLimitsV2,
    ) -> Result<Self, AuthorityStoreErrorV2> {
        provision_private_file(
            path,
            |_| AuthorityStoreErrorV2::InsecureOrMissingStore,
            |file| Self::provision_file(file, state_head, config, limits, &SystemTimeClockV2),
        )
    }

    /// Open an exact existing V2 store. Missing, V1, or corrupt data fails closed; a corrupted
    /// two-phase primary is refused rather than rolled back. An unclean shutdown is recovered by
    /// `redb` before the schema is validated -- see `store_database_builder`.
    ///
    /// This validates the on-disk schema but cannot detect whether a prior process quarantined the
    /// path after [`AuthorityStoreErrorV2::CommitUncertain`]. Such a path must not be reopened for
    /// service unless an external non-rollback monotonic proof or a later recovery protocol has
    /// resolved the old-or-new outcome.
    pub fn open(path: &Path) -> Result<Self, AuthorityStoreErrorV2> {
        let file = open_private_file(path, false)
            .map_err(|_| AuthorityStoreErrorV2::InsecureOrMissingStore)?;
        Self::open_file(file)
    }

    /// Return this explicitly provisioned store epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpochV2 {
        self.authority_epoch
    }

    /// Read a trusted-time projection and durably retain every clock-floor advance.
    pub fn snapshot(&mut self) -> Result<AuthoritySnapshotV2, AuthorityStoreErrorV2> {
        self.snapshot_with_clock(&SystemTimeClockV2)
    }

    /// Apply one exact authority intent and commit its normalized delta before returning.
    pub fn apply(
        &mut self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityReceiptV2, AuthorityStoreErrorV2> {
        self.apply_with_clock(&SystemTimeClockV2, intent)
    }

    /// Query one retained receipt without treating absence as success or failure.
    pub fn query(
        &mut self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityQueryResultV2, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let state = match self.restore_or_poison(&loaded.image) {
            Ok(state) => state,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let result = match state.receipt(operation_id) {
            Some(receipt) => AuthorityQueryResultV2::Found(Box::new(receipt)),
            None => AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: state.persistent_meta().authority_version,
            },
        };
        self.abort_known(transaction)?;
        Ok(result)
    }

    /// Atomically remove one exactly located receipt; absence remains explicitly idempotent.
    pub fn acknowledge_receipt(
        &mut self,
        locator: ReceiptLocatorV2,
    ) -> Result<ReceiptAckDispositionV2, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let mut state = match self.restore_or_poison(&loaded.image) {
            Ok(state) => state,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let outcome = match state.acknowledge_receipt(locator) {
            Ok(outcome) => outcome,
            Err(error) => {
                return self.finish_aborted(
                    transaction,
                    AuthorityStoreErrorV2::ReceiptAcknowledgement(error),
                    false,
                );
            }
        };
        let next = match state.durable_image().map_err(map_restore) {
            Ok(next) => next,
            Err(error) => {
                let poison_after_abort = error.poisons_after_abort();
                return self.finish_aborted(transaction, error, poison_after_abort);
            }
        };
        if outcome == ReceiptAckDispositionV2::AlreadyAbsent {
            self.abort_known(transaction)?;
            return Ok(outcome);
        }
        if let Err(error) = self.persist_or_poison(&transaction, &loaded.image, &next) {
            let poison_after_abort = error.poisons_after_abort();
            return self.finish_aborted(transaction, error, poison_after_abort);
        }
        self.commit_or_poison(transaction)?;
        Ok(outcome)
    }

    pub(crate) fn wire_v2_history_is_lease_only(
        &mut self,
        expected_config: DeploymentConfigRevisionV2,
    ) -> Result<bool, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        if let Err(error) = self.restore_or_poison(&loaded.image) {
            return self.finish_aborted(transaction, error, false);
        }
        let safe = loaded.image.capabilities.is_empty()
            && loaded.image.keys.is_empty()
            && loaded.image.receipts.iter().all(|(_, receipt)| {
                receipt.intent().expected_config() == expected_config
                    && reachable_lease_receipt_kind(receipt).is_some()
            });
        self.abort_known(transaction)?;
        Ok(safe)
    }

    fn snapshot_with_clock<C: TrustedClockV2>(
        &mut self,
        clock: &C,
    ) -> Result<AuthoritySnapshotV2, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let mut state = match self.restore_or_poison(&loaded.image) {
            Ok(state) => state,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let outcome = match state.snapshot(clock) {
            Ok(outcome) => outcome,
            Err(error) => {
                return self.finish_aborted(
                    transaction,
                    AuthorityStoreErrorV2::Authority(error),
                    false,
                );
            }
        };
        let observed_floor = state.persistent_meta().clock_floor_millis;
        let next = match self.export_state(&state) {
            Ok(next) => next,
            Err(error) => {
                let poison_after_floor = error.poisons_after_abort();
                return self.finish_precommit_failure(
                    transaction,
                    &loaded,
                    observed_floor,
                    error,
                    poison_after_floor,
                );
            }
        };
        if let Err(error) = self.persist_diff_with_fault(&transaction, &loaded.image, &next) {
            let poison_after_floor = error.poisons_after_abort();
            return self.finish_precommit_failure(
                transaction,
                &loaded,
                observed_floor,
                error,
                poison_after_floor,
            );
        }
        self.commit_or_poison(transaction)?;
        Ok(outcome)
    }

    fn apply_with_clock<C: TrustedClockV2>(
        &mut self,
        clock: &C,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityReceiptV2, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        let mut state = match self.restore_or_poison(&loaded.image) {
            Ok(state) => state,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        #[cfg(test)]
        if let Some(point) = self.faults.next_reservation.take() {
            state.fail_next_reservation_for_store_test(point);
        }
        let outcome = state.apply(clock, intent);
        #[cfg(test)]
        let outcome = if self.faults.next_internal_invariant {
            self.faults.next_internal_invariant = false;
            Err(AuthorityErrorV2::InternalInvariant)
        } else {
            outcome
        };
        let observed_floor = state.persistent_meta().clock_floor_millis;
        if outcome == Err(AuthorityErrorV2::InternalInvariant) {
            return self.finish_precommit_failure(
                transaction,
                &loaded,
                observed_floor,
                AuthorityStoreErrorV2::Authority(AuthorityErrorV2::InternalInvariant),
                true,
            );
        }
        let next = match self.export_state(&state) {
            Ok(next) => next,
            Err(error) => {
                let poison_after_floor = error.poisons_after_abort();
                return self.finish_precommit_failure(
                    transaction,
                    &loaded,
                    observed_floor,
                    error,
                    poison_after_floor,
                );
            }
        };
        if let Err(error) = self.persist_diff_with_fault(&transaction, &loaded.image, &next) {
            let poison_after_floor = error.poisons_after_abort();
            return self.finish_precommit_failure(
                transaction,
                &loaded,
                observed_floor,
                error,
                poison_after_floor,
            );
        }
        self.commit_or_poison(transaction)?;
        outcome.map_err(AuthorityStoreErrorV2::Authority)
    }

    /// Provision through the same path-based route as `provision`, but with a
    /// caller-supplied clock, so a test can fail initialization after the file
    /// has already been created.
    // Gated like its only caller: the test that uses it needs an owner-only
    // directory mode, so it is unix-only and this would be dead code elsewhere.
    #[cfg(all(test, unix))]
    pub(crate) fn provision_with_clock_for_test<C: TrustedClockV2>(
        path: &Path,
        state_head: StateHeadV2,
        config: DeploymentConfigRevisionV2,
        limits: AuthorityLimitsV2,
        clock: &C,
    ) -> Result<Self, AuthorityStoreErrorV2> {
        provision_private_file(
            path,
            |_| AuthorityStoreErrorV2::InsecureOrMissingStore,
            |file| Self::provision_file(file, state_head, config, limits, clock),
        )
    }

    fn provision_file<C: TrustedClockV2>(
        file: File,
        state_head: StateHeadV2,
        config: DeploymentConfigRevisionV2,
        limits: AuthorityLimitsV2,
        clock: &C,
    ) -> Result<Self, AuthorityStoreErrorV2> {
        let database = store_database_builder()
            .create_file(file)
            .map_err(map_database_open)?;
        let authority_epoch = generate_authority_epoch()?;
        let state = AuthorityStateV2::provision(state_head, config, limits, clock)
            .map_err(AuthorityStoreErrorV2::Authority)?;
        let image = state.durable_image().map_err(map_restore)?;
        let transaction = durable_write(&database)?;
        if let Err(error) = provision_tables(&transaction, authority_epoch, &image) {
            abort_transaction(transaction)?;
            return Err(error);
        }
        transaction
            .commit()
            .map_err(|_| AuthorityStoreErrorV2::CommitUncertain)?;
        Ok(Self {
            database,
            authority_epoch,
            poisoned: false,
            #[cfg(test)]
            faults: StoreFaults::default(),
        })
    }

    fn open_file(file: File) -> Result<Self, AuthorityStoreErrorV2> {
        if file
            .metadata()
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
            .len()
            == 0
        {
            return Err(AuthorityStoreErrorV2::UnsupportedSchema);
        }
        refuse_unclean_foreign_redb(&file).map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        let database = store_database_builder()
            .create_file(file)
            .map_err(map_database_open)?;
        verify_existing_schema(&database)?;
        let transaction = durable_write(&database)?;
        let loaded = match load_image(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => {
                abort_transaction(transaction)?;
                return Err(error);
            }
        };
        if let Err(error) = AuthorityStateV2::restore(&loaded.image).map_err(map_restore) {
            abort_transaction(transaction)?;
            return Err(error);
        }
        abort_transaction(transaction)?;
        Ok(Self {
            database,
            authority_epoch: loaded.epoch,
            poisoned: false,
            #[cfg(test)]
            faults: StoreFaults::default(),
        })
    }

    fn begin_write(&mut self) -> Result<redb::WriteTransaction, AuthorityStoreErrorV2> {
        match durable_write(&self.database) {
            Ok(transaction) => Ok(transaction),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn load_matching(
        &mut self,
        transaction: &redb::WriteTransaction,
    ) -> Result<LoadedImage, AuthorityStoreErrorV2> {
        match load_image(transaction) {
            Ok(loaded) if loaded.epoch == self.authority_epoch => Ok(loaded),
            Ok(_) | Err(AuthorityStoreErrorV2::CorruptStore) => {
                self.poisoned = true;
                Err(AuthorityStoreErrorV2::CorruptStore)
            }
            Err(AuthorityStoreErrorV2::AllocationFailed) => {
                Err(AuthorityStoreErrorV2::AllocationFailed)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn restore_or_poison(
        &mut self,
        image: &AuthorityRestoreV2,
    ) -> Result<AuthorityStateV2, AuthorityStoreErrorV2> {
        match AuthorityStateV2::restore(image).map_err(map_restore) {
            Ok(state) => Ok(state),
            Err(AuthorityStoreErrorV2::CorruptStore) => {
                self.poisoned = true;
                Err(AuthorityStoreErrorV2::CorruptStore)
            }
            Err(error) => Err(error),
        }
    }

    fn persist_or_poison(
        &mut self,
        transaction: &redb::WriteTransaction,
        old: &AuthorityRestoreV2,
        new: &AuthorityRestoreV2,
    ) -> Result<(), AuthorityStoreErrorV2> {
        match self.persist_diff_with_fault(transaction, old, new) {
            Ok(()) => Ok(()),
            Err(AuthorityStoreErrorV2::AllocationFailed) => {
                Err(AuthorityStoreErrorV2::AllocationFailed)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn persist_diff_with_fault(
        &mut self,
        transaction: &redb::WriteTransaction,
        old: &AuthorityRestoreV2,
        new: &AuthorityRestoreV2,
    ) -> Result<(), AuthorityStoreErrorV2> {
        #[cfg(test)]
        let inject_encode_allocation = {
            let fail = self.faults.next_encode_allocation;
            self.faults.next_encode_allocation = false;
            fail
        };
        #[cfg(not(test))]
        let inject_encode_allocation = false;
        #[cfg(test)]
        let inject_allocation_after_meta = {
            let fail = self.faults.next_persist_allocation_after_meta;
            self.faults.next_persist_allocation_after_meta = false;
            fail
        };
        #[cfg(not(test))]
        let inject_allocation_after_meta = false;
        persist_diff(
            transaction,
            old,
            new,
            inject_encode_allocation,
            inject_allocation_after_meta,
        )
    }

    fn export_state(
        &mut self,
        state: &AuthorityStateV2,
    ) -> Result<AuthorityRestoreV2, AuthorityStoreErrorV2> {
        #[cfg(test)]
        if self.faults.next_export_allocation {
            self.faults.next_export_allocation = false;
            return Err(AuthorityStoreErrorV2::AllocationFailed);
        }
        state.durable_image().map_err(map_restore)
    }

    fn finish_precommit_failure<T>(
        &mut self,
        transaction: redb::WriteTransaction,
        loaded: &LoadedImage,
        observed_floor: u64,
        error: AuthorityStoreErrorV2,
        poison_after_floor: bool,
    ) -> Result<T, AuthorityStoreErrorV2> {
        self.abort_known(transaction)?;
        self.persist_clock_floor_only(loaded, observed_floor)?;
        if poison_after_floor {
            self.poisoned = true;
        }
        Err(error)
    }

    fn finish_aborted<T>(
        &mut self,
        transaction: redb::WriteTransaction,
        error: AuthorityStoreErrorV2,
        poison_after_abort: bool,
    ) -> Result<T, AuthorityStoreErrorV2> {
        self.abort_known(transaction)?;
        if poison_after_abort {
            self.poisoned = true;
        }
        Err(error)
    }

    fn abort_known(
        &mut self,
        transaction: redb::WriteTransaction,
    ) -> Result<(), AuthorityStoreErrorV2> {
        let aborted = abort_transaction(transaction).is_ok();
        #[cfg(test)]
        let injected_failure = {
            let fail = self.faults.report_next_abort_failure;
            self.faults.report_next_abort_failure = false;
            fail
        };
        #[cfg(not(test))]
        let injected_failure = false;
        if !aborted || injected_failure {
            self.poisoned = true;
            return Err(AuthorityStoreErrorV2::CommitUncertain);
        }
        Ok(())
    }

    fn persist_clock_floor_only(
        &mut self,
        loaded: &LoadedImage,
        observed_floor: u64,
    ) -> Result<(), AuthorityStoreErrorV2> {
        let transaction = match durable_write(&self.database) {
            Ok(transaction) => transaction,
            Err(_) => {
                self.poisoned = true;
                return Err(AuthorityStoreErrorV2::CommitUncertain);
            }
        };
        if write_clock_floor_cas(
            &transaction,
            loaded.epoch,
            loaded.image.meta,
            observed_floor,
        )
        .is_err()
        {
            if transaction.abort().is_err() {
                self.poisoned = true;
                return Err(AuthorityStoreErrorV2::CommitUncertain);
            }
            self.poisoned = true;
            return Err(AuthorityStoreErrorV2::CommitUncertain);
        }
        self.commit_or_poison(transaction)
    }

    fn commit_or_poison(
        &mut self,
        transaction: redb::WriteTransaction,
    ) -> Result<(), AuthorityStoreErrorV2> {
        #[cfg(test)]
        let abort_before_commit = {
            let fail = self.faults.before_next_commit;
            self.faults.before_next_commit = false;
            fail
        };
        #[cfg(not(test))]
        let abort_before_commit = false;
        if abort_before_commit {
            self.abort_known(transaction)?;
            self.poisoned = true;
            return Err(AuthorityStoreErrorV2::CommitUncertain);
        }
        let committed = transaction.commit().is_ok();
        #[cfg(test)]
        let injected = {
            let fail = self.faults.after_next_commit;
            self.faults.after_next_commit = false;
            fail
        };
        #[cfg(not(test))]
        let injected = false;
        if !committed || injected {
            self.poisoned = true;
            return Err(AuthorityStoreErrorV2::CommitUncertain);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), AuthorityStoreErrorV2> {
        if self.poisoned {
            Err(AuthorityStoreErrorV2::Poisoned)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn fail_next_reservation_for_test(&mut self, point: ReservationPointV2) {
        self.faults.next_reservation = Some(point);
    }

    #[cfg(test)]
    fn fail_before_next_commit_for_test(&mut self) {
        self.faults.before_next_commit = true;
    }

    #[cfg(test)]
    fn fail_after_next_commit_for_test(&mut self) {
        self.faults.after_next_commit = true;
    }

    #[cfg(test)]
    fn fail_next_export_allocation_for_test(&mut self) {
        self.faults.next_export_allocation = true;
    }

    #[cfg(test)]
    fn fail_next_encode_allocation_for_test(&mut self) {
        self.faults.next_encode_allocation = true;
    }

    #[cfg(test)]
    fn fail_next_internal_invariant_for_test(&mut self) {
        self.faults.next_internal_invariant = true;
    }

    #[cfg(test)]
    fn report_next_abort_failure_for_test(&mut self) {
        self.faults.report_next_abort_failure = true;
    }

    #[cfg(test)]
    fn fail_next_persist_allocation_after_meta_for_test(&mut self) {
        self.faults.next_persist_allocation_after_meta = true;
    }

    #[cfg(test)]
    fn durable_image_for_test(&mut self) -> Result<AuthorityRestoreV2, AuthorityStoreErrorV2> {
        self.ensure_live()?;
        let transaction = self.begin_write()?;
        let loaded = match self.load_matching(&transaction) {
            Ok(loaded) => loaded,
            Err(error) => return self.finish_aborted(transaction, error, false),
        };
        if let Err(error) = self.restore_or_poison(&loaded.image) {
            return self.finish_aborted(transaction, error, false);
        }
        self.abort_known(transaction)?;
        Ok(loaded.image)
    }
}

/// redb is allowed to finish crash recovery when this store is opened.
///
/// This store used to install `RepairSession::abort`, on the understanding
/// that redb asks for a repair only when a file is corrupt or foreign and that
/// two-phase commit spared an ordinary crash from it. It does not: redb asks
/// after every unclean shutdown whose last commit did not save allocator state,
/// and plain two-phase commit never saves it. The serving daemons have no clean
/// shutdown path -- the service manager stops them with a signal, and only a
/// fatal serving error ever returns and drops the store first -- so every
/// restart after a commit is an unclean shutdown, not only a crash. Refusing therefore meant this store could not be
/// reopened after any restart at all, and the authority that grants every
/// instance lease stayed down until an operator intervened.
///
/// Allowing it costs no data safety. Every commit here is two-phase, so the
/// recovery only reconstructs the free-page allocator by walking the committed
/// tree; redb refuses a corrupted two-phase primary outright ("Primary is
/// corrupted despite 2-phase commit") instead of falling back to an older slot,
/// and committed data is never altered. redb's alternative, quick-repair, saves
/// the allocator state on every commit and measured about five times slower per
/// durable commit on this workload, on the path every lease operation takes.
fn store_database_builder() -> redb::Builder {
    let mut builder = Database::builder();
    builder.set_cache_size(STORE_CACHE_BYTES);
    builder
}

fn generate_authority_epoch() -> Result<AuthorityEpochV2, AuthorityStoreErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| AuthorityStoreErrorV2::EntropyUnavailable)?;
        if let Ok(epoch) = AuthorityEpochV2::from_bytes(bytes) {
            return Ok(epoch);
        }
    }
    Err(AuthorityStoreErrorV2::EntropyUnavailable)
}

fn map_database_open(error: redb::DatabaseError) -> AuthorityStoreErrorV2 {
    match error {
        redb::DatabaseError::DatabaseAlreadyOpen => AuthorityStoreErrorV2::AlreadyOpen,
        redb::DatabaseError::RepairAborted
        | redb::DatabaseError::UpgradeRequired(_)
        | redb::DatabaseError::Storage(_) => AuthorityStoreErrorV2::CorruptStore,
        _ => AuthorityStoreErrorV2::CorruptStore,
    }
}

struct LoadedImage {
    epoch: AuthorityEpochV2,
    image: AuthorityRestoreV2,
}

fn durable_write(database: &Database) -> Result<redb::WriteTransaction, AuthorityStoreErrorV2> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction.set_durability(Durability::Immediate);
    transaction.set_two_phase_commit(true);
    Ok(transaction)
}

fn abort_transaction(transaction: redb::WriteTransaction) -> Result<(), AuthorityStoreErrorV2> {
    transaction
        .abort()
        .map_err(|_| AuthorityStoreErrorV2::CommitUncertain)
}

fn write_clock_floor_cas(
    transaction: &redb::WriteTransaction,
    expected_epoch: AuthorityEpochV2,
    expected_meta: AuthorityPersistentMetaV2,
    observed_floor: u64,
) -> Result<(), AuthorityStoreErrorV2> {
    let mut meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    if meta
        .len()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
        != META_ENTRY_COUNT
    {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    {
        let epoch = meta
            .get(META_AUTHORITY_EPOCH)
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
            .ok_or(AuthorityStoreErrorV2::CorruptStore)?;
        if epoch.value() != expected_epoch.as_bytes() {
            return Err(AuthorityStoreErrorV2::CorruptStore);
        }
    }
    {
        let authority_version = meta
            .get(META_AUTHORITY_VERSION)
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
            .ok_or(AuthorityStoreErrorV2::CorruptStore)?;
        if authority_version.value() != expected_meta.authority_version.to_be_bytes() {
            return Err(AuthorityStoreErrorV2::CorruptStore);
        }
    }
    let stored_floor = {
        let clock_floor = meta
            .get(META_CLOCK_FLOOR)
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
            .ok_or(AuthorityStoreErrorV2::CorruptStore)?;
        decode_u64(clock_floor.value())?
    };
    let next_floor = stored_floor
        .max(expected_meta.clock_floor_millis)
        .max(observed_floor)
        .to_be_bytes();
    meta.insert(META_CLOCK_FLOOR, next_floor.as_slice())
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    Ok(())
}

fn provision_tables(
    transaction: &redb::WriteTransaction,
    epoch: AuthorityEpochV2,
    image: &AuthorityRestoreV2,
) -> Result<(), AuthorityStoreErrorV2> {
    let mut meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction
        .open_table(RECEIPT_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction
        .open_table(CAPABILITY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction
        .open_table(KEY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    meta.insert(META_SCHEMA, STORE_SCHEMA.as_slice())
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    meta.insert(META_AUTHORITY_EPOCH, epoch.as_bytes().as_slice())
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    write_meta(&mut meta, image.meta)
}

fn verify_existing_schema(database: &Database) -> Result<(), AuthorityStoreErrorV2> {
    let transaction = database
        .begin_read()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::UnsupportedSchema)?;
    let schema = meta
        .get(META_SCHEMA)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
        .ok_or(AuthorityStoreErrorV2::UnsupportedSchema)?;
    if schema.value() != STORE_SCHEMA {
        return Err(AuthorityStoreErrorV2::UnsupportedSchema);
    }
    drop(schema);
    drop(meta);
    let mut seen = [false; 4];
    for table in transaction
        .list_tables()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
    {
        let name = table.name();
        let slot = if name == META_TABLE.name() {
            0
        } else if name == RECEIPT_TABLE.name() {
            1
        } else if name == CAPABILITY_TABLE.name() {
            2
        } else if name == KEY_TABLE.name() {
            3
        } else {
            return Err(AuthorityStoreErrorV2::CorruptStore);
        };
        let flag = seen
            .get_mut(slot)
            .ok_or(AuthorityStoreErrorV2::CorruptStore)?;
        if *flag {
            return Err(AuthorityStoreErrorV2::CorruptStore);
        }
        *flag = true;
    }
    if seen != [true; 4]
        || transaction
            .list_multimap_tables()
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
            .next()
            .is_some()
    {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    transaction
        .open_table(RECEIPT_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction
        .open_table(CAPABILITY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    transaction
        .open_table(KEY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    Ok(())
}

fn load_image(transaction: &redb::WriteTransaction) -> Result<LoadedImage, AuthorityStoreErrorV2> {
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    if meta
        .len()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
        != META_ENTRY_COUNT
    {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    if read_meta(&meta, META_SCHEMA, STORE_SCHEMA.len())?.as_slice() != STORE_SCHEMA {
        return Err(AuthorityStoreErrorV2::UnsupportedSchema);
    }
    let epoch = AuthorityEpochV2::from_bytes(read_exact_meta(&meta, META_AUTHORITY_EPOCH)?)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let authority_version = decode_u64(&read_meta(&meta, META_AUTHORITY_VERSION, 8)?)?;
    let clock_floor_millis = decode_u64(&read_meta(&meta, META_CLOCK_FLOOR, 8)?)?;
    let config = decode_config(&read_meta(&meta, META_CONFIG, 40)?)?;
    let state_head = decode_state_head(&read_meta(&meta, META_STATE_HEAD, 112)?)?;
    let lease_generation = decode_u64(&read_meta(&meta, META_LEASE_GENERATION, 8)?)?;
    let lease = decode_lease(&read_meta(&meta, META_LEASE, 49)?)?;
    let limits = decode_limits(&read_meta(&meta, META_LIMITS, 32)?)?;
    drop(meta);

    let receipts = read_receipts(transaction, limits.max_receipts())?;
    let capabilities = read_capabilities(transaction, limits.max_capabilities())?;
    let keys = read_keys(transaction, limits.max_keys())?;
    Ok(LoadedImage {
        epoch,
        image: AuthorityRestoreV2 {
            meta: AuthorityPersistentMetaV2 {
                authority_version,
                clock_floor_millis,
                config,
                state_head,
                lease_generation,
                lease,
                limits,
            },
            receipts,
            capabilities,
            keys,
        },
    })
}

fn read_meta(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, AuthorityStoreErrorV2> {
    let value = meta
        .get(name)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?
        .ok_or(AuthorityStoreErrorV2::CorruptStore)?;
    let bytes = value.value();
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn read_exact_meta<const N: usize>(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    name: &'static str,
) -> Result<[u8; N], AuthorityStoreErrorV2> {
    read_meta(meta, name, N)?
        .as_slice()
        .try_into()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)
}

fn read_receipts(
    transaction: &redb::WriteTransaction,
    maximum: usize,
) -> Result<Vec<(OperationIdV2, AuthorityReceiptV2)>, AuthorityStoreErrorV2> {
    let table = transaction
        .open_table(RECEIPT_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let length = bounded_table_len(&table, maximum)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(length)
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
    let entries = table
        .iter()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    for entry in entries {
        let (key, value) = entry.map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        let operation_id = decode_operation_id(key.value())?;
        let receipt = decode_receipt(value.value())?;
        if receipt.intent().operation_id() != operation_id {
            return Err(AuthorityStoreErrorV2::CorruptStore);
        }
        records.push((operation_id, receipt));
    }
    records.sort_unstable_by_key(|(id, _)| *id);
    Ok(records)
}

fn read_capabilities(
    transaction: &redb::WriteTransaction,
    maximum: usize,
) -> Result<Vec<(CapabilityIdV2, CapabilityRecordV2)>, AuthorityStoreErrorV2> {
    let table = transaction
        .open_table(CAPABILITY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let length = bounded_table_len(&table, maximum)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(length)
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
    let entries = table
        .iter()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    for entry in entries {
        let (key, value) = entry.map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        let capability_id = CapabilityIdV2::from_bytes(
            key.value()
                .try_into()
                .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?,
        )
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        records.push((capability_id, decode_capability_record(value.value())?));
    }
    records.sort_unstable_by_key(|(id, _)| *id);
    Ok(records)
}

fn read_keys(
    transaction: &redb::WriteTransaction,
    maximum: usize,
) -> Result<Vec<(AcceptedKeyIdV2, AcceptedKeyRecordV2)>, AuthorityStoreErrorV2> {
    let table = transaction
        .open_table(KEY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let length = bounded_table_len(&table, maximum)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(length)
        .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
    let entries = table
        .iter()
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    for entry in entries {
        let (key, value) = entry.map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        records.push((
            decode_accepted_key_id(key.value())?,
            decode_key_record(value.value())?,
        ));
    }
    records.sort_unstable_by_key(|(id, _)| *id);
    Ok(records)
}

fn bounded_table_len<K: redb::Key + 'static, V: redb::Value + 'static>(
    table: &impl ReadableTable<K, V>,
    maximum: usize,
) -> Result<usize, AuthorityStoreErrorV2> {
    let length = usize::try_from(
        table
            .len()
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?,
    )
    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    if length > maximum {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    Ok(length)
}

fn persist_diff(
    transaction: &redb::WriteTransaction,
    old: &AuthorityRestoreV2,
    new: &AuthorityRestoreV2,
    inject_encode_allocation: bool,
    inject_allocation_after_meta: bool,
) -> Result<(), AuthorityStoreErrorV2> {
    {
        let mut meta = transaction
            .open_table(META_TABLE)
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
        write_meta(&mut meta, new.meta)?;
    }
    if inject_allocation_after_meta {
        return Err(AuthorityStoreErrorV2::AllocationFailed);
    }
    persist_receipt_diff(
        transaction,
        &old.receipts,
        &new.receipts,
        inject_encode_allocation,
    )?;
    persist_capability_diff(transaction, &old.capabilities, &new.capabilities)?;
    persist_key_diff(transaction, &old.keys, &new.keys)
}

fn write_meta(
    meta: &mut redb::Table<&str, &[u8]>,
    value: AuthorityPersistentMetaV2,
) -> Result<(), AuthorityStoreErrorV2> {
    let authority_version = value.authority_version.to_be_bytes();
    let clock_floor = value.clock_floor_millis.to_be_bytes();
    let config = encode_config(value.config);
    let state_head = encode_state_head(value.state_head);
    let lease_generation = value.lease_generation.to_be_bytes();
    let lease = encode_lease(value.lease)?;
    let limits = encode_limits(value.limits)?;
    for (name, bytes) in [
        (META_AUTHORITY_VERSION, authority_version.as_slice()),
        (META_CLOCK_FLOOR, clock_floor.as_slice()),
        (META_CONFIG, config.as_slice()),
        (META_STATE_HEAD, state_head.as_slice()),
        (META_LEASE_GENERATION, lease_generation.as_slice()),
        (META_LEASE, lease.as_slice()),
        (META_LIMITS, limits.as_slice()),
    ] {
        meta.insert(name, bytes)
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    }
    Ok(())
}

fn persist_receipt_diff(
    transaction: &redb::WriteTransaction,
    old: &[(OperationIdV2, AuthorityReceiptV2)],
    new: &[(OperationIdV2, AuthorityReceiptV2)],
    inject_encode_allocation: bool,
) -> Result<(), AuthorityStoreErrorV2> {
    let mut table = transaction
        .open_table(RECEIPT_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let mut old_index = 0usize;
    let mut new_index = 0usize;
    while old_index < old.len() || new_index < new.len() {
        match (old.get(old_index), new.get(new_index)) {
            (Some((old_id, old_receipt)), Some((new_id, new_receipt))) if old_id == new_id => {
                if old_receipt != new_receipt {
                    if inject_encode_allocation {
                        return Err(AuthorityStoreErrorV2::AllocationFailed);
                    }
                    let key = encode_operation_id(*new_id);
                    let value = encode_receipt(*new_receipt)?;
                    let previous = table
                        .insert(key.as_slice(), value.as_slice())
                        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                    if previous.is_none() {
                        return Err(AuthorityStoreErrorV2::CorruptStore);
                    }
                }
                old_index += 1;
                new_index += 1;
            }
            (Some((old_id, _)), Some((new_id, _))) if old_id < new_id => {
                let key = encode_operation_id(*old_id);
                let removed = table
                    .remove(key.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (_, Some((new_id, new_receipt))) => {
                if inject_encode_allocation {
                    return Err(AuthorityStoreErrorV2::AllocationFailed);
                }
                let key = encode_operation_id(*new_id);
                let value = encode_receipt(*new_receipt)?;
                let previous = table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if previous.is_some() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                new_index += 1;
            }
            (Some((old_id, _)), None) => {
                let key = encode_operation_id(*old_id);
                let removed = table
                    .remove(key.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (None, None) => break,
        }
    }
    if bounded_table_len(&table, new.len())? != new.len() {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    Ok(())
}

fn persist_capability_diff(
    transaction: &redb::WriteTransaction,
    old: &[(CapabilityIdV2, CapabilityRecordV2)],
    new: &[(CapabilityIdV2, CapabilityRecordV2)],
) -> Result<(), AuthorityStoreErrorV2> {
    let mut table = transaction
        .open_table(CAPABILITY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let mut old_index = 0usize;
    let mut new_index = 0usize;
    while old_index < old.len() || new_index < new.len() {
        match (old.get(old_index), new.get(new_index)) {
            (Some((old_id, old_record)), Some((new_id, new_record))) if old_id == new_id => {
                if old_record != new_record {
                    let value = encode_capability_record(*new_record)?;
                    let previous = table
                        .insert(new_id.as_bytes().as_slice(), value.as_slice())
                        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                    if previous.is_none() {
                        return Err(AuthorityStoreErrorV2::CorruptStore);
                    }
                }
                old_index += 1;
                new_index += 1;
            }
            (Some((old_id, _)), Some((new_id, _))) if old_id < new_id => {
                let removed = table
                    .remove(old_id.as_bytes().as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (_, Some((new_id, new_record))) => {
                let value = encode_capability_record(*new_record)?;
                let previous = table
                    .insert(new_id.as_bytes().as_slice(), value.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if previous.is_some() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                new_index += 1;
            }
            (Some((old_id, _)), None) => {
                let removed = table
                    .remove(old_id.as_bytes().as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (None, None) => break,
        }
    }
    if bounded_table_len(&table, new.len())? != new.len() {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    Ok(())
}

fn persist_key_diff(
    transaction: &redb::WriteTransaction,
    old: &[(AcceptedKeyIdV2, AcceptedKeyRecordV2)],
    new: &[(AcceptedKeyIdV2, AcceptedKeyRecordV2)],
) -> Result<(), AuthorityStoreErrorV2> {
    let mut table = transaction
        .open_table(KEY_TABLE)
        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
    let mut old_index = 0usize;
    let mut new_index = 0usize;
    while old_index < old.len() || new_index < new.len() {
        match (old.get(old_index), new.get(new_index)) {
            (Some((old_id, old_record)), Some((new_id, new_record))) if old_id == new_id => {
                if old_record != new_record {
                    let key = encode_accepted_key_id(*new_id);
                    let value = encode_key_record(*new_record)?;
                    let previous = table
                        .insert(key.as_slice(), value.as_slice())
                        .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                    if previous.is_none() {
                        return Err(AuthorityStoreErrorV2::CorruptStore);
                    }
                }
                old_index += 1;
                new_index += 1;
            }
            (Some((old_id, _)), Some((new_id, _))) if old_id < new_id => {
                let key = encode_accepted_key_id(*old_id);
                let removed = table
                    .remove(key.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (_, Some((new_id, new_record))) => {
                let key = encode_accepted_key_id(*new_id);
                let value = encode_key_record(*new_record)?;
                let previous = table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if previous.is_some() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                new_index += 1;
            }
            (Some((old_id, _)), None) => {
                let key = encode_accepted_key_id(*old_id);
                let removed = table
                    .remove(key.as_slice())
                    .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?;
                if removed.is_none() {
                    return Err(AuthorityStoreErrorV2::CorruptStore);
                }
                old_index += 1;
            }
            (None, None) => break,
        }
    }
    if bounded_table_len(&table, new.len())? != new.len() {
        return Err(AuthorityStoreErrorV2::CorruptStore);
    }
    Ok(())
}

fn decode_u64(bytes: &[u8]) -> Result<u64, AuthorityStoreErrorV2> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| AuthorityStoreErrorV2::CorruptStore)?,
    ))
}

impl From<AuthorityCodecError> for AuthorityStoreErrorV2 {
    fn from(error: AuthorityCodecError) -> Self {
        match error {
            AuthorityCodecError::Allocation => Self::AllocationFailed,
            AuthorityCodecError::Invalid => Self::CorruptStore,
        }
    }
}

#[cfg(test)]
fn map_codec(error: CodecError) -> AuthorityStoreErrorV2 {
    match error {
        CodecError::Allocation => AuthorityStoreErrorV2::AllocationFailed,
        CodecError::InvalidLength
        | CodecError::InvalidValue
        | CodecError::Io
        | CodecError::Oversized
        | CodecError::TrailingBytes
        | CodecError::Truncated => AuthorityStoreErrorV2::CorruptStore,
    }
}

fn map_restore(error: AuthorityRestoreErrorV2) -> AuthorityStoreErrorV2 {
    match error {
        AuthorityRestoreErrorV2::Allocation => AuthorityStoreErrorV2::AllocationFailed,
        AuthorityRestoreErrorV2::Invalid => AuthorityStoreErrorV2::CorruptStore,
    }
}

#[cfg(test)]
mod tests;
