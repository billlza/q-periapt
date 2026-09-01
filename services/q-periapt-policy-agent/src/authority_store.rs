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
use crate::filesystem::{open_private_file, provision_private_file};

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
    next_reservation_fault: Option<ReservationPointV2>,
    #[cfg(test)]
    fail_before_next_commit: bool,
    #[cfg(test)]
    fail_after_next_commit: bool,
    #[cfg(test)]
    fail_next_export_allocation: bool,
    #[cfg(test)]
    fail_next_encode_allocation: bool,
    #[cfg(test)]
    fail_next_internal_invariant: bool,
    #[cfg(test)]
    report_next_abort_failure: bool,
    #[cfg(test)]
    fail_next_persist_allocation_after_meta: bool,
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

    /// Open an exact existing V2 store. Missing, V1, full-repair-required, or corrupt data fails
    /// closed. Valid allocator state from an interrupted two-phase commit remains recoverable.
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
                let poison_after_abort = error != AuthorityStoreErrorV2::AllocationFailed;
                return self.finish_aborted(transaction, error, poison_after_abort);
            }
        };
        if outcome == ReceiptAckDispositionV2::AlreadyAbsent {
            self.abort_known(transaction)?;
            return Ok(outcome);
        }
        if let Err(error) = self.persist_or_poison(&transaction, &loaded.image, &next) {
            let poison_after_abort = error != AuthorityStoreErrorV2::AllocationFailed;
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
                let poison_after_floor = error != AuthorityStoreErrorV2::AllocationFailed;
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
            let poison_after_floor = error != AuthorityStoreErrorV2::AllocationFailed;
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
        if let Some(point) = self.next_reservation_fault.take() {
            state.fail_next_reservation_for_store_test(point);
        }
        let outcome = state.apply(clock, intent);
        #[cfg(test)]
        let outcome = if self.fail_next_internal_invariant {
            self.fail_next_internal_invariant = false;
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
                let poison_after_floor = error != AuthorityStoreErrorV2::AllocationFailed;
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
            let poison_after_floor = error != AuthorityStoreErrorV2::AllocationFailed;
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
    #[cfg(test)]
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
            next_reservation_fault: None,
            #[cfg(test)]
            fail_before_next_commit: false,
            #[cfg(test)]
            fail_after_next_commit: false,
            #[cfg(test)]
            fail_next_export_allocation: false,
            #[cfg(test)]
            fail_next_encode_allocation: false,
            #[cfg(test)]
            fail_next_internal_invariant: false,
            #[cfg(test)]
            report_next_abort_failure: false,
            #[cfg(test)]
            fail_next_persist_allocation_after_meta: false,
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
            next_reservation_fault: None,
            #[cfg(test)]
            fail_before_next_commit: false,
            #[cfg(test)]
            fail_after_next_commit: false,
            #[cfg(test)]
            fail_next_export_allocation: false,
            #[cfg(test)]
            fail_next_encode_allocation: false,
            #[cfg(test)]
            fail_next_internal_invariant: false,
            #[cfg(test)]
            report_next_abort_failure: false,
            #[cfg(test)]
            fail_next_persist_allocation_after_meta: false,
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
            let fail = self.fail_next_encode_allocation;
            self.fail_next_encode_allocation = false;
            fail
        };
        #[cfg(not(test))]
        let inject_encode_allocation = false;
        #[cfg(test)]
        let inject_allocation_after_meta = {
            let fail = self.fail_next_persist_allocation_after_meta;
            self.fail_next_persist_allocation_after_meta = false;
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
        if self.fail_next_export_allocation {
            self.fail_next_export_allocation = false;
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
            let fail = self.report_next_abort_failure;
            self.report_next_abort_failure = false;
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
            let fail = self.fail_before_next_commit;
            self.fail_before_next_commit = false;
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
            let fail = self.fail_after_next_commit;
            self.fail_after_next_commit = false;
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
        self.next_reservation_fault = Some(point);
    }

    #[cfg(test)]
    fn fail_before_next_commit_for_test(&mut self) {
        self.fail_before_next_commit = true;
    }

    #[cfg(test)]
    fn fail_after_next_commit_for_test(&mut self) {
        self.fail_after_next_commit = true;
    }

    #[cfg(test)]
    fn fail_next_export_allocation_for_test(&mut self) {
        self.fail_next_export_allocation = true;
    }

    #[cfg(test)]
    fn fail_next_encode_allocation_for_test(&mut self) {
        self.fail_next_encode_allocation = true;
    }

    #[cfg(test)]
    fn fail_next_internal_invariant_for_test(&mut self) {
        self.fail_next_internal_invariant = true;
    }

    #[cfg(test)]
    fn report_next_abort_failure_for_test(&mut self) {
        self.report_next_abort_failure = true;
    }

    #[cfg(test)]
    fn fail_next_persist_allocation_after_meta_for_test(&mut self) {
        self.fail_next_persist_allocation_after_meta = true;
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

fn store_database_builder() -> redb::Builder {
    let mut builder = Database::builder();
    builder
        .set_cache_size(STORE_CACHE_BYTES)
        .set_repair_callback(redb::RepairSession::abort);
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
mod tests {
    use std::cell::Cell;
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    struct FakeClock {
        now: Cell<Option<u64>>,
    }

    impl FakeClock {
        const fn new(now: u64) -> Self {
            Self {
                now: Cell::new(Some(now)),
            }
        }

        fn set(&self, now: u64) {
            self.now.set(Some(now));
        }

        fn fail(&self) {
            self.now.set(None);
        }
    }

    impl TrustedClockV2 for FakeClock {
        fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
            self.now.get().ok_or(TrustedClockErrorV2)
        }
    }

    #[test]
    fn a_failed_provision_leaves_the_path_retryable() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        // `open_private_file` requires an owner-only parent and refuses to
        // follow symlinks, so the directory needs the explicit mode and the
        // canonical path -- on macOS the temporary root is reached through
        // /var, a symlink to /private/var.
        let directory = tempfile::Builder::new()
            .prefix("q-periapt-authority-store-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?.join("authority.redb");

        // Fail initialization after the file has already been created, the way
        // unavailable entropy or a pre-epoch clock would.
        let broken = FakeClock::new(100);
        broken.fail();
        assert!(AuthorityStoreV2::provision_with_clock_for_test(
            &path,
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
            &broken,
        )
        .is_err());

        // The half-provisioned file must not survive. Creation is
        // O_CREAT|O_EXCL, so a leftover makes every later provision fail with
        // EEXIST while `open` rejects the store it finds -- one transient
        // failure would brick the path forever.
        assert!(
            !path.exists(),
            "a failed provision left its store file behind"
        );

        // And the path is genuinely reusable, not merely tidy.
        let working = FakeClock::new(100);
        let retried = AuthorityStoreV2::provision_with_clock_for_test(
            &path,
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
            &working,
        );
        assert!(retried.is_ok(), "retry failed: {:?}", retried.err());
        Ok(())
    }

    fn state_head(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
        fence: u8,
    ) -> TestResult<StateHeadV2> {
        Ok(StateHeadV2::new(
            StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])?,
            StateFenceV2::from_bytes([fence; 32])?,
        ))
    }

    fn config(generation: u64, digest: u8) -> TestResult<DeploymentConfigRevisionV2> {
        Ok(DeploymentConfigRevisionV2::new(generation, [digest; 32])?)
    }

    fn limits(receipts: usize, capabilities: usize, keys: usize) -> TestResult<AuthorityLimitsV2> {
        Ok(AuthorityLimitsV2::new(
            receipts,
            capabilities,
            keys,
            10_000,
        )?)
    }

    fn create_file(path: &Path) -> TestResult<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?)
    }

    fn open_file(path: &Path) -> TestResult<File> {
        Ok(OpenOptions::new().read(true).write(true).open(path)?)
    }

    fn provision_test_store(
        path: &Path,
        clock: &FakeClock,
        configured_limits: AuthorityLimitsV2,
    ) -> TestResult<AuthorityStoreV2> {
        Ok(AuthorityStoreV2::provision_file(
            create_file(path)?,
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            configured_limits,
            clock,
        )?)
    }

    fn reopen(mut store: AuthorityStoreV2, path: &Path) -> TestResult<AuthorityStoreV2> {
        let expected_epoch = store.authority_epoch();
        let expected_image = store.durable_image_for_test()?;
        drop(store);
        let mut reopened = AuthorityStoreV2::open_file(open_file(path)?)?;
        assert_eq!(reopened.authority_epoch(), expected_epoch);
        assert_eq!(reopened.durable_image_for_test()?, expected_image);
        Ok(reopened)
    }

    fn operation(version: u64, byte: u8) -> TestResult<OperationIdV2> {
        Ok(OperationIdV2::new(version, [byte; 32])?)
    }

    fn current_intent(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
        byte: u8,
        mutation: AuthorityMutationV2,
    ) -> TestResult<AuthorityIntentV2> {
        let snapshot = store.snapshot_with_clock(clock)?;
        Ok(AuthorityIntentV2::new(
            operation(snapshot.authority_version(), byte)?,
            snapshot.authority_version(),
            snapshot.config(),
            mutation,
        )?)
    }

    fn apply_current(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
        byte: u8,
        mutation: AuthorityMutationV2,
    ) -> TestResult<AuthorityReceiptV2> {
        let intent = current_intent(store, clock, byte, mutation)?;
        Ok(store.apply_with_clock(clock, intent)?)
    }

    fn active_fence(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
    ) -> TestResult<InstanceFenceV2> {
        store
            .snapshot_with_clock(clock)?
            .active_lease()
            .map(InstanceLeaseV2::fence)
            .ok_or_else(|| "expected active lease".into())
    }

    fn acquire(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
        operation_byte: u8,
        instance_byte: u8,
    ) -> TestResult<InstanceFenceV2> {
        let expected_lease_generation = store.snapshot_with_clock(clock)?.lease_generation();
        let receipt = apply_current(
            store,
            clock,
            operation_byte,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id: ProcessInstanceIdV2::from_bytes([instance_byte; 32])?,
            },
        )?;
        assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
        active_fence(store, clock)
    }

    fn register_one_key(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
        instance_byte: u8,
        capability_byte: u8,
        key_byte: u8,
    ) -> TestResult<(InstanceFenceV2, CapabilityIdV2, AcceptedKeyIdV2)> {
        let fence = acquire(store, clock, 1, instance_byte)?;
        let capability_id = CapabilityIdV2::from_bytes([capability_byte; 32])?;
        assert_eq!(
            apply_current(
                store,
                clock,
                2,
                AuthorityMutationV2::ConsumeCapability {
                    fence,
                    capability_id,
                },
            )?
            .disposition(),
            AuthorityDispositionV2::Applied
        );
        let key_id = AcceptedKeyIdV2::new(1, fence.generation(), [key_byte; 32])?;
        assert_eq!(
            apply_current(
                store,
                clock,
                3,
                AuthorityMutationV2::RegisterKey {
                    fence,
                    capability_id,
                    key_id,
                },
            )?
            .disposition(),
            AuthorityDispositionV2::Applied
        );
        Ok((fence, capability_id, key_id))
    }

    fn assert_all_operations_poisoned(
        store: &mut AuthorityStoreV2,
        clock: &FakeClock,
        intent: AuthorityIntentV2,
        locator: ReceiptLocatorV2,
    ) {
        assert_eq!(
            store.query(intent.operation_id()),
            Err(AuthorityStoreErrorV2::Poisoned)
        );
        assert_eq!(
            store.snapshot_with_clock(clock),
            Err(AuthorityStoreErrorV2::Poisoned)
        );
        assert_eq!(
            store.apply_with_clock(clock, intent),
            Err(AuthorityStoreErrorV2::Poisoned)
        );
        assert_eq!(
            store.acknowledge_receipt(locator),
            Err(AuthorityStoreErrorV2::Poisoned)
        );
    }

    fn reopen_and_assert_floor(
        store: AuthorityStoreV2,
        path: &Path,
        clock: &FakeClock,
        expected_floor: u64,
    ) -> TestResult<AuthorityStoreV2> {
        let mut reopened = reopen(store, path)?;
        clock.set(1);
        assert_eq!(
            reopened.snapshot_with_clock(clock)?.clock_floor_millis(),
            expected_floor
        );
        Ok(reopened)
    }

    fn assert_only_clock_floor_changed(
        before: &AuthorityRestoreV2,
        after: &AuthorityRestoreV2,
        expected_floor: u64,
    ) {
        let mut expected_meta = before.meta;
        expected_meta.clock_floor_millis = expected_floor;
        assert_eq!(after.meta, expected_meta);
        assert_eq!(after.receipts, before.receipts);
        assert_eq!(after.capabilities, before.capabilities);
        assert_eq!(after.keys, before.keys);
    }

    #[test]
    fn all_eight_mutations_survive_normalized_restart_roundtrips() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("authority.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(64, 16, 16)?)?;
        let authority_epoch = store.authority_epoch();

        let first_fence = acquire(&mut store, &clock, 1, 11)?;
        store = reopen(store, &path)?;
        assert_eq!(store.authority_epoch(), authority_epoch);
        let held = apply_current(
            &mut store,
            &clock,
            10,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: first_fence.generation(),
                instance_id: ProcessInstanceIdV2::from_bytes([99; 32])?,
            },
        )?;
        assert_eq!(
            held.disposition(),
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::LeaseHeld)
        );
        store = reopen(store, &path)?;

        clock.set(200);
        let renewed = apply_current(
            &mut store,
            &clock,
            2,
            AuthorityMutationV2::RenewLease { fence: first_fence },
        )?;
        assert_eq!(renewed.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;

        let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
        let consumed = apply_current(
            &mut store,
            &clock,
            3,
            AuthorityMutationV2::ConsumeCapability {
                fence: first_fence,
                capability_id,
            },
        )?;
        assert_eq!(consumed.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;

        let key_id = AcceptedKeyIdV2::new(1, first_fence.generation(), [31; 32])?;
        let registered = apply_current(
            &mut store,
            &clock,
            4,
            AuthorityMutationV2::RegisterKey {
                fence: first_fence,
                capability_id,
                key_id,
            },
        )?;
        assert_eq!(registered.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;
        assert_eq!(store.snapshot_with_clock(&clock)?.active_key_count(), 1);

        let revoked = apply_current(
            &mut store,
            &clock,
            5,
            AuthorityMutationV2::RevokeKey {
                fence: first_fence,
                key_id,
            },
        )?;
        assert_eq!(revoked.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;
        assert_eq!(store.snapshot_with_clock(&clock)?.active_key_count(), 0);

        let released = apply_current(
            &mut store,
            &clock,
            6,
            AuthorityMutationV2::ReleaseLease { fence: first_fence },
        )?;
        assert_eq!(released.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;
        assert_eq!(store.snapshot_with_clock(&clock)?.retained_key_count(), 0);

        let second_fence = acquire(&mut store, &clock, 7, 12)?;
        let original_head = store.snapshot_with_clock(&clock)?.state_head();
        let next_head = state_head(2, 1, 2, 2, 2)?;
        let state_advance =
            StateAdvanceV2::new(StateTransitionKindV2::Advance, original_head, next_head)?;
        let advanced = apply_current(
            &mut store,
            &clock,
            8,
            AuthorityMutationV2::AdvanceState {
                fence: second_fence,
                advance: state_advance,
            },
        )?;
        assert_eq!(advanced.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;
        let after_state = store.snapshot_with_clock(&clock)?;
        assert_eq!(after_state.state_head(), next_head);
        assert_eq!(after_state.capability_count(), 0);
        assert_eq!(after_state.retained_key_count(), 0);

        let first_config = after_state.config();
        let second_config = config(2, 2)?;
        let config_advance = ConfigAdvanceV2::new(first_config, second_config)?;
        let configured = apply_current(
            &mut store,
            &clock,
            9,
            AuthorityMutationV2::AdvanceConfig {
                fence: second_fence,
                advance: config_advance,
            },
        )?;
        assert_eq!(configured.disposition(), AuthorityDispositionV2::Applied);
        store = reopen(store, &path)?;
        let final_snapshot = store.snapshot_with_clock(&clock)?;
        assert_eq!(final_snapshot.authority_version(), 11);
        assert_eq!(final_snapshot.config(), second_config);
        assert_eq!(final_snapshot.active_lease(), None);
        assert_eq!(final_snapshot.receipt_count(), 10);
        Ok(())
    }

    #[test]
    fn active_missing_key_is_corrupt_but_historical_bindings_survive_restart() -> TestResult {
        let directory = tempfile::tempdir()?;
        let clock = FakeClock::new(100);

        let active_path = directory.path().join("active-missing-key.redb");
        let mut active = provision_test_store(&active_path, &clock, limits(16, 4, 4)?)?;
        let (_, _, active_key_id) = register_one_key(&mut active, &clock, 11, 21, 31)?;
        drop(active);
        let database = Database::builder().create_file(open_file(&active_path)?)?;
        let transaction = database.begin_write()?;
        {
            let mut keys = transaction.open_table(KEY_TABLE)?;
            let encoded_key = encode_accepted_key_id(active_key_id);
            assert!(keys.remove(encoded_key.as_slice())?.is_some());
        }
        transaction.commit()?;
        drop(database);
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&active_path)?),
            Err(AuthorityStoreErrorV2::CorruptStore)
        ));

        let release_path = directory.path().join("released-key-tombstone.redb");
        let mut released = provision_test_store(&release_path, &clock, limits(16, 4, 4)?)?;
        let (released_fence, _, _) = register_one_key(&mut released, &clock, 12, 22, 32)?;
        assert_eq!(
            apply_current(
                &mut released,
                &clock,
                4,
                AuthorityMutationV2::ReleaseLease {
                    fence: released_fence,
                },
            )?
            .disposition(),
            AuthorityDispositionV2::Applied
        );
        released = reopen(released, &release_path)?;
        let released_snapshot = released.snapshot_with_clock(&clock)?;
        assert_eq!(released_snapshot.capability_count(), 1);
        assert_eq!(released_snapshot.retained_key_count(), 0);
        assert_eq!(released_snapshot.active_lease(), None);
        let _ = acquire(&mut released, &clock, 5, 13)?;
        released = reopen(released, &release_path)?;
        let reacquired_snapshot = released.snapshot_with_clock(&clock)?;
        assert_eq!(reacquired_snapshot.capability_count(), 1);
        assert_eq!(reacquired_snapshot.retained_key_count(), 0);

        let config_path = directory.path().join("old-config-key-tombstone.redb");
        let mut configured = provision_test_store(&config_path, &clock, limits(16, 4, 4)?)?;
        let (configured_fence, _, _) = register_one_key(&mut configured, &clock, 14, 24, 34)?;
        let next_config = config(2, 2)?;
        assert_eq!(
            apply_current(
                &mut configured,
                &clock,
                4,
                AuthorityMutationV2::AdvanceConfig {
                    fence: configured_fence,
                    advance: ConfigAdvanceV2::new(config(1, 1)?, next_config)?,
                },
            )?
            .disposition(),
            AuthorityDispositionV2::Applied
        );
        configured = reopen(configured, &config_path)?;
        let configured_snapshot = configured.snapshot_with_clock(&clock)?;
        assert_eq!(configured_snapshot.config(), next_config);
        assert_eq!(configured_snapshot.capability_count(), 1);
        assert_eq!(configured_snapshot.retained_key_count(), 0);
        assert_eq!(configured_snapshot.active_lease(), None);
        Ok(())
    }

    #[test]
    fn all_rejection_tags_survive_normalized_restart_roundtrip() -> TestResult {
        const REJECTIONS: &[(u8, AuthorityRejectionV2)] = &[
            (1, AuthorityRejectionV2::ConfigurationMismatch),
            (2, AuthorityRejectionV2::LeaseHeld),
            (3, AuthorityRejectionV2::LeaseGenerationMismatch),
            (4, AuthorityRejectionV2::LeaseAbsent),
            (5, AuthorityRejectionV2::LeaseExpired),
            (6, AuthorityRejectionV2::FenceMismatch),
            (7, AuthorityRejectionV2::LeaseRenewalNotExtended),
            (8, AuthorityRejectionV2::MutationOverflow),
            (9, AuthorityRejectionV2::StateMismatch),
            (10, AuthorityRejectionV2::ConfigTransitionMismatch),
            (11, AuthorityRejectionV2::CapabilityReplay),
            (12, AuthorityRejectionV2::CapabilityUnknown),
            (13, AuthorityRejectionV2::CapabilityStale),
            (14, AuthorityRejectionV2::CapabilityAlreadyBound),
            (15, AuthorityRejectionV2::KeyAlreadyRegistered),
            (16, AuthorityRejectionV2::KeyStateGenerationMismatch),
            (17, AuthorityRejectionV2::KeyLeaseGenerationMismatch),
            (18, AuthorityRejectionV2::KeyUnknown),
            (19, AuthorityRejectionV2::KeyRevoked),
            (20, AuthorityRejectionV2::CapabilityCapacityExceeded),
            (21, AuthorityRejectionV2::KeyCapacityExceeded),
        ];

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("rejections.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(32, 4, 4)?)?;
        let mut image = store.durable_image_for_test()?;
        image
            .receipts
            .try_reserve_exact(REJECTIONS.len())
            .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;

        for &(tag, rejection) in REJECTIONS {
            assert_eq!(encode_rejection(rejection), tag);
            assert_eq!(decode_rejection(tag)?, rejection);
            let expected_authority_version = u64::from(tag);
            let intent = AuthorityIntentV2::new(
                operation(expected_authority_version, tag)?,
                expected_authority_version,
                config(1, 1)?,
                AuthorityMutationV2::AcquireLease {
                    expected_lease_generation: 0,
                    instance_id: ProcessInstanceIdV2::from_bytes([tag; 32])?,
                },
            )?;
            let receipt = AuthorityReceiptV2::restore(
                intent,
                AuthorityDispositionV2::Rejected(rejection),
                expected_authority_version + 1,
            )
            .map_err(map_restore)?;
            assert_eq!(decode_receipt(&encode_receipt(receipt)?)?, receipt);
            image.receipts.push((intent.operation_id(), receipt));
        }
        image.meta.authority_version = 22;
        image.receipts.sort_unstable_by_key(|(id, _)| *id);
        let next = AuthorityStateV2::restore(&image)
            .map_err(map_restore)?
            .durable_image()
            .map_err(map_restore)?;

        let transaction = store.begin_write()?;
        let loaded = store.load_matching(&transaction)?;
        store.persist_or_poison(&transaction, &loaded.image, &next)?;
        store.commit_or_poison(transaction)?;
        store = reopen(store, &path)?;
        for &(_, receipt) in &next.receipts {
            assert_eq!(
                store.query(receipt.intent().operation_id())?,
                AuthorityQueryResultV2::Found(Box::new(receipt))
            );
        }
        Ok(())
    }

    #[test]
    fn replay_clock_floor_and_acknowledgement_are_durable() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("authority.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(8, 4, 4)?)?;
        let intent = current_intent(
            &mut store,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let receipt = store.apply_with_clock(&clock, intent)?;
        clock.set(500);
        assert_eq!(store.apply_with_clock(&clock, intent)?, receipt);
        store = reopen(store, &path)?;
        clock.set(1);
        assert_eq!(store.snapshot_with_clock(&clock)?.clock_floor_millis(), 500);
        assert_eq!(
            store.query(intent.operation_id())?,
            AuthorityQueryResultV2::Found(Box::new(receipt))
        );

        let wrong = ReceiptLocatorV2::new(
            receipt.intent().operation_id(),
            receipt.resulting_authority_version() + 1,
        )?;
        assert_eq!(
            store.acknowledge_receipt(wrong),
            Err(AuthorityStoreErrorV2::ReceiptAcknowledgement(
                ReceiptAckErrorV2::ResultingVersionMismatch
            ))
        );
        assert_eq!(
            store.acknowledge_receipt(receipt.locator())?,
            ReceiptAckDispositionV2::Removed
        );
        store = reopen(store, &path)?;
        assert_eq!(
            store.query(intent.operation_id())?,
            AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: receipt.resulting_authority_version()
            }
        );
        assert_eq!(
            store.acknowledge_receipt(receipt.locator())?,
            ReceiptAckDispositionV2::AlreadyAbsent
        );
        Ok(())
    }

    #[test]
    fn clock_failure_and_receipt_bound_fail_closed_without_losing_floor() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("authority.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(1, 1, 1)?)?;
        let first = current_intent(
            &mut store,
            &clock,
            1,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let receipt = store.apply_with_clock(&clock, first)?;
        let fence = active_fence(&mut store, &clock)?;
        clock.set(700);
        let second = AuthorityIntentV2::new(
            operation(2, 2)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        assert_eq!(
            store.apply_with_clock(&clock, second),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ReceiptCapacityExceeded
            ))
        );
        store = reopen(store, &path)?;
        clock.set(1);
        assert_eq!(store.snapshot_with_clock(&clock)?.clock_floor_millis(), 700);

        clock.fail();
        assert_eq!(
            store.snapshot_with_clock(&clock),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ClockUnavailable
            ))
        );
        assert_eq!(
            store.apply_with_clock(&clock, first),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ClockUnavailable
            ))
        );
        assert_eq!(
            store.query(receipt.intent().operation_id())?,
            AuthorityQueryResultV2::Found(Box::new(receipt))
        );
        Ok(())
    }

    #[test]
    fn every_non_receipt_error_persists_its_observed_clock_floor() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("errors.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(1, 2, 2)?)?;
        let first = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        store.apply_with_clock(&clock, first)?;

        clock.set(200);
        let conflicting = AuthorityIntentV2::new(
            first.operation_id(),
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
            },
        )?;
        assert_eq!(
            store.apply_with_clock(&clock, conflicting),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::OperationConflict
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 200)?;

        clock.set(300);
        let stale = AuthorityIntentV2::new(
            operation(1, 2)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 1,
                instance_id: ProcessInstanceIdV2::from_bytes([13; 32])?,
            },
        )?;
        assert_eq!(
            store.apply_with_clock(&clock, stale),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::AuthorityVersionMismatch
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 300)?;

        clock.set(400);
        let full = AuthorityIntentV2::new(
            operation(2, 3)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::RenewLease {
                fence: active_fence(&mut store, &FakeClock::new(300))?,
            },
        )?;
        assert_eq!(
            store.apply_with_clock(&clock, full),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ReceiptCapacityExceeded
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 400)?;

        let before_unavailable = store.durable_image_for_test()?;
        clock.fail();
        assert_eq!(
            store.snapshot_with_clock(&clock),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ClockUnavailable
            ))
        );
        assert_eq!(
            store.apply_with_clock(&clock, first),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::ClockUnavailable
            ))
        );
        assert_eq!(store.durable_image_for_test()?, before_unavailable);

        let exhausted_path = directory.path().join("exhausted.redb");
        let exhausted_clock = FakeClock::new(100);
        let exhausted = provision_test_store(&exhausted_path, &exhausted_clock, limits(2, 2, 2)?)?;
        drop(exhausted);
        let database = Database::builder().create_file(open_file(&exhausted_path)?)?;
        let transaction = database.begin_write()?;
        {
            let mut meta = transaction.open_table(META_TABLE)?;
            meta.insert(META_AUTHORITY_VERSION, u64::MAX.to_be_bytes().as_slice())?;
        }
        transaction.commit()?;
        drop(database);
        let mut exhausted = AuthorityStoreV2::open_file(open_file(&exhausted_path)?)?;
        let exhausted_intent = AuthorityIntentV2::new(
            operation(u64::MAX, 4)?,
            u64::MAX,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([14; 32])?,
            },
        )?;
        exhausted_clock.set(500);
        assert_eq!(
            exhausted.apply_with_clock(&exhausted_clock, exhausted_intent),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::AuthorityVersionExhausted
            ))
        );
        let _ = reopen_and_assert_floor(exhausted, &exhausted_path, &exhausted_clock, 500)?;
        Ok(())
    }

    #[test]
    fn every_reservation_allocation_failure_persists_floor_without_partial_effect() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("allocations.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(16, 4, 4)?)?;
        let acquire_intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;

        clock.set(1_000);
        store.fail_next_reservation_for_test(ReservationPointV2::Receipt);
        assert_eq!(
            store.apply_with_clock(&clock, acquire_intent),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::AllocationFailed
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 1_000)?;
        assert_eq!(
            store.query(acquire_intent.operation_id())?,
            AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: 1
            }
        );

        clock.set(1_001);
        store.apply_with_clock(&clock, acquire_intent)?;
        let fence = active_fence(&mut store, &clock)?;
        let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
        let consume_intent = AuthorityIntentV2::new(
            operation(2, 2)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
        )?;
        clock.set(2_000);
        store.fail_next_reservation_for_test(ReservationPointV2::Capability);
        assert_eq!(
            store.apply_with_clock(&clock, consume_intent),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::AllocationFailed
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 2_000)?;
        let after_capability_failure = store.snapshot_with_clock(&FakeClock::new(2_000))?;
        assert_eq!(after_capability_failure.authority_version(), 2);
        assert_eq!(after_capability_failure.capability_count(), 0);

        clock.set(2_001);
        store.apply_with_clock(&clock, consume_intent)?;
        let key_id = AcceptedKeyIdV2::new(1, fence.generation(), [31; 32])?;
        let register_intent = AuthorityIntentV2::new(
            operation(3, 3)?,
            3,
            config(1, 1)?,
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            },
        )?;
        clock.set(3_000);
        store.fail_next_reservation_for_test(ReservationPointV2::Key);
        assert_eq!(
            store.apply_with_clock(&clock, register_intent),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::AllocationFailed
            ))
        );
        store = reopen_and_assert_floor(store, &path, &clock, 3_000)?;
        let after_key_failure = store.snapshot_with_clock(&FakeClock::new(3_000))?;
        assert_eq!(after_key_failure.authority_version(), 3);
        assert_eq!(after_key_failure.capability_count(), 1);
        assert_eq!(after_key_failure.retained_key_count(), 0);
        assert_eq!(
            store.query(register_intent.operation_id())?,
            AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: 3
            }
        );
        Ok(())
    }

    #[test]
    fn precommit_export_and_encode_allocations_commit_only_the_observed_floor() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("precommit-allocations.redb");
        let clock = FakeClock::new(100);
        let mut store = provision_test_store(&path, &clock, limits(16, 4, 4)?)?;

        let before_snapshot = store.durable_image_for_test()?;
        clock.set(500);
        store.fail_next_export_allocation_for_test();
        assert_eq!(
            store.snapshot_with_clock(&clock),
            Err(AuthorityStoreErrorV2::AllocationFailed)
        );
        let after_snapshot = store.durable_image_for_test()?;
        assert_only_clock_floor_changed(&before_snapshot, &after_snapshot, 500);
        store = reopen(store, &path)?;

        let acquire_intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let before_export = store.durable_image_for_test()?;
        clock.set(600);
        store.fail_next_export_allocation_for_test();
        assert_eq!(
            store.apply_with_clock(&clock, acquire_intent),
            Err(AuthorityStoreErrorV2::AllocationFailed)
        );
        let after_export = store.durable_image_for_test()?;
        assert_only_clock_floor_changed(&before_export, &after_export, 600);
        assert_eq!(
            store.query(acquire_intent.operation_id())?,
            AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: 1
            }
        );
        store = reopen(store, &path)?;
        assert_eq!(
            store
                .apply_with_clock(&clock, acquire_intent)?
                .disposition(),
            AuthorityDispositionV2::Applied
        );

        let fence = active_fence(&mut store, &clock)?;
        let renew_intent = AuthorityIntentV2::new(
            operation(2, 2)?,
            2,
            config(1, 1)?,
            AuthorityMutationV2::RenewLease { fence },
        )?;
        let before_encode = store.durable_image_for_test()?;
        clock.set(700);
        store.fail_next_encode_allocation_for_test();
        assert_eq!(
            store.apply_with_clock(&clock, renew_intent),
            Err(AuthorityStoreErrorV2::AllocationFailed)
        );
        let after_encode = store.durable_image_for_test()?;
        assert_only_clock_floor_changed(&before_encode, &after_encode, 700);
        assert_eq!(
            store.query(renew_intent.operation_id())?,
            AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: 2
            }
        );
        store = reopen(store, &path)?;
        assert_eq!(
            store.apply_with_clock(&clock, renew_intent)?.disposition(),
            AuthorityDispositionV2::Applied
        );
        Ok(())
    }

    #[test]
    fn acknowledgement_partial_writes_are_explicitly_aborted_or_poisoned() -> TestResult {
        let directory = tempfile::tempdir()?;
        let clock = FakeClock::new(100);

        let retry_path = directory.path().join("ack-abort-retry.redb");
        let mut retry = provision_test_store(&retry_path, &clock, limits(8, 4, 4)?)?;
        let retry_intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let retry_receipt = retry.apply_with_clock(&clock, retry_intent)?;
        let before_retry = retry.durable_image_for_test()?;
        retry.fail_next_persist_allocation_after_meta_for_test();
        assert_eq!(
            retry.acknowledge_receipt(retry_receipt.locator()),
            Err(AuthorityStoreErrorV2::AllocationFailed)
        );
        assert_eq!(retry.durable_image_for_test()?, before_retry);
        assert_eq!(
            retry.query(retry_intent.operation_id())?,
            AuthorityQueryResultV2::Found(Box::new(retry_receipt))
        );
        retry = reopen(retry, &retry_path)?;
        assert_eq!(
            retry.acknowledge_receipt(retry_receipt.locator())?,
            ReceiptAckDispositionV2::Removed
        );

        let poisoned_path = directory.path().join("ack-abort-reported-failure.redb");
        let mut poisoned = provision_test_store(&poisoned_path, &clock, limits(8, 4, 4)?)?;
        let poisoned_intent = AuthorityIntentV2::new(
            operation(1, 2)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
            },
        )?;
        let poisoned_receipt = poisoned.apply_with_clock(&clock, poisoned_intent)?;
        let before_poison = poisoned.durable_image_for_test()?;
        poisoned.fail_next_persist_allocation_after_meta_for_test();
        poisoned.report_next_abort_failure_for_test();
        assert_eq!(
            poisoned.acknowledge_receipt(poisoned_receipt.locator()),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(
            &mut poisoned,
            &clock,
            poisoned_intent,
            poisoned_receipt.locator(),
        );
        drop(poisoned);
        // Test-only forensic inspection of a quarantined path; this is not permission to serve it.
        let mut reopened_poisoned = AuthorityStoreV2::open_file(open_file(&poisoned_path)?)?;
        assert_eq!(reopened_poisoned.durable_image_for_test()?, before_poison);
        Ok(())
    }

    #[test]
    fn query_and_already_absent_never_hide_a_reported_abort_failure() -> TestResult {
        let directory = tempfile::tempdir()?;
        let clock = FakeClock::new(100);

        let query_path = directory.path().join("query-abort-failure.redb");
        let mut query = provision_test_store(&query_path, &clock, limits(8, 4, 4)?)?;
        let operation_id = operation(1, 1)?;
        query.report_next_abort_failure_for_test();
        assert_eq!(
            query.query(operation_id),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_eq!(
            query.query(operation_id),
            Err(AuthorityStoreErrorV2::Poisoned)
        );

        let absent_path = directory.path().join("absent-abort-failure.redb");
        let mut absent = provision_test_store(&absent_path, &clock, limits(8, 4, 4)?)?;
        let locator = ReceiptLocatorV2::new(operation(1, 2)?, 2)?;
        absent.report_next_abort_failure_for_test();
        assert_eq!(
            absent.acknowledge_receipt(locator),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_eq!(
            absent.acknowledge_receipt(locator),
            Err(AuthorityStoreErrorV2::Poisoned)
        );
        Ok(())
    }

    #[test]
    fn floor_only_commit_failures_and_internal_invariants_permanently_poison() -> TestResult {
        let directory = tempfile::tempdir()?;

        let abort_path = directory
            .path()
            .join("business-abort-reported-failure.redb");
        let abort_clock = FakeClock::new(100);
        let mut abort = provision_test_store(&abort_path, &abort_clock, limits(8, 4, 4)?)?;
        let abort_intent = AuthorityIntentV2::new(
            operation(1, 9)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([19; 32])?,
            },
        )?;
        let abort_locator = ReceiptLocatorV2::new(abort_intent.operation_id(), 2)?;
        let abort_before = abort.durable_image_for_test()?;
        abort_clock.set(450);
        abort.fail_next_encode_allocation_for_test();
        abort.report_next_abort_failure_for_test();
        assert_eq!(
            abort.apply_with_clock(&abort_clock, abort_intent),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(&mut abort, &abort_clock, abort_intent, abort_locator);
        drop(abort);
        // Every reopen below is test-only forensic old-or-new inspection, never service recovery.
        let mut reopened_abort = AuthorityStoreV2::open_file(open_file(&abort_path)?)?;
        assert_eq!(reopened_abort.durable_image_for_test()?, abort_before);

        let precommit_path = directory.path().join("floor-precommit.redb");
        let precommit_clock = FakeClock::new(100);
        let mut precommit =
            provision_test_store(&precommit_path, &precommit_clock, limits(8, 4, 4)?)?;
        let precommit_intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let precommit_locator = ReceiptLocatorV2::new(precommit_intent.operation_id(), 2)?;
        let precommit_before = precommit.durable_image_for_test()?;
        precommit_clock.set(500);
        precommit.fail_next_export_allocation_for_test();
        precommit.fail_before_next_commit_for_test();
        assert_eq!(
            precommit.apply_with_clock(&precommit_clock, precommit_intent),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(
            &mut precommit,
            &precommit_clock,
            precommit_intent,
            precommit_locator,
        );
        drop(precommit);
        let mut reopened_precommit = AuthorityStoreV2::open_file(open_file(&precommit_path)?)?;
        let precommit_after = reopened_precommit.durable_image_for_test()?;
        assert_only_clock_floor_changed(
            &precommit_before,
            &precommit_after,
            precommit_before.meta.clock_floor_millis,
        );

        let durable_path = directory.path().join("floor-post-durable.redb");
        let durable_clock = FakeClock::new(100);
        let mut durable = provision_test_store(&durable_path, &durable_clock, limits(8, 4, 4)?)?;
        let durable_intent = AuthorityIntentV2::new(
            operation(1, 2)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
            },
        )?;
        let durable_locator = ReceiptLocatorV2::new(durable_intent.operation_id(), 2)?;
        let durable_before = durable.durable_image_for_test()?;
        durable_clock.set(600);
        durable.fail_next_export_allocation_for_test();
        durable.fail_after_next_commit_for_test();
        assert_eq!(
            durable.apply_with_clock(&durable_clock, durable_intent),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(
            &mut durable,
            &durable_clock,
            durable_intent,
            durable_locator,
        );
        drop(durable);
        let mut reopened_durable = AuthorityStoreV2::open_file(open_file(&durable_path)?)?;
        let durable_after = reopened_durable.durable_image_for_test()?;
        assert_only_clock_floor_changed(&durable_before, &durable_after, 600);

        let invariant_path = directory.path().join("internal-invariant.redb");
        let invariant_clock = FakeClock::new(100);
        let mut invariant =
            provision_test_store(&invariant_path, &invariant_clock, limits(8, 4, 4)?)?;
        let invariant_intent = AuthorityIntentV2::new(
            operation(1, 3)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([13; 32])?,
            },
        )?;
        let invariant_locator = ReceiptLocatorV2::new(invariant_intent.operation_id(), 2)?;
        let invariant_before = invariant.durable_image_for_test()?;
        invariant_clock.set(700);
        invariant.fail_next_internal_invariant_for_test();
        assert_eq!(
            invariant.apply_with_clock(&invariant_clock, invariant_intent),
            Err(AuthorityStoreErrorV2::Authority(
                AuthorityErrorV2::InternalInvariant
            ))
        );
        assert_all_operations_poisoned(
            &mut invariant,
            &invariant_clock,
            invariant_intent,
            invariant_locator,
        );
        drop(invariant);
        let mut reopened_invariant = AuthorityStoreV2::open_file(open_file(&invariant_path)?)?;
        let invariant_after = reopened_invariant.durable_image_for_test()?;
        assert_only_clock_floor_changed(&invariant_before, &invariant_after, 700);
        Ok(())
    }

    #[test]
    fn uncertain_commit_quarantines_path_and_forensics_observe_old_or_new_images() -> TestResult {
        let directory = tempfile::tempdir()?;
        let clock = FakeClock::new(100);
        let precommit_path = directory.path().join("precommit.redb");
        let mut precommit = provision_test_store(&precommit_path, &clock, limits(8, 4, 4)?)?;
        let precommit_intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let precommit_locator = ReceiptLocatorV2::new(precommit_intent.operation_id(), 2)?;
        precommit.fail_before_next_commit_for_test();
        assert_eq!(
            precommit.apply_with_clock(&clock, precommit_intent),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(&mut precommit, &clock, precommit_intent, precommit_locator);
        drop(precommit);
        // Test-only forensic inspection: Stage 2A1 cannot clear this path's quarantine.
        let mut reopened_precommit = AuthorityStoreV2::open_file(open_file(&precommit_path)?)?;
        let precommit_image = reopened_precommit.durable_image_for_test()?;
        assert_eq!(precommit_image.meta.authority_version, 1);
        assert!(precommit_image.receipts.is_empty());

        let durable_path = directory.path().join("durable.redb");
        let mut durable = provision_test_store(&durable_path, &clock, limits(8, 4, 4)?)?;
        let durable_intent = AuthorityIntentV2::new(
            operation(1, 2)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([12; 32])?,
            },
        )?;
        let durable_locator = ReceiptLocatorV2::new(durable_intent.operation_id(), 2)?;
        durable.fail_after_next_commit_for_test();
        assert_eq!(
            durable.apply_with_clock(&clock, durable_intent),
            Err(AuthorityStoreErrorV2::CommitUncertain)
        );
        assert_all_operations_poisoned(&mut durable, &clock, durable_intent, durable_locator);
        drop(durable);
        // Test-only forensic inspection: observing the new image is not safe reopen-and-serve.
        let mut reopened_durable = AuthorityStoreV2::open_file(open_file(&durable_path)?)?;
        let durable_image = reopened_durable.durable_image_for_test()?;
        let receipt = durable_image
            .receipts
            .iter()
            .find_map(|(operation_id, receipt)| {
                (*operation_id == durable_intent.operation_id()).then_some(*receipt)
            })
            .ok_or("forensic new image did not contain committed receipt")?;
        assert_eq!(receipt.intent(), durable_intent);
        assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
        assert_eq!(durable_image.meta.authority_version, 2);
        Ok(())
    }

    #[test]
    fn v1_missing_and_corrupt_normalized_state_never_open_as_v2() -> TestResult {
        let directory = tempfile::tempdir()?;
        let missing_path = directory.path().join("missing.redb");
        assert!(matches!(
            AuthorityStoreV2::open(&missing_path),
            Err(AuthorityStoreErrorV2::InsecureOrMissingStore)
        ));

        let v1_path = directory.path().join("v1.redb");
        let database = Database::builder().create_file(create_file(&v1_path)?)?;
        let transaction = database.begin_write()?;
        let v1_meta: TableDefinition<&str, &[u8]> = TableDefinition::new("authority_meta_v1");
        {
            let mut table = transaction.open_table(v1_meta)?;
            table.insert("schema", [0u8, 1].as_slice())?;
        }
        transaction.commit()?;
        drop(database);
        match AuthorityStoreV2::open_file(open_file(&v1_path)?) {
            Err(AuthorityStoreErrorV2::UnsupportedSchema) => {}
            Err(error) => return Err(format!("unexpected V1 rejection: {error:?}").into()),
            Ok(_) => return Err("V1 database opened as V2".into()),
        }
        assert!(matches!(
            AuthorityStoreV2::provision(
                &v1_path,
                state_head(1, 1, 1, 1, 1)?,
                config(1, 1)?,
                limits(8, 4, 4)?,
            ),
            Err(AuthorityStoreErrorV2::InsecureOrMissingStore)
        ));

        let empty_path = directory.path().join("empty.redb");
        drop(create_file(&empty_path)?);
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&empty_path)?),
            Err(AuthorityStoreErrorV2::UnsupportedSchema)
        ));
        assert_eq!(std::fs::metadata(&empty_path)?.len(), 0);

        let corrupt_path = directory.path().join("corrupt.redb");
        let clock = FakeClock::new(100);
        let store = provision_test_store(&corrupt_path, &clock, limits(8, 4, 4)?)?;
        drop(store);
        let database = Database::builder().create_file(open_file(&corrupt_path)?)?;
        let transaction = database.begin_write()?;
        {
            let mut meta = transaction.open_table(META_TABLE)?;
            meta.insert(META_CLOCK_FLOOR, [1u8; 7].as_slice())?;
        }
        transaction.commit()?;
        drop(database);
        match AuthorityStoreV2::open_file(open_file(&corrupt_path)?) {
            Err(AuthorityStoreErrorV2::CorruptStore) => {}
            Err(error) => return Err(format!("unexpected corruption result: {error:?}").into()),
            Ok(_) => return Err("corrupt database opened".into()),
        }

        let extra_path = directory.path().join("extra.redb");
        let store = provision_test_store(&extra_path, &clock, limits(8, 4, 4)?)?;
        drop(store);
        let database = Database::builder().create_file(open_file(&extra_path)?)?;
        let transaction = database.begin_write()?;
        let extra: TableDefinition<&[u8], &[u8]> = TableDefinition::new("unexpected_table");
        transaction.open_table(extra)?;
        transaction.commit()?;
        drop(database);
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&extra_path)?),
            Err(AuthorityStoreErrorV2::CorruptStore)
        ));

        let multimap_path = directory.path().join("multimap.redb");
        let store = provision_test_store(&multimap_path, &clock, limits(8, 4, 4)?)?;
        drop(store);
        let database = Database::builder().create_file(open_file(&multimap_path)?)?;
        let transaction = database.begin_write()?;
        let multimap: redb::MultimapTableDefinition<&[u8], &[u8]> =
            redb::MultimapTableDefinition::new("unexpected_multimap");
        transaction.open_multimap_table(multimap)?;
        transaction.commit()?;
        drop(database);
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&multimap_path)?),
            Err(AuthorityStoreErrorV2::CorruptStore)
        ));

        let missing_path = directory.path().join("missing-table.redb");
        let store = provision_test_store(&missing_path, &clock, limits(8, 4, 4)?)?;
        drop(store);
        let database = Database::builder().create_file(open_file(&missing_path)?)?;
        let transaction = database.begin_write()?;
        assert!(transaction.delete_table(RECEIPT_TABLE)?);
        transaction.commit()?;
        drop(database);
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&missing_path)?),
            Err(AuthorityStoreErrorV2::CorruptStore)
        ));
        Ok(())
    }

    #[test]
    fn full_repair_requirement_is_rejected_without_mutating_the_store() -> TestResult {
        const REDDB_GOD_BYTE_OFFSET: u64 = 9;
        const REDDB_RECOVERY_REQUIRED: u8 = 2;
        const REDDB_TWO_PHASE_COMMIT: u8 = 4;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("repair-required.redb");
        let clock = FakeClock::new(100);
        let store = provision_test_store(&path, &clock, limits(8, 4, 4)?)?;
        drop(store);

        // redb 2.6's byte after its nine-byte magic carries these recovery flags. Marking an
        // otherwise valid database as unclean without two-phase allocator state deterministically
        // selects the full-repair callback path.
        let mut file = open_file(&path)?;
        file.seek(SeekFrom::Start(REDDB_GOD_BYTE_OFFSET))?;
        let mut flags = [0u8; 1];
        file.read_exact(&mut flags)?;
        flags[0] |= REDDB_RECOVERY_REQUIRED;
        flags[0] &= !REDDB_TWO_PHASE_COMMIT;
        file.seek(SeekFrom::Start(REDDB_GOD_BYTE_OFFSET))?;
        file.write_all(&flags)?;
        file.sync_all()?;
        drop(file);

        let before_open = std::fs::read(&path)?;
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&path)?),
            Err(AuthorityStoreErrorV2::CorruptStore)
        ));
        assert_eq!(std::fs::read(&path)?, before_open);
        Ok(())
    }

    #[test]
    fn database_lock_rejects_second_open_and_epoch_is_fresh() -> TestResult {
        let directory = tempfile::tempdir()?;
        let first_path = directory.path().join("first.redb");
        let second_path = directory.path().join("second.redb");
        let clock = FakeClock::new(100);
        let first = provision_test_store(&first_path, &clock, limits(8, 4, 4)?)?;
        assert!(matches!(
            AuthorityStoreV2::open_file(open_file(&first_path)?),
            Err(AuthorityStoreErrorV2::AlreadyOpen)
        ));
        assert!(matches!(
            AuthorityStoreV2::provision_file(
                open_file(&first_path)?,
                state_head(1, 1, 1, 1, 1)?,
                config(1, 1)?,
                limits(8, 4, 4)?,
                &clock,
            ),
            Err(AuthorityStoreErrorV2::AlreadyOpen)
        ));
        let second = provision_test_store(&second_path, &clock, limits(8, 4, 4)?)?;
        assert_ne!(first.authority_epoch(), second.authority_epoch());
        Ok(())
    }

    #[test]
    fn closed_store_copy_can_open_and_is_explicitly_not_clone_defense() -> TestResult {
        let directory = tempfile::tempdir()?;
        let original_path = directory.path().join("original.redb");
        let copied_path = directory.path().join("copied.redb");
        let clock = FakeClock::new(100);
        let mut original = provision_test_store(&original_path, &clock, limits(8, 4, 4)?)?;
        let _ = acquire(&mut original, &clock, 1, 11)?;
        let epoch = original.authority_epoch();
        let image = original.durable_image_for_test()?;
        drop(original);

        std::fs::copy(&original_path, &copied_path)?;
        let mut copied = AuthorityStoreV2::open_file(open_file(&copied_path)?)?;
        assert_eq!(copied.authority_epoch(), epoch);
        assert_eq!(copied.durable_image_for_test()?, image);
        Ok(())
    }

    #[test]
    fn codec_rejects_trailing_unknown_and_inconsistent_records() -> TestResult {
        assert_eq!(
            map_codec(CodecError::Allocation),
            AuthorityStoreErrorV2::AllocationFailed
        );
        let clock = FakeClock::new(100);
        let state = AuthorityStateV2::provision(
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
            &clock,
        )?;
        let mut image = state.durable_image().map_err(map_restore)?;
        image.meta.authority_version = 0;
        match AuthorityStateV2::restore(&image) {
            Err(AuthorityRestoreErrorV2::Invalid) => {}
            Err(error) => return Err(format!("unexpected restore result: {error:?}").into()),
            Ok(_) => return Err("invalid authority image restored".into()),
        }

        let mut linked = AuthorityStateV2::provision(
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 2, 2)?,
            &clock,
        )?;
        let acquire = AuthorityIntentV2::new(
            operation(1, 10)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        linked.apply(&clock, acquire)?;
        let fence = linked
            .snapshot(&clock)?
            .active_lease()
            .map(InstanceLeaseV2::fence)
            .ok_or("expected linked lease")?;
        let capability_id = CapabilityIdV2::from_bytes([21; 32])?;
        linked.apply(
            &clock,
            AuthorityIntentV2::new(
                operation(2, 11)?,
                2,
                config(1, 1)?,
                AuthorityMutationV2::ConsumeCapability {
                    fence,
                    capability_id,
                },
            )?,
        )?;
        linked.apply(
            &clock,
            AuthorityIntentV2::new(
                operation(3, 12)?,
                3,
                config(1, 1)?,
                AuthorityMutationV2::RegisterKey {
                    fence,
                    capability_id,
                    key_id: AcceptedKeyIdV2::new(1, 1, [31; 32])?,
                },
            )?,
        )?;
        let mut broken_link = linked.durable_image().map_err(map_restore)?;
        let key = broken_link
            .keys
            .first_mut()
            .ok_or("expected linked key record")?;
        key.1.capability_id = CapabilityIdV2::from_bytes([99; 32])?;
        assert!(matches!(
            AuthorityStateV2::restore(&broken_link),
            Err(AuthorityRestoreErrorV2::Invalid)
        ));

        let mut bounded = AuthorityStateV2::provision(
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 1, 1)?,
            &clock,
        )?;
        bounded.apply(&clock, acquire)?;
        bounded.apply(
            &clock,
            AuthorityIntentV2::new(
                operation(2, 13)?,
                2,
                config(1, 1)?,
                AuthorityMutationV2::ConsumeCapability {
                    fence,
                    capability_id,
                },
            )?,
        )?;
        let mut over_capacity = bounded.durable_image().map_err(map_restore)?;
        let record = over_capacity
            .capabilities
            .first()
            .map(|(_, record)| *record)
            .ok_or("expected bounded capability")?;
        over_capacity
            .capabilities
            .try_reserve_exact(1)
            .map_err(|_| AuthorityStoreErrorV2::AllocationFailed)?;
        over_capacity
            .capabilities
            .push((CapabilityIdV2::from_bytes([22; 32])?, record));
        assert!(matches!(
            AuthorityStateV2::restore(&over_capacity),
            Err(AuthorityRestoreErrorV2::Invalid)
        ));

        let intent = AuthorityIntentV2::new(
            operation(1, 1)?,
            1,
            config(1, 1)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([11; 32])?,
            },
        )?;
        let mut state = AuthorityStateV2::provision(
            state_head(1, 1, 1, 1, 1)?,
            config(1, 1)?,
            limits(8, 4, 4)?,
            &clock,
        )?;
        let receipt = state.apply(&clock, intent)?;
        let encoded = encode_receipt(receipt)?;
        assert_eq!(decode_receipt(&encoded)?, receipt);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(decode_receipt(&trailing), Err(AuthorityCodecError::Invalid));
        let mut unknown_rejection = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut unknown_rejection, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION)
            .map_err(map_codec)?;
        encode_intent(&mut unknown_rejection, intent)?;
        unknown_rejection.byte(2).map_err(map_codec)?;
        unknown_rejection.byte(255).map_err(map_codec)?;
        unknown_rejection.u64(2).map_err(map_codec)?;
        assert_eq!(
            decode_receipt(&unknown_rejection.finish()),
            Err(AuthorityCodecError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn file_helpers_are_cross_platform_test_only() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path: PathBuf = directory.path().join("portable.redb");
        let clock = FakeClock::new(100);
        let store = provision_test_store(&path, &clock, limits(8, 4, 4)?)?;
        let epoch = store.authority_epoch();
        let reopened = reopen(store, &path)?;
        assert_eq!(reopened.authority_epoch(), epoch);
        Ok(())
    }
}
