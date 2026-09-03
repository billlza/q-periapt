//! Durable local intent journal and authenticated migration-state replay.

use core::fmt;
use std::path::Path;

use q_periapt_backends::{MlDsa65, ML_DSA_65_VK_LEN};
use q_periapt_migration::{
    CommittedMigrationStateV1, MigrationAuthorityKeyId, MigrationStateMachineV1,
    PendingMigrationCommitKind, PendingMigrationCommitV1, SignedMigrationResetV1,
    SignedMigrationStateV1, StateRevisionV1, UninitializedMigrationStateV1,
};
use redb::{Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::authority::OperationIdV2;
use crate::authority_codec::{decode_operation_id, encode_operation_id};
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};
use crate::filesystem::{open_private_file, provision_private_file, refuse_unclean_foreign_redb};
use crate::types::{
    FenceToken, OperationId, SessionId, StateAdvance, StateHead, StateRevision, TransitionKind,
};
use crate::witness::{WitnessDisposition, WitnessIntent, WitnessReceipt};

const REPOSITORY_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-REPOSITORY/v1";
const REPOSITORY_SCHEMA_VERSION: u16 = 1;
const REPOSITORY_SCHEMA: [u8; 2] = REPOSITORY_SCHEMA_VERSION.to_be_bytes();
const MAX_HISTORY_ENTRIES: u64 = 4096;
const MAX_DURABLE_SESSIONS: u64 = 1024;
const MAX_USED_CAPABILITIES: u64 = 4096;
/// Bound on the lease-intent journal: one row per lease operation this
/// instance has journaled and not yet settled with the authority.
///
/// The service's in-memory acknowledgement queue has the same bound, and the
/// journal is what makes that queue safe to lose: every queued receipt has a
/// row here, so the journal always fills first and refuses before the queue
/// could overflow.
pub(crate) const MAX_JOURNALED_LEASE_INTENTS: u64 = 64;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_meta_v1");
const HISTORY_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("agent_state_history_v1");
const SESSION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("agent_session_reservations_v1");
const CAPABILITY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("agent_used_capabilities_v1");
/// Lease intents journaled before dispatch, so that the acknowledgement each
/// receipt is owed survives a crash. Key: the canonical operation id bytes;
/// value: the one-byte `Prepared` tag.
///
/// Additive: a store provisioned before this table existed opens without it,
/// and the first journal write creates it.
const ACK_JOURNAL_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("agent_authority_ack_journal_v1");
const ACK_JOURNAL_PREPARED: [u8; 1] = [1];
const META_SCHEMA: &str = "schema";
const META_HEAD: &str = "head";
const META_PENDING: &str = "pending_transition";

/// Independently provisioned authority roots used to replay every state certificate.
#[derive(Clone, Eq, PartialEq)]
pub struct MigrationTrustRoots {
    authority_key_id: MigrationAuthorityKeyId,
    authority_verification_key: [u8; ML_DSA_65_VK_LEN],
    recovery_key_id: MigrationAuthorityKeyId,
    recovery_verification_key: [u8; ML_DSA_65_VK_LEN],
}

impl fmt::Debug for MigrationTrustRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationTrustRoots([redacted])")
    }
}

impl MigrationTrustRoots {
    /// Pin the sole accepted migration authority and the separate reset authority.
    pub fn new(
        authority_key_id: MigrationAuthorityKeyId,
        authority_verification_key: [u8; ML_DSA_65_VK_LEN],
        recovery_key_id: MigrationAuthorityKeyId,
        recovery_verification_key: [u8; ML_DSA_65_VK_LEN],
    ) -> Result<Self, RepositoryError> {
        if authority_key_id.as_bytes().iter().all(|byte| *byte == 0)
            || recovery_key_id.as_bytes().iter().all(|byte| *byte == 0)
            || authority_verification_key.iter().all(|byte| *byte == 0)
            || recovery_verification_key.iter().all(|byte| *byte == 0)
            || authority_key_id == recovery_key_id
            || authority_verification_key == recovery_verification_key
        {
            return Err(RepositoryError::UnprovisionedAuthority);
        }
        Ok(Self {
            authority_key_id,
            authority_verification_key,
            recovery_key_id,
            recovery_verification_key,
        })
    }
}

/// Local persistence, journal, authentication, or invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RepositoryError {
    /// The database path was missing, a symlink, or outside an owner-only directory.
    InsecureOrMissingStore,
    /// The database was corrupt (a corrupted two-phase primary included), left
    /// unclean by a writer that did not commit two-phase, incomplete, or had an
    /// unknown schema.
    CorruptStore,
    /// A signed state/reset envelope was malformed, non-canonical, or unauthenticated.
    InvalidCertificate,
    /// A reset attempted to install an authority not present in this fixed root set.
    UnprovisionedAuthority,
    /// History was empty, non-contiguous, duplicated, forked, or inconsistent with the head.
    InvalidHistory,
    /// An unresolved durable transition already exists; only its exact operation may continue.
    TransitionPending,
    /// No durable transition exists for the requested reconciliation or commit.
    NoPendingTransition,
    /// A witness receipt was not the exact authenticated result for the durable intent.
    WitnessMismatch,
    /// The local state/fence changed since an operation or session was reserved.
    StaleReservation,
    /// A bounded durable table reached its explicit capacity.
    CapacityExceeded,
    /// A session reservation did not exist.
    SessionNotFound,
    /// A signed capability session identifier was already consumed in this state.
    CapabilityReplay,
    /// Cryptographic randomness was unavailable.
    EntropyUnavailable,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InsecureOrMissingStore => "repository path missing or not owner protected",
            Self::CorruptStore => "repository is corrupt, incomplete, or has an unknown schema",
            Self::InvalidCertificate => "migration certificate invalid or non-canonical",
            Self::UnprovisionedAuthority => "migration reset selected an unprovisioned authority",
            Self::InvalidHistory => "migration certificate journal is incomplete or forked",
            Self::TransitionPending => "an exact durable transition remains unresolved",
            Self::NoPendingTransition => "no durable transition is pending",
            Self::WitnessMismatch => "witness result does not match the durable transition",
            Self::StaleReservation => "state revision or writer fence changed",
            Self::CapacityExceeded => "repository capacity exceeded",
            Self::SessionNotFound => "session reservation not found",
            Self::CapabilityReplay => "signed capability session was already consumed",
            Self::EntropyUnavailable => "cryptographic randomness unavailable",
        })
    }
}

impl std::error::Error for RepositoryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum JournalKind {
    Genesis = 1,
    Advance = 2,
    Reset = 3,
}

impl JournalKind {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Genesis),
            2 => Some(Self::Advance),
            3 => Some(Self::Reset),
            _ => None,
        }
    }
}

struct PreparedTransition {
    token: PendingMigrationCommitV1,
    intent: WitnessIntent,
    kind: JournalKind,
    envelope: Vec<u8>,
}

/// Transactional local state. All methods require exclusive access from the service linearizer.
pub struct StateRepository {
    database: Database,
    machine: MigrationStateMachineV1,
    roots: MigrationTrustRoots,
    pending: Option<PreparedTransition>,
    restart_rejections: u64,
    /// Test-only: sleep this long after the next durable session reserve or
    /// release commits, standing in for a slow fsync. The lease-coverage check
    /// that runs after those writes is only meaningful if the write can
    /// outlive the coverage, and nothing in a test can make a real fsync do
    /// that on demand.
    #[cfg(all(test, unix))]
    delay_after_next_durable_write: std::sync::Mutex<Option<std::time::Duration>>,
    /// Test-only: sleep this long after every session cancellation commits,
    /// standing in for a store whose fsyncs are slow. The stop erases one
    /// session per durable commit and no deadline bounds that, which a test
    /// can only exercise if the erase can be made to outlast a budget.
    #[cfg(all(test, unix))]
    delay_after_each_session_cancel: std::sync::Mutex<Option<std::time::Duration>>,
    /// Test-only: fail the next lease-journal write the way a corrupt store
    /// would, before anything is committed, so a test can see what a lease
    /// operation does when its intent cannot be journaled for storage reasons.
    #[cfg(all(test, unix))]
    fail_next_lease_journal_write: std::sync::Mutex<bool>,
}

impl fmt::Debug for StateRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateRepository([redacted])")
    }
}

impl StateRepository {
    /// Explicitly provision a new store from an authenticated canonical genesis certificate.
    ///
    /// No missing-store or implicit-genesis path exists. The returned head must be
    /// independently provisioned into the mandatory external witness before serving.
    pub fn provision_new(
        path: &Path,
        canonical_genesis: &[u8],
        roots: MigrationTrustRoots,
    ) -> Result<(Self, StateHead), RepositoryError> {
        let certificate = decode_canonical_state(canonical_genesis)?;
        if certificate.state().authority_key_id() != roots.authority_key_id {
            return Err(RepositoryError::UnprovisionedAuthority);
        }
        let pending_genesis = UninitializedMigrationStateV1
            .verify_genesis(
                &certificate,
                &MlDsa65,
                &roots.authority_verification_key,
                roots.authority_key_id,
            )
            .map_err(|_| RepositoryError::InvalidCertificate)?;
        let machine = pending_genesis
            .commit()
            .map_err(|_| RepositoryError::InvalidCertificate)?;
        let head = StateHead::new(
            project_revision(machine.current_revision())?,
            FenceToken::generate().map_err(|_| RepositoryError::EntropyUnavailable)?,
        );
        provision_private_file(
            path,
            |_| RepositoryError::InsecureOrMissingStore,
            |file| {
                let database = Database::builder()
                    .create_file(file)
                    .map_err(|_| RepositoryError::CorruptStore)?;
                let transaction = durable_write(&database)?;
                {
                    let mut meta = transaction
                        .open_table(META_TABLE)
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    let mut history = transaction
                        .open_table(HISTORY_TABLE)
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    transaction
                        .open_table(SESSION_TABLE)
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    transaction
                        .open_table(CAPABILITY_TABLE)
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    transaction
                        .open_table(ACK_JOURNAL_TABLE)
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    meta.insert(META_SCHEMA, REPOSITORY_SCHEMA.as_slice())
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    meta.insert(META_HEAD, head.to_bytes().as_slice())
                        .map_err(|_| RepositoryError::CorruptStore)?;
                    let entry = encode_journal_entry(JournalKind::Genesis, canonical_genesis)?;
                    history
                        .insert(&1, entry.as_slice())
                        .map_err(|_| RepositoryError::CorruptStore)?;
                }
                transaction
                    .commit()
                    .map_err(|_| RepositoryError::CorruptStore)?;
                Ok((
                    Self {
                        database,
                        machine,
                        roots,
                        pending: None,
                        restart_rejections: 0,
                        #[cfg(all(test, unix))]
                        delay_after_next_durable_write: std::sync::Mutex::new(None),
                        #[cfg(all(test, unix))]
                        delay_after_each_session_cancel: std::sync::Mutex::new(None),
                        #[cfg(all(test, unix))]
                        fail_next_lease_journal_write: std::sync::Mutex::new(false),
                    },
                    head,
                ))
            },
        )
    }

    /// Open and fully replay an existing store. Missing/corrupt state never becomes genesis.
    ///
    /// redb is allowed to finish crash recovery first. Every commit here is
    /// two-phase, so after an unclean shutdown that recovery only reconstructs
    /// the free-page allocator from the committed tree; a corrupted two-phase
    /// primary is refused outright rather than rolled back, and committed data
    /// is never altered. The canonical history is then decoded and reverified
    /// in full below, and the head is compared against the witness on every
    /// agent start, so what this store replays is what was committed.
    pub fn open_existing(path: &Path, roots: MigrationTrustRoots) -> Result<Self, RepositoryError> {
        let file =
            open_private_file(path, false).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
        refuse_unclean_foreign_redb(&file).map_err(|_| RepositoryError::CorruptStore)?;
        let mut database = Database::builder()
            .create_file(file)
            .map_err(|_| RepositoryError::CorruptStore)?;
        if !database
            .check_integrity()
            .map_err(|_| RepositoryError::CorruptStore)?
        {
            return Err(RepositoryError::CorruptStore);
        }
        verify_schema(&database)?;
        let machine = replay_history(&database, &roots)?;
        let durable_head = read_head(&database)?;
        if project_revision(machine.current_revision())? != durable_head.revision() {
            return Err(RepositoryError::InvalidHistory);
        }
        let pending = read_pending(&database)?
            .map(|record| reconstruct_pending(&machine, &roots, record))
            .transpose()?;
        if matches!(pending.as_ref(), Some(value) if value.intent.expected() != durable_head) {
            return Err(RepositoryError::InvalidHistory);
        }
        validate_used_capabilities(&database, durable_head)?;
        validate_ack_journal(&database)?;
        let restart_rejections = reject_restart_sessions(&database)?;
        Ok(Self {
            database,
            machine,
            roots,
            pending,
            restart_rejections,
            #[cfg(all(test, unix))]
            delay_after_next_durable_write: std::sync::Mutex::new(None),
            #[cfg(all(test, unix))]
            delay_after_each_session_cancel: std::sync::Mutex::new(None),
            #[cfg(all(test, unix))]
            fail_next_lease_journal_write: std::sync::Mutex::new(false),
        })
    }

    /// Test-only: make the next durable session reserve or release take this
    /// long after it commits, the way a slow fsync would.
    #[cfg(all(test, unix))]
    pub(crate) fn delay_after_next_durable_write_for_test(&self, delay: std::time::Duration) {
        *self
            .delay_after_next_durable_write
            .lock()
            .expect("repository test hook poisoned") = Some(delay);
    }

    /// Test-only: whether the delay above is still armed. It is taken only by
    /// a durable session write that actually committed, so this doubles as
    /// "no durable session reserve or release has run since it was armed".
    #[cfg(all(test, unix))]
    pub(crate) fn durable_write_delay_armed_for_test(&self) -> bool {
        self.delay_after_next_durable_write
            .lock()
            .expect("repository test hook poisoned")
            .is_some()
    }

    /// Test-only: make every session cancellation take this long after it
    /// commits, the way a store with slow fsyncs would.
    #[cfg(all(test, unix))]
    pub(crate) fn delay_after_each_session_cancel_for_test(&self, delay: std::time::Duration) {
        *self
            .delay_after_each_session_cancel
            .lock()
            .expect("repository test hook poisoned") = Some(delay);
    }

    /// Test-only: fail the next lease-journal write as a corrupt store would.
    #[cfg(all(test, unix))]
    pub(crate) fn fail_next_lease_journal_write_for_test(&self) {
        *self
            .fail_next_lease_journal_write
            .lock()
            .expect("repository test hook poisoned") = true;
    }

    #[cfg(all(test, unix))]
    fn refuse_lease_journal_write_if_armed_for_test(&self) -> Result<(), RepositoryError> {
        let armed = std::mem::take(
            &mut *self
                .fail_next_lease_journal_write
                .lock()
                .expect("repository test hook poisoned"),
        );
        if armed {
            return Err(RepositoryError::CorruptStore);
        }
        Ok(())
    }

    #[cfg(all(test, unix))]
    fn sleep_after_durable_write_for_test(&self) {
        let pending = self
            .delay_after_next_durable_write
            .lock()
            .expect("repository test hook poisoned")
            .take();
        if let Some(delay) = pending {
            std::thread::sleep(delay);
        }
    }

    #[cfg(all(test, unix))]
    fn sleep_after_session_cancel_for_test(&self) {
        let pending = *self
            .delay_after_each_session_cancel
            .lock()
            .expect("repository test hook poisoned");
        if let Some(delay) = pending {
            std::thread::sleep(delay);
        }
    }

    /// Test-only: number of durable session reservations currently held.
    #[cfg(all(test, unix))]
    pub(crate) fn durable_session_count_for_test(&self) -> Result<u64, RepositoryError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| RepositoryError::CorruptStore)?;
        let sessions = transaction
            .open_table(SESSION_TABLE)
            .map_err(|_| RepositoryError::CorruptStore)?;
        sessions.len().map_err(|_| RepositoryError::CorruptStore)
    }

    /// Return the exact durable head.
    pub fn head(&self) -> Result<StateHead, RepositoryError> {
        read_head(&self.database)
    }

    /// Return the re-authenticated committed migration state.
    #[must_use]
    pub const fn committed_state(&self) -> CommittedMigrationStateV1 {
        self.machine.current()
    }

    pub(crate) const fn state_machine(&self) -> &MigrationStateMachineV1 {
        &self.machine
    }

    /// Number of secretless durable reservations explicitly rejected during this restart.
    #[must_use]
    pub const fn restart_rejections(&self) -> u64 {
        self.restart_rejections
    }

    /// Return the sole operation that may continue after an uncertain witness outcome.
    #[must_use]
    pub fn pending_intent(&self) -> Option<WitnessIntent> {
        self.pending.as_ref().map(|pending| pending.intent)
    }

    pub(crate) fn pending_next_state(&self) -> Option<q_periapt_migration::MigrationStateV1> {
        self.pending
            .as_ref()
            .map(|pending| pending.token.next_state())
    }

    /// Authenticate and durably reserve one normal state certificate before witness CAS.
    pub fn prepare_advance(
        &mut self,
        canonical_certificate: &[u8],
    ) -> Result<WitnessIntent, RepositoryError> {
        if self.pending.is_some() {
            return Err(RepositoryError::TransitionPending);
        }
        let certificate = decode_canonical_state(canonical_certificate)?;
        if certificate.state().authority_key_id() != self.roots.authority_key_id {
            return Err(RepositoryError::UnprovisionedAuthority);
        }
        let token = self
            .machine
            .prepare_advance(
                &certificate,
                &MlDsa65,
                &self.roots.authority_verification_key,
            )
            .map_err(|_| RepositoryError::InvalidCertificate)?;
        self.persist_prepared(JournalKind::Advance, canonical_certificate, token)
    }

    /// Authenticate and durably reserve one separately authorized reset before witness CAS.
    pub fn prepare_reset(
        &mut self,
        canonical_certificate: &[u8],
    ) -> Result<WitnessIntent, RepositoryError> {
        if self.pending.is_some() {
            return Err(RepositoryError::TransitionPending);
        }
        let certificate = decode_canonical_reset(canonical_certificate)?;
        let token = self
            .machine
            .prepare_reset(
                &certificate,
                &MlDsa65,
                &self.roots.recovery_verification_key,
                self.roots.recovery_key_id,
            )
            .map_err(|_| RepositoryError::InvalidCertificate)?;
        if token.next_state().authority_key_id() != self.roots.authority_key_id {
            return Err(RepositoryError::UnprovisionedAuthority);
        }
        self.persist_prepared(JournalKind::Reset, canonical_certificate, token)
    }

    /// Finish the local transaction only for the exact authenticated applied receipt.
    pub fn commit_applied(
        &mut self,
        receipt: WitnessReceipt,
    ) -> Result<CommittedMigrationStateV1, RepositoryError> {
        let prepared = self
            .pending
            .take()
            .ok_or(RepositoryError::NoPendingTransition)?;
        if !receipt.is_exact_applied(prepared.intent) {
            self.pending = Some(prepared);
            return Err(RepositoryError::WitnessMismatch);
        }
        let local_head = read_head(&self.database)?;
        if local_head != prepared.intent.expected() {
            self.pending = Some(prepared);
            return Err(RepositoryError::StaleReservation);
        }
        let generation = prepared.intent.next().revision().global_generation();
        let entry = encode_journal_entry(prepared.kind, &prepared.envelope)?;
        let transaction = durable_write(&self.database)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            let mut history = transaction
                .open_table(HISTORY_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            let mut sessions = transaction
                .open_table(SESSION_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            let mut capabilities = transaction
                .open_table(CAPABILITY_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            let transaction_head = decode_head_from_meta(&meta)?;
            if transaction_head != prepared.intent.expected()
                || history
                    .get(&generation)
                    .map_err(|_| RepositoryError::CorruptStore)?
                    .is_some()
            {
                self.pending = Some(prepared);
                return Err(RepositoryError::StaleReservation);
            }
            history
                .insert(&generation, entry.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
            meta.insert(META_HEAD, prepared.intent.next().to_bytes().as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
            meta.remove(META_PENDING)
                .map_err(|_| RepositoryError::CorruptStore)?;
            sessions
                .retain(|_, _| false)
                .map_err(|_| RepositoryError::CorruptStore)?;
            capabilities
                .retain(|_, _| false)
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        if transaction.commit().is_err() {
            self.pending = Some(prepared);
            return Err(RepositoryError::CorruptStore);
        }
        self.machine
            .commit(prepared.token)
            .map_err(|_| RepositoryError::InvalidHistory)
    }

    /// Validate a known non-applied/conflict receipt without discarding the operation.
    ///
    /// `NotApplied` only permits retrying the same intent when the witness still has
    /// the exact expected head. Conflict or a different head is a fail-closed fork.
    pub fn validate_unapplied(
        &self,
        receipt: WitnessReceipt,
    ) -> Result<WitnessIntent, RepositoryError> {
        let intent = self
            .pending_intent()
            .ok_or(RepositoryError::NoPendingTransition)?;
        if receipt.disposition() == WitnessDisposition::NotApplied
            && receipt.intent().is_none()
            && receipt.authoritative_head() == intent.expected()
        {
            Ok(intent)
        } else {
            Err(RepositoryError::WitnessMismatch)
        }
    }

    /// Durably reserve a session against the exact current state and fence.
    pub fn reserve_session(
        &self,
        session_id: SessionId,
        capability_session_id: [u8; 32],
        expected: StateHead,
    ) -> Result<(), RepositoryError> {
        if self.pending.is_some() {
            return Err(RepositoryError::TransitionPending);
        }
        let transaction = durable_write(&self.database)?;
        {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != expected
                || meta
                    .get(META_PENDING)
                    .map_err(|_| RepositoryError::CorruptStore)?
                    .is_some()
            {
                return Err(RepositoryError::StaleReservation);
            }
            if capability_session_id.iter().all(|byte| *byte == 0) {
                return Err(RepositoryError::CapabilityReplay);
            }
            let mut sessions = transaction
                .open_table(SESSION_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if sessions.len().map_err(|_| RepositoryError::CorruptStore)? >= MAX_DURABLE_SESSIONS {
                return Err(RepositoryError::CapacityExceeded);
            }
            if sessions
                .insert(
                    session_id.as_bytes().as_slice(),
                    expected.to_bytes().as_slice(),
                )
                .map_err(|_| RepositoryError::CorruptStore)?
                .is_some()
            {
                return Err(RepositoryError::StaleReservation);
            }
            let mut capabilities = transaction
                .open_table(CAPABILITY_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if capabilities
                .len()
                .map_err(|_| RepositoryError::CorruptStore)?
                >= MAX_USED_CAPABILITIES
            {
                return Err(RepositoryError::CapacityExceeded);
            }
            if capabilities
                .insert(
                    capability_session_id.as_slice(),
                    expected.to_bytes().as_slice(),
                )
                .map_err(|_| RepositoryError::CorruptStore)?
                .is_some()
            {
                return Err(RepositoryError::CapabilityReplay);
            }
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)?;
        #[cfg(all(test, unix))]
        self.sleep_after_durable_write_for_test();
        Ok(())
    }

    /// Release a session only if both its reservation and repository head remain exact.
    pub fn release_session(
        &self,
        session_id: SessionId,
        expected: StateHead,
    ) -> Result<(), RepositoryError> {
        if self.pending.is_some() {
            return Err(RepositoryError::TransitionPending);
        }
        let transaction = durable_write(&self.database)?;
        {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != expected
                || meta
                    .get(META_PENDING)
                    .map_err(|_| RepositoryError::CorruptStore)?
                    .is_some()
            {
                return Err(RepositoryError::StaleReservation);
            }
            let mut sessions = transaction
                .open_table(SESSION_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            let stored = sessions
                .get(session_id.as_bytes().as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?
                .ok_or(RepositoryError::SessionNotFound)?;
            let stored_head = decode_head(stored.value())?;
            drop(stored);
            if stored_head != expected {
                return Err(RepositoryError::StaleReservation);
            }
            sessions
                .remove(session_id.as_bytes().as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)?;
        #[cfg(all(test, unix))]
        self.sleep_after_durable_write_for_test();
        Ok(())
    }

    /// Cancel and erase a durable reservation, including one made stale by a transition.
    pub fn cancel_session(&self, session_id: SessionId) -> Result<(), RepositoryError> {
        let transaction = durable_write(&self.database)?;
        {
            let mut sessions = transaction
                .open_table(SESSION_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if sessions
                .remove(session_id.as_bytes().as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?
                .is_none()
            {
                return Err(RepositoryError::SessionNotFound);
            }
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)?;
        #[cfg(all(test, unix))]
        self.sleep_after_session_cancel_for_test();
        Ok(())
    }

    /// Durably journal one lease intent before it is dispatched, and in the
    /// same transaction forget the journaled intents this process has since
    /// settled with the authority.
    ///
    /// The row is what lets a successor process discharge the acknowledgement
    /// this operation's receipt will be owed: after a crash it queries every
    /// journaled id, acknowledges the receipt it finds, and forgets the row.
    /// Folding the deletions into the same commit keeps the steady-state cost
    /// at one durable transaction per lease operation.
    ///
    /// Refuses with [`RepositoryError::CapacityExceeded`] when the journal
    /// would hold more than [`MAX_JOURNALED_LEASE_INTENTS`] rows after the
    /// deletions. Nothing is committed on refusal, the deletions included, so
    /// the caller's settled list stays accurate.
    pub(crate) fn journal_lease_intent(
        &self,
        intent: OperationIdV2,
        forget: &[OperationIdV2],
    ) -> Result<(), RepositoryError> {
        #[cfg(all(test, unix))]
        self.refuse_lease_journal_write_if_armed_for_test()?;
        let transaction = durable_write(&self.database)?;
        {
            let mut journal = transaction
                .open_table(ACK_JOURNAL_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            for id in forget {
                journal
                    .remove(encode_operation_id(*id).as_slice())
                    .map_err(|_| RepositoryError::CorruptStore)?;
            }
            if journal.len().map_err(|_| RepositoryError::CorruptStore)?
                >= MAX_JOURNALED_LEASE_INTENTS
            {
                return Err(RepositoryError::CapacityExceeded);
            }
            journal
                .insert(
                    encode_operation_id(intent).as_slice(),
                    ACK_JOURNAL_PREPARED.as_slice(),
                )
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)
    }

    /// Every journaled lease intent, in key order.
    ///
    /// Empty for a store provisioned before the journal existed: the table is
    /// created by the first journal write, not at open.
    pub(crate) fn journaled_lease_intents(&self) -> Result<Vec<OperationIdV2>, RepositoryError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| RepositoryError::CorruptStore)?;
        let journal = match transaction.open_table(ACK_JOURNAL_TABLE) {
            Ok(journal) => journal,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(_) => return Err(RepositoryError::CorruptStore),
        };
        decode_ack_journal(&journal)
    }

    /// Durably forget journaled lease intents whose outcome is settled: their
    /// receipts are acknowledged, or the authority never saw them.
    pub(crate) fn forget_lease_intents(
        &self,
        ids: &[OperationIdV2],
    ) -> Result<(), RepositoryError> {
        if ids.is_empty() {
            return Ok(());
        }
        let transaction = durable_write(&self.database)?;
        {
            let mut journal = transaction
                .open_table(ACK_JOURNAL_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            for id in ids {
                journal
                    .remove(encode_operation_id(*id).as_slice())
                    .map_err(|_| RepositoryError::CorruptStore)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)
    }

    /// Test-only: remove the lease-intent journal table, leaving the store as
    /// one provisioned before the journal existed.
    #[cfg(all(test, unix))]
    pub(crate) fn drop_lease_journal_table_for_test(&self) -> Result<(), RepositoryError> {
        let transaction = durable_write(&self.database)?;
        transaction
            .delete_table(ACK_JOURNAL_TABLE)
            .map_err(|_| RepositoryError::CorruptStore)?;
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)
    }

    /// Test-only: whether the lease-intent journal table exists.
    #[cfg(all(test, unix))]
    pub(crate) fn lease_journal_table_exists_for_test(&self) -> Result<bool, RepositoryError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| RepositoryError::CorruptStore)?;
        match transaction.open_table(ACK_JOURNAL_TABLE) {
            Ok(_) => Ok(true),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(_) => Err(RepositoryError::CorruptStore),
        }
    }

    /// Test-only: write raw rows into the lease-intent journal, bypassing
    /// every check the production writer makes.
    #[cfg(all(test, unix))]
    pub(crate) fn write_raw_lease_journal_rows_for_test(
        &self,
        rows: &[(&[u8], &[u8])],
    ) -> Result<(), RepositoryError> {
        let transaction = durable_write(&self.database)?;
        {
            let mut journal = transaction
                .open_table(ACK_JOURNAL_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            for (key, value) in rows {
                journal
                    .insert(*key, *value)
                    .map_err(|_| RepositoryError::CorruptStore)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)
    }

    fn persist_prepared(
        &mut self,
        kind: JournalKind,
        envelope: &[u8],
        token: PendingMigrationCommitV1,
    ) -> Result<WitnessIntent, RepositoryError> {
        let expected_head = read_head(&self.database)?;
        if expected_head.revision().global_generation() >= MAX_HISTORY_ENTRIES {
            return Err(RepositoryError::CapacityExceeded);
        }
        if project_revision(token.expected_revision())? != expected_head.revision() {
            return Err(RepositoryError::StaleReservation);
        }
        let next_revision = project_revision(
            token
                .next_revision()
                .map_err(|_| RepositoryError::InvalidCertificate)?,
        )?;
        let transition_kind = match token.kind() {
            PendingMigrationCommitKind::Advance => TransitionKind::Advance,
            PendingMigrationCommitKind::Reset => TransitionKind::AuthorizedReset,
        };
        let advance = StateAdvance::new(transition_kind, expected_head.revision(), next_revision)
            .map_err(|_| RepositoryError::InvalidCertificate)?;
        let intent = WitnessIntent::new(
            OperationId::generate().map_err(|_| RepositoryError::EntropyUnavailable)?,
            advance,
            expected_head.fence(),
            FenceToken::generate().map_err(|_| RepositoryError::EntropyUnavailable)?,
        )
        .map_err(|_| RepositoryError::InvalidCertificate)?;
        let encoded = encode_pending(kind, intent, envelope)?;
        let transaction = durable_write(&self.database)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != expected_head
                || meta
                    .get(META_PENDING)
                    .map_err(|_| RepositoryError::CorruptStore)?
                    .is_some()
            {
                return Err(RepositoryError::TransitionPending);
            }
            meta.insert(META_PENDING, encoded.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CorruptStore)?;
        self.pending = Some(PreparedTransition {
            token,
            intent,
            kind,
            envelope: envelope.to_vec(),
        });
        Ok(intent)
    }
}

struct PendingRecord {
    kind: JournalKind,
    intent: WitnessIntent,
    envelope: Vec<u8>,
}

fn durable_write(database: &Database) -> Result<redb::WriteTransaction, RepositoryError> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| RepositoryError::CorruptStore)?;
    transaction.set_durability(Durability::Immediate);
    transaction.set_two_phase_commit(true);
    Ok(transaction)
}

fn verify_schema(database: &Database) -> Result<(), RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    let schema = meta
        .get(META_SCHEMA)
        .map_err(|_| RepositoryError::CorruptStore)?
        .ok_or(RepositoryError::CorruptStore)?;
    if schema.value() != REPOSITORY_SCHEMA {
        return Err(RepositoryError::CorruptStore);
    }
    Ok(())
}

fn replay_history(
    database: &Database,
    roots: &MigrationTrustRoots,
) -> Result<MigrationStateMachineV1, RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let history = transaction
        .open_table(HISTORY_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    let count = history.len().map_err(|_| RepositoryError::CorruptStore)?;
    if count == 0 || count > MAX_HISTORY_ENTRIES {
        return Err(RepositoryError::InvalidHistory);
    }
    let mut entries = history
        .range::<u64>(..)
        .map_err(|_| RepositoryError::CorruptStore)?;
    let Some(first) = entries.next() else {
        return Err(RepositoryError::InvalidHistory);
    };
    let (generation, encoded) = first.map_err(|_| RepositoryError::CorruptStore)?;
    if generation.value() != 1 {
        return Err(RepositoryError::InvalidHistory);
    }
    let (kind, envelope) = decode_journal_entry(encoded.value())?;
    if kind != JournalKind::Genesis {
        return Err(RepositoryError::InvalidHistory);
    }
    let genesis = decode_canonical_state(envelope)?;
    if genesis.state().authority_key_id() != roots.authority_key_id {
        return Err(RepositoryError::UnprovisionedAuthority);
    }
    let pending = UninitializedMigrationStateV1
        .verify_genesis(
            &genesis,
            &MlDsa65,
            &roots.authority_verification_key,
            roots.authority_key_id,
        )
        .map_err(|_| RepositoryError::InvalidCertificate)?;
    let mut machine = pending
        .commit()
        .map_err(|_| RepositoryError::InvalidCertificate)?;
    let mut expected_generation = 2u64;
    for entry in entries {
        let (generation, encoded) = entry.map_err(|_| RepositoryError::CorruptStore)?;
        if generation.value() != expected_generation {
            return Err(RepositoryError::InvalidHistory);
        }
        let (kind, envelope) = decode_journal_entry(encoded.value())?;
        let pending = match kind {
            JournalKind::Genesis => return Err(RepositoryError::InvalidHistory),
            JournalKind::Advance => {
                let certificate = decode_canonical_state(envelope)?;
                if certificate.state().authority_key_id() != roots.authority_key_id {
                    return Err(RepositoryError::UnprovisionedAuthority);
                }
                machine
                    .prepare_advance(&certificate, &MlDsa65, &roots.authority_verification_key)
                    .map_err(|_| RepositoryError::InvalidCertificate)?
            }
            JournalKind::Reset => {
                let certificate = decode_canonical_reset(envelope)?;
                let pending = machine
                    .prepare_reset(
                        &certificate,
                        &MlDsa65,
                        &roots.recovery_verification_key,
                        roots.recovery_key_id,
                    )
                    .map_err(|_| RepositoryError::InvalidCertificate)?;
                if pending.next_state().authority_key_id() != roots.authority_key_id {
                    return Err(RepositoryError::UnprovisionedAuthority);
                }
                pending
            }
        };
        if pending
            .next_revision()
            .map_err(|_| RepositoryError::InvalidCertificate)?
            .global_generation()
            != expected_generation
        {
            return Err(RepositoryError::InvalidHistory);
        }
        machine
            .commit(pending)
            .map_err(|_| RepositoryError::InvalidHistory)?;
        expected_generation = expected_generation
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
    }
    if count != expected_generation.saturating_sub(1) {
        return Err(RepositoryError::InvalidHistory);
    }
    Ok(machine)
}

fn reconstruct_pending(
    machine: &MigrationStateMachineV1,
    roots: &MigrationTrustRoots,
    record: PendingRecord,
) -> Result<PreparedTransition, RepositoryError> {
    let token = match record.kind {
        JournalKind::Genesis => return Err(RepositoryError::InvalidHistory),
        JournalKind::Advance => {
            let certificate = decode_canonical_state(&record.envelope)?;
            if certificate.state().authority_key_id() != roots.authority_key_id {
                return Err(RepositoryError::UnprovisionedAuthority);
            }
            machine
                .prepare_advance(&certificate, &MlDsa65, &roots.authority_verification_key)
                .map_err(|_| RepositoryError::InvalidCertificate)?
        }
        JournalKind::Reset => {
            let certificate = decode_canonical_reset(&record.envelope)?;
            let token = machine
                .prepare_reset(
                    &certificate,
                    &MlDsa65,
                    &roots.recovery_verification_key,
                    roots.recovery_key_id,
                )
                .map_err(|_| RepositoryError::InvalidCertificate)?;
            if token.next_state().authority_key_id() != roots.authority_key_id {
                return Err(RepositoryError::UnprovisionedAuthority);
            }
            token
        }
    };
    let expected = project_revision(token.expected_revision())?;
    let next = project_revision(
        token
            .next_revision()
            .map_err(|_| RepositoryError::InvalidCertificate)?,
    )?;
    let kind = match token.kind() {
        PendingMigrationCommitKind::Advance => TransitionKind::Advance,
        PendingMigrationCommitKind::Reset => TransitionKind::AuthorizedReset,
    };
    if record.intent.advance()
        != StateAdvance::new(kind, expected, next)
            .map_err(|_| RepositoryError::InvalidCertificate)?
    {
        return Err(RepositoryError::InvalidHistory);
    }
    Ok(PreparedTransition {
        token,
        intent: record.intent,
        kind: record.kind,
        envelope: record.envelope,
    })
}

fn project_revision(revision: StateRevisionV1) -> Result<StateRevision, RepositoryError> {
    StateRevision::new(
        revision.global_generation(),
        revision.epoch(),
        *revision.digest().as_bytes(),
    )
    .map_err(|_| RepositoryError::InvalidHistory)
}

fn read_head(database: &Database) -> Result<StateHead, RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    decode_head_from_meta(&meta)
}

fn decode_head_from_meta(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<StateHead, RepositoryError> {
    let encoded = meta
        .get(META_HEAD)
        .map_err(|_| RepositoryError::CorruptStore)?
        .ok_or(RepositoryError::CorruptStore)?;
    decode_head(encoded.value())
}

fn decode_head(bytes: &[u8]) -> Result<StateHead, RepositoryError> {
    let mut decoder = Decoder::new(bytes);
    let head = StateHead::decode(&mut decoder).map_err(map_codec)?;
    decoder.finish().map_err(map_codec)?;
    Ok(head)
}

fn read_pending(database: &Database) -> Result<Option<PendingRecord>, RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    meta.get(META_PENDING)
        .map_err(|_| RepositoryError::CorruptStore)?
        .map(|value| decode_pending(value.value()))
        .transpose()
}

fn reject_restart_sessions(database: &Database) -> Result<u64, RepositoryError> {
    let transaction = durable_write(database)?;
    let count = {
        let mut sessions = transaction
            .open_table(SESSION_TABLE)
            .map_err(|_| RepositoryError::CorruptStore)?;
        let count = sessions.len().map_err(|_| RepositoryError::CorruptStore)?;
        if count > MAX_DURABLE_SESSIONS {
            return Err(RepositoryError::CorruptStore);
        }
        for entry in sessions
            .range::<&[u8]>(..)
            .map_err(|_| RepositoryError::CorruptStore)?
        {
            let (id, head) = entry.map_err(|_| RepositoryError::CorruptStore)?;
            SessionId::decode(
                id.value()
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptStore)?,
            )
            .map_err(|_| RepositoryError::CorruptStore)?;
            decode_head(head.value())?;
        }
        sessions
            .retain(|_, _| false)
            .map_err(|_| RepositoryError::CorruptStore)?;
        count
    };
    transaction
        .commit()
        .map_err(|_| RepositoryError::CorruptStore)?;
    Ok(count)
}

fn validate_used_capabilities(
    database: &Database,
    current_head: StateHead,
) -> Result<(), RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let capabilities = transaction
        .open_table(CAPABILITY_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    if capabilities
        .len()
        .map_err(|_| RepositoryError::CorruptStore)?
        > MAX_USED_CAPABILITIES
    {
        return Err(RepositoryError::CorruptStore);
    }
    for entry in capabilities
        .range::<&[u8]>(..)
        .map_err(|_| RepositoryError::CorruptStore)?
    {
        let (session_id, head) = entry.map_err(|_| RepositoryError::CorruptStore)?;
        let session_id: [u8; 32] = session_id
            .value()
            .try_into()
            .map_err(|_| RepositoryError::CorruptStore)?;
        if session_id.iter().all(|byte| *byte == 0) || decode_head(head.value())? != current_head {
            return Err(RepositoryError::CorruptStore);
        }
    }
    Ok(())
}

/// Refuse a journal whose rows do not decode or that exceeds its bound. A
/// store provisioned before the journal existed simply has no table yet.
fn validate_ack_journal(database: &Database) -> Result<(), RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let journal = match transaction.open_table(ACK_JOURNAL_TABLE) {
        Ok(journal) => journal,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(_) => return Err(RepositoryError::CorruptStore),
    };
    decode_ack_journal(&journal).map(drop)
}

fn decode_ack_journal(
    journal: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<Vec<OperationIdV2>, RepositoryError> {
    let count = journal.len().map_err(|_| RepositoryError::CorruptStore)?;
    if count > MAX_JOURNALED_LEASE_INTENTS {
        return Err(RepositoryError::CorruptStore);
    }
    let mut ids = Vec::new();
    ids.try_reserve(usize::try_from(count).map_err(|_| RepositoryError::CorruptStore)?)
        .map_err(|_| RepositoryError::CorruptStore)?;
    for entry in journal
        .range::<&[u8]>(..)
        .map_err(|_| RepositoryError::CorruptStore)?
    {
        let (key, value) = entry.map_err(|_| RepositoryError::CorruptStore)?;
        if value.value() != ACK_JOURNAL_PREPARED {
            return Err(RepositoryError::CorruptStore);
        }
        ids.push(decode_operation_id(key.value()).map_err(|_| RepositoryError::CorruptStore)?);
    }
    Ok(ids)
}

fn encode_journal_entry(kind: JournalKind, envelope: &[u8]) -> Result<Vec<u8>, RepositoryError> {
    if envelope.is_empty() || envelope.len() > MAX_FRAME_BYTES {
        return Err(RepositoryError::InvalidCertificate);
    }
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, REPOSITORY_DOMAIN, REPOSITORY_SCHEMA_VERSION).map_err(map_codec)?;
    encoder.byte(kind as u8).map_err(map_codec)?;
    encoder.lp16(envelope).map_err(map_codec)?;
    Ok(encoder.finish())
}

fn decode_journal_entry(bytes: &[u8]) -> Result<(JournalKind, &[u8]), RepositoryError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, REPOSITORY_DOMAIN, REPOSITORY_SCHEMA_VERSION)
        .map_err(map_codec)?;
    let kind = JournalKind::from_u8(decoder.byte().map_err(map_codec)?)
        .ok_or(RepositoryError::CorruptStore)?;
    let envelope = decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?;
    if envelope.is_empty() {
        return Err(RepositoryError::CorruptStore);
    }
    decoder.finish().map_err(map_codec)?;
    Ok((kind, envelope))
}

fn encode_pending(
    kind: JournalKind,
    intent: WitnessIntent,
    envelope: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, REPOSITORY_DOMAIN, REPOSITORY_SCHEMA_VERSION).map_err(map_codec)?;
    encoder.byte(kind as u8).map_err(map_codec)?;
    intent.encode(&mut encoder).map_err(map_codec)?;
    encoder.lp16(envelope).map_err(map_codec)?;
    Ok(encoder.finish())
}

fn decode_pending(bytes: &[u8]) -> Result<PendingRecord, RepositoryError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, REPOSITORY_DOMAIN, REPOSITORY_SCHEMA_VERSION)
        .map_err(map_codec)?;
    let kind = JournalKind::from_u8(decoder.byte().map_err(map_codec)?)
        .filter(|kind| *kind != JournalKind::Genesis)
        .ok_or(RepositoryError::CorruptStore)?;
    let intent = WitnessIntent::decode(&mut decoder).map_err(map_codec)?;
    let envelope = decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?.to_vec();
    if envelope.is_empty() {
        return Err(RepositoryError::CorruptStore);
    }
    decoder.finish().map_err(map_codec)?;
    Ok(PendingRecord {
        kind,
        intent,
        envelope,
    })
}

fn decode_canonical_state(bytes: &[u8]) -> Result<SignedMigrationStateV1, RepositoryError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(RepositoryError::InvalidCertificate);
    }
    let value =
        SignedMigrationStateV1::decode(bytes).map_err(|_| RepositoryError::InvalidCertificate)?;
    if value
        .encode()
        .map_err(|_| RepositoryError::InvalidCertificate)?
        != bytes
    {
        return Err(RepositoryError::InvalidCertificate);
    }
    Ok(value)
}

fn decode_canonical_reset(bytes: &[u8]) -> Result<SignedMigrationResetV1, RepositoryError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(RepositoryError::InvalidCertificate);
    }
    let value =
        SignedMigrationResetV1::decode(bytes).map_err(|_| RepositoryError::InvalidCertificate)?;
    if value
        .encode()
        .map_err(|_| RepositoryError::InvalidCertificate)?
        != bytes
    {
        return Err(RepositoryError::InvalidCertificate);
    }
    Ok(value)
}

fn map_codec(_: CodecError) -> RepositoryError {
    RepositoryError::CorruptStore
}
