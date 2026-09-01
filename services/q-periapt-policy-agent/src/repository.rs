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

use crate::authority::{
    AuthorityDispositionV2, AuthorityIntentV2, AuthorityMutationV2, AuthorityReceiptV2,
    InstanceFenceV2, OperationIdV2, ReceiptAckDispositionV2, StateAdvanceV2, StateFenceV2,
    StateHeadV2, StateRevisionV2, StateTransitionKindV2,
};
use crate::authority_codec::{decode_intent, decode_receipt, encode_intent, encode_receipt};
use crate::authority_journal::{self, AuthorityJournalError, DurableAuthorityOperation};
use crate::authority_protocol::{AuthorityWireIdentityV3, DurablyRetainedAuthorityReceiptV3};
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};
use crate::filesystem::open_private_file;
use crate::types::{
    FenceToken, OperationId, SessionId, StateAdvance, StateHead, StateRevision, TransitionKind,
};
use crate::witness::{WitnessDisposition, WitnessIntent, WitnessReceipt};

const REPOSITORY_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-REPOSITORY/v1";
const REPOSITORY_RECORD_SCHEMA_VERSION: u16 = 1;
const PENDING_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-AGENT-PENDING/v3";
const PENDING_SCHEMA_VERSION: u16 = 3;
const REPOSITORY_STORAGE_SCHEMA_VERSION: u16 = 3;
const REPOSITORY_STORAGE_SCHEMA: [u8; 2] = REPOSITORY_STORAGE_SCHEMA_VERSION.to_be_bytes();
const LEGACY_REPOSITORY_STORAGE_SCHEMA: [u8; 2] = 1u16.to_be_bytes();
const MAX_HISTORY_ENTRIES: u64 = 4096;
const MAX_DURABLE_SESSIONS: u64 = 1024;
const MAX_USED_CAPABILITIES: u64 = 4096;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("agent_meta_v1");
const HISTORY_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("agent_state_history_v1");
const SESSION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("agent_session_reservations_v1");
const CAPABILITY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("agent_used_capabilities_v1");
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
    /// The database was corrupt, repaired, incomplete, or had an unknown schema.
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
    /// The durable authority journal is bound to a different exact wire identity.
    AuthorityBindingMismatch,
    /// One exact durable lease operation must be reconciled before another may start.
    LeaseOperationPending,
    /// No durable lease operation exists for the requested transition.
    NoPendingLeaseOperation,
    /// A lease receipt, intent, locator, or authority version did not match durable state.
    LeaseReceiptMismatch,
    /// A lease-journal commit completed with an uncertain old-or-new outcome.
    CommitUncertain,
    /// A prior lease-journal persistence failure forbids further use of this instance.
    RepositoryPoisoned,
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
            Self::AuthorityBindingMismatch => {
                "authority wire identity does not match repository binding"
            }
            Self::LeaseOperationPending => "an exact durable lease operation remains unresolved",
            Self::NoPendingLeaseOperation => "no durable lease operation is pending",
            Self::LeaseReceiptMismatch => "lease receipt does not match durable operation state",
            Self::CommitUncertain => "lease journal commit outcome is uncertain",
            Self::RepositoryPoisoned => "repository instance is poisoned",
        })
    }
}

impl std::error::Error for RepositoryError {}

impl From<AuthorityJournalError> for RepositoryError {
    fn from(error: AuthorityJournalError) -> Self {
        match error {
            AuthorityJournalError::CorruptStore => Self::CorruptStore,
            AuthorityJournalError::AuthorityBindingMismatch => Self::AuthorityBindingMismatch,
            AuthorityJournalError::OperationPending => Self::LeaseOperationPending,
            AuthorityJournalError::ReceiptMismatch => Self::LeaseReceiptMismatch,
            AuthorityJournalError::NoPendingOperation => Self::NoPendingLeaseOperation,
            #[cfg(test)]
            AuthorityJournalError::CommitUncertain => Self::CommitUncertain,
        }
    }
}

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
    authority_intent: AuthorityIntentV2,
    authority_receipt: Option<AuthorityReceiptV2>,
    authority_acknowledged: bool,
    kind: JournalKind,
    envelope: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatedTransition {
    witness_intent: WitnessIntent,
    authority_intent: AuthorityIntentV2,
    authority_receipt: Option<AuthorityReceiptV2>,
    authority_acknowledged: bool,
}

impl CoordinatedTransition {
    pub(crate) const fn witness_intent(self) -> WitnessIntent {
        self.witness_intent
    }

    pub(crate) const fn authority_intent(self) -> AuthorityIntentV2 {
        self.authority_intent
    }

    pub(crate) const fn authority_receipt(self) -> Option<AuthorityReceiptV2> {
        self.authority_receipt
    }

    pub(crate) const fn authority_acknowledged(self) -> bool {
        self.authority_acknowledged
    }
}

pub(crate) struct CommittedTransition {
    pub(crate) expected_identity: AuthorityWireIdentityV3,
    pub(crate) next_identity: AuthorityWireIdentityV3,
}

/// Transactional local state. All methods require exclusive access from the service linearizer.
pub struct StateRepository {
    database: Database,
    machine: MigrationStateMachineV1,
    roots: MigrationTrustRoots,
    pending: Option<PreparedTransition>,
    restart_rejections: u64,
    authority_journal_poisoned: bool,
    #[cfg(test)]
    authority_journal_commits_until_fault: Option<usize>,
}

impl fmt::Debug for StateRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateRepository([redacted])")
    }
}

impl StateRepository {
    pub(crate) fn has_v3_storage_schema(path: &Path) -> Result<bool, RepositoryError> {
        let file =
            open_private_file(path, false).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
        let mut database = Database::builder()
            .create_file(file)
            .map_err(|_| RepositoryError::CorruptStore)?;
        if !database
            .check_integrity()
            .map_err(|_| RepositoryError::CorruptStore)?
        {
            return Err(RepositoryError::CorruptStore);
        }
        match read_schema(&database)? {
            REPOSITORY_STORAGE_SCHEMA => Ok(true),
            LEGACY_REPOSITORY_STORAGE_SCHEMA => Ok(false),
            _ => Err(RepositoryError::CorruptStore),
        }
    }

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
        let file =
            open_private_file(path, true).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
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
            authority_journal::provision_tables(&transaction)?;
            meta.insert(META_SCHEMA, REPOSITORY_STORAGE_SCHEMA.as_slice())
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
                authority_journal_poisoned: false,
                #[cfg(test)]
                authority_journal_commits_until_fault: None,
            },
            head,
        ))
    }

    /// Open and fully replay an existing store. Missing/corrupt state never becomes genesis.
    pub fn open_existing(path: &Path, roots: MigrationTrustRoots) -> Result<Self, RepositoryError> {
        let file =
            open_private_file(path, false).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
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
        authority_journal::validate(&database)?;
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
        validate_sessions(&database)?;
        validate_used_capabilities(&database, durable_head)?;
        validate_coordinator_binding(&database, &machine, pending.as_ref(), durable_head)?;
        let restart_rejections = reject_restart_sessions(&database)?;
        Ok(Self {
            database,
            machine,
            roots,
            pending,
            restart_rejections,
            authority_journal_poisoned: false,
            #[cfg(test)]
            authority_journal_commits_until_fault: None,
        })
    }

    /// Explicitly migrate one exact legacy V1 repository to storage schema V3.
    ///
    /// Normal service open never accepts V1. This offline entry point validates
    /// the authenticated history first, adds the empty lease-journal tables and
    /// advances the storage schema in one immediate-durability transaction. A
    /// second call validates the already-migrated V3 store and returns without a
    /// compatibility fallback.
    pub(crate) fn migrate_v1_to_v3(
        path: &Path,
        roots: MigrationTrustRoots,
        identity: AuthorityWireIdentityV3,
    ) -> Result<(), RepositoryError> {
        let file =
            open_private_file(path, false).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
        let mut database = Database::builder()
            .create_file(file)
            .map_err(|_| RepositoryError::CorruptStore)?;
        if !database
            .check_integrity()
            .map_err(|_| RepositoryError::CorruptStore)?
        {
            return Err(RepositoryError::CorruptStore);
        }
        let schema = read_schema(&database)?;
        if schema == REPOSITORY_STORAGE_SCHEMA {
            authority_journal::validate(&database)?;
            validate_authenticated_repository(&database, &roots)?;
            if authority_journal::bound_identity(&database)? != Some(identity) {
                return Err(RepositoryError::AuthorityBindingMismatch);
            }
            return Ok(());
        }
        if schema != LEGACY_REPOSITORY_STORAGE_SCHEMA {
            return Err(RepositoryError::CorruptStore);
        }
        let (machine, durable_head) = validate_repository_without_coordinator(&database, &roots)?;
        if project_authority_head(machine.current().state(), durable_head)? != identity.state_head()
        {
            return Err(RepositoryError::AuthorityBindingMismatch);
        }
        let transaction = durable_write(&database)?;
        authority_journal::provision_tables(&transaction)?;
        authority_journal::bind(&transaction, identity)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            meta.insert(META_SCHEMA, REPOSITORY_STORAGE_SCHEMA.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::CommitUncertain)?;
        authority_journal::validate(&database)?;
        validate_authenticated_repository(&database, &roots)?;
        (authority_journal::bound_identity(&database)? == Some(identity))
            .then_some(())
            .ok_or(RepositoryError::AuthorityBindingMismatch)
    }

    /// Finish an interrupted fresh V3 provisioning after the caller has locked
    /// and validated the actual pristine authority store.
    ///
    /// Normal open remains fail-closed for an unbound repository. This narrow,
    /// idempotent entry point accepts only a fully authenticated repository with
    /// no pending transition and an entirely empty authority journal.
    pub(crate) fn finalize_unbound_v3_binding(
        path: &Path,
        roots: MigrationTrustRoots,
        identity: AuthorityWireIdentityV3,
    ) -> Result<(), RepositoryError> {
        let file =
            open_private_file(path, false).map_err(|_| RepositoryError::InsecureOrMissingStore)?;
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
        authority_journal::validate(&database)?;
        let (machine, durable_head) = validate_repository_without_coordinator(&database, &roots)?;
        if project_authority_head(machine.current().state(), durable_head)? != identity.state_head()
        {
            return Err(RepositoryError::AuthorityBindingMismatch);
        }
        match authority_journal::bound_identity(&database)? {
            Some(bound) if bound == identity => {
                return validate_authenticated_repository(&database, &roots)
            }
            Some(_) => return Err(RepositoryError::AuthorityBindingMismatch),
            None => {}
        }
        let transaction = durable_write(&database)?;
        authority_journal::bind(&transaction, identity)?;
        transaction
            .commit()
            .map_err(|_| RepositoryError::CommitUncertain)?;
        authority_journal::validate(&database)?;
        validate_authenticated_repository(&database, &roots)?;
        (authority_journal::bound_identity(&database)? == Some(identity))
            .then_some(())
            .ok_or(RepositoryError::AuthorityBindingMismatch)
    }

    /// Bind a newly provisioned repository to one exact fresh Authority Wire V3 store.
    pub fn provision_authority_binding(
        &mut self,
        identity: AuthorityWireIdentityV3,
    ) -> Result<(), RepositoryError> {
        self.ensure_authority_journal_live()?;
        if self.pending.is_some()
            || identity.state_head()
                != project_authority_head(self.machine.current().state(), self.head()?)?
        {
            return Err(RepositoryError::AuthorityBindingMismatch);
        }
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        authority_journal::bind(&transaction, identity)?;
        self.finish_authority_journal_commit(transaction, inject)
    }

    pub(crate) fn authority_identity(&self) -> Result<AuthorityWireIdentityV3, RepositoryError> {
        self.ensure_authority_journal_live()?;
        authority_journal::bound_identity(&self.database)?
            .ok_or(RepositoryError::AuthorityBindingMismatch)
    }

    pub(crate) fn durable_lease_operation(
        &self,
        identity: AuthorityWireIdentityV3,
    ) -> Result<Option<DurableAuthorityOperation>, RepositoryError> {
        self.ensure_authority_journal_live()?;
        Ok(authority_journal::active(&self.database, identity)?)
    }

    pub(crate) fn prepare_lease_operation(
        &mut self,
        identity: AuthorityWireIdentityV3,
        intent: AuthorityIntentV2,
    ) -> Result<(), RepositoryError> {
        self.ensure_authority_journal_live()?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        authority_journal::prepare(&transaction, identity, intent)?;
        self.finish_authority_journal_commit(transaction, inject)
    }

    pub(crate) fn resolve_lease_operation(
        &mut self,
        identity: AuthorityWireIdentityV3,
        intent: AuthorityIntentV2,
        receipt: AuthorityReceiptV2,
    ) -> Result<DurablyRetainedAuthorityReceiptV3, RepositoryError> {
        self.ensure_authority_journal_live()?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        authority_journal::resolve(&transaction, identity, intent, receipt)?;
        self.finish_authority_journal_commit(transaction, inject)?;
        DurablyRetainedAuthorityReceiptV3::after_repository_commit(receipt)
            .map_err(|_| RepositoryError::LeaseReceiptMismatch)
    }

    pub(crate) fn cancel_prepared_lease_operation(
        &mut self,
        identity: AuthorityWireIdentityV3,
        intent: AuthorityIntentV2,
    ) -> Result<(), RepositoryError> {
        self.ensure_authority_journal_live()?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        authority_journal::cancel_prepared(&transaction, identity, intent)?;
        self.finish_authority_journal_commit(transaction, inject)
    }

    pub(crate) fn complete_lease_acknowledgement(
        &mut self,
        identity: AuthorityWireIdentityV3,
        retained: DurablyRetainedAuthorityReceiptV3,
        disposition: ReceiptAckDispositionV2,
    ) -> Result<(), RepositoryError> {
        self.ensure_authority_journal_live()?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        authority_journal::complete_acknowledgement(&transaction, identity, retained, disposition)?;
        self.finish_authority_journal_commit(transaction, inject)
    }

    fn ensure_authority_journal_live(&self) -> Result<(), RepositoryError> {
        if self.authority_journal_poisoned {
            Err(RepositoryError::RepositoryPoisoned)
        } else {
            Ok(())
        }
    }

    fn finish_authority_journal_commit(
        &mut self,
        transaction: redb::WriteTransaction,
        inject_commit_uncertain: bool,
    ) -> Result<(), RepositoryError> {
        let committed = transaction.commit().is_ok();
        if !committed || inject_commit_uncertain {
            self.authority_journal_poisoned = true;
            return Err(RepositoryError::CommitUncertain);
        }
        Ok(())
    }

    fn take_lease_commit_fault(&mut self) -> bool {
        #[cfg(test)]
        {
            match self.authority_journal_commits_until_fault {
                Some(1) => {
                    self.authority_journal_commits_until_fault = None;
                    true
                }
                Some(remaining) => {
                    self.authority_journal_commits_until_fault = remaining.checked_sub(1);
                    false
                }
                None => false,
            }
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_authority_journal_commit_for_test(&mut self) {
        self.authority_journal_commits_until_fault = Some(1);
    }

    #[cfg(test)]
    pub(crate) fn fail_after_authority_journal_commits_for_test(&mut self, commits: usize) {
        self.authority_journal_commits_until_fault = Some(commits);
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

    pub(crate) fn coordinated_transition(&self) -> Option<CoordinatedTransition> {
        self.pending.as_ref().map(|pending| CoordinatedTransition {
            witness_intent: pending.intent,
            authority_intent: pending.authority_intent,
            authority_receipt: pending.authority_receipt,
            authority_acknowledged: pending.authority_acknowledged,
        })
    }

    pub(crate) fn pending_next_state(&self) -> Option<q_periapt_migration::MigrationStateV1> {
        self.pending
            .as_ref()
            .map(|pending| pending.token.next_state())
    }

    /// Authenticate and durably reserve one normal state certificate before witness CAS.
    pub(crate) fn prepare_advance(
        &mut self,
        canonical_certificate: &[u8],
        authority_version: u64,
        instance_fence: InstanceFenceV2,
    ) -> Result<CoordinatedTransition, RepositoryError> {
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
        self.persist_prepared(
            JournalKind::Advance,
            canonical_certificate,
            token,
            authority_version,
            instance_fence,
        )
    }

    /// Authenticate and durably reserve one separately authorized reset before witness CAS.
    pub(crate) fn prepare_reset(
        &mut self,
        canonical_certificate: &[u8],
        authority_version: u64,
        instance_fence: InstanceFenceV2,
    ) -> Result<CoordinatedTransition, RepositoryError> {
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
        self.persist_prepared(
            JournalKind::Reset,
            canonical_certificate,
            token,
            authority_version,
            instance_fence,
        )
    }

    /// Retain the exact authority result in both the transition record and receipt journal.
    pub(crate) fn record_transition_authority_result(
        &mut self,
        intent: AuthorityIntentV2,
        receipt: AuthorityReceiptV2,
    ) -> Result<DurablyRetainedAuthorityReceiptV3, RepositoryError> {
        let (kind, witness_intent, durable_authority_intent, envelope) = {
            let prepared = self
                .pending
                .as_ref()
                .ok_or(RepositoryError::NoPendingTransition)?;
            (
                prepared.kind,
                prepared.intent,
                prepared.authority_intent,
                prepared.envelope.clone(),
            )
        };
        if durable_authority_intent != intent
            || self.pending.as_ref().is_some_and(|prepared| {
                prepared.authority_receipt.is_some() || prepared.authority_acknowledged
            })
            || receipt.intent() != intent
        {
            return Err(RepositoryError::LeaseReceiptMismatch);
        }
        let encoded = encode_pending(
            kind,
            witness_intent,
            durable_authority_intent,
            Some(receipt),
            false,
            &envelope,
        )?;
        let identity = self.authority_identity()?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != witness_intent.expected() {
                return Err(RepositoryError::StaleReservation);
            }
            meta.insert(META_PENDING, encoded.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        authority_journal::resolve(&transaction, identity, intent, receipt)?;
        self.finish_authority_journal_commit(transaction, inject)?;
        self.pending
            .as_mut()
            .ok_or(RepositoryError::NoPendingTransition)?
            .authority_receipt = Some(receipt);
        DurablyRetainedAuthorityReceiptV3::after_repository_commit(receipt)
            .map_err(|_| RepositoryError::LeaseReceiptMismatch)
    }

    /// Atomically make the authority ACK terminal and advance the durable
    /// transition phase. A server-side `AlreadyAbsent` result is safe only
    /// because the exact receipt remains bound in the pending record.
    pub(crate) fn complete_transition_authority_acknowledgement(
        &mut self,
        identity: AuthorityWireIdentityV3,
        retained: DurablyRetainedAuthorityReceiptV3,
        disposition: ReceiptAckDispositionV2,
    ) -> Result<(), RepositoryError> {
        self.ensure_authority_journal_live()?;
        let receipt = retained.receipt();
        let (kind, witness_intent, authority_intent, envelope) = {
            let prepared = self
                .pending
                .as_ref()
                .ok_or(RepositoryError::NoPendingTransition)?;
            if prepared.authority_receipt != Some(receipt)
                || prepared.authority_acknowledged
                || prepared.authority_intent != receipt.intent()
            {
                return Err(RepositoryError::LeaseReceiptMismatch);
            }
            (
                prepared.kind,
                prepared.intent,
                prepared.authority_intent,
                prepared.envelope.clone(),
            )
        };
        let encoded = encode_pending(
            kind,
            witness_intent,
            authority_intent,
            Some(receipt),
            true,
            &envelope,
        )?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != witness_intent.expected() {
                return Err(RepositoryError::StaleReservation);
            }
            meta.insert(META_PENDING, encoded.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        authority_journal::complete_acknowledgement(&transaction, identity, retained, disposition)?;
        self.finish_authority_journal_commit(transaction, inject)?;
        self.pending
            .as_mut()
            .ok_or(RepositoryError::NoPendingTransition)?
            .authority_acknowledged = true;
        Ok(())
    }

    pub(crate) fn replace_rejected_transition_authority_attempt(
        &mut self,
        rejected: AuthorityReceiptV2,
        authority_version: u64,
        instance_fence: InstanceFenceV2,
    ) -> Result<CoordinatedTransition, RepositoryError> {
        let (kind, witness_intent, old_intent, envelope, advance) = {
            let prepared = self
                .pending
                .as_ref()
                .ok_or(RepositoryError::NoPendingTransition)?;
            let allowed = matches!(
                rejected.disposition(),
                AuthorityDispositionV2::Rejected(
                    crate::authority::AuthorityRejectionV2::LeaseAbsent
                        | crate::authority::AuthorityRejectionV2::LeaseExpired
                        | crate::authority::AuthorityRejectionV2::FenceMismatch
                )
            );
            let advance = match prepared.authority_intent.mutation() {
                AuthorityMutationV2::AdvanceState { advance, .. } => advance,
                _ => return Err(RepositoryError::InvalidHistory),
            };
            if !allowed
                || prepared.authority_receipt != Some(rejected)
                || !prepared.authority_acknowledged
                || rejected.intent() != prepared.authority_intent
            {
                return Err(RepositoryError::LeaseReceiptMismatch);
            }
            (
                prepared.kind,
                prepared.intent,
                prepared.authority_intent,
                prepared.envelope.clone(),
                advance,
            )
        };
        let identity = self.authority_identity()?;
        if advance.expected() != identity.state_head() {
            return Err(RepositoryError::AuthorityBindingMismatch);
        }
        let new_intent = AuthorityIntentV2::new(
            fresh_authority_operation_id(authority_version)?,
            authority_version,
            identity.config(),
            AuthorityMutationV2::AdvanceState {
                fence: instance_fence,
                advance,
            },
        )
        .map_err(|_| RepositoryError::InvalidHistory)?;
        if new_intent == old_intent {
            return Err(RepositoryError::LeaseReceiptMismatch);
        }
        let encoded = encode_pending(kind, witness_intent, new_intent, None, false, &envelope)?;
        let inject = self.take_lease_commit_fault();
        let transaction = durable_write(&self.database)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| RepositoryError::CorruptStore)?;
            if decode_head_from_meta(&meta)? != witness_intent.expected() {
                return Err(RepositoryError::StaleReservation);
            }
            meta.insert(META_PENDING, encoded.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
        }
        authority_journal::require_terminal(&transaction, identity)?;
        authority_journal::prepare(&transaction, identity, new_intent)?;
        self.finish_authority_journal_commit(transaction, inject)?;
        let prepared = self
            .pending
            .as_mut()
            .ok_or(RepositoryError::NoPendingTransition)?;
        prepared.authority_intent = new_intent;
        prepared.authority_receipt = None;
        prepared.authority_acknowledged = false;
        Ok(CoordinatedTransition {
            witness_intent,
            authority_intent: new_intent,
            authority_receipt: None,
            authority_acknowledged: false,
        })
    }

    /// Finish the local transaction only after exact authority and witness application.
    pub(crate) fn commit_applied(
        &mut self,
        receipt: WitnessReceipt,
    ) -> Result<CommittedTransition, RepositoryError> {
        let (witness_intent, expected_identity, next_identity, generation, entry) = {
            let prepared = self
                .pending
                .as_ref()
                .ok_or(RepositoryError::NoPendingTransition)?;
            if !receipt.is_exact_applied(prepared.intent) {
                return Err(RepositoryError::WitnessMismatch);
            }
            if read_head(&self.database)? != prepared.intent.expected() {
                return Err(RepositoryError::StaleReservation);
            }
            let authority_receipt = match prepared.authority_receipt {
                Some(authority_receipt)
                    if authority_receipt.intent() == prepared.authority_intent
                        && authority_receipt.disposition() == AuthorityDispositionV2::Applied
                        && prepared.authority_acknowledged =>
                {
                    authority_receipt
                }
                _ => return Err(RepositoryError::LeaseReceiptMismatch),
            };
            let expected_identity = self.authority_identity()?;
            let next_authority_head = match authority_receipt.intent().mutation() {
                AuthorityMutationV2::AdvanceState { advance, .. }
                    if advance.expected() == expected_identity.state_head() =>
                {
                    advance.next()
                }
                _ => return Err(RepositoryError::AuthorityBindingMismatch),
            };
            (
                prepared.intent,
                expected_identity,
                expected_identity.at_state_head(next_authority_head),
                prepared.intent.next().revision().global_generation(),
                encode_journal_entry(prepared.kind, &prepared.envelope)?,
            )
        };
        let inject = self.take_lease_commit_fault();
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
            if transaction_head != witness_intent.expected()
                || history
                    .get(&generation)
                    .map_err(|_| RepositoryError::CorruptStore)?
                    .is_some()
            {
                return Err(RepositoryError::StaleReservation);
            }
            history
                .insert(&generation, entry.as_slice())
                .map_err(|_| RepositoryError::CorruptStore)?;
            meta.insert(META_HEAD, witness_intent.next().to_bytes().as_slice())
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
        authority_journal::require_terminal(&transaction, expected_identity)?;
        authority_journal::advance_binding(&transaction, expected_identity, next_identity)?;
        if transaction.commit().is_err() || inject {
            self.authority_journal_poisoned = true;
            return Err(RepositoryError::CommitUncertain);
        }
        let prepared = self
            .pending
            .take()
            .ok_or(RepositoryError::RepositoryPoisoned)?;
        self.machine.commit(prepared.token).map_err(|_| {
            self.authority_journal_poisoned = true;
            RepositoryError::RepositoryPoisoned
        })?;
        Ok(CommittedTransition {
            expected_identity,
            next_identity,
        })
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
            .map_err(|_| RepositoryError::CorruptStore)
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
            .map_err(|_| RepositoryError::CorruptStore)
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
            .map_err(|_| RepositoryError::CorruptStore)
    }

    fn persist_prepared(
        &mut self,
        kind: JournalKind,
        envelope: &[u8],
        token: PendingMigrationCommitV1,
        authority_version: u64,
        instance_fence: InstanceFenceV2,
    ) -> Result<CoordinatedTransition, RepositoryError> {
        self.ensure_authority_journal_live()?;
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
        let identity = self.authority_identity()?;
        let expected_authority_head =
            project_authority_head(self.machine.current().state(), intent.expected())?;
        if identity.state_head() != expected_authority_head {
            return Err(RepositoryError::AuthorityBindingMismatch);
        }
        let next_authority_head = project_authority_head(token.next_state(), intent.next())?;
        let authority_kind = match token.kind() {
            PendingMigrationCommitKind::Advance => StateTransitionKindV2::Advance,
            PendingMigrationCommitKind::Reset => StateTransitionKindV2::AuthorizedReset,
        };
        let authority_advance =
            StateAdvanceV2::new(authority_kind, expected_authority_head, next_authority_head)
                .map_err(|_| RepositoryError::InvalidCertificate)?;
        let authority_intent = AuthorityIntentV2::new(
            fresh_authority_operation_id(authority_version)?,
            authority_version,
            identity.config(),
            AuthorityMutationV2::AdvanceState {
                fence: instance_fence,
                advance: authority_advance,
            },
        )
        .map_err(|_| RepositoryError::InvalidCertificate)?;
        let encoded = encode_pending(kind, intent, authority_intent, None, false, envelope)?;
        let inject = self.take_lease_commit_fault();
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
        authority_journal::prepare(&transaction, identity, authority_intent)?;
        self.finish_authority_journal_commit(transaction, inject)?;
        self.pending = Some(PreparedTransition {
            token,
            intent,
            authority_intent,
            authority_receipt: None,
            authority_acknowledged: false,
            kind,
            envelope: envelope.to_vec(),
        });
        Ok(CoordinatedTransition {
            witness_intent: intent,
            authority_intent,
            authority_receipt: None,
            authority_acknowledged: false,
        })
    }
}

struct PendingRecord {
    kind: JournalKind,
    intent: WitnessIntent,
    authority_intent: AuthorityIntentV2,
    authority_receipt: Option<AuthorityReceiptV2>,
    authority_acknowledged: bool,
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
    if read_schema(database)? != REPOSITORY_STORAGE_SCHEMA {
        return Err(RepositoryError::CorruptStore);
    }
    Ok(())
}

fn read_schema(database: &Database) -> Result<[u8; 2], RepositoryError> {
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
    schema
        .value()
        .try_into()
        .map_err(|_| RepositoryError::CorruptStore)
}

fn validate_authenticated_repository(
    database: &Database,
    roots: &MigrationTrustRoots,
) -> Result<(), RepositoryError> {
    let machine = replay_history(database, roots)?;
    let durable_head = read_head(database)?;
    if project_revision(machine.current_revision())? != durable_head.revision() {
        return Err(RepositoryError::InvalidHistory);
    }
    let pending = read_pending(database)?
        .map(|record| reconstruct_pending(&machine, roots, record))
        .transpose()?;
    if matches!(pending.as_ref(), Some(value) if value.intent.expected() != durable_head) {
        return Err(RepositoryError::InvalidHistory);
    }
    validate_sessions(database)?;
    validate_used_capabilities(database, durable_head)?;
    validate_coordinator_binding(database, &machine, pending.as_ref(), durable_head)
}

fn validate_repository_without_coordinator(
    database: &Database,
    roots: &MigrationTrustRoots,
) -> Result<(MigrationStateMachineV1, StateHead), RepositoryError> {
    let machine = replay_history(database, roots)?;
    let durable_head = read_head(database)?;
    if project_revision(machine.current_revision())? != durable_head.revision()
        || raw_pending_exists(database)?
    {
        return Err(RepositoryError::InvalidHistory);
    }
    validate_sessions(database)?;
    validate_used_capabilities(database, durable_head)?;
    Ok((machine, durable_head))
}

fn validate_coordinator_binding(
    database: &Database,
    machine: &MigrationStateMachineV1,
    pending: Option<&PreparedTransition>,
    durable_head: StateHead,
) -> Result<(), RepositoryError> {
    let identity = authority_journal::bound_identity(database)?
        .ok_or(RepositoryError::AuthorityBindingMismatch)?;
    if identity.state_head() != project_authority_head(machine.current().state(), durable_head)? {
        return Err(RepositoryError::AuthorityBindingMismatch);
    }
    let active = authority_journal::active(database, identity)?;
    let Some(pending) = pending else {
        if active.is_some_and(|operation| match operation {
            DurableAuthorityOperation::Prepared(intent) => {
                matches!(intent.mutation(), AuthorityMutationV2::AdvanceState { .. })
            }
            DurableAuthorityOperation::Resolved(receipt) => matches!(
                receipt.intent().mutation(),
                AuthorityMutationV2::AdvanceState { .. }
            ),
        }) {
            return Err(RepositoryError::InvalidHistory);
        }
        return Ok(());
    };
    if pending.authority_intent.expected_config() != identity.config()
        || !matches!(
            pending.authority_intent.mutation(),
            AuthorityMutationV2::AdvanceState { advance, .. }
                if advance.expected() == identity.state_head()
        )
    {
        return Err(RepositoryError::AuthorityBindingMismatch);
    }
    match (
        pending.authority_receipt,
        pending.authority_acknowledged,
        active,
    ) {
        (None, false, Some(DurableAuthorityOperation::Prepared(intent)))
            if intent == pending.authority_intent =>
        {
            Ok(())
        }
        (Some(expected), false, Some(DurableAuthorityOperation::Resolved(actual)))
            if expected == actual =>
        {
            Ok(())
        }
        (Some(_), true, None) => Ok(()),
        (Some(receipt), true, Some(operation))
            if matches!(
                receipt.disposition(),
                AuthorityDispositionV2::Rejected(
                    crate::authority::AuthorityRejectionV2::LeaseAbsent
                        | crate::authority::AuthorityRejectionV2::LeaseExpired
                        | crate::authority::AuthorityRejectionV2::FenceMismatch
                )
            ) && !matches!(
                operation,
                DurableAuthorityOperation::Prepared(intent)
                    if matches!(intent.mutation(), AuthorityMutationV2::AdvanceState { .. })
            ) && !matches!(
                operation,
                DurableAuthorityOperation::Resolved(actual)
                    if matches!(actual.intent().mutation(), AuthorityMutationV2::AdvanceState { .. })
            ) =>
        {
            Ok(())
        }
        _ => Err(RepositoryError::InvalidHistory),
    }
}

fn raw_pending_exists(database: &Database) -> Result<bool, RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let meta = transaction
        .open_table(META_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    Ok(meta
        .get(META_PENDING)
        .map_err(|_| RepositoryError::CorruptStore)?
        .is_some())
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
    let expected_authority_head =
        project_authority_head(machine.current().state(), record.intent.expected())?;
    let next_authority_head = project_authority_head(token.next_state(), record.intent.next())?;
    let expected_kind = match token.kind() {
        PendingMigrationCommitKind::Advance => StateTransitionKindV2::Advance,
        PendingMigrationCommitKind::Reset => StateTransitionKindV2::AuthorizedReset,
    };
    let authority_advance = match record.authority_intent.mutation() {
        AuthorityMutationV2::AdvanceState { advance, .. } => advance,
        _ => return Err(RepositoryError::InvalidHistory),
    };
    if authority_advance
        != StateAdvanceV2::new(expected_kind, expected_authority_head, next_authority_head)
            .map_err(|_| RepositoryError::InvalidHistory)?
        || record
            .authority_receipt
            .is_some_and(|receipt| receipt.intent() != record.authority_intent)
        || (record.authority_acknowledged && record.authority_receipt.is_none())
    {
        return Err(RepositoryError::InvalidHistory);
    }
    Ok(PreparedTransition {
        token,
        intent: record.intent,
        authority_intent: record.authority_intent,
        authority_receipt: record.authority_receipt,
        authority_acknowledged: record.authority_acknowledged,
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

fn project_authority_head(
    state: q_periapt_migration::MigrationStateV1,
    head: StateHead,
) -> Result<StateHeadV2, RepositoryError> {
    let revision = head.revision();
    let digest = state
        .digest()
        .map_err(|_| RepositoryError::InvalidHistory)?;
    if state.global_generation() != revision.global_generation()
        || state.epoch() != revision.epoch()
        || digest.as_bytes() != revision.digest()
    {
        return Err(RepositoryError::InvalidHistory);
    }
    let authority_revision = StateRevisionV2::new(
        revision.global_generation(),
        *state.chain_id().as_bytes(),
        revision.epoch(),
        *revision.digest(),
    )
    .map_err(|_| RepositoryError::InvalidHistory)?;
    let authority_fence = StateFenceV2::from_bytes(*head.fence().as_bytes())
        .map_err(|_| RepositoryError::InvalidHistory)?;
    Ok(StateHeadV2::new(authority_revision, authority_fence))
}

fn fresh_authority_operation_id(authority_version: u64) -> Result<OperationIdV2, RepositoryError> {
    for _ in 0..4 {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| RepositoryError::EntropyUnavailable)?;
        if random.iter().any(|byte| *byte != 0) {
            return OperationIdV2::new(authority_version, random)
                .map_err(|_| RepositoryError::InvalidHistory);
        }
    }
    Err(RepositoryError::EntropyUnavailable)
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

fn validate_sessions(database: &Database) -> Result<(), RepositoryError> {
    let transaction = database
        .begin_read()
        .map_err(|_| RepositoryError::CorruptStore)?;
    let sessions = transaction
        .open_table(SESSION_TABLE)
        .map_err(|_| RepositoryError::CorruptStore)?;
    if sessions.len().map_err(|_| RepositoryError::CorruptStore)? > MAX_DURABLE_SESSIONS {
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
    Ok(())
}

fn reject_restart_sessions(database: &Database) -> Result<u64, RepositoryError> {
    validate_sessions(database)?;
    let transaction = durable_write(database)?;
    let count = {
        let mut sessions = transaction
            .open_table(SESSION_TABLE)
            .map_err(|_| RepositoryError::CorruptStore)?;
        let count = sessions.len().map_err(|_| RepositoryError::CorruptStore)?;
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

fn encode_journal_entry(kind: JournalKind, envelope: &[u8]) -> Result<Vec<u8>, RepositoryError> {
    if envelope.is_empty() || envelope.len() > MAX_FRAME_BYTES {
        return Err(RepositoryError::InvalidCertificate);
    }
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(
        &mut encoder,
        REPOSITORY_DOMAIN,
        REPOSITORY_RECORD_SCHEMA_VERSION,
    )
    .map_err(map_codec)?;
    encoder.byte(kind as u8).map_err(map_codec)?;
    encoder.lp16(envelope).map_err(map_codec)?;
    Ok(encoder.finish())
}

fn decode_journal_entry(bytes: &[u8]) -> Result<(JournalKind, &[u8]), RepositoryError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(
        &mut decoder,
        REPOSITORY_DOMAIN,
        REPOSITORY_RECORD_SCHEMA_VERSION,
    )
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
    authority_intent: AuthorityIntentV2,
    authority_receipt: Option<AuthorityReceiptV2>,
    authority_acknowledged: bool,
    envelope: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    if authority_acknowledged && authority_receipt.is_none() {
        return Err(RepositoryError::LeaseReceiptMismatch);
    }
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, PENDING_DOMAIN, PENDING_SCHEMA_VERSION).map_err(map_codec)?;
    encoder.byte(kind as u8).map_err(map_codec)?;
    intent.encode(&mut encoder).map_err(map_codec)?;
    encode_intent(&mut encoder, authority_intent).map_err(map_authority_codec)?;
    match authority_receipt {
        Some(receipt) => {
            encoder.byte(1).map_err(map_codec)?;
            let encoded_receipt = encode_receipt(receipt).map_err(map_authority_codec)?;
            encoder.lp16(&encoded_receipt).map_err(map_codec)?;
        }
        None => encoder.byte(0).map_err(map_codec)?,
    }
    encoder
        .byte(u8::from(authority_acknowledged))
        .map_err(map_codec)?;
    encoder.lp16(envelope).map_err(map_codec)?;
    Ok(encoder.finish())
}

fn decode_pending(bytes: &[u8]) -> Result<PendingRecord, RepositoryError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, PENDING_DOMAIN, PENDING_SCHEMA_VERSION).map_err(map_codec)?;
    let kind = JournalKind::from_u8(decoder.byte().map_err(map_codec)?)
        .filter(|kind| *kind != JournalKind::Genesis)
        .ok_or(RepositoryError::CorruptStore)?;
    let intent = WitnessIntent::decode(&mut decoder).map_err(map_codec)?;
    let authority_intent = decode_intent(&mut decoder).map_err(map_authority_codec)?;
    let authority_receipt = match decoder.byte().map_err(map_codec)? {
        0 => None,
        1 => Some(
            decode_receipt(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?)
                .map_err(map_authority_codec)?,
        ),
        _ => return Err(RepositoryError::CorruptStore),
    };
    let authority_acknowledged = match decoder.byte().map_err(map_codec)? {
        0 => false,
        1 if authority_receipt.is_some() => true,
        _ => return Err(RepositoryError::CorruptStore),
    };
    let envelope = decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?.to_vec();
    if envelope.is_empty() {
        return Err(RepositoryError::CorruptStore);
    }
    decoder.finish().map_err(map_codec)?;
    Ok(PendingRecord {
        kind,
        intent,
        authority_intent,
        authority_receipt,
        authority_acknowledged,
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

fn map_authority_codec(_: crate::authority_codec::AuthorityCodecError) -> RepositoryError {
    RepositoryError::CorruptStore
}
