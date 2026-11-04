// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Private directory allocation ledger. A receipt is history, not live permission.
//!
//! The host supplies independent authorization and a trusted current clock. Neither
//! a connection nor the requester identifier in a request grants authorization.
//! Storage errors poison this owner: drop it and open the original database.
//! Expiry and cancellation never release either physical one-time key.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("directory_configuration");
const OPERATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("directory_operations");
const CLASSICAL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("directory_classical");
const POST_QUANTUM: TableDefinition<&[u8], &[u8]> = TableDefinition::new("directory_post_quantum");
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// A trusted provisioner may choose a smaller bound, never a larger one.
pub const MAX_OPERATIONS: u64 = 4096;

#[derive(Debug)]
pub enum Error {
    Invalid,
    Conflict,
    Capacity,
    KeyAlreadyReserved,
    Unauthorized,
    Clock,
    Cancelled,
    ReopenRequired,
    CorruptState,
    /// The transaction committed. Inspect the original operation; do not reassign its keys.
    CommittedAuthorizationLost,
    Protocol(sdk::Error),
    Storage(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<sdk::Error> for Error {
    fn from(error: sdk::Error) -> Self {
        Self::Protocol(error)
    }
}
impl From<q_periapt_host_store::filesystem::PrivateDatabaseError> for Error {
    fn from(error: q_periapt_host_store::filesystem::PrivateDatabaseError) -> Self {
        storage(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Issue,
    Cancel,
}

/// Implement this using independently authenticated, current host authority.
/// The request is the exact subject of the decision, never its source of trust.
pub trait DirectoryAuthorization {
    fn authorize(
        &self,
        action: Action,
        request: &sdk::DirectoryLeaseRequest,
        now: u64,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub struct LeaseRecord {
    wire: Vec<u8>,
    cancelled: bool,
}
impl LeaseRecord {
    /// Original signed bytes, including after cancellation or expiration.
    /// Current use requires DirectoryPin::verify_lease and current host authorization.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    service_binding: [u8; 32],
    limit: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRecord {
    schema: u32,
    wire: Vec<u8>,
    cancelled: bool,
}
impl SavedRecord {
    fn public(self) -> LeaseRecord {
        LeaseRecord {
            wire: self.wire,
            cancelled: self.cancelled,
        }
    }
}

pub struct DirectoryLedger {
    db: Database,
    pin: sdk::DirectoryPin,
    limit: u64,
    failed: bool,
}
impl DirectoryLedger {
    /// Explicit initialization. Never use this to recover a missing original ledger.
    pub fn provision(path: &Path, pin: &sdk::DirectoryPin, limit: u64) -> Result<Self, Error> {
        if limit == 0 || limit > MAX_OPERATIONS {
            return Err(Error::Invalid);
        }
        let config = encode(&Configuration {
            schema: 1,
            service_binding: pin.binding(),
            limit,
        })?;
        let db = provision_private_database(path, |db| {
            let tx = transaction(db)?;
            tx.open_table(CONFIG)
                .map_err(storage)?
                .insert("state", config.as_slice())
                .map_err(storage)?;
            tx.open_table(OPERATIONS).map_err(storage)?;
            tx.open_table(CLASSICAL).map_err(storage)?;
            tx.open_table(POST_QUANTUM).map_err(storage)?;
            tx.commit().map_err(storage)
        })?;
        Ok(Self {
            db,
            pin: pin.clone(),
            limit,
            failed: false,
        })
    }

    /// Open only the original private database with an independently supplied service pin.
    /// Every retained receipt and both occupancy indexes are checked before use.
    pub fn open(path: &Path, pin: &sdk::DirectoryPin) -> Result<Self, Error> {
        let db = open_private_database(path)?;
        let limit = validate_database(&db, pin)?;
        Ok(Self {
            db,
            pin: pin.clone(),
            limit,
            failed: false,
        })
    }

    /// Historical reconciliation. No live-policy or expiry check can hide a committed receipt.
    /// Access to this private owner must itself be restricted by the host.
    pub fn lookup(&mut self, operation: [u8; 32]) -> Result<Option<LeaseRecord>, Error> {
        self.action(|owner| {
            owner
                .read(operation)
                .map(|record| record.map(SavedRecord::public))
        })
    }

    /// Allocate both physical one-time keys atomically with the original signed receipt.
    ///
    /// Exact retries return the first wire without signing again, even after expiry or
    /// capacity exhaustion. A cancelled operation is terminal; use lookup for its history.
    /// The trusted clock is read again after commit. Any resulting authorization or live
    /// verification failure leaves all committed state intact and reports that fact.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        key: &sdk::DirectorySigningKey,
        request: sdk::DirectoryLeaseRequest,
        selection: &sdk::AuthenticatedPrekeySelection,
        device: &sdk::VerifiedDevice,
        policy: &sdk::VerifiedSessionPolicy,
        authorization: &impl DirectoryAuthorization,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<LeaseRecord, Error> {
        self.action(|owner| {
            let now = clock()?;
            authorization.authorize(Action::Issue, &request, now)?;
            if let Some(record) = owner.read(request.operation())? {
                let verified = owner.pin.verify_historical_lease(&record.wire)?;
                if !verified.matches_request(request, selection) {
                    return Err(Error::Conflict);
                }
                if record.cancelled {
                    return Err(Error::Cancelled);
                }
                authorization.authorize(Action::Issue, &request, clock()?)?;
                return Ok(record.public());
            }
            let classical = selection.classical().key_fingerprint();
            let post_quantum = selection.post_quantum().key_fingerprint();
            let tx = transaction(&owner.db)?;
            {
                let operations = tx.open_table(OPERATIONS).map_err(storage)?;
                if operations.len().map_err(storage)? >= owner.limit {
                    return Err(Error::Capacity);
                }
                if tx
                    .open_table(CLASSICAL)
                    .map_err(storage)?
                    .get(classical.as_slice())
                    .map_err(storage)?
                    .is_some()
                    || tx
                        .open_table(POST_QUANTUM)
                        .map_err(storage)?
                        .get(post_quantum.as_slice())
                        .map_err(storage)?
                        .is_some()
                {
                    return Err(Error::KeyAlreadyReserved);
                }
            }
            let signing_time = clock()?;
            authorization.authorize(Action::Issue, &request, signing_time)?;
            let issued =
                key.issue_lease(&owner.pin, request, selection, device, policy, signing_time)?;
            let record = SavedRecord {
                schema: 1,
                wire: issued.as_bytes().to_vec(),
                cancelled: false,
            };
            let encoded = encode(&record)?;
            let operation = request.operation();
            {
                tx.open_table(OPERATIONS)
                    .map_err(storage)?
                    .insert(operation.as_slice(), encoded.as_slice())
                    .map_err(storage)?;
                tx.open_table(CLASSICAL)
                    .map_err(storage)?
                    .insert(classical.as_slice(), operation.as_slice())
                    .map_err(storage)?;
                tx.open_table(POST_QUANTUM)
                    .map_err(storage)?
                    .insert(post_quantum.as_slice(), operation.as_slice())
                    .map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            let current = clock().map_err(|_| Error::CommittedAuthorizationLost)?;
            if authorization
                .authorize(Action::Issue, &request, current)
                .is_err()
                || owner
                    .pin
                    .verify_lease(&record.wire, request, selection, device, policy, current)
                    .is_err()
            {
                return Err(Error::CommittedAuthorizationLost);
            }
            Ok(record.public())
        })
    }

    /// Cancellation is a permanent host state. It does not erase or revoke signed bytes.
    /// A current, independent cancellation decision is required even for an exact retry.
    pub fn cancel(
        &mut self,
        operation: [u8; 32],
        authorization: &impl DirectoryAuthorization,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<LeaseRecord, Error> {
        self.action(|owner| {
            let mut record = owner.read(operation)?.ok_or(Error::Conflict)?;
            let verified = owner.pin.verify_historical_lease(&record.wire)?;
            let request = verified.request();
            authorization.authorize(Action::Cancel, &request, clock()?)?;
            if record.cancelled {
                return Ok(record.public());
            }
            record.cancelled = true;
            let encoded = encode(&record)?;
            let tx = transaction(&owner.db)?;
            tx.open_table(OPERATIONS)
                .map_err(storage)?
                .insert(operation.as_slice(), encoded.as_slice())
                .map_err(storage)?;
            tx.commit().map_err(storage)?;
            let current = clock().map_err(|_| Error::CommittedAuthorizationLost)?;
            authorization
                .authorize(Action::Cancel, &request, current)
                .map_err(|_| Error::CommittedAuthorizationLost)?;
            Ok(record.public())
        })
    }

    fn action<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.failed {
            return Err(Error::ReopenRequired);
        }
        // An unwind may hide a committed effect. Only an ordinary, known result
        // may restore this owner; callers catching a panic must reopen the original.
        self.failed = true;
        let result = action(self);
        if !matches!(result, Err(Error::Storage(_) | Error::CorruptState)) {
            self.failed = false;
        }
        result
    }

    fn read(&self, operation: [u8; 32]) -> Result<Option<SavedRecord>, Error> {
        if operation == [0; 32] {
            return Err(Error::Invalid);
        }
        let tx = self.db.begin_read().map_err(storage)?;
        let operations = tx.open_table(OPERATIONS).map_err(storage)?;
        let Some(value) = operations.get(operation.as_slice()).map_err(storage)? else {
            return Ok(None);
        };
        let record: SavedRecord = decode(value.value())?;
        let verified = self
            .pin
            .verify_historical_lease(&record.wire)
            .map_err(|_| Error::CorruptState)?;
        if record.schema != 1 || verified.request().operation() != operation {
            return Err(Error::CorruptState);
        }
        Ok(Some(record))
    }
}

fn transaction(db: &Database) -> Result<redb::WriteTransaction, Error> {
    let mut tx = db.begin_write().map_err(storage)?;
    tx.set_durability(redb::Durability::Immediate)
        .map_err(storage)?;
    tx.set_two_phase_commit(true);
    Ok(tx)
}

fn validate_database(db: &Database, pin: &sdk::DirectoryPin) -> Result<u64, Error> {
    let tx = db.begin_read().map_err(storage)?;
    let mut names: Vec<_> = tx
        .list_tables()
        .map_err(storage)?
        .map(|table| table.name().to_owned())
        .collect();
    names.sort();
    let mut expected = vec![
        CONFIG.name(),
        OPERATIONS.name(),
        CLASSICAL.name(),
        POST_QUANTUM.name(),
    ];
    expected.sort();
    if names != expected || tx.list_multimap_tables().map_err(storage)?.next().is_some() {
        return Err(Error::Conflict);
    }
    let config_table = tx.open_table(CONFIG).map_err(storage)?;
    if config_table.len().map_err(storage)? != 1 {
        return Err(Error::Conflict);
    }
    let config: Configuration = decode(
        config_table
            .get("state")
            .map_err(storage)?
            .ok_or(Error::Conflict)?
            .value(),
    )?;
    if config.schema != 1
        || config.service_binding != pin.binding()
        || config.limit == 0
        || config.limit > MAX_OPERATIONS
    {
        return Err(Error::Conflict);
    }
    let operations = tx.open_table(OPERATIONS).map_err(storage)?;
    let classical = tx.open_table(CLASSICAL).map_err(storage)?;
    let post_quantum = tx.open_table(POST_QUANTUM).map_err(storage)?;
    let count = operations.len().map_err(storage)?;
    if count > config.limit
        || classical.len().map_err(storage)? != count
        || post_quantum.len().map_err(storage)? != count
    {
        return Err(Error::Conflict);
    }
    for entry in operations.iter().map_err(storage)? {
        let (operation, bytes) = entry.map_err(storage)?;
        let record: SavedRecord = decode(bytes.value())?;
        let verified = pin.verify_historical_lease(&record.wire)?;
        let request = verified.request();
        if record.schema != 1 || request.operation().as_slice() != operation.value() {
            return Err(Error::Conflict);
        }
        let classical_key = verified.classical_fingerprint();
        let post_quantum_key = verified.post_quantum_fingerprint();
        if classical
            .get(classical_key.as_slice())
            .map_err(storage)?
            .is_none_or(|value| value.value() != operation.value())
            || post_quantum
                .get(post_quantum_key.as_slice())
                .map_err(storage)?
                .is_none_or(|value| value.value() != operation.value())
        {
            return Err(Error::Conflict);
        }
    }
    Ok(config.limit)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(storage)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::CorruptState);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::CorruptState)
}

fn storage(error: impl std::fmt::Display) -> Error {
    Error::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct PrivateDirectory {
        _temporary: tempfile::TempDir,
        path: std::path::PathBuf,
    }
    impl PrivateDirectory {
        fn path(&self) -> &Path {
            &self.path
        }
    }
    fn private_directory() -> TestResult<PrivateDirectory> {
        let temporary = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        // macOS temporary paths may include a symlink; production storage
        // requires a canonical absolute parent as well as private permissions.
        let path = temporary.path().canonicalize()?;
        Ok(PrivateDirectory {
            _temporary: temporary,
            path,
        })
    }

    struct Permit;
    impl DirectoryAuthorization for Permit {
        fn authorize(
            &self,
            _action: Action,
            _request: &sdk::DirectoryLeaseRequest,
            _now: u64,
        ) -> Result<(), Error> {
            Ok(())
        }
    }
    struct Deny;
    impl DirectoryAuthorization for Deny {
        fn authorize(
            &self,
            _action: Action,
            _request: &sdk::DirectoryLeaseRequest,
            _now: u64,
        ) -> Result<(), Error> {
            Err(Error::Unauthorized)
        }
    }
    struct Until(u64);
    impl DirectoryAuthorization for Until {
        fn authorize(
            &self,
            _action: Action,
            _request: &sdk::DirectoryLeaseRequest,
            now: u64,
        ) -> Result<(), Error> {
            if now < self.0 {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            }
        }
    }

    struct Fixture {
        runtime: Arc<q_periapt_sdk::Runtime>,
        signer: sdk::DeviceSigningKey,
        device: sdk::VerifiedDevice,
        policy: sdk::VerifiedSessionPolicy,
        key: sdk::DirectorySigningKey,
        pin: sdk::DirectoryPin,
    }
    impl Fixture {
        fn new() -> TestResult<Self> {
            let runtime = crate::test_support::sdk_input()?.verify()?;
            let validity = sdk::Validity::new(100, 200)?;
            let policy_signer = sdk::PolicySigningKey::generate()?;
            let issued = policy_signer.issue_session_policy(
                &runtime,
                sdk::SessionPolicyParameters::new(
                    1,
                    validity,
                    sdk::AllowedPrekeyModes::new(&[sdk::PrekeyQuality::OneTimeBoth])?,
                    sdk::AnchorRequirement::local_only(),
                    sdk::ApplicationSendBudget::new(1024)?,
                )?,
            )?;
            let policy = sdk::PolicyPin::new(
                policy_signer.policy_family()?,
                policy_signer.public_key()?,
                issued.checkpoint(),
            )?
            .verify(issued.as_bytes(), Arc::clone(&runtime), 150)?;
            let root = sdk::RootSigningKey::generate()?;
            let signer = sdk::DeviceSigningKey::generate()?;
            let certificate = root.issue_device(
                sdk::DeviceDescription::new([5; 16], 1, policy.family(), validity)?,
                signer.public_key()?,
            )?;
            let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
            let device = sdk::AccountPin::new(
                root.account_id()?,
                root.public_key()?,
                roster.checkpoint(),
                policy.family(),
            )?
            .verify_device(&certificate, roster.as_bytes(), 150)?;
            let key = sdk::DirectorySigningKey::generate()?;
            let pin = sdk::DirectoryPin::new([9; 32], key.public_key()?)?;
            Ok(Self {
                runtime,
                signer,
                device,
                policy,
                key,
                pin,
            })
        }

        fn selection(
            &self,
            epoch: u64,
            classical: u8,
            post_quantum: u8,
        ) -> TestResult<sdk::AuthenticatedPrekeySelection> {
            let validity = sdk::Validity::new(100, 200)?;
            let context = sdk::ManifestContext::new(
                epoch,
                self.runtime.trusted_state().digest(),
                sdk::bootstrap_suite_digest(),
                [8; 32],
                validity,
            )?;
            // Receipt qualification authenticates exact public bytes. KEM admission
            // and mathematical key validation belong to the later SDK use boundary.
            let leaves = [
                sdk::PrekeyLeaf::new(sdk::LeafKind::SignedClassical, &[71; 32], validity)?,
                sdk::PrekeyLeaf::new(sdk::LeafKind::OneTimeClassical, &[classical; 32], validity)?,
                sdk::PrekeyLeaf::new(sdk::LeafKind::LastResortPq, &[72; 1184], validity)?,
                sdk::PrekeyLeaf::new(sdk::LeafKind::OneTimePq, &[post_quantum; 1184], validity)?,
            ];
            let issued = self.signer.issue_manifest(&self.device, context, &leaves)?;
            let manifest = self.device.verify_manifest(issued.as_bytes(), 150)?;
            let mut signed = None;
            let mut last = None;
            let mut once_classical = None;
            let mut once_pq = None;
            for index in 0..issued.leaf_count() {
                let proof = issued.proof(index)?;
                match manifest.verify_leaf(&proof, 150)?.kind() {
                    sdk::LeafKind::SignedClassical => signed = Some(proof),
                    sdk::LeafKind::LastResortPq => last = Some(proof),
                    sdk::LeafKind::OneTimeClassical => once_classical = Some(proof),
                    sdk::LeafKind::OneTimePq => once_pq = Some(proof),
                }
            }
            Ok(manifest.select_prekeys(
                &signed.ok_or("signed leaf")?,
                &last.ok_or("last-resort leaf")?,
                sdk::ClassicalChoice::OneTime(&once_classical.ok_or("classical leaf")?),
                sdk::PqChoice::OneTime(&once_pq.ok_or("PQ leaf")?),
                150,
            )?)
        }

        fn request(&self, operation: u8, requester: u8) -> TestResult<sdk::DirectoryLeaseRequest> {
            Ok(sdk::DirectoryLeaseRequest::new(
                [operation; 32],
                [requester; 32],
                [8; 32],
                sdk::Validity::new(140, 180)?,
            )?)
        }

        fn issue(
            &self,
            ledger: &mut DirectoryLedger,
            request: sdk::DirectoryLeaseRequest,
            selection: &sdk::AuthenticatedPrekeySelection,
        ) -> Result<LeaseRecord, Error> {
            ledger.issue(
                &self.key,
                request,
                selection,
                &self.device,
                &self.policy,
                &Permit,
                || Ok(150),
            )
        }
    }

    #[test]
    fn original_wire_survives_reopen_expiry_capacity_and_changed_signer() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let path = directory.path().join("directory.redb");
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 1)?;
        let original = fixture.issue(&mut ledger, request, &selection)?;
        drop(ledger);
        let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
        let unrelated_signer = sdk::DirectorySigningKey::generate()?;
        let historical = ledger.issue(
            &unrelated_signer,
            request,
            &selection,
            &fixture.device,
            &fixture.policy,
            &Permit,
            || Ok(250),
        )?;
        assert_eq!(historical.wire(), original.wire());
        assert!(!historical.cancelled());
        let fresh = fixture.selection(2, 13, 14)?;
        assert!(matches!(
            fixture.issue(&mut ledger, fixture.request(3, 4)?, &fresh),
            Err(Error::Capacity)
        ));
        assert_eq!(
            ledger
                .lookup(request.operation())?
                .ok_or("missing history")?
                .wire(),
            original.wire()
        );
        Ok(())
    }

    #[test]
    fn operation_conflicts_and_each_cross_epoch_physical_key_are_rejected() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let path = directory.path().join("directory.redb");
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
        fixture.issue(&mut ledger, request, &selection)?;
        for changed in [
            fixture.request(1, 3)?,
            sdk::DirectoryLeaseRequest::new(
                request.operation(),
                request.requester(),
                [7; 32],
                request.validity(),
            )?,
            sdk::DirectoryLeaseRequest::new(
                request.operation(),
                request.requester(),
                request.checkpoint(),
                sdk::Validity::new(141, 180)?,
            )?,
        ] {
            assert!(matches!(
                fixture.issue(&mut ledger, changed, &selection),
                Err(Error::Conflict)
            ));
        }
        let changed_selection = fixture.selection(2, 13, 14)?;
        assert!(matches!(
            fixture.issue(&mut ledger, request, &changed_selection),
            Err(Error::Conflict)
        ));
        for (epoch, classical, pq) in [(2, 11, 14), (3, 13, 12), (4, 11, 12)] {
            let selection = fixture.selection(epoch, classical, pq)?;
            assert!(matches!(
                fixture.issue(&mut ledger, fixture.request(epoch as u8, 5)?, &selection),
                Err(Error::KeyAlreadyReserved)
            ));
        }
        drop(ledger);
        let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
        assert!(ledger.lookup(request.operation())?.is_some());
        assert!(ledger.lookup([2; 32])?.is_none());
        Ok(())
    }

    #[test]
    fn cancellation_requires_current_authority_and_never_releases_keys() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let path = directory.path().join("directory.redb");
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
        assert!(matches!(
            ledger.issue(
                &fixture.key,
                request,
                &selection,
                &fixture.device,
                &fixture.policy,
                &Deny,
                || Ok(150),
            ),
            Err(Error::Unauthorized)
        ));
        assert!(ledger.lookup(request.operation())?.is_none());
        let original = fixture.issue(&mut ledger, request, &selection)?;
        assert!(matches!(
            ledger.cancel(request.operation(), &Deny, || Ok(150)),
            Err(Error::Unauthorized)
        ));
        assert!(!ledger
            .lookup(request.operation())?
            .ok_or("missing")?
            .cancelled());
        let cancelled = ledger.cancel(request.operation(), &Permit, || Ok(150))?;
        assert!(cancelled.cancelled());
        assert_eq!(cancelled.wire(), original.wire());
        assert_eq!(
            ledger
                .cancel(request.operation(), &Permit, || Ok(250))?
                .wire(),
            original.wire()
        );
        assert!(matches!(
            ledger.cancel(request.operation(), &Deny, || Ok(250)),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            fixture.issue(&mut ledger, request, &selection),
            Err(Error::Cancelled)
        ));
        drop(ledger);
        let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
        assert!(ledger
            .lookup(request.operation())?
            .ok_or("missing")?
            .cancelled());
        let later = fixture.selection(2, 11, 12)?;
        assert!(matches!(
            fixture.issue(&mut ledger, fixture.request(3, 4)?, &later),
            Err(Error::KeyAlreadyReserved)
        ));
        Ok(())
    }

    #[test]
    fn post_commit_expiry_or_authorization_loss_preserves_receipt_and_occupancy() -> TestResult {
        let fixture = Fixture::new()?;
        for (final_time, authorization) in [(180, Until(300)), (151, Until(151)), (0, Until(300))] {
            let directory = private_directory()?;
            let path = directory.path().join("directory.redb");
            let selection = fixture.selection(1, 11, 12)?;
            let request = fixture.request(1, 2)?;
            let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
            let mut calls = 0;
            assert!(matches!(
                ledger.issue(
                    &fixture.key,
                    request,
                    &selection,
                    &fixture.device,
                    &fixture.policy,
                    &authorization,
                    || {
                        calls += 1;
                        if calls <= 2 {
                            Ok(150)
                        } else if final_time == 0 {
                            Err(Error::Clock)
                        } else {
                            Ok(final_time)
                        }
                    },
                ),
                Err(Error::CommittedAuthorizationLost)
            ));
            drop(ledger);
            let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
            let retained = ledger.lookup(request.operation())?.ok_or("lost commit")?;
            assert!(fixture.pin.verify_historical_lease(retained.wire()).is_ok());
            assert!(matches!(
                fixture.issue(&mut ledger, fixture.request(3, 4)?, &selection),
                Err(Error::KeyAlreadyReserved)
            ));
        }
        Ok(())
    }

    #[test]
    fn storage_error_requires_new_owner_and_original_committed_database() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let path = directory.path().join("directory.redb");
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
        // A reported storage failure can follow a durable effect. No continued
        // operation on this owner may convert that uncertainty into another lease.
        fixture.issue(&mut ledger, request, &selection)?;
        let result: Result<(), Error> =
            ledger.action(|_owner| Err(Error::Storage("injected after committed effect".into())));
        assert!(matches!(result, Err(Error::Storage(_))));
        assert!(matches!(
            ledger.lookup(request.operation()),
            Err(Error::ReopenRequired)
        ));
        assert!(matches!(
            fixture.issue(&mut ledger, request, &selection),
            Err(Error::ReopenRequired)
        ));
        drop(ledger);
        let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
        assert!(ledger.lookup(request.operation())?.is_some());
        assert!(DirectoryLedger::provision(&path, &fixture.pin, 8).is_err());
        assert!(
            DirectoryLedger::open(&directory.path().join("absent.redb"), &fixture.pin).is_err()
        );
        drop(ledger);
        let other = sdk::DirectoryPin::new([10; 32], fixture.key.public_key()?)?;
        assert!(DirectoryLedger::open(&path, &other).is_err());
        let other_key = sdk::DirectorySigningKey::generate()?;
        let other = sdk::DirectoryPin::new(fixture.pin.identity(), other_key.public_key()?)?;
        assert!(DirectoryLedger::open(&path, &other).is_err());
        Ok(())
    }

    #[test]
    fn aborted_transaction_never_publishes_partial_indexes_or_receipt() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let issued = fixture.key.issue_lease(
            &fixture.pin,
            request,
            &selection,
            &fixture.device,
            &fixture.policy,
            150,
        )?;
        let record = encode(&SavedRecord {
            schema: 1,
            wire: issued.as_bytes().to_vec(),
            cancelled: false,
        })?;
        for writes in 1..=3 {
            let path = directory.path().join(format!("cut-{writes}.redb"));
            let ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
            let tx = transaction(&ledger.db)?;
            let operation = request.operation();
            tx.open_table(OPERATIONS)
                .map_err(storage)?
                .insert(operation.as_slice(), record.as_slice())
                .map_err(storage)?;
            if writes >= 2 {
                tx.open_table(CLASSICAL)
                    .map_err(storage)?
                    .insert(
                        selection.classical().key_fingerprint().as_slice(),
                        operation.as_slice(),
                    )
                    .map_err(storage)?;
            }
            if writes == 3 {
                tx.open_table(POST_QUANTUM)
                    .map_err(storage)?
                    .insert(
                        selection.post_quantum().key_fingerprint().as_slice(),
                        operation.as_slice(),
                    )
                    .map_err(storage)?;
            }
            drop(tx);
            drop(ledger);
            let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
            assert!(ledger.lookup(operation)?.is_none());
            assert!(!fixture.issue(&mut ledger, request, &selection)?.cancelled());
        }
        Ok(())
    }

    #[test]
    fn signing_rechecks_current_authority_after_reading_and_reserving_inputs() -> TestResult {
        let fixture = Fixture::new()?;
        let directory = private_directory()?;
        let path = directory.path().join("directory.redb");
        let selection = fixture.selection(1, 11, 12)?;
        let request = fixture.request(1, 2)?;
        let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
        let mut calls = 0;
        assert!(matches!(
            ledger.issue(
                &fixture.key,
                request,
                &selection,
                &fixture.device,
                &fixture.policy,
                &Until(151),
                || {
                    calls += 1;
                    Ok(if calls == 1 { 150 } else { 151 })
                },
            ),
            Err(Error::Unauthorized)
        ));
        assert_eq!(calls, 2);
        assert!(ledger.lookup(request.operation())?.is_none());
        assert!(!fixture.issue(&mut ledger, request, &selection)?.cancelled());
        Ok(())
    }

    #[test]
    fn post_commit_clock_or_authorization_panic_requires_reopen_with_receipt_intact() -> TestResult
    {
        use std::cell::Cell;
        use std::panic::{catch_unwind, AssertUnwindSafe};

        struct PanicOnFinalCheck {
            checks: Cell<usize>,
            enabled: bool,
        }
        impl DirectoryAuthorization for PanicOnFinalCheck {
            fn authorize(
                &self,
                _action: Action,
                _request: &sdk::DirectoryLeaseRequest,
                _now: u64,
            ) -> Result<(), Error> {
                let checks = self.checks.get() + 1;
                self.checks.set(checks);
                assert!(
                    !self.enabled || checks != 3,
                    "injected authorization panic after commit"
                );
                Ok(())
            }
        }

        let fixture = Fixture::new()?;
        for panic_in_authorization in [false, true] {
            let directory = private_directory()?;
            let path = directory.path().join("directory.redb");
            let selection = fixture.selection(1, 11, 12)?;
            let request = fixture.request(1, 2)?;
            let mut ledger = DirectoryLedger::provision(&path, &fixture.pin, 8)?;
            let authorization = PanicOnFinalCheck {
                checks: Cell::new(0),
                enabled: panic_in_authorization,
            };
            let mut clock_reads = 0;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                ledger.issue(
                    &fixture.key,
                    request,
                    &selection,
                    &fixture.device,
                    &fixture.policy,
                    &authorization,
                    || {
                        clock_reads += 1;
                        assert!(
                            panic_in_authorization || clock_reads != 3,
                            "injected clock panic after commit"
                        );
                        Ok(150)
                    },
                )
            }));
            assert!(outcome.is_err());
            assert!(matches!(
                ledger.lookup(request.operation()),
                Err(Error::ReopenRequired)
            ));
            assert!(matches!(
                ledger.cancel(request.operation(), &Permit, || Ok(150)),
                Err(Error::ReopenRequired)
            ));
            drop(ledger);
            let mut ledger = DirectoryLedger::open(&path, &fixture.pin)?;
            let retained = ledger.lookup(request.operation())?.ok_or("lost commit")?;
            let retry = fixture.issue(&mut ledger, request, &selection)?;
            assert_eq!(retained.wire(), retry.wire());
            assert!(matches!(
                fixture.issue(&mut ledger, fixture.request(3, 4)?, &selection),
                Err(Error::KeyAlreadyReserved)
            ));
        }
        Ok(())
    }
}
