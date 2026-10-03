// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable service initialization above the existing journal and archive owners.
use crate::{
    bootstrap,
    crypto::digest,
    durable::{storage, transaction},
    AnchorClient, AnchorGenesis, DeviceJournal, DurableError, Error, JournalIdentity, JournalKey,
    PrekeyQuality, SessionArchiveStore, VerifiedDevice, VerifiedSessionPolicy,
};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use std::{
    io,
    path::{Component, Path, PathBuf},
};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_installation_v1");
const TAG: &[u8; 8] = b"QPCINS01";

mod recovery;
mod reopen;
pub use recovery::{InstallationRecovery, InstalledAccountRecovery, InstalledSessionRecovery};
pub use reopen::{BootstrapPeer, ReopenedPeer, ReopenedSession};

/// Exact independently configured paths. Keep the installation database and
/// wrapping key outside journal backups. Missing configuration is not first use.
#[derive(Clone)]
pub struct InstallationPaths {
    configuration: PathBuf,
    journal: PathBuf,
    archives: PathBuf,
}
impl InstallationPaths {
    /// Bind three distinct absolute UTF-8 paths without dot/parent components.
    /// Existing private parent directories are required by each file operation.
    pub fn new(
        configuration: &Path,
        journal: &Path,
        archives: &Path,
    ) -> Result<Self, DurableError> {
        validate_paths(&[configuration, journal, archives])?;
        Ok(Self {
            configuration: configuration.into(),
            journal: journal.into(),
            archives: archives.into(),
        })
    }
    pub(crate) fn files(&self) -> [&Path; 3] {
        [&self.configuration, &self.journal, &self.archives]
    }
    pub(crate) fn binding(&self) -> Result<[u8; 32], DurableError> {
        let mut bytes = Vec::new();
        for path in [&self.configuration, &self.journal, &self.archives] {
            let text = path.to_str().ok_or(DurableError::PrivateFile)?.as_bytes();
            bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
            bytes.extend_from_slice(text);
        }
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-INSTALLATION-PATHS/v1",
            &bytes,
        ))
    }
}

pub(crate) fn validate_paths(paths: &[&Path]) -> Result<(), DurableError> {
    for path in paths {
        if !path.is_absolute()
            || path.to_str().is_none_or(|s| s.len() > 4096)
            || path.file_name().is_none()
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(DurableError::PrivateFile);
        }
    }
    if paths
        .iter()
        .enumerate()
        .any(|(i, path)| paths.iter().skip(i + 1).any(|other| path == other))
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

/// Persisted release boundary. Neither state authorizes replacement of configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationStatus {
    /// No service journal has been released; only exact genesis preparation is allowed.
    Creating,
    /// A service may have operated. Missing child storage must never be recreated.
    Active,
}
impl InstallationStatus {
    fn byte(self) -> u8 {
        match self {
            Self::Creating => 1,
            Self::Active => 2,
        }
    }
}

/// Preparation releases no operational journal or enrollment authority.
pub enum InstallationPreparation {
    /// Local-only genesis and its empty archive index were durably read back.
    Local,
    /// Explicit independent witness enrollment is required before activation.
    RequiresEnrollment(AnchorGenesis),
}

pub(crate) fn admit(
    device: &VerifiedDevice,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<(), DurableError> {
    policy.check_device(device, now)?;
    let mode = [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ]
    .into_iter()
    .find(|mode| policy.allowed_modes().permits(*mode))
    .ok_or(Error::PolicyDenied)?;
    policy.check_mode(mode, now)?;
    Ok(())
}
fn scope(
    paths: &InstallationPaths,
    id: JournalIdentity,
    key_binding: [u8; 32],
    device: &VerifiedDevice,
    policy: &VerifiedSessionPolicy,
) -> Result<Vec<u8>, DurableError> {
    let mut bytes = TAG.to_vec();
    for value in [
        *id.as_bytes(),
        bootstrap::storage_owner(device),
        policy.checkpoint().digest(),
        key_binding,
        paths.binding()?,
    ] {
        bytes.extend_from_slice(&value);
    }
    match policy.anchor_requirement().binding() {
        None => bytes.push(0),
        Some(witness) => {
            bytes.push(1);
            bytes.extend_from_slice(&witness);
        }
    }
    Ok(bytes)
}
fn read(db: &Database) -> Result<(JournalIdentity, Vec<u8>, InstallationStatus), DurableError> {
    let tx = db.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx.list_tables().map_err(storage)?.collect();
    if tables.len() != 1
        || tables.first().ok_or(DurableError::Corrupt)?.name() != TABLE.name()
        || tx.list_multimap_tables().map_err(storage)?.next().is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let row = table
        .get("installation")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    let bytes = row.value();
    let (phase, binding) = bytes.split_last().ok_or(DurableError::Corrupt)?;
    if binding.get(..8) != Some(TAG.as_slice()) || !matches!(binding.len(), 169 | 201) {
        return Err(DurableError::Corrupt);
    }
    let id = JournalIdentity::from_trusted_state(
        binding
            .get(8..40)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)?,
    )?;
    let status = match phase {
        1 => InstallationStatus::Creating,
        2 => InstallationStatus::Active,
        _ => return Err(DurableError::Corrupt),
    };
    Ok((id, binding.to_vec(), status))
}
pub(crate) fn missing(path: &Path) -> Result<bool, DurableError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Exclusive independent initialization record for one configured device lineage.
/// Provision only after an explicit first-install decision; never on an open error.
/// The trusted configuration is not an anti-rollback witness or a backup of the journal.
pub struct DeviceInstallation {
    active: Option<Database>,
    paths: InstallationPaths,
    identity: JournalIdentity,
    key_binding: [u8; 32],
    scope: Vec<u8>,
}
impl DeviceInstallation {
    /// Durably retain a fresh journal ID and exact key/device/policy/path bindings
    /// before any journal creation. Existing child paths cannot be adopted.
    pub fn provision(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Self, DurableError> {
        Self::provision_inner(paths, key, device, policy, now, None)
    }
    pub(crate) fn provision_with_identity(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        identity: JournalIdentity,
    ) -> Result<Self, DurableError> {
        Self::provision_inner(paths, key, device, policy, now, Some(identity))
    }
    fn provision_inner(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        retained_identity: Option<JournalIdentity>,
    ) -> Result<Self, DurableError> {
        admit(device, policy, now)?;
        if !missing(&paths.journal)? || !missing(&paths.archives)? {
            return Err(DurableError::Conflict);
        }
        let identity = match retained_identity {
            Some(identity) => identity,
            None => JournalIdentity::generate()?,
        };
        let key_binding = key.installation_binding();
        let scope = scope(&paths, identity, key_binding, device, policy)?;
        let db = provision_private_database(&paths.configuration, |db| {
            let mut row = scope.clone();
            row.push(InstallationStatus::Creating.byte());
            let tx = transaction(&db)?;
            tx.open_table(TABLE)
                .map_err(storage)?
                .insert("installation", row.as_slice())
                .map_err(storage)?;
            #[cfg(all(test, unix))]
            tests::at_boundary("intent-before-commit");
            tx.commit().map_err(DurableError::CommitUncertain)?;
            Ok::<_, DurableError>(db)
        })?;
        let mut owner = Self {
            active: Some(db),
            paths,
            identity,
            key_binding,
            scope,
        };
        if owner.status()? != InstallationStatus::Creating {
            return Err(DurableError::Conflict);
        }
        #[cfg(all(test, unix))]
        tests::at_boundary("intent");
        Ok(owner)
    }
    /// Reopen only existing independent configuration and verify every binding.
    /// Missing, corrupt, wrong-key, changed-device/policy/path and busy states fail.
    pub fn open(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Self, DurableError> {
        admit(device, policy, now)?;
        Self::open_bound(paths, key, device, policy)
    }
    fn open_bound(
        paths: InstallationPaths,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
    ) -> Result<Self, DurableError> {
        let db = open_private_database(&paths.configuration)?;
        let (identity, saved, _) = read(&db)?;
        let key_binding = key.installation_binding();
        let expected = scope(&paths, identity, key_binding, device, policy)?;
        if saved != expected {
            return Err(DurableError::Conflict);
        }
        Ok(Self {
            active: Some(db),
            paths,
            identity,
            key_binding,
            scope: expected,
        })
    }
    /// Original independently retained public journal identity; no message authority.
    pub fn identity(&self) -> Result<JournalIdentity, DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        Ok(self.identity)
    }
    /// Fresh schema-checked phase; failures close the configuration owner.
    pub fn status(&mut self) -> Result<InstallationStatus, DurableError> {
        let result = (|| {
            let (id, saved, phase) = read(self.active.as_ref().ok_or(DurableError::Closed)?)?;
            if id != self.identity || saved != self.scope {
                return Err(DurableError::Conflict);
            }
            Ok(phase)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn check(
        &self,
        key: &JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        admit(device, policy, now)?;
        if scope(
            &self.paths,
            self.identity,
            key.installation_binding(),
            device,
            policy,
        )? != self.scope
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Prepare exact initial storage without releasing a service. Only Creating
    /// can create missing children. Existing partial/wrong/advanced files fail;
    /// no file is deleted, repaired or overwritten. Required-witness preparation
    /// returns only the original genesis for explicit independent enrollment.
    pub fn prepare(
        &mut self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        let result = (|| {
            self.check(&key, device, policy, now)?;
            if self.status()? != InstallationStatus::Creating {
                return Err(DurableError::Conflict);
            }
            let anchored = policy.anchor_requirement().binding().is_some();
            let prepared = if missing(&self.paths.journal)? {
                let mut journal = if anchored {
                    DeviceJournal::provision_anchored(
                        &self.paths.journal,
                        key,
                        device,
                        policy,
                        self.identity,
                        now,
                    )?
                } else {
                    DeviceJournal::provision(&self.paths.journal, key, device, self.identity)?
                };
                if anchored {
                    InstallationPreparation::RequiresEnrollment(
                        journal.anchor_genesis(device, policy)?,
                    )
                } else {
                    journal.check_installation_state(device, policy, true)?;
                    InstallationPreparation::Local
                }
            } else if anchored {
                InstallationPreparation::RequiresEnrollment(DeviceJournal::recover_anchor_genesis(
                    &self.paths.journal,
                    key,
                    device,
                    policy,
                    self.identity,
                )?)
            } else {
                let mut journal =
                    DeviceJournal::open(&self.paths.journal, key, device, self.identity)?;
                journal.check_installation_state(device, policy, true)?;
                InstallationPreparation::Local
            };
            #[cfg(all(test, unix))]
            tests::at_boundary("journal");
            let mut archives = if missing(&self.paths.archives)? {
                SessionArchiveStore::provision(&self.paths.archives, self.identity)?
            } else {
                SessionArchiveStore::open(&self.paths.archives, self.identity)?
            };
            if !archives.session_ids()?.is_empty() {
                return Err(DurableError::Conflict);
            }
            #[cfg(all(test, unix))]
            tests::at_boundary("archives");
            admit(device, policy, now)?;
            Ok(prepared)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Open prepared/existing children, freshly admit the original required
    /// witness, then durably record Active before releasing any operational owner.
    /// None is permitted only for an originally local-only policy. Unknown commits
    /// return no service; reopen the original configuration to reconcile its phase.
    pub fn activate(
        mut self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<DeviceService, DurableError> {
        self.check(&key, device, policy, now)?;
        let phase = self.status()?;
        let (mut journal, mut archives) = self.open_children(key, device, policy, anchor)?;
        if phase == InstallationStatus::Creating {
            journal.check_installation_state(device, policy, true)?;
            if !archives.session_ids()?.is_empty() {
                return Err(DurableError::Conflict);
            }
            let mut row = self.scope.clone();
            row.push(InstallationStatus::Active.byte());
            let tx = transaction(self.active.as_ref().ok_or(DurableError::Closed)?)?;
            tx.open_table(TABLE)
                .map_err(storage)?
                .insert("installation", row.as_slice())
                .map_err(storage)?;
            #[cfg(all(test, unix))]
            tests::at_boundary("activation-before-commit");
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            tests::at_boundary("activation-after-commit");
            if self.status()? != InstallationStatus::Active {
                return Err(DurableError::Conflict);
            }
        }
        admit(device, policy, now)?;
        journal.check_installation_state(device, policy, false)?;
        admit(device, policy, now)?;
        Ok(DeviceService {
            active: Some(ServiceOwners {
                journal,
                archives,
                installation: self,
            }),
        })
    }
    fn open_children(
        &self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        anchor: Option<AnchorClient>,
    ) -> Result<(DeviceJournal, SessionArchiveStore), DurableError> {
        let journal = match (policy.anchor_requirement().binding(), anchor) {
            (None, None) => DeviceJournal::open(&self.paths.journal, key, device, self.identity)?,
            (Some(_), Some(client)) => DeviceJournal::open_anchored(
                &self.paths.journal,
                key,
                device,
                policy,
                self.identity,
                client,
            )?,
            (Some(_), None) => return Err(DurableError::AnchorRequired),
            (None, Some(_)) => return Err(DurableError::Conflict),
        };
        let archives = SessionArchiveStore::open(&self.paths.archives, self.identity)?;
        archives.check_journal(&journal)?;
        Ok((journal, archives))
    }
    /// Release the initialization lease. Persisted phase and identities remain.
    pub fn close(&mut self) {
        self.active = None;
    }
}

struct ServiceOwners {
    journal: DeviceJournal,
    archives: SessionArchiveStore,
    installation: DeviceInstallation,
}
/// Active journal/index pair retaining its exclusive installation lease for its
/// complete lifetime. Closing erases journal key ownership and drops child leases
/// before releasing configuration. It never deletes persisted state.
pub struct DeviceService {
    active: Option<ServiceOwners>,
}
impl DeviceService {
    /// Borrow the existing protocol engines together; no key material is exported.
    pub fn stores(
        &mut self,
    ) -> Result<(&mut DeviceJournal, &mut SessionArchiveStore), DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        owners
            .installation
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        Ok((&mut owners.journal, &mut owners.archives))
    }
    /// Shut down this service owner and retain its Active initialization record.
    pub fn close(&mut self) {
        self.active = None;
    }
}

#[cfg(all(test, unix))]
mod tests;
