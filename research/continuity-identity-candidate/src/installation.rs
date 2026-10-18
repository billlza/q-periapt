// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable service initialization above the existing journal and archive owners.
use crate::durable::AccountAuthorityOpen;
use crate::{
    bootstrap,
    crypto::digest,
    durable::{storage, transaction},
    AnchorClient, AnchorGenesis, DeviceJournal, DurableError, Error, JournalIdentity, JournalKey,
    PrekeyQuality, SessionArchiveStore, VerifiedDevice, VerifiedSessionPolicy,
};
#[cfg(all(test, unix))]
use q_periapt_host_store::filesystem::open_private_database;
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use std::path::{Component, Path, PathBuf};

#[cfg(all(test, unix))]
use std::io;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_installation_v1");
const TAG: &[u8; 8] = b"QPCINS01";

mod admission;
mod opening;
mod recovery;
mod reopen;
mod retired;
pub use admission::InstallationAdmission;
pub use recovery::{InstallationRecovery, InstalledAccountRecovery, InstalledSessionRecovery};
pub use reopen::{BootstrapPeer, ReopenedPeer, ReopenedSession};
pub use retired::RetiredInstallationRecovery;

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
    /// Windows accepts local drive paths, including verbatim drive prefixes;
    /// network and device namespaces are rejected without rewriting path bytes.
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
        // The browser backend addresses a rooted logical namespace. The unknown
        // target has no native absolute-path semantics, even for RootDir paths.
        // Admission to a particular browser root remains the storage owner's job.
        let rooted = if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
            matches!(path.components().next(), Some(Component::RootDir))
        } else {
            path.is_absolute()
        };
        if !rooted
            || path.to_str().is_none_or(|s| s.len() > 4096)
            || path.file_name().is_none()
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
            || path.components().any(|component| match component {
                Component::RootDir | Component::Normal(_) => false,
                // Match the private storage adapter's local-drive namespace,
                // including the spelling returned by Windows canonicalize().
                // Keep the original path bytes in the persisted binding.
                #[cfg(windows)]
                Component::Prefix(prefix) => !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ),
                _ => true,
            })
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
    admit_policy(policy, now)
}
// Current runtime permission shared by admission against a credential's pinned
// roster and admission against a newer authenticated journal roster.
pub(crate) fn admit_policy(policy: &VerifiedSessionPolicy, now: u64) -> Result<(), DurableError> {
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
    policy: &impl AsRef<crate::HistoricalSessionPolicy>,
) -> Result<Vec<u8>, DurableError> {
    let policy = policy.as_ref();
    scope_for_owner(
        paths,
        id,
        key_binding,
        bootstrap::storage_owner(device),
        policy,
    )
}
fn scope_for_owner(
    paths: &InstallationPaths,
    id: JournalIdentity,
    key_binding: [u8; 32],
    owner: [u8; 32],
    policy: &impl AsRef<crate::HistoricalSessionPolicy>,
) -> Result<Vec<u8>, DurableError> {
    let policy = policy.as_ref();
    let mut bytes = TAG.to_vec();
    for value in [
        *id.as_bytes(),
        owner,
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
    let saved = read_configuration(db)?;
    if saved.retired.is_some() {
        return Err(DurableError::Suspended);
    }
    Ok((saved.identity, saved.scope, saved.status))
}
struct Configuration {
    identity: JournalIdentity,
    scope: Vec<u8>,
    status: InstallationStatus,
    retired: Option<crate::AnchorRetiredCleanupProposal>,
    retired_report: Option<crate::AnchorRetiredReportProposal>,
    retired_ack: Option<crate::AnchorRetiredReportProposal>,
}
fn read_configuration(db: &Database) -> Result<Configuration, DurableError> {
    let tx = db.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx.list_tables().map_err(storage)?.collect();
    if tables.len() != 1
        || tables.first().ok_or(DurableError::Corrupt)?.name() != TABLE.name()
        || tx.list_multimap_tables().map_err(storage)?.next().is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(TABLE).map_err(storage)?;
    let cleanup = table.get("retired-cleanup").map_err(storage)?;
    let report = table.get("retired-report").map_err(storage)?;
    let ack = table.get("retired-ack").map_err(storage)?;
    if table.len().map_err(storage)?
        != 1 + u64::from(cleanup.is_some()) + u64::from(report.is_some()) + u64::from(ack.is_some())
    {
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
    let retired = cleanup
        .map(|row| retired::decode_request(row.value(), binding, status))
        .transpose()?;
    let retired_report = report
        .map(|row| {
            let proposal = crate::AnchorRetiredReportProposal::from_trusted_state(row.value())
                .map_err(|_| DurableError::Corrupt)?;
            if retired.as_ref() != Some(proposal.inventory()) {
                return Err(DurableError::Corrupt);
            }
            Ok(proposal)
        })
        .transpose()?;
    let retired_ack = ack
        .map(|row| {
            if row.value().get(..8) != Some(b"QPCIAK01") {
                return Err(DurableError::Corrupt);
            }
            let proposal = crate::AnchorRetiredReportProposal::from_trusted_state(
                row.value().get(8..).ok_or(DurableError::Corrupt)?,
            )
            .map_err(|_| DurableError::Corrupt)?;
            if retired_report.as_ref() != Some(&proposal) {
                return Err(DurableError::Corrupt);
            }
            Ok(proposal)
        })
        .transpose()?;
    Ok(Configuration {
        identity: id,
        scope: binding.to_vec(),
        status,
        retired,
        retired_report,
        retired_ack,
    })
}

/// Exclusive independent initialization record for one configured device lineage.
/// Provision only after an explicit first-install decision; never on an open error.
/// The trusted configuration is not an anti-rollback witness or a backup of the journal.
pub struct DeviceInstallation {
    storage: crate::storage::Storage,
    active: Option<Database>,
    paths: InstallationPaths,
    identity: JournalIdentity,
    key_binding: [u8; 32],
    scope: Vec<u8>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceInstallation {
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
    pub async fn prepare(
        &mut self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        let result = self.prepare_attempt(key, device, policy, now).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn prepare_attempt(
        &mut self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, DurableError> {
        self.check(&key, device, policy, now)?;
        if self.status()? != InstallationStatus::Creating {
            return Err(DurableError::Conflict);
        }
        let anchored = policy.anchor_requirement().binding().is_some();
        let prepared = if self.storage.missing(&self.paths.journal).await? {
            let mut journal = if anchored {
                DeviceJournal::provision_anchored_with_storage(
                    self.storage.clone(),
                    &self.paths.journal,
                    key,
                    device,
                    policy,
                    self.identity,
                    now,
                )
                .await?
            } else {
                DeviceJournal::provision_with_storage(
                    self.storage.clone(),
                    &self.paths.journal,
                    key,
                    device,
                    self.identity,
                )
                .await?
            };
            if anchored {
                InstallationPreparation::RequiresEnrollment(journal.anchor_genesis(device, policy)?)
            } else {
                journal
                    .check_installation_state(device, policy, true)
                    .await?;
                InstallationPreparation::Local
            }
        } else if anchored {
            InstallationPreparation::RequiresEnrollment(
                DeviceJournal::recover_anchor_genesis_with_storage(
                    self.storage.clone(),
                    &self.paths.journal,
                    key,
                    device,
                    policy,
                    self.identity,
                )
                .await?,
            )
        } else {
            let mut journal = DeviceJournal::open_with_storage(
                self.storage.clone(),
                &self.paths.journal,
                key,
                device,
                self.identity,
            )
            .await?;
            journal
                .check_installation_state(device, policy, true)
                .await?;
            InstallationPreparation::Local
        };
        #[cfg(all(test, unix))]
        tests::at_boundary("journal");
        let mut archives = if self.storage.missing(&self.paths.archives).await? {
            SessionArchiveStore::provision_with_storage(
                self.storage.clone(),
                &self.paths.archives,
                self.identity,
            )
            .await?
        } else {
            SessionArchiveStore::open_with_storage(
                self.storage.clone(),
                &self.paths.archives,
                self.identity,
            )
            .await?
        };
        if !archives.session_ids()?.is_empty() {
            return Err(DurableError::Conflict);
        }
        #[cfg(all(test, unix))]
        tests::at_boundary("archives");
        admit(device, policy, now)?;
        Ok(prepared)
    }

    /// Open prepared/existing children, freshly admit the original required
    /// witness, then durably record Active before releasing any operational owner.
    /// None is permitted only for an originally local-only policy. Unknown commits
    /// return no service; reopen the original configuration to reconcile its phase.
    /// Managed journals require their original [`InstallationAdmission`], which
    /// also permits explicit initial binding after genesis validation.
    pub async fn activate(
        self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        admission: impl Into<InstallationAdmission>,
    ) -> Result<DeviceService, DurableError> {
        self.activate_admitted(key, device, policy, now, admission.into())
            .await
    }
    pub(crate) async fn activate_admitted(
        mut self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        admission: InstallationAdmission,
    ) -> Result<DeviceService, DurableError> {
        self.check(&key, device, policy, now)?;
        let phase = self.status()?;
        let mode = match &admission.account {
            Some(authority) => AccountAuthorityOpen::Bind(authority.clone()),
            None => AccountAuthorityOpen::Existing(None),
        };
        let (mut journal, mut archives) = self
            .open_children(key, device, policy, admission.anchor, mode)
            .await?;
        if phase == InstallationStatus::Creating {
            journal
                .check_installation_state(device, policy, true)
                .await?;
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
        if let Some(authority) = admission.account {
            journal.adopt_account_authority(authority).await?;
        }
        admit(device, policy, now)?;
        journal
            .check_installation_state(device, policy, false)
            .await?;
        admit(device, policy, now)?;
        Ok(DeviceService {
            active: Some(Box::new(ServiceOwners {
                original_device: device.clone(),
                authority: crate::RetainedInstallationAuthority::active_installation(
                    device, policy,
                ),
                original_policy: policy.historical().clone(),
                journal,
                archives,
                installation: self,
            })),
        })
    }
    pub(crate) async fn reconcile_original_enrollment(
        paths: InstallationPaths,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        admission: impl Into<InstallationAdmission>,
    ) -> Result<DeviceService, DurableError> {
        Self::reconcile_original_enrollment_with_storage(
            crate::storage::Storage::native()?,
            paths,
            key,
            original,
            policy,
            admission,
        )
        .await
    }
    pub(crate) async fn reconcile_original_enrollment_with_storage(
        storage: crate::storage::Storage,
        paths: InstallationPaths,
        key: JournalKey,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        admission: impl Into<InstallationAdmission>,
    ) -> Result<DeviceService, DurableError> {
        let admission = admission.into();
        let anchor = admission.anchor;
        let policy = policy.as_ref();
        if policy.anchor_requirement().binding().is_some() && anchor.is_none() {
            return Err(DurableError::AnchorRequired);
        }
        if policy.anchor_requirement().binding().is_none() && anchor.is_some() {
            return Err(DurableError::Conflict);
        }
        let mut installation =
            Self::open_bound_with_storage(storage, paths, &key, original, policy).await?;
        if installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        let (mut journal, archives) = installation
            .open_children(
                key,
                original,
                policy,
                anchor,
                AccountAuthorityOpen::Existing(admission.account),
            )
            .await?;
        journal
            .check_installation_state(original, policy, false)
            .await?;
        Ok(DeviceService {
            active: Some(Box::new(ServiceOwners {
                original_device: original.clone(),
                authority: crate::RetainedInstallationAuthority::active_installation(
                    original, policy,
                ),
                original_policy: policy.clone(),
                journal,
                archives,
                installation,
            })),
        })
    }
    async fn open_children(
        &self,
        key: JournalKey,
        device: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        anchor: Option<AnchorClient>,
        account: AccountAuthorityOpen,
    ) -> Result<(DeviceJournal, SessionArchiveStore), DurableError> {
        let policy = policy.as_ref();
        let journal = match (policy.anchor_requirement().binding(), anchor, account) {
            (None, None, AccountAuthorityOpen::Existing(None)) => {
                DeviceJournal::open_with_storage(
                    self.storage.clone(),
                    &self.paths.journal,
                    key,
                    device,
                    self.identity,
                )
                .await?
            }
            (Some(_), Some(client), account) => {
                DeviceJournal::open_anchored_database_admitted(
                    self.storage.open_database(&self.paths.journal).await?,
                    key,
                    device,
                    policy,
                    self.identity,
                    client,
                    account,
                )
                .await?
            }
            (_, None, _) => return Err(DurableError::AnchorRequired),
            (None, Some(_), _) => return Err(DurableError::Conflict),
        };
        let archives = SessionArchiveStore::open_with_storage(
            self.storage.clone(),
            &self.paths.archives,
            self.identity,
        )
        .await?;
        archives.check_journal(&journal)?;
        Ok((journal, archives))
    }
    /// Release the initialization lease. Persisted phase and identities remain.
    pub fn close(&mut self) {
        self.active = None;
    }
}

// Original verified installation metadata. This borrowed view is not current
// permission; the journal must authenticate its adopted policy, credential and roster.
pub(crate) struct PolicyScope<'a> {
    pub(crate) authority: &'a crate::RetainedInstallationAuthority,
    pub(crate) original_policy: &'a crate::HistoricalSessionPolicy,
    pub(crate) original_device: &'a VerifiedDevice,
}
impl PolicyScope<'_> {
    pub(crate) fn local_identity(&self) -> ([u8; 32], [u8; 16]) {
        (
            self.original_device.account_id(),
            self.original_device.device_id(),
        )
    }
}
struct ServiceOwners {
    original_policy: crate::HistoricalSessionPolicy,
    original_device: VerifiedDevice,
    authority: crate::RetainedInstallationAuthority,
    journal: DeviceJournal,
    archives: SessionArchiveStore,
    installation: DeviceInstallation,
}
/// Active journal/index pair retaining its exclusive installation lease for its
/// complete lifetime. Closing erases journal key ownership and drops child leases
/// before releasing configuration. It never deletes persisted state.
pub struct DeviceService {
    // Keep the large authenticated owner state at one stable location. Service
    // returns and transfers otherwise copy value-sized temporaries through every
    // admission frame, exhausting ordinary foreign worker stacks in Debug.
    active: Option<Box<ServiceOwners>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
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
    /// Read the original inventory operation through this installation, even if
    /// the current credential was revoked or its renewal grant was superseded.
    /// This metadata operation grants no fresh key or traffic authority.
    pub async fn prekey_status(
        &mut self,
        policy: &VerifiedSessionPolicy,
        request: crate::PrekeyId,
    ) -> Result<crate::PrekeyStatus, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        if owners.installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        owners
            .journal
            .installation_prekey_status(&owners.authority, policy, request)
            .await
    }
    /// Retire an original inventory operation without restoring permission or
    /// clearing a one-time consumption tombstone. Pending responses still block.
    pub async fn retire_prekey(
        &mut self,
        policy: &VerifiedSessionPolicy,
        request: crate::PrekeyId,
    ) -> Result<crate::PrekeyStatus, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        if owners.installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        owners
            .journal
            .retire_installation_prekey(&owners.authority, policy, request)
            .await
    }
    /// Shut down this service owner and retain its Active initialization record.
    pub fn close(&mut self) {
        self.active = None;
    }
}

#[cfg(all(test, unix))]
mod tests;
