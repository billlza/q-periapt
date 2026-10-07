// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-installation admission for restricted session cleanup after expiry.
use super::*;
use crate::{
    codec::Decoder, FanoutAbandonmentJournal, FanoutId, RetainedInstallationAuthority as Authority,
    SessionClosureArchive, SessionClosureJournal,
};

impl Authority {
    pub(super) fn retained(
        saved: &[u8],
        paths: &InstallationPaths,
        identity: JournalIdentity,
        key: &JournalKey,
    ) -> Result<Self, DurableError> {
        let mut d = Decoder::new(saved);
        if d.array::<8>()? != *TAG || d.array::<32>()? != *identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let owner = d.array()?;
        let policy = d.array()?;
        if d.array::<32>()? != key.installation_binding() || d.array::<32>()? != paths.binding()? {
            return Err(DurableError::Conflict);
        }
        let witness = match d.array::<1>()? {
            [0] => None,
            [1] => Some(d.array()?),
            _ => return Err(DurableError::Corrupt),
        };
        d.finish()?;
        Ok(Self {
            owner,
            policy,
            witness,
        })
    }
}

struct RecoveryOwners {
    archives: SessionArchiveStore,
    key: JournalKey,
    installation: DeviceInstallation,
    authority: Authority,
}
/// Recovery discovery for the original Active installation, without reconstructing
/// expired policy or device objects. Holds its configuration, index and original
/// wrapping-key owners. Index IDs are untrusted discovery hints, not proof of an
/// existing session. This object has no operational/provisioning API.
pub struct InstallationRecovery {
    active: Option<RecoveryOwners>,
}
impl InstallationRecovery {
    /// Open existing Active configuration and archive index using the independently
    /// retained original key and exact paths. Missing/Creating/partial configuration
    /// and invalid indices fail without provisioning or repair. Journal existence
    /// and authenticity are checked on session selection. Configuration remains
    /// trusted host state outside journal backups, not a rollback witness.
    pub fn open(paths: InstallationPaths, key: JournalKey) -> Result<Self, DurableError> {
        let db = open_private_database(&paths.configuration)?;
        let (identity, saved, phase) = read(&db)?;
        if phase != InstallationStatus::Active {
            return Err(DurableError::Suspended);
        }
        let authority = Authority::retained(&saved, &paths, identity, &key)?;
        let key_binding = key.installation_binding();
        let archives = SessionArchiveStore::open(&paths.archives, identity)?;
        Ok(Self {
            active: Some(RecoveryOwners {
                archives,
                key,
                installation: DeviceInstallation {
                    active: Some(db),
                    paths,
                    identity,
                    key_binding,
                    scope: saved,
                },
                authority,
            }),
        })
    }
    /// Enumerate bounded index hints. Authentication and fresh original-witness
    /// admission occur when selecting a session, including an already closed one.
    pub fn session_ids(&mut self) -> Result<Vec<[u8; 32]>, DurableError> {
        let result = self
            .active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .archives
            .session_ids();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Select an existing indexed archive. Consumes discovery ownership and opens
    /// only the existing cleanup journal, retaining all three database leases.
    /// Missing index rows fail; they do not select a different session or archive.
    pub fn open_session(
        self,
        session: [u8; 32],
        anchor: Option<AnchorClient>,
    ) -> Result<InstalledSessionRecovery, DurableError> {
        self.select(anchor, |index| index.get(session))
    }
    /// Explicitly select independently retained original archive bytes when the
    /// index row is lost. The existing index must still be valid. This does not
    /// restore a row or infer absence; use the existing index restore operation
    /// only after this owner authenticates the exact archive and original journal.
    pub fn open_session_from_archive(
        self,
        archive: &SessionClosureArchive,
        anchor: Option<AnchorClient>,
    ) -> Result<InstalledSessionRecovery, DurableError> {
        self.select(anchor, |_| {
            SessionClosureArchive::from_bytes(archive.as_bytes())
        })
    }
    /// Select one independently retained account operation. The authenticated
    /// journal chooses every member; the caller supplies no recipient subset.
    /// Consumes discovery and retains the original installation/index leases.
    /// All member archives must match the retained authority before reconciliation
    /// can write. Missing state or the original required witness never provisions,
    /// retries under different defaults, or restores operational authority.
    pub fn open_account(
        mut self,
        id: FanoutId,
        anchor: Option<AnchorClient>,
    ) -> Result<InstalledAccountRecovery, DurableError> {
        let RecoveryOwners {
            mut archives,
            key,
            mut installation,
            authority,
        } = self.active.take().ok_or(DurableError::Closed)?;
        if installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        match (authority.witness, anchor.is_some()) {
            (None, false) | (Some(_), true) => {}
            (Some(_), false) => return Err(DurableError::AnchorRequired),
            (None, true) => return Err(DurableError::Conflict),
        }
        let identity = installation.identity;
        let journal = FanoutAbandonmentJournal::open_installed(
            &installation.paths.journal,
            key,
            identity,
            id,
            &mut archives,
            anchor,
            &authority,
        )?;
        Ok(InstalledAccountRecovery {
            active: Some(AccountOwners {
                journal,
                archives,
                installation,
            }),
        })
    }
    fn select(
        mut self,
        anchor: Option<AnchorClient>,
        archive: impl FnOnce(&mut SessionArchiveStore) -> Result<SessionClosureArchive, DurableError>,
    ) -> Result<InstalledSessionRecovery, DurableError> {
        let RecoveryOwners {
            mut archives,
            key,
            mut installation,
            authority,
        } = self.active.take().ok_or(DurableError::Closed)?;
        if installation.status()? != InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        let archive = archive(&mut archives)?;
        archive.check_installation(
            &key,
            installation.identity,
            authority.owner,
            authority.policy,
            authority.witness,
        )?;
        let journal = match (authority.witness, anchor) {
            (None, None) => SessionClosureJournal::open(
                &installation.paths.journal,
                key,
                installation.identity,
                &archive,
            )?,
            (Some(_), Some(client)) => SessionClosureJournal::open_anchored(
                &installation.paths.journal,
                key,
                installation.identity,
                &archive,
                client,
            )?,
            (Some(_), None) => return Err(DurableError::AnchorRequired),
            (None, Some(_)) => return Err(DurableError::Conflict),
        };
        Ok(InstalledSessionRecovery {
            active: Some(SessionOwners {
                journal,
                archives,
                installation,
            }),
        })
    }
    /// Release discovery/key ownership without deleting or recreating any state.
    pub fn close(&mut self) {
        self.active = None;
    }
}

struct SessionOwners {
    journal: SessionClosureJournal,
    archives: SessionArchiveStore,
    installation: DeviceInstallation,
}
/// The original installation's authenticated session-cleanup owner and index.
/// Only existing closure/accounting/catalogue APIs are available. Operational
/// policy admission cannot be recovered through this type. Child owners drop
/// before the installation lease, including after a failed cleanup operation.
pub struct InstalledSessionRecovery {
    active: Option<SessionOwners>,
}
impl InstalledSessionRecovery {
    /// Borrow only the cleanup journal and index. Host loss accounting and exact
    /// report acknowledgement retain their original explicit transaction contract.
    pub fn stores(
        &mut self,
    ) -> Result<(&mut SessionClosureJournal, &mut SessionArchiveStore), DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        owners
            .installation
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        Ok((&mut owners.journal, &mut owners.archives))
    }
    /// Release all original owners without acknowledging loss or erasing records.
    pub fn close(&mut self) {
        self.active = None;
    }
}

struct AccountOwners {
    journal: FanoutAbandonmentJournal,
    archives: SessionArchiveStore,
    installation: DeviceInstallation,
}
/// Original-installation ownership of one complete account cleanup transaction.
/// Only aggregate status, loss reporting, acknowledgement and metadata retirement
/// are available. No peer contexts, operational keys or individual member erasure
/// can be obtained through this owner. Closing it never acknowledges any loss.
pub struct InstalledAccountRecovery {
    active: Option<AccountOwners>,
}
impl InstalledAccountRecovery {
    /// Borrow the existing restricted journal. The archive index stays pinned
    /// privately; it cannot be replaced with a caller-selected recipient set.
    pub fn journal(&mut self) -> Result<&mut FanoutAbandonmentJournal, DurableError> {
        let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
        owners
            .installation
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        owners
            .archives
            .check_identity(owners.installation.identity)?;
        Ok(&mut owners.journal)
    }
    /// Release the journal/key, archive index and installation leases in order.
    /// This does not begin, acknowledge or retire an account transaction.
    pub fn close(&mut self) {
        self.active = None;
    }
}
