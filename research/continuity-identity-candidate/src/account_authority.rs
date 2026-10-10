// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently retained application-account authority, outside journal backups.
use crate::{
    codec::nonzero,
    durable::{storage, transaction},
    AccountPin, AnchorAccountReplacementId, AnchorAccountReplacementPlan,
    AnchorAccountReplacementProposal as Proposal, AnchorPin, AnchorRetiredAccount, DurableError,
    Error, JournalKey, PublicKey, RosterCheckpoint, VerifiedDevice,
};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, TableDefinition};
use std::{collections::BTreeMap, path::Path, sync::Arc};

mod codec;
mod preparation;
mod runtime;
#[cfg(all(test, unix))]
pub(crate) mod tests;
use runtime::Runtime;
pub use runtime::{AccountAuthorityAccess, AccountAuthorityLease};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_account_authority_v1");
const MAX_ACCOUNTS: usize = 64;
const MAX_REPLACEMENTS: usize = 256;

/// Stable application identity supplied by independently authenticated host state.
/// This does not rename the cryptographic account bound to a root public key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ApplicationAccountId([u8; 32]);
impl ApplicationAccountId {
    /// Restore the host's original association; incoming replacement bytes cannot select it.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Stable public application correlation bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Original independently retained identity of this authority database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountAuthorityIdentity([u8; 32]);
impl AccountAuthorityIdentity {
    /// Generate and retain before provisioning; missing existing state is never first use.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore the original identity from independent configuration, not a database header.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public identity bytes for original-operation recovery.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact current mapping observed from an original authority owner.
/// A cached checkpoint grants no permission after its entry or parent closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountAuthorityCheckpoint {
    application: ApplicationAccountId,
    revision: u64,
    account: [u8; 32],
}
impl AccountAuthorityCheckpoint {
    /// Restore retained public expectations. This value is never authority without a live store check.
    pub fn from_trusted_state(
        application: ApplicationAccountId,
        revision: u64,
        account: [u8; 32],
    ) -> Result<Self, Error> {
        crate::codec::generation(revision)?;
        nonzero(&account)?;
        Ok(Self {
            application,
            revision,
            account,
        })
    }
    /// Stable host application account.
    pub fn application(self) -> ApplicationAccountId {
        self.application
    }
    /// Store-derived sequence, starting at one and advancing by exactly one per replacement.
    pub fn revision(self) -> u64 {
        self.revision
    }
    /// Selected cryptographic account; historical sessions retain their own original identity.
    pub fn account(self) -> [u8; 32] {
        self.account
    }
}

/// Original root replacement state, not successor device or message authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountAuthorityReplacementState {
    /// Original target and freeze request are durable; old and new authority are fenced.
    Preparing,
    /// Exact approved descriptor is durable; both roots are fenced at this application entry.
    Pending,
    /// A verified historical retirement selected the target root; current device admission is separate.
    Committed,
}

#[derive(Clone)]
struct Initial {
    root: PublicKey,
    roster: RosterCheckpoint,
}
#[derive(Clone)]
struct Replacement {
    application: ApplicationAccountId,
    revision: u64,
    proposal: Proposal,
    preparation: Option<AnchorAccountReplacementPlan>,
    committed: bool,
}
#[derive(Clone, Default)]
struct Image {
    initial: BTreeMap<ApplicationAccountId, Initial>,
    replacements: Vec<Replacement>,
}
#[derive(Clone)]
struct Current {
    checkpoint: AccountAuthorityCheckpoint,
    root: PublicKey,
    roster: RosterCheckpoint,
    pending: bool,
}

impl Image {
    fn root_seen(&self, account: [u8; 32]) -> bool {
        self.initial
            .values()
            .any(|r| crate::identity::account_id(&r.root) == account)
            || self
                .replacements
                .iter()
                .any(|r| r.proposal.successor_account() == account)
    }
    fn current(
        &self,
        family: [u8; 32],
        witness: &AnchorPin,
    ) -> Result<BTreeMap<ApplicationAccountId, Current>, DurableError> {
        use std::collections::BTreeSet;
        if self.initial.len() > MAX_ACCOUNTS || self.replacements.len() > MAX_REPLACEMENTS {
            return Err(DurableError::Capacity);
        }
        let mut roots = BTreeSet::new();
        let mut current = BTreeMap::new();
        for (application, initial) in &self.initial {
            let account = crate::identity::account_id(&initial.root);
            if initial.root.shares_component(witness.public_key()) || !roots.insert(account) {
                return Err(DurableError::Corrupt);
            }
            current.insert(
                *application,
                Current {
                    checkpoint: AccountAuthorityCheckpoint {
                        application: *application,
                        revision: 1,
                        account,
                    },
                    root: initial.root.clone(),
                    roster: initial.roster,
                    pending: false,
                },
            );
        }
        let mut operations = BTreeSet::new();
        for replacement in &self.replacements {
            let p = &replacement.proposal;
            if let Some(plan) = &replacement.preparation {
                let bound = plan.check_retained(p)?;
                if replacement.committed && !bound {
                    return Err(DurableError::Corrupt);
                }
            }
            let (previous, successor, proposed_family, roster) = p.authority_transition();
            let selected = current
                .get_mut(&replacement.application)
                .ok_or(DurableError::Corrupt)?;
            if selected.pending
                || replacement.revision != selected.checkpoint.revision
                || previous != &selected.root
                || proposed_family != family
                || p.witness_binding() != witness.binding()
                || successor.shares_component(witness.public_key())
                || !operations.insert(*p.operation().as_bytes())
                || !roots.insert(p.successor_account())
            {
                return Err(DurableError::Corrupt);
            }
            if replacement.committed {
                selected.checkpoint.revision = selected
                    .checkpoint
                    .revision
                    .checked_add(1)
                    .filter(|r| *r != u64::MAX)
                    .ok_or(DurableError::Capacity)?;
                selected.checkpoint.account = p.successor_account();
                selected.root = successor.clone();
                selected.roster = roster;
            } else {
                selected.pending = true;
            }
        }
        Ok(current)
    }
}

struct Active {
    db: Database,
    key: JournalKey,
    image: Image,
}

/// Exclusive MAC-authenticated public authority state and revocable read leases.
/// Keep this original database and key outside journal backups. Its MAC does not
/// detect rollback of the entire authority database or whole host. Association and
/// replacement approval must come from independent host authentication, never the old root alone.
/// This component alone does not attach authority checks to journals or services.
/// The current bounded format retains 64 associations and 256 original replacement
/// operations globally. Exhaustion fails explicitly; history must never be reset
/// to make space. Managed binding, lifetime migration and workflow integration remain required.
pub struct AccountAuthorityStore {
    active: Option<Active>,
    binding: [u8; 32],
    family: [u8; 32],
    pin: AnchorPin,
    runtime: Arc<Runtime>,
}
impl AccountAuthorityStore {
    /// Explicitly provision an empty authority registry under an already retained identity/key.
    pub fn provision(
        path: &Path,
        key: JournalKey,
        identity: AccountAuthorityIdentity,
        family: [u8; 32],
        pin: AnchorPin,
    ) -> Result<Self, DurableError> {
        nonzero(&family)?;
        crate::installation::validate_paths(&[path])?;
        let binding = codec::binding(path, &key, identity, family, pin.binding())?;
        let image = Image::default();
        let wire = codec::encode(&image, &key, binding)?;
        let db = provision_private_database(path, |db| codec::write(db, &wire))?;
        Ok(Self {
            active: Some(Active { db, key, image }),
            binding,
            family,
            runtime: Arc::new(Runtime::new(binding, family, pin.binding())),
            pin,
        })
    }
    /// Open only the original existing database. No error creates a replacement registry or key.
    pub fn open(
        path: &Path,
        key: JournalKey,
        identity: AccountAuthorityIdentity,
        family: [u8; 32],
        pin: AnchorPin,
    ) -> Result<Self, DurableError> {
        nonzero(&family)?;
        crate::installation::validate_paths(&[path])?;
        let binding = codec::binding(path, &key, identity, family, pin.binding())?;
        let db = open_private_database(path)?;
        let image = codec::read(&db, &key, binding)?;
        let current = image.current(family, &pin)?;
        let runtime = Arc::new(Runtime::new(binding, family, pin.binding()));
        runtime.publish(&current)?;
        Ok(Self {
            active: Some(Active { db, key, image }),
            binding,
            family,
            pin,
            runtime,
        })
    }
    /// Borrow a read capability. Closing/dropping the store revokes every such capability.
    pub fn access(&self) -> Result<AccountAuthorityAccess, DurableError> {
        self.active.as_ref().ok_or(DurableError::Closed)?;
        Ok(AccountAuthorityAccess(Arc::clone(&self.runtime)))
    }
    /// Bind a new application account to an independently verified original device/root.
    /// Root reuse across another association or a retained transition is refused.
    pub fn associate(
        &mut self,
        application: ApplicationAccountId,
        device: &VerifiedDevice,
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        if device.description.family != self.family
            || device.authority_key.shares_component(self.pin.public_key())
        {
            return Err(DurableError::Conflict);
        }
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let current = image.current(self.family, &self.pin)?;
        if let Some(saved) = current.get(&application) {
            if saved.root != device.authority_key {
                return Err(DurableError::Conflict);
            }
            return self.access()?.current(application);
        }
        if image.initial.len() == MAX_ACCOUNTS {
            return Err(DurableError::Capacity);
        }
        if image.root_seen(device.account_id()) {
            return Err(DurableError::Conflict);
        }
        image.initial.insert(
            application,
            Initial {
                root: device.authority_key.clone(),
                roster: device.roster().checkpoint(),
            },
        );
        image.current(self.family, &self.pin)?;
        self.save(image, application)?;
        self.access()?.current(application)
    }
    /// Select the current root with an independently obtained roster checkpoint at or above its floor.
    /// The resulting pin verifies identity; it is not a live operating capability.
    pub fn account_pin(
        &self,
        application: ApplicationAccountId,
        checkpoint: RosterCheckpoint,
    ) -> Result<AccountPin, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let current = active.image.current(self.family, &self.pin)?;
        let selected = current.get(&application).ok_or(DurableError::Absent)?;
        self.access()?.current(application)?;
        if checkpoint.version() < selected.roster.version()
            || (checkpoint.version() == selected.roster.version() && checkpoint != selected.roster)
        {
            return Err(Error::Checkpoint.into());
        }
        Ok(AccountPin::new(
            selected.checkpoint.account,
            selected.root.clone(),
            checkpoint,
            self.family,
        )?)
    }
    /// Durably retain the exact independently approved operation before reporting a root fence.
    /// Version input is the original observed checkpoint; callers cannot choose the next revision.
    pub fn begin_replacement(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        proposal: Proposal,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        self.begin_operation(expected, proposal, None)
    }
    /// Adopt the exact verified historical retirement. This selects the target root,
    /// but current policy, target enrollment and actual witness admission remain mandatory.
    pub fn commit_replacement(
        &mut self,
        retired: &AnchorRetiredAccount,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let original = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == retired.proposal().operation())
            .ok_or(DurableError::Absent)?;
        if original.state() == AccountAuthorityReplacementState::Preparing {
            return Err(DurableError::Suspended);
        }
        if &original.proposal != retired.proposal() {
            return Err(DurableError::Conflict);
        }
        if original.committed {
            return Ok(AccountAuthorityReplacementState::Committed);
        }
        original.committed = true;
        let application = original.application;
        self.save(image, application)?;
        Ok(AccountAuthorityReplacementState::Committed)
    }
    /// Read the retained exact proposal. Preparing returns Suspended; recover its
    /// original target and freeze request through `preparation` instead. Committed
    /// is history, not a claim that its target is still current.
    pub fn replacement(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<
        (
            ApplicationAccountId,
            AccountAuthorityReplacementState,
            &Proposal,
        ),
        DurableError,
    > {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let record = active
            .image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        if record.state() == AccountAuthorityReplacementState::Preparing {
            return Err(DurableError::Suspended);
        }
        Ok((record.application, record.state(), &record.proposal))
    }
    fn save(
        &mut self,
        image: Image,
        application: ApplicationAccountId,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let current = image.current(self.family, &self.pin)?;
            self.runtime.invalidate(application)?;
            let active = self.active.as_mut().ok_or(DurableError::Closed)?;
            let wire = codec::encode(&image, &active.key, self.binding)?;
            codec::write(&active.db, &wire)?;
            #[cfg(all(test, unix))]
            tests::after_preparation_commit(&image);
            active.image = image;
            self.runtime.publish(&current)?;
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Revoke readers before closing the database lease and erasing this key owner.
    pub fn close(&mut self) {
        self.runtime.close();
        self.active = None;
    }
}
impl Drop for AccountAuthorityStore {
    fn drop(&mut self) {
        self.close();
    }
}
