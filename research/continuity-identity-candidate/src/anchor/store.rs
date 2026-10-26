// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    durable::{storage, transaction},
    DurableError, JournalKey, PrekeyQuality, Validity, PUBLIC_KEY_BYTES,
};
use hmac::{Hmac, Mac};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::ReadableDatabase;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use sha2::Sha256;
use std::{collections::BTreeMap, path::Path};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_anchor_candidate_v1");
const MAX_ENTRIES: usize = 256;
const MAX_IMAGE: usize = 1024 * 1024;

#[cfg(all(test, unix))]
mod tests;

mod lineage;
mod pending_recovery;
use lineage::OriginalIdentity;
mod image_codec;
use image_codec::{decode, encode, encode_entry, EntryFormat};
mod image_authority;
use image_authority::ImageAuthority;
mod handoff_source;
pub use handoff_source::AnchorHandoffSourceState;
mod handoff;
pub use handoff::{
    AnchorHandoffActivationReceipt, AnchorHandoffClientAuthorizationReceipt, AnchorHandoffHistory,
    AnchorHandoffImportReceipt, AnchorHandoffObserver, AnchorHandoffPlan, AnchorHandoffReceipt,
    AnchorHandoffState, AnchorHandoffTarget, AnchorHandoffTargetApproval, AnchorHandoffTargetState,
};
mod image_version;
use image_version::ImageVersion;
mod account_replacement;
pub use account_replacement::{
    AnchorAccountFreezeId, AnchorAccountFreezeRequest, AnchorAccountReplacementId,
    AnchorAccountReplacementPlan, AnchorAccountReplacementProposal, AnchorAccountReplacementState,
    AnchorClosedAccountPreparation, AnchorClosedAccountReplacement, AnchorFrozenAccount,
    AnchorRetiredAccount, AnchorRetiredAccountSubject, AnchorTransferredAccountFreezeApproval,
    AnchorTransferredAccountFreezeProposal,
};
mod replacement;
pub use replacement::{
    AnchorDeviceReplacementProposal, AnchorDeviceReplacementState, AnchorRetiredSubject,
};
mod retired_report;
pub use retired_report::{
    AnchorRetiredReport, AnchorRetiredReportAcknowledgement,
    AnchorRetiredReportAcknowledgementState, AnchorRetiredReportProposal, AnchorRetiredReportState,
};
mod retired_cleanup;
pub use retired_cleanup::{
    AnchorRetiredCleanup, AnchorRetiredCleanupProposal, AnchorRetiredCleanupState,
};
mod roster_refresh;
use roster_refresh::RosterRefresh;
mod policy_renewal;
use policy_renewal::PolicyRenewal;
mod renewal;
use renewal::{CredentialRenewalRecord, PolicyAuthority};

mod commands;
mod transferred;
mod transferred_control;
pub use transferred_control::AnchorTransferredControl;

struct Entry {
    subject: AnchorSubject,
    original_identity: Option<OriginalIdentity>,
    device: PublicKey,
    credential_owner: [u8; 32],
    authority: [u8; 32],
    validity: Validity,
    genesis: [u8; 32],
    head: AnchorHead,
    last: Option<[u8; 32]>,
    renewal_floor: u64,
    renewal_ack: Option<[u8; 32]>,
    renewal: Option<CredentialRenewalRecord>,
    credential_authorization: Option<[u8; 32]>,
    policy_authorization: Option<PolicyAuthority>,
    policy_floor: u64,
    independent_policy: Option<PolicyRenewal>,
    independent_roster: Option<RosterRefresh>,
}
struct Image {
    namespace: [u8; 32],
    inherited: std::collections::BTreeSet<[u8; 32]>,
    revision: u64,
    digest: [u8; 32],
    entries: BTreeMap<[u8; 32], Entry>,
    replacements: BTreeMap<[u8; 32], AnchorDeviceReplacementProposal>,
    retired_cleanup: BTreeMap<[u8; 32], AnchorRetiredCleanupProposal>,
    retired_reports: BTreeMap<[u8; 32], retired_report::ReportRecord>,
    account_replacements: BTreeMap<[u8; 32], AnchorAccountReplacementProposal>,
    account_freezes: BTreeMap<[u8; 32], AnchorFrozenAccount>,
    account_closures: BTreeMap<[u8; 32], account_replacement::closure::ClosureRecord>,
    // Optional handoff receipts are large. Keep image moves and nested source
    // validation bounded by a pointer rather than the entire absent journal.
    handoff: Option<Box<handoff::Journal>>,
}
struct Active {
    transferred: Option<handoff::Transferred>,
    db: Database,
    wrapping: JournalKey,
    signer: AnchorSigningKey,
    pin: AnchorPin,
}

/// A bounded, durable witness with explicit trusted enrollment and authenticated
/// data-plane requests. Keep its state independent of protected journal snapshots.
/// Its own storage/key continuity remains a deployment trust requirement.
pub struct AnchorStore {
    // Moving the public owner must not copy its signer and verified history
    // onto each caller's stack. Closing still drops this entire controlled state.
    active: Option<Box<Active>>,
}
impl AnchorStore {
    /// Provision a new empty witness. The instance ID and verification key must be
    /// distributed through independent trusted configuration, not an incoming reply.
    pub fn provision(
        path: &Path,
        wrapping: JournalKey,
        signer: AnchorSigningKey,
        identity: AnchorIdentity,
    ) -> Result<Self, DurableError> {
        let pin = AnchorPin::new(identity, signer.public_key()?);
        let image = Image {
            namespace: pin.binding,
            inherited: Default::default(),
            revision: 1,
            digest: [0; 32],
            entries: BTreeMap::new(),
            replacements: BTreeMap::new(),
            retired_cleanup: BTreeMap::new(),
            retired_reports: BTreeMap::new(),
            account_replacements: BTreeMap::new(),
            account_freezes: BTreeMap::new(),
            account_closures: BTreeMap::new(),
            handoff: None,
        };
        let bytes = encode(&wrapping, &pin, &image)?;
        let db = provision_private_database(path, |db| {
            let tx = transaction(db)?;
            tx.open_table(TABLE)
                .map_err(storage)?
                .insert("image", bytes.as_slice())
                .map_err(storage)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            Ok::<_, DurableError>(())
        })?;
        Ok(Self {
            active: Some(Box::new(Active {
                transferred: None,
                db,
                wrapping,
                signer,
                pin,
            })),
        })
    }
    /// Reopen the same witness instance and key. Missing/corrupt state never creates
    /// a fresh witness or resets an enrolled journal to genesis.
    pub fn open(
        path: &Path,
        wrapping: JournalKey,
        signer: AnchorSigningKey,
        identity: AnchorIdentity,
    ) -> Result<Self, DurableError> {
        let pin = AnchorPin::new(identity, signer.public_key()?);
        let db = open_private_database(path)?;
        load(&db, &wrapping, &pin)?;
        Ok(Self {
            active: Some(Box::new(Active {
                transferred: None,
                db,
                wrapping,
                signer,
                pin,
            })),
        })
    }
    /// Return provisioning metadata from the existing trusted owner.
    pub fn pin(&self) -> Result<AnchorPin, DurableError> {
        Ok(self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .pin
            .clone())
    }
    fn namespace(&self) -> Result<[u8; 32], DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        Ok(active
            .transferred
            .as_ref()
            .map_or(active.pin.binding, |t| t.namespace()))
    }
    /// Release the database lease and erase this instance's wrapping/signing owners.
    pub fn close(&mut self) {
        self.active = None;
    }
    /// Trusted control-plane enrollment of a new journal at revision/fence 1.
    /// The operator must independently validate the supplied account/roster/policy
    /// pins and genesis image. Ordinary request bytes cannot call this operation.
    /// Exact retries never reset an already advanced entry. A known device ID
    /// requires explicit replacement; unclassified legacy identities suspend new
    /// enrollment until their original authenticated metadata is retained.
    pub fn enroll(
        &mut self,
        genesis: &AnchorGenesis,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        let subject = genesis.subject;
        let genesis = genesis.digest;
        let validity = self.admit_enrollment(subject, device, policy, now)?;
        let id = subject.id(&self.namespace()?);
        let mut image = self.image()?;
        image.require_live(subject)?;
        if let Some(entry) = image.entries.get(&id) {
            return if entry.subject == subject
                && entry.device == device.key
                && entry.credential_owner == storage_owner(device)
                && entry.validity == validity
                && entry.authority == device.authority_binding()
                && entry.genesis == genesis
            {
                Ok(())
            } else {
                Err(DurableError::Conflict)
            };
        }
        image.admit_new_device(device)?;
        if image
            .entries
            .values()
            .any(|entry| entry.subject.owner == subject.owner)
        {
            return Err(DurableError::Conflict);
        }
        if image.entries.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image
            .entries
            .insert(id, Entry::at_genesis(subject, genesis, device, validity)?);
        self.persist(&mut image)
    }
    fn admit_enrollment(
        &self,
        subject: AnchorSubject,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Validity, DurableError> {
        if subject.owner != storage_owner(device) || subject.policy != policy.checkpoint().digest()
        {
            return Err(Error::Scope.into());
        }
        self.admit_current_device(device, policy, now)
    }
    fn admit_current_device(
        &self,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Validity, DurableError> {
        let binding = self.pin()?.binding();
        self.admit_current_device_with_binding(device, policy, now, binding)
    }
    fn admit_current_device_with_binding(
        &self,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
        binding: [u8; 32],
    ) -> Result<Validity, DurableError> {
        let quality = [
            PrekeyQuality::OneTimeBoth,
            PrekeyQuality::ReusableBoth,
            PrekeyQuality::SignedClassicalOneTimePq,
            PrekeyQuality::OneTimeClassicalLastResortPq,
        ]
        .into_iter()
        .find(|quality| policy.allowed_modes().permits(*quality))
        .ok_or(Error::PolicyDenied)?;
        policy.check_mode(quality, now)?;
        policy.check_device(device, now)?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        if policy
            .anchor_requirement()
            .binding()
            .is_some_and(|required| required != binding)
        {
            return Err(Error::Scope.into());
        }
        if active.pin.key.shares_component(&device.key)
            || active.pin.key.shares_component(&device.authority_key)
        {
            return Err(Error::Scope.into());
        }
        policy.check_external_signer(&active.pin.key)?;
        enrollment_validity(device, policy)
    }
    /// Explicit trusted control-plane refresh for the SAME credential and policy.
    /// Restore `subject` from the original trusted configuration; it must already
    /// exist in this witness. `previous` is an independently retained expectation,
    /// not historical authority. The operator independently admits the current
    /// next roster; ordinary signed requests cannot invoke this method. It must be
    /// newer than the expected predecessor and still contain the exact device
    /// credential. Credential/key/policy replacement
    /// requires a different lifecycle transaction.
    ///
    /// Compare the retained enrollment authority with `previous`, or reconcile an
    /// already-current exact `next` target. Preserve subject, genesis, head, fence
    /// and the last data-plane command. A storage error closes the owner; reopen
    /// and retry the same inputs. The returned checkpoint confirms current state,
    /// not which invocation committed it. Expired targets grant no renewed authority.
    pub fn update_roster_authority(
        &mut self,
        subject: AnchorSubject,
        previous: crate::RosterCheckpoint,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::RosterCheckpoint, DurableError> {
        let id = subject.id(&self.namespace()?);
        let mut image = self.image()?;
        image.require_live(subject)?;
        let entry = match image.entries.get_mut(&id) {
            Some(entry) => entry,
            // Only an enrolled subject with retained T can explain a policy
            // different from its original P0. Preserve the original scope error.
            None if subject.policy != policy.checkpoint().digest() => {
                return Err(Error::Scope.into())
            }
            None => return Err(DurableError::Absent),
        };
        match entry
            .independent_policy
            .as_ref()
            .and_then(|p| p.current)
            .or(entry.policy_authorization)
        {
            None if subject.policy == policy.checkpoint().digest() => {}
            Some(current)
                if current.checkpoint == policy.checkpoint()
                    && current.validity == policy.validity() => {}
            _ => return Err(Error::Scope.into()),
        }
        if entry.independent_roster.is_some() {
            return Err(DurableError::Conflict);
        }
        let validity = self.admit_current_device(next, policy, now)?;
        if next.checkpoint.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        let expected =
            crate::identity::authority_binding(next.account, previous, next.description.family);
        if entry.renewal.is_some()
            || entry
                .independent_policy
                .as_ref()
                .is_some_and(PolicyRenewal::pending)
        {
            return Err(DurableError::Suspended);
        }
        if entry.renewal_floor != 0 && next.checkpoint.version() <= entry.renewal_floor {
            return Err(Error::Retired.into());
        }
        if entry.credential_owner != storage_owner(next) {
            return Err(Error::Scope.into());
        }
        if entry.subject != subject || entry.device != next.key {
            return Err(DurableError::Conflict);
        }
        if entry.authority == next.authority_binding() && entry.validity == validity {
            return Ok(next.checkpoint);
        }
        if entry.authority != expected {
            return Err(DurableError::Conflict);
        }
        entry.authority = next.authority_binding();
        entry.validity = validity;
        self.persist(&mut image)?;
        self.admit_current_device(next, policy, now)?;
        Ok(next.checkpoint)
    }
    /// Independently adopt a root-authorized same-key credential renewal for the
    /// ORIGINAL witness subject. The operator verifies the grant against current
    /// independent account/roster/policy pins and retains its operation before
    /// calling this trusted control-plane method. Ordinary requests cannot call it.
    ///
    /// Compare the exact predecessor credential, roster authority and validity,
    /// or observe an already-current exact target. Preserve subject, genesis,
    /// head, fence and last data-plane command. A returned checkpoint confirms
    /// current state, not which invocation committed it. Errors during storage
    /// close the owner; reopen the same store and reconcile the original inputs.
    /// Expired targets cannot renew authority, even on a previously applied retry.
    pub fn renew_credential_authority(
        &mut self,
        subject: AnchorSubject,
        grant: &crate::VerifiedCredentialRenewal,
        operation: crate::CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::RosterCheckpoint, DurableError> {
        if grant.operation() != operation
            || subject.owner != grant.original_storage_owner()
            || subject.policy != grant.policy_digest()
            || subject.policy != policy.checkpoint().digest()
        {
            return Err(Error::Scope.into());
        }
        let next = grant.successor_device();
        let previous = grant.previous_device();
        let validity = self.admit_current_device(next, policy, now)?;
        let id = subject.id(&self.namespace()?);
        let mut image = self.image()?;
        image.require_live(subject)?;
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        // Once this subject uses joint renewal, terminal retirement must never
        // reopen the legacy authority-only path for an old signed target.
        if entry.renewal.is_some()
            || entry.renewal_floor != 0
            || entry.independent_policy.is_some()
            || entry.independent_roster.is_some()
        {
            return Err(DurableError::Suspended);
        }
        if entry.subject != subject || entry.device != next.key || entry.device != previous.key {
            return Err(DurableError::Conflict);
        }
        let next_owner = storage_owner(next);
        if entry.credential_owner == next_owner
            && entry.authority == next.authority_binding()
            && entry.validity == validity
        {
            return Ok(next.checkpoint);
        }
        if entry.credential_owner != storage_owner(previous)
            || entry.authority != previous.authority_binding()
            || entry.validity != enrollment_validity(previous, policy)?
        {
            return Err(DurableError::Conflict);
        }
        entry.credential_owner = next_owner;
        entry.authority = next.authority_binding();
        entry.validity = validity;
        self.persist(&mut image)?;
        Ok(next.checkpoint)
    }
    /// Handle one bounded dual-signed request. Sign a reply only after any exact
    /// state/fence mutation commits. Fresh query challenges prevent receipt replay;
    /// a missing reply always requires reconciliation of the original command.
    pub fn handle(&mut self, wire: &[u8], now: u64) -> Result<Vec<u8>, AnchorError> {
        if crate::anchor::transferred::is_request(wire) {
            return self.handle_transferred(wire, now);
        }
        let pin = self.pin()?;
        let request = incoming(&pin, wire)?;
        let mut image = self.image()?;
        if image.subject_retired(request.subject) || image.subject_frozen(request.subject) {
            return Err(Error::Scope.into());
        }
        image.require_adopted(request.subject)?;
        let entry = image
            .entries
            .get_mut(&request.subject.id(&image.namespace))
            .ok_or(Error::Scope)?;
        if entry.subject != request.subject {
            return Err(Error::Scope.into());
        }
        entry
            .device
            .verify(Purpose::AnchorRequest, request.body, request.signature)?;
        let (outcome, changed) = entry.execute(&request, now)?;
        let (head, last) = (entry.head, entry.last);
        if changed {
            self.persist(&mut image)?;
        }
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        match reply(&pin, &active.signer, &request, outcome, head, last) {
            Ok(wire) => Ok(wire),
            Err(error) => {
                self.close();
                Err(AnchorError::ReplyUnavailable(error))
            }
        }
    }
    fn image(&mut self) -> Result<Image, DurableError> {
        let image = self.handoff_image()?;
        if image
            .handoff
            .as_ref()
            .is_some_and(|state| state.frozen.is_some())
        {
            return Err(DurableError::Suspended);
        }
        Ok(image)
    }
    fn handoff_image(&mut self) -> Result<Image, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let result = match &active.transferred {
            None => load(&active.db, &active.wrapping, &active.pin),
            Some(transferred) => transferred.load(&active.db, &active.wrapping),
        };
        if result.is_err() {
            self.close();
        }
        result
    }
    fn persist(&mut self, image: &mut Image) -> Result<(), DurableError> {
        if image
            .handoff
            .as_ref()
            .is_some_and(|state| state.frozen.is_some())
        {
            return Err(DurableError::Suspended);
        }
        self.persist_image(image, true)
    }
    fn persist_image(
        &mut self,
        image: &mut Image,
        advance_revision: bool,
    ) -> Result<(), DurableError> {
        self.persist_image_checked(image, advance_revision, || Ok(()))
    }

    fn persist_image_checked(
        &mut self,
        image: &mut Image,
        advance_revision: bool,
        admit_commit: impl FnOnce() -> Result<(), DurableError>,
    ) -> Result<(), DurableError> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            if advance_revision {
                image.revision = increment(image.revision)?;
            }
            if let Some(transferred) = &active.transferred {
                if advance_revision {
                    transferred.persist(&active.db, &active.wrapping, image, admit_commit)?;
                } else {
                    transferred.persist_handoff(
                        &active.db,
                        &active.wrapping,
                        image,
                        admit_commit,
                    )?;
                }
            } else {
                let bytes = encode(&active.wrapping, &active.pin, image)?;
                let tx = transaction(&active.db)?;
                {
                    let mut table = tx.open_table(TABLE).map_err(storage)?;
                    if table.len().map_err(storage)? != 1 {
                        return Err(DurableError::Corrupt);
                    }
                    let current = table
                        .get("image")
                        .map_err(storage)?
                        .ok_or(DurableError::Corrupt)?;
                    if image_digest(current.value()) != image.digest {
                        return Err(DurableError::Conflict);
                    }
                    drop(current);
                    table.insert("image", bytes.as_slice()).map_err(storage)?;
                }
                admit_commit()?;
                tx.commit().map_err(DurableError::CommitUncertain)?;
                image.digest = image_digest(&bytes);
            }
            #[cfg(all(test, unix))]
            tests::after_commit(image);
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

fn enrollment_validity(
    device: &VerifiedDevice,
    policy: &impl AsRef<crate::HistoricalSessionPolicy>,
) -> Result<Validity, DurableError> {
    enrollment_interval(device, policy.as_ref().validity())
}
fn enrollment_interval(
    device: &VerifiedDevice,
    policy: Validity,
) -> Result<Validity, DurableError> {
    Ok(Validity::new(
        device
            .description
            .validity
            .from()
            .max(device.roster_validity.from())
            .max(policy.from()),
        device
            .description
            .validity
            .until()
            .min(device.roster_validity.until())
            .min(policy.until()),
    )?)
}

fn authenticator(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.anchor_state_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
fn image_digest(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-IMAGE/v1", bytes)
}
fn load(db: &Database, key: &JournalKey, pin: &AnchorPin) -> Result<Image, DurableError> {
    let tx = db.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx
        .list_tables()
        .map_err(storage)?
        .map(|table| table.name().to_owned())
        .collect();
    if tables != [TABLE.name()] || tx.list_multimap_tables().map_err(storage)?.next().is_some() {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let value = table
        .get("image")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    decode(key, pin, value.value())
}
