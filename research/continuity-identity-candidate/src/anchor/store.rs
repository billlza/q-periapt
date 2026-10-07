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
use lineage::OriginalIdentity;
mod replacement;
pub use replacement::{
    AnchorDeviceReplacementProposal, AnchorDeviceReplacementState, AnchorRetiredSubject,
};
mod retired_report;
pub use retired_report::{
    AnchorRetiredReport, AnchorRetiredReportProposal, AnchorRetiredReportState,
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
    revision: u64,
    digest: [u8; 32],
    entries: BTreeMap<[u8; 32], Entry>,
    replacements: BTreeMap<[u8; 32], AnchorDeviceReplacementProposal>,
    retired_cleanup: BTreeMap<[u8; 32], AnchorRetiredCleanupProposal>,
    retired_reports: BTreeMap<[u8; 32], AnchorRetiredReportProposal>,
}
struct Active {
    db: Database,
    wrapping: JournalKey,
    signer: AnchorSigningKey,
    pin: AnchorPin,
}

/// A bounded, durable witness with explicit trusted enrollment and authenticated
/// data-plane requests. Keep its state independent of protected journal snapshots.
/// Its own storage/key continuity remains a deployment trust requirement.
pub struct AnchorStore {
    active: Option<Active>,
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
            revision: 1,
            digest: [0; 32],
            entries: BTreeMap::new(),
            replacements: BTreeMap::new(),
            retired_cleanup: BTreeMap::new(),
            retired_reports: BTreeMap::new(),
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
            active: Some(Active {
                db,
                wrapping,
                signer,
                pin,
            }),
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
            active: Some(Active {
                db,
                wrapping,
                signer,
                pin,
            }),
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
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let id = subject.id(&active.pin.binding);
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
            .is_some_and(|binding| binding != active.pin.binding())
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
        let id = subject.id(&self.pin()?.binding);
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
        let id = subject.id(&self.pin()?.binding);
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
        let pin = self.pin()?;
        let request = incoming(&pin, wire)?;
        let mut image = self.image()?;
        if image.retirement(request.subject).is_some() {
            return Err(Error::Scope.into());
        }
        let entry = image
            .entries
            .get_mut(&request.subject.id(&pin.binding))
            .ok_or(Error::Scope)?;
        if entry.subject != request.subject {
            return Err(Error::Scope.into());
        }
        entry
            .device
            .verify(Purpose::AnchorRequest, request.body, request.signature)?;
        let roster_pending = entry
            .independent_roster
            .as_ref()
            .is_some_and(RosterRefresh::pending);
        let mut changed = false;
        let outcome = match request.operation.0 {
            Command::Query => AnchorOutcome::Current,
            Command::PolicyCommit(_)
            | Command::PolicyStatus(_)
            | Command::PolicyClose(_)
            | Command::PolicyAcknowledge(_) => {
                let (result, mutation) = entry.handle_independent_policy(&request, now)?;
                changed = mutation;
                result
            }
            Command::AdmitPolicy(authority, statement) => {
                let live = |v: Validity| match v.check(now) {
                    Ok(()) => Ok(true),
                    Err(Error::Validity) => Ok(false),
                    Err(e) => Err(e),
                };
                let state = entry.independent_policy.as_ref();
                let current = state.and_then(|s| s.current);
                if !roster_pending
                    && entry.authority == authority
                    && state.is_some_and(|s| !s.pending())
                    && current.is_some_and(|p| p.statement == statement)
                    && live(entry.validity)?
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::AdmitAuthority(expected) => {
                let live = match entry.validity.check(now) {
                    Ok(()) => true,
                    Err(Error::Validity) => false,
                    Err(error) => return Err(error.into()),
                };
                if !roster_pending
                    && entry.policy_authorization.is_none()
                    && entry
                        .independent_policy
                        .as_ref()
                        .is_none_or(|s| s.current.is_none() && !s.pending())
                    && entry.authority == expected
                    && live
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::AdmitContinuation(authority, credential, statement) => {
                let live = |validity: Validity| match validity.check(now) {
                    Ok(()) => Ok(true),
                    Err(Error::Validity) => Ok(false),
                    Err(error) => Err(error),
                };
                let policy_live = match entry.policy_authorization {
                    Some(policy) => policy.statement == statement && live(policy.validity)?,
                    None => false,
                };
                if !roster_pending
                    && entry.authority == authority
                    && entry.renewal.is_none()
                    && entry.credential_authorization == Some(credential)
                    && policy_live
                    && live(entry.validity)?
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::RosterCommit(_)
            | Command::RosterStatus(_)
            | Command::RosterClose(_)
            | Command::RosterAcknowledge(_) => {
                let (outcome, mutation) = entry.handle_independent_roster(&request, now)?;
                changed = mutation;
                outcome
            }
            Command::CredentialCommit(_)
            | Command::CredentialStatus(_)
            | Command::CredentialClose(_)
            | Command::CredentialAcknowledge(_) => {
                let (outcome, mutation) = entry.handle_renewal(&request, now)?;
                changed = mutation;
                outcome
            }
            Command::Advance(expected, next) | Command::Fence(expected, next) => {
                // Neither ordinary commands nor a writer fence may bypass an
                // unacknowledged joint transition, including its terminal state.
                if entry
                    .independent_roster
                    .as_ref()
                    .is_some_and(RosterRefresh::pending)
                    || entry.renewal.is_some()
                    || entry
                        .independent_policy
                        .as_ref()
                        .is_some_and(PolicyRenewal::pending)
                {
                    return Err(Error::State.into());
                }
                if entry.head == next && entry.last == Some(request.command) {
                    // Exact last-command confirmation is read-only after expiry too.
                    AnchorOutcome::AlreadyAppliedExact
                } else {
                    entry.validity.check(now)?;
                    if entry.head != expected {
                        AnchorOutcome::Conflict
                    } else {
                        entry.head = next;
                        entry.last = Some(request.command);
                        AnchorOutcome::Advanced
                    }
                }
            }
        };
        let (head, last) = (entry.head, entry.last);
        if changed || outcome == AnchorOutcome::Advanced {
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
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let result = load(&active.db, &active.wrapping, &active.pin);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn persist(&mut self, image: &mut Image) -> Result<(), DurableError> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            image.revision = increment(image.revision)?;
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
            tx.commit().map_err(DurableError::CommitUncertain)?;
            image.digest = image_digest(&bytes);
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
#[derive(Clone, Copy)]
struct EntryFormat {
    joint: bool,
    policy: bool,
    independent: bool,
    roster: bool,
    lineage: bool,
}
impl EntryFormat {
    const COMPLETE: Self = Self {
        joint: true,
        policy: true,
        independent: true,
        roster: true,
        lineage: true,
    };
}
fn encode_entry(
    entry: &Entry,
    pin: &AnchorPin,
    format: EntryFormat,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    entry.check_renewal_state(pin)?;
    if let Some(identity) = &entry.original_identity {
        identity.check(entry)?;
    }
    entry.subject.encode(out);
    out.extend_from_slice(&entry.device.encode());
    out.extend_from_slice(&entry.credential_owner);
    out.extend_from_slice(&entry.authority);
    entry.validity.encode(out);
    out.extend_from_slice(&entry.genesis);
    entry.head.encode(out);
    encode_last(entry.last, out);
    if format.joint {
        out.extend_from_slice(&entry.renewal_floor.to_be_bytes());
        out.push(u8::from(entry.renewal_ack.is_some()));
        out.extend_from_slice(&entry.renewal_ack.unwrap_or([0; 32]));
        if let Some(record) = &entry.renewal {
            record.encode(out);
        } else {
            out.push(0);
        }
    }
    if format.policy {
        out.extend_from_slice(&entry.policy_floor.to_be_bytes());
        match (entry.credential_authorization, entry.policy_authorization) {
            (None, None) => out.push(0),
            (Some(credential), Some(policy)) => {
                out.push(1);
                out.extend_from_slice(&credential);
                policy.encode(out);
            }
            _ => return Err(DurableError::Corrupt),
        }
    }
    if format.independent {
        match &entry.independent_policy {
            None => out.push(0),
            Some(state) => {
                out.push(1);
                state.encode(out);
            }
        }
    }
    if format.roster {
        match &entry.independent_roster {
            None => out.push(0),
            Some(state) => {
                out.push(1);
                state.encode(out);
            }
        }
    }
    if format.lineage {
        match &entry.original_identity {
            None => out.push(0),
            Some(identity) => {
                out.push(1);
                identity.encode(out);
            }
        }
    }
    Ok(())
}

fn encode(key: &JournalKey, pin: &AnchorPin, image: &Image) -> Result<Vec<u8>, DurableError> {
    if image.entries.len() > MAX_ENTRIES {
        return Err(DurableError::Capacity);
    }
    image.check_replacements(pin)?;
    image.check_retired_cleanup(pin)?;
    image.check_retired_reports(pin)?;
    let report_format = !image.retired_reports.is_empty();
    let cleanup_format = report_format || !image.retired_cleanup.is_empty();
    let replacement_format = cleanup_format || !image.replacements.is_empty();
    let lineage_format = replacement_format
        || image
            .entries
            .values()
            .any(|entry| entry.original_identity.is_some());
    let roster_format = lineage_format
        || image
            .entries
            .values()
            .any(|entry| entry.independent_roster.is_some());
    let independent = roster_format
        || image
            .entries
            .values()
            .any(|entry| entry.independent_policy.is_some());
    let joint = image
        .entries
        .values()
        .any(|entry| entry.renewal_floor != 0 || entry.renewal.is_some());
    let cancellation = image.entries.values().any(|entry| {
        entry
            .renewal
            .as_ref()
            .is_some_and(CredentialRenewalRecord::is_cancellation)
    });
    let policy_format = image.entries.values().any(|entry| {
        entry.policy_floor != 0
            || entry.policy_authorization.is_some()
            || entry.credential_authorization.is_some()
            || entry
                .renewal
                .as_ref()
                .is_some_and(CredentialRenewalRecord::has_policy)
    });
    let policy_cancellation = image.entries.values().any(|e| {
        e.renewal
            .as_ref()
            .is_some_and(CredentialRenewalRecord::is_policy_cancellation)
    });
    let mut bytes = if report_format {
        b"QPANC013".to_vec()
    } else if cleanup_format {
        b"QPANC012".to_vec()
    } else if replacement_format {
        b"QPANC011".to_vec()
    } else if lineage_format {
        b"QPANC010".to_vec()
    } else if roster_format {
        b"QPANC009".to_vec()
    } else if independent {
        b"QPANC008".to_vec()
    } else if policy_cancellation {
        b"QPANC007".to_vec()
    } else if policy_format {
        b"QPANC006".to_vec()
    } else if cancellation {
        b"QPANC004".to_vec()
    } else if joint {
        b"QPANC003".to_vec()
    } else {
        b"QPANC002".to_vec()
    };
    bytes.extend_from_slice(&pin.binding);
    bytes.extend_from_slice(&image.revision.to_be_bytes());
    bytes.extend_from_slice(&(image.entries.len() as u16).to_be_bytes());
    for (id, entry) in &image.entries {
        bytes.extend_from_slice(id);
        encode_entry(
            entry,
            pin,
            EntryFormat {
                joint: joint || policy_format || independent,
                policy: policy_format || independent,
                independent,
                roster: roster_format,
                lineage: lineage_format,
            },
            &mut bytes,
        )?;
    }
    if replacement_format {
        bytes.extend_from_slice(
            &u16::try_from(image.replacements.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for (binding, proposal) in &image.replacements {
            bytes.extend_from_slice(binding);
            let encoded = proposal.to_bytes()?;
            bytes.extend_from_slice(
                &u32::try_from(encoded.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&encoded);
        }
    }
    if cleanup_format {
        retired_cleanup::encode_records(&image.retired_cleanup, &mut bytes)?;
    }
    if report_format {
        retired_report::encode_records(&image.retired_reports, &mut bytes)?;
    }
    if bytes.len() + 32 > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    let mut auth = authenticator(key)?;
    auth.update(&bytes);
    bytes.extend_from_slice(&auth.finalize().into_bytes());
    Ok(bytes)
}
fn decode(key: &JournalKey, pin: &AnchorPin, bytes: &[u8]) -> Result<Image, DurableError> {
    let result = (|| {
        if !(82..=MAX_IMAGE).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let version = d.array::<8>()?;
        let has_replacement = [*b"QPANC011", *b"QPANC012", *b"QPANC013"].contains(&version);
        if ![
            *b"QPANC001",
            *b"QPANC002",
            *b"QPANC003",
            *b"QPANC004",
            *b"QPANC006",
            *b"QPANC007",
            *b"QPANC008",
            *b"QPANC009",
            *b"QPANC010",
            *b"QPANC011",
            *b"QPANC012",
            *b"QPANC013",
        ]
        .contains(&version)
            || d.array::<32>()? != pin.binding
        {
            return Err(DurableError::Conflict);
        }
        let revision = d.u64()?;
        generation(revision)?;
        let count = usize::from(d.u16()?);
        if count > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        let mut entries = BTreeMap::new();
        let mut previous = None;
        let mut owners = std::collections::BTreeSet::new();
        for _ in 0..count {
            let id = d.array()?;
            if previous.is_some_and(|previous| previous >= id) {
                return Err(DurableError::Corrupt);
            }
            previous = Some(id);
            let subject = AnchorSubject::decode(&mut d)?;
            let device = PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?;
            let credential_owner = if version != *b"QPANC001" {
                let owner = d.array()?;
                nonzero(&owner)?;
                owner
            } else {
                subject.owner
            };
            let authority = d.array()?;
            nonzero(&authority)?;
            let validity = Validity::decode(&mut d)?;
            let genesis = d.array()?;
            nonzero(&genesis)?;
            let head = AnchorHead::decode(&mut d)?;
            let last = decode_last(&mut d, head)?;
            let (renewal_floor, renewal_ack, renewal) = if [
                *b"QPANC003",
                *b"QPANC004",
                *b"QPANC006",
                *b"QPANC007",
                *b"QPANC008",
                *b"QPANC009",
                *b"QPANC010",
                *b"QPANC011",
                *b"QPANC012",
                *b"QPANC013",
            ]
            .contains(&version)
            {
                let floor = d.u64()?;
                let [present] = d.array()?;
                let binding = d.array()?;
                let ack = match present {
                    0 if binding == [0; 32] => None,
                    1 => {
                        nonzero(&binding)?;
                        Some(binding)
                    }
                    _ => return Err(DurableError::Corrupt),
                };
                (
                    floor,
                    ack,
                    CredentialRenewalRecord::decode(
                        &mut d,
                        [
                            *b"QPANC004",
                            *b"QPANC006",
                            *b"QPANC007",
                            *b"QPANC008",
                            *b"QPANC009",
                            *b"QPANC010",
                            *b"QPANC011",
                            *b"QPANC012",
                            *b"QPANC013",
                        ]
                        .contains(&version),
                        version == *b"QPANC006"
                            || version == *b"QPANC007"
                            || version == *b"QPANC008"
                            || version == *b"QPANC009"
                            || (version == *b"QPANC010" || has_replacement),
                        version == *b"QPANC007"
                            || version == *b"QPANC008"
                            || version == *b"QPANC009"
                            || (version == *b"QPANC010" || has_replacement),
                    )?,
                )
            } else {
                (0, None, None)
            };
            let (policy_floor, credential_authorization, policy_authorization) = if version
                == *b"QPANC006"
                || version == *b"QPANC007"
                || version == *b"QPANC008"
                || version == *b"QPANC009"
                || (version == *b"QPANC010" || has_replacement)
            {
                let floor = d.u64()?;
                let (credential, policy) = match d.array::<1>()? {
                    [0] => (None, None),
                    [1] => {
                        let credential = d.array()?;
                        nonzero(&credential)?;
                        (Some(credential), Some(PolicyAuthority::decode(&mut d)?))
                    }
                    _ => return Err(DurableError::Corrupt),
                };
                (floor, credential, policy)
            } else {
                (0, None, None)
            };
            let independent_policy = if version == *b"QPANC008"
                || version == *b"QPANC009"
                || (version == *b"QPANC010" || has_replacement)
            {
                match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(PolicyRenewal::decode(&mut d)?),
                    _ => return Err(DurableError::Corrupt),
                }
            } else {
                None
            };
            let independent_roster =
                if version == *b"QPANC009" || (version == *b"QPANC010" || has_replacement) {
                    match d.array::<1>()? {
                        [0] => None,
                        [1] => Some(RosterRefresh::decode(&mut d)?),
                        _ => return Err(DurableError::Corrupt),
                    }
                } else {
                    None
                };
            let original_identity = if version == *b"QPANC010" || has_replacement {
                match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(OriginalIdentity::decode(&mut d)?),
                    _ => return Err(DurableError::Corrupt),
                }
            } else {
                None
            };
            if id != subject.id(&pin.binding)
                || device.shares_component(&pin.key)
                || !owners.insert(subject.owner)
                || (last.is_none() && head.digest != genesis)
            {
                return Err(DurableError::Corrupt);
            }
            let entry = Entry {
                subject,
                original_identity,
                device,
                credential_owner,
                authority,
                validity,
                genesis,
                head,
                last,
                renewal_floor,
                renewal_ack,
                renewal,
                credential_authorization,
                policy_authorization,
                policy_floor,
                independent_policy,
                independent_roster,
            };
            entry.check_renewal_state(pin)?;
            if let Some(identity) = &entry.original_identity {
                identity.check(&entry)?;
            }
            entries.insert(id, entry);
        }
        let replacements = if has_replacement {
            replacement::decode_decisions(&mut d)?
        } else {
            BTreeMap::new()
        };
        let retired_cleanup = if version == *b"QPANC012" || version == *b"QPANC013" {
            retired_cleanup::decode_records(&mut d, pin)?
        } else {
            BTreeMap::new()
        };
        let retired_reports = if version == *b"QPANC013" {
            retired_report::decode_records(&mut d, pin)?
        } else {
            BTreeMap::new()
        };
        d.finish()?;
        if (version == *b"QPANC010" || has_replacement)
            && !entries
                .values()
                .any(|entry| entry.original_identity.is_some())
        {
            return Err(DurableError::Corrupt);
        }
        let image = Image {
            revision,
            digest: image_digest(bytes),
            entries,
            replacements,
            retired_cleanup,
            retired_reports,
        };
        image.check_replacements(pin)?;
        image.check_retired_cleanup(pin)?;
        image.check_retired_reports(pin)?;
        if has_replacement && image.replacements.is_empty() {
            return Err(DurableError::Corrupt);
        }
        Ok(image)
    })();
    match result {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        other => other,
    }
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
