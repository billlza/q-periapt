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

mod renewal;
use renewal::CredentialRenewalRecord;

struct Entry {
    subject: AnchorSubject,
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
}
struct Image {
    revision: u64,
    digest: [u8; 32],
    entries: BTreeMap<[u8; 32], Entry>,
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
    /// Exact retries never reset an already advanced entry.
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
        let head = AnchorHead::from_trusted_state(1, 1, genesis)?;
        let id = subject.id(&active.pin.binding);
        let mut image = self.image()?;
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
        image.entries.insert(
            id,
            Entry {
                subject,
                device: device.key.clone(),
                credential_owner: storage_owner(device),
                authority: device.authority_binding(),
                validity,
                genesis,
                head,
                last: None,
                renewal_floor: 0,
                renewal_ack: None,
                renewal: None,
            },
        );
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
        if subject.policy != policy.checkpoint().digest() {
            return Err(Error::Scope.into());
        }
        let validity = self.admit_current_device(next, policy, now)?;
        if next.checkpoint.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        let expected =
            crate::identity::authority_binding(next.account, previous, next.description.family);
        let id = subject.id(&self.pin()?.binding);
        let mut image = self.image()?;
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        if entry.renewal.is_some() {
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
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        // Once this subject uses joint renewal, terminal retirement must never
        // reopen the legacy authority-only path for an old signed target.
        if entry.renewal.is_some() || entry.renewal_floor != 0 {
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
        let mut changed = false;
        let outcome = match request.operation.0 {
            Command::Query => AnchorOutcome::Current,
            Command::AdmitAuthority(expected) => {
                let live = match entry.validity.check(now) {
                    Ok(()) => true,
                    Err(Error::Validity) => false,
                    Err(error) => return Err(error.into()),
                };
                if entry.authority == expected && live {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
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
                if entry.renewal.is_some() {
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
    policy: &VerifiedSessionPolicy,
) -> Result<Validity, DurableError> {
    Ok(Validity::new(
        device
            .description
            .validity
            .from()
            .max(device.roster_validity.from())
            .max(policy.validity().from()),
        device
            .description
            .validity
            .until()
            .min(device.roster_validity.until())
            .min(policy.validity().until()),
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
fn encode(key: &JournalKey, pin: &AnchorPin, image: &Image) -> Result<Vec<u8>, DurableError> {
    if image.entries.len() > MAX_ENTRIES {
        return Err(DurableError::Capacity);
    }
    let joint = image
        .entries
        .values()
        .any(|entry| entry.renewal_floor != 0 || entry.renewal.is_some());
    let mut bytes = if joint {
        b"QPANC003".to_vec()
    } else {
        b"QPANC002".to_vec()
    };
    bytes.extend_from_slice(&pin.binding);
    bytes.extend_from_slice(&image.revision.to_be_bytes());
    bytes.extend_from_slice(&(image.entries.len() as u16).to_be_bytes());
    for (id, entry) in &image.entries {
        entry.check_renewal_state(pin)?;
        bytes.extend_from_slice(id);
        entry.subject.encode(&mut bytes);
        bytes.extend_from_slice(&entry.device.encode());
        bytes.extend_from_slice(&entry.credential_owner);
        bytes.extend_from_slice(&entry.authority);
        entry.validity.encode(&mut bytes);
        bytes.extend_from_slice(&entry.genesis);
        entry.head.encode(&mut bytes);
        encode_last(entry.last, &mut bytes);
        if joint {
            bytes.extend_from_slice(&entry.renewal_floor.to_be_bytes());
            bytes.push(u8::from(entry.renewal_ack.is_some()));
            bytes.extend_from_slice(&entry.renewal_ack.unwrap_or([0; 32]));
            if let Some(record) = &entry.renewal {
                record.encode(&mut bytes);
            } else {
                bytes.push(0);
            }
        }
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
        if ![*b"QPANC001", *b"QPANC002", *b"QPANC003"].contains(&version)
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
            let (renewal_floor, renewal_ack, renewal) = if version == *b"QPANC003" {
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
                (floor, ack, CredentialRenewalRecord::decode(&mut d)?)
            } else {
                (0, None, None)
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
            };
            entry.check_renewal_state(pin)?;
            entries.insert(id, entry);
        }
        d.finish()?;
        Ok(Image {
            revision,
            digest: image_digest(bytes),
            entries,
        })
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
