// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Persist the exact sealed aggregate before attempting its state transaction.
use super::*;
use hmac::{Hmac, Mac};
use redb::ReadableDatabase;
use sha2::Sha256;

const INTENT_HEADER: usize = 8 + 32 + 32 + 8 + 32 + 8 + 32 + 4;
const MAX_TARGET: usize = HEADER + MAX_IMAGE + 16;
const RENEWAL_BINDING_BYTES: usize = 64;

#[cfg(all(test, unix))]
pub(super) mod tests;

pub(super) struct PendingWrite {
    expected_revision: u64,
    expected_digest: [u8; 32],
    next_revision: u64,
    next_digest: [u8; 32],
    target: Vec<u8>,
    wire: Vec<u8>,
    protection: Protection,
    local_account: [u8; 32],
    renewal: Option<(crate::CredentialRenewalId, [u8; 32])>,
}
impl PendingWrite {
    pub(super) fn authenticated_target(
        &self,
        key: &JournalKey,
        owner: [u8; 32],
    ) -> Result<Image, DurableError> {
        unseal(key, owner, &self.target)
    }

    fn new(active: &Active, image: &Image, target: &[u8]) -> Result<Self, DurableError> {
        Self::new_bound(active, image, target, None)
    }
    fn new_bound(
        active: &Active,
        image: &Image,
        target: &[u8],
        renewal: Option<(crate::CredentialRenewalId, [u8; 32])>,
    ) -> Result<Self, DurableError> {
        let expected_revision = image.revision.checked_sub(1).ok_or(DurableError::Corrupt)?;
        let mut wire = if renewal.is_some() {
            b"QPWINT02".to_vec()
        } else {
            b"QPWINT01".to_vec()
        };
        if let Some((operation, statement)) = renewal {
            wire.extend_from_slice(operation.as_bytes());
            wire.extend_from_slice(&statement);
        }
        wire.extend_from_slice(&active.id);
        wire.extend_from_slice(&active.owner);
        wire.extend_from_slice(&expected_revision.to_be_bytes());
        wire.extend_from_slice(&image.digest);
        wire.extend_from_slice(&image.revision.to_be_bytes());
        wire.extend_from_slice(&image_hash(target));
        let length = u32::try_from(target.len()).map_err(|_| DurableError::Capacity)?;
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(target);
        let mut auth = authenticator(&active.key)?;
        auth.update(&wire);
        wire.extend_from_slice(&auth.finalize().into_bytes());
        Self::decode(&active.key, active.owner, active.id, &wire)
    }
    fn decode(
        key: &JournalKey,
        owner: [u8; 32],
        id: [u8; 32],
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        match Self::decode_checked(key, owner, id, wire) {
            Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
            result => result,
        }
    }
    fn decode_checked(
        key: &JournalKey,
        owner: [u8; 32],
        id: [u8; 32],
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        if !(INTENT_HEADER + HEADER + 16 + 115 + 32
            ..=INTENT_HEADER + RENEWAL_BINDING_BYTES + MAX_TARGET + 32)
            .contains(&wire.len())
        {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let renewal = match d.array::<8>()? {
            tag if tag == *b"QPWINT01" => None,
            tag if tag == *b"QPWINT02" => {
                let operation = crate::CredentialRenewalId::from_trusted_state(d.array()?)?;
                let statement = d.array()?;
                crate::codec::nonzero(&statement)?;
                Some((operation, statement))
            }
            _ => return Err(DurableError::Corrupt),
        };
        if d.array::<32>()? != id || d.array::<32>()? != owner {
            return Err(DurableError::Conflict);
        }
        let expected_revision = u64::from_be_bytes(d.array()?);
        let expected_digest = d.array()?;
        let next_revision = u64::from_be_bytes(d.array()?);
        let next_digest = d.array()?;
        let length = u32::from_be_bytes(d.array()?) as usize;
        if expected_revision == 0
            || next_revision == u64::MAX
            || expected_revision.checked_add(1) != Some(next_revision)
            || length > MAX_TARGET
        {
            return Err(DurableError::Corrupt);
        }
        let target = d.take(length)?.to_vec();
        d.finish()?;
        if image_hash(&target) != next_digest {
            return Err(DurableError::Corrupt);
        }
        let next = unseal(key, owner, &target)?;
        if next.id != id || next.revision != next_revision {
            return Err(DurableError::Conflict);
        }
        if let Some((operation, statement)) = renewal {
            rosters::check_credential_renewal_intent(&next, operation, statement)?;
        }
        Ok(Self {
            expected_revision,
            expected_digest,
            next_revision,
            next_digest,
            target,
            wire: wire.to_vec(),
            protection: next.protection,
            local_account: next.local_account,
            renewal,
        })
    }
    fn check_current(&self, current: &Image) -> Result<(), DurableError> {
        if current.revision == self.expected_revision
            && current.digest == self.expected_digest
            && current.protection == self.protection
            && current.local_account == self.local_account
        {
            Ok(())
        } else {
            Err(DurableError::Conflict)
        }
    }
    fn credential_proposal(
        &self,
        current: &Image,
    ) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
        self.check_current(current)?;
        let (operation, statement) = self.renewal.ok_or(DurableError::Conflict)?;
        let Protection::Required {
            policy,
            witness,
            fence,
        } = current.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        let mut subject = current.id.to_vec();
        subject.extend_from_slice(&current.owner);
        subject.extend_from_slice(&policy);
        Ok(crate::AnchorCredentialRenewalProposal::from_journal(
            witness,
            crate::AnchorSubject::from_trusted_state(&subject)?,
            operation,
            statement,
            crate::AnchorHead::from_trusted_state(
                fence,
                self.expected_revision,
                self.expected_digest,
            )?,
            crate::AnchorHead::from_trusted_state(fence, self.next_revision, self.next_digest)?,
        )?)
    }
}

fn authenticator(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.write_intent_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| DurableError::Protocol(Error::Provider))
}

pub(super) fn load_snapshot(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
) -> Result<(Image, Option<PendingWrite>), DurableError> {
    let read = db.begin_read().map_err(storage)?;
    let table = image_table(&read)?;
    let value = table
        .get("image")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    let image = unseal(key, owner, value.value())?;
    let pending = table.get("pending").map_err(storage)?;
    if table.len().map_err(storage)? != if pending.is_some() { 2 } else { 1 } {
        return Err(DurableError::Corrupt);
    }
    let pending = pending
        .map(|bytes| PendingWrite::decode(key, owner, image.id, bytes.value()))
        .transpose()?;
    if let Some(intent) = &pending {
        intent.check_current(&image)?;
    }
    Ok((image, pending))
}

// The writer lease is held throughout. The expected image and exact intent are
// still checked inside the write transaction, not from a cached pre-lock read.
fn apply(db: &Database, pending: &PendingWrite) -> Result<(), DurableError> {
    // No ordinary recovery path may commit a credential transition without its
    // separate, exact witness head-and-authority transaction.
    if pending.renewal.is_some() {
        return Err(DurableError::Suspended);
    }
    let tx = transaction(db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        let current_digest = image_hash(current.value());
        if current_digest != pending.expected_digest && current_digest != pending.next_digest {
            return Err(DurableError::Conflict);
        }
        drop(current);
        let saved = table.get("pending").map_err(storage)?;
        match saved.as_ref() {
            None if current_digest == pending.next_digest && table.len().map_err(storage)? == 1 => {
                return Ok(()); // Exact state already committed; no second advance.
            }
            Some(saved)
                if saved.value() == pending.wire
                    && current_digest == pending.expected_digest
                    && table.len().map_err(storage)? == 2 => {}
            _ => return Err(DurableError::Conflict),
        }
        drop(saved);
        table
            .insert("image", pending.target.as_slice())
            .map_err(storage)?;
        table.remove("pending").map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}

pub(super) fn commit(
    active: &mut Active,
    image: &Image,
    target: &[u8],
) -> Result<(), DurableError> {
    let pending = PendingWrite::new(active, image, target)?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    tests::after_intent(&pending, image);
    reconcile(active, &pending)
}

pub(super) fn reconcile(active: &mut Active, pending: &PendingWrite) -> Result<(), DurableError> {
    if pending.renewal.is_some() {
        return Err(DurableError::Suspended);
    }
    if pending.protection != active.protection {
        return Err(DurableError::Conflict);
    }
    active.advance_anchor(
        pending.expected_revision,
        pending.expected_digest,
        pending.next_digest,
    )?;
    apply(&active.db, pending)
}

pub(super) fn reserve_credential_renewal(
    active: &Active,
    image: &Image,
    target: &[u8],
    operation: crate::CredentialRenewalId,
    statement: [u8; 32],
) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
    let pending = PendingWrite::new_bound(active, image, target, Some((operation, statement)))?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    {
        tests::after_credential_preparation();
        tests::after_intent(&pending, image);
    }
    let (current, readback) = load_snapshot(&active.db, &active.key, active.owner)?;
    let readback = readback.ok_or(DurableError::Conflict)?;
    if readback.wire != pending.wire {
        return Err(DurableError::Conflict);
    }
    readback.credential_proposal(&current)
}

impl DeviceJournal {
    /// Read original authenticated preparation metadata without applying its
    /// target, dispatching to a witness, or claiming current authority. `None`
    /// means no local pending record; it is never evidence of witness NoCommit.
    /// A different pending operation is explicitly rejected.
    pub fn inspect_credential_renewal_preparation(
        path: &Path,
        key: JournalKey,
        original: &crate::VerifiedDevice,
        policy: &crate::VerifiedSessionPolicy,
        expected_id: JournalIdentity,
    ) -> Result<Option<crate::AnchorCredentialRenewalProposal>, DurableError> {
        let db = open_private_database(path)?;
        let owner = bootstrap::storage_owner(original);
        let (image, pending) = load_snapshot(&db, &key, owner)?;
        if image.id != expected_id.0 || image.local_account != original.account_id() {
            return Err(DurableError::Conflict);
        }
        image.protection.check_policy(policy)?;
        if !matches!(image.protection, Protection::Required { .. }) {
            return Err(DurableError::AnchorRequired);
        }
        pending
            .map(|intent| intent.credential_proposal(&image))
            .transpose()
    }
}

fn reserve(active: &Active, pending: &PendingWrite) -> Result<(), DurableError> {
    let tx = transaction(&active.db)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        if table.len().map_err(storage)? != 1 || table.get("pending").map_err(storage)?.is_some() {
            return Err(DurableError::Conflict);
        }
        let current = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if image_hash(current.value()) != pending.expected_digest {
            return Err(DurableError::Conflict);
        }
        drop(current);
        table
            .insert("pending", pending.wire.as_slice())
            .map_err(storage)?;
    }
    tx.commit().map_err(DurableError::CommitUncertain)
}

/// Read-only cleanup admission. An untrusted header is only a decryption hint;
/// the complete image and independent expected ID authenticate before any write.
pub(super) fn load_cleanup_snapshot(
    db: &Database,
    key: &JournalKey,
    expected: JournalIdentity,
) -> Result<(Image, Option<PendingWrite>), DurableError> {
    let owner = {
        let read = db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let value = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        let wire = value.value();
        if !(HEADER + 16..=HEADER + MAX_IMAGE + 16).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        wire.get(40..72)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)?
    };
    let (image, pending) = load_snapshot(db, key, owner)?;
    if image.id != expected.0 {
        return Err(DurableError::Conflict);
    }
    Ok((image, pending))
}

pub(super) fn recover(
    db: &Database,
    key: &JournalKey,
    owner: [u8; 32],
    expected_id: JournalIdentity,
) -> Result<Image, DurableError> {
    let (image, pending) = load_snapshot(db, key, owner)?;
    if image.id != expected_id.0 {
        return Err(DurableError::Conflict);
    }
    if image.protection != Protection::Local {
        return Err(DurableError::AnchorRequired);
    }
    if let Some(pending) = pending {
        apply(db, &pending)?;
        let recovered = load(db, key, owner)?;
        if recovered.id != image.id
            || recovered.revision != pending.next_revision
            || recovered.digest != pending.next_digest
        {
            return Err(DurableError::Conflict);
        }
        Ok(recovered)
    } else {
        Ok(image)
    }
}
