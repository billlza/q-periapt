// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Persist the exact sealed aggregate before attempting its state transaction.
use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const INTENT_HEADER: usize = 8 + 32 + 32 + 8 + 32 + 8 + 32 + 4;
const MAX_TARGET: usize = HEADER + MAX_IMAGE + 16;

#[cfg(all(test, unix))]
mod tests;

pub(super) struct PendingWrite {
    expected_revision: u64,
    expected_digest: [u8; 32],
    next_revision: u64,
    next_digest: [u8; 32],
    target: Vec<u8>,
    wire: Vec<u8>,
}
impl PendingWrite {
    fn new(active: &Active, image: &Image, target: &[u8]) -> Result<Self, DurableError> {
        let expected_revision = image.revision.checked_sub(1).ok_or(DurableError::Corrupt)?;
        let mut wire = b"QPWINT01".to_vec();
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
        if !(INTENT_HEADER + HEADER + 16 + 10 + 32..=INTENT_HEADER + MAX_TARGET + 32)
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
        if d.array::<8>()? != *b"QPWINT01" {
            return Err(DurableError::Corrupt);
        }
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
        Ok(Self {
            expected_revision,
            expected_digest,
            next_revision,
            next_digest,
            target,
            wire: wire.to_vec(),
        })
    }
    fn check_current(&self, current: &Image) -> Result<(), DurableError> {
        if current.revision == self.expected_revision && current.digest == self.expected_digest {
            Ok(())
        } else {
            Err(DurableError::Conflict)
        }
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

pub(super) fn commit(active: &Active, image: &Image, target: &[u8]) -> Result<(), DurableError> {
    let pending = PendingWrite::new(active, image, target)?;
    reserve(active, &pending)?;
    #[cfg(all(test, unix))]
    tests::after_intent(&pending, image);
    apply(&active.db, &pending)
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
