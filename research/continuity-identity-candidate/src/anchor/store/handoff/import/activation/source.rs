// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete public capture of an activated import, without its storage MAC.
//! This read-only stage does not freeze, retire or activate another authority.
use super::*;

const TAG: &[u8; 8] = b"QPAHSS01";
const CONTROL_TAG: &[u8; 8] = b"QPAHSS02";
// The complete current import and all separately stored authorization rows are
// retained. Capture has a distinct bound; no existing image limit is increased.
const MAX_HISTORY: usize = super::super::super::history::MAX_HISTORY_BYTES;
pub(in crate::anchor::store::handoff::import) const MAX_SOURCE: usize = 8
    + 8
    + MAX_HISTORY
    + storage::MAX_ACTIVATED_IMAGE
    + 2
    + MAX_ENTRIES * (32 + 4 + authorization::MAX_RECORD_BYTES)
    + 4
    + source_control::MAX_CONTROL_IMAGE;

fn take<'a>(d: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8], Error> {
    let length = usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| Error::Capacity)?;
    if length > maximum {
        return Err(Error::Capacity);
    }
    d.take(length)
}

pub(in crate::anchor::store) fn validate_capture(
    bytes: &[u8],
    local_key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    expected_history: &AnchorHandoffHistory,
) -> Result<Image, DurableError> {
    if bytes.len() > MAX_SOURCE {
        return Err(DurableError::Capacity);
    }
    let mut d = Decoder::new(bytes);
    let tag = d.array::<8>()?;
    if (tag != *TAG && tag != *CONTROL_TAG)
        || take(&mut d, MAX_HISTORY)? != expected_history.to_bytes()?
        || expected_history.current_pin().binding() != approval.plan.target.binding()
    {
        return Err(Error::Scope.into());
    }
    let body = take(&mut d, storage::MAX_ACTIVATED_IMAGE)?;
    // Reuse the complete existing decoder under a local test/target key. This
    // does not authenticate mutable state: the later exact source freeze must
    // sign its commitment before any future import can admit it.
    let mut sealed = body.to_vec();
    let mut auth = authenticator(local_key)?;
    auth.update(body);
    sealed.extend_from_slice(&auth.finalize().into_bytes());
    let saved = storage::decode_authenticated(local_key, approval, &sealed)?;
    let original = storage::validate(local_key, approval, &saved)?;
    let activated = saved.activation.as_ref().ok_or(DurableError::Absent)?;
    let (_, checked) = verify(
        approval,
        &saved.freeze,
        &saved.acknowledgement,
        &activated.retirement,
        &activated.receipt,
    )?;
    if checked.to_bytes()? != expected_history.to_bytes()?
        || storage::seal(local_key, approval, &saved)? != sealed
    {
        return Err(DurableError::Corrupt);
    }
    let count = usize::from(d.u16()?);
    if count > MAX_ENTRIES || count != saved.client_index.len() {
        return Err(DurableError::Corrupt);
    }
    let mut rows = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = d.array()?;
        if previous.is_some_and(|old| old >= id) {
            return Err(DurableError::Corrupt);
        }
        rows.insert(id, take(&mut d, authorization::MAX_RECORD_BYTES)?.to_vec());
        previous = Some(id);
    }
    let control = if tag == *CONTROL_TAG {
        Some(take(&mut d, source_control::MAX_CONTROL_IMAGE)?)
    } else {
        None
    };
    d.finish()?;
    authorization::decode_records(&rows, approval, &saved, &original)?;
    let mut image = image_codec::decode_content(expected_history, &activated.content)?;
    image.handoff = match (saved.source_control, control) {
        (None, None) => None,
        (Some(expected), Some(bytes)) if source_control::digest_public(bytes) == expected => {
            let journal = source_control::public_journal(bytes, expected_history, image.revision)?;
            if journal.frozen.is_some() {
                return Err(DurableError::Suspended);
            }
            Some(journal)
        }
        _ => return Err(DurableError::Corrupt),
    };
    Ok(image)
}

// Construct the exact public view for a selected source Journal. Reconstructing
// its cancelled-only predecessor is read-only and must match the freeze digest.
pub(in crate::anchor::store::handoff::import) fn wire(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    revision: u64,
    journal: Option<&Journal>,
) -> Result<Vec<u8>, DurableError> {
    let public = journal
        .map(|j| source_control::public_bytes(history, revision, j))
        .transpose()?;
    let mut selected = saved.clone();
    selected.source_control = public.as_deref().map(source_control::digest_public);
    let sealed = storage::seal(key, approval, &selected)?;
    let end = sealed.len().checked_sub(32).ok_or(DurableError::Corrupt)?;
    let records = authorization::capture_rows(db, &saved.client_index)?;
    let mut bytes = if public.is_some() { CONTROL_TAG } else { TAG }.to_vec();
    super::super::super::codec::put(&history.to_bytes()?, &mut bytes)?;
    super::super::super::codec::put(sealed.get(..end).ok_or(DurableError::Corrupt)?, &mut bytes)?;
    bytes.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (id, record) in records {
        bytes.extend_from_slice(&id);
        super::super::super::codec::put(&record, &mut bytes)?;
    }
    if let Some(public) = public {
        super::super::super::codec::put(&public, &mut bytes)?;
    }
    if bytes.len() > MAX_SOURCE {
        return Err(DurableError::Capacity);
    }
    Ok(bytes)
}

impl Transferred {
    pub(in crate::anchor::store) fn capture_source(
        &self,
        db: &Database,
        key: &JournalKey,
        expected: &Image,
    ) -> Result<AnchorHandoffSourceState, DurableError> {
        let saved = storage::load_authenticated(db, key, &self.approval)?;
        self.admit(&saved)?;
        if saved.digest != expected.digest {
            return Err(DurableError::Conflict);
        }
        let bytes = wire(
            db,
            key,
            &self.approval,
            &saved,
            &self.history,
            expected.revision,
            expected.handoff.as_ref(),
        )?;
        let restored = validate_capture(&bytes, key, &self.approval, &self.history)?;
        if image_codec::encode_content(&self.history, &restored)?
            != image_codec::encode_content(&self.history, expected)?
        {
            return Err(DurableError::Conflict);
        }
        Ok(AnchorHandoffSourceState::captured(
            self.history.current_pin(),
            restored.revision,
            bytes,
            self.history.context(),
        ))
    }
}
