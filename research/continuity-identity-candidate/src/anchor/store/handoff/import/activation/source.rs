// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete public capture of an activated import, without its storage MAC.
//! This read-only stage does not freeze, retire or activate another authority.
use super::*;

const TAG: &[u8; 8] = b"QPAHSS01";
// The complete current import and all separately stored authorization rows are
// retained. Capture has a distinct bound; no existing image limit is increased.
const MAX_HISTORY: usize = super::super::super::history::MAX_HISTORY_BYTES;
const MAX_SOURCE: usize = 8
    + 8
    + MAX_HISTORY
    + storage::MAX_ACTIVATED_IMAGE
    + 2
    + MAX_ENTRIES * (32 + 4 + authorization::MAX_RECORD_BYTES);

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
    if d.array::<8>()? != *TAG
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
    d.finish()?;
    authorization::decode_records(&rows, approval, &saved, &original)?;
    let image = image_codec::decode_content(expected_history, &activated.content)?;
    if image.handoff.is_some() {
        return Err(DurableError::Corrupt);
    }
    Ok(image)
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
        let records = authorization::capture_rows(db, &saved.client_index)?;
        let sealed = storage::seal(key, &self.approval, &saved)?;
        let end = sealed.len().checked_sub(32).ok_or(DurableError::Corrupt)?;
        let mut bytes = TAG.to_vec();
        super::super::super::codec::put(&self.history.to_bytes()?, &mut bytes)?;
        super::super::super::codec::put(
            sealed.get(..end).ok_or(DurableError::Corrupt)?,
            &mut bytes,
        )?;
        bytes.extend_from_slice(
            &u16::try_from(records.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for (id, record) in records {
            bytes.extend_from_slice(&id);
            super::super::super::codec::put(&record, &mut bytes)?;
        }
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
