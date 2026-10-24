// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::codec::{put, take};
use super::*;

pub(super) fn image_digest(bytes: &[u8]) -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-IMPORT-IMAGE/v1",
        bytes,
    )
}

pub(super) fn validate_source(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    source: &[u8],
    freeze: &[u8],
) -> Result<Image, DurableError> {
    if source.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE {
        return Err(DurableError::Capacity);
    }
    if approval.plan.verify_receipt(freeze)?.state() != AnchorHandoffState::Frozen
        || source_commitment(source) != approval.plan.commitment
    {
        return Err(Error::Scope.into());
    }
    approval
        .plan
        .require_history(history::HistoryContext::initial(&approval.plan.source))?;
    // The source signature/commitment above authenticates the transfer. Only
    // then seal locally to reuse the complete existing authenticated-image
    // decoder and every cross-record invariant. No source storage key is used.
    let mut bytes = source.to_vec();
    let mut auth = authenticator(key)?;
    auth.update(source);
    bytes.extend_from_slice(&auth.finalize().into_bytes());
    let image = image_codec::decode(key, &approval.plan.source, &bytes)?;
    if image.revision != approval.plan.revision
        || image.handoff.as_ref().is_some_and(|j| j.frozen.is_some())
        || image_codec::encode_body(&approval.plan.source, &image)? != source
    {
        return Err(DurableError::Corrupt);
    }
    image.check_witness_key(&approval.plan.target.key)?;
    Ok(image)
}

fn validate(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<(), DurableError> {
    validate_source(key, approval, &image.source, &image.freeze)?;
    approval.verify_import_receipt(&image.freeze, &image.acknowledgement)?;
    if let Some(wire) = &image.cancellation {
        if approval.plan.verify_receipt(wire)?.state() != AnchorHandoffState::Cancelled {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn encode(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Vec<u8>, DurableError> {
    validate(key, approval, image)?;
    let mut bytes = b"QPAHI001".to_vec();
    put(&approval.to_bytes(), &mut bytes)?;
    put(&image.source, &mut bytes)?;
    put(&image.freeze, &mut bytes)?;
    put(&image.acknowledgement, &mut bytes)?;
    match &image.cancellation {
        None => bytes.push(0),
        Some(wire) => {
            bytes.push(1);
            put(wire, &mut bytes)?;
        }
    }
    // The exact source cancellation has the same fixed-width plan/signature
    // layout as freeze. Reserve its complete record before publishing import.
    let completion = if image.cancellation.is_none() {
        4 + image.freeze.len()
    } else {
        0
    };
    if bytes
        .len()
        .checked_add(32 + completion)
        .ok_or(DurableError::Capacity)?
        > MAX_IMPORT_IMAGE
    {
        return Err(DurableError::Capacity);
    }
    let mut auth = authenticator(key)?;
    auth.update(&bytes);
    bytes.extend_from_slice(&auth.finalize().into_bytes());
    Ok(bytes)
}

fn decode(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    bytes: &[u8],
) -> Result<ImportedImage, DurableError> {
    let result = (|| {
        if !(40..=MAX_IMPORT_IMAGE).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPAHI001" {
            return Err(DurableError::Corrupt);
        }
        if take(&mut d)? != approval.to_bytes() {
            return Err(DurableError::Conflict);
        }
        let source = take(&mut d)?.to_vec();
        let freeze = take(&mut d)?.to_vec();
        let acknowledgement = take(&mut d)?.to_vec();
        let cancellation = match d.array::<1>()? {
            [0] => None,
            [1] => Some(take(&mut d)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        d.finish()?;
        let image = ImportedImage {
            source,
            freeze,
            acknowledgement,
            cancellation,
            digest: image_digest(bytes),
        };
        validate(key, approval, &image)?;
        Ok(image)
    })();
    match result {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        other => other,
    }
}

pub(super) fn load(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
) -> Result<ImportedImage, DurableError> {
    let tx = db.begin_read().map_err(storage)?;
    let tables: Vec<_> = tx
        .list_tables()
        .map_err(storage)?
        .map(|table| table.name().to_owned())
        .collect();
    if tables != [IMPORT_TABLE.name()]
        || tx.list_multimap_tables().map_err(storage)?.next().is_some()
    {
        return Err(DurableError::Corrupt);
    }
    let table = tx.open_table(IMPORT_TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let bytes = table
        .get("image")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    decode(key, approval, bytes.value())
}
