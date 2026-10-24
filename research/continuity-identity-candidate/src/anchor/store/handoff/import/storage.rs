// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::codec::{put, take};
use super::*;
pub(super) const MAX_ACTIVATED_IMAGE: usize = 2 * MAX_IMAGE + 64 * 1024;

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
    // Reopening/cancelling a retained inactive import is historical recovery.
    // Fresh target-key admission belongs before acknowledgement/publication,
    // not in this shared authenticated decoder.
    Ok(image)
}

fn validate(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Image, DurableError> {
    let original = validate_source(key, approval, &image.source, &image.freeze)?;
    activation::validate(approval, image, &original)?;
    approval.verify_import_receipt(&image.freeze, &image.acknowledgement)?;
    if let Some(wire) = &image.cancellation {
        if approval.plan.verify_receipt(wire)?.state() != AnchorHandoffState::Cancelled {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(original)
}

pub(super) fn encode(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Vec<u8>, DurableError> {
    validate(key, approval, image)?;
    seal(key, approval, image)
}

// Callers either validate all public proofs or use the exact verified immutable
// commitment cached by a transferred service owner, plus current content checks.
pub(super) fn seal(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Vec<u8>, DurableError> {
    let mut bytes = if !image.client_index.is_empty() {
        if image.activation.is_none()
            || image.cancellation.is_some()
            || image.client_index.len() > MAX_ENTRIES
        {
            return Err(DurableError::Corrupt);
        }
        b"QPAHI003"
    } else if image.activation.is_some() {
        b"QPAHI002"
    } else {
        b"QPAHI001"
    }
    .to_vec();
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
    if let Some(activation) = &image.activation {
        if image.cancellation.is_some() {
            return Err(DurableError::Corrupt);
        }
        put(&activation.retirement, &mut bytes)?;
        put(&activation.receipt, &mut bytes)?;
        put(&activation.content, &mut bytes)?;
    }
    if !image.client_index.is_empty() {
        bytes.extend_from_slice(
            &u16::try_from(image.client_index.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for (subject, commitment) in &image.client_index {
            nonzero(subject)?;
            nonzero(commitment)?;
            bytes.extend_from_slice(subject);
            bytes.extend_from_slice(commitment);
        }
    }
    // The exact source cancellation has the same fixed-width plan/signature
    // layout as freeze. Reserve its complete record before publishing import.
    let completion = if image.cancellation.is_none() && image.activation.is_none() {
        4 + image.freeze.len()
    } else {
        0
    };
    if bytes
        .len()
        .checked_add(32 + completion)
        .ok_or(DurableError::Capacity)?
        > if image.activation.is_some() {
            MAX_ACTIVATED_IMAGE
        } else {
            MAX_IMPORT_IMAGE
        }
    {
        return Err(DurableError::Capacity);
    }
    let mut auth = authenticator(key)?;
    auth.update(&bytes);
    bytes.extend_from_slice(&auth.finalize().into_bytes());
    Ok(bytes)
}

fn decode_authenticated(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    bytes: &[u8],
) -> Result<ImportedImage, DurableError> {
    let result = (|| {
        if !(40..=MAX_ACTIVATED_IMAGE).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = authenticator(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let tag = d.array::<8>()?;
        let activated = match &tag {
            b"QPAHI001" if bytes.len() <= MAX_IMPORT_IMAGE => false,
            b"QPAHI002" | b"QPAHI003" => true,
            _ => return Err(DurableError::Corrupt),
        };
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
        let activation = if activated {
            Some(activation::Activation {
                retirement: take(&mut d)?.to_vec(),
                receipt: take(&mut d)?.to_vec(),
                content: take(&mut d)?.to_vec(),
            })
        } else {
            None
        };
        let mut client_index = BTreeMap::new();
        if &tag == b"QPAHI003" {
            let count = usize::from(d.u16()?);
            if count == 0 || count > MAX_ENTRIES || cancellation.is_some() {
                return Err(DurableError::Corrupt);
            }
            let mut previous = None;
            for _ in 0..count {
                let subject = d.array()?;
                let commitment = d.array()?;
                nonzero(&subject)?;
                nonzero(&commitment)?;
                if previous.is_some_and(|old| old >= subject) {
                    return Err(DurableError::Corrupt);
                }
                client_index.insert(subject, commitment);
                previous = Some(subject);
            }
        }
        d.finish()?;
        let image = ImportedImage {
            client_index,
            activation,
            source,
            freeze,
            acknowledgement,
            cancellation,
            digest: image_digest(bytes),
        };
        Ok(image)
    })();
    match result {
        Err(DurableError::Protocol(Error::Encoding)) => Err(DurableError::Corrupt),
        other => other,
    }
}

pub(super) fn load_authenticated(
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
    if !tables.iter().any(|name| name == IMPORT_TABLE.name())
        || tables.len() > 2
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
    let image = decode_authenticated(key, approval, bytes.value())?;
    let expected = if image.client_index.is_empty() {
        vec![IMPORT_TABLE.name()]
    } else {
        vec![IMPORT_TABLE.name(), activation::authorization::TABLE.name()]
    };
    if tables.len() != expected.len()
        || tables.iter().any(|name| !expected.contains(&name.as_str()))
    {
        return Err(DurableError::Corrupt);
    }
    activation::authorization::check_row_hashes(&tx, &image.client_index)?;
    Ok(image)
}

pub(super) fn load(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
) -> Result<ImportedImage, DurableError> {
    let image = load_authenticated(db, key, approval)?;
    let original = validate(key, approval, &image)?;
    activation::authorization::load_records(db, approval, &image, &original)?;
    Ok(image)
}

pub(in crate::anchor::store::handoff) fn preflight_activation(
    approval: &AnchorHandoffTargetApproval,
    source: usize,
    freeze: usize,
    acknowledgement: usize,
    retirement: usize,
    content: usize,
) -> Result<(), DurableError> {
    if source.checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE
        || content.checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE
    {
        return Err(DurableError::Capacity);
    }
    let mut total = 8usize + 1 + 32;
    for size in [
        approval.to_bytes().len(),
        source,
        freeze,
        acknowledgement,
        retirement,
        activation::RECEIPT_BYTES,
        content,
    ] {
        total = total
            .checked_add(4)
            .and_then(|n| n.checked_add(size))
            .ok_or(DurableError::Capacity)?;
    }
    // Reserve every supported client's index before irreversible retirement.
    // Complete fixed-bound proofs live in separate rows, not every data update.
    total = total
        .checked_add(2 + MAX_ENTRIES * 64)
        .ok_or(DurableError::Capacity)?;
    if total > MAX_ACTIVATED_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(())
}
