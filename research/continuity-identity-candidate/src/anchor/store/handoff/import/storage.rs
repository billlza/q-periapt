// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::codec::{put, take};
use super::*;
pub(super) const MAX_ACTIVATED_IMAGE: usize = 2 * MAX_IMAGE + 64 * 1024;

pub(in crate::anchor::store::handoff) struct SourceState {
    pub(in crate::anchor::store::handoff) image: Image,
    pub(in crate::anchor::store::handoff) history: AnchorHandoffHistory,
    pub(super) commitment: [u8; 32],
    pub(super) archived: bool,
}

pub(super) fn image_digest(bytes: &[u8]) -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-IMPORT-IMAGE/v1",
        bytes,
    )
}

pub(in crate::anchor::store::handoff) fn validate_source(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    source: &[u8],
    freeze: &[u8],
) -> Result<SourceState, DurableError> {
    let maximum = if archive::is_capture(source) {
        activation::source::MAX_SOURCE
    } else {
        MAX_IMAGE - 32
    };
    if source.len() > maximum {
        return Err(DurableError::Capacity);
    }
    if approval.plan.verify_receipt(freeze)?.state() != AnchorHandoffState::Frozen
        || source_commitment(source) != approval.plan.commitment
    {
        return Err(Error::Scope.into());
    }
    if archive::is_capture(source) {
        return archive::validate_source(key, approval, source);
    }
    if source.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE {
        return Err(DurableError::Capacity);
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
    Ok(SourceState {
        image,
        history: AnchorHandoffHistory::from_trusted_origin(approval.plan.source.clone()),
        commitment: source_commitment(source),
        archived: false,
    })
}

pub(super) fn source_state(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<SourceState, DurableError> {
    let bytes = image.source.resolve(db, approval)?;
    validate_source(key, approval, &bytes, &image.freeze)
}

pub(super) fn validate(
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
    source: &SourceState,
) -> Result<(), DurableError> {
    image.source.admit(approval)?;
    if image.source.commitment() != source.commitment
        || image.source.is_archived() != source.archived
    {
        return Err(DurableError::Corrupt);
    }
    source.history.admit_successor(&approval.plan)?;
    activation::validate(approval, image, source)?;
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
    source: &SourceState,
) -> Result<Vec<u8>, DurableError> {
    validate(approval, image, source)?;
    seal(key, approval, image)
}

// Callers either validate all public proofs or use the exact verified immutable
// commitment cached by a transferred service owner, plus current content checks.
pub(super) fn seal(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Vec<u8>, DurableError> {
    image.source.admit(approval)?;
    if image.client_index.len() > MAX_ENTRIES {
        return Err(DurableError::Capacity);
    }
    let mut bytes = if image.source.is_archived() {
        if image.activation.is_some() {
            if image.cancellation.is_some() {
                return Err(DurableError::Corrupt);
            }
            b"QPAHI006"
        } else {
            if image.source_control.is_some() || !image.client_index.is_empty() {
                return Err(DurableError::Corrupt);
            }
            b"QPAHI005"
        }
    } else if image.source_control.is_some() {
        if image.activation.is_none() || image.cancellation.is_some() {
            return Err(DurableError::Corrupt);
        }
        b"QPAHI004"
    } else if !image.client_index.is_empty() {
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
    match &image.source {
        archive::Source::Inline(source) => put(source, &mut bytes)?,
        archive::Source::Archived(commitment) => bytes.extend_from_slice(commitment),
    }
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
    if !image.client_index.is_empty()
        || image.source_control.is_some()
        || (image.source.is_archived() && image.activation.is_some())
    {
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
    if image.source.is_archived() && image.activation.is_some() {
        bytes.push(u8::from(image.source_control.is_some()));
    }
    if let Some(commitment) = image.source_control {
        nonzero(&commitment)?;
        bytes.extend_from_slice(&commitment);
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

pub(super) fn decode_authenticated(
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
            b"QPAHI001" | b"QPAHI005" if bytes.len() <= MAX_IMPORT_IMAGE => false,
            b"QPAHI002" | b"QPAHI003" | b"QPAHI004" | b"QPAHI006" => true,
            _ => return Err(DurableError::Corrupt),
        };
        if take(&mut d)? != approval.to_bytes() {
            return Err(DurableError::Conflict);
        }
        let source_archived = &tag == b"QPAHI005" || &tag == b"QPAHI006";
        let source = if source_archived {
            if d.array::<32>()? != approval.plan.commitment {
                return Err(DurableError::Conflict);
            }
            archive::Source::Archived(approval.plan.commitment)
        } else {
            archive::Source::Inline(take(&mut d)?.to_vec())
        };
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
        if &tag == b"QPAHI003" || &tag == b"QPAHI004" || &tag == b"QPAHI006" {
            let count = usize::from(d.u16()?);
            if (count == 0 && &tag == b"QPAHI003") || count > MAX_ENTRIES || cancellation.is_some()
            {
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
        let has_control = if &tag == b"QPAHI006" {
            match d.array()? {
                [0] => false,
                [1] => true,
                _ => return Err(DurableError::Corrupt),
            }
        } else {
            &tag == b"QPAHI004"
        };
        let source_control = if has_control {
            let commitment = d.array()?;
            nonzero(&commitment)?;
            Some(commitment)
        } else {
            None
        };
        d.finish()?;
        let image = ImportedImage {
            source_control,
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
        || tables.len() > 4
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
    let mut expected = if image.client_index.is_empty() {
        vec![IMPORT_TABLE.name()]
    } else {
        vec![IMPORT_TABLE.name(), activation::authorization::TABLE.name()]
    };
    if image.source_control.is_some() {
        expected.push(source_control::TABLE.name());
    }
    if image.source.is_archived() {
        expected.push(archive::TABLE.name());
    }
    if tables.len() != expected.len()
        || tables.iter().any(|name| !expected.contains(&name.as_str()))
    {
        return Err(DurableError::Corrupt);
    }
    if image.source.is_archived() {
        image.source.admit(approval)?;
        archive::check_membership(&tx)?;
    }
    activation::authorization::check_row_hashes(&tx, &image.client_index)?;
    source_control::check_row_hash(&tx, key, image.source_control)?;
    Ok(image)
}

pub(super) fn load(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
) -> Result<ImportedImage, DurableError> {
    let image = load_authenticated(db, key, approval)?;
    let source = source_state(db, key, approval, &image)?;
    validate(approval, &image, &source)?;
    activation::authorization::load_records(db, approval, &image, &source)?;
    source_control::verify_image(db, key, approval, &image, &source)?;
    Ok(image)
}

pub(in crate::anchor::store::handoff) fn preflight_activation(
    approval: &AnchorHandoffTargetApproval,
    source: &[u8],
    freeze: usize,
    acknowledgement: usize,
    retirement: usize,
    content: usize,
) -> Result<(), DurableError> {
    let archived = archive::is_capture(source);
    if source.len()
        > (if archived {
            activation::source::MAX_SOURCE
        } else {
            MAX_IMAGE - 32
        })
        || content.checked_add(32).ok_or(DurableError::Capacity)? > MAX_IMAGE
    {
        return Err(DurableError::Capacity);
    }
    let mut total = 8usize + 1 + 32;
    for size in [
        approval.to_bytes().len(),
        if archived { 28 } else { source.len() },
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
    // Reserve every supported client's index and a later source-control digest
    // before irreversible retirement. Complete fixed-bound proofs and source
    // decisions live in separate rows, not every data update.
    total = total
        .checked_add(2 + MAX_ENTRIES * 64 + 32 + usize::from(archived))
        .ok_or(DurableError::Capacity)?;
    if total > MAX_ACTIVATED_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(())
}
