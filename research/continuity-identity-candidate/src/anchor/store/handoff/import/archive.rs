// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable complete prior-state archive, outside the bounded primary row.
use super::*;

pub(super) const TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_source_archive_v1");
const MAX_ARCHIVE: usize = activation::source::MAX_SOURCE;

pub(super) fn is_capture(bytes: &[u8]) -> bool {
    bytes.starts_with(b"QPAHSS01") || bytes.starts_with(b"QPAHSS02")
}
fn admit_bytes(approval: &AnchorHandoffTargetApproval, source: &[u8]) -> Result<(), DurableError> {
    if source.len() > MAX_ARCHIVE {
        return Err(DurableError::Capacity);
    }
    if !is_capture(source) || source_commitment(source) != approval.plan.commitment {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}

pub(super) fn validate_source(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    source: &[u8],
) -> Result<Image, DurableError> {
    admit_bytes(approval, source)?;
    let mut d = Decoder::new(source);
    d.take(8)?;
    let history_bytes = super::super::codec::take(&mut d)?;
    let history = AnchorHandoffHistory::restore_approved_source(history_bytes, &approval.plan)?;
    let image =
        activation::source::validate_capture(source, key, history.current_approval()?, &history)?;
    if image.revision != approval.plan.revision {
        return Err(DurableError::Corrupt);
    }
    Ok(image)
}

pub(super) fn publish(
    tx: &redb::WriteTransaction,
    approval: &AnchorHandoffTargetApproval,
    source: &[u8],
) -> Result<(), DurableError> {
    admit_bytes(approval, source)?;
    let mut table = tx.open_table(TABLE).map_err(storage)?;
    if !table.is_empty().map_err(storage)? {
        return Err(DurableError::Conflict);
    }
    table.insert("source", source).map_err(storage)?;
    Ok(())
}

pub(super) fn read(
    tx: &redb::ReadTransaction,
    approval: &AnchorHandoffTargetApproval,
) -> Result<Vec<u8>, DurableError> {
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let row = table
        .get("source")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    admit_bytes(approval, row.value())?;
    Ok(row.value().to_vec())
}

pub(super) fn seal_primary(
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    image: &ImportedImage,
) -> Result<Vec<u8>, DurableError> {
    // Successive activation needs full prior-history admission and its own
    // immutable-archive operating boundary. Never route this import through the
    // first-transition owner merely because the primary row fits.
    if image.activation.is_some()
        || image.source_control.is_some()
        || !image.client_index.is_empty()
    {
        return Err(DurableError::Suspended);
    }
    admit_bytes(approval, &image.source)?;
    let mut bytes = b"QPAHI005".to_vec();
    super::super::codec::put(&approval.to_bytes(), &mut bytes)?;
    bytes.extend_from_slice(&approval.plan.commitment);
    super::super::codec::put(&image.freeze, &mut bytes)?;
    super::super::codec::put(&image.acknowledgement, &mut bytes)?;
    match &image.cancellation {
        None => bytes.push(0),
        Some(wire) => {
            bytes.push(1);
            super::super::codec::put(wire, &mut bytes)?;
        }
    }
    let reserved = if image.cancellation.is_none() {
        4 + image.freeze.len()
    } else {
        0
    };
    if bytes
        .len()
        .checked_add(32 + reserved)
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
