// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable complete prior-state archive, outside the bounded current row.
use super::*;
mod source;
pub(super) use source::Source;

pub(super) const TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_source_archive_v1");
const MAX_ARCHIVE: usize = activation::source::MAX_SOURCE;

#[cfg(all(test, unix))]
std::thread_local! {static SOURCE_READS: std::cell::Cell<usize> = const {std::cell::Cell::new(0)};}
#[cfg(all(test, unix))]
pub(in crate::anchor::store) fn take_archive_reads() -> usize {
    SOURCE_READS.with(|count| count.replace(0))
}

pub(super) fn is_capture(bytes: &[u8]) -> bool {
    bytes.starts_with(b"QPAHSS01")
        || bytes.starts_with(b"QPAHSS02")
        || bytes.starts_with(b"QPAHSS03")
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
) -> Result<storage::SourceState, DurableError> {
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
    Ok(storage::SourceState {
        image,
        history,
        commitment: source_commitment(source),
        archived: true,
    })
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
pub(super) fn check_membership(tx: &redb::ReadTransaction) -> Result<(), DurableError> {
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let value = table
        .get("source")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    if value.value().len() > MAX_ARCHIVE || !is_capture(value.value()) {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
fn read(
    tx: &redb::ReadTransaction,
    approval: &AnchorHandoffTargetApproval,
) -> Result<Vec<u8>, DurableError> {
    #[cfg(all(test, unix))]
    SOURCE_READS.with(|count| count.set(count.get().checked_add(1).expect("bounded test reads")));
    check_membership(tx)?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    let row = table
        .get("source")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    admit_bytes(approval, row.value())?;
    Ok(row.value().to_vec())
}
