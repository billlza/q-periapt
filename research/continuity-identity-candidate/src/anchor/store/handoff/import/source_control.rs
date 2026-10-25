// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The activated source's shared handoff Journal, indexed by its primary image.
use super::super::codec as decisions;
use super::*;
mod codec;

pub(super) const TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("continuity_anchor_handoff_source_v1");
pub(super) const MAX_CONTROL_IMAGE: usize = MAX_IMAGE;

pub(super) fn digest_public(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-ANCHOR-SOURCE-CONTROL-ROW/v1", bytes)
}
pub(super) fn public_bytes(
    history: &AnchorHandoffHistory,
    revision: u64,
    journal: &Journal,
) -> Result<Vec<u8>, DurableError> {
    decisions::validate_decisions(history.current_pin(), history.context(), revision, journal)?;
    let mut bytes = b"QPAHSC01".to_vec();
    history.context().encode(&mut bytes);
    bytes.extend_from_slice(&decisions::raw_wrap(&[], Some(journal))?);
    if bytes.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_CONTROL_IMAGE {
        return Err(DurableError::Capacity);
    }
    Ok(bytes)
}
pub(super) fn public_journal(
    bytes: &[u8],
    history: &AnchorHandoffHistory,
    revision: u64,
) -> Result<Journal, DurableError> {
    if bytes.len().checked_add(32).ok_or(DurableError::Capacity)? > MAX_CONTROL_IMAGE {
        return Err(DurableError::Capacity);
    }
    let mut d = Decoder::new(bytes);
    if d.array::<8>()? != *b"QPAHSC01"
        || history::HistoryContext::decode(&mut d)? != history.context()
    {
        return Err(Error::Scope.into());
    }
    let (content, journal) = decisions::unwrap(history.current_pin(), d.take(d.remaining())?)?;
    if !content.is_empty() {
        return Err(DurableError::Corrupt);
    }
    let journal = journal.ok_or(DurableError::Corrupt)?;
    decisions::validate_decisions(history.current_pin(), history.context(), revision, &journal)?;
    if public_bytes(history, revision, &journal)? != bytes {
        return Err(DurableError::Corrupt);
    }
    Ok(journal)
}
pub(super) fn check_row_hash(
    tx: &redb::ReadTransaction,
    key: &JournalKey,
    expected: Option<[u8; 32]>,
) -> Result<(), DurableError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let table = tx.open_table(TABLE).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(DurableError::Corrupt);
    }
    let row = table
        .get("state")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    if digest_public(codec::authenticate(key, row.value())?) != expected {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}
fn read_public(
    db: &Database,
    key: &JournalKey,
    expected: [u8; 32],
) -> Result<Vec<u8>, DurableError> {
    let tx = db.begin_read().map_err(storage)?;
    check_row_hash(&tx, key, Some(expected))?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    let row = table
        .get("state")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    Ok(codec::authenticate(key, row.value())?.to_vec())
}
pub(super) fn load(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    revision: u64,
) -> Result<Option<Journal>, DurableError> {
    let Some(expected) = saved.source_control else {
        return Ok(None);
    };
    let journal = public_journal(&read_public(db, key, expected)?, history, revision)?;
    verify_frozen(db, key, approval, saved, history, revision, &journal)?;
    Ok(Some(journal))
}
fn verify_frozen(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    revision: u64,
    journal: &Journal,
) -> Result<(), DurableError> {
    if let Some(frozen) = &journal.frozen {
        let prior = decisions::prior(journal);
        let bytes =
            activation::source::wire(db, key, approval, saved, history, revision, prior.as_ref())?;
        if source_commitment(&bytes) != frozen.plan.commitment {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(())
}
pub(super) fn verify_image(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
) -> Result<Option<Journal>, DurableError> {
    if saved.source_control.is_none() {
        return Ok(None);
    }
    let active = saved.activation.as_ref().ok_or(DurableError::Corrupt)?;
    let history = activation::history(
        approval,
        &saved.freeze,
        &saved.acknowledgement,
        &active.retirement,
    )?;
    let image = image_codec::decode_content(&history, &active.content)?;
    load(db, key, approval, saved, &history, image.revision)
}
pub(super) fn same(
    left: Option<&Journal>,
    right: Option<&Journal>,
    history: &AnchorHandoffHistory,
    revision: u64,
) -> Result<(), DurableError> {
    let bytes = |j: Option<&Journal>| j.map(|j| public_bytes(history, revision, j)).transpose();
    if bytes(left)? != bytes(right)? {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

fn prepare(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    image: &Image,
) -> Result<(Vec<u8>, Vec<u8>), DurableError> {
    if saved.digest != image.digest
        || saved
            .activation
            .as_ref()
            .ok_or(DurableError::Corrupt)?
            .content
            != image_codec::encode_content(history, image)?
    {
        return Err(DurableError::Conflict);
    }
    let journal = image.handoff.as_ref().ok_or(DurableError::Corrupt)?;
    let public = public_bytes(history, image.revision, journal)?;
    verify_frozen(db, key, approval, saved, history, image.revision, journal)?;
    let row = codec::seal(key, &public)?;
    let mut next = saved.clone();
    next.source_control = Some(digest_public(&public));
    Ok((storage::seal(key, approval, &next)?, row))
}
pub(super) fn preflight(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    image: &Image,
) -> Result<(), DurableError> {
    prepare(db, key, approval, saved, history, image).map(|_| ())
}
pub(super) fn persist(
    db: &Database,
    key: &JournalKey,
    approval: &AnchorHandoffTargetApproval,
    saved: &ImportedImage,
    history: &AnchorHandoffHistory,
    image: &mut Image,
    admit: impl FnOnce() -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let (primary_bytes, control_bytes) = prepare(db, key, approval, saved, history, image)?;
    let tx = transaction(db)?;
    {
        let mut primary = tx.open_table(IMPORT_TABLE).map_err(storage)?;
        if primary.len().map_err(storage)? != 1 {
            return Err(DurableError::Corrupt);
        }
        let old = primary
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        if storage::image_digest(old.value()) != saved.digest {
            return Err(DurableError::Conflict);
        }
        drop(old);
        let mut control = tx.open_table(TABLE).map_err(storage)?;
        if control.len().map_err(storage)? != u64::from(saved.source_control.is_some()) {
            return Err(DurableError::Corrupt);
        }
        let old = control.get("state").map_err(storage)?;
        match (saved.source_control, old.as_ref()) {
            (None, None) => {}
            (Some(expected), Some(row))
                if digest_public(codec::authenticate(key, row.value())?) == expected => {}
            _ => return Err(DurableError::Conflict),
        }
        drop(old);
        control
            .insert("state", control_bytes.as_slice())
            .map_err(storage)?;
        primary
            .insert("image", primary_bytes.as_slice())
            .map_err(storage)?;
    }
    admit()?;
    #[cfg(all(test, unix))]
    let kind = if image.handoff.as_ref().is_some_and(|j| j.retired.is_some()) {
        "retire"
    } else if image.handoff.as_ref().is_some_and(|j| j.frozen.is_some()) {
        "freeze"
    } else {
        "cancel"
    };
    #[cfg(all(test, unix))]
    testing::source_boundary(kind, false);
    tx.commit().map_err(DurableError::CommitUncertain)?;
    image.digest = storage::image_digest(&primary_bytes);
    #[cfg(all(test, unix))]
    testing::source_boundary(kind, true);
    Ok(())
}

impl AnchorHandoffTarget {
    /// Observe the exact current target's subsequent source decision without its
    /// signing key. This historical receipt grants no current client permission.
    pub fn observe_source_handoff(
        &mut self,
        plan: &AnchorHandoffPlan,
    ) -> Result<AnchorHandoffReceipt, DurableError> {
        let saved = self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        verify_image(&owner.db, &owner.wrapping, &owner.approval, &saved)?
            .ok_or(DurableError::Absent)?
            .observe(plan)
    }
    /// Reconstruct the exact complete pre-freeze public state after an unknown
    /// result, without either the former or current source signing key.
    pub fn frozen_source_handoff_state(
        &mut self,
        plan: &AnchorHandoffPlan,
    ) -> Result<AnchorHandoffSourceState, DurableError> {
        let saved = self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let journal = verify_image(&owner.db, &owner.wrapping, &owner.approval, &saved)?
            .ok_or(DurableError::Absent)?;
        if journal.observe(plan)?.state == AnchorHandoffState::Cancelled {
            return Err(Error::Retired.into());
        }
        let active = saved.activation.as_ref().ok_or(DurableError::Corrupt)?;
        let history = activation::history(
            &owner.approval,
            &saved.freeze,
            &saved.acknowledgement,
            &active.retirement,
        )?;
        let revision = image_codec::decode_content(&history, &active.content)?.revision;
        let bytes = activation::source::wire(
            &owner.db,
            &owner.wrapping,
            &owner.approval,
            &saved,
            &history,
            revision,
            decisions::prior(&journal).as_ref(),
        )?;
        let state = AnchorHandoffSourceState::captured(
            history.current_pin(),
            revision,
            bytes,
            history.context(),
        );
        if state.commitment() != plan.commitment {
            return Err(DurableError::Corrupt);
        }
        Ok(state)
    }
}
