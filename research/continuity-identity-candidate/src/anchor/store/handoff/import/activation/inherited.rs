// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Inherited state cannot acquire current authority through a management shortcut.
use super::*;

fn retained<V>(
    before: &BTreeMap<[u8; 32], V>,
    after: &BTreeMap<[u8; 32], V>,
    encode: impl Fn(&V) -> Result<Vec<u8>, DurableError>,
) -> Result<(), DurableError> {
    for (id, original) in before {
        let current = after.get(id).ok_or(DurableError::Suspended)?;
        if encode(original)? != encode(current)? {
            return Err(DurableError::Suspended);
        }
    }
    Ok(())
}
pub(super) fn check(
    original: &Image,
    current: &Image,
    history: &AnchorHandoffHistory,
    authorized: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(), DurableError> {
    if current.namespace != original.namespace
        || current.namespace != history.namespace_binding()
        || current.revision < original.revision
    {
        return Err(DurableError::Corrupt);
    }
    current.check_retired_transfers(history)?;
    for (id, before) in &original.retired_transfers {
        if !current
            .retired_transfers
            .get(id)
            .is_some_and(|after| after.preserves(before))
        {
            return Err(DurableError::Suspended);
        }
    }
    for (id, old) in &original.entries {
        let next = current.entries.get(id).ok_or(DurableError::Suspended)?;
        let encode = |entry: &Entry| {
            let mut bytes = Vec::new();
            encode_entry(entry, history, EntryFormat::COMPLETE, &mut bytes)?;
            Ok::<_, DurableError>(bytes)
        };
        if authorized.contains_key(id) {
            // Cold open validates every indexed public authorization before
            // returning an owner. Live owners require its exact cached index.
            // Transferred requests and the explicitly receipt-bound independent
            // control plane may change these entries. Legacy management retains
            // its inherited fence; neither path can adopt another subject.
            if next.subject != old.subject
                || next.device != old.device
                || next.genesis != old.genesis
                || next.original_identity != old.original_identity
                || next.head.fence < old.head.fence
                || next.head.revision < old.head.revision
                || next.renewal_floor < old.renewal_floor
                || next.policy_floor < old.policy_floor
            {
                return Err(DurableError::Suspended);
            }
            encode(next)?;
        } else if encode(old)? != encode(next)? {
            return Err(DurableError::Suspended);
        }
    }
    retained(&original.replacements, &current.replacements, |p| {
        Ok(p.to_bytes()?)
    })?;
    retained(
        &original.account_replacements,
        &current.account_replacements,
        |p| Ok(p.to_bytes()?),
    )?;
    retained(&original.account_freezes, &current.account_freezes, |p| {
        Ok(p.to_bytes()?)
    })?;
    retained(&original.retired_cleanup, &current.retired_cleanup, |p| {
        Ok(p.to_bytes())
    })?;
    for (id, before) in &original.retired_reports {
        let after = current
            .retired_reports
            .get(id)
            .ok_or(DurableError::Suspended)?;
        if after.proposal != before.proposal
            || (after.acknowledged != before.acknowledged
                && (before.acknowledged || !current.retired_transfers.contains_key(id)))
        {
            return Err(DurableError::Suspended);
        }
    }
    retained(&original.account_closures, &current.account_closures, |r| {
        let mut bytes = Vec::new();
        account_replacement::closure::encode_records(&BTreeMap::from([([1; 32], *r)]), &mut bytes)?;
        Ok(bytes)
    })?;
    retained(
        &original.account_decisions,
        &current.account_decisions,
        |r| Ok(r.as_bytes().to_vec()),
    )?;
    let inherited = |subject: AnchorSubject| {
        original
            .entries
            .contains_key(&subject.id(&original.namespace))
    };
    for (id, p) in &current.replacements {
        if !original.replacements.contains_key(id)
            && (inherited(p.successor()) || p.predecessors().any(&inherited))
        {
            return Err(DurableError::Suspended);
        }
    }
    for (id, p) in &current.account_replacements {
        if !original.account_replacements.contains_key(id)
            && (inherited(p.successor()) || p.predecessors().any(&inherited))
        {
            current.require_account_decision(p, history)?;
        }
    }
    for (id, p) in &current.account_freezes {
        if !original.account_freezes.contains_key(id)
            && p.subjects().any(|s| inherited(s.subject()))
        {
            // A client adoption authorizes only one subject. Account-wide
            // recovery instead requires the exact separately approved snapshot
            // and its durably retained current-authority signature.
            p.require_transfer_proof(history)?;
        }
    }
    if current.retired_cleanup.keys().any(|id| {
        original.entries.contains_key(id)
            && !original.retired_cleanup.contains_key(id)
            && !current.retired_transfers.contains_key(id)
    }) || current.retired_reports.keys().any(|id| {
        original.entries.contains_key(id)
            && !original.retired_reports.contains_key(id)
            && !current.retired_transfers.contains_key(id)
    }) {
        return Err(DurableError::Suspended);
    }
    Ok(())
}
