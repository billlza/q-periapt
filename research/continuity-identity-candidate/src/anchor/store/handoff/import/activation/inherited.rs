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
) -> Result<(), DurableError> {
    if current.namespace != original.namespace
        || current.namespace != history.namespace_binding()
        || current.revision < original.revision
        || current.handoff.is_some()
    {
        return Err(DurableError::Corrupt);
    }
    retained(&original.entries, &current.entries, |entry| {
        let mut bytes = Vec::new();
        encode_entry(entry, history, EntryFormat::COMPLETE, &mut bytes)?;
        Ok(bytes)
    })?;
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
    retained(&original.retired_reports, &current.retired_reports, |r| {
        let mut bytes = r.proposal.to_bytes();
        bytes.push(u8::from(r.acknowledged));
        Ok(bytes)
    })?;
    retained(&original.account_closures, &current.account_closures, |r| {
        let mut bytes = Vec::new();
        account_replacement::closure::encode_records(&BTreeMap::from([([1; 32], *r)]), &mut bytes)?;
        Ok(bytes)
    })?;
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
            return Err(DurableError::Suspended);
        }
    }
    for (id, p) in &current.account_freezes {
        if !original.account_freezes.contains_key(id)
            && p.subjects().any(|s| inherited(s.subject()))
        {
            return Err(DurableError::Suspended);
        }
    }
    if current
        .retired_cleanup
        .keys()
        .any(|id| original.entries.contains_key(id) && !original.retired_cleanup.contains_key(id))
        || current.retired_reports.keys().any(|id| {
            original.entries.contains_key(id) && !original.retired_reports.contains_key(id)
        })
    {
        return Err(DurableError::Suspended);
    }
    Ok(())
}
