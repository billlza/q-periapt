// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Permanent original-operation non-commit; never permission to revive an old root.
use super::*;
mod receipt;

/// Authenticated permanent non-commit of an exact original replacement proposal.
/// It does not unfreeze an account, enroll a successor or prove message delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorClosedAccountReplacement {
    proposal: AnchorAccountReplacementProposal,
}
impl AnchorClosedAccountReplacement {
    /// Exact original statement that this witness can never commit.
    pub fn proposal(&self) -> &AnchorAccountReplacementProposal {
        &self.proposal
    }
}
pub(super) fn check_scope(
    p: &AnchorAccountReplacementProposal,
    pin: &AnchorPin,
) -> Result<(), Error> {
    p.check_shape()?;
    if p.witness != pin.binding
        || p.previous_root.shares_component(&pin.key)
        || p.successor_root.shares_component(&pin.key)
    {
        return Err(Error::Scope);
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub(in crate::anchor::store) enum ClosureRecord {
    Exact([u8; 32]),
    Plan { binding: [u8; 32], freeze: [u8; 32] },
}
impl ClosureRecord {
    fn matches(&self, p: &AnchorAccountReplacementProposal) -> Result<bool, Error> {
        match self {
            Self::Exact(binding) => Ok(*binding == p.binding()?),
            Self::Plan { binding, freeze } => {
                AnchorAccountReplacementPlan::matches_closed_target(p, *freeze, *binding)
            }
        }
    }
}
impl Image {
    pub(in crate::anchor::store) fn check_account_closures(&self) -> Result<(), DurableError> {
        if self.account_closures.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        if self.account_closures.is_empty() {
            return Ok(());
        }
        for (operation, record) in &self.account_closures {
            nonzero(operation)?;
            if let ClosureRecord::Plan { freeze, .. } = record {
                nonzero(freeze)?;
            }
        }
        if self
            .account_replacements
            .values()
            .any(|p| self.account_closures.contains_key(p.operation.as_bytes()))
        {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn closed_account_operation(
        &self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<Option<AnchorAccountReplacementState>, DurableError> {
        match self.account_closures.get(p.operation.as_bytes()) {
            Some(record) if record.matches(p)? => Ok(Some(AnchorAccountReplacementState::Closed)),
            Some(_) => Err(DurableError::Conflict),
            None => Ok(None),
        }
    }
}
impl AnchorStore {
    /// Independently authorize permanent non-commit of this original operation.
    /// Closing does not require current target validity or a still-current old-head
    /// snapshot. It never rewrites an already committed decision or unfreezes an
    /// account. A different proposal cannot reuse a closed operation ID.
    ///
    /// This is a trusted control-plane action. Retain the exact proposal before
    /// submission. I/O errors can follow commit: reopen the same witness and retry.
    pub fn close_account_replacement(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<AnchorAccountReplacementState, DurableError> {
        check_scope(p, &self.pin()?)?;
        let mut image = self.image()?;
        if let Some(saved) = image
            .account_replacements
            .values()
            .find(|saved| saved.operation == p.operation)
        {
            return if saved == p {
                Ok(AnchorAccountReplacementState::Committed)
            } else {
                Err(DurableError::Conflict)
            };
        }
        if let Some(closed) = image.closed_account_operation(p)? {
            return Ok(closed);
        }
        if image.account_closures.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image
            .account_closures
            .insert(*p.operation.as_bytes(), ClosureRecord::Exact(p.binding()?));
        self.persist(&mut image)?;
        Ok(AnchorAccountReplacementState::Closed)
    }
    /// Recover only an exact retained terminal non-commit, never infer it from absence.
    pub fn closed_account_replacement(
        &mut self,
        p: &AnchorAccountReplacementProposal,
    ) -> Result<AnchorClosedAccountReplacement, DurableError> {
        check_scope(p, &self.pin()?)?;
        if self.image()?.closed_account_operation(p)? != Some(AnchorAccountReplacementState::Closed)
        {
            return Err(DurableError::Absent);
        }
        Ok(AnchorClosedAccountReplacement {
            proposal: p.clone(),
        })
    }
}
// Compact authenticated history: one operation ID and exact proposal commitment.
// The independently retained proposal remains required for status and signed proof.
pub(in crate::anchor::store) fn encode_records(
    records: &BTreeMap<[u8; 32], ClosureRecord>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (operation, record) in records {
        out.extend_from_slice(operation);
        match record {
            ClosureRecord::Exact(binding) => {
                out.push(0);
                out.extend_from_slice(binding);
            }
            ClosureRecord::Plan { binding, freeze } => {
                out.push(1);
                out.extend_from_slice(binding);
                out.extend_from_slice(freeze);
            }
        }
    }
    Ok(())
}
pub(in crate::anchor::store) fn decode_records(
    d: &mut Decoder<'_>,
) -> Result<BTreeMap<[u8; 32], ClosureRecord>, DurableError> {
    let count = usize::from(d.u16()?);
    if count == 0 || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut records = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let operation = *AnchorAccountReplacementId::from_trusted_state(d.array()?)?.as_bytes();
        if previous.is_some_and(|old| old >= operation) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(operation);
        let record = match d.array::<1>()? {
            [0] => ClosureRecord::Exact(d.array()?),
            [1] => {
                let binding = d.array()?;
                let freeze = *AnchorAccountFreezeId::from_trusted_state(d.array()?)?.as_bytes();
                ClosureRecord::Plan { binding, freeze }
            }
            _ => return Err(DurableError::Corrupt),
        };
        records.insert(operation, record);
    }
    Ok(records)
}
