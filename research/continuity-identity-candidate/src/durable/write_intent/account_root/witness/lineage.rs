// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact signed non-commit history for transferred account-root attempts.
use super::*;

const MAX_STEPS: usize = transfer::MAX_TRANSFERS;
const STEP_BYTES: usize = 32 * 3 + 96 * 2 + WITNESS_RECEIPT_BYTES;
pub(crate) const MAX_BYTES: usize = 2 + MAX_STEPS * STEP_BYTES;

#[derive(Clone, Eq, PartialEq)]
struct Step {
    operation: [u8; 32],
    previous: [u8; 32],
    next: [u8; 32],
    previous_authority: Binding,
    next_authority: Binding,
    closed: Vec<u8>,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct Attempts(Vec<Step>);
impl Attempts {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn check(
        &self,
        proposal: &Proposal,
        authority: Option<&Binding>,
    ) -> Result<(), DurableError> {
        if self.0.len() > MAX_STEPS {
            return Err(DurableError::Capacity);
        }
        let mut operations = std::collections::BTreeSet::new();
        let mut previous: Option<&Step> = None;
        for step in &self.0 {
            for hash in [step.operation, step.previous, step.next] {
                crate::codec::nonzero(&hash)?;
            }
            if !operations.insert(step.operation)
                || step.previous == step.next
                || step.closed.len() != WITNESS_RECEIPT_BYTES
                || step.previous_authority.logical != step.next_authority.logical
                || previous.is_some_and(|old| {
                    old.next != step.previous || old.next_authority != step.previous_authority
                })
            {
                return Err(DurableError::Corrupt);
            }
            previous = Some(step);
        }
        let current_binding = proposal.binding()?;
        if operations.contains(proposal.operation().as_bytes())
            || previous.is_some_and(|last| {
                authority != Some(&last.next_authority) || current_binding != last.next
            })
        {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn append(
        &self,
        previous: &TransferredAccountRootJournalPlan,
        next: &TransferredAccountRootJournalPlan,
        closed: &[u8],
    ) -> Result<Self, DurableError> {
        let mut result = self.clone();
        result.0.push(Step {
            operation: *previous.proposal().operation().as_bytes(),
            previous: previous.proposal().binding()?,
            next: next.proposal().binding()?,
            previous_authority: previous.binding()?,
            next_authority: next.binding()?,
            closed: closed.to_vec(),
        });
        result.check(next.proposal(), Some(&next.binding()?))?;
        Ok(result)
    }
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        if self.0.len() > MAX_STEPS {
            return Err(DurableError::Capacity);
        }
        out.extend_from_slice(
            &u16::try_from(self.0.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        for step in &self.0 {
            for hash in [step.operation, step.previous, step.next] {
                out.extend_from_slice(&hash);
            }
            step.previous_authority.encode(out)?;
            step.next_authority.encode(out)?;
            if step.closed.len() != WITNESS_RECEIPT_BYTES {
                return Err(DurableError::Corrupt);
            }
            out.extend_from_slice(&step.closed);
        }
        Ok(())
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let count = usize::from(d.u16()?);
        if count == 0 || count > MAX_STEPS {
            return Err(DurableError::Corrupt);
        }
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            steps.push(Step {
                operation: d.array()?,
                previous: d.array()?,
                next: d.array()?,
                previous_authority: Binding::decode(d)?,
                next_authority: Binding::decode(d)?,
                closed: d.take(WITNESS_RECEIPT_BYTES)?.to_vec(),
            });
        }
        Ok(Self(steps))
    }
}
