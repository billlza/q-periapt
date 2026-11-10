// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact prior adopted decisions, shared by journal and installation selection.
use super::*;
pub(crate) const DECISION_BYTES: usize = 16 * 1024;
pub(crate) const RECEIPT_BYTES: usize = 4 + 80 + crate::crypto::SIGNATURE_BYTES;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Decision {
    pub(super) request: Vec<u8>,
    pub(super) prepared_at: u64,
    pub(super) receipt: Vec<u8>,
}
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct WitnessAdoptionLineage {
    pub(super) decisions: Vec<Decision>,
}
impl WitnessAdoptionLineage {
    pub(crate) const DECISION_BYTES: usize = DECISION_BYTES;
    pub(crate) fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }
    pub(crate) fn maximum_bytes(&self) -> usize {
        if self.is_empty() {
            DECISION_BYTES
        } else {
            Self::MAX_BYTES
        }
    }
    pub(crate) const MAX_BYTES: usize = DECISION_BYTES * AnchorHandoffHistory::MAX_TRANSITIONS;
    pub(crate) fn check(&self, request: &[u8], prepared_at: u64) -> Result<(), DurableError> {
        if self.decisions.len() >= AnchorHandoffHistory::MAX_TRANSITIONS {
            return Err(DurableError::Capacity);
        }
        let current = crate::session_policy::RetainedAdoptionRequest::unverified_scope(request)?;
        current.validity().check(prepared_at)?;
        let mut ids = std::collections::BTreeSet::from([*current.operation().as_bytes()]);
        let mut last_time = 0;
        for decision in &self.decisions {
            let scope = crate::session_policy::RetainedAdoptionRequest::unverified_scope(
                &decision.request,
            )?;
            scope.validity().check(decision.prepared_at)?;
            if scope.subject != current.subject
                || scope.namespace != current.namespace
                || scope.logical != current.logical
                || !ids.insert(*scope.operation().as_bytes())
                || decision.prepared_at < last_time
                || decision.prepared_at > prepared_at
                || decision.receipt.len() != RECEIPT_BYTES
            {
                return Err(DurableError::Conflict);
            }
            last_time = decision.prepared_at;
        }
        Ok(())
    }
    pub(crate) fn append(
        &self,
        request: &[u8],
        prepared_at: u64,
        receipt: &[u8],
    ) -> Result<Self, DurableError> {
        self.check(request, prepared_at)?;
        if self.decisions.len() + 1 >= AnchorHandoffHistory::MAX_TRANSITIONS
            || receipt.len() != RECEIPT_BYTES
        {
            return Err(DurableError::Capacity);
        }
        let mut next = self.clone();
        next.decisions.push(Decision {
            request: request.to_vec(),
            prepared_at,
            receipt: receipt.to_vec(),
        });
        Ok(next)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, DurableError> {
        if self.decisions.len() >= AnchorHandoffHistory::MAX_TRANSITIONS {
            return Err(DurableError::Capacity);
        }
        let mut out = vec![u8::try_from(self.decisions.len()).map_err(|_| DurableError::Capacity)?];
        for d in &self.decisions {
            crate::session_policy::RetainedAdoptionRequest::unverified_scope(&d.request)?
                .validity()
                .check(d.prepared_at)?;
            if d.receipt.len() != RECEIPT_BYTES
                || d.request
                    .len()
                    .checked_add(RECEIPT_BYTES + 14)
                    .ok_or(DurableError::Capacity)?
                    > DECISION_BYTES
            {
                return Err(DurableError::Capacity);
            }
            out.extend_from_slice(&d.prepared_at.to_be_bytes());
            out.extend_from_slice(
                &u32::try_from(d.request.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(&d.request);
            out.extend_from_slice(
                &u16::try_from(d.receipt.len())
                    .map_err(|_| DurableError::Capacity)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(&d.receipt);
        }
        Ok(out)
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let [count] = d.array()?;
        if count == 0 || usize::from(count) >= AnchorHandoffHistory::MAX_TRANSITIONS {
            return Err(DurableError::Corrupt);
        }
        let mut decisions = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let prepared_at = d.u64()?;
            let len = usize::try_from(u32::from_be_bytes(d.array()?))
                .map_err(|_| DurableError::Capacity)?;
            if len
                .checked_add(RECEIPT_BYTES + 14)
                .ok_or(DurableError::Capacity)?
                > DECISION_BYTES
            {
                return Err(DurableError::Capacity);
            }
            let request = d.take(len)?.to_vec();
            crate::session_policy::RetainedAdoptionRequest::unverified_scope(&request)?
                .validity()
                .check(prepared_at)?;
            if usize::from(d.u16()?) != RECEIPT_BYTES {
                return Err(DurableError::Corrupt);
            }
            let receipt = d.take(RECEIPT_BYTES)?.to_vec();
            decisions.push(Decision {
                request,
                prepared_at,
                receipt,
            });
        }
        Ok(Self { decisions })
    }
    pub(crate) fn checkpoint(&self, prepared_at: u64) -> Result<[u8; 32], DurableError> {
        let mut bytes = prepared_at.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.encode()?);
        Ok(digest(b"Q-PERIAPT-WITNESS-SELECTION-LINEAGE/v1", &bytes))
    }
}
