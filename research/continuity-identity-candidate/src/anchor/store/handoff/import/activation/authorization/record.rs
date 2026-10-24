// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(in crate::anchor::store::handoff::import) struct Record {
    pub(super) request: RetainedAdoptionRequest,
    pub(super) receipt: AnchorHandoffClientAuthorizationReceipt,
}
impl Record {
    pub(super) fn encode(&self) -> Result<Vec<u8>, DurableError> {
        let mut bytes = b"QPAHCR01".to_vec();
        super::super::super::super::codec::put(self.request.as_bytes(), &mut bytes)?;
        super::super::super::super::codec::put(self.receipt.as_bytes(), &mut bytes)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(bytes)
    }
    pub(super) fn decode(
        bytes: &[u8],
        id: [u8; 32],
        original: &Image,
        approval: &AnchorHandoffTargetApproval,
        history: &AnchorHandoffHistory,
        activation: &AnchorHandoffActivationReceipt,
    ) -> Result<Self, DurableError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DurableError::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHCR01" {
            return Err(DurableError::Corrupt);
        }
        let incoming = super::super::super::super::codec::take(&mut d)?;
        let entry = original.entries.get(&id).ok_or(DurableError::Absent)?;
        let request =
            RetainedAdoptionRequest::restore(incoming, &entry.device, history, activation)?;
        check_request(&request, id, original, approval, history)?;
        let receipt = AnchorHandoffClientAuthorizationReceipt::verify(
            super::super::super::super::codec::take(&mut d)?,
            &request.approved,
            history,
        )?;
        d.finish()?;
        Ok(Self { request, receipt })
    }
}
