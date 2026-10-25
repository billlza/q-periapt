// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
const MAX_BYTES: usize = lineage::DECISION_BYTES;
const RECEIPT_BYTES: usize = lineage::RECEIPT_BYTES;

#[derive(Clone)]
pub(super) struct Fence {
    pub(super) image: [u8; 32],
    pub(super) pending: Option<[u8; 32]>,
    pub(super) request: Vec<u8>,
    pub(super) prepared_at: u64,
    pub(super) receipt: Option<Vec<u8>>,
    pub(super) lineage: WitnessAdoptionLineage,
}
pub(super) fn pending_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-WITNESS-HANDOFF-PENDING/v1", wire)
}
fn mac(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let key = key.witness_handoff_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_bytes())
        .map_err(|_| Error::Provider.into())
}
impl Fence {
    pub(super) fn new(
        image: &Image,
        pending: Option<&PendingIntent>,
        plan: &WitnessJournalAdoptionPlan,
        prepared_at: u64,
    ) -> Self {
        Self {
            image: image.digest,
            pending: pending.map(|p| pending_digest(p.wire())),
            request: plan.request.clone(),
            prepared_at,
            receipt: None,
            lineage: WitnessAdoptionLineage::default(),
        }
    }
    pub(super) fn check(
        &self,
        image: &Image,
        pending: Option<&PendingIntent>,
    ) -> Result<(), DurableError> {
        self.lineage.check(&self.request, self.prepared_at)?;
        let scope =
            crate::session_policy::RetainedAdoptionRequest::unverified_scope(&self.request)?;
        let Protection::Required {
            policy, witness, ..
        } = image.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        scope.validity().check(self.prepared_at)?;
        if scope.subject.journal_parts() != (image.id, image.owner, policy)
            || scope.logical != witness
            || self.image != image.digest
            || self.pending != pending.map(|p| pending_digest(p.wire()))
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn encode(&self, key: &JournalKey) -> Result<Vec<u8>, DurableError> {
        self.lineage.check(&self.request, self.prepared_at)?;
        let mut out = if self.lineage.is_empty() {
            b"QPWJAH01"
        } else {
            b"QPWJAH02"
        }
        .to_vec();
        out.extend_from_slice(&self.image);
        out.push(u8::from(self.pending.is_some()));
        out.extend_from_slice(&self.pending.unwrap_or([0; 32]));
        out.extend_from_slice(&self.prepared_at.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.request.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.request);
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        if !receipt.is_empty() && receipt.len() != RECEIPT_BYTES {
            return Err(DurableError::Corrupt);
        }
        out.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        out.extend_from_slice(receipt);
        // A first preparation reserves the whole exact target receipt. Adoption
        // must not run out of metadata space after target authorization commits.
        let reserved = if self.receipt.is_none() {
            RECEIPT_BYTES
        } else {
            0
        };
        if out
            .len()
            .checked_add(reserved + 32)
            .ok_or(DurableError::Capacity)?
            > MAX_BYTES
        {
            return Err(DurableError::Capacity);
        }
        if !self.lineage.is_empty() {
            out.extend_from_slice(&self.lineage.encode()?);
        }
        if out
            .len()
            .checked_add(reserved + 32)
            .ok_or(DurableError::Capacity)?
            > self.lineage.maximum_bytes()
        {
            return Err(DurableError::Capacity);
        }
        let mut auth = mac(key)?;
        auth.update(&out);
        out.extend_from_slice(&auth.finalize().into_bytes());
        Ok(out)
    }
    pub(super) fn decode(key: &JournalKey, wire: &[u8]) -> Result<Self, DurableError> {
        if !(119..=WitnessAdoptionLineage::MAX_BYTES).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut auth = mac(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let successive = match d.array::<8>()? {
            tag if tag == *b"QPWJAH01" && wire.len() <= MAX_BYTES => false,
            tag if tag == *b"QPWJAH02" => true,
            _ => return Err(DurableError::Corrupt),
        };
        let image = d.array()?;
        crate::codec::nonzero(&image)?;
        let [present] = d.array()?;
        let value = d.array()?;
        let pending = match present {
            0 if value == [0; 32] => None,
            1 => {
                crate::codec::nonzero(&value)?;
                Some(value)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let prepared_at = d.u64()?;
        let len =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        let request = d.take(len)?.to_vec();
        crate::session_policy::RetainedAdoptionRequest::unverified_scope(&request)?;
        let len = usize::from(d.u16()?);
        let receipt = match len {
            0 => None,
            RECEIPT_BYTES => Some(d.take(len)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        let lineage = if successive {
            WitnessAdoptionLineage::decode(&mut d)?
        } else {
            WitnessAdoptionLineage::default()
        };
        d.finish()?;
        let result = Self {
            image,
            pending,
            request,
            prepared_at,
            receipt,
            lineage,
        };
        if result.encode(key)? != wire {
            return Err(DurableError::Corrupt);
        }
        Ok(result)
    }
}
