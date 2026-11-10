// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded parent retirement keeps exact proof bytes after the old journal is gone.
use super::*;
const LEGACY: &[u8; 8] = b"QPERTR01";
const TRANSFERRED: &[u8; 8] = b"QPERTR02";
const LEGACY_MAX: usize = 8192;
const MAX: usize = LEGACY_MAX + 64 + 4 + Control::MAX_BYTES;
impl State {
    pub(in crate::enrollment) fn decode(
        wire: &[u8],
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Self, DurableError> {
        if !(8 + 32 + 32 + 32 + 313 + 1 + 32..=MAX).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let tag = d.array::<8>()?;
        if (tag != *LEGACY && tag != *TRANSFERRED)
            || d.array::<32>()? != binding
            || (tag == *LEGACY && wire.len() > LEGACY_MAX)
        {
            return Err(DurableError::Conflict);
        }
        let context = if tag == *TRANSFERRED {
            let binding = d.array()?;
            let original_child = d.array()?;
            crate::codec::nonzero(&binding)?;
            crate::codec::nonzero(&original_child)?;
            Some(TransferredMetadata {
                binding,
                original_child,
            })
        } else {
            None
        };
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let enrollment_digest = d.array()?;
        let inventory = AnchorRetiredCleanupProposal::from_trusted_state(d.take(313)?)?;
        let signer = match d.array::<1>()? {
            [0] => None,
            [1] => {
                let file = SigningFilePlan::decode(&mut d)?;
                if file.identity() != identity || file.report().inventory() != &inventory {
                    return Err(DurableError::Corrupt);
                }
                let proof = if let Some(context) = &context {
                    let len = usize::try_from(u32::from_be_bytes(d.array()?))
                        .map_err(|_| DurableError::Capacity)?;
                    if len > Control::MAX_BYTES {
                        return Err(DurableError::Corrupt);
                    }
                    let raw = d.take(len)?;
                    if Control::context_binding(raw)? != context.binding {
                        return Err(DurableError::Conflict);
                    }
                    SignerProof::Transferred(raw.to_vec())
                } else {
                    SignerProof::Legacy(d.take(3730)?.to_vec())
                };
                Some(Box::new(SignerPlan { file, proof }))
            }
            _ => return Err(DurableError::Corrupt),
        };
        d.finish()?;
        Ok(Self {
            identity,
            enrollment_digest,
            inventory,
            signer,
            context,
        })
    }
    pub(super) fn encode(
        &self,
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Vec<u8>, DurableError> {
        let mut wire = if self.context.is_some() {
            TRANSFERRED.to_vec()
        } else {
            LEGACY.to_vec()
        };
        wire.extend_from_slice(&binding);
        if let Some(context) = &self.context {
            crate::codec::nonzero(&context.binding)?;
            crate::codec::nonzero(&context.original_child)?;
            wire.extend_from_slice(&context.binding);
            wire.extend_from_slice(&context.original_child);
        }
        wire.extend_from_slice(self.identity.as_bytes());
        wire.extend_from_slice(&self.enrollment_digest);
        wire.extend_from_slice(&self.inventory.to_bytes());
        match &self.signer {
            None => wire.push(0),
            Some(plan) => {
                wire.push(1);
                plan.file.encode(&mut wire);
                match (&self.context, &plan.proof) {
                    (None, SignerProof::Legacy(raw)) if raw.len() == 3730 => {
                        wire.extend_from_slice(raw)
                    }
                    (Some(context), SignerProof::Transferred(raw)) => {
                        if raw.len() > Control::MAX_BYTES
                            || Control::context_binding(raw)? != context.binding
                        {
                            return Err(DurableError::Conflict);
                        }
                        wire.extend_from_slice(
                            &u32::try_from(raw.len())
                                .map_err(|_| DurableError::Capacity)?
                                .to_be_bytes(),
                        );
                        wire.extend_from_slice(raw);
                    }
                    _ => return Err(DurableError::Conflict),
                }
            }
        }
        let mut mac = auth(key)?;
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        if wire.len()
            > if self.context.is_some() {
                MAX
            } else {
                LEGACY_MAX
            }
        {
            return Err(DurableError::Capacity);
        }
        Ok(wire)
    }
}
