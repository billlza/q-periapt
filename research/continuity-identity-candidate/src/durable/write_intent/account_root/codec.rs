// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical original root-intent layouts; authentication precedes parsing.
use super::*;
impl Fence {
    pub(super) fn encode(&self, key: &JournalKey) -> Result<Vec<u8>, DurableError> {
        transfer::check_history(&self.history, &self.proposal)?;
        let proposal = self.proposal.to_bytes()?;
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        let witness = self.authority.is_some();
        if (!witness && self.selection.is_some()) || (witness && !self.history.is_empty()) {
            return Err(DurableError::Corrupt);
        }
        let expected_receipt = if witness {
            WITNESS_RECEIPT_BYTES
        } else {
            RECEIPT_BYTES
        };
        if !receipt.is_empty() && receipt.len() != expected_receipt {
            return Err(DurableError::Corrupt);
        }
        let extended = !self.history.is_empty();
        let mut bytes = if witness {
            WITNESS_TAG
        } else if extended {
            TRANSFER_TAG
        } else {
            TAG
        }
        .to_vec();
        bytes.extend_from_slice(&self.subject.to_bytes());
        bytes.extend_from_slice(&self.image);
        bytes.push(u8::from(self.pending.is_some()));
        bytes.extend_from_slice(&self.pending.unwrap_or([0; 32]));
        bytes.extend_from_slice(
            &u32::try_from(proposal.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&proposal);
        bytes.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(receipt);
        if extended {
            transfer::encode_history(&self.history, &mut bytes)?;
        }
        if let Some(authority) = &self.authority {
            authority.encode(&mut bytes)?;
            bytes.push(u8::from(self.selection.is_some()));
            bytes.extend_from_slice(&self.selection.unwrap_or([0; 32]));
        }
        let mut auth = mac(key)?;
        auth.update(&bytes);
        bytes.extend_from_slice(&auth.finalize().into_bytes());
        if bytes.len() > MAX_FENCE_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(bytes)
    }
    pub(super) fn decode(key: &JournalKey, bytes: &[u8]) -> Result<Self, DurableError> {
        if !(207..=MAX_FENCE_BYTES).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = mac(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let (extended, witness) = match &d.array::<8>()? {
            tag if tag == TAG => (false, false),
            tag if tag == TRANSFER_TAG => (true, false),
            tag if tag == WITNESS_TAG => (false, true),
            _ => return Err(DurableError::Corrupt),
        };
        let subject = AnchorSubject::from_trusted_state(d.take(96)?)?;
        let image = d.array()?;
        crate::codec::nonzero(&image)?;
        let [present] = d.array()?;
        let fingerprint = d.array()?;
        let pending = match present {
            0 if fingerprint == [0; 32] => None,
            1 => {
                crate::codec::nonzero(&fingerprint)?;
                Some(fingerprint)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let size =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if size > 65_536 {
            return Err(DurableError::Capacity);
        }
        let proposal = Proposal::from_trusted_state(d.take(size)?)?;
        let size = usize::from(d.u16()?);
        let expected_receipt = if witness {
            WITNESS_RECEIPT_BYTES
        } else {
            RECEIPT_BYTES
        };
        let receipt = match size {
            0 => None,
            n if n == expected_receipt => Some(d.take(size)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        let history = if extended {
            transfer::decode_history(&mut d)?
        } else {
            Vec::new()
        };
        let (authority, selection) = if witness {
            if !history.is_empty() {
                return Err(DurableError::Corrupt);
            }
            let authority = witness::Binding::decode(&mut d)?;
            let [present] = d.array()?;
            let fingerprint = d.array()?;
            let selection = match present {
                0 if fingerprint == [0; 32] => None,
                1 => {
                    crate::codec::nonzero(&fingerprint)?;
                    Some(fingerprint)
                }
                _ => return Err(DurableError::Corrupt),
            };
            (Some(authority), selection)
        } else {
            (None, None)
        };
        d.finish()?;
        transfer::check_history(&history, &proposal)?;
        Ok(Self {
            subject,
            image,
            pending,
            proposal,
            receipt,
            history,
            authority,
            selection,
        })
    }
}
