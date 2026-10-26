// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical parent intent formats; every extension is authenticated and bounded.
use super::*;
impl State {
    pub(in crate::enrollment) fn decode(
        wire: &[u8],
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Box<Self>, DurableError> {
        if !(174..=MAX_BYTES).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let (extended, context, attempted) = match &d.array::<8>()? {
            tag if tag == TAG => (false, false, false),
            tag if tag == TRANSFER_TAG => (true, false, false),
            tag if tag == CONTEXT_TAG => (false, true, false),
            tag if tag == ATTEMPT_TAG => (false, true, true),
            _ => return Err(DurableError::Conflict),
        };
        if d.array::<32>()? != binding {
            return Err(DurableError::Conflict);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let image = d.array()?;
        crate::codec::nonzero(&image)?;
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        let n =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if n > 65_536 {
            return Err(DurableError::Capacity);
        }
        let proposal = Proposal::from_trusted_state(d.take(n)?)?;
        let receipt = match usize::from(d.u16()?) {
            0 => None,
            n if n == RECEIPT_BYTES || (context && n == CURRENT_RECEIPT_BYTES) => {
                Some(d.take(n)?.to_vec())
            }
            _ => return Err(DurableError::Corrupt),
        };
        let history_present = if context {
            match d.array::<1>()? {
                [0] => false,
                [1] => true,
                _ => return Err(DurableError::Corrupt),
            }
        } else {
            extended
        };
        let history = if history_present {
            transfer::decode_history(&mut d)?
        } else {
            Vec::new()
        };
        let (child, authority, selection) = if context {
            let child = d.array()?;
            crate::codec::nonzero(&child)?;
            let authority = match d.array::<1>()? {
                [0] => None,
                [1] => Some(crate::durable::RootWitnessBinding::decode(&mut d)?),
                _ => return Err(DurableError::Corrupt),
            };
            let selection = match d.array::<1>()? {
                [0] => None,
                [1] => {
                    let hash = d.array()?;
                    crate::codec::nonzero(&hash)?;
                    Some(hash)
                }
                _ => return Err(DurableError::Corrupt),
            };
            (Some(child), authority, selection)
        } else {
            (None, None, None)
        };
        let attempts = if attempted {
            crate::durable::root_attempts::Attempts::decode(&mut d)?
        } else {
            crate::durable::root_attempts::Attempts::default()
        };
        d.finish()?;
        transfer::check_history(&history, &proposal)?;
        let result = Self {
            identity,
            image,
            journal,
            proposal,
            receipt,
            history,
            child,
            authority,
            selection,
            attempts,
        };
        result.check_context()?;
        Ok(Box::new(result))
    }
    pub(super) fn encode(
        &self,
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Vec<u8>, DurableError> {
        transfer::check_history(&self.history, &self.proposal)?;
        self.check_context()?;
        let proposal = self.proposal.to_bytes()?;
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        let extended = !self.history.is_empty();
        let mut wire = if !self.attempts.is_empty() {
            ATTEMPT_TAG
        } else if self.child.is_some() {
            CONTEXT_TAG
        } else if extended {
            TRANSFER_TAG
        } else {
            TAG
        }
        .to_vec();
        wire.extend_from_slice(&binding);
        wire.extend_from_slice(self.identity.as_bytes());
        wire.extend_from_slice(&self.image);
        wire.extend_from_slice(self.journal.as_bytes());
        wire.extend_from_slice(
            &u32::try_from(proposal.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(&proposal);
        wire.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(receipt);
        if self.child.is_some() {
            wire.push(u8::from(extended));
        }
        if extended {
            transfer::encode_history(&self.history, &mut wire)?;
        }
        if let Some(child) = self.child {
            wire.extend_from_slice(&child);
            wire.push(u8::from(self.authority.is_some()));
            if let Some(authority) = &self.authority {
                authority.encode(&mut wire)?;
            }
            wire.push(u8::from(self.selection.is_some()));
            if let Some(selection) = self.selection {
                wire.extend_from_slice(&selection);
            }
        }
        if !self.attempts.is_empty() {
            self.attempts.encode(&mut wire)?;
        }
        let mut mac = auth(key)?;
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        if wire.len() > MAX_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(wire)
    }
    fn check_context(&self) -> Result<(), DurableError> {
        self.attempts
            .check(&self.proposal, self.authority.as_ref())?;
        if self.child.is_none() && (self.authority.is_some() || self.selection.is_some()) {
            return Err(DurableError::Corrupt);
        }
        if self.authority.is_none() && self.selection.is_some() {
            return Err(DurableError::Corrupt);
        }
        if self.authority.is_some() && !self.history.is_empty() {
            return Err(DurableError::Suspended);
        }
        if let Some(child) = self.child {
            crate::codec::nonzero(&child)?;
        }
        if let Some(selection) = self.selection {
            crate::codec::nonzero(&selection)?;
        }
        if let Some(receipt) = &self.receipt {
            if receipt.len()
                != if self.authority.is_some() {
                    CURRENT_RECEIPT_BYTES
                } else {
                    RECEIPT_BYTES
                }
            {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
}
