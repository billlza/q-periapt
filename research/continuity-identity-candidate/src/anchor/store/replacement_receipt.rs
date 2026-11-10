// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Portable proof of permanent retirement, separate from fresh operating replies.
use super::*;

const BODY_BYTES: usize = 8 + 32 + 32 + 96 + 48 + 33 + 32 + 96;
const TAG: &[u8; 8] = b"QPDRTR01";

impl AnchorRetiredSubject {
    fn receipt_body(self) -> Vec<u8> {
        let mut body = TAG.to_vec();
        body.extend_from_slice(&self.witness);
        body.extend_from_slice(&self.replacement);
        self.subject.encode(&mut body);
        self.head.encode(&mut body);
        encode_last(self.last, &mut body);
        body.extend_from_slice(&self.state);
        self.successor.encode(&mut body);
        body
    }
}
impl AnchorStore {
    /// Sign immutable historical metadata for the exact retained replacement.
    /// The trusted controller may distribute these public bytes after retirement.
    /// No current device/policy validity or old signing key is needed, because the
    /// proof grants no operating authority. It cannot be an ordinary anchor reply.
    /// Repeated issuance may use different signature randomness for the same body.
    pub fn retired_subject_receipt(
        &mut self,
        proposal: &AnchorDeviceReplacementProposal,
        subject: AnchorSubject,
    ) -> Result<Vec<u8>, DurableError> {
        let observed = self.retired_subject_observation(proposal, subject)?;
        let body = observed.receipt_body();
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active.signer.sign(Purpose::AnchorRetirement, &body)?;
            envelope(&body, &signature).map_err(DurableError::from)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify a permanent retirement fact against an independently pinned witness,
    /// the complete original replacement proposal, and the expected old subject.
    /// There is no freshness nonce: the retained retirement cannot be undone. The
    /// result permits neither ordinary activation nor reads/writes under that old
    /// subject. Old witness key/storage continuity remains a trust assumption.
    ///
    /// ```compile_fail
    /// use q_periapt_continuity_identity_candidate::{AnchorReply, AnchorRetiredSubject};
    /// fn operating_reply(retired: AnchorRetiredSubject) -> AnchorReply { retired }
    /// ```
    pub fn verify_retired_subject(
        &self,
        proposal: &AnchorDeviceReplacementProposal,
        subject: AnchorSubject,
        wire: &[u8],
    ) -> Result<AnchorRetiredSubject, Error> {
        if wire.len() != 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        if proposal.witness != self.binding {
            return Err(Error::Scope);
        }
        let predecessor = proposal
            .predecessors
            .iter()
            .find(|entry| entry.subject == subject)
            .ok_or(Error::Scope)?;
        let (body, signature) = open_envelope(wire)?;
        if body.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        self.key
            .verify(Purpose::AnchorRetirement, body, signature)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *TAG
            || d.array::<32>()? != self.binding
            || d.array::<32>()? != proposal.binding()?
            || AnchorSubject::decode(&mut d)? != subject
        {
            return Err(Error::Scope);
        }
        let head = AnchorHead::decode(&mut d)?;
        let last = decode_last(&mut d, head)?;
        if let Some(command) = last {
            nonzero(&command)?;
        }
        let state = d.array()?;
        let successor = AnchorSubject::decode(&mut d)?;
        d.finish()?;
        if state != predecessor.state || successor != proposal.target {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredSubject {
            witness: self.binding,
            subject,
            head,
            last,
            state,
            replacement: proposal.binding()?,
            successor,
        })
    }
}
