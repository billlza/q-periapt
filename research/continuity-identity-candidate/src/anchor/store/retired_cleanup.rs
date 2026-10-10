// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bind one retired journal's exact local inventory before historical accounting.
use super::*;

const PROPOSAL_BYTES: usize = 8 + 32 + 32 + 96 + 32 + 48 + 32 + 33;

/// Original cleanup inventory expectation. These public bytes are not a loss
/// report, host acknowledgement, erasure permit or operating authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredCleanupProposal {
    witness: [u8; 32],
    replacement: [u8; 32],
    subject: AnchorSubject,
    state: [u8; 32],
    head: AnchorHead,
    stored_image: [u8; 32],
    pending: Option<[u8; 32]>,
}
impl AnchorRetiredCleanupProposal {
    pub(crate) fn from_journal(
        retired: AnchorRetiredSubject,
        stored_image: [u8; 32],
        pending: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        let proposal = Self {
            witness: retired.witness_binding(),
            replacement: retired.replacement_binding(),
            subject: retired.subject(),
            state: retired.state_commitment(),
            head: retired.observed_head(),
            stored_image,
            pending,
        };
        proposal.check_shape()?;
        Ok(proposal)
    }
    fn check_shape(&self) -> Result<(), Error> {
        for value in [
            self.witness,
            self.replacement,
            self.state,
            self.stored_image,
        ] {
            nonzero(&value)?;
        }
        if let Some(pending) = self.pending {
            nonzero(&pending)?;
        } else if self.stored_image != self.head.digest() {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn check_retirement(&self, retired: AnchorRetiredSubject) -> Result<(), Error> {
        self.check_shape()?;
        if self.witness != retired.witness_binding()
            || self.replacement != retired.replacement_binding()
            || self.subject != retired.subject()
            || self.state != retired.state_commitment()
            || self.head != retired.observed_head()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    /// Restore the original canonical expectation from independently retained
    /// host state. Parsing alone never authorizes a controller or cleanup action.
    pub fn from_trusted_state(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() != PROPOSAL_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(wire);
        if d.array::<8>()? != *b"QPRCLP01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        let replacement = d.array()?;
        let subject = AnchorSubject::decode(&mut d)?;
        let state = d.array()?;
        let head = AnchorHead::decode(&mut d)?;
        let stored_image = d.array()?;
        let flag = d.array::<1>()?;
        let fingerprint = d.array()?;
        let pending = match flag {
            [0] if fingerprint == [0; 32] => None,
            [1] => Some(fingerprint),
            _ => return Err(Error::Encoding),
        };
        d.finish()?;
        let proposal = Self {
            witness,
            replacement,
            subject,
            state,
            head,
            stored_image,
            pending,
        };
        proposal.check_shape()?;
        Ok(proposal)
    }
    /// Canonical inventory bytes. Persist them outside old-journal backups before
    /// dispatching the independent retention request; reconcile this exact plan.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"QPRCLP01".to_vec();
        out.extend_from_slice(&self.witness);
        out.extend_from_slice(&self.replacement);
        self.subject.encode(&mut out);
        out.extend_from_slice(&self.state);
        self.head.encode(&mut out);
        out.extend_from_slice(&self.stored_image);
        out.push(u8::from(self.pending.is_some()));
        out.extend_from_slice(&self.pending.unwrap_or([0; 32]));
        out
    }
    /// Stable binding of the complete original cleanup inventory.
    pub fn binding(&self) -> [u8; 32] {
        digest(
            b"Q-PERIAPT-CONTINUITY-RETIRED-CLEANUP-INVENTORY/v1",
            &self.to_bytes(),
        )
    }
    /// Original permanently retired journal subject.
    pub fn subject(&self) -> AnchorSubject {
        self.subject
    }
    pub(crate) fn witness_binding(&self) -> [u8; 32] {
        self.witness
    }
    /// Actual encrypted current-image fingerprint, possibly preceding a sealed
    /// target already committed at the witness. It is not a currentness grant.
    pub fn stored_image_digest(&self) -> [u8; 32] {
        self.stored_image
    }
    /// Exact authenticated local pending-record fingerprint, or actual absence.
    /// This preserves an ordinary, G/P/R or cancellation intent without claiming
    /// that the corresponding lifecycle transition succeeded.
    pub fn pending_intent_digest(&self) -> Option<[u8; 32]> {
        self.pending
    }
}

/// Trusted local observation of independent inventory retention, not accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorRetiredCleanupState {
    /// This exact inventory is permanently retained. No report or host ACK follows.
    Retained,
    /// The retired subject has no retained cleanup inventory at this observation.
    /// This does not settle an outstanding invocation or authorize a new plan.
    Unavailable,
}

/// Verified permanent binding of one complete cleanup inventory. This is neither
/// an ordinary witness reply nor a host accounting/erasure acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredCleanup {
    proposal: AnchorRetiredCleanupProposal,
}
impl AnchorRetiredCleanup {
    /// Original independently retained inventory; no runtime permission is exposed.
    pub fn proposal(&self) -> &AnchorRetiredCleanupProposal {
        &self.proposal
    }
}

impl Image {
    fn admit_cleanup(
        &self,
        proposal: &AnchorRetiredCleanupProposal,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        let replacement = self
            .replacements
            .get(&proposal.replacement)
            .ok_or(DurableError::Absent)?;
        proposal.check_retirement(self.retired_observation(
            replacement,
            proposal.subject,
            pin,
        )?)?;
        Ok(())
    }
    pub(super) fn check_retired_cleanup(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if self.retired_cleanup.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        for (id, proposal) in &self.retired_cleanup {
            if *id != proposal.subject.id(&pin.binding) {
                return Err(DurableError::Corrupt);
            }
            match self.admit_cleanup(proposal, pin) {
                Ok(()) => {}
                Err(DurableError::Absent | DurableError::Protocol(_)) => {
                    return Err(DurableError::Corrupt)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
impl AnchorStore {
    /// Independently retain the first complete original cleanup inventory.
    /// This trusted controller must authenticate the recovery caller separately;
    /// possession of public proposal/retirement bytes is not authorization. It
    /// binds metadata only and changes neither the frozen old entry nor G/P/R.
    /// A different inventory for the same retired subject permanently conflicts.
    /// I/O errors can hide commit: reopen and retry this exact proposal.
    pub fn retain_retired_cleanup(
        &mut self,
        proposal: &AnchorRetiredCleanupProposal,
    ) -> Result<AnchorRetiredCleanupState, DurableError> {
        let pin = self.pin()?;
        let mut image = self.image()?;
        image.admit_cleanup(proposal, &pin)?;
        let id = proposal.subject.id(&pin.binding);
        if let Some(saved) = image.retired_cleanup.get(&id) {
            return if saved == proposal {
                Ok(AnchorRetiredCleanupState::Retained)
            } else {
                Err(DurableError::Conflict)
            };
        }
        if image.retired_cleanup.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image.retired_cleanup.insert(id, proposal.clone());
        self.persist(&mut image)?;
        Ok(AnchorRetiredCleanupState::Retained)
    }
    /// Inspect only this exact original inventory. A competing retained inventory
    /// is Conflict, never absence. No reporting or destructive action is admitted.
    pub fn retired_cleanup_status(
        &mut self,
        proposal: &AnchorRetiredCleanupProposal,
    ) -> Result<AnchorRetiredCleanupState, DurableError> {
        let pin = self.pin()?;
        let image = self.image()?;
        image.admit_cleanup(proposal, &pin)?;
        Ok(
            match image
                .retired_cleanup
                .get(&proposal.subject.id(&pin.binding))
            {
                Some(saved) if saved == proposal => AnchorRetiredCleanupState::Retained,
                Some(_) => return Err(DurableError::Conflict),
                None => AnchorRetiredCleanupState::Unavailable,
            },
        )
    }
    /// Sign the permanently retained inventory under its own signature purpose.
    /// The proof is historical: it supplies neither host ACK nor erasure authority.
    pub fn retired_cleanup_receipt(
        &mut self,
        proposal: &AnchorRetiredCleanupProposal,
    ) -> Result<Vec<u8>, DurableError> {
        if self.retired_cleanup_status(proposal)? != AnchorRetiredCleanupState::Retained {
            return Err(DurableError::Absent);
        }
        let body = proposal.to_bytes();
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let signature = active.signer.sign(Purpose::AnchorRetiredCleanup, &body)?;
            envelope(&body, &signature).map_err(DurableError::from)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Verify independent retention of the exact original local inventory.
    /// Its separate type/purpose cannot authorize an ordinary anchor operation.
    /// The result is not a loss report or accounting acknowledgement.
    /// ```compile_fail
    /// use q_periapt_continuity_identity_candidate::{AnchorReply, AnchorRetiredCleanup};
    /// fn operating_reply(cleanup: AnchorRetiredCleanup) -> AnchorReply { cleanup }
    /// ```
    pub fn verify_retired_cleanup(
        &self,
        retired: AnchorRetiredSubject,
        proposal: &AnchorRetiredCleanupProposal,
        wire: &[u8],
    ) -> Result<AnchorRetiredCleanup, Error> {
        if wire.len() != 4 + PROPOSAL_BYTES + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        proposal.check_retirement(retired)?;
        if self.binding != proposal.witness {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        self.key
            .verify(Purpose::AnchorRetiredCleanup, body, signature)?;
        if body != proposal.to_bytes() {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredCleanup {
            proposal: proposal.clone(),
        })
    }
}

pub(super) fn encode_records(
    records: &BTreeMap<[u8; 32], AnchorRetiredCleanupProposal>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (id, proposal) in records {
        out.extend_from_slice(id);
        out.extend_from_slice(&proposal.to_bytes());
    }
    Ok(())
}
pub(super) fn decode_records(
    d: &mut Decoder<'_>,
    pin: &AnchorPin,
    allow_empty: bool,
) -> Result<BTreeMap<[u8; 32], AnchorRetiredCleanupProposal>, DurableError> {
    let count = usize::from(d.u16()?);
    if (!allow_empty && count == 0) || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut records = BTreeMap::new();
    let mut last = None;
    for _ in 0..count {
        let id = d.array()?;
        if last.is_some_and(|previous| previous >= id) {
            return Err(DurableError::Corrupt);
        }
        last = Some(id);
        let proposal = AnchorRetiredCleanupProposal::from_trusted_state(d.take(PROPOSAL_BYTES)?)?;
        if id != proposal.subject.id(&pin.binding) {
            return Err(DurableError::Corrupt);
        }
        records.insert(id, proposal);
    }
    Ok(records)
}
