// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Source freeze/cancellation. Neither receipt authorizes target activation.
use super::*;

mod codec;
pub(super) use codec::{unwrap, validate, wrap};
pub(super) const MAX_CANCELLED: usize = 16;

/// Exact source transaction independently approved by the witness operator.
/// This candidate format is not a client policy grant or a target approval.
#[derive(Clone)]
pub struct AnchorHandoffPlan {
    operation: [u8; 32],
    source: AnchorPin,
    target: AnchorPin,
    revision: u64,
    commitment: [u8; 32],
    validity: Validity,
    authorization: [u8; 32],
}

impl AnchorHandoffPlan {
    /// Bind a trusted operator decision to the complete captured state and an
    /// independently selected, different target key. The authorization digest
    /// identifies the operator's retained approval; it does not authenticate an
    /// incoming claim. Never expose this constructor as a network approval API.
    pub fn from_trusted_state(
        operation: [u8; 32],
        source: &AnchorHandoffSourceState,
        target: AnchorPin,
        validity: Validity,
        authorization: [u8; 32],
    ) -> Result<Self, Error> {
        let plan = Self {
            operation,
            source: source.pin().clone(),
            target,
            revision: source.revision(),
            commitment: source.commitment(),
            validity,
            authorization,
        };
        plan.check()?;
        Ok(plan)
    }

    fn check(&self) -> Result<(), Error> {
        nonzero(&self.operation)?;
        nonzero(&self.commitment)?;
        nonzero(&self.authorization)?;
        generation(self.revision)?;
        if self.source.binding == self.target.binding
            || self.source.key.shares_component(&self.target.key)
        {
            return Err(Error::Scope);
        }
        Ok(())
    }

    /// Exact public intent for authenticated local retention, not permission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"QPAHPL01".to_vec();
        out.extend_from_slice(&self.operation);
        for pin in [&self.source, &self.target] {
            out.extend_from_slice(pin.identity.as_bytes());
            out.extend_from_slice(&pin.key.encode());
        }
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.commitment);
        self.validity.encode(&mut out);
        out.extend_from_slice(&self.authorization);
        out
    }

    /// Restore an independently approved exact intent. Shape checking here does
    /// not make a network-supplied descriptor an approved control-plane command.
    pub fn restore_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHPL01" {
            return Err(Error::Encoding);
        }
        let operation = d.array()?;
        let mut pin = || {
            Ok::<_, Error>(AnchorPin::new(
                AnchorIdentity::from_trusted_state(d.array()?)?,
                PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?,
            ))
        };
        let source = pin()?;
        let target = pin()?;
        let result = Self {
            operation,
            source,
            target,
            revision: d.u64()?,
            commitment: d.array()?,
            validity: Validity::decode(&mut d)?,
            authorization: d.array()?,
        };
        d.finish()?;
        result.check()?;
        Ok(result)
    }

    /// Authenticate only this exact source freeze/cancellation observation.
    /// Freeze is not retirement; neither outcome activates a target or renews a
    /// client. Historical observations remain readable after admission expires.
    pub fn verify_receipt(&self, wire: &[u8]) -> Result<AnchorHandoffReceipt, Error> {
        let (body, signature) = open_envelope(wire)?;
        let mut d = Decoder::new(body);
        let state = match d.array::<8>()? {
            tag if tag == *b"QPAHFR01" => AnchorHandoffState::Frozen,
            tag if tag == *b"QPAHCL01" => AnchorHandoffState::Cancelled,
            _ => return Err(Error::Encoding),
        };
        let expected = self.to_bytes();
        if d.take(expected.len())? != expected {
            return Err(Error::Scope);
        }
        d.finish()?;
        self.source.key.verify(state.purpose(), body, signature)?;
        Ok(AnchorHandoffReceipt {
            plan: self.clone(),
            state,
            wire: wire.to_vec(),
        })
    }
}

/// Historical source decision. No variant denotes target activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorHandoffState {
    /// Original state is retained and all ordinary source operations suspend.
    Frozen,
    /// This operation was cancelled durably and can never be frozen again.
    Cancelled,
}
impl AnchorHandoffState {
    fn purpose(self) -> Purpose {
        match self {
            Self::Frozen => Purpose::AnchorHandoffFreeze,
            Self::Cancelled => Purpose::AnchorHandoffCancellation,
        }
    }
    fn tag(self) -> &'static [u8; 8] {
        match self {
            Self::Frozen => b"QPAHFR01",
            Self::Cancelled => b"QPAHCL01",
        }
    }
}

/// Exact signed bytes retained with the durable decision. Never an AnchorReply.
#[derive(Clone)]
pub struct AnchorHandoffReceipt {
    plan: AnchorHandoffPlan,
    state: AnchorHandoffState,
    wire: Vec<u8>,
}
impl AnchorHandoffReceipt {
    /// The authenticated source decision, not current client permission.
    pub fn state(&self) -> AnchorHandoffState {
        self.state
    }
    /// Exact dual-signed bytes persisted with the source decision.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    fn sign(
        plan: &AnchorHandoffPlan,
        state: AnchorHandoffState,
        key: &AnchorSigningKey,
    ) -> Result<Self, Error> {
        let mut body = state.tag().to_vec();
        body.extend_from_slice(&plan.to_bytes());
        let wire = envelope(&body, &key.sign(state.purpose(), &body)?)?;
        plan.verify_receipt(&wire)
    }
}

#[derive(Clone, Default)]
pub(super) struct Journal {
    cancelled: Vec<AnchorHandoffReceipt>,
    pub(super) frozen: Option<AnchorHandoffReceipt>,
}
impl Journal {
    fn observe(&self, plan: &AnchorHandoffPlan) -> Result<AnchorHandoffReceipt, DurableError> {
        let found = self
            .cancelled
            .iter()
            .chain(self.frozen.iter())
            .find(|r| r.plan.operation == plan.operation)
            .ok_or(DurableError::Absent)?;
        if found.plan.to_bytes() != plan.to_bytes() {
            return Err(DurableError::Conflict);
        }
        Ok(found.clone())
    }
}

impl AnchorStore {
    /// Atomically freeze the exact complete source state. All ordinary mutation,
    /// query and retry paths suspend, including trusted enrollment/management.
    /// Exact repeats return retained bytes without signing again or extending
    /// admission. A competing update makes the captured commitment stale.
    pub fn freeze_handoff(
        &mut self,
        plan: &AnchorHandoffPlan,
        now: u64,
    ) -> Result<AnchorHandoffReceipt, DurableError> {
        let mut image = self.handoff_image()?;
        if self.pin()?.binding != plan.source.binding {
            return Err(Error::Scope.into());
        }
        if let Some(journal) = &image.handoff {
            match journal.observe(plan) {
                Ok(r) if r.state == AnchorHandoffState::Frozen => return Ok(r),
                Ok(_) => return Err(Error::Retired.into()),
                Err(DurableError::Absent) => {}
                Err(e) => return Err(e),
            }
            if journal.frozen.is_some() {
                return Err(DurableError::Conflict);
            }
            if journal.cancelled.len() >= MAX_CANCELLED {
                return Err(DurableError::Capacity);
            }
        }
        plan.validity.check(now)?;
        let body = image_codec::encode_body(&plan.source, &image)?;
        if image.revision != plan.revision || source_commitment(&body) != plan.commitment {
            return Err(DurableError::Conflict);
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let receipt = AnchorHandoffReceipt::sign(plan, AnchorHandoffState::Frozen, &owner.signer)?;
        image.handoff.get_or_insert_with(Journal::default).frozen = Some(receipt.clone());
        // Cancellation moves this same-sized receipt into the retained history.
        // Reserve that space before the freeze; never require a later reset.
        image_codec::encode_body(&plan.source, &image)?;
        self.persist_image(&mut image, false)?;
        Ok(receipt)
    }

    /// Trusted cancellation of the exact still-frozen source operation, even
    /// after its admission deadline. The terminal operation remains nonreusable.
    /// Sign internally, commit the decision and exact bytes, then release them.
    /// Unknown commit errors close the owner; reopen the original store and
    /// observe/retry this same plan, never infer noncommit from a missing reply.
    pub fn cancel_handoff(
        &mut self,
        plan: &AnchorHandoffPlan,
    ) -> Result<AnchorHandoffReceipt, DurableError> {
        let mut image = self.handoff_image()?;
        let journal = image.handoff.as_mut().ok_or(DurableError::Absent)?;
        let observed = journal.observe(plan)?;
        if observed.state == AnchorHandoffState::Cancelled {
            return Ok(observed);
        }
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let receipt =
            AnchorHandoffReceipt::sign(plan, AnchorHandoffState::Cancelled, &owner.signer)?;
        journal.cancelled.push(receipt.clone());
        journal.frozen = None;
        image_codec::encode_body(&plan.source, &image)?;
        self.persist_image(&mut image, false)?;
        Ok(receipt)
    }

    /// Read an exact retained decision without changing state or re-signing.
    pub fn observe_handoff(
        &mut self,
        plan: &AnchorHandoffPlan,
    ) -> Result<AnchorHandoffReceipt, DurableError> {
        self.handoff_image()?
            .handoff
            .as_ref()
            .ok_or(DurableError::Absent)?
            .observe(plan)
    }

    /// Recover the exact complete state bound by the retained freeze receipt.
    /// The source remains frozen. This is not permission to activate a target;
    /// target approval, import and irreversible source retirement are separate.
    pub fn frozen_handoff_state(
        &mut self,
        plan: &AnchorHandoffPlan,
    ) -> Result<AnchorHandoffSourceState, DurableError> {
        let mut image = self.handoff_image()?;
        let journal = image.handoff.as_mut().ok_or(DurableError::Absent)?;
        if journal.observe(plan)?.state != AnchorHandoffState::Frozen {
            return Err(Error::Retired.into());
        }
        journal.frozen = None;
        if journal.cancelled.is_empty() {
            image.handoff = None;
        }
        let state = AnchorHandoffSourceState::from_image(&plan.source, &image)?;
        if state.commitment() != plan.commitment {
            return Err(DurableError::Corrupt);
        }
        Ok(state)
    }
}

/// Read-only durable decision observer requiring storage authentication and the
/// independently retained public pin, but no previous private signing key.
pub struct AnchorHandoffObserver {
    db: Database,
    wrapping: JournalKey,
    pin: AnchorPin,
}
impl AnchorHandoffObserver {
    /// Open the original authenticated image using an independently retained pin.
    /// This takes the ordinary database lease and never creates missing state.
    pub fn open(path: &Path, wrapping: JournalKey, pin: AnchorPin) -> Result<Self, DurableError> {
        let db = open_private_database(path)?;
        load(&db, &wrapping, &pin)?;
        Ok(Self { db, wrapping, pin })
    }
    /// Reauthenticate durable state and return only the exact original decision.
    pub fn observe(&self, plan: &AnchorHandoffPlan) -> Result<AnchorHandoffReceipt, DurableError> {
        load(&self.db, &self.wrapping, &self.pin)?
            .handoff
            .as_ref()
            .ok_or(DurableError::Absent)?
            .observe(plan)
    }
}

fn source_commitment(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-SOURCE/v1", bytes)
}
