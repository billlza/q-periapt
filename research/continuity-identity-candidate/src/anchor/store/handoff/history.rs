// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical namespace and authority proof, never live client admission.
use super::*;

pub(in crate::anchor::store) const MAX_TRANSITIONS: usize = 8;
pub(in crate::anchor::store) const MAX_HISTORY_BYTES: usize =
    MAX_TRANSITIONS * 32 * 1024 + PUBLIC_KEY_BYTES + 128;
#[cfg(all(test, unix))]
mod tests;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::anchor::store) struct HistoryContext {
    namespace: [u8; 32],
    sequence: u64,
    checkpoint: [u8; 32],
}
impl HistoryContext {
    pub(in crate::anchor::store) fn initial(pin: &AnchorPin) -> Self {
        Self {
            namespace: pin.binding,
            sequence: 0,
            checkpoint: digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HISTORY-ROOT/v1", &pin.binding),
        }
    }
    pub(super) fn check(self, source: &AnchorPin) -> Result<(), Error> {
        nonzero(&self.namespace)?;
        nonzero(&self.checkpoint)?;
        if self.sequence == u64::MAX || (self.sequence == 0 && self != Self::initial(source)) {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(super) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.checkpoint);
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Self {
            namespace: d.array()?,
            sequence: d.u64()?,
            checkpoint: d.array()?,
        })
    }
}

#[derive(Clone)]
struct Transition {
    approval: AnchorHandoffTargetApproval,
    freeze: Vec<u8>,
    acknowledgement: Vec<u8>,
    retirement: Vec<u8>,
}
impl Transition {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        for bytes in [
            self.approval.to_bytes().as_slice(),
            &self.freeze,
            &self.acknowledgement,
            &self.retirement,
        ] {
            codec::put(bytes, out)?;
        }
        Ok(())
    }
}

/// A bounded authenticated history anchored in an independently retained origin.
/// The namespace is immutable; historical keys are never current client grants.
/// This proof does not itself activate a store, adopt a client or validate a
/// transferred mixed-authority image. Those consumers must retain the exact
/// independently approved current checkpoint and their own admission checks.
#[derive(Clone)]
pub struct AnchorHandoffHistory {
    origin: AnchorPin,
    context: HistoryContext,
    transitions: Vec<Transition>,
}
impl AnchorHandoffHistory {
    pub(in crate::anchor::store) fn checkpoint_at(
        &self,
        binding: [u8; 32],
    ) -> Result<[u8; 32], DurableError> {
        let mut checkpoint = HistoryContext::initial(&self.origin).checkpoint;
        if binding == self.origin.binding {
            return Ok(checkpoint);
        }
        for step in &self.transitions {
            let mut body = checkpoint.to_vec();
            step.encode(&mut body)?;
            checkpoint = digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HISTORY-STEP/v1", &body);
            if binding == step.approval.plan.target.binding {
                return Ok(checkpoint);
            }
        }
        Err(Error::Scope.into())
    }
    pub(crate) const MAX_TRANSITIONS: usize = MAX_TRANSITIONS;

    pub(crate) fn require_extension_of(&self, prior: &Self) -> Result<(), Error> {
        if self.origin.binding != prior.origin.binding
            || self.sequence() <= prior.sequence()
            || !prior
                .transitions
                .iter()
                .zip(&self.transitions)
                .all(|(old, next)| {
                    old.approval.to_bytes() == next.approval.to_bytes()
                        && old.freeze == next.freeze
                        && old.acknowledgement == next.acknowledgement
                        && old.retirement == next.retirement
                })
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(in crate::anchor::store) fn context(&self) -> HistoryContext {
        self.context
    }
    /// Establish the independently retained original namespace and authority.
    /// Never derive this root trust from an incoming history or peer response.
    pub fn from_trusted_origin(origin: AnchorPin) -> Self {
        Self {
            context: HistoryContext::initial(&origin),
            origin,
            transitions: Vec::new(),
        }
    }
    /// Original subject namespace, unchanged by every verified transition.
    pub fn namespace_binding(&self) -> [u8; 32] {
        self.context.namespace
    }
    /// Number of authenticated transitions; this is not a client policy version.
    pub fn sequence(&self) -> u64 {
        self.context.sequence
    }
    /// Exact public-history checkpoint for independent authenticated retention.
    pub fn checkpoint(&self) -> [u8; 32] {
        self.context.checkpoint
    }
    /// Last authority in this historical proof, not permission to serve a client.
    pub fn current_pin(&self) -> &AnchorPin {
        self.transitions
            .last()
            .map_or(&self.origin, |entry| &entry.approval.plan.target)
    }
    /// Resolve one exact historical binding only from the authenticated chain.
    /// A record cannot supply its own verification key. Unknown bindings fail.
    pub fn historical_pin(&self, binding: [u8; 32]) -> Result<&AnchorPin, Error> {
        std::iter::once(&self.origin)
            .chain(
                self.transitions
                    .iter()
                    .map(|entry| &entry.approval.plan.target),
            )
            .find(|pin| pin.binding == binding)
            .ok_or(Error::Scope)
    }
    /// Check only the current end of the proof. A known historical key cannot
    /// satisfy this check; client account/policy authorization remains separate.
    pub fn require_current(&self, binding: [u8; 32]) -> Result<(), Error> {
        if self.current_pin().binding == binding {
            Ok(())
        } else {
            Err(Error::Retired)
        }
    }

    /// Extend history only with an exact verified retirement and its matching
    /// independently retained approval, freeze and import acknowledgement.
    /// Source, original namespace, sequence and predecessor must all match.
    /// Legacy v1 plans can establish only the first transition from their own
    /// original namespace. Capacity exhaustion never truncates older proofs.
    pub fn append_verified(
        &mut self,
        approval: &AnchorHandoffTargetApproval,
        freeze: &[u8],
        acknowledgement: &[u8],
        retirement: &[u8],
    ) -> Result<(), DurableError> {
        self.admit_successor(&approval.plan)?;
        approval.verify_retirement_receipt(freeze, acknowledgement, retirement)?;
        let transition = Transition {
            approval: approval.clone(),
            freeze: freeze.to_vec(),
            acknowledgement: acknowledgement.to_vec(),
            retirement: retirement.to_vec(),
        };
        let mut commitment = self.context.checkpoint.to_vec();
        transition.encode(&mut commitment)?;
        let mut next = self.clone();
        next.context.sequence = next
            .context
            .sequence
            .checked_add(1)
            .ok_or(DurableError::Capacity)?;
        next.context.checkpoint =
            digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-HISTORY-STEP/v1", &commitment);
        next.transitions.push(transition);
        next.to_bytes()?;
        *self = next;
        Ok(())
    }

    // Admission is shared by prospective imports and committed history extension.
    // A target acknowledgement must not promise a transition that cannot fit or
    // that would reuse an earlier authority/key/operation.
    pub(in crate::anchor::store::handoff) fn admit_successor(
        &self,
        plan: &AnchorHandoffPlan,
    ) -> Result<(), DurableError> {
        if self.transitions.len() >= MAX_TRANSITIONS {
            return Err(DurableError::Capacity);
        }
        if plan.source.binding != self.current_pin().binding
            || self
                .transitions
                .iter()
                .any(|old| old.approval.plan.operation == plan.operation)
            || std::iter::once(&self.origin)
                .chain(self.transitions.iter().map(|old| &old.approval.plan.target))
                .any(|pin| {
                    pin.binding == plan.target.binding || pin.key.shares_component(&plan.target.key)
                })
        {
            return Err(Error::Scope.into());
        }
        plan.require_history(self.context)?;
        Ok(())
    }

    pub(in crate::anchor::store::handoff) fn restore_approved_source(
        bytes: &[u8],
        plan: &AnchorHandoffPlan,
    ) -> Result<Self, DurableError> {
        let context = plan.history.ok_or(Error::Scope)?;
        if bytes.len() > MAX_HISTORY_BYTES || context.sequence == 0 {
            return Err(Error::Scope.into());
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHHS01" {
            return Err(Error::Encoding.into());
        }
        let origin = AnchorPin::new(
            AnchorIdentity::from_trusted_state(d.array()?)?,
            PublicKey::decode(d.take(PUBLIC_KEY_BYTES)?)?,
        );
        // The encoded origin is only a candidate preimage of the independently
        // approved namespace binding. It does not establish its own root trust.
        if origin.binding != context.namespace {
            return Err(Error::Scope.into());
        }
        let history =
            Self::restore_trusted_state(bytes, &origin, &plan.source, context.checkpoint)?;
        if history.context != context {
            return Err(Error::Scope.into());
        }
        history.admit_successor(plan)?;
        Ok(history)
    }

    pub(in crate::anchor::store::handoff) fn current_approval(
        &self,
    ) -> Result<&AnchorHandoffTargetApproval, DurableError> {
        self.transitions
            .last()
            .map(|entry| &entry.approval)
            .ok_or(Error::Scope.into())
    }

    pub(in crate::anchor::store::handoff) fn require_tail(
        &self,
        approval: &AnchorHandoffTargetApproval,
        freeze: &[u8],
        acknowledgement: &[u8],
        retirement: &[u8],
    ) -> Result<(), DurableError> {
        let tail = self.transitions.last().ok_or(Error::Scope)?;
        if tail.approval.to_bytes() != approval.to_bytes()
            || tail.freeze != freeze
            || tail.acknowledgement != acknowledgement
            || tail.retirement != retirement
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }

    /// Canonical bounded public proof. No private signer or storage key is included.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DurableError> {
        let mut out = b"QPAHHS01".to_vec();
        out.extend_from_slice(self.origin.identity.as_bytes());
        out.extend_from_slice(&self.origin.key.encode());
        out.push(u8::try_from(self.transitions.len()).map_err(|_| DurableError::Capacity)?);
        for transition in &self.transitions {
            transition.encode(&mut out)?;
        }
        if out.len() > MAX_HISTORY_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(out)
    }

    /// Revalidate every proof against independently retained root, current pin
    /// and checkpoint. A signed but different branch or shorter prefix fails.
    pub fn restore_trusted_state(
        bytes: &[u8],
        origin: &AnchorPin,
        current: &AnchorPin,
        checkpoint: [u8; 32],
    ) -> Result<Self, DurableError> {
        if bytes.len() > MAX_HISTORY_BYTES {
            return Err(DurableError::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHHS01"
            || d.array::<32>()? != *origin.identity.as_bytes()
            || d.take(PUBLIC_KEY_BYTES)? != origin.key.encode()
        {
            return Err(Error::Scope.into());
        }
        let [count] = d.array()?;
        if usize::from(count) > MAX_TRANSITIONS {
            return Err(DurableError::Capacity);
        }
        let mut history = Self::from_trusted_origin(origin.clone());
        for _ in 0..count {
            let raw = codec::take(&mut d)?;
            let mut a = Decoder::new(raw);
            if a.array::<8>()? != *b"QPAHTA01" {
                return Err(Error::Encoding.into());
            }
            let length = a.remaining().checked_sub(48).ok_or(Error::Encoding)?;
            let plan = AnchorHandoffPlan::restore_trusted_state(a.take(length)?)?;
            // These pins are historical claims verified by the source's signed
            // retirement below, not new control-plane operator permission.
            let approval = AnchorHandoffTargetApproval::restore_trusted_state(
                raw,
                history.current_pin(),
                &plan.target,
            )?;
            let freeze = codec::take(&mut d)?;
            let ack = codec::take(&mut d)?;
            let retired = codec::take(&mut d)?;
            history.append_verified(&approval, freeze, ack, retired)?;
        }
        d.finish()?;
        if history.current_pin().binding != current.binding || history.checkpoint() != checkpoint {
            return Err(Error::Scope.into());
        }
        Ok(history)
    }
}
