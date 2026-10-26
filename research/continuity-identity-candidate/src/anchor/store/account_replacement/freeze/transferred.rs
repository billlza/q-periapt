// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent whole-account preparation under a verified successor Witness.
use super::*;
pub(super) mod codec;
mod store;

/// Unsigned observation of every classified subject in an account. It neither
/// freezes the account nor authorizes recovery. An operator must independently
/// authenticate account recovery and approve this complete exact snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredAccountFreezeProposal {
    frozen: AnchorFrozenAccount,
    namespace: [u8; 32],
    history: [u8; 32],
}
impl AnchorTransferredAccountFreezeProposal {
    /// Exact original freeze operation and account root, not authority.
    pub fn request(&self) -> &AnchorAccountFreezeRequest {
        &self.frozen.request
    }
    /// Complete snapshot, including offline devices and pending operations.
    pub fn subjects(&self) -> impl Iterator<Item = AnchorRetiredAccountSubject> + '_ {
        self.frozen.subjects()
    }
    fn check(&self, history: &AnchorHandoffHistory) -> Result<(), DurableError> {
        self.frozen.check_shape()?;
        let pin = history.historical_pin(self.frozen.request.witness)?;
        self.frozen.request.check_pin(pin)?;
        if self.frozen.transfer.is_some()
            || self.namespace != history.namespace_binding()
            || self.namespace == pin.binding
            || self.history != history.checkpoint_at(pin.binding)?
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
}

/// Independently retained approval of one complete account snapshot. A device
/// adoption receipt, previous-root signature or parsed network message is not
/// this approval. The host must authenticate its account-recovery operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredAccountFreezeApproval {
    proposal: AnchorTransferredAccountFreezeProposal,
    decision: [u8; 32],
    validity: Validity,
}
impl AnchorTransferredAccountFreezeApproval {
    /// Approve the exact inspected snapshot against separately retained request
    /// and verified Witness history. Persist these inputs before submission.
    pub fn from_trusted_state(
        proposal: AnchorTransferredAccountFreezeProposal,
        request: &AnchorAccountFreezeRequest,
        history: &AnchorHandoffHistory,
        decision: [u8; 32],
        validity: Validity,
    ) -> Result<Self, DurableError> {
        nonzero(&decision)?;
        proposal.check(history)?;
        if proposal.request() != request {
            return Err(Error::Scope.into());
        }
        Ok(Self {
            proposal,
            decision,
            validity,
        })
    }
    /// Complete original independently approved account snapshot.
    pub fn proposal(&self) -> &AnchorTransferredAccountFreezeProposal {
        &self.proposal
    }
    fn scope(&self) -> Scope {
        Scope {
            namespace: self.proposal.namespace,
            history: self.proposal.history,
            decision: self.decision,
            validity: self.validity,
        }
    }
    /// Verify a historical exact freeze. Expiry prevents new commitment, not
    /// recovery of a committed fact. This grants no retirement or traffic right.
    pub fn verify_receipt(
        &self,
        history: &AnchorHandoffHistory,
        wire: &[u8],
    ) -> Result<AnchorFrozenAccount, DurableError> {
        self.proposal.check(history)?;
        let frozen = AnchorFrozenAccount::decode(wire)?;
        frozen.require_transfer_proof(history)?;
        let proof = frozen.transfer.as_ref().ok_or(Error::Scope)?;
        if proof.scope != self.scope() || frozen.unproved() != self.proposal.frozen {
            return Err(Error::Scope.into());
        }
        Ok(frozen)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    namespace: [u8; 32],
    history: [u8; 32],
    decision: [u8; 32],
    validity: Validity,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Proof {
    scope: Scope,
    admitted: u64,
    wire: Vec<u8>,
}
impl Proof {
    fn body(&self, frozen: &AnchorFrozenAccount) -> Result<Vec<u8>, Error> {
        let mut body = b"QPTAFS01".to_vec();
        self.scope.encode(&mut body);
        body.extend_from_slice(&self.admitted.to_be_bytes());
        body.extend_from_slice(&frozen.unproved().binding()?);
        Ok(body)
    }
}
impl AnchorFrozenAccount {
    fn unproved(&self) -> Self {
        Self {
            request: self.request.clone(),
            subjects: self.subjects.clone(),
            transfer: None,
        }
    }
    pub(in crate::anchor::store) fn verify_transfer(
        &self,
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        if let Some(proof) = &self.transfer {
            let pin = authority.resolve(self.request.witness)?;
            if proof.scope.namespace != authority.namespace()
                || proof.scope.namespace == pin.binding
                || proof.scope.history != authority.history_checkpoint(pin.binding)?
            {
                return Err(Error::Scope.into());
            }
            nonzero(&proof.scope.decision)?;
            proof.scope.validity.check(proof.admitted)?;
            let (body, signature) = open_envelope(&proof.wire)?;
            if body != proof.body(self)? {
                return Err(Error::Scope.into());
            }
            pin.key
                .verify(Purpose::AnchorTransferredAccountFreeze, body, signature)?;
        }
        Ok(())
    }
    pub(in crate::anchor::store) fn require_transfer_proof(
        &self,
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        if self.transfer.is_none() {
            return Err(DurableError::Suspended);
        }
        self.verify_transfer(authority)
    }
}
