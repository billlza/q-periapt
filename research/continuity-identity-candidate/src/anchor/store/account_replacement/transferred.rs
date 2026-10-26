// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Account-root decisions under an explicit current Witness, after a retained freeze.
use super::*;
mod codec;
mod record;
mod store;
pub(in crate::anchor::store) use record::{decode_records, encode_records, Record};

/// Independently pinned successor inputs. The policy must name the Witness that
/// will enroll this new journal; original inherited policies are not reinterpreted.
pub struct AnchorTransferredAccountReplacementMaterials<'a> {
    /// Independently authenticated previous account root.
    pub previous_root: &'a PublicKey,
    /// Actual independently retained successor journal genesis.
    pub genesis: &'a AnchorGenesis,
    /// Verified successor credential and complete roster.
    pub device: &'a VerifiedDevice,
    /// Independently verified successor policy.
    pub policy: &'a VerifiedSessionPolicy,
    /// Verified history rooted in independently retained original trust.
    pub history: &'a AnchorHandoffHistory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    namespace: [u8; 32],
    history: [u8; 32],
    decision: [u8; 32],
    validity: Validity,
}
impl Scope {
    fn check(
        &self,
        witness: [u8; 32],
        authority: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        nonzero(&self.decision)?;
        if self.namespace != authority.namespace()
            || self.namespace == witness
            || self.history != authority.history_checkpoint(witness)?
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
}

/// Host-authenticated account recovery approval, distinct from a device adoption
/// or previous-root signature. It approves the complete frozen account and exact
/// successor. It also permits permanently closing this attempt without unfreezing
/// the account. Retain it before either trusted control-plane action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredAccountReplacementApproval {
    proposal: AnchorAccountReplacementProposal,
    scope: Scope,
}
impl AnchorTransferredAccountReplacementApproval {
    /// Bind the exact proposed transition to independently selected roots,
    /// genesis, credential, roster, policy and verified Witness history.
    pub fn from_trusted_state(
        proposal: AnchorAccountReplacementProposal,
        materials: &AnchorTransferredAccountReplacementMaterials<'_>,
        decision: [u8; 32],
        validity: Validity,
    ) -> Result<Self, DurableError> {
        let pin = materials.history.historical_pin(proposal.witness)?;
        proposal.check_target(
            materials.previous_root,
            materials.genesis,
            materials.device,
            materials.policy,
            pin,
        )?;
        if proposal.preparation.is_none() {
            return Err(Error::Scope.into());
        }
        let scope = Scope {
            namespace: materials.history.namespace_binding(),
            history: materials.history.checkpoint_at(proposal.witness)?,
            decision,
            validity,
        };
        scope.check(proposal.witness, materials.history)?;
        Ok(Self { proposal, scope })
    }
    /// Complete independently approved transition, not a committed decision.
    pub fn proposal(&self) -> &AnchorAccountReplacementProposal {
        &self.proposal
    }
    fn check(&self, authority: &impl ImageAuthority) -> Result<(), DurableError> {
        self.scope.check(self.proposal.witness, authority)?;
        closure::check_scope(&self.proposal, authority.resolve(self.proposal.witness)?)?;
        if self.proposal.preparation.is_none() {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
    fn check_materials(
        &self,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
    ) -> Result<(), DurableError> {
        self.proposal.check_target(
            m.previous_root,
            m.genesis,
            m.device,
            m.policy,
            m.history.historical_pin(self.proposal.witness)?,
        )
    }
    /// Verify only the exact historical decision. Neither retirement nor closure
    /// is a fresh operating reply, delivery confirmation or key-erasure proof.
    pub fn verify_decision(
        &self,
        history: &AnchorHandoffHistory,
        wire: &[u8],
    ) -> Result<AnchorTransferredAccountDecision, DurableError> {
        self.check(history)?;
        let record = Record::decode(wire, history)?;
        record.decision(self)
    }
}

/// Authenticated permanent result of the original independently approved attempt.
#[derive(Clone)]
pub struct AnchorTransferredAccountDecision {
    proposal: AnchorAccountReplacementProposal,
    state: AnchorAccountReplacementState,
    wire: Vec<u8>,
}
impl AnchorTransferredAccountDecision {
    /// Original signed bytes; recovery returns them without re-signing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// This verified type is always Committed or Closed, never Unavailable.
    pub fn state(&self) -> AnchorAccountReplacementState {
        self.state
    }
    /// Extract only a verified permanent account retirement observation.
    pub fn retirement(&self) -> Result<AnchorRetiredAccount, Error> {
        if self.state != AnchorAccountReplacementState::Committed {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredAccount {
            proposal: self.proposal.clone(),
        })
    }
    /// Extract only a verified permanent non-commit observation for this attempt.
    pub fn closure(&self) -> Result<AnchorClosedAccountReplacement, Error> {
        if self.state != AnchorAccountReplacementState::Closed {
            return Err(Error::Scope);
        }
        Ok(AnchorClosedAccountReplacement {
            proposal: self.proposal.clone(),
        })
    }
}
