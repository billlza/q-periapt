// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A retained target approval whose old-account snapshot is selected only by an exact freeze.
use super::*;

/// Independently approved original freeze and successor target, before freezing.
/// This authorizes binding the then-current snapshot returned for that exact freeze
/// request. It is deliberately distinct from an exact snapshot replacement proposal.
/// Retain it in the original application registry before contacting the witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorAccountReplacementPlan {
    request: AnchorAccountFreezeRequest,
    target: AnchorAccountReplacementProposal,
}
impl AnchorAccountReplacementPlan {
    pub(crate) const MAX_BYTES: usize = 8192;
    /// Exact independently approved witness-freeze request.
    pub fn request(&self) -> &AnchorAccountFreezeRequest {
        &self.request
    }
    /// Original target replacement operation, distinct from the freeze operation.
    pub fn operation(&self) -> AnchorAccountReplacementId {
        self.target.operation()
    }
    pub(crate) fn target(&self) -> &AnchorAccountReplacementProposal {
        &self.target
    }
    fn check(&self) -> Result<(), Error> {
        self.target.check_shape()?;
        if self.target.witness != self.request.witness
            || self.target.previous_root != self.request.root
            || !self.target.frozen.is_empty()
            || self.target.preparation.is_some()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    /// Stable commitment to the complete independently retained original plan.
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-ACCOUNT-PREPARATION/v1",
            &self.to_bytes()?,
        ))
    }
    pub(in crate::anchor::store::account_replacement) fn matches_closed_target(
        p: &AnchorAccountReplacementProposal,
        freeze: [u8; 32],
        binding: [u8; 32],
    ) -> Result<bool, Error> {
        let request = AnchorAccountFreezeRequest {
            witness: p.witness,
            operation: AnchorAccountFreezeId::from_trusted_state(freeze)?,
            root: p.previous_root.clone(),
        };
        let mut target = p.clone();
        target.frozen.clear();
        target.preparation = None;
        Ok(Self { request, target }.binding()? == binding)
    }
    /// Canonical original approval. Serialization grants no control-plane authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut bytes = b"QPAFPL01".to_vec();
        bytes.extend_from_slice(&self.request.to_bytes());
        let target = self.target.to_bytes()?;
        bytes.extend_from_slice(
            &u32::try_from(target.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&target);
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::Capacity);
        }
        Ok(bytes)
    }
    /// Parse only an independently retained original plan; network bytes cannot approve it.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAFPL01" {
            return Err(Error::Encoding);
        }
        let request = AnchorAccountFreezeRequest::from_bytes(d.take(codec::REQUEST_BYTES)?)?;
        let size = usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| Error::Capacity)?;
        if size > Self::MAX_BYTES {
            return Err(Error::Capacity);
        }
        let target = AnchorAccountReplacementProposal::from_trusted_state(d.take(size)?)?;
        d.finish()?;
        let result = Self { request, target };
        result.check()?;
        Ok(result)
    }
    pub(crate) fn bind(
        &self,
        frozen: &AnchorFrozenAccount,
    ) -> Result<AnchorAccountReplacementProposal, Error> {
        self.check()?;
        if frozen.request != self.request {
            return Err(Error::Scope);
        }
        let mut p = self.target.clone();
        p.frozen = frozen.subjects.clone();
        p.preparation = Some(frozen.binding()?);
        p.check_shape()?;
        Ok(p)
    }
    /// Validate an already MAC-authenticated local record, without manufacturing a
    /// transferable witness proof. A fresh bind requires the verified freeze type.
    pub(crate) fn check_retained(
        &self,
        proposal: &AnchorAccountReplacementProposal,
    ) -> Result<bool, Error> {
        self.check()?;
        if proposal == &self.target {
            return Ok(false);
        }
        let expected = self.bind(&AnchorFrozenAccount {
            request: self.request.clone(),
            subjects: proposal.frozen.clone(),
        })?;
        if proposal != &expected {
            return Err(Error::Scope);
        }
        Ok(true)
    }
}
impl AnchorStore {
    /// Prepare a fresh independently approved target against an existing exact
    /// freeze. Local controllers must first terminally close any earlier attempt.
    pub fn frozen_account_replacement_plan(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorAccountReplacementPlan, DurableError> {
        let mut target = self
            .frozen_account_replacement_proposal(operation, frozen, genesis, next, policy, now)?;
        target.frozen.clear();
        target.preparation = None;
        let result = AnchorAccountReplacementPlan {
            request: frozen.request.clone(),
            target,
        };
        result.check()?;
        Ok(result)
    }

    /// Prepare independently approved freeze and exact target inputs before any
    /// witness mutation. The target is fixed; the future snapshot is authenticated
    /// by the exact freeze request. This read-only plan grants no traffic authority.
    pub fn account_replacement_plan(
        &mut self,
        operation: AnchorAccountReplacementId,
        request: AnchorAccountFreezeRequest,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorAccountReplacementPlan, DurableError> {
        request.check_pin(&self.pin()?)?;
        let mut target = self.account_root_replacement_proposal(
            operation,
            &request.root,
            genesis,
            next,
            policy,
            now,
        )?;
        // This new plan type approves the target and exact future freeze, not this
        // transient read-only snapshot. Never reinterpret a retained exact proposal.
        target.frozen.clear();
        let result = AnchorAccountReplacementPlan { request, target };
        result.check()?;
        Ok(result)
    }
}
