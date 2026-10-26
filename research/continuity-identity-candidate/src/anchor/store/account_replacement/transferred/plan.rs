// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retain the independently approved target before the transferred account freeze.
use super::*;
mod target;
use target::PreparedTarget;

/// Independently retained target under a verified successor Witness. A future
/// freeze plan binds its exact original request; an already frozen plan also
/// binds the original signed snapshot digest, even under a later Witness.
/// The full account-root replacement still needs its own operator approval.
/// Persist the target in the original host registry before proceeding. It is
/// neither a legacy preparation nor permission to operate either account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorTransferredAccountReplacementPlan {
    target: PreparedTarget,
    namespace: [u8; 32],
    history: [u8; 32],
}
impl AnchorTransferredAccountReplacementPlan {
    pub(crate) const MAX_BYTES: usize = 8 + 64 + PreparedTarget::MAX_BYTES;

    pub(crate) fn check(&self, history: &AnchorHandoffHistory) -> Result<(), DurableError> {
        let witness = self.target().witness_binding();
        if self.namespace != history.namespace_binding()
            || self.namespace == witness
            || self.history != history.checkpoint_at(witness)?
        {
            return Err(Error::Scope.into());
        }
        self.target.check(history)?;
        closure::check_scope(self.target(), history.historical_pin(witness)?)?;
        Ok(())
    }
    pub(crate) fn target(&self) -> &AnchorAccountReplacementProposal {
        self.target.proposal()
    }
    /// Original operation identity, unchanged when the freeze becomes committed.
    pub fn operation(&self) -> AnchorAccountReplacementId {
        self.target().operation()
    }
    /// Independently retained request; incoming freeze bytes cannot select it.
    pub fn request(&self) -> &AnchorAccountFreezeRequest {
        self.target.request()
    }
    /// Match the original target and exact historical context to independent
    /// enrollment and policy inputs. Expiry does not erase a historical plan.
    pub fn verify_target(
        &self,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
    ) -> Result<(), DurableError> {
        self.check(m.history)?;
        self.target().check_target(
            m.previous_root,
            m.genesis,
            m.device,
            m.policy,
            m.history.historical_pin(self.target().witness_binding())?,
        )
    }
    /// Bind only the original signed, complete transferred freeze. The returned
    /// proposal preserves every target input and operation ID; it is not itself
    /// the independently authenticated approval required to retire the account.
    pub fn bind(
        &self,
        frozen: &AnchorFrozenAccount,
        history: &AnchorHandoffHistory,
    ) -> Result<AnchorAccountReplacementProposal, DurableError> {
        self.check(history)?;
        self.target.bind(frozen, history)
    }
    /// Canonical host-retained public intent; serialization grants no authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.target.tag().to_vec();
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.history);
        self.target.encode(&mut out)?;
        if out.len() > Self::MAX_BYTES {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
    /// Restore the original host record against independently retained target
    /// materials and verified history. Never use a network-selected record as
    /// account recovery approval. An extended history preserves the exact prefix.
    pub fn restore_trusted_state(
        bytes: &[u8],
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
    ) -> Result<Self, DurableError> {
        let restored = Self::restore_authenticated_record(bytes, m.history)?;
        restored.verify_target(m)?;
        Ok(restored)
    }
    // Only for a complete MAC-authenticated host registry, never a network grant.
    pub(crate) fn restore_authenticated_record(
        bytes: &[u8],
        history: &AnchorHandoffHistory,
    ) -> Result<Self, DurableError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::Capacity.into());
        }
        let mut d = Decoder::new(bytes);
        let tag = d.array::<8>()?;
        let namespace = d.array()?;
        let checkpoint = d.array()?;
        let target = PreparedTarget::decode(tag, d.take(d.remaining())?)?;
        d.finish()?;
        let restored = Self {
            target,
            namespace,
            history: checkpoint,
        };
        restored.check(history)?;
        Ok(restored)
    }
    /// Commitment to the complete retained target, freeze request and history.
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-TRANSFERRED-ACCOUNT-PREPARATION/v1",
            &self.to_bytes()?,
        ))
    }
}

impl AnchorStore {
    /// Read-only preparation before a whole-account freeze under the current
    /// Witness. The host independently authenticates the target approval and
    /// persists it before freezing. No account, pending command or ID is changed.
    /// Fresh enrollment admission is checked here and again at actual commitment.
    pub fn transferred_account_replacement_plan(
        &mut self,
        operation: AnchorAccountReplacementId,
        request: AnchorAccountFreezeRequest,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
        now: u64,
    ) -> Result<AnchorTransferredAccountReplacementPlan, DurableError> {
        let current = self.pin()?;
        let history = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .history();
        if history.checkpoint() != m.history.checkpoint()
            || history.namespace_binding() != m.history.namespace_binding()
        {
            return Err(Error::Scope.into());
        }
        let validity = self.admit_enrollment(m.genesis.subject, m.device, m.policy, now)?;
        let image = self.image()?;
        image.require_account_live(crate::identity::account_id(m.previous_root))?;
        let mut target = Target {
            genesis: m.genesis,
            device: m.device,
            policy: m.policy,
            pin: &current,
        }
        .proposal(
            operation,
            (m.previous_root, None),
            validity,
            image.account_snapshot_at(
                crate::identity::account_id(m.previous_root),
                current.binding(),
                m.history,
            )?,
        )?;
        image.check_new_account_replacement_at(&target, m.history)?;
        target.frozen.clear();
        let plan = AnchorTransferredAccountReplacementPlan {
            target: PreparedTarget::Future(Box::new(AnchorAccountReplacementPlan::from_target(
                request, target,
            )?)),
            namespace: m.history.namespace_binding(),
            history: m.history.checkpoint(),
        };
        plan.verify_target(m)?;
        Ok(plan)
    }

    /// Prepare a separately approved next target against the exact already signed
    /// whole-account freeze. Closing an earlier attempt never unfreezes the account.
    /// The compact plan retains that freeze commitment and original request even
    /// when a later current Witness will decide the new attempt. It is read-only:
    /// the host must retain the earlier signed non-commit and separately approve
    /// this target in its original registry before binding and committing it.
    pub fn frozen_transferred_account_replacement_plan(
        &mut self,
        operation: AnchorAccountReplacementId,
        frozen: &AnchorFrozenAccount,
        m: &AnchorTransferredAccountReplacementMaterials<'_>,
        now: u64,
    ) -> Result<AnchorTransferredAccountReplacementPlan, DurableError> {
        let proposal = self.transferred_account_replacement_proposal(operation, frozen, m, now)?;
        let plan = AnchorTransferredAccountReplacementPlan {
            target: PreparedTarget::frozen(frozen, proposal.clone())?,
            namespace: m.history.namespace_binding(),
            history: m.history.checkpoint(),
        };
        plan.verify_target(m)?;
        if plan.bind(frozen, m.history)? != proposal {
            return Err(DurableError::Conflict);
        }
        Ok(plan)
    }
}
