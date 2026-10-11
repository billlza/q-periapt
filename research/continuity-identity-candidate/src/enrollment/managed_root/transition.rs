// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated non-commit and independently approved next-target coordination.
use super::*;
use crate::{AccountRootJournalTransition, AnchorClosedAccountPreparation, AnchorFrozenAccount};

/// Original signed non-commit plus an independently approved next plan and its
/// authenticated freeze. Retain both plans and receipts outside replaceable
/// journal backups, and reconstruct this same object after an uncertain result.
/// It authorizes no traffic and cannot cancel an already dispatched freeze.
#[derive(Clone)]
pub struct ManagedAccountRootTransition {
    closed: AnchorClosedAccountPreparation,
    next: Plan,
    frozen: AnchorFrozenAccount,
    journal: AccountRootJournalTransition,
}
impl ManagedAccountRootTransition {
    /// Authenticate both receipts with the independently retained witness. The
    /// host approves `next` separately; neither receipt may choose that target.
    pub fn verify(
        pin: &AnchorPin,
        original: &Plan,
        next: Plan,
        noncommit_receipt: &[u8],
        freeze_receipt: &[u8],
    ) -> Result<Self, Error> {
        let closed = pin.verify_closed_account_preparation(original, noncommit_receipt)?;
        let frozen = pin.verify_account_freeze(next.request(), freeze_receipt)?;
        let journal = AccountRootJournalTransition::from_closed_preparation(
            closed.clone(),
            next.bind(&frozen)?,
        )?;
        Ok(Self {
            closed,
            next,
            frozen,
            journal,
        })
    }
}
impl Owners {
    fn check_transition(
        &self,
        transition: &ManagedAccountRootTransition,
    ) -> Result<(), DurableError> {
        let original = transition.closed.plan();
        let (application, state, retained) = self.registry.preparation(original.operation())?;
        if retained != original
            || application != self.expected.application()
            || self.registry.operation_checkpoint(original.operation())? != self.expected
            || (!self.operation.matches_plan(original)
                && !self.operation.matches_plan(&transition.next))
            || state == State::Committed
            || self.pin.binding() != transition.next.target().witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        match self.registry.preparation(transition.next.operation()) {
            Ok((application, state, retained)) => {
                if application != self.expected.application() || retained != &transition.next {
                    return Err(DurableError::Conflict);
                }
                if state == State::Closed {
                    return Err(Error::Retired.into());
                }
            }
            Err(DurableError::Absent) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
    fn apply_transition(
        &mut self,
        transition: &ManagedAccountRootTransition,
    ) -> Result<Proposal, DurableError> {
        self.validate_parent_transition(&transition.journal)?;
        self.registry.close_preparation(&transition.closed)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("noncommit");
        self.registry
            .begin_preparation(self.expected, transition.next.clone())?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("next-preparation");
        self.registry
            .bind_preparation(transition.next.operation(), &transition.frozen)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("next-binding");
        self.advance_parent(&transition.journal)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("next-parent");
        self.operation = Operation::Prepared(Box::new(transition.next.clone()));
        Ok(transition.journal.next_proposal().clone())
    }
}
impl ManagedAccountRootReplacement {
    /// Retain signed permanent non-commit of the current plan, including before
    /// a freeze has returned. The original account stays suspended. This is a
    /// terminal observation, not unfreezing or permission to select another root.
    pub fn retain_witness_noncommit(&mut self, receipt: &[u8]) -> Result<State, DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        let closed = owners
            .pin
            .verify_closed_account_preparation(owners.operation.plan()?, receipt)?;
        if owners.state()? == State::Committed {
            return Err(DurableError::Conflict);
        }
        self.run(|owners| {
            let state = owners.registry.close_preparation(&closed)?;
            #[cfg(all(test, unix))]
            account_root::managed_boundary("noncommit");
            Ok(state)
        })
    }
    /// Close the original plan, retain/bind the separately approved next plan,
    /// then reconcile the original parent and child. Each commit can precede an
    /// error. Retry only this same transition through `resume_transition`.
    pub fn transition_after_noncommit(
        &mut self,
        transition: &ManagedAccountRootTransition,
    ) -> Result<Proposal, DurableError> {
        self.active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .check_transition(transition)?;
        self.run(|owners| owners.apply_transition(transition))
    }
    /// Reconcile the same approved transition across any of its registry, parent
    /// or child commits. The original parent may be unfenced, retain the previous
    /// proposal, or already retain this exact next proposal. Missing or conflicting
    /// state is refused; no database, identity, key or operation is regenerated.
    pub fn resume_transition(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        transition: &ManagedAccountRootTransition,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            original: None,
            registry,
            expected,
            operation: Operation::Prepared(Box::new(transition.closed.plan().clone())),
            paths,
            intent,
            pin,
        };
        Self::check_inputs(&owners)?;
        owners.check_transition(transition)?;
        owners.apply_transition(transition)?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
