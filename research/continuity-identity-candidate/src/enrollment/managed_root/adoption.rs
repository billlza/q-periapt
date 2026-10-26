// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Adopt an independently approved committed winner without inventing a plan.
use super::*;
use crate::{AccountRootJournalTransition, AnchorClosedAccountPreparation, AnchorRetiredAccount};

/// Original non-commit and the exact independently approved committed winner.
/// Retain both expectations and signed receipts for original-operation recovery.
/// This historical proof is not current successor credential or traffic authority.
#[derive(Clone)]
pub struct ManagedAccountRootAdoption {
    closed: AnchorClosedAccountPreparation,
    retired: AnchorRetiredAccount,
    journal: AccountRootJournalTransition,
    receipt: Vec<u8>,
}
impl ManagedAccountRootAdoption {
    /// Authenticate original non-commit and the approved exact winner under the
    /// independently retained witness. Incoming receipt bytes cannot choose it.
    pub fn verify(
        pin: &AnchorPin,
        original: &Plan,
        approved: Proposal,
        noncommit_receipt: &[u8],
        retirement_receipt: &[u8],
    ) -> Result<Self, Error> {
        let closed = pin.verify_closed_account_preparation(original, noncommit_receipt)?;
        let retired = pin.verify_retired_account(&approved, retirement_receipt)?;
        let journal =
            AccountRootJournalTransition::from_closed_preparation(closed.clone(), approved)?;
        Ok(Self {
            closed,
            retired,
            journal,
            receipt: retirement_receipt.to_vec(),
        })
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    fn check_adoption(&self, adoption: &ManagedAccountRootAdoption) -> Result<(), DurableError> {
        let original = adoption.closed.plan();
        let approved = adoption.retired.proposal();
        let (application, state, retained) = self.registry.preparation(original.operation())?;
        let same_operation = self.operation.matches_plan(original)
            || matches!(&self.operation, Operation::Adopted(proposal) if proposal.as_ref() == approved);
        if retained != original
            || application != self.expected.application()
            || self.registry.operation_checkpoint(original.operation())? != self.expected
            || !same_operation
            || state == State::Committed
            || self.pin.binding() != approved.witness_binding()
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    async fn apply_adoption(
        &mut self,
        adoption: &ManagedAccountRootAdoption,
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        self.validate_parent_transition(&adoption.journal).await?;
        self.registry.close_preparation(&adoption.closed)?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("adoption-closure");
        let approved = adoption.retired.proposal();
        // Check the same prospective registry image used by the actual commit,
        // including cross-application root reuse, before changing the parent.
        self.registry
            .validate_committed_adoption(self.expected, approved, &adoption.retired)?;
        self.advance_parent(&adoption.journal).await?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("adoption-parent");
        self.retain_parent_retirement(approved, &adoption.receipt)
            .await?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("adoption-retirement");
        self.registry.adopt_committed_replacement(
            self.expected,
            approved.clone(),
            &adoption.retired,
        )?;
        #[cfg(all(test, unix))]
        account_root::managed_boundary("adoption-registry");
        self.operation = Operation::Adopted(Box::new(approved.clone()));
        Ok(self.successor().await?.0)
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl ManagedAccountRootReplacement {
    /// Retain original non-commit, reconcile the exact approved winner into the
    /// original parent/journal, retain its retirement, then select it locally.
    /// Errors consume the controller and may follow any of these ordered commits.
    pub async fn adopt_committed_winner(
        &mut self,
        adoption: &ManagedAccountRootAdoption,
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        self.active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .check_adoption(adoption)?;
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        let result = owners.apply_adoption(adoption).await?;
        self.active = Some(owners);
        Ok(result)
    }
    /// Reconcile this same independently approved adoption after an unknown
    /// result. The registry need not have a local plan for the winner. Original
    /// parent/journal state is required; absence never creates replacement state.
    pub async fn resume_adoption(
        registry: AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        adoption: &ManagedAccountRootAdoption,
    ) -> Result<Self, DurableError> {
        let mut owners = Owners {
            original: None,
            registry,
            expected,
            operation: Operation::Prepared(Box::new(adoption.closed.plan().clone())),
            paths,
            intent,
            pin,
            cleanup_history: None,
        };
        Self::check_inputs(&owners)?;
        owners.check_adoption(adoption)?;
        owners.apply_adoption(adoption).await?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
}
