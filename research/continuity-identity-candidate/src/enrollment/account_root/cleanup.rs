// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transfer the original parent lease into historical accounting after root retirement.
use super::*;
use crate::{AnchorRetiredCleanupProposal, AnchorRetiredSubject, RetiredDeviceEnrollment};

impl State {
    pub(in crate::enrollment) fn check_retirement_inventory(
        &self,
        inventory: &AnchorRetiredCleanupProposal,
        transferred: bool,
    ) -> Result<(), DurableError> {
        if self.receipt.is_none()
            || self.authority.is_some() != transferred
            || (transferred && self.child.is_none())
        {
            return Err(DurableError::Suspended);
        }
        inventory.check_account_proposal(&self.proposal)?;
        Ok(())
    }
    pub(in crate::enrollment) fn check_retirement_context(
        &self,
        context: &crate::TransferredRetirementContext,
    ) -> Result<(), DurableError> {
        let plan = context.plan();
        if self.authority.as_ref() != Some(&plan.binding()?)
            || self.proposal != *plan.proposal()
            || &self.attempts != plan.attempts()
            || self.receipt.as_deref() != Some(context.decision())
            || self.child.is_none()
            || *self.journal.as_bytes() != context.retired_subject().subject().journal_parts().0
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn check_retirement_observation(
        &self,
        observation: &crate::retired_device::transferred::RetirementObservation,
    ) -> Result<(), DurableError> {
        self.check_retirement_inventory(&observation.inventory, true)?;
        if self.child != Some(observation.parent_fence) {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn retirement_subject(
        &self,
        pin: &AnchorPin,
        subject: crate::AnchorSubject,
    ) -> Result<AnchorRetiredSubject, DurableError> {
        if self.authority.is_some() {
            return Err(DurableError::Suspended);
        }
        let receipt = self.receipt.as_deref().ok_or(DurableError::Suspended)?;
        let retired = pin.verify_retired_account(&self.proposal, receipt)?;
        if subject.journal_parts().0 != *self.journal.as_bytes() {
            return Err(DurableError::Conflict);
        }
        Ok(retired.retired_subject(subject)?)
    }
}

impl DeviceEnrollment {
    pub(in crate::enrollment) fn retained_transferred_cleanup(
        &self,
        plan: crate::TransferredAccountRootJournalPlan,
        decision: &[u8],
        history: crate::AnchorHandoffHistory,
    ) -> Result<Option<crate::TransferredRetirementContext>, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, self.binding)?;
        if snapshot.retirement.is_none() {
            return Ok(None);
        }
        let root = snapshot
            .root_replacement
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let original = validate(self, &snapshot.image, plan.witness_pin()?, plan.proposal())?;
        let Phase::Accepted { admission, .. } = &snapshot.image.phase else {
            return Err(DurableError::Conflict);
        };
        let scope = (
            *admission.journal.as_bytes(),
            crate::bootstrap::storage_owner(&original),
            admission.policy,
        );
        let subject = plan
            .proposal()
            .predecessors()
            .find(|s| s.journal_parts() == scope)
            .ok_or(DurableError::Conflict)?;
        let context = crate::TransferredRetirementContext::new(plan, decision, subject, history)?;
        root.check_retirement_context(&context)?;
        Ok(Some(context))
    }
    /// A retained combined parent, never absence inferred from a failed read.
    pub(in crate::enrollment) fn retained_root_cleanup(
        &self,
        pin: &AnchorPin,
        expected: &Proposal,
    ) -> Result<Option<AnchorRetiredSubject>, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, self.binding)?;
        if snapshot.retirement.is_none() {
            return Ok(None);
        }
        let root = snapshot.root_replacement.ok_or(DurableError::Conflict)?;
        if &root.proposal != expected {
            return Err(DurableError::Conflict);
        }
        let original = validate(self, &snapshot.image, pin, expected)?;
        let Phase::Accepted { admission, .. } = snapshot.image.phase else {
            return Err(DurableError::Conflict);
        };
        let scope = (
            *admission.journal.as_bytes(),
            crate::bootstrap::storage_owner(&original),
            admission.policy,
        );
        let subject = expected
            .predecessors()
            .find(|s| s.journal_parts() == scope)
            .ok_or(DurableError::Conflict)?;
        Ok(Some(root.retirement_subject(pin, subject)?))
    }
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AccountRootEnrollmentRecovery {
    /// Consume the original fenced owner into inventory/report/host-ACK recovery.
    /// A retained purpose-22 commitment is required. The original enrollment lease
    /// is transferred without reopening; no successor, signer or traffic is returned.
    /// After this transition, resume with `RetiredDeviceEnrollment::open` for
    /// legacy retirement, or `open_transferred` with the complete independently
    /// retained transferred context, even after journal erasure.
    pub async fn into_retired(self) -> Result<RetiredDeviceEnrollment, DurableError> {
        self.into_retired_history(None).await
    }
    /// Consume the same transferred parent using independently verified later
    /// accounting history. The original root plan and exact decision remain fixed;
    /// historical cleanup grants no renewed operating or signing authority.
    pub async fn into_retired_with_accounting_history(
        self,
        history: crate::AnchorHandoffHistory,
    ) -> Result<RetiredDeviceEnrollment, DurableError> {
        self.into_retired_history(Some(history)).await
    }
    async fn into_retired_history(
        mut self,
        history: Option<crate::AnchorHandoffHistory>,
    ) -> Result<RetiredDeviceEnrollment, DurableError> {
        let mut owners = self.active.take().ok_or(DurableError::Closed)?;
        let original = owners.read()?;
        let active = owners
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, owners.enrollment.binding)?;
        let Phase::Accepted { admission, .. } = snapshot.image.phase else {
            return Err(DurableError::Conflict);
        };
        let scope = (
            *admission.journal.as_bytes(),
            crate::bootstrap::storage_owner(&original),
            admission.policy,
        );
        let subject = owners
            .state
            .proposal
            .predecessors()
            .find(|subject| subject.journal_parts() == scope)
            .ok_or(DurableError::Conflict)?;
        if history.is_some() && owners.transferred.is_none() {
            return Err(DurableError::Conflict);
        }
        let context = owners
            .transferred
            .as_ref()
            .map(|plan| {
                crate::TransferredRetirementContext::new(
                    (**plan).clone(),
                    owners
                        .state
                        .receipt
                        .as_deref()
                        .ok_or(DurableError::Suspended)?,
                    subject,
                    history.clone().unwrap_or_else(|| plan.history().clone()),
                )
            })
            .transpose()?;
        let retired = if let Some(context) = &context {
            context.retired_subject()
        } else {
            owners.state.retirement_subject(&owners.pin, subject)?
        };
        // Release only the restricted child. Keep its independent parent leased
        // while the existing cleanup flow commits its original inventory.
        owners.journal = None;
        if let Some(context) = context {
            RetiredDeviceEnrollment::from_transferred_enrollment(owners.enrollment, context).await
        } else {
            RetiredDeviceEnrollment::from_enrollment(owners.enrollment, owners.pin, retired).await
        }
    }
}

#[cfg(all(test, unix))]
pub(in crate::enrollment) fn at_boundary(after: bool) {
    super::tests::at_boundary("cleanup-parent", after);
}
