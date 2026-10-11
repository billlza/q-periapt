// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transfer the original parent lease into historical accounting after root retirement.
use super::*;
use crate::{AnchorRetiredCleanupProposal, AnchorRetiredSubject, RetiredDeviceEnrollment};

impl State {
    pub(in crate::enrollment) fn check_retirement_inventory(
        &self,
        inventory: &AnchorRetiredCleanupProposal,
    ) -> Result<(), DurableError> {
        if self.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        inventory.check_account_proposal(&self.proposal)?;
        Ok(())
    }
    pub(in crate::enrollment) fn retirement_subject(
        &self,
        pin: &AnchorPin,
        subject: crate::AnchorSubject,
    ) -> Result<AnchorRetiredSubject, DurableError> {
        let receipt = self.receipt.as_deref().ok_or(DurableError::Suspended)?;
        let retired = pin.verify_retired_account(&self.proposal, receipt)?;
        if subject.journal_parts().0 != *self.journal.as_bytes() {
            return Err(DurableError::Conflict);
        }
        Ok(retired.retired_subject(subject)?)
    }
}

impl DeviceEnrollment {
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

impl AccountRootEnrollmentRecovery {
    /// Consume the original fenced owner into inventory/report/host-ACK recovery.
    /// A retained purpose-22 commitment is required. The original enrollment lease
    /// is transferred without reopening; no successor, signer or traffic is returned.
    /// After this transition, resume with `RetiredDeviceEnrollment::open` and the
    /// same verified account retirement's `retired_subject`, even after journal erasure.
    pub fn into_retired(mut self) -> Result<RetiredDeviceEnrollment, DurableError> {
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
        let retired = owners.state.retirement_subject(&owners.pin, subject)?;
        // Release only the restricted child. Keep its independent parent leased
        // while the existing cleanup flow commits its original inventory.
        owners.journal = None;
        RetiredDeviceEnrollment::from_enrollment(owners.enrollment, owners.pin, retired)
    }
}

#[cfg(all(test, unix))]
pub(in crate::enrollment) fn at_boundary(after: bool) {
    super::tests::at_boundary("cleanup-parent", after);
}
