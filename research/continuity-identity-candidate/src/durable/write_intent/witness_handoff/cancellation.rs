// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local cancellation keeps the adopted selection without loading a signer.
use super::*;

impl WitnessJournalAdoption {
    pub(crate) fn credential_cancellation_intent(
        &self,
        original: &crate::VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        id: JournalIdentity,
    ) -> Result<Option<WitnessedCredentialIntent>, DurableError> {
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let fence = owner.read()?;
        if fence.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        owner.plan.check_original_enrollment(original, policy, id)?;
        let (image, pending) = owner.snapshot()?;
        credential_cancellation::check_scope(&image, original, policy, id)?;
        pending.map(|p| p.credential_intent(&image)).transpose()
    }

    pub(crate) fn reserve_credential_cancellation(
        &mut self,
        original: &crate::VerifiedDevice,
        policy: &crate::HistoricalSessionPolicy,
        id: JournalIdentity,
        target: CredentialCancellationTarget<'_>,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        let owner = self.active.take().ok_or(DurableError::Closed)?;
        if owner.read()?.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        let result = DeviceJournal::reserve_bound_cancellation_selected(
            &owner.db,
            &owner.key,
            original,
            policy,
            id,
            target,
            Some(&owner.plan),
        )?;
        owner.read()?;
        self.active = Some(owner);
        Ok(result)
    }
}
