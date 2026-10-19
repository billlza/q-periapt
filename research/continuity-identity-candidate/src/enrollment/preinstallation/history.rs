// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl DeviceEnrollment {
    /// Read whether first-installation selection was durably recorded. Untracked
    /// is not equivalent to Unprepared; missing old files cannot fill that gap.
    pub fn preparation_status(&mut self) -> Result<EnrollmentPreparationStatus, DurableError> {
        let image = self.image()?;
        let Phase::Accepted { stage, .. } = image.phase else {
            return Ok(EnrollmentPreparationStatus::NotAccepted);
        };
        Ok(
            if stage != AdmissionPhase::Accepted
                || image.preparation.as_ref().is_some_and(|p| p.selected)
            {
                EnrollmentPreparationStatus::Selected
            } else if image.preparation.is_some() {
                EnrollmentPreparationStatus::Unprepared
            } else {
                EnrollmentPreparationStatus::Untracked
            },
        )
    }
    /// Last retained result; this does not reopen traffic or extend its validity.
    pub fn credential_extension_status(
        &mut self,
    ) -> Result<Option<EnrollmentExtensionStatus>, DurableError> {
        let image = self.image()?;
        Ok(image.preparation.as_ref().and_then(|p| {
            p.extension.as_ref().map(|e| EnrollmentExtensionStatus {
                approval: e.approval.clone(),
                journal: e.origin.journal,
                issued_checkpoint: e.issued_checkpoint,
                policy: p.policy,
            })
        }))
    }
    pub(in crate::enrollment) fn installation_intent(
        &self,
        image: &Image,
    ) -> Result<EnrollmentIntent, DurableError> {
        let mut intent = self.intent.clone();
        if let Some(e) = image
            .preparation
            .as_ref()
            .and_then(|p| p.extension.as_ref())
        {
            intent.description.validity =
                Validity::new(intent.description.validity.from(), e.approval.until)?;
        }
        Ok(intent)
    }
    pub(in crate::enrollment) fn validate_preparation(
        &self,
        image: &Image,
    ) -> Result<(), DurableError> {
        let Some(p) = &image.preparation else {
            return Ok(());
        };
        let Phase::Accepted {
            request,
            admission,
            stage,
        } = &image.phase
        else {
            return Err(DurableError::Corrupt);
        };
        if (!p.selected && *stage != AdmissionPhase::Accepted)
            || p.policy.digest() != admission.policy
        {
            return Err(DurableError::Corrupt);
        }
        let Some(e) = &p.extension else {
            return Ok(());
        };
        let origin = self.historical_device_metadata(
            &e.origin.certificate,
            &e.origin.roster,
            e.origin.checkpoint,
        )?;
        self.intent.verify_device(&origin)?;
        let proof = authenticate_enrollment_proof(request, &self.intent)?;
        if proof.identity != image.identity
            || proof.public != origin.key
            || e.origin.journal != admission.journal
            || e.origin.policy != e.origin_policy.digest()
            || e.previous_until < self.intent.description.validity.until()
            || e.previous_until >= e.approval.until
            || e.approval.previous.is_none()
                != (e.previous_until == self.intent.description.validity.until())
        {
            return Err(DurableError::Conflict);
        }
        let (certificate, roster, head) = image.renewal.as_ref().map_or(
            (
                admission.certificate.as_slice(),
                admission.roster.as_slice(),
                admission.checkpoint,
            ),
            LocalRenewal::installation_origin,
        );
        let initial = self.historical_device_metadata(certificate, roster, head)?;
        self.installation_intent(image)?.verify_device(&initial)?;
        let issuance =
            self.historical_device_metadata(certificate, &e.issued_roster, e.issued_checkpoint)?;
        if initial.key != origin.key
            || initial.credential_digest() != e.target
            || issuance.credential_digest() != e.target
            || e.approval.predecessor.version().checked_add(1)
                != Some(e.issued_checkpoint.version())
        {
            return Err(DurableError::Conflict);
        }
        monotonic(e.previous_checkpoint, e.origin.checkpoint)?;
        monotonic(e.approval.predecessor, e.previous_checkpoint)?;
        monotonic(head, e.issued_checkpoint)?;
        policy_monotonic(e.previous_policy, e.origin_policy)?;
        policy_monotonic(p.policy, e.previous_policy)
    }
    pub(in crate::enrollment) fn select_installation(
        &mut self,
        image: &mut Image,
    ) -> Result<(), DurableError> {
        if let Some(p) = &mut image.preparation {
            if !p.selected {
                p.selected = true;
                self.save(image)?;
            }
        }
        Ok(())
    }
}
