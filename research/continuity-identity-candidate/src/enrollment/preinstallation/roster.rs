// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    pub(in crate::enrollment) async fn refresh_unprepared_roster(
        &mut self,
        mut image: Image,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrollmentStatus, DurableError> {
        let preparation = image.preparation.as_ref().ok_or(DurableError::Suspended)?;
        if preparation.selected || preparation.policy != policy.checkpoint() {
            return Err(DurableError::Conflict);
        }
        for path in self.paths.installation.files() {
            if !self.storage.missing(path).await? {
                return Err(DurableError::Conflict);
            }
        }
        if roster.is_empty() || roster.len() > 8192 {
            return Err(DurableError::Capacity);
        }
        let Phase::Accepted {
            admission,
            request,
            stage: AdmissionPhase::Accepted,
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        let target = pin.verify_device(&admission.certificate, roster, now)?;
        self.installation_intent(&image)?.verify_device(&target)?;
        let proof = authenticate_enrollment_proof(request, &self.intent)?;
        if proof.identity != image.identity
            || proof.public != target.key
            || admission.policy != policy.checkpoint().digest()
        {
            return Err(DurableError::Conflict);
        }
        self.signer(image.identity, false)
            .await?
            .check_device(&target)?;
        admit(&target, policy, now)?;
        let next = target.roster().checkpoint();
        if next.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        let journal = admission.journal;
        if admission.checkpoint == next {
            return Ok(EnrollmentStatus::Accepted(journal));
        }
        if admission.checkpoint != previous {
            return Err(DurableError::Conflict);
        }
        let Phase::Accepted { admission, .. } = &mut image.phase else {
            return Err(DurableError::Corrupt);
        };
        admission.roster = roster.to_vec();
        admission.checkpoint = next;
        self.validate_preparation(&image)?;
        self.save(&image)?;
        admit(&target, policy, now)?;
        Ok(EnrollmentStatus::Accepted(journal))
    }
}
