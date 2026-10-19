// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Adopt a root-issued same-key validity extension before selecting any
    /// installation. Preserve original request/key/journal and retained history.
    /// Only positively tracked Unprepared records qualify. Older Accepted records
    /// need explicit history reconciliation; absence never proves first use.
    /// This is fresh admission, not retained-session G or a witness override.
    pub async fn adopt_credential_extension(
        &mut self,
        inputs: EnrollmentExtensionInputs<'_>,
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, DurableError> {
        let result = self.adopt_extension_attempt(inputs, pin, policy, now).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn adopt_extension_attempt(
        &mut self,
        inputs: EnrollmentExtensionInputs<'_>,
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, DurableError> {
        let mut image = self.image_without_policy_renewal()?;
        image.check_time_floor(now)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Accepted,
            request,
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        let p = image.preparation.as_ref().ok_or(DurableError::Suspended)?;
        if p.selected || image.renewal.is_some() {
            return Err(DurableError::Conflict);
        }
        for path in self.paths.installation.files() {
            if !self.storage.missing(path).await? {
                return Err(DurableError::Conflict);
            }
        }
        if [
            inputs.certificate,
            inputs.issued_roster,
            inputs.current_roster,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 8192)
        {
            return Err(DurableError::Capacity);
        }
        let a = inputs.approval;
        if a.predecessor.version().checked_add(1) != Some(inputs.issued_checkpoint.version()) {
            return Err(Error::Checkpoint.into());
        }
        let issuance = self.historical_device_metadata(
            inputs.certificate,
            inputs.issued_roster,
            inputs.issued_checkpoint,
        )?;
        let target = pin.verify_device(inputs.certificate, inputs.current_roster, now)?;
        let mut expected = self.intent.clone();
        expected.description.validity =
            Validity::new(expected.description.validity.from(), a.until)?;
        expected.verify_device(&target)?;
        let proof = authenticate_enrollment_proof(request, &self.intent)?;
        if proof.identity != image.identity
            || proof.public != target.key
            || issuance.credential_digest() != target.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        self.signer(image.identity, false)
            .await?
            .check_device(&target)?;
        admit(&target, policy, now)?;
        monotonic(target.roster().checkpoint(), inputs.issued_checkpoint)?;
        monotonic(target.roster().checkpoint(), admission.checkpoint)?;
        if let Some(e) = &p.extension {
            if e.approval.operation == a.operation {
                if e.approval != *a
                    || e.issued_checkpoint != inputs.issued_checkpoint
                    || e.target != target.credential_digest()
                    || p.policy != policy.checkpoint()
                {
                    return Err(DurableError::Conflict);
                }
                return Ok(admission.journal);
            }
        }
        if a.previous != p.extension.as_ref().map(|e| e.approval.operation) {
            return Err(DurableError::Conflict);
        }
        let previous = self
            .installation_intent(&image)?
            .description
            .validity
            .until();
        if a.until <= previous {
            return Err(Error::Validity.into());
        }
        monotonic(a.predecessor, admission.checkpoint)?;
        policy_monotonic(policy.checkpoint(), p.policy)?;
        let (origin, origin_policy) = p
            .extension
            .as_ref()
            .map_or((admission.clone(), p.policy), |e| {
                (e.origin.clone(), e.origin_policy)
            });
        let extension = Extension {
            approval: a.clone(),
            origin,
            origin_policy,
            previous_until: previous,
            previous_checkpoint: admission.checkpoint,
            previous_policy: p.policy,
            issued_checkpoint: inputs.issued_checkpoint,
            issued_roster: inputs.issued_roster.to_vec(),
            target: target.credential_digest(),
        };
        let journal = admission.journal;
        let Phase::Accepted { admission, .. } = &mut image.phase else {
            return Err(DurableError::Corrupt);
        };
        *admission = Admission {
            certificate: inputs.certificate.to_vec(),
            roster: inputs.current_roster.to_vec(),
            checkpoint: target.roster().checkpoint(),
            policy: policy.checkpoint().digest(),
            journal,
        };
        image.preparation = Some(Preparation {
            selected: false,
            policy: policy.checkpoint(),
            extension: Some(Box::new(extension)),
        });
        self.validate_preparation(&image)?;
        self.save(&image)?;
        admit(&target, policy, now)?;
        Ok(journal)
    }
}
