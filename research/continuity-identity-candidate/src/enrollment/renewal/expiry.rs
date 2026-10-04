// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit reconciliation of an expired original intent without new authority.
use super::*;

impl DeviceEnrollment {
    /// Resolve an exact pending renewal whose target expired before recovery.
    /// A journal-committed target is reported as Committed, even after revocation;
    /// only unchanged same-generation credential history permits ExpiredUncommitted.
    /// This never returns a service or implicitly stages another operation.
    ///
    /// The last abandonment remains queryable through exact retries until another
    /// abandonment or a later renewal completes; its time floor remains thereafter.
    /// Persist caller-known outcomes if a longer history is needed. An old/foreign request that is no
    /// longer retained is rejected, never inferred to have been uncommitted.
    pub fn reconcile_expired_credential_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result = self.reconcile_expired(operation, statement, policy, now);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn reconcile_expired(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let mut image = self.image()?;
        let original = self.original_device(&image, now)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        if admission.policy != policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let journal_id = admission.journal;
        let renewal = image.renewal.as_ref().ok_or(Error::State)?;
        if let Some(expired) = &renewal.expired {
            if expired.operation == operation && expired.statement == statement {
                return Ok(expired.status());
            }
        }
        if let Some(completed) = &renewal.completed {
            if completed.operation == operation && completed.statement == statement {
                return Ok(CredentialRenewalStatus::Committed {
                    operation,
                    statement,
                    target: completed.target,
                });
            }
        }
        let pending = renewal.pending.as_ref().ok_or(DurableError::Conflict)?;
        if pending.operation != operation || pending.statement != statement {
            return Err(DurableError::Conflict);
        }
        let grant = VerifiedCredentialRenewal::from_journal(&pending.wire, original.roster())?;
        if grant.operation() != operation
            || grant.statement_digest() != statement
            || grant.original_storage_owner() != crate::bootstrap::storage_owner(&original)
            || grant.policy_digest() != admission.policy
        {
            return Err(DurableError::Conflict);
        }
        grant.resolve_established(&original, admission.policy)?;
        let authority = RetainedInstallationAuthority::active_installation(&original, policy);
        let mut service = DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            &original,
            policy,
            None,
        )?;
        let journal = service.stores()?.0;
        if journal.identity()? != journal_id {
            return Err(DurableError::Conflict);
        }
        journal.reconcile_prior_local_renewal(&authority, &grant, renewal.completed.as_ref())?;
        match journal.inspect_local_credential_renewal(&authority, &grant, policy)? {
            LocalRenewalResolution::Committed(commit) => {
                image = self.persist_renewal_completion(image, &grant, commit)?;
                #[cfg(all(test, unix))]
                super::super::tests::renewal::boundary("expiry-completion");
                let completed = image
                    .renewal
                    .as_ref()
                    .and_then(|r| r.completed.as_ref())
                    .ok_or(DurableError::Corrupt)?;
                journal.acknowledge_local_credential_renewal(&authority, completed)?;
            }
            LocalRenewalResolution::Uncommitted(observed_head) => {
                let expired_at = grant.successor_device().description.validity.until();
                if expired_at > now {
                    return Err(Error::Validity.into());
                }
                let renewal = image.renewal.as_mut().ok_or(DurableError::Corrupt)?;
                renewal.check_time_floor(now)?;
                renewal.pending = None;
                renewal.time_floor = now;
                renewal.expired = Some(ExpiredRenewal {
                    operation,
                    statement,
                    observed_head,
                    expired_at,
                    observed_at: now,
                });
                #[cfg(all(test, unix))]
                super::super::tests::renewal::boundary("expiry-before-save");
                self.save(&image)?;
                #[cfg(all(test, unix))]
                super::super::tests::renewal::boundary("expiry-after-save");
                image = self.image()?;
            }
        }
        // The original journal lease remains held through authenticated readback.
        image
            .renewal
            .as_ref()
            .ok_or(DurableError::Corrupt)?
            .status()
    }
}
