// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit reconciliation of an expired original intent without new authority.
use super::*;

#[derive(Clone, Copy)]
enum ExpiryPolicy<'a> {
    Original(&'a VerifiedSessionPolicy),
    Independent {
        original: &'a crate::HistoricalSessionPolicy,
        target: &'a crate::HistoricalSessionPolicy,
    },
}
impl ExpiryPolicy<'_> {
    fn original(&self) -> &crate::HistoricalSessionPolicy {
        match self {
            Self::Original(policy) => policy.historical(),
            Self::Independent { original, .. } => original,
        }
    }
    fn target(&self) -> &crate::HistoricalSessionPolicy {
        match self {
            Self::Original(policy) => policy.historical(),
            Self::Independent { target, .. } => target,
        }
    }
}

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
        let result =
            self.reconcile_expired(operation, statement, ExpiryPolicy::Original(policy), now);
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Classify an exact original G carrying an independently adopted policy.
    /// An existing journal commit remains Committed. Otherwise unchanged
    /// same-generation predecessor history must prove no commit, and the exact
    /// signed target credential, roster or adopted policy must have expired.
    /// `now` must come from the application's trusted clock. It is retained as
    /// a monotonic floor; backdating cannot reactivate the abandoned operation.
    ///
    /// This historical reconciliation needs independently verified P0/Pnext
    /// metadata, not a live runtime or private signer, and never returns an
    /// operational owner. Exact retained outcome retries remain historical even
    /// if a later policy has been adopted; unknown or forgotten IDs are refused.
    pub fn reconcile_expired_policy_credential(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        original_policy: &crate::HistoricalSessionPolicy,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result = self.reconcile_expired(
            operation,
            statement,
            ExpiryPolicy::Independent {
                original: original_policy,
                target: policy,
            },
            now,
        );
        if result.is_err() {
            self.close();
        }
        result
    }
    fn reconcile_expired(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: ExpiryPolicy<'_>,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let mut image = self.image()?;
        let original = match policy {
            ExpiryPolicy::Original(_) => {
                image.require_no_policy_renewal()?;
                self.original_device(&image, now)?
            }
            ExpiryPolicy::Independent { .. } => {
                if image.policy_completed.is_none() {
                    return Err(DurableError::Conflict);
                }
                if policy.original().anchor_requirement().binding().is_some()
                    || policy.target().anchor_requirement().binding().is_some()
                {
                    return Err(DurableError::AnchorRequired);
                }
                self.original_device_metadata(&image)?
            }
        };
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        if admission.policy != policy.original().checkpoint().digest() {
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
                if matches!(policy, ExpiryPolicy::Independent { .. })
                    && image.policy_device_binding
                        == super::super::PolicyDeviceBinding::CredentialRenewal
                    && image.policy_pending.is_none()
                    && renewal.pending.is_none()
                    && renewal.expired.is_none()
                {
                    return self.recover_historical_policy_credential(
                        operation,
                        statement,
                        policy.original(),
                        policy.target(),
                    );
                }
                return Ok(CredentialRenewalStatus::Committed {
                    operation,
                    statement,
                    target: completed.target,
                });
            }
        }
        let independent = match policy {
            ExpiryPolicy::Original(_) => None,
            ExpiryPolicy::Independent { .. } => {
                if image.policy_device_binding
                    != super::super::PolicyDeviceBinding::CredentialRenewal
                    || image.policy_pending.is_some()
                    || renewal.witnessed()
                {
                    return Err(DurableError::Suspended);
                }
                let approval = self
                    .completed_policy_approval(&image)?
                    .ok_or(DurableError::Conflict)?;
                approval.check_target(policy.target())?;
                if approval.scope().original_policy != policy.original().checkpoint() {
                    return Err(DurableError::Conflict);
                }
                Some(approval)
            }
        };
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
        let authority =
            RetainedInstallationAuthority::active_installation(&original, policy.original());
        let mut service = DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            &original,
            policy.original(),
            None,
        )?;
        let journal = service.stores()?.0;
        if journal.identity()? != journal_id {
            return Err(DurableError::Conflict);
        }
        let target = LocalRenewalTarget {
            grant: &grant,
            continuation: None,
            policy_renewal: independent.as_ref().map(|p| (p, &original)),
        };
        let resolution = if let Some(approval) = &independent {
            let receipt = journal.inspect_policy_credential_authorization(approval, &original)?;
            journal.acknowledge_local_policy_renewal(&authority, &receipt)?;
            journal.reconcile_prior_local_target(
                &authority,
                &target,
                renewal.completed.as_ref(),
            )?;
            journal.inspect_local_renewal_target(&authority, &target, policy.target())?
        } else {
            let ExpiryPolicy::Original(current) = policy else {
                return Err(DurableError::Corrupt);
            };
            journal.reconcile_prior_local_renewal(
                &authority,
                &grant,
                renewal.completed.as_ref(),
            )?;
            journal.inspect_local_credential_renewal(&authority, &grant, current)?
        };
        match resolution {
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
                let mut expired_at = grant.successor_device().description.validity.until();
                if independent.is_some() {
                    expired_at = expired_at
                        .min(grant.successor_device().roster_validity.until())
                        .min(policy.target().validity().until());
                }
                if expired_at > now {
                    return Err(Error::Validity.into());
                }
                image.check_time_floor(now)?;
                let renewal = image.renewal.as_mut().ok_or(DurableError::Corrupt)?;
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
