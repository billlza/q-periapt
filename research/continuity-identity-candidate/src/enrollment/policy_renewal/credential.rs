// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A real credential grant may carry an already adopted independent policy.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    pub(in crate::enrollment) fn completed_policy_approval(
        &self,
        image: &Image,
    ) -> Result<Option<HistoricalPolicyRenewal>, DurableError> {
        image
            .policy_completed
            .as_ref()
            .map(|r| self.authenticated_policy_record(r))
            .transpose()
    }

    // Configuration can authenticate historical completion metadata. Actual
    // permission additionally needs the matching real G in the original journal.
    pub(in crate::enrollment) fn check_completed_policy_identity(
        &self,
        image: &Image,
        approval: &HistoricalPolicyRenewal,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        if current.credential_digest() == approval.scope().current_credential {
            return Ok(approval.check_credential_lineage(original, current)?);
        }
        if image.policy_device_binding != PolicyDeviceBinding::CredentialRenewal {
            return Err(DurableError::Conflict);
        }
        let completed = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_prior_credential_completion)
            .ok_or(DurableError::Conflict)?;
        approval.check_same_identity(original, current)?;
        let head = current.roster().checkpoint();
        if completed.owner != approval.scope().original_owner
            || completed.policy != approval.scope().original_policy.digest()
            || completed.credential != current.credential_digest()
            || completed.target.version() > head.version()
            || (completed.target.version() == head.version() && completed.target != head)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }

    /// Finish the exact already-committed real credential renewal carrying an
    /// adopted independent policy. Independently verified P0/Pnext history and
    /// the caller's original G operation/statement are required. No live runtime
    /// or private signer is borrowed, and no absent target or owner is created.
    /// An uncommitted original intent remains Pending/Suspended.
    pub async fn recover_historical_policy_credential(
        &mut self,
        operation: crate::CredentialRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<crate::CredentialRenewalStatus, DurableError> {
        let result = self
            .recover_historical_policy_credential_attempt(
                operation,
                statement,
                original_policy,
                policy,
            )
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn recover_historical_policy_credential_attempt(
        &mut self,
        operation: crate::CredentialRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<crate::CredentialRenewalStatus, DurableError> {
        let image = self.image()?;
        if image.policy_device_binding != PolicyDeviceBinding::CredentialRenewal
            || image.policy_pending.is_some()
            || image.policy_completed.is_none()
        {
            return Err(DurableError::Conflict);
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Conflict)?;
        match renewal.status()? {
            crate::CredentialRenewalStatus::Pending {
                operation: expected,
                statement: digest,
            }
            | crate::CredentialRenewalStatus::Committed {
                operation: expected,
                statement: digest,
                ..
            } if operation == expected && statement == digest => {}
            _ => return Err(DurableError::Conflict),
        }
        let (image, mut service) = self
            .reconcile_local_renewal(
                image,
                original_policy,
                super::super::renewal::LocalRenewalPolicy::Historical(policy),
                0,
                None,
            )
            .await?;
        service.close();
        image
            .renewal
            .as_ref()
            .ok_or(DurableError::Conflict)?
            .status()
    }
}
