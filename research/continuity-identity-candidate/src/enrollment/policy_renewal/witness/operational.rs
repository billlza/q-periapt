// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment completion remains a separate durable fact from journal bytes.
use super::*;
use std::sync::Arc;

/// Only the original enrollment's authenticated completion can construct this.
/// Holding it does not grant current policy, membership or witness authority.
pub(crate) struct EnrollmentPolicyCompletion {
    proposal: Proposal,
    approval: HistoricalPolicyRenewal,
    original: VerifiedDevice,
}
impl EnrollmentPolicyCompletion {
    pub(crate) fn proposal(&self) -> Proposal {
        self.proposal
    }
    pub(crate) fn approval(&self) -> &HistoricalPolicyRenewal {
        &self.approval
    }
    pub(crate) fn original(&self) -> &VerifiedDevice {
        &self.original
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    pub(in crate::enrollment) fn policy_enrollment_completion(
        &self,
        image: &Image,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<Option<Arc<EnrollmentPolicyCompletion>>, DurableError> {
        let (original, _) = self.policy_witness_scope(image, original_policy)?;
        self.retained_policy_enrollment_completion(image, original_policy, &original)
    }
    // Historical completion can authenticate an older ordinary intent while a
    // new approval is staged. It neither retires nor activates that approval.
    pub(in crate::enrollment) fn retained_policy_enrollment_completion(
        &self,
        image: &Image,
        original_policy: &HistoricalSessionPolicy,
        original: &VerifiedDevice,
    ) -> Result<Option<Arc<EnrollmentPolicyCompletion>>, DurableError> {
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        let binding = original_policy
            .anchor_requirement()
            .binding()
            .ok_or(DurableError::AnchorRequired)?;
        if admission.policy != original_policy.checkpoint().digest()
            || image
                .policy_witness
                .as_ref()
                .is_some_and(|w| w.binding != binding)
        {
            return Err(DurableError::Conflict);
        }
        let proposal = image.policy_witness.as_ref().and_then(|w| w.completed);
        let Some(proposal) = proposal else {
            return if image.policy_completed.is_none() {
                Ok(None)
            } else {
                Err(DurableError::Suspended)
            };
        };
        let record = image
            .policy_completed
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        if record.operation != proposal.operation() || record.statement != proposal.statement() {
            return Err(DurableError::Suspended);
        }
        let approval = self.authenticated_policy_record(record)?;
        approval.check_original_policy(original_policy)?;
        let current = self.policy_witness_current_device(image)?;
        self.check_completed_policy_identity(image, &approval, original, &current)?;
        Ok(Some(Arc::new(EnrollmentPolicyCompletion {
            proposal,
            approval,
            original: original.clone(),
        })))
    }
    /// Release the same original installation only after a durable Applied
    /// completion, witness retirement and fresh independent-P admission. The
    /// journal receipt remains bound to that retained enrollment owner; no new
    /// metadata head advance is needed merely to acknowledge historical completion.
    pub async fn activate_witnessed_policy_renewal(
        mut self,
        original_policy: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
        client: AnchorClient,
    ) -> Result<EnrolledDevice, DurableError> {
        let image = self.image()?;
        image.check_time_floor(now)?;
        image.require_roster_retired()?;
        let (original, id) = self.policy_witness_scope(&image, original_policy)?;
        if image.policy_pending.is_some()
            || image
                .renewal
                .as_ref()
                .is_some_and(|r| !r.permits_policy_pending())
            || image
                .policy_witness
                .as_ref()
                .and_then(|w| w.coordination)
                .is_none_or(|c| !c.retired)
        {
            return Err(DurableError::Suspended);
        }
        let completed = self
            .policy_enrollment_completion(&image, original_policy)?
            .ok_or(DurableError::Suspended)?;
        completed
            .approval
            .check_context_policy(original_policy, policy)?;
        let retained = self.policy_witness_current_device(&image)?;
        let mut service = self
            .reconcile_installation(&original, original_policy, Some(client))
            .await?;
        let journal = service.stores()?.0;
        if journal.identity()? != id {
            return Err(DurableError::Conflict);
        }
        journal
            .retain_enrollment_policy_completion(completed)
            .await?;
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let current = journal
            .admit_continued_local_device(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy,
                    original_device: &original,
                },
                &retained,
                policy,
                now,
            )
            .await?;
        let signer = self.signer(image.identity, false).await?;
        signer.check_device(&current)?;
        admit(&current, policy, now)?;
        Ok(EnrolledDevice {
            active: Some(Box::new(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device: current,
            })),
        })
    }
    /// Restore the original established session while retaining its registration,
    /// service and signer owners. Every traffic release checks current independent P.
    pub async fn activate_witnessed_policy_renewed_session(
        mut self,
        request: crate::SessionReopenRequest,
        policy: Arc<VerifiedSessionPolicy>,
        now: u64,
        client: AnchorClient,
    ) -> Result<(EnrolledDevice, crate::ReopenedPeer), DurableError> {
        let image = self.image()?;
        let original = self.original_device(&image, now).await?;
        if request.context.device(request.role).credential_digest() != original.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        let mut active = self
            .activate_witnessed_policy_renewal(
                request.context.original_policy(),
                &policy,
                now,
                client,
            )
            .await?;
        let (service, _, current) = active.parts()?;
        let peer = service.reopen_continued_peer(request, policy, now).await?;
        if peer
            .context()
            .session_device(peer.role())
            .credential_digest()
            != current.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        Ok((active, peer))
    }
}
