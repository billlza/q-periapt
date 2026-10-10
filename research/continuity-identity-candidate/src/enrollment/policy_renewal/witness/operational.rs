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
impl DeviceEnrollment {
    pub(in crate::enrollment) fn policy_enrollment_completion(
        &self,
        image: &Image,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<Option<Arc<EnrollmentPolicyCompletion>>, DurableError> {
        let (original, _) = self.policy_witness_scope(image, original_policy)?;
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
        approval.check_credential_lineage(&original, &original)?;
        Ok(Some(Arc::new(EnrollmentPolicyCompletion {
            proposal,
            approval,
            original,
        })))
    }
    /// Release the same original installation only after a durable Applied
    /// completion, witness retirement and fresh independent-P admission. The
    /// journal receipt remains bound to that retained enrollment owner; no new
    /// metadata head advance is needed merely to acknowledge historical completion.
    pub fn activate_witnessed_policy_renewal(
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
        let mut service = self.reconcile_installation(&original, original_policy, Some(client))?;
        let journal = service.stores()?.0;
        if journal.identity()? != id {
            return Err(DurableError::Conflict);
        }
        journal.retain_enrollment_policy_completion(completed)?;
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let current = journal.admit_continued_local_device(
            &crate::installation::PolicyScope {
                authority: &authority,
                original_policy,
                original_device: &original,
            },
            &original,
            policy,
            now,
        )?;
        let signer = self.signer(image.identity, false)?;
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
    pub fn activate_witnessed_policy_renewed_session(
        mut self,
        request: crate::SessionReopenRequest,
        policy: Arc<VerifiedSessionPolicy>,
        now: u64,
        client: AnchorClient,
    ) -> Result<(EnrolledDevice, crate::ReopenedPeer), DurableError> {
        let image = self.image()?;
        let original = self.original_device(&image, now)?;
        if request.context.device(request.role).credential_digest() != original.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        let mut active = self.activate_witnessed_policy_renewal(
            request.context.original_policy(),
            &policy,
            now,
            client,
        )?;
        let (service, _, current) = active.parts()?;
        let peer = service.reopen_continued_peer(request, policy, now)?;
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
