// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent policy-only intent in the original enrollment. Pending is not a
//! journal commit and cannot release a service, signer or witness client.
use super::*;
use crate::durable::{LocalPolicyRenewalCommit, LocalPolicyRenewalTarget};
use crate::{
    HistoricalPolicyRenewal, HistoricalSessionPolicy, PolicyCheckpoint, PolicyRenewalId,
    VerifiedPolicyRenewal, MAX_POLICY_RENEWAL_BYTES,
};

const RETAINED_BYTES: usize = PUBLIC_KEY_BYTES + MAX_POLICY_RENEWAL_BYTES;
mod witness;
pub(super) use witness::WitnessPolicy;
pub(crate) use witness::{EnrollmentPolicyCompletion, PersistedPolicyTerminal};
pub use witness::{WitnessedPolicyRenewalDisposition, WitnessedPolicyRenewalProgress};
mod credential;
mod request;
pub use request::PolicyRenewalRequest;
mod resolution;
pub(super) use resolution::RetainedPolicyResolution;
mod roster;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PolicyDeviceBinding {
    Exact,
    MonotonicRoster,
    CredentialRenewal,
}
enum Reconciliation<'a> {
    Current {
        policy: &'a VerifiedSessionPolicy,
        now: u64,
    },
    Historical {
        operation: PolicyRenewalId,
        statement: [u8; 32],
    },
}

/// Authenticated policy-only progress, independent of credential-renewal status.
/// Every state is progress metadata and grants no traffic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRenewalStatus {
    /// No independent policy-only intent has been retained.
    Absent,
    /// Exact approval bytes are retained; original journal reconciliation is
    /// required before any operational owner can be released.
    Pending {
        /// Original operation, distinct from every credential-renewal ID.
        operation: PolicyRenewalId,
        /// Canonical two-root statement commitment.
        statement: [u8; 32],
        /// Approved target checkpoint, not an adopted policy assertion.
        target: PolicyCheckpoint,
    },
    /// The exact original journal adoption was observed and enrollment completion
    /// persisted. This historical fact never grants a session or runtime owner.
    Committed {
        /// Original independently approved operation.
        operation: PolicyRenewalId,
        /// Exact canonical statement adopted by the journal.
        statement: [u8; 32],
        /// Historical target checkpoint; expiry/revocation still deny traffic.
        target: PolicyCheckpoint,
    },
    /// The journal still had the exact previous policy authorization, proving
    /// this fixed target was never adopted. Expiry or a later roster makes it
    /// unusable. This is not revocation of an already committed policy.
    AbandonedUncommitted {
        /// Exact original independent operation.
        operation: PolicyRenewalId,
        /// Exact original approved statement.
        statement: [u8; 32],
        /// The abandoned target, never an adopted-policy claim.
        target: PolicyCheckpoint,
        /// Why this fixed target can no longer be committed.
        reason: PolicyRenewalAbandonment,
        /// Actual journal head observed while its original lease was held.
        observed_roster: RosterCheckpoint,
        /// Trusted observation time retained as an enrollment time floor.
        observed_at: u64,
    },
}

/// Permanent obstruction to one exact uncommitted policy-only target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRenewalAbandonment {
    /// The fixed credential, roster or target policy validity has ended.
    Expired,
    /// The actual roster advanced beyond the approval's exact C/R expectation.
    RosterAdvanced,
}

pub(super) struct RetainedPolicyRenewal {
    operation: PolicyRenewalId,
    statement: [u8; 32],
    target: PolicyCheckpoint,
    approval: Vec<u8>,
}
impl RetainedPolicyRenewal {
    fn new(approval: &HistoricalPolicyRenewal) -> Self {
        Self {
            operation: approval.scope().operation,
            statement: approval.statement_digest(),
            target: approval.target_policy(),
            approval: approval.journal_bytes(),
        }
    }
    fn status(&self) -> PolicyRenewalStatus {
        PolicyRenewalStatus::Pending {
            operation: self.operation,
            statement: self.statement,
            target: self.target,
        }
    }
    fn committed_status(&self) -> PolicyRenewalStatus {
        PolicyRenewalStatus::Committed {
            operation: self.operation,
            statement: self.statement,
            target: self.target,
        }
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        if self.approval.len() != RETAINED_BYTES {
            return Err(DurableError::Corrupt);
        }
        crate::codec::nonzero(&self.statement)?;
        out.extend_from_slice(self.operation.as_bytes());
        out.extend_from_slice(&self.statement);
        out.extend_from_slice(&self.target.version().to_be_bytes());
        out.extend_from_slice(&self.target.digest());
        out.extend_from_slice(&self.approval);
        Ok(())
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let operation = PolicyRenewalId::from_trusted_state(d.array()?)?;
        let statement = d.array()?;
        crate::codec::nonzero(&statement)?;
        let target = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let approval = d.take(RETAINED_BYTES)?.to_vec();
        Ok(Self {
            operation,
            statement,
            target,
            approval,
        })
    }
}

impl DeviceEnrollment {
    /// Complete the original local policy-only transaction and return its same
    /// enrollment, signer and installation owners only after current admission.
    /// Historical P0 authenticates storage; current Pnext and the journal's
    /// latest roster authorize the approved credential or its actually adopted
    /// real same-key G successor. No new bootstrap or
    /// prekey permission is granted. Required-witness renewal remains separate.
    /// Completion may persist even when current admission fails; reopen this
    /// enrollment and query the original operation after any error.
    pub fn activate_policy_renewal(
        mut self,
        original_policy: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrolledDevice, DurableError> {
        let (_, mut service) = self.reconcile_policy_renewal_service(
            original_policy,
            Reconciliation::Current { policy, now },
        )?;
        let image = self.image()?;
        if image.policy_pending.is_some() {
            return Err(DurableError::Suspended);
        }
        let completed = image
            .policy_completed
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let approval = self.authenticated_policy_record(completed)?;
        approval.check_context_policy(original_policy, policy)?;
        let original = self.original_device(&image, now)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        let retained = self.historical_device_metadata(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
        )?;
        self.check_completed_policy_identity(&image, &approval, &original, &retained)?;
        let authority =
            crate::RetainedInstallationAuthority::active_installation(&original, original_policy);
        let journal = service.stores()?.0;
        if image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal {
            let completed = image
                .renewal
                .as_ref()
                .and_then(LocalRenewal::policy_prior_credential_completion)
                .ok_or(DurableError::Conflict)?;
            journal.check_policy_credential_completion(&approval, &original, completed)?;
        }
        journal.inspect_local_policy_renewal(&LocalPolicyRenewalTarget {
            approval: &approval,
            original: &original,
            current: &retained,
            original_policy,
        })?;
        let current = journal.admit_continued_local_device(
            &crate::installation::PolicyScope {
                authority: &authority,
                original_policy,
                original_device: &original,
            },
            &retained,
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

    /// Restore one exact original established session under the independently
    /// adopted policy-only authorization. Original bundle, role, transcript,
    /// journal and archive bindings remain mandatory. Current peer credentials
    /// must already be admitted; use the installation owner to renew peers first.
    pub fn activate_policy_renewed_session(
        mut self,
        request: crate::SessionReopenRequest,
        policy: std::sync::Arc<VerifiedSessionPolicy>,
        now: u64,
    ) -> Result<(EnrolledDevice, crate::ReopenedPeer), DurableError> {
        let image = self.image()?;
        let original = self.original_device(&image, now)?;
        if request.context.device(request.role).credential_digest() != original.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        let mut active =
            self.activate_policy_renewal(request.context.original_policy(), &policy, now)?;
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
    /// Coordinate this original enrollment's local policy-only Pending with its
    /// original journal. An absent commit requires current C/R/Pnext/runtime;
    /// an exact existing commit can finish after expiry. Completion grants no
    /// operational owner. Required-witness policy-only coordination is separate.
    pub fn reconcile_policy_renewal(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, DurableError> {
        self.coordinate_policy_renewal(original_policy, Reconciliation::Current { policy, now })
    }
    /// Finish only the caller's exact already-committed policy-only operation.
    /// No live runtime, private signer or unexpired policy is needed for this
    /// historical acknowledgement. An absent commit remains Pending/Suspended.
    pub fn recover_historical_policy_renewal(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<PolicyRenewalStatus, DurableError> {
        self.coordinate_policy_renewal(
            original_policy,
            Reconciliation::Historical {
                operation,
                statement,
            },
        )
    }
    fn coordinate_policy_renewal(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        mode: Reconciliation<'_>,
    ) -> Result<PolicyRenewalStatus, DurableError> {
        let (status, mut service) = self.reconcile_policy_renewal_service(original_policy, mode)?;
        service.close();
        Ok(status)
    }
    fn reconcile_policy_renewal_service(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        mode: Reconciliation<'_>,
    ) -> Result<(PolicyRenewalStatus, DeviceService), DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            if let Reconciliation::Current { now, .. } = mode {
                image.check_time_floor(now)?;
            }
            if image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal
                && image.policy_pending.is_none()
                && matches!(
                    image.phase,
                    Phase::Accepted {
                        stage: AdmissionPhase::Active,
                        ..
                    }
                )
            {
                if let Reconciliation::Current { policy, now } = mode {
                    let (image, service) = self.reconcile_local_renewal(
                        image,
                        original_policy,
                        super::renewal::LocalRenewalPolicy::Current(policy),
                        now,
                        None,
                    )?;
                    return Ok((
                        image
                            .policy_completed
                            .as_ref()
                            .ok_or(DurableError::Conflict)?
                            .committed_status(),
                        service,
                    ));
                }
                if image
                    .renewal
                    .as_ref()
                    .is_some_and(LocalRenewal::has_pending_credential)
                {
                    return Err(DurableError::Suspended);
                }
            }
            let retained = image
                .policy_pending
                .as_ref()
                .or(image.policy_completed.as_ref())
                .ok_or(DurableError::Conflict)?;
            let approval = self.authenticated_policy_record(retained)?;
            if let Reconciliation::Historical {
                operation,
                statement,
            } = mode
            {
                if operation != approval.scope().operation
                    || statement != approval.statement_digest()
                {
                    return Err(DurableError::Conflict);
                }
            }
            if original_policy.anchor_requirement().binding().is_some() {
                return Err(DurableError::AnchorRequired);
            }
            let Phase::Accepted {
                admission,
                stage: AdmissionPhase::Active | AdmissionPhase::Refreshing { .. },
                ..
            } = &image.phase
            else {
                return Err(DurableError::Suspended);
            };
            if admission.policy != original_policy.checkpoint().digest() {
                return Err(DurableError::Conflict);
            }
            let original = self.original_device_metadata(&image)?;
            let current = self.historical_device_metadata(
                &admission.certificate,
                &admission.roster,
                admission.checkpoint,
            )?;
            let target = LocalPolicyRenewalTarget {
                approval: &approval,
                original: &original,
                current: &current,
                original_policy,
            };
            let authority = crate::RetainedInstallationAuthority::active_installation(
                &original,
                original_policy,
            );
            let mut service = DeviceInstallation::reconcile_original_enrollment(
                self.paths.installation.clone(),
                self.key()?,
                &original,
                original_policy,
                None,
            )?;
            let journal = service.stores()?.0;
            if journal.identity()? != admission.journal {
                return Err(DurableError::Conflict);
            }
            self.reconcile_policy_roster(&mut image, journal, &target, &authority, &mode)?;
            let previous = image
                .policy_completed
                .as_ref()
                .map(|c| {
                    self.authenticated_policy_record(c)
                        .map(|a| LocalPolicyRenewalCommit::for_approval(&a))
                })
                .transpose()?;
            let receipt = match mode {
                Reconciliation::Historical { .. } => {
                    journal.inspect_local_policy_renewal(&target)?
                }
                Reconciliation::Current { policy, now } => {
                    if image.policy_pending.is_some() {
                        if let Some(completed) = image
                            .renewal
                            .as_ref()
                            .and_then(LocalRenewal::policy_prior_credential_completion)
                        {
                            journal.acknowledge_local_credential_renewal(&authority, completed)?;
                        }
                    }
                    journal.commit_local_policy_renewal(&target, policy, now, previous.as_ref())?
                }
            };
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("policy-only-journal");
            if receipt != LocalPolicyRenewalCommit::for_approval(&approval) {
                return Err(DurableError::Conflict);
            }
            if let Some(pending) = image.policy_pending.take() {
                image.policy_completed = Some(pending);
                image.policy_device_binding = PolicyDeviceBinding::Exact;
                if let Some(resolution) = &mut image.policy_resolution {
                    resolution.clear_abandoned();
                }
                self.save(&image)?;
            }
            let readback = self.image()?;
            let completed = readback
                .policy_completed
                .as_ref()
                .ok_or(DurableError::Corrupt)?;
            if readback.policy_pending.is_some()
                || self.authenticated_policy_record(completed)?.journal_bytes()
                    != approval.journal_bytes()
            {
                return Err(DurableError::Conflict);
            }
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("policy-only-completion");
            journal.acknowledge_local_policy_renewal(&authority, &receipt)?;
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("policy-only-acknowledgement");
            Ok((completed.committed_status(), service))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn check_policy_predecessor(
        &self,
        image: &Image,
        approval: &HistoricalPolicyRenewal,
        original: &VerifiedDevice,
        admission: &Admission,
    ) -> Result<(), DurableError> {
        let scope = approval.scope();
        if scope.journal != admission.journal || scope.original_policy.digest() != admission.policy
        {
            return Err(DurableError::Conflict);
        }
        if let Some(completed) = &image.policy_completed {
            let previous = self.authenticated_policy_record(completed)?;
            if scope.operation == previous.scope().operation
                || scope.previous_authorization != Some(previous.statement_digest())
                || scope.previous_policy != previous.target_policy()
                || scope.original_policy != previous.scope().original_policy
            {
                return Err(DurableError::Conflict);
            }
            return Ok(());
        }
        let predecessor = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor)
            .map(|bytes| self.retained_policy(bytes))
            .transpose()?;
        match predecessor {
            None if scope.previous_authorization.is_none()
                && scope.previous_policy == scope.original_policy =>
            {
                Ok(())
            }
            Some(previous) => {
                Self::check_policy_scope(&previous, original, admission)?;
                if scope.previous_authorization != Some(previous.statement_digest())
                    || scope.previous_policy != previous.target_policy()
                    || scope.original_policy != previous.scope().original_policy
                {
                    return Err(DurableError::Conflict);
                }
                Ok(())
            }
            _ => Err(DurableError::Conflict),
        }
    }
    // Called for every authenticated read. Expired/closed runtime owners and
    // unavailable private signers are not needed to observe public history.
    pub(super) fn validate_policy_pending(&self, image: &Image) -> Result<(), DurableError> {
        image.validate_policy_phase()?;
        self.validate_policy_resolution(image)?;
        self.validate_witness_policy(image)?;
        if image.policy_pending.is_none() && image.policy_completed.is_none() {
            return Ok(());
        }
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let original = self.original_device_metadata(image)?;
        let current = self.historical_device_metadata(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
        )?;
        for (record, completed) in image
            .policy_completed
            .iter()
            .map(|r| (r, true))
            .chain(image.policy_pending.iter().map(|r| (r, false)))
        {
            let approval = self.authenticated_policy_record(record)?;
            if completed && image.policy_device_binding != PolicyDeviceBinding::Exact {
                self.check_completed_policy_identity(image, &approval, &original, &current)?;
                let checkpoint = match image.phase {
                    Phase::Accepted {
                        stage: AdmissionPhase::Refreshing { previous },
                        ..
                    } => previous,
                    _ => admission.checkpoint,
                };
                let approved = approval.scope().current_roster;
                if checkpoint.version() < approved.version()
                    || (checkpoint.version() == approved.version() && checkpoint != approved)
                {
                    return Err(DurableError::Conflict);
                }
            } else {
                approval.check_devices(&original, &current)?;
            }
            if approval.scope().journal != admission.journal
                || approval.scope().original_policy.digest() != admission.policy
            {
                return Err(DurableError::Conflict);
            }
        }
        if let Some(pending) = &image.policy_pending {
            self.check_policy_predecessor(
                image,
                &self.authenticated_policy_record(pending)?,
                &original,
                admission,
            )?;
        }
        Ok(())
    }
    fn authenticated_policy_record(
        &self,
        record: &RetainedPolicyRenewal,
    ) -> Result<HistoricalPolicyRenewal, DurableError> {
        let approval = HistoricalPolicyRenewal::from_authority(
            &record.approval,
            &self.intent.root,
            self.intent.description.family,
        )?;
        if approval.scope().operation != record.operation
            || approval.statement_digest() != record.statement
            || approval.target_policy() != record.target
        {
            return Err(DurableError::Conflict);
        }
        Ok(approval)
    }

    /// Read the independent policy intent, including after policy/runtime expiry.
    /// Active enrollment status still describes the original installation only.
    pub fn policy_renewal_status(&mut self) -> Result<PolicyRenewalStatus, DurableError> {
        let image = self.image()?;
        if let Some(pending) = &image.policy_pending {
            return Ok(pending.status());
        }
        if let Some(status) = image
            .policy_resolution
            .as_ref()
            .and_then(RetainedPolicyResolution::status)
        {
            return Ok(status);
        }
        Ok(image.policy_completed.as_ref().map_or(
            PolicyRenewalStatus::Absent,
            RetainedPolicyRenewal::committed_status,
        ))
    }
    /// Recover exact original public approval bytes for the caller's retained
    /// operation. This does not re-sign, renew permission or report completion.
    pub fn pending_policy_renewal_approval(
        &mut self,
        operation: PolicyRenewalId,
    ) -> Result<Vec<u8>, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let pending = image
                .policy_pending
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if pending.operation != operation {
                return Err(DurableError::Conflict);
            }
            Ok(pending
                .approval
                .get(PUBLIC_KEY_BYTES..)
                .ok_or(DurableError::Corrupt)?
                .to_vec())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Persist an independently approved extension without replacing C/R, the
    /// original signer, journal, installation or credential-renewal history.
    /// Rechecks the actual retained credential/roster and live target/runtime.
    /// Exact retries retain the first signatures even if issuers sign again.
    ///
    /// `reconcile_policy_renewal` coordinates the original local journal and
    /// completion. `activate_policy_renewal` additionally checks current owner
    /// permission. Legacy P0 activation stays suspended; a real G can separately
    /// extend the credential under the exact adopted current policy.
    /// After an unknown save result, reopen this original enrollment and query
    /// the operation. Never provision another record or manufacture a G grant.
    pub fn stage_policy_renewal(
        &mut self,
        renewal: &VerifiedPolicyRenewal,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            image.check_time_floor(now)?;
            if image
                .policy_resolution
                .as_ref()
                .is_some_and(|r| r.contains(operation))
            {
                return Err(DurableError::Conflict);
            }
            let Phase::Accepted {
                admission,
                stage: AdmissionPhase::Active,
                ..
            } = &image.phase
            else {
                return Err(Error::State.into());
            };
            if let Some(history) = &image.renewal {
                if !history.permits_policy_pending() {
                    return Err(DurableError::Suspended);
                }
                history.policy_time_floor(now)?;
            }
            let approval = renewal.historical();
            if approval.scope().operation != operation {
                return Err(DurableError::Conflict);
            }
            let original = self.original_device(&image, now)?;
            let pin = AccountPin::new(
                crate::identity::account_id(&self.intent.root),
                self.intent.root.clone(),
                admission.checkpoint,
                self.intent.description.family,
            )?;
            let current = pin.verify_device(&admission.certificate, &admission.roster, now)?;
            approval.check_devices(&original, &current)?;
            approval.check_context_policy(original_policy, target)?;
            admit(&current, target, now)?;
            if let Some(completed) = &image.policy_completed {
                if completed.operation == operation {
                    if image.policy_pending.is_none()
                        && completed.statement == approval.statement_digest()
                        && completed.target == approval.target_policy()
                    {
                        return Ok(completed.committed_status());
                    }
                    return Err(DurableError::Conflict);
                }
            }
            self.check_policy_predecessor(&image, &approval, &original, admission)?;
            if let Some(pending) = &image.policy_pending {
                if pending.operation != operation
                    || pending.statement != approval.statement_digest()
                    || pending.target != approval.target_policy()
                {
                    return Err(DurableError::Conflict);
                }
                return Ok(pending.status());
            }
            self.begin_witness_policy(&mut image, original_policy, operation)?;
            image.policy_pending = Some(RetainedPolicyRenewal::new(&approval));
            self.validate_policy_pending(&image)?;
            self.save(&image)?;
            self.policy_renewal_status()
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
