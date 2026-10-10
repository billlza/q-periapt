// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same-credential roster maintenance after independent policy adoption.
use super::*;

impl DeviceEnrollment {
    pub(in crate::enrollment) fn refresh_policy_roster(
        &mut self,
        mut image: Image,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrollmentStatus, DurableError> {
        if image.policy_pending.is_some()
            || image
                .renewal
                .as_ref()
                .is_some_and(LocalRenewal::has_pending_credential)
        {
            return Err(DurableError::Suspended);
        }
        let completed = image
            .policy_completed
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let approval = self.authenticated_policy_record(completed)?;
        approval.check_target(policy)?;
        if policy.anchor_requirement().binding().is_some() {
            return Err(DurableError::AnchorRequired);
        }
        if let Some(history) = &image.renewal {
            history.policy_time_floor(now)?;
        }
        let original = self.original_device(&image, now)?;
        let Phase::Accepted {
            admission, stage, ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        if !matches!(
            *stage,
            AdmissionPhase::Active
                | AdmissionPhase::Refreshing { .. }
                | AdmissionPhase::RosterResolved { .. }
        ) {
            return Err(Error::State.into());
        }
        let current = pin.verify_device(&admission.certificate, roster, now)?;
        self.check_completed_policy_identity(&image, &approval, &original, &current)?;
        self.signer(image.identity, false)?.check_device(&current)?;
        admit(&current, policy, now)?;
        let next = current.roster().checkpoint();
        if next.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        let Phase::Accepted {
            admission, stage, ..
        } = &mut image.phase
        else {
            return Err(DurableError::Corrupt);
        };
        match *stage {
            AdmissionPhase::Refreshing { previous: expected }
                if expected == previous && admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == previous => {
                admission.roster = roster.to_vec();
                admission.checkpoint = next;
                *stage = AdmissionPhase::Refreshing { previous };
                if image.policy_device_binding != PolicyDeviceBinding::CredentialRenewal {
                    image.policy_device_binding = PolicyDeviceBinding::MonotonicRoster;
                }
                self.validate_policy_pending(&image)?;
                self.save(&image)?;
            }
            AdmissionPhase::RosterResolved { observed } if observed == previous => {
                admission.roster = roster.to_vec();
                admission.checkpoint = next;
                *stage = AdmissionPhase::Refreshing { previous };
                if image.policy_device_binding != PolicyDeviceBinding::CredentialRenewal {
                    image.policy_device_binding = PolicyDeviceBinding::MonotonicRoster;
                }
                self.validate_policy_pending(&image)?;
                self.save(&image)?;
            }
            _ => return Err(DurableError::Conflict),
        }
        admit(&current, policy, now)?;
        self.status()
    }

    pub(super) fn reconcile_policy_roster(
        &mut self,
        image: &mut Image,
        journal: &mut crate::DeviceJournal,
        target: &LocalPolicyRenewalTarget<'_>,
        authority: &crate::RetainedInstallationAuthority,
        mode: &Reconciliation<'_>,
    ) -> Result<(), DurableError> {
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Refreshing { previous },
            ..
        } = &image.phase
        else {
            return Ok(());
        };
        if image.policy_pending.is_some()
            || image.policy_device_binding == PolicyDeviceBinding::Exact
        {
            return Err(DurableError::Corrupt);
        }
        let next = admission.checkpoint;
        if target.current.roster().checkpoint() != next {
            return Err(DurableError::Conflict);
        }
        let receipt = journal.inspect_local_policy_renewal(target)?;
        if image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal {
            let completed = image
                .renewal
                .as_ref()
                .and_then(LocalRenewal::policy_prior_credential_completion)
                .ok_or(DurableError::Conflict)?;
            journal.check_policy_credential_completion(
                target.approval,
                target.original,
                completed,
            )?;
            journal.acknowledge_local_credential_renewal(authority, completed)?;
        }
        let head = journal.roster_checkpoint(target.current.account_id())?;
        if head == *previous {
            let Reconciliation::Current { policy, now } = mode else {
                return Err(DurableError::Suspended);
            };
            target.approval.check_target(policy)?;
            admit(target.current, policy, *now)?;
            journal.acknowledge_local_policy_renewal(authority, &receipt)?;
            if journal.install_roster(target.current.roster(), *now)? != next {
                return Err(DurableError::Conflict);
            }
        } else if head == next {
            // Exact journal adoption is historical metadata, so configuration
            // completion can finish after target policy/runtime expiry.
            journal.acknowledge_local_policy_renewal(authority, &receipt)?;
        } else {
            return Err(DurableError::Conflict);
        }
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("policy-roster-journal");
        let Phase::Accepted { stage, .. } = &mut image.phase else {
            return Err(DurableError::Corrupt);
        };
        *stage = AdmissionPhase::Active;
        self.save(image)?;
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("policy-roster-completion");
        Ok(())
    }
}
