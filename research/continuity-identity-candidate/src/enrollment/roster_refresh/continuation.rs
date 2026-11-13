// SPDX-License-Identifier: Apache-2.0 OR MIT
//! R carries an already adopted two-root T without creating policy authority.
use super::*;

impl WitnessRoster {
    pub(super) fn continuation_shape_matches(&self, image: &Image) -> bool {
        let adopted = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor);
        if self.continued {
            return self.credential_bound()
                && adopted.is_some()
                && self.scope.policy_authorization.is_some()
                && image.policy_completed.is_none()
                && image.policy_pending.is_none();
        }
        if adopted.is_none() {
            return true;
        }
        let Phase::Accepted { admission, .. } = &image.phase else {
            return false;
        };
        self.retired()
            && self.scope.policy.digest() == admission.policy
            && self.scope.policy_authorization.is_none()
    }
}

impl DeviceEnrollment {
    pub(super) fn roster_continuation(
        &self,
        image: &Image,
    ) -> Result<Option<crate::HistoricalPolicyContinuation>, DurableError> {
        let Some(bytes) = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_predecessor)
        else {
            return Ok(None);
        };
        if image.policy_pending.is_some() || image.policy_completed.is_some() {
            return Err(DurableError::Conflict);
        }
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        let original = self.original_device_metadata(image)?;
        let retained = self.retained_policy(bytes)?;
        Self::check_policy_scope(&retained, &original, admission)?;
        Ok(Some(retained))
    }
    pub(super) fn validate_roster_policy(
        &self,
        image: &Image,
        r: &WitnessRoster,
    ) -> Result<(), DurableError> {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        match (r.continued, self.roster_continuation(image)?) {
            (true, Some(t)) => {
                if !r.credential_bound()
                    || (!r.retired()
                        && (r.scope.policy != t.target_policy()
                            || r.scope.policy_authorization != Some(t.statement_digest())))
                {
                    return Err(DurableError::Conflict);
                }
            }
            (true, None) => return Err(DurableError::Conflict),
            (false, Some(_)) => {
                // Legacy R may precede T; it cannot claim to have used T.
                if !r.retired()
                    || r.scope.policy.digest() != admission.policy
                    || r.scope.policy_authorization.is_some()
                {
                    return Err(DurableError::Conflict);
                }
            }
            (false, None) if !r.retired() => match (
                self.completed_policy_approval(image)?,
                r.scope.policy_authorization,
            ) {
                (None, None) if r.scope.policy.digest() == admission.policy => {}
                (Some(p), Some(s))
                    if p.target_policy() == r.scope.policy && p.statement_digest() == s => {}
                _ => return Err(DurableError::Conflict),
            },
            (false, None) => {}
        }
        Ok(())
    }
}
