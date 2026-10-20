// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent two-root policy adoption; outcomes never confer fresh bootstrap permission.
use super::*;
use crate::policy_renewal::Request;

pub struct PolicyRecoveryInputs<'a> {
    pub request: &'a Request,
    pub account_approval: &'a [u8],
    pub policy_approval: &'a [u8],
    pub current: &'a RootInfo,
    pub original: &'a sdk::HistoricalSessionPolicy,
    pub previous: &'a sdk::HistoricalSessionPolicy,
    pub target: &'a sdk::VerifiedSessionPolicy,
}
impl NativeDevice {
    pub fn policy_recovery_status(&mut self) -> Result<sdk::PolicyRenewalStatus> {
        Ok(self.owner.policy_renewal_status()?)
    }
    pub fn policy_renewal_request(
        &mut self,
        operation: sdk::PolicyRenewalId,
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<Request> {
        let result = (|| {
            if original.family() != self.invitation.family {
                return Err("Original policy family differs".into());
            }
            let request = self.owner.policy_renewal_request(operation, original)?;
            Ok(Request::from_owner(&request, &self.invitation))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn checked_policy_recovery(
        &mut self,
        inputs: &PolicyRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::VerifiedPolicyRenewal> {
        let r = inputs.request;
        if r.application != self.invitation.application
            || r.enrollment != self.invitation.operation
            || r.root_revision != self.invitation.root_revision
            || r.scope.journal != *self.owner.public_admission()?.journal().as_bytes()
            || [inputs.original, inputs.previous, inputs.target.historical()]
                .iter()
                .any(|p| {
                    p.family() != self.invitation.family
                        || p.anchor_requirement() != sdk::AnchorRequirement::local_only()
                })
        {
            return Err("Policy adoption differs from the original local-only installation".into());
        }
        self.pin(inputs.current)?;
        let request = r.verify_identities(inputs.current, now)?;
        Ok(sdk::VerifiedPolicyRenewal::verify(
            &sdk::PolicyRenewalApproval::from_bytes(inputs.account_approval)?,
            &sdk::PolicyRenewalApproval::from_bytes(inputs.policy_approval)?,
            request.scope(),
            &request.materials(inputs.original, inputs.previous, inputs.target),
            now,
        )?)
    }
    pub fn stage_policy_recovery(
        &mut self,
        inputs: &PolicyRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::PolicyRenewalStatus> {
        let result = (|| {
            let approval = self.checked_policy_recovery(inputs, now)?;
            Ok(self.owner.stage_policy_renewal(
                &approval,
                approval.scope().operation,
                inputs.original,
                inputs.target,
                now,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Coordinate the exact approved intent and return historical progress only.
    pub fn adopt_policy(
        &mut self,
        inputs: &PolicyRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::PolicyRenewalStatus> {
        let result = (|| {
            self.stage_policy_recovery(inputs, now)?;
            let at = clock()?;
            if at < now {
                return Err("Host time moved behind policy adoption".into());
            }
            Ok(self
                .owner
                .reconcile_policy_renewal(inputs.original, inputs.target, at)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Finish an exact already-committed original operation, without a live target
    /// or private signer. Pending without a commit remains an explicit error.
    pub fn recover_policy(
        &mut self,
        operation: sdk::PolicyRenewalId,
        statement: [u8; 32],
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<sdk::PolicyRenewalStatus> {
        let result = (|| {
            if original.family() != self.invitation.family {
                return Err("Original policy family differs".into());
            }
            Ok(self
                .owner
                .recover_historical_policy_renewal(operation, statement, original)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Inspect the exact original operation. Only proven non-commit plus signed
    /// expiry or actual roster advancement permits abandonment; no owner returns.
    pub fn resolve_policy(
        &mut self,
        operation: sdk::PolicyRenewalId,
        statement: [u8; 32],
        original: &sdk::HistoricalSessionPolicy,
        target: &sdk::HistoricalSessionPolicy,
        now: u64,
    ) -> Result<sdk::PolicyRenewalStatus> {
        let result = (|| {
            if [original, target].iter().any(|p| {
                p.family() != self.invitation.family
                    || p.anchor_requirement() != sdk::AnchorRequirement::local_only()
            }) {
                return Err("Policy resolution requires original local-only policy history".into());
            }
            let at = clock()?;
            if at < now {
                return Err("Host time moved behind policy resolution".into());
            }
            Ok(self
                .owner
                .resolve_policy_renewal(operation, statement, original, target, at)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
