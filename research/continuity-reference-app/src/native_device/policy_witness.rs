// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Required-witness P delegates every durable transition to the original owner.
use super::*;
use crate::policy_renewal::{
    witness::{Outcome, Preparation},
    Request,
};

pub struct PolicyTransitionInputs<'a> {
    pub operation: sdk::PolicyRenewalId,
    pub statement: [u8; 32],
    pub original: &'a sdk::HistoricalSessionPolicy,
    pub previous: &'a sdk::HistoricalSessionPolicy,
    pub target: &'a sdk::VerifiedSessionPolicy,
}
fn current_time(floor: u64) -> Result<u64> {
    let now = clock()?;
    if now < floor {
        return Err("Host time moved behind policy invocation".into());
    }
    Ok(now)
}
impl NativeDevice {
    fn policy_history(&self, original: &sdk::HistoricalSessionPolicy) -> Result<()> {
        if original.family() != self.invitation.family
            || original.anchor_requirement() == sdk::AnchorRequirement::local_only()
        {
            return Err("Original witnessed policy is required".into());
        }
        Ok(())
    }
    fn policy_client(
        &mut self,
        original: &sdk::HistoricalSessionPolicy,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
    ) -> Result<sdk::AnchorClient> {
        self.policy_history(original)?;
        if original.anchor_requirement() != sdk::AnchorRequirement::required(&pin) {
            return Err("Policy witness differs from independently selected original".into());
        }
        Ok(self.owner.policy_renewal_anchor_client(
            original,
            pin,
            Box::new(sdk::AnchorTcpTransport::new(endpoint)),
            Duration::from_secs(10),
        )?)
    }
    pub fn witnessed_policy_request(
        &mut self,
        operation: sdk::PolicyRenewalId,
        original: &sdk::HistoricalSessionPolicy,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
    ) -> Result<Request> {
        let result = (|| {
            let client = self.policy_client(original, pin, endpoint)?;
            let request = self
                .owner
                .witnessed_policy_renewal_request(operation, original, client)?;
            Ok(Request::from_owner(&request, &self.invitation))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn stage_witnessed_policy(
        &mut self,
        inputs: &PolicyRecoveryInputs<'_>,
        now: u64,
    ) -> Result<sdk::PolicyRenewalStatus> {
        let result = (|| {
            self.policy_history(inputs.original)?;
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
    pub fn witnessed_policy_status(
        &mut self,
    ) -> Result<Option<sdk::WitnessedPolicyRenewalProgress>> {
        let result = self
            .owner
            .witnessed_policy_renewal_progress()
            .map_err(Into::into);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn original_policy_operation(
        &mut self,
        operation: sdk::PolicyRenewalId,
        statement: [u8; 32],
    ) -> Result<()> {
        use sdk::{PolicyRenewalStatus as S, WitnessedPolicyRenewalProgress as P};
        let retained = match self.owner.witnessed_policy_renewal_progress()? {
            Some(P::Reserved { proposal, .. } | P::Terminal { proposal, .. }) => {
                (proposal.operation(), proposal.statement())
            }
            Some(P::AbandonedBeforePreparation {
                operation,
                statement,
                ..
            }) => (operation, statement),
            None => match self.owner.policy_renewal_status()? {
                S::Pending {
                    operation,
                    statement,
                    ..
                } => (operation, statement),
                _ => return Err("No original witnessed policy intent retained".into()),
            },
        };
        if retained != (operation, statement) {
            return Err("Original policy operation or statement differs".into());
        }
        Ok(())
    }
    pub fn prepare_witnessed_policy(
        &mut self,
        inputs: &PolicyTransitionInputs<'_>,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<Preparation> {
        let result = (|| {
            self.original_policy_operation(inputs.operation, inputs.statement)?;
            let approval = self
                .owner
                .pending_policy_renewal_approval(inputs.operation)?;
            let client = self.policy_client(inputs.original, pin, endpoint)?;
            let p = self.owner.prepare_witnessed_policy_renewal(
                inputs.original,
                inputs.previous,
                inputs.target,
                current_time(now)?,
                client,
            )?;
            Preparation::new(p, approval)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Local proposal recovery, including failed export. None does not prove a
    /// witness result; caller may explicitly abandon only an unprepared approval.
    pub fn recover_witnessed_policy_preparation(
        &mut self,
        operation: sdk::PolicyRenewalId,
        statement: [u8; 32],
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<Option<Preparation>> {
        let result = (|| {
            self.policy_history(original)?;
            self.original_policy_operation(operation, statement)?;
            let approval = self.owner.pending_policy_renewal_approval(operation)?;
            self.owner
                .recover_witnessed_policy_renewal_preparation(original)?
                .map(|p| Preparation::new(p, approval))
                .transpose()
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn abandon_unprepared_policy(
        &mut self,
        operation: sdk::PolicyRenewalId,
        statement: [u8; 32],
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<sdk::WitnessedPolicyRenewalProgress> {
        let result = (|| {
            self.policy_history(original)?;
            Ok(self
                .owner
                .abandon_unprepared_policy_renewal(operation, statement, original)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn commit_witnessed_policy(
        &mut self,
        preparation: &Preparation,
        inputs: &PolicyTransitionInputs<'_>,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<Outcome> {
        let result = (|| {
            let p = preparation.as_proposal()?;
            if (p.operation(), p.statement()) != (inputs.operation, inputs.statement) {
                return Err("Policy preparation differs from selected transition".into());
            }
            let mut client = self.policy_client(inputs.original, pin, endpoint)?;
            Ok(Outcome::new(
                preparation,
                self.owner.commit_witnessed_policy_renewal(
                    &p,
                    inputs.original,
                    inputs.target,
                    current_time(now)?,
                    &mut client,
                )?,
            ))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Signed historical status or closure of the same original target. Closure
    /// never converts an already applied transaction into a non-commit outcome.
    pub fn reconcile_witnessed_policy(
        &mut self,
        preparation: &Preparation,
        original: &sdk::HistoricalSessionPolicy,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
        close: bool,
    ) -> Result<Outcome> {
        let result = (|| {
            let p = preparation.as_proposal()?;
            let retained = match self.owner.witnessed_policy_renewal_progress()? {
                Some(
                    sdk::WitnessedPolicyRenewalProgress::Reserved { proposal, .. }
                    | sdk::WitnessedPolicyRenewalProgress::Terminal { proposal, .. },
                ) => proposal,
                _ => return Err("Original policy has no retained coordination proposal".into()),
            };
            if retained != p {
                return Err("Complete original policy proposal differs".into());
            }
            let mut client = self.policy_client(original, pin, endpoint)?;
            let state = if close {
                self.owner.close_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    original,
                    &mut client,
                )?
            } else {
                self.owner.reconcile_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    original,
                    &mut client,
                )?
            };
            Ok(Outcome::new(preparation, state))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Fresh current admission after exact original P completion. History alone
    /// cannot release this owner; original journal, signer and witness are reused.
    pub fn activate_witnessed_policy(
        mut self,
        current: &RootInfo,
        original: &sdk::HistoricalSessionPolicy,
        target: &sdk::VerifiedSessionPolicy,
        pin: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<ActiveDevice> {
        self.refresh_current(current, target, current_time(now)?)?;
        let client = self.policy_client(original, pin, endpoint)?;
        let mut active = ActiveDevice::from_owner(self.owner.activate_witnessed_policy_renewal(
            original,
            target,
            current_time(now)?,
            client,
        )?)?;
        active.original_policy = Some(std::sync::Arc::new(original.clone()));
        Ok(active)
    }
}
