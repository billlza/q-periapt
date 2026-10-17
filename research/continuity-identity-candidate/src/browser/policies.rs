// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent policy maintenance delegates to the original enrollment state machine.
use super::*;
use crate::{
    AnchorPolicyRenewalProposal as Proposal, AnchorPolicyRenewalState as WitnessState,
    HistoricalSessionPolicy, PolicyRenewalId, PolicyRenewalStatus, VerifiedPolicyRenewal,
    WitnessedPolicyRenewalProgress,
};

async fn client(
    op: &mut Operation<'_>,
    original: &HistoricalSessionPolicy,
    config: (AnchorPin, Box<dyn AnchorTransport>, Duration),
) -> Result<AnchorClient, DurableError> {
    op.enrollment()?
        .policy_renewal_anchor_client(original, config.0, config.1, config.2)
        .await
}
impl BrowserDevice {
    /// Historical progress only. Current traffic requires separate activation.
    pub async fn policy_renewal_status(&self) -> Result<PolicyRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = match op.state.as_mut() {
            Some(State::Enrollment(owner)) => owner.policy_renewal_status(),
            Some(State::Active(owner)) => owner.policy_renewal_status(),
            Some(State::Recovery(_) | State::Retired(_)) => Err(Error::State.into()),
            None => Err(DurableError::Closed),
        };
        op.finish(result).await
    }
    /// Retained local terminal and cleanup, distinct from a remote status response.
    pub async fn witnessed_policy_renewal_progress(
        &self,
    ) -> Result<Option<WitnessedPolicyRenewalProgress>, JsValue> {
        let mut op = self.operation()?;
        let result = match op.state.as_mut() {
            Some(State::Enrollment(owner)) => owner.witnessed_policy_renewal_progress(),
            Some(State::Active(owner)) => owner.witnessed_policy_renewal_progress(),
            Some(State::Recovery(_) | State::Retired(_)) => Err(Error::State.into()),
            None => Err(DurableError::Closed),
        };
        op.finish(result).await
    }
    /// Stage both independently verified approvals under the caller-retained operation.
    pub async fn stage_policy_renewal(
        &self,
        grant: &VerifiedPolicyRenewal,
        operation: PolicyRenewalId,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .stage_policy_renewal(grant, operation, original, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Commit/recover local protection only; this does not release traffic authority.
    pub async fn reconcile_policy_renewal(
        &self,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .reconcile_policy_renewal(original, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Finish an exact already-committed local operation without a live runtime.
    pub async fn recover_historical_policy_renewal(
        &self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
    ) -> Result<PolicyRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .recover_historical_policy_renewal(operation, statement, original)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Resolve an expired or superseded local target against its actual original journal.
    pub async fn resolve_policy_renewal(
        &self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        target: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .resolve_policy_renewal(operation, statement, original, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Recover exact retained approval bytes; no new signatures or permission.
    pub async fn pending_policy_renewal_approval(
        &self,
        operation: PolicyRenewalId,
    ) -> Result<Vec<u8>, JsValue> {
        let mut op = self.operation()?;
        let result = op
            .enrollment()
            .and_then(|e| e.pending_policy_renewal_approval(operation));
        op.finish(result).await
    }
    /// Seal an exact staged target. Independent witness approval is still required.
    pub async fn prepare_witnessed_policy_renewal(
        &self,
        original: &HistoricalSessionPolicy,
        previous: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<Proposal, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .prepare_witnessed_policy_renewal(original, previous, target, now, anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Absence of a local proposal never proves remote non-commit.
    pub async fn recover_witnessed_policy_renewal_preparation(
        &self,
        original: &HistoricalSessionPolicy,
    ) -> Result<Option<Proposal>, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .recover_witnessed_policy_renewal_preparation(original)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Commit the independently prepared original proposal; errors can leave it applied.
    pub async fn commit_witnessed_policy_renewal(
        &self,
        proposal: &Proposal,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .commit_witnessed_policy_renewal(proposal, original, target, now, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Query the original outcome, retain its terminal, then ACK and clean up.
    pub async fn reconcile_witnessed_policy_renewal(
        &self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .reconcile_witnessed_policy_renewal(operation, statement, original, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Explicit closure preserves Applied if the witness already committed.
    pub async fn close_witnessed_policy_renewal(
        &self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .close_witnessed_policy_renewal(operation, statement, original, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Release the same installation only after current target-policy and identity checks.
    /// None selects local protection, never fallback from required witness failure.
    pub async fn activate_policy_renewal(
        &self,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<JournalIdentity, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let anchor = match witness {
                Some(config) => Some(client(&mut op, original, config).await?),
                None => None,
            };
            let Some(State::Enrollment(owner)) = op.state.take() else {
                return Err(Error::State.into());
            };
            let mut active = match anchor {
                Some(anchor) => {
                    (*owner)
                        .activate_witnessed_policy_renewal(original, target, now, anchor)
                        .await?
                }
                None => {
                    (*owner)
                        .activate_policy_renewal(original, target, now)
                        .await?
                }
            };
            let journal = active.parts()?.0.stores()?.0.identity()?;
            op.state = Some(State::Active(active));
            Ok(journal)
        }
        .await;
        op.finish(result).await
    }
}
