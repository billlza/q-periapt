// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential maintenance keeps original enrollment ownership and explicit outcomes.
use super::*;
use crate::{
    AnchorCredentialRenewalCancellation as CancellationRequest,
    AnchorCredentialRenewalProposal as Proposal, CredentialRenewalId, CredentialRenewalStatus,
    HistoricalSessionPolicy, VerifiedCredentialRenewal,
};

async fn client(
    op: &mut Operation<'_>,
    original: &HistoricalSessionPolicy,
    now: u64,
    config: (AnchorPin, Box<dyn AnchorTransport>, Duration),
) -> Result<AnchorClient, DurableError> {
    op.enrollment()?
        .credential_renewal_anchor_client(original, now, config.0, config.1, config.2)
        .await
}
impl BrowserDevice {
    /// Retained historical outcome, including Committed before remaining ACK cleanup.
    /// Only separate successful activation establishes current traffic authority.
    pub async fn credential_renewal_status(&self) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = match op.state.as_mut() {
            Some(State::Enrollment(owner)) => owner.credential_renewal_status(),
            Some(State::Active(owner)) => owner.credential_renewal_status(),
            None => Err(DurableError::Closed),
        };
        op.finish(result).await
    }
    /// Stage independently approved G under the caller-retained exact operation.
    /// Required witness still needs preparation/explicit commit before activation.
    pub async fn stage_credential_renewal(
        &self,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .stage_credential_renewal(grant, operation, policy, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Resolve an expired local target against the retained original journal history.
    pub async fn reconcile_expired_credential_renewal(
        &self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            if policy.historical().anchor_requirement().binding().is_some() {
                return Err(DurableError::AnchorRequired);
            }
            op.enrollment()?
                .reconcile_expired_credential_renewal(operation, statement, policy, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Seal original target once. Returned metadata requires independent witness approval.
    pub async fn prepare_witnessed_credential_renewal(
        &self,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<Proposal, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let anchor = client(&mut op, original, now, witness).await?;
            op.enrollment()?
                .prepare_witnessed_policy_continuation(original, policy, now, anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Restore only the original local proposal; absence is not remote non-commit.
    pub async fn recover_witnessed_credential_renewal_preparation(
        &self,
        original: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<Option<Proposal>, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .recover_witnessed_credential_renewal_preparation(original, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Close an unprepared staged target without inventing a sealed image.
    /// Returned cancellation still requires independent witness authorization.
    pub async fn prepare_witnessed_credential_cancellation(
        &self,
        original: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<CancellationRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .prepare_witnessed_credential_cancellation(original, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Commit an exact independently approved proposal under live current policy.
    pub async fn commit_witnessed_credential_renewal(
        &self,
        proposal: &Proposal,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, now, witness).await?;
            op.enrollment()?
                .commit_witnessed_policy_continuation(proposal, original, policy, now, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Recover original historical outcome, durably retain terminal, then ACK/clean up.
    pub async fn reconcile_witnessed_credential_renewal(
        &self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, now, witness).await?;
            op.enrollment()?
                .reconcile_witnessed_credential_renewal(
                    operation,
                    statement,
                    original,
                    now,
                    &mut anchor,
                )
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Explicit Close does not undo a Commit that the witness already applied.
    pub async fn close_witnessed_credential_renewal(
        &self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, now, witness).await?;
            op.enrollment()?
                .close_witnessed_credential_renewal(
                    operation,
                    statement,
                    original,
                    now,
                    &mut anchor,
                )
                .await
        }
        .await;
        op.finish(result).await
    }
}
