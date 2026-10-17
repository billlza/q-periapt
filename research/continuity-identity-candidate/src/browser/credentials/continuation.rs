// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Joint G/T maintenance through the existing original enrollment transaction.
use super::*;

impl BrowserDevice {
    /// Stage an independently double-approved target; never activates a service.
    pub async fn stage_policy_continuation(
        &self,
        grant: &VerifiedCredentialRenewal,
        continuation: &crate::VerifiedPolicyContinuation,
        operation: CredentialRenewalId,
        target: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .stage_policy_continuation(grant, continuation, operation, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }

    /// Local protection only. Required-witness targets use their exact proposal.
    pub async fn reconcile_policy_continuation(
        &self,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .reconcile_policy_continuation(original, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }

    /// Finish only the exact already-committed local target after policy expiry.
    /// Pending without a matching receipt stays suspended, never becomes NoCommit.
    pub async fn recover_historical_policy_continuation(
        &self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        original: &HistoricalSessionPolicy,
        target: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .recover_historical_policy_continuation(operation, statement, original, target, now)
                .await
        }
        .await;
        op.finish(result).await
    }

    /// Release the same installation after current-policy and exact G/T admission.
    /// None is local-only, never fallback from missing or failed required witness.
    pub async fn activate_policy_continuation(
        &self,
        original: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<JournalIdentity, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let anchor = match witness {
                Some(config) => Some(client(&mut op, original, now, config).await?),
                None => None,
            };
            let Some(State::Enrollment(owner)) = op.state.take() else {
                return Err(Error::State.into());
            };
            let mut active = match anchor {
                Some(anchor) => {
                    (*owner)
                        .activate_witnessed_policy_continuation(original, target, now, anchor)
                        .await?
                }
                None => {
                    (*owner)
                        .activate_policy_continuation(original, target, now)
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
