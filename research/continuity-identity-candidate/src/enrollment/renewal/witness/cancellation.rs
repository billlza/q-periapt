// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original target-free cancellation and exact selected-journal reservation.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Reserve an original staged grant for independent cancellation without
    /// sealing a target or dispatching a witness command. The returned descriptor
    /// must be approved through the independent witness control plane. Ordinary
    /// journal work remains suspended until Closed is durably retained and ACKed.
    /// Historical policy suffices; this does not grant current device authority.
    pub async fn prepare_witnessed_credential_cancellation(
        &mut self,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        let result = self
            .prepare_witnessed_credential_cancellation_attempt(policy.as_ref(), now, None)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(in crate::enrollment) async fn prepare_witnessed_credential_cancellation_attempt(
        &mut self,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
        plan: Option<&crate::WitnessJournalAdoptionPlan>,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        let image = self.image_for_witnessed_credential()?;
        let (original, id) = self.witness_cancellation_scope(&image, policy, now)?;
        if let Some(plan) = plan {
            self.selected_cancellation_journal(policy, plan.clone())
                .await?
                .close();
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        if let Some(coord) = renewal.witness.as_ref().and_then(|w| w.coordination) {
            match coord.intent {
                WitnessedCredentialIntent::Cancellation(c) if coord.terminal.is_some() => {
                    return Ok(c)
                }
                WitnessedCredentialIntent::Cancellation(_) => {}
                WitnessedCredentialIntent::Proposal(_) => return Err(DurableError::Conflict),
            }
        }
        let grant = self.pending_grant(&image, &original, policy)?;
        let pending = renewal.pending.as_ref().ok_or(DurableError::Conflict)?;
        let continuation = pending
            .continuation
            .as_deref()
            .or(renewal.adopted_policy.as_deref())
            .map(|bytes| self.retained_policy(bytes))
            .transpose()?;
        let _lease = self.witness_lease(&original, policy, id).await?;
        // A retained coordination must never be re-created against a changed
        // head after local record loss. Inspect and compare before reserving.
        if let Some(coord) = renewal.witness.as_ref().and_then(|w| w.coordination) {
            let retained = if let Some(plan) = plan {
                self.selected_cancellation_journal(policy, plan.clone())
                    .await?
                    .credential_cancellation_intent(&original, policy, id)?
            } else {
                self.inspect_original_credential_intent(&original, policy, id)
                    .await?
            };
            if retained != Some(coord.intent) {
                return Err(DurableError::Conflict);
            }
        }
        let independent = if image.policy_completed.is_some() {
            self.policy_enrollment_completion(&image, policy)?
        } else {
            None
        };
        let cancellation = self
            .reserve_original_credential_cancellation(
                &original,
                policy,
                id,
                crate::durable::CredentialCancellationTarget {
                    grant: grant.historical(),
                    continuation: continuation.as_ref(),
                    adopts: pending.continuation.is_some(),
                    completed: renewal.completed.as_ref(),
                    independent: independent.as_deref(),
                },
                plan,
            )
            .await?;
        self.check_witnessed_pending(
            &image,
            &original,
            &grant,
            WitnessedCredentialIntent::Cancellation(cancellation),
        )?;
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("cancellation-reserved");
        self.retain_witnessed_preparation(
            image,
            policy,
            now,
            WitnessedCredentialIntent::Cancellation(cancellation),
        )
        .await?;
        Ok(cancellation)
    }
}
