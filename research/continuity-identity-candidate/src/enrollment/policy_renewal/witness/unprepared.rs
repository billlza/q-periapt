// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Abandon only a staged approval that never released a sealed P proposal.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Retire an exact local P approval only before proposal release. Holds the
    /// original service lease and authenticates the journal's absence of any
    /// sealed P target. A returned observation is local abandonment, never a
    /// witness Closed or no-commit reply. Reserved/terminal proposals must use
    /// their existing signed reconciliation, even when history is unavailable.
    ///
    /// Requires neither a live target nor a private signer and sends no request.
    /// An uncertain save is recovered by repeating this exact operation and
    /// statement or reading progress. Original keys, journal and previous P/G/R
    /// completion remain intact; no runtime owner is returned.
    pub async fn abandon_unprepared_policy_renewal(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<WitnessedPolicyRenewalProgress, DurableError> {
        let result = self
            .abandon_unprepared_policy_renewal_attempt(operation, statement, original_policy)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn abandon_unprepared_policy_renewal_attempt(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<WitnessedPolicyRenewalProgress, DurableError> {
        let mut image = self.image()?;
        let (original, id) = self.policy_witness_scope(&image, original_policy)?;
        let w = image
            .policy_witness
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        if w.coordination.is_some() {
            return Err(DurableError::Conflict);
        }
        let record = w
            .closed
            .as_ref()
            .or(image.policy_pending.as_ref())
            .ok_or(DurableError::Conflict)?;
        if record.operation != operation || record.statement != statement {
            return Err(DurableError::Conflict);
        }
        let expected = WitnessedPolicyRenewalProgress::AbandonedBeforePreparation {
            operation,
            statement,
            target: record.target,
        };
        if w.abandoned_before_preparation() {
            return Ok(expected);
        }
        let lease = self.witness_lease(&original, original_policy, id).await?;
        if self
            .inspect_original_policy_preparation(&original, original_policy, id)
            .await?
            .is_some()
        {
            return Err(DurableError::Suspended);
        }
        let record = image.policy_pending.take().ok_or(DurableError::Corrupt)?;
        image
            .policy_witness
            .as_mut()
            .ok_or(DurableError::Corrupt)?
            .closed = Some(record);
        #[cfg(all(test, unix))]
        super::super::super::tests::renewal::boundary("independent-policy-unprepared-before-save");
        self.save(&image)?;
        #[cfg(all(test, unix))]
        super::super::super::tests::renewal::boundary("independent-policy-unprepared-after-save");
        if self.witnessed_policy_renewal_progress()? != Some(expected) {
            return Err(DurableError::Conflict);
        }
        drop(lease);
        Ok(expected)
    }
}
