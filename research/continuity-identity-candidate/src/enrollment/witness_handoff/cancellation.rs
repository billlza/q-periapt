// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Target-free local cleanup under an independently retained Witness plan.
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceEnrollment {
    /// Reserve the original staged grant after a completed Witness adoption.
    /// The independent plan and both durable selections are required, including
    /// after expiry. This loads no device signer, sends no RPC, creates no target
    /// image and grants no traffic authority. Keep the exact cancellation for
    /// independent target approval; reconciliation still uses the original signer.
    pub async fn prepare_witnessed_credential_cancellation_with_witness_plan(
        &mut self,
        policy: &impl AsRef<HistoricalSessionPolicy>,
        plan: WitnessJournalAdoptionPlan,
        now: u64,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        let mut attempt = Attempt {
            owner: self,
            success: false,
        };
        let result = attempt
            .owner
            .prepare_witnessed_credential_cancellation_attempt(policy.as_ref(), now, Some(&plan))
            .await;
        attempt.success = result.is_ok();
        result
    }

    pub(in crate::enrollment) async fn selected_cancellation_journal(
        &mut self,
        policy: &HistoricalSessionPolicy,
        plan: WitnessJournalAdoptionPlan,
    ) -> Result<WitnessJournalAdoption, DurableError> {
        let image = self.image()?;
        self.witness_handoff_scope(&image, policy, &plan)?;
        let selected = self.witness_selection()?.ok_or(DurableError::Absent)?;
        selected.check_plan(&plan)?;
        if selected.receipt.is_none() {
            return Err(DurableError::Suspended);
        }
        let db = self
            .storage
            .open_database(self.paths.installation.files()[1])
            .await?;
        let child = WitnessJournalAdoption::resume_in_database(db, self.key().await?, plan)?;
        selected.check_child(&child.enrollment_selection()?)?;
        Ok(child)
    }
}
