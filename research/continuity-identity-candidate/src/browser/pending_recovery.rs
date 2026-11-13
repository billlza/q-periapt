// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original pending write recovery under the existing asynchronous device owner.
use super::*;
use crate::{
    AnchorPendingWriteRecoveryProposal, HistoricalSessionPolicy, PendingWriteRecoveryRequest,
};

impl BrowserDevice {
    /// Inspect the original ordinary intent without replay or traffic permission.
    /// Persist the complete request before independently approving its effect.
    pub async fn pending_write_recovery_request(
        &self,
        original: &HistoricalSessionPolicy,
        pin: &AnchorPin,
    ) -> Result<PendingWriteRecoveryRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .pending_write_recovery_request(original, pin)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Confirm the exact retained target using a fresh signed Query, then apply
    /// only the original sealed image. An absent result is not non-commit.
    /// This preserves staged approvals and creates no live traffic owner.
    pub async fn confirm_pending_write_recovery(
        &self,
        approved: &AnchorPendingWriteRecoveryProposal,
        recorded_metadata: &[u8],
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .confirm_pending_write_recovery(
                    approved,
                    recorded_metadata,
                    original,
                    witness.0,
                    witness.1,
                    witness.2,
                )
                .await?;
            Ok(())
        }
        .await;
        op.finish(result).await
    }
}
