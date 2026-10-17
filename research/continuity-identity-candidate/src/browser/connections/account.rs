// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{FanoutId, FanoutReconciliation, FanoutStatus};

impl BrowserDevice {
    /// Observe the next journal-bound ID without reserving input or permission.
    pub async fn next_account_message_id(&self) -> Result<FanoutId, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.next_account_message_id().await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Read original aggregate progress without releasing ciphertext.
    pub async fn account_message_status(&self, id: FanoutId) -> Result<FanoutStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.account_message_status(id).await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Read every original committed/accounted member; reserved work stays suspended.
    pub async fn reconcile_account_message(
        &self,
        id: FanoutId,
        sessions: &[exchange::Session],
    ) -> Result<FanoutReconciliation, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.reconcile_account_message(id, sessions).await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Retire only after all original members have authenticated or accounted outcomes.
    pub async fn retire_account_message(
        &self,
        id: FanoutId,
        sessions: &[exchange::Session],
    ) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.retire_account_message(id, sessions).await }.await;
        op.finish_failure(result.map_err(exchange_failure)).await
    }
    /// Commit the complete roster before one selected dispatch; retain the original input after failure.
    pub async fn deliver_account_member(
        &self,
        input: exchange::AccountSubmission<'_>,
        selected: usize,
        endpoint: &PeerEndpoint,
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<exchange::AccountDelivered, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut carrier = endpoint
            .carrier(self.cancellation.clone())
            .map_err(|e| failure(&DurableError::Io(e)))?;
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let result = async {
            op.active()?
                .deliver_account_member(input, selected, &mut carrier, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(clock.finish(result)).await
    }
}
