// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl BrowserDevice {
    /// Original local rekey metadata; this grants no new dispatch authority.
    pub async fn session_rekey_progress(
        &self,
        session: &exchange::Session,
    ) -> Result<crate::RekeyProgress, JsValue> {
        let mut op = self.operation()?;
        let value = async { op.active()?.session_rekey_progress(session).await }.await;
        op.finish_failure(value.map_err(exchange_failure)).await
    }

    /// Deliver one explicit target through a finite number of bounded exchanges.
    /// Success describes local completion, never remote receipt or PCS recovery.
    pub async fn drive_session_rekey(
        &self,
        session: &exchange::Session,
        target: u64,
        exchanges: u16,
        endpoint: &PeerEndpoint,
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<exchange::RekeyCompleted, JsValue> {
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
                .drive_session_rekey(session, target, exchanges, &mut carrier, &run, || {
                    clock.read()
                })
                .await
        }
        .await;
        op.finish_failure(clock.finish(result)).await
    }

    /// Authenticate one original-session control request. A completed receiver
    /// remains available for exact final/receipt replay after a lost response.
    pub async fn serve_session_control(
        &self,
        session: &exchange::Session,
        wire: &[u8],
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<Vec<u8>, JsValue> {
        let run = run(&self.cancellation, timeout)?;
        let mut clock = Clock {
            callback: clock,
            failure: None,
        };
        let mut op = self.operation()?;
        let value = async {
            op.active()?
                .serve_session_control(session, wire, &run, || clock.read())
                .await
        }
        .await;
        op.finish_failure(clock.finish(value)).await
    }
}
