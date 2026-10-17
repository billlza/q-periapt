// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Browser access to the original recoverable publication state machine.
use super::*;
use crate::{
    MonotonicInstant, PrekeyPublicationError, PrekeyPublicationId, PrekeyPublicationPlan,
    PrekeyPublicationRun, PrekeyPublicationStatus, PreparedPrekeyPublication,
};
use std::io;

fn publication_failure(error: PrekeyPublicationError) -> JsValue {
    match error {
        PrekeyPublicationError::Durable(error) => failure(&error),
        PrekeyPublicationError::Cancelled => failure(&DurableError::Io(io::Error::new(
            io::ErrorKind::Interrupted,
            "prekey publication cancelled; reconcile the original ID",
        ))),
        PrekeyPublicationError::Deadline => failure(&DurableError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "prekey publication deadline; reconcile the original ID",
        ))),
    }
}

impl BrowserDevice {
    /// Observe, without reserving, the next journal-bound publication identity.
    pub async fn next_publication_id(&self) -> Result<PrekeyPublicationId, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.next_prekey_publication_id().await }.await;
        op.finish(result).await
    }
    /// Read original local state. This establishes neither key usability nor delivery.
    pub async fn publication_status(
        &self,
        id: PrekeyPublicationId,
    ) -> Result<PrekeyPublicationStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.prekey_publication_status(id).await }.await;
        op.finish(result).await
    }
    /// Prepare/recover the complete original advertisement. The host's trusted
    /// clock is sampled at every shared-engine release boundary, not frozen at
    /// dispatch. It must return a u64 bigint and may throw to refuse clock access.
    pub async fn prepare_publication(
        &self,
        id: PrekeyPublicationId,
        plan: &PrekeyPublicationPlan,
        policy: &VerifiedSessionPolicy,
        timeout: Duration,
        clock: &js_sys::Function,
    ) -> Result<PreparedPrekeyPublication, JsValue> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(input_failure(
                js_sys::Error::new("invalid publication timeout").into(),
            ));
        }
        let deadline = MonotonicInstant::now()
            .checked_add(timeout)
            .ok_or_else(|| {
                input_failure(js_sys::Error::new("publication deadline overflow").into())
            })?;
        let mut op = self.operation()?;
        let mut clock_error = None;
        let result = async {
            op.active()?
                .prepare_prekey_publication(
                    id,
                    plan,
                    policy,
                    PrekeyPublicationRun {
                        cancel: &self.cancellation,
                        deadline,
                    },
                    || match clock.call0(&JsValue::UNDEFINED).and_then(u64::try_from) {
                        Ok(now) => Ok(now),
                        Err(cause) => {
                            clock_error = Some(cause);
                            Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "trusted clock failed",
                            ))
                        }
                    },
                )
                .await
        }
        .await;
        let result = match clock_error {
            Some(cause) => Err(Storage::input_failure("InvalidClock", &cause)),
            None => result.map_err(publication_failure),
        };
        op.finish_failure(result).await
    }
    /// Retire local public-artifact history; this does not revoke its inventory.
    pub async fn retire_publication(
        &self,
        id: PrekeyPublicationId,
        artifact: [u8; 32],
    ) -> Result<PrekeyPublicationStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.retire_prekey_publication(id, artifact).await }.await;
        op.finish(result).await
    }
    /// Abandon only the original reserved intent; reused keys remain independent.
    pub async fn abandon_publication(
        &self,
        id: PrekeyPublicationId,
        intent: [u8; 32],
        policy: &VerifiedSessionPolicy,
    ) -> Result<PrekeyPublicationStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.active()?
                .abandon_prekey_publication(id, intent, policy)
                .await
        }
        .await;
        op.finish(result).await
    }
}
