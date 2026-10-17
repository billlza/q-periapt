// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original-enrollment transition into cleanup with the existing browser lease.
use super::*;
use crate::{
    FanoutAbandonment, FanoutAbandonmentId, FanoutId, FanoutReconciliation, FanoutStatus,
    HistoricalSessionPolicy, SessionClosure, SessionClosureId, SessionClosureStatus,
};

enum Target {
    Account(FanoutId),
    Session([u8; 32]),
}
impl BrowserDevice {
    /// Consume original enrollment access into complete-account recovery. No
    /// current policy/runtime is needed and no recipient subset is accepted.
    pub async fn recover_account(
        &self,
        operation: FanoutId,
        original_policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<(), JsValue> {
        self.recover(Target::Account(operation), original_policy, witness)
            .await
    }
    /// Select an original archived session for explicit loss accounting only.
    /// A reserved aggregate cannot be split through this independent flow.
    pub async fn recover_session(
        &self,
        session: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<(), JsValue> {
        self.recover(Target::Session(session), original_policy, witness)
            .await
    }
    async fn recover(
        &self,
        target: Target,
        original_policy: &HistoricalSessionPolicy,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let Some(State::Enrollment(owner)) = op.state.take() else {
                return Err(Error::State.into());
            };
            let owner = match target {
                Target::Account(id) => {
                    (*owner)
                        .recover_account(id, original_policy, witness)
                        .await?
                }
                Target::Session(id) => {
                    (*owner)
                        .recover_session(id, original_policy, witness)
                        .await?
                }
            };
            op.state = Some(State::Recovery(Box::new(owner)));
            Ok(())
        }
        .await;
        op.finish(result).await
    }
    /// Read the selected original batch's retained phase without traffic authority.
    pub async fn recovered_account_status(&self) -> Result<(FanoutId, FanoutStatus), JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let owner = op.recovery()?.account()?;
            Ok((owner.operation_id(), owner.status().await?))
        }
        .await;
        op.finish(result).await
    }
    /// Return every original committed/accounted member, without ciphertext release.
    pub async fn recovered_account_members(&self) -> Result<FanoutReconciliation, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.account()?.reconcile_members().await }.await;
        op.finish(result).await
    }
    /// Freeze all reserved member sessions and return the complete loss report.
    pub async fn begin_account_abandonment(&self) -> Result<FanoutAbandonment, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.account()?.begin().await }.await;
        op.finish(result).await
    }
    /// Acknowledge only after the host has durably accounted for the complete report.
    pub async fn acknowledge_account_abandonment(
        &self,
        id: FanoutAbandonmentId,
    ) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.account()?.acknowledge(id).await }.await;
        op.finish(result).await
    }
    /// Retire aggregate metadata only after every original member is accounted.
    pub async fn retire_recovered_account(&self) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.account()?.retire_metadata().await }.await;
        op.finish(result).await
    }
    /// Observe the selected original session's permanent closure progress.
    pub async fn recovered_session_status(&self) -> Result<SessionClosureStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.session()?.status().await }.await;
        op.finish(result).await
    }
    /// Freeze one independent session and return every retained unknown/lost outcome.
    pub async fn begin_session_closure(&self) -> Result<SessionClosure, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.session()?.begin().await }.await;
        op.finish(result).await
    }
    /// Acknowledge the complete host-accounted report; this never confirms delivery.
    pub async fn acknowledge_session_closure(&self, id: SessionClosureId) -> Result<(), JsValue> {
        let mut op = self.operation()?;
        let result = async { op.recovery()?.session()?.acknowledge(id).await }.await;
        op.finish(result).await
    }
}
