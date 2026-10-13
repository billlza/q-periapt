// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment coordinates roster maintenance; it never releases a raw store.
use super::*;
use crate::{
    AnchorRosterRefreshProposal as Proposal, AnchorRosterRefreshState as WitnessState,
    HistoricalSessionPolicy, RosterCheckpoint, RosterRefreshId, RosterRefreshResolution,
    VerifiedDevice, WitnessedRosterRefreshProgress as Progress,
};

async fn client(
    op: &mut Operation<'_>,
    original: &HistoricalSessionPolicy,
    config: (AnchorPin, Box<dyn AnchorTransport>, Duration),
) -> Result<AnchorClient, DurableError> {
    op.enrollment()?
        .roster_refresh_anchor_client(original, config.0, config.1, config.2)
        .await
}
impl BrowserDevice {
    /// Accept an independently pinned signed head for an already known remote
    /// account. Local account updates must use the original enrollment workflow.
    /// An unknown result requires this same target and original device on retry;
    /// success reports the installed head, not which attempt first committed it.
    pub async fn admit_peer_roster(
        &self,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let service = op.active()?.parts()?.0;
            let roster = pin.verify_roster(roster, now)?;
            service.admit_peer_roster(&roster, policy, now).await
        }
        .await;
        op.finish(result).await
    }
    /// Retain a local-only roster target. Reopen the original device before
    /// maintenance; activation reconciles it afterwards. Required witness is refused.
    pub async fn refresh_local_roster(
        &self,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::EnrollmentStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            if policy.historical().anchor_requirement().binding().is_some() {
                return Err(DurableError::AnchorRequired);
            }
            op.enrollment()?
                .refresh_roster(previous, roster, pin, policy, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Recover local original history without inventing an uncommitted result.
    /// This resolver never substitutes for required-witness reconciliation.
    pub async fn resolve_local_roster_refresh(
        &self,
        previous: RosterCheckpoint,
        target: RosterCheckpoint,
        original: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<RosterRefreshResolution, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .resolve_roster_refresh(previous, target, original, now)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Authenticated original coordination, available before or after activation.
    /// Absence means no retained local operation, never remote non-commit.
    pub async fn witnessed_roster_refresh_progress(&self) -> Result<Option<Progress>, JsValue> {
        let mut op = self.operation()?;
        let result = match op.state.as_mut() {
            Some(State::Enrollment(owner)) => owner.witnessed_roster_refresh_progress(),
            Some(State::Active(owner)) => owner.witnessed_roster_refresh_progress(),
            None => Err(DurableError::Closed),
        };
        op.finish(result).await
    }
    /// Seal one independently approved target under the exact retained operation.
    /// The returned proposal still requires independent witness preparation.
    pub async fn prepare_witnessed_roster_refresh(
        &self,
        operation: RosterRefreshId,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        target: &VerifiedDevice,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<Proposal, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .prepare_witnessed_roster_refresh(operation, original, policy, target, now, anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Inspect original preparation after an unknown local result. None is local
    /// absence only; no new proposal or witness command is synthesized.
    pub async fn recover_witnessed_roster_refresh_preparation(
        &self,
        original: &HistoricalSessionPolicy,
    ) -> Result<Option<Proposal>, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .recover_witnessed_roster_refresh_preparation(original)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Abandon only an original staged intent which never released a proposal.
    /// Reserved operations require the witness Close/Status path instead.
    pub async fn abandon_unprepared_roster_refresh(
        &self,
        operation: RosterRefreshId,
        original: &HistoricalSessionPolicy,
    ) -> Result<Progress, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .abandon_unprepared_roster_refresh(operation, original)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Reconcile historical exact outcome, persist terminal, ACK and clean up.
    /// No live runtime is required and no new traffic authority is granted.
    pub async fn reconcile_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .reconcile_witnessed_roster_refresh(proposal, original, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Commit this independently witness-prepared target under live policy.
    /// Operational activation remains a separate current-authority check.
    pub async fn commit_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .commit_witnessed_roster_refresh(proposal, original, policy, now, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Request exact Close; a previously committed target remains Applied.
    /// Missing history never authorizes replacement or a non-commit claim.
    pub async fn close_witnessed_roster_refresh(
        &self,
        proposal: &Proposal,
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<WitnessState, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let mut anchor = client(&mut op, original, witness).await?;
            op.enrollment()?
                .close_witnessed_roster_refresh(proposal, original, &mut anchor)
                .await
        }
        .await;
        op.finish(result).await
    }
}
