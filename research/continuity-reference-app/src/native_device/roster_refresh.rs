// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Own-account R uses the original enrollment coordinator, including after G/P.
use super::*;
use crate::roster_refresh::{Outcome, Request};

pub struct RosterRefreshInputs<'a> {
    pub target: &'a RootInfo,
    pub original_policy: &'a sdk::HistoricalSessionPolicy,
    pub policy: &'a sdk::VerifiedSessionPolicy,
}
fn current_time(floor: u64) -> Result<u64> {
    let now = clock()?;
    if now < floor {
        return Err("Host time moved behind the roster invocation".into());
    }
    Ok(now)
}
impl NativeDevice {
    fn roster_history(&self, original: &sdk::HistoricalSessionPolicy) -> Result<()> {
        if original.family() != self.invitation.family
            || original.anchor_requirement() == sdk::AnchorRequirement::local_only()
        {
            return Err("Roster coordination requires the original witnessed policy".into());
        }
        Ok(())
    }
    fn roster_client(
        &mut self,
        original: &sdk::HistoricalSessionPolicy,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
    ) -> Result<sdk::AnchorClient> {
        self.roster_history(original)?;
        if original.anchor_requirement() != sdk::AnchorRequirement::required(&witness) {
            return Err("Roster witness differs from the original policy".into());
        }
        Ok(self.owner.roster_refresh_anchor_client(
            original,
            witness,
            Box::new(sdk::AnchorTcpTransport::new(endpoint)),
            Duration::from_secs(10),
        )?)
    }
    fn roster_target(
        &mut self,
        inputs: &RosterRefreshInputs<'_>,
        now: u64,
    ) -> Result<sdk::VerifiedDevice> {
        self.roster_history(inputs.original_policy)?;
        if inputs.target.suspended
            || inputs.policy.family() != self.invitation.family
            || inputs.policy.anchor_requirement() != inputs.original_policy.anchor_requirement()
        {
            return Err("Roster target policy or account authority differs".into());
        }
        let pin = self.pin(inputs.target)?;
        let roster = inputs
            .target
            .roster
            .as_ref()
            .ok_or("Explicit target roster required")?;
        let admission = self.owner.public_admission()?;
        Ok(pin.verify_device(admission.certificate(), &roster.bytes, now)?)
    }
    /// Prepare one sealed original target. The witness must independently approve
    /// the exported request; this returns no runtime or fresh traffic permission.
    pub fn prepare_roster_refresh(
        &mut self,
        operation: sdk::RosterRefreshId,
        inputs: &RosterRefreshInputs<'_>,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<Request> {
        let result = (|| {
            let target = self.roster_target(inputs, current_time(now)?)?;
            let previous = self.owner.public_admission()?;
            let client = self.roster_client(inputs.original_policy, witness, endpoint)?;
            let proposal = self.owner.prepare_witnessed_roster_refresh(
                operation,
                inputs.original_policy,
                inputs.policy,
                &target,
                current_time(now)?,
                client,
            )?;
            Request::from_owner(proposal, &previous)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn roster_refresh_status(&mut self) -> Result<Option<sdk::WitnessedRosterRefreshProgress>> {
        let result = self
            .owner
            .witnessed_roster_refresh_progress()
            .map_err(Into::into);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn original_roster_operation(&mut self, operation: sdk::RosterRefreshId) -> Result<()> {
        use sdk::WitnessedRosterRefreshProgress as P;
        let retained = match self.owner.witnessed_roster_refresh_progress()? {
            Some(P::Staged(s) | P::AbandonedBeforePreparation(s)) => s.operation,
            Some(P::Reserved(p) | P::Terminal { proposal: p, .. }) => p.scope().operation,
            None => return Err("No original roster intent is retained".into()),
        };
        if retained != operation {
            return Err("Original roster operation differs".into());
        }
        Ok(())
    }
    /// Recover an original sealed proposal without current permission or network
    /// mutation. None means no local proposal, never witness non-commit.
    pub fn recover_roster_refresh_preparation(
        &mut self,
        operation: sdk::RosterRefreshId,
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<Option<Request>> {
        let result = (|| {
            self.roster_history(original)?;
            self.original_roster_operation(operation)?;
            let previous = self.owner.public_admission()?;
            self.owner
                .recover_witnessed_roster_refresh_preparation(original)?
                .map(|p| Request::from_owner(p, &previous))
                .transpose()
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Abandon only an intent proven never to have released a sealed proposal.
    pub fn abandon_unprepared_roster_refresh(
        &mut self,
        operation: sdk::RosterRefreshId,
        original: &sdk::HistoricalSessionPolicy,
    ) -> Result<sdk::WitnessedRosterRefreshProgress> {
        let result = (|| {
            self.roster_history(original)?;
            Ok(self
                .owner
                .abandon_unprepared_roster_refresh(operation, original)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Commit only the retained request under independently current target inputs.
    /// Errors may follow commitment; reopen and observe the same request.
    pub fn commit_roster_refresh(
        &mut self,
        request: &Request,
        inputs: &RosterRefreshInputs<'_>,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
        now: u64,
    ) -> Result<Outcome> {
        let result = (|| {
            let proposal = request.as_proposal()?;
            let target = self.roster_target(inputs, current_time(now)?)?;
            request.target_pin(inputs.target)?;
            let previous = request.previous(inputs.target)?;
            if previous.device_id() != self.invitation.device
                || previous.generation() != self.invitation.generation
                || previous.credential_digest() != target.credential_digest()
                || proposal.scope().policy != inputs.policy.checkpoint()
            {
                return Err(
                    "Roster request differs from original identity or current policy".into(),
                );
            }
            let mut client = self.roster_client(inputs.original_policy, witness, endpoint)?;
            Ok(Outcome::new(
                request,
                self.owner.commit_witnessed_roster_refresh(
                    &proposal,
                    inputs.original_policy,
                    inputs.policy,
                    current_time(now)?,
                    &mut client,
                )?,
            ))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Reconcile exact history, including after target expiry; no new Commit.
    pub fn observe_roster_refresh(
        &mut self,
        request: &Request,
        original: &sdk::HistoricalSessionPolicy,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
    ) -> Result<Outcome> {
        let result = (|| {
            let proposal = request.as_proposal()?;
            let mut client = self.roster_client(original, witness, endpoint)?;
            Ok(Outcome::new(
                request,
                self.owner
                    .reconcile_witnessed_roster_refresh(&proposal, original, &mut client)?,
            ))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Close the exact original target; an already committed result remains Applied.
    pub fn close_roster_refresh(
        &mut self,
        request: &Request,
        original: &sdk::HistoricalSessionPolicy,
        witness: sdk::AnchorPin,
        endpoint: SocketAddr,
    ) -> Result<Outcome> {
        let result = (|| {
            let proposal = request.as_proposal()?;
            let mut client = self.roster_client(original, witness, endpoint)?;
            Ok(Outcome::new(
                request,
                self.owner
                    .close_witnessed_roster_refresh(&proposal, original, &mut client)?,
            ))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
