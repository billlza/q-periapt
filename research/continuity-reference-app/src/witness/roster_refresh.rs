// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent approval of the original same-credential roster/head transition.
use super::*;
use crate::{
    enrollment::RootInfo,
    policy_publisher::PolicyInput,
    roster_refresh::{Outcome, Request},
};

/// Select these expectations through the trusted operator/account channel.
/// The request may supply signed predecessor evidence, never its own trust root,
/// selected target, immutable original subject or approved proposal binding.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterRefreshTrust {
    pub schema: String,
    pub account: RootInfo,
    pub device: [u8; 16],
    pub generation: u64,
    #[serde(with = "crate::enrollment::wire")]
    pub subject: Vec<u8>,
    pub proposal_binding: [u8; 32],
    pub policy: PolicyInput,
}
impl RosterRefreshTrust {
    fn inputs(
        &self,
        request: &Request,
        witness: &sdk::AnchorPin,
    ) -> Result<(
        sdk::AnchorRosterRefreshProposal,
        sdk::VerifiedDevice,
        sdk::AccountPin,
    )> {
        let proposal = request.as_proposal()?;
        if self.schema != "qperiapt-witness-roster-refresh-trust/1"
            || self.proposal_binding != request.binding
            || proposal.subject() != sdk::AnchorSubject::from_trusted_state(&self.subject)?
            || proposal.witness_binding() != witness.binding()
        {
            return Err("Roster proposal differs from independent operator approval".into());
        }
        let previous = request.previous(&self.account)?;
        if previous.device_id() != self.device || previous.generation() != self.generation {
            return Err("Roster credential differs from independently approved device".into());
        }
        Ok((proposal, previous, request.target_pin(&self.account)?))
    }
}

pub(super) fn prepare(
    store: &mut sdk::AnchorStore,
    trust: &RosterRefreshTrust,
    request: &Request,
    now: u64,
) -> Result<Outcome> {
    if trust.account.suspended {
        return Err("Selected roster account is suspended".into());
    }
    let witness = store.pin()?;
    let (proposal, previous, target_pin) = trust.inputs(request, &witness)?;
    let roster = trust
        .account
        .roster
        .as_ref()
        .ok_or("Explicit target roster required")?;
    let target = target_pin.verify_device(&request.certificate, &roster.bytes, now)?;
    let (policy, selected) =
        trust
            .policy
            .pins
            .verify(&trust.policy.materials, trust.account.family, now)?;
    if selected.as_ref().map(|p| p.binding()) != Some(witness.binding()) {
        return Err("Roster policy requires a different witness".into());
    }
    let state = store.prepare_roster_refresh(proposal, &previous, &target, &policy, now)?;
    #[cfg(test)]
    boundary("witness-roster-prepared")?;
    Ok(Outcome::new(request, state))
}

pub(super) fn close(
    store: &mut sdk::AnchorStore,
    trust: &RosterRefreshTrust,
    request: &Request,
) -> Result<Outcome> {
    let witness = store.pin()?;
    let (proposal, previous, target_pin) = trust.inputs(request, &witness)?;
    let roster = trust
        .account
        .roster
        .as_ref()
        .ok_or("Explicit target roster required")?;
    let target = target_pin.verify_historical_device(&request.certificate, &roster.bytes)?;
    let (policy, selected) = trust
        .policy
        .pins
        .verify_historical(&trust.policy.materials, trust.account.family)?;
    if selected.as_ref().map(|p| p.binding()) != Some(witness.binding()) {
        return Err("Historical roster policy requires a different witness".into());
    }
    let state = store.close_roster_refresh(proposal, &previous, &target, &policy)?;
    #[cfg(test)]
    boundary("witness-roster-closed")?;
    Ok(Outcome::new(request, state))
}
