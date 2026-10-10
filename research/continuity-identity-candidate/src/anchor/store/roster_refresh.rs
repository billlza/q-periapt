// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Root-approved roster and exact journal head use one existing witness transaction.
use super::*;
use crate::anchor::roster_refresh::ROSTER_REFRESH_PROPOSAL_BYTES;
use crate::{
    AnchorRosterRefreshProposal as Proposal, AnchorRosterRefreshState as State,
    HistoricalSessionPolicy,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Applied,
    Closed,
}
impl Phase {
    fn state(self) -> State {
        match self {
            Self::Prepared => State::Prepared,
            Self::Applied => State::Applied,
            Self::Closed => State::Closed,
        }
    }
    fn outcome(self) -> AnchorOutcome {
        match self {
            Self::Prepared => AnchorOutcome::RosterPrepared,
            Self::Applied => AnchorOutcome::RosterApplied,
            Self::Closed => AnchorOutcome::RosterClosed,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    proposal: Proposal,
    previous_authority: [u8; 32],
    target_authority: [u8; 32],
    previous_validity: Validity,
    target_validity: Validity,
    policy_validity: Validity,
    phase: Phase,
}
#[derive(Default)]
pub(super) struct RosterRefresh {
    floor: u64,
    ack: Option<[u8; 32]>,
    record: Option<Record>,
}
impl RosterRefresh {
    pub(super) fn roster_floor(&self) -> u64 {
        self.floor.max(
            self.record
                .map_or(0, |r| r.proposal.scope().target.version()),
        )
    }
    pub(super) fn pending(&self) -> bool {
        self.record.is_some()
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.floor.to_be_bytes());
        out.push(u8::from(self.ack.is_some()));
        out.extend_from_slice(&self.ack.unwrap_or([0; 32]));
        match self.record {
            None => out.push(0),
            Some(r) => {
                out.push(match r.phase {
                    Phase::Prepared => 1,
                    Phase::Applied => 2,
                    Phase::Closed => 3,
                });
                out.extend_from_slice(&r.proposal.to_bytes());
                out.extend_from_slice(&r.previous_authority);
                out.extend_from_slice(&r.target_authority);
                r.previous_validity.encode(out);
                r.target_validity.encode(out);
                r.policy_validity.encode(out);
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let floor = d.u64()?;
        let flag = d.array::<1>()?;
        let value = d.array()?;
        let ack = match flag {
            [0] if value == [0; 32] => None,
            [1] => {
                nonzero(&value)?;
                Some(value)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let record = match d.array::<1>()? {
            [0] => None,
            [tag @ 1..=3] => Some(Record {
                proposal: Proposal::from_trusted_state(d.take(ROSTER_REFRESH_PROPOSAL_BYTES)?)?,
                previous_authority: d.array()?,
                target_authority: d.array()?,
                previous_validity: Validity::decode(d)?,
                target_validity: Validity::decode(d)?,
                policy_validity: Validity::decode(d)?,
                phase: match tag {
                    1 => Phase::Prepared,
                    2 => Phase::Applied,
                    3 => Phase::Closed,
                    _ => return Err(DurableError::Corrupt),
                },
            }),
            _ => return Err(DurableError::Corrupt),
        };
        Ok(Self { floor, ack, record })
    }
}
impl Entry {
    fn roster_policy_matches(&self, proposal: Proposal) -> bool {
        let scope = proposal.scope();
        match self.independent_policy.as_ref().and_then(|p| p.current) {
            None => {
                scope.policy_authorization.is_none() && scope.policy.digest() == self.subject.policy
            }
            Some(p) => {
                scope.policy == p.checkpoint && scope.policy_authorization == Some(p.statement)
            }
        }
    }
    pub(super) fn check_independent_roster(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        let Some(state) = &self.independent_roster else {
            return Ok(());
        };
        if self.renewal.is_some()
            || self.renewal_floor != 0
            || self.renewal_ack.is_some()
            || self.credential_authorization.is_some()
            || self.policy_authorization.is_some()
            || self.policy_floor != 0
            || self.credential_owner != self.subject.owner
            || state.floor == 1
            || state.floor == u64::MAX
            || (state.ack.is_some() && state.floor == 0)
            || (state.record.is_none() && state.floor == 0)
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(ack) = state.ack {
            nonzero(&ack)?;
        }
        if let Some(r) = state.record {
            let p = r.proposal;
            nonzero(&r.previous_authority)?;
            nonzero(&r.target_authority)?;
            if p.witness_binding() != pin.binding
                || p.subject() != self.subject
                || !self.roster_policy_matches(p)
                || r.previous_authority == r.target_authority
                || !r.policy_validity.contains(r.previous_validity)
                || !r.policy_validity.contains(r.target_validity)
                || self
                    .independent_policy
                    .as_ref()
                    .and_then(|s| s.current)
                    .is_some_and(|p| p.validity != r.policy_validity)
                || state.ack == Some(p.binding())
                || self
                    .independent_policy
                    .as_ref()
                    .is_some_and(PolicyRenewal::pending)
            {
                return Err(DurableError::Corrupt);
            }
            let valid = match r.phase {
                Phase::Prepared => {
                    self.head == p.expected_head()
                        && self.authority == r.previous_authority
                        && self.validity == r.previous_validity
                        && p.scope().target.version() > state.floor
                }
                Phase::Closed => {
                    self.head == p.expected_head()
                        && self.authority == r.previous_authority
                        && self.validity == r.previous_validity
                        && p.scope().target.version() == state.floor
                }
                Phase::Applied => {
                    self.head == p.target_head()
                        && self.authority == r.target_authority
                        && self.validity == r.target_validity
                        && p.scope().target.version() == state.floor
                        && self.last
                            == Some(command_id(
                                &pin.binding,
                                self.subject,
                                AnchorOperation::commit_roster_refresh(&p),
                            ))
                }
            };
            if !valid {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
    pub(super) fn handle_independent_roster(
        &mut self,
        request: &Incoming<'_>,
        now: u64,
    ) -> Result<(AnchorOutcome, bool), Error> {
        let binding = request.operation.roster_binding().ok_or(Error::State)?;
        let Some(state) = self.independent_roster.as_mut() else {
            return Ok((AnchorOutcome::RosterUnavailable, false));
        };
        if matches!(request.operation.0, Command::RosterAcknowledge(_))
            && state.ack == Some(binding)
        {
            return Ok((AnchorOutcome::RosterAcknowledged, false));
        }
        let Some(record) = state
            .record
            .as_mut()
            .filter(|r| r.proposal.binding() == binding)
        else {
            return Ok((AnchorOutcome::RosterUnavailable, false));
        };
        match request.operation.0 {
            Command::RosterStatus(_) => Ok((record.phase.outcome(), false)),
            Command::RosterCommit(_) if record.phase == Phase::Prepared => {
                record.target_validity.check(now)?;
                if self.head != record.proposal.expected_head()
                    || self.authority != record.previous_authority
                    || self.validity != record.previous_validity
                {
                    return Err(Error::Conflict);
                }
                self.head = record.proposal.target_head();
                self.authority = record.target_authority;
                self.validity = record.target_validity;
                self.last = Some(request.command);
                state.floor = record.proposal.scope().target.version();
                record.phase = Phase::Applied;
                Ok((AnchorOutcome::RosterApplied, true))
            }
            Command::RosterClose(_) if record.phase == Phase::Prepared => {
                state.floor = record.proposal.scope().target.version();
                record.phase = Phase::Closed;
                Ok((AnchorOutcome::RosterClosed, true))
            }
            Command::RosterCommit(_) | Command::RosterClose(_) => {
                Ok((record.phase.outcome(), false))
            }
            Command::RosterAcknowledge(_) if record.phase != Phase::Prepared => {
                state.ack = Some(binding);
                state.record = None;
                Ok((AnchorOutcome::RosterAcknowledged, true))
            }
            _ => Err(Error::State),
        }
    }
}
enum Admission<'a> {
    Prepare(&'a VerifiedSessionPolicy, u64),
    Close(&'a HistoricalSessionPolicy),
}
impl Admission<'_> {
    fn history(&self) -> &HistoricalSessionPolicy {
        match self {
            Self::Prepare(p, _) => p.historical(),
            Self::Close(p) => p,
        }
    }
}
impl AnchorStore {
    /// Independently admit the root-approved unchanged credential, exact actual
    /// roster/policy predecessor and original sealed head target. Preparation
    /// changes neither current head nor roster. Current scope excludes real G/T.
    pub fn prepare_roster_refresh(
        &mut self,
        proposal: Proposal,
        previous: &VerifiedDevice,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<State, DurableError> {
        self.retain_roster_refresh(proposal, previous, next, Admission::Prepare(policy, now))
    }
    /// Permanently close an exact independently root-approved roster/head target,
    /// even before preparation or after expiry. This grants no current authority.
    pub fn close_roster_refresh(
        &mut self,
        proposal: Proposal,
        previous: &VerifiedDevice,
        next: &VerifiedDevice,
        policy: &HistoricalSessionPolicy,
    ) -> Result<State, DurableError> {
        self.retain_roster_refresh(proposal, previous, next, Admission::Close(policy))
    }
    fn retain_roster_refresh(
        &mut self,
        proposal: Proposal,
        previous: &VerifiedDevice,
        next: &VerifiedDevice,
        admission: Admission<'_>,
    ) -> Result<State, DurableError> {
        let pin = self.pin()?;
        let policy = admission.history();
        let scope = *proposal.scope();
        let subject = proposal.subject();
        if proposal.witness_binding() != pin.binding
            || scope.policy != policy.checkpoint()
            || policy.anchor_requirement().binding() != Some(pin.binding)
            || storage_owner(previous) != subject.owner
            || storage_owner(next) != subject.owner
            || previous.account_id() != next.account_id()
            || previous.key != next.key
            || previous.authority_key != next.authority_key
            || previous.roster().checkpoint() != scope.previous
            || next.roster().checkpoint() != scope.target
            || !previous.roster().same_authority(next.roster())
            || previous.description.family != policy.family()
            || next.description.family != policy.family()
        {
            return Err(Error::Scope.into());
        }
        policy.check_external_signer(pin.public_key())?;
        if pin.public_key().shares_component(&next.key)
            || pin.public_key().shares_component(&next.authority_key)
        {
            return Err(Error::Scope.into());
        }
        let previous_validity = enrollment_interval(previous, policy.validity())?;
        let target_validity = enrollment_interval(next, policy.validity())?;
        let phase = match admission {
            Admission::Prepare(..) => Phase::Prepared,
            Admission::Close(_) => Phase::Closed,
        };
        let record = Record {
            proposal,
            previous_authority: previous.authority_binding(),
            target_authority: next.authority_binding(),
            previous_validity,
            target_validity,
            policy_validity: policy.validity(),
            phase,
        };
        let mut image = self.image()?;
        image.require_live(subject)?;
        let entry = image
            .entries
            .get_mut(&subject.id(&pin.binding))
            .ok_or(DurableError::Absent)?;
        if entry.subject != subject
            || entry.device != next.key
            || entry.credential_owner != subject.owner
            || entry.renewal.is_some()
            || entry.renewal_floor != 0
            || entry.renewal_ack.is_some()
            || entry.credential_authorization.is_some()
            || entry.policy_authorization.is_some()
            || entry.policy_floor != 0
            || !entry.roster_policy_matches(proposal)
            || entry
                .independent_policy
                .as_ref()
                .is_some_and(PolicyRenewal::pending)
        {
            return Err(DurableError::Conflict);
        }
        if let Some(retained) = entry.independent_roster.as_ref().and_then(|r| r.record) {
            if retained.proposal != proposal
                || retained.previous_authority != record.previous_authority
                || retained.target_authority != record.target_authority
                || retained.previous_validity != previous_validity
                || retained.target_validity != target_validity
                || retained.policy_validity != policy.validity()
            {
                return Err(DurableError::Conflict);
            }
            if phase == Phase::Closed && retained.phase == Phase::Prepared {
                let state = entry
                    .independent_roster
                    .as_mut()
                    .ok_or(DurableError::Corrupt)?;
                state.floor = scope.target.version();
                state.record = Some(Record {
                    phase: Phase::Closed,
                    ..retained
                });
                self.persist(&mut image)?;
                return Ok(State::Closed);
            }
            return Ok(retained.phase.state());
        }
        if entry.head != proposal.expected_head()
            || entry.authority != record.previous_authority
            || entry.validity != previous_validity
        {
            return Err(DurableError::Conflict);
        }
        let state = entry
            .independent_roster
            .get_or_insert_with(RosterRefresh::default);
        if scope.target.version() <= state.floor {
            return Err(Error::Retired.into());
        }
        if let Admission::Prepare(current, now) = admission {
            self.admit_current_device(next, current, now)?;
        }
        state.record = Some(record);
        if phase == Phase::Closed {
            state.floor = scope.target.version();
        }
        self.persist(&mut image)?;
        Ok(phase.state())
    }
}
#[cfg(all(test, unix))]
mod tests;
