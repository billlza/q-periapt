// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent policy transaction in the existing witness image and commit.
use super::*;
use crate::{
    AnchorPolicyRenewalProposal as Proposal, AnchorPolicyRenewalState as State,
    HistoricalPolicyRenewal, HistoricalPolicyRenewalMaterials, PolicyRenewalMaterials,
    VerifiedPolicyRenewal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
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
            Self::Prepared => AnchorOutcome::PolicyPrepared,
            Self::Applied => AnchorOutcome::PolicyApplied,
            Self::Closed => AnchorOutcome::PolicyClosed,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    proposal: Proposal,
    policy: PolicyAuthority,
    validity: Validity,
    phase: Phase,
}
/// Separate metadata prevents policy statements from being interpreted as G/T.
#[derive(Default)]
pub(super) struct PolicyRenewal {
    pub(super) current: Option<PolicyAuthority>,
    // Sticky format discriminator: later G must never erase independently adopted P.
    pub(super) credential_after: bool,
    floor: u64,
    ack: Option<[u8; 32]>,
    record: Option<Record>,
}
impl PolicyRenewal {
    pub(super) fn pending(&self) -> bool {
        self.record.is_some()
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.floor.to_be_bytes());
        out.push(u8::from(self.ack.is_some()));
        out.extend_from_slice(&self.ack.unwrap_or([0; 32]));
        match self.current {
            None => out.push(0),
            Some(p) => {
                out.push(if self.credential_after { 2 } else { 1 });
                p.encode(out);
            }
        }
        match self.record {
            None => out.push(0),
            Some(r) => {
                out.push(match r.phase {
                    Phase::Prepared => 1,
                    Phase::Applied => 2,
                    Phase::Closed => 3,
                });
                out.extend_from_slice(&r.proposal.to_bytes());
                r.policy.encode(out);
                r.validity.encode(out);
            }
        }
    }
    pub(super) fn decode(
        d: &mut Decoder<'_>,
        credential_format: bool,
    ) -> Result<Self, DurableError> {
        let floor = d.u64()?;
        let present = d.array::<1>()?;
        let value = d.array()?;
        let ack = match (present, value) {
            ([0], v) if v == [0; 32] => None,
            ([1], v) => {
                nonzero(&v)?;
                Some(v)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let (current, credential_after) = match d.array::<1>()? {
            [0] => (None, false),
            [1] => (Some(PolicyAuthority::decode(d)?), false),
            [2] if credential_format => (Some(PolicyAuthority::decode(d)?), true),
            _ => return Err(DurableError::Corrupt),
        };
        let record = match d.array::<1>()? {
            [0] => None,
            [tag @ 1..=3] => Some(Record {
                proposal: Proposal::from_trusted_state(d.take(296)?)?,
                policy: PolicyAuthority::decode(d)?,
                validity: Validity::decode(d)?,
                phase: match tag {
                    1 => Phase::Prepared,
                    2 => Phase::Applied,
                    3 => Phase::Closed,
                    _ => return Err(DurableError::Corrupt),
                },
            }),
            _ => return Err(DurableError::Corrupt),
        };
        Ok(Self {
            current,
            credential_after,
            floor,
            ack,
            record,
        })
    }
}
impl Entry {
    pub(super) fn has_credential_policy_composition(&self) -> bool {
        self.independent_policy.is_some()
            && (self.renewal_floor != 0
                || self.renewal.is_some()
                || self.renewal_ack.is_some()
                || self.credential_owner != self.subject.owner)
    }
    pub(super) fn check_independent_policy(
        &self,
        pin: &impl ImageAuthority,
    ) -> Result<(), DurableError> {
        let Some(s) = &self.independent_policy else {
            return Ok(());
        };
        // Only an exact retained-P G may coexist with an acknowledged P.
        if (self.renewal.is_some()
            && (!s.credential_after
                || s.record.is_some()
                || self
                    .renewal
                    .as_ref()
                    .and_then(CredentialRenewalRecord::independent_policy)
                    != s.current.map(|p| p.statement)))
            || (s.credential_after
                && (s.current.is_none() || (self.renewal_floor == 0 && self.renewal.is_none())))
            || self.credential_authorization.is_some()
            || self.policy_authorization.is_some()
            || self.policy_floor != 0
            || s.floor == 1
            || s.floor == u64::MAX
            || (s.ack.is_some() && s.floor == 0)
            || (s.current.is_none() && s.record.is_none() && s.floor == 0)
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(ack) = s.ack {
            nonzero(&ack)?;
        }
        if let Some(p) = s.current {
            if p.checkpoint.version() > s.floor
                || p.checkpoint.version() <= 1
                || !p.validity.contains(self.validity)
            {
                return Err(DurableError::Corrupt);
            }
        }
        if let Some(r) = s.record {
            let p = r.proposal;
            pin.resolve(p.witness_binding())?;
            if p.subject() != self.subject
                || p.statement() != r.policy.statement
                || !r.policy.validity.contains(r.validity)
                || r.policy.checkpoint.version() <= 1
                || s.ack == Some(p.binding())
            {
                return Err(DurableError::Corrupt);
            }
            let successor = s
                .current
                .is_none_or(|old| old.checkpoint.version() < r.policy.checkpoint.version());
            let valid = match r.phase {
                Phase::Prepared => {
                    self.head == p.expected_head()
                        && r.policy.checkpoint.version() > s.floor
                        && successor
                }
                Phase::Closed => {
                    self.head == p.expected_head()
                        && r.policy.checkpoint.version() == s.floor
                        && successor
                }
                Phase::Applied => {
                    self.head == p.target_head()
                        && r.policy.checkpoint.version() == s.floor
                        && s.current == Some(r.policy)
                        && self.validity == r.validity
                        && self.last
                            == Some(command_id(
                                &p.witness_binding(),
                                self.subject,
                                AnchorOperation::commit_policy_renewal(&p),
                            ))
                }
            };
            if !valid {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
    pub(super) fn handle_independent_policy(
        &mut self,
        request: &Incoming<'_>,
        now: u64,
    ) -> Result<(AnchorOutcome, bool), Error> {
        let binding = request.operation.policy_binding().ok_or(Error::State)?;
        let Some(state) = self.independent_policy.as_mut() else {
            return Ok((AnchorOutcome::PolicyUnavailable, false));
        };
        if matches!(request.operation.0, Command::PolicyAcknowledge(_))
            && state.ack == Some(binding)
        {
            return Ok((AnchorOutcome::PolicyAcknowledged, false));
        }
        let Some(r) = state
            .record
            .as_mut()
            .filter(|r| r.proposal.binding() == binding)
        else {
            return Ok((AnchorOutcome::PolicyUnavailable, false));
        };
        match request.operation.0 {
            Command::PolicyStatus(_) => Ok((r.phase.outcome(), false)),
            Command::PolicyCommit(_) if r.phase == Phase::Prepared => {
                r.validity.check(now)?;
                if self.head != r.proposal.expected_head() {
                    return Err(Error::Conflict);
                }
                self.head = r.proposal.target_head();
                self.last = Some(request.command);
                self.validity = r.validity;
                state.current = Some(r.policy);
                state.floor = r.policy.checkpoint.version();
                r.phase = Phase::Applied;
                Ok((AnchorOutcome::PolicyApplied, true))
            }
            Command::PolicyClose(_) if r.phase == Phase::Prepared => {
                state.floor = r.policy.checkpoint.version();
                r.phase = Phase::Closed;
                Ok((AnchorOutcome::PolicyClosed, true))
            }
            Command::PolicyCommit(_) | Command::PolicyClose(_) => Ok((r.phase.outcome(), false)),
            Command::PolicyAcknowledge(_) if r.phase != Phase::Prepared => {
                state.ack = Some(binding);
                state.record = None;
                Ok((AnchorOutcome::PolicyAcknowledged, true))
            }
            _ => Err(Error::State),
        }
    }
}
impl AnchorStore {
    /// Independently prepare an exact same-credential policy-only target.
    /// Reverify both roots against caller-pinned materials and the actual witness
    /// predecessor. This reserves one transaction, grants no operational owner,
    /// and does not fabricate a credential renewal or advance the roster.
    /// An already retired plain credential renewal is retained; joint continuation
    /// and unfinished credential coordination remain separate.
    pub fn prepare_policy_renewal(
        &mut self,
        proposal: Proposal,
        approval: &VerifiedPolicyRenewal,
        materials: &PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<State, DurableError> {
        let verified = VerifiedPolicyRenewal::from_bytes(
            approval.as_bytes(),
            approval.scope(),
            materials,
            now,
        )?;
        self.retain_policy_renewal(
            proposal,
            &verified.historical(),
            &materials.historical(),
            Phase::Prepared,
        )
    }
    /// Independently close an exact target before preparation. Historical signed
    /// materials confer no current permission; the durable floor prevents revival.
    /// A matching applied target remains Applied. Missing history is not Closed.
    pub fn close_policy_renewal(
        &mut self,
        proposal: Proposal,
        approval: &HistoricalPolicyRenewal,
        materials: &HistoricalPolicyRenewalMaterials<'_>,
    ) -> Result<State, DurableError> {
        self.retain_policy_renewal(proposal, approval, materials, Phase::Closed)
    }
    fn retain_policy_renewal(
        &mut self,
        proposal: Proposal,
        approval: &HistoricalPolicyRenewal,
        m: &HistoricalPolicyRenewalMaterials<'_>,
        phase: Phase,
    ) -> Result<State, DurableError> {
        let scope = super::transferred_control::Scope::original(self, proposal.subject())?;
        self.retain_policy_renewal_controlled(
            scope.bind(proposal, proposal.subject())?,
            approval,
            m,
            phase,
        )
    }
    pub(super) fn retain_policy_renewal_controlled(
        &mut self,
        controlled: super::transferred_control::Proposal<Proposal>,
        approval: &HistoricalPolicyRenewal,
        m: &HistoricalPolicyRenewalMaterials<'_>,
        phase: Phase,
    ) -> Result<State, DurableError> {
        let super::transferred_control::Proposal {
            scope: control,
            value: proposal,
        } = controlled;
        let verified =
            HistoricalPolicyRenewal::from_bytes(approval.as_bytes(), approval.scope(), m)?;
        let pin = &control.logical;
        let scope = verified.scope();
        let current = m.current_device;
        control.check_keys(current, m.original)?;
        control.check_keys(current, m.target)?;
        if proposal.witness_binding() != pin.binding
            || proposal.operation() != scope.operation
            || proposal.statement() != verified.statement_digest()
            || proposal.subject()
                != AnchorSubject::for_device(scope.journal, m.original_device, m.original)?
            || m.original.anchor_requirement().binding() != Some(pin.binding)
            || pin.key.shares_component(&current.key)
            || pin.key.shares_component(&current.authority_key)
        {
            return Err(Error::Scope.into());
        }
        m.target.check_external_signer(&pin.key)?;
        let target = PolicyAuthority {
            statement: verified.statement_digest(),
            checkpoint: verified.target_policy(),
            validity: m.target.validity(),
        };
        let record = Record {
            proposal,
            policy: target,
            validity: enrollment_interval(current, m.target.validity())?,
            phase,
        };
        let mut image = self.image()?;
        control.live(self, &image)?;
        let entry = image
            .entries
            .get_mut(&proposal.subject().id(&self.namespace()?))
            .ok_or(DurableError::Absent)?;
        if entry
            .independent_roster
            .as_ref()
            .is_some_and(RosterRefresh::pending)
            || entry.renewal.is_some()
            || entry.credential_authorization.is_some()
            || entry.policy_authorization.is_some()
            || entry.policy_floor != 0
        {
            return Err(DurableError::Conflict);
        }
        if entry.subject != proposal.subject()
            || entry.device != current.key
            || entry.credential_owner != storage_owner(current)
            || entry.authority != current.authority_binding()
        {
            return Err(DurableError::Conflict);
        }
        if let Some(prior) = entry.independent_policy.as_ref().and_then(|s| s.record) {
            if prior.proposal != proposal
                || prior.policy != record.policy
                || prior.validity != record.validity
            {
                return Err(DurableError::Conflict);
            }
            if phase == Phase::Closed && prior.phase == Phase::Prepared {
                let state = entry
                    .independent_policy
                    .as_mut()
                    .ok_or(DurableError::Corrupt)?;
                state.record = Some(record);
                state.floor = target.checkpoint.version();
                self.persist(&mut image)?;
                return Ok(State::Closed);
            }
            return Ok(prior.phase.state());
        }
        let state = entry.independent_policy.as_ref();
        if state.is_some_and(|s| target.checkpoint.version() <= s.floor) {
            return Err(Error::Retired.into());
        }
        let predecessor = state.and_then(|s| s.current);
        let exact = match predecessor {
            None => {
                scope.previous_policy == scope.original_policy
                    && scope.previous_authorization.is_none()
            }
            Some(p) => {
                scope.previous_policy == p.checkpoint
                    && scope.previous_authorization == Some(p.statement)
                    && m.previous.validity() == p.validity
            }
        };
        if !exact
            || entry.head != proposal.expected_head()
            || entry.validity != enrollment_interval(current, m.previous.validity())?
        {
            return Err(DurableError::Conflict);
        }
        let state = entry
            .independent_policy
            .get_or_insert_with(PolicyRenewal::default);
        state.record = Some(record);
        if phase == Phase::Closed {
            state.floor = target.checkpoint.version();
        }
        self.persist(&mut image)?;
        Ok(phase.state())
    }
}

#[cfg(all(test, unix))]
pub(super) mod tests;
