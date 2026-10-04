// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One exact joint head/credential transaction and a permanent retirement floor.
use super::*;
use crate::{
    AnchorCredentialRenewalProposal, AnchorCredentialRenewalState, VerifiedCredentialRenewal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Prepared,
    Applied,
    Closed,
}
impl Phase {
    fn outcome(self) -> AnchorOutcome {
        match self {
            Self::Prepared => AnchorOutcome::CredentialPrepared,
            Self::Applied => AnchorOutcome::CredentialApplied,
            Self::Closed => AnchorOutcome::CredentialClosed,
        }
    }
    fn state(self) -> AnchorCredentialRenewalState {
        match self {
            Self::Prepared => AnchorCredentialRenewalState::Prepared,
            Self::Applied => AnchorCredentialRenewalState::Applied,
            Self::Closed => AnchorCredentialRenewalState::Closed,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CredentialRenewalRecord {
    proposal: AnchorCredentialRenewalProposal,
    owner: [u8; 32],
    authority: [u8; 32],
    validity: Validity,
    version: u64,
    phase: Phase,
}
impl CredentialRenewalRecord {
    fn for_grant(
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
        phase: Phase,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            proposal,
            owner: storage_owner(grant.successor_device()),
            authority: grant.successor_device().authority_binding(),
            validity: enrollment_validity(grant.successor_device(), policy)?,
            version: grant.successor_device().roster().checkpoint().version(),
            phase,
        })
    }
    fn same_target(&self, other: &Self) -> bool {
        self.proposal == other.proposal
            && self.owner == other.owner
            && self.authority == other.authority
            && self.validity == other.validity
            && self.version == other.version
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.push(match self.phase {
            Phase::Prepared => 1,
            Phase::Applied => 2,
            Phase::Closed => 3,
        });
        out.extend_from_slice(&self.proposal.to_bytes());
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.authority);
        self.validity.encode(out);
        out.extend_from_slice(&self.version.to_be_bytes());
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Option<Self>, DurableError> {
        let phase = match d.array::<1>()? {
            [0] => return Ok(None),
            [1] => Phase::Prepared,
            [2] => Phase::Applied,
            [3] => Phase::Closed,
            _ => return Err(DurableError::Corrupt),
        };
        let proposal = AnchorCredentialRenewalProposal::from_trusted_state(d.take(296)?)?;
        let owner = d.array()?;
        nonzero(&owner)?;
        let authority = d.array()?;
        nonzero(&authority)?;
        let validity = Validity::decode(d)?;
        let version = d.u64()?;
        generation(version)?;
        if version <= 1 {
            return Err(DurableError::Corrupt);
        }
        Ok(Some(Self {
            proposal,
            owner,
            authority,
            validity,
            version,
            phase,
        }))
    }
}
impl Entry {
    pub(super) fn check_renewal_state(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if self.renewal_floor == 1
            || self.renewal_floor == u64::MAX
            || (self.renewal_ack.is_some() && self.renewal_floor == 0)
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(binding) = self.renewal_ack {
            nonzero(&binding)?;
        }
        if let Some(record) = &self.renewal {
            let proposal = &record.proposal;
            if proposal.witness != pin.binding
                || proposal.subject != self.subject
                || self.renewal_ack == Some(proposal.binding())
            {
                return Err(DurableError::Corrupt);
            }
            match record.phase {
                Phase::Prepared
                    if self.head == proposal.expected
                        && record.version > self.renewal_floor
                        && self.credential_owner != record.owner => {}
                Phase::Closed
                    if self.head == proposal.expected
                        && record.version == self.renewal_floor
                        && self.credential_owner != record.owner => {}
                Phase::Applied
                    if self.head == proposal.target
                        && record.version == self.renewal_floor
                        && self.credential_owner == record.owner
                        && self.authority == record.authority
                        && self.validity == record.validity
                        && self.last
                            == Some(command_id(
                                &pin.binding,
                                self.subject,
                                AnchorOperation::commit_credential_renewal(proposal),
                            )) => {}
                _ => return Err(DurableError::Corrupt),
            }
        }
        Ok(())
    }
    pub(super) fn handle_renewal(
        &mut self,
        request: &Incoming<'_>,
        now: u64,
    ) -> Result<(AnchorOutcome, bool), Error> {
        let binding = request.operation.credential_binding().ok_or(Error::State)?;
        if matches!(request.operation.0, Command::CredentialAcknowledge(_))
            && self.renewal_ack == Some(binding)
        {
            return Ok((AnchorOutcome::CredentialAcknowledged, false));
        }
        let Some(record) = self
            .renewal
            .as_mut()
            .filter(|r| r.proposal.binding() == binding)
        else {
            return Ok((AnchorOutcome::CredentialUnavailable, false));
        };
        match request.operation.0 {
            Command::CredentialStatus(_) => Ok((record.phase.outcome(), false)),
            Command::CredentialCommit(_) => match record.phase {
                Phase::Prepared => {
                    // The independently approved root continuation may replace
                    // an expired predecessor. Only the exact target must be live;
                    // historical exact applied recovery below is read-only.
                    record.validity.check(now)?;
                    if self.head != record.proposal.expected {
                        return Err(Error::Conflict);
                    }
                    self.head = record.proposal.target;
                    self.credential_owner = record.owner;
                    self.authority = record.authority;
                    self.validity = record.validity;
                    self.last = Some(request.command);
                    self.renewal_floor = record.version;
                    record.phase = Phase::Applied;
                    Ok((AnchorOutcome::CredentialApplied, true))
                }
                _ => Ok((record.phase.outcome(), false)),
            },
            Command::CredentialClose(_) => match record.phase {
                Phase::Prepared => {
                    self.renewal_floor = record.version;
                    record.phase = Phase::Closed;
                    Ok((AnchorOutcome::CredentialClosed, true))
                }
                _ => Ok((record.phase.outcome(), false)),
            },
            Command::CredentialAcknowledge(_) if record.phase != Phase::Prepared => {
                self.renewal_ack = Some(binding);
                self.renewal = None;
                Ok((AnchorOutcome::CredentialAcknowledged, true))
            }
            Command::CredentialAcknowledge(_) => Err(Error::State),
            _ => Err(Error::State),
        }
    }
}
impl AnchorStore {
    fn check_renewal_scope(
        &self,
        proposal: &AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
    ) -> Result<(), DurableError> {
        let pin = self.pin()?;
        let next = grant.successor_device();
        if proposal.witness != pin.binding
            || proposal.operation != grant.operation()
            || proposal.statement != grant.statement_digest()
            || proposal.subject.owner != grant.original_storage_owner()
            || proposal.subject.policy != grant.policy_digest()
            || proposal.subject.policy != policy.checkpoint().digest()
            || next.description.family != policy.family()
            || policy
                .anchor_requirement()
                .binding()
                .is_some_and(|b| b != pin.binding)
            || pin.key.shares_component(&next.key)
            || pin.key.shares_component(&next.authority_key)
        {
            return Err(Error::Scope.into());
        }
        policy.check_external_signer(&pin.key)?;
        policy.check_external_signer(&next.key)?;
        Ok(())
    }
    fn check_renewal_predecessor(
        entry: &Entry,
        proposal: &AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
    ) -> Result<(), DurableError> {
        let previous = grant.previous_device();
        if entry.subject != proposal.subject
            || entry.head != proposal.expected
            || entry.device != previous.key
            || entry.device != grant.successor_device().key
            || entry.credential_owner != storage_owner(previous)
            || entry.authority != previous.authority_binding()
            || entry.validity != enrollment_validity(previous, policy)?
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn retain_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
        now: Option<u64>,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.check_renewal_scope(&proposal, grant, policy)?;
        let phase = if now.is_some() {
            Phase::Prepared
        } else {
            Phase::Closed
        };
        let record = CredentialRenewalRecord::for_grant(proposal, grant, policy, phase)?;
        let id = proposal.subject.id(&self.pin()?.binding);
        let mut image = self.image()?;
        let entry = image.entries.get(&id).ok_or(DurableError::Absent)?;
        if let Some(saved) = &entry.renewal {
            if !saved.same_target(&record) {
                return Err(DurableError::Conflict);
            }
            if now.is_some() || saved.phase != Phase::Prepared {
                return Ok(saved.phase.state());
            }
            // The independent control plane may close the same preparation too.
        } else {
            if record.version <= entry.renewal_floor {
                return Err(Error::Retired.into());
            }
            Self::check_renewal_predecessor(entry, &proposal, grant, policy)?;
        }
        if let Some(now) = now {
            self.admit_current_device(grant.successor_device(), policy, now)?;
        }
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        if phase == Phase::Closed {
            entry.renewal_floor = record.version;
        }
        entry.renewal = Some(record);
        self.persist(&mut image)?;
        if let Some(now) = now {
            // Preserve committed preparation if this instance closes concurrently.
            self.admit_current_device(grant.successor_device(), policy, now)?;
        }
        Ok(phase.state())
    }
    /// Independently approve the exact protected-journal proposal and verified
    /// root grant. This retains one bounded preparation, without changing the
    /// head or credential. Device-signed commands cannot prepare a new grant.
    /// Reuse all original inputs after an unknown result. An exact retained
    /// terminal is historical readback; it does not grant current authority.
    pub fn prepare_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.retain_credential_renewal(proposal, grant, policy, Some(now))
    }
    /// Independently close one exact root-authorized target, including before
    /// preparation or after expiry. The operator must authenticate retained grant
    /// material and the original proposal; this grants no new credential authority.
    /// Applied is recovered as Applied, never relabelled Closed. Older/pruned
    /// targets are refused rather than classified as uncommitted.
    pub fn close_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        policy: &VerifiedSessionPolicy,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.retain_credential_renewal(proposal, grant, policy, None)
    }
}
