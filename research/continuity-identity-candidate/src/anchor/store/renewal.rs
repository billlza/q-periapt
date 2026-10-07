// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One exact joint head/credential transaction and a permanent retirement floor.
use super::*;
use crate::{
    AnchorCredentialCancellationState, AnchorCredentialRenewalCancellation,
    AnchorCredentialRenewalProposal, AnchorCredentialRenewalState, HistoricalCredentialRenewal,
    HistoricalSessionPolicy, VerifiedCredentialRenewal,
};

// Authenticated witness control-plane metadata, independent of the latest G
// and of the bounded transaction/ACK slot. It is not a client runtime owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PolicyAuthority {
    pub(super) statement: [u8; 32],
    pub(super) checkpoint: crate::PolicyCheckpoint,
    pub(super) validity: Validity,
}
impl PolicyAuthority {
    pub(super) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.statement);
        out.extend_from_slice(&self.checkpoint.version().to_be_bytes());
        out.extend_from_slice(&self.checkpoint.digest());
        self.validity.encode(out);
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let statement = d.array()?;
        nonzero(&statement)?;
        let checkpoint = crate::PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let validity = Validity::decode(d)?;
        Ok(Self {
            statement,
            checkpoint,
            validity,
        })
    }
}

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
pub(super) struct JointRenewalRecord {
    proposal: Box<AnchorCredentialRenewalProposal>,
    owner: [u8; 32],
    authority: [u8; 32],
    validity: Validity,
    version: u64,
    phase: Phase,
    policy: Option<PolicyAuthority>,
}
impl JointRenewalRecord {
    fn for_grant(
        proposal: AnchorCredentialRenewalProposal,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
        phase: Phase,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            proposal: Box::new(proposal),
            owner: storage_owner(grant.successor_device()),
            authority: grant.successor_device().authority_binding(),
            validity: enrollment_validity(grant.successor_device(), policy)?,
            version: grant.successor_device().roster().checkpoint().version(),
            phase,
            policy: None,
        })
    }
    fn same_target(&self, other: &Self) -> bool {
        self.proposal == other.proposal
            && self.owner == other.owner
            && self.authority == other.authority
            && self.validity == other.validity
            && self.version == other.version
            && self.policy == other.policy
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        let phase = match self.phase {
            Phase::Prepared => 1,
            Phase::Applied => 2,
            Phase::Closed => 3,
        };
        out.push(phase + if self.policy.is_some() { 4 } else { 0 });
        out.extend_from_slice(&self.proposal.to_bytes());
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.authority);
        self.validity.encode(out);
        out.extend_from_slice(&self.version.to_be_bytes());
        if let Some(policy) = self.policy {
            policy.encode(out);
        }
    }
    fn decode(d: &mut Decoder<'_>, tag: u8) -> Result<Self, DurableError> {
        let policy_format = (5..=7).contains(&tag);
        let phase = match tag {
            1 | 5 => Phase::Prepared,
            2 | 6 => Phase::Applied,
            3 | 7 => Phase::Closed,
            _ => return Err(DurableError::Corrupt),
        };
        let proposal =
            AnchorCredentialRenewalProposal::from_trusted_state(d.take(if policy_format {
                329
            } else {
                296
            })?)?;
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
        let policy = if policy_format {
            Some(PolicyAuthority::decode(d)?)
        } else {
            None
        };
        Ok(Self {
            proposal: Box::new(proposal),
            owner,
            authority,
            validity,
            version,
            phase,
            policy,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CredentialRenewalRecord {
    Joint(JointRenewalRecord),
    GrantClosed {
        cancellation: AnchorCredentialRenewalCancellation,
        version: u64,
        policy: Option<PolicyAuthority>,
    },
}
impl CredentialRenewalRecord {
    pub(super) fn roster_floor(&self) -> u64 {
        match self {
            Self::Joint(record) => record.version,
            Self::GrantClosed { version, .. } => *version,
        }
    }
    pub(super) fn is_cancellation(&self) -> bool {
        matches!(self, Self::GrantClosed { .. })
    }
    pub(super) fn has_policy(&self) -> bool {
        match self {
            Self::Joint(record) => record.policy.is_some(),
            Self::GrantClosed { policy, .. } => policy.is_some(),
        }
    }
    pub(super) fn is_policy_cancellation(&self) -> bool {
        matches!(
            self,
            Self::GrantClosed {
                policy: Some(_),
                ..
            }
        )
    }
    fn binding(&self) -> [u8; 32] {
        match self {
            Self::Joint(record) => record.proposal.binding(),
            Self::GrantClosed { cancellation, .. } => cancellation.binding(),
        }
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Joint(record) => record.encode(out),
            Self::GrantClosed {
                cancellation,
                version,
                policy,
            } => {
                out.push(if policy.is_some() { 8 } else { 4 });
                out.extend_from_slice(&cancellation.to_bytes());
                out.extend_from_slice(&version.to_be_bytes());
                if let Some(policy) = policy {
                    policy.encode(out);
                }
            }
        }
    }
    pub(super) fn decode(
        d: &mut Decoder<'_>,
        cancellation_format: bool,
        policy_format: bool,
        policy_cancellation_format: bool,
    ) -> Result<Option<Self>, DurableError> {
        let [tag] = d.array()?;
        match tag {
            0 => Ok(None),
            1..=3 => Ok(Some(Self::Joint(JointRenewalRecord::decode(d, tag)?))),
            5..=7 if policy_format => Ok(Some(Self::Joint(JointRenewalRecord::decode(d, tag)?))),
            4 | 8
                if (tag == 4 && cancellation_format)
                    || (tag == 8 && policy_cancellation_format) =>
            {
                let cancellation = AnchorCredentialRenewalCancellation::from_trusted_state(
                    d.take(if tag == 8 { 281 } else { 248 })?,
                )?;
                let version = d.u64()?;
                generation(version)?;
                if version <= 1 {
                    return Err(DurableError::Corrupt);
                }
                Ok(Some(Self::GrantClosed {
                    cancellation,
                    version,
                    policy: if tag == 8 {
                        Some(PolicyAuthority::decode(d)?)
                    } else {
                        None
                    },
                }))
            }
            _ => Err(DurableError::Corrupt),
        }
    }
}
#[derive(Clone, Copy)]
struct RenewalScope {
    witness: [u8; 32],
    subject: AnchorSubject,
    operation: crate::CredentialRenewalId,
    statement: [u8; 32],
    expected: AnchorHead,
}
impl From<&AnchorCredentialRenewalProposal> for RenewalScope {
    fn from(p: &AnchorCredentialRenewalProposal) -> Self {
        Self {
            witness: p.witness,
            subject: p.subject,
            operation: p.operation,
            statement: p.statement,
            expected: p.expected,
        }
    }
}
impl From<&AnchorCredentialRenewalCancellation> for RenewalScope {
    fn from(c: &AnchorCredentialRenewalCancellation) -> Self {
        Self {
            witness: c.witness,
            subject: c.subject,
            operation: c.operation,
            statement: c.statement,
            expected: c.expected,
        }
    }
}

impl Entry {
    pub(super) fn check_renewal_state(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        self.check_independent_policy(pin)?;
        self.check_independent_roster(pin)?;
        if self.policy_floor == 1 || self.policy_floor == u64::MAX {
            return Err(DurableError::Corrupt);
        }
        match (self.credential_authorization, self.policy_authorization) {
            (None, None) => {}
            (Some(credential), Some(policy)) => {
                nonzero(&credential)?;
                nonzero(&policy.statement)?;
                if policy.checkpoint.version() > self.policy_floor
                    || !policy.validity.contains(self.validity)
                    || self.renewal_floor < 2
                {
                    return Err(DurableError::Corrupt);
                }
            }
            _ => return Err(DurableError::Corrupt),
        }
        if self.renewal_floor == 1
            || self.renewal_floor == u64::MAX
            || (self.renewal_ack.is_some() && self.renewal_floor == 0)
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(binding) = self.renewal_ack {
            nonzero(&binding)?;
        }
        if let Some(CredentialRenewalRecord::GrantClosed {
            cancellation,
            version,
            policy,
        }) = &self.renewal
        {
            if *version <= 1
                || cancellation.witness != pin.binding
                || cancellation.subject != self.subject
                || cancellation.expected != self.head
                || *version != self.renewal_floor
                || self.renewal_ack == Some(cancellation.binding())
            {
                return Err(DurableError::Corrupt);
            }
            if cancellation.policy_continuation() != policy.map(|p| p.statement) {
                return Err(DurableError::Corrupt);
            }
            match policy {
                None if self.policy_authorization.is_none() && !cancellation.adopts_policy() => {}
                Some(p)
                    if cancellation.adopts_policy()
                        && p.checkpoint.version() == self.policy_floor
                        && self.policy_authorization.is_none_or(|old| {
                            old.checkpoint.version() < p.checkpoint.version()
                        }) => {}
                Some(p)
                    if !cancellation.adopts_policy() && self.policy_authorization == Some(*p) => {}
                _ => return Err(DurableError::Corrupt),
            }
        }
        if let Some(CredentialRenewalRecord::Joint(record)) = &self.renewal {
            let proposal = &record.proposal;
            if proposal.policy_continuation() != record.policy.map(|p| p.statement)
                || (record.policy.is_none()
                    && (record.proposal.adopts_policy() || self.policy_authorization.is_some()))
            {
                return Err(DurableError::Corrupt);
            }
            if let Some(policy) = record.policy {
                if !policy.validity.contains(record.validity) {
                    return Err(DurableError::Corrupt);
                }
                let valid = match record.phase {
                    Phase::Prepared if record.proposal.adopts_policy() => {
                        policy.checkpoint.version() > self.policy_floor
                    }
                    Phase::Closed if record.proposal.adopts_policy() => {
                        policy.checkpoint.version() == self.policy_floor
                    }
                    Phase::Applied => {
                        self.policy_authorization == Some(policy)
                            && self.credential_authorization == Some(proposal.statement())
                            && (!record.proposal.adopts_policy()
                                || self.policy_floor == policy.checkpoint.version())
                    }
                    Phase::Prepared | Phase::Closed => self.policy_authorization == Some(policy),
                };
                if !valid {
                    return Err(DurableError::Corrupt);
                }
            }
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
        let Some(record) = self.renewal.as_mut().filter(|r| r.binding() == binding) else {
            return Ok((AnchorOutcome::CredentialUnavailable, false));
        };
        if matches!(record, CredentialRenewalRecord::GrantClosed { .. }) {
            return match request.operation.0 {
                Command::CredentialStatus(_) => Ok((AnchorOutcome::CredentialClosed, false)),
                Command::CredentialAcknowledge(_) => {
                    self.renewal_ack = Some(binding);
                    self.renewal = None;
                    Ok((AnchorOutcome::CredentialAcknowledged, true))
                }
                _ => Err(Error::State),
            };
        }
        let CredentialRenewalRecord::Joint(record) = record else {
            return Err(Error::State);
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
                    if let Some(policy) = record.policy {
                        self.credential_authorization = Some(record.proposal.statement());
                        self.policy_authorization = Some(policy);
                        if record.proposal.adopts_policy() {
                            self.policy_floor = policy.checkpoint.version();
                        }
                    }
                    record.phase = Phase::Applied;
                    Ok((AnchorOutcome::CredentialApplied, true))
                }
                _ => Ok((record.phase.outcome(), false)),
            },
            Command::CredentialClose(_) => match record.phase {
                Phase::Prepared => {
                    self.renewal_floor = record.version;
                    if record.proposal.adopts_policy() {
                        self.policy_floor = record.policy.ok_or(Error::State)?.checkpoint.version();
                    }
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
        proposal: &RenewalScope,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
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
        proposal: &RenewalScope,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
    ) -> Result<(), DurableError> {
        let previous = grant.previous_device();
        if entry.independent_policy.is_some()
            || entry.independent_roster.is_some()
            || entry.subject != proposal.subject
            || entry.head != proposal.expected
            || entry.device != previous.key
            || entry.device != grant.successor_device().key
            || entry.credential_owner != storage_owner(previous)
            || entry.authority != previous.authority_binding()
            || entry.validity
                != enrollment_interval(
                    previous,
                    entry
                        .policy_authorization
                        .map_or(policy.validity(), |p| p.validity),
                )?
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn retain_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
        target_policy: &HistoricalSessionPolicy,
        current: Option<(&VerifiedSessionPolicy, u64)>,
        continuation: Option<&crate::HistoricalPolicyContinuation>,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.adopts_policy() != continuation.is_some()
            || current.is_some_and(|(p, _)| p.checkpoint() != target_policy.checkpoint())
        {
            return Err(DurableError::Conflict);
        }
        self.check_renewal_scope(&RenewalScope::from(&proposal), grant, policy)?;
        let phase = if current.is_some() {
            Phase::Prepared
        } else {
            Phase::Closed
        };
        let mut record = JointRenewalRecord::for_grant(proposal, grant, target_policy, phase)?;
        let id = proposal.subject.id(&self.pin()?.binding);
        let mut image = self.image()?;
        image.require_live(proposal.subject)?;
        let entry = image.entries.get(&id).ok_or(DurableError::Absent)?;
        if entry.independent_policy.is_some() || entry.independent_roster.is_some() {
            return Err(DurableError::Conflict);
        }
        match proposal.policy_continuation() {
            None => {
                if continuation.is_some()
                    || entry.policy_authorization.is_some()
                    || target_policy.checkpoint() != policy.checkpoint()
                {
                    return Err(DurableError::Conflict);
                }
            }
            Some(statement) => {
                let target = target_policy;
                if let Some(t) = continuation {
                    t.check_context_policy(policy, target)?;
                    t.check_credential(grant)?;
                    if t.statement_digest() != statement
                        || t.scope().journal.as_bytes() != &proposal.subject.journal
                        || t.scope().original_owner != proposal.subject.owner
                    {
                        return Err(DurableError::Conflict);
                    }
                    record.policy = Some(PolicyAuthority {
                        statement,
                        checkpoint: target.checkpoint(),
                        validity: target.validity(),
                    });
                } else {
                    let retained = entry.policy_authorization.ok_or(DurableError::Conflict)?;
                    if retained.statement != statement
                        || retained.checkpoint != target.checkpoint()
                        || retained.validity != target.validity()
                    {
                        return Err(DurableError::Conflict);
                    }
                    record.policy = Some(retained);
                }
            }
        }
        if let Some(saved) = &entry.renewal {
            let CredentialRenewalRecord::Joint(saved) = saved else {
                return Err(DurableError::Conflict);
            };
            if !saved.same_target(&record) {
                return Err(DurableError::Conflict);
            }
            if current.is_some() || saved.phase != Phase::Prepared {
                return Ok(saved.phase.state());
            }
            // The independent control plane may close the same preparation too.
        } else {
            if record.version <= entry.renewal_floor {
                return Err(Error::Retired.into());
            }
            Self::check_renewal_predecessor(entry, &RenewalScope::from(&proposal), grant, policy)?;
            if let Some(t) = continuation {
                let (previous, statement, validity) = entry
                    .policy_authorization
                    .map_or((policy.checkpoint(), None, policy.validity()), |p| {
                        (p.checkpoint, Some(p.statement), p.validity)
                    });
                if t.scope().previous_policy != previous
                    || t.scope().previous_authorization != statement
                    || t.target_policy().version() <= entry.policy_floor
                    || target_policy.validity().until() <= validity.until()
                {
                    return Err(DurableError::Conflict);
                }
            }
        }
        if let Some((policy, now)) = current {
            self.admit_current_device(grant.successor_device(), policy, now)?;
        }
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        if phase == Phase::Closed {
            entry.renewal_floor = record.version;
            if proposal.adopts_policy() {
                entry.policy_floor = record
                    .policy
                    .ok_or(DurableError::Conflict)?
                    .checkpoint
                    .version();
            }
        }
        entry.renewal = Some(CredentialRenewalRecord::Joint(record));
        self.persist(&mut image)?;
        if let Some((policy, now)) = current {
            // Preserve committed preparation if this instance closes concurrently.
            self.admit_current_device(grant.successor_device(), policy, now)?;
        }
        Ok(phase.state())
    }
    /// Independently close an original grant for which no proposal is retained.
    /// The caller authenticates operator authority and original public metadata.
    /// Any existing proposal (including Applied/Closed) is preserved and conflicts;
    /// only its original proposal path may recover it. An empty/pruned slot alone
    /// never proves non-commit. The signed-version floor survives acknowledgement.
    /// Reuse the exact cancellation after an unknown result; never refresh its head.
    pub fn close_unprepared_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        policy: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        let (grant, policy) = (grant.as_ref(), policy.as_ref());
        self.close_unprepared_renewal(cancellation, grant, policy, None)
    }
    /// Close an independently authenticated historical G/T target without
    /// inventing a sealed image. Current policy/runtime permission is unnecessary.
    /// The operator still authenticates the original request and both issuers.
    pub fn close_unprepared_policy_continuation(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        continuation: &crate::HistoricalPolicyContinuation,
        materials: &crate::HistoricalPolicyContinuationMaterials<'_>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if !cancellation.adopts_policy() {
            return Err(DurableError::Conflict);
        }
        let checked = crate::HistoricalPolicyContinuation::from_bytes(
            continuation.as_bytes(),
            continuation.scope(),
            materials,
        )?;
        self.close_unprepared_renewal(
            cancellation,
            materials.credential,
            materials.original,
            Some((&checked, materials.target)),
        )
    }
    /// Close a later G while explicitly retaining the independently adopted T.
    /// Closing a G cannot restore an earlier policy-version floor.
    pub fn close_unprepared_continued_credential_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        original: &HistoricalSessionPolicy,
        retained: &crate::HistoricalPolicyContinuation,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        if cancellation.adopts_policy() {
            return Err(DurableError::Conflict);
        }
        self.close_unprepared_renewal(
            cancellation,
            grant.as_ref(),
            original,
            Some((retained, policy)),
        )
    }
    fn close_unprepared_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
        continuation: Option<(
            &crate::HistoricalPolicyContinuation,
            &HistoricalSessionPolicy,
        )>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        let scope = RenewalScope::from(&cancellation);
        self.check_renewal_scope(&scope, grant, policy)?;
        let version = grant.successor_checkpoint().version();
        let id = cancellation.subject.id(&self.pin()?.binding);
        let mut image = self.image()?;
        image.require_live(cancellation.subject)?;
        let entry = image.entries.get(&id).ok_or(DurableError::Absent)?;
        if entry.independent_policy.is_some() || entry.independent_roster.is_some() {
            return Err(DurableError::Conflict);
        }
        let target = match continuation {
            None if cancellation.policy_continuation().is_none()
                && entry.policy_authorization.is_none() =>
            {
                None
            }
            Some((t, target)) => {
                t.check_context_policy(policy, target)?;
                if cancellation.policy_continuation() != Some(t.statement_digest())
                    || t.scope().journal.as_bytes() != &scope.subject.journal
                    || t.scope().original_owner != scope.subject.owner
                {
                    return Err(DurableError::Conflict);
                }
                if cancellation.adopts_policy() {
                    t.check_credential(grant)?;
                } else if t.scope().operation == grant.operation() {
                    return Err(DurableError::Conflict);
                }
                Some(PolicyAuthority {
                    statement: t.statement_digest(),
                    checkpoint: target.checkpoint(),
                    validity: target.validity(),
                })
            }
            _ => return Err(DurableError::Conflict),
        };
        if let Some(record) = &entry.renewal {
            return if matches!(record, CredentialRenewalRecord::GrantClosed {
                cancellation: saved, version: saved_version, policy: saved_policy }
                if *saved == cancellation && *saved_version == version && *saved_policy == target)
            {
                Ok(AnchorCredentialCancellationState::Closed)
            } else {
                Err(DurableError::Conflict)
            };
        }
        if version <= entry.renewal_floor {
            return Err(Error::Retired.into());
        }
        Self::check_renewal_predecessor(entry, &scope, grant, policy)?;
        if let Some((t, target)) = continuation {
            if cancellation.adopts_policy() {
                let (previous, statement, validity) = entry
                    .policy_authorization
                    .map_or((policy.checkpoint(), None, policy.validity()), |p| {
                        (p.checkpoint, Some(p.statement), p.validity)
                    });
                if t.scope().previous_policy != previous
                    || t.scope().previous_authorization != statement
                    || target.checkpoint().version() <= entry.policy_floor
                    || target.validity().until() <= validity.until()
                {
                    return Err(DurableError::Conflict);
                }
            } else if entry.policy_authorization
                != Some(PolicyAuthority {
                    statement: t.statement_digest(),
                    checkpoint: target.checkpoint(),
                    validity: target.validity(),
                })
            {
                return Err(DurableError::Conflict);
            }
        }
        let entry = image.entries.get_mut(&id).ok_or(DurableError::Absent)?;
        entry.renewal_floor = version;
        if cancellation.adopts_policy() {
            entry.policy_floor = target.ok_or(DurableError::Conflict)?.checkpoint.version();
        }
        entry.renewal = Some(CredentialRenewalRecord::GrantClosed {
            cancellation,
            version,
            policy: target,
        });
        self.persist(&mut image)?;
        Ok(AnchorCredentialCancellationState::Closed)
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
        self.retain_credential_renewal(
            proposal,
            grant.as_ref(),
            policy.as_ref(),
            policy.historical(),
            Some((policy, now)),
            None,
        )
    }
    /// Independently close one exact root-authorized target, including before
    /// preparation or after expiry. The operator must authenticate retained grant
    /// material and the original proposal; this grants no new credential authority.
    /// Applied is recovered as Applied, never relabelled Closed. Older/pruned
    /// targets are refused rather than classified as uncommitted.
    pub fn close_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        policy: &impl AsRef<HistoricalSessionPolicy>,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        self.retain_credential_renewal(
            proposal,
            grant.as_ref(),
            policy.as_ref(),
            policy.as_ref(),
            None,
            None,
        )
    }

    /// Independently prepare an exact G/T target for the original P0 subject.
    /// Approval does not Apply the sealed image or release a device owner.
    /// Current policy/runtime checks are required for new preparation; an exact
    /// retained terminal remains historical readback after target expiry.
    pub fn prepare_policy_continuation(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        continuation: &crate::VerifiedPolicyContinuation,
        materials: &crate::PolicyContinuationMaterials<'_>,
        now: u64,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.policy_continuation() != Some(continuation.statement_digest())
            || continuation.scope().previous_policy != materials.previous.checkpoint()
        {
            return Err(DurableError::Conflict);
        }
        self.retain_credential_renewal(
            proposal,
            materials.credential.as_ref(),
            materials.original,
            materials.target.historical(),
            Some((materials.target, now)),
            Some(&continuation.historical()),
        )
    }

    /// Prepare a later credential-only G under the already adopted exact T/P1.
    /// T's checkpoint, statement and validity are retained unchanged; the original
    /// P0 remains immutable scope and supplies no current permission.
    pub fn prepare_continued_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &VerifiedCredentialRenewal,
        original: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.policy_continuation().is_none() {
            return Err(DurableError::Conflict);
        }
        self.retain_credential_renewal(
            proposal,
            grant.as_ref(),
            original,
            policy.historical(),
            Some((policy, now)),
            None,
        )
    }
    /// Independently close an exact sealed G/T proposal using historical pins and
    /// approvals. An already Applied target remains Applied; no target is resealed.
    pub fn close_policy_continuation(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        continuation: &crate::HistoricalPolicyContinuation,
        materials: &crate::HistoricalPolicyContinuationMaterials<'_>,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        let checked = crate::HistoricalPolicyContinuation::from_bytes(
            continuation.as_bytes(),
            continuation.scope(),
            materials,
        )?;
        self.retain_credential_renewal(
            proposal,
            materials.credential,
            materials.original,
            materials.target,
            None,
            Some(&checked),
        )
    }
    /// Independently close a sealed later G proposal that explicitly retains T.
    /// Current policy permission is unnecessary; the original P0 and retained P1
    /// are authenticated historical inputs and cannot change the current T.
    pub fn close_continued_credential_renewal(
        &mut self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &impl AsRef<HistoricalCredentialRenewal>,
        original: &HistoricalSessionPolicy,
        policy: &HistoricalSessionPolicy,
    ) -> Result<AnchorCredentialRenewalState, DurableError> {
        if proposal.policy_continuation().is_none() || proposal.adopts_policy() {
            return Err(DurableError::Conflict);
        }
        self.retain_credential_renewal(proposal, grant.as_ref(), original, policy, None, None)
    }
}
