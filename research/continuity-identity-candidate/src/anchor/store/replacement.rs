// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One trusted transaction admits a fresh generation and retires all predecessors.
use super::*;
use crate::{HistoricalSessionPolicy, PolicyCheckpoint, RosterCheckpoint};
use std::collections::BTreeSet;

#[path = "replacement_receipt.rs"]
mod receipt;

const MAX_PROPOSAL_BYTES: usize = 450 + MAX_ENTRIES * 224;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Predecessor {
    subject: AnchorSubject,
    checkpoint: RosterCheckpoint,
    policy: PolicyCheckpoint,
    policy_validity: Validity,
    state: [u8; 32],
}

/// Complete retained expectation for one trusted device-generation replacement.
/// Parsing or possessing these public bytes grants no current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorDeviceReplacementProposal {
    witness: [u8; 32],
    identity: OriginalIdentity,
    target: AnchorSubject,
    genesis: [u8; 32],
    key: [u8; 32],
    authority: [u8; 32],
    validity: Validity,
    roster: RosterCheckpoint,
    policy: PolicyCheckpoint,
    policy_validity: Validity,
    predecessors: Vec<Predecessor>,
}
impl AnchorDeviceReplacementProposal {
    /// Restore a canonical bounded expectation from protected host state.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROPOSAL_BYTES {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPDRPL01" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        let identity = OriginalIdentity::decode(&mut d)?;
        let target = AnchorSubject::decode(&mut d)?;
        let genesis = d.array()?;
        let key = d.array()?;
        let authority = d.array()?;
        let validity = Validity::decode(&mut d)?;
        let roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let policy_validity = Validity::decode(&mut d)?;
        let count = usize::from(d.u16()?);
        if count == 0 || count > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        let mut predecessors = Vec::with_capacity(count);
        for _ in 0..count {
            predecessors.push(Predecessor {
                subject: AnchorSubject::decode(&mut d)?,
                checkpoint: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
                policy: PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
                policy_validity: Validity::decode(&mut d)?,
                state: d.array()?,
            });
        }
        d.finish()?;
        let proposal = Self {
            witness,
            identity,
            target,
            genesis,
            key,
            authority,
            validity,
            roster,
            policy,
            policy_validity,
            predecessors,
        };
        proposal.check_shape()?;
        Ok(proposal)
    }
    fn check_shape(&self) -> Result<(), Error> {
        for value in [self.witness, self.genesis, self.key, self.authority] {
            nonzero(&value)?;
        }
        if self.predecessors.is_empty() || self.predecessors.len() > MAX_ENTRIES {
            return Err(Error::Capacity);
        }
        if !self.identity.description.validity.contains(self.validity)
            || !self.policy_validity.contains(self.validity)
            || self.policy.digest() != self.target.policy
            || self.authority
                != crate::identity::authority_binding(
                    self.identity.account,
                    self.roster,
                    self.identity.description.family,
                )
        {
            return Err(Error::Scope);
        }
        let mut previous = None;
        for p in &self.predecessors {
            nonzero(&p.state)?;
            let key = p.subject.to_bytes();
            if previous.as_ref().is_some_and(|last| last >= &key)
                || p.subject == self.target
                || p.checkpoint.version() >= self.roster.version()
                || self.policy.version() < p.policy.version()
                || (self.policy.version() == p.policy.version() && self.policy != p.policy)
            {
                return Err(Error::Scope);
            }
            previous = Some(key);
        }
        Ok(())
    }
    /// Canonical public proposal; retain it before dispatching the mutation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.check_shape()?;
        let mut out = b"QPDRPL01".to_vec();
        out.extend_from_slice(&self.witness);
        self.identity.encode(&mut out);
        self.target.encode(&mut out);
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.authority);
        self.validity.encode(&mut out);
        out.extend_from_slice(&self.roster.version().to_be_bytes());
        out.extend_from_slice(&self.roster.digest());
        out.extend_from_slice(&self.policy.version().to_be_bytes());
        out.extend_from_slice(&self.policy.digest());
        self.policy_validity.encode(&mut out);
        out.extend_from_slice(
            &u16::try_from(self.predecessors.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        for p in &self.predecessors {
            p.subject.encode(&mut out);
            out.extend_from_slice(&p.checkpoint.version().to_be_bytes());
            out.extend_from_slice(&p.checkpoint.digest());
            out.extend_from_slice(&p.policy.version().to_be_bytes());
            out.extend_from_slice(&p.policy.digest());
            p.policy_validity.encode(&mut out);
            out.extend_from_slice(&p.state);
        }
        Ok(out)
    }
    /// Stable binding of the complete expectation, independent of retry timing.
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-DEVICE-REPLACEMENT-CANDIDATE/v1",
            &self.to_bytes()?,
        ))
    }
    /// The exact fresh journal admitted by this transition.
    pub fn successor(&self) -> AnchorSubject {
        self.target
    }
    /// All original subjects which this transition permanently retires.
    pub fn predecessors(&self) -> impl Iterator<Item = AnchorSubject> + '_ {
        self.predecessors.iter().map(|p| p.subject)
    }
    /// Retained predecessor roster expectations. Independently authenticated
    /// historical policy snapshots must still accompany commit or retry.
    pub fn predecessor_checkpoints(
        &self,
    ) -> impl Iterator<Item = (AnchorSubject, RosterCheckpoint)> + '_ {
        self.predecessors.iter().map(|p| (p.subject, p.checkpoint))
    }
}

/// Trusted local witness observation, never permission to release traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorDeviceReplacementState {
    /// The exact complete replacement is durably retained, even if its successor
    /// later renewed, advanced, expired or was itself replaced.
    Committed,
    /// No exact retained replacement is available. This is not a traffic grant or
    /// a substitute for reconciling an outstanding control-plane invocation.
    Unavailable,
}

/// Immutable metadata of a subject frozen by one exact replacement.
/// It cannot be used as a normal anchor reply or authorize a journal advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorRetiredSubject {
    witness: [u8; 32],
    subject: AnchorSubject,
    head: AnchorHead,
    last: Option<[u8; 32]>,
    state: [u8; 32],
    replacement: [u8; 32],
    successor: AnchorSubject,
}
impl AnchorRetiredSubject {
    /// Original independently pinned witness instance and key binding.
    pub fn witness_binding(self) -> [u8; 32] {
        self.witness
    }
    /// Original retired subject.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Frozen authoritative head; not a new cryptographic release admission.
    pub fn observed_head(self) -> AnchorHead {
        self.head
    }
    /// Exact last applied data command, retained across replacement.
    pub fn last_command_id(self) -> Option<[u8; 32]> {
        self.last
    }
    /// Commitment to the complete frozen entry, including all G/P/R metadata.
    pub fn state_commitment(self) -> [u8; 32] {
        self.state
    }
    /// Complete replacement that retired this subject.
    pub fn replacement_binding(self) -> [u8; 32] {
        self.replacement
    }
    /// New journal named by that original replacement.
    pub fn successor(self) -> AnchorSubject {
        self.successor
    }
}

fn check_policy_proofs(
    p: &AnchorDeviceReplacementProposal,
    proofs: &[(AnchorSubject, RosterCheckpoint, &HistoricalSessionPolicy)],
) -> Result<(), DurableError> {
    if proofs.len() != p.predecessors.len() {
        return Err(Error::Scope.into());
    }
    let mut seen = BTreeSet::new();
    for (subject, checkpoint, historical) in proofs {
        if !seen.insert(subject.to_bytes()) {
            return Err(Error::Scope.into());
        }
        let retained = p
            .predecessors
            .iter()
            .find(|old| old.subject == *subject)
            .ok_or(Error::Scope)?;
        if retained.checkpoint != *checkpoint
            || retained.policy != historical.checkpoint()
            || retained.policy_validity != historical.validity()
            || historical.anchor_requirement().binding() != Some(p.witness)
            || historical.family() != p.identity.description.family
        {
            return Err(Error::Scope.into());
        }
    }
    Ok(())
}

pub(super) fn key_commitment(key: &PublicKey) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-REPLACEMENT-KEY/v1", &key.encode())
}
pub(super) fn state_commitment(entry: &Entry, pin: &AnchorPin) -> Result<[u8; 32], DurableError> {
    let mut bytes = pin.binding.to_vec();
    encode_entry(entry, pin, EntryFormat::COMPLETE, &mut bytes)?;
    Ok(digest(
        b"Q-PERIAPT-CONTINUITY-RETIRED-WITNESS-STATE/v1",
        &bytes,
    ))
}
impl Entry {
    pub(super) fn at_genesis(
        subject: AnchorSubject,
        genesis: [u8; 32],
        device: &VerifiedDevice,
        validity: Validity,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            subject,
            original_identity: Some(OriginalIdentity::from_verified(device)),
            device: device.key.clone(),
            credential_owner: storage_owner(device),
            authority: device.authority_binding(),
            validity,
            genesis,
            head: AnchorHead::from_trusted_state(1, 1, genesis)?,
            last: None,
            renewal_floor: 0,
            renewal_ack: None,
            renewal: None,
            credential_authorization: None,
            policy_authorization: None,
            policy_floor: 0,
            independent_policy: None,
            independent_roster: None,
        })
    }
    fn matches_current_policy(&self, checkpoint: PolicyCheckpoint, validity: Validity) -> bool {
        if !validity.contains(self.validity) {
            return false;
        }
        match self
            .independent_policy
            .as_ref()
            .and_then(|p| p.current)
            .or(self.policy_authorization)
        {
            Some(current) => checkpoint == current.checkpoint && validity == current.validity,
            None => checkpoint.digest() == self.subject.policy,
        }
    }
    fn roster_floor(&self) -> u64 {
        self.renewal_floor
            .max(
                self.renewal
                    .as_ref()
                    .map_or(0, CredentialRenewalRecord::roster_floor),
            )
            .max(
                self.independent_roster
                    .as_ref()
                    .map_or(0, RosterRefresh::roster_floor),
            )
    }
}
impl Image {
    pub(super) fn retirement(
        &self,
        subject: AnchorSubject,
    ) -> Option<(&[u8; 32], &AnchorDeviceReplacementProposal)> {
        self.replacements
            .iter()
            .find(|(_, p)| p.predecessors.iter().any(|e| e.subject == subject))
    }
    pub(super) fn require_live(&self, subject: AnchorSubject) -> Result<(), DurableError> {
        if self.subject_retired(subject) || self.subject_frozen(subject) {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
    pub(super) fn subject_retired(&self, subject: AnchorSubject) -> bool {
        self.retirement(subject).is_some() || self.account_retirement(subject)
    }
    pub(super) fn admit_new_device(&self, device: &VerifiedDevice) -> Result<(), DurableError> {
        self.require_account_live(device.account_id())?;
        for entry in self.entries.values() {
            let original = entry
                .original_identity
                .as_ref()
                .ok_or(DurableError::Suspended)?;
            if original.account == device.account_id()
                && original.description.id == device.device_id()
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    pub(super) fn check_replacements(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if self.replacements.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        if self.replacements.is_empty() {
            return Ok(());
        }
        if self.entries.values().any(|e| e.original_identity.is_none()) {
            return Err(DurableError::Corrupt);
        }
        let mut retired = BTreeSet::new();
        let mut successors = BTreeSet::new();
        for (binding, p) in &self.replacements {
            if p.witness != pin.binding
                || p.binding()? != *binding
                || !successors.insert(p.target.id(&pin.binding))
            {
                return Err(DurableError::Corrupt);
            }
            let target = self
                .entries
                .get(&p.target.id(&pin.binding))
                .ok_or(DurableError::Corrupt)?;
            if target.subject != p.target
                || target.genesis != p.genesis
                || target.original_identity.as_ref() != Some(&p.identity)
                || key_commitment(&target.device) != p.key
            {
                return Err(DurableError::Corrupt);
            }
            for predecessor in &p.predecessors {
                let id = predecessor.subject.id(&pin.binding);
                if !retired.insert(id) {
                    return Err(DurableError::Corrupt);
                }
                let entry = self.entries.get(&id).ok_or(DurableError::Corrupt)?;
                let original = entry
                    .original_identity
                    .as_ref()
                    .ok_or(DurableError::Corrupt)?;
                if entry.subject != predecessor.subject
                    || original.account != p.identity.account
                    || original.description.id != p.identity.description.id
                    || original.description.family != p.identity.description.family
                    || original.description.generation >= p.identity.description.generation
                    || entry.authority
                        != crate::identity::authority_binding(
                            original.account,
                            predecessor.checkpoint,
                            original.description.family,
                        )
                    || !entry
                        .matches_current_policy(predecessor.policy, predecessor.policy_validity)
                    || predecessor.state != state_commitment(entry, pin)?
                    || p.roster.version() <= entry.roster_floor()
                {
                    return Err(DurableError::Corrupt);
                }
            }
        }
        for p in self.replacements.values() {
            let target = self
                .entries
                .get(&p.target.id(&pin.binding))
                .ok_or(DurableError::Corrupt)?;
            let mut active = 0;
            let mut highest = 0;
            let mut live_generation = 0;
            for entry in self.entries.values() {
                let identity = entry
                    .original_identity
                    .as_ref()
                    .ok_or(DurableError::Corrupt)?;
                if identity.account != p.identity.account
                    || identity.description.id != p.identity.description.id
                {
                    continue;
                }
                if identity.description.family != p.identity.description.family {
                    return Err(DurableError::Corrupt);
                }
                highest = highest.max(identity.description.generation);
                if !retired.contains(&entry.subject.id(&pin.binding)) {
                    active += 1;
                    live_generation = identity.description.generation;
                }
                if identity.description.generation < p.identity.description.generation
                    && entry.device.shares_component(&target.device)
                {
                    return Err(DurableError::Corrupt);
                }
            }
            if active != 1 || live_generation != highest {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
}

impl AnchorStore {
    /// Read a complete proposal for trusted account-authorized replacement.
    /// The caller independently admits `next` and `policy`, retains the original
    /// new-device request/genesis, and supplies each original subject's retained
    /// current roster checkpoint. This read reserves nothing: persist its result
    /// before calling `replace_device`. A concurrent old-state change conflicts.
    pub fn device_replacement_proposal(
        &mut self,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        previous: &[(AnchorSubject, RosterCheckpoint, &HistoricalSessionPolicy)],
        now: u64,
    ) -> Result<AnchorDeviceReplacementProposal, DurableError> {
        let validity = self.admit_enrollment(genesis.subject, next, policy, now)?;
        let pin = self.pin()?;
        if policy.anchor_requirement().binding() != Some(pin.binding) {
            return Err(Error::Scope.into());
        }
        let image = self.image()?;
        let mut p = AnchorDeviceReplacementProposal {
            witness: pin.binding,
            identity: OriginalIdentity::from_verified(next),
            target: genesis.subject,
            genesis: genesis.digest,
            key: key_commitment(&next.key),
            authority: next.authority_binding(),
            validity,
            roster: next.roster().checkpoint(),
            policy: policy.checkpoint(),
            policy_validity: policy.validity(),
            predecessors: Vec::new(),
        };
        if previous.is_empty() || previous.len() > MAX_ENTRIES {
            return Err(Error::Capacity.into());
        }
        for (subject, checkpoint, historical) in previous {
            let entry = image
                .entries
                .get(&subject.id(&pin.binding))
                .ok_or(DurableError::Absent)?;
            p.predecessors.push(Predecessor {
                subject: *subject,
                checkpoint: *checkpoint,
                policy: historical.checkpoint(),
                policy_validity: historical.validity(),
                state: state_commitment(entry, &pin)?,
            });
        }
        p.predecessors.sort_by_key(|p| p.subject.to_bytes());
        p.check_shape()?;
        check_policy_proofs(&p, previous)?;
        self.check_replacement_predecessors(&image, &p, next, &pin)?;
        Ok(p)
    }
    fn check_replacement_predecessors(
        &self,
        image: &Image,
        p: &AnchorDeviceReplacementProposal,
        next: &VerifiedDevice,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        image.require_account_live(next.account_id())?;
        if image.entries.contains_key(&p.target.id(&pin.binding)) {
            return Err(DurableError::Conflict);
        }
        let mut active = BTreeSet::new();
        let mut supplied = BTreeSet::new();
        for entry in image.entries.values() {
            let original = entry
                .original_identity
                .as_ref()
                .ok_or(DurableError::Suspended)?;
            if original.account != p.identity.account {
                continue;
            }
            if original.description.id != p.identity.description.id {
                if image.retirement(entry.subject).is_none()
                    && !next
                        .roster()
                        .members()
                        .any(|(id, generation, certificate)| {
                            id == original.description.id
                                && generation == original.description.generation
                                && crate::bootstrap::credential_storage_owner(
                                    original.account,
                                    id,
                                    generation,
                                    certificate,
                                ) == entry.credential_owner
                        })
                {
                    return Err(Error::Scope.into());
                }
                continue;
            }
            if original.description.family != p.identity.description.family
                || original.description.generation >= p.identity.description.generation
                || entry.device.shares_component(&next.key)
            {
                return Err(Error::Scope.into());
            }
            if image.retirement(entry.subject).is_none() {
                active.insert(entry.subject.id(&pin.binding));
            }
        }
        for old in &p.predecessors {
            let id = old.subject.id(&pin.binding);
            if !supplied.insert(id) {
                return Err(Error::Scope.into());
            }
            let entry = image.entries.get(&id).ok_or(DurableError::Absent)?;
            if entry.subject != old.subject
                || entry.authority
                    != crate::identity::authority_binding(
                        p.identity.account,
                        old.checkpoint,
                        p.identity.description.family,
                    )
                || !entry.matches_current_policy(old.policy, old.policy_validity)
                || old.state != state_commitment(entry, pin)?
                || p.roster.version() <= entry.roster_floor()
            {
                return Err(DurableError::Conflict);
            }
        }
        if active.is_empty() || active != supplied {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Atomically admit the exact fresh journal and retire every predecessor.
    /// Current replacement authority is checked for a new commit. An exact
    /// committed retry returns historical Committed after expiry too; it grants
    /// no current operating owner. Reopen and retry the same proposal after any
    /// uncertain error. Retired state and complete G/P/R records are never erased.
    pub fn replace_device(
        &mut self,
        p: &AnchorDeviceReplacementProposal,
        genesis: &AnchorGenesis,
        next: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        previous: &[(AnchorSubject, RosterCheckpoint, &HistoricalSessionPolicy)],
        now: u64,
    ) -> Result<AnchorDeviceReplacementState, DurableError> {
        let pin = self.pin()?;
        p.check_shape()?;
        check_policy_proofs(p, previous)?;
        if p.witness != pin.binding
            || policy.anchor_requirement().binding() != Some(pin.binding)
            || p.target != genesis.subject
            || p.genesis != genesis.digest
            || p.identity != OriginalIdentity::from_verified(next)
            || p.key != key_commitment(&next.key)
            || p.authority != next.authority_binding()
            || p.roster != next.roster().checkpoint()
            || p.validity != enrollment_validity(next, policy)?
            || p.policy != policy.checkpoint()
            || p.policy_validity != policy.validity()
            || p.target.owner != storage_owner(next)
        {
            return Err(Error::Scope.into());
        }
        let binding = p.binding()?;
        let mut image = self.image()?;
        if let Some(saved) = image.replacements.get(&binding) {
            return if saved == p {
                Ok(AnchorDeviceReplacementState::Committed)
            } else {
                Err(DurableError::Conflict)
            };
        }
        self.admit_enrollment(genesis.subject, next, policy, now)?;
        self.check_replacement_predecessors(&image, p, next, &pin)?;
        if image.entries.len() >= MAX_ENTRIES || image.replacements.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image.entries.insert(
            p.target.id(&pin.binding),
            Entry::at_genesis(p.target, p.genesis, next, p.validity)?,
        );
        image.replacements.insert(binding, p.clone());
        self.persist(&mut image)?;
        Ok(AnchorDeviceReplacementState::Committed)
    }
    /// Observe a retained complete replacement through this trusted local owner.
    /// This is not a network freshness receipt or authority for its successor.
    pub fn device_replacement_status(
        &mut self,
        p: &AnchorDeviceReplacementProposal,
    ) -> Result<AnchorDeviceReplacementState, DurableError> {
        if p.witness != self.pin()?.binding {
            return Err(Error::Scope.into());
        }
        let image = self.image()?;
        Ok(match image.replacements.get(&p.binding()?) {
            Some(saved) if saved == p => AnchorDeviceReplacementState::Committed,
            Some(_) => return Err(DurableError::Conflict),
            None => AnchorDeviceReplacementState::Unavailable,
        })
    }
    /// Read frozen metadata under the exact replacement that retired this subject.
    /// It preserves the commitment to unresolved lifecycle state; it is not a loss
    /// report, a consumption acknowledgement or permission to mutate an old journal.
    pub fn retired_subject_observation(
        &mut self,
        p: &AnchorDeviceReplacementProposal,
        subject: AnchorSubject,
    ) -> Result<AnchorRetiredSubject, DurableError> {
        let pin = self.pin()?;
        if p.witness != pin.binding {
            return Err(Error::Scope.into());
        }
        let image = self.image()?;
        image.retired_observation(p, subject, &pin)
    }
}
impl Image {
    pub(super) fn retired_observation(
        &self,
        p: &AnchorDeviceReplacementProposal,
        subject: AnchorSubject,
        pin: &AnchorPin,
    ) -> Result<AnchorRetiredSubject, DurableError> {
        if p.witness != pin.binding {
            return Err(Error::Scope.into());
        }
        let binding = p.binding()?;
        if self.replacements.get(&binding) != Some(p) {
            return Err(DurableError::Absent);
        }
        let predecessor = p
            .predecessors
            .iter()
            .find(|old| old.subject == subject)
            .ok_or(Error::Scope)?;
        let entry = self
            .entries
            .get(&subject.id(&pin.binding))
            .ok_or(DurableError::Corrupt)?;
        Ok(AnchorRetiredSubject {
            witness: pin.binding,
            subject,
            head: entry.head,
            last: entry.last,
            state: predecessor.state,
            replacement: binding,
            successor: p.target,
        })
    }
}

pub(super) fn decode_decisions(
    d: &mut Decoder<'_>,
    allow_empty: bool,
) -> Result<BTreeMap<[u8; 32], AnchorDeviceReplacementProposal>, DurableError> {
    let count = usize::from(d.u16()?);
    if (!allow_empty && count == 0) || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut decisions = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let binding = d.array()?;
        nonzero(&binding)?;
        if previous.is_some_and(|last| last >= binding) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(binding);
        let size =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if size > MAX_PROPOSAL_BYTES {
            return Err(DurableError::Capacity);
        }
        let p = AnchorDeviceReplacementProposal::from_trusted_state(d.take(size)?)?;
        if p.binding()? != binding {
            return Err(DurableError::Corrupt);
        }
        decisions.insert(binding, p);
    }
    Ok(decisions)
}
