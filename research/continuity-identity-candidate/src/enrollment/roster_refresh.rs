// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The original enrollment owns R terminal persistence before ACK and cleanup.
use super::*;
use crate::{
    AnchorOperation, AnchorRosterRefreshProposal as Proposal, AnchorRosterRefreshState as State,
    AnchorSubject, DeviceJournal, HistoricalSessionPolicy, RosterRefreshId, RosterRefreshMaterials,
    RosterRefreshScope,
};

/// Durable historical R outcome; this does not grant current traffic permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedRosterRefreshDisposition {
    /// Witness committed the exact target, which was installed in the original journal.
    Applied,
    /// Witness permanently closed this original target without applying it.
    Closed,
}
impl WitnessedRosterRefreshDisposition {
    fn state(self) -> State {
        match self {
            Self::Applied => State::Applied,
            Self::Closed => State::Closed,
        }
    }
}
/// Authenticated original enrollment progress, separate from operational admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedRosterRefreshProgress {
    /// Exact root-approved intent retained before any sealed proposal is released.
    Staged(RosterRefreshScope),
    /// No proposal was ever released by this enrollment and the original journal
    /// had no pending target under its lease. This is not witness Closed/no-commit.
    AbandonedBeforePreparation(RosterRefreshScope),
    /// Original sealed target retained; independent witness preparation is still required.
    Reserved(Proposal),
    /// Exact original terminal persisted before witness ACK and pending cleanup.
    Terminal {
        /// Full original proposal, including its expected and target journal heads.
        proposal: Proposal,
        /// Actual Applied or Closed result, never inferred from missing history.
        disposition: WitnessedRosterRefreshDisposition,
        /// Exact ACK/cleanup and enrollment completion have been read back.
        retired: bool,
    },
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Coordination {
    proposal: Proposal,
    terminal: Option<WitnessedRosterRefreshDisposition>,
    retired: bool,
}
pub(super) struct WitnessRoster {
    scope: RosterRefreshScope,
    roster: Vec<u8>,
    coordination: Option<Coordination>,
    abandoned: bool,
}
impl WitnessRoster {
    pub(super) fn retired(&self) -> bool {
        self.abandoned || self.coordination.is_some_and(|c| c.retired)
    }
    pub(super) fn validate(&self, image: &Image) -> Result<(), DurableError> {
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Corrupt);
        };
        if (self.abandoned && self.coordination.is_some())
            || image.renewal.is_some()
            || image.policy_resolution.is_some()
            || image.roster_resolution.is_some()
            || (image.policy_pending.is_some() && !self.retired())
            || self.scope.target.version() <= self.scope.previous.version()
        {
            return Err(DurableError::Corrupt);
        }
        let applied = if let Some(c) = self.coordination {
            if c.proposal.scope() != &self.scope || (c.retired && c.terminal.is_none()) {
                return Err(DurableError::Conflict);
            }
            c.terminal == Some(WitnessedRosterRefreshDisposition::Applied)
        } else {
            false
        };
        let expected = if applied {
            self.scope.target
        } else {
            self.scope.previous
        };
        if admission.checkpoint != expected || (applied && admission.roster != self.roster) {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        self.scope.encode(out);
        field(out, &self.roster)?;
        match self.coordination {
            None => out.push(if self.abandoned { 6 } else { 0 }),
            Some(c) => {
                out.push(match (c.terminal, c.retired) {
                    (None, false) => 1,
                    (Some(WitnessedRosterRefreshDisposition::Applied), false) => 2,
                    (Some(WitnessedRosterRefreshDisposition::Closed), false) => 3,
                    (Some(WitnessedRosterRefreshDisposition::Applied), true) => 4,
                    (Some(WitnessedRosterRefreshDisposition::Closed), true) => 5,
                    _ => return Err(DurableError::Corrupt),
                });
                out.extend_from_slice(&c.proposal.to_bytes());
            }
        }
        Ok(())
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let scope = RosterRefreshScope::decode(d)?;
        let roster = take(d)?;
        let flag = d.array::<1>()?;
        let coordination = match flag {
            [0] | [6] => None,
            [tag @ 1..=5] => Some(Coordination {
                proposal: Proposal::from_trusted_state(d.take(417)?)?,
                terminal: match tag {
                    1 => None,
                    2 | 4 => Some(WitnessedRosterRefreshDisposition::Applied),
                    3 | 5 => Some(WitnessedRosterRefreshDisposition::Closed),
                    _ => return Err(DurableError::Corrupt),
                },
                retired: tag >= 4,
            }),
            _ => return Err(DurableError::Corrupt),
        };
        Ok(Self {
            scope,
            roster,
            coordination,
            abandoned: flag == [6],
        })
    }
    fn progress(&self) -> WitnessedRosterRefreshProgress {
        match self.coordination {
            None if self.abandoned => {
                WitnessedRosterRefreshProgress::AbandonedBeforePreparation(self.scope)
            }
            None => WitnessedRosterRefreshProgress::Staged(self.scope),
            Some(c) => match c.terminal {
                None => WitnessedRosterRefreshProgress::Reserved(c.proposal),
                Some(disposition) => WitnessedRosterRefreshProgress::Terminal {
                    proposal: c.proposal,
                    disposition,
                    retired: c.retired,
                },
            },
        }
    }
}
/// Private capability constructed only from authenticated original enrollment readback.
pub(crate) struct PersistedRosterTerminal {
    proposal: Proposal,
    disposition: WitnessedRosterRefreshDisposition,
    completion: Option<std::sync::Arc<EnrollmentPolicyCompletion>>,
}
impl PersistedRosterTerminal {
    pub(crate) fn proposal(&self) -> Proposal {
        self.proposal
    }
    pub(crate) fn disposition(&self) -> WitnessedRosterRefreshDisposition {
        self.disposition
    }
    pub(crate) fn completion(&self) -> Option<&EnrollmentPolicyCompletion> {
        self.completion.as_deref()
    }
}
#[derive(Clone, Copy)]
enum Action<'a> {
    Status,
    Commit {
        policy: &'a VerifiedSessionPolicy,
        now: u64,
    },
    Close,
}
impl DeviceEnrollment {
    pub(super) fn validate_witness_roster(&self, image: &Image) -> Result<(), DurableError> {
        let Some(r) = &image.roster_witness else {
            return Ok(());
        };
        r.validate(image)?;
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let original = self.original_device_metadata(image)?;
        let target =
            self.historical_device_metadata(&admission.certificate, &r.roster, r.scope.target)?;
        self.intent.verify_device(&target)?;
        if target.credential_digest() != original.credential_digest() || target.key != original.key
        {
            return Err(DurableError::Conflict);
        }
        if let Some(c) = r.coordination {
            let mut subject = admission.journal.as_bytes().to_vec();
            subject.extend_from_slice(&crate::bootstrap::storage_owner(&original));
            subject.extend_from_slice(&admission.policy);
            if c.proposal.subject() != AnchorSubject::from_trusted_state(&subject)? {
                return Err(DurableError::Conflict);
            }
        }
        if !r.retired() {
            match (
                self.completed_policy_approval(image)?,
                r.scope.policy_authorization,
            ) {
                (None, None) if r.scope.policy.digest() == admission.policy => {}
                (Some(p), Some(statement))
                    if p.target_policy() == r.scope.policy && p.statement_digest() == statement => {
                }
                _ => return Err(DurableError::Conflict),
            }
        }
        Ok(())
    }
    fn roster_witness_scope(
        &self,
        image: &Image,
        policy: &HistoricalSessionPolicy,
    ) -> Result<(VerifiedDevice, JournalIdentity), DurableError> {
        let (original, id) = self.policy_witness_scope(image, policy)?;
        if image.policy_pending.is_some() || !image.policy_coordination_retired() {
            return Err(DurableError::Suspended);
        }
        if let Some(r) = &image.roster_witness {
            if r.coordination.is_some_and(|c| {
                Some(c.proposal.witness_binding()) != policy.anchor_requirement().binding()
            }) {
                return Err(DurableError::Conflict);
            }
        }
        Ok((original, id))
    }
    /// Open a historical control client for this original enrollment's R operation.
    /// It grants no runtime permission and does not prepare, commit or acknowledge R.
    pub fn roster_refresh_anchor_client(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        self.policy_renewal_anchor_client(original_policy, pin, transport, timeout)
    }
    /// Retain and seal one root-approved same-credential roster target. Exact retries
    /// preserve the original sealed bytes. The journal's actual predecessor must
    /// match the original enrollment; an old split authority state is not repaired.
    pub fn prepare_witnessed_roster_refresh(
        &mut self,
        operation: RosterRefreshId,
        original_policy: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        target: &VerifiedDevice,
        now: u64,
        client: AnchorClient,
    ) -> Result<Proposal, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            image.check_time_floor(now)?;
            let (original, id) = self.roster_witness_scope(&image, original_policy)?;
            self.intent.verify_device(target)?;
            if target.credential_digest() != original.credential_digest()
                || target.key != original.key
            {
                return Err(DurableError::Conflict);
            }
            admit(target, policy, now)?;
            let completion = self.policy_enrollment_completion(&image, original_policy)?;
            let authorization = match &completion {
                Some(c) => {
                    c.approval().check_context_policy(original_policy, policy)?;
                    Some(c.approval().statement_digest())
                }
                None if policy.checkpoint() == original_policy.checkpoint() => None,
                _ => return Err(DurableError::Conflict),
            };
            let Phase::Accepted { admission, .. } = &image.phase else {
                return Err(DurableError::Corrupt);
            };
            let existing = image.roster_witness.as_ref();
            if existing.is_some_and(|r| r.scope.operation == operation) {
                let r = existing.ok_or(DurableError::Conflict)?;
                if r.scope.target != target.roster().checkpoint()
                    || r.scope.policy != policy.checkpoint()
                    || r.scope.policy_authorization != authorization
                    || r.retired()
                {
                    return Err(DurableError::Conflict);
                }
            } else {
                image.require_roster_retired()?;
                if existing.is_some_and(|r| {
                    target.roster().checkpoint().version() <= r.scope.target.version()
                }) {
                    return Err(Error::Checkpoint.into());
                }
                let scope = RosterRefreshScope {
                    operation,
                    previous: admission.checkpoint,
                    target: target.roster().checkpoint(),
                    policy: policy.checkpoint(),
                    policy_authorization: authorization,
                };
                if scope.target.version() <= scope.previous.version() {
                    return Err(Error::Checkpoint.into());
                }
                image.roster_witness = Some(WitnessRoster {
                    scope,
                    roster: target.roster().as_bytes().to_vec(),
                    coordination: None,
                    abandoned: false,
                });
                self.validate_witness_roster(&image)?;
                self.save(&image)?;
                image = self.image()?;
            }
            let lease = self.witness_lease(&original, original_policy, id)?;
            let path = self.paths.installation.files()[1];
            let proposal = match DeviceJournal::inspect_roster_refresh_preparation(
                path,
                self.key()?,
                &original,
                original_policy,
                id,
            )? {
                Some(p) => p,
                None => {
                    if image
                        .roster_witness
                        .as_ref()
                        .is_none_or(|r| r.coordination.is_some())
                    {
                        return Err(DurableError::Conflict);
                    }
                    let mut journal = DeviceJournal::open_anchored_retained(
                        path,
                        self.key()?,
                        &original,
                        original_policy,
                        id,
                        client,
                    )?;
                    if let Some(completion) = completion {
                        journal.retain_enrollment_policy_completion(completion)?;
                    }
                    journal.prepare_roster_refresh(
                        operation,
                        &RosterRefreshMaterials {
                            original: &original,
                            original_policy,
                            policy,
                            target,
                        },
                        now,
                    )?
                }
            };
            self.retain_roster_proposal(image, original_policy, proposal)?;
            drop(lease);
            Ok(proposal)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn retain_roster_proposal(
        &mut self,
        mut image: Image,
        policy: &HistoricalSessionPolicy,
        proposal: Proposal,
    ) -> Result<(), DurableError> {
        let (original, id) = self.roster_witness_scope(&image, policy)?;
        let r = image
            .roster_witness
            .as_mut()
            .ok_or(DurableError::Conflict)?;
        if r.abandoned
            || proposal.scope() != &r.scope
            || proposal.subject() != AnchorSubject::for_device(id, &original, policy)?
            || Some(proposal.witness_binding()) != policy.anchor_requirement().binding()
        {
            return Err(DurableError::Conflict);
        }
        let expected = Coordination {
            proposal,
            terminal: None,
            retired: false,
        };
        if let Some(prior) = r.coordination {
            if prior != expected {
                return Err(DurableError::Conflict);
            }
        } else {
            r.coordination = Some(expected);
            self.save(&image)?;
        }
        if self
            .image()?
            .roster_witness
            .as_ref()
            .and_then(|r| r.coordination)
            != Some(expected)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    /// Inspect the actual original R preparation after an uncertain local return.
    /// None means local absence only; no network command or new target is created.
    pub fn recover_witnessed_roster_refresh_preparation(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<Option<Proposal>, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let (original, id) = self.roster_witness_scope(&image, original_policy)?;
            let r = image
                .roster_witness
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if r.abandoned || r.coordination.is_some_and(|c| c.terminal.is_some()) {
                return Err(DurableError::Conflict);
            }
            let lease = self.witness_lease(&original, original_policy, id)?;
            let found = DeviceJournal::inspect_roster_refresh_preparation(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                original_policy,
                id,
            )?;
            if let Some(p) = found {
                self.retain_roster_proposal(image, original_policy, p)?;
            } else if r.coordination.is_some() {
                return Err(DurableError::Conflict);
            }
            drop(lease);
            Ok(found)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Abandon only a staged intent whose proposal has never been released by
    /// this original enrollment and whose journal has no pending target. Holds
    /// the original service lease, sends nothing, and grants no witness outcome.
    /// Reserved/terminal operations must use their exact witness reconciliation.
    pub fn abandon_unprepared_roster_refresh(
        &mut self,
        operation: RosterRefreshId,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<WitnessedRosterRefreshProgress, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let (original, id) = self.roster_witness_scope(&image, original_policy)?;
            let r = image
                .roster_witness
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if r.scope.operation != operation || r.coordination.is_some() {
                return Err(DurableError::Conflict);
            }
            if r.abandoned {
                return Ok(r.progress());
            }
            let scope = r.scope;
            let lease = self.witness_lease(&original, original_policy, id)?;
            if DeviceJournal::inspect_roster_refresh_preparation(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                original_policy,
                id,
            )?
            .is_some()
            {
                return Err(DurableError::Suspended);
            }
            image
                .roster_witness
                .as_mut()
                .ok_or(DurableError::Corrupt)?
                .abandoned = true;
            self.save(&image)?;
            let expected = WitnessedRosterRefreshProgress::AbandonedBeforePreparation(scope);
            if self.witnessed_roster_refresh_progress()? != Some(expected) {
                return Err(DurableError::Conflict);
            }
            drop(lease);
            Ok(expected)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read authenticated R coordination without borrowing a signer or runtime.
    pub fn witnessed_roster_refresh_progress(
        &mut self,
    ) -> Result<Option<WitnessedRosterRefreshProgress>, DurableError> {
        Ok(self
            .image()?
            .roster_witness
            .as_ref()
            .map(WitnessRoster::progress))
    }
    pub(in crate::enrollment) fn persisted_roster_terminal(
        &mut self,
        policy: &HistoricalSessionPolicy,
    ) -> Result<PersistedRosterTerminal, DurableError> {
        let image = self.image()?;
        self.roster_witness_scope(&image, policy)?;
        let c = image
            .roster_witness
            .as_ref()
            .and_then(|r| r.coordination)
            .ok_or(DurableError::Conflict)?;
        Ok(PersistedRosterTerminal {
            proposal: c.proposal,
            disposition: c.terminal.ok_or(DurableError::Suspended)?,
            completion: self.policy_enrollment_completion(&image, policy)?,
        })
    }
    /// Fresh exact R status, historical installation, original terminal, ACK and
    /// pending cleanup in that order. Recovery may finish after runtime expiry.
    pub fn reconcile_witnessed_roster_refresh(
        &mut self,
        proposal: &Proposal,
        original_policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_roster(proposal, original_policy, client, Action::Status)
    }
    /// Commit only this independently prepared original target under live current P.
    pub fn commit_witnessed_roster_refresh(
        &mut self,
        proposal: &Proposal,
        original_policy: &HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_roster(
            proposal,
            original_policy,
            client,
            Action::Commit { policy, now },
        )
    }
    /// Close the original R target. If already committed, its result remains Applied.
    pub fn close_witnessed_roster_refresh(
        &mut self,
        proposal: &Proposal,
        original_policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_roster(proposal, original_policy, client, Action::Close)
    }
    fn run_witnessed_roster(
        &mut self,
        proposal: &Proposal,
        policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
        action: Action<'_>,
    ) -> Result<State, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let (original, id) = self.roster_witness_scope(&image, policy)?;
            let r = image
                .roster_witness
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if proposal.scope() != &r.scope {
                return Err(DurableError::Conflict);
            }
            if r.coordination.is_none() {
                self.recover_witnessed_roster_refresh_preparation(policy)?
                    .ok_or(DurableError::Suspended)?;
                image = self.image()?;
            }
            let r = image
                .roster_witness
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            let mut c = r.coordination.ok_or(DurableError::Conflict)?;
            if c.proposal != *proposal || client.pin().binding() != proposal.witness_binding() {
                return Err(DurableError::Conflict);
            }
            if let Action::Commit {
                policy: current, ..
            } = action
            {
                if current.checkpoint() != r.scope.policy {
                    return Err(DurableError::Conflict);
                }
            }
            client.check_device(&original)?;
            policy.check_external_signer(client.pin().public_key())?;
            if client
                .pin()
                .public_key()
                .shares_component(&original.authority_key)
            {
                return Err(Error::Scope.into());
            }
            let lease = self.witness_lease(&original, policy, id)?;
            if c.retired {
                return Ok(c.terminal.ok_or(DurableError::Corrupt)?.state());
            }
            if c.terminal.is_none() {
                match action {
                    Action::Status => {}
                    Action::Commit {
                        policy: current,
                        now,
                    } => {
                        image.check_time_floor(now)?;
                        let Phase::Accepted { admission, .. } = &image.phase else {
                            return Err(DurableError::Corrupt);
                        };
                        let target = self.historical_device_metadata(
                            &admission.certificate,
                            &r.roster,
                            r.scope.target,
                        )?;
                        admit(&target, current, now)?;
                        client
                            .exchange(
                                proposal.subject(),
                                AnchorOperation::commit_roster_refresh(proposal),
                            )?
                            .roster_refresh_state(proposal)?;
                    }
                    Action::Close => {
                        client
                            .exchange(
                                proposal.subject(),
                                AnchorOperation::close_roster_refresh(proposal),
                            )?
                            .roster_refresh_state(proposal)?;
                    }
                }
                let observed = DeviceJournal::recover_roster_refresh(
                    self.paths.installation.files()[1],
                    self.key()?,
                    &original,
                    policy,
                    id,
                    *proposal,
                    client,
                )?;
                #[cfg(all(test, unix))]
                tests::renewal::boundary("independent-roster-observed");
                let disposition = match observed {
                    State::Applied => WitnessedRosterRefreshDisposition::Applied,
                    State::Closed => WitnessedRosterRefreshDisposition::Closed,
                    State::Prepared | State::Unavailable => return Ok(observed),
                    State::Acknowledged => return Err(DurableError::Conflict),
                };
                if disposition == WitnessedRosterRefreshDisposition::Applied {
                    let Phase::Accepted { admission, .. } = &mut image.phase else {
                        return Err(DurableError::Corrupt);
                    };
                    admission.roster = r.roster.clone();
                    admission.checkpoint = r.scope.target;
                    if image.policy_completed.is_some() {
                        image.policy_device_binding = PolicyDeviceBinding::MonotonicRoster;
                    }
                }
                c.terminal = Some(disposition);
                image
                    .roster_witness
                    .as_mut()
                    .ok_or(DurableError::Corrupt)?
                    .coordination = Some(c);
                self.validate_policy_pending(&image)?;
                self.validate_witness_roster(&image)?;
                self.save(&image)?;
            }
            let terminal = self.persisted_roster_terminal(policy)?;
            #[cfg(all(test, unix))]
            tests::renewal::boundary("independent-roster-terminal");
            DeviceJournal::retire_roster_refresh(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                policy,
                id,
                &terminal,
                client,
            )?;
            #[cfg(all(test, unix))]
            tests::renewal::boundary("independent-roster-retired");
            image = self.image()?;
            let r = image.roster_witness.as_mut().ok_or(DurableError::Corrupt)?;
            let current = r.coordination.ok_or(DurableError::Corrupt)?;
            if current.proposal != terminal.proposal
                || current.terminal != Some(terminal.disposition)
            {
                return Err(DurableError::Conflict);
            }
            r.coordination = Some(Coordination {
                retired: true,
                ..current
            });
            self.save(&image)?;
            if self
                .image()?
                .roster_witness
                .as_ref()
                .and_then(|r| r.coordination)
                != Some(Coordination {
                    retired: true,
                    ..current
                })
            {
                return Err(DurableError::Conflict);
            }
            #[cfg(all(test, unix))]
            tests::renewal::boundary("independent-roster-complete");
            drop(lease);
            Ok(terminal.disposition.state())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
