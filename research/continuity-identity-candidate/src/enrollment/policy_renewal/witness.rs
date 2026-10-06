// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment retains the exact P terminal before witness ACK/cleanup.
use super::*;
use crate::{
    AnchorOperation, AnchorPolicyRenewalProposal as Proposal, AnchorPolicyRenewalState as State,
    AnchorSubject, DeviceJournal, PolicyRenewalMaterials, RetainedInstallationAuthority,
};

mod operational;
pub(crate) use operational::EnrollmentPolicyCompletion;

/// Historical disposition of one independent P operation; no runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedPolicyRenewalDisposition {
    /// Exact target was committed by the original witness and installed locally.
    Applied,
    /// Original witness permanently closed this target without application.
    Closed,
}
impl WitnessedPolicyRenewalDisposition {
    fn state(self) -> State {
        match self {
            Self::Applied => State::Applied,
            Self::Closed => State::Closed,
        }
    }
}
/// Original enrollment's authenticated coordination metadata, never a live lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedPolicyRenewalProgress {
    /// Exact local sealed proposal is retained; witness preparation is independent.
    Reserved {
        /// Original independently typed proposal.
        proposal: Proposal,
        /// Signed target policy checkpoint, not proof of adoption.
        target: PolicyCheckpoint,
    },
    /// This exact terminal has been persisted by the original enrollment.
    Terminal {
        /// Original proposal whose terminal was retained.
        proposal: Proposal,
        /// Exact historical target checkpoint.
        target: PolicyCheckpoint,
        /// Actual Applied/Closed terminal, distinct from unavailable history.
        disposition: WitnessedPolicyRenewalDisposition,
        /// Witness ACK and original pending cleanup have been read back and saved.
        /// This does not acknowledge the journal policy receipt or release an owner.
        retired: bool,
    },
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Coordination {
    proposal: Proposal,
    terminal: Option<WitnessedPolicyRenewalDisposition>,
    retired: bool,
}
pub(in crate::enrollment) struct WitnessPolicy {
    binding: [u8; 32],
    coordination: Option<Coordination>,
    closed: Option<RetainedPolicyRenewal>,
    completed: Option<Proposal>,
}
impl WitnessPolicy {
    pub(in crate::enrollment) fn validate(&self, image: &Image) -> Result<(), DurableError> {
        crate::codec::nonzero(&self.binding)?;
        if image.renewal.is_some()
            || image.policy_resolution.is_some()
            || image.roster_resolution.is_some()
            || image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal
            || !matches!(
                image.phase,
                Phase::Accepted {
                    stage: AdmissionPhase::Active,
                    ..
                }
            )
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(completed) = self.completed {
            if completed.witness_binding() != self.binding || image.policy_completed.is_none() {
                return Err(DurableError::Corrupt);
            }
        }
        let Some(c) = self.coordination else {
            return if image.policy_pending.is_some() && self.closed.is_none() {
                Ok(())
            } else {
                Err(DurableError::Corrupt)
            };
        };
        if c.proposal.witness_binding() != self.binding || (c.terminal.is_none() && c.retired) {
            return Err(DurableError::Corrupt);
        }
        let record = match c.terminal {
            None if self.closed.is_none() => image.policy_pending.as_ref(),
            Some(WitnessedPolicyRenewalDisposition::Applied)
                if image.policy_pending.is_none() && self.closed.is_none() =>
            {
                image.policy_completed.as_ref()
            }
            Some(WitnessedPolicyRenewalDisposition::Closed) if image.policy_pending.is_none() => {
                self.closed.as_ref()
            }
            _ => return Err(DurableError::Corrupt),
        }
        .ok_or(DurableError::Corrupt)?;
        if record.operation != c.proposal.operation() || record.statement != c.proposal.statement()
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        out.extend_from_slice(&self.binding);
        match self.coordination {
            None => out.push(0),
            Some(c) => {
                let tag = match (c.terminal, c.retired) {
                    (None, false) => 1,
                    (Some(WitnessedPolicyRenewalDisposition::Applied), false) => 2,
                    (Some(WitnessedPolicyRenewalDisposition::Closed), false) => 3,
                    (Some(WitnessedPolicyRenewalDisposition::Applied), true) => 4,
                    (Some(WitnessedPolicyRenewalDisposition::Closed), true) => 5,
                    _ => return Err(DurableError::Corrupt),
                };
                out.push(tag);
                out.extend_from_slice(&c.proposal.to_bytes());
            }
        }
        out.push(u8::from(self.closed.is_some()));
        if let Some(closed) = &self.closed {
            closed.encode(out)?;
        }
        out.push(u8::from(self.completed.is_some()));
        if let Some(completed) = self.completed {
            out.extend_from_slice(&completed.to_bytes());
        }
        Ok(())
    }
    pub(in crate::enrollment) fn decode(
        d: &mut Decoder<'_>,
        completion_metadata: bool,
    ) -> Result<Self, DurableError> {
        let binding = d.array()?;
        crate::codec::nonzero(&binding)?;
        let coordination = match d.array::<1>()? {
            [0] => None,
            [tag @ 1..=5] => {
                let proposal = Proposal::from_trusted_state(d.take(296)?)?;
                let terminal = match tag {
                    1 => None,
                    2 | 4 => Some(WitnessedPolicyRenewalDisposition::Applied),
                    3 | 5 => Some(WitnessedPolicyRenewalDisposition::Closed),
                    _ => return Err(DurableError::Corrupt),
                };
                Some(Coordination {
                    proposal,
                    terminal,
                    retired: tag >= 4,
                })
            }
            _ => return Err(DurableError::Corrupt),
        };
        let closed = match d.array::<1>()? {
            [0] => None,
            [1] => Some(RetainedPolicyRenewal::decode(d)?),
            _ => return Err(DurableError::Corrupt),
        };
        let completed = if completion_metadata {
            match d.array::<1>()? {
                [0] => None,
                [1] => Some(Proposal::from_trusted_state(d.take(296)?)?),
                _ => return Err(DurableError::Corrupt),
            }
        } else {
            coordination
                .filter(|c| {
                    c.retired && c.terminal == Some(WitnessedPolicyRenewalDisposition::Applied)
                })
                .map(|c| c.proposal)
        };
        Ok(Self {
            binding,
            coordination,
            closed,
            completed,
        })
    }
}
/// Constructible only from the authenticated original enrollment's durable readback.
/// A signed approval or caller-supplied disposition cannot grant ACK authority.
pub(crate) struct PersistedPolicyTerminal {
    proposal: Proposal,
    disposition: WitnessedPolicyRenewalDisposition,
    approval: HistoricalPolicyRenewal,
    previous: Option<HistoricalPolicyRenewal>,
    previous_completion: Option<std::sync::Arc<EnrollmentPolicyCompletion>>,
}
impl PersistedPolicyTerminal {
    pub(crate) fn proposal(&self) -> Proposal {
        self.proposal
    }
    pub(crate) fn disposition(&self) -> WitnessedPolicyRenewalDisposition {
        self.disposition
    }
    pub(crate) fn approval(&self) -> &HistoricalPolicyRenewal {
        &self.approval
    }
    pub(crate) fn previous(&self) -> Option<&HistoricalPolicyRenewal> {
        self.previous.as_ref()
    }
    pub(crate) fn previous_completion(&self) -> Option<&EnrollmentPolicyCompletion> {
        self.previous_completion.as_deref()
    }
}
#[derive(Clone, Copy)]
enum Action<'a> {
    Status,
    Commit {
        proposal: &'a Proposal,
        target: &'a VerifiedSessionPolicy,
        now: u64,
    },
    Close,
}

impl DeviceEnrollment {
    pub(super) fn begin_witness_policy(
        &self,
        image: &mut Image,
        original: &HistoricalSessionPolicy,
        operation: PolicyRenewalId,
    ) -> Result<(), DurableError> {
        image.require_roster_retired()?;
        let Some(binding) = original.anchor_requirement().binding() else {
            return Ok(());
        };
        if image.renewal.is_some()
            || image.policy_resolution.is_some()
            || image.roster_resolution.is_some()
        {
            return Err(DurableError::Conflict);
        }
        if let Some(w) = &image.policy_witness {
            if w.binding != binding
                || w.coordination.is_some_and(|c| !c.retired)
                || w.closed.as_ref().is_some_and(|r| r.operation == operation)
            {
                return Err(DurableError::Conflict);
            }
        }
        let completed = image.policy_witness.as_ref().and_then(|w| w.completed);
        image.policy_witness = Some(WitnessPolicy {
            binding,
            completed,
            coordination: None,
            closed: None,
        });
        Ok(())
    }
    pub(super) fn validate_witness_policy(&self, image: &Image) -> Result<(), DurableError> {
        let Some(w) = &image.policy_witness else {
            return Ok(());
        };
        w.validate(image)?;
        let original = self.original_device_metadata(image)?;
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        if let Some(completed) = w.completed {
            let record = image
                .policy_completed
                .as_ref()
                .ok_or(DurableError::Corrupt)?;
            if record.operation != completed.operation()
                || record.statement != completed.statement()
            {
                let current = w.coordination.ok_or(DurableError::Corrupt)?;
                let approval = self.authenticated_policy_record(record)?;
                if current.retired
                    || current.terminal != Some(WitnessedPolicyRenewalDisposition::Applied)
                    || approval.scope().previous_authorization != Some(completed.statement())
                    || completed.target_head().revision()
                        > current.proposal.expected_head().revision()
                {
                    return Err(DurableError::Conflict);
                }
            }
        }
        if let Some(current) = w.coordination {
            if current.retired
                && current.terminal == Some(WitnessedPolicyRenewalDisposition::Applied)
                && w.completed != Some(current.proposal)
            {
                return Err(DurableError::Conflict);
            }
        }
        if let Some(closed) = &w.closed {
            let approval = self.authenticated_policy_record(closed)?;
            if image.policy_device_binding == PolicyDeviceBinding::MonotonicRoster {
                approval.check_credential_lineage(&original, &original)?;
                let approved = approval.scope().current_roster;
                if admission.checkpoint.version() < approved.version()
                    || (admission.checkpoint.version() == approved.version()
                        && admission.checkpoint != approved)
                {
                    return Err(DurableError::Conflict);
                }
            } else {
                approval.check_devices(&original, &original)?;
            }
            self.check_policy_predecessor(image, &approval, &original, admission)?;
        }
        for proposal in w
            .coordination
            .map(|c| c.proposal)
            .into_iter()
            .chain(w.completed)
        {
            let mut subject = admission.journal.as_bytes().to_vec();
            subject.extend_from_slice(&crate::bootstrap::storage_owner(&original));
            subject.extend_from_slice(&admission.policy);
            if proposal.subject() != AnchorSubject::from_trusted_state(&subject)? {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    pub(in crate::enrollment) fn policy_witness_scope(
        &self,
        image: &Image,
        policy: &HistoricalSessionPolicy,
    ) -> Result<(VerifiedDevice, JournalIdentity), DurableError> {
        let binding = policy
            .anchor_requirement()
            .binding()
            .ok_or(DurableError::AnchorRequired)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if image.renewal.is_some()
            || admission.policy != policy.checkpoint().digest()
            || image.policy_device_binding == PolicyDeviceBinding::CredentialRenewal
            || image
                .policy_witness
                .as_ref()
                .is_some_and(|w| w.binding != binding)
        {
            return Err(DurableError::Conflict);
        }
        for record in image
            .policy_pending
            .iter()
            .chain(image.policy_completed.iter())
            .chain(
                image
                    .policy_witness
                    .iter()
                    .filter_map(|w| w.closed.as_ref()),
            )
        {
            self.authenticated_policy_record(record)?
                .check_original_policy(policy)?;
        }
        Ok((self.original_device_metadata(image)?, admission.journal))
    }
    /// Construct an original-signer control client for historical P coordination.
    /// This grants no runtime/session owner; each command rechecks its exact scope.
    pub fn policy_renewal_anchor_client(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let (original, _) = self.policy_witness_scope(&image, original_policy)?;
            if original_policy.anchor_requirement().binding() != Some(pin.binding()) {
                return Err(DurableError::Conflict);
            }
            original_policy.check_external_signer(pin.public_key())?;
            if pin.public_key().shares_component(&original.authority_key) {
                return Err(Error::Scope.into());
            }
            let client =
                AnchorClient::new(pin, self.signer(image.identity, false)?, transport, timeout)?;
            client.check_device(&original)?;
            Ok(client)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read issuer materials from the original required journal under its service
    /// lease and fresh witness head. No policy/credential/runtime permission is granted.
    pub fn witnessed_policy_renewal_request(
        &mut self,
        operation: PolicyRenewalId,
        original_policy: &HistoricalSessionPolicy,
        client: AnchorClient,
    ) -> Result<crate::PolicyRenewalRequest, DurableError> {
        let result = (|| {
            let image = self.image()?;
            image.require_roster_retired()?;
            let (original, id) = self.policy_witness_scope(&image, original_policy)?;
            if image.policy_pending.is_some()
                || image
                    .policy_witness
                    .as_ref()
                    .and_then(|w| w.coordination)
                    .is_some_and(|c| !c.retired || c.proposal.operation() == operation)
            {
                return Err(DurableError::Suspended);
            }
            let lease = self.witness_lease(&original, original_policy, id)?;
            let mut journal = DeviceJournal::open_anchored_retained(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                original_policy,
                id,
                client,
            )?;
            if let Some(completed) = self.policy_enrollment_completion(&image, original_policy)? {
                journal.retain_enrollment_policy_completion(completed)?;
            }
            let authority =
                RetainedInstallationAuthority::active_installation(&original, original_policy);
            let completed = self.completed_policy_approval(&image)?;
            let scope = journal.policy_renewal_request_scope(
                &crate::installation::PolicyScope {
                    authority: &authority,
                    original_policy,
                    original_device: &original,
                },
                &original,
                operation,
                completed.as_ref(),
                None,
            )?;
            let Phase::Accepted { admission, .. } = &image.phase else {
                return Err(DurableError::Corrupt);
            };
            let request = crate::PolicyRenewalRequest::new(
                scope,
                original.clone(),
                original,
                admission.certificate.clone(),
                admission.certificate.clone(),
            );
            journal.close();
            drop(lease);
            Ok(request)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn retain_policy_proposal(
        &mut self,
        mut image: Image,
        policy: &HistoricalSessionPolicy,
        proposal: Proposal,
    ) -> Result<Proposal, DurableError> {
        let (original, id) = self.policy_witness_scope(&image, policy)?;
        let pending = image
            .policy_pending
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        if proposal.operation() != pending.operation
            || proposal.statement() != pending.statement
            || proposal.subject() != AnchorSubject::for_device(id, &original, policy)?
            || Some(proposal.witness_binding()) != policy.anchor_requirement().binding()
        {
            return Err(DurableError::Conflict);
        }
        let w = image
            .policy_witness
            .as_mut()
            .ok_or(DurableError::Conflict)?;
        let expected = Coordination {
            proposal,
            terminal: None,
            retired: false,
        };
        if let Some(prior) = w.coordination {
            if prior != expected {
                return Err(DurableError::Conflict);
            }
        } else {
            w.coordination = Some(expected);
            self.save(&image)?;
        }
        let readback = self.image()?;
        if readback
            .policy_witness
            .as_ref()
            .and_then(|w| w.coordination)
            != Some(expected)
        {
            return Err(DurableError::Conflict);
        }
        Ok(proposal)
    }
    /// Recover an original local sealed proposal without current runtime or network.
    /// None means no local preparation, never witness no-commit. Retains exact
    /// metadata in this original enrollment after an interrupted prepare return.
    pub fn recover_witnessed_policy_renewal_preparation(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
    ) -> Result<Option<Proposal>, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let (original, id) = self.policy_witness_scope(&image, original_policy)?;
            if image.policy_pending.is_none() {
                return Err(DurableError::Conflict);
            }
            let lease = self.witness_lease(&original, original_policy, id)?;
            let observed = DeviceJournal::inspect_policy_renewal_preparation(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                original_policy,
                id,
            )?;
            let result = match observed {
                Some(p) => Some(self.retain_policy_proposal(image, original_policy, p)?),
                None => {
                    if image
                        .policy_witness
                        .as_ref()
                        .and_then(|w| w.coordination)
                        .is_some()
                    {
                        return Err(DurableError::Conflict);
                    }
                    None
                }
            };
            drop(lease);
            Ok(result)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Seal/recover the exact staged P target and retain its proposal before any
    /// independent witness preparation. Exact retries never reseal a saved target.
    pub fn prepare_witnessed_policy_renewal(
        &mut self,
        original_policy: &HistoricalSessionPolicy,
        previous_policy: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        client: AnchorClient,
    ) -> Result<Proposal, DurableError> {
        let result = (|| {
            let image = self.image()?;
            image.check_time_floor(now)?;
            let (original, id) = self.policy_witness_scope(&image, original_policy)?;
            let pending = image
                .policy_pending
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            let retained = self.authenticated_policy_record(pending)?;
            let materials = PolicyRenewalMaterials {
                original: original_policy,
                previous: previous_policy,
                target,
                original_device: &original,
                current_device: &original,
            };
            let approval = VerifiedPolicyRenewal::from_bytes(
                retained.as_bytes(),
                retained.scope(),
                &materials,
                now,
            )?;
            let lease = self.witness_lease(&original, original_policy, id)?;
            let path = self.paths.installation.files()[1];
            let proposal = match DeviceJournal::inspect_policy_renewal_preparation(
                path,
                self.key()?,
                &original,
                original_policy,
                id,
            )? {
                Some(p) => p,
                None => {
                    if image
                        .policy_witness
                        .as_ref()
                        .and_then(|w| w.coordination)
                        .is_some()
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
                    if let Some(completed) =
                        self.policy_enrollment_completion(&image, original_policy)?
                    {
                        journal.retain_enrollment_policy_completion(completed)?;
                    }
                    journal.prepare_policy_renewal(&approval, &materials, now)?
                }
            };
            let result = self.retain_policy_proposal(image, original_policy, proposal)?;
            drop(lease);
            Ok(result)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read only this enrollment's retained proposal/terminal. None means the
    /// proposal has not been retained here, not that the witness did not commit.
    pub fn witnessed_policy_renewal_progress(
        &mut self,
    ) -> Result<Option<WitnessedPolicyRenewalProgress>, DurableError> {
        let image = self.image()?;
        let Some(w) = &image.policy_witness else {
            return Ok(None);
        };
        let Some(c) = w.coordination else {
            return Ok(None);
        };
        let record = match c.terminal {
            None => image.policy_pending.as_ref(),
            Some(WitnessedPolicyRenewalDisposition::Applied) => image.policy_completed.as_ref(),
            Some(WitnessedPolicyRenewalDisposition::Closed) => w.closed.as_ref(),
        }
        .ok_or(DurableError::Corrupt)?;
        Ok(Some(match c.terminal {
            None => WitnessedPolicyRenewalProgress::Reserved {
                proposal: c.proposal,
                target: record.target,
            },
            Some(disposition) => WitnessedPolicyRenewalProgress::Terminal {
                proposal: c.proposal,
                target: record.target,
                disposition,
                retired: c.retired,
            },
        }))
    }
    pub(in crate::enrollment) fn persisted_policy_terminal(
        &mut self,
        policy: &HistoricalSessionPolicy,
    ) -> Result<PersistedPolicyTerminal, DurableError> {
        let image = self.image()?;
        self.policy_witness_scope(&image, policy)?;
        let w = image
            .policy_witness
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let c = w.coordination.ok_or(DurableError::Conflict)?;
        let disposition = c.terminal.ok_or(DurableError::Suspended)?;
        let record = match disposition {
            WitnessedPolicyRenewalDisposition::Applied => image.policy_completed.as_ref(),
            WitnessedPolicyRenewalDisposition::Closed => w.closed.as_ref(),
        }
        .ok_or(DurableError::Conflict)?;
        Ok(PersistedPolicyTerminal {
            proposal: c.proposal,
            disposition,
            approval: self.authenticated_policy_record(record)?,
            previous_completion: if disposition == WitnessedPolicyRenewalDisposition::Closed {
                self.policy_enrollment_completion(&image, policy)?
            } else {
                None
            },
            previous: if disposition == WitnessedPolicyRenewalDisposition::Closed {
                self.completed_policy_approval(&image)?
            } else {
                None
            },
        })
    }
    /// Query, persist the original terminal, then ACK and clear only its pending
    /// intent. Historical completion never releases an operational owner.
    pub fn reconcile_witnessed_policy_renewal(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_policy(
            operation,
            statement,
            original_policy,
            client,
            Action::Status,
        )
    }
    /// Commit the exact already independently prepared target while its current
    /// policy and identity remain live. Lost replies require original reconciliation.
    pub fn commit_witnessed_policy_renewal(
        &mut self,
        proposal: &Proposal,
        original_policy: &HistoricalSessionPolicy,
        target: &VerifiedSessionPolicy,
        now: u64,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_policy(
            proposal.operation(),
            proposal.statement(),
            original_policy,
            client,
            Action::Commit {
                proposal,
                target,
                now,
            },
        )
    }
    /// Close an exact witness preparation; an already applied target remains Applied.
    /// This does not invent a target when no local sealed proposal exists.
    pub fn close_witnessed_policy_renewal(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
    ) -> Result<State, DurableError> {
        self.run_witnessed_policy(operation, statement, original_policy, client, Action::Close)
    }
    fn run_witnessed_policy(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        policy: &HistoricalSessionPolicy,
        client: &mut AnchorClient,
        action: Action<'_>,
    ) -> Result<State, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let (original, id) = self.policy_witness_scope(&image, policy)?;
            if image
                .policy_witness
                .as_ref()
                .and_then(|w| w.coordination)
                .is_none()
            {
                let pending = image
                    .policy_pending
                    .as_ref()
                    .ok_or(DurableError::Conflict)?;
                if pending.operation != operation || pending.statement != statement {
                    return Err(DurableError::Conflict);
                }
                self.recover_witnessed_policy_renewal_preparation(policy)?
                    .ok_or(DurableError::Suspended)?;
                image = self.image()?;
            }
            let mut c = image
                .policy_witness
                .as_ref()
                .and_then(|w| w.coordination)
                .ok_or(DurableError::Suspended)?;
            if c.proposal.operation() != operation
                || c.proposal.statement() != statement
                || client.pin().binding() != c.proposal.witness_binding()
            {
                return Err(DurableError::Conflict);
            }
            if let Action::Commit {
                proposal, target, ..
            } = action
            {
                if c.proposal != *proposal {
                    return Err(DurableError::Conflict);
                }
                let record = match c.terminal {
                    None => image.policy_pending.as_ref(),
                    Some(WitnessedPolicyRenewalDisposition::Applied) => {
                        image.policy_completed.as_ref()
                    }
                    Some(WitnessedPolicyRenewalDisposition::Closed) => image
                        .policy_witness
                        .as_ref()
                        .and_then(|w| w.closed.as_ref()),
                }
                .ok_or(DurableError::Conflict)?;
                self.authenticated_policy_record(record)?
                    .check_context_policy(policy, target)?;
            }
            client.check_device(&original)?;
            let lease = self.witness_lease(&original, policy, id)?;
            if let Some(state) = c.terminal {
                if c.retired {
                    return Ok(state.state());
                }
            }
            if c.terminal.is_none() {
                match action {
                    Action::Status => {}
                    Action::Commit { target, now, .. } => {
                        image.check_time_floor(now)?;
                        admit(&original, target, now)?;
                        let reply = client.exchange(
                            c.proposal.subject(),
                            AnchorOperation::commit_policy_renewal(&c.proposal),
                        )?;
                        reply.policy_renewal_state(&c.proposal)?;
                    }
                    Action::Close => {
                        let reply = client.exchange(
                            c.proposal.subject(),
                            AnchorOperation::close_policy_renewal(&c.proposal),
                        )?;
                        reply.policy_renewal_state(&c.proposal)?;
                    }
                }
                let observed = DeviceJournal::recover_policy_renewal(
                    self.paths.installation.files()[1],
                    self.key()?,
                    &original,
                    policy,
                    id,
                    c.proposal,
                    client,
                )?;
                #[cfg(all(test, unix))]
                super::super::tests::renewal::boundary("independent-policy-observed");
                let disposition = match observed {
                    State::Applied => WitnessedPolicyRenewalDisposition::Applied,
                    State::Closed => WitnessedPolicyRenewalDisposition::Closed,
                    State::Prepared | State::Unavailable => return Ok(observed),
                    State::Acknowledged => return Err(DurableError::Conflict),
                };
                let pending = image.policy_pending.take().ok_or(DurableError::Conflict)?;
                match disposition {
                    WitnessedPolicyRenewalDisposition::Applied => {
                        image.policy_completed = Some(pending)
                    }
                    WitnessedPolicyRenewalDisposition::Closed => {
                        image
                            .policy_witness
                            .as_mut()
                            .ok_or(DurableError::Corrupt)?
                            .closed = Some(pending)
                    }
                }
                c.terminal = Some(disposition);
                image
                    .policy_witness
                    .as_mut()
                    .ok_or(DurableError::Corrupt)?
                    .coordination = Some(c);
                self.save(&image)?;
            }
            let terminal = self.persisted_policy_terminal(policy)?;
            #[cfg(all(test, unix))]
            super::super::tests::renewal::boundary("independent-policy-terminal");
            DeviceJournal::retire_policy_renewal(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                policy,
                id,
                &terminal,
                client,
            )?;
            #[cfg(all(test, unix))]
            super::super::tests::renewal::boundary("independent-policy-retired");
            image = self.image()?;
            let current = image.policy_witness.as_mut().ok_or(DurableError::Corrupt)?;
            let original_coord = current.coordination.ok_or(DurableError::Corrupt)?;
            if original_coord.proposal != terminal.proposal
                || original_coord.terminal != Some(terminal.disposition)
            {
                return Err(DurableError::Conflict);
            }
            if terminal.disposition == WitnessedPolicyRenewalDisposition::Applied {
                current.completed = Some(terminal.proposal);
            }
            current.coordination = Some(Coordination {
                retired: true,
                ..original_coord
            });
            self.save(&image)?;
            let readback = self.persisted_policy_terminal(policy)?;
            if readback.proposal != terminal.proposal
                || readback.disposition != terminal.disposition
            {
                return Err(DurableError::Conflict);
            }
            #[cfg(all(test, unix))]
            super::super::tests::renewal::boundary("independent-policy-complete");
            drop(lease);
            Ok(terminal.disposition.state())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

impl Image {
    pub(in crate::enrollment) fn policy_coordination_retired(&self) -> bool {
        self.policy_witness
            .as_ref()
            .is_none_or(|w| w.coordination.is_some_and(|c| c.retired))
    }
}
