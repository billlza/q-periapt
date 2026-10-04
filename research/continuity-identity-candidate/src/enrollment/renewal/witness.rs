// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment owns terminal durability, exact witness ACK and cleanup.
use super::*;
use crate::{
    AnchorCredentialRenewalProposal as Proposal, AnchorCredentialRenewalState as State,
    AnchorOperation, AnchorSubject, DeviceJournal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Terminal {
    Applied,
    Closed,
}
impl Terminal {
    fn byte(self) -> u8 {
        match self {
            Self::Applied => 1,
            Self::Closed => 2,
        }
    }
    fn state(self) -> State {
        match self {
            Self::Applied => State::Applied,
            Self::Closed => State::Closed,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Coordination {
    pub(super) intent: WitnessedCredentialIntent,
    terminal: Option<Terminal>,
}
pub(super) struct ClosedRenewal {
    operation: CredentialRenewalId,
    statement: [u8; 32],
    target: RosterCheckpoint,
}
impl ClosedRenewal {
    pub(super) fn status(&self) -> CredentialRenewalStatus {
        CredentialRenewalStatus::Closed {
            operation: self.operation,
            statement: self.statement,
            target: self.target,
        }
    }
}
pub(super) struct WitnessRenewal {
    floor: u64,
    pub(super) closed: Option<ClosedRenewal>,
    pub(super) coordination: Option<Coordination>,
}
impl WitnessRenewal {
    pub(super) fn new() -> Self {
        Self {
            floor: 0,
            closed: None,
            coordination: None,
        }
    }
    pub(super) fn check_next(&self, grant: &VerifiedCredentialRenewal) -> Result<(), DurableError> {
        if self.coordination.is_some() {
            return Err(DurableError::Suspended);
        }
        if grant.successor_device().roster().checkpoint().version() <= self.floor
            || self
                .closed
                .as_ref()
                .is_some_and(|c| c.operation == grant.operation())
        {
            return Err(Error::Retired.into());
        }
        Ok(())
    }
    pub(super) fn validate(&self, renewal: &LocalRenewal) -> Result<(), DurableError> {
        if renewal.time_floor != 0 || renewal.expired.is_some() {
            return Err(DurableError::Corrupt);
        }
        let expected_floor = self
            .closed
            .as_ref()
            .map(|c| c.target.version())
            .or_else(|| renewal.completed.as_ref().map(|c| c.target.version()))
            .unwrap_or(0);
        if self.floor != expected_floor {
            return Err(DurableError::Corrupt);
        }
        if let Some(closed) = &self.closed {
            crate::codec::nonzero(&closed.statement)?;
            if renewal.completed.as_ref().is_some_and(|c| {
                c.operation == closed.operation || c.target.version() >= closed.target.version()
            }) || renewal
                .pending
                .as_ref()
                .is_some_and(|p| p.operation == closed.operation)
            {
                return Err(DurableError::Corrupt);
            }
        }
        if let Some(coord) = self.coordination {
            let p = coord.intent;
            if matches!(p, WitnessedCredentialIntent::Cancellation(_))
                && coord.terminal == Some(Terminal::Applied)
            {
                return Err(DurableError::Corrupt);
            }
            let matches = match coord.terminal {
                None => renewal
                    .pending
                    .as_ref()
                    .is_some_and(|v| v.operation == p.operation() && v.statement == p.statement()),
                Some(Terminal::Applied) => {
                    renewal.pending.is_none()
                        && self.closed.is_none()
                        && renewal.completed.as_ref().is_some_and(|v| {
                            v.operation == p.operation() && v.statement == p.statement()
                        })
                }
                Some(Terminal::Closed) => {
                    renewal.pending.is_none()
                        && self.closed.as_ref().is_some_and(|v| {
                            v.operation == p.operation() && v.statement == p.statement()
                        })
                }
            };
            if !matches {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.floor.to_be_bytes());
        match &self.closed {
            None => out.push(0),
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c.operation.as_bytes());
                out.extend_from_slice(&c.statement);
                out.extend_from_slice(&c.target.version().to_be_bytes());
                out.extend_from_slice(&c.target.digest());
            }
        }
        match self.coordination {
            None => out.push(0),
            Some(c) => {
                match c.intent {
                    WitnessedCredentialIntent::Proposal(p) => {
                        out.push(1);
                        out.extend_from_slice(&p.to_bytes());
                    }
                    WitnessedCredentialIntent::Cancellation(c) => {
                        out.push(2);
                        out.extend_from_slice(&c.to_bytes());
                    }
                }
                out.push(c.terminal.map_or(0, Terminal::byte));
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>, cancellation: bool) -> Result<Self, DurableError> {
        let floor = d.u64()?;
        let closed = match d.array::<1>()? {
            [0] => None,
            [1] => Some(ClosedRenewal {
                operation: CredentialRenewalId::from_trusted_state(d.array()?)?,
                statement: d.array()?,
                target: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
            }),
            _ => return Err(DurableError::Corrupt),
        };
        let coordination = match d.array::<1>()? {
            [0] => None,
            [kind @ 1..=2] if kind == 1 || cancellation => Some(Coordination {
                intent: if kind == 1 {
                    WitnessedCredentialIntent::Proposal(Proposal::from_trusted_state(d.take(296)?)?)
                } else {
                    WitnessedCredentialIntent::Cancellation(
                        crate::AnchorCredentialRenewalCancellation::from_trusted_state(
                            d.take(248)?,
                        )?,
                    )
                },
                terminal: match d.array::<1>()? {
                    [0] => None,
                    [1] => Some(Terminal::Applied),
                    [2] => Some(Terminal::Closed),
                    _ => return Err(DurableError::Corrupt),
                },
            }),
            _ => return Err(DurableError::Corrupt),
        };
        if cancellation
            != coordination
                .is_some_and(|c| matches!(c.intent, WitnessedCredentialIntent::Cancellation(_)))
        {
            return Err(DurableError::Corrupt);
        }
        Ok(Self {
            floor,
            closed,
            coordination,
        })
    }
}

impl DeviceEnrollment {
    /// Build a historical renewal carrier from the original controlled signer.
    /// This does not admit the credential or permit traffic after expiry. Every
    /// renewal operation separately binds the original policy, journal and intent.
    pub fn credential_renewal_anchor_client(
        &mut self,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
        pin: AnchorPin,
        transport: Box<dyn AnchorTransport>,
        timeout: Duration,
    ) -> Result<AnchorClient, DurableError> {
        let policy = policy.as_ref();
        let result = (|| {
            let image = self.image()?;
            let original = self.original_device(&image, now)?;
            let Phase::Accepted {
                admission,
                stage: AdmissionPhase::Active | AdmissionPhase::Refreshing { .. },
                ..
            } = &image.phase
            else {
                return Err(DurableError::Suspended);
            };
            if admission.policy != policy.checkpoint().digest()
                || policy.anchor_requirement().binding() != Some(pin.binding())
            {
                return Err(DurableError::Conflict);
            }
            policy.check_external_signer(pin.public_key())?;
            if pin.public_key().shares_component(&original.authority_key) {
                return Err(Error::Scope.into());
            }
            Ok(AnchorClient::new(
                pin,
                self.signer(image.identity, false)?,
                transport,
                timeout,
            )?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn witness_scope(
        &self,
        image: &Image,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
    ) -> Result<(VerifiedDevice, JournalIdentity), DurableError> {
        let policy = policy.as_ref();
        let original = self.original_device(image, now)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if admission.policy != policy.checkpoint().digest()
            || policy.anchor_requirement().binding().is_none()
            || !image.renewal.as_ref().is_some_and(LocalRenewal::witnessed)
        {
            return Err(DurableError::Conflict);
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        let admitted = self.historical_device(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
            now,
        )?;
        let completed = renewal.completed.as_ref();
        if admitted.credential_digest()
            != completed.map_or(original.credential_digest(), |c| c.credential)
            || admitted.account_id() != original.account_id()
            || admitted.device_id() != original.device_id()
            || admitted.generation() != original.generation()
            || admitted.key != original.key
            || admitted.description.family != original.description.family
            || completed.is_some_and(|c| {
                c.owner != crate::bootstrap::storage_owner(&original)
                    || c.policy != admission.policy
                    || admission.checkpoint.version() < c.target.version()
                    || (admission.checkpoint.version() == c.target.version()
                        && admission.checkpoint != c.target)
            })
        {
            return Err(DurableError::Conflict);
        }
        if let Some(coord) = image
            .renewal
            .as_ref()
            .and_then(|r| r.witness.as_ref())
            .and_then(|w| w.coordination)
        {
            if coord.intent.subject()
                != AnchorSubject::for_device(admission.journal, &original, policy)?
                || Some(coord.intent.witness_binding()) != policy.anchor_requirement().binding()
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok((original, admission.journal))
    }
    #[cfg(all(test, unix))]
    pub(in crate::enrollment) fn persisted_witness_terminal(
        &mut self,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
        proposal: Proposal,
    ) -> Result<PersistedRenewalTerminal, DurableError> {
        self.persisted_witness_intent_terminal(
            policy.as_ref(),
            now,
            WitnessedCredentialIntent::Proposal(proposal),
        )
    }
    pub(in crate::enrollment) fn persisted_witness_intent_terminal(
        &mut self,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
        proposal: WitnessedCredentialIntent,
    ) -> Result<PersistedRenewalTerminal, DurableError> {
        let image = self.image()?;
        self.witness_scope(&image, policy, now)?;
        let coord = image
            .renewal
            .as_ref()
            .and_then(|r| r.witness.as_ref())
            .and_then(|w| w.coordination)
            .ok_or(DurableError::Conflict)?;
        if coord.intent != proposal {
            return Err(DurableError::Conflict);
        }
        Ok(PersistedRenewalTerminal {
            intent: proposal,
            state: coord.terminal.ok_or(DurableError::Conflict)?.state(),
        })
    }
    fn witness_lease(
        &self,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        id: JournalIdentity,
    ) -> Result<DeviceInstallation, DurableError> {
        let policy = policy.as_ref();
        let mut owner = DeviceInstallation::open_bound(
            self.paths.installation.clone(),
            &self.key()?,
            original,
            policy,
        )?;
        if owner.identity()? != id || owner.status()? != crate::InstallationStatus::Active {
            return Err(DurableError::Conflict);
        }
        Ok(owner)
    }
    fn pending_grant(
        image: &Image,
        original: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    ) -> Result<VerifiedCredentialRenewal, DurableError> {
        let policy = policy.as_ref();
        let pending = image
            .renewal
            .as_ref()
            .and_then(|r| r.pending.as_ref())
            .ok_or(DurableError::Conflict)?;
        let grant = VerifiedCredentialRenewal::from_journal(&pending.wire, original.roster())?;
        if grant.operation() != pending.operation
            || grant.statement_digest() != pending.statement
            || grant.original_storage_owner() != crate::bootstrap::storage_owner(original)
            || grant.policy_digest() != policy.checkpoint().digest()
        {
            return Err(DurableError::Conflict);
        }
        grant.resolve_established(original, policy.checkpoint().digest())?;
        Ok(grant)
    }
    /// Recover an existing exact journal proposal into this original enrollment.
    /// This never creates/reseals a target or sends a witness command. `None`
    /// means no retained local proposal, never witness NoCommit. It remains usable
    /// with independently verified historical policy after policy/runtime expiry.
    pub fn recover_witnessed_credential_renewal_preparation(
        &mut self,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
    ) -> Result<Option<Proposal>, DurableError> {
        let result = self
            .recover_witnessed_preparation(policy.as_ref(), now)
            .and_then(|intent| intent.map(WitnessedCredentialIntent::proposal).transpose());
        if result.is_err() {
            self.close();
        }
        result
    }
    fn recover_witnessed_preparation(
        &mut self,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
    ) -> Result<Option<WitnessedCredentialIntent>, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let (original, id) = self.witness_scope(&image, policy, now)?;
            let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
            let coordination = renewal
                .witness
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .coordination;
            if let Some(coord) = coordination.filter(|c| c.terminal.is_some()) {
                return Ok(Some(coord.intent)); // Historical retained metadata only.
            }
            if renewal.pending.is_none() {
                return Ok(None);
            }
            let grant = Self::pending_grant(&image, &original, policy)?;
            let _lease = self.witness_lease(&original, policy, id)?;
            let proposal = DeviceJournal::inspect_witnessed_credential_intent(
                self.paths.installation.files()[1],
                self.key()?,
                &original,
                policy,
                id,
            )?;
            let Some(proposal) = proposal else {
                if coordination.is_some() {
                    return Err(DurableError::Conflict);
                }
                return Ok(None);
            };
            if proposal.operation() != grant.operation()
                || proposal.statement() != grant.statement_digest()
            {
                return Err(DurableError::Conflict);
            }
            Ok(Some(self.retain_witnessed_preparation(
                image, policy, now, proposal,
            )?))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn retain_witnessed_preparation(
        &mut self,
        mut image: Image,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
        proposal: WitnessedCredentialIntent,
    ) -> Result<WitnessedCredentialIntent, DurableError> {
        let witness = image
            .renewal
            .as_mut()
            .and_then(|r| r.witness.as_mut())
            .ok_or(DurableError::Corrupt)?;
        match witness.coordination {
            Some(c) if c.intent == proposal && c.terminal.is_none() => {}
            None => {
                witness.coordination = Some(Coordination {
                    intent: proposal,
                    terminal: None,
                });
                self.save(&image)?;
            }
            _ => return Err(DurableError::Conflict),
        }
        let readback = self.image()?;
        self.witness_scope(&readback, policy, now)?;
        let saved = readback
            .renewal
            .as_ref()
            .and_then(|r| r.witness.as_ref())
            .and_then(|w| w.coordination)
            .ok_or(DurableError::Corrupt)?;
        if saved.intent != proposal || saved.terminal.is_some() {
            return Err(DurableError::Conflict);
        }
        Ok(proposal)
    }
    /// Prepare the original staged renewal once and durably retain its exact
    /// proposal. The returned public proposal needs independent witness approval;
    /// it is not itself permission to commit. Unknown results preserve both files.
    pub fn prepare_witnessed_credential_renewal(
        &mut self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        client: AnchorClient,
    ) -> Result<Proposal, DurableError> {
        let result = (|| {
            let image = self.image()?;
            let (original, id) = self.witness_scope(&image, policy, now)?;
            let grant = Self::pending_grant(&image, &original, policy)?;
            client.check_device(&original)?;
            if Some(client.pin().binding()) != policy.anchor_requirement().binding() {
                return Err(DurableError::Conflict);
            }
            let lease = self.witness_lease(&original, policy, id)?;
            let path = self.paths.installation.files()[1];
            let proposal = match DeviceJournal::inspect_credential_renewal_preparation(
                path,
                self.key()?,
                &original,
                policy,
                id,
            )? {
                Some(p) => p,
                None => {
                    if image
                        .renewal
                        .as_ref()
                        .and_then(|r| r.witness.as_ref())
                        .is_some_and(|w| w.coordination.is_some())
                    {
                        return Err(DurableError::Conflict);
                    }
                    let mut journal = DeviceJournal::open_anchored(
                        path,
                        self.key()?,
                        &original,
                        policy,
                        id,
                        client,
                    )?;
                    journal.prepare_enrollment_credential_renewal(
                        &original,
                        &grant,
                        policy,
                        now,
                        image.renewal.as_ref().and_then(|r| r.completed.as_ref()),
                    )?
                }
            };
            if proposal.operation() != grant.operation()
                || proposal.statement() != grant.statement_digest()
            {
                return Err(DurableError::Conflict);
            }
            let proposal = self
                .retain_witnessed_preparation(
                    image,
                    policy.historical(),
                    now,
                    WitnessedCredentialIntent::Proposal(proposal),
                )?
                .proposal()?;
            drop(lease);
            Ok(proposal)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Reserve an original staged grant for independent cancellation without
    /// sealing a target or dispatching a witness command. The returned descriptor
    /// must be approved through the independent witness control plane. Ordinary
    /// journal work remains suspended until Closed is durably retained and ACKed.
    /// Historical policy suffices; this does not grant current device authority.
    pub fn prepare_witnessed_credential_cancellation(
        &mut self,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
    ) -> Result<crate::AnchorCredentialRenewalCancellation, DurableError> {
        let policy = policy.as_ref();
        let result = (|| {
            let image = self.image()?;
            let (original, id) = self.witness_scope(&image, policy, now)?;
            let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
            if let Some(coord) = renewal.witness.as_ref().and_then(|w| w.coordination) {
                match coord.intent {
                    WitnessedCredentialIntent::Cancellation(c) if coord.terminal.is_some() => {
                        return Ok(c)
                    }
                    WitnessedCredentialIntent::Cancellation(_) => {}
                    WitnessedCredentialIntent::Proposal(_) => return Err(DurableError::Conflict),
                }
            }
            let grant = Self::pending_grant(&image, &original, policy)?;
            let _lease = self.witness_lease(&original, policy, id)?;
            let path = self.paths.installation.files()[1];
            // A retained coordination must never be re-created against a changed
            // head after local record loss. Inspect and compare before reserving.
            if let Some(coord) = renewal.witness.as_ref().and_then(|w| w.coordination) {
                if DeviceJournal::inspect_witnessed_credential_intent(
                    path,
                    self.key()?,
                    &original,
                    policy,
                    id,
                )? != Some(coord.intent)
                {
                    return Err(DurableError::Conflict);
                }
            }
            let cancellation = DeviceJournal::reserve_enrollment_credential_cancellation(
                path,
                self.key()?,
                &original,
                policy,
                id,
                grant.historical(),
                renewal.completed.as_ref(),
            )?;
            #[cfg(all(test, unix))]
            super::super::tests::renewal::boundary("cancellation-reserved");
            self.retain_witnessed_preparation(
                image,
                policy,
                now,
                WitnessedCredentialIntent::Cancellation(cancellation),
            )?;
            Ok(cancellation)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Observe and finish only an original prepared renewal. Never sends Commit
    /// or Close. Exact terminal durability precedes ACK and local intent removal.
    /// Prepared/Unavailable remain Pending unless an exact terminal was retained.
    pub fn reconcile_witnessed_credential_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
        client: &mut AnchorClient,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let policy = policy.as_ref();
        self.run_witnessed_renewal(
            operation,
            statement,
            policy,
            now,
            client,
            RenewalAction::Observe,
        )
    }
    /// Explicitly commit a root-approved original proposal while its successor is
    /// live, then complete cross-store recovery. Unknown replies return no owner.
    pub fn commit_witnessed_credential_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &VerifiedSessionPolicy,
        now: u64,
        client: &mut AnchorClient,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        self.run_witnessed_renewal(
            operation,
            statement,
            policy.historical(),
            now,
            client,
            RenewalAction::Commit(policy),
        )
    }
    /// Explicitly close an independently prepared original proposal. A competing
    /// successful Commit remains Committed; early Closed does not expire C0/C1.
    pub fn close_witnessed_credential_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        now: u64,
        client: &mut AnchorClient,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let policy = policy.as_ref();
        self.run_witnessed_renewal(
            operation,
            statement,
            policy,
            now,
            client,
            RenewalAction::Close,
        )
    }
    fn run_witnessed_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
        client: &mut AnchorClient,
        action: RenewalAction<'_>,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result =
            self.coordinate_witnessed_renewal(operation, statement, policy, now, client, action);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn coordinate_witnessed_renewal(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
        client: &mut AnchorClient,
        action: RenewalAction<'_>,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let mut image = self.image()?;
        let (original, id) = self.witness_scope(&image, policy, now)?;
        client.check_device(&original)?;
        if Some(client.pin().binding()) != policy.anchor_requirement().binding() {
            return Err(DurableError::Conflict);
        }
        let prepared = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        if prepared
            .witness
            .as_ref()
            .ok_or(DurableError::Corrupt)?
            .coordination
            .is_none()
        {
            if let Some(pending) = &prepared.pending {
                if pending.operation != operation || pending.statement != statement {
                    return Err(DurableError::Conflict);
                }
                self.recover_witnessed_preparation(policy, now)?;
                image = self.image()?;
            }
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        let witness = renewal.witness.as_ref().ok_or(DurableError::Corrupt)?;
        let Some(coord) = witness.coordination else {
            if renewal
                .pending
                .as_ref()
                .is_some_and(|p| p.operation == operation && p.statement == statement)
            {
                return if matches!(action, RenewalAction::Observe) {
                    renewal.status()
                } else {
                    Err(DurableError::Suspended)
                };
            }
            if let Some(c) = renewal
                .completed
                .as_ref()
                .filter(|c| c.operation == operation && c.statement == statement)
            {
                return Ok(CredentialRenewalStatus::Committed {
                    operation,
                    statement,
                    target: c.target,
                });
            }
            if let Some(c) = witness
                .closed
                .as_ref()
                .filter(|c| c.operation == operation && c.statement == statement)
            {
                return Ok(c.status());
            }
            return Err(DurableError::Conflict);
        };
        let proposal = coord.intent;
        if proposal.operation() != operation || proposal.statement() != statement {
            return Err(DurableError::Conflict);
        }
        let _lease = self.witness_lease(&original, policy, id)?;
        let journal_path = self.paths.installation.files()[1].to_path_buf();
        if coord.terminal.is_none() {
            let grant = Self::pending_grant(&image, &original, policy)?;
            // Verify exact retained intent before dispatching even an explicit
            // command. A substituted local proposal cannot cause remote work.
            if DeviceJournal::inspect_witnessed_credential_intent(
                &journal_path,
                self.key()?,
                &original,
                policy,
                id,
            )? != Some(proposal)
            {
                return Err(DurableError::Conflict);
            }
            let command = match action {
                RenewalAction::Observe => None,
                RenewalAction::Commit(current) => {
                    admit(grant.successor_device(), current, now)?;
                    Some(AnchorOperation::commit_credential_renewal(
                        &proposal.proposal()?,
                    ))
                }
                RenewalAction::Close => match proposal {
                    WitnessedCredentialIntent::Proposal(p) => {
                        Some(AnchorOperation::close_credential_renewal(&p))
                    }
                    WitnessedCredentialIntent::Cancellation(_) => None,
                },
            };
            if let Some(command) = command {
                proposal.interpret(&client.exchange(proposal.subject(), command)?)?;
            }
            let observed = DeviceJournal::recover_witnessed_credential_intent(
                &journal_path,
                self.key()?,
                &original,
                policy,
                id,
                proposal,
                client,
            )?;
            #[cfg(all(test, unix))]
            super::super::tests::renewal::boundary("witness-observed");
            let terminal = match observed {
                State::Applied => Terminal::Applied,
                State::Closed => Terminal::Closed,
                State::Prepared | State::Unavailable => return renewal.status(),
                State::Acknowledged => return Err(Error::State.into()),
            };
            let renewal = image.renewal.as_mut().ok_or(DurableError::Corrupt)?;
            let witness = renewal.witness.as_mut().ok_or(DurableError::Corrupt)?;
            witness.floor = grant.successor_device().roster().checkpoint().version();
            witness.coordination = Some(Coordination {
                intent: proposal,
                terminal: Some(terminal),
            });
            match terminal {
                Terminal::Applied => {
                    witness.closed = None;
                    image = self.persist_renewal_completion(
                        image,
                        &grant,
                        LocalRenewalCommit::for_grant(&grant),
                    )?;
                }
                Terminal::Closed => {
                    witness.closed = Some(ClosedRenewal {
                        operation,
                        statement,
                        target: grant.successor_device().roster().checkpoint(),
                    });
                    renewal.pending = None;
                    self.save(&image)?;
                    image = self.image()?;
                }
            }
        }
        self.witness_scope(&image, policy, now)?;
        let durable = image
            .renewal
            .as_ref()
            .and_then(|r| r.witness.as_ref())
            .and_then(|w| w.coordination)
            .ok_or(DurableError::Corrupt)?;
        if durable.intent != proposal {
            return Err(DurableError::Conflict);
        }
        durable.terminal.ok_or(DurableError::Corrupt)?;
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("witness-terminal");
        // This crate-private entry accepts only the authenticated durable record,
        // never caller-constructed terminal metadata. It checks local bytes before
        // sending ACK and deletes only the exact intent, retaining the image.
        DeviceJournal::retire_witnessed_credential_intent(
            &journal_path,
            self.key()?,
            &original,
            policy,
            id,
            &self.persisted_witness_intent_terminal(policy, now, proposal)?,
            client,
        )?;
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("witness-retired");
        let witness = image
            .renewal
            .as_mut()
            .and_then(|r| r.witness.as_mut())
            .ok_or(DurableError::Corrupt)?;
        witness.coordination = None;
        self.save(&image)?;
        #[cfg(all(test, unix))]
        super::super::tests::renewal::boundary("witness-complete");
        self.credential_renewal_status()
    }
    pub(super) fn activate_witnessed(
        mut self,
        mut image: Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<EnrolledDevice, DurableError> {
        let original = self.original_device(&image, now)?;
        let current = self.admitted_renewed(&image, policy, now)?;
        let authority = RetainedInstallationAuthority::active_installation(&original, policy);
        let mut service = DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            &original,
            policy,
            anchor,
        )?;
        let journal = service.stores()?.0;
        let Phase::Accepted {
            admission, stage, ..
        } = &mut image.phase
        else {
            return Err(DurableError::Corrupt);
        };
        if journal.identity()? != admission.journal {
            return Err(DurableError::Conflict);
        }
        if let AdmissionPhase::Refreshing { previous } = *stage {
            let checkpoint = journal.roster_checkpoint(current.account_id())?;
            if checkpoint != previous && checkpoint != admission.checkpoint {
                return Err(DurableError::Conflict);
            }
            if journal.install_roster(current.roster(), now)? != admission.checkpoint {
                return Err(DurableError::Conflict);
            }
            *stage = AdmissionPhase::Active;
            self.save(&image)?;
        }
        if image
            .renewal
            .as_ref()
            .is_some_and(|r| r.completed.is_some())
        {
            journal.check_renewed_local_device(&authority, &current, policy, now)?;
        }
        journal.check_enrollment_authority(&current, policy, now)?;
        let signer = self.signer(image.identity, false)?;
        admit(&current, policy, now)?;
        Ok(EnrolledDevice {
            active: Some(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device: current,
            }),
        })
    }
}
#[derive(Clone, Copy)]
enum RenewalAction<'a> {
    Observe,
    Commit(&'a VerifiedSessionPolicy),
    Close,
}
