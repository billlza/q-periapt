// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment's bounded, cross-file credential-renewal transaction.
use super::*;
mod expiry;
mod witness;
use crate::durable::{LocalRenewalCommit, LocalRenewalResolution, WitnessedCredentialIntent};
use crate::{CredentialRenewalId, RetainedInstallationAuthority, VerifiedCredentialRenewal};

// Constructed only by the original enrollment coordinator after authenticated
// durable terminal readback. Other modules cannot promote public metadata to it.
pub(crate) struct PersistedRenewalTerminal {
    intent: WitnessedCredentialIntent,
    state: crate::AnchorCredentialRenewalState,
}
impl PersistedRenewalTerminal {
    pub(crate) fn parts(
        &self,
    ) -> (
        WitnessedCredentialIntent,
        crate::AnchorCredentialRenewalState,
    ) {
        (self.intent, self.state)
    }
}

/// Historical progress for the original renewal operation, never traffic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRenewalStatus {
    /// No credential-renewal intent has been retained by this enrollment.
    Absent,
    /// The exact intent is durable; the journal outcome still needs reconciliation.
    /// This does not assert that the journal has not committed it.
    Pending {
        /// Caller-retained original operation.
        operation: CredentialRenewalId,
        /// Canonical root-signed statement, excluding randomized signatures.
        statement: [u8; 32],
    },
    /// An expired target was checked against monotonic predecessor history and
    /// its abandonment was durably retained. No target commit was observed, and
    /// the retained time floor prevents this expired target's later activation.
    ExpiredUncommitted {
        /// Original abandoned operation.
        operation: CredentialRenewalId,
        /// Exact abandoned root-signed statement.
        statement: [u8; 32],
        /// Authenticated head observed while the original journal was locked.
        observed_head: RosterCheckpoint,
        /// Trusted time of the historical observation, not a current permission.
        observed_at: u64,
    },
    /// The exact journal commit was observed and enrollment completion persisted.
    /// A later revocation, expiry or successor can still deny all operational use.
    Committed {
        /// Original committed operation.
        operation: CredentialRenewalId,
        /// Exact committed statement.
        statement: [u8; 32],
        /// Historical committed target; it is not a current authority checkpoint.
        target: RosterCheckpoint,
    },
    /// The independent witness permanently closed this exact target without
    /// applying it. The preceding credential may still be live.
    Closed {
        /// Original closed operation.
        operation: CredentialRenewalId,
        /// Exact closed root-signed statement.
        statement: [u8; 32],
        /// Rejected successor checkpoint, never current authority.
        target: RosterCheckpoint,
    },
}
struct Origin {
    certificate: Vec<u8>,
    roster: Vec<u8>,
    checkpoint: RosterCheckpoint,
}
struct Pending {
    operation: CredentialRenewalId,
    statement: [u8; 32],
    wire: Vec<u8>,
}
struct ExpiredRenewal {
    operation: CredentialRenewalId,
    statement: [u8; 32],
    observed_head: RosterCheckpoint,
    expired_at: u64,
    observed_at: u64,
}
impl ExpiredRenewal {
    fn status(&self) -> CredentialRenewalStatus {
        CredentialRenewalStatus::ExpiredUncommitted {
            operation: self.operation,
            statement: self.statement,
            observed_head: self.observed_head,
            observed_at: self.observed_at,
        }
    }
}
pub(super) struct LocalRenewal {
    origin: Origin,
    pending: Option<Pending>,
    completed: Option<LocalRenewalCommit>,
    time_floor: u64,
    expired: Option<ExpiredRenewal>,
    witness: Option<witness::WitnessRenewal>,
}
impl LocalRenewal {
    pub(super) fn extended(&self) -> bool {
        self.time_floor != 0 || self.expired.is_some() || self.witness.is_some()
    }
    pub(super) fn witnessed(&self) -> bool {
        self.witness.is_some()
    }
    pub(super) fn cancellation(&self) -> bool {
        self.witness
            .as_ref()
            .and_then(|w| w.coordination)
            .is_some_and(|c| matches!(c.intent, WitnessedCredentialIntent::Cancellation(_)))
    }
    fn check_time_floor(&self, now: u64) -> Result<(), DurableError> {
        if now < self.time_floor {
            return Err(Error::Validity.into());
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), DurableError> {
        if self.pending.is_none()
            && self.completed.is_none()
            && self.expired.is_none()
            && self
                .witness
                .as_ref()
                .and_then(|w| w.closed.as_ref())
                .is_none()
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(expired) = &self.expired {
            crate::codec::nonzero(&expired.statement)?;
            if expired.expired_at == 0
                || expired.expired_at > expired.observed_at
                || expired.observed_at != self.time_floor
                || self
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.operation == expired.operation)
                || self
                    .completed
                    .as_ref()
                    .is_some_and(|c| c.operation == expired.operation)
            {
                return Err(DurableError::Corrupt);
            }
        }
        if let Some(witness) = &self.witness {
            witness.validate(self)?;
        }
        Ok(())
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        field(out, &self.origin.certificate)?;
        field(out, &self.origin.roster)?;
        out.extend_from_slice(&self.origin.checkpoint.version().to_be_bytes());
        out.extend_from_slice(&self.origin.checkpoint.digest());
        match &self.pending {
            None => out.push(0),
            Some(p) => {
                if p.wire.is_empty() || p.wire.len() > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                    return Err(DurableError::Capacity);
                }
                out.push(1);
                out.extend_from_slice(p.operation.as_bytes());
                out.extend_from_slice(&p.statement);
                out.extend_from_slice(
                    &u32::try_from(p.wire.len())
                        .map_err(|_| DurableError::Capacity)?
                        .to_be_bytes(),
                );
                out.extend_from_slice(&p.wire);
            }
        }
        match &self.completed {
            None => out.push(0),
            Some(c) => {
                out.push(1);
                c.encode(out);
            }
        }
        self.validate()?;
        if self.extended() {
            out.extend_from_slice(&self.time_floor.to_be_bytes());
            match &self.expired {
                None => out.push(0),
                Some(expired) => {
                    out.push(1);
                    out.extend_from_slice(expired.operation.as_bytes());
                    out.extend_from_slice(&expired.statement);
                    out.extend_from_slice(&expired.observed_head.version().to_be_bytes());
                    out.extend_from_slice(&expired.observed_head.digest());
                    out.extend_from_slice(&expired.expired_at.to_be_bytes());
                    out.extend_from_slice(&expired.observed_at.to_be_bytes());
                }
            }
        }
        if let Some(witness) = &self.witness {
            witness.encode(out);
        }
        Ok(())
    }
    pub(super) fn decode(
        d: &mut Decoder<'_>,
        extended: bool,
        witnessed: bool,
        cancellation: bool,
    ) -> Result<Self, DurableError> {
        let origin = Origin {
            certificate: take(d)?,
            roster: take(d)?,
            checkpoint: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
        };
        let pending = match d.array::<1>()? {
            [0] => None,
            [1] => {
                let operation = CredentialRenewalId::from_trusted_state(d.array()?)?;
                let statement = d.array()?;
                crate::codec::nonzero(&statement)?;
                let size = u32::from_be_bytes(d.array()?) as usize;
                if size == 0 || size > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                    return Err(DurableError::Corrupt);
                }
                Some(Pending {
                    operation,
                    statement,
                    wire: d.take(size)?.to_vec(),
                })
            }
            _ => return Err(DurableError::Corrupt),
        };
        let completed = match d.array::<1>()? {
            [0] => None,
            [1] => Some(LocalRenewalCommit::decode(d)?),
            _ => return Err(DurableError::Corrupt),
        };
        let (time_floor, expired) = if extended {
            let time_floor = d.u64()?;
            if time_floor == 0 && !witnessed {
                return Err(DurableError::Corrupt);
            }
            let expired = match d.array::<1>()? {
                [0] => None,
                [1] => Some(ExpiredRenewal {
                    operation: CredentialRenewalId::from_trusted_state(d.array()?)?,
                    statement: d.array()?,
                    observed_head: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
                    expired_at: d.u64()?,
                    observed_at: d.u64()?,
                }),
                _ => return Err(DurableError::Corrupt),
            };
            (time_floor, expired)
        } else {
            (0, None)
        }; // QPENST02 predates expired-intent reconciliation.
        let value = Self {
            origin,
            pending,
            completed,
            time_floor,
            expired,
            witness: if witnessed {
                Some(witness::WitnessRenewal::decode(d, cancellation)?)
            } else {
                None
            },
        };
        value.validate()?;
        Ok(value)
    }
    fn status(&self) -> Result<CredentialRenewalStatus, DurableError> {
        self.validate()?;
        if let Some(p) = &self.pending {
            return Ok(CredentialRenewalStatus::Pending {
                operation: p.operation,
                statement: p.statement,
            });
        }
        if let Some(expired) = &self.expired {
            return Ok(expired.status());
        }
        if let Some(closed) = self.witness.as_ref().and_then(|w| w.closed.as_ref()) {
            return Ok(closed.status());
        }
        let c = self.completed.as_ref().ok_or(DurableError::Corrupt)?;
        Ok(CredentialRenewalStatus::Committed {
            operation: c.operation,
            statement: c.statement,
            target: c.target,
        })
    }
}
impl DeviceEnrollment {
    /// Read original renewal progress without extending validity or membership.
    pub fn credential_renewal_status(&mut self) -> Result<CredentialRenewalStatus, DurableError> {
        match self.image()?.renewal {
            None => Ok(CredentialRenewalStatus::Absent),
            Some(renewal) => renewal.status(),
        }
    }
    fn historical_device(
        &self,
        certificate: &[u8],
        roster: &[u8],
        checkpoint: RosterCheckpoint,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        let pin = AccountPin::new(
            crate::identity::account_id(&self.intent.root),
            self.intent.root.clone(),
            checkpoint,
            self.intent.description.family,
        )?;
        let at = pin.snapshot_start(certificate, roster)?;
        if at > now {
            return Err(Error::Validity.into());
        }
        Ok(pin.verify_device(certificate, roster, at)?)
    }
    fn original_device(&self, image: &Image, now: u64) -> Result<VerifiedDevice, DurableError> {
        let Phase::Accepted {
            request, admission, ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        let original = if let Some(renewal) = &image.renewal {
            self.historical_device(
                &renewal.origin.certificate,
                &renewal.origin.roster,
                renewal.origin.checkpoint,
                now,
            )?
        } else {
            self.historical_device(
                &admission.certificate,
                &admission.roster,
                admission.checkpoint,
                now,
            )?
        };
        self.intent.verify_device(&original)?;
        let at = original.description.validity.from();
        if at > now {
            return Err(Error::Validity.into());
        }
        let proof = VerifiedEnrollmentRequest::verify(request, &self.intent, at)?;
        if proof.identity != image.identity || proof.public != original.key {
            return Err(DurableError::Conflict);
        }
        self.signer(image.identity, false)?
            .check_device(&original)?;
        Ok(original)
    }
    /// Durably stage a same-key renewal under this ORIGINAL enrollment owner.
    /// Call activate to reconcile its original journal and publish an owner only
    /// after current admission. Unknown results require reopening this enrollment;
    /// an exact pending retry preserves the original bytes and operation identity.
    pub fn stage_credential_renewal(
        &mut self,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result =
            (|| {
                let mut image = self.image()?;
                let original = self.original_device(&image, now)?;
                let Phase::Accepted {
                    admission,
                    stage: AdmissionPhase::Active,
                    ..
                } = &image.phase
                else {
                    return Err(Error::State.into());
                };
                if grant.operation() != operation
                    || grant.original_storage_owner() != crate::bootstrap::storage_owner(&original)
                    || grant.policy_digest() != admission.policy
                    || admission.policy != policy.checkpoint().digest()
                {
                    return Err(DurableError::Conflict);
                }
                grant.resolve_established(&original, admission.policy)?;
                if let Some(renewal) = &image.renewal {
                    if renewal.witnessed() != policy.anchor_requirement().binding().is_some() {
                        return Err(DurableError::Conflict);
                    }
                    if let Some(p) = &renewal.pending {
                        if p.operation != operation || p.statement != grant.statement_digest() {
                            return Err(DurableError::Conflict);
                        }
                        return renewal.status();
                    }
                    if let Some(c) = renewal.completed.as_ref().filter(|c| {
                        c.operation == operation && c.statement == grant.statement_digest()
                    }) {
                        return Ok(CredentialRenewalStatus::Committed {
                            operation: c.operation,
                            statement: c.statement,
                            target: c.target,
                        });
                    }
                    if let Some(witness) = &renewal.witness {
                        witness.check_next(grant)?;
                    }
                }
                if let Some(renewal) = &image.renewal {
                    renewal.check_time_floor(now)?;
                    if renewal
                        .expired
                        .as_ref()
                        .is_some_and(|e| e.operation == operation)
                    {
                        return Err(DurableError::Conflict);
                    }
                }
                let current = self.historical_device(
                    &admission.certificate,
                    &admission.roster,
                    admission.checkpoint,
                    now,
                )?;
                if current.credential_digest() != grant.previous_device().credential_digest()
                    || admission.checkpoint.version()
                        > grant.previous_device().roster().checkpoint().version()
                    || (admission.checkpoint.version()
                        == grant.previous_device().roster().checkpoint().version()
                        && admission.checkpoint != grant.previous_device().roster().checkpoint())
                {
                    return Err(DurableError::Conflict);
                }
                admit(grant.successor_device(), policy, now)?;
                if image.renewal.is_none() {
                    image.renewal = Some(LocalRenewal {
                        origin: Origin {
                            certificate: admission.certificate.clone(),
                            roster: admission.roster.clone(),
                            checkpoint: admission.checkpoint,
                        },
                        pending: None,
                        completed: None,
                        time_floor: 0,
                        expired: None,
                        witness: policy
                            .anchor_requirement()
                            .binding()
                            .map(|_| witness::WitnessRenewal::new()),
                    });
                }
                image.renewal.as_mut().ok_or(DurableError::Corrupt)?.pending = Some(Pending {
                    operation,
                    statement: grant.statement_digest(),
                    wire: grant.as_bytes().to_vec(),
                });
                self.save(&image)?;
                #[cfg(all(test, unix))]
                super::tests::renewal::boundary("intent");
                self.credential_renewal_status()
            })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(super) fn admitted_renewed(
        &self,
        image: &Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        let original = self.original_device(image, now)?;
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        renewal.check_time_floor(now)?;
        if renewal.pending.is_none() && renewal.completed.is_none() && renewal.expired.is_some() {
            return Err(Error::Validity.into());
        }
        if renewal.pending.is_some()
            || renewal
                .witness
                .as_ref()
                .is_some_and(|w| w.coordination.is_some())
        {
            return Err(DurableError::Suspended);
        }
        let complete = renewal.completed.as_ref();
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        if admission.policy != policy.checkpoint().digest()
            || complete.is_some_and(|c| {
                c.policy != admission.policy
                    || c.owner != crate::bootstrap::storage_owner(&original)
            })
        {
            return Err(DurableError::Conflict);
        }
        let pin = AccountPin::new(
            original.account_id(),
            self.intent.root.clone(),
            admission.checkpoint,
            self.intent.description.family,
        )?;
        let current = pin.verify_device(&admission.certificate, &admission.roster, now)?;
        let expected_credential = complete.map_or(original.credential_digest(), |c| c.credential);
        if current.credential_digest() != expected_credential
            || current.account_id() != original.account_id()
            || current.device_id() != original.device_id()
            || current.generation() != original.generation()
            || current.key != original.key
            || current.description.family != original.description.family
        {
            return Err(DurableError::Conflict);
        }
        self.signer(image.identity, false)?.check_device(&current)?;
        admit(&current, policy, now)?;
        Ok(current)
    }
    pub(super) fn refresh_renewed_roster(
        &mut self,
        mut image: Image,
        previous: RosterCheckpoint,
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrollmentStatus, DurableError> {
        let original = self.original_device(&image, now)?;
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        renewal.check_time_floor(now)?;
        if renewal.pending.is_none() && renewal.completed.is_none() && renewal.expired.is_some() {
            return Err(Error::Validity.into());
        }
        if renewal.pending.is_some()
            || renewal
                .witness
                .as_ref()
                .is_some_and(|w| w.coordination.is_some())
        {
            return Err(DurableError::Suspended);
        }
        let completed = renewal.completed.as_ref();
        let Phase::Accepted {
            admission, stage, ..
        } = &mut image.phase
        else {
            return Err(DurableError::Corrupt);
        };
        if admission.policy != policy.checkpoint().digest()
            || completed.is_some_and(|c| {
                c.policy != admission.policy
                    || c.owner != crate::bootstrap::storage_owner(&original)
            })
        {
            return Err(DurableError::Conflict);
        }
        let current = pin.verify_device(&admission.certificate, roster, now)?;
        if current.credential_digest()
            != completed.map_or(original.credential_digest(), |c| c.credential)
            || current.account_id() != original.account_id()
            || current.device_id() != original.device_id()
            || current.generation() != original.generation()
            || current.key != original.key
            || current.description.family != original.description.family
        {
            return Err(DurableError::Conflict);
        }
        admit(&current, policy, now)?;
        let next = current.roster().checkpoint();
        if next.version() <= previous.version() {
            return Err(Error::Checkpoint.into());
        }
        match *stage {
            AdmissionPhase::Refreshing { previous: expected }
                if expected == previous && admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == next => {}
            AdmissionPhase::Active if admission.checkpoint == previous => {
                admission.roster = roster.to_vec();
                admission.checkpoint = next;
                *stage = AdmissionPhase::Refreshing { previous };
                self.save(&image)?;
            }
            _ => return Err(DurableError::Conflict),
        }
        admit(&current, policy, now)?;
        self.status()
    }
    fn persist_renewal_completion(
        &mut self,
        mut image: Image,
        grant: &VerifiedCredentialRenewal,
        commit: LocalRenewalCommit,
    ) -> Result<Image, DurableError> {
        let Phase::Accepted { admission, .. } = &mut image.phase else {
            return Err(DurableError::Corrupt);
        };
        admission.certificate = grant.successor_credential()?.to_vec();
        admission.roster = grant.successor_device().roster().as_bytes().to_vec();
        admission.checkpoint = grant.successor_device().roster().checkpoint();
        let renewal = image.renewal.as_mut().ok_or(DurableError::Corrupt)?;
        renewal.pending = None;
        renewal.completed = Some(commit);
        renewal.expired = None;
        self.save(&image)?;
        self.image() // Durable readback must precede journal receipt pruning.
    }
    pub(super) fn activate_renewed(
        mut self,
        mut image: Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<EnrolledDevice, DurableError> {
        if image.renewal.as_ref().is_some_and(LocalRenewal::witnessed) {
            return self.activate_witnessed(image, policy, now, anchor);
        }
        let original = self.original_device(&image, now)?;
        let authority = RetainedInstallationAuthority::active_installation(&original, policy);
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active | AdmissionPhase::Refreshing { .. },
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if admission.policy != policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let journal_id = admission.journal;
        let mut service = DeviceInstallation::reconcile_original_enrollment(
            self.paths.installation.clone(),
            self.key()?,
            &original,
            policy,
            anchor,
        )?;
        let journal = service.stores()?.0;
        if journal.identity()? != journal_id {
            return Err(DurableError::Conflict);
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        renewal.check_time_floor(now)?;
        if renewal.pending.is_none() && renewal.completed.is_none() && renewal.expired.is_some() {
            return Err(Error::Validity.into());
        }
        if let Some(pending) = &renewal.pending {
            let grant = VerifiedCredentialRenewal::from_journal(&pending.wire, original.roster())?;
            if grant.operation() != pending.operation
                || grant.statement_digest() != pending.statement
            {
                return Err(DurableError::Conflict);
            }
            journal.reconcile_prior_local_renewal(
                &authority,
                &grant,
                renewal.completed.as_ref(),
            )?;
            let commit = journal.commit_local_credential_renewal(
                &authority,
                &grant,
                pending.operation,
                policy,
                now,
            )?;
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("journal");
            image = self.persist_renewal_completion(image, &grant, commit)?;
        }
        let completed = image
            .renewal
            .as_ref()
            .and_then(|r| r.completed.as_ref())
            .ok_or(DurableError::Corrupt)?;
        #[cfg(all(test, unix))]
        super::tests::renewal::boundary("completion");
        journal.acknowledge_local_credential_renewal(&authority, completed)?;
        #[cfg(all(test, unix))]
        super::tests::renewal::boundary("acknowledgement");
        let current = self.admitted_renewed(&image, policy, now)?;
        let Phase::Accepted {
            admission, stage, ..
        } = &mut image.phase
        else {
            return Err(DurableError::Corrupt);
        };
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
        journal.check_renewed_local_device(&authority, &current, policy, now)?;
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
