// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment's bounded, cross-file credential-renewal transaction.
use super::*;
mod expiry;
mod request;
pub use request::CredentialRenewalRequest;
mod witness;
use crate::durable::{
    LocalRenewalCommit, LocalRenewalResolution, LocalRenewalTarget, WitnessedCredentialIntent,
};
use crate::{CredentialRenewalId, RetainedInstallationAuthority, VerifiedCredentialRenewal};

#[derive(Clone, Copy)]
pub(super) enum LocalRenewalPolicy<'a> {
    Current(&'a VerifiedSessionPolicy),
    Historical(&'a crate::HistoricalSessionPolicy),
}
impl LocalRenewalPolicy<'_> {
    fn historical(&self) -> &crate::HistoricalSessionPolicy {
        match self {
            Self::Current(policy) => policy.historical(),
            Self::Historical(policy) => policy,
        }
    }
}

// Constructed only by the original enrollment coordinator after authenticated
// durable terminal readback. Other modules cannot promote public metadata to it.
pub(crate) struct PersistedRenewalTerminal {
    intent: WitnessedCredentialIntent,
    state: crate::AnchorCredentialRenewalState,
    adopted_policy: Option<[u8; 32]>,
    completed: Option<LocalRenewalCommit>,
}
impl PersistedRenewalTerminal {
    pub(crate) fn completed(&self) -> Option<&LocalRenewalCommit> {
        self.completed.as_ref()
    }
    pub(crate) fn parts(
        &self,
    ) -> (
        WitnessedCredentialIntent,
        crate::AnchorCredentialRenewalState,
        Option<[u8; 32]>,
    ) {
        (self.intent, self.state, self.adopted_policy)
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
    /// For G under an independent policy, the fixed target is expired when its
    /// credential, roster or adopted policy validity interval has ended.
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
    continuation: Option<Vec<u8>>,
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
    adopted_policy: Option<Vec<u8>>,
}
impl LocalRenewal {
    pub(super) fn permits_policy_credential(&self, policy_pending: bool) -> bool {
        self.witness.is_none()
            && self
                .pending
                .as_ref()
                .is_none_or(|p| !policy_pending && p.continuation.is_none())
    }
    pub(super) fn has_pending_credential(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn permits_policy_pending(&self) -> bool {
        self.pending.is_none() && self.witness.as_ref().and_then(|w| w.coordination).is_none()
    }
    pub(super) fn policy_predecessor(&self) -> Option<&[u8]> {
        self.adopted_policy.as_deref()
    }
    pub(super) fn policy_prior_credential_completion(&self) -> Option<&LocalRenewalCommit> {
        self.completed.as_ref()
    }
    pub(super) fn policy_time_floor(&self, now: u64) -> Result<(), DurableError> {
        self.check_time_floor(now)
    }
    pub(super) fn joint(&self) -> bool {
        self.policy_coordination()
            || self.adopted_policy.is_some()
            || self
                .pending
                .as_ref()
                .is_some_and(|p| p.continuation.is_some())
    }
    pub(super) fn policy_coordination(&self) -> bool {
        self.witness
            .as_ref()
            .and_then(|w| w.coordination)
            .is_some_and(|c| match c.intent {
                WitnessedCredentialIntent::Proposal(p) => p.policy_continuation().is_some(),
                WitnessedCredentialIntent::Cancellation(c) => c.policy_continuation().is_some(),
            })
    }
    pub(super) fn policy_cancellation(&self) -> bool {
        self.policy_coordination() && self.cancellation()
    }
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
        if self.joint() {
            out.push(
                u8::from(self.extended())
                    | (u8::from(self.witnessed()) << 1)
                    | (u8::from(self.cancellation()) << 2),
            );
        }
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
                if self.joint() {
                    encode_continuation(out, p.continuation.as_deref())?;
                }
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
        if self.joint() {
            encode_continuation(out, self.adopted_policy.as_deref())?;
        }
        Ok(())
    }
    pub(super) fn decode(
        d: &mut Decoder<'_>,
        extended: bool,
        witnessed: bool,
        cancellation: bool,
        joint: bool,
        policy_coordination: bool,
        policy_cancellation: bool,
    ) -> Result<Self, DurableError> {
        let (extended, witnessed, cancellation) = if joint {
            let [flags] = d.array()?;
            if flags & !7 != 0
                || (flags & 2 != 0 && flags & 1 == 0)
                || (flags & 4 != 0 && flags & 2 == 0)
            {
                return Err(DurableError::Corrupt);
            }
            (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0)
        } else {
            (extended, witnessed, cancellation)
        };
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
                    continuation: if joint { decode_continuation(d)? } else { None },
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
                Some(witness::WitnessRenewal::decode(
                    d,
                    cancellation,
                    policy_coordination,
                    policy_cancellation,
                )?)
            } else {
                None
            },
            adopted_policy: if joint { decode_continuation(d)? } else { None },
        };
        if value.joint() != joint
            || value.policy_coordination() != policy_coordination
            || value.policy_cancellation() != policy_cancellation
        {
            return Err(DurableError::Corrupt);
        }
        value.validate()?;
        Ok(value)
    }
    pub(super) fn status(&self) -> Result<CredentialRenewalStatus, DurableError> {
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

fn encode_continuation(out: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), DurableError> {
    match value {
        None => out.push(0),
        Some(bytes) => {
            if bytes.len() != crate::PUBLIC_KEY_BYTES + crate::MAX_POLICY_CONTINUATION_BYTES {
                return Err(DurableError::Capacity);
            }
            out.push(1);
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}
fn decode_continuation(d: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, DurableError> {
    match d.array::<1>()? {
        [0] => Ok(None),
        [1] => Ok(Some(
            d.take(crate::PUBLIC_KEY_BYTES + crate::MAX_POLICY_CONTINUATION_BYTES)?
                .to_vec(),
        )),
        _ => Err(DurableError::Corrupt),
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
        let device = self.historical_device_metadata(certificate, roster, checkpoint)?;
        if device
            .description
            .validity
            .from()
            .max(device.roster_validity.from())
            > now
        {
            return Err(Error::Validity.into());
        }
        Ok(device)
    }
    pub(super) fn historical_device_metadata(
        &self,
        certificate: &[u8],
        roster: &[u8],
        checkpoint: RosterCheckpoint,
    ) -> Result<VerifiedDevice, DurableError> {
        let pin = AccountPin::new(
            crate::identity::account_id(&self.intent.root),
            self.intent.root.clone(),
            checkpoint,
            self.intent.description.family,
        )?;
        Ok(pin.verify_historical_device(certificate, roster)?)
    }
    pub(super) fn original_device(
        &self,
        image: &Image,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        image.check_time_floor(now)?;
        let original = self.original_device_metadata(image)?;
        if original
            .description
            .validity
            .from()
            .max(original.roster_validity.from())
            > now
        {
            return Err(Error::Validity.into());
        }
        self.signer(image.identity, false)?
            .check_device(&original)?;
        Ok(original)
    }
    // Public signatures and the original enrollment intent suffice for status
    // readback. No runtime lease or private signing file is opened here.
    pub(super) fn original_device_metadata(
        &self,
        image: &Image,
    ) -> Result<VerifiedDevice, DurableError> {
        let Phase::Accepted {
            request, admission, ..
        } = &image.phase
        else {
            return Err(Error::State.into());
        };
        let original = if let Some(renewal) = &image.renewal {
            self.historical_device_metadata(
                &renewal.origin.certificate,
                &renewal.origin.roster,
                renewal.origin.checkpoint,
            )?
        } else {
            self.historical_device_metadata(
                &admission.certificate,
                &admission.roster,
                admission.checkpoint,
            )?
        };
        self.intent.verify_device(&original)?;
        let at = original.description.validity.from();
        let proof = VerifiedEnrollmentRequest::verify(request, &self.intent, at)?;
        if proof.identity != image.identity || proof.public != original.key {
            return Err(DurableError::Conflict);
        }
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
        self.stage_renewal(grant, operation, policy, now, None)
    }
    /// Durably stage one independently double-approved credential/policy target
    /// in the original enrollment. The first saved intent includes the complete
    /// joint statement; a credential-only pending operation cannot acquire it.
    /// This is preparation only and returns no P1 service or session owner.
    pub fn stage_policy_continuation(
        &mut self,
        grant: &VerifiedCredentialRenewal,
        continuation: &crate::VerifiedPolicyContinuation,
        operation: CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        self.stage_renewal(grant, operation, policy, now, Some(continuation))
    }
    pub(super) fn retained_policy(
        &self,
        bytes: &[u8],
    ) -> Result<crate::HistoricalPolicyContinuation, DurableError> {
        Ok(crate::HistoricalPolicyContinuation::from_authority(
            bytes,
            &self.intent.root,
            self.intent.description.family,
        )?)
    }
    pub(super) fn check_policy_scope(
        continuation: &crate::HistoricalPolicyContinuation,
        original: &VerifiedDevice,
        admission: &Admission,
    ) -> Result<(), DurableError> {
        let scope = continuation.scope();
        if scope.journal != admission.journal
            || scope.original_owner != crate::bootstrap::storage_owner(original)
            || scope.original_credential != original.credential_digest()
            || scope.original_policy.digest() != admission.policy
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn stage_renewal(
        &mut self,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &VerifiedSessionPolicy,
        now: u64,
        continuation: Option<&crate::VerifiedPolicyContinuation>,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            image.check_time_floor(now)?;
            let independent = self.completed_policy_approval(&image)?;
            if image.policy_pending.is_some() || (independent.is_some() && continuation.is_some()) {
                return Err(DurableError::Suspended);
            }
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
            {
                return Err(DurableError::Conflict);
            }
            grant.resolve_established(&original, admission.policy)?;
            let joint = continuation.map(crate::VerifiedPolicyContinuation::historical);
            let adopted = image
                .renewal
                .as_ref()
                .and_then(|r| r.adopted_policy.as_deref())
                .map(|bytes| self.retained_policy(bytes))
                .transpose()?;
            if let Some(previous) = &adopted {
                Self::check_policy_scope(previous, &original, admission)?;
            }
            if let Some(approval) = &independent {
                if policy.anchor_requirement().binding().is_some() {
                    return Err(DurableError::AnchorRequired);
                }
                approval.check_target(policy)?;
                approval.check_renewed_identity(&original, grant)?;
            } else if let Some(joint) = &joint {
                Self::check_policy_scope(joint, &original, admission)?;
                joint.check_credential(grant)?;
                joint.check_target(policy)?;
            } else if let Some(previous) = &adopted {
                previous.check_target(policy)?;
            } else if admission.policy != policy.checkpoint().digest() {
                return Err(DurableError::Conflict);
            }
            let statement = joint.as_ref().map_or_else(
                || grant.statement_digest(),
                crate::HistoricalPolicyContinuation::statement_digest,
            );
            if let Some(renewal) = &image.renewal {
                if renewal.witnessed() != policy.anchor_requirement().binding().is_some() {
                    return Err(DurableError::Conflict);
                }
                if let Some(p) = &renewal.pending {
                    if p.operation != operation
                        || p.statement != statement
                        || p.continuation.is_some() != joint.is_some()
                    {
                        return Err(DurableError::Conflict);
                    }
                    if let Some(bytes) = &p.continuation {
                        let saved = self.retained_policy(bytes)?;
                        Self::check_policy_scope(&saved, &original, admission)?;
                        saved.check_credential(grant)?;
                        if saved.statement_digest() != p.statement {
                            return Err(DurableError::Conflict);
                        }
                    }
                    return renewal.status();
                }
                if let Some(c) = renewal
                    .completed
                    .as_ref()
                    .filter(|c| c.operation == operation && c.statement == statement)
                {
                    if joint.is_some()
                        && adopted
                            .as_ref()
                            .is_none_or(|saved| saved.statement_digest() != statement)
                    {
                        return Err(DurableError::Conflict);
                    }
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
            if let Some(joint) = &joint {
                match &adopted {
                    None if joint.scope().previous_authorization.is_none()
                        && joint.scope().previous_policy == joint.scope().original_policy => {}
                    Some(previous)
                        if joint.scope().previous_authorization
                            == Some(previous.statement_digest())
                            && joint.scope().previous_policy == previous.target_policy()
                            && joint.scope().original_policy
                                == previous.scope().original_policy
                            && joint.scope().operation != previous.scope().operation => {}
                    _ => return Err(DurableError::Conflict),
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
                    adopted_policy: None,
                });
            }
            image.renewal.as_mut().ok_or(DurableError::Corrupt)?.pending = Some(Pending {
                operation,
                statement,
                wire: grant.as_bytes().to_vec(),
                continuation: joint
                    .as_ref()
                    .map(crate::HistoricalPolicyContinuation::journal_bytes),
            });
            if independent.is_some() {
                image.policy_device_binding = super::PolicyDeviceBinding::CredentialRenewal;
            }
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
        self.current_renewed_device(image, &original, policy, now)
    }
    // Ordinary renewal still requires its configured roster to be current.
    // Continued-owner admission below resolves its current roster from journal.
    fn current_renewed_device(
        &self,
        image: &Image,
        original: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDevice, DurableError> {
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        renewal.check_time_floor(now)?;
        if renewal.pending.is_some() {
            return Err(DurableError::Suspended);
        }
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let pin = AccountPin::new(
            original.account_id(),
            self.intent.root.clone(),
            admission.checkpoint,
            self.intent.description.family,
        )?;
        let current = pin.verify_device(&admission.certificate, &admission.roster, now)?;
        self.check_renewed_identity(image, original, &current)?;
        admit(&current, policy, now)?;
        Ok(current)
    }
    // Immutable configuration/signing-key binding, not current admission. The
    // caller must separately check its current policy and authenticated roster.
    fn check_renewed_identity(
        &self,
        image: &Image,
        original: &VerifiedDevice,
        current: &VerifiedDevice,
    ) -> Result<(), DurableError> {
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        let complete = renewal.completed.as_ref();
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
        self.signer(image.identity, false)?.check_device(current)?;
        Ok(())
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
            AdmissionPhase::RosterResolved { observed } if observed == previous => {
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
        let independent = self.completed_policy_approval(&image)?;
        let original = self.original_device_metadata(&image)?;
        let pending = image
            .renewal
            .as_ref()
            .and_then(|r| r.pending.as_ref())
            .ok_or(DurableError::Corrupt)?;
        let continuation = pending
            .continuation
            .as_deref()
            .map(|bytes| self.retained_policy(bytes))
            .transpose()?;
        let target = LocalRenewalTarget {
            policy_renewal: independent.as_ref().map(|p| (p, &original)),
            grant,
            continuation: continuation.as_ref(),
        };
        if pending.operation != grant.operation()
            || pending.statement != commit.statement
            || target.receipt()? != commit
        {
            return Err(DurableError::Conflict);
        }
        let Phase::Accepted { admission, .. } = &mut image.phase else {
            return Err(DurableError::Corrupt);
        };
        admission.certificate = grant.successor_credential()?.to_vec();
        admission.roster = grant.successor_device().roster().as_bytes().to_vec();
        admission.checkpoint = grant.successor_device().roster().checkpoint();
        let renewal = image.renewal.as_mut().ok_or(DurableError::Corrupt)?;
        if let Some(t) = continuation {
            renewal.adopted_policy = Some(t.journal_bytes());
        }
        renewal.pending = None;
        renewal.completed = Some(commit.clone());
        renewal.expired = None;
        let adopted = renewal.adopted_policy.clone();
        self.save(&image)?;
        let readback = self.image()?;
        let saved = readback.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        if saved.pending.is_some()
            || saved.completed.as_ref() != Some(&commit)
            || saved.adopted_policy != adopted
            || self
                .completed_policy_approval(&readback)?
                .map(|p| p.journal_bytes())
                != independent.map(|p| p.journal_bytes())
        {
            return Err(DurableError::Conflict);
        }
        Ok(readback) // Exact durable readback must precede journal receipt pruning.
    }
    // Shared original-enrollment transaction. Current permission is checked
    // only for a new journal mutation; exact committed history remains readable.
    pub(super) fn reconcile_local_renewal(
        &mut self,
        mut image: Image,
        original_policy: &crate::HistoricalSessionPolicy,
        policy: LocalRenewalPolicy<'_>,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<(Image, DeviceService), DurableError> {
        let independent = self.completed_policy_approval(&image)?;
        if independent.is_some() {
            if image.policy_device_binding != super::PolicyDeviceBinding::CredentialRenewal
                || image.policy_pending.is_some()
                || original_policy.anchor_requirement().binding().is_some()
                || policy.historical().anchor_requirement().binding().is_some()
                || anchor.is_some()
            {
                return Err(DurableError::Suspended);
            }
        } else {
            image.require_no_policy_renewal()?;
        }
        let original =
            if independent.is_some() && matches!(policy, LocalRenewalPolicy::Historical(_)) {
                self.original_device_metadata(&image)?
            } else {
                self.original_device(&image, now)?
            };
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active | AdmissionPhase::Refreshing { .. },
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        if admission.policy != original_policy.checkpoint().digest() {
            return Err(DurableError::Conflict);
        }
        let journal_id = admission.journal;
        let mut service = self.reconcile_installation(&original, original_policy, anchor)?;
        let journal = service.stores()?.0;
        if journal.identity()? != journal_id {
            return Err(DurableError::Conflict);
        }
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        if independent.is_none() || matches!(policy, LocalRenewalPolicy::Current(_)) {
            renewal.check_time_floor(now)?;
        }
        if renewal.pending.is_none() && renewal.completed.is_none() && renewal.expired.is_some() {
            return Err(Error::Validity.into());
        }
        if let Some(approval) = &independent {
            approval.check_target(policy.historical())?;
            if approval.scope().original_policy != original_policy.checkpoint() {
                return Err(DurableError::Conflict);
            }
            let receipt = journal.inspect_policy_credential_authorization(approval, &original)?;
            journal.acknowledge_local_policy_renewal(&authority, &receipt)?;
        } else if let Some(bytes) = &renewal.adopted_policy {
            let adopted = self.retained_policy(bytes)?;
            Self::check_policy_scope(&adopted, &original, admission)?;
            // A new T can name P2; otherwise all continuation work stays on
            // the exact adopted P1, even when only G changes next.
            if renewal
                .pending
                .as_ref()
                .is_none_or(|p| p.continuation.is_none())
            {
                adopted.check_target(policy.historical())?;
            }
        } else if renewal
            .pending
            .as_ref()
            .is_none_or(|p| p.continuation.is_none())
            && admission.policy != policy.historical().checkpoint().digest()
        {
            return Err(DurableError::Conflict);
        }
        if let Some(pending) = &renewal.pending {
            let grant = VerifiedCredentialRenewal::from_journal(&pending.wire, original.roster())?;
            let continuation = pending
                .continuation
                .as_deref()
                .map(|bytes| self.retained_policy(bytes))
                .transpose()?;
            if let Some(t) = &continuation {
                Self::check_policy_scope(t, &original, admission)?;
                t.check_target(policy.historical())?;
            }
            let target = LocalRenewalTarget {
                policy_renewal: independent.as_ref().map(|p| (p, &original)),
                grant: &grant,
                continuation: continuation.as_ref(),
            };
            if grant.operation() != pending.operation
                || target.receipt()?.statement != pending.statement
            {
                return Err(DurableError::Conflict);
            }
            let commit = match policy {
                LocalRenewalPolicy::Current(current) => {
                    journal.reconcile_prior_local_target(
                        &authority,
                        &target,
                        renewal.completed.as_ref(),
                    )?;
                    if continuation.is_some() || independent.is_some() {
                        journal.commit_local_renewal(&authority, &target, current, now)?
                    } else {
                        journal.commit_local_credential_renewal(
                            &authority,
                            &grant,
                            pending.operation,
                            current,
                            now,
                        )?
                    }
                }
                LocalRenewalPolicy::Historical(historical) => journal
                    .inspect_committed_local_renewal(
                        &authority,
                        &target,
                        historical,
                        renewal.completed.as_ref(),
                    )?,
            };
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("journal");
            image = self.persist_renewal_completion(image, &grant, commit)?;
        }
        let completed = image
            .renewal
            .as_ref()
            .and_then(|r| r.completed.as_ref())
            .ok_or(DurableError::Corrupt)?;
        if let Some(approval) = &independent {
            journal.check_policy_credential_completion(approval, &original, completed)?;
        } else if let Some(bytes) = image
            .renewal
            .as_ref()
            .and_then(|r| r.adopted_policy.as_deref())
        {
            let adopted = self.retained_policy(bytes)?;
            journal.check_local_policy_continuation(&authority, &adopted)?;
        }
        #[cfg(all(test, unix))]
        super::tests::renewal::boundary("completion");
        journal.acknowledge_local_credential_renewal(&authority, completed)?;
        #[cfg(all(test, unix))]
        super::tests::renewal::boundary("acknowledgement");
        Ok((image, service))
    }
    /// Reconcile the original local-only joint transaction and retain its exact
    /// completion. This returns historical status only, never an operational
    /// owner or permission to bootstrap under the continued policy. A new commit
    /// needs current P1; an already committed target can finish after P1 expires.
    /// Required-witness continuation needs its independent exact-T protocol and
    /// is refused here, without falling back to local storage.
    pub fn reconcile_policy_continuation(
        &mut self,
        original_policy: &crate::HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result = (|| {
            let image = self.image_without_policy_renewal()?;
            let renewal = image.renewal.as_ref().ok_or(DurableError::Conflict)?;
            if !renewal.joint() {
                return Err(DurableError::Conflict);
            }
            if renewal.witnessed()
                || original_policy.anchor_requirement().binding().is_some()
                || policy.anchor_requirement().binding().is_some()
            {
                return Err(DurableError::AnchorRequired);
            }
            let (image, mut service) = self.reconcile_local_renewal(
                image,
                original_policy,
                LocalRenewalPolicy::Current(policy),
                now,
                None,
            )?;
            service.close();
            image
                .renewal
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .status()
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Finish one exact already-committed local G/T transaction using only
    /// independently signature-verified P0 and target policy history. This can
    /// resume after all current runtimes and policy validity intervals have ended.
    /// It never creates a journal target or returns an operational owner. If the
    /// original Pending has no exact committed receipt, it remains Pending and
    /// this call returns Suspended; that is not a NoCommit or abandonment fact.
    /// Required protection must use its independent witness recovery protocol.
    pub fn recover_historical_policy_continuation(
        &mut self,
        operation: CredentialRenewalId,
        statement: [u8; 32],
        original_policy: &crate::HistoricalSessionPolicy,
        policy: &crate::HistoricalSessionPolicy,
        now: u64,
    ) -> Result<CredentialRenewalStatus, DurableError> {
        let result = (|| {
            let image = self.image_without_policy_renewal()?;
            let renewal = image.renewal.as_ref().ok_or(DurableError::Conflict)?;
            if !renewal.joint() {
                return Err(DurableError::Conflict);
            }
            if renewal.witnessed()
                || original_policy.anchor_requirement().binding().is_some()
                || policy.anchor_requirement().binding().is_some()
            {
                return Err(DurableError::AnchorRequired);
            }
            match renewal.status()? {
                CredentialRenewalStatus::Pending {
                    operation: expected,
                    statement: digest,
                }
                | CredentialRenewalStatus::Committed {
                    operation: expected,
                    statement: digest,
                    ..
                } if operation == expected && statement == digest => {}
                _ => return Err(DurableError::Conflict),
            }
            let (image, mut service) = self.reconcile_local_renewal(
                image,
                original_policy,
                LocalRenewalPolicy::Historical(policy),
                now,
                None,
            )?;
            service.close();
            image
                .renewal
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .status()
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Complete the original local joint renewal and restore one retained live
    /// session while keeping its enrollment lease, original signer and service.
    /// Historical P0 authenticates the unchanged installation; independently
    /// verified P1 authorizes only the exact existing session under durable T.
    /// No fresh-bootstrap or prekey permission is granted. Required-witness
    /// continuation remains unavailable until independent exact-T admission.
    /// On an unknown commit, reopen the original enrollment and retry this same
    /// request. The authorized renewal can complete before session admission
    /// fails; query the original enrollment status after any error. Historical
    /// completion alone never returns an operational owner.
    pub fn activate_continued_session(
        mut self,
        request: crate::SessionReopenRequest,
        policy: std::sync::Arc<VerifiedSessionPolicy>,
        now: u64,
    ) -> Result<(EnrolledDevice, crate::ReopenedPeer), DurableError> {
        let image = self.image_without_policy_renewal()?;
        let original = self.original_device(&image, now)?;
        if request.context.device(request.role).credential_digest() != original.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        let mut active =
            self.activate_policy_continuation(request.context.original_policy(), &policy, now)?;
        let (service, _, current) = active.parts()?;
        let peer = service.reopen_continued_peer(request, policy, now)?;
        if peer
            .context()
            .session_device(peer.role())
            .credential_digest()
            != current.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        Ok((active, peer))
    }
    /// Complete/reopen the original local-only continued enrollment without
    /// requiring current peer credentials first. This retains the original
    /// signer and service only after exact durable T/G, local membership,
    /// completion ACK and independently verified P1 runtime admission.
    /// The caller can then install independently approved peer renewals and
    /// reopen original sessions. Fresh bootstrap/prekey permission is not granted.
    /// Historical progress can complete before current admission fails; after an
    /// error, reopen this original enrollment and query its exact operation.
    pub fn activate_policy_continuation(
        mut self,
        original_policy: &crate::HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrolledDevice, DurableError> {
        let image = self.image_without_policy_renewal()?;
        let renewal = image.renewal.as_ref().ok_or(DurableError::Conflict)?;
        if !renewal.joint() {
            return Err(DurableError::Conflict);
        }
        if renewal.witnessed()
            || original_policy.anchor_requirement().binding().is_some()
            || policy.anchor_requirement().binding().is_some()
        {
            return Err(DurableError::AnchorRequired);
        }
        let (image, service) = self.reconcile_local_renewal(
            image,
            original_policy,
            LocalRenewalPolicy::Current(policy),
            now,
            None,
        )?;
        self.release_continued_owner(image, service, original_policy, policy, now)
    }
    fn release_continued_owner(
        self,
        image: Image,
        mut service: DeviceService,
        original_policy: &crate::HistoricalSessionPolicy,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<EnrolledDevice, DurableError> {
        let original = self.original_device(&image, now)?;
        let Phase::Accepted {
            admission,
            stage: AdmissionPhase::Active,
            ..
        } = &image.phase
        else {
            return Err(DurableError::Suspended);
        };
        let renewal = image.renewal.as_ref().ok_or(DurableError::Corrupt)?;
        let complete = renewal.completed.as_ref().ok_or(DurableError::Corrupt)?;
        let adopted = self.retained_policy(
            renewal
                .adopted_policy
                .as_deref()
                .ok_or(DurableError::Conflict)?,
        )?;
        Self::check_policy_scope(&adopted, &original, admission)?;
        adopted.check_context_policy(original_policy, policy)?;
        if complete.policy != admission.policy
            || complete.owner != crate::bootstrap::storage_owner(&original)
        {
            return Err(DurableError::Conflict);
        }
        // Admission retains the exact original G receipt, whose roster can
        // expire after a newer roster is accepted by the journal. Authenticate
        // that immutable history, then obtain all current authority from the
        // exact journal G/T and its current roster; history alone grants none.
        let retained = self.historical_device(
            &admission.certificate,
            &admission.roster,
            admission.checkpoint,
            now,
        )?;
        self.check_renewed_identity(&image, &original, &retained)?;
        let authority =
            RetainedInstallationAuthority::active_installation(&original, original_policy);
        let current = service.stores()?.0.admit_continued_local_device(
            &crate::installation::PolicyScope {
                authority: &authority,
                original_policy,
                original_device: &original,
            },
            &retained,
            policy,
            now,
        )?;
        let signer = self.signer(image.identity, false)?;
        signer.check_device(&current)?;
        admit(&current, policy, now)?;
        Ok(EnrolledDevice {
            active: Some(Box::new(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device: current,
            })),
        })
    }
    pub(super) fn activate_renewed(
        mut self,
        image: Image,
        policy: &VerifiedSessionPolicy,
        now: u64,
        anchor: Option<AnchorClient>,
    ) -> Result<EnrolledDevice, DurableError> {
        if image.renewal.as_ref().is_some_and(LocalRenewal::joint) {
            return Err(DurableError::Suspended);
        }
        if image.renewal.as_ref().is_some_and(LocalRenewal::witnessed) {
            return self.activate_witnessed(image, policy, now, anchor);
        }
        let original = self.original_device(&image, now)?;
        let authority = RetainedInstallationAuthority::active_installation(&original, policy);
        let (mut image, mut service) = self.reconcile_local_renewal(
            image,
            policy.historical(),
            LocalRenewalPolicy::Current(policy),
            now,
            anchor,
        )?;
        let journal = service.stores()?.0;
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
            active: Some(Box::new(EnrolledOwners {
                enrollment: self,
                service,
                signer,
                device: current,
            })),
        })
    }
}
