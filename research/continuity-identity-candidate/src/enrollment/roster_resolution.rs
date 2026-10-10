// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retained outcomes for the original same-credential roster refresh.
use super::*;
use crate::{HistoricalSessionPolicy, RetainedInstallationAuthority, VerifiedRoster};

/// Historical outcome of one original expected-predecessor/target pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterRefreshOutcome {
    /// The exact target was observed in the original journal.
    Committed,
    /// The journal remained below the target and the signed target roster expired.
    ExpiredUncommitted,
    /// A different head at the target version excludes any adoption of this target.
    SupersededUncommitted,
    /// A later head permanently supersedes the target; its past adoption is unknown.
    SupersededUnknown,
}

/// Original refresh identity and its retained historical observation, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterRefreshResolution {
    /// Original installation journal.
    pub journal: JournalIdentity,
    /// Expected predecessor retained by the original refresh.
    pub previous: RosterCheckpoint,
    /// Original signed roster target.
    pub target: RosterCheckpoint,
    /// What the original journal observation proves.
    pub outcome: RosterRefreshOutcome,
    /// Actual head observed while the original journal lease was held.
    pub observed: RosterCheckpoint,
    /// Trusted observation time retained as a floor for future current operations.
    pub observed_at: u64,
}

pub(super) struct RetainedRosterResolution {
    result: RosterRefreshResolution,
    target: VerifiedRoster,
    observed: VerifiedRoster,
}
impl RetainedRosterResolution {
    pub(super) fn result(&self) -> RosterRefreshResolution {
        self.result
    }
    pub(super) fn check_time(&self, now: u64) -> Result<(), DurableError> {
        if now < self.result.observed_at {
            return Err(Error::Validity.into());
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), DurableError> {
        let r = self.result;
        if r.previous.version() >= r.target.version()
            || r.target != self.target.checkpoint()
            || r.observed != self.observed.checkpoint()
            || !self.target.same_authority(&self.observed)
            || r.observed.version() < r.previous.version()
            || (r.observed.version() == r.previous.version() && r.observed != r.previous)
            || r.observed_at == 0
            || r.observed_at
                < self
                    .target
                    .validity()
                    .from()
                    .max(self.observed.validity().from())
        {
            return Err(DurableError::Corrupt);
        }
        let valid = match r.outcome {
            RosterRefreshOutcome::Committed => r.observed == r.target,
            RosterRefreshOutcome::ExpiredUncommitted => {
                r.observed.version() < r.target.version()
                    && self.target.validity().until() <= r.observed_at
            }
            RosterRefreshOutcome::SupersededUncommitted => {
                r.observed.version() == r.target.version() && r.observed != r.target
            }
            RosterRefreshOutcome::SupersededUnknown => r.observed.version() > r.target.version(),
        };
        if !valid {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        self.validate()?;
        out.extend_from_slice(self.result.journal.as_bytes());
        for cp in [
            self.result.previous,
            self.result.target,
            self.result.observed,
        ] {
            out.extend_from_slice(&cp.version().to_be_bytes());
            out.extend_from_slice(&cp.digest());
        }
        out.extend_from_slice(&self.result.observed_at.to_be_bytes());
        out.push(match self.result.outcome {
            RosterRefreshOutcome::Committed => 1,
            RosterRefreshOutcome::ExpiredUncommitted => 2,
            RosterRefreshOutcome::SupersededUncommitted => 3,
            RosterRefreshOutcome::SupersededUnknown => 4,
        });
        field(out, &self.target.journal_bytes())?;
        field(out, &self.observed.journal_bytes())?;
        Ok(())
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        let previous = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let target = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let observed = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let observed_at = d.u64()?;
        let outcome = match d.array::<1>()? {
            [1] => RosterRefreshOutcome::Committed,
            [2] => RosterRefreshOutcome::ExpiredUncommitted,
            [3] => RosterRefreshOutcome::SupersededUncommitted,
            [4] => RosterRefreshOutcome::SupersededUnknown,
            _ => return Err(DurableError::Corrupt),
        };
        let value = Self {
            result: RosterRefreshResolution {
                journal,
                previous,
                target,
                outcome,
                observed,
                observed_at,
            },
            target: VerifiedRoster::from_journal(&take(d)?)?,
            observed: VerifiedRoster::from_journal(&take(d)?)?,
        };
        value.validate()?;
        Ok(value)
    }
}

pub(super) fn validate_phase(image: &Image) -> Result<(), DurableError> {
    let unresolved = matches!(
        image.phase,
        Phase::Accepted {
            stage: AdmissionPhase::RosterResolved { .. },
            ..
        }
    );
    let Some(record) = &image.roster_resolution else {
        return if unresolved {
            Err(DurableError::Corrupt)
        } else {
            Ok(())
        };
    };
    record.validate()?;
    let Phase::Accepted {
        admission, stage, ..
    } = &image.phase
    else {
        return Err(DurableError::Corrupt);
    };
    if admission.journal != record.result.journal
        || !matches!(
            stage,
            AdmissionPhase::Active
                | AdmissionPhase::Refreshing { .. }
                | AdmissionPhase::RosterResolved { .. }
        )
    {
        return Err(DurableError::Corrupt);
    }
    if let AdmissionPhase::RosterResolved { observed } = stage {
        if *observed != record.result.observed
            || admission.checkpoint != record.result.target
            || record.result.outcome == RosterRefreshOutcome::Committed
            || image.policy_pending.is_some()
            || image
                .renewal
                .as_ref()
                .is_some_and(LocalRenewal::has_pending_credential)
        {
            return Err(DurableError::Corrupt);
        }
    } else {
        let retained_head = match stage {
            AdmissionPhase::Refreshing { previous } => *previous,
            AdmissionPhase::Active => admission.checkpoint,
            _ => return Err(DurableError::Corrupt),
        };
        if retained_head.version() < record.result.observed.version()
            || (retained_head.version() == record.result.observed.version()
                && retained_head != record.result.observed)
        {
            return Err(DurableError::Corrupt);
        }
    }
    Ok(())
}

impl Image {
    pub(super) fn require_reconciled_roster(&self) -> Result<(), DurableError> {
        if matches!(
            self.phase,
            Phase::Accepted {
                stage: AdmissionPhase::RosterResolved { .. },
                ..
            }
        ) {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
}

impl DeviceEnrollment {
    pub(super) fn validate_roster_resolution(&self, image: &Image) -> Result<(), DurableError> {
        validate_phase(image)?;
        let Some(record) = &image.roster_resolution else {
            return Ok(());
        };
        let (root, family) = record.target.continuation_authority();
        if root != &self.intent.root
            || family != self.intent.description.family
            || record.target.account_id() != crate::identity::account_id(&self.intent.root)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }

    /// Resolve the original roster refresh using its retained predecessor and
    /// target, verified original policy history and a trusted current time.
    /// This local metadata path needs no live runtime/private signer or witness.
    /// Required-witness installations are refused, never downgraded.
    ///
    /// A higher current head cannot prove whether the target once committed:
    /// SupersededUnknown preserves that uncertainty while permitting progress
    /// from the actual head. A still-live target beyond the current head
    /// remains pending. The journal is never changed by this resolver.
    /// A retained exact result stays queryable until another refresh resolution.
    pub fn resolve_roster_refresh(
        &mut self,
        previous: RosterCheckpoint,
        target: RosterCheckpoint,
        original_policy: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<RosterRefreshResolution, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let Phase::Accepted {
                admission, stage, ..
            } = &image.phase
            else {
                return Err(Error::State.into());
            };
            if original_policy.anchor_requirement().binding().is_some() {
                return Err(DurableError::AnchorRequired);
            }
            if admission.policy != original_policy.checkpoint().digest() {
                return Err(DurableError::Conflict);
            }
            if let Some(record) = &image.roster_resolution {
                if record.result.previous == previous && record.result.target == target {
                    return Ok(record.result);
                }
            }
            if *stage != (AdmissionPhase::Refreshing { previous }) || admission.checkpoint != target
            {
                return Err(DurableError::Conflict);
            }
            if image.policy_pending.is_some()
                || image
                    .renewal
                    .as_ref()
                    .is_some_and(LocalRenewal::has_pending_credential)
            {
                return Err(DurableError::Suspended);
            }
            image.check_time_floor(now)?;
            let original = self.original_device_metadata(&image)?;
            let current =
                self.historical_device_metadata(&admission.certificate, &admission.roster, target)?;
            let authority =
                RetainedInstallationAuthority::active_installation(&original, original_policy);
            let mut service = self.reconcile_installation(&original, original_policy, None)?;
            let journal = service.stores()?.0;
            if journal.identity()? != admission.journal {
                return Err(DurableError::Conflict);
            }
            let observed = journal.local_roster_for_reconciliation(&authority)?;
            let head = observed.checkpoint();
            if !observed.same_authority(current.roster())
                || head.version() < previous.version()
                || (head.version() == previous.version() && head != previous)
            {
                return Err(DurableError::Conflict);
            }
            if now == 0
                || now
                    < current
                        .roster_validity
                        .from()
                        .max(observed.validity().from())
            {
                return Err(Error::Validity.into());
            }
            let outcome = if head == target {
                RosterRefreshOutcome::Committed
            } else if head.version() == target.version() {
                RosterRefreshOutcome::SupersededUncommitted
            } else if head.version() > target.version() {
                RosterRefreshOutcome::SupersededUnknown
            } else if current.roster_validity.until() <= now {
                RosterRefreshOutcome::ExpiredUncommitted
            } else {
                return Err(DurableError::Suspended);
            };
            let expected = RosterRefreshResolution {
                journal: admission.journal,
                previous,
                target,
                outcome,
                observed: head,
                observed_at: now,
            };
            let can_rebind = observed.contains_member(
                current.device_id(),
                current.generation(),
                current.credential_digest(),
            ) && current
                .description
                .validity
                .from()
                .max(observed.validity().from())
                < current
                    .description
                    .validity
                    .until()
                    .min(observed.validity().until());
            if can_rebind {
                self.historical_device_metadata(&admission.certificate, observed.as_bytes(), head)?;
            }
            image.roster_resolution = Some(RetainedRosterResolution {
                result: expected,
                target: current.roster().clone(),
                observed,
            });
            let Phase::Accepted {
                admission, stage, ..
            } = &mut image.phase
            else {
                return Err(DurableError::Corrupt);
            };
            if outcome == RosterRefreshOutcome::Committed {
                *stage = AdmissionPhase::Active;
            } else if can_rebind {
                admission.roster = image
                    .roster_resolution
                    .as_ref()
                    .ok_or(DurableError::Corrupt)?
                    .observed
                    .as_bytes()
                    .to_vec();
                admission.checkpoint = head;
                *stage = AdmissionPhase::Active;
            } else {
                *stage = AdmissionPhase::RosterResolved { observed: head };
            }
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("roster-resolution-before-save");
            self.save(&image)?;
            #[cfg(all(test, unix))]
            super::tests::renewal::boundary("roster-resolution-after-save");
            let readback = self.image()?;
            let record = readback
                .roster_resolution
                .as_ref()
                .ok_or(DurableError::Corrupt)?;
            if record.result != expected || record.target.as_bytes() != current.roster().as_bytes()
            {
                return Err(DurableError::Conflict);
            }
            Ok(record.result)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
