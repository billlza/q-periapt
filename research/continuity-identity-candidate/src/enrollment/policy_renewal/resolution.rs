// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original policy-only outcome resolution; never infer no commit from an error.
use super::*;
use crate::durable::LocalPolicyRenewalResolution;

struct AbandonedPolicy {
    record: RetainedPolicyRenewal,
    reason: PolicyRenewalAbandonment,
    observed_roster: RosterCheckpoint,
    expired_at: u64,
    observed_at: u64,
}
pub(in crate::enrollment) struct RetainedPolicyResolution {
    floor: u64,
    abandoned: Option<AbandonedPolicy>,
}
impl RetainedPolicyResolution {
    pub(in crate::enrollment) fn check_time(&self, now: u64) -> Result<(), DurableError> {
        if now < self.floor {
            return Err(Error::Validity.into());
        }
        Ok(())
    }
    pub(in crate::enrollment) fn contains(&self, operation: PolicyRenewalId) -> bool {
        self.abandoned
            .as_ref()
            .is_some_and(|r| r.record.operation == operation)
    }
    pub(in crate::enrollment) fn clear_abandoned(&mut self) {
        self.abandoned = None;
    }
    pub(in crate::enrollment) fn status(&self) -> Option<PolicyRenewalStatus> {
        self.abandoned
            .as_ref()
            .map(|r| PolicyRenewalStatus::AbandonedUncommitted {
                operation: r.record.operation,
                statement: r.record.statement,
                target: r.record.target,
                reason: r.reason,
                observed_roster: r.observed_roster,
                observed_at: r.observed_at,
            })
    }
    pub(in crate::enrollment) fn validate(&self, image: &Image) -> Result<(), DurableError> {
        if self.floor == 0
            || !matches!(
                image.phase,
                Phase::Accepted {
                    stage: AdmissionPhase::Active
                        | AdmissionPhase::Refreshing { .. }
                        | AdmissionPhase::RosterResolved { .. },
                    ..
                }
            )
        {
            return Err(DurableError::Corrupt);
        }
        if let Some(r) = &self.abandoned {
            if r.observed_at != self.floor
                || image
                    .policy_pending
                    .as_ref()
                    .is_some_and(|p| p.operation == r.record.operation)
                || image
                    .policy_completed
                    .as_ref()
                    .is_some_and(|p| p.operation == r.record.operation)
                || match r.reason {
                    PolicyRenewalAbandonment::Expired => {
                        r.expired_at == 0 || r.expired_at > r.observed_at
                    }
                    PolicyRenewalAbandonment::RosterAdvanced => r.expired_at != 0,
                }
            {
                return Err(DurableError::Corrupt);
            }
        } else if image.policy_completed.is_none() {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        out.extend_from_slice(&self.floor.to_be_bytes());
        out.push(u8::from(self.abandoned.is_some()));
        if let Some(r) = &self.abandoned {
            r.record.encode(out)?;
            out.push(match r.reason {
                PolicyRenewalAbandonment::Expired => 1,
                PolicyRenewalAbandonment::RosterAdvanced => 2,
            });
            out.extend_from_slice(&r.observed_roster.version().to_be_bytes());
            out.extend_from_slice(&r.observed_roster.digest());
            out.extend_from_slice(&r.expired_at.to_be_bytes());
            out.extend_from_slice(&r.observed_at.to_be_bytes());
        }
        Ok(())
    }
    pub(in crate::enrollment) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let floor = d.u64()?;
        let abandoned = match d.array::<1>()? {
            [0] => None,
            [1] => Some(AbandonedPolicy {
                record: RetainedPolicyRenewal::decode(d)?,
                reason: match d.array::<1>()? {
                    [1] => PolicyRenewalAbandonment::Expired,
                    [2] => PolicyRenewalAbandonment::RosterAdvanced,
                    _ => return Err(DurableError::Corrupt),
                },
                observed_roster: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
                expired_at: d.u64()?,
                observed_at: d.u64()?,
            }),
            _ => return Err(DurableError::Corrupt),
        };
        Ok(Self { floor, abandoned })
    }
}

impl DeviceEnrollment {
    pub(in crate::enrollment) fn validate_policy_resolution(
        &self,
        image: &Image,
    ) -> Result<(), DurableError> {
        let Some(resolution) = &image.policy_resolution else {
            return Ok(());
        };
        resolution.validate(image)?;
        let Some(r) = &resolution.abandoned else {
            return Ok(());
        };
        let approval = self.authenticated_policy_record(&r.record)?;
        let original = self.original_device_metadata(image)?;
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let scope = approval.scope();
        if scope.original_owner != crate::bootstrap::storage_owner(&original)
            || scope.original_credential != original.credential_digest()
            || scope.journal != admission.journal
            || scope.original_policy.digest() != admission.policy
            || r.observed_roster.version() < scope.current_roster.version()
            || (r.observed_roster.version() == scope.current_roster.version()
                && r.observed_roster != scope.current_roster)
            || (r.reason == PolicyRenewalAbandonment::RosterAdvanced
                && r.observed_roster.version() <= scope.current_roster.version())
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }

    /// Resolve only this original policy-only operation. An exact journal
    /// adoption is completed as Committed. An unchanged policy predecessor can
    /// prove no commit; only signed target expiry or an advanced actual roster
    /// then permits AbandonedUncommitted. Other conflicts remain unresolved.
    ///
    /// Independently verified original/target policy history and a trusted clock
    /// are required. This uses no live runtime/private signer and returns no
    /// owner. A last abandoned outcome is retained until another abandonment or
    /// a later policy completion; its time floor remains after retirement.
    pub fn resolve_policy_renewal(
        &mut self,
        operation: PolicyRenewalId,
        statement: [u8; 32],
        original_policy: &HistoricalSessionPolicy,
        target_policy: &HistoricalSessionPolicy,
        now: u64,
    ) -> Result<PolicyRenewalStatus, DurableError> {
        let result = (|| {
            let mut image = self.image()?;
            let Phase::Accepted {
                admission, stage, ..
            } = &image.phase
            else {
                return Err(Error::State.into());
            };
            if original_policy.anchor_requirement().binding().is_some()
                || target_policy.anchor_requirement().binding().is_some()
            {
                return Err(DurableError::AnchorRequired);
            }
            if admission.policy != original_policy.checkpoint().digest() {
                return Err(DurableError::Conflict);
            }
            if let Some(resolution) = &image.policy_resolution {
                if let Some(r) = &resolution.abandoned {
                    if r.record.operation == operation {
                        if r.record.statement != statement {
                            return Err(DurableError::Conflict);
                        }
                        self.authenticated_policy_record(&r.record)?
                            .check_target(target_policy)?;
                        return resolution.status().ok_or(DurableError::Corrupt);
                    }
                }
            }
            if image.policy_pending.is_none()
                && image
                    .policy_completed
                    .as_ref()
                    .is_some_and(|r| r.operation == operation && r.statement == statement)
            {
                self.completed_policy_approval(&image)?
                    .ok_or(DurableError::Conflict)?
                    .check_target(target_policy)?;
                return self.recover_historical_policy_renewal(
                    operation,
                    statement,
                    original_policy,
                );
            }
            if *stage != AdmissionPhase::Active {
                return Err(DurableError::Suspended);
            }
            let pending = image
                .policy_pending
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if pending.operation != operation || pending.statement != statement {
                return Err(DurableError::Conflict);
            }
            let approval = self.authenticated_policy_record(pending)?;
            approval.check_target(target_policy)?;
            let original = self.original_device_metadata(&image)?;
            let current = self.historical_device_metadata(
                &admission.certificate,
                &admission.roster,
                admission.checkpoint,
            )?;
            let target = LocalPolicyRenewalTarget {
                approval: &approval,
                original: &original,
                current: &current,
                original_policy,
            };
            let completed = self
                .completed_policy_approval(&image)?
                .as_ref()
                .map(LocalPolicyRenewalCommit::for_approval);
            let authority = crate::RetainedInstallationAuthority::active_installation(
                &original,
                original_policy,
            );
            let mut service = self.reconcile_installation(&original, original_policy, None)?;
            let journal = service.stores()?.0;
            if journal.identity()? != admission.journal {
                return Err(DurableError::Conflict);
            }
            match journal.inspect_policy_renewal_outcome(&target, completed.as_ref())? {
                LocalPolicyRenewalResolution::Committed(receipt) => {
                    image.policy_completed = image.policy_pending.take();
                    image.policy_device_binding = PolicyDeviceBinding::Exact;
                    if let Some(r) = &mut image.policy_resolution {
                        r.clear_abandoned();
                    }
                    self.save(&image)?;
                    let readback = self.image()?;
                    let actual = readback
                        .policy_completed
                        .as_ref()
                        .ok_or(DurableError::Corrupt)?;
                    if readback.policy_pending.is_some()
                        || self.authenticated_policy_record(actual)?.journal_bytes()
                            != approval.journal_bytes()
                    {
                        return Err(DurableError::Conflict);
                    }
                    #[cfg(all(test, unix))]
                    super::super::tests::renewal::boundary("policy-resolution-completion");
                    journal.acknowledge_local_policy_renewal(&authority, &receipt)?;
                    Ok(actual.committed_status())
                }
                LocalPolicyRenewalResolution::Uncommitted(head) => {
                    image.check_time_floor(now)?;
                    let from = current
                        .description
                        .validity
                        .from()
                        .max(current.roster_validity.from())
                        .max(target_policy.validity().from());
                    if now < from || now == 0 {
                        return Err(Error::Validity.into());
                    }
                    let expired_at = current
                        .description
                        .validity
                        .until()
                        .min(current.roster_validity.until())
                        .min(target_policy.validity().until());
                    let (reason, expired_at) = if expired_at <= now {
                        (PolicyRenewalAbandonment::Expired, expired_at)
                    } else if head.version() > approval.scope().current_roster.version() {
                        (PolicyRenewalAbandonment::RosterAdvanced, 0)
                    } else {
                        return Err(DurableError::Suspended);
                    };
                    image.policy_resolution = Some(RetainedPolicyResolution {
                        floor: now,
                        abandoned: Some(AbandonedPolicy {
                            record: image.policy_pending.take().ok_or(DurableError::Corrupt)?,
                            reason,
                            observed_roster: head,
                            expired_at,
                            observed_at: now,
                        }),
                    });
                    let expected = image
                        .policy_resolution
                        .as_ref()
                        .and_then(RetainedPolicyResolution::status)
                        .ok_or(DurableError::Corrupt)?;
                    #[cfg(all(test, unix))]
                    super::super::tests::renewal::boundary("policy-resolution-before-save");
                    self.save(&image)?;
                    #[cfg(all(test, unix))]
                    super::super::tests::renewal::boundary("policy-resolution-after-save");
                    let readback = self.image()?;
                    let actual = readback
                        .policy_resolution
                        .as_ref()
                        .and_then(RetainedPolicyResolution::status)
                        .ok_or(DurableError::Corrupt)?;
                    if readback.policy_pending.is_some() || actual != expected {
                        return Err(DurableError::Conflict);
                    }
                    Ok(actual)
                }
            }
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
