// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Target-free closure reuses original scope, head, policy and version-floor checks.
use super::*;

impl AnchorStore {
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
        self.close_unprepared_renewal(cancellation, grant, policy, None, None)
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
            None,
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
            None,
        )
    }
    pub(super) fn close_unprepared_renewal(
        &mut self,
        cancellation: AnchorCredentialRenewalCancellation,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
        continuation: Option<(
            &crate::HistoricalPolicyContinuation,
            &HistoricalSessionPolicy,
        )>,
        retained_policy: Option<&HistoricalSessionPolicy>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        let control = super::transferred_control::Scope::original(self, cancellation.subject())?;
        self.close_unprepared_renewal_controlled(
            control.bind(cancellation, cancellation.subject())?,
            grant,
            policy,
            continuation,
            retained_policy,
        )
    }
    pub(in crate::anchor::store) fn close_unprepared_renewal_controlled(
        &mut self,
        controlled: super::transferred_control::Proposal<AnchorCredentialRenewalCancellation>,
        grant: &HistoricalCredentialRenewal,
        policy: &HistoricalSessionPolicy,
        continuation: Option<(
            &crate::HistoricalPolicyContinuation,
            &HistoricalSessionPolicy,
        )>,
        retained_policy: Option<&HistoricalSessionPolicy>,
    ) -> Result<AnchorCredentialCancellationState, DurableError> {
        let super::transferred_control::Proposal {
            scope: control,
            value: cancellation,
        } = controlled;
        let scope = RenewalScope::from(&cancellation);
        Self::check_renewal_scope_controlled(&scope, grant, policy, &control)?;
        if let Some((_, target)) = continuation {
            control.check_keys(grant.successor_device(), target)?;
        }
        if let Some(target) = retained_policy {
            control.check_keys(grant.successor_device(), target)?;
        }
        let version = grant.successor_checkpoint().version();
        let id = cancellation.subject.id(&self.namespace()?);
        let mut image = self.image()?;
        control.live(self, &image)?;
        let entry = image.entries.get(&id).ok_or(DurableError::Absent)?;
        if entry
            .independent_roster
            .as_ref()
            .is_some_and(RosterRefresh::pending)
        {
            return Err(DurableError::Conflict);
        }
        let target = if let Some(policy) = retained_policy {
            if continuation.is_some() || cancellation.adopts_policy() {
                return Err(DurableError::Conflict);
            }
            Some(
                entry.retained_independent_policy(
                    cancellation
                        .policy_renewal()
                        .ok_or(DurableError::Conflict)?,
                    policy,
                )?,
            )
        } else {
            if entry.independent_policy.is_some() || cancellation.policy_renewal().is_some() {
                return Err(DurableError::Conflict);
            }
            match continuation {
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
            }
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
        if version <= entry.roster_floor() {
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
        if retained_policy.is_some() {
            entry
                .independent_policy
                .as_mut()
                .ok_or(DurableError::Conflict)?
                .credential_after = true;
        }
        entry.renewal = Some(CredentialRenewalRecord::GrantClosed {
            cancellation,
            version,
            policy: target,
        });
        self.persist(&mut image)?;
        Ok(AnchorCredentialCancellationState::Closed)
    }
}
