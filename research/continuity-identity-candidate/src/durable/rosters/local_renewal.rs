// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded unacknowledged local completion, independent of current membership.
use super::*;

// Exact transaction identity shared by journal commit and the original
// enrollment coordinator. Historical approvals are not current permission.
pub(crate) struct LocalRenewalTarget<'a> {
    pub(crate) grant: &'a VerifiedCredentialRenewal,
    pub(crate) continuation: Option<&'a crate::HistoricalPolicyContinuation>,
    pub(crate) policy_renewal: Option<(&'a crate::HistoricalPolicyRenewal, &'a VerifiedDevice)>,
}
impl<'a> LocalRenewalTarget<'a> {
    pub(crate) fn credential(grant: &'a VerifiedCredentialRenewal) -> Self {
        Self {
            grant,
            continuation: None,
            policy_renewal: None,
        }
    }
    pub(crate) fn receipt(&self) -> Result<LocalRenewalCommit, DurableError> {
        let mut receipt = LocalRenewalCommit::for_grant(self.grant);
        if let Some(t) = self.continuation {
            t.check_credential(self.grant)?;
            receipt.statement = t.statement_digest();
        }
        Ok(receipt)
    }
    fn check_scope(
        &self,
        image: &Image,
        authority: &crate::RetainedInstallationAuthority,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        saved: &Stored,
    ) -> Result<(), DurableError> {
        if saved.policy_renewal.is_some() && self.policy_renewal.is_none() {
            return Err(DurableError::Suspended);
        }
        let policy = policy.as_ref();
        let required = match image.protection {
            Protection::Local => None,
            Protection::Required {
                policy, witness, ..
            } => Some((policy, witness)),
        };
        authority.check(image.owner, required)?;
        if policy.anchor_requirement().binding() != authority.witness
            || self.grant.original_storage_owner() != image.owner
            || self.grant.successor_device().account_id() != image.local_account
            || self.grant.policy_digest() != authority.policy
        {
            return Err(DurableError::Conflict);
        }
        if let Some((approval, original)) = self.policy_renewal {
            if self.continuation.is_some() || image.protection != Protection::Local {
                return Err(DurableError::Conflict);
            }
            super::policy_renewal::check_credential_target(
                image, saved, approval, original, self.grant,
            )?;
            approval.check_target(policy)?;
        } else if let Some(t) = self.continuation.or(saved.policy_continuation.as_ref()) {
            if t.scope().journal.as_bytes() != &image.id
                || t.scope().original_owner != image.owner
                || t.scope().original_policy.digest() != authority.policy
                || t.scope().original_credential != self.grant.original_credential_digest()
            {
                return Err(DurableError::Conflict);
            }
            t.check_target(policy)?;
        } else if policy.checkpoint().digest() != authority.policy {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn check_committed(&self, saved: &Stored) -> Result<(), DurableError> {
        if let Some((approval, original)) = self.policy_renewal {
            let retained = saved
                .policy_renewal
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            let grant = retained
                .carried_grant
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            approval.check_renewed_identity(original, grant)?;
            if retained.approval_bytes() != approval.journal_bytes()
                || grant.statement_digest() != self.grant.statement_digest()
            {
                return Err(DurableError::Conflict);
            }
        }
        if let Some(t) = self.continuation {
            if saved
                .policy_continuation
                .as_ref()
                .is_none_or(|current| current.journal_bytes() != t.journal_bytes())
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    fn advance(&self, saved: Stored) -> Result<Stored, DurableError> {
        if saved.policy_renewal.is_some() && self.policy_renewal.is_none() {
            return Err(DurableError::Suspended);
        }
        if let Some(t) = self.continuation {
            match &saved.policy_continuation {
                None if t.scope().previous_authorization.is_none()
                    && t.scope().previous_policy == t.scope().original_policy => {}
                Some(previous)
                    if t.scope().previous_authorization == Some(previous.statement_digest())
                        && t.scope().previous_policy == previous.target_policy()
                        && t.scope().original_policy == previous.scope().original_policy
                        && t.scope().operation != previous.scope().operation => {}
                _ => return Err(DurableError::Conflict),
            }
        }
        let mut updated =
            saved.advance_with_renewal(self.grant.successor_device().roster(), Some(self.grant))?;
        if self.policy_renewal.is_some() {
            updated
                .policy_renewal
                .as_mut()
                .ok_or(DurableError::Conflict)?
                .carried_grant = Some(VerifiedCredentialRenewal::from_journal(
                self.grant.as_bytes(),
                &updated.roster,
            )?);
        }
        if let Some(t) = self.continuation {
            updated.policy_continuation = Some(t.clone());
        }
        updated.local_commit = Some(self.receipt()?);
        Ok(updated)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalRenewalCommit {
    pub(crate) operation: CredentialRenewalId,
    pub(crate) statement: [u8; 32],
    pub(crate) owner: [u8; 32],
    pub(crate) policy: [u8; 32],
    pub(crate) target: RosterCheckpoint,
    pub(crate) credential: [u8; 32],
}
impl LocalRenewalCommit {
    pub(crate) fn for_grant(grant: &VerifiedCredentialRenewal) -> Self {
        Self {
            operation: grant.operation(),
            statement: grant.statement_digest(),
            owner: grant.original_storage_owner(),
            policy: grant.policy_digest(),
            target: grant.successor_device().roster().checkpoint(),
            credential: grant.successor_device().credential_digest(),
        }
    }
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.operation.as_bytes());
        for value in [self.statement, self.owner, self.policy, self.credential] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.target.version().to_be_bytes());
        out.extend_from_slice(&self.target.digest());
    }
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, DurableError> {
        let operation = CredentialRenewalId::from_trusted_state(d.array()?)?;
        let statement = d.array()?;
        let owner = d.array()?;
        let policy = d.array()?;
        let credential = d.array()?;
        for value in [statement, owner, policy, credential] {
            crate::codec::nonzero(&value)?;
        }
        let target = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        Ok(Self {
            operation,
            statement,
            owner,
            policy,
            target,
            credential,
        })
    }
}
pub(crate) enum LocalRenewalResolution {
    Committed(LocalRenewalCommit),
    // Only authenticated monotonic predecessor history establishes this fact.
    Uncommitted(RosterCheckpoint),
}
impl DeviceJournal {
    /// Reserve the exact root-authorized local credential target for an explicit
    /// required-witness transaction, without sending Advance or changing authority.
    /// This closes the journal on success or failure. After an unknown result,
    /// inspect the original protected preparation before proposing another target.
    /// The returned metadata grants no current authority or operational owner.
    pub fn prepare_local_credential_renewal(
        &mut self,
        original: &crate::VerifiedDevice,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
        if operation != grant.operation() {
            self.close();
            return Err(DurableError::Conflict);
        }
        self.prepare_enrollment_credential_renewal(original, grant, policy, now, None)
    }
    // The preceding receipt is authenticated by original enrollment. Replace it
    // only INSIDE this new sealed target, without an extra ordinary Advance.
    pub(crate) fn prepare_enrollment_credential_renewal(
        &mut self,
        original: &crate::VerifiedDevice,
        grant: &VerifiedCredentialRenewal,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
        let authority = crate::RetainedInstallationAuthority::active_installation(original, policy);
        self.prepare_enrollment_renewal(
            &crate::installation::PolicyScope {
                authority: &authority,
                original_policy: policy.historical(),
                original_device: original,
            },
            &LocalRenewalTarget::credential(grant),
            policy,
            now,
            completed,
        )
    }
    pub(crate) fn prepare_enrollment_renewal(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        target: &LocalRenewalTarget<'_>,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<crate::AnchorCredentialRenewalProposal, DurableError> {
        let result = (|| {
            if policy.anchor_requirement().binding().is_none() {
                return Err(DurableError::AnchorRequired);
            }
            let grant = target.grant;
            self.check_policy(scope.original_policy)?;
            let (mut image, saved, _) = self.local_renewal_state_with_prior(
                scope.authority,
                target,
                grant.operation(),
                policy,
                completed,
            )?;
            if saved.local_commit.as_ref() != completed
                || scope.local_identity()
                    != (image.local_account, grant.successor_device().device_id())
                || scope.original_policy.checkpoint().digest() != scope.authority.policy
            {
                return Err(DurableError::Conflict);
            }
            if let Some(t) = target.continuation.or(saved.policy_continuation.as_ref()) {
                t.check_context_policy(scope.original_policy, policy)?;
            }
            self.check_release(&image)?;
            crate::installation::admit(grant.successor_device(), policy, now)?;
            let updated = target.advance(saved)?;
            let policy_intent = updated.policy_continuation.as_ref().map(|t| {
                if target.continuation.is_some() {
                    write_intent::PolicyIntent::Adopt(t.statement_digest())
                } else {
                    write_intent::PolicyIntent::Retain(t.statement_digest())
                }
            });
            image
                .records
                .insert(id(&image.local_account), updated.record()?);
            let sealed = self.seal_next_image(&mut image)?;
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let proposal = write_intent::reserve_credential_renewal(
                active,
                &image,
                &sealed,
                write_intent::RenewalBinding {
                    operation: grant.operation(),
                    credential: grant.statement_digest(),
                    policy: policy_intent,
                },
            )?;
            // Preserve the preparation if authority closes during persistence,
            // but withhold a fresh successful return from that closed runtime.
            crate::installation::admit(grant.successor_device(), policy, now)?;
            Ok(proposal)
        })();
        self.close();
        result
    }
    fn local_renewal_state_with_prior(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        target: &LocalRenewalTarget<'_>,
        operation: CredentialRenewalId,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<(Image, Stored, LocalRenewalCommit), DurableError> {
        let image = self.image()?;
        if operation != target.grant.operation() {
            return Err(DurableError::Conflict);
        }
        let saved = get(&image, &image.local_account)?;
        target.check_scope(&image, authority, policy, &saved)?;
        let receipt = target.receipt()?;
        if saved
            .local_commit
            .as_ref()
            .is_some_and(|current| current != &receipt && Some(current) != completed)
        {
            return Err(DurableError::Conflict);
        }
        if saved.local_commit.as_ref() == Some(&receipt) {
            target.check_committed(&saved)?;
        }
        Ok((image, saved, receipt))
    }
    // A historical continuation caller can finish only an exact existing
    // receipt. The predecessor or an older completion is not a new commit.
    pub(crate) fn inspect_committed_local_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        target: &LocalRenewalTarget<'_>,
        policy: &crate::HistoricalSessionPolicy,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<LocalRenewalCommit, DurableError> {
        let (image, saved, receipt) = self.local_renewal_state_with_prior(
            authority,
            target,
            target.grant.operation(),
            policy,
            completed,
        )?;
        if image.protection != Protection::Local {
            return Err(DurableError::AnchorRequired);
        }
        if saved.local_commit.as_ref() != Some(&receipt) {
            return Err(DurableError::Suspended);
        }
        self.check_release(&image)?;
        Ok(receipt)
    }
    // Called only by original enrollment while its exact pending intent is held.
    // This publishes historical classification, never operational authority.
    pub(crate) fn inspect_local_credential_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        grant: &VerifiedCredentialRenewal,
        policy: &crate::VerifiedSessionPolicy,
    ) -> Result<LocalRenewalResolution, DurableError> {
        self.inspect_local_renewal_target(authority, &LocalRenewalTarget::credential(grant), policy)
    }
    pub(crate) fn inspect_local_renewal_target(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        target: &LocalRenewalTarget<'_>,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    ) -> Result<LocalRenewalResolution, DurableError> {
        let grant = target.grant;
        let (image, saved, receipt) = self.local_renewal_state_with_prior(
            authority,
            target,
            grant.operation(),
            policy,
            None,
        )?;
        if saved.local_commit.is_some() {
            self.check_release(&image)?;
            return Ok(LocalRenewalResolution::Committed(receipt));
        }
        let previous = grant.previous_device();
        let head = saved.roster.checkpoint();
        let predecessor = previous.roster().checkpoint();
        // The authenticated history never removes a generation or restores its
        // older credential. Renewal strictly extends validity, so observing this
        // exact same-generation predecessor still in history proves that the
        // target was never installed, even if unrelated roster updates/revocation
        // advanced the head. A higher generation loses this proof and fails.
        if !saved.roster.same_authority(previous.roster())
            || head.version() < predecessor.version()
            || (head.version() == predecessor.version() && head != predecessor)
            || saved.history.get(&previous.device_id())
                != Some(&(previous.generation(), previous.credential_digest()))
            || saved
                .renewals
                .get(&previous.device_id())
                .is_some_and(|current| {
                    current.original_credential_digest() != grant.original_credential_digest()
                        || current.policy_digest() != grant.policy_digest()
                })
        {
            return Err(DurableError::Conflict);
        }
        self.check_release(&image)?;
        Ok(LocalRenewalResolution::Uncommitted(head))
    }
    // Called only after exact intent persistence. An existing receipt is a
    // historical fact; an absent target still needs fresh admission to commit.
    pub(crate) fn commit_local_credential_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<LocalRenewalCommit, DurableError> {
        if operation != grant.operation() {
            return Err(DurableError::Conflict);
        }
        self.commit_local_renewal(
            authority,
            &LocalRenewalTarget::credential(grant),
            policy,
            now,
        )
    }
    pub(crate) fn commit_local_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        target: &LocalRenewalTarget<'_>,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<LocalRenewalCommit, DurableError> {
        let (mut image, saved, receipt) = self.local_renewal_state_with_prior(
            authority,
            target,
            target.grant.operation(),
            policy,
            None,
        )?;
        // Only the exact sealed witness transaction may adopt or carry T.
        // Ordinary Advance cannot establish the witness's policy authority.
        if image.protection != Protection::Local
            && (target.continuation.is_some() || saved.policy_continuation.is_some())
        {
            return Err(DurableError::AnchorRequired);
        }
        if saved.local_commit.is_some() {
            self.check_release(&image)?;
            return Ok(receipt);
        }
        crate::installation::admit(target.grant.successor_device(), policy, now)?;
        // Both credential and policy predecessor CAS occur in this original
        // journal transaction; no independent T write can race the credential.
        let updated = target.advance(saved)?;
        image
            .records
            .insert(id(&image.local_account), updated.record()?);
        self.persist(&mut image)?;
        self.check_release(&image)?;
        Ok(receipt)
    }
    // A new intent may follow an already completed enrollment whose journal
    // receipt acknowledgement was interrupted. Never mistake a committed PENDING
    // target for that older completion: its receipt must survive config recovery.
    pub(crate) fn reconcile_prior_local_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        pending: &VerifiedCredentialRenewal,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<(), DurableError> {
        self.reconcile_prior_local_target(
            authority,
            &LocalRenewalTarget::credential(pending),
            completed,
        )
    }
    pub(crate) fn reconcile_prior_local_target(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        pending: &LocalRenewalTarget<'_>,
        completed: Option<&LocalRenewalCommit>,
    ) -> Result<(), DurableError> {
        let image = self.image()?;
        let required = match image.protection {
            Protection::Local => None,
            Protection::Required {
                policy, witness, ..
            } => Some((policy, witness)),
        };
        authority.check(image.owner, required)?;
        if pending.grant.original_storage_owner() != image.owner
            || pending.grant.successor_device().account_id() != image.local_account
            || pending.grant.policy_digest() != authority.policy
        {
            return Err(DurableError::Conflict);
        }
        let saved = get(&image, &image.local_account)?;
        match saved.local_commit.clone() {
            Some(current) if current == pending.receipt()? => {
                pending.check_committed(&saved)?;
                self.check_release(&image)
            }
            Some(current) if completed == Some(&current) => {
                self.acknowledge_local_credential_renewal(authority, &current)
            }
            None => self.check_release(&image),
            Some(_) => Err(DurableError::Conflict),
        }
    }

    // Original enrollment must have durably read back completion before this
    // acknowledgement. Revocation is allowed to advance while this receipt waits.
    pub(crate) fn acknowledge_local_credential_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        commit: &LocalRenewalCommit,
    ) -> Result<(), DurableError> {
        let mut image = self.image()?;
        if authority.owner != image.owner
            || commit.owner != image.owner
            || authority.policy != commit.policy
        {
            return Err(DurableError::Conflict);
        }
        let required = match image.protection {
            Protection::Local => None,
            Protection::Required {
                policy, witness, ..
            } => Some((policy, witness)),
        };
        authority.check(image.owner, required)?;
        let mut saved = get(&image, &image.local_account)?;
        match &saved.local_commit {
            Some(current) if current == commit => {
                saved.local_commit = None;
                image
                    .records
                    .insert(id(&image.local_account), saved.record()?);
                self.persist(&mut image)?;
            }
            None => {} // Exact enrollment completion is independently durable.
            Some(_) => return Err(DurableError::Conflict),
        }
        self.check_release(&image)
    }
    pub(crate) fn check_local_policy_continuation(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        continuation: &crate::HistoricalPolicyContinuation,
    ) -> Result<(), DurableError> {
        let image = self.image()?;
        if image.protection != Protection::Local {
            return Err(DurableError::AnchorRequired);
        }
        authority.check(image.owner, None)?;
        let saved = get(&image, &image.local_account)?;
        if continuation.scope().original_policy.digest() != authority.policy
            || saved
                .policy_continuation
                .as_ref()
                .is_none_or(|current| current.journal_bytes() != continuation.journal_bytes())
        {
            return Err(DurableError::Conflict);
        }
        self.check_release(&image)
    }
    pub(crate) fn check_witnessed_policy_completion(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        continuation: &crate::HistoricalPolicyContinuation,
        completed: &LocalRenewalCommit,
    ) -> Result<(), DurableError> {
        let image = self.image()?;
        let Protection::Required {
            policy, witness, ..
        } = image.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        authority.check(image.owner, Some((policy, witness)))?;
        check_terminal_completion(
            &image,
            Some(continuation.statement_digest()),
            Some(completed),
        )?;
        self.check_release(&image)
    }
    pub(crate) fn check_renewed_local_device(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        current: &VerifiedDevice,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<(), DurableError> {
        self.check_policy(policy)?;
        crate::installation::admit(current, policy, now)?;
        let image = self.image()?;
        authority.check(
            image.owner,
            policy
                .anchor_requirement()
                .binding()
                .map(|w| (policy.checkpoint().digest(), w)),
        )?;
        let saved = get(&image, &image.local_account)?;
        let grant = saved
            .renewals
            .get(&current.device_id())
            .ok_or(DurableError::Conflict)?;
        if authority.policy != policy.checkpoint().digest()
            || grant.successor_device().credential_digest() != current.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
        authorize_local_device(&image, current, policy, now)?;
        self.check_release(&image)
    }
}

#[cfg(all(test, unix))]
#[path = "local_renewal_tests.rs"]
mod tests;
