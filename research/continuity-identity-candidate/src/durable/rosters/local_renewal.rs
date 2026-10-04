// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded unacknowledged local completion, independent of current membership.
use super::*;

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
    fn for_grant(grant: &VerifiedCredentialRenewal) -> Self {
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
    fn local_renewal_state(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        grant: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
    ) -> Result<(Image, Stored, LocalRenewalCommit), DurableError> {
        self.check_policy(policy)?;
        let image = self.image()?;
        authority.check(
            image.owner,
            policy
                .anchor_requirement()
                .binding()
                .map(|w| (policy.checkpoint().digest(), w)),
        )?;
        if image.owner != grant.original_storage_owner()
            || image.local_account != grant.successor_device().account_id()
            || authority.policy != policy.checkpoint().digest()
            || grant.policy_digest() != authority.policy
            || operation != grant.operation()
        {
            return Err(DurableError::Conflict);
        }
        let saved = get(&image, &image.local_account)?;
        let receipt = LocalRenewalCommit::for_grant(grant);
        if saved
            .local_commit
            .as_ref()
            .is_some_and(|current| current != &receipt)
        {
            return Err(DurableError::Conflict);
        }
        Ok((image, saved, receipt))
    }
    // Called only by original enrollment while its exact pending intent is held.
    // This publishes historical classification, never operational authority.
    pub(crate) fn inspect_local_credential_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        grant: &VerifiedCredentialRenewal,
        policy: &crate::VerifiedSessionPolicy,
    ) -> Result<LocalRenewalResolution, DurableError> {
        let (image, saved, receipt) =
            self.local_renewal_state(authority, grant, grant.operation(), policy)?;
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
        let (mut image, saved, receipt) =
            self.local_renewal_state(authority, grant, operation, policy)?;
        if saved.local_commit.is_some() {
            self.check_release(&image)?;
            return Ok(receipt);
        }
        crate::installation::admit(grant.successor_device(), policy, now)?;
        // Unlike historical classification, a new mutation still requires the
        // exact predecessor checkpoint signed by this particular root grant.
        let mut updated =
            saved.advance_with_renewal(grant.successor_device().roster(), Some(grant))?;
        updated.local_commit = Some(receipt.clone());
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
        let image = self.image()?;
        let required = match image.protection {
            Protection::Local => None,
            Protection::Required {
                policy, witness, ..
            } => Some((policy, witness)),
        };
        authority.check(image.owner, required)?;
        if pending.original_storage_owner() != image.owner
            || pending.successor_device().account_id() != image.local_account
            || pending.policy_digest() != authority.policy
        {
            return Err(DurableError::Conflict);
        }
        let saved = get(&image, &image.local_account)?;
        match saved.local_commit {
            Some(current) if current == LocalRenewalCommit::for_grant(pending) => {
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
