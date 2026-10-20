// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same-C/R policy adoption and its separately typed original-journal receipt.
use super::*;
use crate::{HistoricalPolicyRenewal, HistoricalSessionPolicy, PolicyCheckpoint, PolicyRenewalId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalPolicyRenewalCommit {
    pub(crate) operation: PolicyRenewalId,
    pub(crate) statement: [u8; 32],
    pub(crate) journal: crate::JournalIdentity,
    pub(crate) owner: [u8; 32],
    pub(crate) original_policy: PolicyCheckpoint,
    pub(crate) credential: [u8; 32],
    pub(crate) roster: RosterCheckpoint,
    pub(crate) target: PolicyCheckpoint,
}
pub(crate) enum LocalPolicyRenewalResolution {
    Committed(Box<LocalPolicyRenewalCommit>),
    Uncommitted(RosterCheckpoint),
}
impl LocalPolicyRenewalCommit {
    pub(crate) fn for_approval(approval: &HistoricalPolicyRenewal) -> Self {
        let s = approval.scope();
        Self {
            operation: s.operation,
            statement: approval.statement_digest(),
            journal: s.journal,
            owner: s.original_owner,
            original_policy: s.original_policy,
            credential: s.current_credential,
            roster: s.current_roster,
            target: approval.target_policy(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReceiptPhase {
    AwaitingEnrollment,
    Acknowledged,
}
pub(super) struct StoredPolicyRenewal {
    approval: HistoricalPolicyRenewal,
    phase: ReceiptPhase,
    // Historical G evidence must survive revocation/generation replacement,
    // which can legitimately remove its active entry from Stored.renewals.
    pub(super) carried_grant: Option<crate::VerifiedCredentialRenewal>,
}
impl StoredPolicyRenewal {
    pub(super) fn format_tag(&self) -> Result<&'static [u8; 8], DurableError> {
        match self.carried_grant.as_ref() {
            None => Ok(b"QPRHST05"),
            Some(grant)
                if grant.successor_device().credential_digest()
                    == self.approval.scope().current_credential
                    && self.phase == ReceiptPhase::AwaitingEnrollment =>
            {
                Ok(b"QPRHST08")
            }
            Some(grant)
                if grant.successor_device().credential_digest()
                    != self.approval.scope().current_credential
                    && self.phase == ReceiptPhase::Acknowledged =>
            {
                Ok(b"QPRHST06")
            }
            Some(grant)
                if grant.successor_device().credential_digest()
                    != self.approval.scope().current_credential
                    && self.phase == ReceiptPhase::AwaitingEnrollment =>
            {
                Ok(b"QPRHST09")
            }
            _ => Err(DurableError::Corrupt),
        }
    }
    pub(super) fn policy_binding(&self) -> (PolicyCheckpoint, [u8; 32]) {
        (
            self.approval.target_policy(),
            self.approval.statement_digest(),
        )
    }
    pub(super) fn approval_bytes(&self) -> Vec<u8> {
        self.approval.journal_bytes()
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), DurableError> {
        out.push(match self.phase {
            ReceiptPhase::AwaitingEnrollment => 0,
            ReceiptPhase::Acknowledged => 1,
        });
        out.extend_from_slice(&self.approval.journal_bytes());
        if let Some(grant) = &self.carried_grant {
            let length =
                u32::try_from(grant.as_bytes().len()).map_err(|_| DurableError::Capacity)?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(grant.as_bytes());
        }
        Ok(())
    }
    pub(super) fn decode(
        d: &mut Decoder<'_>,
        roster: &VerifiedRoster,
        format_tag: [u8; 8],
    ) -> Result<Self, DurableError> {
        let phase = match d.array::<1>()? {
            [0] => ReceiptPhase::AwaitingEnrollment,
            [1] => ReceiptPhase::Acknowledged,
            _ => return Err(DurableError::Corrupt),
        };
        let (root, family) = roster.continuation_authority();
        let approval = HistoricalPolicyRenewal::from_authority(
            d.take(crate::PUBLIC_KEY_BYTES + crate::MAX_POLICY_RENEWAL_BYTES)?,
            root,
            family,
        )
        .map_err(DurableError::InvalidCheckpoint)?;
        let carried_grant = if matches!(&format_tag, b"QPRHST06" | b"QPRHST08" | b"QPRHST09") {
            let length = usize::try_from(u32::from_be_bytes(d.array()?))
                .map_err(|_| DurableError::Corrupt)?;
            if length > crate::MAX_CREDENTIAL_RENEWAL_BYTES {
                return Err(DurableError::Corrupt);
            }
            Some(crate::VerifiedCredentialRenewal::from_journal(
                d.take(length)?,
                roster,
            )?)
        } else {
            None
        };
        let value = Self {
            approval,
            phase,
            carried_grant,
        };
        if value.format_tag()? != &format_tag {
            return Err(DurableError::Corrupt);
        }
        Ok(value)
    }

    fn receipt(&self) -> LocalPolicyRenewalCommit {
        LocalPolicyRenewalCommit::for_approval(&self.approval)
    }
}

fn credential_precedes_policy(
    image: &Image,
    saved: &Stored,
    approval: &HistoricalPolicyRenewal,
) -> bool {
    let scope = approval.scope();
    if !matches!(image.protection, Protection::Required { policy, .. } if policy == scope.original_policy.digest())
    {
        return false;
    }
    let Some(receipt) = saved.local_commit.as_ref() else {
        return false;
    };
    let matches = |grant: &crate::VerifiedCredentialRenewal| {
        let checkpoint = grant.successor_device().roster().checkpoint();
        receipt.matches_credential_grant(grant)
            && grant.original_storage_owner() == image.owner
            && grant.original_credential_digest() == scope.original_credential
            && grant.policy_digest() == scope.original_policy.digest()
            && grant.successor_device().credential_digest() == scope.current_credential
            && checkpoint.version() <= scope.current_roster.version()
            && (checkpoint.version() != scope.current_roster.version()
                || checkpoint == scope.current_roster)
    };
    // Adopted P carries its own exact G, including after active roster history
    // retires it. Regular traffic must not scan every device's renewal record.
    match saved
        .policy_renewal
        .as_ref()
        .and_then(|p| p.carried_grant.as_ref())
    {
        Some(grant) => matches(grant),
        None => saved.renewals.values().any(matches), // Initial P preparation only.
    }
}

fn credential_follows_policy(
    image: &Image,
    saved: &Stored,
    retained: &StoredPolicyRenewal,
) -> bool {
    matches!(image.protection, Protection::Required { .. })
        && retained.carried_grant.as_ref().is_some_and(|g| {
            g.successor_device().credential_digest() != retained.approval.scope().current_credential
                && saved
                    .local_commit
                    .as_ref()
                    .is_some_and(|c| c.matches_credential_grant(g))
        })
}

pub(super) fn adopted<'a>(
    image: &Image,
    saved: &'a Stored,
) -> Result<&'a HistoricalPolicyRenewal, DurableError> {
    check_scope(image, saved)?;
    let retained = saved
        .policy_renewal
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    if !completion_acknowledged(image, retained)?
        || (saved.local_commit.is_some()
            && !credential_precedes_policy(image, saved, &retained.approval)
            && !credential_follows_policy(image, saved, retained))
    {
        return Err(DurableError::Suspended);
    }
    Ok(&retained.approval)
}
fn credential<'a>(
    image: &Image,
    saved: &'a Stored,
    original: &'a VerifiedDevice,
    approval: &HistoricalPolicyRenewal,
) -> Result<&'a VerifiedDevice, DurableError> {
    if original.account_id() != image.local_account
        || crate::bootstrap::storage_owner(original) != image.owner
    {
        return Err(DurableError::Conflict);
    }
    let carried = saved
        .policy_renewal
        .as_ref()
        .and_then(|r| r.carried_grant.as_ref());
    let current = if let Some(grant) = carried.or_else(|| saved.renewals.get(&original.device_id()))
    {
        if grant.original_storage_owner() != image.owner
            || grant.original_credential_digest() != original.credential_digest()
            || grant.policy_digest() != approval.scope().original_policy.digest()
        {
            return Err(DurableError::Conflict);
        }
        grant.successor_device()
    } else {
        original
    };
    if let Some(grant) = carried
        .filter(|g| g.successor_device().credential_digest() != approval.scope().current_credential)
    {
        approval.check_renewed_identity(original, grant)?;
    } else {
        approval.check_credential_lineage(original, current)?;
    }
    Ok(current)
}

// Bind only the current acknowledged policy to this original transcript. The
// message engine then resolves both identities, current rosters and runtime.
pub(super) fn bind_session(
    image: &Image,
    saved: &Stored,
    context: &BootstrapContext,
    role: crate::BootstrapRole,
    policy: &crate::VerifiedSessionPolicy,
) -> Result<[u8; 32], DurableError> {
    let approval = adopted(image, saved)?;
    approval.check_context_policy(context.original_policy(), policy)?;
    credential(image, saved, context.device(role), approval)?;
    Ok(approval.statement_digest())
}

pub(super) fn authorize_installation(
    image: &Image,
    saved: &Stored,
    scope: &crate::installation::PolicyScope<'_>,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<VerifiedDevice, DurableError> {
    let approval = adopted(image, saved)?;
    scope.authority.check(
        image.owner,
        scope
            .original_policy
            .anchor_requirement()
            .binding()
            .map(|w| (scope.original_policy.checkpoint().digest(), w)),
    )?;
    image.protection.check_policy(scope.original_policy)?;
    if scope.authority.policy != scope.original_policy.checkpoint().digest() {
        return Err(DurableError::Conflict);
    }
    approval.check_context_policy(scope.original_policy, policy)?;
    let current = credential(image, saved, scope.original_device, approval)?;
    let current = saved.roster.refresh_device(current, now)?;
    crate::installation::admit(&current, policy, now)?;
    Ok(current)
}

pub(super) fn check_scope(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    let Some(current) = &saved.policy_renewal else {
        return Ok(());
    };
    let s = current.approval.scope();
    let head = saved.roster.checkpoint();
    let supported_protection = match image.protection {
        Protection::Local => current.format_tag()? != b"QPRHST09",
        Protection::Required { policy, .. } => {
            policy == s.original_policy.digest()
                && current.phase == ReceiptPhase::AwaitingEnrollment
                && saved.policy_continuation.is_none()
                && (s.current_credential == s.original_credential
                    || current.carried_grant.is_some())
        }
    };
    if !supported_protection
        || image.local_account != saved.roster.account_id()
        || s.journal.as_bytes() != &image.id
        || s.original_owner != image.owner
        || head.version() < s.current_roster.version()
        || (head.version() == s.current_roster.version() && head != s.current_roster)
        || (saved.local_commit.is_some() && current.carried_grant.is_none())
        || saved.renewals.values().any(|g| {
            g.original_storage_owner() == image.owner
                && (g.policy_digest() != s.original_policy.digest()
                    || g.original_credential_digest() != s.original_credential)
        })
        || saved.policy_continuation.as_ref().is_some_and(|t| {
            t.scope().original_policy != s.original_policy
                || t.scope().original_credential != s.original_credential
        })
    {
        return Err(DurableError::Conflict);
    }
    if let Some(grant) = &current.carried_grant {
        let device = grant.successor_device();
        let target = device.roster().checkpoint();
        if grant.original_storage_owner() != image.owner
            || grant.original_credential_digest() != s.original_credential
            || grant.policy_digest() != s.original_policy.digest()
            || target.version() > head.version()
            || (target.version() == head.version() && target != head)
            || saved
                .local_commit
                .as_ref()
                .is_some_and(|receipt| !receipt.matches_credential_grant(grant))
        {
            return Err(DurableError::Conflict);
        }
        match saved.history.get(&device.device_id()) {
            Some(&(generation, certificate))
                if generation == device.generation()
                    && certificate == device.credential_digest() =>
            {
                if saved
                    .renewals
                    .get(&device.device_id())
                    .is_none_or(|active| active.as_bytes() != grant.as_bytes())
                {
                    return Err(DurableError::Conflict);
                }
            }
            Some(&(generation, _)) if generation > device.generation() => {}
            _ => return Err(DurableError::Conflict),
        }
    }
    Ok(())
}

pub(super) fn check_credential_target(
    image: &Image,
    saved: &Stored,
    approval: &HistoricalPolicyRenewal,
    original: &VerifiedDevice,
    grant: &crate::VerifiedCredentialRenewal,
) -> Result<(), DurableError> {
    check_scope(image, saved)?;
    let retained = saved
        .policy_renewal
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    if retained.approval.journal_bytes() != approval.journal_bytes()
        || !completion_acknowledged(image, retained)?
    {
        return Err(DurableError::Conflict);
    }
    approval.check_renewed_identity(original, grant)?;
    let current = credential(image, saved, original, approval)?;
    let expected = if saved
        .local_commit
        .as_ref()
        .is_some_and(|c| c.matches_credential_grant(grant))
    {
        grant.successor_device()
    } else {
        grant.previous_device()
    };
    if current.credential_digest() != expected.credential_digest() {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

pub(crate) struct LocalPolicyRenewalTarget<'a> {
    pub(crate) approval: &'a HistoricalPolicyRenewal,
    pub(crate) original: &'a VerifiedDevice,
    pub(crate) current: &'a VerifiedDevice,
    pub(crate) original_policy: &'a HistoricalSessionPolicy,
}
impl LocalPolicyRenewalTarget<'_> {
    fn check_scope(&self, image: &Image, saved: &Stored) -> Result<(), DurableError> {
        if image.protection != Protection::Local
            || self
                .original_policy
                .anchor_requirement()
                .binding()
                .is_some()
        {
            return Err(DurableError::AnchorRequired);
        }
        self.check_identity_scope(image, saved)
    }
    fn check_identity_scope(&self, image: &Image, saved: &Stored) -> Result<(), DurableError> {
        let s = self.approval.scope();
        if saved.policy_renewal.as_ref().is_some_and(|r| {
            r.carried_grant.is_some() && r.approval.journal_bytes() == self.approval.journal_bytes()
        }) {
            if credential(image, saved, self.original, self.approval)?.credential_digest()
                != self.current.credential_digest()
            {
                return Err(DurableError::Conflict);
            }
        } else {
            self.approval
                .check_credential_lineage(self.original, self.current)?;
        }
        if s.journal.as_bytes() != &image.id
            || s.original_owner != image.owner
            || image.local_account != self.original.account_id()
            || s.original_policy != self.original_policy.checkpoint()
            || !saved.roster.same_authority(self.current.roster())
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn check_predecessor(
        &self,
        image: &Image,
        saved: &Stored,
        completed: Option<&LocalPolicyRenewalCommit>,
    ) -> Result<(), DurableError> {
        let s = self.approval.scope();
        if saved.local_commit.is_some() && !credential_precedes_policy(image, saved, self.approval)
        {
            return Err(DurableError::Suspended);
        }
        if saved.roster.checkpoint() != s.current_roster
            || saved.history.get(&self.current.device_id())
                != Some(&(self.current.generation(), s.current_credential))
            || !saved.roster.contains_member(
                self.current.device_id(),
                self.current.generation(),
                s.current_credential,
            )
        {
            return Err(DurableError::Conflict);
        }
        self.check_policy_predecessor(saved, completed)
    }
    fn check_policy_predecessor(
        &self,
        saved: &Stored,
        completed: Option<&LocalPolicyRenewalCommit>,
    ) -> Result<(), DurableError> {
        let s = self.approval.scope();
        if let Some(previous) = &saved.policy_renewal {
            let prior = previous.receipt();
            // A retained exact enrollment completion can retire its own receipt
            // atomically inside this successor. It cannot retire this Pending.
            if completed != Some(&prior)
                || s.operation == prior.operation
                || s.previous_authorization != Some(prior.statement)
                || s.previous_policy != prior.target
                || s.original_policy != prior.original_policy
            {
                return Err(DurableError::Conflict);
            }
        } else {
            if completed.is_some() {
                return Err(DurableError::Conflict);
            }
            match &saved.policy_continuation {
                None if s.previous_authorization.is_none()
                    && s.previous_policy == s.original_policy => {}
                Some(previous)
                    if s.previous_authorization == Some(previous.statement_digest())
                        && s.previous_policy == previous.target_policy()
                        && s.original_policy == previous.scope().original_policy => {}
                _ => return Err(DurableError::Conflict),
            }
        }
        Ok(())
    }
}

pub(crate) struct RenewalRequestSnapshot {
    pub(crate) journal: crate::JournalIdentity,
    pub(crate) original_owner: [u8; 32],
    pub(crate) original_credential: [u8; 32],
    pub(crate) current_credential: [u8; 32],
    pub(crate) current_roster: RosterCheckpoint,
    pub(crate) current_device: VerifiedDevice,
    pub(crate) original_policy: crate::PolicyCheckpoint,
    pub(crate) current_policy: crate::PolicyCheckpoint,
    pub(crate) current_policy_authorization: Option<[u8; 32]>,
}
pub(in crate::durable) enum RequestRoster {
    Configured,
    Actual,
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    // Signature-bound historical admission, not current membership or an owner.
    // A committed exact target survives later C/R changes. Otherwise only the
    // actual unchanged policy predecessor proves this target never committed.
    pub(crate) async fn inspect_policy_renewal_outcome(
        &mut self,
        target: &LocalPolicyRenewalTarget<'_>,
        completed: Option<&LocalPolicyRenewalCommit>,
    ) -> Result<LocalPolicyRenewalResolution, DurableError> {
        let image = self.image().await?;
        let saved = get(&image, &image.local_account)?;
        if image.protection != Protection::Local
            || target
                .original_policy
                .anchor_requirement()
                .binding()
                .is_some()
        {
            return Err(DurableError::AnchorRequired);
        }
        target
            .approval
            .check_devices(target.original, target.current)?;
        let scope = target.approval.scope();
        if scope.journal.as_bytes() != &image.id
            || scope.original_owner != image.owner
            || scope.original_policy != target.original_policy.checkpoint()
            || image.local_account != target.original.account_id()
            || !saved.roster.same_authority(target.current.roster())
        {
            return Err(DurableError::Conflict);
        }
        if let Some(actual) = &saved.policy_renewal {
            if actual.approval.journal_bytes() == target.approval.journal_bytes() {
                self.check_release(&image).await?;
                return Ok(LocalPolicyRenewalResolution::Committed(Box::new(
                    actual.receipt(),
                )));
            }
        }
        target.check_policy_predecessor(&saved, completed)?;
        let head = saved.roster.checkpoint();
        if head.version() < scope.current_roster.version()
            || (head.version() == scope.current_roster.version() && head != scope.current_roster)
        {
            return Err(DurableError::Conflict);
        }
        self.check_release(&image).await?;
        Ok(LocalPolicyRenewalResolution::Uncommitted(head))
    }
    pub(crate) async fn inspect_policy_credential_authorization(
        &mut self,
        approval: &HistoricalPolicyRenewal,
        original: &VerifiedDevice,
    ) -> Result<LocalPolicyRenewalCommit, DurableError> {
        let image = self.image().await?;
        let saved = get(&image, &image.local_account)?;
        let retained = saved
            .policy_renewal
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        if retained.approval.journal_bytes() != approval.journal_bytes() {
            return Err(DurableError::Conflict);
        }
        credential(&image, &saved, original, approval)?;
        self.check_release(&image).await?;
        Ok(retained.receipt())
    }
    pub(crate) async fn check_policy_credential_completion(
        &mut self,
        approval: &HistoricalPolicyRenewal,
        original: &VerifiedDevice,
        completed: &LocalRenewalCommit,
    ) -> Result<(), DurableError> {
        let image = self.image().await?;
        let saved = get(&image, &image.local_account)?;
        let retained = saved
            .policy_renewal
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        let grant = retained
            .carried_grant
            .as_ref()
            .ok_or(DurableError::Conflict)?;
        if retained.approval.journal_bytes() != approval.journal_bytes()
            || retained.phase != ReceiptPhase::Acknowledged
            || completed != &saved.credential_receipt(grant)?
        {
            return Err(DurableError::Conflict);
        }
        approval.check_renewed_identity(original, grant)?;
        self.check_release(&image).await
    }
    pub(crate) async fn policy_renewal_request_scope(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        current: &VerifiedDevice,
        operation: PolicyRenewalId,
        completed: Option<&HistoricalPolicyRenewal>,
        joint: Option<&crate::HistoricalPolicyContinuation>,
        witnessed_completion: Option<&LocalRenewalCommit>,
    ) -> Result<crate::PolicyRenewalScope, DurableError> {
        let snapshot = self
            .inspect_renewal_request(
                scope,
                current,
                completed,
                joint,
                RequestRoster::Configured,
                witnessed_completion,
            )
            .await?;
        if completed.is_some_and(|approval| approval.scope().operation == operation) {
            return Err(DurableError::Conflict);
        }
        Ok(crate::PolicyRenewalScope {
            operation,
            journal: snapshot.journal,
            original_owner: snapshot.original_owner,
            original_credential: snapshot.original_credential,
            current_credential: snapshot.current_credential,
            current_roster: snapshot.current_roster,
            original_policy: snapshot.original_policy,
            previous_policy: snapshot.current_policy,
            previous_authorization: snapshot.current_policy_authorization,
        })
    }
    pub(crate) async fn renewal_request_snapshot(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        current: &VerifiedDevice,
        completed: Option<&HistoricalPolicyRenewal>,
        joint: Option<&crate::HistoricalPolicyContinuation>,
        witnessed_completion: Option<&LocalRenewalCommit>,
    ) -> Result<RenewalRequestSnapshot, DurableError> {
        self.inspect_renewal_request(
            scope,
            current,
            completed,
            joint,
            RequestRoster::Actual,
            witnessed_completion,
        )
        .await
    }
    async fn inspect_renewal_request(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        current: &VerifiedDevice,
        completed: Option<&HistoricalPolicyRenewal>,
        joint: Option<&crate::HistoricalPolicyContinuation>,
        roster_binding: RequestRoster,
        witnessed_completion: Option<&LocalRenewalCommit>,
    ) -> Result<RenewalRequestSnapshot, DurableError> {
        self.check_policy(scope.original_policy)?;
        let image = self.image().await?;
        let snapshot = inspect_renewal_snapshot(
            &image,
            scope,
            current,
            completed,
            joint,
            roster_binding,
            witnessed_completion,
        )?;
        self.check_release(&image).await?;
        Ok(snapshot)
    }

    // Original enrollment must hold a durable exact Pending. All current CAS
    // checks and the policy/receipt write occur in the original image transaction.
    pub(crate) async fn commit_local_policy_renewal(
        &mut self,
        target: &LocalPolicyRenewalTarget<'_>,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
        completed: Option<&LocalPolicyRenewalCommit>,
    ) -> Result<LocalPolicyRenewalCommit, DurableError> {
        let mut image = self.image().await?;
        let mut saved = get(&image, &image.local_account)?;
        target.check_scope(&image, &saved)?;
        target
            .approval
            .check_context_policy(target.original_policy, policy)?;
        let receipt = LocalPolicyRenewalCommit::for_approval(target.approval);
        if let Some(current) = &saved.policy_renewal {
            if current.receipt() == receipt {
                if current.approval.journal_bytes() != target.approval.journal_bytes() {
                    return Err(DurableError::Conflict);
                }
                self.check_release(&image).await?;
                return Ok(receipt);
            }
        }
        target
            .approval
            .check_devices(target.original, target.current)?;
        target.check_predecessor(&image, &saved, completed)?;
        crate::installation::admit(target.current, policy, now)?;
        saved.roster.authorize_device(target.current, now)?;
        saved.policy_renewal = Some(StoredPolicyRenewal {
            approval: target.approval.clone(),
            phase: ReceiptPhase::AwaitingEnrollment,
            carried_grant: None,
        });
        image
            .records
            .insert(id(&image.local_account), saved.record()?);
        self.persist(&mut image).await?;
        self.check_release(&image).await?;
        Ok(receipt)
    }
    // A historical coordinator may finish only this exact committed target.
    // No absent or older receipt is promoted into a new adoption after expiry.
    pub(crate) async fn inspect_local_policy_renewal(
        &mut self,
        target: &LocalPolicyRenewalTarget<'_>,
    ) -> Result<LocalPolicyRenewalCommit, DurableError> {
        let image = self.image().await?;
        let saved = get(&image, &image.local_account)?;
        target.check_scope(&image, &saved)?;
        let current = saved
            .policy_renewal
            .as_ref()
            .ok_or(DurableError::Suspended)?;
        if current.approval.journal_bytes() != target.approval.journal_bytes() {
            return Err(DurableError::Conflict);
        }
        self.check_release(&image).await?;
        Ok(current.receipt())
    }
    // Caller must first read back this exact original-enrollment completion.
    // This acknowledges history only and is permitted after roster revocation.
    pub(crate) async fn acknowledge_local_policy_renewal(
        &mut self,
        authority: &crate::RetainedInstallationAuthority,
        receipt: &LocalPolicyRenewalCommit,
    ) -> Result<(), DurableError> {
        let mut image = self.image().await?;
        if image.protection != Protection::Local {
            return Err(DurableError::AnchorRequired);
        }
        authority.check(image.owner, None)?;
        if receipt.owner != image.owner
            || receipt.journal.as_bytes() != &image.id
            || receipt.original_policy.digest() != authority.policy
        {
            return Err(DurableError::Conflict);
        }
        let mut saved = get(&image, &image.local_account)?;
        let current = saved
            .policy_renewal
            .as_mut()
            .ok_or(DurableError::Conflict)?;
        if current.receipt() != *receipt {
            return Err(DurableError::Conflict);
        }
        if current.phase == ReceiptPhase::AwaitingEnrollment {
            current.phase = ReceiptPhase::Acknowledged;
            image
                .records
                .insert(id(&image.local_account), saved.record()?);
            self.persist(&mut image).await?;
        }
        self.check_release(&image).await
    }
}

// Completion is retained by the original enrollment, never silently written into
// a different journal phase. Direct journal opens have no such capability.
fn completion_acknowledged(
    image: &Image,
    retained: &StoredPolicyRenewal,
) -> Result<bool, DurableError> {
    if image.protection == Protection::Local {
        return Ok(retained.phase == ReceiptPhase::Acknowledged);
    }
    let Some(completion) = &image.enrollment_completion else {
        return Ok(false);
    };
    check_enrollment_policy_completion(image, completion)?;
    Ok(true)
}
pub(in crate::durable) fn check_enrollment_policy_completion(
    image: &Image,
    completion: &crate::enrollment::EnrollmentPolicyCompletion,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    check_scope(image, &saved)?;
    let actual = saved
        .policy_renewal
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    let approval = completion.approval();
    let original = completion.original();
    let proposal = completion.proposal();
    let scope = approval.scope();
    let Protection::Required {
        policy,
        witness,
        fence,
    } = image.protection
    else {
        return Err(DurableError::AnchorRequired);
    };
    let mut subject = image.id.to_vec();
    subject.extend_from_slice(&image.owner);
    subject.extend_from_slice(&policy);
    if actual.phase != ReceiptPhase::AwaitingEnrollment
        || actual.approval.journal_bytes() != approval.journal_bytes()
        || scope.original_policy.digest() != policy
        || scope.journal.as_bytes() != &image.id
        || scope.original_owner != image.owner
        || proposal.operation() != scope.operation
        || proposal.statement() != approval.statement_digest()
        || proposal.witness_binding() != witness
        || proposal.subject() != crate::AnchorSubject::from_trusted_state(&subject)?
        || proposal.target_head().fence() != fence
        || image.revision < proposal.target_head().revision()
        || (image.revision == proposal.target_head().revision()
            && image.digest != proposal.target_head().digest())
    {
        return Err(DurableError::Conflict);
    }
    // credential() checks exact P lineage, or the original-root G retained after P.
    credential(image, &saved, original, approval)?;
    Ok(())
}
pub(super) fn witness_admission(
    image: &Image,
    saved: &Stored,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<(crate::AnchorOperation, VerifiedDevice), DurableError> {
    let approval = adopted(image, saved)?;
    approval.check_target(policy)?;
    let completion = image
        .enrollment_completion
        .as_ref()
        .ok_or(DurableError::Suspended)?;
    let retained = credential(image, saved, completion.original(), approval)?;
    let current = saved.roster.refresh_device(retained, now)?;
    crate::installation::admit(&current, policy, now)?;
    Ok((
        crate::AnchorOperation::admit_policy_renewal(
            current.authority_binding(),
            approval.statement_digest(),
        )?,
        current,
    ))
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    pub(crate) async fn retain_enrollment_policy_completion(
        &mut self,
        completion: std::sync::Arc<crate::enrollment::EnrollmentPolicyCompletion>,
    ) -> Result<(), DurableError> {
        let result = self
            .retain_enrollment_policy_completion_attempt(completion)
            .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn retain_enrollment_policy_completion_attempt(
        &mut self,
        completion: std::sync::Arc<crate::enrollment::EnrollmentPolicyCompletion>,
    ) -> Result<(), DurableError> {
        let image = self.image().await?;
        check_enrollment_policy_completion(&image, &completion)?;
        self.active
            .as_mut()
            .ok_or(DurableError::Closed)?
            .enrollment_completion = Some(completion);
        Ok(())
    }
}

// Decode the sealed P target under its own typed intent binding. A G/T image
// or an ordinary local-only receipt cannot stand in for this required target.
pub(in crate::durable) fn check_policy_renewal_intent(
    image: &Image,
    binding: write_intent::PolicyRenewalBinding,
) -> Result<(), DurableError> {
    if !matches!(image.protection, Protection::Required { .. }) {
        return Err(DurableError::AnchorRequired);
    }
    let saved = get(image, &image.local_account)?;
    check_scope(image, &saved)?;
    let actual = saved
        .policy_renewal
        .as_ref()
        .ok_or(DurableError::Conflict)?;
    if actual.phase != ReceiptPhase::AwaitingEnrollment
        || actual.approval.scope().operation != binding.operation
        || actual.approval.statement_digest() != binding.statement
        || actual.approval.scope().current_roster != saved.roster.checkpoint()
        || (saved.local_commit.is_some()
            && !credential_precedes_policy(image, &saved, &actual.approval))
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    /// Seal and retain one exact same-credential required-witness P target.
    /// This only reserves the original journal intent; it neither prepares nor
    /// commits the witness. The journal closes on success or failure. After an
    /// unknown result, inspect the original preparation before attempting any
    /// new target. No runtime or operational owner is returned.
    pub async fn prepare_policy_renewal(
        &mut self,
        approval: &crate::VerifiedPolicyRenewal,
        materials: &crate::PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<crate::AnchorPolicyRenewalProposal, DurableError> {
        let result = self
            .prepare_policy_renewal_attempt(approval, materials, now)
            .await;
        self.close();
        result
    }
    async fn prepare_policy_renewal_attempt(
        &mut self,
        approval: &crate::VerifiedPolicyRenewal,
        materials: &crate::PolicyRenewalMaterials<'_>,
        now: u64,
    ) -> Result<crate::AnchorPolicyRenewalProposal, DurableError> {
        let verified = crate::VerifiedPolicyRenewal::from_bytes(
            approval.as_bytes(),
            approval.scope(),
            materials,
            now,
        )?;
        let history = verified.historical();
        let mut image = self.image().await?;
        image.protection.check_policy(materials.original)?;
        if !matches!(image.protection, Protection::Required { .. }) {
            return Err(DurableError::AnchorRequired);
        }
        let mut saved = get(&image, &image.local_account)?;
        if saved.policy_continuation.is_some()
            || (history.scope().current_credential != history.scope().original_credential
                && !credential_precedes_policy(&image, &saved, &history))
        {
            return Err(DurableError::Conflict);
        }
        let completed = if let Some(previous) = &saved.policy_renewal {
            if !completion_acknowledged(&image, previous)? {
                return Err(DurableError::Suspended);
            }
            Some(previous.receipt())
        } else {
            None
        };
        let target = LocalPolicyRenewalTarget {
            approval: &history,
            original: materials.original_device,
            current: materials.current_device,
            original_policy: materials.original,
        };
        target.check_identity_scope(&image, &saved)?;
        target.check_predecessor(&image, &saved, completed.as_ref())?;
        self.check_release(&image).await?;
        crate::installation::admit(materials.current_device, materials.target, now)?;
        saved
            .roster
            .authorize_device(materials.current_device, now)?;
        let carried_grant = saved
            .renewals
            .get(&materials.original_device.device_id())
            .map(|g| crate::VerifiedCredentialRenewal::from_journal(g.as_bytes(), &saved.roster))
            .transpose()?;
        saved.policy_renewal = Some(StoredPolicyRenewal {
            approval: history,
            phase: ReceiptPhase::AwaitingEnrollment,
            carried_grant,
        });
        image
            .records
            .insert(id(&image.local_account), saved.record()?);
        let sealed = self.seal_next_image(&mut image)?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let proposal = write_intent::reserve_policy_renewal(
            active,
            &image,
            &sealed,
            write_intent::PolicyRenewalBinding {
                operation: verified.scope().operation,
                statement: verified.statement_digest(),
            },
        )?;
        crate::installation::admit(materials.current_device, materials.target, now)?;
        Ok(proposal)
    }
}

pub(in crate::durable) fn check_witnessed_policy_terminal(
    image: &Image,
    original: &VerifiedDevice,
    terminal: &crate::enrollment::PersistedPolicyTerminal,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    check_scope(image, &saved)?;
    let approval = terminal.approval();
    let scope = approval.scope();
    if !matches!(image.protection, Protection::Required { policy, .. } if policy==scope.original_policy.digest())
        || terminal.proposal().operation() != scope.operation
        || terminal.proposal().statement() != approval.statement_digest()
        || scope.journal.as_bytes() != &image.id
        || scope.original_owner != image.owner
        || (saved.local_commit.is_some() && !credential_precedes_policy(image, &saved, approval))
        || saved.policy_continuation.is_some()
        || saved.roster.checkpoint() != scope.current_roster
        || saved.history.get(&original.device_id())
            != Some(&(original.generation(), scope.current_credential))
    {
        return Err(DurableError::Conflict);
    }
    match terminal.disposition() {
        crate::WitnessedPolicyRenewalDisposition::Applied => {
            let actual = saved
                .policy_renewal
                .as_ref()
                .ok_or(DurableError::Conflict)?;
            if actual.phase != ReceiptPhase::AwaitingEnrollment
                || actual.approval.journal_bytes() != approval.journal_bytes()
            {
                return Err(DurableError::Conflict);
            }
        }
        crate::WitnessedPolicyRenewalDisposition::Closed => {
            match (&saved.policy_renewal, terminal.previous()) {
                (None, None)
                    if scope.previous_authorization.is_none()
                        && scope.previous_policy == scope.original_policy => {}
                (Some(actual), Some(previous))
                    if actual.approval.journal_bytes() == previous.journal_bytes()
                        && scope.previous_authorization == Some(previous.statement_digest())
                        && scope.previous_policy == previous.target_policy() =>
                {
                    let completion = terminal
                        .previous_completion()
                        .ok_or(DurableError::Suspended)?;
                    check_enrollment_policy_completion(image, completion)?;
                }
                _ => return Err(DurableError::Conflict),
            }
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "policy_renewal_tests.rs"]
mod tests;

// The original enrollment may inspect an authenticated source/target pair without
// replaying it. This projection grants neither current authority nor a live lease.
pub(in crate::durable) fn inspect_renewal_snapshot(
    image: &Image,
    scope: &crate::installation::PolicyScope<'_>,
    current: &VerifiedDevice,
    completed: Option<&HistoricalPolicyRenewal>,
    joint: Option<&crate::HistoricalPolicyContinuation>,
    roster_binding: RequestRoster,
    witnessed_completion: Option<&LocalRenewalCommit>,
) -> Result<RenewalRequestSnapshot, DurableError> {
    image.protection.check_policy(scope.original_policy)?;
    let required = match image.protection {
        Protection::Local => None,
        Protection::Required {
            policy, witness, ..
        } => Some((policy, witness)),
    };
    scope.authority.check(image.owner, required)?;
    let original = scope.original_device;
    if scope.local_identity().0 != image.local_account
        || scope.authority.policy != scope.original_policy.checkpoint().digest()
        || (current.account_id(), current.device_id()) != scope.local_identity()
    {
        return Err(DurableError::Conflict);
    }
    let saved = get(image, &image.local_account)?;
    // A required G keeps its exact original receipt after ACK. Only the
    // original enrollment may supply this authenticated prior completion; a new
    // staged approval is not completion. Local unacknowledged receipts stay refused.
    if let Some(retained) = &saved.local_commit {
        if required.is_none() || witnessed_completion != Some(retained) {
            return Err(DurableError::Suspended);
        }
    } else if witnessed_completion.is_some() {
        return Err(DurableError::Conflict);
    }
    // Never guess a credential from a newer journal. G may use the actual
    // newer roster containing the same credential even after C expires;
    // requiring a live-C roster refresh first would prevent that renewal.
    // Policy-only preparation separately keeps its exact enrollment-R fence.
    let head = saved.roster.checkpoint();
    let configured = current.roster().checkpoint();
    if (matches!(roster_binding, RequestRoster::Configured) && head != configured)
        || head.version() < configured.version()
        || (head.version() == configured.version() && head != configured)
        || !saved.roster.same_authority(current.roster())
        || saved.history.get(&current.device_id())
            != Some(&(current.generation(), current.credential_digest()))
        || !saved.roster.contains_member(
            current.device_id(),
            current.generation(),
            current.credential_digest(),
        )
    {
        return Err(DurableError::Conflict);
    }
    let historical = current
        .description
        .validity
        .from()
        .max(saved.roster.validity().from());
    let actual_device = saved.roster.refresh_device(current, historical)?;
    if let Some(grant) = saved.renewals.get(&original.device_id()) {
        let resolved = grant.resolve_established(original, scope.authority.policy)?;
        if resolved.device.credential_digest() != current.credential_digest()
            || resolved.owner != image.owner
            || grant.original_credential_digest() != original.credential_digest()
        {
            return Err(DurableError::Conflict);
        }
    } else if current.credential_digest() != original.credential_digest() {
        return Err(DurableError::Conflict);
    }
    let (previous_policy, previous_authorization) = match &saved.policy_renewal {
        Some(retained) => {
            if completed.is_none_or(|expected| {
                expected.journal_bytes() != retained.approval.journal_bytes()
            }) {
                return Err(DurableError::Conflict);
            }
            let approval = adopted(image, &saved)?;
            if credential(image, &saved, original, approval)?.credential_digest()
                != current.credential_digest()
            {
                return Err(DurableError::Conflict);
            }
            if approval.scope().original_policy != scope.original_policy.checkpoint() {
                return Err(DurableError::Conflict);
            }
            (approval.target_policy(), Some(approval.statement_digest()))
        }
        None => {
            if completed.is_some() {
                return Err(DurableError::Conflict);
            }
            match (&saved.policy_continuation, joint) {
                (None, None) => (scope.original_policy.checkpoint(), None),
                (Some(actual), Some(expected))
                    if actual.journal_bytes() == expected.journal_bytes()
                        && actual.scope().original_policy == scope.original_policy.checkpoint()
                        && actual.scope().original_credential == original.credential_digest() =>
                {
                    (actual.target_policy(), Some(actual.statement_digest()))
                }
                _ => return Err(DurableError::Conflict),
            }
        }
    };
    Ok(RenewalRequestSnapshot {
        journal: crate::JournalIdentity::from_trusted_state(image.id)?,
        original_owner: image.owner,
        original_credential: original.credential_digest(),
        current_credential: current.credential_digest(),
        current_roster: saved.roster.checkpoint(),
        current_device: actual_device,
        original_policy: scope.original_policy.checkpoint(),
        current_policy: previous_policy,
        current_policy_authorization: previous_authorization,
    })
}
