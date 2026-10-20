// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Seal the real original journal's same-credential roster target exactly once.
use super::*;
use crate::{
    AnchorRosterRefreshProposal, HistoricalSessionPolicy, RosterRefreshId, RosterRefreshScope,
    VerifiedSessionPolicy,
};
mod credential;
pub(in crate::durable) fn roster_refresh_authority(
    image: &Image,
) -> Result<write_intent::RosterAuthority, DurableError> {
    let saved = get(image, &image.local_account)?;
    credential::authority(image, &saved)
}

/// Independently retained original identity/policy and root-approved current R target.
/// These inputs do not supply a witness outcome or original enrollment completion.
pub struct RosterRefreshMaterials<'a> {
    /// Original immutable credential owner; historical roster time is permitted.
    pub original: &'a VerifiedDevice,
    /// Original P0 authenticates journal protection and immutable subject.
    pub original_policy: &'a HistoricalSessionPolicy,
    /// Independently pinned current policy and live runtime for preparing new work.
    pub policy: &'a VerifiedSessionPolicy,
    /// Same current credential under the independently pinned target roster.
    pub target: &'a VerifiedDevice,
}
fn supported(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    if !matches!(image.protection, Protection::Required { .. }) {
        return Err(DurableError::AnchorRequired);
    }
    credential::grant(image, saved)?;
    policy_renewal::check_scope(image, saved)
}
pub(in crate::durable) fn check_roster_refresh_intent(
    image: &Image,
    scope: RosterRefreshScope,
    authority: write_intent::RosterAuthority,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    supported(image, &saved)?;
    credential::check_scope(image, &saved, scope, authority)?;
    if saved.roster.checkpoint() != scope.target
        || scope.target.version() <= scope.previous.version()
    {
        return Err(DurableError::Conflict);
    }
    match (
        &saved.policy_renewal,
        &saved.policy_continuation,
        scope.policy_authorization,
    ) {
        (None, None, None) => match image.protection {
            Protection::Required { policy, .. } if policy == scope.policy.digest() => {}
            _ => return Err(DurableError::Conflict),
        },
        (Some(p), None, Some(statement)) if p.policy_binding() == (scope.policy, statement) => {}
        (None, Some(t), Some(statement))
            if t.target_policy() == scope.policy && t.statement_digest() == statement => {}
        _ => return Err(DurableError::Conflict),
    }
    Ok(())
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    /// Reserve the exact sealed same-credential roster/head target in this
    /// original journal. This neither prepares nor commits the witness and
    /// releases no operational owner. The journal closes on success or error;
    /// inspect the original preparation after any uncertain return before retrying.
    pub async fn prepare_roster_refresh(
        &mut self,
        operation: RosterRefreshId,
        materials: &RosterRefreshMaterials<'_>,
        now: u64,
    ) -> Result<AnchorRosterRefreshProposal, DurableError> {
        let result = self
            .prepare_roster_refresh_attempt(operation, materials, now, None, None)
            .await;
        self.close();
        result
    }
    pub(crate) async fn prepare_enrolled_roster_refresh(
        &mut self,
        operation: RosterRefreshId,
        materials: &RosterRefreshMaterials<'_>,
        now: u64,
        completion: Option<&LocalRenewalCommit>,
        continuation: Option<&crate::HistoricalPolicyContinuation>,
    ) -> Result<AnchorRosterRefreshProposal, DurableError> {
        let result = self
            .prepare_roster_refresh_attempt(operation, materials, now, completion, continuation)
            .await;
        self.close();
        result
    }
    async fn prepare_roster_refresh_attempt(
        &mut self,
        operation: RosterRefreshId,
        materials: &RosterRefreshMaterials<'_>,
        now: u64,
        completion: Option<&LocalRenewalCommit>,
        continuation: Option<&crate::HistoricalPolicyContinuation>,
    ) -> Result<AnchorRosterRefreshProposal, DurableError> {
        let m = materials;
        let mut image = self.image().await?;
        image.protection.check_policy(m.original_policy)?;
        let saved = get(&image, &image.local_account)?;
        supported(&image, &saved)?;
        if saved.local_commit.as_ref() != completion {
            return Err(DurableError::Suspended);
        }
        if saved
            .policy_continuation
            .as_ref()
            .map(|t| t.journal_bytes())
            != continuation.map(|t| t.journal_bytes())
        {
            return Err(DurableError::Conflict);
        }
        let current = credential::current(&image, &saved, m.original)?;
        if image.owner != bootstrap::storage_owner(m.original)
            || image.local_account != m.original.account_id()
            || m.target.credential_digest() != current.credential_digest()
            || m.target.key != m.original.key
            || !saved.roster.same_authority(m.target.roster())
        {
            return Err(DurableError::Conflict);
        }
        let policy_authorization = if saved.policy_renewal.is_some() {
            let approval = policy_renewal::adopted(&image, &saved)?;
            approval.check_context_policy(m.original_policy, m.policy)?;
            if policy_renewal::credential(&image, &saved, m.original, approval)?.credential_digest()
                != current.credential_digest()
            {
                return Err(DurableError::Conflict);
            }
            Some(approval.statement_digest())
        } else if let Some(t) = &saved.policy_continuation {
            t.check_context_policy(m.original_policy, m.policy)?;
            Some(t.statement_digest())
        } else {
            if m.original_policy.checkpoint() != m.policy.checkpoint() {
                return Err(DurableError::Conflict);
            }
            None
        };
        crate::installation::admit(m.target, m.policy, now)?;
        let scope = RosterRefreshScope {
            operation,
            previous: saved.roster.checkpoint(),
            target: m.target.roster().checkpoint(),
            policy: m.policy.checkpoint(),
            policy_authorization,
        };
        if scope.target.version() <= scope.previous.version() {
            return Err(Error::Checkpoint.into());
        }
        self.check_release(&image).await?;
        let updated = saved.advance(m.target.roster())?;
        image
            .records
            .insert(id(&image.local_account), updated.record()?);
        let sealed = self.seal_next_image(&mut image)?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let proposal = write_intent::reserve_roster_refresh(active, &image, &sealed, scope)?;
        crate::installation::admit(m.target, m.policy, now)?;
        Ok(proposal)
    }
}

#[cfg(all(test, unix))]
impl DeviceJournal {
    pub(crate) fn assert_roster_target_preserves_assets(
        key: &JournalKey,
        original: &VerifiedDevice,
        before: &[u8],
        target: &[u8],
        scope: &RosterRefreshScope,
    ) -> usize {
        let owner = bootstrap::storage_owner(original);
        let before = unseal(key, owner, before).expect("authenticated original image");
        let after = unseal(key, owner, target).expect("authenticated sealed roster target");
        assert_eq!(
            (
                before.id,
                before.owner,
                before.local_account,
                before.protection,
                before.next_fanout
            ),
            (
                after.id,
                after.owner,
                after.local_account,
                after.protection,
                after.next_fanout
            )
        );
        assert_eq!(after.revision, before.revision + 1);
        assert!(
            before.records.keys().eq(after.records.keys()),
            "record identities changed"
        );
        let old = get(&before, &before.local_account).expect("original roster");
        let new = get(&after, &after.local_account).expect("target roster");
        assert_eq!(
            old.local_commit, new.local_commit,
            "original G completion changed"
        );
        assert!(
            old.renewals
                .iter()
                .map(|(id, g)| (id, g.as_bytes()))
                .eq(new.renewals.iter().map(|(id, g)| (id, g.as_bytes()))),
            "original grants changed"
        );
        assert_eq!(old.roster.checkpoint(), scope.previous);
        assert_eq!(new.roster.checkpoint(), scope.target);
        assert_eq!(
            old.policy_continuation.as_ref().map(|t| t.journal_bytes()),
            new.policy_continuation.as_ref().map(|t| t.journal_bytes()),
            "original T changed"
        );
        assert!(
            old.policy_renewal
                .as_ref()
                .map(StoredPolicyRenewal::approval_bytes)
                == new
                    .policy_renewal
                    .as_ref()
                    .map(StoredPolicyRenewal::approval_bytes),
            "independent P approval changed"
        );
        let mut count = 0;
        for (key, record) in &before.records {
            let target = after.records.get(key).expect("retained record");
            if *key != id(&before.local_account) {
                assert!(record == target, "non-roster record changed");
                count += 1;
            }
        }
        count
    }
}

pub(in crate::durable) fn check_witnessed_roster_terminal(
    image: &Image,
    original: &VerifiedDevice,
    terminal: &crate::enrollment::PersistedRosterTerminal,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    supported(image, &saved)?;
    if saved.local_commit.as_ref() != terminal.credential_completion() {
        return Err(DurableError::Conflict);
    }
    let scope = terminal.proposal().scope().to_owned();
    let checkpoint = match terminal.disposition() {
        crate::WitnessedRosterRefreshDisposition::Applied => scope.target,
        crate::WitnessedRosterRefreshDisposition::Closed => scope.previous,
    };
    if saved.roster.checkpoint() != checkpoint || image.owner != bootstrap::storage_owner(original)
    {
        return Err(DurableError::Conflict);
    }
    credential::current(image, &saved, original)?;
    match (
        &saved.policy_renewal,
        &saved.policy_continuation,
        scope.policy_authorization,
        terminal.completion(),
        terminal.continuation(),
    ) {
        (None, None, None, None, None) => match image.protection {
            Protection::Required { policy, .. } if policy == scope.policy.digest() => {}
            _ => return Err(DurableError::Conflict),
        },
        (Some(p), None, Some(statement), Some(completion), None)
            if p.policy_binding() == (scope.policy, statement) =>
        {
            policy_renewal::check_enrollment_policy_completion(image, completion)?;
        }
        (None, Some(t), Some(statement), None, Some(completion))
            if t.target_policy() == scope.policy
                && t.statement_digest() == statement
                && t.journal_bytes() == completion.journal_bytes() =>
        {
            check_continuation_completion(image, &saved)?;
        }
        _ => return Err(DurableError::Conflict),
    }
    Ok(())
}
