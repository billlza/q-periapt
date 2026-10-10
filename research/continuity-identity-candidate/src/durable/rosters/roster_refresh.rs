// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Seal the real original journal's same-credential roster target exactly once.
use super::*;
use crate::{
    AnchorRosterRefreshProposal, HistoricalSessionPolicy, RosterRefreshId, RosterRefreshScope,
    VerifiedSessionPolicy,
};

/// Independently retained original identity/policy and root-approved current R target.
/// These inputs do not supply a witness outcome or original enrollment completion.
pub struct RosterRefreshMaterials<'a> {
    /// Original immutable credential owner; historical roster time is permitted.
    pub original: &'a VerifiedDevice,
    /// Original P0 authenticates journal protection and immutable subject.
    pub original_policy: &'a HistoricalSessionPolicy,
    /// Independently pinned current policy and live runtime for preparing new work.
    pub policy: &'a VerifiedSessionPolicy,
    /// Same immutable credential under the independently pinned target roster.
    pub target: &'a VerifiedDevice,
}
fn supported(image: &Image, saved: &Stored) -> Result<(), DurableError> {
    if !matches!(image.protection, Protection::Required { .. }) {
        return Err(DurableError::AnchorRequired);
    }
    if saved.local_commit.is_some()
        || saved.policy_continuation.is_some()
        || saved
            .renewals
            .values()
            .any(|g| g.original_storage_owner() == image.owner)
    {
        return Err(DurableError::Conflict);
    }
    policy_renewal::check_scope(image, saved)
}
pub(in crate::durable) fn check_roster_refresh_intent(
    image: &Image,
    scope: RosterRefreshScope,
) -> Result<(), DurableError> {
    let saved = get(image, &image.local_account)?;
    supported(image, &saved)?;
    if saved.roster.checkpoint() != scope.target
        || scope.target.version() <= scope.previous.version()
    {
        return Err(DurableError::Conflict);
    }
    match (&saved.policy_renewal, scope.policy_authorization) {
        (None, None) => match image.protection {
            Protection::Required { policy, .. } if policy == scope.policy.digest() => {}
            _ => return Err(DurableError::Conflict),
        },
        (Some(p), Some(statement)) if p.policy_binding() == (scope.policy, statement) => {}
        _ => return Err(DurableError::Conflict),
    }
    Ok(())
}
impl DeviceJournal {
    /// Reserve the exact sealed same-credential roster/head target in this
    /// original journal. This neither prepares nor commits the witness and
    /// releases no operational owner. The journal closes on success or error;
    /// inspect the original preparation after any uncertain return before retrying.
    pub fn prepare_roster_refresh(
        &mut self,
        operation: RosterRefreshId,
        materials: &RosterRefreshMaterials<'_>,
        now: u64,
    ) -> Result<AnchorRosterRefreshProposal, DurableError> {
        let result = (|| {
            let m = materials;
            let mut image = self.image()?;
            image.protection.check_policy(m.original_policy)?;
            let saved = get(&image, &image.local_account)?;
            supported(&image, &saved)?;
            if image.owner != bootstrap::storage_owner(m.original)
                || image.owner != bootstrap::storage_owner(m.target)
                || image.local_account != m.original.account_id()
                || m.target.credential_digest() != m.original.credential_digest()
                || m.target.key != m.original.key
                || !saved.roster.same_authority(m.target.roster())
                || saved.history.get(&m.original.device_id())
                    != Some(&(m.original.generation(), m.original.credential_digest()))
            {
                return Err(DurableError::Conflict);
            }
            let historical = m
                .original
                .description
                .validity
                .from()
                .max(saved.roster.validity().from());
            saved.roster.refresh_device(m.original, historical)?;
            let policy_authorization = if saved.policy_renewal.is_some() {
                let approval = policy_renewal::adopted(&image, &saved)?;
                approval.check_context_policy(m.original_policy, m.policy)?;
                approval.check_credential_lineage(m.original, m.original)?;
                Some(approval.statement_digest())
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
            self.check_release(&image)?;
            let updated = saved.advance(m.target.roster())?;
            image
                .records
                .insert(id(&image.local_account), updated.record()?);
            let sealed = self.seal_next_image(&mut image)?;
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let proposal = write_intent::reserve_roster_refresh(active, &image, &sealed, scope)?;
            crate::installation::admit(m.target, m.policy, now)?;
            Ok(proposal)
        })();
        self.close();
        result
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
        assert_eq!(old.roster.checkpoint(), scope.previous);
        assert_eq!(new.roster.checkpoint(), scope.target);
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
    let scope = terminal.proposal().scope().to_owned();
    let checkpoint = match terminal.disposition() {
        crate::WitnessedRosterRefreshDisposition::Applied => scope.target,
        crate::WitnessedRosterRefreshDisposition::Closed => scope.previous,
    };
    if saved.roster.checkpoint() != checkpoint
        || image.owner != bootstrap::storage_owner(original)
        || saved.history.get(&original.device_id())
            != Some(&(original.generation(), original.credential_digest()))
    {
        return Err(DurableError::Conflict);
    }
    let at = original
        .description
        .validity
        .from()
        .max(saved.roster.validity().from());
    saved.roster.refresh_device(original, at)?;
    match (
        &saved.policy_renewal,
        scope.policy_authorization,
        terminal.completion(),
    ) {
        (None, None, None) => match image.protection {
            Protection::Required { policy, .. } if policy == scope.policy.digest() => {}
            _ => return Err(DurableError::Conflict),
        },
        (Some(p), Some(statement), Some(completion))
            if p.policy_binding() == (scope.policy, statement) =>
        {
            policy_renewal::check_enrollment_policy_completion(image, completion)?;
        }
        _ => return Err(DurableError::Conflict),
    }
    Ok(())
}
