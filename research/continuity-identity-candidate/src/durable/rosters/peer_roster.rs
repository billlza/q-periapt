// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Known remote-account heads admitted through an original current device owner.
use super::*;

fn authorize(
    image: &Image,
    scope: &crate::installation::PolicyScope<'_>,
    policy: &crate::VerifiedSessionPolicy,
    now: u64,
) -> Result<(), DurableError> {
    authorize_peer_installation(image, scope, policy, now)?;
    let saved = get(image, &image.local_account)?;
    if saved.policy_continuation.is_none() && saved.policy_renewal.is_none() {
        let resolved = saved
            .renewals
            .get(&scope.local_identity().1)
            .map(|grant| grant.resolve_established(scope.original_device, scope.authority.policy))
            .transpose()?;
        let current = match &resolved {
            Some(resolved) => {
                if resolved.owner != image.owner {
                    return Err(DurableError::Conflict);
                }
                resolved.device.as_ref()
            }
            None => scope.original_device,
        };
        let current = saved.roster.refresh_device(current, now)?;
        crate::installation::admit(&current, policy, now)?;
    }
    Ok(())
}

impl DeviceJournal {
    pub(crate) fn install_peer_roster(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        roster: &VerifiedRoster,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        self.check_policy(scope.original_policy)?;
        if roster.account_id() == scope.local_identity().0
            || roster.continuation_authority().1 != policy.family()
        {
            return Err(DurableError::Conflict);
        }
        roster.check_time(now)?;
        let mut image = self.image()?;
        authorize(&image, scope, policy, now)?;
        // Initial peer trust is admitted only by the original bootstrap. An
        // update cannot introduce a new account or replace an existing root.
        let saved = get(&image, &roster.account_id())?;
        if !saved.roster.same_authority(roster) {
            return Err(DurableError::Conflict);
        }
        let target = roster.checkpoint();
        let previous = saved.roster.checkpoint();
        if target.version() < previous.version()
            || (target.version() == previous.version() && target != previous)
        {
            return Err(Error::Checkpoint.into());
        }
        let unchanged = previous == target;
        let updated = if unchanged {
            None
        } else {
            Some(saved.advance(roster)?)
        };
        self.check_operational_release(&image, policy, now)?;
        // A runtime may close during witness I/O. Do not commit or return a
        // cached success after losing the exact local/current-policy authority.
        authorize(&image, scope, policy, now)?;
        if let Some(updated) = updated {
            image
                .records
                .insert(id(&roster.account_id()), updated.record()?);
            self.persist(&mut image)?;
            self.check_operational_release(&image, policy, now)?;
            authorize(&image, scope, policy, now)?;
        }
        Ok(target)
    }
}
