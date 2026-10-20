// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure account-record transitions, before any image sealing or durable commit.
use super::*;

impl Stored {
    pub(super) fn advance(self, roster: &VerifiedRoster) -> Result<Self, DurableError> {
        self.advance_with_renewals(roster, &[])
    }
    pub(super) fn advance_with_renewal(
        self,
        roster: &VerifiedRoster,
        renewal: Option<&VerifiedCredentialRenewal>,
    ) -> Result<Self, DurableError> {
        match renewal {
            Some(grant) => self.advance_with_renewals(roster, &[grant]),
            None => self.advance(roster),
        }
    }

    /// Validate the complete common-predecessor/target/original-policy grant set before
    /// returning one account image. No journal is written and no owner released.
    /// Operational callers must still bind their exact local intent, check the
    /// required current policy/time admission, and coordinate the original witness.
    /// Existing public entrypoints continue supplying at most one grant.
    pub(super) fn advance_with_renewals(
        self,
        roster: &VerifiedRoster,
        grants: &[&VerifiedCredentialRenewal],
    ) -> Result<Self, DurableError> {
        self.require_live_account()?;
        if grants.len() > MAX_DEVICE_HISTORY {
            return Err(DurableError::Capacity);
        }
        if !self.roster.same_authority(roster)
            || roster.checkpoint().version() <= self.roster.checkpoint().version()
        {
            return Err(DurableError::Conflict);
        }
        let policy = grants.first().map(|grant| grant.policy_digest());
        let mut selected = BTreeMap::new();
        for grant in grants {
            let previous = grant.previous_device();
            let next = grant.successor_device();
            if Some(grant.policy_digest()) != policy
                || selected.insert(next.device_id(), *grant).is_some()
                || self.roster.checkpoint() != previous.roster().checkpoint()
                || roster.checkpoint() != next.roster().checkpoint()
                || !self.roster.contains_member(
                    previous.device_id(),
                    previous.generation(),
                    previous.credential_digest(),
                )
                || self.history.get(&previous.device_id())
                    != Some(&(previous.generation(), previous.credential_digest()))
            {
                return Err(DurableError::Conflict);
            }
            if let Some(retained) = self.renewals.get(&next.device_id()) {
                if retained.original_credential_digest() != grant.original_credential_digest()
                    || retained.policy_digest() != grant.policy_digest()
                {
                    return Err(DurableError::Conflict);
                }
            }
        }
        let mut history = self.history;
        for (id, generation, certificate) in roster.members() {
            if let Some((floor, original)) = history.get(&id) {
                let permitted = selected.get(&id).is_some_and(|grant| {
                    let previous = grant.previous_device();
                    let next = grant.successor_device();
                    generation == next.generation()
                        && generation == *floor
                        && certificate == next.credential_digest()
                        && *original == previous.credential_digest()
                        && self.roster.contains_member(id, generation, *original)
                });
                if generation < *floor
                    || (generation == *floor
                        && (*original != certificate
                            || !self.roster.contains_member(id, generation, certificate))
                        && !permitted)
                {
                    return Err(Error::Checkpoint.into());
                }
            } else if history.len() >= MAX_DEVICE_HISTORY {
                return Err(DurableError::Capacity);
            }
            history.insert(id, (generation, certificate));
        }
        let mut renewals = self.renewals;
        renewals.retain(|id, grant| {
            let next = grant.successor_device();
            history.get(id) == Some(&(next.generation(), next.credential_digest()))
        });
        for (id, grant) in selected {
            renewals.insert(
                id,
                VerifiedCredentialRenewal::from_journal(grant.as_bytes(), roster)?,
            );
        }
        Ok(Self {
            roster: roster.clone(),
            history,
            renewals,
            local_commit: self.local_commit,
            account_commit: self.account_commit,
            policy_continuation: self.policy_continuation,
            policy_renewal: self.policy_renewal,
            peer_retirement: None,
        })
    }
}
