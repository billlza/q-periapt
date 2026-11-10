// SPDX-License-Identifier: Apache-2.0 OR MIT
//! R resolves the exact already-adopted local G, never a caller-selected credential.
use super::*;

pub(super) fn grant<'a>(
    image: &Image,
    saved: &'a Stored,
) -> Result<Option<&'a VerifiedCredentialRenewal>, DurableError> {
    let mut grants = saved
        .renewals
        .values()
        .filter(|g| g.original_storage_owner() == image.owner);
    let grant = grants.next();
    if grants.next().is_some() {
        return Err(DurableError::Conflict);
    }
    match (grant, &saved.local_commit) {
        (None, None) if saved.policy_continuation.is_none() => Ok(None),
        (Some(g), Some(commit)) => {
            let Protection::Required { policy, .. } = image.protection else {
                return Err(DurableError::AnchorRequired);
            };
            if g.policy_digest() != policy
                || g.successor_device().account_id() != image.local_account
            {
                return Err(DurableError::Conflict);
            }
            if saved.policy_continuation.is_some() {
                check_continuation_completion(image, saved)?;
            } else if !commit.matches_credential_grant(g) {
                return Err(DurableError::Conflict);
            }
            Ok(Some(g))
        }
        _ => Err(DurableError::Conflict),
    }
}
fn authority_for(
    saved: &Stored,
    grant: bool,
) -> Result<write_intent::RosterAuthority, DurableError> {
    use write_intent::RosterAuthority;
    match (grant, saved.policy_continuation.is_some()) {
        (false, false) => Ok(RosterAuthority::Original),
        (true, false) => Ok(RosterAuthority::Credential),
        (true, true) => Ok(RosterAuthority::Continued),
        (false, true) => Err(DurableError::Conflict),
    }
}
pub(super) fn authority(
    image: &Image,
    saved: &Stored,
) -> Result<write_intent::RosterAuthority, DurableError> {
    authority_for(saved, grant(image, saved)?.is_some())
}
pub(super) fn check_scope(
    image: &Image,
    saved: &Stored,
    scope: RosterRefreshScope,
    bound: write_intent::RosterAuthority,
) -> Result<(), DurableError> {
    let grant = grant(image, saved)?;
    if bound != authority_for(saved, grant.is_some())? {
        return Err(DurableError::Conflict);
    }
    if let Some(g) = grant {
        let checkpoint = g.successor_device().roster().checkpoint();
        if checkpoint.version() > scope.previous.version()
            || (checkpoint.version() == scope.previous.version() && checkpoint != scope.previous)
        {
            return Err(DurableError::Conflict);
        }
    }
    Ok(())
}
pub(super) fn current(
    image: &Image,
    saved: &Stored,
    original: &VerifiedDevice,
) -> Result<VerifiedDevice, DurableError> {
    let Protection::Required { policy, .. } = image.protection else {
        return Err(DurableError::AnchorRequired);
    };
    let resolved = grant(image, saved)?
        .map(|g| g.resolve_established(original, policy))
        .transpose()?;
    if resolved.as_ref().is_some_and(|r| r.owner != image.owner) {
        return Err(DurableError::Conflict);
    }
    let device = resolved.as_ref().map_or(original, |r| r.device.as_ref());
    if saved.history.get(&device.device_id())
        != Some(&(device.generation(), device.credential_digest()))
    {
        return Err(DurableError::Conflict);
    }
    let at = device
        .description
        .validity
        .from()
        .max(saved.roster.validity().from());
    Ok(saved.roster.refresh_device(device, at)?)
}
