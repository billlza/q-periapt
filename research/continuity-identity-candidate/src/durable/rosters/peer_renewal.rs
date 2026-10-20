// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One peer account transition with every changed credential explicitly authorized.
use super::*;

fn complete_collection(
    primary: &VerifiedCredentialRenewal,
    companions: &[&VerifiedCredentialRenewal],
) -> Result<(), DurableError> {
    // Reuse exact predecessor/target/policy and unique-device validation.
    let _ = primary.companion_binding(companions)?;
    if companions.is_empty() {
        // Preserve the existing single-grant exact readback contract. Advancing
        // a head still requires Stored::advance_with_renewals to admit every change.
        return Ok(());
    }
    let previous = primary.previous_device().roster();
    for (id, generation, certificate) in primary.successor_device().roster().members() {
        if let Some((_, old_generation, old_certificate)) =
            previous.members().find(|(old, _, _)| *old == id)
        {
            let authorized = std::iter::once(primary)
                .chain(companions.iter().copied())
                .any(|g| {
                    g.successor_device().device_id() == id
                        && g.previous_device().credential_digest() == old_certificate
                        && g.successor_device().credential_digest() == certificate
                });
            if generation < old_generation
                || (generation == old_generation && certificate != old_certificate && !authorized)
            {
                return Err(Error::Checkpoint.into());
            }
        }
    }
    Ok(())
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl DeviceJournal {
    pub(crate) async fn install_peer_credential_renewal(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        renewal: &VerifiedCredentialRenewal,
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        self.install_peer_account_credential_renewal(scope, renewal, &[], operation, policy, now)
            .await
    }

    pub(crate) async fn install_peer_account_credential_renewal(
        &mut self,
        scope: &crate::installation::PolicyScope<'_>,
        primary: &VerifiedCredentialRenewal,
        companions: &[&VerifiedCredentialRenewal],
        operation: CredentialRenewalId,
        policy: &crate::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<RosterCheckpoint, DurableError> {
        self.check_policy(scope.original_policy)?;
        if operation != primary.operation() {
            return Err(DurableError::Conflict);
        }
        complete_collection(primary, companions)?;
        let grants: Vec<_> = std::iter::once(primary)
            .chain(companions.iter().copied())
            .collect();
        for grant in &grants {
            let successor = grant.successor_device();
            if grant.policy_digest() != scope.authority.policy
                || (successor.account_id(), successor.device_id()) == scope.local_identity()
            {
                return Err(DurableError::Conflict);
            }
            crate::installation::admit(successor, policy, now)?;
        }
        let mut image = self.image().await?;
        peer_roster::authorize(&image, scope, policy, now)?;
        let successor = primary.successor_device();
        image.check_account_authorities(&[successor.account_id()])?;
        let saved = get(&image, &successor.account_id())?;
        saved.require_live_account()?;
        let target = successor.roster().checkpoint();
        let updated = if saved.roster.checkpoint() == target {
            for grant in &grants {
                let device = grant.successor_device();
                let retained = saved
                    .renewals
                    .get(&device.device_id())
                    .ok_or(DurableError::Conflict)?;
                if retained.operation() != grant.operation()
                    || retained.statement_digest() != grant.statement_digest()
                    || saved.history.get(&device.device_id())
                        != Some(&(device.generation(), device.credential_digest()))
                {
                    return Err(DurableError::Conflict);
                }
                saved.roster.authorize_device(device, now)?;
            }
            None
        } else {
            Some(if companions.is_empty() {
                saved.advance_with_renewal(successor.roster(), Some(primary))?
            } else {
                saved.advance_with_renewals(successor.roster(), &grants)?
            })
        };
        self.check_operational_release(&image, policy, now).await?;
        peer_roster::authorize(&image, scope, policy, now)?;
        if let Some(updated) = updated {
            image.check_account_authorities(&[successor.account_id()])?;
            image
                .records
                .insert(id(&successor.account_id()), updated.record()?);
            // Same-account peer changes can revoke the local member. Persist
            // that observed authority, then deny release without undoing it.
            self.persist(&mut image).await?;
            peer_roster::authorize(&image, scope, policy, now)?;
            for grant in &grants {
                crate::installation::admit(grant.successor_device(), policy, now)?;
            }
            self.check_operational_release(&image, policy, now).await?;
            peer_roster::authorize(&image, scope, policy, now)?;
        }
        image.check_account_authorities(&[successor.account_id()])?;
        Ok(target)
    }
}
