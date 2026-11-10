// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real account authentication, fresh SDK enrollment and atomic roster changes.
use super::{
    extension::{extension, issued},
    *,
};
use crate::enrollment::DeviceReplacementRequest;
mod crash;
mod historical;

fn schema6(store: &mut Store) -> Result {
    store.enable_enrollment([42; 32])?;
    store.enable_enrollment_reapproval()?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    store.enable_policy_approvals()?;
    Ok(())
}
fn input(
    host: &mut Service,
    token: &str,
    invitation: &Invitation,
) -> Result<DeviceReplacementRequest> {
    Ok(DeviceReplacementRequest {
        request_id: crate::enrollment::random()?,
        enrollment: invitation.operation,
        predecessor: host
            .enrollment_root(token)?
            .roster
            .ok_or("roster")?
            .checkpoint,
    })
}
fn replacement(
    host: &mut Service,
    path: &Path,
    token: &str,
    input: &DeviceReplacementRequest,
) -> Result<(Invitation, Vec<u8>, Vec<u8>)> {
    let invitation = host.invite_device_replacement(token, input)?;
    let (_, proof) = request(path, &invitation)?;
    host.approve_enrollment(token, invitation.operation, &proof)?;
    let response = host.issue_enrollment(token, invitation.operation)?;
    Ok((invitation, proof, response))
}

#[test]
fn replacement_explicit_upgrade_and_reopen_preserve_history_and_other_members() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema6(&mut host.store)?;
    host.prepare_enrollment_root(&token)?;
    let (old, old_proof, old_response) = issued(&mut host, &path, &token)?;
    let (other, _, other_response) = issued(&mut host, &path, &token)?;
    let extension_input = extension(&mut host, &token, &other)?;
    let extension_response = host.extend_enrollment_credential(&token, &extension_input)?;
    let extended: crate::enrollment::IssuedCredentialExtension =
        serde_json::from_slice(&extension_response)?;
    let before = host.enrollment_root(&token)?;
    let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
    let replace = input(&mut host, &token, &old)?;
    assert!(host.invite_device_replacement(&token, &replace).is_err());
    host.store.enable_device_replacements()?;
    host.store.enable_device_replacements()?;
    assert_eq!(host.enrollment_root(&token)?, before);
    assert_eq!(
        serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
        account
    );
    let invitation = host.invite_device_replacement(&token, &replace)?;
    assert_eq!(invitation.device, old.device);
    assert_eq!(invitation.generation, 2);
    assert_eq!(invitation.root, old.root);
    assert_eq!(invitation.predecessor, Some(replace.predecessor));
    assert_ne!(invitation.operation, old.operation);
    assert!(host
        .approve_enrollment(&token, invitation.operation, &old_proof)
        .is_err());
    assert!(host.issue_enrollment(&token, invitation.operation).is_err());
    let (_, proof) = request(&path, &invitation)?;
    let old_key = sdk::VerifiedEnrollmentRequest::verify(
        &old_proof,
        &old.intent()?,
        crate::enrollment::now()?,
    )?;
    let new_key = sdk::VerifiedEnrollmentRequest::verify(
        &proof,
        &invitation.intent()?,
        crate::enrollment::now()?,
    )?;
    assert_ne!(old_key.public_key().encode(), new_key.public_key().encode());
    assert_ne!(old_key.identity(), new_key.identity());
    host.approve_enrollment(&token, invitation.operation, &proof)?;
    assert_eq!(
        host.enrollment_root(&token)?,
        before,
        "approval alone does not change membership"
    );
    let response = host.issue_enrollment(&token, invitation.operation)?;
    let receipt: IssuedEnrollment = serde_json::from_slice(&response)?;
    let after = host.enrollment_root(&token)?;
    verify(&after, &receipt)?;
    assert!(verify(&after, &serde_json::from_slice(&old_response)?).is_err());
    let pin = sdk::AccountPin::new(
        after.account,
        sdk::PublicKey::decode(&after.public_key)?,
        receipt.checkpoint.as_sdk()?,
        after.family,
    )?;
    let roster = pin.verify_roster(&receipt.roster, crate::enrollment::now()?)?;
    assert_eq!(roster.members().count(), 2);
    assert!(roster.validity().until() >= extension_input.valid_until);
    pin.verify_device(
        &extended.certificate,
        &receipt.roster,
        crate::enrollment::now()?,
    )?;
    assert_eq!(host.issue_enrollment(&token, old.operation)?, old_response);
    assert_eq!(
        host.issue_enrollment(&token, other.operation)?,
        other_response
    );
    drop(host);
    let mut host = reopen(&path)?;
    assert!(
        host.invite_device_replacement(&token, &replace).is_err(),
        "sessions do not survive restart"
    );
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(
        host.invite_device_replacement(&token, &replace)?,
        invitation
    );
    assert_eq!(
        host.issue_enrollment(&token, invitation.operation)?,
        response
    );
    assert_eq!(host.enrollment_root(&token)?, after);
    assert_eq!(host.issue_enrollment(&token, old.operation)?, old_response);
    let stale = input(&mut host, &token, &old)?;
    assert!(host.invite_device_replacement(&token, &stale).is_err());
    let next = input(&mut host, &token, &invitation)?;
    let (third, _, third_response) = replacement(&mut host, &path, &token, &next)?;
    assert_eq!(third.generation, 3);
    verify(
        &host.enrollment_root(&token)?,
        &serde_json::from_slice(&third_response)?,
    )?;
    Ok(())
}

#[test]
fn replacement_authentication_conflicts_and_fresh_decisions_cannot_rebase() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let mut bob = authenticator();
    register(&mut host, &mut bob, "bob")?;
    let (other, _) = login(&mut host, &mut bob, "bob")?;
    schema6(&mut host.store)?;
    host.store.enable_device_replacements()?;
    host.prepare_enrollment_root(&token)?;
    let (old, old_proof, old_response) = issued(&mut host, &path, &token)?;
    let replace = input(&mut host, &token, &old)?;
    let before = host.enrollment_root(&token)?;
    assert!(host.invite_device_replacement("invalid", &replace).is_err());
    assert!(host.invite_device_replacement(&other, &replace).is_err());
    let ordinary = host.invite_enrollment(&token, crate::enrollment::random()?)?;
    for bad in [
        DeviceReplacementRequest {
            request_id: [0; 32],
            ..replace.clone()
        },
        DeviceReplacementRequest {
            enrollment: ordinary.operation,
            ..replace.clone()
        },
        DeviceReplacementRequest {
            request_id: ordinary.request_id,
            ..replace.clone()
        },
        DeviceReplacementRequest {
            predecessor: crate::enrollment::Checkpoint {
                version: replace.predecessor.version + 1,
                ..replace.predecessor
            },
            ..replace.clone()
        },
    ] {
        assert!(host.invite_device_replacement(&token, &bad).is_err());
    }
    let first = host.invite_device_replacement(&token, &replace)?;
    assert!(host.invite_enrollment(&token, replace.request_id).is_err());
    let retarget = DeviceReplacementRequest {
        enrollment: ordinary.operation,
        ..replace.clone()
    };
    assert!(host.invite_device_replacement(&token, &retarget).is_err());
    let competing = input(&mut host, &token, &old)?;
    let second = host.invite_device_replacement(&token, &competing)?;
    let (_, first_proof) = request(&path, &first)?;
    let (_, second_proof) = request(&path, &second)?;
    assert!(host
        .approve_enrollment(&other, first.operation, &first_proof)
        .is_err());
    // The wire proof binds the approved device intent, not the host operation
    // ID. Concurrent invitations may share that intent; the explicit approval
    // chooses its exact proof and the signer index prevents cross-operation reuse.
    assert!(host
        .approve_enrollment(&token, first.operation, &old_proof)
        .is_err());
    assert!(host
        .reapprove_enrollment(
            &token,
            first.operation,
            crate::enrollment::random()?,
            first.predecessor,
            &first_proof
        )
        .is_err());
    host.approve_enrollment(&token, first.operation, &first_proof)?;
    assert!(host
        .approve_enrollment(&token, second.operation, &first_proof)
        .is_err());
    host.approve_enrollment(&token, second.operation, &second_proof)?;
    assert_eq!(host.enrollment_root(&token)?, before);
    host.issue_enrollment(&token, first.operation)?;
    let after = host.enrollment_root(&token)?;
    assert!(host.issue_enrollment(&token, second.operation).is_err());
    assert_eq!(host.enrollment_root(&token)?, after);
    host.cancel_enrollment(&token, second.operation)?;
    assert!(host.invite_device_replacement(&token, &competing).is_err());
    assert!(host
        .approve_enrollment(&token, second.operation, &old_proof)
        .is_err());
    let suspended = input(&mut host, &token, &first)?;
    host.suspend_enrollment_root(&token)?;
    assert!(host.invite_device_replacement(&token, &suspended).is_err());
    assert_eq!(host.issue_enrollment(&token, old.operation)?, old_response);
    Ok(())
}

#[test]
fn replacement_resolves_exact_extended_credential_and_works_at_full_roster_capacity() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema6(&mut host.store)?;
    host.store.enable_device_replacements()?;
    host.prepare_enrollment_root(&token)?;
    let (old, _, original) = issued(&mut host, &path, &token)?;
    for _ in 1..sdk::MAX_DEVICES {
        issued(&mut host, &path, &token)?;
    }
    assert!(matches!(
        host.invite_enrollment(&token, crate::enrollment::random()?),
        Err(Error::Capacity)
    ));
    let extension_input = extension(&mut host, &token, &old)?;
    let extended = host.extend_enrollment_credential(&token, &extension_input)?;
    let input = input(&mut host, &token, &old)?;
    let (next, _, response) = replacement(&mut host, &path, &token, &input)?;
    let receipt: IssuedEnrollment = serde_json::from_slice(&response)?;
    let root = host.enrollment_root(&token)?;
    verify(&root, &receipt)?;
    let pin = sdk::AccountPin::new(
        root.account,
        sdk::PublicKey::decode(&root.public_key)?,
        receipt.checkpoint.as_sdk()?,
        root.family,
    )?;
    assert_eq!(
        pin.verify_roster(&receipt.roster, crate::enrollment::now()?)?
            .members()
            .count(),
        sdk::MAX_DEVICES
    );
    assert_eq!(next.generation, 2);
    assert_eq!(host.issue_enrollment(&token, old.operation)?, original);
    assert_eq!(
        host.extend_enrollment_credential(&token, &extension_input)?,
        extended
    );
    Ok(())
}
