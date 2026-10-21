// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native enrollment requests and real signatures with software host authentication.
use super::{tests::*, *};
use crate::enrollment::{EnrollmentStatus, Invitation, IssuedEnrollment, RootInfo};
use q_periapt_continuity_identity_candidate as sdk;
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

fn reopen(path: &Path) -> Result<Service> {
    Ok(Service::new(
        WebauthnBuilder::new("localhost", &Url::parse(ORIGIN)?)?.build()?,
        Store::open(&path.join("accounts.redb"), ORIGIN)?,
    ))
}
fn request(path: &Path, invitation: &Invitation) -> Result<(sdk::EnrollmentPaths, Vec<u8>)> {
    request_at(path, invitation, crate::enrollment::now()?)
}
fn request_at(
    path: &Path,
    invitation: &Invitation,
    trusted_time: u64,
) -> Result<(sdk::EnrollmentPaths, Vec<u8>)> {
    let dir = path.join(URL_SAFE_NO_PAD.encode(invitation.operation));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    drop(sdk::JournalKey::provision(&dir.join("wrap.key"))?);
    let paths = sdk::EnrollmentPaths::new(
        &dir.join("wrap.key"),
        &dir.join("signer.key"),
        &dir.join("enrollment.redb"),
        sdk::InstallationPaths::new(
            &dir.join("installation.redb"),
            &dir.join("journal.redb"),
            &dir.join("archive.redb"),
        )?,
    )?;
    let mut owner = sdk::DeviceEnrollment::provision(paths.clone(), invitation.intent()?)?;
    let wire = owner.request(trusted_time)?;
    owner.close();
    Ok((paths, wire))
}
fn verify(root: &RootInfo, receipt: &IssuedEnrollment) -> Result {
    let current = root.roster.as_ref().ok_or("no current roster")?;
    let pin = sdk::AccountPin::new(
        root.account,
        sdk::PublicKey::decode(&root.public_key)?,
        current.checkpoint.as_sdk()?,
        root.family,
    )?;
    pin.verify_device(
        &receipt.certificate,
        &current.bytes,
        crate::enrollment::now()?,
    )?;
    Ok(())
}

#[test]
fn explicit_upgrade_preserves_account_and_issuance_reopens_exact_original_result() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    let identity = register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    let before = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
    assert!(host.prepare_enrollment_root(&session).is_err());
    host.store.enable_enrollment([42; 32])?;
    host.store.enable_enrollment([42; 32])?;
    assert!(host.store.enable_enrollment([43; 32]).is_err());
    assert_eq!(
        serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
        before
    );
    let root = host.prepare_enrollment_root(&session)?;
    let invitation = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (paths, wire) = request(&path, &invitation)?;
    assert!(host
        .issue_enrollment(&session, invitation.operation)
        .is_err());
    host.approve_enrollment(&session, invitation.operation, &wire)?;
    let first = host.issue_enrollment(&session, invitation.operation)?;
    let issued: IssuedEnrollment = serde_json::from_slice(&first)?;
    verify(&host.enrollment_root(&session)?, &issued)?;
    drop(host);
    let mut host = reopen(&path)?;
    assert!(host
        .issue_enrollment(&session, invitation.operation)
        .is_err());
    let (session, after) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(after.application_id, identity.application_id);
    assert_eq!(
        host.prepare_enrollment_root(&session)?.public_key,
        root.public_key
    );
    assert_eq!(
        host.issue_enrollment(&session, invitation.operation)?,
        first
    );
    let mut client = sdk::DeviceEnrollment::open(paths, invitation.intent()?)?;
    assert_eq!(client.request(crate::enrollment::now()?)?, wire);
    client.close();
    assert_eq!(
        host.enrollment_root(&session)?
            .roster
            .ok_or("roster")?
            .checkpoint
            .version,
        1
    );
    assert!(host
        .cancel_enrollment(&session, invitation.operation)
        .is_err());
    Ok(())
}

#[test]
fn authorization_request_binding_roster_conflicts_and_two_devices() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    let mut bob = authenticator();
    register(&mut host, &mut bob, "bob")?;
    let (other, _) = login(&mut host, &mut bob, "bob")?;
    host.store.enable_enrollment([42; 32])?;
    assert!(host.prepare_enrollment_root("unknown").is_err());
    host.prepare_enrollment_root(&session)?;
    let first = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let conflicting = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wire) = request(&path, &first)?;
    let (_, other_wire) = request(&path, &conflicting)?;
    assert!(host
        .approve_enrollment(&other, first.operation, &wire)
        .is_err());
    assert!(host
        .approve_enrollment(&session, first.operation, &other_wire)
        .is_err());
    assert!(host
        .approve_enrollment(&session, first.operation, &[0; 8193])
        .is_err());
    host.approve_enrollment(&session, first.operation, &wire)?;
    host.approve_enrollment(&session, first.operation, &wire)?;
    assert!(host
        .approve_enrollment(&session, first.operation, &other_wire)
        .is_err());
    host.approve_enrollment(&session, conflicting.operation, &other_wire)?;
    let first_response = host.issue_enrollment(&session, first.operation)?;
    assert!(host
        .issue_enrollment(&session, conflicting.operation)
        .is_err());
    host.cancel_enrollment(&session, conflicting.operation)?;
    assert!(matches!(
        host.enrollment_status(&session, conflicting.operation)?,
        EnrollmentStatus::Closed
    ));
    assert!(host
        .issue_enrollment(&session, conflicting.operation)
        .is_err());
    let second = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, second_wire) = request(&path, &second)?;
    host.approve_enrollment(&session, second.operation, &second_wire)?;
    let second_response = host.issue_enrollment(&session, second.operation)?;
    let current = host.enrollment_root(&session)?;
    assert_eq!(
        current.roster.as_ref().ok_or("roster")?.checkpoint.version,
        2
    );
    verify(&current, &serde_json::from_slice(&first_response)?)?;
    verify(&current, &serde_json::from_slice(&second_response)?)?;
    assert_eq!(
        host.issue_enrollment(&session, first.operation)?,
        first_response
    );
    assert!(host.enrollment_status(&other, first.operation).is_err());
    host.sessions.get_mut(&session).ok_or("session")?.deadline = Instant::now();
    assert!(host.issue_enrollment(&session, first.operation).is_err());
    Ok(())
}

#[test]
fn root_suspension_fences_pending_approval_but_preserves_historical_result() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.prepare_enrollment_root(&session)?;
    let first = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wire) = request(&path, &first)?;
    host.approve_enrollment(&session, first.operation, &wire)?;
    let response = host.issue_enrollment(&session, first.operation)?;
    let pending = host.invite_enrollment(&session, crate::enrollment::random()?)?;
    let (_, wire) = request(&path, &pending)?;
    host.approve_enrollment(&session, pending.operation, &wire)?;
    host.suspend_enrollment_root(&session)?;
    assert!(host.prepare_enrollment_root(&session)?.suspended);
    assert!(host
        .invite_enrollment(&session, crate::enrollment::random()?)
        .is_err());
    assert!(host.issue_enrollment(&session, pending.operation).is_err());
    drop(host);
    let mut host = reopen(&path)?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    assert!(host.issue_enrollment(&session, pending.operation).is_err());
    assert_eq!(host.issue_enrollment(&session, first.operation)?, response);
    assert!(
        matches!(host.enrollment_status(&session, first.operation)?, EnrollmentStatus::Issued { current, .. } if current.suspended)
    );
    Ok(())
}

mod crash;
mod extension;
mod grant;
mod historical;
mod reapproval;
mod reapproval_crash;
mod replacement;
mod root_preparation;

#[test]
fn admitted_root_never_regenerates_a_missing_wrapping_key() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    host.store.enable_enrollment([42; 32])?;
    host.prepare_enrollment_root(&session)?;
    let key = fs::read_dir(&path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .find(|path| path.extension().is_some_and(|ext| ext == "wrap"))
        .ok_or("wrapping file")?;
    let retained = key.with_extension("retained");
    let mut bob = authenticator();
    register(&mut host, &mut bob, "bob")?;
    let (other, _) = login(&mut host, &mut bob, "bob")?;
    host.prepare_enrollment_root(&other)?;
    fs::rename(&key, &retained)?;
    assert!(matches!(
        host.prepare_enrollment_root(&session),
        Err(Error::IssuerUnavailable)
    ));
    assert!(!key.exists() && retained.is_file());
    assert!(
        host.identity(&other).is_ok(),
        "one missing root key must not disable unrelated account authentication"
    );
    host.invite_enrollment(&other, crate::enrollment::random()?)?;
    assert!(host.identity(&session).is_ok());
    drop(host);
    let mut host = reopen(&path)?;
    let (session, _) = login(&mut host, &mut auth, "alice")?;
    assert!(host.prepare_enrollment_root(&session).is_err());
    assert!(!key.exists() && retained.is_file());
    Ok(())
}
