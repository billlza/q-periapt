// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::{CredentialExtensionRequest, IssuedCredentialExtension, RosterSnapshot};
use crate::root_preparation::SuccessorRequest;
mod crash;

fn successor(preparation: &Preparation) -> Result<SuccessorRequest> {
    Ok(SuccessorRequest {
        preparation: preparation.operation,
        request_id: crate::enrollment::random()?,
    })
}
fn issuer(preparation: &Preparation, issued: &IssuedEnrollment) -> Result<RootInfo> {
    let key = candidate(preparation)?;
    Ok(RootInfo {
        revision: key.revision,
        account: key.account,
        public_key: key.public_key.clone(),
        family: key.family,
        suspended: false,
        roster: Some(RosterSnapshot {
            checkpoint: issued.checkpoint,
            bytes: issued.roster.clone(),
        }),
    })
}
fn issue_candidate(
    host: &mut Service,
    path: &Path,
    token: &str,
    preparation: &Preparation,
) -> Result<(Invitation, Vec<u8>, Vec<u8>)> {
    let invitation = host.invite_root_successor(token, &successor(preparation)?)?;
    let (_, proof) = request(path, &invitation)?;
    host.approve_enrollment(token, invitation.operation, &proof)?;
    let response = host.issue_enrollment(token, invitation.operation)?;
    Ok((invitation, proof, response))
}

#[test]
fn candidate_enrollment_uses_original_approval_and_never_selects_its_root() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema7(&mut host.store)?;
    host.store.enable_root_preparations()?;
    host.prepare_enrollment_root(&token)?;
    let (old, old_proof, old_response) = super::super::extension::issued(&mut host, &path, &token)?;
    let root = host.suspend_enrollment_root(&token)?;
    let prepared = host.prepare_account_root(&token, &input(&root)?)?;
    let input = successor(&prepared)?;
    assert!(matches!(
        host.invite_root_successor(&token, &input),
        Err(Error::Conflict(_))
    ));
    host.store.enable_root_successors()?;
    host.store.enable_root_successors()?;
    assert!(host
        .root_successor(&token, prepared.operation)?
        .enrollment
        .is_none());
    let next = host.invite_root_successor(&token, &input)?;
    assert_eq!(
        host.root_successor(&token, prepared.operation)?.enrollment,
        Some(next.clone())
    );
    assert_eq!(host.invite_root_successor(&token, &input)?, next);
    assert_eq!(next.root, candidate(&prepared)?.public_key);
    assert_eq!(next.root_revision, root.revision + 1);
    assert_eq!(next.application, old.application);
    assert_ne!(next.device, old.device);
    assert!(next.predecessor.is_none());
    assert_eq!(next.generation, 1);
    assert!(matches!(
        host.issue_enrollment(&token, next.operation),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        host.approve_enrollment(&token, next.operation, &old_proof),
        Err(Error::Invalid(_))
    ));
    let (paths, proof) = request(&path, &next)?;
    host.approve_enrollment(&token, next.operation, &proof)?;
    let response = host.issue_enrollment(&token, next.operation)?;
    let issued: IssuedEnrollment = serde_json::from_slice(&response)?;
    verify(&issuer(&prepared, &issued)?, &issued)?;
    assert_eq!(issued.checkpoint.version, 1);
    assert_eq!(host.enrollment_root(&token)?, root);
    assert_eq!(host.issue_enrollment(&token, old.operation)?, old_response);
    assert!(
        matches!(host.enrollment_status(&token,next.operation)?,EnrollmentStatus::Issued {current,..} if current==root)
    );
    let all_keys = keys(&path)?;
    drop(host);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(host.invite_root_successor(&token, &input)?, next);
    assert_eq!(host.issue_enrollment(&token, next.operation)?, response);
    assert_eq!(host.enrollment_root(&token)?, root);
    unchanged(&all_keys)?;
    let mut device = sdk::DeviceEnrollment::open(paths, next.intent()?)?;
    assert_eq!(device.request(crate::enrollment::now()?)?, proof);
    device.close();
    Ok(())
}

#[test]
fn candidate_enrollment_refuses_other_accounts_correlations_and_branching() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let mut bob = authenticator();
    register(&mut host, &mut bob, "bob")?;
    let (other, _) = login(&mut host, &mut bob, "bob")?;
    schema7(&mut host.store)?;
    host.store.enable_root_preparations()?;
    host.store.enable_root_successors()?;
    let root = host.prepare_enrollment_root(&token)?;
    let prepared = host.prepare_account_root(&token, &input(&root)?)?;
    let second = host.prepare_account_root(&token, &input(&root)?)?;
    let input = successor(&prepared)?;
    assert!(matches!(
        host.invite_root_successor("absent", &input),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        host.invite_root_successor(&other, &input),
        Err(Error::Unauthorized)
    ));
    let next = host.invite_root_successor(&token, &input)?;
    assert!(matches!(
        host.invite_enrollment(&token, input.request_id),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        host.invite_root_successor(
            &token,
            &SuccessorRequest {
                preparation: second.operation,
                ..input
            }
        ),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        host.invite_root_successor(&token, &successor(&prepared)?),
        Err(Error::Conflict(_))
    ));
    let (_, proof) = request(&path, &next)?;
    assert!(matches!(
        host.approve_enrollment(&other, next.operation, &proof),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        host.issue_enrollment(&other, next.operation),
        Err(Error::Unauthorized)
    ));
    host.approve_enrollment(&token, next.operation, &proof)?;
    host.close_account_root_preparation(&token, prepared.operation)?;
    assert!(matches!(
        host.enrollment_status(&token, next.operation)?,
        EnrollmentStatus::Closed
    ));
    assert!(matches!(
        host.issue_enrollment(&token, next.operation),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        host.approve_enrollment(&token, next.operation, &proof),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        host.invite_root_successor(&token, &input),
        Err(Error::Conflict(_))
    ));
    assert_eq!(host.enrollment_root(&token)?, root);
    Ok(())
}

#[test]
fn candidate_reapproval_moves_the_original_signer_reservation_and_closes_as_one_operation() -> Result
{
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema7(&mut host.store)?;
    host.store.enable_root_preparations()?;
    host.store.enable_root_successors()?;
    let root = host.prepare_enrollment_root(&token)?;
    let prepared = host.prepare_account_root(&token, &input(&root)?)?;
    let original = host.invite_root_successor(&token, &successor(&prepared)?)?;
    let (_, proof) = request(&path, &original)?;
    host.approve_enrollment(&token, original.operation, &proof)?;
    let correlation = crate::enrollment::random()?;
    let next = host.reapprove_enrollment(&token, original.operation, correlation, None, &proof)?;
    assert_eq!(
        host.root_successor(&token, prepared.operation)?.enrollment,
        Some(next.clone())
    );
    assert_ne!(next.operation, original.operation);
    assert_eq!(next.device, original.device);
    assert_eq!(next.root, original.root);
    assert_eq!(next.valid_until, original.valid_until);
    assert_eq!(
        host.reapprove_enrollment(&token, original.operation, correlation, None, &proof)?,
        next
    );
    assert!(
        matches!(host.enrollment_status(&token,original.operation)?,EnrollmentStatus::Reapproved {successor} if successor==next)
    );
    assert!(matches!(
        host.issue_enrollment(&token, original.operation),
        Err(Error::Conflict(_))
    ));
    let bytes = host.issue_enrollment(&token, next.operation)?;
    let issued = serde_json::from_slice(&bytes)?;
    verify(&issuer(&prepared, &issued)?, &issued)?;
    assert_eq!(host.enrollment_root(&token)?, root);
    host.close_account_root_preparation(&token, prepared.operation)?;
    assert_eq!(host.issue_enrollment(&token, next.operation)?, bytes);
    assert_eq!(
        host.root_successor(&token, prepared.operation)?.enrollment,
        Some(next.clone())
    );
    assert!(
        matches!(host.enrollment_status(&token,original.operation)?,EnrollmentStatus::Reapproved {successor} if successor==next)
    );
    Ok(())
}

#[test]
fn candidate_same_key_extension_and_history_survive_old_root_key_loss_and_closure() -> Result {
    use crate::{
        native_device::NativeDevice,
        policy_publisher::{Anchor, BootstrapMode, Publisher, Request as PolicyRequest},
    };
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    let mut publisher = Publisher::provision(
        &path.join("publisher.redb"),
        [90; 32],
        crate::test_support::sdk_input()?,
    )?;
    let family = publisher.prepare()?.family;
    let at = crate::enrollment::now()?;
    publisher.issue(
        [91; 32],
        PolicyRequest {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: at,
            valid_until: at + 10800,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        at,
    )?;
    let (pins, materials) = publisher.export([91; 32])?;
    let (policy, _) = pins.verify(&materials, family, at)?;
    host.store.enable_enrollment(family)?;
    host.store.enable_enrollment_reapproval()?;
    host.store.enable_enrollment_extensions()?;
    host.store.enable_credential_grants()?;
    host.store.enable_policy_approvals()?;
    host.store.enable_device_replacements()?;
    host.store.enable_root_preparations()?;
    host.store.enable_root_successors()?;
    host.prepare_enrollment_root(&token)?;
    let root = host.suspend_enrollment_root(&token)?;
    let old_keys: BTreeMap<_, _> = keys(&path)?
        .into_iter()
        .filter(|(p, _)| {
            p.file_name()
                .is_some_and(|v| v.to_string_lossy().starts_with("enrollment-"))
        })
        .collect();
    for file in old_keys.keys() {
        fs::rename(
            file,
            file.with_extension(format!(
                "{}.retained",
                file.extension().ok_or("extension")?.to_string_lossy()
            )),
        )?;
    }
    let prepared = host.prepare_account_root(&token, &input(&root)?)?;
    let invitation = host.invite_root_successor(&token, &successor(&prepared)?)?;
    let device_path = path.join("native-device");
    fs::DirBuilder::new().mode(0o700).create(&device_path)?;
    let wrapping = path.join("native.wrap");
    drop(sdk::JournalKey::provision(&wrapping)?);
    let mut native = NativeDevice::begin(
        &device_path,
        &wrapping,
        invitation.clone(),
        crate::enrollment::now()?,
    )?;
    let proof = native.request(crate::enrollment::now()?)?;
    let device_key = fs::read(device_path.join("device.key"))?;
    let original_wrapping = fs::read(&wrapping)?;
    host.approve_enrollment(&token, invitation.operation, &proof)?;
    let response = host.issue_enrollment(&token, invitation.operation)?;
    let original: IssuedEnrollment = serde_json::from_slice(&response)?;
    let installation = native.accept(
        &original,
        &issuer(&prepared, &original)?,
        &policy,
        crate::enrollment::now()?,
    )?;
    let input = CredentialExtensionRequest {
        request_id: crate::enrollment::random()?,
        enrollment: invitation.operation,
        previous_extension: None,
        predecessor: original.checkpoint,
        valid_until: invitation.valid_until + 3600,
    };
    let bytes = host.extend_enrollment_credential(&token, &input)?;
    let extended: IssuedCredentialExtension = serde_json::from_slice(&bytes)?;
    let key = candidate(&prepared)?;
    let pin = sdk::AccountPin::new(
        key.account,
        sdk::PublicKey::decode(&key.public_key)?,
        extended.checkpoint.as_sdk()?,
        key.family,
    )?;
    let before = sdk::AccountPin::new(
        key.account,
        sdk::PublicKey::decode(&key.public_key)?,
        original.checkpoint.as_sdk()?,
        key.family,
    )?
    .verify_historical_device(&original.certificate, &original.roster)?;
    let after = pin.verify_device(
        &extended.certificate,
        &extended.roster,
        crate::enrollment::now()?,
    )?;
    let current = RootInfo {
        roster: Some(RosterSnapshot {
            checkpoint: extended.checkpoint,
            bytes: extended.roster.clone(),
        }),
        ..issuer(&prepared, &original)?
    };
    assert_eq!(
        native.extend(
            &input,
            &extended,
            &current,
            &policy,
            crate::enrollment::now()?
        )?,
        installation
    );
    native.close();
    assert!(
        fs::read(device_path.join("device.key"))? == device_key,
        "original device signing file changed"
    );
    assert!(
        fs::read(&wrapping)? == original_wrapping,
        "original device wrapping file changed"
    );
    assert_eq!(before.device_id(), after.device_id());
    assert_eq!(before.generation(), after.generation());
    assert_eq!(extended.checkpoint.version, 2);
    assert_eq!(host.enrollment_root(&token)?, root);
    host.close_account_root_preparation(&token, prepared.operation)?;
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, bytes);
    let further = CredentialExtensionRequest {
        request_id: crate::enrollment::random()?,
        previous_extension: Some(input.request_id),
        predecessor: extended.checkpoint,
        valid_until: input.valid_until + 3600,
        ..input
    };
    assert!(matches!(
        host.extend_enrollment_credential(&token, &further),
        Err(Error::Conflict(_))
    ));
    let all_keys = keys(&path)?;
    drop(host);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(
        host.issue_enrollment(&token, invitation.operation)?,
        response
    );
    assert_eq!(host.extend_enrollment_credential(&token, &input)?, bytes);
    assert_eq!(host.enrollment_root(&token)?, root);
    unchanged(&all_keys)?;
    for file in old_keys.keys() {
        assert!(!file.exists());
    }
    Ok(())
}
