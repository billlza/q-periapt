// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real WebAuthn signature exercises with a software test authenticator. Its UV
//! flag is simulated by the upstream test backend; these are not hardware proofs.
use super::*;
use std::{error::Error as StdError, os::unix::fs::PermissionsExt};
use tempfile::TempDir;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
pub(super) type Result<T = ()> = std::result::Result<T, Box<dyn StdError>>;
pub(super) const ORIGIN: &str = "http://localhost:8087";
pub(super) fn service() -> Result<(TempDir, Service)> {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = directory.path().canonicalize()?.join("accounts.redb");
    let store = Store::provision(&path, ORIGIN)?;
    let webauthn = WebauthnBuilder::new("localhost", &Url::parse(ORIGIN)?)?.build()?;
    Ok((directory, Service::new(webauthn, store)))
}
pub(super) fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}
pub(super) fn register(
    service: &mut Service,
    device: &mut WebauthnAuthenticator<SoftPasskey>,
    name: &str,
) -> Result<Identity> {
    let (id, options) = service.start_registration(name, None, None)?;
    let credential = device.do_registration(Url::parse(ORIGIN)?, options)?;
    Ok(service.finish_registration(&id, credential, None)?)
}
pub(super) fn login(
    service: &mut Service,
    device: &mut WebauthnAuthenticator<SoftPasskey>,
    name: &str,
) -> Result<(String, Identity)> {
    let (id, options) = service.start_login(name, None)?;
    let credential = device.do_authentication(Url::parse(ORIGIN)?, options)?;
    Ok(service.finish_login(&id, credential, None)?)
}
#[test]
fn real_signatures_single_use_reopen_and_logout() -> Result {
    let (directory, mut service) = service()?;
    let mut device = authenticator();
    let original = register(&mut service, &mut device, "alice")?;
    assert!(service.sessions.is_empty());
    let (challenge, options) = service.start_login("alice", None)?;
    let credential = device.do_authentication(Url::parse(ORIGIN)?, options)?;
    let replay = serde_json::from_slice(&serde_json::to_vec(&credential)?)?;
    let (session, identity) = service.finish_login(&challenge, credential, None)?;
    assert_eq!(identity.application_id, original.application_id);
    assert!(matches!(
        service.finish_login(&challenge, replay, None),
        Err(Error::Unauthorized)
    ));
    assert_eq!(service.identity(&session)?.account, "alice");
    service.logout(&session)?;
    assert!(matches!(
        service.identity(&session),
        Err(Error::Unauthorized)
    ));
    drop(service);
    let path = directory.path().canonicalize()?.join("accounts.redb");
    assert!(Store::open(&path, "http://localhost:9999").is_err());
    let store = Store::open(&path, ORIGIN)?;
    let webauthn = WebauthnBuilder::new("localhost", &Url::parse(ORIGIN)?)?.build()?;
    let mut service = Service::new(webauthn, store);
    let (_, reopened) = login(&mut service, &mut device, "alice")?;
    assert_eq!(reopened.application_id, original.application_id);
    assert!(Store::open(&directory.path().join("missing.redb"), ORIGIN).is_err());
    assert!(!directory.path().join("missing.redb").exists());
    Ok(())
}
#[test]
fn wrong_challenge_origin_and_expired_ceremonies_fail() -> Result {
    let (_directory, mut service) = service()?;
    let mut device = authenticator();
    register(&mut service, &mut device, "alice")?;
    let (first, options) = service.start_login("alice", None)?;
    let credential = device.do_authentication(Url::parse(ORIGIN)?, options)?;
    let (second, _) = service.start_login("alice", None)?;
    assert!(matches!(
        service.finish_login(&second, credential, None),
        Err(Error::Unauthorized)
    ));
    assert!(!service.pending.contains_key(&second));
    service
        .pending
        .get_mut(&first)
        .ok_or("pending challenge absent")?
        .deadline = Instant::now();
    assert!(matches!(service.take(&first), Err(Error::Unauthorized)));
    let (id, options) = service.start_registration("bob", None, None)?;
    let credential = device.do_registration(Url::parse("http://localhost:9999")?, options)?;
    assert!(matches!(
        service.finish_registration(&id, credential, None),
        Err(Error::Unauthorized)
    ));
    assert!(service.store.account("bob")?.is_none());
    assert!(service.sessions.is_empty());
    Ok(())
}
#[test]
fn extra_passkey_requires_original_live_session_at_finish() -> Result {
    let (_directory, mut service) = service()?;
    let mut original = authenticator();
    register(&mut service, &mut original, "alice")?;
    let (session, _) = login(&mut service, &mut original, "alice")?;
    let mut second = authenticator();
    let (id, options) = service.start_registration("alice", Some(&session), None)?;
    let credential = second.do_registration(Url::parse(ORIGIN)?, options)?;
    assert!(matches!(
        service.finish_registration(&id, credential, None),
        Err(Error::Unauthorized)
    ));
    assert_eq!(service.identity(&session)?.passkeys, 1);
    let (id, options) = service.start_registration("alice", Some(&session), None)?;
    let credential = second.do_registration(Url::parse(ORIGIN)?, options)?;
    service.logout(&session)?;
    assert!(matches!(
        service.finish_registration(&id, credential, Some(&session)),
        Err(Error::Unauthorized)
    ));
    let (session, identity) = login(&mut service, &mut original, "alice")?;
    let (id, options) = service.start_registration("alice", Some(&session), None)?;
    let credential = second.do_registration(Url::parse(ORIGIN)?, options)?;
    assert_eq!(
        service
            .finish_registration(&id, credential, Some(&session))?
            .passkeys,
        2
    );
    let (_, second_identity) = login(&mut service, &mut second, "alice")?;
    assert_eq!(second_identity.application_id, identity.application_id);
    Ok(())
}
#[test]
fn registration_race_cannot_replace_original_account() -> Result {
    let (_directory, mut service) = service()?;
    let mut one = authenticator();
    let mut two = authenticator();
    let (first, options) = service.start_registration("alice", None, None)?;
    let first_key = one.do_registration(Url::parse(ORIGIN)?, options)?;
    let (second, options) = service.start_registration("alice", None, None)?;
    let second_key = two.do_registration(Url::parse(ORIGIN)?, options)?;
    let original = service.finish_registration(&first, first_key, None)?;
    assert!(matches!(
        service.finish_registration(&second, second_key, None),
        Err(Error::Conflict(_))
    ));
    let (_, identity) = login(&mut service, &mut one, "alice")?;
    assert_eq!(identity.application_id, original.application_id);
    assert!(login(&mut service, &mut two, "alice").is_err());
    Ok(())
}

#[test]
fn public_parent_is_rejected_before_any_account_database_is_published() -> Result {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o755))
        .tempdir()?;
    let path = directory.path().canonicalize()?.join("accounts.redb");
    assert!(Store::provision(&path, ORIGIN).is_err());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn unknown_account_login_is_explicit_and_does_not_create_an_account() -> Result {
    let (_directory, mut service) = service()?;
    assert!(matches!(
        service.start_login("not_registered", None),
        Err(Error::AccountNotRegistered)
    ));
    assert!(service.store.account("not_registered")?.is_none());
    assert!(service.pending.is_empty() && service.sessions.is_empty());
    Ok(())
}
