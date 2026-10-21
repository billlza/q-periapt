// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real software account authentication, retained signed policy and native authority storage.
use super::*;
use crate::{
    account_authority::{AssociationRequest, Initialization},
    policy_publisher::{Anchor, BootstrapMode, PolicyInput, Publisher, Request as PolicyRequest},
    root_preparation::Predecessor,
    witness::Witness,
};
use std::path::PathBuf;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
mod crash;
mod cutover;

struct Case {
    path: PathBuf,
    host: Service,
    auth: WebauthnAuthenticator<SoftPasskey>,
    token: String,
    request: AssociationRequest,
    root: RootInfo,
    original: Invitation,
}
impl Case {
    fn new() -> Result<Self> {
        Self::with_duration(3600)
    }
    fn with_duration(seconds: u64) -> Result<Self> {
        let (directory, mut host) = service()?;
        let path = directory.keep().canonicalize()?;
        eprintln!("Retained account authority fixture: {}", path.display());
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let mut witness = Witness::provision(&path.join("witness.redb"), [100; 32])?;
        let pin = witness.prepare()?;
        let mut publisher = Publisher::provision(
            &path.join("publisher.redb"),
            [101; 32],
            crate::test_support::sdk_input()?,
        )?;
        let family = publisher.prepare()?.family;
        let at = crate::enrollment::now()?;
        publisher.issue(
            [102; 32],
            PolicyRequest {
                bootstrap_mode: BootstrapMode::ReusableBoth,
                valid_from: at,
                valid_until: at + seconds,
                send_budget: 8,
                anchor: Anchor::Required {
                    identity: pin.identity,
                    key: pin.key,
                },
            },
            at,
        )?;
        let (pins, materials) = publisher.export([102; 32])?;
        host.store.enable_enrollment(family)?;
        host.store.enable_enrollment_reapproval()?;
        host.store.enable_enrollment_extensions()?;
        host.store.enable_credential_grants()?;
        host.store.enable_policy_approvals()?;
        host.store.enable_device_replacements()?;
        host.store.enable_root_preparations()?;
        host.store.enable_root_successors()?;
        host.prepare_enrollment_root(&token)?;
        let (invitation, _, _) = super::extension::issued(&mut host, &path, &token)?;
        let root = host.enrollment_root(&token)?;
        let request = AssociationRequest {
            request_id: crate::enrollment::random()?,
            enrollment: invitation.operation,
            root: Predecessor {
                revision: root.revision,
                account: root.account,
            },
            roster: root.roster.as_ref().ok_or("roster")?.checkpoint,
            policy: PolicyInput { pins, materials },
        };
        Ok(Self {
            path,
            host,
            auth,
            token,
            request,
            root,
            original: invitation,
        })
    }
}
fn authority_files(path: &Path) -> Result<Vec<PathBuf>> {
    Ok(fs::read_dir(path)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|p| p.to_string_lossy().starts_with("authority-"))
                && matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("wrap" | "redb")
                )
        })
        .collect())
}

#[test]
fn original_signed_witness_association_survives_explicit_upgrade_and_reopen() -> Result {
    let mut c = Case::new()?;
    assert!(matches!(
        c.host.associate_account_authority(&c.token, &c.request),
        Err(Error::Conflict(_))
    ));
    let account = serde_json::to_vec(&c.host.store.account("alice")?.ok_or("account")?)?;
    c.host.store.enable_account_authorities()?;
    c.host.store.enable_account_authorities()?;
    assert_eq!(
        serde_json::to_vec(&c.host.store.account("alice")?.ok_or("account")?)?,
        account
    );
    assert!(matches!(
        c.host.account_authority(&c.token),
        Err(Error::Conflict(_))
    ));
    let first = c.host.associate_account_authority(&c.token, &c.request)?;
    assert_eq!(first.initialization, Initialization::Initialized);
    let (_, pin) = c
        .request
        .policy
        .pins
        .verify_historical(&c.request.policy.materials, c.root.family)?;
    assert_eq!(
        first.witness.as_sdk()?.binding(),
        pin.ok_or("required witness")?.binding()
    );
    assert!(first.request == c.request);
    assert!(c.host.associate_account_authority(&c.token, &c.request)? == first);
    assert_eq!(c.host.enrollment_root(&c.token)?, c.root);
    let files = authority_files(&c.path)?;
    assert_eq!(files.len(), 2);
    let wrap = files
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == "wrap"))
        .ok_or("wrapping key")?;
    let original = fs::read(wrap)?;
    drop(c.host);
    let mut host = reopen(&c.path)?;
    assert!(matches!(
        host.account_authority(&c.token),
        Err(Error::Unauthorized)
    ));
    let (token, _) = login(&mut host, &mut c.auth, "alice")?;
    assert!(host.account_authority(&token)? == first);
    assert!(host.associate_account_authority(&token, &c.request)? == first);
    assert_eq!(host.enrollment_root(&token)?, c.root);
    assert!(
        fs::read(wrap)? == original,
        "authority wrapping key changed"
    );
    Ok(())
}

#[test]
fn association_rejects_policy_substitution_and_retarget_without_allocating_new_authority() -> Result
{
    let mut c = Case::new()?;
    c.host.store.enable_account_authorities()?;
    assert!(matches!(
        c.host.associate_account_authority("absent", &c.request),
        Err(Error::Unauthorized)
    ));
    let mut altered = serde_json::to_value(&c.request)?;
    altered["policy"]["pins"]["witness"]["identity"] = serde_json::json!(vec![88u8; 32]);
    let wrong: AssociationRequest = serde_json::from_value(altered)?;
    assert!(matches!(
        c.host.associate_account_authority(&c.token, &wrong),
        Err(Error::Invalid(_))
    ));
    assert!(authority_files(&c.path)?.is_empty());
    let mut changed = c.request.clone();
    changed.root.account = [87; 32];
    assert!(matches!(
        c.host.associate_account_authority(&c.token, &changed),
        Err(Error::Conflict(_))
    ));
    let first = c.host.associate_account_authority(&c.token, &c.request)?;
    changed = c.request.clone();
    changed.request_id = crate::enrollment::random()?;
    assert!(matches!(
        c.host.associate_account_authority(&c.token, &changed),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        c.host.associate_account_authority(&c.token, &wrong),
        Err(Error::Conflict(_))
    ));
    assert!(c.host.account_authority(&c.token)? == first);
    assert_eq!(authority_files(&c.path)?.len(), 2);
    assert_eq!(c.host.enrollment_root(&c.token)?, c.root);
    Ok(())
}

#[test]
fn old_issuer_key_loss_and_expired_original_policy_do_not_replace_trust() -> Result {
    let mut c = Case::with_duration(2)?;
    c.host.store.enable_account_authorities()?;
    c.root = c.host.suspend_enrollment_root(&c.token)?;
    for entry in fs::read_dir(&c.path)? {
        let file = entry?.path();
        if file
            .file_name()
            .is_some_and(|p| p.to_string_lossy().starts_with("enrollment-"))
        {
            fs::rename(
                &file,
                file.with_extension(format!(
                    "{}.retained",
                    file.extension().ok_or("extension")?.to_string_lossy()
                )),
            )?;
        }
    }
    let (policy, _) = c
        .request
        .policy
        .pins
        .verify_historical(&c.request.policy.materials, c.root.family)?;
    let limit = Instant::now() + std::time::Duration::from_secs(10);
    while crate::enrollment::now()? < policy.validity().until() {
        if Instant::now() >= limit {
            return Err("original policy did not expire".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(c
        .request
        .policy
        .pins
        .verify(
            &c.request.policy.materials,
            c.root.family,
            crate::enrollment::now()?
        )
        .is_err());
    let first = c.host.associate_account_authority(&c.token, &c.request)?;
    assert_eq!(first.initialization, Initialization::Initialized);
    assert_eq!(c.host.enrollment_root(&c.token)?, c.root);
    assert!(matches!(
        c.host.prepare_enrollment_root(&c.token),
        Err(Error::IssuerUnavailable)
    ));
    Ok(())
}

#[test]
fn initialized_authority_never_recreates_a_missing_registry_or_wrapping_key() -> Result {
    for extension in ["wrap", "redb"] {
        let mut c = Case::new()?;
        c.host.store.enable_account_authorities()?;
        let first = c.host.associate_account_authority(&c.token, &c.request)?;
        let file = authority_files(&c.path)?
            .into_iter()
            .find(|p| p.extension().is_some_and(|e| e == extension))
            .ok_or("authority file")?;
        let retained = file.with_extension(format!("{extension}.retained"));
        fs::rename(&file, &retained)?;
        assert!(matches!(
            c.host.associate_account_authority(&c.token, &c.request),
            Err(Error::AuthorityUnavailable)
        ));
        assert!(matches!(
            c.host
                .invite_enrollment(&c.token, crate::enrollment::random()?),
            Err(Error::AuthorityUnavailable)
        ));
        assert!(c.host.account_authority(&c.token)? == first);
        assert_eq!(c.host.enrollment_root(&c.token)?, c.root);
        assert!(!file.exists() && retained.exists());
        drop(c.host);
        let mut host = reopen(&c.path)?;
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        assert!(matches!(
            host.associate_account_authority(&token, &c.request),
            Err(Error::AuthorityUnavailable)
        ));
        assert!(matches!(
            host.invite_enrollment(&token, crate::enrollment::random()?),
            Err(Error::AuthorityUnavailable)
        ));
        assert!(host.account_authority(&token)? == first);
        assert!(!file.exists());
    }
    Ok(())
}
