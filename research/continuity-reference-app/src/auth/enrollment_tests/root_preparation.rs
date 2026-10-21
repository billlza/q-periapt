// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate creation is host-authenticated and recoverable, never issuer cutover.
use super::*;
use crate::root_preparation::{Candidate, Predecessor, Preparation, Request, Status};
use std::{collections::BTreeMap, path::PathBuf};
mod crash;

fn schema7(store: &mut Store) -> Result {
    store.enable_enrollment([42; 32])?;
    store.enable_enrollment_reapproval()?;
    store.enable_enrollment_extensions()?;
    store.enable_credential_grants()?;
    store.enable_policy_approvals()?;
    store.enable_device_replacements()?;
    Ok(())
}
fn input(root: &RootInfo) -> Result<Request> {
    Ok(Request {
        request_id: crate::enrollment::random()?,
        predecessor: Predecessor {
            revision: root.revision,
            account: root.account,
        },
    })
}
fn candidate(value: &Preparation) -> Result<&Candidate> {
    match &value.status {
        Status::Prepared { candidate } => Ok(candidate),
        _ => Err("candidate is not prepared".into()),
    }
}
fn keys(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut keys = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let file = entry?.path();
        if matches!(
            file.extension().and_then(|e| e.to_str()),
            Some("wrap" | "signer")
        ) {
            keys.insert(file.clone(), fs::read(file)?);
        }
    }
    Ok(keys)
}
fn unchanged(original: &BTreeMap<PathBuf, Vec<u8>>) -> Result {
    for (file, bytes) in original {
        assert!(fs::read(file)? == *bytes, "retained key file changed");
    }
    Ok(())
}

#[test]
fn explicit_upgrade_preparation_and_reopen_preserve_current_issuer_and_history() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    let identity = register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert!(matches!(
        host.store.enable_root_preparations(),
        Err(Error::Conflict(_))
    ));
    schema7(&mut host.store)?;
    host.prepare_enrollment_root(&token)?;
    let (invitation, _, response) = super::extension::issued(&mut host, &path, &token)?;
    let root = host.enrollment_root(&token)?;
    let input = input(&root)?;
    let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
    let original_keys = keys(&path)?;
    assert!(matches!(
        host.prepare_account_root(&token, &input),
        Err(Error::Conflict(_))
    ));
    host.store.enable_root_preparations()?;
    host.store.enable_root_preparations()?;
    assert_eq!(
        serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
        account
    );
    let prepared = host.prepare_account_root(&token, &input)?;
    let next = candidate(&prepared)?;
    assert_eq!(prepared.request, input);
    assert_ne!(prepared.operation, [0; 32]);
    assert_eq!(next.revision, root.revision + 1);
    assert_ne!(next.account, root.account);
    assert_ne!(next.public_key, root.public_key);
    assert_eq!(next.family, root.family);
    sdk::PublicKey::decode(&next.public_key)?;
    assert_eq!(host.prepare_account_root(&token, &input)?, prepared);
    assert_eq!(host.enrollment_root(&token)?, root);
    assert_eq!(
        host.issue_enrollment(&token, invitation.operation)?,
        response
    );
    unchanged(&original_keys)?;
    let all_keys = keys(&path)?;
    assert_eq!(all_keys.len(), original_keys.len() + 2);
    drop(host);
    let mut host = reopen(&path)?;
    assert!(matches!(
        host.account_root_preparation(&token, prepared.operation),
        Err(Error::Unauthorized)
    ));
    let (token, reopened) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(reopened.application_id, identity.application_id);
    assert_eq!(
        host.account_root_preparation(&token, prepared.operation)?,
        prepared
    );
    assert_eq!(host.prepare_account_root(&token, &input)?, prepared);
    assert_eq!(host.enrollment_root(&token)?, root);
    assert_eq!(
        host.issue_enrollment(&token, invitation.operation)?,
        response
    );
    assert_eq!(
        host.invite_enrollment(&token, crate::enrollment::random()?)?
            .root,
        root.public_key
    );
    unchanged(&all_keys)?;
    assert_eq!(keys(&path)?.len(), all_keys.len());
    Ok(())
}

#[test]
fn original_request_account_authentication_and_permanent_closure_are_enforced() -> Result {
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
    let root = host.prepare_enrollment_root(&token)?;
    host.prepare_enrollment_root(&other)?;
    let input = input(&root)?;
    assert!(matches!(
        host.prepare_account_root("absent", &input),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        host.prepare_account_root(&other, &input),
        Err(Error::Conflict(_))
    ));
    let zero = Request {
        request_id: [0; 32],
        ..input
    };
    assert!(matches!(
        host.prepare_account_root(&token, &zero),
        Err(Error::Invalid(_))
    ));
    let prepared = host.prepare_account_root(&token, &input)?;
    for change in [
        Predecessor {
            revision: root.revision + 1,
            account: root.account,
        },
        Predecessor {
            revision: root.revision,
            account: [91; 32],
        },
    ] {
        assert!(matches!(
            host.prepare_account_root(
                &token,
                &Request {
                    predecessor: change,
                    ..input
                }
            ),
            Err(Error::Conflict(_))
        ));
    }
    assert!(matches!(
        host.account_root_preparation(&other, prepared.operation),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        host.close_account_root_preparation(&other, prepared.operation),
        Err(Error::Unauthorized)
    ));
    let all_keys = keys(&path)?;
    let closed = host.close_account_root_preparation(&token, prepared.operation)?;
    assert_eq!(closed.status, Status::Closed);
    assert_eq!(closed.request, input);
    assert_eq!(
        host.close_account_root_preparation(&token, prepared.operation)?,
        closed
    );
    assert!(matches!(
        host.prepare_account_root(&token, &input),
        Err(Error::Conflict(_))
    ));
    assert_eq!(host.enrollment_root(&token)?, root);
    host.sessions.get_mut(&token).ok_or("session")?.deadline = Instant::now();
    assert!(matches!(
        host.account_root_preparation(&token, prepared.operation),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        host.close_account_root_preparation(&token, prepared.operation),
        Err(Error::Unauthorized)
    ));
    drop(host);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(
        host.account_root_preparation(&token, prepared.operation)?,
        closed
    );
    assert!(matches!(
        host.prepare_account_root(&token, &input),
        Err(Error::Conflict(_))
    ));
    unchanged(&all_keys)?;
    assert_eq!(keys(&path)?.len(), all_keys.len());
    Ok(())
}

#[test]
fn unavailable_old_keys_do_not_block_independent_candidate_or_clear_suspension() -> Result {
    let (dir, mut host) = service()?;
    let path = dir.path().canonicalize()?;
    let mut auth = authenticator();
    register(&mut host, &mut auth, "alice")?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    schema7(&mut host.store)?;
    host.store.enable_root_preparations()?;
    host.prepare_enrollment_root(&token)?;
    let root = host.suspend_enrollment_root(&token)?;
    let input = input(&root)?;
    let old_keys = keys(&path)?;
    assert_eq!(old_keys.len(), 2);
    for file in old_keys.keys() {
        fs::rename(
            file,
            file.with_extension(format!(
                "{}.retained",
                file.extension().ok_or("extension")?.to_string_lossy()
            )),
        )?;
    }
    assert!(matches!(
        host.prepare_enrollment_root(&token),
        Err(Error::IssuerUnavailable)
    ));
    let prepared = host.prepare_account_root(&token, &input)?;
    assert_ne!(candidate(&prepared)?.account, root.account);
    assert_eq!(host.enrollment_root(&token)?, root);
    assert!(matches!(
        host.invite_enrollment(&token, crate::enrollment::random()?),
        Err(Error::Conflict(_))
    ));
    drop(host);
    let mut host = reopen(&path)?;
    let (token, _) = login(&mut host, &mut auth, "alice")?;
    assert_eq!(host.prepare_account_root(&token, &input)?, prepared);
    assert_eq!(host.enrollment_root(&token)?, root);
    for (file, bytes) in old_keys {
        assert!(!file.exists());
        let retained = file.with_extension(format!(
            "{}.retained",
            file.extension().ok_or("extension")?.to_string_lossy()
        ));
        assert!(
            fs::read(retained)? == bytes,
            "lost original private file was modified"
        );
    }
    Ok(())
}

#[test]
fn prepared_candidate_never_regenerates_missing_private_files_and_history_survives() -> Result {
    for extension in ["wrap", "signer"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema7(&mut host.store)?;
        host.store.enable_root_preparations()?;
        let root = host.prepare_enrollment_root(&token)?;
        let old_keys = keys(&path)?;
        let input = input(&root)?;
        let prepared = host.prepare_account_root(&token, &input)?;
        let all_keys = keys(&path)?;
        let missing = all_keys
            .keys()
            .find(|p| !old_keys.contains_key(*p) && p.extension().is_some_and(|v| v == extension))
            .ok_or("candidate key")?;
        let retained = missing.with_extension(format!("{extension}.retained"));
        fs::rename(missing, &retained)?;
        assert!(matches!(
            host.prepare_account_root(&token, &input),
            Err(Error::IssuerUnavailable)
        ));
        assert_eq!(
            host.account_root_preparation(&token, prepared.operation)?,
            prepared
        );
        assert_eq!(host.prepare_enrollment_root(&token)?, root);
        drop(host);
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        assert!(matches!(
            host.prepare_account_root(&token, &input),
            Err(Error::IssuerUnavailable)
        ));
        assert_eq!(
            host.account_root_preparation(&token, prepared.operation)?,
            prepared
        );
        assert!(!missing.exists());
        assert!(
            fs::read(retained)? == *all_keys.get(missing).ok_or("saved key")?,
            "missing candidate key was replaced"
        );
        unchanged(&old_keys)?;
        assert_eq!(
            host.close_account_root_preparation(&token, prepared.operation)?
                .status,
            Status::Closed
        );
        assert!(!missing.exists());
    }
    Ok(())
}
