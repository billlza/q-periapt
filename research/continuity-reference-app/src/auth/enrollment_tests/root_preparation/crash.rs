// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn preparation_upgrade_kills_preserve_account_issuer_and_original_issuance() -> Result {
    for boundary in [
        "root-preparation-upgrade-before-commit",
        "root-preparation-upgrade-after-commit",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema7(&mut host.store)?;
        host.prepare_enrollment_root(&token)?;
        let (enrollment, _, response) = super::super::extension::issued(&mut host, &path, &token)?;
        let root = host.enrollment_root(&token)?;
        let input = input(&root)?;
        let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
        let old_keys = keys(&path)?;
        drop(host);
        kill_at(&path, boundary, Work::RootPreparationUpgrade)?;
        let mut host = reopen(&path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, root);
        assert_eq!(
            host.issue_enrollment(&token, enrollment.operation)?,
            response
        );
        if boundary.ends_with("before-commit") {
            assert!(matches!(
                host.prepare_account_root(&token, &input),
                Err(Error::Conflict(_))
            ));
        } else {
            // The committed schema is usable immediately after reopen.
            candidate(&host.prepare_account_root(&token, &input)?)?;
        }
        host.store.enable_root_preparations()?;
        let prepared = host.prepare_account_root(&token, &input)?;
        assert_eq!(host.prepare_account_root(&token, &input)?, prepared);
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&old_keys)?;
    }
    Ok(())
}

#[test]
fn candidate_keys_and_original_operation_survive_five_process_kills() -> Result {
    for boundary in [
        "root-preparation-retained",
        "root-wrapping-published",
        "root-signing-prepared",
        "root-signer-published",
        "root-ready-committed",
    ] {
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
        drop(host);
        let cut = kill_at(&path, boundary, Work::PrepareRoot(input))?;
        let published = keys(&path)?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let prepared = host.prepare_account_root(&token, &input)?;
        let next = candidate(&prepared)?;
        if boundary == "root-preparation-retained" {
            assert_eq!(prepared.operation.as_slice(), cut);
        }
        if matches!(boundary, "root-signer-published" | "root-ready-committed") {
            assert_eq!(next.public_key, cut);
        }
        unchanged(&published)?;
        assert_eq!(keys(&path)?.len(), old_keys.len() + 2);
        assert_eq!(host.prepare_account_root(&token, &input)?, prepared);
        assert_eq!(
            host.account_root_preparation(&token, prepared.operation)?,
            prepared
        );
        assert_eq!(host.enrollment_root(&token)?, root);
        assert!(matches!(
            host.invite_enrollment(&token, crate::enrollment::random()?),
            Err(Error::Conflict(_))
        ));
    }
    Ok(())
}

#[test]
fn candidate_closure_is_atomic_permanent_and_does_not_erase_original_keys() -> Result {
    for boundary in [
        "root-preparation-close-before-commit",
        "root-preparation-closed",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema7(&mut host.store)?;
        host.store.enable_root_preparations()?;
        let root = host.prepare_enrollment_root(&token)?;
        let input = input(&root)?;
        let prepared = host.prepare_account_root(&token, &input)?;
        let all_keys = keys(&path)?;
        drop(host);
        assert_eq!(
            kill_at(
                &path,
                boundary,
                Work::CloseRootPreparation(prepared.operation)
            )?,
            prepared.operation
        );
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let observed = host.account_root_preparation(&token, prepared.operation)?;
        if boundary.ends_with("before-commit") {
            assert_eq!(observed, prepared);
        } else {
            assert_eq!(observed.status, Status::Closed);
            assert!(matches!(
                host.prepare_account_root(&token, &input),
                Err(Error::Conflict(_))
            ));
        }
        let closed = host.close_account_root_preparation(&token, prepared.operation)?;
        assert_eq!(closed.status, Status::Closed);
        assert_eq!(
            host.close_account_root_preparation(&token, prepared.operation)?,
            closed
        );
        assert!(matches!(
            host.prepare_account_root(&token, &input),
            Err(Error::Conflict(_))
        ));
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&all_keys)?;
        assert_eq!(keys(&path)?.len(), all_keys.len());
    }
    Ok(())
}
