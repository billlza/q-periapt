// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn successor_schema_and_invitation_commit_cuts_retain_candidate_and_current_root() -> Result {
    for boundary in [
        "root-successor-upgrade-before-commit",
        "root-successor-upgrade-after-commit",
        "invitation-before-commit",
        "invitation-after-commit",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema7(&mut host.store)?;
        host.store.enable_root_preparations()?;
        let root = host.prepare_enrollment_root(&token)?;
        let prepared = host.prepare_account_root(&token, &input(&root)?)?;
        let input = successor(&prepared)?;
        let upgrading = boundary.starts_with("root-successor-upgrade");
        if !upgrading {
            host.store.enable_root_successors()?;
        }
        let all_keys = keys(&path)?;
        drop(host);
        let observed = kill_at(
            &path,
            boundary,
            if upgrading {
                Work::RootSuccessorUpgrade
            } else {
                Work::InviteRootSuccessor(input)
            },
        )?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        assert_eq!(
            host.account_root_preparation(&token, prepared.operation)?,
            prepared
        );
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&all_keys)?;
        if boundary == "root-successor-upgrade-before-commit" {
            assert!(matches!(
                host.invite_root_successor(&token, &input),
                Err(Error::Conflict(_))
            ));
        } else if upgrading {
            host.invite_root_successor(&token, &input)?;
        }
        host.store.enable_root_successors()?;
        let next = host.invite_root_successor(&token, &input)?;
        if boundary == "invitation-after-commit" {
            assert_eq!(next, serde_json::from_slice::<Invitation>(&observed)?);
        }
        assert_eq!(host.invite_root_successor(&token, &input)?, next);
        assert!(matches!(
            host.invite_root_successor(&token, &successor(&prepared)?),
            Err(Error::Conflict(_))
        ));
        let (_, proof) = request(&path, &next)?;
        host.approve_enrollment(&token, next.operation, &proof)?;
        let issued = serde_json::from_slice(&host.issue_enrollment(&token, next.operation)?)?;
        verify(&issuer(&prepared, &issued)?, &issued)?;
        assert_eq!(host.enrollment_root(&token)?, root);
    }
    Ok(())
}

#[test]
fn candidate_issuance_and_reapproval_kills_preserve_one_original_target() -> Result {
    for boundary in [
        "issue-before-commit",
        "issue-after-commit",
        "reapproval-before-commit",
        "reapproval-after-commit",
    ] {
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
        let next = host.invite_root_successor(&token, &successor(&prepared)?)?;
        let (_, proof) = request(&path, &next)?;
        host.approve_enrollment(&token, next.operation, &proof)?;
        let correlation = crate::enrollment::random()?;
        let reapproving = boundary.starts_with("reapproval");
        let all_keys = keys(&path)?;
        drop(host);
        let observed = kill_at(
            &path,
            boundary,
            if reapproving {
                Work::Reapprove((next.operation, correlation, None, proof.clone()))
            } else {
                Work::Issue(next.operation)
            },
        )?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let selected = if reapproving {
            let selected =
                host.reapprove_enrollment(&token, next.operation, correlation, None, &proof)?;
            if boundary.ends_with("after-commit") {
                assert_eq!(selected, serde_json::from_slice::<Invitation>(&observed)?);
            }
            assert!(matches!(
                host.issue_enrollment(&token, next.operation),
                Err(Error::Conflict(_))
            ));
            selected
        } else {
            next
        };
        let response = host.issue_enrollment(&token, selected.operation)?;
        if boundary == "issue-after-commit" {
            assert_eq!(response, observed);
        }
        assert_eq!(host.issue_enrollment(&token, selected.operation)?, response);
        let issued = serde_json::from_slice(&response)?;
        verify(&issuer(&prepared, &issued)?, &issued)?;
        assert_eq!(issued.checkpoint.version, 1);
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&all_keys)?;
    }
    Ok(())
}

#[test]
fn candidate_extension_kills_commit_its_roster_and_exact_response_together() -> Result {
    for boundary in [
        "credential-extension-before-commit",
        "credential-extension-after-commit",
    ] {
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
        let (next, _, original) = issue_candidate(&mut host, &path, &token, &prepared)?;
        let first: IssuedEnrollment = serde_json::from_slice(&original)?;
        let input = CredentialExtensionRequest {
            request_id: crate::enrollment::random()?,
            enrollment: next.operation,
            previous_extension: None,
            predecessor: first.checkpoint,
            valid_until: next.valid_until + 3600,
        };
        let all_keys = keys(&path)?;
        drop(host);
        let observed = kill_at(&path, boundary, Work::Extend(input.clone()))?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        let response = host.extend_enrollment_credential(&token, &input)?;
        if boundary.ends_with("after-commit") {
            assert_eq!(response, observed);
        }
        assert_eq!(host.extend_enrollment_credential(&token, &input)?, response);
        let extended: IssuedCredentialExtension = serde_json::from_slice(&response)?;
        assert_eq!(extended.checkpoint.version, 2);
        let key = candidate(&prepared)?;
        sdk::AccountPin::new(
            key.account,
            sdk::PublicKey::decode(&key.public_key)?,
            extended.checkpoint.as_sdk()?,
            key.family,
        )?
        .verify_device(
            &extended.certificate,
            &extended.roster,
            crate::enrollment::now()?,
        )?;
        assert_eq!(host.issue_enrollment(&token, next.operation)?, original);
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&all_keys)?;
    }
    Ok(())
}

#[test]
fn candidate_closure_kills_also_close_the_latest_unissued_enrollment() -> Result {
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
        host.store.enable_root_successors()?;
        let root = host.prepare_enrollment_root(&token)?;
        let prepared = host.prepare_account_root(&token, &input(&root)?)?;
        let old = host.invite_root_successor(&token, &successor(&prepared)?)?;
        let (_, proof) = request(&path, &old)?;
        host.approve_enrollment(&token, old.operation, &proof)?;
        let next = host.reapprove_enrollment(
            &token,
            old.operation,
            crate::enrollment::random()?,
            None,
            &proof,
        )?;
        let all_keys = keys(&path)?;
        drop(host);
        kill_at(
            &path,
            boundary,
            Work::CloseRootPreparation(prepared.operation),
        )?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        if boundary.ends_with("before-commit") {
            assert!(matches!(
                host.enrollment_status(&token, next.operation)?,
                EnrollmentStatus::Approved { .. }
            ));
        } else {
            assert!(matches!(
                host.enrollment_status(&token, next.operation)?,
                EnrollmentStatus::Closed
            ));
        }
        host.close_account_root_preparation(&token, prepared.operation)?;
        assert!(matches!(
            host.enrollment_status(&token, next.operation)?,
            EnrollmentStatus::Closed
        ));
        assert!(
            matches!(host.enrollment_status(&token,old.operation)?,EnrollmentStatus::Reapproved {successor} if successor==next)
        );
        assert!(matches!(
            host.issue_enrollment(&token, next.operation),
            Err(Error::Conflict(_))
        ));
        assert_eq!(host.enrollment_root(&token)?, root);
        unchanged(&all_keys)?;
    }
    Ok(())
}
