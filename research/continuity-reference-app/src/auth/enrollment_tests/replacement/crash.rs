// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn replacement_upgrade_and_invitation_kills_preserve_original_account_and_decision() -> Result {
    for boundary in [
        "replacement-upgrade-before-commit",
        "replacement-upgrade-after-commit",
        "invitation-before-commit",
        "invitation-after-commit",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema6(&mut host.store)?;
        host.prepare_enrollment_root(&token)?;
        let (old, _, original) = issued(&mut host, &path, &token)?;
        let input = input(&mut host, &token, &old)?;
        let before = host.enrollment_root(&token)?;
        let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
        let upgrading = boundary.starts_with("replacement-upgrade");
        if !upgrading {
            host.store.enable_device_replacements()?;
        }
        drop(host);
        let observed = kill_at(
            &path,
            boundary,
            if upgrading {
                Work::ReplacementUpgrade
            } else {
                Work::Replace(input.clone())
            },
        )?;
        let mut host = reopen(&path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, before);
        assert_eq!(host.issue_enrollment(&token, old.operation)?, original);
        if boundary == "replacement-upgrade-before-commit" {
            assert!(host.invite_device_replacement(&token, &input).is_err());
        }
        host.store.enable_device_replacements()?;
        let recovered = host.invite_device_replacement(&token, &input)?;
        if boundary == "invitation-after-commit" {
            assert_eq!(recovered, serde_json::from_slice::<Invitation>(&observed)?);
        }
        assert_eq!(host.invite_device_replacement(&token, &input)?, recovered);
        assert_eq!(recovered.generation, 2);
        assert_eq!(host.enrollment_root(&token)?, before);
    }
    Ok(())
}

#[test]
fn replacement_issue_kills_commit_membership_and_exact_response_together() -> Result {
    for boundary in ["issue-before-commit", "issue-after-commit"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        schema6(&mut host.store)?;
        host.store.enable_device_replacements()?;
        host.prepare_enrollment_root(&token)?;
        let (old, _, original) = issued(&mut host, &path, &token)?;
        let input = input(&mut host, &token, &old)?;
        let next = host.invite_device_replacement(&token, &input)?;
        let (_, proof) = request(&path, &next)?;
        host.approve_enrollment(&token, next.operation, &proof)?;
        let before = host.enrollment_root(&token)?;
        let old_dir = path.join(URL_SAFE_NO_PAD.encode(old.operation));
        let signer = fs::read(old_dir.join("signer.key"))?;
        let wrap = fs::read(old_dir.join("wrap.key"))?;
        drop(host);
        let cut = kill_at(&path, boundary, Work::Issue(next.operation))?;
        let mut host = reopen(&path)?;
        let (token, _) = login(&mut host, &mut auth, "alice")?;
        if boundary.ends_with("before-commit") {
            assert_eq!(host.enrollment_root(&token)?, before);
        }
        let recovered = host.issue_enrollment(&token, next.operation)?;
        if boundary.ends_with("after-commit") {
            assert_eq!(recovered, cut);
        }
        let after = host.enrollment_root(&token)?;
        let receipt: IssuedEnrollment = serde_json::from_slice(&recovered)?;
        assert_eq!(receipt.checkpoint.version, input.predecessor.version + 1);
        verify(&after, &receipt)?;
        assert!(verify(&after, &serde_json::from_slice(&original)?).is_err());
        assert_eq!(host.issue_enrollment(&token, next.operation)?, recovered);
        assert_eq!(host.issue_enrollment(&token, old.operation)?, original);
        assert_eq!(fs::read(old_dir.join("signer.key"))?, signer);
        assert_eq!(fs::read(old_dir.join("wrap.key"))?, wrap);
    }
    Ok(())
}
