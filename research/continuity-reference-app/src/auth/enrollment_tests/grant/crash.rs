// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn retained_grant_sigkill_preserves_pending_scope_and_committed_result() -> Result {
    for boundary in [
        "grant-pending-before-commit",
        "grant-pending-after-commit",
        "grant-issued-before-commit",
        "grant-issued-after-commit",
    ] {
        let mut c = Case::new()?;
        c.host.store.enable_credential_grants()?;
        let before = c.host.enrollment_root(&c.token)?;
        drop(c.host);
        let cut: serde_json::Value = serde_json::from_slice(&kill_at(
            &c.path,
            boundary,
            Work::Grant(Box::new(c.input.clone())),
        )?)?;
        let mut host = reopen(&c.path)?;
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, before);
        if boundary != "grant-pending-before-commit" {
            let mut changed = c.input.clone();
            changed.retained.journal[0] ^= 1;
            assert!(matches!(
                host.issue_credential_grant(&token, &changed),
                Err(Error::Conflict("Original retained grant request differs"))
            ));
        }
        let bytes = host.issue_credential_grant(&token, &c.input)?;
        if boundary == "grant-issued-after-commit" {
            assert_eq!(
                bytes,
                URL_SAFE_NO_PAD.decode(cut["phase"]["response"].as_str().ok_or("response")?)?
            );
        }
        assert_eq!(host.issue_credential_grant(&token, &c.input)?, bytes);
        assert_eq!(
            host.issue_enrollment(&token, c.invitation.operation)?,
            c.first
        );
    }
    Ok(())
}

#[test]
fn retained_grant_pending_head_change_refuses_and_cancel_is_durable() -> Result {
    for boundary in ["grant-closed-before-commit", "grant-closed-after-commit"] {
        let mut c = Case::new()?;
        c.host.store.enable_credential_grants()?;
        drop(c.host);
        kill_at(
            &c.path,
            "grant-pending-after-commit",
            Work::Grant(Box::new(c.input.clone())),
        )?;
        let mut host = reopen(&c.path)?;
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        let changed = CredentialExtensionRequest {
            request_id: crate::enrollment::random()?,
            enrollment: c.invitation.operation,
            previous_extension: Some(c.input.successor_extension),
            predecessor: c.input.target_checkpoint,
            valid_until: c.invitation.valid_until + 7200,
        };
        host.extend_enrollment_credential(&token, &changed)?;
        assert!(matches!(
            host.issue_credential_grant(&token, &c.input),
            Err(Error::Conflict("Selected target roster changed"))
        ));
        drop(host);
        kill_at(
            &c.path,
            boundary,
            Work::CancelGrant(Box::new(c.input.clone())),
        )?;
        let mut host = reopen(&c.path)?;
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        if boundary.ends_with("after-commit") {
            assert!(matches!(
                host.issue_credential_grant(&token, &c.input),
                Err(Error::Conflict("Original retained grant is closed"))
            ));
        }
        host.cancel_credential_grant(&token, &c.input)?;
        assert!(matches!(
            host.issue_credential_grant(&token, &c.input),
            Err(Error::Conflict("Original retained grant is closed"))
        ));
    }
    Ok(())
}

#[test]
fn retained_grant_upgrade_sigkill_preserves_original_account_and_issuance() -> Result {
    for boundary in ["grant-upgrade-before-commit", "grant-upgrade-after-commit"] {
        let mut c = Case::new()?;
        let account = serde_json::to_vec(&c.host.store.account("alice")?.ok_or("account")?)?;
        drop(c.host);
        kill_at(&c.path, boundary, Work::GrantUpgrade)?;
        let mut host = reopen(&c.path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut c.auth, "alice")?;
        assert_eq!(
            host.issue_enrollment(&token, c.invitation.operation)?,
            c.first
        );
        if boundary.ends_with("before-commit") {
            assert!(host.issue_credential_grant(&token, &c.input).is_err());
        }
        host.store.enable_credential_grants()?;
        host.issue_credential_grant(&token, &c.input)?;
    }
    Ok(())
}
