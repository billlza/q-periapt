// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::super::crash::{kill_at, Work};
use std::time::Duration;

#[test]
fn account_policy_pending_target_expiry_never_issues_or_silently_discards_the_original() -> Result {
    let mut c = PolicyCase::with_validity(false, 30, 10)?;
    c.base.host.store.enable_policy_approvals()?;
    let until = c.publisher.result([94; 32])?.request.valid_until;
    let mut issued_request = c.request.clone();
    issued_request.retained.scope.operation = crate::enrollment::random()?;
    let issued = c
        .base
        .host
        .issue_policy_approval(&c.base.token, &issued_request)?;
    drop(c.base.host);
    kill_at(
        &c.base.path,
        "policy-approval-pending-after-commit",
        Work::PolicyApproval(Box::new(c.request.clone())),
    )?;
    let mut host = reopen(&c.base.path)?;
    let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
    let pending = serde_json::to_vec(&host.policy_approval_status(&token, &c.request)?)?;
    assert!(matches!(
        host.policy_approval_status(&token, &c.request)?,
        PolicyApprovalStatus::Pending { .. }
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    while crate::enrollment::now()? < until {
        if Instant::now() >= deadline {
            return Err("Actual account policy target expiry exceeded bound".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(host.issue_policy_approval(&token, &c.request).is_err());
    assert_eq!(
        serde_json::to_vec(&host.policy_approval_status(&token, &c.request)?)?,
        pending
    );
    assert_eq!(host.issue_policy_approval(&token, &issued_request)?, issued);
    host.cancel_policy_approval(&token, &c.request)?;
    drop(host);
    let mut host = reopen(&c.base.path)?;
    let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
    assert!(matches!(
        host.policy_approval_status(&token, &c.request)?,
        PolicyApprovalStatus::Closed
    ));
    Ok(())
}
use super::*;

#[test]
fn account_policy_upgrade_preserves_original_account_and_root_at_both_cuts() -> Result {
    for boundary in [
        "policy-approval-upgrade-before-commit",
        "policy-approval-upgrade-after-commit",
    ] {
        let mut c = PolicyCase::new(false)?;
        let before = c.base.host.enrollment_root(&c.base.token)?;
        let account = serde_json::to_vec(&c.base.host.store.account("alice")?.ok_or("account")?)?;
        drop(c.base.host);
        kill_at(&c.base.path, boundary, Work::PolicyUpgrade)?;
        let mut host = reopen(&c.base.path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, before);
        if boundary.ends_with("before-commit") {
            assert!(host.issue_policy_approval(&token, &c.request).is_err());
        }
        host.store.enable_policy_approvals()?;
        host.issue_policy_approval(&token, &c.request)?;
    }
    Ok(())
}

#[test]
fn account_policy_signing_and_commit_cuts_preserve_exact_original_decision() -> Result {
    for boundary in [
        "policy-approval-pending-before-commit",
        "policy-approval-pending-after-commit",
        "policy-approval-signed-before-commit",
        "policy-approval-issued-before-commit",
        "policy-approval-issued-after-commit",
    ] {
        let mut c = PolicyCase::new(false)?;
        c.base.host.store.enable_policy_approvals()?;
        let before = c.base.host.enrollment_root(&c.base.token)?;
        drop(c.base.host);
        let cut = kill_at(
            &c.base.path,
            boundary,
            Work::PolicyApproval(Box::new(c.request.clone())),
        )?;
        let mut host = reopen(&c.base.path)?;
        let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
        assert_eq!(host.enrollment_root(&token)?, before);
        let status = serde_json::to_vec(&host.policy_approval_status(&token, &c.request)?)?;
        assert_eq!(
            serde_json::to_vec(&host.policy_approval_status(&token, &c.request)?)?,
            status
        );
        if boundary.ends_with("pending-before-commit") {
            assert!(matches!(
                host.policy_approval_status(&token, &c.request)?,
                PolicyApprovalStatus::Absent
            ));
        } else if boundary != "policy-approval-issued-after-commit" {
            assert!(matches!(
                host.policy_approval_status(&token, &c.request)?,
                PolicyApprovalStatus::Pending { .. }
            ));
        }
        if boundary != "policy-approval-pending-before-commit" {
            let mut wrong = c.request.clone();
            wrong.retained.scope.journal[0] ^= 1;
            assert!(host.issue_policy_approval(&token, &wrong).is_err());
        }
        let issued = host.issue_policy_approval(&token, &c.request)?;
        if boundary == "policy-approval-issued-after-commit" {
            let saved: serde_json::Value = serde_json::from_slice(&cut)?;
            assert_eq!(
                issued,
                URL_SAFE_NO_PAD.decode(saved["phase"]["response"].as_str().ok_or("response")?)?
            );
        }
        assert_eq!(host.issue_policy_approval(&token, &c.request)?, issued);
    }
    Ok(())
}

#[test]
fn account_policy_pending_roster_change_refuses_and_cancellation_survives_cuts() -> Result {
    for boundary in [
        "policy-approval-closed-before-commit",
        "policy-approval-closed-after-commit",
    ] {
        let mut c = PolicyCase::new(false)?;
        c.base.host.store.enable_policy_approvals()?;
        drop(c.base.host);
        kill_at(
            &c.base.path,
            "policy-approval-pending-after-commit",
            Work::PolicyApproval(Box::new(c.request.clone())),
        )?;
        let mut host = reopen(&c.base.path)?;
        let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
        host.extend_enrollment_credential(
            &token,
            &CredentialExtensionRequest {
                request_id: crate::enrollment::random()?,
                enrollment: c.base.invitation.operation,
                previous_extension: c.request.current_extension,
                predecessor: c.request.retained.scope.current_roster,
                valid_until: c.base.invitation.valid_until + 7200,
            },
        )?;
        assert!(host.issue_policy_approval(&token, &c.request).is_err());
        assert!(matches!(
            host.policy_approval_status(&token, &c.request)?,
            PolicyApprovalStatus::Pending { .. }
        ));
        drop(host);
        kill_at(
            &c.base.path,
            boundary,
            Work::CancelPolicyApproval(Box::new(c.request.clone())),
        )?;
        let mut host = reopen(&c.base.path)?;
        let (token, _) = login(&mut host, &mut c.base.auth, "alice")?;
        if boundary.ends_with("after-commit") {
            assert!(matches!(
                host.policy_approval_status(&token, &c.request)?,
                PolicyApprovalStatus::Closed
            ));
        }
        host.cancel_policy_approval(&token, &c.request)?;
        assert!(matches!(
            host.issue_policy_approval(&token, &c.request),
            Err(Error::Conflict("Original policy approval is closed"))
        ));
    }
    Ok(())
}
