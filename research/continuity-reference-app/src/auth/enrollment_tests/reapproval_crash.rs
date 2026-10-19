// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{
    crash::{kill_at, Work},
    *,
};

#[test]
fn reapproval_schema_upgrade_crashes_preserve_original_records_and_explicit_admission() -> Result {
    for boundary in [
        "reapproval-upgrade-before-commit",
        "reapproval-upgrade-after-commit",
    ] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        host.prepare_enrollment_root(&session)?;
        let invitation = host.invite_enrollment(&session, crate::enrollment::random()?)?;
        let (_, wire) = request(&path, &invitation)?;
        host.approve_enrollment(&session, invitation.operation, &wire)?;
        let original = host.enrollment_status(&session, invitation.operation)?;
        let account = serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?;
        drop(host);
        kill_at(&path, boundary, Work::ReapprovalUpgrade)?;
        let mut host = reopen(&path)?;
        assert_eq!(
            serde_json::to_vec(&host.store.account("alice")?.ok_or("account")?)?,
            account
        );
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        assert_eq!(
            host.enrollment_status(&session, invitation.operation)?,
            original
        );
        let correlation = crate::enrollment::random()?;
        if boundary == "reapproval-upgrade-before-commit" {
            assert!(host
                .reapprove_enrollment(&session, invitation.operation, correlation, None, &wire)
                .is_err());
        }
        host.store.enable_enrollment_reapproval()?;
        let next =
            host.reapprove_enrollment(&session, invitation.operation, correlation, None, &wire)?;
        let result: IssuedEnrollment =
            serde_json::from_slice(&host.issue_enrollment(&session, next.operation)?)?;
        verify(&host.enrollment_root(&session)?, &result)?;
    }
    Ok(())
}

#[test]
fn reapproval_kill_reconciles_one_signer_reservation_and_exact_successor_without_client_reset(
) -> Result {
    for boundary in ["reapproval-before-commit", "reapproval-after-commit"] {
        let (dir, mut host) = service()?;
        let path = dir.path().canonicalize()?;
        let mut auth = authenticator();
        register(&mut host, &mut auth, "alice")?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        host.store.enable_enrollment([42; 32])?;
        host.store.enable_enrollment_reapproval()?;
        host.prepare_enrollment_root(&session)?;
        let invitation = host.invite_enrollment(&session, crate::enrollment::random()?)?;
        let (paths, wire) = request(&path, &invitation)?;
        host.approve_enrollment(&session, invitation.operation, &wire)?;
        let correlation = crate::enrollment::random()?;
        let input = (invitation.operation, correlation, None, wire.clone());
        drop(host);
        let candidate: Invitation =
            serde_json::from_slice(&kill_at(&path, boundary, Work::Reapprove(input))?)?;
        let mut host = reopen(&path)?;
        let (session, _) = login(&mut host, &mut auth, "alice")?;
        if boundary == "reapproval-before-commit" {
            assert!(matches!(
                host.enrollment_status(&session, invitation.operation)?,
                EnrollmentStatus::Approved { .. }
            ));
            assert!(host
                .enrollment_status(&session, candidate.operation)
                .is_err());
        } else {
            assert!(
                matches!(host.enrollment_status(&session, invitation.operation)?, EnrollmentStatus::Reapproved { successor } if successor == candidate)
            );
        }
        let next =
            host.reapprove_enrollment(&session, invitation.operation, correlation, None, &wire)?;
        if boundary == "reapproval-after-commit" {
            assert_eq!(next, candidate);
        }
        assert_eq!(
            host.reapprove_enrollment(&session, invitation.operation, correlation, None, &wire)?,
            next
        );
        assert!(host
            .reapprove_enrollment(
                &session,
                invitation.operation,
                crate::enrollment::random()?,
                None,
                &wire
            )
            .is_err());
        let mut client = sdk::DeviceEnrollment::open(paths, invitation.intent()?)?;
        assert_eq!(client.request(crate::enrollment::now()?)?, wire);
        client.close();
        let bytes = host.issue_enrollment(&session, next.operation)?;
        assert_eq!(host.issue_enrollment(&session, next.operation)?, bytes);
        let issued: IssuedEnrollment = serde_json::from_slice(&bytes)?;
        assert_eq!(issued.checkpoint.version, 1);
        verify(&host.enrollment_root(&session)?, &issued)?;
        assert!(host
            .issue_enrollment(&session, invitation.operation)
            .is_err());
    }
    Ok(())
}
