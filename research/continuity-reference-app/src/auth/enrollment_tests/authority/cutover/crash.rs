// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual process-kill coverage for original root selection.
use super::super::super::crash::{kill_at, Work};
use super::*;

#[test]
fn cutover_approval_and_commit_process_kills_reconcile_original_account_and_target() -> Result {
    for boundary in [
        "root-cutover-approved",
        "root-cutover-native-prepared",
        "root-cutover-retirement-retained",
        "root-cutover-native-retired",
        "root-cutover-host-before-commit",
        "root-cutover-host-committed",
    ] {
        let mut c = Case::new()?;
        associate(&mut c)?;
        let t = Target::new(&mut c)?;
        let approval = matches!(
            boundary,
            "root-cutover-approved" | "root-cutover-native-prepared"
        );
        let proof = if approval {
            None
        } else {
            c.host.approve_account_root(&c.token, &t.input)?;
            Some(t.retirement(&c)?)
        };
        let account =
            serde_json::to_vec(&c.host.store.account("alice")?.ok_or("original account")?)?;
        let keys = super::super::super::root_preparation::keys(&c.path)?;
        drop(c.host);
        let marker = kill_at(
            &c.path,
            boundary,
            if let Some(proof) = &proof {
                Work::CommitRoot(t.trust.operation, Box::new(proof.clone()))
            } else {
                Work::ApproveRoot(Box::new(t.input.clone()))
            },
        )?;
        assert_eq!(marker, t.trust.operation);
        c.host = reopen(&c.path)?;
        assert_eq!(
            serde_json::to_vec(&c.host.store.account("alice")?.ok_or("retained account")?)?,
            account
        );
        c.token = login(&mut c.host, &mut c.auth, "alice")?.0;
        let selected = boundary == "root-cutover-host-committed";
        assert_eq!(
            c.host.enrollment_root(&c.token)?,
            if selected {
                t.root.clone()
            } else {
                RootInfo {
                    suspended: true,
                    ..c.root.clone()
                }
            }
        );
        if !selected {
            assert!(matches!(
                c.host
                    .invite_enrollment(&c.token, crate::enrollment::random()?),
                Err(Error::Conflict(_))
            ));
        }
        if approval {
            assert_eq!(
                c.host
                    .resume_account_root(&c.token, t.trust.operation)?
                    .status,
                CutoverStatus::AwaitingOutcome
            );
            let retired = t.retirement(&c)?;
            c.host
                .commit_account_root(&c.token, t.trust.operation, &retired)?;
        } else {
            assert!(matches!(
                c.host
                    .resume_account_root(&c.token, t.trust.operation)?
                    .status,
                CutoverStatus::Committed { .. }
            ));
        }
        assert_eq!(c.host.enrollment_root(&c.token)?, t.root);
        assert_eq!(
            c.host.retired_account_root(&c.token, c.root.revision)?,
            RootInfo {
                suspended: true,
                ..c.root.clone()
            }
        );
        assert_eq!(
            c.host
                .invite_enrollment(&c.token, crate::enrollment::random()?)?
                .root,
            t.root.public_key
        );
        assert_eq!(
            c.host.issue_enrollment(&c.token, t.invitation.operation)?,
            t.issued
        );
        super::super::super::root_preparation::unchanged(&keys)?;
    }
    Ok(())
}

#[test]
fn cutover_closure_process_kills_preserve_noncommit_and_old_root_suspension() -> Result {
    for boundary in [
        "root-cutover-closure-retained",
        "root-cutover-native-closed",
        "root-cutover-close-before-commit",
        "root-cutover-closed",
    ] {
        let mut c = Case::new()?;
        associate(&mut c)?;
        let t = Target::new(&mut c)?;
        c.host.approve_account_root(&c.token, &t.input)?;
        witness(&c)?.freeze_account_root(&t.input.plan)?;
        let AccountRootOutcome::Closed { receipt, .. } =
            witness(&c)?.close_account_root_plan(&t.input.plan)?
        else {
            return Err("closed plan".into());
        };
        let keys = super::super::super::root_preparation::keys(&c.path)?;
        drop(c.host);
        assert_eq!(
            kill_at(
                &c.path,
                boundary,
                Work::CloseRoot(t.trust.operation, receipt.clone())
            )?,
            t.trust.operation
        );
        c.host = reopen(&c.path)?;
        c.token = login(&mut c.host, &mut c.auth, "alice")?.0;
        assert_eq!(
            c.host
                .resume_account_root(&c.token, t.trust.operation)?
                .status,
            CutoverStatus::Closed
        );
        assert_eq!(
            c.host
                .close_account_root(&c.token, t.trust.operation, &receipt)?
                .status,
            CutoverStatus::Closed
        );
        assert_eq!(
            c.host.enrollment_root(&c.token)?,
            RootInfo {
                suspended: true,
                ..c.root.clone()
            }
        );
        assert!(matches!(
            c.host
                .invite_enrollment(&c.token, crate::enrollment::random()?),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            c.host.retired_account_root(&c.token, c.root.revision),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            c.host.issue_enrollment(&c.token, t.invitation.operation)?,
            t.issued
        );
        super::super::super::root_preparation::unchanged(&keys)?;
    }
    Ok(())
}
