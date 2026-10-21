// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A host intent can precede both native preparation and witness freeze.
use super::super::super::crash::{kill_at, Work};
use super::*;

fn registry(c: &mut Case) -> Result<sdk::AccountAuthorityStore> {
    let association = c.host.account_authority(&c.token)?;
    let files = authority_files(&c.path)?;
    let database = files
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == "redb"))
        .ok_or("original authority registry")?;
    let stem = database
        .file_stem()
        .and_then(|p| p.to_str())
        .ok_or("original registry stem")?;
    let identity = URL_SAFE_NO_PAD
        .decode(
            stem.strip_prefix("authority-")
                .ok_or("original registry name")?,
        )?
        .try_into()
        .map_err(|_| "registry identity length")?;
    Ok(sdk::AccountAuthorityStore::open(
        database,
        sdk::JournalKey::open(&database.with_extension("wrap"))?,
        sdk::AccountAuthorityIdentity::from_trusted_state(identity)?,
        c.root.family,
        association.witness.as_sdk()?,
    )?)
}

#[test]
fn original_unfrozen_plan_closure_fences_native_authority_after_each_preparation_cut() -> Result {
    for (boundary, interrupt_closure) in [
        ("root-cutover-approved", false),
        ("root-cutover-native-prepared", false),
        ("root-cutover-approved", true),
    ] {
        let mut c = Case::new()?;
        associate(&mut c)?;
        let first = Target::new(&mut c)?;
        let keys = super::super::super::root_preparation::keys(&c.path)?;
        drop(c.host);
        kill_at(
            &c.path,
            boundary,
            Work::ApproveRoot(Box::new(first.input.clone())),
        )?;
        c.host = reopen(&c.path)?;
        c.token = login(&mut c.host, &mut c.auth, "alice")?.0;
        let operation = sdk::AnchorAccountReplacementId::from_trusted_state(first.trust.operation)?;
        {
            let owner = registry(&mut c)?;
            if boundary == "root-cutover-approved" {
                assert!(matches!(
                    owner.preparation(operation),
                    Err(sdk::DurableError::Absent)
                ));
            } else {
                assert_eq!(
                    owner.preparation(operation)?.1,
                    sdk::AccountAuthorityReplacementState::Preparing
                );
            }
        }
        assert!(c
            .host
            .close_account_root(&c.token, first.trust.operation, &[])
            .is_err());
        assert_eq!(
            c.host
                .account_root_cutover(&c.token, first.trust.operation)?
                .status,
            CutoverStatus::AwaitingOutcome
        );
        let AccountRootOutcome::Closed { receipt, .. } =
            witness(&c)?.close_account_root_plan(&first.input.plan)?
        else {
            return Err("signed original plan closure".into());
        };
        if interrupt_closure {
            drop(c.host);
            kill_at(
                &c.path,
                "root-cutover-closure-native-prepared",
                Work::CloseRoot(first.trust.operation, receipt.clone()),
            )?;
            c.host = reopen(&c.path)?;
            c.token = login(&mut c.host, &mut c.auth, "alice")?.0;
            assert_eq!(
                c.host
                    .account_root_cutover(&c.token, first.trust.operation)?
                    .status,
                CutoverStatus::Reconciling
            );
            assert_eq!(
                registry(&mut c)?.preparation(operation)?.1,
                sdk::AccountAuthorityReplacementState::Preparing
            );
            assert_eq!(
                c.host
                    .resume_account_root(&c.token, first.trust.operation)?
                    .status,
                CutoverStatus::Closed
            );
        }
        assert_eq!(
            c.host
                .close_account_root(&c.token, first.trust.operation, &receipt)?
                .status,
            CutoverStatus::Closed
        );
        assert!(c.host.enrollment_root(&c.token)?.suspended);
        {
            let owner = registry(&mut c)?;
            let expected = sdk::AccountAuthorityCheckpoint::from_trusted_state(
                sdk::ApplicationAccountId::from_trusted_state(c.original.application)?,
                1,
                c.root.account,
            )?;
            assert!(matches!(owner.access()?.admit(expected),Err(sdk::DurableError::Suspended)),
                "a signed host noncommit must retain the native root fence even before initial preparation");
            assert_eq!(
                owner.preparation(operation)?.1,
                sdk::AccountAuthorityReplacementState::Closed
            );
        }
        // The witness has not frozen. A new independently approved plan retains
        // the original freeze request, so a delayed original freeze cannot fork it.
        let next = Target::prepare(&mut c, Some(Prior::Unfrozen(&first)))?;
        assert_eq!(
            next.input.plan.as_sdk()?.request(),
            first.input.plan.as_sdk()?.request()
        );
        assert_ne!(next.trust.operation, first.trust.operation);
        c.host.approve_account_root(&c.token, &next.input)?;
        let retirement = next.retirement(&c)?;
        c.host
            .commit_account_root(&c.token, next.trust.operation, &retirement)?;
        assert_eq!(c.host.enrollment_root(&c.token)?, next.root);
        assert_eq!(
            c.host
                .close_account_root(&c.token, first.trust.operation, &receipt)?
                .status,
            CutoverStatus::Closed
        );
        assert_eq!(c.host.enrollment_root(&c.token)?, next.root);
        super::super::super::root_preparation::unchanged(&keys)?;
    }
    Ok(())
}
