// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Account-wide independent approval cannot be replaced by one adopted device.
use super::*;
#[path = "handoff_account_freeze_tests/coverage.rs"]
mod coverage;
#[path = "handoff_account_freeze_tests/recovery.rs"]
mod recovery;

fn approval(f: &mut Prepared, seed: u8) -> AnchorTransferredAccountFreezeApproval {
    let request = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([seed; 32]).expect("operation"),
        f.c.account
            .public_key()
            .expect("original independently pinned account"),
        &f.f.pin,
    )
    .expect("independent current Witness");
    assert!(matches!(
        f.active.freeze_account(&request),
        Err(DurableError::Suspended)
    ));
    let proposal = f
        .active
        .transferred_account_freeze_proposal(&request, &f.history)
        .expect("whole-account observation");
    let approved = AnchorTransferredAccountFreezeApproval::from_trusted_state(
        proposal,
        &request,
        &f.history,
        [seed.wrapping_add(1); 32],
        Validity::new(180, 190).expect("operator validity"),
    )
    .expect("independent account recovery authorization");
    let restored = AnchorTransferredAccountFreezeApproval::restore_trusted_state(
        &approved.to_bytes().expect("retain approval"),
        &request,
        &f.history,
    )
    .expect("exact independently retained inputs");
    assert_eq!(approved, restored);
    approved
}

#[test]
fn transferred_account_freeze_retains_unadopted_pending_gpr_and_exact_proof() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let mut f = Prepared::new(Some((kind, applied)));
            let old = f.original_entry();
            let approved = approval(&mut f, 201);
            let before = fs::read(f.f.db_path()).expect("original bytes");
            assert!(matches!(
                f.active.transferred_account_freeze_receipt(&approved),
                Err(DurableError::Absent)
            ));
            assert_eq!(fs::read(f.f.db_path()).expect("read only"), before);
            let mut calls = 0;
            let wire = f
                .active
                .freeze_transferred_account(&approved, || {
                    calls += 1;
                    Ok(180)
                })
                .expect("signed proof and freeze committed together");
            assert_eq!(calls, 2);
            let frozen = approved
                .verify_receipt(&f.history, &wire)
                .expect("independent verification");
            assert_eq!(frozen.subjects().count(), 1);
            assert_eq!(f.original_entry(), old);
            assert!(matches!(
                f.active.authorize_handoff_client(&f.request, || Ok(180)),
                Err(DurableError::Protocol(Error::Retired))
            ));
            assert!(f
                .active
                .account_freeze_receipt(approved.proposal().request())
                .is_err());
            let before = fs::read(f.f.db_path()).expect("committed database");
            let mut retry_time_calls = 0;
            assert_eq!(
                f.active
                    .freeze_transferred_account(&approved, || {
                        retry_time_calls += 1;
                        Err(DurableError::Conflict)
                    })
                    .expect("exact retry"),
                wire
            );
            assert_eq!(
                retry_time_calls, 0,
                "historical retry must not consult clock"
            );
            assert_eq!(
                fs::read(f.f.db_path()).expect("no rewrite or resign"),
                before
            );
            let capture = f
                .active
                .handoff_source_state()
                .expect("complete source with proof");
            f.reopen();
            assert_eq!(
                f.active
                    .transferred_account_freeze_receipt(&approved)
                    .expect("cold verified proof"),
                wire
            );
            assert_eq!(f.original_entry(), old);
            assert_eq!(
                f.active
                    .handoff_source_state()
                    .expect("same complete capture")
                    .as_bytes(),
                capture.as_bytes()
            );
            for offset in [8, 8 + 32, wire.len() - 1] {
                let mut bad = wire.clone();
                *bad.get_mut(offset).expect("bounded proof field") ^= 1;
                assert!(approved.verify_receipt(&f.history, &bad).is_err());
            }
        }
    }
}

#[test]
fn transferred_account_freeze_checks_both_times_and_preserves_original_on_refusal() {
    for times in [[179, 180], [180, 190], [181, 180]] {
        let mut f = Prepared::new(None);
        let approved = approval(&mut f, 203);
        let original = f.original_entry();
        let mut times = times.into_iter();
        assert!(f
            .active
            .freeze_transferred_account(&approved, || Ok(times.next().expect("at most two checks")))
            .is_err());
        f.reopen();
        assert_eq!(f.original_entry(), original);
        assert!(matches!(
            f.active.transferred_account_freeze_receipt(&approved),
            Err(DurableError::Absent)
        ));
        f.active
            .freeze_transferred_account(&approved, || Ok(180))
            .expect("same original approval after noncommit");
    }
}

#[test]
fn transferred_account_freeze_cannot_use_an_unrelated_history_or_approval() {
    let mut f = Prepared::new(None);
    let approved = approval(&mut f, 205);
    let request = approved.proposal().request();
    let mut bytes = approved.to_bytes().expect("approval");
    *bytes.get_mut(8 + 32).expect("retained history checkpoint") ^= 1;
    assert!(
        AnchorTransferredAccountFreezeApproval::restore_trusted_state(&bytes, request, &f.history)
            .is_err()
    );
    assert!(f
        .active
        .transferred_account_freeze_proposal(
            request,
            &AnchorHandoffHistory::from_trusted_origin(f.c.pin.clone())
        )
        .is_err());
    let second = approval(&mut f, 207);
    let wire = f
        .active
        .freeze_transferred_account(&approved, || Ok(180))
        .expect("first exact approval");
    assert!(second.verify_receipt(&f.history, &wire).is_err());
    assert!(f
        .active
        .freeze_transferred_account(&second, || Ok(180))
        .is_err());
    assert_eq!(
        f.active
            .transferred_account_freeze_receipt(&approved)
            .expect("original decision retained"),
        wire
    );
}
