// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn successive_retirement_sync_failures_reconcile_exact_decision_and_original_p() {
    for archived in [false, true] {
        let mut f = RecoveryCase::new(archived);
        f.active.close();
        let (db, _, count, _) = fault_database_path(&f.source.db_path(), false);
        f.active =
            AnchorHandoffTarget::from_database(db, f.source.key(), f.source.approval.clone())
                .expect("fault-capable original source")
                .activate(&f.prior_retirement, f.source.signer())
                .expect("original source activation")
                .0;
        count.store(0, Ordering::SeqCst);
        f.retire();
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        count.store(0, Ordering::SeqCst);
        f.active.close();
        let close_syncs = count.load(Ordering::SeqCst);
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut f = RecoveryCase::new(archived);
                f.active.close();
                let (db, remaining, _, _) = fault_database_path(&f.source.db_path(), after);
                f.active = AnchorHandoffTarget::from_database(
                    db,
                    f.source.key(),
                    f.source.approval.clone(),
                )
                .expect("original source")
                .activate(&f.prior_retirement, f.source.signer())
                .expect("original activation")
                .0;
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    f.active
                        .retire_handoff(&f.next.approval, &f.acknowledgement, || Ok(f.next.now))
                        .map(|_| ()),
                    after,
                );
                assert_eq!(
                    remaining.load(Ordering::SeqCst),
                    0,
                    "selected fault consumed"
                );
                assert!(matches!(f.active.pin(), Err(DurableError::Closed)));
                f.reopen_source();
                let observed = f
                    .active
                    .observe_handoff(&f.next.plan)
                    .expect("actual original decision");
                assert!(matches!(
                    observed.state(),
                    AnchorHandoffState::Frozen | AnchorHandoffState::Retired
                ));
                let receipt = f.retire();
                if observed.state() == AnchorHandoffState::Retired {
                    assert_eq!(observed.as_bytes(), receipt.as_bytes());
                }
                f.finish(&receipt, None);
            }
        }
        eprintln!("SUCCESSIVE_RETIREMENT_SYNC archived={archived} barriers={barriers} faults={} close_syncs={close_syncs}", barriers * 2);
    }
}

#[test]
fn successive_activation_sync_failures_reconcile_exact_receipt_and_original_p() {
    for archived in [false, true] {
        let mut f = RecoveryCase::new(archived);
        let retirement = f.retire();
        let (db, _, count, _) = fault_database_path(&f.next.db_path(), false);
        let mut target =
            AnchorHandoffTarget::from_database(db, f.next.key(), f.next.approval.clone())
                .expect("calibration target");
        count.store(0, Ordering::SeqCst);
        let (mut active, _) = target
            .activate(retirement.as_bytes(), f.next.signer())
            .expect("calibrate");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        count.store(0, Ordering::SeqCst);
        active.close();
        let close_syncs = count.load(Ordering::SeqCst);
        for after in [false, true] {
            for cut in 1..=barriers {
                let mut f = RecoveryCase::new(archived);
                let retirement = f.retire();
                let (db, remaining, _, _) = fault_database_path(&f.next.db_path(), after);
                let mut target =
                    AnchorHandoffTarget::from_database(db, f.next.key(), f.next.approval.clone())
                        .expect("original target");
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    target
                        .activate(retirement.as_bytes(), f.next.signer())
                        .map(|_| ()),
                    after,
                );
                assert_eq!(
                    remaining.load(Ordering::SeqCst),
                    0,
                    "selected fault consumed"
                );
                assert!(matches!(target.status(), Err(DurableError::Closed)));
                let mut target = f.next.open();
                let prior = match target.status().expect("actual original target state") {
                    AnchorHandoffTargetState::Activated => Some(
                        target
                            .activation_receipt()
                            .expect("exact retained certificate")
                            .as_bytes()
                            .to_vec(),
                    ),
                    other => {
                        assert_eq!(
                            other,
                            AnchorHandoffTargetState::ImportedInactive,
                            "activation failure cannot cancel the target"
                        );
                        None
                    }
                };
                target.close();
                f.finish(&retirement, prior.as_deref());
            }
        }
        eprintln!("SUCCESSIVE_ACTIVATION_SYNC archived={archived} barriers={barriers} faults={} close_syncs={close_syncs}", barriers * 2);
    }
}
