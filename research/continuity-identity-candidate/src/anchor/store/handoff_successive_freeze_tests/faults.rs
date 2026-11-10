// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::Ordering;

fn prepared(cancel: bool) -> (Prepared, AnchorHandoffSourceState, AnchorHandoffPlan) {
    let mut f = Prepared::new(Some(("G", false)));
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("current authorization");
    let (snapshot, plan) = next_plan(&mut f.active, 244);
    if cancel {
        f.active
            .freeze_handoff(&plan, 180)
            .expect("already committed source freeze");
    }
    f.active.close();
    (f, snapshot, plan)
}
fn action(
    f: &mut Prepared,
    plan: &AnchorHandoffPlan,
    cancel: bool,
) -> Result<AnchorHandoffReceipt, DurableError> {
    if cancel {
        f.active.cancel_handoff(plan)
    } else {
        f.active.freeze_handoff(plan, 180)
    }
}

#[test]
fn successive_source_control_sync_failures_keep_primary_index_and_decision_atomic(
) -> Result<(), Box<dyn std::error::Error>> {
    for cancel in [false, true] {
        let (mut f, _, plan) = prepared(cancel);
        let (db, _, count, _) = fault_database_path(&f.f.db_path(), false);
        f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
            .expect("calibration target")
            .activate(&f.retired, f.f.signer())
            .expect("same activation")
            .0;
        count.store(0, Ordering::SeqCst);
        action(&mut f, &plan, cancel).expect("calibrate exact transaction");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        count.store(0, Ordering::SeqCst);
        f.active.close();
        let close_syncs = count.load(Ordering::SeqCst);
        for after in [false, true] {
            for cut in 1..=barriers {
                let (mut f, snapshot, plan) = prepared(cancel);
                let (db, remaining, _, _) = fault_database_path(&f.f.db_path(), after);
                f.active = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
                    .expect("fault target")
                    .activate(&f.retired, f.f.signer())
                    .expect("same activation")
                    .0;
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    action(&mut f, &plan, cancel).map(|_| ()),
                    after,
                );
                assert_eq!(
                    remaining.load(Ordering::SeqCst),
                    0,
                    "exact calibrated cut must execute"
                );
                assert!(matches!(f.active.pin(), Err(DurableError::Closed)));
                f.reopen();
                let observed = match f.active.observe_handoff(&plan) {
                    Ok(receipt) => Some(receipt),
                    Err(DurableError::Absent) if !cancel => None,
                    Err(error) => {
                        return Err(format!("cannot recover original transaction: {error:?}").into())
                    }
                };
                let receipt =
                    action(&mut f, &plan, cancel).expect("same plan, never replacement state");
                if let Some(old) = observed {
                    if old.state() == receipt.state() {
                        assert_eq!(old.as_bytes(), receipt.as_bytes());
                    }
                }
                if !cancel {
                    assert_eq!(receipt.state(), AnchorHandoffState::Frozen);
                    assert_eq!(
                        f.active
                            .frozen_handoff_state(&plan)
                            .expect("exact complete source")
                            .as_bytes(),
                        snapshot.as_bytes()
                    );
                    f.active
                        .cancel_handoff(&plan)
                        .expect("still independently cancellable");
                } else {
                    assert_eq!(receipt.state(), AnchorHandoffState::Cancelled);
                }
                f.reopen();
                assert_eq!(
                    f.active
                        .observe_handoff(&plan)
                        .expect("no forgotten source decision")
                        .state(),
                    AnchorHandoffState::Cancelled
                );
                assert_eq!(
                    f.active
                        .handoff_client_authorization(f.c.subject)
                        .expect("same client proof")
                        .scope(),
                    f.approved.scope()
                );
            }
        }
        eprintln!("SUCCESSIVE_SOURCE_SYNC cancel={cancel} barriers={barriers} faults={} close_syncs={close_syncs}", barriers*2);
    }
    Ok(())
}
