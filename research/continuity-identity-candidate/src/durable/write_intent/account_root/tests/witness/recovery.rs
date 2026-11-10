// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn prepare_fault(
    f: &Ready,
    after: bool,
    cut: usize,
) -> (
    Result<AccountRootJournalRecovery, DurableError>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(&f.c.path(), after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    let result = AccountRootJournalRecovery::prepare_transferred_database(
        db,
        f.c.key(),
        bootstrap::storage_owner(&f.c.device),
        f.c.identity,
        f.plan.clone(),
    );
    (result, count)
}

#[test]
fn transferred_root_journal_sync_failures_preserve_exact_secrets_selection_and_decision() {
    for receipt in [false, true] {
        for closed in [false, true] {
            let mut f = Ready::new();
            let outcome = f.decide(closed);
            let barriers = if receipt {
                let mut owner = f.open().expect("calibration fence");
                let (_, count) = fault_recovery(&mut owner, &f.c.path(), false);
                count.store(0, Ordering::SeqCst);
                owner
                    .retain_account_decision(outcome.as_bytes())
                    .expect("receipt calibration");
                let n = count.load(Ordering::SeqCst);
                owner.close();
                n
            } else {
                let (owner, count) = prepare_fault(&f, false, 0);
                let mut owner = owner.expect("fence calibration");
                let n = count.load(Ordering::SeqCst);
                owner.close();
                n
            };
            assert!((2..=8).contains(&barriers));
            for after in [false, true] {
                for cut in 1..=barriers {
                    let mut f = Ready::new();
                    let old = f.c.original_rows();
                    let selected = control(&f.c);
                    let outcome = f.decide(closed);
                    if receipt {
                        let mut owner = f.open().expect("original fence");
                        let (remaining, _) = fault_recovery(&mut owner, &f.c.path(), after);
                        remaining.store(cut, Ordering::SeqCst);
                        crate::durable::tests::assert_sync_failure(
                            owner.retain_account_decision(outcome.as_bytes()),
                            after,
                        );
                        assert!(matches!(owner.status(), Err(DurableError::Closed)));
                    } else {
                        let (result, _) = prepare_fault(&f, after, cut);
                        crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
                    }
                    assert_eq!(f.c.original_rows(), old);
                    assert_eq!(control(&f.c), selected);
                    let mut recovered = f.open().expect("same exact authority and original store");
                    let state = if closed {
                        AccountRootJournalState::WitnessClosed
                    } else {
                        AccountRootJournalState::WitnessCommitted
                    };
                    assert_eq!(
                        recovered
                            .retain_account_decision(outcome.as_bytes())
                            .expect("original receipt reconciliation"),
                        state
                    );
                    assert_eq!(
                        recovered
                            .account_decision()
                            .expect("no resigned result")
                            .as_bytes(),
                        outcome.as_bytes()
                    );
                    recovered.close();
                    let mut cold = f.open().expect("cold same original");
                    assert_eq!(cold.status().expect("exact outcome"), state);
                    cold.close();
                    assert_eq!(f.c.original_rows(), old);
                    assert_eq!(control(&f.c), selected);
                }
            }
            eprintln!("TRANSFERRED_ROOT_SYNC receipt={receipt} closed={closed} barriers={barriers} faults={}", barriers * 2);
        }
    }
}
