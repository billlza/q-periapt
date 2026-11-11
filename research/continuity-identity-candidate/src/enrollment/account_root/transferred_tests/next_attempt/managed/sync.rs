// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_next_managed_registry_sync_faults_close_controller_and_reconcile_exact_attempt() {
    for phase in 0..=2 {
        let (c, plan) = process::case(Work::Credential(1), phase);
        let mut registry = c.s.recovery.open(&c.s.t.f);
        let backup = crate::account_authority::tests::snapshot_registry(&registry);
        registry.close();
        let parent = fs::read(&c.s.t.f.original.paths.configuration).expect("original parent");
        let child =
            fs::read(c.s.t.f.original.paths.installation.files()[1]).expect("original child");
        let before = retained(&c.s.t.f.original.paths);
        let apply = |after, cut| {
            let mut registry = c.s.recovery.open(&c.s.t.f);
            let (remaining, count) = crate::account_authority::tests::fault_database(
                &mut registry,
                &c.s.recovery.path,
                after,
            );
            if phase == 0 {
                remaining.store(cut, Ordering::SeqCst);
                count.store(0, Ordering::SeqCst);
                (
                    ManagedAccountRootReplacement::begin_transferred(
                        registry,
                        c.s.recovery.expected,
                        plan.clone(),
                        c.s.t.f.original.paths.clone(),
                        c.s.t.f.original.intent.clone(),
                    ),
                    count,
                )
            } else {
                let mut owner = ManagedAccountRootReplacement::resume_transferred_original(
                    registry,
                    c.s.recovery.expected,
                    plan.clone(),
                    c.s.t.f.original.paths.clone(),
                    c.s.t.f.original.intent.clone(),
                )
                .expect("original managed pre-operation");
                remaining.store(cut, Ordering::SeqCst);
                count.store(0, Ordering::SeqCst);
                let result = if phase == 1 {
                    owner
                        .bind_transferred_freeze(&c.s.t.frozen, c.next.approval.clone())
                        .map(|_| ())
                } else {
                    owner
                        .retain_transferred_decision(
                            c.wire.as_deref().expect("original exact next receipt"),
                        )
                        .map(|_| ())
                };
                if result.is_err() {
                    assert!(matches!(owner.state(), Err(DurableError::Closed)));
                }
                (result.map(|_| owner), count)
            }
        };
        let (owner, count) = apply(false, usize::MAX);
        let mut owner = owner.expect("calibrate exact registry transaction");
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        let close_syncs = count.load(Ordering::SeqCst) - barriers;
        assert!((2..=8).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                crate::account_authority::tests::restore_registry_snapshot(
                    &c.s.recovery.path,
                    &backup,
                );
                fs::write(&c.s.t.f.original.paths.configuration, &parent)
                    .expect("restore same owned parent");
                fs::write(c.s.t.f.original.paths.installation.files()[1], &child)
                    .expect("restore same owned child");
                let (result, _) = apply(after, cut);
                crate::durable::tests::assert_sync_failure(result.map(|_| ()), after);
                let mut owner = if phase == 0 {
                    ManagedAccountRootReplacement::begin_transferred(
                        c.s.recovery.open(&c.s.t.f),
                        c.s.recovery.expected,
                        plan.clone(),
                        c.s.t.f.original.paths.clone(),
                        c.s.t.f.original.intent.clone(),
                    )
                    .expect("same prepare after unknown commit")
                } else {
                    resume(&c.s, &plan).expect("exact same next controller")
                };
                let expected = if phase == 0 {
                    State::Preparing
                } else if phase == 1 {
                    owner
                        .bind_transferred_freeze(&c.s.t.frozen, c.next.approval.clone())
                        .expect("exact bind retry");
                    State::Pending
                } else {
                    owner
                        .retain_transferred_decision(c.wire.as_deref().expect("same next outcome"))
                        .expect("exact outcome retry");
                    State::Committed
                };
                assert_eq!(owner.state().expect("exact durable state"), expected);
                owner.close();
                assert!(retained(&c.s.t.f.original.paths) == before);
            }
        }
        eprintln!("TRANSFERRED_MANAGED_NEXT_SYNC phase={phase} barriers={barriers} close_syncs={close_syncs} faults={}",2*barriers);
    }
}
