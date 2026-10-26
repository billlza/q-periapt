// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority::tests::{fault_database, restore_registry_snapshot};

fn setup(phase: u8, closed: bool) -> (Transferred, Vec<u8>) {
    let mut t = Transferred::with_controller(Some(2), 2);
    let mut owner = t
        .controller
        .take()
        .expect("actual original pre-freeze preparation");
    if phase == 2 {
        owner
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("bound original intent");
    }
    owner.close();
    if phase == 0 {
        // Initial fixture already proves local preparation precedes remote freeze.
        // Replaying its exact pre-prepare registry isolates first-write failures.
        restore_registry_snapshot(
            &t.registry_recovery.as_ref().expect("registry").path,
            t.registry_before
                .as_ref()
                .expect("exact original pre-prepare image"),
        );
    }
    let wire = t.decide(closed).as_bytes().to_vec();
    (t, wire)
}
fn perform(
    t: &Transferred,
    registry: AccountAuthorityStore,
    phase: u8,
    wire: &[u8],
) -> Result<ManagedAccountRootReplacement, DurableError> {
    let expected = t
        .registry_recovery
        .as_ref()
        .expect("original registry expectation")
        .expected;
    if phase == 0 {
        return ManagedAccountRootReplacement::begin_transferred(
            registry,
            expected,
            context(t),
            t.f.original.paths.clone(),
            t.f.original.intent.clone(),
        );
    }
    let mut owner = ManagedAccountRootReplacement::resume_transferred_original(
        registry,
        expected,
        context(t),
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
    )?;
    match phase {
        1 => {
            owner.bind_transferred_freeze(&t.frozen, t.approval.clone())?;
        }
        2 => {
            owner.retain_transferred_decision(wire)?;
        }
        _ => return Err(DurableError::Corrupt),
    }
    Ok(owner)
}
#[test]
fn transferred_managed_sync_errors_close_all_leases_and_reconcile_original_commits() {
    let mut total = 0;
    for closed in [false, true] {
        for phase in 0..=2 {
            let (t, wire) = setup(phase, closed);
            let recovery = t.registry_recovery.as_ref().expect("original registry");
            let mut registry = recovery.open(&t.f);
            let (_, count) = fault_database(&mut registry, &recovery.path, false);
            count.store(0, Ordering::SeqCst);
            let mut owner =
                perform(&t, registry, phase, &wire).expect("measure actual managed commit");
            let barriers = count.load(Ordering::SeqCst);
            assert!((1..=8).contains(&barriers));
            owner.close();
            for after in [false, true] {
                for cut in 1..=barriers {
                    let (t, wire) = setup(phase, closed);
                    let rows = journal_rows(&t);
                    let recovery = t
                        .registry_recovery
                        .as_ref()
                        .expect("same original registry");
                    let mut registry = recovery.open(&t.f);
                    let access = registry.access().expect("original revocable capability");
                    let (remaining, _) = fault_database(&mut registry, &recovery.path, after);
                    remaining.store(cut, Ordering::SeqCst);
                    crate::durable::tests::assert_sync_failure(
                        perform(&t, registry, phase, &wire),
                        after,
                    );
                    assert_eq!(
                        remaining.load(Ordering::SeqCst),
                        0,
                        "actual selected sync failed"
                    );
                    assert!(matches!(
                        access.current(recovery.expected.application()),
                        Err(DurableError::Closed)
                    ));
                    let mut owner = perform(&t, recovery.open(&t.f), phase, &wire)
                        .expect("same original operation after unknown commit");
                    owner
                        .bind_transferred_freeze(&t.frozen, t.approval.clone())
                        .expect("same exact binding");
                    let expected = if closed {
                        State::Closed
                    } else {
                        State::Committed
                    };
                    assert_eq!(
                        owner
                            .retain_transferred_decision(&wire)
                            .expect("same exact result"),
                        expected
                    );
                    owner.close();
                    assert!(
                        journal_rows(&t) == rows,
                        "original sealed image, pending and selection unchanged"
                    );
                    let mut observer = resume(&t).expect("cold exact durable outcome");
                    assert_eq!(observer.state().expect("same outcome"), expected);
                    observer.close();
                    total += 1;
                    eprintln!("TRANSFERRED_MANAGED_SYNC phase={phase} closed={closed} after={after} cut={cut} barriers={barriers} same_original=true");
                }
            }
        }
    }
    assert!(
        total >= 12,
        "all measured before/after barriers executed for both outcomes"
    );
}
