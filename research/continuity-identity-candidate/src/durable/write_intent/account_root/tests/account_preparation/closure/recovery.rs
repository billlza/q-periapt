// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
fn at_cut(cut: usize, after: bool) -> usize {
    let mut p = Prepared::new();
    p.registry
        .begin_preparation(p.expected, p.plan.clone())
        .expect("original intent");
    let frozen = p.frozen();
    p.registry
        .bind_preparation(p.plan.operation(), &frozen)
        .expect("original authenticated freeze");
    let closed = close_plan(&p);
    let access = p.registry.access().expect("original alias");
    let path =
        p.c.path
            .parent()
            .expect("original root")
            .join("authority.redb");
    let (remaining, count) =
        crate::account_authority::tests::fault_database(&mut p.registry, &path, after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    let result = p.registry.close_preparation(&closed);
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        assert_eq!(result.expect("calibrate actual barriers"), State::Closed);
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert!(matches!(
            access.current(p.other.application()),
            Err(DurableError::Closed)
        ));
    }
    p.reopen();
    assert!(matches!(
        p.registry
            .preparation(p.plan.operation())
            .expect("same original plan")
            .1,
        State::Pending | State::Closed
    ));
    assert!(matches!(
        p.registry
            .access()
            .expect("recovered owner")
            .current(p.expected.application()),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.registry
            .close_preparation(&closed)
            .expect("retry exact original closure"),
        State::Closed
    );
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("exact original history")
            .2,
        &p.plan
    );
    assert_eq!(
        p.registry
            .access()
            .expect("owner")
            .current(p.other.application())
            .expect("unrelated account"),
        p.other
    );
    barriers
}
#[test]
fn account_closure_local_terminal_sync_faults_never_restore_old_authority() {
    let barriers = at_cut(0, false);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            at_cut(cut, after);
        }
    }
    eprintln!(
        "ACCOUNT_CLOSURE_REGISTRY_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}
