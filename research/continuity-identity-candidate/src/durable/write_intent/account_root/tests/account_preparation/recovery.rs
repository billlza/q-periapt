// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[derive(Clone, Copy, Debug)]
enum Phase {
    Prepare,
    Bind,
    Commit,
}
fn at_cut(phase: Phase, cut: usize, after: bool) -> usize {
    let mut p = Prepared::new();
    let frozen = match phase {
        Phase::Prepare => None,
        Phase::Bind | Phase::Commit => {
            p.registry
                .begin_preparation(p.expected, p.plan.clone())
                .expect("original local draft before witness");
            Some(p.frozen())
        }
    };
    let retired = if matches!(phase, Phase::Commit) {
        p.registry
            .bind_preparation(p.plan.operation(), frozen.as_ref().expect("exact freeze"))
            .expect("original binding");
        let proposal = p
            .registry
            .replacement(p.plan.operation())
            .expect("bound proposal")
            .2
            .clone();
        let receipt = p.c.receipt(&proposal);
        Some(
            p.c.pin
                .verify_retired_account(&proposal, &receipt)
                .expect("exact witnessed retirement"),
        )
    } else {
        None
    };
    let access = p.registry.access().expect("owner before fault");
    let path =
        p.c.path
            .parent()
            .expect("owned fixture root")
            .join("authority.redb");
    let (remaining, count) =
        crate::account_authority::tests::fault_database(&mut p.registry, &path, after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    let result = match phase {
        Phase::Prepare => p.registry.begin_preparation(p.expected, p.plan.clone()),
        Phase::Bind => p
            .registry
            .bind_preparation(p.plan.operation(), frozen.as_ref().expect("same freeze")),
        Phase::Commit => p
            .registry
            .commit_replacement(retired.as_ref().expect("same retirement")),
    };
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        result.expect("calibrate actual persistence barriers");
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert!(
            matches!(
                access.current(p.other.application()),
                Err(DurableError::Closed)
            ),
            "uncertain parent closes all aliases"
        );
    }
    p.reopen();
    match phase {
        Phase::Prepare => {
            match p.registry.preparation(p.plan.operation()) {
                Ok((app, state, plan)) => {
                    assert_eq!(app, p.expected.application());
                    assert_eq!(state, State::Preparing);
                    assert_eq!(plan, &p.plan);
                    assert!(matches!(
                        p.registry.access().expect("owner").current(app),
                        Err(DurableError::Suspended)
                    ));
                    Ok(())
                }
                Err(DurableError::Absent) => {
                    assert_eq!(
                        p.registry
                            .access()
                            .expect("owner")
                            .current(p.expected.application())
                            .expect("no local draft committed"),
                        p.expected
                    );
                    Ok(())
                }
                Err(error) => Err(error),
            }
            .expect("only original prepared state or genuine absence is recoverable");
            p.query(); // The original workflow has not contacted freeze before local retention.
            assert_eq!(
                p.registry
                    .begin_preparation(p.expected, p.plan.clone())
                    .expect("retry original draft"),
                State::Preparing
            );
            let frozen = p.frozen();
            p.registry
                .bind_preparation(p.plan.operation(), &frozen)
                .expect("original freeze binding after recovered draft");
        }
        Phase::Bind => {
            let (_, state, plan) = p
                .registry
                .preparation(p.plan.operation())
                .expect("original plan must survive");
            assert_eq!(plan, &p.plan);
            assert!(matches!(state, State::Preparing | State::Pending));
            assert!(matches!(
                p.registry
                    .access()
                    .expect("owner")
                    .current(p.expected.application()),
                Err(DurableError::Suspended)
            ));
            assert_eq!(
                p.registry
                    .bind_preparation(
                        p.plan.operation(),
                        frozen.as_ref().expect("original freeze")
                    )
                    .expect("retry exact binding"),
                State::Pending
            );
        }
        Phase::Commit => {
            let (_, state, plan) = p
                .registry
                .preparation(p.plan.operation())
                .expect("original plan survives root commit");
            assert_eq!(plan, &p.plan);
            assert!(matches!(state, State::Pending | State::Committed));
            assert_eq!(
                p.registry
                    .commit_replacement(retired.as_ref().expect("original retirement"))
                    .expect("retry exact root commit"),
                State::Committed
            );
            let current = p
                .registry
                .access()
                .expect("owner")
                .current(p.expected.application())
                .expect("exact successor mapping");
            assert_eq!(current.revision(), 2);
            assert_eq!(current.account(), p.c.next.account_id());
        }
    }
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("unchanged original plan")
            .2,
        &p.plan
    );
    assert_eq!(
        p.registry
            .access()
            .expect("owner")
            .current(p.other.application())
            .expect("unrelated account remains selected"),
        p.other
    );
    barriers
}
#[test]
fn account_preparation_every_sync_fault_recovers_original_draft_binding_and_mapping() {
    for phase in [Phase::Prepare, Phase::Bind, Phase::Commit] {
        let barriers = at_cut(phase, 0, false);
        assert!((2..=8).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                at_cut(phase, cut, after);
            }
        }
        eprintln!(
            "ACCOUNT_PREPARATION_SYNC phase={phase:?} barriers={barriers} before_after_faults={}",
            barriers * 2
        );
    }
}
