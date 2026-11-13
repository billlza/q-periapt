// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority::tests::{
    rejects_transferred_images, restore_registry_snapshot, snapshot_registry,
};

#[test]
fn transferred_registry_rejects_wrong_context_proofs_and_authenticated_phase_damage() {
    for closed in [false, true] {
        let mut t = Transferred::with_registry(Some(2), 2);
        let other = Transferred::new();
        let mut registry = t.registry.take().expect("original registry");
        rejects_transferred_images(&registry.owner);
        let before = snapshot_registry(&registry.owner);
        assert!(registry
            .owner
            .begin_transferred_preparation(registry.expected, t.preparation.clone(), &other.history)
            .is_err());
        assert!(registry
            .owner
            .bind_transferred_preparation(
                t.preparation.operation(),
                &other.frozen,
                t.approval.clone()
            )
            .is_err());
        assert!(registry
            .owner
            .bind_transferred_preparation(
                t.preparation.operation(),
                &t.frozen,
                other.approval.clone()
            )
            .is_err());
        assert_eq!(snapshot_registry(&registry.owner), before);
        registry
            .owner
            .bind_transferred_preparation(t.preparation.operation(), &t.frozen, t.approval.clone())
            .expect("exact full approval");
        rejects_transferred_images(&registry.owner);
        let decision = t.decide(closed);
        let mut damaged = decision.as_bytes().to_vec();
        *damaged.last_mut().expect("signature") ^= 1;
        let before = snapshot_registry(&registry.owner);
        assert!(registry
            .owner
            .retain_transferred_account_decision(t.preparation.operation(), &damaged)
            .is_err());
        assert_eq!(snapshot_registry(&registry.owner), before);
        registry
            .owner
            .retain_transferred_account_decision(t.preparation.operation(), decision.as_bytes())
            .expect("original permanent outcome");
        rejects_transferred_images(&registry.owner);
        registry.owner.close();
        assert!(
            AccountAuthorityStore::open(
                &registry.path,
                JournalKey::open(&registry.key).expect("same key"),
                registry.identity,
                t.f.policy.family(),
                t.history.current_pin().clone()
            )
            .is_err(),
            "must not rebind the original registry to B"
        );
        registry.reopen(&t.f);
        assert_eq!(
            registry
                .owner
                .transferred_account_decision(t.preparation.operation())
                .expect("unchanged signed result")
                .as_bytes(),
            decision.as_bytes()
        );
    }
}

fn apply(
    registry: &mut OriginalRegistry,
    t: &Transferred,
    phase: u8,
    wire: &[u8],
) -> Result<State, DurableError> {
    match phase {
        0 => registry.owner.begin_transferred_preparation(
            registry.expected,
            t.preparation.clone(),
            &t.history,
        ),
        1 => registry.owner.bind_transferred_preparation(
            t.preparation.operation(),
            &t.frozen,
            t.approval.clone(),
        ),
        2 => registry
            .owner
            .retain_transferred_account_decision(t.preparation.operation(), wire),
        _ => Err(DurableError::Corrupt),
    }
}
pub(super) fn setup(phase: u8, closed: bool) -> (Transferred, OriginalRegistry, Vec<u8>) {
    let mut t = Transferred::with_registry(Some(2), 2);
    let mut registry = t.registry.take().expect("original registry");
    if phase == 0 {
        registry.owner.close();
        // This is the exact original pre-preparation registry backup. The real
        // fixture already proved local intent preceded the remote freeze. Replaying
        // that same intent here isolates its write failures without generating IDs.
        restore_registry_snapshot(&registry.path, &registry.before_preparation);
        registry.reopen(&t.f);
    }
    if phase == 2 {
        registry
            .owner
            .bind_transferred_preparation(t.preparation.operation(), &t.frozen, t.approval.clone())
            .expect("bound original intent");
    }
    let decision = t.decide(closed).as_bytes().to_vec();
    (t, registry, decision)
}
#[test]
fn transferred_registry_sync_errors_close_leases_and_recover_same_original_operation() {
    for closed in [false, true] {
        for phase in 0..=2 {
            let (t, mut registry, wire) = setup(phase, closed);
            let (_, count) = crate::account_authority::tests::fault_database(
                &mut registry.owner,
                &registry.path,
                false,
            );
            count.store(0, Ordering::SeqCst);
            apply(&mut registry, &t, phase, &wire).expect("measure actual transaction");
            let barriers = count.load(Ordering::SeqCst);
            assert!((1..=8).contains(&barriers));
            registry.owner.close();
            for after in [false, true] {
                for cut in 1..=barriers {
                    let (t, mut registry, wire) = setup(phase, closed);
                    let rows = journal_rows(&t);
                    let (remaining, _) = crate::account_authority::tests::fault_database(
                        &mut registry.owner,
                        &registry.path,
                        after,
                    );
                    let access = registry.owner.access().expect("original revocable access");
                    remaining.store(cut, Ordering::SeqCst);
                    crate::durable::tests::assert_sync_failure(
                        apply(&mut registry, &t, phase, &wire),
                        after,
                    );
                    assert!(matches!(registry.owner.access(), Err(DurableError::Closed)));
                    assert!(matches!(
                        access.current(registry.unrelated.application()),
                        Err(DurableError::Closed)
                    ));
                    registry.reopen(&t.f);
                    let observed = match registry
                        .owner
                        .transferred_account_decision(t.preparation.operation())
                    {
                        Err(DurableError::Absent) if phase == 0 => None,
                        Err(DurableError::Suspended) => None,
                        result => Some(result.expect("only an exact decision or explicit absent/pending phase is valid").as_bytes().to_vec()),
                    };
                    let result =
                        apply(&mut registry, &t, phase, &wire).expect("exact original retry");
                    if phase == 2 {
                        assert_eq!(
                            result,
                            if closed {
                                State::Closed
                            } else {
                                State::Committed
                            }
                        );
                        let returned = registry
                            .owner
                            .transferred_account_decision(t.preparation.operation())
                            .expect("same permanent result");
                        assert_eq!(returned.as_bytes(), wire);
                        if let Some(previous) = observed {
                            assert_eq!(previous, wire);
                        }
                    }
                    assert!(
                        journal_rows(&t) == rows,
                        "registry write must never rewrite original P/selection"
                    );
                    registry.reopen(&t.f);
                    assert_eq!(
                        registry
                            .owner
                            .transferred_preparation(t.preparation.operation())
                            .expect("original plan")
                            .2,
                        &t.preparation
                    );
                }
            }
            eprintln!("TRANSFERRED_REGISTRY_SYNC phase={phase} closed={closed} barriers={barriers} faults={}",barriers*2);
        }
    }
}
