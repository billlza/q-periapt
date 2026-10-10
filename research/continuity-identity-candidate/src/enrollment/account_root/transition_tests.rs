// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityIdentity,
    AccountAuthorityReplacementState as RegistryState, AccountAuthorityStore,
    AccountRootJournalTransition, AnchorAccountFreezeId, AnchorAccountFreezeRequest,
    AnchorAccountReplacementState as WitnessState, ApplicationAccountId,
};
#[path = "transition_tests/support.rs"]
mod support;
use support::Transition;
#[path = "transition_tests/process.rs"]
mod process;

#[test]
fn account_root_parent_transition_retains_multiple_closures_across_old_child_backups() {
    let mut t = Transition::new();
    t.owner
        .transition_after_noncommit(&t.transition)
        .expect("first approved transition");
    t.owner.close();
    let intermediate =
        fs::read(t.f.original.paths.installation.files()[1]).expect("child with one transition");
    t.resume();
    t.approve_another_target();
    t.owner
        .transition_after_noncommit(&t.transition)
        .expect("second approved transition");
    t.assert_parent_preserved();
    t.owner.close();
    for backup in [t.before_fence.clone(), intermediate] {
        fs::write(t.f.original.paths.installation.files()[1], backup)
            .expect("restore owned compatible child backup");
        t.owner = t.f.resume(&t.next);
        t.assert_parent_preserved();
        t.commit();
        t.owner.close();
        t.assert_child_preserved();
        t.f.assert_fenced();
    }
    assert_eq!(
        t.registry
            .access()
            .expect("owner")
            .current(t.expected.application())
            .expect("one selected successor")
            .revision(),
        2
    );
}

#[test]
fn account_root_parent_transition_rejects_wrong_local_head_before_committing_new_parent_intent() {
    let mut t = Transition::new();
    let digest = t
        .next
        .predecessor_observation(t.f.original.genesis.subject())
        .expect("exact original journal")
        .observed_head()
        .digest();
    let mut bytes = t.next.to_bytes().expect("approved descriptor");
    let positions: Vec<_> = bytes
        .windows(32)
        .enumerate()
        .filter_map(|(i, b)| (b == digest).then_some(i))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "identify the original head field without an assumed wire offset"
    );
    *bytes
        .get_mut(*positions.first().expect("head position"))
        .expect("actual digest byte") ^= 1;
    let changed = Proposal::from_trusted_state(&bytes)
        .expect("structurally valid but incompatible journal head");
    let plan = t
        .registry
        .preparation(t.old.operation())
        .expect("original plan")
        .2;
    let wire =
        t.f.witness
            .lock()
            .expect("witness")
            .closed_account_preparation_receipt(plan)
            .expect("actual original non-commit");
    let closed =
        t.f.pin
            .verify_closed_account_preparation(plan, &wire)
            .expect("authenticated original decision");
    let wrong = AccountRootJournalTransition::from_closed_preparation(closed, changed)
        .expect("same root and family scope");
    assert!(matches!(
        t.owner.transition_after_noncommit(&wrong),
        Err(DurableError::Conflict)
    ));
    assert!(t.owner.active.is_none());
    let key = JournalKey::open(&t.f.original.paths.wrapping).expect("same key");
    let binding =
        t.f.original
            .paths
            .binding(&key, &t.f.original.intent)
            .expect("original scope");
    let db = open_private_database(&t.f.original.paths.configuration).expect("same parent");
    let snapshot = read_snapshot(&db, &key, binding).expect("actual retained state");
    assert_eq!(
        snapshot.root_replacement.expect("retained fence").proposal,
        t.old,
        "invalid local-head expectation must not replace the parent intent"
    );
    drop(db);
    t.resume();
    t.commit();
}

#[test]
fn account_root_parent_transition_expired_target_reaches_a_real_current_successor_owner() {
    let mut t = Transition::new();
    assert_eq!(
        t.owner
            .transition_after_noncommit(&t.transition)
            .expect("parent then child transition"),
        AccountRootEnrollmentState::IntentRetained
    );
    assert_eq!(t.owner.proposal().expect("approved successor"), t.next);
    t.assert_parent_preserved();
    t.owner.close();
    t.assert_child_preserved();
    t.f.assert_fenced();
    assert!(AccountRootEnrollmentRecovery::resume_original(
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
        t.f.pin.clone(),
        t.old.clone()
    )
    .is_err());
    t.resume();
    t.commit();
    t.owner.close();
    t.assert_child_preserved();
    t.resume();
    assert_eq!(
        t.owner.status().expect("exact retained outcome"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    t.commit(); // Historical retry must not select another authority revision.
    assert_eq!(
        t.registry
            .access()
            .expect("owner")
            .current(t.expected.application())
            .expect("current mapping")
            .revision(),
        2
    );
    eprintln!("ACCOUNT_ROOT_PARENT_TRANSITION old_expires=160 new_activation_time=170 parent_and_child_preserved=true real_successor_owner=true");
}

#[test]
fn account_root_parent_transition_recovers_child_backups_before_and_after_the_original_fence() {
    for before_fence in [true, false] {
        let mut t = Transition::new();
        t.owner.close();
        let backup = if before_fence {
            t.before_fence.clone()
        } else {
            fs::read(t.f.original.paths.installation.files()[1]).expect("original fenced backup")
        };
        t.resume();
        t.owner.close();
        fs::write(t.f.original.paths.installation.files()[1], &backup)
            .expect("restore only owned child fixture");
        t.f.assert_fenced();
        t.owner = t.f.resume(&t.next); // Parent authorization suffices after its commit.
        t.assert_parent_preserved();
        t.commit();
        t.owner.close();
        fs::write(t.f.original.paths.installation.files()[1], &backup)
            .expect("restore same child after parent retirement");
        t.owner = t.f.resume(&t.next);
        assert_eq!(
            t.owner.status().expect("parent retained retirement"),
            AccountRootEnrollmentState::WitnessCommitted
        );
        t.assert_parent_preserved();
        t.owner.close();
        t.assert_child_preserved();
        t.f.assert_fenced();
    }
}

#[test]
fn account_root_parent_transition_sync_failures_reconcile_original_approval_without_traffic() {
    let mut calibration = Transition::new();
    let (_, count) = fault_parent(
        &mut calibration.owner.active.as_mut().expect("owner").enrollment,
        false,
    );
    count.store(0, Ordering::SeqCst);
    calibration
        .owner
        .transition_after_noncommit(&calibration.transition)
        .expect("calibrate actual parent commit");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    calibration.owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut t = Transition::new();
            let (remaining, _) = fault_parent(
                &mut t.owner.active.as_mut().expect("owner").enrollment,
                after,
            );
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                t.owner.transition_after_noncommit(&t.transition),
                after,
            );
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            assert!(t.owner.active.is_none());
            t.f.assert_fenced();
            t.resume();
            t.assert_parent_preserved();
            t.commit();
            t.owner.close();
            t.assert_child_preserved();
        }
    }
    eprintln!(
        "ACCOUNT_ROOT_PARENT_HANDOFF_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}
