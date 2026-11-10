// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently approved next server/registry attempt keeps the old full freeze.
use super::fixture::Work;
use super::*;
#[path = "next_attempt/client.rs"]
mod client;
#[path = "next_attempt/managed.rs"]
mod managed;
#[path = "next_attempt/support.rs"]
mod support;
use crate::AccountAuthorityReplacementState as State;
use support::{Next, Scenario};
#[path = "next_attempt/faults.rs"]
mod faults;
#[path = "next_attempt/process.rs"]
mod process;

#[test]
fn transferred_next_attempt_mac_valid_missing_closed_prefix_refuses_reopen() {
    let mut s = Scenario::new(Work::Roster(1), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    next.prepare(&mut s);
    let original = crate::account_authority::tests::snapshot_registry(&s.registry);
    let damaged = crate::account_authority::tests::without_closed_transferred_prefix(&s.registry);
    s.registry.close();
    crate::account_authority::tests::restore_registry_snapshot(&s.recovery.path, &damaged);
    assert!(
        s.recovery
            .try_open(s.t.f.policy.family(), s.t.f.pin.clone())
            .is_err(),
        "a valid local MAC cannot delete the required signed Closed prefix"
    );
    crate::account_authority::tests::restore_registry_snapshot(&s.recovery.path, &original);
    s.reopen();
    assert_eq!(
        s.registry
            .begin_transferred_preparation(s.recovery.expected, next.plan.clone(), &s.t.history,)
            .expect("exact already bound preparation retry"),
        State::Pending
    );
    assert_eq!(s.registry.bind_transferred_preparation(
        next.plan.operation(), &s.t.frozen, next.approval.clone(),
    ).expect("exact already bound freeze retry"), State::Pending);
    s.assert_old();
}

#[test]
fn transferred_next_attempt_missing_original_closed_history_refuses_new_preparation() {
    let mut s = Scenario::new(Work::Credential(1), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let original = crate::account_authority::tests::snapshot_registry(&s.registry);
    s.registry.close();
    crate::account_authority::tests::restore_registry_snapshot(
        &s.recovery.path,
        s.t.registry_before
            .as_ref()
            .expect("exact original pre-intent backup"),
    );
    s.reopen();
    assert!(
        matches!(
            s.registry.begin_transferred_preparation(
                s.recovery.expected,
                next.plan.clone(),
                &s.t.history,
            ),
            Err(DurableError::Suspended)
        ),
        "absence of the original signed closure cannot authorize the next attempt"
    );
    s.registry.close();
    crate::account_authority::tests::restore_registry_snapshot(&s.recovery.path, &original);
    s.reopen();
    next.prepare(&mut s);
    s.assert_old();
}

fn finish(work: Work) {
    let mut s = Scenario::new(work, true);
    let rows = journal_rows(&s.t);
    let parent = original_parent(&s.t);
    let old_frozen =
        s.t.frozen
            .transferred_record()
            .expect("original signed snapshot");
    let next = Next::new(&mut s, "next-target", 211, 186);
    next.prepare(&mut s);
    s.reopen();
    assert_eq!(
        s.registry
            .transferred_preparation(next.plan.operation())
            .expect("same next plan")
            .2,
        &next.plan
    );
    let result = next.decide(&mut s, false);
    assert_eq!(
        s.registry
            .retain_transferred_account_decision(next.plan.operation(), &result)
            .expect("exact independent next commitment"),
        State::Committed
    );
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_account_decision(next.plan.operation())
            .expect("same result")
            .as_bytes(),
        result
    );
    assert_eq!(
        s.t.target
            .transferred_account_decision(&s.t.approval)
            .expect("historical old closed result")
            .as_bytes(),
        s.closed
    );
    assert!(journal_rows(&s.t) == rows && original_parent(&s.t) == parent);
    assert_eq!(
        s.t.frozen
            .transferred_record()
            .expect("unchanged signed freeze"),
        old_frozen
    );
    eprintln!("TRANSFERRED_NEXT_ATTEMPT work={work:?} original_freeze=true original_pending=true old_closed_retained=true next_committed=true");
    next.activate(s);
}
#[test]
fn transferred_next_attempt_real_credential_and_roster_states_keep_original_pending() {
    for work in [
        Work::Credential(0),
        Work::Credential(1),
        Work::Credential(2),
        Work::Roster(0),
        Work::Roster(1),
        Work::Roster(2),
    ] {
        finish(work);
    }
}
#[test]
fn transferred_next_attempt_policy_and_cancellation_states_keep_original_pending() {
    for work in [
        Work::None,
        Work::Policy(0),
        Work::Policy(1),
        Work::Policy(2),
        Work::Cancellation(false),
        Work::Cancellation(true),
    ] {
        finish(work);
    }
}
#[test]
fn transferred_next_attempt_unknown_or_forged_closed_never_selects_new_target() {
    let mut s = Scenario::new(Work::Credential(1), false);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let before = crate::account_authority::tests::snapshot_registry(&s.registry);
    assert!(matches!(
        s.registry.begin_transferred_preparation(
            s.recovery.expected,
            next.plan.clone(),
            &s.t.history
        ),
        Err(DurableError::Suspended)
    ));
    let mut forged = s.closed.clone();
    *forged.last_mut().expect("signature") ^= 1;
    assert!(s
        .registry
        .retain_transferred_account_decision(s.t.preparation.operation(), &forged)
        .is_err());
    assert_eq!(
        crate::account_authority::tests::snapshot_registry(&s.registry),
        before
    );
    s.registry
        .retain_transferred_account_decision(s.t.preparation.operation(), &s.closed)
        .expect("independently received exact old closure");
    next.prepare(&mut s);
    let other = Next::new(&mut s, "competing-target", 213, 186);
    assert!(matches!(
        s.registry.begin_transferred_preparation(
            s.recovery.expected,
            other.plan.clone(),
            &s.t.history
        ),
        Err(DurableError::Suspended)
    ));
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_preparation(next.plan.operation())
            .expect("original selected next")
            .2,
        &next.plan
    );
}
#[test]
fn transferred_next_attempt_preserves_exact_old_freeze_under_a_later_witness() {
    let mut s = Scenario::new(Work::Roster(1), true);
    let old = s.t.frozen.transferred_record().expect("B freeze");
    s.extend_history();
    let next = Next::new(&mut s, "C-target", 211, 196);
    assert_eq!(next.plan.request(), s.t.frozen.request());
    assert_ne!(
        next.approval.proposal().witness_binding(),
        s.t.approval.proposal().witness_binding()
    );
    next.prepare(&mut s);
    s.reopen();
    s.assert_old();
    let result = next.decide(&mut s, false);
    s.registry
        .retain_transferred_account_decision(next.plan.operation(), &result)
        .expect("exact C commitment");
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.t.frozen
            .transferred_record()
            .expect("same historical B freeze"),
        old
    );
    next.activate(s);
}
#[test]
fn transferred_next_attempt_compact_codec_refuses_wrong_freeze_target_history_and_framing() {
    let mut s = Scenario::new(Work::Cancellation(true), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let root = s.t.f.original.root.public_key().expect("root");
    let m = AnchorTransferredAccountReplacementMaterials {
        previous_root: &root,
        genesis: &next.account.genesis,
        device: &next.account.device,
        policy: &s.t.policy,
        history: &s.t.history,
    };
    let wire = next.plan.to_bytes().expect("exact host approval");
    for cut in [0, 8, 72, wire.len() - 1] {
        assert!(
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(
                wire.get(..cut).expect("bounded truncation"),
                &m,
            )
            .is_err()
        );
    }
    for offset in [0, 8, 40, 72] {
        let mut changed = wire.clone();
        *changed.get_mut(offset).expect("existing encoded field") ^= 1;
        assert!(
            AnchorTransferredAccountReplacementPlan::restore_trusted_state(&changed, &m).is_err()
        );
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(AnchorTransferredAccountReplacementPlan::restore_trusted_state(&trailing, &m).is_err());
    let mut huge = wire.clone();
    huge.resize(100_000, 0);
    assert!(AnchorTransferredAccountReplacementPlan::restore_trusted_state(&huge, &m).is_err());
    let freeze = s.t.frozen.binding().expect("exact signed original digest");
    let positions = wire
        .windows(32)
        .enumerate()
        .filter(|(_, w)| *w == freeze)
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let mut changed = wire.clone();
    *changed
        .get_mut(*positions.first().expect("one exact binding"))
        .expect("existing freeze binding") ^= 1;
    let wrong = AnchorTransferredAccountReplacementPlan::restore_trusted_state(&changed, &m)
        .expect("syntactic alternate host plan is not authorization for original freeze");
    assert!(wrong.bind(&s.t.frozen, &s.t.history).is_err());
    let before = crate::account_authority::tests::snapshot_registry(&s.registry);
    assert!(s
        .registry
        .begin_transferred_preparation(s.recovery.expected, wrong, &s.t.history)
        .is_err());
    assert_eq!(
        crate::account_authority::tests::snapshot_registry(&s.registry),
        before
    );
    let other = Scenario::new(Work::None, true);
    assert!(next.plan.bind(&other.t.frozen, &s.t.history).is_err());
    assert!(next.plan.bind(&s.t.frozen, &other.t.history).is_err());
    assert!(
        AnchorTransferredAccountReplacementPlan::restore_trusted_state(
            &wire,
            &AnchorTransferredAccountReplacementMaterials {
                genesis: &other.t.successor.genesis,
                ..m
            }
        )
        .is_err()
    );
}
#[test]
fn transferred_next_attempt_two_closed_targets_retain_both_signed_results_before_third_commit() {
    let mut s = Scenario::new(Work::Policy(2), true);
    let rows = journal_rows(&s.t);
    let second = Next::new(&mut s, "second-target", 211, 186);
    second.prepare(&mut s);
    let closed = second.decide(&mut s, true);
    s.registry
        .retain_transferred_account_decision(second.plan.operation(), &closed)
        .expect("second closed fact");
    let third = Next::new(&mut s, "third-target", 213, 187);
    third.prepare(&mut s);
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_account_decision(second.plan.operation())
            .expect("second exact closure")
            .as_bytes(),
        closed
    );
    let committed = third.decide(&mut s, false);
    s.registry
        .retain_transferred_account_decision(third.plan.operation(), &committed)
        .expect("third exact commitment");
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_account_decision(second.plan.operation())
            .expect("second closure survives")
            .as_bytes(),
        closed
    );
    assert!(journal_rows(&s.t) == rows);
    third.activate(s);
}
