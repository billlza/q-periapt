// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original parent/child state advances only with exact independently trusted plans.
use super::*;
#[path = "client/faults.rs"]
mod faults;
#[path = "client/process.rs"]
mod process;

fn fresh_plan(s: &Scenario, next: &Next) -> TransferredAccountRootJournalPlan {
    TransferredAccountRootJournalPlan::new(
        s.t.f.pin.clone(),
        next.approval.clone(),
        s.t.history.clone(),
        s.t.selected.clone(),
    )
    .expect("independent next full approval")
}
fn open(
    s: &Scenario,
    transition: &TransferredAccountRootJournalTransition,
) -> Result<AccountRootEnrollmentRecovery, DurableError> {
    AccountRootEnrollmentRecovery::resume_transferred_transition(
        s.t.f.original.paths.clone(),
        s.t.f.original.intent.clone(),
        transition,
    )
}

#[test]
fn transferred_client_next_attempt_preserves_real_gpr_and_cancellation_under_both_outcomes() {
    for work in [
        Work::None,
        Work::Policy(0),
        Work::Policy(1),
        Work::Policy(2),
        Work::Credential(0),
        Work::Credential(1),
        Work::Credential(2),
        Work::Roster(0),
        Work::Roster(1),
        Work::Roster(2),
        Work::Cancellation(false),
        Work::Cancellation(true),
    ] {
        let mut s = Scenario::new(work, true);
        let rows = journal_rows(&s.t);
        let parent = original_parent(&s.t);
        let sealed = fs::read(&s.t.f.original.paths.signer).expect("original sealed signer");
        let next = Next::new(&mut s, "next-target", 211, 186);
        let plan = fresh_plan(&s, &next);
        assert!(
            AccountRootEnrollmentRecovery::resume_transferred_original(
                s.t.f.original.paths.clone(),
                s.t.f.original.intent.clone(),
                plan.clone(),
            )
            .is_err(),
            "ordinary recovery cannot silently substitute a new approval"
        );
        next.prepare(&mut s);
        let transition =
            TransferredAccountRootJournalTransition::verify(s.t.plan(), plan.clone(), &s.closed)
                .expect("exact signed Closed and independent next approval");
        let mut owner = open(&s, &transition).expect("parent-first next attempt");
        assert_eq!(
            owner.status().expect("restricted next"),
            AccountRootEnrollmentState::IntentRetained
        );
        owner.close();
        assert!(
            s.t.open().is_err(),
            "old approval cannot reopen selected next attempt"
        );
        assert!(
            AccountRootEnrollmentRecovery::resume_transferred_original(
                s.t.f.original.paths.clone(),
                s.t.f.original.intent.clone(),
                plan,
            )
            .is_err(),
            "missing signed attempt prefix is not the same next expectation"
        );
        let mut owner = open(&s, &transition).expect("exact restart");
        let closed = matches!(work, Work::Policy(_) | Work::Credential(_));
        let decision = next.decide(&mut s, closed);
        let expected = if closed {
            AccountRootEnrollmentState::WitnessClosed
        } else {
            AccountRootEnrollmentState::WitnessCommitted
        };
        assert_eq!(
            owner
                .retain_account_decision(&decision)
                .expect("exact new outcome"),
            expected
        );
        owner.close();
        let mut owner = open(&s, &transition).expect("restart after next outcome");
        assert_eq!(owner.status().expect("same outcome"), expected);
        assert_eq!(
            owner.account_decision().expect("same signature").as_bytes(),
            decision
        );
        owner.close();
        AccountRootEnrollmentRecovery::resume_transferred_original(
            s.t.f.original.paths.clone(),
            s.t.f.original.intent.clone(),
            transition.next_plan().clone(),
        )
        .expect("exact new plan retains signed prefix")
        .close();
        assert!(journal_rows(&s.t) == rows && original_parent(&s.t) == parent);
        assert!(fs::read(&s.t.f.original.paths.signer).expect("original signer") == sealed);
        s.t.f.assert_fenced();
        eprintln!("TRANSFERRED_CLIENT_NEXT work={work:?} closed={closed} original_rows=true exact_signed_prefix=true");
    }
}

#[test]
fn transferred_client_next_attempt_two_closures_and_later_witness_keep_full_history() {
    let mut s = Scenario::new(Work::Roster(1), true);
    let original = s.t.plan();
    let rows = journal_rows(&s.t);
    let second = Next::new(&mut s, "second-target", 211, 186);
    second.prepare(&mut s);
    let first = TransferredAccountRootJournalTransition::verify(
        original,
        fresh_plan(&s, &second),
        &s.closed,
    )
    .expect("first transition");
    let mut owner = open(&s, &first).expect("next local fences");
    let closed = second.decide(&mut s, true);
    owner
        .retain_account_decision(&closed)
        .expect("second Closed in parent and child");
    owner.close();
    s.registry
        .retain_transferred_account_decision(second.plan.operation(), &closed)
        .expect("same second closure");
    s.extend_history();
    let third = Next::new(&mut s, "third-target", 213, 196);
    third.prepare(&mut s);
    let transition = TransferredAccountRootJournalTransition::verify(
        first.next_plan().clone(),
        fresh_plan(&s, &third),
        &closed,
    )
    .expect("C approval keeps exact B history");
    let mut owner = open(&s, &transition).expect("second local transition under C");
    let committed = third.decide(&mut s, false);
    owner
        .retain_account_decision(&committed)
        .expect("third commitment");
    owner.close();
    assert!(
        open(&s, &first).is_err(),
        "an earlier independently valid transition cannot roll back the latest selection"
    );
    open(&s, &transition)
        .expect("latest exact transition retry")
        .close();
    assert!(journal_rows(&s.t) == rows);
    let context = TransferredRetirementContext::new(
        transition.next_plan().clone(),
        &committed,
        s.t.f.original.genesis.subject(),
        s.t.history.clone(),
    )
    .expect("all signed closures in cleanup context");
    let mut retirement = RetiredInstallationRecovery::open_transferred(
        s.t.f.original.paths.installation.clone(),
        JournalKey::open(&s.t.f.original.paths.wrapping).expect("same wrapping key"),
        context,
    )
    .expect("original installation admits full verified attempt history for accounting");
    retirement.close();
}

#[test]
fn transferred_client_next_attempt_rejects_forged_closure_foreign_freeze_and_changed_selection() {
    let mut s = Scenario::new(Work::Cancellation(true), true);
    let next = Next::new(&mut s, "next-target", 211, 186);
    let mut damaged = s.closed.clone();
    *damaged.last_mut().expect("signature") ^= 1;
    assert!(TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        fresh_plan(&s, &next),
        &damaged
    )
    .is_err());
    assert!(
        TransferredAccountRootJournalTransition::verify(s.t.plan(), s.t.plan(), &s.closed).is_err()
    );
    let without_selection = TransferredAccountRootJournalPlan::new(
        s.t.f.pin.clone(),
        next.approval.clone(),
        s.t.history.clone(),
        None,
    )
    .expect("explicit no-selection expectation");
    assert!(TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        without_selection,
        &s.closed
    )
    .is_err());
    let other = Scenario::new(Work::Cancellation(true), true);
    assert!(TransferredAccountRootJournalTransition::verify(
        other.t.plan(),
        fresh_plan(&s, &next),
        &other.closed
    )
    .is_err());
    // A retained authenticated outcome has to match byte-for-byte, even if the
    // caller also possesses a valid non-commit for a different target.
    let third = Next::new(&mut s, "third-target", 213, 186);
    let wrong = third.decide(&mut s, true);
    assert!(TransferredAccountRootJournalTransition::verify(
        s.t.plan(),
        fresh_plan(&s, &next),
        &wrong
    )
    .is_err());
    s.t.open()
        .expect("all rejected construction leaves original recoverable")
        .close();
}
