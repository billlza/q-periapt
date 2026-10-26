// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_next_managed_two_closed_attempts_and_later_witness_keep_original_history() {
    let mut s = Scenario::new(Work::Roster(2), true);
    let old = original(&s.t);
    let bytes = retained(&s.t.f.original.paths);
    let second = Next::new(&mut s, "second-managed", 211, 186);
    let second_plan = context(&s, &second, &old);
    let mut owner = begin(&mut s, &second_plan).expect("second intent");
    owner
        .bind_transferred_freeze(&s.t.frozen, second.approval.clone())
        .expect("second bound");
    let closed = second.decide(&mut s, true);
    owner
        .retain_transferred_decision(&closed)
        .expect("second exact Closed");
    owner.close();
    s.extend_history();
    let third = Next::new(&mut s, "third-managed", 213, 196);
    let plan = fresh(&s, &third)
        .after_closed(
            &second_plan,
            second.approval.clone(),
            third.approval.clone(),
            &s.t.frozen,
            &closed,
        )
        .expect("continuous independently approved third context");
    let mut owner = begin(&mut s, &plan).expect("third preparation under later Witness");
    owner
        .bind_transferred_freeze(&s.t.frozen, third.approval.clone())
        .expect("same original whole freeze");
    let committed = third.decide(&mut s, false);
    owner
        .retain_transferred_decision(&committed)
        .expect("third exact commitment");
    owner.close();
    let mut owner = resume(&s, &plan).expect("cold third controller");
    assert_eq!(owner.state().expect("third outcome"), State::Committed);
    owner
        .successor_authority()
        .expect("only final approved mapping");
    owner.close();
    assert!(
        resume(&s, &second_plan).is_err(),
        "older context cannot roll back latest parent and child"
    );
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_account_decision(second.plan.operation())
            .expect("second Closed remains exact")
            .as_bytes(),
        closed
    );
    assert_eq!(
        s.registry
            .transferred_account_decision(third.plan.operation())
            .expect("third exact result")
            .as_bytes(),
        committed
    );
    s.registry.close();
    assert!(retained(&s.t.f.original.paths) == bytes);
}

#[test]
fn transferred_next_managed_preparation_never_requires_or_regenerates_original_signer() {
    let mut s = Scenario::new(Work::Policy(2), true);
    let old = original(&s.t);
    let next = Next::new(&mut s, "next-no-signer", 211, 186);
    let plan = context(&s, &next, &old);
    let rows = journal_rows(&s.t);
    let signer = fs::read(&s.t.f.original.paths.signer).expect("owned original signer bytes");
    fs::remove_file(&s.t.f.original.paths.signer).expect("only owned fixture signer unavailable");
    let mut owner = begin(&mut s, &plan).expect("signer-free next preparation");
    owner
        .bind_transferred_freeze(&s.t.frozen, next.approval.clone())
        .expect("historical public context and original wrapping key");
    let closed = next.decide(&mut s, true);
    owner
        .retain_transferred_decision(&closed)
        .expect("same original outcome");
    owner.close();
    resume(&s, &plan).expect("signer-free cold retry").close();
    assert!(!s.t.f.original.paths.signer.exists());
    assert!(journal_rows(&s.t) == rows);
    fs::write(&s.t.f.original.paths.signer, signer).expect("restore original fixture signer bytes");
}
