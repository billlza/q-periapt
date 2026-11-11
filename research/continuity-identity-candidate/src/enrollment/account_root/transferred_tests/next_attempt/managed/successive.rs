// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::super::client_cleanup::Flow;
use super::super::super::registry::RegistryRecovery;
use super::*;
use crate::retired_device::JournalErasureState;
#[path = "successive/process.rs"]
mod process;

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

struct CleanupCase {
    flow: Box<Flow>,
    plan: Box<TransferredAccountRootPreparation>,
    second_plan: Box<TransferredAccountRootPreparation>,
    second: Box<Next>,
    third: Box<Next>,
    recovery: RegistryRecovery,
    first_closed: Vec<u8>,
    closed: Vec<u8>,
    committed: Vec<u8>,
    original_bytes: (Rows, Vec<u8>, [Vec<u8>; 2]),
}
struct ClosedSetup {
    scenario: Box<Scenario>,
    next: Box<Next>,
    plan: Box<TransferredAccountRootPreparation>,
    closed: Vec<u8>,
    original_bytes: (Rows, Vec<u8>, [Vec<u8>; 2]),
}
#[inline(never)]
fn prepare_cleanup(work: Work) -> Box<CleanupCase> {
    // Do not reserve the later multi-attempt fixture frame while constructing
    // the original enrollment and its real pending cryptographic operation.
    prepare_final(prepare_second(Box::new(Scenario::new(work, true))))
}
#[inline(never)]
fn prepare_second(mut s: Box<Scenario>) -> ClosedSetup {
    let old = original(&s.t);
    let original_bytes = retained(&s.t.f.original.paths);
    let second = Box::new(Next::new(&mut s, "cleanup-second", 211, 186));
    let second_plan = Box::new(context(&s, &second, &old));
    let closed = retain_attempt(&mut s, &second, &second_plan, true);
    ClosedSetup {
        scenario: s,
        next: second,
        plan: second_plan,
        closed,
        original_bytes,
    }
}
#[inline(never)]
fn retain_attempt(
    s: &mut Scenario,
    next: &Next,
    plan: &TransferredAccountRootPreparation,
    closed: bool,
) -> Vec<u8> {
    let mut owner = begin(s, plan).expect("independently approved managed attempt");
    owner
        .bind_transferred_freeze(&s.t.frozen, next.approval.clone())
        .expect("same full signed freeze");
    let wire = next.decide(s, closed);
    owner
        .retain_transferred_decision(&wire)
        .expect("same exact permanent decision");
    owner.close();
    wire
}
#[inline(never)]
fn prepare_final(mut previous: ClosedSetup) -> Box<CleanupCase> {
    let s = &mut previous.scenario;
    let third = Box::new(Next::new(s, "cleanup-third", 213, 187));
    let plan = Box::new(
        fresh(s, &third)
            .after_closed(
                &previous.plan,
                previous.next.approval.clone(),
                third.approval.clone(),
                &s.t.frozen,
                &previous.closed,
            )
            .expect("both exact closed attempts in final context"),
    );
    let committed = retain_attempt(s, &third, &plan, false);
    assert!(retained(&s.t.f.original.paths) == previous.original_bytes);
    finish_preparation(previous, third, plan, committed)
}
#[inline(never)]
fn finish_preparation(
    previous: ClosedSetup,
    third: Box<Next>,
    plan: Box<TransferredAccountRootPreparation>,
    committed: Vec<u8>,
) -> Box<CleanupCase> {
    let ClosedSetup {
        scenario: s,
        next: second,
        plan: second_plan,
        closed,
        original_bytes,
    } = previous;
    let journal_plan = plan
        .bind(third.approval.clone())
        .expect("complete signed prefix");
    let decision = third
        .approval
        .verify_decision(&s.t.history, &committed)
        .expect("independent final decision verification");
    let mut flow = Box::new(Flow::committed(s.t, journal_plan, decision));
    flow.cleanup_time = 188;
    Box::new(CleanupCase {
        flow,
        plan,
        second_plan,
        second,
        third,
        recovery: s.recovery,
        first_closed: s.closed,
        closed,
        committed,
        original_bytes,
    })
}
fn later_accounting(flow: &mut Flow) {
    super::super::super::cleanup::handoff(&mut flow.t);
    flow.context = TransferredRetirementContext::new(
        flow.plan.clone(),
        flow.decision.as_bytes(),
        flow.t.f.original.genesis.subject(),
        flow.t.history.clone(),
    )
    .expect("later accounting authority retains original root and full attempt prefix");
}
fn cleanup_after_two_closures(work: Work, later: bool) {
    let CleanupCase {
        mut flow,
        plan,
        second_plan,
        second,
        third,
        recovery,
        first_closed,
        closed,
        committed,
        original_bytes,
    } = *prepare_cleanup(work);
    if later {
        later_accounting(&mut flow);
    }
    let resume_cleanup = |flow: &Flow, preparation: &TransferredAccountRootPreparation| {
        ManagedAccountRootReplacement::resume_transferred_cleanup_original(
            recovery.open(&flow.t.f),
            recovery.expected,
            preparation.clone(),
            flow.t.f.original.paths.clone(),
            flow.t.f.original.intent.clone(),
            flow.context.history().clone(),
        )
    };
    let mut owner = resume_cleanup(&flow, &plan).expect("original final controller for cleanup");
    let ack = owner
        .with_retired_cleanup(|parent| {
            let child = parent.installation()?;
            let (report, verified, previous) = flow.report(child);
            let ack = flow.account(child, &report, &verified, &previous);
            let exact = ack.as_bytes().to_vec();
            child.erase_journal(flow.context.accounting_pin(), &exact)?;
            parent.prepare_signer_erasure(&exact)?;
            parent.erase_signer()?;
            Ok(exact)
        })
        .expect("full original inventory, host ACK, journal and signer logical erasure");
    owner
        .successor_authority()
        .expect("final successor remains selected");
    owner.close();
    assert_eq!(
        fs::read(&flow.t.f.original.paths.signer).expect("terminal signer"),
        b"QPSRET01"
    );
    assert!(
        fs::read(&flow.t.f.original.paths.wrapping).expect("original wrapping key")
            == original_bytes.2[0]
    );
    let stripped = TransferredAccountRootPreparation::new(
        third.plan.clone(),
        flow.plan.logical_pin().clone(),
        flow.plan.history().clone(),
        flow.plan.selection().cloned(),
    )
    .expect("same final target without independently supplied closure history");
    assert!(
        resume_cleanup(&flow, &stripped).is_err(),
        "erasure cannot authorize a missing prefix"
    );
    assert!(
        resume_cleanup(&flow, &second_plan).is_err(),
        "old closed attempt cannot replace final context"
    );
    let mut owner =
        resume_cleanup(&flow, &plan).expect("cold original controller after full erasure");
    owner
        .retain_transferred_decision(&committed)
        .expect("same final decision retry without journal or signer");
    owner
        .with_retired_cleanup(|parent| {
            assert_eq!(
                parent.signer_erasure_status()?,
                SigningFileErasureState::Erased
            );
            assert_eq!(
                parent
                    .installation()?
                    .journal_erasure_status(flow.context.accounting_pin())?,
                JournalErasureState::Erased
            );
            parent.prepare_signer_erasure(&ack)?;
            Ok(())
        })
        .expect("same exact acknowledged historical terminal");
    owner
        .successor_authority()
        .expect("cleanup cannot replace current registry mapping");
    owner.close();
    let mut registry = recovery.open(&flow.t.f);
    for (operation, expected) in [
        (flow.t.preparation.operation(), first_closed.as_slice()),
        (second.plan.operation(), closed.as_slice()),
        (third.plan.operation(), committed.as_slice()),
    ] {
        assert_eq!(
            registry
                .transferred_account_decision(operation)
                .expect("retained original proof")
                .as_bytes(),
            expected
        );
    }
    registry.close();
    eprintln!("TRANSFERRED_SUCCESSIVE_CLEANUP work={work:?} later_accounting={later} exact_two_closures=true journal_erased=true signer_erased=true cold_original_controller=true");
}

#[test]
fn transferred_next_managed_cleanup_after_two_closures_preserves_original_pending_and_history() {
    for work in [
        Work::Policy(2),
        Work::Credential(1),
        Work::Roster(1),
        Work::Cancellation(true),
    ] {
        for later_accounting in [false, true] {
            cleanup_after_two_closures(work, later_accounting);
        }
    }
}
