// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorAccountReplacementState as WitnessState;
#[path = "closure/recovery.rs"]
mod recovery;
pub(super) fn close_plan(p: &Prepared) -> crate::AnchorClosedAccountPreparation {
    let mut witness = p.c.witness.lock().expect("original witness");
    assert_eq!(
        witness
            .close_account_preparation(&p.plan)
            .expect("durable original non-commit"),
        WitnessState::Closed
    );
    let wire = witness
        .closed_account_preparation_receipt(&p.plan)
        .expect("signed original plan non-commit");
    p.c.pin
        .verify_closed_account_preparation(&p.plan, &wire)
        .expect("independently pinned original plan non-commit")
}
#[test]
fn account_closure_unbound_plan_can_terminate_without_claiming_or_canceling_a_freeze() {
    let mut p = Prepared::new();
    let legacy = p.c.proposal(242);
    p.registry
        .begin_preparation(p.expected, p.plan.clone())
        .expect("original local draft");
    let closed = close_plan(&p);
    assert_eq!(closed.plan(), &p.plan);
    assert_eq!(
        p.registry
            .close_preparation(&closed)
            .expect("retain original terminal outcome"),
        State::Closed
    );
    assert_eq!(
        p.query().outcome(),
        crate::AnchorOutcome::Current,
        "a plan non-commit does not pretend its freeze happened"
    );
    assert!(
        matches!(
            p.registry.replacement(p.plan.operation()),
            Err(DurableError::Suspended)
        ),
        "an unbound template is still not a witness snapshot"
    );
    assert!(matches!(
        p.registry
            .access()
            .expect("access")
            .current(p.expected.application()),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.registry
            .operation_checkpoint(p.plan.operation())
            .expect("original checkpoint without guessing"),
        p.expected
    );
    let mut witness = p.c.witness.lock().expect("witness");
    assert_eq!(
        witness
            .replace_account_root(
                &legacy,
                &p.c.f.local_device().authority_key,
                &p.c.next_genesis,
                &p.c.next,
                p.c.f.responder.current_policy().expect("policy"),
                150
            )
            .expect("all snapshots of closed planned target are barred"),
        WitnessState::Closed
    );
    assert!(witness.closed_account_preparation_receipt(&p.plan).is_ok());
    drop(witness);
    let frozen = p.frozen(); // An already dispatched original freeze may arrive late.
    assert!(matches!(
        p.registry.bind_preparation(p.plan.operation(), &frozen),
        Err(DurableError::Conflict)
    ));
    p.reopen();
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("same closed original plan")
            .1,
        State::Closed
    );
    assert_eq!(
        p.registry
            .begin_preparation(p.expected, p.plan.clone())
            .expect("original closed retry"),
        State::Closed
    );
    assert_eq!(
        p.registry
            .close_preparation(&closed)
            .expect("terminal retry"),
        State::Closed
    );
    assert!(matches!(
        p.registry
            .access()
            .expect("access")
            .current(p.expected.application()),
        Err(DurableError::Suspended)
    ));
}
#[test]
fn account_closure_competing_freeze_loser_adopts_only_the_explicitly_approved_committed_winner() {
    let mut p = Prepared::new();
    let other_request = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([244; 32]).expect("competing freeze operation"),
        p.c.f.local_device().authority_key.clone(),
        &p.c.pin,
    )
    .expect("independent competing approval");
    let other =
        p.c.witness
            .lock()
            .expect("witness")
            .account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([245; 32])
                    .expect("other root operation"),
                other_request,
                &p.c.next_genesis,
                &p.c.next,
                p.c.f.responder.current_policy().expect("policy"),
                150,
            )
            .expect("separate approved operation targeting the same prepared root");
    p.registry
        .begin_preparation(p.expected, p.plan.clone())
        .expect("local original intent before competition");
    let (winner, wire) = {
        let mut witness = p.c.witness.lock().expect("witness");
        let frozen = witness
            .freeze_account(other.request())
            .expect("competing freeze wins first");
        assert!(matches!(
            witness.freeze_account(p.plan.request()),
            Err(DurableError::Conflict)
        ));
        let winner = witness
            .frozen_account_replacement_proposal(
                other.operation(),
                &frozen,
                &p.c.next_genesis,
                &p.c.next,
                p.c.f.responder.current_policy().expect("policy"),
                150,
            )
            .expect("exact competing original proposal");
        assert_eq!(
            witness
                .replace_account_root(
                    &winner,
                    &p.c.f.local_device().authority_key,
                    &p.c.next_genesis,
                    &p.c.next,
                    p.c.f.responder.current_policy().expect("policy"),
                    150
                )
                .expect("actual competing commit"),
            WitnessState::Committed
        );
        assert_eq!(
            witness
                .close_account_preparation(&other)
                .expect("committed plan cannot become closed"),
            WitnessState::Committed
        );
        assert!(witness.closed_account_preparation_receipt(&other).is_err());
        let wire = witness
            .retired_account_receipt(&winner)
            .expect("signed exact winning decision");
        (winner, wire)
    };
    let retired =
        p.c.pin
            .verify_retired_account(&winner, &wire)
            .expect("actual winner fact under original witness");
    assert!(
        p.registry
            .adopt_committed_replacement(p.expected, winner.clone(), &retired)
            .is_err(),
        "unknown original outcome cannot be silently replaced"
    );
    let closed = close_plan(&p);
    p.registry
        .close_preparation(&closed)
        .expect("losing original terminates while still unbound");
    p.reopen();
    let expected = p
        .registry
        .operation_checkpoint(p.plan.operation())
        .expect("original independently retained scope");
    let mut changed = winner.to_bytes().expect("original winner descriptor");
    *changed.last_mut().expect("frozen state commitment") ^= 1;
    let wrong = Proposal::from_trusted_state(&changed).expect("parseable different expectation");
    assert!(matches!(
        p.registry
            .adopt_committed_replacement(expected, wrong, &retired),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        p.registry
            .access()
            .expect("owner")
            .current(expected.application()),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.registry
            .adopt_committed_replacement(expected, winner.clone(), &retired)
            .expect("independent approval and exact witnessed winner"),
        State::Committed
    );
    let current = p
        .registry
        .access()
        .expect("owner")
        .current(expected.application())
        .expect("winner selected once");
    assert_eq!(current.revision(), 2);
    assert_eq!(current.account(), p.c.next.account_id());
    crate::account_authority::tests::rejects_terminal_images(&p.registry);
    p.reopen();
    assert_eq!(
        p.registry
            .adopt_committed_replacement(expected, winner.clone(), &retired)
            .expect("exact historical adoption retry"),
        State::Committed
    );
    assert_eq!(
        p.registry
            .access()
            .expect("owner")
            .current(expected.application())
            .expect("same mapping"),
        current
    );
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("losing original remains recorded")
            .1,
        State::Closed
    );
    p.c.journal.close();
    let mut recovery = p.c.resume(&winner);
    recovery
        .retain_witness_retirement(&wire)
        .expect("original journal recovered under exact approved winner");
}
#[test]
fn account_closure_matching_retirement_recovers_a_lost_local_binding_acknowledgement() {
    let mut p = Prepared::new();
    p.registry
        .begin_preparation(p.expected, p.plan.clone())
        .expect("durable original plan");
    let frozen = p.frozen();
    let proposal =
        p.c.witness
            .lock()
            .expect("witness")
            .frozen_account_replacement_proposal(
                p.plan.operation(),
                &frozen,
                &p.c.next_genesis,
                &p.c.next,
                p.c.f.responder.current_policy().expect("policy"),
                150,
            )
            .expect("exact original target and authenticated freeze");
    let wire = p.c.receipt(&proposal);
    let retired =
        p.c.pin
            .verify_retired_account(&proposal, &wire)
            .expect("actual original commit");
    p.reopen();
    assert_eq!(
        p.registry
            .preparation(p.plan.operation())
            .expect("original unbound draft survives")
            .1,
        State::Preparing
    );
    assert_eq!(
        p.registry
            .commit_replacement(&retired)
            .expect("stronger exact retirement recovers missing local bind"),
        State::Committed
    );
    assert_eq!(
        p.registry
            .replacement(p.plan.operation())
            .expect("original complete proposal retained")
            .2,
        &proposal
    );
    assert_eq!(
        p.registry
            .access()
            .expect("owner")
            .current(p.expected.application())
            .expect("target mapping")
            .revision(),
        2
    );
}
