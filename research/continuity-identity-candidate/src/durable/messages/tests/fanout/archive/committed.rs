// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::FanoutMemberState;

fn consumed() -> (Network, FanoutId, SessionArchiveStore) {
    let mut n = Network::new(4, false);
    let index = retain(&mut n);
    let id = n.sender.next_fanout_id().expect("original ID");
    let members = n.send(id, b"independently consumed").expect("whole commit");
    n.check_delivery(&members, b"independently consumed");
    for ((receiver, context), member) in n.receivers.iter_mut().zip(&n.f.contexts).zip(&members) {
        receiver
            .consume_message(context, member.session, member.message, 150)
            .expect("actual consumption");
        let ack = receiver
            .message_acknowledgement(context, member.session, 150)
            .expect("authentic ACK");
        n.sender
            .accept_message_acknowledgement(context, member.session, &ack, 150)
            .expect("recorded ACK");
    }
    n.sender.close();
    (n, id, index)
}

#[test]
fn committed_metadata_retirement_preserves_live_sessions_and_never_reuses_identity() {
    let (mut n, id, mut index) = consumed();
    let mut owner = open(&n.sender_path, id, &mut index).expect("original batch");
    let report = owner.reconcile_members().expect("complete results");
    assert_eq!(report.batch, id);
    assert_eq!(report.members.len(), n.sessions.len());
    assert!(report
        .members
        .iter()
        .all(|member| member.state == FanoutMemberState::Acknowledged));
    owner
        .retire_metadata()
        .expect("all independently acknowledged");
    owner
        .retire_metadata()
        .expect("duplicate retains actual settled live members");
    assert_eq!(owner.status().expect("status"), FanoutStatus::Retired);
    assert!(matches!(
        owner.reconcile_members(),
        Err(DurableError::Protocol(Error::Retired))
    ));
    owner.close();
    assert!(matches!(
        open(&n.sender_path, id, &mut index),
        Err(DurableError::Protocol(Error::Retired))
    ));
    n.sender = reopen(&n.sender_path, &n.f.local);
    let successor = n.sender.next_fanout_id().expect("next identity");
    assert!(successor > id);
    n.send(successor, b"same live sessions")
        .expect("retirement did not close settled sessions");
}

#[test]
fn committed_metadata_retirement_process_exit_preserves_actual_retired_fact() {
    let (mut n, id, mut index) = consumed();
    fs::write(n.sender_path.join("fanout-id"), id.as_bytes()).expect("original batch identity");
    index.close();
    cut(&n.sender_path, "retire", "fanout-archive-retired");
    let mut index = self::super::index(&n.sender_path);
    assert!(matches!(
        open(&n.sender_path, id, &mut index),
        Err(DurableError::Protocol(Error::Retired))
    ));
    n.sender = reopen(&n.sender_path, &n.f.local);
    assert_eq!(
        n.sender.fanout_status(id).expect("actual journal"),
        FanoutStatus::Retired
    );
    assert!(n.sender.next_fanout_id().expect("next") > id);
}

#[test]
fn committed_metadata_retirement_sync_failures_reconcile_original_target() {
    let (mut baseline, id, _) = consumed();
    let (journal, _, count, _) = fault_store(&baseline.sender_path, &baseline.f.local, false);
    baseline.sender = journal;
    count.store(0, Ordering::SeqCst);
    baseline
        .sender
        .retire_fanout(id, &targets(&baseline.f, &baseline.sessions))
        .expect("measured shared kernel");
    let barriers = count.load(Ordering::SeqCst);
    assert!(barriers > 0);
    baseline.sender.close();
    for after in [false, true] {
        for at in 1..=barriers {
            let (mut n, id, mut index) = consumed();
            let (journal, remaining, _, _) = fault_store(&n.sender_path, &n.f.local, after);
            n.sender = journal;
            remaining.store(at, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                n.sender.retire_fanout(id, &targets(&n.f, &n.sessions)),
                after,
            );
            assert!(n.sender.active.is_none());
            let state = open(&n.sender_path, id, &mut index);
            if !matches!(&state, Err(DurableError::Protocol(Error::Retired))) {
                let mut owner = state.expect("original cleanup reconciliation");
                if owner.status().expect("reconciled actual phase") == FanoutStatus::Committed {
                    assert!(owner
                        .reconcile_members()
                        .expect("original members")
                        .members
                        .iter()
                        .all(|member| member.state == FanoutMemberState::Acknowledged));
                }
                owner.retire_metadata().expect("same original retirement");
                assert_eq!(owner.status().expect("retired"), FanoutStatus::Retired);
                owner.close();
            }
            n.sender = reopen(&n.sender_path, &n.f.local);
            assert_eq!(
                n.sender.fanout_status(id).expect("actual retirement"),
                FanoutStatus::Retired
            );
            assert!(n.sender.next_fanout_id().expect("next") > id);
        }
    }
    eprintln!(
        "COMMITTED_FANOUT_RETIRE_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn member_reconciliation_preserves_whole_reserved_abandonment_contract() {
    let mut n = Network::new(4, false);
    let mut index = retain(&mut n);
    let id = reserve(&mut n);
    n.sender.close();
    let mut owner = open(&n.sender_path, id, &mut index).expect("original reserved batch");
    assert!(matches!(
        owner.reconcile_members(),
        Err(DurableError::Suspended)
    ));
    let report = owner.begin().expect("complete original loss report");
    assert!(matches!(
        owner.reconcile_members(),
        Err(DurableError::Suspended)
    ));
    abandonment::account(&n.sender_path, &report);
    owner
        .acknowledge(report.report)
        .expect("durable complete host accounting");
    let results = owner.reconcile_members().expect("all terminal members");
    assert_eq!(results.members.len(), report.sessions.len());
    for member in &results.members {
        let original = report
            .sessions
            .iter()
            .find(|session| session.session == member.session)
            .expect("original session");
        assert_eq!(member.message, original.reserved.message);
        assert_eq!(member.state, FanoutMemberState::ReservationAbandoned);
    }
    owner
        .retire_metadata()
        .expect("original abandonment retirement");
    owner.retire_metadata().expect("same-owner duplicate");
    assert_eq!(owner.status().expect("retired"), FanoutStatus::Retired);
}
