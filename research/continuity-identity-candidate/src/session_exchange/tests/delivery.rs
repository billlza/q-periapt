// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn connected() -> (Pair, Session, Session) {
    let mut pair = Pair::new();
    let (a, b) = pair.peers();
    let cancel = Cancellation::default();
    let mut effects = Effects::default();
    let mut carrier = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    let session = pair
        .a
        .owner
        .establish_session(
            &a,
            InitiationId::generate().expect("id"),
            &mut carrier,
            &run(&cancel),
            || Ok(150),
        )
        .expect("establish");
    let (a, b) = pair.reopened(session.id());
    (pair, a, b)
}

fn prepare(owner: &mut EnrolledDevice, session: &Session) -> PreparedMessage {
    let cancel = Cancellation::default();
    let message = owner
        .next_session_message_id(session, 150)
        .expect("original ID");
    owner
        .prepare_session_message(
            session,
            Submission {
                message,
                plaintext: b"original opposing delivery",
                associated_data: b"original AD",
            },
            &run(&cancel),
            || Ok(150),
        )
        .expect("durable preparation")
}

#[test]
fn prepared_opposing_deliveries_release_leases_and_complete_on_original_reopened_owners() {
    let (mut pair, a, b) = connected();
    let first = prepare(&mut pair.a.owner, &a);
    let second = prepare(&mut pair.b.owner, &b);
    // Prepared public bytes retain neither private owner nor database lease.
    pair.a.reopen(&pair.policy);
    pair.b.reopen(&pair.policy);
    let (a, b) = pair.reopened(a.id());
    let cancel = Cancellation::default();
    let mut at_a = Effects::default();
    let mut at_b = Effects::default();
    let ack_second = pair
        .a
        .owner
        .serve_session_message(&a, second.as_bytes(), &mut at_a, &run(&cancel), || Ok(150))
        .expect("opposite incoming operation");
    let ack_first = pair
        .b
        .owner
        .serve_session_message(&b, first.as_bytes(), &mut at_b, &run(&cancel), || Ok(150))
        .expect("opposite incoming operation");
    for _ in 0..2 {
        assert_eq!(
            pair.a
                .owner
                .complete_session_message(&a, &first, &ack_first, &run(&cancel), || Ok(150))
                .expect("original completion"),
            Consumption::Confirmed
        );
        assert_eq!(
            pair.b
                .owner
                .complete_session_message(&b, &second, &ack_second, &run(&cancel), || Ok(150))
                .expect("original completion"),
            Consumption::Confirmed
        );
    }
    assert_eq!((at_a.calls, at_b.calls), (1, 1));
}

#[test]
fn prepared_message_cannot_complete_on_another_journal_or_direction() {
    let (mut pair, a, b) = connected();
    let prepared = prepare(&mut pair.a.owner, &a);
    let cancel = Cancellation::default();
    let mut effects = Effects::default();
    let ack = pair
        .b
        .owner
        .serve_session_message(&b, prepared.as_bytes(), &mut effects, &run(&cancel), || {
            Ok(150)
        })
        .expect("original incoming");
    assert!(pair
        .b
        .owner
        .complete_session_message(&b, &prepared, &ack, &run(&cancel), || Ok(150))
        .is_err());
    assert!(pair.b.owner.parts().is_err());
    assert_eq!(
        pair.a
            .owner
            .session_message_status(&a, prepared.message_id())
            .expect("unchanged"),
        MessageStatus::Committed
    );
}

#[test]
fn detached_reply_completion_still_requires_live_time_cancellation_and_authentication() {
    for failure in ["cancel", "expiry", "signature"] {
        let (mut pair, a, b) = connected();
        let prepared = prepare(&mut pair.a.owner, &a);
        let cancel = Cancellation::default();
        let mut effects = Effects::default();
        let mut ack = pair
            .b
            .owner
            .serve_session_message(&b, prepared.as_bytes(), &mut effects, &run(&cancel), || {
                Ok(150)
            })
            .expect("real authenticated ACK");
        if failure == "cancel" {
            cancel.cancel();
        }
        if failure == "signature" {
            *ack.last_mut().expect("ACK bytes") ^= 1;
        }
        assert!(pair
            .a
            .owner
            .complete_session_message(&a, &prepared, &ack, &run(&cancel), || Ok(
                if failure == "expiry" {
                    u64::MAX - 1
                } else {
                    150
                }
            ))
            .is_err());
        assert!(pair.a.owner.parts().is_err());
        pair.a.reopen(&pair.policy);
        assert_eq!(
            pair.a
                .owner
                .session_message_status(&a, prepared.message_id())
                .expect("original retained status"),
            MessageStatus::Committed
        );
    }
}
