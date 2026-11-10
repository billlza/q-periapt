// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A later aggregate image is not a new reservation for an unchanged session.
use super::*;
use redb::ReadableDatabase;

fn second_session(p: &mut Pair) -> [u8; 32] {
    let request = InitiationId::generate().expect("second original request");
    let initial =
        p.ji.initiate(Arc::clone(&p.f.initiator), request, &p.f.signer_i, 150)
            .expect("second initial");
    let (pq, classical) = p.f.sources();
    let reply =
        p.jr.respond(
            Arc::clone(&p.f.responder),
            &initial,
            &p.f.signer_r,
            pq,
            classical,
            150,
        )
        .expect("second response using admitted reusable prekeys");
    let completed =
        p.ji.accept_reply(Arc::clone(&p.f.initiator), request, &reply, 150)
            .expect("second final");
    let session = completed.session_id();
    assert_ne!(session, p.session);
    assert_eq!(
        p.jr.finish(
            Arc::clone(&p.f.responder),
            &initial,
            completed.final_message(),
            150,
        )
        .expect("second finish"),
        session
    );
    assert_eq!(
        p.ji.activate_initiator_messages(Arc::clone(&p.f.initiator), request, 150)
            .expect("activate second initiator"),
        session
    );
    assert_eq!(
        p.jr.activate_responder_messages(Arc::clone(&p.f.responder), &initial, 150)
            .expect("activate second responder"),
        session
    );
    session
}

fn sealed_image(journal: &DeviceJournal) -> Vec<u8> {
    let tx = journal
        .active
        .as_ref()
        .expect("owned journal")
        .db
        .begin_read()
        .expect("read aggregate");
    let table = tx.open_table(crate::durable::TABLE).expect("image table");
    let bytes = table
        .get("image")
        .expect("image lookup")
        .expect("committed image")
        .value()
        .to_vec();
    bytes
}

#[test]
fn another_session_write_preserves_the_original_reservation_and_its_exposure() {
    let mut p = Pair::with_fixture(fixture(PrekeyQuality::ReusableBoth));
    p.activate();
    let sibling = second_session(&mut p);
    assert_eq!(complete_rekey(&mut p), 1);
    let offer =
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
            .expect("target epoch-two offer with retained generation reservation");
    let before = p.jr.image().expect("before sibling write");
    let original_target = &before
        .records
        .get(&record_id(&p.session))
        .expect("target")
        .payload;
    let original_sibling = &before
        .records
        .get(&record_id(&sibling))
        .expect("sibling")
        .payload;
    let old_wire = sealed_image(&p.jr);

    let message =
        p.jr.next_message_id(&p.f.responder, sibling, 150)
            .expect("sibling message identifier");
    assert_eq!(message.epoch().expect("sibling epoch"), 0);
    let wire =
        p.jr.send_message(
            &p.f.responder,
            sibling,
            message,
            b"sibling payload",
            b"application",
            150,
        )
        .expect("unrelated session commits through the actual journal");
    assert_eq!(
        p.ji.receive_message(&p.f.initiator, sibling, &wire, b"application", 150)
            .expect("honest sibling delivery")
            .as_bytes(),
        b"sibling payload"
    );
    let after = p.jr.image().expect("after sibling write");
    let new_wire = sealed_image(&p.jr);
    assert!(after.revision > before.revision);
    assert_ne!(after.digest, before.digest);
    assert_ne!(new_wire, old_wire);
    assert_ne!(new_wire.get(80..104), old_wire.get(80..104));
    assert_eq!(
        after
            .records
            .get(&record_id(&p.session))
            .expect("copied target")
            .payload
            .as_slice(),
        original_target.as_slice()
    );
    assert_ne!(
        after
            .records
            .get(&record_id(&sibling))
            .expect("changed sibling")
            .payload
            .as_slice(),
        original_sibling.as_slice()
    );

    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(sealed_image(&p.jr), new_wire);
    assert_eq!(
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
            .expect("exact target retry after unrelated write and reopen"),
        offer
    );
    // Only this later capture is passed to the predictor. Earlier images above
    // serve equality assertions, not additional attacker input. No later state,
    // sibling private state or signing owner enters the Disclosure value.
    let disclosed = capture_committed_second_offer(&mut p, &offer);
    let response =
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &offer, &p.f.signer_i, 150)
            .expect("target response after the later snapshot");
    let runtime =
        &p.f.responder
            .current_policy()
            .expect("public policy")
            .runtime;
    let intercepts = disclosed.predict_traffic(runtime, &offer, &response, 2);
    assert_eq!(complete_rekey(&mut p), 2);
    let recovered = recover_messages(&mut p, intercepts, 2);
    eprintln!("AGGREGATE_RESERVATION_COPY sessions=2 changed_session=sibling target_phase=3 original_target_bytes_preserved=1 changed_image_nonce=1 exact_retry_after_reopen=1 recovered_epoch=2 recovered_messages={recovered} directions=2 private_input=one_later_target_snapshot");
}
