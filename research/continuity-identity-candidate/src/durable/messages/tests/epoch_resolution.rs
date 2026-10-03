// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn resolution_id_is_not_a_public_plaintext_guess_verifier() {
    let mut p = Pair::new();
    p.activate();
    let wire = p.send(id(p.session, 1, 1), b"choice-A");
    p.receive(&wire);
    assert_eq!(complete_rekey(&mut p), 1);
    let report =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .expect("private application report");
    // Attacker inputs: observed public frame/session/AD, a small plaintext
    // dictionary, public progress counts, and the opaque report correlation ID.
    // No traffic, identity, journal or report-key bytes are provided.
    fn public_guess(session: [u8; 32], wire: &[u8], guess: &[u8]) -> [u8; 32] {
        let header = Header::decode(wire).expect("public header");
        let mut body = session.to_vec();
        body.push(2);
        for value in [0_u64, 0, 0, 0, 1, 1] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(header.id.as_bytes());
        body.extend_from_slice(&0_u64.to_be_bytes());
        body.extend_from_slice(intent(b"receive-intent", wire, b"application").as_ref());
        body.push(0);
        body.extend_from_slice(&(guess.len() as u32).to_be_bytes());
        body.extend_from_slice(&digest(&label(b"resolution-plaintext/v1"), guess));
        body.extend_from_slice(&0_u16.to_be_bytes());
        digest(&label(b"closed-epoch-resolution/v1"), &body)
    }
    for guess in [b"choice-A", b"choice-B"] {
        assert_ne!(
            report.resolution_id().as_bytes(),
            &public_guess(p.session, &wire, guess),
            "public metadata and a plaintext guess must not reproduce the report ID"
        );
    }
}

#[test]
fn resolution_scope_authority_and_checkpoint_invariants_are_enforced() {
    let mut p = resolution_pair();
    let before = p.jr.image().expect("before").revision;
    assert!(matches!(
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 1, 150),
        Err(DurableError::Protocol(Error::State))
    ));
    assert!(matches!(
        p.jr.acknowledge_closed_epoch_resolution(
            &p.f.responder,
            p.session,
            0,
            EpochResolutionId::from_trusted_state([7; 32]).expect("id"),
            150
        ),
        Err(DurableError::Protocol(Error::State))
    ));
    assert_eq!(p.jr.image().expect("no changes").revision, before);
    p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
        .expect("pending next control");
    let before = p.jr.image().expect("pending").revision;
    assert!(matches!(
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.jr.image().expect("signed assertion unchanged").revision,
        before
    );
    assert_eq!(complete_rekey(&mut p), 2);
    let resolution =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .expect("report")
            .resolution_id();
    for change in 0..6 {
        let mut changed = state(&mut p.jr, &p.session);
        let t = epoch_mut(&mut changed);
        match change {
            0 => {
                t.resolution = EpochResolutionStatus::Pending(
                    EpochResolutionId::from_trusted_state([8; 32]).expect("other ID"),
                )
            }
            1 => {
                *t.incoming
                    .first_entry()
                    .expect("delivery")
                    .get_mut()
                    .plaintext
                    .first_mut()
                    .expect("body") ^= 1
            }
            2 => {
                *t.outgoing
                    .first_entry()
                    .expect("outbox")
                    .get_mut()
                    .wire
                    .last_mut()
                    .expect("tag") ^= 1
            }
            3 => t.resolution_key = None,
            4 => t.resolution_key = Some(key(&[19; 32]).expect("different report key")),
            _ => t.resolution = EpochResolutionStatus::Acknowledged(resolution),
        }
        assert!(
            State::decode(&changed.encode()).is_err(),
            "altered frozen state {change} admitted"
        );
    }
    let before = p.jr.image().expect("unchanged actual journal").revision;
    assert!(p
        .jr
        .begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 1000)
        .is_err());
    assert!(p
        .jr
        .acknowledge_closed_epoch_resolution(&p.f.responder, p.session, 0, resolution, 1000)
        .is_err());
    assert_eq!(
        p.jr.image().expect("expiry makes no progress").revision,
        before
    );
    p.f.responder.policy().close();
    assert!(p
        .jr
        .begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
        .is_err());
    assert!(p
        .jr
        .acknowledge_closed_epoch_resolution(&p.f.responder, p.session, 0, resolution, 150)
        .is_err());
    assert_eq!(
        p.jr.closed_epoch_resolution_status(&p.f.responder, p.session, 0)
            .expect("read-only status"),
        EpochResolutionStatus::Pending(resolution)
    );
}

#[test]
fn committed_revocation_fences_resolution_reports_and_acknowledgements_after_restart() {
    let mut p = resolution_pair();
    let resolution =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .expect("pending")
            .resolution_id();
    let retained = roster_update(p.f.local_device(), 94, 2, true);
    p.jr.install_roster(&retained, 150).expect("roster head");
    let revoked = roster_update(p.f.local_device(), 94, 3, false);
    p.jr.install_roster(&revoked, 150)
        .expect("durable revocation");
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    let before = p.jr.image().expect("revoked state").revision;
    let denied =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .err()
            .expect("revoked report must not be released");
    assert!(
        matches!(denied, DurableError::Protocol(Error::Scope)),
        "{denied:?}"
    );
    let denied =
        p.jr.acknowledge_closed_epoch_resolution(&p.f.responder, p.session, 0, resolution, 150)
            .expect_err("revoked acknowledgement must not mutate state");
    assert!(
        matches!(denied, DurableError::Protocol(Error::Scope)),
        "{denied:?}"
    );
    assert_eq!(p.jr.image().expect("not changed").revision, before);
    assert_eq!(
        p.jr.closed_epoch_resolution_status(&p.f.responder, p.session, 0)
            .expect("status grants no output"),
        EpochResolutionStatus::Pending(resolution)
    );
}

fn prepared_resolution(operation: &str) -> (Pair, Option<EpochResolutionId>) {
    let mut p = resolution_pair();
    let id = if operation == "epoch-resolution-ack" {
        Some(
            p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
                .expect("report before fault")
                .resolution_id(),
        )
    } else {
        assert_eq!(operation, "epoch-resolution-begin");
        None
    };
    (p, id)
}

fn resolution_call(
    journal: &mut DeviceJournal,
    f: &Fixture,
    session: [u8; 32],
    operation: &str,
    id: Option<EpochResolutionId>,
) -> Result<EpochResolutionId, DurableError> {
    match operation {
        "epoch-resolution-begin" => journal
            .begin_closed_epoch_resolution(&f.responder, session, 0, 150)
            .map(|report| report.resolution_id()),
        "epoch-resolution-ack" => {
            let id = id.ok_or(DurableError::Absent)?;
            journal.acknowledge_closed_epoch_resolution(&f.responder, session, 0, id, 150)?;
            Ok(id)
        }
        _ => Err(DurableError::Protocol(Error::State)),
    }
}

fn check_recovered_resolution(p: &mut Pair, operation: &str, resolution: EpochResolutionId) {
    let observed =
        p.jr.closed_epoch_resolution_status(&p.f.responder, p.session, 0)
            .expect("recovered status");
    if operation == "epoch-resolution-begin" {
        assert_eq!(observed, EpochResolutionStatus::Pending(resolution));
        let report =
            p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
                .expect("exact report");
        assert_eq!(report.resolution_id(), resolution);
        assert_eq!(
            report
                .unconfirmed_messages()
                .first()
                .expect("unknown send")
                .message_id(),
            id(p.session, 2, 1)
        );
        assert_eq!(
            report
                .unconsumed_deliveries()
                .first()
                .expect("pending plaintext")
                .as_bytes(),
            b"retained old plaintext"
        );
        assert_eq!(report.skipped_indices(), &[0]);
    } else {
        assert_eq!(observed, EpochResolutionStatus::Acknowledged(resolution));
        assert_eq!(
            p.jr.message_status(&p.f.responder, p.session, id(p.session, 2, 1))
                .expect("no false delivery"),
            MessageStatus::DeliveryUnknown
        );
    }
    let next =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("current send");
    let wire = p.send(next, b"fresh traffic after resolution recovery");
    assert_eq!(
        p.receive(&wire).as_bytes(),
        b"fresh traffic after resolution recovery"
    );
}

#[test]
fn every_resolution_sync_fault_recovers_exact_report_or_application_acknowledgement() {
    for operation in ["epoch-resolution-begin", "epoch-resolution-ack"] {
        let (mut baseline, id) = prepared_resolution(operation);
        baseline.jr.close();
        let (mut normal, _, count, _) = fault_store(&baseline.pr, baseline.f.local_device(), false);
        count.store(0, Ordering::SeqCst);
        resolution_call(&mut normal, &baseline.f, baseline.session, operation, id)
            .expect("measure barriers");
        let barriers = count.load(Ordering::SeqCst);
        assert!(
            (4..=24).contains(&barriers),
            "{operation} barriers={barriers}"
        );
        normal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let (mut p, id) = prepared_resolution(operation);
                let revision = p.jr.image().expect("before").revision;
                p.jr.close();
                let (mut failed, remaining, _, _) = fault_store(&p.pr, p.f.local_device(), after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    resolution_call(&mut failed, &p.f, p.session, operation, id),
                    after,
                );
                assert!(failed.active.is_none());
                p.jr = reopen(&p.pr, p.f.local_device());
                let recovered = resolution_call(&mut p.jr, &p.f, p.session, operation, id)
                    .expect("recover exact operation");
                assert_eq!(
                    resolution_call(&mut p.jr, &p.f, p.session, operation, id).expect("duplicate"),
                    recovered
                );
                assert_eq!(
                    p.jr.image().expect("one committed transition").revision,
                    revision + 1
                );
                check_recovered_resolution(&mut p, operation, recovered);
            }
        }
        eprintln!(
            "EPOCH_RESOLUTION_SYNC_RECOVERY operation={operation} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn killed_resolution_commits_recover_without_early_report_or_false_delivery() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for (operation, stage) in [
        ("epoch-resolution-begin", "epoch-resolution-frozen"),
        ("epoch-resolution-ack", "epoch-resolution-acknowledged"),
    ] {
        let (mut p, id) = prepared_resolution(operation);
        p.jr.close();
        let path = &p.pr;
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("public fixture");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("operation"), operation).expect("operation");
        if let Some(id) = id {
            fs::write(path.join("resolution-id"), id.as_bytes()).expect("application ID");
        }
        let log = fs::File::create(path.join("child.log")).expect("child log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "durable::messages::tests::message_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{stage} not reached"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        p.jr = reopen(&p.pr, p.f.local_device());
        let recovered =
            resolution_call(&mut p.jr, &p.f, p.session, operation, id).expect("recover");
        check_recovered_resolution(&mut p, operation, recovered);
    }
}

fn resolution_pair() -> Pair {
    let mut p = Pair::new();
    p.activate();
    p.send(id(p.session, 1, 1), b"missing old plaintext");
    let wire = p.send(id(p.session, 1, 2), b"retained old plaintext");
    p.receive(&wire);
    p.jr.send_message(
        &p.f.responder,
        p.session,
        id(p.session, 2, 1),
        b"unconfirmed reverse",
        b"application",
        150,
    )
    .expect("reverse send");
    assert_eq!(complete_rekey(&mut p), 1);
    p
}

#[test]
fn closed_epoch_resolution_reports_exact_data_and_never_invents_delivery_success() {
    let mut p = resolution_pair();
    let old = id(p.session, 2, 1);
    let reply =
        p.jr.resume_message(&p.f.responder, p.session, old, 150)
            .expect("old outbox");
    let missing =
        p.ji.resume_message(&p.f.initiator, p.session, id(p.session, 1, 1), 150)
            .expect("missing old frame");
    let report =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .expect("report");
    assert_eq!(
        (
            report.acknowledged_before(),
            report.sent_count(),
            report.consumed_before(),
            report.observed_receive_count(),
            report.peer_sent_count()
        ),
        (0, 1, 0, 2, 2)
    );
    assert_eq!(report.skipped_indices(), &[0]);
    assert_eq!(report.unconsumed_deliveries().len(), 1);
    let delivery = report
        .unconsumed_deliveries()
        .first()
        .expect("one retained plaintext");
    assert_eq!(
        (delivery.message_id(), delivery.index(), delivery.as_bytes()),
        (id(p.session, 1, 2), 1, b"retained old plaintext".as_slice())
    );
    assert_eq!(report.unconfirmed_messages().len(), 1);
    let outgoing = report
        .unconfirmed_messages()
        .first()
        .expect("one unknown send");
    assert_eq!(outgoing.message_id(), old);
    assert_eq!(
        *outgoing.ciphertext_digest(),
        digest(&label(b"resolution-ciphertext/v1"), &reply)
    );
    let resolution = report.resolution_id();
    let before = p.jr.image().expect("frozen").revision;
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &missing, b"application", 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.resume_message(&p.f.responder, p.session, old, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.consume_message(&p.f.responder, p.session, id(p.session, 1, 2), 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.message_acknowledgement_for_epoch(&p.f.responder, p.session, 0, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.acknowledge_closed_epoch_resolution(
            &p.f.responder,
            p.session,
            0,
            EpochResolutionId::from_trusted_state([7; 32]).expect("other id"),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        p.jr.image().expect("unchanged pending report").revision,
        before
    );
    let fresh_id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("current traffic remains enabled");
    let wire = p.send(fresh_id, b"new epoch during resolution");
    assert_eq!(p.receive(&wire).as_bytes(), b"new epoch during resolution");
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    let restored =
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150)
            .expect("reopened report");
    assert_eq!(restored.resolution_id(), resolution);
    assert_eq!(
        restored
            .unconsumed_deliveries()
            .first()
            .expect("plaintext retained")
            .as_bytes(),
        b"retained old plaintext"
    );
    p.jr.acknowledge_closed_epoch_resolution(&p.f.responder, p.session, 0, resolution, 150)
        .expect("application accounts for all outcomes");
    let after = p.jr.image().expect("acknowledged").revision;
    p.jr.acknowledge_closed_epoch_resolution(&p.f.responder, p.session, 0, resolution, 150)
        .expect("idempotent retry");
    assert_eq!(p.jr.image().expect("no new commit").revision, after);
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, old)
            .expect("unknown"),
        MessageStatus::DeliveryUnknown
    );
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, id(p.session, 2, 2))
            .expect("never sent"),
        MessageStatus::Absent
    );
    assert!(matches!(
        p.jr.begin_closed_epoch_resolution(&p.f.responder, p.session, 0, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let s = state(&mut p.jr, &p.session);
    let t = epoch(&s);
    assert!(t.outgoing.is_empty() && t.incoming.is_empty() && t.skipped.is_empty());
    assert!(t.resolution_key.is_none());
    assert_eq!(
        (
            t.send_floor,
            t.sent,
            t.receive_floor,
            t.received,
            t.receive_limit
        ),
        (0, 1, 0, 2, Some(2))
    );
    for key in [&t.send, &t.receive, &t.send_ack, &t.receive_ack] {
        assert_eq!(key.as_bytes(), &[0; 32]);
    }
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.closed_epoch_resolution_status(&p.f.responder, p.session, 0)
            .expect("persistent accounting"),
        EpochResolutionStatus::Acknowledged(resolution)
    );
}
