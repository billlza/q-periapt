// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
mod archive;
use crate::{SessionClosure, SessionClosureId, SessionClosureStatus};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn populated() -> Pair {
    let mut p = Pair::new();
    p.activate();
    p.send(id(p.session, 1, 1), b"unseen forward");
    let wire = p.send(id(p.session, 1, 2), b"unconsumed forward content");
    p.receive(&wire);
    p.jr.send_message(
        &p.f.responder,
        p.session,
        id(p.session, 2, 1),
        b"unknown reverse",
        b"application",
        150,
    )
    .expect("reverse");
    assert_eq!(complete_rekey(&mut p), 1);
    p
}
pub(super) fn account(path: &Path, report: &SessionClosure) {
    let mut file = fs::File::create_new(path.join(format!(
            "closure-accounting-{}",
            report
                .report
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )))
    .expect("new host record");
    file.write_all(format!("{report:#?}\n").as_bytes())
        .expect("complete public metadata");
    file.sync_all().expect("durable host accounting");
    fs::File::open(path)
        .expect("directory")
        .sync_all()
        .expect("durable host name");
}
fn terminal(p: &mut Pair, report: SessionClosureId) {
    assert_eq!(
        p.jr.session_closure_status(&p.f.responder, p.session)
            .expect("phase"),
        SessionClosureStatus::Closed(report)
    );
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, id(p.session, 2, 1))
            .expect("unknown"),
        MessageStatus::DeliveryUnknown
    );
    assert!(p
        .jr
        .next_message_id(&p.f.responder, p.session, 150)
        .is_err());
    assert!(p
        .jr
        .resume_response(Arc::clone(&p.f.responder), &p.initial, &p.f.signer_r, 150)
        .is_err());
    assert!(p
        .jr
        .finish(Arc::clone(&p.f.responder), &p.initial, &p.final_wire, 150)
        .is_err());
    assert!(p
        .jr
        .activate_responder_messages(Arc::clone(&p.f.responder), &p.initial, 150)
        .is_err());
    assert!(p
        .jr
        .prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
        .is_err());
    assert!(p
        .jr
        .message_acknowledgement(&p.f.responder, p.session, 150)
        .is_err());
    let image = p.jr.image().expect("terminal image");
    let record = image.records.get(&record_id(&p.session)).expect("record");
    assert_eq!(record.phase, DurableStatus::MessagesClosed);
    assert!(State::decode(&record.payload).is_err());
    let retired = Retired::decode(&record.payload).expect("keyless grammar");
    assert_eq!(retired.batch, None);
    assert_eq!(retired.report, *report.as_bytes());
    assert!(!record
        .payload
        .windows(b"unconsumed forward content".len())
        .any(|w| w == b"unconsumed forward content"));
    for length in 0..record.payload.len() {
        assert!(Retired::decode(record.payload.get(..length).expect("prefix")).is_err());
    }
}
fn kill_responder(p: &mut Pair, operation: &str, stage: &str, report: Option<SessionClosureId>) {
    use crate::durable::tests::ChildGuard;
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
    if let Some(report) = report {
        fs::write(path.join("closure-id"), report.as_bytes()).expect("report ID");
    }
    let spawn = |contender: bool| {
        let log = fs::File::create_new(path.join(format!(
            "{operation}-{}.log",
            if contender { "contender" } else { "child" }
        )))
        .expect("new log");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "durable::messages::tests::message_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log));
        if contender {
            command
                .env("QPERIAPT_REQUEST_CONTENDER", "1")
                .env_remove("QPERIAPT_MESSAGES_STAGE");
        } else {
            command
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .env_remove("QPERIAPT_REQUEST_CONTENDER");
        }
        ChildGuard(command.spawn().expect("owned process"))
    };
    let mut child = spawn(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "{operation} did not reach {stage}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(path.join("ready")).expect("published stage"),
        stage
    );
    let mut contender = spawn(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = contender.0.try_wait().expect("contender") {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "contender must return Busy without blocking"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.join("returned").exists());
    child.0.kill().expect("kill owned child");
    assert!(!child.0.wait().expect("reap").success());
    fs::rename(path.join("ready"), path.join(format!("{operation}-ready"))).expect("retain marker");
    p.jr = reopen(path, p.f.local_device());
}
#[test]
fn independent_session_closure_accounts_all_epochs_and_a_real_reserved_input() {
    let mut p = populated();
    let pending =
        p.jr.next_message_id(&p.f.responder, p.session, 150)
            .expect("slot");
    kill_responder(&mut p, "session-reserved", "reserved", None);
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, pending)
            .expect("real reservation"),
        MessageStatus::Reserved
    );
    let before = p.jr.image().expect("before");
    let report =
        p.jr.begin_session_closure(&p.f.responder, p.session)
            .expect("freeze");
    assert_eq!(report.peer_device, p.f.initiator_device().device_id());
    assert_eq!(report.progress.confirmed_epoch, 1);
    assert_eq!(report.reserved.len(), 1);
    assert_eq!(report.reserved.first().expect("reserved").message, pending);
    assert_eq!(
        report.reserved.first().expect("reserved").plaintext_bytes,
        b"reserved session input".len()
    );
    assert_eq!(report.epochs.len(), 2);
    let old = report.epochs.first().expect("epoch zero");
    assert_eq!(
        (
            old.sent,
            old.acknowledged_before,
            old.received,
            old.consumed_before
        ),
        (1, 0, 2, 0)
    );
    assert_eq!(old.unconfirmed.len(), 1);
    assert_eq!(old.deliveries.len(), 1);
    assert_eq!(
        old.deliveries.first().expect("delivery").plaintext_bytes,
        b"unconsumed forward content".len()
    );
    assert_eq!(old.skipped, vec![0]);
    let frozen = p.jr.image().expect("frozen");
    assert_eq!(frozen.records.len(), before.records.len());
    assert_eq!(
        frozen
            .records
            .get(&record_id(&p.session))
            .expect("frozen")
            .payload
            .len(),
        before
            .records
            .get(&record_id(&p.session))
            .expect("before")
            .payload
            .len()
    );
    assert_eq!(
        p.jr.begin_session_closure(&p.f.responder, p.session)
            .expect("same report"),
        report
    );
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, id(p.session, 2, 1))
            .expect("pending loss"),
        MessageStatus::ResolutionPending
    );
    assert!(p
        .jr
        .resume_message(&p.f.responder, p.session, pending, 150)
        .is_err());
    assert!(p
        .jr
        .resume_response(Arc::clone(&p.f.responder), &p.initial, &p.f.signer_r, 150)
        .is_err());
    assert!(p
        .jr
        .message_acknowledgement(&p.f.responder, p.session, 150)
        .is_err());
    assert!(p
        .jr
        .prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
        .is_err());
    let retained =
        p.ji.resume_message(&p.f.initiator, p.session, id(p.session, 1, 2), 150)
            .expect("real retained frame");
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &retained, b"application", 150),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        p.jr.consume_message(&p.f.responder, p.session, id(p.session, 1, 2), 150),
        Err(DurableError::Suspended)
    ));
    let mut changed = p.jr.image().expect("snapshot");
    let record = changed
        .records
        .get_mut(&record_id(&p.session))
        .expect("record");
    let mut state = State::decode(&record.payload).expect("state");
    *state
        .traffic_mut(0)
        .expect("old")
        .incoming
        .first_entry()
        .expect("inbox")
        .get_mut()
        .plaintext
        .first_mut()
        .expect("byte") ^= 1;
    record.payload = state.encode();
    assert!(
        validate_image(&changed).is_err(),
        "private-state edits must invalidate the frozen report"
    );
    assert!(matches!(
        p.jr.acknowledge_session_closure(
            &p.f.responder,
            p.session,
            SessionClosureId::from_trusted_state([8; 32]).expect("wrong ID")
        ),
        Err(DurableError::Conflict)
    ));
    let unrelated = fixture(PrekeyQuality::OneTimeBoth);
    assert!(matches!(
        p.jr.begin_session_closure(&unrelated.responder, p.session),
        Err(DurableError::Conflict)
    ));
    assert_eq!(p.jr.image().expect("unchanged").revision, frozen.revision);
    let revoked = roster_update(p.f.local_device(), 94, 2, false);
    p.jr.install_roster(&revoked, 150)
        .expect("revocation does not prevent cleanup");
    p.f.responder
        .current_policy()
        .expect("fixture policy owner")
        .close();
    assert_eq!(
        p.jr.begin_session_closure(&p.f.responder, p.session)
            .expect("closed policy cleanup"),
        report
    );
    account(&p.pr, &report);
    p.jr.acknowledge_session_closure(&p.f.responder, p.session, report.report)
        .expect("complete");
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    terminal(&mut p, report.report);
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, pending)
            .expect("abandoned slot"),
        MessageStatus::ReservationAbandoned
    );
    p.jr.acknowledge_session_closure(&p.f.responder, p.session, report.report)
        .expect("idempotent");
}
#[test]
fn independent_session_closure_empty_initiator_preserves_sources_and_never_requires_a_send() {
    let mut p = Pair::new();
    p.activate();
    let before =
        p.ji.application_send_progress(&p.f.initiator, p.session)
            .expect("unused budget");
    assert_eq!(before.committed, 0);
    let report =
        p.ji.begin_session_closure(&p.f.initiator, p.session)
            .expect("close empty session");
    assert!(report.reserved.is_empty());
    assert!(report.epochs.iter().all(|e| e.sent == 0 && e.received == 0));
    account(&p.pi, &report);
    p.ji.acknowledge_session_closure(&p.f.initiator, p.session, report.report)
        .expect("terminal");
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.session_closure_status(&p.f.initiator, p.session)
            .expect("closed"),
        SessionClosureStatus::Closed(report.report)
    );
    assert!(p
        .ji
        .resume_initial(Arc::clone(&p.f.initiator), p.request, 150)
        .is_err());
    assert!(p
        .ji
        .resume_reply(Arc::clone(&p.f.initiator), p.request, 150)
        .is_err());
    assert!(p
        .ji
        .activate_initiator_messages(Arc::clone(&p.f.initiator), p.request, 150)
        .is_err());
    assert!(p
        .ji
        .next_message_id(&p.f.initiator, p.session, 150)
        .is_err());
    assert!(p
        .ji
        .begin_session_closure(&p.f.initiator, p.session)
        .is_err());
}
fn prepared(finish: bool) -> (Pair, Option<SessionClosureId>) {
    let mut p = populated();
    let report = if finish {
        let report =
            p.jr.begin_session_closure(&p.f.responder, p.session)
                .expect("freeze");
        account(&p.pr, &report);
        Some(report.report)
    } else {
        None
    };
    (p, report)
}
fn call(
    journal: &mut DeviceJournal,
    f: &Fixture,
    session: [u8; 32],
    report: Option<SessionClosureId>,
) -> Result<SessionClosureId, DurableError> {
    if let Some(report) = report {
        journal.acknowledge_session_closure(&f.responder, session, report)?;
        Ok(report)
    } else {
        Ok(journal.begin_session_closure(&f.responder, session)?.report)
    }
}
#[test]
fn independent_session_closure_every_observed_sync_fault_reconciles_one_transition() {
    for finish in [false, true] {
        let (mut baseline, report) = prepared(finish);
        baseline.jr.close();
        let (mut journal, _, count, _) =
            fault_store(&baseline.pr, baseline.f.local_device(), false);
        count.store(0, Ordering::SeqCst);
        call(&mut journal, &baseline.f, baseline.session, report).expect("measure barriers");
        let barriers = count.load(Ordering::SeqCst);
        assert!((4..=24).contains(&barriers));
        journal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let (mut p, report) = prepared(finish);
                let revision = p.jr.image().expect("before").revision;
                let archive =
                    p.jr.archive_session_closure(&p.f.responder, p.session)
                        .expect("retained cleanup binding");
                p.jr.close();
                let (mut failed, remaining, _, _) = fault_store(&p.pr, p.f.local_device(), after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    call(&mut failed, &p.f, p.session, report),
                    after,
                );
                assert!(failed.active.is_none());
                let mut cleanup = crate::SessionClosureJournal::open(
                    &p.pr.join("state.redb"),
                    JournalKey::open(&p.pr.join("key")).expect("key"),
                    crate::durable::tests::identity(&p.pr),
                    &crate::SessionClosureArchive::from_bytes(archive.as_bytes())
                        .expect("parsed archive"),
                )
                .expect("archived reconciliation of uncertain write");
                let saved = if let Some(report) = report {
                    cleanup
                        .acknowledge(report)
                        .expect("exact terminal reconciliation");
                    report
                } else {
                    cleanup.begin().expect("exact freeze reconciliation").report
                };
                cleanup.close();
                p.jr = reopen(&p.pr, p.f.local_device());
                assert_eq!(
                    call(&mut p.jr, &p.f, p.session, report).expect("duplicate"),
                    saved
                );
                assert_eq!(p.jr.image().expect("once").revision, revision + 1);
                if finish {
                    terminal(&mut p, saved);
                } else {
                    assert_eq!(
                        p.jr.session_closure_status(&p.f.responder, p.session)
                            .expect("frozen"),
                        SessionClosureStatus::Pending(saved)
                    );
                }
            }
        }
        eprintln!(
            "SESSION_CLOSURE_SYNC finish={finish} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}
#[test]
fn independent_session_closure_process_cuts_keep_freeze_and_terminal_effects_with_busy_writers() {
    for finish in [false, true] {
        let (mut p, saved) = prepared(finish);
        kill_responder(
            &mut p,
            if finish {
                "session-closure-ack"
            } else {
                "session-closure-begin"
            },
            if finish {
                "session-closed"
            } else {
                "session-closing"
            },
            saved,
        );
        let report = call(&mut p.jr, &p.f, p.session, saved).expect("recover exact effect");
        if !finish {
            let accounted =
                p.jr.begin_session_closure(&p.f.responder, p.session)
                    .expect("same report");
            assert_eq!(accounted.report, report);
            account(&p.pr, &accounted);
            p.jr.acknowledge_session_closure(&p.f.responder, p.session, report)
                .expect("finish accounting");
        }
        terminal(&mut p, report);
        eprintln!("SESSION_CLOSURE_PROCESS finish={finish} competing_writer=Busy observed_commit_killed=true");
    }
}

#[test]
fn independent_session_closure_fences_pending_rekey_flights_before_and_after_cutover() {
    for stage in 0..3 {
        let mut p = Pair::new();
        p.activate();
        let offer =
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("real signed offer");
        let response = if stage >= 1 {
            Some(
                p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                    .expect("real signed response"),
            )
        } else {
            None
        };
        let final_wire = if stage == 2 {
            Some(
                p.ji.accept_rekey_response(
                    &p.f.initiator,
                    p.session,
                    response.as_ref().expect("response"),
                    &p.f.signer_i,
                    150,
                )
                .expect("real signed final and cutover"),
            )
        } else {
            None
        };
        let report = if stage == 1 {
            p.jr.begin_session_closure(&p.f.responder, p.session)
                .expect("freeze responder control")
        } else {
            p.ji.begin_session_closure(&p.f.initiator, p.session)
                .expect("freeze initiator control")
        };
        assert_eq!(report.progress.pending_epoch, Some(1));
        assert!(report.reserved.is_empty());
        match stage {
            0 => {
                assert!(matches!(
                    p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150),
                    Err(DurableError::Suspended)
                ));
                let response =
                    p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                        .expect("live peer responds");
                assert!(matches!(
                    p.ji.accept_rekey_response(
                        &p.f.initiator,
                        p.session,
                        &response,
                        &p.f.signer_i,
                        150
                    ),
                    Err(DurableError::Suspended)
                ));
            }
            1 => {
                assert!(matches!(
                    p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150),
                    Err(DurableError::Suspended)
                ));
                let final_wire =
                    p.ji.accept_rekey_response(
                        &p.f.initiator,
                        p.session,
                        response.as_ref().expect("response"),
                        &p.f.signer_i,
                        150,
                    )
                    .expect("live peer final");
                assert!(matches!(
                    p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150),
                    Err(DurableError::Suspended)
                ));
            }
            _ => {
                assert_eq!(report.progress.sending_epoch, 1);
                assert!(matches!(
                    p.ji.accept_rekey_response(
                        &p.f.initiator,
                        p.session,
                        response.as_ref().expect("response"),
                        &p.f.signer_i,
                        150
                    ),
                    Err(DurableError::Suspended)
                ));
                let receipt =
                    p.jr.finish_rekey(
                        &p.f.responder,
                        p.session,
                        final_wire.as_ref().expect("final"),
                        &p.f.signer_r,
                        150,
                    )
                    .expect("live peer receipt");
                assert!(matches!(
                    p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150),
                    Err(DurableError::Suspended)
                ));
            }
        }
        let (journal, context, path) = if stage == 1 {
            (&mut p.jr, &p.f.responder, &p.pr)
        } else {
            (&mut p.ji, &p.f.initiator, &p.pi)
        };
        account(path, &report);
        journal
            .acknowledge_session_closure(context, p.session, report.report)
            .expect("terminal despite incomplete rekey");
        assert_eq!(
            journal
                .session_closure_status(context, p.session)
                .expect("closed"),
            SessionClosureStatus::Closed(report.report)
        );
    }
}

#[test]
fn historical_session_projection_preserves_prior_closure_and_terminal_counts() {
    use crate::retired_device::{RecordMetadata, SessionState};
    let mut p = populated();
    let key = JournalKey::open(&p.pr.join("key")).expect("key");
    let mut archives = crate::SessionArchiveStore::provision(
        &p.pr.join("history-archives.redb"),
        p.jr.identity().expect("identity"),
    )
    .expect("archives");
    let archive =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("original peer binding");
    archives
        .retain(&p.jr, &p.f.responder, p.session, &archive)
        .expect("retain archive");
    let prior =
        p.jr.begin_session_closure(&p.f.responder, p.session)
            .expect("original closure");
    for terminal in [false, true] {
        if terminal {
            p.jr.acknowledge_session_closure(&p.f.responder, p.session, prior.report)
                .expect("prior host acknowledgment");
        }
        let image = p.jr.image().expect("original image");
        let record = image.records.get(&record_id(&p.session)).expect("session");
        let projected = super::super::historical_session(&image, &key, record, &mut archives)
            .expect("historical metadata");
        let state = match projected {
            RecordMetadata::Session(session) => Ok(session.state),
            _ => Err("expected session"),
        }
        .expect("session");
        match state {
            SessionState::Live {
                epochs,
                previous_closure,
            } => {
                assert!(!terminal);
                assert_eq!(previous_closure, Some(prior.report));
                assert_eq!(epochs.len(), prior.epochs.len());
            }
            SessionState::Terminal { report, epochs, .. } => {
                assert!(terminal);
                assert_eq!(report, *prior.report.as_bytes());
                assert_eq!(epochs.len(), prior.epochs.len());
                for (retained, original) in epochs.iter().zip(&prior.epochs) {
                    assert_eq!(
                        (retained.epoch, retained.sent, retained.acknowledged),
                        (original.epoch, original.sent, original.acknowledged_before)
                    );
                }
            }
        }
    }
}
