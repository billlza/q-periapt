// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::{envelope, open_envelope, Purpose};
use crate::durable::tests::ChildGuard;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn advance(p: &mut Pair, role: u8, target: u64) -> RekeyControlStep {
    let (journal, context, signer) = if role == 1 {
        (&mut p.ji, &p.f.initiator, &p.f.signer_i)
    } else {
        (&mut p.jr, &p.f.responder, &p.f.signer_r)
    };
    journal
        .advance_rekey_control(context, p.session, target, signer, 150)
        .expect("control step")
}
fn receive(p: &mut Pair, role: u8, wire: &[u8]) -> RekeyControlStep {
    let (journal, context, signer) = if role == 1 {
        (&mut p.ji, &p.f.initiator, &p.f.signer_i)
    } else {
        (&mut p.jr, &p.f.responder, &p.f.signer_r)
    };
    journal
        .receive_rekey_control(context, p.session, wire, signer, 150)
        .expect("authenticated control")
}
fn output(step: RekeyControlStep) -> Vec<u8> {
    let message = match step {
        RekeyControlStep::Output(message) => Ok(message),
        RekeyControlStep::LocallyConfirmed(epoch) => Err(epoch),
    }
    .expect("expected committed output, observed local completion");
    assert!(message.target_epoch() > 0);
    message.as_bytes().to_vec()
}

#[test]
fn control_request_is_durable_and_repeated_targets_never_start_another_exchange() {
    let mut p = Pair::new();
    p.activate();
    let request = output(advance(&mut p, 2, 1));
    assert_eq!(
        p.jr.rekey_progress(&p.f.responder, p.session)
            .expect("pending target")
            .pending_epoch,
        Some(1)
    );
    assert_eq!(open_envelope(&request).expect("envelope").0.len(), 153);
    assert_eq!(
        p.jr.rekey_request_status(&p.f.responder, p.session)
            .expect("status"),
        RekeyRequestStatus::Committed
    );
    let revision = p.jr.image().expect("committed").revision;
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(output(advance(&mut p, 2, 1)), request);
    assert_eq!(p.jr.image().expect("replay").revision, revision);
    let offer = output(receive(&mut p, 1, &request));
    let proposer_revision = p.ji.image().expect("offer").revision;
    assert_eq!(output(receive(&mut p, 1, &request)), offer);
    assert_eq!(p.ji.image().expect("one offer").revision, proposer_revision);
    let response = output(receive(&mut p, 2, &offer));
    let final_wire = output(receive(&mut p, 1, &response));
    assert_eq!(output(receive(&mut p, 1, &request)), offer);
    let receipt = output(receive(&mut p, 2, &final_wire));
    assert!(matches!(
        receive(&mut p, 1, &receipt),
        RekeyControlStep::LocallyConfirmed(1)
    ));
    let settled = p.ji.image().expect("settled").revision;
    assert_eq!(output(receive(&mut p, 1, &request)), offer);
    assert_eq!(p.ji.image().expect("old request").revision, settled);
    for role in [1, 2] {
        assert!(matches!(
            advance(&mut p, role, 1),
            RekeyControlStep::LocallyConfirmed(1)
        ));
    }
    assert_eq!(
        p.jr.rekey_request_status(&p.f.responder, p.session)
            .expect("retired request"),
        RekeyRequestStatus::Absent
    );
    assert_eq!(complete_rekey(&mut p), 2);
    assert!(matches!(
        p.ji.receive_rekey_control(&p.f.initiator, p.session, &request, &p.f.signer_i, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

fn queue(queue: &mut VecDeque<(u8, Vec<u8>)>, recipient: u8, step: RekeyControlStep) {
    if let RekeyControlStep::Output(message) = step {
        assert!(message.as_bytes().len() < 8192);
        queue.push_back((recipient, message.as_bytes().to_vec()));
        assert!(queue.len() <= 32, "bounded retained control delivery queue");
    }
}

#[test]
fn control_driver_progresses_one_way_with_idle_peer_loss_duplicates_and_dispatch_cancellation() {
    for active in [1, 2] {
        let mut p = Pair::with_fixture(crate::bootstrap::tests::fixture_with_send_budget(
            PrekeyQuality::OneTimeBoth,
            crate::ApplicationSendBudget::new(1).expect("budget"),
        ));
        p.activate();
        for target in 1..=3 {
            let (sender, receiver, sc, rc) = if active == 1 {
                (&mut p.ji, &mut p.jr, &p.f.initiator, &p.f.responder)
            } else {
                (&mut p.jr, &mut p.ji, &p.f.responder, &p.f.initiator)
            };
            let slot = sender
                .next_message_id(sc, p.session, 150)
                .expect("single application slot");
            let wire = sender
                .send_message(sc, p.session, slot, b"one-way", b"application", 150)
                .expect("real data");
            assert_eq!(
                receiver
                    .receive_message(rc, p.session, &wire, b"application", 150)
                    .expect("peer decrypts")
                    .as_bytes(),
                b"one-way"
            );
            receiver
                .consume_message(rc, p.session, slot, 150)
                .expect("consume");
            let ack = receiver
                .message_acknowledgement(rc, p.session, 150)
                .expect("ACK");
            sender
                .accept_message_acknowledgement(sc, p.session, &ack, 150)
                .expect("retire data");
            assert!(matches!(
                sender.next_message_id(sc, p.session, 150),
                Err(DurableError::Protocol(Error::RekeyRequired))
            ));
            // Cancellation discards a committed public output and the local owner.
            // The peer emits no application messages or autonomous poll requests.
            let cancelled = output(advance(&mut p, active, target));
            if active == 1 {
                p.ji.close();
                p.ji = reopen(&p.pi, p.f.initiator_device());
            } else {
                p.jr.close();
                p.jr = reopen(&p.pr, p.f.local_device());
            }
            assert_eq!(output(advance(&mut p, active, target)), cancelled);
            let mut dropped = BTreeSet::new();
            let mut duplicated = BTreeSet::new();
            let mut seen = BTreeMap::new();
            let mut pending = VecDeque::new();
            let mut completed = false;
            for _attempt in 0..32 {
                let step = advance(&mut p, active, target);
                if matches!(step,RekeyControlStep::LocallyConfirmed(epoch) if epoch==target) {
                    completed = true;
                    break;
                }
                queue(&mut pending, 3 - active, step);
                for _delivery in 0..8 {
                    let Some((recipient, wire)) = pending.pop_front() else {
                        break;
                    };
                    let (body, _) = open_envelope(&wire).expect("wire");
                    let tag: [u8; 8] = body.get(..8).expect("tag").try_into().expect("width");
                    let key = (recipient, tag);
                    if let Some(previous) = seen.insert(key, wire.clone()) {
                        assert_eq!(previous, wire, "exact output after retries");
                    }
                    if dropped.insert(key) {
                        continue;
                    }
                    if duplicated.insert(key) {
                        pending.push_front((recipient, wire.clone()));
                    }
                    let reply = receive(&mut p, recipient, &wire);
                    queue(&mut pending, 3 - recipient, reply);
                }
            }
            assert!(completed, "bounded control-only retry schedule exhausted");
            let expected = if (target % 2 == 1 && active == 2) || (target % 2 == 0 && active == 1) {
                5
            } else {
                4
            };
            assert_eq!(dropped.len(), expected, "lose every distinct flight once");
            for role in [1, 2] {
                assert!(
                    matches!(advance(&mut p,role,target),RekeyControlStep::LocallyConfirmed(epoch) if epoch==target)
                );
            }
            let idle = if active == 1 {
                p.jr.application_send_progress(&p.f.responder, p.session)
            } else {
                p.ji.application_send_progress(&p.f.initiator, p.session)
            }
            .expect("idle accounting");
            assert_eq!(
                (idle.committed, idle.reserved, idle.remaining),
                (0, false, 1)
            );
        }
    }
}

#[test]
fn control_request_rejects_untrusted_fields_signatures_and_revoked_cached_output() {
    let mut p = Pair::new();
    p.activate();
    let request = output(advance(&mut p, 2, 1));
    let original = p.ji.image().expect("before").revision;
    let (body, signature) = open_envelope(&request).expect("body");
    for at in [0, 8, 40, 72, 104, 112, 120, 121] {
        let mut altered = body.to_vec();
        *altered.get_mut(at).expect("field") ^= 1;
        let signed =
            p.f.signer_r
                .sign(Purpose::RekeyRequest, &altered)
                .expect("actual signature");
        let wire = envelope(&altered, &signed).expect("envelope");
        assert!(p
            .ji
            .receive_rekey_control(&p.f.initiator, p.session, &wire, &p.f.signer_i, 150)
            .is_err());
    }
    for at in [0, signature.len() - 1] {
        let mut altered = signature.to_vec();
        *altered.get_mut(at).expect("signature") ^= 1;
        let wire = envelope(body, &altered).expect("envelope");
        assert!(matches!(
            p.ji.respond_rekey_request(&p.f.initiator, p.session, &wire, &p.f.signer_i, 150),
            Err(DurableError::Protocol(Error::Authentication))
        ));
    }
    let wrong_purpose =
        p.f.signer_r
            .sign(Purpose::RekeyOffer, body)
            .expect("different purpose");
    assert!(p
        .ji
        .respond_rekey_request(
            &p.f.initiator,
            p.session,
            &envelope(body, &wrong_purpose).expect("wire"),
            &p.f.signer_i,
            150
        )
        .is_err());
    assert_eq!(p.ji.image().expect("no rejected work").revision, original);
    assert!(p
        .jr
        .prepare_rekey_request(&p.f.responder, p.session, &p.f.signer_r, u64::MAX)
        .is_err());
    let update = rosters::tests::update(p.f.initiator_device(), 90, 2, false);
    p.jr.install_roster(&update, 150).expect("revocation");
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.rekey_request_status(&p.f.responder, p.session)
            .expect("metadata"),
        RekeyRequestStatus::Committed
    );
    assert!(matches!(
        p.jr.prepare_rekey_request(&p.f.responder, p.session, &p.f.signer_r, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));

    let mut p = Pair::new();
    p.activate();
    let request = output(advance(&mut p, 2, 1));
    let mut image = p.jr.image().expect("cached request");
    let record = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("state");
    let start = record
        .payload
        .windows(request.len())
        .position(|bytes| bytes == request)
        .expect("exact retained wire");
    *record
        .payload
        .get_mut(start + request.len() - 1)
        .expect("signature byte") ^= 1;
    p.jr.persist(&mut image)
        .expect("authenticated image with corrupt signature");
    assert!(matches!(
        p.jr.prepare_rekey_request(&p.f.responder, p.session, &p.f.signer_r, 150),
        Err(DurableError::InvalidCheckpoint(Error::Authentication))
    ));
    assert!(p.jr.active.is_none());
}

#[test]
fn control_request_sync_faults_recover_exact_preparation_and_offer_admission() {
    for replying in [false, true] {
        let mut baseline = Pair::new();
        baseline.activate();
        let request = if replying {
            output(advance(&mut baseline, 2, 1))
        } else {
            Vec::new()
        };
        let (path, device, context, signer) = if replying {
            baseline.ji.close();
            (
                &baseline.pi,
                baseline.f.initiator_device(),
                &baseline.f.initiator,
                &baseline.f.signer_i,
            )
        } else {
            baseline.jr.close();
            (
                &baseline.pr,
                baseline.f.local_device(),
                &baseline.f.responder,
                &baseline.f.signer_r,
            )
        };
        let (mut normal, _, count, _) = fault_store(path, device, false);
        count.store(0, Ordering::SeqCst);
        if replying {
            normal
                .respond_rekey_request(context, baseline.session, &request, signer, 150)
                .expect("measure offer");
        } else {
            normal
                .prepare_rekey_request(context, baseline.session, signer, 150)
                .expect("measure request");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((8..=24).contains(&barriers), "barriers={barriers}");
        normal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let mut p = Pair::new();
                p.activate();
                let request = if replying {
                    output(advance(&mut p, 2, 1))
                } else {
                    Vec::new()
                };
                let (path, device, context, signer) = if replying {
                    p.ji.close();
                    (&p.pi, p.f.initiator_device(), &p.f.initiator, &p.f.signer_i)
                } else {
                    p.jr.close();
                    (&p.pr, p.f.local_device(), &p.f.responder, &p.f.signer_r)
                };
                let (mut failed, remaining, _, _) = fault_store(path, device, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = if replying {
                    failed.respond_rekey_request(context, p.session, &request, signer, 150)
                } else {
                    failed.prepare_rekey_request(context, p.session, signer, 150)
                };
                crate::durable::tests::assert_sync_failure(result, after);
                assert!(failed.active.is_none());
                let mut restored = reopen(path, device);
                let wire = if replying {
                    restored
                        .respond_rekey_request(context, p.session, &request, signer, 150)
                        .expect("exact offer")
                } else {
                    restored
                        .prepare_rekey_request(context, p.session, signer, 150)
                        .expect("exact request")
                };
                let repeat = if replying {
                    restored
                        .respond_rekey_request(context, p.session, &request, signer, 150)
                        .expect("replay")
                } else {
                    restored
                        .prepare_rekey_request(context, p.session, signer, 150)
                        .expect("replay")
                };
                assert_eq!(wire, repeat);
                assert_eq!(
                    restored
                        .application_send_progress(context, p.session)
                        .expect("no app spending")
                        .committed,
                    0
                );
            }
        }
        eprintln!(
            "CONTROL_REQUEST_SYNC_RECOVERY replying={replying} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn control_request_process_cuts_keep_exact_signatures_and_exclude_concurrent_writers() {
    for stage in [
        "rekey-request-reserved",
        "rekey-request-computed",
        "rekey-request-committed",
    ] {
        let mut p = Pair::new();
        p.activate();
        p.jr.close();
        let path = &p.pr;
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("fixture");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("operation"), b"rekey-request").expect("operation");
        let log = fs::File::create_new(path.join("control-child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
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
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{stage}: {}",
                fs::read_to_string(path.join("control-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(path.join("ready")).expect("complete marker"),
            stage
        );
        // The competitor is deadline-bounded too: a blocking nested lock is a
        // failure, not permission for this test to wait forever.
        let log = fs::File::create_new(path.join("contender.log")).expect("log");
        let mut competitor = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::messages::tests::message_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_REQUEST_CONTENDER", "1")
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned contender"),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = competitor.0.try_wait().expect("contender status") {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(path.join("contender.log")).expect("log")
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "contending writer did not fail within deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill");
        assert!(!child.0.wait().expect("reap").success());
        p.jr = reopen(path, p.f.local_device());
        assert_eq!(
            p.jr.rekey_request_status(&p.f.responder, p.session)
                .expect("durable phase"),
            if stage == "rekey-request-committed" {
                RekeyRequestStatus::Committed
            } else {
                RekeyRequestStatus::SignatureReserved
            }
        );
        let request = output(advance(&mut p, 2, 1));
        if stage == "rekey-request-computed" {
            assert_eq!(
                fs::read(p.pr.join("rekey-effect")).expect("actual pre-pin signature"),
                request
            );
        }
        assert_eq!(output(advance(&mut p, 2, 1)), request);
        let offer = output(receive(&mut p, 1, &request));
        let reply = output(receive(&mut p, 2, &offer));
        let final_wire = output(receive(&mut p, 1, &reply));
        let receipt = output(receive(&mut p, 2, &final_wire));
        assert!(matches!(
            receive(&mut p, 1, &receipt),
            RekeyControlStep::LocallyConfirmed(1)
        ));
    }
}
