// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{durable::tests::ChildGuard, ApplicationSendBudget};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn pair(limit: u16) -> Pair {
    let mut p = Pair::with_fixture(crate::bootstrap::tests::fixture_with_send_budget(
        PrekeyQuality::OneTimeBoth,
        ApplicationSendBudget::new(limit).expect("budget"),
    ));
    p.activate();
    p
}
fn progress(p: &mut Pair) -> SendProgress {
    p.ji.application_send_progress(&p.f.initiator, p.session)
        .expect("progress")
}
fn send(p: &mut Pair, text: &[u8]) -> (MessageId, Vec<u8>) {
    let id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("slot");
    (id, p.send(id, text))
}
fn final_only(p: &mut Pair) -> (Vec<u8>, Vec<u8>) {
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let reply =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("response");
    let final_wire =
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150)
            .expect("final");
    (reply, final_wire)
}
fn finish(p: &mut Pair, final_wire: &[u8]) -> Vec<u8> {
    p.jr.finish_rekey(&p.f.responder, p.session, final_wire, &p.f.signer_r, 150)
        .expect("receipt")
}
fn accept(p: &mut Pair, receipt: &[u8]) {
    assert_eq!(
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, receipt, 150)
            .expect("accept receipt"),
        1
    );
}

#[test]
fn send_budget_survives_acks_reopen_and_direct_ids_in_both_directions() {
    for role in [1, 2] {
        let mut p = pair(3);
        let (sender, receiver, sc, rc) = if role == 1 {
            (&mut p.ji, &mut p.jr, &p.f.initiator, &p.f.responder)
        } else {
            (&mut p.jr, &mut p.ji, &p.f.responder, &p.f.initiator)
        };
        let mut wires = Vec::new();
        for index in 0..3 {
            let id = MessageId::for_epoch(&p.session, role, 0, index).expect("direct ID");
            let wire = sender
                .send_message(sc, p.session, id, b"bounded", b"application", 150)
                .expect("send");
            wires.push((id, wire));
        }
        let before = sender.image().expect("spent").revision;
        assert!(matches!(
            sender.next_message_id(sc, p.session, 150),
            Err(DurableError::Protocol(Error::RekeyRequired))
        ));
        let extra = MessageId::for_epoch(&p.session, role, 0, 3).expect("direct extra ID");
        assert!(matches!(
            sender.send_message(sc, p.session, extra, b"extra", b"application", 150),
            Err(DurableError::Protocol(Error::RekeyRequired))
        ));
        let (id, wire) = wires.first().expect("retained outbox");
        assert_eq!(
            sender
                .resume_message(sc, p.session, *id, 150)
                .expect("cached output"),
            *wire
        );
        assert_eq!(
            sender
                .send_message(sc, p.session, *id, b"bounded", b"application", 150)
                .expect("same input"),
            *wire
        );
        assert!(matches!(
            sender.send_message(sc, p.session, *id, b"changed", b"application", 150),
            Err(DurableError::Protocol(Error::Conflict))
        ));
        assert_eq!(
            sender.image().expect("no admission mutation").revision,
            before
        );
        for (id, wire) in &wires {
            assert_eq!(
                receiver
                    .receive_message(rc, p.session, wire, b"application", 150)
                    .expect("delivery")
                    .as_bytes(),
                b"bounded"
            );
            receiver
                .consume_message(rc, p.session, *id, 150)
                .expect("consume");
        }
        let ack = receiver
            .message_acknowledgement(rc, p.session, 150)
            .expect("ACK");
        assert_eq!(
            sender
                .accept_message_acknowledgement(sc, p.session, &ack, 150)
                .expect("retire all outboxes"),
            3
        );
        let observed = sender
            .application_send_progress(sc, p.session)
            .expect("no refund");
        assert_eq!(
            (observed.committed, observed.remaining, observed.reserved),
            (3, 0, false)
        );
        assert!(matches!(
            sender.resume_message(sc, p.session, *id, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        p.ji.close();
        p.jr.close();
        p.ji = reopen(&p.pi, p.f.initiator_device());
        p.jr = reopen(&p.pr, p.f.local_device());
        let (sender, sc) = if role == 1 {
            (&mut p.ji, &p.f.initiator)
        } else {
            (&mut p.jr, &p.f.responder)
        };
        assert_eq!(
            sender
                .application_send_progress(sc, p.session)
                .expect("durable budget"),
            observed
        );
        assert!(matches!(
            sender.next_message_id(sc, p.session, 150),
            Err(DurableError::Protocol(Error::RekeyRequired))
        ));
        assert_eq!(complete_rekey(&mut p), 1);
        let (sender, sc) = if role == 1 {
            (&mut p.ji, &p.f.initiator)
        } else {
            (&mut p.jr, &p.f.responder)
        };
        assert_eq!(
            sender
                .application_send_progress(sc, p.session)
                .expect("confirmed budget")
                .remaining,
            3
        );
    }
}

#[test]
fn send_budget_counts_both_epochs_until_receipt_and_preserves_new_epoch_spending() {
    let mut p = pair(3);
    send(&mut p, b"old");
    let (_, final_wire) = final_only(&mut p);
    send(&mut p, b"early one");
    send(&mut p, b"early two");
    let before = progress(&mut p);
    assert_eq!(
        (
            before.confirmed_epoch,
            before.sending_epoch,
            before.committed,
            before.remaining
        ),
        (0, 1, 3, 0)
    );
    assert!(matches!(
        p.ji.next_message_id(&p.f.initiator, p.session, 150),
        Err(DurableError::Protocol(Error::RekeyRequired))
    ));
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(progress(&mut p), before);
    let receipt = finish(&mut p, &final_wire);
    // Receipt generation at the other peer is not local receipt acceptance.
    assert_eq!(progress(&mut p), before);
    accept(&mut p, &receipt);
    let after = progress(&mut p);
    assert_eq!(
        (
            after.confirmed_epoch,
            after.sending_epoch,
            after.committed,
            after.remaining
        ),
        (1, 1, 2, 1)
    );
    accept(&mut p, &receipt);
    assert_eq!(progress(&mut p), after);
    let (id, wire) = send(&mut p, b"last new-epoch slot");
    assert_eq!(p.receive(&wire).as_bytes(), b"last new-epoch slot");
    p.jr.consume_message(&p.f.responder, p.session, id, 150)
        .expect("out-of-order consumption");
    assert_eq!(progress(&mut p).remaining, 0);
    let report =
        p.ji.begin_closed_epoch_resolution(&p.f.initiator, p.session, 0, 150)
            .expect("old unknown outcome");
    p.ji.acknowledge_closed_epoch_resolution(
        &p.f.initiator,
        p.session,
        0,
        report.resolution_id(),
        150,
    )
    .expect("application accounts for old send");
    assert_eq!(progress(&mut p).remaining, 0);
}

#[test]
fn send_budget_crash_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_SEND_BUDGET_CHILD") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let public = fs::read(path.join("public-keys"))?;
    let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
    let budget = ApplicationSendBudget::new(u16::from_be_bytes(
        fs::read(path.join("budget"))?
            .try_into()
            .map_err(|_| "budget length")?,
    ))?;
    let f = crate::bootstrap::tests::fixture_from_public_with_budget(
        PrekeyQuality::OneTimeBoth,
        Some((a.try_into()?, b.try_into()?)),
        budget,
    );
    let session = fs::read(path.join("session"))?
        .try_into()
        .map_err(|_| "session length")?;
    let id = MessageId::from_trusted_state(
        fs::read(path.join("slot"))?
            .try_into()
            .map_err(|_| "slot length")?,
    )?;
    let mut journal = reopen(path, f.initiator_device());
    journal.send_message(
        &f.initiator,
        session,
        id,
        b"reserved last slot",
        b"application",
        150,
    )?;
    fs::write(path.join("returned"), b"unexpected return")?;
    Ok(())
}

fn kill_with_last_slot_reserved(p: &mut Pair) -> MessageId {
    let limit = progress(p).limit;
    let slot =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("last available slot");
    assert_eq!(progress(p).remaining, 1);
    p.ji.close();
    let path = &p.pi;
    let mut public =
        p.f.reusable
            .public_key()
            .expect("public")
            .to_bytes()
            .to_vec();
    public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
    for (name, bytes) in [
        ("public-keys", public.as_slice()),
        ("session", &p.session),
        ("slot", slot.as_bytes()),
        ("budget", &limit.to_be_bytes()),
    ] {
        fs::write(path.join(name), bytes).expect("owned public fixture");
    }
    let log = fs::File::create_new(path.join("budget-child.log")).expect("log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::messages::tests::send_budget::send_budget_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_SEND_BUDGET_CHILD", path)
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .env("QPERIAPT_MESSAGES_STAGE", "reserved")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "reservation barrier not reached: {}",
            fs::read_to_string(path.join("budget-child.log")).expect("child log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.join("returned").exists());
    child.0.kill().expect("kill owned child");
    assert!(!child.0.wait().expect("reap").success());
    p.ji = reopen(path, p.f.initiator_device());
    let held = progress(p);
    assert!(held.reserved);
    assert_eq!(held.remaining, 0);
    slot
}

#[test]
fn send_budget_last_reservation_resumes_before_or_after_receipt_without_deadlock() {
    let mut p = pair(1);
    let slot = kill_with_last_slot_reserved(&mut p);
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("control ignores app budget");
    let reply =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("response");
    assert!(matches!(
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150),
        Err(DurableError::Suspended)
    ));
    let wire =
        p.ji.resume_message(&p.f.initiator, p.session, slot, 150)
            .expect("already admitted slot");
    assert_eq!(p.receive(&wire).as_bytes(), b"reserved last slot");
    assert_eq!(
        (progress(&mut p).committed, progress(&mut p).remaining),
        (1, 0)
    );
    let (_, final_wire) = final_only(&mut p);
    assert!(matches!(
        p.ji.next_message_id(&p.f.initiator, p.session, 150),
        Err(DurableError::Protocol(Error::RekeyRequired))
    ));
    let receipt = finish(&mut p, &final_wire);
    accept(&mut p, &receipt);
    assert_eq!(progress(&mut p).remaining, 1);

    let mut p = pair(3);
    send(&mut p, b"old");
    let (_, final_wire) = final_only(&mut p);
    send(&mut p, b"new first");
    let slot = kill_with_last_slot_reserved(&mut p);
    let before = progress(&mut p);
    assert_eq!(
        (before.committed, before.reserved, before.remaining),
        (2, true, 0)
    );
    let receipt = finish(&mut p, &final_wire);
    accept(&mut p, &receipt);
    let pending = progress(&mut p);
    assert_eq!(
        (pending.committed, pending.reserved, pending.remaining),
        (1, true, 1)
    );
    let wire =
        p.ji.resume_message(&p.f.initiator, p.session, slot, 150)
            .expect("reservation survives receipt");
    assert_eq!(p.receive(&wire).as_bytes(), b"reserved last slot");
    let done = progress(&mut p);
    assert_eq!(
        (done.committed, done.reserved, done.remaining),
        (2, false, 1)
    );
    assert_eq!(
        p.ji.resume_message(&p.f.initiator, p.session, slot, 150)
            .expect("exact duplicate"),
        wire
    );
    assert_eq!(progress(&mut p), done);
}

#[test]
fn send_budget_last_slot_sync_faults_never_refund_or_double_charge() {
    for role in [1, 2] {
        let mut baseline = pair(1);
        let (path, device, context) = if role == 1 {
            baseline.ji.close();
            (
                &baseline.pi,
                baseline.f.initiator_device(),
                &baseline.f.initiator,
            )
        } else {
            baseline.jr.close();
            (
                &baseline.pr,
                baseline.f.local_device(),
                &baseline.f.responder,
            )
        };
        let (mut normal, _, count, _) = fault_store(path, device, false);
        count.store(0, Ordering::SeqCst);
        let slot = id(baseline.session, role, 1);
        normal
            .send_message(
                context,
                baseline.session,
                slot,
                b"last",
                b"application",
                150,
            )
            .expect("measure last-slot commit");
        let barriers = count.load(Ordering::SeqCst);
        assert!((8..=24).contains(&barriers), "barriers={barriers}");
        normal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let mut p = pair(1);
                let slot = id(p.session, role, 1);
                let (path, device, context) = if role == 1 {
                    p.ji.close();
                    (&p.pi, p.f.initiator_device(), &p.f.initiator)
                } else {
                    p.jr.close();
                    (&p.pr, p.f.local_device(), &p.f.responder)
                };
                let (mut failed, remaining, _, _) = fault_store(path, device, after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    failed.send_message(context, p.session, slot, b"last", b"application", 150),
                    after,
                );
                assert!(failed.active.is_none());
                let mut recovered = reopen(path, device);
                let wire = recovered
                    .send_message(context, p.session, slot, b"last", b"application", 150)
                    .expect("same admitted operation");
                assert_eq!(
                    recovered
                        .resume_message(context, p.session, slot, 150)
                        .expect("exact output"),
                    wire
                );
                let result = recovered
                    .application_send_progress(context, p.session)
                    .expect("durable count");
                assert_eq!(
                    (result.committed, result.reserved, result.remaining),
                    (1, false, 0)
                );
                assert!(matches!(
                    recovered.next_message_id(context, p.session, 150),
                    Err(DurableError::Protocol(Error::RekeyRequired))
                ));
                if role == 1 {
                    assert_eq!(p.receive(&wire).as_bytes(), b"last");
                } else {
                    assert_eq!(
                        p.ji.receive_message(&p.f.initiator, p.session, &wire, b"application", 150)
                            .expect("reverse delivery")
                            .as_bytes(),
                        b"last"
                    );
                }
            }
        }
        eprintln!(
            "SEND_BUDGET_SYNC_RECOVERY role={role} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn send_budget_rejects_authenticated_over_limit_frames_and_stored_own_counts() {
    let mut p = pair(3);
    for _ in 0..3 {
        let (_, wire) = send(&mut p, b"admitted");
        p.receive(&wire);
    }
    let mut exceeded = state(&mut p.ji, &p.session);
    let slot = MessageId::for_epoch(&p.session, 1, 0, 3).expect("one past budget");
    let t = exceeded.traffic_mut(0).expect("traffic");
    t.pending = Some(SendPlan {
        id: slot,
        plaintext: Zeroizing::new(b"bypassing the public governor".to_vec()),
        ad: b"application".to_vec(),
    });
    let wire = t
        .send(slot, b"bypassing the public governor", b"application")
        .expect("malicious peer with valid traffic keys");
    let mut ungoverned = state(&mut p.jr, &p.session);
    assert_eq!(
        ungoverned
            .traffic_mut(0)
            .expect("receiver")
            .receive(&wire, b"application")
            .expect("frame really authenticates")
            .as_bytes(),
        b"bypassing the public governor"
    );
    let before = p.jr.image().expect("before").revision;
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &wire, b"application", 150),
        Err(DurableError::Protocol(Error::PolicyDenied))
    ));
    assert_eq!(p.jr.image().expect("no receive advance").revision, before);
    let mut image = p.ji.image().expect("image");
    image
        .records
        .get_mut(&record_id(&p.session))
        .expect("record")
        .payload = exceeded.encode();
    p.ji.persist(&mut image)
        .expect("authenticated structurally valid but policy-invalid fixture");
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert!(matches!(
        p.ji.application_send_progress(&p.f.initiator, p.session),
        Err(DurableError::Protocol(Error::State))
    ));
    assert!(matches!(
        p.ji.resume_message(&p.f.initiator, p.session, slot, 150),
        Err(DurableError::Protocol(Error::State))
    ));
}

fn over_limit_control(
    wire: &[u8],
    root: &ZeroizingBytes<32>,
    signer: &crate::DeviceSigningKey,
    receipt: bool,
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let (body, _) = crate::crypto::open_envelope(wire).expect("body");
    let mut body = body.to_vec();
    let core = body.len() - 32;
    body.get_mut(core - 8..core)
        .expect("signed close count")
        .copy_from_slice(&4_u64.to_be_bytes());
    let (name, domain, purpose) = if receipt {
        (
            b"receipt-confirmation".as_slice(),
            b"receipt-core".as_slice(),
            crate::crypto::Purpose::RekeyReceipt,
        )
    } else {
        (
            b"final-confirmation".as_slice(),
            b"final-core".as_slice(),
            crate::crypto::Purpose::RekeyFinal,
        )
    };
    let mut mac_key = ZeroizingBytes::<32>::zeroed();
    Hkdf::<Sha256>::new(None, root.as_bytes())
        .expand(
            &[b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/".as_slice(), name].concat(),
            mac_key.as_mut_bytes(),
        )
        .expect("confirmation key");
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key.as_bytes()).expect("MAC");
    mac.update(&rekey_digest(domain, body.get(..core).expect("core")));
    body.get_mut(core..)
        .expect("tag")
        .copy_from_slice(&mac.finalize().into_bytes());
    let signature = signer.sign(purpose, &body).expect("actual peer signatures");
    signer
        .public_key()
        .expect("public identity")
        .verify(purpose, &body, &signature)
        .expect("both signatures authenticate the changed count");
    crate::crypto::envelope(&body, &signature).expect("wire")
}

#[test]
fn send_budget_rejects_over_limit_signed_close_counts_before_committing_work() {
    let mut p = pair(3);
    let (_, final_wire) = final_only(&mut p);
    let root = state(&mut p.ji, &p.session).rekey;
    let bad = over_limit_control(&final_wire, &root, &p.f.signer_i, false);
    let before = p.jr.image().expect("before final").revision;
    assert!(matches!(
        p.jr.finish_rekey(&p.f.responder, p.session, &bad, &p.f.signer_r, 150),
        Err(DurableError::Protocol(Error::PolicyDenied))
    ));
    assert_eq!(
        p.jr.image().expect("no signature reservation").revision,
        before
    );
    let receipt = finish(&mut p, &final_wire);
    let bad = over_limit_control(&receipt, &root, &p.f.signer_r, true);
    let before = p.ji.image().expect("before receipt").revision;
    assert!(matches!(
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &bad, 150),
        Err(DurableError::Protocol(Error::PolicyDenied))
    ));
    assert_eq!(p.ji.image().expect("no cutover").revision, before);
    accept(&mut p, &receipt);
    assert_eq!(progress(&mut p).remaining, 3);
}
