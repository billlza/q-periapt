// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, Fixture},
    durable::tests::{directory, fault_store, new_store, reopen},
    PrekeyQuality,
};
use std::{fs, sync::atomic::Ordering};

struct Pair {
    f: Fixture,
    di: tempfile::TempDir,
    dr: tempfile::TempDir,
    pi: std::path::PathBuf,
    pr: std::path::PathBuf,
    ji: DeviceJournal,
    jr: DeviceJournal,
    request: InitiationId,
    initial: Vec<u8>,
    reply: Vec<u8>,
    final_wire: Vec<u8>,
    session: [u8; 32],
}
impl Pair {
    fn new() -> Self {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let di = directory();
        let dr = directory();
        let pi = di.path().canonicalize().expect("initiator path");
        let pr = dr.path().canonicalize().expect("responder path");
        let mut ji = new_store(&pi, f.initiator_device());
        let mut jr = new_store(&pr, f.local_device());
        let request = InitiationId::generate().expect("request");
        let initial = ji
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("initial");
        let (pq, classical) = f.sources();
        let reply = jr
            .respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classical,
                150,
            )
            .expect("reply");
        assert!(matches!(
            ji.activate_initiator_messages(Arc::clone(&f.initiator), request, 150),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            jr.activate_responder_messages(Arc::clone(&f.responder), &initial, 150),
            Err(DurableError::Suspended)
        ));
        let completed = ji
            .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
            .expect("final");
        let final_wire = completed.final_message().to_vec();
        let session = completed.session_id();
        assert_eq!(
            jr.finish(Arc::clone(&f.responder), &initial, &final_wire, 150)
                .expect("finish"),
            session
        );
        Self {
            f,
            di,
            dr,
            pi,
            pr,
            ji,
            jr,
            request,
            initial,
            reply,
            final_wire,
            session,
        }
    }
    fn activate(&mut self) {
        assert_eq!(
            self.ji
                .activate_initiator_messages(Arc::clone(&self.f.initiator), self.request, 150)
                .expect("activate initiator"),
            self.session
        );
        assert_eq!(
            self.jr
                .activate_responder_messages(Arc::clone(&self.f.responder), &self.initial, 150)
                .expect("activate responder"),
            self.session
        );
    }
    fn send(&mut self, id: MessageId, value: &[u8]) -> Vec<u8> {
        self.ji
            .send_message(
                &self.f.initiator,
                self.session,
                id,
                value,
                b"application",
                150,
            )
            .expect("send")
    }
    fn receive(&mut self, wire: &[u8]) -> CommittedPlaintext {
        self.jr
            .receive_message(&self.f.responder, self.session, wire, b"application", 150)
            .expect("receive")
    }
}
fn id(session: [u8; 32], role: u8, ordinal: u64) -> MessageId {
    MessageId::for_index(&session, role, ordinal - 1).expect("id")
}
fn state(journal: &mut DeviceJournal, session: &[u8; 32]) -> State {
    State::decode(
        &journal
            .image()
            .expect("image")
            .records
            .get(&record_id(session))
            .expect("message record")
            .payload,
    )
    .expect("state")
}

#[test]
fn confirmed_roots_transfer_atomically_and_both_directions_survive_reopen() {
    let mut p = Pair::new();
    let old = p.ji.image().expect("bootstrap");
    let record = old
        .records
        .get(&initiator::operation_id(p.request))
        .expect("bootstrap record");
    let mut operation =
        p.ji.restore_initiator(
            Arc::clone(&p.f.initiator),
            initiator::checkpoint(record).expect("checkpoint"),
        )
        .expect("root owner");
    let (_, original_root) = operation.retire_session_root().expect("fixture root");
    p.activate();
    p.activate();
    for journal in [&mut p.ji, &mut p.jr] {
        let image = journal.image().expect("image");
        for record in image.records.values() {
            assert!(!record
                .payload
                .windows(32)
                .any(|bytes| bytes == original_root.as_bytes()));
        }
    }
    assert_eq!(
        p.ji.resume_initial(Arc::clone(&p.f.initiator), p.request, 150)
            .expect("initial replay"),
        p.initial
    );
    assert_eq!(
        p.ji.resume_reply(Arc::clone(&p.f.initiator), p.request, 150)
            .expect("final replay")
            .final_message(),
        p.final_wire
    );
    assert_eq!(
        p.jr.resume(Arc::clone(&p.f.responder), &p.initial, 150)
            .expect("reply replay"),
        p.reply
    );
    assert_eq!(
        p.jr.finish(Arc::clone(&p.f.responder), &p.initial, &p.final_wire, 150)
            .expect("finish replay"),
        p.session
    );
    let message = b"private application plaintext; never store this in a public outbox";
    let first = p.send(id(p.session, 1, 1), message);
    assert_eq!(p.receive(&first).as_bytes(), message);
    let before = p.jr.image().expect("image").digest;
    assert_eq!(p.receive(&first).message_id(), id(p.session, 1, 1));
    assert_eq!(p.jr.image().expect("same image").digest, before);
    assert_eq!(p.send(id(p.session, 1, 1), message), first);
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            id(p.session, 1, 1),
            b"replacement",
            b"application",
            150
        ),
        Err(DurableError::Protocol(Error::Conflict))
    ));
    let reverse =
        p.jr.send_message(
            &p.f.responder,
            p.session,
            id(p.session, 2, 1),
            message,
            b"application",
            150,
        )
        .expect("reverse");
    assert_ne!(first, reverse);
    assert_eq!(
        p.ji.receive_message(&p.f.initiator, p.session, &reverse, b"application", 150)
            .expect("reverse delivery")
            .as_bytes(),
        message
    );
    p.ji.close();
    p.jr.close();
    for dir in [&p.di, &p.dr] {
        let bytes = fs::read(dir.path().join("state.redb")).expect("disk");
        assert!(!bytes.windows(message.len()).any(|bytes| bytes == message));
    }
    p.ji = reopen(&p.pi, p.f.initiator_device());
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(p.send(id(p.session, 1, 1), message), first);
    assert_eq!(p.receive(&first).as_bytes(), message);
    let second = p.send(id(p.session, 1, 2), message);
    assert_ne!(first, second);
    assert_eq!(p.receive(&second).as_bytes(), message);
    assert_eq!(state(&mut p.ji, &p.session).sent, 2);
    assert_eq!(state(&mut p.jr, &p.session).received, 2);
}

#[test]
fn forged_header_ciphertext_tag_and_ad_leave_persisted_chains_unchanged() {
    let mut p = Pair::new();
    p.activate();
    let first = p.send(id(p.session, 1, 1), b"first");
    let second = p.send(id(p.session, 1, 2), b"second");
    assert_eq!(p.receive(&second).as_bytes(), b"second");
    let original = p.jr.image().expect("image").digest;
    for position in 0..first.len() {
        let mut changed = first.clone();
        *changed.get_mut(position).expect("byte") ^= 1;
        assert!(
            p.jr.receive_message(&p.f.responder, p.session, &changed, b"application", 150)
                .is_err(),
            "position {position}"
        );
        assert_eq!(p.jr.image().expect("unchanged").digest, original);
    }
    assert!(p
        .jr
        .receive_message(&p.f.responder, p.session, &first, b"wrong application", 150)
        .is_err());
    assert!(p
        .ji
        .receive_message(&p.f.initiator, p.session, &first, b"application", 150)
        .is_err());
    assert!(p
        .jr
        .receive_message(&p.f.responder, [7; 32], &first, b"application", 150)
        .is_err());
    assert_eq!(
        p.receive(&first).as_bytes(),
        b"first",
        "failed authentication consumed skipped key"
    );
    assert!(state(&mut p.jr, &p.session).skipped.is_empty());
}

#[test]
fn authenticated_image_rejects_missing_or_grafted_session_and_consumed_key_state() {
    let mut p = Pair::new();
    p.activate();
    let wire = p.send(id(p.session, 1, 1), b"payload");
    p.receive(&wire);
    let mut image = p.jr.image().expect("image");
    let saved = image.records.remove(&record_id(&p.session)).expect("saved");
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
    image.records.insert(record_id(&p.session), saved);
    let record = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("record");
    let mut value = State::decode(&record.payload).expect("state");
    value.skipped.insert(0, ZeroizingBytes::zeroed());
    record.payload = value.encode();
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
    value.skipped.clear();
    value.source = [99; 32];
    image
        .records
        .get_mut(&record_id(&p.session))
        .expect("record")
        .payload = value.encode();
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
}

#[test]
fn out_of_order_receipts_and_resource_admission_preserve_exact_outputs() {
    let mut p = Pair::new();
    p.activate();
    let mut wires = Vec::new();
    for n in 1..=MAX_RECEIPTS {
        wires.push(p.send(id(p.session, 1, n as u64), &[n as u8]));
    }
    let before = p.ji.image().expect("image").digest;
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            id(p.session, 1, 65),
            b"overflow",
            b"application",
            150
        ),
        Err(DurableError::Capacity)
    ));
    assert_eq!(p.ji.image().expect("unchanged").digest, before);
    for (n, wire) in wires.iter().enumerate().rev() {
        assert_eq!(p.receive(wire).as_bytes(), &[n as u8 + 1]);
    }
    assert!(state(&mut p.jr, &p.session).skipped.is_empty());
    assert_eq!(
        p.send(id(p.session, 1, 1), &[1]),
        *wires.first().expect("first")
    );
}

#[test]
fn every_message_sync_failure_reconciles_without_early_output_or_replacement() {
    for operation in ["activate_i", "activate_r", "send", "receive"] {
        let syncs = if operation == "send" { 8 } else { 4 };
        for after in [false, true] {
            for cut in 1..=syncs {
                let mut p = Pair::new();
                if operation != "activate_i" && operation != "activate_r" {
                    p.activate();
                }
                let wire = if operation == "receive" {
                    Some(p.send(id(p.session, 1, 1), b"persist before release"))
                } else {
                    None
                };
                let is_i = matches!(operation, "activate_i" | "send");
                let (journal, path, device) = if is_i {
                    (&mut p.ji, &p.pi, p.f.initiator_device())
                } else {
                    (&mut p.jr, &p.pr, p.f.local_device())
                };
                journal.close();
                let (mut failed, remaining, _, _) = fault_store(path, device, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = match operation {
                    "activate_i" => failed
                        .activate_initiator_messages(Arc::clone(&p.f.initiator), p.request, 150)
                        .map(|_| ()),
                    "activate_r" => failed
                        .activate_responder_messages(Arc::clone(&p.f.responder), &p.initial, 150)
                        .map(|_| ()),
                    "send" => failed
                        .send_message(
                            &p.f.initiator,
                            p.session,
                            id(p.session, 1, 1),
                            b"persist before release",
                            b"application",
                            150,
                        )
                        .map(|_| ()),
                    "receive" => failed
                        .receive_message(
                            &p.f.responder,
                            p.session,
                            wire.as_ref().expect("wire"),
                            b"application",
                            150,
                        )
                        .map(|_| ()),
                    _ => unreachable!(),
                };
                assert!(result.is_err(), "{operation} cut={cut} after={after}");
                assert!(failed.active.is_none());
                drop(failed);
                *journal = reopen(path, device);
                if operation == "send" {
                    let saved = state(journal, &p.session);
                    if saved.pending.is_some() || saved.outgoing.contains_key(&id(p.session, 1, 1))
                    {
                        assert!(journal
                            .send_message(
                                &p.f.initiator,
                                p.session,
                                id(p.session, 1, 1),
                                b"replacement",
                                b"application",
                                150
                            )
                            .is_err());
                    }
                }
                p.activate();
                let actual = p.send(id(p.session, 1, 1), b"persist before release");
                if let Some(wire) = wire {
                    assert_eq!(actual, wire);
                }
                assert_eq!(p.receive(&actual).as_bytes(), b"persist before release");
                assert_eq!(state(&mut p.ji, &p.session).sent, 1);
                assert_eq!(state(&mut p.jr, &p.session).received, 1);
            }
        }
    }
}

#[test]
fn closed_or_expired_authority_cannot_release_cached_messages() {
    let mut p = Pair::new();
    p.activate();
    let wire = p.send(id(p.session, 1, 1), b"payload");
    p.receive(&wire);
    assert!(p
        .ji
        .send_message(
            &p.f.initiator,
            p.session,
            id(p.session, 1, 1),
            b"payload",
            b"application",
            1000
        )
        .is_err());
    assert!(p
        .jr
        .receive_message(&p.f.responder, p.session, &wire, b"application", 1000)
        .is_err());
    p.f.initiator.policy().close();
    assert_eq!(
        p.ji.message_status(&p.f.initiator, p.session, id(p.session, 1, 1))
            .expect("read-only status"),
        MessageStatus::Committed
    );
    assert!(p
        .ji
        .resume_message(&p.f.initiator, p.session, id(p.session, 1, 1), 150)
        .is_err());
    p.f.responder.policy().close();
    assert!(p
        .jr
        .receive_message(&p.f.responder, p.session, &wire, b"application", 150)
        .is_err());
}

#[test]
fn initial_and_chain_keys_match_independent_hmac_sha256_vectors() {
    let s =
        State::new([8; 32], [9; 32], 1, key(&[7; 32]).expect("root"), &[11; 32]).expect("state");
    let hex = |bytes: &[u8]| {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"))
                .expect("hex formatting");
        }
        output
    };
    let initial = format!(
        "{}{}{}",
        hex(s.rekey.as_bytes()),
        hex(s.send.as_bytes()),
        hex(s.receive.as_bytes())
    );
    assert_eq!(initial, "c94afb4355b05a32f9cf8682a7231596c40e5d5fd8a6b9328d13109a5cd6e33e99fda0772b0f13582050c1f206a8ba3dfd8ec32ec2b35f6d86ff647e4bef6aa4f588f6ad682062e0df2c21e474aaa8b77ca58f3ca5e37e4e42c0acb0374d95e1");
    let (next, message) = step(&s.send, 0).expect("first step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "5d88de809323126e111f0b711a1ba04bff9f3864ed4781191d6be635ad4f287eef0229693f35b1952dfde7d459cabcb337dd9f83b570c4ce08a83dbef5b0189f");
    let (next, message) = step(&next, 1).expect("second step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "51e5a3a82942e7790bd6706ba7316ff05246b47da9a2ef4f5064155c5bbe040f5f7d6c48d6dc918f54c0e8e0ef934fee0140ad80146e2b567085309570957771");
    let reverse = State::new([8; 32], [9; 32], 2, key(&[7; 32]).expect("root"), &[11; 32])
        .expect("responder state");
    assert_eq!(s.send.as_bytes(), reverse.receive.as_bytes());
    assert_eq!(s.receive.as_bytes(), reverse.send.as_bytes());
    assert_ne!(s.send.as_bytes(), s.receive.as_bytes());
    assert_eq!(s.send_ack.as_bytes(), reverse.receive_ack.as_bytes());
    assert_eq!(hex(&s.acknowledgement().expect("known acknowledgement")), "5150434d41434b310909090909090909090909090909090909090909090909090909090909090909020000000000000000d7011dd0974bf86048eedd1cdb1aafe537a48ef6c0f08e3145b960fc11efa172");
    let bytes = s.encode();
    assert_eq!(
        State::decode(&bytes).expect("decode").encode().as_slice(),
        bytes.as_slice()
    );
    for length in 0..bytes.len() {
        assert!(State::decode(bytes.get(..length).expect("prefix")).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(State::decode(&trailing).is_err());
}

pub(super) fn after_stage(stage: &str) {
    if std::env::var("QPERIAPT_MESSAGES_STAGE").ok().as_deref() != Some(stage) {
        return;
    }
    let path = std::env::var_os("QPERIAPT_MESSAGES_CRASH_DIR").expect("owned fixture");
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&path).join("ready"))
        .expect("new marker");
    marker.write_all(stage.as_bytes()).expect("marker");
    marker.sync_all().expect("marker sync");
    loop {
        std::thread::park();
    }
}

#[test]
fn message_crash_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_MESSAGES_CRASH_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let public = fs::read(path.join("public-keys")).expect("public keys");
    let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
    let f = crate::bootstrap::tests::fixture_from_public(
        PrekeyQuality::OneTimeBoth,
        Some((
            a.try_into().expect("key width"),
            b.try_into().expect("key width"),
        )),
    );
    let operation = fs::read_to_string(path.join("operation")).expect("operation");
    let is_i = matches!(
        operation.as_str(),
        "activate_i" | "reserved" | "sent" | "acknowledged"
    );
    let mut journal = reopen(
        path,
        if is_i {
            f.initiator_device()
        } else {
            f.local_device()
        },
    );
    let session: [u8; 32] = fs::read(path.join("session"))
        .expect("session")
        .try_into()
        .expect("width");
    match operation.as_str() {
        "activate_i" => {
            let request = InitiationId::from_trusted_state(
                fs::read(path.join("request"))
                    .expect("request")
                    .try_into()
                    .expect("width"),
            )
            .expect("id");
            journal
                .activate_initiator_messages(Arc::clone(&f.initiator), request, 150)
                .expect("activate");
        }
        "activate_r" => {
            journal
                .activate_responder_messages(
                    Arc::clone(&f.responder),
                    &fs::read(path.join("initial")).expect("initial"),
                    150,
                )
                .expect("activate");
        }
        "reserved" | "sent" => {
            journal
                .send_message(
                    &f.initiator,
                    session,
                    id(session, 1, 1),
                    b"process message",
                    b"application",
                    150,
                )
                .expect("send");
        }
        "received" => {
            journal
                .receive_message(
                    &f.responder,
                    session,
                    &fs::read(path.join("wire")).expect("wire"),
                    b"application",
                    150,
                )
                .expect("receive");
        }
        "consumed" => {
            journal
                .consume_message(&f.responder, session, id(session, 1, 1), 150)
                .expect("consumption");
        }
        "acknowledged" => {
            journal
                .accept_message_acknowledgement(
                    &f.initiator,
                    session,
                    &fs::read(path.join("ack")).expect("ack"),
                    150,
                )
                .expect("acknowledgement");
        }
        _ => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "unknown owned test operation").into(),
            )
        }
    }
    fs::write(path.join("returned"), b"unexpected early return").expect("return marker");
    Ok(())
}

#[test]
fn killed_process_recovers_each_root_transfer_and_message_release_boundary() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for operation in [
        "activate_i",
        "activate_r",
        "reserved",
        "sent",
        "received",
        "consumed",
        "acknowledged",
    ] {
        let mut p = Pair::new();
        if !operation.starts_with("activate") {
            p.activate();
        }
        let wire = if matches!(operation, "received" | "consumed" | "acknowledged") {
            Some(p.send(id(p.session, 1, 1), b"process message"))
        } else {
            None
        };
        if matches!(operation, "consumed" | "acknowledged") {
            p.receive(wire.as_ref().expect("message"));
        }
        let ack = if operation == "acknowledged" {
            p.jr.consume_message(&p.f.responder, p.session, id(p.session, 1, 1), 150)
                .expect("consume before acknowledgement");
            Some(
                p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                    .expect("acknowledgement"),
            )
        } else {
            None
        };
        let is_i = matches!(
            operation,
            "activate_i" | "reserved" | "sent" | "acknowledged"
        );
        let path = if is_i {
            p.ji.close();
            p.pi.clone()
        } else {
            p.jr.close();
            p.pr.clone()
        };
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("public fixture");
        fs::write(path.join("operation"), operation).expect("operation");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("request"), p.request.as_bytes()).expect("request");
        fs::write(path.join("initial"), &p.initial).expect("initial");
        if let Some(wire) = &wire {
            fs::write(path.join("wire"), wire).expect("wire");
        }
        if let Some(ack) = &ack {
            fs::write(path.join("ack"), ack).expect("ack fixture");
        }
        let log = fs::File::create(path.join("child.log")).expect("log");
        let child = Command::new(std::env::current_exe().expect("executable"))
            .args([
                "--exact",
                "durable::messages::tests::message_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MESSAGES_CRASH_DIR", &path)
            .env(
                "QPERIAPT_MESSAGES_STAGE",
                if operation.starts_with("activate") {
                    "activation"
                } else {
                    operation
                },
            )
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child");
        let mut child = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{operation}: {}",
                fs::read_to_string(path.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned process");
        child.0.wait().expect("reap");
        if is_i {
            p.ji = reopen(&path, p.f.initiator_device());
        } else {
            p.jr = reopen(&path, p.f.local_device());
        }
        p.activate();
        if matches!(operation, "consumed" | "acknowledged") {
            let ack =
                p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                    .expect("recovered consumption");
            assert_eq!(
                p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
                    .expect("reconcile same floor"),
                1
            );
            assert_eq!(
                p.ji.message_status(&p.f.initiator, p.session, id(p.session, 1, 1))
                    .expect("retired"),
                MessageStatus::Acknowledged
            );
            assert!(matches!(
                p.jr.receive_message(
                    &p.f.responder,
                    p.session,
                    wire.as_ref().expect("old message"),
                    b"application",
                    150
                ),
                Err(DurableError::Protocol(Error::Retired))
            ));
            continue;
        }
        if operation == "reserved" {
            assert_eq!(
                p.ji.message_status(&p.f.initiator, p.session, id(p.session, 1, 1))
                    .expect("status"),
                MessageStatus::Reserved
            );
            assert!(p
                .ji
                .send_message(
                    &p.f.initiator,
                    p.session,
                    id(p.session, 1, 1),
                    b"replacement",
                    b"application",
                    150
                )
                .is_err());
        }
        let recovered = if matches!(operation, "reserved" | "sent") {
            p.ji.resume_message(&p.f.initiator, p.session, id(p.session, 1, 1), 150)
                .expect("resume sealed input")
        } else {
            p.send(id(p.session, 1, 1), b"process message")
        };
        if let Some(wire) = wire {
            assert_eq!(recovered, wire);
        }
        assert_eq!(p.receive(&recovered).as_bytes(), b"process message");
        assert_eq!(
            p.ji.message_status(&p.f.initiator, p.session, id(p.session, 1, 1))
                .expect("committed"),
            MessageStatus::Committed
        );
        assert_eq!(state(&mut p.ji, &p.session).sent, 1);
        assert_eq!(state(&mut p.jr, &p.session).received, 1);
    }
}

#[test]
fn frame_length_is_bounded_before_arithmetic_and_future_epochs_are_rejected() {
    let mut wire = Header {
        session: [9; 32],
        role: 1,
        index: 0,
        id: id([9; 32], 1, 1),
        length: 0,
    }
    .encode();
    wire.extend_from_slice(&[0; 16]);
    assert!(Header::decode(&wire).is_ok());
    let mut excessive = wire.clone();
    excessive
        .get_mut(MESSAGE_HEADER - 4..MESSAGE_HEADER)
        .expect("length")
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(Header::decode(&excessive), Err(Error::Encoding)));
    let mut epoch = wire.clone();
    epoch
        .get_mut(41..49)
        .expect("epoch")
        .copy_from_slice(&1u64.to_be_bytes());
    assert!(matches!(Header::decode(&epoch), Err(Error::Encoding)));
    let mut counter = wire.clone();
    counter
        .get_mut(49..57)
        .expect("index")
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(Header::decode(&counter), Err(Error::Capacity)));
    wire.push(0);
    assert!(matches!(Header::decode(&wire), Err(Error::Encoding)));
    assert!(matches!(key(&[0; 31]), Err(Error::Encoding)));
}

#[test]
fn acknowledged_sessions_pass_the_old_capacity_without_retaining_history_or_reusing_ids() {
    let mut p = Pair::new();
    p.activate();
    let first_id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("slot");
    let initial_size = state(&mut p.ji, &p.session).encode().len();
    let mut first_wire = None;
    let mut first_ack = None;
    for index in 0..130 {
        let id =
            p.ji.next_message_id(&p.f.initiator, p.session, 150)
                .expect("retained slot");
        assert_eq!(id.index().expect("index"), index);
        let wire = p.send(id, b"long session application data");
        let value = p.receive(&wire);
        assert_eq!(value.message_id(), id);
        assert_eq!(value.as_bytes(), b"long session application data");
        assert_eq!(
            p.jr.consume_message(&p.f.responder, p.session, id, 150)
                .expect("consumption"),
            index + 1
        );
        let ack =
            p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                .expect("ack");
        assert_eq!(
            p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
                .expect("peer consumption"),
            index + 1
        );
        assert_eq!(
            p.ji.message_status(&p.f.initiator, p.session, id)
                .expect("status"),
            MessageStatus::Acknowledged
        );
        let send = state(&mut p.ji, &p.session);
        let receive = state(&mut p.jr, &p.session);
        assert!(
            send.outgoing.is_empty() && receive.incoming.is_empty() && receive.skipped.is_empty()
        );
        assert_eq!(send.encode().len(), initial_size);
        if index == 0 {
            first_wire = Some(wire);
            first_ack = Some(ack);
        }
    }
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            first_id,
            b"new plaintext in old slot",
            b"application",
            150
        ),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.ji.resume_message(&p.f.initiator, p.session, first_id, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.receive_message(
            &p.f.responder,
            p.session,
            first_wire.as_ref().expect("old wire"),
            b"application",
            150
        ),
        Err(DurableError::Protocol(Error::Retired))
    ));
    let before = p.ji.image().expect("image").digest;
    assert_eq!(
        p.ji.accept_message_acknowledgement(
            &p.f.initiator,
            p.session,
            first_ack.as_ref().expect("stale ack"),
            150
        )
        .expect("stale ack"),
        130
    );
    assert_eq!(p.ji.image().expect("same image").digest, before);
    p.ji.close();
    p.jr.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.ji.message_status(&p.f.initiator, p.session, first_id)
            .expect("retained status"),
        MessageStatus::Acknowledged
    );
    assert_eq!(
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("next slot")
            .index()
            .expect("index"),
        130
    );
}

#[test]
fn consumption_waits_for_gaps_and_authenticated_acknowledgements_cannot_regress_or_forge_progress()
{
    let mut p = Pair::new();
    p.activate();
    let a = id(p.session, 1, 1);
    let b = id(p.session, 1, 2);
    let first = p.send(a, b"first");
    let second = p.send(b, b"second");
    p.receive(&second);
    assert_eq!(
        p.jr.consume_message(&p.f.responder, p.session, b, 150)
            .expect("out of order consumption"),
        0
    );
    let consumed = state(&mut p.jr, &p.session);
    assert!(consumed
        .incoming
        .get(&b)
        .expect("retained marker")
        .plaintext
        .is_empty());
    assert_eq!(consumed.skipped.len(), 1);
    let ack0 =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("zero contiguous progress");
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack0, 150)
            .expect("no retirement"),
        0
    );
    assert_eq!(state(&mut p.ji, &p.session).outgoing.len(), 2);
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &second, b"application", 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    p.receive(&first);
    assert_eq!(
        p.jr.consume_message(&p.f.responder, p.session, a, 150)
            .expect("close gap"),
        2
    );
    let ack =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("cumulative ack");
    let before = p.ji.image().expect("image").digest;
    for n in 0..ack.len() {
        let mut modified = ack.clone();
        *modified.get_mut(n).expect("byte") ^= 1;
        assert!(
            p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &modified, 150)
                .is_err(),
            "byte {n}"
        );
        assert_eq!(p.ji.image().expect("unchanged").digest, before);
    }
    assert!(p
        .jr
        .accept_message_acknowledgement(&p.f.responder, p.session, &ack, 150)
        .is_err());
    let mut dishonest = state(&mut p.jr, &p.session);
    dishonest.receive_floor = 3;
    let future = dishonest
        .acknowledgement()
        .expect("authenticated impossible peer claim");
    assert!(p
        .ji
        .accept_message_acknowledgement(&p.f.initiator, p.session, &future, 150)
        .is_err());
    assert_eq!(
        p.ji.image().expect("unchanged after future ack").digest,
        before
    );
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("lost ack recovery"),
        ack
    );
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
            .expect("retire"),
        2
    );
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack0, 150)
            .expect("older cumulative ack"),
        2
    );
    assert!(state(&mut p.ji, &p.session).outgoing.is_empty());
    let reverse_id =
        p.jr.next_message_id(&p.f.responder, p.session, 150)
            .expect("reverse slot");
    let reverse_wire =
        p.jr.send_message(
            &p.f.responder,
            p.session,
            reverse_id,
            b"reverse direction",
            b"application",
            150,
        )
        .expect("reverse send");
    assert_eq!(
        p.ji.receive_message(
            &p.f.initiator,
            p.session,
            &reverse_wire,
            b"application",
            150
        )
        .expect("reverse receive")
        .as_bytes(),
        b"reverse direction"
    );
    assert_eq!(
        p.ji.consume_message(&p.f.initiator, p.session, reverse_id, 150)
            .expect("reverse consume"),
        1
    );
    let reverse_ack =
        p.ji.message_acknowledgement(&p.f.initiator, p.session, 150)
            .expect("reverse ack");
    assert_eq!(
        p.jr.accept_message_acknowledgement(&p.f.responder, p.session, &reverse_ack, 150)
            .expect("reverse confirmation"),
        1
    );
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, reverse_id)
            .expect("reverse status"),
        MessageStatus::Acknowledged
    );
}

#[test]
fn every_retention_commit_fault_preserves_a_monotonic_consumption_boundary() {
    for operation in ["consume", "ack"] {
        for after in [false, true] {
            for cut in 1..=4 {
                let mut p = Pair::new();
                p.activate();
                let id = id(p.session, 1, 1);
                let wire = p.send(id, b"consumable payload");
                p.receive(&wire);
                let ack = if operation == "ack" {
                    p.jr.consume_message(&p.f.responder, p.session, id, 150)
                        .expect("consume");
                    Some(
                        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                            .expect("ack"),
                    )
                } else {
                    None
                };
                let (journal, path, device) = if operation == "ack" {
                    (&mut p.ji, &p.pi, p.f.initiator_device())
                } else {
                    (&mut p.jr, &p.pr, p.f.local_device())
                };
                journal.close();
                let (mut failed, remaining, _, _) = fault_store(path, device, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = if let Some(ack) = &ack {
                    failed.accept_message_acknowledgement(&p.f.initiator, p.session, ack, 150)
                } else {
                    failed.consume_message(&p.f.responder, p.session, id, 150)
                };
                assert!(result.is_err(), "{operation} cut={cut} after={after}");
                assert!(failed.active.is_none());
                drop(failed);
                *journal = reopen(path, device);
                assert_eq!(
                    p.jr.consume_message(&p.f.responder, p.session, id, 150)
                        .expect("reconcile original consumption"),
                    1
                );
                let ack =
                    p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                        .expect("committed prefix");
                assert_eq!(
                    p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
                        .expect("reconcile acknowledgement"),
                    1
                );
                assert_eq!(
                    p.ji.message_status(&p.f.initiator, p.session, id)
                        .expect("acknowledged"),
                    MessageStatus::Acknowledged
                );
                assert!(matches!(
                    p.ji.send_message(
                        &p.f.initiator,
                        p.session,
                        id,
                        b"replacement",
                        b"application",
                        150
                    ),
                    Err(DurableError::Protocol(Error::Retired))
                ));
            }
        }
    }
}

#[test]
fn retired_boundaries_are_canonical_and_counter_exhaustion_cannot_recreate_a_slot() {
    let mut s =
        State::new([8; 32], [9; 32], 1, key(&[7; 32]).expect("root"), &[11; 32]).expect("state");
    s.sent = u64::MAX;
    s.send_floor = u64::MAX;
    s.received = u64::MAX;
    s.receive_floor = u64::MAX;
    assert_eq!(
        State::decode(&s.encode())
            .expect("terminal counters")
            .encode()
            .as_slice(),
        s.encode().as_slice()
    );
    assert!(MessageId::for_index(&s.session, s.role, u64::MAX).is_err());
    let retired = MessageId::for_index(&s.session, s.role, u64::MAX - 1).expect("last old slot");
    assert!(matches!(
        s.send(retired, b"replacement", b""),
        Err(Error::Retired)
    ));
    s.sent -= 1;
    assert!(State::decode(&s.encode()).is_err(), "floor exceeds counter");
    let mut p = Pair::new();
    p.activate();
    let expected =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("slot");
    let before = p.ji.image().expect("image").digest;
    let random = MessageId::from_trusted_state([1; 32]).expect("untrusted bytes");
    assert!(p
        .ji
        .send_message(
            &p.f.initiator,
            p.session,
            random,
            b"payload",
            b"application",
            150
        )
        .is_err());
    assert!(p
        .ji
        .send_message(
            &p.f.initiator,
            p.session,
            id(p.session, 1, 2),
            b"future slot",
            b"application",
            150
        )
        .is_err());
    assert_eq!(p.ji.image().expect("unchanged").digest, before);
    assert_eq!(
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("same slot"),
        expected
    );
}

fn roster_update(
    device: &VerifiedDevice,
    seed: u8,
    version: u64,
    keep: bool,
) -> crate::VerifiedRoster {
    rosters::tests::update(device, seed, version, keep)
}

#[test]
fn installed_roster_expiry_blocks_cached_context_but_retained_renewal_recovers_messages() {
    let mut p = Pair::new();
    p.activate();
    let short = rosters::tests::update_with_validity(
        p.f.initiator_device(),
        90,
        2,
        true,
        crate::Validity::new(100, 160).expect("short interval"),
    );
    p.ji.install_roster(&short, 150).expect("short roster");
    let slot =
        p.ji.next_message_id(&p.f.initiator, p.session, 159)
            .expect("before expiry");
    p.f.initiator_device()
        .roster()
        .authorize_device(p.f.initiator_device(), 160)
        .expect("original snapshot still valid");
    assert!(matches!(
        p.ji.next_message_id(&p.f.initiator, p.session, 160),
        Err(DurableError::Protocol(Error::Validity))
    ));
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert!(matches!(
        p.ji.next_message_id(&p.f.initiator, p.session, 160),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let renewal = roster_update(p.f.initiator_device(), 90, 3, true);
    p.ji.install_roster(&renewal, 160)
        .expect("explicit retained-credential renewal");
    assert_eq!(
        p.ji.next_message_id(&p.f.initiator, p.session, 160)
            .expect("same pending slot"),
        slot
    );
}

#[test]
fn committed_roster_revocation_fences_cached_messages_and_bootstrap_after_restart() {
    for (initiator, seed) in [(true, 90), (false, 94)] {
        let mut p = Pair::new();
        p.activate();
        let device = if initiator {
            p.f.initiator_device()
        } else {
            p.f.local_device()
        };
        let retained = roster_update(device, seed, 2, true);
        p.ji.install_roster(&retained, 150)
            .expect("retain initiator view");
        p.jr.install_roster(&retained, 150)
            .expect("retain responder view");
        let revoked = roster_update(device, seed, 3, false);
        let fork = roster_update(device, seed, 3, true);
        let resurrection = roster_update(device, seed, 4, true);
        let account = device.account_id();
        let slot =
            p.ji.next_message_id(&p.f.initiator, p.session, 150)
                .expect("unrevoked old context remains usable");
        let wire = p.send(slot, b"retained private delivery");
        assert_eq!(p.receive(&wire).as_bytes(), b"retained private delivery");
        let ack =
            p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                .expect("old acknowledgement");
        p.ji.install_roster(&revoked, 150)
            .expect("commit revocation at sender");
        p.jr.install_roster(&revoked, 150)
            .expect("commit revocation at receiver");
        let revision = p.ji.image().expect("committed").revision;
        assert_eq!(
            p.ji.install_roster(&revoked, 150).expect("idempotent"),
            revoked.checkpoint()
        );
        assert_eq!(p.ji.image().expect("unchanged").revision, revision);
        for update in [&retained, &fork, &resurrection] {
            assert!(matches!(
                p.ji.install_roster(update, 150),
                Err(DurableError::Protocol(Error::Checkpoint))
            ));
        }
        p.ji.close();
        p.jr.close();
        p.ji = reopen(&p.pi, p.f.initiator_device());
        p.jr = reopen(&p.pr, p.f.local_device());
        assert_eq!(
            p.ji.roster_checkpoint(account).expect("durable head"),
            revoked.checkpoint()
        );
        assert_eq!(
            p.ji.message_status(&p.f.initiator, p.session, slot)
                .expect("read-only reconciliation"),
            MessageStatus::Committed
        );
        assert!(matches!(
            p.ji.next_message_id(&p.f.initiator, p.session, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.ji.send_message(
                &p.f.initiator,
                p.session,
                slot,
                b"retained private delivery",
                b"application",
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.ji.resume_message(&p.f.initiator, p.session, slot, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.jr.receive_message(&p.f.responder, p.session, &wire, b"application", 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.jr.message_acknowledgement(&p.f.responder, p.session, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.ji.initiate(Arc::clone(&p.f.initiator), p.request, &p.f.signer_i, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.jr.resume(Arc::clone(&p.f.responder), &p.initial, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.ji.activate_initiator_messages(Arc::clone(&p.f.initiator), p.request, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            p.jr.activate_responder_messages(Arc::clone(&p.f.responder), &p.initial, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(
            p.ji.image().expect("denials do not rewrite").revision,
            revision
        );
    }
}
