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
fn id(byte: u8) -> MessageId {
    MessageId::from_trusted_state([byte; 32]).expect("id")
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
    let first = p.send(id(1), message);
    assert_eq!(p.receive(&first).as_bytes(), message);
    let before = p.jr.image().expect("image").digest;
    assert_eq!(p.receive(&first).message_id(), id(1));
    assert_eq!(p.jr.image().expect("same image").digest, before);
    assert_eq!(p.send(id(1), message), first);
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            id(1),
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
            id(1),
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
    assert_eq!(p.send(id(1), message), first);
    assert_eq!(p.receive(&first).as_bytes(), message);
    let second = p.send(id(2), message);
    assert_ne!(first, second);
    assert_eq!(p.receive(&second).as_bytes(), message);
    assert_eq!(state(&mut p.ji, &p.session).sent, 2);
    assert_eq!(state(&mut p.jr, &p.session).received, 2);
}

#[test]
fn forged_header_ciphertext_tag_and_ad_leave_persisted_chains_unchanged() {
    let mut p = Pair::new();
    p.activate();
    let first = p.send(id(1), b"first");
    let second = p.send(id(2), b"second");
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
    let wire = p.send(id(1), b"payload");
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
        wires.push(p.send(id(n as u8), &[n as u8]));
    }
    let before = p.ji.image().expect("image").digest;
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            id(99),
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
    assert_eq!(p.send(id(1), &[1]), *wires.first().expect("first"));
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
                    Some(p.send(id(1), b"persist before release"))
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
                            id(1),
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
                    if saved.pending.is_some() || saved.outgoing.contains_key(&id(1)) {
                        assert!(journal
                            .send_message(
                                &p.f.initiator,
                                p.session,
                                id(1),
                                b"replacement",
                                b"application",
                                150
                            )
                            .is_err());
                    }
                }
                p.activate();
                let actual = p.send(id(1), b"persist before release");
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
    let wire = p.send(id(1), b"payload");
    p.receive(&wire);
    assert!(p
        .ji
        .send_message(
            &p.f.initiator,
            p.session,
            id(1),
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
        p.ji.message_status(&p.f.initiator, p.session, id(1))
            .expect("read-only status"),
        MessageStatus::Committed
    );
    assert!(p
        .ji
        .resume_message(&p.f.initiator, p.session, id(1), 150)
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
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let initial = format!(
        "{}{}{}",
        hex(s.rekey.as_bytes()),
        hex(s.send.as_bytes()),
        hex(s.receive.as_bytes())
    );
    assert_eq!(initial, "83440d219ed5a8f03798c04c0fd23e33faf24ba646bcd1e0f92c78cb7b82863fb9e8cdf88287e2f4172dc49ec376c2df8e54a318966942858ac5c0c6e0eb6e22348d898526ce239a94446521d3ee403dcb4364cf349dae14edd6abe23a5ed212");
    let (next, message) = step(&s.send, 0).expect("first step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "248894a8d4fe9a4748155ca9487d8a6e319d38d4559b88a5066145ac0d60678c43293582aca112761be2abbfb54d0e108b957b758da48bcc28d6b0c8f99806a5");
    let (next, message) = step(&next, 1).expect("second step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "3caa15fec531b998786552abd3d9f2a7b3c60b9abbaa9601cf5f7c38f73bd314dffad6ca7c7b740337a2be73ae449d33d6269c11c12f998377b0c38e62458ed2");
    let reverse = State::new([8; 32], [9; 32], 2, key(&[7; 32]).expect("root"), &[11; 32])
        .expect("responder state");
    assert_eq!(s.send.as_bytes(), reverse.receive.as_bytes());
    assert_eq!(s.receive.as_bytes(), reverse.send.as_bytes());
    assert_ne!(s.send.as_bytes(), s.receive.as_bytes());
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
    let is_i = matches!(operation.as_str(), "activate_i" | "reserved" | "sent");
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
                    id(1),
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
    for operation in ["activate_i", "activate_r", "reserved", "sent", "received"] {
        let mut p = Pair::new();
        if !operation.starts_with("activate") {
            p.activate();
        }
        let wire = if operation == "received" {
            Some(p.send(id(1), b"process message"))
        } else {
            None
        };
        let is_i = matches!(operation, "activate_i" | "reserved" | "sent");
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
        if operation == "reserved" {
            assert_eq!(
                p.ji.message_status(&p.f.initiator, p.session, id(1))
                    .expect("status"),
                MessageStatus::Reserved
            );
            assert!(p
                .ji
                .send_message(
                    &p.f.initiator,
                    p.session,
                    id(1),
                    b"replacement",
                    b"application",
                    150
                )
                .is_err());
        }
        let recovered = if matches!(operation, "reserved" | "sent") {
            p.ji.resume_message(&p.f.initiator, p.session, id(1), 150)
                .expect("resume sealed input")
        } else {
            p.send(id(1), b"process message")
        };
        if let Some(wire) = wire {
            assert_eq!(recovered, wire);
        }
        assert_eq!(p.receive(&recovered).as_bytes(), b"process message");
        assert_eq!(
            p.ji.message_status(&p.f.initiator, p.session, id(1))
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
        id: id(1),
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
