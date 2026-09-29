// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, Fixture},
    durable::tests::{directory, fault_store, new_store, reopen},
    PrekeyQuality,
};
use std::{fs, sync::atomic::Ordering};

mod epoch_resolution;
mod reservation_disclosure;

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
    MessageId::for_epoch(&session, role, 0, ordinal - 1).expect("id")
}
fn epoch(state: &State) -> &Traffic {
    state.traffic(0).expect("initial epoch")
}
fn epoch_mut(state: &mut State) -> &mut Traffic {
    state.traffic_mut(0).expect("initial epoch")
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
    assert_eq!(epoch(&state(&mut p.ji, &p.session)).sent, 2);
    assert_eq!(epoch(&state(&mut p.jr, &p.session)).received, 2);
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
    assert!(epoch(&state(&mut p.jr, &p.session)).skipped.is_empty());
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
    epoch_mut(&mut value)
        .skipped
        .insert(0, ZeroizingBytes::zeroed());
    record.payload = value.encode();
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
    epoch_mut(&mut value).skipped.clear();
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
    assert!(epoch(&state(&mut p.jr, &p.session)).skipped.is_empty());
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
                    if epoch(&saved).pending.is_some()
                        || epoch(&saved).outgoing.contains_key(&id(p.session, 1, 1))
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
                assert_eq!(epoch(&state(&mut p.ji, &p.session)).sent, 1);
                assert_eq!(epoch(&state(&mut p.jr, &p.session)).received, 1);
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
        hex(epoch(&s).send.as_bytes()),
        hex(epoch(&s).receive.as_bytes())
    );
    assert_eq!(initial, "c94afb4355b05a32f9cf8682a7231596c40e5d5fd8a6b9328d13109a5cd6e33e99fda0772b0f13582050c1f206a8ba3dfd8ec32ec2b35f6d86ff647e4bef6aa4f588f6ad682062e0df2c21e474aaa8b77ca58f3ca5e37e4e42c0acb0374d95e1");
    let (next, message) = step(&epoch(&s).send, 0).expect("first step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "5d88de809323126e111f0b711a1ba04bff9f3864ed4781191d6be635ad4f287eef0229693f35b1952dfde7d459cabcb337dd9f83b570c4ce08a83dbef5b0189f");
    let (next, message) = step(&next, 1).expect("second step");
    assert_eq!(format!("{}{}", hex(next.as_bytes()), hex(message.as_bytes())), "51e5a3a82942e7790bd6706ba7316ff05246b47da9a2ef4f5064155c5bbe040f5f7d6c48d6dc918f54c0e8e0ef934fee0140ad80146e2b567085309570957771");
    let reverse = State::new([8; 32], [9; 32], 2, key(&[7; 32]).expect("root"), &[11; 32])
        .expect("responder state");
    assert_eq!(
        epoch(&s).send.as_bytes(),
        epoch(&reverse).receive.as_bytes()
    );
    assert_eq!(
        epoch(&s).receive.as_bytes(),
        epoch(&reverse).send.as_bytes()
    );
    assert_ne!(epoch(&s).send.as_bytes(), epoch(&s).receive.as_bytes());
    assert_eq!(
        epoch(&s).send_ack.as_bytes(),
        epoch(&reverse).receive_ack.as_bytes()
    );
    assert_eq!(hex(&epoch(&s).acknowledgement().expect("known acknowledgement")), "5150434d41434b310909090909090909090909090909090909090909090909090909090909090909020000000000000000d7011dd0974bf86048eedd1cdb1aafe537a48ef6c0f08e3145b960fc11efa172");
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
    ) || matches!(
        operation.as_str(),
        "rekey" | "rekey-final" | "rekey-accept-receipt"
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
        "epoch-resolution-begin" => {
            journal
                .begin_closed_epoch_resolution(&f.responder, session, 0, 150)
                .expect("freeze report");
        }
        "epoch-resolution-ack" => {
            let id = EpochResolutionId::from_trusted_state(
                fs::read(path.join("resolution-id"))
                    .expect("application ID")
                    .try_into()
                    .expect("ID width"),
            )
            .expect("ID");
            journal
                .acknowledge_closed_epoch_resolution(&f.responder, session, 0, id, 150)
                .expect("commit application accounting");
        }
        "rekey-final" => {
            journal
                .accept_rekey_response(
                    &f.initiator,
                    session,
                    &fs::read(path.join("rekey-response")).expect("response"),
                    &f.signer_i,
                    150,
                )
                .expect("durable final");
        }
        "rekey-receipt" => {
            journal
                .finish_rekey(
                    &f.responder,
                    session,
                    &fs::read(path.join("rekey-final")).expect("final"),
                    &f.signer_r,
                    150,
                )
                .expect("durable receipt");
        }
        "rekey-accept-receipt" => {
            journal
                .accept_rekey_receipt(
                    &f.initiator,
                    session,
                    &fs::read(path.join("rekey-receipt")).expect("receipt"),
                    150,
                )
                .expect("durable receive cutover");
        }
        "rekey-response" => {
            journal
                .respond_rekey_offer(
                    &f.responder,
                    session,
                    &fs::read(path.join("rekey-offer")).expect("public offer"),
                    &f.signer_r,
                    150,
                )
                .expect("prepare exact rekey response");
        }
        "rekey" => {
            journal
                .prepare_rekey_offer(&f.initiator, session, &f.signer_i, 150)
                .expect("prepare exact rekey offer");
        }
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

fn rekey_digest(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    digest(
        &[
            b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/".as_slice(),
            label,
        ]
        .concat(),
        bytes,
    )
}

fn complete_rekey(p: &mut Pair) -> u64 {
    let current =
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("initiator progress")
            .confirmed_epoch;
    assert_eq!(
        p.jr.rekey_progress(&p.f.responder, p.session)
            .expect("responder progress")
            .confirmed_epoch,
        current
    );
    let target = current + 1;
    let (proposer, responder, pc, rc, ps, rs) = if target % 2 == 1 {
        (
            &mut p.ji,
            &mut p.jr,
            &p.f.initiator,
            &p.f.responder,
            &p.f.signer_i,
            &p.f.signer_r,
        )
    } else {
        (
            &mut p.jr,
            &mut p.ji,
            &p.f.responder,
            &p.f.initiator,
            &p.f.signer_r,
            &p.f.signer_i,
        )
    };
    let offer = proposer
        .prepare_rekey_offer(pc, p.session, ps, 150)
        .expect("offer");
    let response = responder
        .respond_rekey_offer(rc, p.session, &offer, rs, 150)
        .expect("response");
    let final_wire = proposer
        .accept_rekey_response(pc, p.session, &response, ps, 150)
        .expect("final");
    let receipt = responder
        .finish_rekey(rc, p.session, &final_wire, rs, 150)
        .expect("receipt");
    assert_eq!(
        proposer
            .accept_rekey_receipt(pc, p.session, &receipt, 150)
            .expect("accept receipt"),
        target
    );
    assert_eq!(
        proposer
            .accept_rekey_response(pc, p.session, &response, ps, 150)
            .expect("exact final replay"),
        final_wire
    );
    assert_eq!(
        responder
            .finish_rekey(rc, p.session, &final_wire, rs, 150)
            .expect("exact receipt replay"),
        receipt
    );
    assert_eq!(
        proposer
            .accept_rekey_receipt(pc, p.session, &receipt, 150)
            .expect("duplicate receipt"),
        target
    );
    target
}

#[test]
fn rekey_epoch_cutover_preserves_old_outboxes_and_separates_new_ids_and_acks() {
    use hmac::{Hmac, Mac};
    let mut p = Pair::new();
    p.activate();
    let first = p.send(id(p.session, 1, 1), b"old first");
    let second = p.send(id(p.session, 1, 2), b"old second");
    assert_eq!(p.receive(&second).as_bytes(), b"old second");
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let response =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("response");
    let old_reverse_id =
        p.jr.next_message_id(&p.f.responder, p.session, 150)
            .expect("old reverse id");
    let old_reverse =
        p.jr.send_message(
            &p.f.responder,
            p.session,
            old_reverse_id,
            b"old reverse during rekey",
            b"application",
            150,
        )
        .expect("old reverse remains open after response");
    let final_wire =
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &response, &p.f.signer_i, 150)
            .expect("final");
    assert_eq!(
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("half cutover"),
        RekeyProgress {
            confirmed_epoch: 0,
            sending_epoch: 1,
            receiving_epoch: 0,
            pending_epoch: Some(1)
        }
    );
    let new_id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("new id");
    assert_eq!(
        (
            new_id.epoch().expect("epoch"),
            new_id.index().expect("index")
        ),
        (1, 0)
    );
    assert_ne!(new_id, id(p.session, 1, 1));
    let new_wire = p.send(new_id, b"new first");
    let before = p.jr.image().expect("before early packet").digest;
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &new_wire, b"application", 150),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.jr.image().expect("early data consumes nothing").digest,
        before
    );
    let receipt =
        p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150)
            .expect("finish");
    assert_eq!(p.receive(&new_wire).as_bytes(), b"new first");
    let reverse_id =
        p.jr.next_message_id(&p.f.responder, p.session, 150)
            .expect("new reverse");
    let reverse =
        p.jr.send_message(
            &p.f.responder,
            p.session,
            reverse_id,
            b"new reverse",
            b"application",
            150,
        )
        .expect("new reverse send");
    let before = p.ji.image().expect("before receipt").digest;
    assert!(matches!(
        p.ji.receive_message(&p.f.initiator, p.session, &reverse, b"application", 150),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        p.ji.image()
            .expect("unadmitted receiving epoch unchanged")
            .digest,
        before
    );
    assert_eq!(
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150)
            .expect("receipt"),
        1
    );
    assert_eq!(
        p.ji.receive_message(&p.f.initiator, p.session, &reverse, b"application", 150)
            .expect("new reverse delivery")
            .as_bytes(),
        b"new reverse"
    );
    assert_eq!(
        p.ji.receive_message(&p.f.initiator, p.session, &old_reverse, b"application", 150)
            .expect("delayed old reverse")
            .as_bytes(),
        b"old reverse during rekey"
    );
    assert_eq!(p.receive(&first).as_bytes(), b"old first");
    assert_eq!(
        p.ji.resume_message(&p.f.initiator, p.session, id(p.session, 1, 1), 150)
            .expect("old outbox replay"),
        first
    );
    for old in [id(p.session, 1, 1), id(p.session, 1, 2)] {
        p.jr.consume_message(&p.f.responder, p.session, old, 150)
            .expect("consume old");
    }
    let old_ack =
        p.jr.message_acknowledgement_for_epoch(&p.f.responder, p.session, 0, 150)
            .expect("old epoch ACK");
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &old_ack, 150)
            .expect("retire old only"),
        2
    );
    assert_eq!(
        p.ji.message_status(&p.f.initiator, p.session, new_id)
            .expect("new remains"),
        MessageStatus::Committed
    );
    let mut forged = b"QPCMACK2".to_vec();
    forged.extend_from_slice(&p.session);
    forged.push(1);
    forged.extend_from_slice(&1u64.to_be_bytes());
    forged.extend_from_slice(&1u64.to_be_bytes());
    let old_state = state(&mut p.jr, &p.session);
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(epoch(&old_state).receive_ack.as_bytes())
            .expect("disclosed old ACK key");
    mac.update(&label(b"acknowledgement"));
    mac.update(&forged);
    forged.extend_from_slice(&mac.finalize().into_bytes());
    assert!(matches!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &forged, 150),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    p.jr.consume_message(&p.f.responder, p.session, new_id, 150)
        .expect("consume new");
    let new_ack =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("new ACK");
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &new_ack, 150)
            .expect("new retirement"),
        1
    );
    for (flight, wire) in [
        (RekeyFlight::Offer, &offer),
        (RekeyFlight::Response, &response),
        (RekeyFlight::Final, &final_wire),
        (RekeyFlight::Receipt, &receipt),
    ] {
        assert_eq!(
            p.ji.rekey_outbox(&p.f.initiator, p.session, 1, flight, 150)
                .expect("retained exact control"),
            *wire
        );
    }
    let root_i = state(&mut p.ji, &p.session);
    let root_r = state(&mut p.jr, &p.session);
    assert_eq!(root_i.rekey.as_bytes(), root_r.rekey.as_bytes());
    assert_eq!(root_i.traffic(0).expect("old").send.as_bytes(), &[0; 32]);
    p.ji.close();
    p.jr.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    p.jr = reopen(&p.pr, p.f.local_device());
    for expected in [2, 3] {
        assert_eq!(complete_rekey(&mut p), expected);
        let next =
            p.ji.next_message_id(&p.f.initiator, p.session, 150)
                .expect("later id");
        assert_eq!(
            (next.epoch().expect("epoch"), next.index().expect("index")),
            (expected, 0)
        );
        let wire = p.send(next, b"later epoch");
        assert_eq!(p.receive(&wire).as_bytes(), b"later epoch");
    }
    let revision = p.jr.image().expect("before capacity").revision;
    assert!(matches!(
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150),
        Err(DurableError::Capacity)
    ));
    assert_eq!(
        p.jr.image().expect("no replacement at bound").revision,
        revision
    );
}

#[test]
fn drained_history_allows_repeated_rekeys_without_reusing_retired_ids() {
    let mut p = Pair::new();
    p.activate();
    let old_id = id(p.session, 1, 1);
    let old_wire = p.send(old_id, b"initial delivery");
    p.receive(&old_wire);
    p.jr.consume_message(&p.f.responder, p.session, old_id, 150)
        .expect("consume initial");
    let old_ack =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("initial ACK");
    p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &old_ack, 150)
        .expect("acknowledge initial");
    for target in 1..=8 {
        assert_eq!(complete_rekey(&mut p), target);
        let next =
            p.ji.next_message_id(&p.f.initiator, p.session, 150)
                .expect("fresh ID");
        assert_eq!(next.epoch().expect("epoch"), target);
        let wire = p.send(next, b"ongoing traffic");
        assert_eq!(p.receive(&wire).as_bytes(), b"ongoing traffic");
        p.jr.consume_message(&p.f.responder, p.session, next, 150)
            .expect("consume");
        let ack =
            p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
                .expect("ACK");
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
            .expect("acknowledge");
        assert!(state(&mut p.ji, &p.session).epochs.len() <= MAX_TRAFFIC_EPOCHS);
        assert!(state(&mut p.jr, &p.session).epochs.len() <= MAX_TRAFFIC_EPOCHS);
        p.ji.close();
        p.jr.close();
        p.ji = reopen(&p.pi, p.f.initiator_device());
        p.jr = reopen(&p.pr, p.f.local_device());
    }
    assert!(matches!(
        p.ji.send_message(
            &p.f.initiator,
            p.session,
            old_id,
            b"initial delivery",
            b"application",
            150
        ),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &old_wire, b"application", 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
    assert!(matches!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &old_ack, 150),
        Err(DurableError::Protocol(Error::Retired))
    ));
}

#[test]
fn epoch_retirement_waits_for_consumption_and_lost_ack_recovery_on_both_peers() {
    let mut p = Pair::new();
    p.activate();
    let old_id = id(p.session, 1, 1);
    let wire = p.send(old_id, b"retained delivery");
    p.receive(&wire);
    for target in 1..=3 {
        assert_eq!(complete_rekey(&mut p), target);
    }
    let before = p.jr.image().expect("before blocked offer").revision;
    assert!(matches!(
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150),
        Err(DurableError::Capacity)
    ));
    assert_eq!(p.jr.image().expect("no discarded inbox").revision, before);
    assert_eq!(p.receive(&wire).as_bytes(), b"retained delivery");
    p.jr.consume_message(&p.f.responder, p.session, old_id, 150)
        .expect("consume old delivery");
    let offer =
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
            .expect("locally drained proposer");
    let before = p.ji.image().expect("before lost ACK").revision;
    assert!(matches!(
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &offer, &p.f.signer_i, 150),
        Err(DurableError::Capacity)
    ));
    assert_eq!(p.ji.image().expect("outbox remains").revision, before);
    assert_eq!(
        p.ji.resume_message(&p.f.initiator, p.session, old_id, 150)
            .expect("exact old replay"),
        wire
    );
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    let ack =
        p.jr.message_acknowledgement_for_epoch(&p.f.responder, p.session, 0, 150)
            .expect("lost ACK recoverable while offer is pending");
    p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
        .expect("sender learns consumption");
    let response =
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &offer, &p.f.signer_i, 150)
            .expect("both peers drained old history");
    let final_wire =
        p.jr.accept_rekey_response(&p.f.responder, p.session, &response, &p.f.signer_r, 150)
            .expect("retire proposer old epoch with exact final");
    assert!(!state(&mut p.jr, &p.session).epochs.contains_key(&0));
    assert!(state(&mut p.ji, &p.session).epochs.contains_key(&0));
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.accept_rekey_response(&p.f.responder, p.session, &response, &p.f.signer_r, 150)
            .expect("lost final exact replay"),
        final_wire
    );
    let receipt =
        p.ji.finish_rekey(&p.f.initiator, p.session, &final_wire, &p.f.signer_i, 150)
            .expect("retire responder old epoch with receipt");
    assert!(!state(&mut p.ji, &p.session).epochs.contains_key(&0));
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.finish_rekey(&p.f.initiator, p.session, &final_wire, &p.f.signer_i, 150)
            .expect("lost receipt exact replay"),
        receipt
    );
    assert_eq!(
        p.jr.accept_rekey_receipt(&p.f.responder, p.session, &receipt, 150)
            .expect("receipt"),
        4
    );
    assert_eq!(complete_rekey(&mut p), 5);
    let next =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("fresh ID");
    let wire = p.send(next, b"traffic after asymmetric retirement");
    assert_eq!(
        p.receive(&wire).as_bytes(),
        b"traffic after asymmetric retirement"
    );
}

#[test]
fn rekey_epoch_rejects_bad_kem_confirmation_signatures_and_revoked_completion() {
    use crate::crypto::{envelope, open_envelope, Purpose};
    let mut p = Pair::new();
    p.activate();
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let reply =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("reply");
    let before = p.ji.image().expect("before").digest;
    let (body, _) = open_envelope(&reply).expect("reply body");
    let mut changed = body.to_vec();
    *changed.get_mut(185).expect("ML-KEM ciphertext byte") ^= 1;
    let signature =
        p.f.signer_r
            .sign(Purpose::RekeyResponse, &changed)
            .expect("valid identity proof for altered ciphertext");
    let invalid = envelope(&changed, &signature).expect("wire");
    assert!(matches!(
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &invalid, &p.f.signer_i, 150),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(
        p.ji.image()
            .expect("no signature reservation after failed KEM confirmation")
            .digest,
        before
    );
    let final_wire =
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150)
            .expect("real final");
    let before = p.jr.image().expect("before final").digest;
    let (body, signature) = open_envelope(&final_wire).expect("final body");
    for offset in [0, signature.len() - 1] {
        let mut invalid = signature.to_vec();
        *invalid.get_mut(offset).expect("signature component") ^= 1;
        let wire = envelope(body, &invalid).expect("wire");
        assert!(p
            .jr
            .finish_rekey(&p.f.responder, p.session, &wire, &p.f.signer_r, 150)
            .is_err());
        assert_eq!(p.jr.image().expect("no mutation").digest, before);
    }
    let mut changed = body.to_vec();
    *changed.last_mut().expect("confirmation MAC") ^= 1;
    let signature =
        p.f.signer_i
            .sign(Purpose::RekeyFinal, &changed)
            .expect("valid identity signature");
    assert!(matches!(
        p.jr.finish_rekey(
            &p.f.responder,
            p.session,
            &envelope(&changed, &signature).expect("wire"),
            &p.f.signer_r,
            150
        ),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(
        p.jr.image()
            .expect("no mutation after bad confirmation")
            .digest,
        before
    );
    let receipt =
        p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150)
            .expect("real receipt");
    let before = p.ji.image().expect("before receipt").digest;
    let (body, _) = open_envelope(&receipt).expect("receipt body");
    let mut changed = body.to_vec();
    *changed.last_mut().expect("receipt MAC") ^= 1;
    let signature =
        p.f.signer_r
            .sign(Purpose::RekeyReceipt, &changed)
            .expect("valid identity signature");
    assert!(matches!(
        p.ji.accept_rekey_receipt(
            &p.f.initiator,
            p.session,
            &envelope(&changed, &signature).expect("wire"),
            150
        ),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(
        p.ji.image().expect("no early receiving cutover").digest,
        before
    );
    p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150)
        .expect("real receipt");
    p.f.signer_i.close();
    p.f.signer_r.close();
    assert_eq!(
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150)
            .expect("cached final after signer close"),
        final_wire
    );
    assert_eq!(
        p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150)
            .expect("cached receipt after signer close"),
        receipt
    );
    let revoked = rosters::tests::update(p.f.initiator_device(), 90, 2, false);
    p.ji.install_roster(&revoked, 150).expect("revocation");
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.rekey_progress(&p.f.initiator, p.session)
            .expect("read-only progress")
            .confirmed_epoch,
        1
    );
    assert!(matches!(
        p.ji.rekey_outbox(&p.f.initiator, p.session, 1, RekeyFlight::Final, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

fn prepared_cutover(operation: &str, completed: u64) -> (Pair, Vec<u8>) {
    assert_eq!(completed % 2, 0, "this harness uses the initiator proposer");
    let mut p = Pair::new();
    p.activate();
    for target in 1..=completed {
        assert_eq!(complete_rekey(&mut p), target);
    }
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let reply =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("reply");
    if operation == "rekey-final" {
        return (p, reply);
    }
    let final_wire =
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150)
            .expect("final");
    if operation == "rekey-receipt" {
        return (p, final_wire);
    }
    assert_eq!(operation, "rekey-accept-receipt");
    let receipt =
        p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150)
            .expect("receipt");
    (p, receipt)
}

fn cutover_call(
    journal: &mut DeviceJournal,
    f: &Fixture,
    session: [u8; 32],
    operation: &str,
    input: &[u8],
) -> Result<Vec<u8>, DurableError> {
    match operation {
        "rekey-final" => {
            journal.accept_rekey_response(&f.initiator, session, input, &f.signer_i, 150)
        }
        "rekey-receipt" => journal.finish_rekey(&f.responder, session, input, &f.signer_r, 150),
        "rekey-accept-receipt" => journal
            .accept_rekey_receipt(&f.initiator, session, input, 150)
            .map(|epoch| epoch.to_be_bytes().to_vec()),
        _ => Err(DurableError::Protocol(Error::State)),
    }
}

fn finish_after_cutover(p: &mut Pair, operation: &str, output: &[u8], target: u64) {
    if operation == "rekey-final" {
        let receipt =
            p.jr.finish_rekey(&p.f.responder, p.session, output, &p.f.signer_r, 150)
                .expect("peer consumes recovered final");
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150)
            .expect("recover proposer receive chain");
    } else if operation == "rekey-receipt" {
        p.ji.accept_rekey_receipt(&p.f.initiator, p.session, output, 150)
            .expect("consume recovered receipt");
    }
    let id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("fresh epoch slot");
    assert_eq!(id.epoch().expect("epoch"), target);
    let expected_first = first_retained_epoch(target);
    for journal in [&mut p.ji, &mut p.jr] {
        let state = state(journal, &p.session);
        assert_eq!(
            state.epochs.first_key_value().expect("retained history").0,
            &expected_first
        );
        assert!(state.epochs.len() <= MAX_TRAFFIC_EPOCHS);
    }
    let wire = p.send(id, b"real new epoch after fault");
    assert_eq!(p.receive(&wire).as_bytes(), b"real new epoch after fault");
}

#[test]
fn rekey_epoch_sync_faults_cover_every_observed_cutover_barrier() {
    rekey_epoch_sync_recovery(0);
}

#[test]
fn rekey_history_retirement_sync_faults_preserve_exact_cutovers() {
    rekey_epoch_sync_recovery(4);
}

fn rekey_epoch_sync_recovery(completed: u64) {
    for operation in ["rekey-final", "rekey-receipt", "rekey-accept-receipt"] {
        let (mut baseline, input) = prepared_cutover(operation, completed);
        let is_i = operation != "rekey-receipt";
        let (path, device) = if is_i {
            baseline.ji.close();
            (&baseline.pi, baseline.f.initiator_device())
        } else {
            baseline.jr.close();
            (&baseline.pr, baseline.f.local_device())
        };
        let (mut normal, _, count, _) = fault_store(path, device, false);
        count.store(0, Ordering::SeqCst);
        cutover_call(
            &mut normal,
            &baseline.f,
            baseline.session,
            operation,
            &input,
        )
        .expect("measure cutover");
        let barriers = count.load(Ordering::SeqCst);
        let persists = if operation == "rekey-accept-receipt" {
            1
        } else {
            2
        };
        assert!(
            (persists * 4..=48).contains(&barriers),
            "{operation} barriers={barriers}"
        );
        normal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let (mut p, input) = prepared_cutover(operation, completed);
                let revision = if is_i {
                    p.ji.image().expect("before").revision
                } else {
                    p.jr.image().expect("before").revision
                };
                let (path, device) = if is_i {
                    p.ji.close();
                    (&p.pi, p.f.initiator_device())
                } else {
                    p.jr.close();
                    (&p.pr, p.f.local_device())
                };
                let (mut failed, remaining, _, _) = fault_store(path, device, after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    cutover_call(&mut failed, &p.f, p.session, operation, &input),
                    after,
                );
                assert!(failed.active.is_none());
                let mut recovered = reopen(path, device);
                let output = cutover_call(&mut recovered, &p.f, p.session, operation, &input)
                    .expect("recover exact cutover");
                assert_eq!(
                    cutover_call(&mut recovered, &p.f, p.session, operation, &input)
                        .expect("same committed output"),
                    output
                );
                assert_eq!(
                    recovered.image().expect("one cutover").revision,
                    revision + persists as u64
                );
                if is_i {
                    p.ji = recovered;
                } else {
                    p.jr = recovered;
                }
                finish_after_cutover(&mut p, operation, &output, completed + 1);
            }
        }
        eprintln!(
            "REKEY_EPOCH_SYNC_RECOVERY prior={completed} operation={operation} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}

#[test]
fn killed_rekey_epoch_cutovers_preserve_signed_outputs_and_real_traffic() {
    killed_rekey_epoch_cutovers(0);
}

#[test]
fn killed_rekey_history_retirement_preserves_signed_outputs_and_real_traffic() {
    killed_rekey_epoch_cutovers(4);
}

fn killed_rekey_epoch_cutovers(completed: u64) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for (operation, stage, input_name) in [
        ("rekey-final", "rekey-final-reserved", "rekey-response"),
        ("rekey-final", "rekey-final-computed", "rekey-response"),
        ("rekey-final", "rekey-final-committed", "rekey-response"),
        ("rekey-receipt", "rekey-receipt-reserved", "rekey-final"),
        ("rekey-receipt", "rekey-receipt-computed", "rekey-final"),
        ("rekey-receipt", "rekey-receipt-committed", "rekey-final"),
        (
            "rekey-accept-receipt",
            "rekey-receipt-accepted",
            "rekey-receipt",
        ),
    ] {
        let (mut p, input) = prepared_cutover(operation, completed);
        let is_i = operation != "rekey-receipt";
        let (path, device) = if is_i {
            p.ji.close();
            (&p.pi, p.f.initiator_device())
        } else {
            p.jr.close();
            (&p.pr, p.f.local_device())
        };
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("public keys");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("operation"), operation).expect("operation");
        fs::write(path.join(input_name), &input).expect("control input");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::messages::tests::message_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{stage} did not reach actual barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let mut recovered = reopen(path, device);
        if stage.ends_with("reserved") {
            let context = if is_i { &p.f.initiator } else { &p.f.responder };
            assert!(matches!(
                recovered.next_message_id(context, p.session, 150),
                Err(DurableError::Suspended)
            ));
        }
        let output = cutover_call(&mut recovered, &p.f, p.session, operation, &input)
            .expect("recover exact cutover");
        if stage.ends_with("computed") {
            assert_eq!(
                output,
                fs::read(path.join("rekey-effect")).expect("original signed output")
            );
        }
        if is_i {
            p.ji = recovered;
        } else {
            p.jr = recovered;
        }
        finish_after_cutover(&mut p, operation, &output, completed + 1);
    }
}

#[test]
fn disclosed_old_chain_can_poison_retention_across_restart_and_key_only_replacement() {
    // One receiver-chain disclosure, before any send. All forged frames are
    // computed now, before further access to either honest journal. Identity,
    // root, ACK, storage and later KEM secrets are not inputs to this attacker.
    fn forge(mut chain: ZeroizingBytes<32>, session: [u8; 32]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        for index in 0..8 {
            let (next, message) = step(&chain, index).expect("disclosed chain step");
            chain = next;
            let mut wire = Header {
                epoch: 0,
                session,
                role: 1,
                index,
                id: MessageId::for_epoch(&session, 1, 0, index).expect("public ID"),
                length: b"forged old epoch".len(),
            }
            .encode();
            let mut plaintext = b"forged old epoch".to_vec();
            let cipher = ChaCha20Poly1305::new_from_slice(message.as_bytes()).expect("key");
            let tag = cipher
                .encrypt_inout_detached(
                    &Nonce::from([0; 12]),
                    &associated(&wire, b"application"),
                    plaintext.as_mut_slice().into(),
                )
                .expect("attacker-owned AEAD calculation");
            wire.extend_from_slice(&plaintext);
            wire.extend_from_slice(&tag);
            packets.push(wire);
        }
        packets
    }
    let mut p = Pair::new();
    p.activate();
    let receiver = state(&mut p.jr, &p.session);
    let stolen = key(epoch(&receiver).receive.as_bytes()).expect("one disclosed chain key");
    drop(receiver);
    let packets = forge(stolen, p.session);
    for packet in &packets {
        let delivery = p.receive(packet);
        assert_eq!(delivery.as_bytes(), b"forged old epoch");
        p.jr.consume_message(&p.f.responder, p.session, delivery.message_id(), 150)
            .expect("application consumes authenticated old-epoch delivery");
    }
    assert_eq!(epoch(&state(&mut p.ji, &p.session)).sent, 0);
    let poisoned = state(&mut p.jr, &p.session);
    assert_eq!(
        (epoch(&poisoned).received, epoch(&poisoned).receive_floor),
        (8, 8)
    );
    assert!(epoch(&poisoned).incoming.is_empty() && epoch(&poisoned).skipped.is_empty());
    drop(poisoned);
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(epoch(&state(&mut p.jr, &p.session)).receive_floor, 8);
    let honest_id = id(p.session, 1, 1);
    let honest_wire = p.send(honest_id, b"honest sender after interference");
    assert!(matches!(
        p.jr.receive_message(&p.f.responder, p.session, &honest_wire, b"application", 150),
        Err(DurableError::Protocol(Error::Retired))
    ));

    // Fresh, independently identity-signed control flights are not affected by
    // this old-chain disclosure. Those first two flights alone do not install an epoch.
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("honest offer");
    let response =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("honest response");
    let (body, signature) = crate::crypto::open_envelope(&response).expect("envelope");
    p.f.local_device()
        .key
        .verify(crate::crypto::Purpose::RekeyResponse, body, signature)
        .expect("uncompromised identity signatures");
    assert_eq!(epoch(&state(&mut p.jr, &p.session)).receive_floor, 8);

    // A deliberately isolated candidate transition: replace ONLY traffic keys,
    // retaining the current namespace/counters. This is not an installed rekey
    // API or a proposed repair. Direct AEAD verification shows the packet has a
    // valid fresh key; normal receive still rejects it at the retired-ID guard.
    let mut sender = state(&mut p.ji, &p.session);
    let mut receiver = state(&mut p.jr, &p.session);
    let mut fresh = ZeroizingBytes::<32>::zeroed();
    getrandom::fill(fresh.as_mut_bytes()).expect("post-interference entropy");
    epoch_mut(&mut sender).send = key(fresh.as_bytes()).expect("fresh sending chain");
    epoch_mut(&mut receiver).receive = key(fresh.as_bytes()).expect("same fresh receiving chain");
    let index = epoch(&sender).sent;
    let fresh_id = MessageId::for_epoch(&p.session, 1, 0, index).expect("unchanged namespace");
    epoch_mut(&mut sender).pending = Some(SendPlan {
        id: fresh_id,
        plaintext: Zeroizing::new(b"fresh-key packet".to_vec()),
        ad: b"application".to_vec(),
    });
    let wire = epoch_mut(&mut sender)
        .send(fresh_id, b"fresh-key packet", b"application")
        .expect("key-only candidate packet");
    let (_, message) = step(&fresh, index).expect("direct key schedule");
    let header = Header::decode(&wire).expect("public header");
    let mut clear = wire
        .get(MESSAGE_HEADER..MESSAGE_HEADER + header.length)
        .expect("ciphertext")
        .to_vec();
    let tag = Tag::from(
        <[u8; 16]>::try_from(
            wire.get(MESSAGE_HEADER + header.length..)
                .expect("AEAD tag"),
        )
        .expect("tag length"),
    );
    ChaCha20Poly1305::new_from_slice(message.as_bytes())
        .expect("fresh key")
        .decrypt_inout_detached(
            &Nonce::from([0; 12]),
            &associated(wire.get(..MESSAGE_HEADER).expect("header"), b"application"),
            clear.as_mut_slice().into(),
            &tag,
        )
        .expect("fresh-key packet is cryptographically valid");
    assert_eq!(clear, b"fresh-key packet");
    assert!(matches!(
        epoch_mut(&mut receiver).receive(&wire, b"application"),
        Err(Error::Retired)
    ));
    assert_eq!(epoch(&receiver).receive_floor, 8);
    // The real epoch-scoped transition now separates those retired IDs while
    // retaining the old state. This is the positive control for the rejected
    // key-only projection above, using actual KEM-derived traffic keys.
    let final_wire =
        p.ji.accept_rekey_response(&p.f.initiator, p.session, &response, &p.f.signer_i, 150)
            .expect("real final");
    let receipt =
        p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150)
            .expect("real receipt");
    p.ji.accept_rekey_receipt(&p.f.initiator, p.session, &receipt, 150)
        .expect("real receive cutover");
    let recovered_id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("fresh epoch ID");
    assert_eq!(recovered_id.epoch().expect("epoch"), 1);
    assert_ne!(recovered_id, honest_id);
    let recovered = p.send(recovered_id, b"honest new epoch survives old poisoning");
    assert_eq!(
        p.receive(&recovered).as_bytes(),
        b"honest new epoch survives old poisoning"
    );
    assert_eq!(epoch(&state(&mut p.jr, &p.session)).receive_floor, 8);
    assert_eq!(
        p.ji.resume_message(&p.f.initiator, p.session, honest_id, 150)
            .expect("old outbox preserved"),
        honest_wire
    );
    eprintln!("OLD_CHAIN_RETENTION_POISON forged=8 honest_sent_before=0 persisted_floor=8 actual_honest_receive=retired signed_rekey_response=valid isolated_fresh_aead=valid key_only_candidate_receive=retired real_epoch_one_receive=accepted old_outbox=retained");
    let poisoned_ack =
        p.jr.message_acknowledgement_for_epoch(&p.f.responder, p.session, 0, 150)
            .expect("authentic ACK with poisoned count");
    assert!(matches!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &poisoned_ack, 150),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    p.jr.consume_message(&p.f.responder, p.session, recovered_id, 150)
        .expect("consume recovered traffic");
    let ack =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("fresh ACK");
    p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack, 150)
        .expect("fresh ACK accepted");
    for target in [2, 3] {
        assert_eq!(complete_rekey(&mut p), target);
    }
    let next_offer =
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150)
            .expect("receiver has no unresolved local data");
    assert!(matches!(
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &next_offer, &p.f.signer_i, 150),
        Err(DurableError::Capacity)
    ));
    eprintln!("OLD_CHAIN_RECOVERY_BOUNDARY fresh_epochs=3 next_response=capacity old_ack=authenticated_but_out_of_range delivery_outcome=unknown");
    let report =
        p.ji.begin_closed_epoch_resolution(&p.f.initiator, p.session, 0, 150)
            .expect("explicit application resolution");
    assert_eq!(
        (
            report.epoch(),
            report.acknowledged_before(),
            report.sent_count()
        ),
        (0, 0, 1)
    );
    assert_eq!(report.unconfirmed_messages().len(), 1);
    let unconfirmed = report
        .unconfirmed_messages()
        .first()
        .expect("exactly the honest old send");
    assert_eq!(unconfirmed.message_id(), honest_id);
    assert_eq!(
        *unconfirmed.ciphertext_digest(),
        digest(&label(b"resolution-ciphertext/v1"), &honest_wire)
    );
    let resolution = report.resolution_id();
    assert_eq!(
        p.ji.message_status(&p.f.initiator, p.session, honest_id)
            .expect("pending outcome"),
        MessageStatus::ResolutionPending
    );
    assert!(matches!(
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &next_offer, &p.f.signer_i, 150),
        Err(DurableError::Capacity)
    ));
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.begin_closed_epoch_resolution(&p.f.initiator, p.session, 0, 150)
            .expect("same report after restart")
            .resolution_id(),
        resolution
    );
    let mut application = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p.pi.join("application-unknown-delivery"))
        .expect("new application receipt");
    application
        .write_all(resolution.as_bytes())
        .expect("report identity");
    application
        .write_all(honest_id.as_bytes())
        .expect("unknown delivery identity");
    application
        .sync_all()
        .expect("persist application outcome before library acknowledgement");
    fs::File::open(&p.pi)
        .expect("application receipt directory")
        .sync_all()
        .expect("persist the new receipt directory entry");
    p.ji.acknowledge_closed_epoch_resolution(&p.f.initiator, p.session, 0, resolution, 150)
        .expect("accounted unknown outcome");
    assert_eq!(
        p.ji.message_status(&p.f.initiator, p.session, honest_id)
            .expect("true unknown outcome"),
        MessageStatus::DeliveryUnknown
    );
    assert_eq!(
        (
            epoch(&state(&mut p.ji, &p.session)).send_floor,
            epoch(&state(&mut p.ji, &p.session)).sent
        ),
        (0, 1)
    );
    assert_eq!(complete_rekey(&mut p), 4);
    for target in [5, 6] {
        assert_eq!(complete_rekey(&mut p), target);
    }
    let next =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("post-resolution ID");
    let fresh = p.send(next, b"continued PQ epochs after explicit unknown outcome");
    assert_eq!(
        p.receive(&fresh).as_bytes(),
        b"continued PQ epochs after explicit unknown outcome"
    );
    eprintln!("OLD_CHAIN_RESOLUTION unknown_deliveries=1 acknowledged_floor=unchanged fresh_epochs=6 actual_traffic=accepted history=bounded");
}

#[test]
fn rekey_response_agrees_with_real_decapsulation_and_replays_without_advancing_traffic() {
    use hmac::{Hmac, Mac};
    use q_periapt_sdk::expert::replay::{RecoveryKey, SealedOperation};
    let mut p = Pair::new();
    p.activate();
    let before = state(&mut p.jr, &p.session);
    let revision = p.jr.image().expect("before").revision;
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let response =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("response");
    let (body, signature) = crate::crypto::open_envelope(&response).expect("envelope");
    p.f.local_device()
        .key
        .verify(crate::crypto::Purpose::RekeyResponse, body, signature)
        .expect("both signatures");
    assert!(p
        .f
        .local_device()
        .key
        .verify(crate::crypto::Purpose::RekeyOffer, body, signature)
        .is_err());
    for offset in [0, signature.len() - 1] {
        let mut changed = signature.to_vec();
        *changed.get_mut(offset).expect("signature byte") ^= 1;
        assert!(p
            .f
            .local_device()
            .key
            .verify(crate::crypto::Purpose::RekeyResponse, body, &changed)
            .is_err());
    }
    let (offer_body, _) = crate::crypto::open_envelope(&offer).expect("offer body");
    let offer_prefix = offer_body.get(..153).expect("fixed prefix");
    let image = p.ji.image().expect("initiator plan");
    let payload = &image
        .records
        .get(&record_id(&p.session))
        .expect("message state")
        .payload;
    let token_end = payload.len() - offer.len();
    let token = SealedOperation::from_bytes(
        payload
            .get(token_end - 277..token_end)
            .expect("sealed generation reservation"),
    )
    .expect("token");
    let scope = rekey_digest(b"operation", &[image.id.as_slice(), offer_prefix].concat());
    let recovery = RecoveryKey::from_host_key(p.ji.active.as_ref().expect("open").key.0.as_bytes())
        .expect("recovery owner");
    let key_owner = recovery
        .generate_key(
            &p.f.initiator.policy().runtime,
            &rekey_digest(b"key", &scope),
            &token,
        )
        .expect("exact offer key");
    let ciphertext =
        q_periapt_sdk::Ciphertext::from_bytes(body.get(185..1305).expect("response ciphertext"))
            .expect("ciphertext");
    let shared = key_owner
        .decapsulate(&ciphertext, &rekey_digest(b"response-kem", &offer))
        .expect("actual two-leg decapsulation")
        .export_for_protocol()
        .expect("protocol secret");
    let core = body.get(..1305).expect("response core");
    let core_hash = rekey_digest(b"response-core", core);
    let mut root = ZeroizingBytes::<32>::zeroed();
    let mut info = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/pending-root/HKDF-SHA256/".to_vec();
    info.extend_from_slice(&core_hash);
    Hkdf::<Sha256>::new(Some(before.rekey.as_bytes()), shared.as_bytes())
        .expand(&info, root.as_mut_bytes())
        .expect("root KDF");
    let after = state(&mut p.jr, &p.session);
    let encoded = after.encode();
    assert_eq!(
        encoded.get(encoded.len() - 32..).expect("pending root"),
        root.as_bytes()
    );
    assert_ne!(root.as_bytes(), before.rekey.as_bytes());
    let mut confirmation = ZeroizingBytes::<32>::zeroed();
    Hkdf::<Sha256>::new(None, root.as_bytes())
        .expand(
            b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/responder-confirmation",
            confirmation.as_mut_bytes(),
        )
        .expect("confirmation key");
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(confirmation.as_bytes()).expect("MAC");
    mac.update(&core_hash);
    mac.verify_slice(body.get(1305..).expect("confirmation tag"))
        .expect("real peer key confirmation");
    for (current, previous) in [
        (&after.rekey, &before.rekey),
        (&epoch(&after).send, &epoch(&before).send),
        (&epoch(&after).receive, &epoch(&before).receive),
        (&epoch(&after).send_ack, &epoch(&before).send_ack),
        (&epoch(&after).receive_ack, &epoch(&before).receive_ack),
    ] {
        assert_eq!(current.as_bytes(), previous.as_bytes());
    }
    assert_eq!(
        (epoch(&after).sent, epoch(&after).received),
        (epoch(&before).sent, epoch(&before).received)
    );
    assert_eq!(p.jr.image().expect("committed").revision, revision + 3);
    p.f.signer_r.close();
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("exact replay with closed signer"),
        response
    );
    assert_eq!(p.jr.image().expect("no rewrite").revision, revision + 3);
    assert_eq!(
        p.jr.rekey_response_status(&p.f.responder, p.session)
            .expect("response state"),
        RekeyResponseStatus::Committed
    );
    let message = p.send(id(p.session, 1, 1), b"initial epoch still active");
    assert_eq!(
        p.receive(&message).as_bytes(),
        b"initial epoch still active"
    );
}

#[test]
fn rekey_response_rejects_unauthenticated_conflicting_and_revoked_offers() {
    let mut p = Pair::new();
    p.activate();
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let revision = p.jr.image().expect("before").revision;
    assert!(matches!(
        p.ji.respond_rekey_offer(&p.f.initiator, p.session, &offer, &p.f.signer_i, 150),
        Err(DurableError::Protocol(Error::State))
    ));
    assert!(matches!(
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_i, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    for at in [
        4,
        12,
        44,
        76,
        108,
        116,
        124,
        125,
        157,
        1373,
        offer.len() - 1,
    ] {
        let mut changed = offer.clone();
        *changed.get_mut(at).expect("bound field or signature") ^= 1;
        assert!(p
            .jr
            .respond_rekey_offer(&p.f.responder, p.session, &changed, &p.f.signer_r, 150)
            .is_err());
    }
    assert_eq!(
        p.jr.image().expect("no rejected input reserved").revision,
        revision
    );
    p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
        .expect("response");
    let (body, _) = crate::crypto::open_envelope(&offer).expect("body");
    let mut alternate = body.to_vec();
    let another =
        p.f.initiator
            .policy()
            .runtime
            .generate_key()
            .expect("alternative peer key");
    alternate
        .get_mut(153..)
        .expect("public key")
        .copy_from_slice(&another.public_key().expect("public").to_bytes());
    let signature =
        p.f.signer_i
            .sign(crate::crypto::Purpose::RekeyOffer, &alternate)
            .expect("valid conflicting offer");
    let different = crate::crypto::envelope(&alternate, &signature).expect("wire");
    assert!(matches!(
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &different, &p.f.signer_r, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        p.jr.image().expect("no alternate reservation").revision,
        revision + 3
    );
    let revoked = rosters::tests::update(p.f.initiator_device(), 90, 2, false);
    p.jr.install_roster(&revoked, 150).expect("revocation");
    p.jr.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.rekey_response_status(&p.f.responder, p.session)
            .expect("read-only phase"),
        RekeyResponseStatus::Committed
    );
    assert!(matches!(
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

#[test]
fn rekey_response_sync_faults_reconcile_every_observed_barrier() {
    let mut baseline = Pair::new();
    baseline.activate();
    let offer = baseline
        .ji
        .prepare_rekey_offer(
            &baseline.f.initiator,
            baseline.session,
            &baseline.f.signer_i,
            150,
        )
        .expect("offer");
    baseline.jr.close();
    let (mut normal, _, count, _) = fault_store(&baseline.pr, baseline.f.local_device(), false);
    count.store(0, Ordering::SeqCst);
    normal
        .respond_rekey_offer(
            &baseline.f.responder,
            baseline.session,
            &offer,
            &baseline.f.signer_r,
            150,
        )
        .expect("measure response");
    let barriers = count.load(Ordering::SeqCst);
    assert!(
        (12..=48).contains(&barriers),
        "observed barriers {barriers}"
    );
    normal.close();
    for cut in 1..=barriers {
        for after in [false, true] {
            let mut p = Pair::new();
            p.activate();
            let offer =
                p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                    .expect("offer");
            let revision = p.jr.image().expect("before").revision;
            p.jr.close();
            let (mut failed, remaining, _, _) = fault_store(&p.pr, p.f.local_device(), after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                failed.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150),
                after,
            );
            assert!(failed.active.is_none());
            p.jr = reopen(&p.pr, p.f.local_device());
            let wire =
                p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                    .expect("recover original plan");
            assert_eq!(
                p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                    .expect("same outbox"),
                wire
            );
            assert_eq!(
                p.jr.image().expect("three transitions").revision,
                revision + 3
            );
        }
    }
    eprintln!(
        "REKEY_RESPONSE_SYNC_RECOVERY barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn rekey_response_rejects_corrupt_pending_root_and_cached_signature() {
    let mut p = Pair::new();
    p.activate();
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let response =
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
            .expect("response");
    let mut image = p.jr.image().expect("committed");
    let saved = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("state");
    let end = saved.payload.len();
    *saved.payload.get_mut(end - 1).expect("pending root") ^= 1;
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
    let mut image = p.jr.image().expect("unaltered image");
    let saved = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("state");
    let offset = saved
        .payload
        .windows(response.len())
        .position(|value| value == response)
        .expect("cached response");
    *saved
        .payload
        .get_mut(offset + response.len() - 1)
        .expect("signature") ^= 1;
    p.jr.persist(&mut image)
        .expect("authenticated invalid-signature fixture");
    assert!(matches!(
        p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150),
        Err(DurableError::InvalidCheckpoint(Error::Authentication))
    ));
    assert!(p.jr.active.is_none());
}

#[test]
fn killed_rekey_response_reuses_encapsulation_and_signature_before_publication() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for stage in [
        "rekey-response-kem-reserved",
        "rekey-response-kem-computed",
        "rekey-response-signature-reserved",
        "rekey-response-signature-computed",
        "rekey-response-committed",
    ] {
        let mut p = Pair::new();
        p.activate();
        let offer =
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("offer");
        p.jr.close();
        let path = &p.pr;
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("public keys");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("rekey-offer"), &offer).expect("offer");
        fs::write(path.join("operation"), b"rekey-response").expect("operation");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::messages::tests::message_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{stage} did not reach its actual barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        p.jr = reopen(path, p.f.local_device());
        let wire =
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                .expect("recover same response");
        if stage == "rekey-response-kem-computed" {
            let (body, _) = crate::crypto::open_envelope(&wire).expect("envelope");
            assert_eq!(
                body,
                fs::read(path.join("rekey-effect")).expect("original computed ciphertext and MAC")
            );
        } else if stage == "rekey-response-signature-computed" {
            assert_eq!(
                wire,
                fs::read(path.join("rekey-effect")).expect("original signature bytes")
            );
        }
        assert_eq!(
            p.jr.rekey_response_status(&p.f.responder, p.session)
                .expect("committed"),
            RekeyResponseStatus::Committed
        );
    }
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
        assert_eq!(epoch(&state(&mut p.ji, &p.session)).sent, 1);
        assert_eq!(epoch(&state(&mut p.jr, &p.session)).received, 1);
    }
}

#[test]
fn frame_length_is_bounded_before_arithmetic_and_future_epochs_are_rejected() {
    let mut wire = Header {
        epoch: 0,
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
            epoch(&send).outgoing.is_empty()
                && epoch(&receive).incoming.is_empty()
                && epoch(&receive).skipped.is_empty()
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
    assert!(epoch(&consumed)
        .incoming
        .get(&b)
        .expect("retained marker")
        .plaintext
        .is_empty());
    assert_eq!(epoch(&consumed).skipped.len(), 1);
    let ack0 =
        p.jr.message_acknowledgement(&p.f.responder, p.session, 150)
            .expect("zero contiguous progress");
    assert_eq!(
        p.ji.accept_message_acknowledgement(&p.f.initiator, p.session, &ack0, 150)
            .expect("no retirement"),
        0
    );
    assert_eq!(epoch(&state(&mut p.ji, &p.session)).outgoing.len(), 2);
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
    epoch_mut(&mut dishonest).receive_floor = 3;
    let future = epoch(&dishonest)
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
    assert!(epoch(&state(&mut p.ji, &p.session)).outgoing.is_empty());
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
    epoch_mut(&mut s).sent = u64::MAX;
    epoch_mut(&mut s).send_floor = u64::MAX;
    epoch_mut(&mut s).received = u64::MAX;
    epoch_mut(&mut s).receive_floor = u64::MAX;
    assert_eq!(
        State::decode(&s.encode())
            .expect("terminal counters")
            .encode()
            .as_slice(),
        s.encode().as_slice()
    );
    assert!(MessageId::for_epoch(&s.session, s.role, 0, u64::MAX).is_err());
    let retired = MessageId::for_epoch(&s.session, s.role, 0, u64::MAX - 1).expect("last old slot");
    assert!(matches!(
        epoch_mut(&mut s).send(retired, b"replacement", b""),
        Err(Error::Retired)
    ));
    epoch_mut(&mut s).sent -= 1;
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

#[test]
fn rekey_offer_is_signed_once_replays_after_restart_and_preserves_traffic_state() {
    let mut p = Pair::new();
    p.activate();
    let before = p.ji.image().expect("before");
    let before_state = State::decode(
        &before
            .records
            .get(&record_id(&p.session))
            .expect("messages")
            .payload,
    )
    .expect("state");
    assert_eq!(
        p.ji.rekey_offer_status(&p.f.initiator, p.session)
            .expect("status"),
        RekeyOfferStatus::Absent
    );
    let wire =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let (body, signature) = crate::crypto::open_envelope(&wire).expect("signed envelope");
    let mut d = Decoder::new(body);
    assert_eq!(d.array::<8>().expect("tag"), *b"QPRKOF01");
    d.array::<32>().expect("profile");
    assert_eq!(d.array::<32>().expect("context"), p.f.initiator.digest());
    assert_eq!(d.array::<32>().expect("session"), p.session);
    assert_eq!(d.u64().expect("prior"), 0);
    assert_eq!(d.u64().expect("target"), 1);
    assert_eq!(d.array::<1>().expect("role"), [1]);
    assert_ne!(d.array::<32>().expect("parent"), [0; 32]);
    q_periapt_sdk::PublicKey::from_bytes(
        d.take(q_periapt_sdk::PUBLIC_KEY_LEN)
            .expect("fresh hybrid key"),
    )
    .expect("public key");
    d.finish().expect("exact body");
    p.f.initiator_device()
        .key
        .verify(crate::crypto::Purpose::RekeyOffer, body, signature)
        .expect("both independent identity signatures");
    for offset in [0, signature.len() - 1] {
        let mut forged = signature.to_vec();
        *forged.get_mut(offset).expect("signature component") ^= 1;
        assert!(p
            .f
            .initiator_device()
            .key
            .verify(crate::crypto::Purpose::RekeyOffer, body, &forged)
            .is_err());
    }
    assert!(p
        .f
        .initiator_device()
        .key
        .verify(crate::crypto::Purpose::BootstrapInitiator, body, signature)
        .is_err());
    let after = p.ji.image().expect("committed");
    let after_state = State::decode(
        &after
            .records
            .get(&record_id(&p.session))
            .expect("messages")
            .payload,
    )
    .expect("state");
    assert_eq!(after.revision, before.revision + 3);
    assert_eq!(
        (epoch(&after_state).sent, epoch(&after_state).received),
        (epoch(&before_state).sent, epoch(&before_state).received)
    );
    assert_eq!(after_state.rekey.as_bytes(), before_state.rekey.as_bytes());
    assert_eq!(
        epoch(&after_state).send.as_bytes(),
        epoch(&before_state).send.as_bytes()
    );
    assert_eq!(
        epoch(&after_state).receive.as_bytes(),
        epoch(&before_state).receive.as_bytes()
    );
    p.f.signer_i.close();
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("replay without a signing owner"),
        wire
    );
    assert_eq!(
        p.ji.image().expect("not rewritten").revision,
        after.revision
    );
    assert_eq!(
        p.ji.rekey_offer_status(&p.f.initiator, p.session)
            .expect("phase"),
        RekeyOfferStatus::Committed
    );
    let id =
        p.ji.next_message_id(&p.f.initiator, p.session, 150)
            .expect("existing initial-epoch slot");
    let message = p.send(id, b"traffic after offer preparation");
    assert_eq!(
        p.receive(&message).as_bytes(),
        b"traffic after offer preparation"
    );
}

#[test]
fn rekey_offer_requires_the_designated_identity_and_current_rosters() {
    let mut p = Pair::new();
    p.activate();
    let revision = p.ji.image().expect("before").revision;
    assert!(matches!(
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_r, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        p.jr.prepare_rekey_offer(&p.f.responder, p.session, &p.f.signer_r, 150),
        Err(DurableError::Protocol(Error::State))
    ));
    assert_eq!(
        p.ji.image().expect("denial does not reserve").revision,
        revision
    );
    p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
        .expect("offer");
    let revoked = rosters::tests::update(p.f.initiator_device(), 90, 2, false);
    p.ji.install_roster(&revoked, 150)
        .expect("commit revocation");
    p.ji.close();
    p.ji = reopen(&p.pi, p.f.initiator_device());
    assert_eq!(
        p.ji.rekey_offer_status(&p.f.initiator, p.session)
            .expect("read-only reconciliation"),
        RekeyOfferStatus::Committed
    );
    assert!(matches!(
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

#[test]
fn rekey_offer_rejects_authenticated_epoch_invention_and_corrupt_cached_signatures() {
    let mut p = Pair::new();
    p.activate();
    let mut image = p.ji.image().expect("image");
    let saved = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("state");
    let offset = saved.payload.len() - 50; // fixed empty QPRKST02 control record
    saved
        .payload
        .get_mut(offset + 8..offset + 16)
        .expect("confirmed epoch")
        .copy_from_slice(&1u64.to_be_bytes());
    assert!(matches!(validate_image(&image), Err(DurableError::Corrupt)));
    let wire =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
            .expect("offer");
    let mut image = p.ji.image().expect("committed");
    let saved = image
        .records
        .get_mut(&record_id(&p.session))
        .expect("state");
    let offset = saved
        .payload
        .windows(wire.len())
        .position(|value| value == wire)
        .expect("exact cached offer");
    *saved
        .payload
        .get_mut(offset + wire.len() - 1)
        .expect("signature byte") ^= 1;
    p.ji.persist(&mut image)
        .expect("authenticated malformed test fixture");
    assert!(matches!(
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150),
        Err(DurableError::InvalidCheckpoint(Error::Authentication))
    ));
    assert!(p.ji.active.is_none());
}

#[test]
fn rekey_offer_sync_faults_reconcile_every_observed_barrier() {
    let mut baseline = Pair::new();
    baseline.activate();
    baseline.ji.close();
    let (mut normal, _, count, _) = fault_store(&baseline.pi, baseline.f.initiator_device(), false);
    count.store(0, Ordering::SeqCst);
    normal
        .prepare_rekey_offer(
            &baseline.f.initiator,
            baseline.session,
            &baseline.f.signer_i,
            150,
        )
        .expect("measure exact preparation");
    let barriers = count.load(Ordering::SeqCst);
    assert!(
        (12..=48).contains(&barriers),
        "observed barriers {barriers}"
    );
    normal.close();
    for cut in 1..=barriers {
        for after in [false, true] {
            let mut p = Pair::new();
            p.activate();
            let revision = p.ji.image().expect("before").revision;
            p.ji.close();
            let (mut failed, remaining, _, _) = fault_store(&p.pi, p.f.initiator_device(), after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                failed.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150),
                after,
            );
            assert!(failed.active.is_none());
            p.ji = reopen(&p.pi, p.f.initiator_device());
            let wire =
                p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                    .expect("recover exact plan");
            assert_eq!(
                p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                    .expect("same outbox"),
                wire
            );
            assert_eq!(
                p.ji.rekey_offer_status(&p.f.initiator, p.session)
                    .expect("phase"),
                RekeyOfferStatus::Committed
            );
            assert_eq!(
                p.ji.image().expect("one preparation").revision,
                revision + 3
            );
        }
    }
    eprintln!(
        "REKEY_OFFER_SYNC_RECOVERY barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn killed_rekey_preparation_reuses_reserved_keys_and_signatures_before_publication() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for stage in [
        "rekey-key-reserved",
        "rekey-key-computed",
        "rekey-signature-reserved",
        "rekey-signature-computed",
        "rekey-offer-committed",
    ] {
        let mut p = Pair::new();
        p.activate();
        p.ji.close();
        let path = &p.pi;
        let mut public =
            p.f.reusable
                .public_key()
                .expect("public")
                .to_bytes()
                .to_vec();
        public.extend_from_slice(&p.f.once.public_key().expect("public").to_bytes());
        fs::write(path.join("public-keys"), public).expect("fixture public keys");
        fs::write(path.join("session"), p.session).expect("session");
        fs::write(path.join("operation"), b"rekey").expect("operation");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::messages::tests::message_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "{stage} did not reach its actual barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        p.ji = reopen(path, p.f.initiator_device());
        let wire =
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("same computation");
        if stage == "rekey-key-computed" {
            let (body, _) = crate::crypto::open_envelope(&wire).expect("envelope");
            assert_eq!(
                body,
                fs::read(path.join("rekey-effect")).expect("original public key body")
            );
        } else if stage == "rekey-signature-computed" {
            assert_eq!(
                wire,
                fs::read(path.join("rekey-effect")).expect("original exact signature and wire")
            );
        }
        assert_eq!(
            p.ji.rekey_offer_status(&p.f.initiator, p.session)
                .expect("committed"),
            RekeyOfferStatus::Committed
        );
    }
}
