// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{directory, fault_store, new_store, reopen, ChildGuard};
use crate::{
    bootstrap::tests::{fixture, fixture_from_public, fixture_with_initiator_limits},
    crypto::{envelope, open_envelope, Purpose},
    PrekeyQuality,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

#[test]
fn both_journals_reopen_and_agree_for_every_mode_with_no_signing_owner() {
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let mut f = fixture(quality);
        let di = directory();
        let dr = directory();
        let pi = di.path().canonicalize().expect("path");
        let pr = dr.path().canonicalize().expect("path");
        let request = InitiationId::generate().expect("request");
        let mut ji = new_store(&pi, f.initiator_device());
        let mut jr = new_store(&pr, f.local_device());
        let initial = ji
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("durable initial");
        assert_eq!(
            ji.initiation_status(&f.initiator, request).expect("phase"),
            DurableStatus::AwaitingReply
        );
        f.signer_i.close();
        drop(ji);
        let (pq, classic) = f.sources();
        let reply = jr
            .respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classic,
                150,
            )
            .expect("durable reply");
        f.signer_r.close();
        f.reusable.close();
        f.once.close();
        drop(jr);
        let mut ji = reopen(&pi, f.initiator_device());
        assert_eq!(
            ji.resume_initial(Arc::clone(&f.initiator), request, 150)
                .expect("replay initial"),
            initial
        );
        let outcome = ji
            .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
            .expect("restore reply key and confirm");
        drop(ji);
        let mut ji = reopen(&pi, f.initiator_device());
        let replay = ji
            .resume_reply(Arc::clone(&f.initiator), request, 150)
            .expect("replay final");
        assert_eq!(outcome.final_message(), replay.final_message());
        assert_eq!(
            ji.initiation_status(&f.initiator, request).expect("phase"),
            DurableStatus::FinalCommitted
        );
        let mut jr = reopen(&pr, f.local_device());
        assert_eq!(
            jr.finish(
                Arc::clone(&f.responder),
                &initial,
                replay.final_message(),
                150
            )
            .expect("responder final"),
            replay.session_id()
        );
        let i = ji.image().expect("initiator image");
        let r = jr.image().expect("responder image");
        let saved_i = i.records.values().next().expect("I record");
        let saved_r = r.records.values().next().expect("R record");
        assert!(
            saved_i.keys.is_empty(),
            "initiator must not claim remote prekey consumption"
        );
        assert!(
            saved_i
                .payload
                .get(32 + PREFIX + 1 + 4633..32 + PREFIX + 1 + 4633 + 32)
                == saved_r.payload.get(10490..10522),
            "persisted roots differ"
        );
        f.close_initiator_policy();
        assert_eq!(
            ji.initiation_status(&f.initiator, request)
                .expect("read-only reconciliation"),
            DurableStatus::FinalCommitted
        );
        assert!(matches!(
            ji.resume_reply(Arc::clone(&f.initiator), request, 150),
            Err(DurableError::Protocol(Error::Closed))
        ));
    }
}

#[test]
fn pinned_reply_survives_local_quota_failure_and_cannot_be_substituted() {
    let f = fixture_with_initiator_limits(
        PrekeyQuality::ReusableBoth,
        q_periapt_sdk::Limits {
            max_live_keys: 1,
            max_in_flight: 1,
        },
    );
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    let request = InitiationId::generate().expect("request");
    let initial = journal
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("initial");
    let (pq, classic) = f.sources();
    let mut first = ResponderOperation::new(Arc::clone(&f.responder));
    let mut other = ResponderOperation::new(Arc::clone(&f.responder));
    let reply = first
        .respond(&initial, &f.signer_r, pq, classic, 150)
        .expect("reply")
        .to_vec();
    let alternative = other
        .respond(&initial, &f.signer_r, pq, classic, 150)
        .expect("alternative valid reply")
        .to_vec();
    let held = f.occupy_initiator_slot();
    assert!(matches!(
        journal.accept_reply(Arc::clone(&f.initiator), request, &reply, 150),
        Err(DurableError::Protocol(Error::Runtime(
            q_periapt_sdk::Error::ResourceLimit
        )))
    ));
    assert_eq!(
        journal
            .initiation_status(&f.initiator, request)
            .expect("phase"),
        DurableStatus::ProcessingReply
    );
    assert!(matches!(
        journal.accept_reply(Arc::clone(&f.initiator), request, &alternative, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        journal
            .resume_initial(Arc::clone(&f.initiator), request, 150)
            .expect("public replay needs no key slot"),
        initial
    );
    drop(held);
    let outcome = journal
        .resume_reply(Arc::clone(&f.initiator), request, 150)
        .expect("same reply after quota recovery");
    first
        .finish(outcome.final_message(), 150)
        .expect("actual final MAC");
    let _held = f.occupy_initiator_slot();
    assert_eq!(
        journal
            .resume_reply(Arc::clone(&f.initiator), request, 150)
            .expect("committed replay needs no key slot")
            .final_message(),
        outcome.final_message()
    );
}

#[test]
fn signature_and_confirmation_failures_preserve_pending_initiation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    let request = InitiationId::generate().expect("request");
    let initial = journal
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("initial");
    let (pq, classic) = f.sources();
    let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
    let reply = responder
        .respond(&initial, &f.signer_r, pq, classic, 150)
        .expect("reply")
        .to_vec();
    let mut bad = reply.clone();
    *bad.last_mut().expect("signature") ^= 1;
    let revision = journal.image().expect("image").revision;
    assert!(matches!(
        journal.accept_reply(Arc::clone(&f.initiator), request, &bad, 150),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(journal.image().expect("unchanged").revision, revision);
    let (body, _) = open_envelope(&reply).expect("body");
    let mut body = body.to_vec();
    *body.last_mut().expect("MAC") ^= 1;
    let bad = envelope(
        &body,
        &f.signer_r
            .sign(Purpose::BootstrapResponder, &body)
            .expect("sign"),
    )
    .expect("wire");
    assert!(matches!(
        journal.accept_reply(Arc::clone(&f.initiator), request, &bad, 150),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(
        journal
            .initiation_status(&f.initiator, request)
            .expect("phase"),
        DurableStatus::AwaitingReply
    );
    let result = journal
        .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
        .expect("valid confirmation");
    responder
        .finish(result.final_message(), 150)
        .expect("responder confirmation");
    let (different, _) = f.next_bundle_epoch();
    assert!(matches!(
        journal.initiate(different, request, &f.signer_i, 150),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        journal.status(&f.responder, &initial),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn each_initial_sync_failure_is_reconciled_without_new_initial_randomness() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let mut states = BTreeSet::new();
    for after_sync in [false, true] {
        for cut in 1..=6 {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            drop(new_store(&path, f.initiator_device()));
            let (mut journal, fault, _, _) = fault_store(&path, f.initiator_device(), after_sync);
            let request = InitiationId::generate().expect("request");
            fault.store(cut, Ordering::SeqCst);
            assert!(
                matches!(
                    journal.initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150),
                    Err(DurableError::CommitUncertain(_))
                ),
                "cut={cut} after={after_sync}"
            );
            let mut recovered = reopen(&path, f.initiator_device());
            let phase = recovered
                .initiation_status(&f.initiator, request)
                .expect("exact query");
            states.insert(phase as u8);
            match phase {
                DurableStatus::Absent => assert!(matches!(
                    recovered.resume_initial(Arc::clone(&f.initiator), request, 150),
                    Err(DurableError::Absent)
                )),
                DurableStatus::Executing => assert!(matches!(
                    recovered.resume_initial(Arc::clone(&f.initiator), request, 150),
                    Err(DurableError::Suspended)
                )),
                DurableStatus::Prepared | DurableStatus::AwaitingReply => {
                    let image = recovered.image().expect("image");
                    let record = image.records.values().next().expect("record");
                    assert_eq!(
                        recovered
                            .resume_initial(Arc::clone(&f.initiator), request, 150)
                            .expect("saved initial"),
                        initial(record).expect("pinned wire")
                    );
                }
                _ => unreachable!("initial write produced a later phase"),
            }
        }
    }
    assert!(
        states.contains(&(DurableStatus::Executing as u8))
            && states.contains(&(DurableStatus::Prepared as u8))
            && states.contains(&(DurableStatus::AwaitingReply as u8))
    );
    eprintln!("initiator initial faults: cases=12 recovered={states:?}");
}

#[test]
fn each_reply_sync_failure_recovers_the_exact_reply_final_and_session() {
    let f = fixture(PrekeyQuality::ReusableBoth);
    let (pq, classic) = f.sources();
    let mut states = BTreeSet::new();
    for after_sync in [false, true] {
        for cut in 1..=6 {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            let mut journal = new_store(&path, f.initiator_device());
            let request = InitiationId::generate().expect("request");
            let initial = journal
                .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
                .expect("initial");
            let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
            let reply = responder
                .respond(&initial, &f.signer_r, pq, classic, 150)
                .expect("reply")
                .to_vec();
            drop(journal);
            let (mut journal, fault, _, _) = fault_store(&path, f.initiator_device(), after_sync);
            fault.store(cut, Ordering::SeqCst);
            assert!(
                matches!(
                    journal.accept_reply(Arc::clone(&f.initiator), request, &reply, 150),
                    Err(DurableError::CommitUncertain(_))
                ),
                "cut={cut} after={after_sync}"
            );
            let mut recovered = reopen(&path, f.initiator_device());
            let phase = recovered
                .initiation_status(&f.initiator, request)
                .expect("query");
            states.insert(phase as u8);
            let result = if phase == DurableStatus::AwaitingReply {
                // No reply-selection commit survived; no confirmation result escaped.
                recovered
                    .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
                    .expect("retry original input")
            } else {
                let mut another = ResponderOperation::new(Arc::clone(&f.responder));
                let other = another
                    .respond(&initial, &f.signer_r, pq, classic, 150)
                    .expect("other valid reply");
                assert!(matches!(
                    recovered.accept_reply(Arc::clone(&f.initiator), request, other, 150),
                    Err(DurableError::Conflict)
                ));
                recovered
                    .resume_reply(Arc::clone(&f.initiator), request, 150)
                    .expect("pinned reply/result")
            };
            assert_eq!(
                responder
                    .finish(result.final_message(), 150)
                    .expect("real final MAC")
                    .id(),
                result.session_id()
            );
            assert_eq!(
                recovered
                    .resume_reply(Arc::clone(&f.initiator), request, 150)
                    .expect("exact replay")
                    .final_message(),
                result.final_message()
            );
        }
    }
    assert!(
        states.contains(&(DurableStatus::ProcessingReply as u8))
            && states.contains(&(DurableStatus::FinalPrepared as u8))
            && states.contains(&(DurableStatus::FinalCommitted as u8))
    );
    eprintln!("initiator reply faults: cases=12 recovered={states:?}");
}

#[test]
fn initiator_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_INITIATOR_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let public = fs::read(path.join("public-keys")).expect("peer public fixture");
    let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
    let f = fixture_from_public(
        PrekeyQuality::OneTimeBoth,
        Some((
            a.try_into().expect("public width"),
            b.try_into().expect("public width"),
        )),
    );
    let request = InitiationId::generate().expect("request");
    fs::write(path.join("request-id"), request.as_bytes()).expect("request queue");
    let mut journal = new_store(path, f.initiator_device());
    let initial = journal
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("initial");
    fs::write(path.join("initial-ready"), &initial).expect("initial after commit");
    fs::rename(path.join("initial-ready"), path.join("returned-initial"))
        .expect("publish complete initial");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("reply").exists() {
        assert!(Instant::now() < deadline, "peer response deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    let reply = fs::read(path.join("reply")).expect("peer reply");
    let outcome = journal
        .accept_reply(Arc::clone(&f.initiator), request, &reply, 150)
        .expect("final");
    fs::write(path.join("returned-final"), outcome.final_message()).expect("final after commit");
}

#[test]
fn process_kill_at_six_initiator_boundaries_recovers_pinned_work_only() {
    for phase in [
        DurableStatus::Executing,
        DurableStatus::Prepared,
        DurableStatus::AwaitingReply,
        DurableStatus::ProcessingReply,
        DurableStatus::FinalPrepared,
        DurableStatus::FinalCommitted,
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut f = fixture(PrekeyQuality::OneTimeBoth);
        f.signer_i.close(); // The surviving peer cannot recreate the initiator proof.
        fs::write(
            path.join("public-keys"),
            [
                f.reusable.public_key().expect("public").to_bytes(),
                f.once.public_key().expect("public").to_bytes(),
            ]
            .concat(),
        )
        .expect("public-only enrollment");
        let (pq, classic) = f.sources();
        let mut peer = ResponderOperation::new(Arc::clone(&f.responder));
        let log = fs::File::create(path.join("child.log")).expect("log");
        let child = Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::initiator::tests::initiator_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_INITIATOR_CRASH_DIR", &path)
            .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
            .env("QPERIAPT_JOURNAL_CRASH_PHASE", (phase as u8).to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child");
        let mut child = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            let status = child.0.try_wait().expect("child status");
            if status.is_some() {
                eprintln!(
                    "child log: {}",
                    fs::read_to_string(path.join("child.log")).expect("child log")
                );
            }
            assert!(
                status.is_none() && Instant::now() < deadline,
                "child failed to reach phase {phase:?}"
            );
            if path.join("returned-initial").exists() && !path.join("reply").exists() {
                let initial = fs::read(path.join("returned-initial")).expect("committed initial");
                assert_eq!(initial.len(), 5817);
                let reply = peer
                    .respond(&initial, &f.signer_r, pq, classic, 150)
                    .expect("live independent peer");
                fs::write(path.join("reply-ready"), reply).expect("public reply");
                fs::rename(path.join("reply-ready"), path.join("reply"))
                    .expect("publish complete reply");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !path.join("returned-final").exists(),
            "final escaped before commit return"
        );
        if matches!(
            phase,
            DurableStatus::Executing | DurableStatus::Prepared | DurableStatus::AwaitingReply
        ) {
            assert!(
                !path.join("returned-initial").exists(),
                "initial escaped before commit return"
            );
        }
        child.0.kill().expect("kill exact process");
        assert!(!child.0.wait().expect("reap").success());
        let request = InitiationId::from_trusted_state(
            fs::read(path.join("request-id"))
                .expect("request queue")
                .try_into()
                .expect("ID width"),
        )
        .expect("request");
        let mut journal = reopen(&path, f.initiator_device());
        assert_eq!(
            journal
                .initiation_status(&f.initiator, request)
                .expect("recovered phase"),
            phase
        );
        if phase == DurableStatus::Executing {
            assert!(matches!(
                journal.resume_initial(Arc::clone(&f.initiator), request, 150),
                Err(DurableError::Suspended)
            ));
        } else {
            let image = journal.image().expect("image");
            let record = image.records.values().next().expect("record");
            let recovered_initial = journal
                .resume_initial(Arc::clone(&f.initiator), request, 150)
                .expect("same initial");
            assert_eq!(recovered_initial, initial(record).expect("pinned initial"));
            let outcome = if matches!(
                phase,
                DurableStatus::Prepared | DurableStatus::AwaitingReply
            ) {
                let reply = peer
                    .respond(&recovered_initial, &f.signer_r, pq, classic, 150)
                    .expect("peer survived the initiator crash");
                journal
                    .accept_reply(Arc::clone(&f.initiator), request, reply, 150)
                    .expect("restored private reply key")
            } else {
                journal
                    .resume_reply(Arc::clone(&f.initiator), request, 150)
                    .expect("same persisted reply")
            };
            assert_eq!(
                peer.finish(outcome.final_message(), 150)
                    .expect("real final MAC at surviving peer")
                    .id(),
                outcome.session_id()
            );
            assert_eq!(
                journal
                    .resume_reply(Arc::clone(&f.initiator), request, 150)
                    .expect("final replay")
                    .final_message(),
                outcome.final_message()
            );
        }
    }
}

#[test]
fn v1_header_and_role_substitution_are_refused() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    let request = InitiationId::generate().expect("request");
    journal
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("initial");
    let mut image = journal.image().expect("image");
    let active = journal.active.as_ref().expect("active");
    let mut old = seal(&active.key, &image).expect("sealed");
    old.get_mut(..8)
        .expect("header")
        .copy_from_slice(b"QPVLT001");
    assert!(matches!(
        unseal(&active.key, active.owner, &old),
        Err(DurableError::Corrupt)
    ));
    image.records.values_mut().next().expect("record").kind = RecordKind::Responder;
    let sealed = seal(&active.key, &image).expect("authenticated wrong role");
    assert!(matches!(
        unseal(&active.key, active.owner, &sealed),
        Err(DurableError::Corrupt)
    ));
}

#[test]
fn restored_private_key_must_be_valid_and_match_the_signed_reply_public_key() {
    for wrong_pair in [false, true] {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut journal = new_store(&path, f.initiator_device());
        let request = InitiationId::generate().expect("request");
        let initial = journal
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("initial");
        let (pq, classic) = f.sources();
        let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
        let reply = responder
            .respond(&initial, &f.signer_r, pq, classic, 150)
            .expect("reply")
            .to_vec();
        let mut image = journal.image().expect("image");
        let record = image.records.values_mut().next().expect("record");
        let key_start = 32 + PREFIX + 1 + 32;
        let expected = if wrong_pair {
            let other = f.occupy_initiator_slot();
            let exported =
                q_periapt_sdk::expert::export_expanded(&other).expect("other private owner");
            record
                .payload
                .get_mut(key_start..)
                .expect("private key")
                .copy_from_slice(exported.as_bytes());
            Error::Scope
        } else {
            *record.payload.get_mut(key_start).expect("private format") ^= 1;
            Error::Runtime(q_periapt_sdk::Error::InvalidPrivateKey)
        };
        journal
            .persist(&mut image)
            .expect("authenticated writer defect");
        assert!(
            matches!(journal.accept_reply(Arc::clone(&f.initiator), request, &reply, 150), Err(DurableError::InvalidCheckpoint(error)) if error == expected)
        );
        assert!(journal.active.is_none());
    }
}
