// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture,
    durable::tests::{directory, fault_store, identity, new_store, reopen, ChildGuard},
    InitiatorOperation, PrekeyQuality,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn request() -> InitiationId {
    InitiationId::from_trusted_state([71; 32]).expect("request")
}
fn cleanup(path: &Path) -> BootstrapCancellationJournal {
    BootstrapCancellationJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        identity(path),
    )
    .expect("cleanup-only open")
}
fn retain(path: &Path, name: &str, bytes: &[u8]) {
    let mut file = fs::File::create_new(path.join(name)).expect("unique metadata");
    file.write_all(bytes).expect("metadata");
    file.sync_all().expect("metadata sync");
}
fn quality() -> PrekeyQuality {
    match std::env::var("QPERIAPT_CANCEL_QUALITY")
        .expect("quality")
        .as_str()
    {
        "0" => PrekeyQuality::OneTimeBoth,
        "1" => PrekeyQuality::ReusableBoth,
        "2" => PrekeyQuality::SignedClassicalOneTimePq,
        "3" => PrekeyQuality::OneTimeClassicalLastResortPq,
        _ => unreachable!("test quality"),
    }
}

#[test]
fn bootstrap_stage_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_CANCEL_STAGE_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    if std::env::var("QPERIAPT_CANCEL_ROLE").expect("role") == "initiator" {
        let f = fixture(quality());
        let mut journal = new_store(path, f.initiator_device());
        retain(path, "context", &f.initiator.digest());
        let initial = journal
            .initiate(Arc::clone(&f.initiator), request(), &f.signer_i, 150)
            .expect("initial");
        let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
        let (pq, classic) = f.sources();
        let reply = responder
            .respond(&initial, &f.signer_r, pq, classic, 150)
            .expect("reply")
            .to_vec();
        journal
            .accept_reply(Arc::clone(&f.initiator), request(), &reply, 150)
            .expect("final");
    } else {
        let mut f = prekeys::tests::inventory_at(quality(), path.to_path_buf(), None);
        retain(path, "context", &f.peer.responder.digest());
        retain(
            path,
            "public-keys",
            &[f.public.0.as_slice(), f.public.1.as_slice()].concat(),
        );
        let mut initiator =
            InitiatorOperation::start(Arc::clone(&f.peer.initiator), &f.peer.signer_i, 150)
                .expect("initial owner");
        let initial = initiator.initial_message(150).expect("initial").to_vec();
        let reply = f
            .store
            .respond_from_inventory(
                Arc::clone(&f.peer.responder),
                &initial,
                &f.peer.signer_r,
                150,
            )
            .expect("reply");
        let final_result = initiator.finish(&reply, 150).expect("confirmation");
        f.store
            .finish(
                Arc::clone(&f.peer.responder),
                &initial,
                final_result.final_message(),
                150,
            )
            .expect("complete");
    }
    Err("expected observed process cut".into())
}

// This child never creates a VerifiedDevice, BootstrapContext or signing key.
#[test]
fn bootstrap_cancel_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_CANCEL_ONLY_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let result = BootstrapCancellationJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        identity(path),
    );
    if std::env::var_os("QPERIAPT_CANCEL_CONTENDER").is_some() {
        assert!(matches!(
            result,
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        return Ok(());
    }
    let mut journal = result.expect("authenticated owner");
    let entries = journal.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    let entry = entries.first().expect("entry");
    journal
        .cancel(entry.context, entry.operation)
        .expect("cancel");
    Err("expected observed cancellation commit cut".into())
}

fn spawn(path: &Path, test: &str, name: &str, environment: &[(&str, String)]) -> ChildGuard {
    let file = fs::File::create_new(path.join(format!("{name}.log"))).expect("child log");
    let mut cmd = Command::new(std::env::current_exe().expect("exe"));
    cmd.args([
        "--exact",
        &format!("durable::cancellation::tests::{test}"),
        "--nocapture",
    ])
    .envs(environment.iter().map(|(k, v)| (k, v)))
    .env("QPERIAPT_JOURNAL_CRASH_DIR", path)
    .stdout(Stdio::from(file.try_clone().expect("log")))
    .stderr(Stdio::from(file));
    ChildGuard(cmd.spawn().expect("spawn"))
}
fn await_cut(path: &Path, child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "missed committed cut at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn kill(path: &Path, child: &mut ChildGuard) {
    child.0.kill().expect("kill at observed boundary");
    assert!(!child.0.wait().expect("reap").success());
    fs::remove_file(path.join("ready")).expect("remove owned marker");
}

#[test]
fn real_bootstrap_stages_cancel_after_process_loss_and_reopen_without_policy_objects() {
    use DurableStatus::*;
    for (role, phases) in [
        (
            "initiator",
            vec![
                InitialKeyReserved,
                InitialKemReserved,
                InitialSignatureReserved,
                Prepared,
                AwaitingReply,
                ProcessingReply,
                FinalPrepared,
                FinalCommitted,
            ],
        ),
        (
            "responder",
            vec![
                Executing,
                ResponseKemReserved,
                ResponseSignatureReserved,
                Prepared,
                AwaitingFinal,
                Complete,
            ],
        ),
    ] {
        for phase in phases {
            // Every responder quality has a pre-response and post-consumption cut.
            let qualities = if role == "responder" && matches!(phase, Prepared | AwaitingFinal) {
                4
            } else {
                1
            };
            for q in 0..qualities {
                let folder = directory();
                let path = folder.path().canonicalize().expect("path");
                let mut child = spawn(
                    &path,
                    "bootstrap_stage_process_child",
                    "stage",
                    &[
                        (
                            "QPERIAPT_CANCEL_STAGE_DIR",
                            path.to_string_lossy().into_owned(),
                        ),
                        ("QPERIAPT_CANCEL_ROLE", role.into()),
                        ("QPERIAPT_CANCEL_QUALITY", q.to_string()),
                        ("QPERIAPT_JOURNAL_CRASH_PHASE", (phase as u8).to_string()),
                    ],
                );
                await_cut(&path, &mut child);
                kill(&path, &mut child);
                let mut owner = cleanup(&path);
                let entries = owner.entries().expect("entries");
                assert_eq!(entries.len(), 1);
                let e = entries.first().expect("one record");
                assert_eq!(e.status, phase);
                let image = owner.journal.image().expect("image");
                let projected = historical_metadata(&image, e.operation.0)
                    .expect("historical projection of every actual bootstrap cut");
                assert!(
                    matches!(projected,crate::retired_device::RecordMetadata::Bootstrap {entry,cancellation:None,..} if entry==*e)
                );
                let expected = metadata(
                    &owner.journal.active.as_ref().expect("active").key,
                    &image,
                    e.operation.0,
                )
                .expect("original receipt");
                let original_size =
                    seal(&owner.journal.active.as_ref().expect("active").key, &image)
                        .expect("original image")
                        .len();
                assert!(matches!(
                    owner.cancel([88; 32], e.operation),
                    Err(DurableError::Conflict)
                ));
                owner.close();
                let mut child = spawn(
                    &path,
                    "bootstrap_cancel_process_child",
                    "cancel",
                    &[
                        (
                            "QPERIAPT_CANCEL_ONLY_DIR",
                            path.to_string_lossy().into_owned(),
                        ),
                        (
                            "QPERIAPT_JOURNAL_CRASH_PHASE",
                            (BootstrapCancelled as u8).to_string(),
                        ),
                    ],
                );
                await_cut(&path, &mut child);
                let mut contender = spawn(
                    &path,
                    "bootstrap_cancel_process_child",
                    "contender",
                    &[
                        (
                            "QPERIAPT_CANCEL_ONLY_DIR",
                            path.to_string_lossy().into_owned(),
                        ),
                        ("QPERIAPT_CANCEL_CONTENDER", "1".into()),
                    ],
                );
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if let Some(status) = contender.0.try_wait().expect("contender") {
                        assert!(status.success());
                        break;
                    }
                    assert!(Instant::now() < deadline, "contender blocked");
                    std::thread::sleep(Duration::from_millis(10));
                }
                kill(&path, &mut child);
                let mut owner = cleanup(&path);
                let receipt = owner
                    .cancel(e.context, e.operation)
                    .expect("exact committed receipt");
                assert_eq!(receipt.previous, phase);
                assert_eq!(receipt.report, expected.report);
                assert_eq!(
                    [
                        receipt.initial_hash,
                        receipt.reply_hash,
                        receipt.final_hash,
                        receipt.session
                    ],
                    expected.values
                );
                let image = owner.journal.image().expect("terminal image");
                let record = image.records.get(&e.operation.0).expect("terminal record");
                assert_eq!(
                    record.payload.len(),
                    if role == "initiator" { 32 } else { 5817 }
                );
                assert_eq!(record.phase, BootstrapCancelled);
                let projected = historical_metadata(&image, e.operation.0)
                    .expect("historical cancellation metadata");
                assert!(
                    matches!(projected,crate::retired_device::RecordMetadata::Bootstrap {cancellation:Some(saved),..} if *saved==receipt)
                );
                assert!(
                    seal(&owner.journal.active.as_ref().expect("active").key, &image)
                        .expect("image")
                        .len()
                        <= original_size
                );
                for used in &receipt.inventory {
                    let one_time =
                        matches!(used.kind, LeafKind::OneTimeClassical | LeafKind::OneTimePq);
                    let expected = if !one_time {
                        BootstrapPrekeyDisposition::ReusableUnchanged
                    } else if matches!(phase, AwaitingFinal | Complete) {
                        BootstrapPrekeyDisposition::AlreadyConsumed
                    } else {
                        BootstrapPrekeyDisposition::AbandonedByCancellation
                    };
                    assert_eq!(used.disposition, expected);
                }
                let revision = image.revision;
                assert_eq!(
                    owner.cancel(e.context, e.operation).expect("duplicate"),
                    receipt
                );
                assert_eq!(owner.journal.image().expect("image").revision, revision);
                owner.close();
                assert!(matches!(owner.entries(), Err(DurableError::Closed)));
                if role == "responder" {
                    let public = fs::read(path.join("public-keys")).expect("public fixture");
                    let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
                    let selected = match q {
                        0 => PrekeyQuality::OneTimeBoth,
                        1 => PrekeyQuality::ReusableBoth,
                        2 => PrekeyQuality::SignedClassicalOneTimePq,
                        3 => PrekeyQuality::OneTimeClassicalLastResortPq,
                        _ => unreachable!(),
                    };
                    let f = crate::bootstrap::tests::fixture_from_public(
                        selected,
                        Some((a.try_into().expect("public"), b.try_into().expect("public"))),
                    );
                    let mut journal = reopen(&path, f.local_device());
                    let (policy, device, _) = f
                        .responder
                        .inventory_inputs()
                        .expect("fixture inventory owner");
                    for used in &receipt.inventory {
                        if used.disposition != BootstrapPrekeyDisposition::ReusableUnchanged {
                            assert_eq!(
                                journal
                                    .prekey_status(policy, device, used.request)
                                    .expect("terminal key"),
                                if used.disposition == BootstrapPrekeyDisposition::AlreadyConsumed {
                                    PrekeyStatus::Consumed
                                } else {
                                    PrekeyStatus::Abandoned
                                }
                            );
                            assert!(matches!(
                                journal.prekey_leaf(policy, device, used.request, 150),
                                Err(DurableError::PrekeyClaimed)
                            ));
                            assert!(matches!(
                                journal.generate_prekey(
                                    policy,
                                    device,
                                    used.request,
                                    used.kind,
                                    crate::tests::interval(),
                                    150
                                ),
                                Err(DurableError::PrekeyClaimed)
                            ));
                        }
                    }
                    let new_i =
                        InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
                            .expect("different initial");
                    let result = journal.respond_from_inventory(
                        Arc::clone(&f.responder),
                        new_i.initial_message(150).expect("new flight"),
                        &f.signer_r,
                        150,
                    );
                    if q == 1 {
                        result.expect("reusable inventory remains live");
                    } else {
                        assert!(matches!(result, Err(DurableError::PrekeyClaimed)));
                    }
                    assert_eq!(
                        report(&journal.image().expect("image"), e.operation.0)
                            .expect("unchanged receipt"),
                        receipt
                    );
                }
            }
        }
    }
}

#[test]
fn cancellation_fences_live_entry_points_and_leaves_reusable_inventory_retirable() {
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let mut f = prekeys::tests::inventory(quality);
        let folder = directory();
        let path = folder.path().canonicalize().expect("path");
        let mut i = new_store(&path, f.peer.initiator_device());
        let initial = i
            .initiate(
                Arc::clone(&f.peer.initiator),
                request(),
                &f.peer.signer_i,
                150,
            )
            .expect("initial");
        let reply = f
            .store
            .respond_from_inventory(
                Arc::clone(&f.peer.responder),
                &initial,
                &f.peer.signer_r,
                150,
            )
            .expect("reply");
        let final_result = i
            .accept_reply(Arc::clone(&f.peer.initiator), request(), &reply, 150)
            .expect("final");
        f.store
            .finish(
                Arc::clone(&f.peer.responder),
                &initial,
                final_result.final_message(),
                150,
            )
            .expect("confirmation");
        let ci = i
            .cancel_initiation(&f.peer.initiator, request())
            .expect("cancel initial");
        let cr = f
            .store
            .cancel_response(&f.peer.responder, &initial)
            .expect("cancel response");
        assert_eq!(ci.session, Some(final_result.session_id()));
        assert_eq!(cr.session, ci.session);
        assert_eq!(ci.final_hash, cr.final_hash);
        assert!(matches!(
            i.initiate(
                Arc::clone(&f.peer.initiator),
                request(),
                &f.peer.signer_i,
                150
            ),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            i.accept_reply(Arc::clone(&f.peer.initiator), request(), &reply, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            i.activate_initiator_messages(Arc::clone(&f.peer.initiator), request(), 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            f.store.resume(Arc::clone(&f.peer.responder), &initial, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            f.store.respond_from_inventory(
                Arc::clone(&f.peer.responder),
                &initial,
                &f.peer.signer_r,
                150
            ),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            f.store.finish(
                Arc::clone(&f.peer.responder),
                &initial,
                final_result.final_message(),
                150
            ),
            Err(DurableError::Protocol(Error::Retired))
        ));
        assert!(matches!(
            f.store
                .activate_responder_messages(Arc::clone(&f.peer.responder), &initial, 150),
            Err(DurableError::Protocol(Error::Retired))
        ));
        let (policy, device, _) = f
            .peer
            .responder
            .inventory_inputs()
            .expect("fixture inventory owner");
        for used in &cr.inventory {
            let status = f
                .store
                .retire_prekey(policy, device, used.request)
                .expect("terminal one-time or reusable retirement");
            assert_eq!(
                status,
                if used.disposition == BootstrapPrekeyDisposition::ReusableUnchanged {
                    PrekeyStatus::Retired
                } else {
                    PrekeyStatus::Consumed
                }
            );
            assert!(f
                .store
                .prekey_leaf(policy, device, used.request, 150)
                .is_err());
        }
        f.peer.close_responder_policy();
        f.peer.close_initiator_policy();
        assert_eq!(
            f.store
                .cancel_response(&f.peer.responder, &initial)
                .expect("after policy close"),
            cr
        );
        assert_eq!(
            i.cancel_initiation(&f.peer.initiator, request())
                .expect("after policy close"),
            ci
        );
    }
}

#[test]
fn cancellation_rejects_active_sessions_and_wrong_identity_or_key() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    let initial = journal
        .initiate(Arc::clone(&f.initiator), request(), &f.signer_i, 150)
        .expect("initial");
    let mut r = ResponderOperation::new(Arc::clone(&f.responder));
    let (pq, classic) = f.sources();
    let reply = r
        .respond(&initial, &f.signer_r, pq, classic, 150)
        .expect("reply")
        .to_vec();
    journal
        .accept_reply(Arc::clone(&f.initiator), request(), &reply, 150)
        .expect("final");
    journal
        .activate_initiator_messages(Arc::clone(&f.initiator), request(), 150)
        .expect("application state");
    let revision = journal.image().expect("image").revision;
    assert!(matches!(
        journal.cancel_initiation(&f.initiator, request()),
        Err(DurableError::Suspended)
    ));
    journal.close();
    assert!(matches!(
        BootstrapCancellationJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            JournalIdentity([89; 32])
        ),
        Err(DurableError::Conflict)
    ));
    let other = directory();
    let wrong = JournalKey::provision(
        &other
            .path()
            .canonicalize()
            .expect("canonical wrong key directory")
            .join("key"),
    )
    .expect("wrong key");
    assert!(matches!(
        BootstrapCancellationJournal::open(&path.join("state.redb"), wrong, identity(&path)),
        Err(DurableError::Authentication)
    ));
    let mut owner = cleanup(&path);
    assert!(matches!(
        owner.cancel(
            f.initiator.digest(),
            BootstrapOperationId::for_initiation(request())
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(owner.journal.image().expect("unchanged").revision, revision);
}

#[test]
fn cancellation_sync_faults_reconcile_exact_original_record_or_exact_terminal_receipt() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let setup = |path: &Path| {
        let mut journal = new_store(path, f.initiator_device());
        journal
            .initiate(Arc::clone(&f.initiator), request(), &f.signer_i, 150)
            .expect("initial");
        journal.close();
    };
    let base = directory();
    let path = base.path().canonicalize().expect("path");
    setup(&path);
    let (mut j, _, count, _) = fault_store(&path, f.initiator_device(), false);
    count.store(0, Ordering::SeqCst);
    j.cancel_initiation(&f.initiator, request())
        .expect("baseline cancellation");
    let barriers = count.load(Ordering::SeqCst);
    assert!(barriers > 0);
    j.close();
    eprintln!("bootstrap cancellation measured {barriers} sync barriers");
    for after in [false, true] {
        for at in 1..=barriers {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            setup(&path);
            let (mut j, remaining, _, _) = fault_store(&path, f.initiator_device(), after);
            let before = j.image().expect("image");
            let expected = metadata(
                &j.active.as_ref().expect("active").key,
                &before,
                initiator::operation_id(request()),
            )
            .expect("original exact report")
            .report;
            remaining.store(at, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                j.cancel_initiation(&f.initiator, request()),
                after,
            );
            assert!(matches!(j.identity(), Err(DurableError::Closed)));
            let mut owner = cleanup(&path);
            let report = owner
                .cancel(
                    f.initiator.digest(),
                    BootstrapOperationId::for_initiation(request()),
                )
                .expect("exact retry");
            assert_eq!(report.report, expected);
            owner.close();
            let mut j = reopen(&path, f.initiator_device());
            assert_eq!(
                j.cancel_initiation(&f.initiator, request())
                    .expect("retained receipt"),
                report
            );
        }
    }
}

#[test]
fn cancellation_codec_is_canonical_and_authenticates_relationships() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    journal
        .initiate(Arc::clone(&f.initiator), request(), &f.signer_i, 150)
        .expect("initial");
    let receipt = journal
        .cancel_initiation(&f.initiator, request())
        .expect("cancel");
    let mut image = journal.image().expect("image");
    let op = initiator::operation_id(request());
    let metadata = image.records.get(&op).expect("record").cancellation.clone();
    let mut bytes = Vec::new();
    encode(&metadata, &mut bytes);
    assert_eq!(bytes.len(), METADATA_BYTES);
    for length in 0..METADATA_BYTES {
        assert!(decode(&mut Decoder::new(bytes.get(..length).expect("prefix"))).is_err());
    }
    for index in [0, 7, 8, 41, 74] {
        let mut malformed = bytes.clone();
        *malformed.get_mut(index).expect("byte") = 255;
        assert!(
            decode(&mut Decoder::new(&malformed)).is_err(),
            "noncanonical byte {index}"
        );
    }
    let mut zeros = Vec::new();
    encode(&None, &mut zeros);
    assert!(decode(&mut Decoder::new(&zeros))
        .expect("reserved zero slot")
        .is_none());
    let key = &journal.active.as_ref().expect("active").key;
    let encoded = seal(key, &image).expect("sealed image");
    assert_eq!(
        report(&unseal(key, image.owner, &encoded).expect("round trip"), op).expect("report"),
        receipt
    );
    for variant in 0..4 {
        let record = image.records.get_mut(&op).expect("record");
        record.cancellation = metadata.clone();
        record.phase = DurableStatus::BootstrapCancelled;
        match variant {
            0 => record.cancellation = None,
            1 => record.phase = DurableStatus::Rejected,
            2 => record.cancellation.as_mut().expect("metadata").previous = DurableStatus::Complete,
            3 => record.cancellation.as_mut().expect("metadata").values[1] = Some([11; 32]),
            _ => unreachable!(),
        }
        assert!(validate_image(&image).is_err());
        let invalid = seal(key, &image).expect("authenticated inconsistent fixture");
        assert!(unseal(key, image.owner, &invalid).is_err());
    }
}
