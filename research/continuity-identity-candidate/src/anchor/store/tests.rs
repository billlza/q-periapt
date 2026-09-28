// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, Fixture},
    durable::tests::{directory, fault_database_path, new_store, ChildGuard},
    DeviceJournal, SigningKeyId,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command as Process, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

struct Case {
    store: AnchorStore,
    pin: AnchorPin,
    genesis: AnchorGenesis,
    peer: Fixture,
    _journal: DeviceJournal,
    server: PathBuf,
    _directory: tempfile::TempDir,
}
fn case() -> Case {
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let client = path.join("client");
    let server = path.join("witness");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&client)
        .expect("client directory");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&server)
        .expect("server directory");
    let peer = fixture(PrekeyQuality::OneTimeBoth);
    let (policy, device, _) = peer.responder.inventory_inputs();
    let mut journal = new_store(&client, device);
    let genesis = journal
        .anchor_genesis(device, policy)
        .expect("actual authenticated genesis");
    let wrapping = JournalKey::provision(&server.join("wrapping")).expect("witness wrapping");
    let signer = AnchorSigningKey::provision(
        &server.join("signer"),
        &wrapping,
        SigningKeyId::from_trusted_state([63; 32]).expect("signer identity"),
    )
    .expect("witness signer");
    let id = AnchorIdentity::generate().expect("instance ID");
    fs::write(server.join("instance"), id.as_bytes()).expect("independent configuration");
    let mut store =
        AnchorStore::provision(&server.join("anchor.redb"), wrapping, signer, id).expect("witness");
    store
        .enroll(&genesis, device, policy, 150)
        .expect("trusted enrollment");
    let pin = store.pin().expect("pin");
    Case {
        store,
        pin,
        genesis,
        peer,
        _journal: journal,
        server,
        _directory: directory,
    }
}
fn owners(path: &Path) -> (JournalKey, AnchorSigningKey, AnchorIdentity) {
    let key = JournalKey::open(&path.join("wrapping")).expect("wrapping");
    let signer = AnchorSigningKey::open(
        &path.join("signer"),
        &key,
        SigningKeyId::from_trusted_state([63; 32]).expect("signer ID"),
    )
    .expect("restored signer");
    let id = AnchorIdentity::from_trusted_state(
        fs::read(path.join("instance"))
            .expect("independent ID")
            .try_into()
            .expect("ID width"),
    )
    .expect("ID");
    (key, signer, id)
}
fn reopen(path: &Path) -> AnchorStore {
    let (key, signer, id) = owners(path);
    AnchorStore::open(&path.join("anchor.redb"), key, signer, id).expect("same witness")
}
fn request(c: &Case, operation: AnchorOperation) -> AnchorRequest {
    AnchorRequest::new(&c.pin, c.genesis.subject(), operation, &c.peer.signer_r)
        .expect("signed attempt")
}
fn apply_request(c: &mut Case, request: &AnchorRequest) -> AnchorReply {
    let reply = c
        .store
        .handle(request.as_bytes(), 150)
        .expect("actual provider reply");
    c.pin
        .verify_reply(request, &reply)
        .expect("independent client verification")
}
fn initial(c: &Case) -> AnchorHead {
    AnchorHead::from_trusted_state(1, 1, c.genesis.image_digest()).expect("genesis expectation")
}

#[test]
fn restored_public_intents_preserve_command_identity_and_reject_noncanonical_bytes() {
    let c = case();
    let subject = AnchorSubject::from_trusted_state(&c.genesis.subject().to_bytes())
        .expect("retained subject");
    for operation in [
        AnchorOperation::query(),
        AnchorOperation::advance(initial(&c), [27; 32]).expect("advance"),
        AnchorOperation::fence_writer(initial(&c)).expect("fence"),
    ] {
        let bytes = operation.to_bytes();
        let restored = AnchorOperation::from_trusted_state(&bytes).expect("retained exact command");
        let first = request(&c, operation);
        let after =
            AnchorRequest::new(&c.pin, subject, restored, &c.peer.signer_r).expect("new attempt");
        assert_eq!(first.command_id(), after.command_id());
        assert_ne!(first.as_bytes(), after.as_bytes());
        for length in 0..bytes.len() {
            assert!(
                AnchorOperation::from_trusted_state(bytes.get(..length).expect("prefix")).is_err()
            );
        }
        let mut extended = bytes;
        extended.push(0);
        assert!(AnchorOperation::from_trusted_state(&extended).is_err());
    }
    let mut query = AnchorOperation::query().to_bytes();
    *query.last_mut().expect("query tail") = 1;
    assert!(AnchorOperation::from_trusted_state(&query).is_err());
    assert!(AnchorSubject::from_trusted_state(&[0; 96]).is_err());
}

#[test]
fn cancelled_attempts_reject_late_replies_but_reconcile_the_original_mutation() {
    let mut c = case();
    let operation = AnchorOperation::advance(initial(&c), [29; 32]).expect("advance");
    let attempt = request(&c, operation);
    let wire = c
        .store
        .handle(attempt.as_bytes(), 150)
        .expect("committed reply");
    attempt.close();
    assert!(matches!(
        c.pin.verify_reply(&attempt, &wire),
        Err(Error::Closed)
    ));
    let retry = request(&c, operation);
    assert_eq!(
        apply_request(&mut c, &retry).outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
}

#[test]
fn concurrent_receipt_verifiers_admit_exactly_one_result_per_attempt() {
    let mut c = case();
    let attempt = request(&c, AnchorOperation::query());
    let wire = c.store.handle(attempt.as_bytes(), 150).expect("reply");
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| c.pin.verify_reply(&attempt, &wire));
        let second = scope.spawn(|| c.pin.verify_reply(&attempt, &wire));
        [
            first.join().expect("first verifier"),
            second.join().expect("second verifier"),
        ]
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Closed)))
            .count(),
        1
    );
}

#[test]
fn fresh_attempts_exact_advances_and_writer_fences_preserve_full_binding() {
    let mut c = case();
    let first = request(&c, AnchorOperation::query());
    let old_reply = c.store.handle(first.as_bytes(), 150).expect("query");
    assert_eq!(
        c.pin
            .verify_reply(&first, &old_reply)
            .expect("verified")
            .observed_head(),
        initial(&c)
    );
    let fresh = request(&c, AnchorOperation::query());
    assert_ne!(first.as_bytes(), fresh.as_bytes());
    assert!(matches!(
        c.pin.verify_reply(&fresh, &old_reply),
        Err(Error::Scope)
    ));
    let advance = AnchorOperation::advance(initial(&c), [31; 32]).expect("immutable command");
    let req = request(&c, advance);
    let reply = apply_request(&mut c, &req);
    assert_eq!(reply.outcome(), AnchorOutcome::Advanced);
    let head = reply.applied_head().expect("exact receipt");
    let retry = request(&c, advance);
    assert_eq!(req.command_id(), retry.command_id());
    assert_ne!(req.as_bytes(), retry.as_bytes());
    assert_eq!(
        apply_request(&mut c, &retry).outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
    let fence = request(
        &c,
        AnchorOperation::fence_writer(head).expect("explicit fence"),
    );
    let fenced = apply_request(&mut c, &fence)
        .applied_head()
        .expect("fenced");
    assert_eq!(
        (fenced.fence(), fenced.revision(), fenced.digest()),
        (2, 2, [31; 32])
    );
    let stale = request(
        &c,
        AnchorOperation::advance(head, [32; 32]).expect("stale writer"),
    );
    let refusal = apply_request(&mut c, &stale);
    assert_eq!(refusal.outcome(), AnchorOutcome::Conflict);
    assert!(matches!(refusal.applied_head(), Err(Error::Conflict)));
    assert_eq!(refusal.observed_head(), fenced);
    // Same next tuple reached via another command is not an exact-applied receipt.
    let fork_before =
        AnchorHead::from_trusted_state(2, 1, c.genesis.image_digest()).expect("other prior");
    let fork = request(
        &c,
        AnchorOperation::advance(fork_before, [31; 32]).expect("other command"),
    );
    let refusal = apply_request(&mut c, &fork);
    assert_eq!(refusal.observed_head(), fenced);
    assert!(matches!(refusal.applied_head(), Err(Error::Conflict)));
    assert_eq!(
        c.store.image().expect("state").revision,
        4,
        "queries/conflicts/retries mutated state"
    );
}

#[test]
fn enrollment_is_explicit_idempotent_and_cannot_reset_a_device_lineage() {
    let mut c = case();
    let operation = request(
        &c,
        AnchorOperation::advance(initial(&c), [41; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &operation)
        .applied_head()
        .expect("head");
    let (policy, device, _) = c.peer.responder.inventory_inputs();
    c.store
        .enroll(&c.genesis, device, policy, 150)
        .expect("exact enrollment retry");
    let changed = AnchorGenesis {
        subject: c.genesis.subject,
        digest: [43; 32],
    };
    assert!(matches!(
        c.store.enroll(&changed, device, policy, 150),
        Err(DurableError::Conflict)
    ));
    let mut other = c.genesis.subject;
    other.journal = [44; 32];
    let query = AnchorRequest::new(&c.pin, other, AnchorOperation::query(), &c.peer.signer_r)
        .expect("unknown subject");
    assert!(matches!(
        c.store.handle(query.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
    assert!(matches!(
        c.store.enroll(
            &AnchorGenesis {
                subject: other,
                digest: [45; 32]
            },
            device,
            policy,
            150
        ),
        Err(DurableError::Conflict)
    ));
    let query = request(&c, AnchorOperation::query());
    let wire = c
        .store
        .handle(query.as_bytes(), 250)
        .expect("read-only reconciliation after expiry");
    assert_eq!(
        c.pin
            .verify_reply(&query, &wire)
            .expect("fresh receipt")
            .observed_head(),
        head
    );
    let mutation = request(
        &c,
        AnchorOperation::fence_writer(head).expect("mutating request"),
    );
    assert!(matches!(
        c.store.handle(mutation.as_bytes(), 250),
        Err(AnchorError::Rejected(Error::Validity))
    ));
    assert!(c.store.active.is_some());
}

#[test]
fn witness_signing_components_cannot_reuse_device_account_or_policy_authorities() {
    let c = case();
    let (policy, device, _) = c.peer.responder.inventory_inputs();
    for (pq, classic) in [(96, 97), (94, 95), (82, 83), (80, 113)] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let signer =
            AnchorSigningKey::deterministic([pq; 32], [classic; 32]).expect("misused test signer");
        let key = JournalKey::provision(&path.join("key")).expect("wrapping");
        let mut store = AnchorStore::provision(
            &path.join("state"),
            key,
            signer,
            AnchorIdentity::generate().expect("ID"),
        )
        .expect("empty witness");
        assert!(matches!(
            store.enroll(&c.genesis, device, policy, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
}

#[test]
fn forged_requests_and_authenticated_but_inconsistent_replies_never_authorize_an_advance() {
    let mut c = case();
    let operation = AnchorOperation::advance(initial(&c), [51; 32]).expect("command");
    let request = request(&c, operation);
    for index in [
        4,
        12,
        44,
        76,
        108,
        140,
        172,
        204,
        236,
        300,
        305,
        request.as_bytes().len() - 1,
    ] {
        let mut changed = request.as_bytes().to_vec();
        *changed.get_mut(index).expect("wire field") ^= 1;
        assert!(
            c.store.handle(&changed, 150).is_err(),
            "changed request field {index}"
        );
    }
    let wrong = AnchorRequest::new(&c.pin, c.genesis.subject(), operation, &c.peer.signer_i)
        .expect("wrong enrolled signer");
    assert!(matches!(
        c.store.handle(wrong.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Authentication))
    ));
    assert_eq!(c.store.image().expect("unchanged").revision, 2);
    let incoming = incoming(&c.pin, request.as_bytes()).expect("parsed");
    let signer = &c.store.active.as_ref().expect("active").signer;
    let malformed = reply(
        &c.pin,
        signer,
        &incoming,
        AnchorOutcome::Advanced,
        initial(&c),
        Some(request.command_id()),
    )
    .expect("signed contradiction");
    assert!(matches!(
        c.pin.verify_reply(&request, &malformed),
        Err(Error::Encoding)
    ));
    let inconsistent = reply(
        &c.pin,
        signer,
        &incoming,
        AnchorOutcome::Advanced,
        AnchorHead::from_trusted_state(1, 2, [252; 32]).expect("different next state"),
        Some(request.command_id()),
    )
    .expect("well-formed signed contradiction");
    assert!(matches!(
        c.pin.verify_reply(&request, &inconsistent),
        Err(Error::State)
    ));
    let legitimate = c
        .store
        .handle(request.as_bytes(), 150)
        .expect("real receipt");
    for index in [
        4,
        12,
        44,
        76,
        108,
        140,
        172,
        204,
        236,
        280,
        290,
        legitimate.len() - 1,
    ] {
        let mut changed = legitimate.clone();
        *changed.get_mut(index).expect("reply field") ^= 1;
        assert!(
            c.pin.verify_reply(&request, &changed).is_err(),
            "changed reply field {index}"
        );
    }
    assert!(AnchorOperation::advance(initial(&c), c.genesis.image_digest()).is_err());
    let exhausted = AnchorHead::from_trusted_state(u64::MAX - 1, u64::MAX - 1, [59; 32])
        .expect("last usable head");
    assert!(matches!(
        AnchorOperation::advance(exhausted, [60; 32]),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        AnchorOperation::fence_writer(exhausted),
        Err(Error::Capacity)
    ));
}

#[test]
fn unknown_commit_outcomes_reconcile_the_same_command_without_a_second_advance() {
    for after_sync in [false, true] {
        for cut in 1..=2 {
            let mut c = case();
            let operation = AnchorOperation::advance(initial(&c), [71; 32]).expect("advance");
            let first = request(&c, operation);
            c.store.close();
            let (db, remaining, _, _) =
                fault_database_path(&c.server.join("anchor.redb"), after_sync);
            let (wrapping, signer, id) = owners(&c.server);
            let pin = AnchorPin::new(id, signer.public_key().expect("public"));
            c.store = AnchorStore {
                active: Some(Active {
                    db,
                    wrapping,
                    signer,
                    pin,
                }),
            };
            remaining.store(cut, Ordering::SeqCst);
            assert!(matches!(
                c.store.handle(first.as_bytes(), 150),
                Err(AnchorError::Storage(DurableError::CommitUncertain(_)))
            ));
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            let retry = request(&c, operation);
            let reply = apply_request(&mut c, &retry);
            assert!(matches!(
                reply.outcome(),
                AnchorOutcome::Advanced | AnchorOutcome::AlreadyAppliedExact
            ));
            assert_eq!(reply.applied_head().expect("applied").revision(), 2);
            assert_eq!(c.store.image().expect("exact mutation").revision, 3);
        }
    }
}

#[test]
fn unavailable_reply_signature_does_not_reclassify_committed_state_as_rejected() {
    let mut c = case();
    let operation = AnchorOperation::advance(initial(&c), [81; 32]).expect("advance");
    let request = request(&c, operation);
    c.store.active.as_mut().expect("active").signer.close();
    assert!(matches!(
        c.store.handle(request.as_bytes(), 150),
        Err(AnchorError::ReplyUnavailable(Error::Closed))
    ));
    assert!(c.store.active.is_none());
    c.store = reopen(&c.server);
    let retry = AnchorRequest::new(&c.pin, c.genesis.subject(), operation, &c.peer.signer_r)
        .expect("new challenge");
    assert_eq!(
        apply_request(&mut c, &retry).outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
}

#[test]
fn witness_image_integrity_bounds_and_independent_identity_are_enforced() {
    let mut c = case();
    let image = c.store.image().expect("image");
    let active = c.store.active.as_ref().expect("active");
    let wire = encode(&active.wrapping, &active.pin, &image).expect("image");
    for index in 0..wire.len() {
        let mut changed = wire.clone();
        *changed.get_mut(index).expect("byte") ^= 1;
        assert!(
            decode(&active.wrapping, &active.pin, &changed).is_err(),
            "image byte {index}"
        );
    }
    let wrong = AnchorPin::new(
        AnchorIdentity::generate().expect("other ID"),
        active.pin.key.clone(),
    );
    assert!(matches!(
        decode(&active.wrapping, &wrong, &wire),
        Err(DurableError::Conflict)
    ));
    let mut excessive = wire.get(..wire.len() - 32).expect("body").to_vec();
    excessive
        .get_mut(48..50)
        .expect("count")
        .copy_from_slice(&257u16.to_be_bytes());
    let mut auth = authenticator(&active.wrapping).expect("key");
    auth.update(&excessive);
    excessive.extend_from_slice(&auth.finalize().into_bytes());
    assert!(matches!(
        decode(&active.wrapping, &active.pin, &excessive),
        Err(DurableError::Capacity)
    ));
    assert!(decode(&active.wrapping, &active.pin, &vec![0; MAX_IMAGE + 1]).is_err());
    let (key, signer, id) = owners(&c.server);
    assert!(AnchorStore::open(&c.server.join("missing"), key, signer, id).is_err());
    assert!(!c.server.join("missing").exists());
}

pub(super) fn after_commit(image: &Image) {
    let Ok(revision) = std::env::var("QPERIAPT_ANCHOR_CRASH_REVISION") else {
        return;
    };
    if revision != image.revision.to_string() {
        return;
    }
    let path = std::env::var_os("QPERIAPT_ANCHOR_SERVER_DIR").expect("owned server directory");
    let path = Path::new(&path);
    fs::write(path.join("ready.tmp"), b"committed").expect("marker");
    fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish marker");
    loop {
        std::thread::park();
    }
}
#[test]
fn witness_request_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ANCHOR_SERVER_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let mut witness = reopen(path);
    let request = fs::read(path.join("request.bin")).expect("public signed request");
    let reply = witness.handle(&request, 150).expect("reply after commit");
    fs::write(path.join("returned-reply"), reply).expect("released reply");
}
#[test]
fn witness_process_loss_after_commit_recovers_before_any_acknowledgement_escaped() {
    let mut c = case();
    let operation = AnchorOperation::advance(initial(&c), [91; 32]).expect("advance");
    let first = request(&c, operation);
    fs::write(c.server.join("request.bin"), first.as_bytes()).expect("request");
    c.store.close();
    let log = fs::File::create(c.server.join("child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::witness_request_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", "3")
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned witness process"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "witness deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !c.server.join("returned-reply").exists(),
        "reply escaped before commit return"
    );
    child.0.kill().expect("kill owned witness");
    assert!(!child.0.wait().expect("reap").success());
    c.store = reopen(&c.server);
    let retry = request(&c, operation);
    let reply = apply_request(&mut c, &retry);
    assert_eq!(reply.outcome(), AnchorOutcome::AlreadyAppliedExact);
    assert_eq!(reply.applied_head().expect("exact head").revision(), 2);
    assert_eq!(c.store.image().expect("one transition").revision, 3);
}

#[test]
fn restoring_the_witness_itself_exposes_its_independent_storage_trust_requirement() {
    let mut c = case();
    c.store.close();
    let snapshot = fs::read(c.server.join("anchor.redb")).expect("closed witness snapshot");
    c.store = reopen(&c.server);
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [101; 32]).expect("advance"),
    );
    assert_eq!(
        apply_request(&mut c, &advance)
            .applied_head()
            .expect("new head")
            .revision(),
        2
    );
    c.store.close();
    fs::write(c.server.join("anchor.redb"), snapshot).expect("owned rollback counterexample");
    c.store = reopen(&c.server);
    let query = request(&c, AnchorOperation::query());
    assert_eq!(
        apply_request(&mut c, &query).observed_head(),
        initial(&c),
        "this software provider does not protect its own authority from whole-store rollback"
    );
}
