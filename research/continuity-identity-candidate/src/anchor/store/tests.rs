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
    case_with_peer(fixture(PrekeyQuality::OneTimeBoth))
}
fn case_with_peer(peer: Fixture) -> Case {
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
    let (policy, device, _) = peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
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
    let remote_subject = AnchorSubject::from_trusted_state(&c.genesis.subject().to_bytes())
        .expect("independently approved subject");
    assert!(AnchorGenesis::from_trusted_state(remote_subject, [0; 32]).is_err());
    let restored = AnchorGenesis::from_trusted_state(remote_subject, c.genesis.image_digest())
        .expect("independently approved original remote image");
    let operation = request(
        &c,
        AnchorOperation::advance(initial(&c), [41; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &operation)
        .applied_head()
        .expect("head");
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    c.store
        .enroll(&restored, device, policy, 150)
        .expect("exact enrollment retry");
    for changed in [
        AnchorSubject {
            owner: [42; 32],
            ..remote_subject
        },
        AnchorSubject {
            policy: [42; 32],
            ..remote_subject
        },
    ] {
        let foreign = AnchorGenesis::from_trusted_state(changed, c.genesis.image_digest())
            .expect("shape is not authority");
        assert!(matches!(
            c.store.enroll(&foreign, device, policy, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
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
    let (policy, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
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

fn renewal_case() -> Case {
    case_with_peer(crate::bootstrap::tests::fixture_with_public_validity(
        PrekeyQuality::OneTimeBoth,
        Validity::new(100, 160).expect("short roster"),
        Validity::new(100, 160).expect("short advertisement"),
    ))
}
fn renewed_device(device: &VerifiedDevice, version: u64, validity: Validity) -> VerifiedDevice {
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("same account root");
    let certificate = root
        .issue_device(device.description.clone(), device.key.clone())
        .expect("same credential body");
    let roster = root
        .issue_roster(
            version,
            validity,
            &[root.roster_entry(&certificate).expect("entry")],
        )
        .expect("new signed roster");
    let pin = crate::AccountPin::new(
        device.account_id(),
        root.public_key().expect("root"),
        roster.checkpoint(),
        device.description.family,
    )
    .expect("independent new checkpoint");
    let verified = pin
        .verify_device(&certificate, roster.as_bytes(), validity.from().max(150))
        .expect("verified unchanged credential");
    assert_eq!(verified.credential_digest(), device.credential_digest());
    verified
}

#[test]
fn roster_authority_refresh_preserves_advanced_head_fence_and_exact_last_command() {
    let mut c = renewal_case();
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [141; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &advance)
        .applied_head()
        .expect("head");
    let fenced = request(&c, AnchorOperation::fence_writer(head).expect("fence"));
    let head = apply_request(&mut c, &fenced)
        .applied_head()
        .expect("fenced head");
    let (policy, previous, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let next = renewed_device(
        previous,
        2,
        Validity::new(100, 190).expect("renewed interval"),
    );
    assert!(matches!(
        c.store.enroll(&c.genesis, &next, policy, 160),
        Err(DurableError::Conflict)
    ));
    let pending = AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        AnchorOperation::advance(head, [142; 32]).expect("next command"),
        &c.peer.signer_r,
    )
    .expect("signed next command");
    assert!(matches!(
        c.store.handle(pending.as_bytes(), 160),
        Err(AnchorError::Rejected(Error::Validity))
    ));
    let before = c.store.image().expect("before").revision;
    assert_eq!(
        c.store
            .update_roster_authority(
                c.genesis.subject(),
                previous.roster().checkpoint(),
                &next,
                policy,
                160
            )
            .expect("explicit renewal"),
        next.roster().checkpoint()
    );
    let image = c.store.image().expect("after");
    assert_eq!(image.revision, before + 1);
    let alternative_previous = renewed_device(
        previous,
        1,
        Validity::new(100, 159).expect("different historical checkpoint"),
    );
    assert_eq!(
        c.store
            .update_roster_authority(
                c.genesis.subject(),
                alternative_previous.roster().checkpoint(),
                &next,
                policy,
                160
            )
            .expect("target readback, not a claim about its predecessor"),
        next.roster().checkpoint()
    );
    assert_eq!(
        c.store.image().expect("readback has no mutation").revision,
        before + 1
    );
    let entry = image
        .entries
        .get(&c.genesis.subject.id(&c.pin.binding))
        .expect("same subject");
    assert_eq!(entry.subject, c.genesis.subject);
    assert_eq!(entry.genesis, c.genesis.digest);
    assert_eq!(entry.head, head);
    assert_eq!(entry.last, Some(fenced.command_id()));
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .update_roster_authority(
                c.genesis.subject(),
                previous.roster().checkpoint(),
                &next,
                policy,
                160
            )
            .expect("exact target reconciliation"),
        next.roster().checkpoint()
    );
    assert_eq!(
        c.store.image().expect("no repeated write").revision,
        before + 1
    );
    let retry = request(&c, fenced.operation);
    assert_eq!(retry.command_id(), fenced.command_id());
    let replay = c
        .store
        .handle(retry.as_bytes(), 160)
        .expect("original data-plane last command");
    assert_eq!(
        c.pin
            .verify_reply(&retry, &replay)
            .expect("authenticated replay")
            .outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
    let wire = c
        .store
        .handle(pending.as_bytes(), 160)
        .expect("pending original command now authorized");
    let result = c
        .pin
        .verify_reply(&pending, &wire)
        .expect("verified real reply");
    assert_eq!(result.outcome(), AnchorOutcome::Advanced);
    assert_eq!(
        result.applied_head().expect("head").revision(),
        head.revision() + 1
    );
    let later = AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        AnchorOperation::fence_writer(result.applied_head().expect("head")).expect("later fence"),
        &c.peer.signer_r,
    )
    .expect("signed");
    assert!(matches!(
        c.store.handle(later.as_bytes(), 190),
        Err(AnchorError::Rejected(Error::Validity))
    ));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            190
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
}

#[test]
fn roster_authority_refresh_refuses_stale_forked_or_different_lineage_inputs() {
    let mut c = renewal_case();
    let (policy, previous, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let next = renewed_device(previous, 2, Validity::new(100, 190).expect("interval"));
    let fork = renewed_device(
        previous,
        2,
        Validity::new(100, 180).expect("different same-version roster"),
    );
    let later = renewed_device(
        previous,
        3,
        Validity::new(100, 195).expect("later interval"),
    );
    let image = c.store.image().expect("original").digest;
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            previous,
            policy,
            150
        ),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            190
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let wrong = c.peer.initiator_device();
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            wrong.roster().checkpoint(),
            &next,
            policy,
            150
        ),
        Err(DurableError::Conflict)
    ));
    let mut unknown = c.genesis.subject;
    unknown.journal = [144; 32];
    assert!(matches!(
        c.store.update_roster_authority(
            unknown,
            previous.roster().checkpoint(),
            &next,
            policy,
            150
        ),
        Err(DurableError::Absent)
    ));
    assert_eq!(
        c.store.image().expect("all refusals preserve image").digest,
        image
    );
    c.store
        .update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            160,
        )
        .expect("first winner");
    let updated = c.store.image().expect("winner").digest;
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &fork,
            policy,
            160
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &later,
            policy,
            160
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            next.roster().checkpoint(),
            &fork,
            policy,
            160
        ),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    assert_eq!(c.store.image().expect("losers unchanged").digest, updated);
    c.store
        .update_roster_authority(
            c.genesis.subject(),
            next.roster().checkpoint(),
            &later,
            policy,
            160,
        )
        .expect("next exact predecessor");
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            160
        ),
        Err(DurableError::Conflict)
    ));
    policy.close();
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            next.roster().checkpoint(),
            &later,
            policy,
            160
        ),
        Err(DurableError::Protocol(Error::Closed))
    ));
}

fn with_fault_database(
    c: &mut Case,
    after: bool,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    c.store.close();
    let (db, remaining, count, _) = fault_database_path(&c.server.join("anchor.redb"), after);
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
    (remaining, count)
}

#[test]
fn roster_authority_refresh_each_sync_fault_reconciles_current_target_without_reset() {
    let mut calibration = renewal_case();
    let (_, count) = with_fault_database(&mut calibration, false);
    let (policy, previous, _) = calibration
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let next = renewed_device(previous, 2, Validity::new(100, 190).expect("interval"));
    count.store(0, Ordering::SeqCst);
    calibration
        .store
        .update_roster_authority(
            calibration.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            160,
        )
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = renewal_case();
            let first = request(
                &c,
                AnchorOperation::advance(initial(&c), [145; 32]).expect("advance"),
            );
            let head = apply_request(&mut c, &first).applied_head().expect("head");
            let (remaining, _) = with_fault_database(&mut c, after);
            let (policy, previous, _) = c
                .peer
                .responder
                .inventory_inputs()
                .expect("fixture inventory owner");
            let next = renewed_device(previous, 2, Validity::new(100, 190).expect("interval"));
            let before = c.store.image().expect("before").revision;
            remaining.store(cut, Ordering::SeqCst);
            let result = c.store.update_roster_authority(
                c.genesis.subject(),
                previous.roster().checkpoint(),
                &next,
                policy,
                160,
            );
            crate::durable::tests::assert_sync_failure(result, after);
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            c.store
                .update_roster_authority(
                    c.genesis.subject(),
                    previous.roster().checkpoint(),
                    &next,
                    policy,
                    160,
                )
                .expect("original target reconciliation");
            let image = c.store.image().expect("one update");
            assert_eq!(image.revision, before + 1);
            let entry = image
                .entries
                .get(&c.genesis.subject.id(&c.pin.binding))
                .expect("entry");
            assert_eq!(entry.head, head);
            assert_eq!(entry.last, Some(first.command_id()));
            assert_eq!(entry.genesis, c.genesis.digest);
            assert_eq!(entry.authority, next.authority_binding());
        }
    }
    eprintln!(
        "ANCHOR_ROSTER_REFRESH_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn roster_authority_refresh_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ANCHOR_RENEWAL_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let bytes = fs::read(path.join("renewal-subject")).expect("retained public metadata");
    let subject = AnchorSubject::from_trusted_state(&bytes).expect("original trusted subject");
    let bytes = fs::read(path.join("renewal-predecessor")).expect("retained checkpoint");
    let mut d = Decoder::new(&bytes);
    let predecessor = crate::RosterCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("original expected checkpoint");
    d.finish().expect("exact checkpoint bytes");
    let peer = crate::bootstrap::tests::fixture_with_public_validity(
        PrekeyQuality::OneTimeBoth,
        Validity::new(100, 160).expect("roster"),
        Validity::new(100, 160).expect("advertisement"),
    );
    let (policy, previous, _) = peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let next = renewed_device(previous, 2, Validity::new(100, 190).expect("renewal"));
    let mut store = reopen(path);
    store
        .update_roster_authority(subject, predecessor, &next, policy, 160)
        .expect("renewal");
    fs::write(path.join("returned-renewal"), b"current target").expect("public result");
}

#[test]
fn roster_authority_refresh_process_loss_recovers_without_resetting_last_data_command() {
    let mut c = renewal_case();
    let first = request(
        &c,
        AnchorOperation::advance(initial(&c), [146; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &first).applied_head().expect("head");
    fs::write(
        c.server.join("renewal-subject"),
        c.genesis.subject().to_bytes(),
    )
    .expect("original public subject");
    let checkpoint = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .1
        .roster()
        .checkpoint();
    let mut expected = checkpoint.version().to_be_bytes().to_vec();
    expected.extend_from_slice(&checkpoint.digest());
    fs::write(c.server.join("renewal-predecessor"), expected)
        .expect("original independent predecessor");
    let revision = c.store.image().expect("before").revision;
    c.store.close();
    let log = fs::File::create_new(c.server.join("renewal-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::roster_authority_refresh_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ANCHOR_RENEWAL_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", (revision + 1).to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned process"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "renewal child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-renewal").exists());
    child.0.kill().expect("kill owned process");
    assert!(!child.0.wait().expect("reap").success());
    c.store = reopen(&c.server);
    let (policy, previous, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let next = renewed_device(previous, 2, Validity::new(100, 190).expect("renewal"));
    c.store
        .update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &next,
            policy,
            160,
        )
        .expect("reconcile original target");
    assert_eq!(
        c.store.image().expect("no second mutation").revision,
        revision + 1
    );
    let retry = request(&c, first.operation);
    assert_eq!(retry.command_id(), first.command_id());
    let reply = c
        .store
        .handle(retry.as_bytes(), 160)
        .expect("original command is still exact last");
    let reply = c
        .pin
        .verify_reply(&retry, &reply)
        .expect("authenticated reply");
    assert_eq!(reply.outcome(), AnchorOutcome::AlreadyAppliedExact);
    assert_eq!(reply.applied_head().expect("original head"), head);
    eprintln!("ANCHOR_ROSTER_REFRESH_PROCESS retained_public_checkpoint=true original_head=true original_last_command=true result_not_returned=true");
}

#[test]
fn roster_authority_refresh_never_becomes_credential_key_or_policy_replacement() {
    let mut c = renewal_case();
    let (policy, previous, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("original root");
    let replacement_key =
        DeviceSigningKey::deterministic([148; 32], [149; 32]).expect("different identity key");
    let before = c.store.image().expect("before").digest;
    #[derive(Debug)]
    enum Change {
        Credential,
        Key,
        Generation,
        Family,
    }
    for change in [
        Change::Credential,
        Change::Key,
        Change::Generation,
        Change::Family,
    ] {
        let mut description = previous.description.clone();
        let mut public = previous.key.clone();
        match change {
            Change::Credential => {
                description.validity = Validity::new(100, 195).expect("different credential body")
            }
            Change::Key => public = replacement_key.public_key().expect("different public key"),
            Change::Generation => description.generation += 1,
            Change::Family => description.family = [150; 32],
        }
        let certificate = root
            .issue_device(description.clone(), public)
            .expect("authentic replacement credential");
        let roster = root
            .issue_roster(
                2,
                Validity::new(100, 190).expect("roster"),
                &[root.roster_entry(&certificate).expect("entry")],
            )
            .expect("signed roster");
        let pin = crate::AccountPin::new(
            previous.account_id(),
            root.public_key().expect("root"),
            roster.checkpoint(),
            description.family,
        )
        .expect("independent pin");
        let next = pin
            .verify_device(&certificate, roster.as_bytes(), 150)
            .expect("valid identity in its own scope");
        assert!(
            matches!(
                c.store.update_roster_authority(
                    c.genesis.subject(),
                    previous.roster().checkpoint(),
                    &next,
                    policy,
                    150
                ),
                Err(DurableError::Protocol(Error::Scope))
            ),
            "{change:?}"
        );
    }
    let next = renewed_device(previous, 2, Validity::new(100, 190).expect("renewal"));
    let mut subject = c.genesis.subject;
    subject.policy = [151; 32];
    assert!(matches!(
        c.store.update_roster_authority(
            subject,
            previous.roster().checkpoint(),
            &next,
            policy,
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let future = renewed_device(previous, 2, Validity::new(160, 190).expect("future roster"));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            previous.roster().checkpoint(),
            &future,
            policy,
            150
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let certificate = root
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("original credential");
    let revoked = root
        .issue_roster(2, Validity::new(100, 190).expect("validity"), &[])
        .expect("explicit revocation");
    let pin = crate::AccountPin::new(
        previous.account_id(),
        root.public_key().expect("root"),
        revoked.checkpoint(),
        previous.description.family,
    )
    .expect("current revoked pin");
    assert!(matches!(
        pin.verify_device(&certificate, revoked.as_bytes(), 150),
        Err(Error::Scope)
    ));
    assert_eq!(
        c.store
            .image()
            .expect("all authentic invalid-scope requests are read-only")
            .digest,
        before
    );
}

#[test]
fn current_authority_observation_is_fresh_scoped_and_never_a_mutation_receipt() {
    let mut c = case();
    let (_, device, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let operation = AnchorOperation::admit_authority(device.authority_binding())
        .expect("independent authority expectation");
    let expected = initial(&c);
    assert_eq!(operation.to_bytes().len(), 97);
    assert_eq!(operation.to_bytes().first(), Some(&4));
    assert_eq!(
        AnchorOperation::from_trusted_state(&operation.to_bytes()).expect("canonical operation"),
        operation
    );
    assert!(AnchorOperation::admit_authority([0; 32]).is_err());
    let mut malformed = operation.to_bytes();
    *malformed.get_mut(33).expect("reserved padding") = 1;
    assert!(AnchorOperation::from_trusted_state(&malformed).is_err());

    let ordinary = request(&c, AnchorOperation::query());
    let query_wire = c
        .store
        .handle(ordinary.as_bytes(), 150)
        .expect("ordinary head query");
    let admitted = request(&c, operation);
    assert!(matches!(
        c.pin.verify_reply(&admitted, &query_wire),
        Err(Error::Scope)
    ));
    let wire = c
        .store
        .handle(admitted.as_bytes(), 150)
        .expect("fresh authority confirmation");
    let observation = c
        .pin
        .verify_reply(&admitted, &wire)
        .expect("exact signed admission");
    assert_eq!(observation.outcome(), AnchorOutcome::AuthorityCurrent);
    assert_eq!(observation.observed_head(), expected);
    assert_eq!(observation.last_command_id(), None);
    assert!(observation.applied_head().is_err());
    let fresh = request(&c, operation);
    assert!(
        matches!(c.pin.verify_reply(&fresh, &wire), Err(Error::Scope)),
        "old challenge cannot confirm a new admission attempt"
    );

    // Even a correctly signed, correctly attempt-bound Query disposition cannot
    // be relabeled as admission. Likewise 5/6 cannot authorize an old operation.
    for (op, outcome) in [
        (operation, AnchorOutcome::Current),
        (AnchorOperation::query(), AnchorOutcome::AuthorityCurrent),
        (AnchorOperation::query(), AnchorOutcome::AuthorityDenied),
    ] {
        let rq = request(&c, op);
        let incoming = incoming(&c.pin, rq.as_bytes()).expect("signed request grammar");
        let active = c.store.active.as_ref().expect("owned signing authority");
        let wrong = reply(&c.pin, &active.signer, &incoming, outcome, expected, None)
            .expect("signed wrong disposition");
        assert!(matches!(c.pin.verify_reply(&rq, &wrong), Err(Error::State)));
    }
    for (op, at) in [
        (operation, 200),
        (operation, 99),
        (
            AnchorOperation::admit_authority([91; 32]).expect("different expected grant"),
            150,
        ),
    ] {
        let rq = request(&c, op);
        let wire = c
            .store
            .handle(rq.as_bytes(), at)
            .expect("authenticated denial");
        let observed = c.pin.verify_reply(&rq, &wire).expect("denial verifies");
        assert_eq!(observed.outcome(), AnchorOutcome::AuthorityDenied);
        assert_eq!(observed.observed_head(), expected);
        assert_eq!(observed.last_command_id(), None);
        assert!(observed.applied_head().is_err());
    }
    let query = request(&c, AnchorOperation::query());
    let wire = c
        .store
        .handle(query.as_bytes(), 200)
        .expect("expiry does not erase original head");
    let observed = c
        .pin
        .verify_reply(&query, &wire)
        .expect("historical readback remains available");
    assert_eq!(observed.outcome(), AnchorOutcome::Current);
    assert_eq!(observed.observed_head(), expected);
}

fn credential_case() -> Case {
    case_with_peer(
        crate::bootstrap::tests::fixture_with_public_and_credential_validity(
            PrekeyQuality::OneTimeBoth,
            Validity::new(100, 200).expect("roster"),
            Validity::new(100, 155).expect("advertisement"),
            Validity::new(100, 160).expect("original credential"),
        ),
    )
}
fn credential_grant(
    c: &Case,
    previous: &VerifiedDevice,
    version: u64,
    until: u64,
) -> crate::VerifiedCredentialRenewal {
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("independent root");
    let (policy, original, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let origin = root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    crate::durable::tests::grant(
        &root,
        &origin,
        previous,
        until,
        version,
        [u8::try_from(160 + version).expect("operation"); 32],
        policy.checkpoint().digest(),
    )
}
fn credential_grant_first(c: &Case) -> crate::VerifiedCredentialRenewal {
    credential_grant(
        c,
        c.peer
            .responder
            .inventory_inputs()
            .expect("fixture inventory owner")
            .1,
        2,
        180,
    )
}

#[test]
fn credential_authority_renewal_preserves_subject_head_and_last_command_across_expiry_and_roster_refresh(
) {
    let mut c = credential_case();
    let first = request(
        &c,
        AnchorOperation::advance(initial(&c), [171; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &first).applied_head().expect("head");
    let fenced = request(&c, AnchorOperation::fence_writer(head).expect("fence"));
    let head = apply_request(&mut c, &fenced)
        .applied_head()
        .expect("fenced");
    let grant = credential_grant_first(&c);
    let (policy, original, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            original.roster().checkpoint(),
            grant.successor_device(),
            policy,
            170
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let admit_next = AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        AnchorOperation::admit_authority(grant.successor_device().authority_binding())
            .expect("target"),
        &c.peer.signer_r,
    )
    .expect("request");
    let denied = c
        .store
        .handle(admit_next.as_bytes(), 170)
        .expect("authenticated refusal");
    assert_eq!(
        c.pin
            .verify_reply(&admit_next, &denied)
            .expect("reply")
            .outcome(),
        AnchorOutcome::AuthorityDenied
    );
    let before = c.store.image().expect("before").revision;
    assert_eq!(
        c.store
            .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
            .expect("root-authorized renewal"),
        grant.successor_device().roster().checkpoint()
    );
    let image = c.store.image().expect("committed");
    let entry = image
        .entries
        .get(&c.genesis.subject.id(&c.pin.binding))
        .expect("original subject");
    assert_eq!(
        (entry.subject, entry.head, entry.last, entry.genesis),
        (
            c.genesis.subject,
            head,
            Some(fenced.command_id()),
            c.genesis.digest
        )
    );
    assert_eq!(
        entry.credential_owner,
        storage_owner(grant.successor_device())
    );
    assert_ne!(entry.credential_owner, entry.subject.owner);
    assert_eq!(image.revision, before + 1);
    c.store.close();
    c.store = reopen(&c.server);
    c.store
        .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
        .expect("current target retry");
    assert_eq!(
        c.store.image().expect("no second commit").revision,
        before + 1
    );
    let admit_next = AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        admit_next.operation,
        &c.peer.signer_r,
    )
    .expect("fresh authority attempt after the denied attempt was consumed");
    let permitted = c
        .store
        .handle(admit_next.as_bytes(), 170)
        .expect("authority reply");
    assert_eq!(
        c.pin
            .verify_reply(&admit_next, &permitted)
            .expect("verified")
            .outcome(),
        AnchorOutcome::AuthorityCurrent
    );
    let successor_roster = renewed_device(
        grant.successor_device(),
        3,
        Validity::new(100, 195).expect("later roster"),
    );
    c.store
        .update_roster_authority(
            c.genesis.subject(),
            grant.successor_device().roster().checkpoint(),
            &successor_roster,
            policy,
            175,
        )
        .expect("same renewed credential roster update");
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &grant,
            grant.operation(),
            policy,
            175
        ),
        Err(DurableError::Conflict)
    ));
    let fenced_retry = AnchorRequest::new(
        &c.pin,
        c.genesis.subject(),
        fenced.operation,
        &c.peer.signer_r,
    )
    .expect("fresh historical exact-command attempt");
    assert_eq!(fenced_retry.command_id(), fenced.command_id());
    let exact = c
        .store
        .handle(fenced_retry.as_bytes(), 180)
        .expect("historical exact command after expiry");
    assert_eq!(
        c.pin
            .verify_reply(&fenced_retry, &exact)
            .expect("verified")
            .outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &grant,
            grant.operation(),
            policy,
            180
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let next = credential_grant(&c, &successor_roster, 4, 195);
    let policy = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .0;
    c.store
        .renew_credential_authority(c.genesis.subject(), &next, next.operation(), policy, 185)
        .expect("second expired predecessor renewal");
    let entry = c
        .store
        .image()
        .expect("second image")
        .entries
        .remove(&c.genesis.subject.id(&c.pin.binding))
        .expect("entry");
    assert_eq!(
        (entry.subject, entry.head, entry.last, entry.genesis),
        (
            c.genesis.subject,
            head,
            Some(fenced.command_id()),
            c.genesis.digest
        )
    );
}

#[test]
fn credential_authority_renewal_refuses_wrong_scope_operation_predecessor_and_fork() {
    let mut c = credential_case();
    let grant = credential_grant_first(&c);
    let fork = credential_grant(
        &c,
        c.peer
            .responder
            .inventory_inputs()
            .expect("fixture inventory owner")
            .1,
        2,
        190,
    );
    let policy = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .0;
    let before = c.store.image().expect("before").digest;
    let wrong_operation =
        crate::CredentialRenewalId::from_trusted_state([199; 32]).expect("other op");
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &grant,
            wrong_operation,
            policy,
            170
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    for field in 0..3 {
        let mut subject = c.genesis.subject();
        match field {
            0 => subject.owner = [201; 32],
            1 => subject.policy = [202; 32],
            _ => subject.journal = [203; 32],
        }
        assert!(c
            .store
            .renew_credential_authority(subject, &grant, grant.operation(), policy, 170)
            .is_err());
    }
    assert_eq!(c.store.image().expect("unchanged").digest, before);
    c.store
        .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
        .expect("one winner");
    let after = c.store.image().expect("after").digest;
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &fork,
            fork.operation(),
            policy,
            170
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(c.store.image().expect("fork refused").digest, after);
    policy.close();
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &grant,
            grant.operation(),
            policy,
            170
        ),
        Err(DurableError::Protocol(Error::Closed))
    ));
}

#[test]
fn credential_authority_renewal_upgrades_authenticated_original_witness_storage_without_reset() {
    let mut c = credential_case();
    let mut image = c.store.image().expect("original");
    assert_eq!(image.entries.len(), 1);
    for entry in image.entries.values_mut() {
        entry.original_identity = None;
    }
    let active = c.store.active.as_ref().expect("active");
    let mut legacy = encode(&active.wrapping, &active.pin, &image).expect("v2 image");
    legacy.truncate(legacy.len() - 32);
    legacy.splice(..8, *b"QPANC001");
    let credential_offset = 8 + 32 + 8 + 2 + 32 + 96 + PUBLIC_KEY_BYTES;
    legacy.drain(credential_offset..credential_offset + 32);
    let mut auth = authenticator(&active.wrapping).expect("original key");
    auth.update(&legacy);
    legacy.extend_from_slice(&auth.finalize().into_bytes());
    let tx = transaction(&active.db).expect("legacy write");
    tx.open_table(TABLE)
        .expect("table")
        .insert("image", legacy.as_slice())
        .expect("original bytes");
    tx.commit().expect("legacy durable image");
    c.store.close();
    c.store = reopen(&c.server);
    let legacy_image = c.store.image().expect("old reader contract");
    let entry = legacy_image
        .entries
        .get(&c.genesis.subject.id(&c.pin.binding))
        .expect("legacy entry");
    assert_eq!(entry.credential_owner, entry.subject.owner);
    assert_eq!(
        (entry.head, entry.genesis, legacy_image.revision),
        (initial(&c), c.genesis.digest, image.revision)
    );
    let grant = credential_grant_first(&c);
    let policy = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .0;
    c.store
        .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
        .expect("migrate once with renewal");
    c.store.close();
    c.store = reopen(&c.server);
    let active = c.store.active.as_ref().expect("reopened");
    let tx = active.db.begin_read().expect("read");
    let table = tx.open_table(TABLE).expect("table");
    let saved = table.get("image").expect("value").expect("image");
    assert_eq!(saved.value().get(..8), Some(b"QPANC002".as_slice()));
    drop(saved);
    drop(table);
    drop(tx);
    assert_eq!(
        c.store.image().expect("one transition").revision,
        image.revision + 1
    );
}

#[test]
fn credential_authority_renewal_each_sync_fault_reconciles_current_target_without_reset() {
    let mut calibration = credential_case();
    let (_, count) = with_fault_database(&mut calibration, false);
    let grant = credential_grant_first(&calibration);
    let policy = calibration
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .0;
    count.store(0, Ordering::SeqCst);
    calibration
        .store
        .renew_credential_authority(
            calibration.genesis.subject(),
            &grant,
            grant.operation(),
            policy,
            170,
        )
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = credential_case();
            let first = request(
                &c,
                AnchorOperation::advance(initial(&c), [174; 32]).expect("advance"),
            );
            let head = apply_request(&mut c, &first).applied_head().expect("head");
            let grant = credential_grant_first(&c);
            let (remaining, _) = with_fault_database(&mut c, after);
            let policy = c
                .peer
                .responder
                .inventory_inputs()
                .expect("fixture inventory owner")
                .0;
            let before = c.store.image().expect("before").revision;
            remaining.store(cut, Ordering::SeqCst);
            let result = c.store.renew_credential_authority(
                c.genesis.subject(),
                &grant,
                grant.operation(),
                policy,
                170,
            );
            crate::durable::tests::assert_sync_failure(result, after);
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            c.store
                .renew_credential_authority(
                    c.genesis.subject(),
                    &grant,
                    grant.operation(),
                    policy,
                    170,
                )
                .expect("original target reconciliation");
            let image = c.store.image().expect("recovered");
            let entry = image
                .entries
                .get(&c.genesis.subject.id(&c.pin.binding))
                .expect("same entry");
            assert_eq!(image.revision, before + 1);
            assert_eq!(
                (entry.head, entry.last, entry.genesis),
                (head, Some(first.command_id()), c.genesis.digest)
            );
            assert_eq!(
                entry.credential_owner,
                storage_owner(grant.successor_device())
            );
        }
    }
    eprintln!(
        "ANCHOR_CREDENTIAL_RENEWAL_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn credential_authority_renewal_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ANCHOR_CREDENTIAL_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let peer = crate::bootstrap::tests::fixture_with_public_and_credential_validity(
        PrekeyQuality::OneTimeBoth,
        Validity::new(100, 200).expect("roster"),
        Validity::new(100, 155).expect("advertisement"),
        Validity::new(100, 160).expect("credential"),
    );
    let (policy, previous, _) = peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner");
    let subject = AnchorSubject::from_trusted_state(
        &fs::read(path.join("renewal-subject")).expect("original public subject"),
    )
    .expect("subject");
    let checkpoint = fs::read(path.join("renewal-target")).expect("retained independent pin");
    let mut d = Decoder::new(&checkpoint);
    let checkpoint = crate::RosterCheckpoint::from_trusted_state(
        d.u64().expect("version"),
        d.array().expect("digest"),
    )
    .expect("checkpoint");
    d.finish().expect("exact target");
    let pin = crate::AccountPin::new(
        previous.account_id(),
        previous.authority_key.clone(),
        checkpoint,
        previous.description.family,
    )
    .expect("independently retained account pin");
    let wire = fs::read(path.join("renewal-grant")).expect("original public bytes");
    let grant =
        crate::VerifiedCredentialRenewal::verify(&wire, &pin, policy.checkpoint().digest(), 170)
            .expect("same independently verified grant");
    let operation = crate::CredentialRenewalId::from_trusted_state(
        fs::read(path.join("renewal-operation"))
            .expect("retained operation")
            .try_into()
            .expect("operation width"),
    )
    .expect("operation");
    let mut store = reopen(path);
    store
        .renew_credential_authority(subject, &grant, operation, policy, 170)
        .expect("trusted authority update");
    fs::write(path.join("returned-renewal"), b"current target").expect("result");
}

#[test]
fn credential_authority_renewal_process_loss_recovers_original_grant_before_any_result() {
    let mut c = credential_case();
    let first = request(
        &c,
        AnchorOperation::advance(initial(&c), [175; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &first).applied_head().expect("head");
    let grant = credential_grant_first(&c);
    let checkpoint = grant.successor_device().roster().checkpoint();
    let mut target = checkpoint.version().to_be_bytes().to_vec();
    target.extend_from_slice(&checkpoint.digest());
    fs::write(
        c.server.join("renewal-subject"),
        c.genesis.subject().to_bytes(),
    )
    .expect("original subject");
    fs::write(c.server.join("renewal-target"), target).expect("independent target pin");
    fs::write(c.server.join("renewal-grant"), grant.as_bytes()).expect("original grant");
    fs::write(
        c.server.join("renewal-operation"),
        grant.operation().as_bytes(),
    )
    .expect("original operation");
    let before = c.store.image().expect("before").revision;
    c.store.close();
    let log = fs::File::create_new(c.server.join("credential-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::credential_authority_renewal_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ANCHOR_CREDENTIAL_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", (before + 1).to_string())
            .stdout(Stdio::from(log.try_clone().expect("clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "credential child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-renewal").exists());
    child.0.kill().expect("kill owned child");
    assert!(!child.0.wait().expect("reap").success());
    c.store = reopen(&c.server);
    let policy = c
        .peer
        .responder
        .inventory_inputs()
        .expect("fixture inventory owner")
        .0;
    c.store
        .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
        .expect("reconcile exact target");
    let image = c.store.image().expect("current image");
    let entry = image
        .entries
        .get(&c.genesis.subject.id(&c.pin.binding))
        .expect("original subject");
    assert_eq!(image.revision, before + 1);
    assert_eq!(
        (entry.head, entry.last, entry.genesis),
        (head, Some(first.command_id()), c.genesis.digest)
    );
    assert_eq!(
        entry.credential_owner,
        storage_owner(grant.successor_device())
    );
    eprintln!("ANCHOR_CREDENTIAL_RENEWAL_PROCESS original_grant=true original_subject=true original_head=true original_last_command=true result_not_returned=true");
}

#[path = "renewal_tests.rs"]
mod joint;

// Materialize the actual pre-lineage format for migration tests. This is an
// authenticated legacy fixture, not a product API for deleting retained identity.
fn legacy_without_original_identity(c: &mut Case) {
    let mut image = c.store.image().expect("current source fixture");
    for entry in image.entries.values_mut() {
        entry.original_identity = None;
    }
    let active = c.store.active.as_ref().expect("active");
    let bytes = encode(&active.wrapping, &active.pin, &image).expect("legacy format");
    let tx = transaction(&active.db).expect("legacy fixture transaction");
    tx.open_table(TABLE)
        .expect("table")
        .insert("image", bytes.as_slice())
        .expect("fixture");
    tx.commit().expect("durable legacy fixture");
    c.store.close();
    c.store = reopen(&c.server);
}

#[test]
fn original_identity_enrollment_and_expired_exact_retry_preserve_all_authority() {
    let mut c = renewal_case();
    let (_, original, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original identity");
    let original = original.clone();
    let before = c.store.image().expect("enrolled");
    let id = c.genesis.subject().id(&c.pin.binding());
    let entry = before.entries.get(&id).expect("entry");
    assert_eq!(
        entry.original_identity,
        Some(OriginalIdentity::from_verified(&original))
    );
    let active = c.store.active.as_ref().expect("active");
    let bytes = encode(&active.wrapping, &active.pin, &before).expect("new encoding");
    assert_eq!(bytes.get(..8), Some(b"QPANC010".as_slice()));
    assert!(matches!(
        original.roster().check_time(180),
        Err(Error::Validity)
    ));
    c.store
        .retain_original_identity(c.genesis.subject(), &original)
        .expect("history is metadata");
    assert_eq!(c.store.image().expect("exact retry").digest, before.digest);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store.image().expect("retained original").digest,
        before.digest
    );
}

#[test]
fn original_identity_migration_after_real_renewal_keeps_current_authority_and_last_command() {
    let mut c = credential_case();
    let grant = credential_grant_first(&c);
    let operation = AnchorOperation::advance(initial(&c), [211; 32]).expect("advance");
    let first = request(&c, operation);
    let head = apply_request(&mut c, &first).applied_head().expect("head");
    let policy = c.peer.responder.current_policy().expect("policy");
    c.store
        .renew_credential_authority(c.genesis.subject(), &grant, grant.operation(), policy, 170)
        .expect("actual renewal");
    let origin = grant.previous_device().clone();
    legacy_without_original_identity(&mut c);
    let before = c.store.image().expect("legacy renewal");
    let id = c.genesis.subject().id(&c.pin.binding());
    let old = before.entries.get(&id).expect("entry");
    assert!(old.original_identity.is_none());
    assert_ne!(old.credential_owner, storage_owner(&origin));
    assert!(matches!(
        c.store
            .retain_original_identity(c.genesis.subject(), grant.successor_device()),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.store.image().expect("successor is not original").digest,
        before.digest
    );
    c.store
        .retain_original_identity(c.genesis.subject(), &origin)
        .expect("original historical owner");
    c.store.close();
    c.store = reopen(&c.server);
    let after = c.store.image().expect("migrated");
    let new = after.entries.get(&id).expect("entry");
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        new.original_identity,
        Some(OriginalIdentity::from_verified(&origin))
    );
    assert_eq!(
        (
            new.subject,
            new.credential_owner,
            new.authority,
            new.validity,
            new.genesis,
            new.head,
            new.last
        ),
        (
            old.subject,
            old.credential_owner,
            old.authority,
            old.validity,
            old.genesis,
            old.head,
            old.last
        )
    );
    assert_eq!(new.head, head);
    c.store
        .retain_original_identity(c.genesis.subject(), &origin)
        .expect("exact retry");
    assert_eq!(
        c.store.image().expect("no duplicate mutation").digest,
        after.digest
    );
    let retry = request(&c, operation);
    assert_eq!(
        apply_request(&mut c, &retry).outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
}

#[test]
fn original_identity_rejects_other_scope_even_on_idempotent_readback() {
    let mut c = case();
    let (_, original, _) = c.peer.responder.inventory_inputs().expect("identity");
    let original = original.clone();
    let before = c.store.image().expect("original").digest;
    assert!(matches!(
        c.store
            .retain_original_identity(c.genesis.subject(), c.peer.initiator_device()),
        Err(DurableError::Protocol(Error::Scope))
    ));
    for dimension in 0..5 {
        let mut changed = original.clone();
        match dimension {
            0 => changed.account = [213; 32],
            1 => changed.description.id = [214; 16],
            2 => changed.description.generation += 1,
            3 => changed.description.family = [215; 32],
            _ => {
                changed.description.validity = Validity::new(110, 190).expect("different interval")
            }
        }
        // Authenticated types cannot be altered through the public API. A forged
        // internal value must also fail the reconstructed original commitment.
        assert!(matches!(
            c.store
                .retain_original_identity(c.genesis.subject(), &changed),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
    let mut absent = c.genesis.subject();
    absent.journal = [216; 32];
    assert!(matches!(
        c.store.retain_original_identity(absent, &original),
        Err(DurableError::Absent)
    ));
    assert_eq!(
        c.store
            .image()
            .expect("all rejected proofs read only")
            .digest,
        before
    );
    c.store.close();
    assert!(matches!(
        c.store
            .retain_original_identity(c.genesis.subject(), &original),
        Err(DurableError::Closed)
    ));
}

#[test]
fn original_identity_authenticated_field_substitution_and_noncanonical_shape_fail_closed() {
    let mut c = case();
    let image = c.store.image().expect("original image");
    let active = c.store.active.as_ref().expect("active");
    let wire = encode(&active.wrapping, &active.pin, &image).expect("lineage encoding");
    let start = wire.len() - 32 - 105;
    assert_eq!(wire.get(start), Some(&1));
    for offset in [0, 1, 33, 49, 57, 65, 73] {
        let mut body = wire.get(..wire.len() - 32).expect("body").to_vec();
        *body.get_mut(start + offset).expect("lineage field") ^= 1;
        let mut auth = authenticator(&active.wrapping).expect("test MAC");
        auth.update(&body);
        body.extend_from_slice(&auth.finalize().into_bytes());
        assert!(
            decode(&active.wrapping, &active.pin, &body).is_err(),
            "lineage offset {offset}"
        );
    }
    let mut malformed = c.store.image().expect("original");
    malformed
        .entries
        .values_mut()
        .next()
        .expect("entry")
        .original_identity
        .as_mut()
        .expect("identity")
        .description
        .family = [219; 32];
    let active = c.store.active.as_ref().expect("active");
    assert!(matches!(
        encode(&active.wrapping, &active.pin, &malformed),
        Err(DurableError::Corrupt)
    ));
}

#[test]
fn original_identity_migration_each_sync_failure_recovers_once_without_new_permission() {
    let mut calibration = renewal_case();
    legacy_without_original_identity(&mut calibration);
    let original = calibration
        .peer
        .responder
        .inventory_inputs()
        .expect("identity")
        .1
        .clone();
    let (_, count) = with_fault_database(&mut calibration, false);
    count.store(0, Ordering::SeqCst);
    calibration
        .store
        .retain_original_identity(calibration.genesis.subject(), &original)
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = renewal_case();
            legacy_without_original_identity(&mut c);
            let original = c
                .peer
                .responder
                .inventory_inputs()
                .expect("identity")
                .1
                .clone();
            let before = c.store.image().expect("legacy image");
            let (remaining, _) = with_fault_database(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            let result = c
                .store
                .retain_original_identity(c.genesis.subject(), &original);
            crate::durable::tests::assert_sync_failure(result, after);
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            c.store
                .retain_original_identity(c.genesis.subject(), &original)
                .expect("original proof exact retry");
            let current = c.store.image().expect("one migration");
            assert_eq!(current.revision, before.revision + 1);
            let id = c.genesis.subject().id(&c.pin.binding());
            let entry = current.entries.get(&id).expect("entry");
            let old = before.entries.get(&id).expect("original");
            assert_eq!(
                (
                    entry.head,
                    entry.last,
                    entry.validity,
                    entry.credential_owner,
                    entry.authority
                ),
                (
                    old.head,
                    old.last,
                    old.validity,
                    old.credential_owner,
                    old.authority
                )
            );
            assert_eq!(
                entry.original_identity,
                Some(OriginalIdentity::from_verified(&original))
            );
            assert!(matches!(entry.validity.check(180), Err(Error::Validity)));
        }
    }
    eprintln!(
        "ANCHOR_ORIGINAL_IDENTITY_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn original_identity_partial_legacy_migration_never_classifies_another_subject() {
    let mut c = case();
    let path = c
        .server
        .parent()
        .expect("canonical test root")
        .join("second-device");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("second device directory");
    let device = c.peer.initiator_device().clone();
    let policy = c.peer.initiator.current_policy().expect("second policy");
    let mut journal = new_store(&path, &device);
    let genesis = journal
        .anchor_genesis(&device, policy)
        .expect("second actual genesis");
    c.store
        .enroll(&genesis, &device, policy, 150)
        .expect("second independent subject");
    let origin = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original identity")
        .1
        .clone();
    legacy_without_original_identity(&mut c);
    c.store
        .retain_original_identity(c.genesis.subject(), &origin)
        .expect("one classified subject");
    c.store.close();
    c.store = reopen(&c.server);
    let image = c.store.image().expect("mixed image");
    assert_eq!(image.entries.len(), 2);
    assert_eq!(
        image
            .entries
            .values()
            .filter(|e| e.original_identity.is_some())
            .count(),
        1
    );
    assert!(image
        .entries
        .get(&genesis.subject().id(&c.pin.binding()))
        .expect("other legacy subject")
        .original_identity
        .is_none());
    let policy = c.peer.initiator.current_policy().expect("same policy");
    c.store
        .enroll(&genesis, &device, policy, 150)
        .expect("exact old enrollment is not migration");
    assert_eq!(
        c.store.image().expect("old retry read only").digest,
        image.digest
    );
    c.store
        .retain_original_identity(genesis.subject(), &device)
        .expect("explicit second proof");
    c.store.close();
    c.store = reopen(&c.server);
    assert!(c
        .store
        .image()
        .expect("both classified")
        .entries
        .values()
        .all(|e| e.original_identity.is_some()));
}

#[test]
fn original_identity_migration_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ANCHOR_IDENTITY_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let subject = AnchorSubject::from_trusted_state(
        &fs::read(path.join("identity-subject")).expect("retained original subject"),
    )
    .expect("subject");
    let peer = crate::bootstrap::tests::fixture_with_public_validity(
        PrekeyQuality::OneTimeBoth,
        Validity::new(100, 160).expect("original roster"),
        Validity::new(100, 160).expect("advertisement"),
    );
    let original = peer
        .responder
        .inventory_inputs()
        .expect("original identity")
        .1;
    let mut store = reopen(path);
    store
        .retain_original_identity(subject, original)
        .expect("original proof");
    fs::write(path.join("returned-identity"), b"retained").expect("returned marker");
}

#[test]
fn original_identity_process_loss_after_commit_keeps_original_head_and_exact_last_command() {
    let mut c = renewal_case();
    let first = request(
        &c,
        AnchorOperation::advance(initial(&c), [223; 32]).expect("original write"),
    );
    let head = apply_request(&mut c, &first).applied_head().expect("head");
    legacy_without_original_identity(&mut c);
    let before = c.store.image().expect("original legacy state");
    fs::write(
        c.server.join("identity-subject"),
        c.genesis.subject().to_bytes(),
    )
    .expect("retained public subject");
    c.store.close();
    let log = fs::File::create_new(c.server.join("identity-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::original_identity_migration_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ANCHOR_IDENTITY_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env(
                "QPERIAPT_ANCHOR_CRASH_REVISION",
                (before.revision + 1).to_string(),
            )
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "identity child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-identity").exists());
    child.0.kill().expect("kill after durable commit");
    assert!(!child.0.wait().expect("reap").success());
    c.store = reopen(&c.server);
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original identity")
        .1
        .clone();
    c.store
        .retain_original_identity(c.genesis.subject(), &original)
        .expect("reconcile same proof");
    let after = c.store.image().expect("one committed migration");
    let entry = after
        .entries
        .get(&c.genesis.subject().id(&c.pin.binding()))
        .expect("subject");
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        entry.original_identity,
        Some(OriginalIdentity::from_verified(&original))
    );
    assert_eq!(entry.head, head);
    assert_eq!(entry.last, Some(first.command_id()));
    let retry = request(&c, first.operation);
    assert_eq!(
        apply_request(&mut c, &retry).outcome(),
        AnchorOutcome::AlreadyAppliedExact
    );
    eprintln!("ANCHOR_ORIGINAL_IDENTITY_PROCESS commit_before_return=true same_subject=true same_head=true same_last_command=true exact_metadata_retry=true");
}

#[path = "replacement_tests.rs"]
mod replacement;
