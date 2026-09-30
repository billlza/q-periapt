// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, fixture_from_public, Fixture},
    durable::tests::{directory, fault_database, identity, new_store, reopen, ChildGuard},
    InitiatorOperation, PrekeyQuality,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn proposal(path: &Path, f: &Fixture) -> (DeviceJournal, PendingWrite) {
    let mut store = new_store(path, f.local_device());
    let peer =
        InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = peer.initial_message(150).expect("wire");
    let mut image = store.image().expect("image");
    rosters::admit_context(&mut image, &f.responder, true, 150).expect("admit account heads");
    image.records.insert(
        operation_id(&f.responder.digest(), initial),
        Record {
            context: f.responder.digest(),
            kind: RecordKind::Responder,
            phase: DurableStatus::Executing,
            authorities: rosters::context_accounts(&f.responder),
            keys: f.responder.one_time_fingerprints(),
            prekeys: Vec::new(),
            cancellation: None,
            payload: Zeroizing::new(initial.to_vec()),
        },
    );
    image.revision += 1;
    let active = store.active.as_ref().expect("active");
    let target = seal(&active.key, &image).expect("target");
    let pending = PendingWrite::new(active, &image, &target).expect("bound intent");
    (store, pending)
}
fn disk_image(db: &Database) -> Vec<u8> {
    let tx = db.begin_read().expect("read");
    let table = tx.open_table(TABLE).expect("table");
    let bytes = table
        .get("image")
        .expect("query")
        .expect("image")
        .value()
        .to_vec();
    bytes
}

#[test]
fn authenticated_intent_cannot_change_journal_protection_metadata() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let (store, pending) = proposal(&path, &f);
    let active = store.active.as_ref().expect("active");
    let original = disk_image(&active.db);
    let mut changed = unseal(&active.key, active.owner, &pending.target).expect("valid target");
    changed.digest = pending.expected_digest;
    changed.protection = Protection::Required {
        policy: [12; 32],
        witness: [13; 32],
        fence: 1,
    };
    let target = seal(&active.key, &changed).expect("authenticated target with changed profile");
    let intent = PendingWrite::new(active, &changed, &target).expect("valid intent MAC");
    reserve(active, &intent).expect("persist adversarial authenticated fixture");
    assert!(matches!(
        load_snapshot(&active.db, &active.key, active.owner),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        recover(
            &active.db,
            &active.key,
            active.owner,
            JournalIdentity(active.id)
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(disk_image(&active.db), original);
}

#[test]
fn authenticated_intent_cannot_rebind_the_journal_local_account() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let (store, pending) = proposal(&path, &f);
    let active = store.active.as_ref().expect("active");
    let original = disk_image(&active.db);
    let mut changed = unseal(&active.key, active.owner, &pending.target).expect("target");
    changed.digest = pending.expected_digest;
    changed.local_account = f.initiator_device().account_id();
    let target = seal(&active.key, &changed).expect("authenticated different account");
    let intent = PendingWrite::new(active, &changed, &target).expect("valid intent MAC");
    reserve(active, &intent).expect("adversarial authenticated fixture");
    assert!(matches!(
        load_snapshot(&active.db, &active.key, active.owner),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        recover(
            &active.db,
            &active.key,
            active.owner,
            JournalIdentity(active.id)
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(disk_image(&active.db), original);
}

#[test]
fn pending_ciphertext_is_applied_exactly_once_and_reopening_checks_identity_first() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let (mut store, pending) = proposal(&path, &f);
    let active = store.active.as_ref().expect("active");
    let before = disk_image(&active.db);
    reserve(active, &pending).expect("durable plan");
    assert_eq!(disk_image(&active.db), before);
    assert!(matches!(
        load(&active.db, &active.key, active.owner),
        Err(DurableError::Suspended)
    ));
    let wrong = JournalIdentity::from_trusted_state([239; 32]).expect("other identity");
    assert!(matches!(
        recover(&active.db, &active.key, active.owner, wrong),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        disk_image(&active.db),
        before,
        "wrong identity mutated state"
    );
    store.close();
    let store = reopen(&path, f.local_device());
    let active = store.active.as_ref().expect("active");
    assert_eq!(disk_image(&active.db), pending.target);
    apply(&active.db, &pending).expect("already applied exact");
    assert_eq!(disk_image(&active.db), pending.target);
    let (image, intent) = load_snapshot(&active.db, &active.key, active.owner).expect("snapshot");
    assert_eq!(image.revision, pending.next_revision);
    assert_eq!(image.digest, pending.next_digest);
    assert!(intent.is_none());
    // A leftover intent beside its installed target cannot be produced by the
    // atomic apply transaction; even an authentic old intent must not repair it.
    let tx = transaction(&active.db).expect("fixture transaction");
    tx.open_table(TABLE)
        .expect("table")
        .insert("pending", pending.wire.as_slice())
        .expect("authenticated inconsistent pair");
    tx.commit().expect("fixture commit");
    assert!(matches!(
        load_snapshot(&active.db, &active.key, active.owner),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        apply(&active.db, &pending),
        Err(DurableError::Conflict)
    ));
    assert_eq!(disk_image(&active.db), pending.target);
}

#[test]
fn recovery_commit_sync_failures_preserve_the_same_sealed_target() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let measured_dir = directory();
    let measured_path = measured_dir.path().canonicalize().expect("path");
    let (mut measured, expected) = proposal(&measured_path, &f);
    reserve(measured.active.as_ref().expect("active"), &expected).expect("plan");
    measured.close();
    let (db, _, count, _) = fault_database(&measured_path, false);
    let key = JournalKey::open(&measured_path.join("key")).expect("wrapping");
    recover(
        &db,
        &key,
        bootstrap::storage_owner(f.local_device()),
        identity(&measured_path),
    )
    .expect("count recovery barriers");
    let syncs = count.load(Ordering::SeqCst);
    assert!((2..=64).contains(&syncs));
    drop(db);
    for after_sync in [false, true] {
        for cut in 1..=syncs {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            let (mut store, pending) = proposal(&path, &f);
            reserve(store.active.as_ref().expect("active"), &pending).expect("plan");
            store.close();
            let (db, remaining, _, _) = fault_database(&path, after_sync);
            let key = JournalKey::open(&path.join("key")).expect("wrapping");
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                recover(
                    &db,
                    &key,
                    bootstrap::storage_owner(f.local_device()),
                    identity(&path),
                ),
                after_sync,
            );
            drop(db);
            let store = reopen(&path, f.local_device());
            assert_eq!(
                disk_image(&store.active.as_ref().expect("active").db),
                pending.target
            );
        }
    }
}

#[test]
fn intent_authentication_and_full_prior_digest_prevent_grafts_and_forked_writes() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let (store, pending) = proposal(&path, &f);
    let active = store.active.as_ref().expect("active");
    for index in 0..pending.wire.len() {
        let mut changed = pending.wire.clone();
        *changed.get_mut(index).expect("byte") ^= 1;
        assert!(
            PendingWrite::decode(&active.key, active.owner, active.id, &changed).is_err(),
            "changed byte {index}"
        );
    }
    for length in [0, INTENT_HEADER, pending.wire.len() - 1] {
        assert!(PendingWrite::decode(
            &active.key,
            active.owner,
            active.id,
            pending.wire.get(..length).expect("prefix")
        )
        .is_err());
    }
    let mut extra = pending.wire.clone();
    extra.push(0);
    assert!(PendingWrite::decode(&active.key, active.owner, active.id, &extra).is_err());
    for mutation in 0..4 {
        let mut invalid = pending
            .wire
            .get(..pending.wire.len() - 32)
            .expect("body")
            .to_vec();
        match mutation {
            0 => invalid.get_mut(72..80).expect("prior revision").fill(0),
            1 => invalid
                .get_mut(112..120)
                .expect("next revision")
                .copy_from_slice(&pending.expected_revision.to_be_bytes()),
            2 => invalid
                .get_mut(152..156)
                .expect("target length")
                .copy_from_slice(&1u32.to_be_bytes()),
            _ => *invalid.get_mut(INTENT_HEADER).expect("target header") ^= 1,
        }
        let mut auth = authenticator(&active.key).expect("key");
        auth.update(&invalid);
        invalid.extend_from_slice(&auth.finalize().into_bytes());
        assert!(
            matches!(
                PendingWrite::decode(&active.key, active.owner, active.id, &invalid),
                Err(DurableError::Corrupt)
            ),
            "authenticated malformed intent {mutation}"
        );
    }
    // A valid writer MAC cannot turn a same-revision/different-digest base into a match.
    let mut fork = pending
        .wire
        .get(..pending.wire.len() - 32)
        .expect("body")
        .to_vec();
    fork.get_mut(80..112).expect("expected digest").fill(19);
    let mut auth = authenticator(&active.key).expect("key");
    auth.update(&fork);
    fork.extend_from_slice(&auth.finalize().into_bytes());
    let fork = PendingWrite::decode(&active.key, active.owner, active.id, &fork)
        .expect("well-formed intent");
    assert!(matches!(
        reserve(active, &fork),
        Err(DurableError::Conflict)
    ));
    reserve(active, &pending).expect("original plan");
    assert!(matches!(
        apply(&active.db, &fork),
        Err(DurableError::Conflict)
    ));
    apply(&active.db, &pending).expect("original succeeds");
    assert_eq!(disk_image(&active.db), pending.target);
}

pub(super) fn after_intent(pending: &PendingWrite, image: &Image) {
    let Ok(phase) = std::env::var("QPERIAPT_WRITE_INTENT_CRASH_PHASE") else {
        return;
    };
    if !image
        .records
        .values()
        .any(|record| phase == (record.phase as u8).to_string())
    {
        return;
    }
    let path = std::env::var_os("QPERIAPT_JOURNAL_CRASH_DIR").expect("owned directory");
    let path = Path::new(&path);
    fs::write(path.join("saved-write-intent"), &pending.wire).expect("saved intent");
    fs::write(path.join("saved-target-image"), &pending.target).expect("saved ciphertext");
    fs::write(path.join("ready.tmp"), b"intent durable").expect("marker");
    fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish marker");
    loop {
        std::thread::park();
    }
}

fn wait_for(path: &Path, marker: &str, child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join(marker).exists() {
        let status = child.0.try_wait().expect("status");
        if status.is_some() {
            eprintln!(
                "child log: {}",
                fs::read_to_string(path.join("child.log")).expect("finished log")
            );
        }
        assert!(
            status.is_none() && Instant::now() < deadline,
            "missing {marker}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn process_kill_between_intent_and_state_commit_restores_exact_bytes_and_real_confirmation() {
    for phase in [DurableStatus::Executing, DurableStatus::AwaitingFinal] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::prekeys::tests::inventory_response_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_PREKEY_CRASH_DIR", &path)
                .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
                .env(
                    "QPERIAPT_WRITE_INTENT_CRASH_PHASE",
                    (phase as u8).to_string(),
                )
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned inventory responder"),
        );
        wait_for(&path, "peer-public", &mut child);
        let public = fs::read(path.join("peer-public")).expect("public inventory");
        let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
        let mut f = fixture_from_public(
            PrekeyQuality::OneTimeBoth,
            Some((a.try_into().expect("width"), b.try_into().expect("width"))),
        );
        f.once.close();
        f.reusable.close();
        if phase == DurableStatus::AwaitingFinal {
            f.signer_r.close();
        }
        let mut peer = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
            .expect("actual initiator");
        let initial = peer.initial_message(150).expect("initial").to_vec();
        fs::write(path.join("initial.tmp"), &initial).expect("initial");
        fs::rename(path.join("initial.tmp"), path.join("peer-initial")).expect("publish initial");
        wait_for(&path, "ready", &mut child);
        assert!(
            !path.join("returned-response").exists(),
            "outbox escaped its state commit"
        );
        child.0.kill().expect("kill owned responder");
        assert!(!child.0.wait().expect("reap").success());
        let expected =
            fs::read(path.join("saved-target-image")).expect("original encrypted target");
        {
            let db = open_private_database(&path.join("state.redb")).expect("open storage");
            let key = JournalKey::open(&path.join("key")).expect("key");
            let (old, pending) =
                load_snapshot(&db, &key, bootstrap::storage_owner(f.local_device()))
                    .expect("authenticated snapshot");
            let pending = pending.expect("intent survived");
            assert_eq!(
                pending.wire,
                fs::read(path.join("saved-write-intent")).expect("exact intent")
            );
            assert_eq!(pending.target, expected);
            assert_eq!(old.digest, pending.expected_digest);
            assert_eq!(old.revision, pending.expected_revision);
        }
        let mut store = reopen(&path, f.local_device());
        assert_eq!(
            disk_image(&store.active.as_ref().expect("active").db),
            expected
        );
        assert_eq!(store.status(&f.responder, &initial).expect("phase"), phase);
        let reply = store
            .respond_from_inventory(Arc::clone(&f.responder), &initial, &f.signer_r, 150)
            .expect("same admitted work");
        let outcome = peer
            .finish(&reply, 150)
            .expect("actual peer verifies recovered response");
        assert_eq!(
            store
                .finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150
                )
                .expect("final MAC"),
            outcome.pending_session().id()
        );
    }
}
