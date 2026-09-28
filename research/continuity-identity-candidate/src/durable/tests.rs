// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, fixture_from_public},
    crypto::{envelope, open_envelope, Purpose},
    InitiatorOperation, PrekeyQuality,
};
use redb::{backends::FileBackend, StorageBackend};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("continuity-journal-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory")
}
fn new_store(dir: &Path, device: &VerifiedDevice) -> ResponderJournal {
    let key = JournalKey::provision(&dir.join("key")).expect("provision key");
    let store =
        ResponderJournal::provision(&dir.join("state.redb"), key, device).expect("provision store");
    fs::write(
        dir.join("store-id"),
        store.identity().expect("identity").as_bytes(),
    )
    .expect("independent identity configuration");
    store
}
fn identity(dir: &Path) -> JournalIdentity {
    JournalIdentity::from_trusted_state(
        fs::read(dir.join("store-id"))
            .expect("independent identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("identity")
}
fn reopen(dir: &Path, device: &VerifiedDevice) -> ResponderJournal {
    ResponderJournal::open(
        &dir.join("state.redb"),
        JournalKey::open(&dir.join("key")).expect("load key"),
        device,
        identity(dir),
    )
    .expect("reopen store")
}

#[test]
fn real_handshake_survives_owner_loss_and_restart_in_every_mode() {
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let mut f = fixture(quality);
        let folder = directory();
        let dir = folder.path().canonicalize().expect("canonical");
        let mut store = new_store(&dir, f.local_device());
        let mut i =
            InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
        let initial = i.initial_message(150).expect("wire").to_vec();
        assert_eq!(
            store.status(&f.responder, &initial).expect("query"),
            DurableStatus::Absent
        );
        let (pq, classic) = f.sources();
        let reply = store
            .respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classic,
                150,
            )
            .expect("durable response");
        let before = store.image().expect("authenticated image");
        drop(store);
        f.signer_r.close();
        f.reusable.close();
        f.once.close();
        let mut store = reopen(&dir, f.local_device());
        assert_eq!(
            store.status(&f.responder, &initial).expect("query"),
            DurableStatus::AwaitingFinal
        );
        assert_eq!(
            store
                .resume(Arc::clone(&f.responder), &initial, 150)
                .expect("no private provider needed"),
            reply
        );
        let after = store.image().expect("image");
        for (id, entry) in &before.records {
            assert!(
                entry.payload.as_slice()
                    == after.records.get(id).expect("record").payload.as_slice(),
                "private checkpoint changed across reopen"
            );
            let root = entry.payload.get(10490..10522).expect("owned session root");
            let disk = fs::read(dir.join("state.redb")).expect("database bytes");
            assert!(
                !disk.windows(root.len()).any(|window| window == root),
                "raw root persisted"
            );
        }
        let outcome = i.finish(&reply, 150).expect("confirmation");
        let final_wire = outcome.final_message();
        assert_eq!(
            store
                .finish(Arc::clone(&f.responder), &initial, final_wire, 150)
                .expect("durable complete"),
            outcome.pending_session().id()
        );
        drop(store);
        let mut store = reopen(&dir, f.local_device());
        assert_eq!(
            store.status(&f.responder, &initial).expect("query"),
            DurableStatus::Complete
        );
        assert_eq!(
            store
                .finish(Arc::clone(&f.responder), &initial, final_wire, 150)
                .expect("exact duplicate"),
            outcome.pending_session().id()
        );
        let mut changed = final_wire.to_vec();
        *changed.last_mut().expect("tag") ^= 1;
        assert!(matches!(
            store.finish(Arc::clone(&f.responder), &initial, &changed, 150),
            Err(DurableError::Protocol(Error::Conflict))
        ));
        f.close_responder_policy();
        assert_eq!(
            store
                .status(&f.responder, &initial)
                .expect("reconcile even after revocation"),
            DurableStatus::Complete
        );
        assert!(matches!(
            store.resume(Arc::clone(&f.responder), &initial, 150),
            Err(DurableError::Protocol(Error::Closed))
        ));
    }
}

#[test]
fn invalid_inputs_never_consume_prekeys_and_second_valid_initial_conflicts() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    let mut store = new_store(&dir, f.local_device());
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire");
    let mut bad_signature = initial.to_vec();
    *bad_signature.last_mut().expect("signature") ^= 1;
    let (pq, classic) = f.sources();
    assert!(matches!(
        store.respond(
            Arc::clone(&f.responder),
            &bad_signature,
            &f.signer_r,
            pq,
            classic,
            150
        ),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert!(store.image().expect("image").records.is_empty());
    let (body, _) = open_envelope(initial).expect("body");
    let mut bad_mac = body.to_vec();
    *bad_mac.last_mut().expect("MAC") ^= 1;
    let bad_mac = envelope(
        &bad_mac,
        &f.signer_i
            .sign(Purpose::BootstrapInitiator, &bad_mac)
            .expect("sign"),
    )
    .expect("wire");
    assert!(matches!(
        store.respond(
            Arc::clone(&f.responder),
            &bad_mac,
            &f.signer_r,
            pq,
            classic,
            150
        ),
        Err(DurableError::Protocol(Error::Authentication))
    ));
    assert_eq!(
        store.status(&f.responder, &bad_mac).expect("query"),
        DurableStatus::Rejected
    );
    assert!(store
        .image()
        .expect("image")
        .records
        .values()
        .all(|r| r.keys.is_empty()));
    store
        .respond(
            Arc::clone(&f.responder),
            initial,
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("valid input after failure");
    let other = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
        .expect("another initial");
    assert!(matches!(
        store.respond(
            Arc::clone(&f.responder),
            other.initial_message(150).expect("wire"),
            &f.signer_r,
            pq,
            classic,
            150
        ),
        Err(DurableError::PrekeyClaimed)
    ));
}

#[test]
fn a_new_signed_manifest_cannot_relabel_a_consumed_public_key() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    let mut store = new_store(&dir, f.local_device());
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let (pq, classic) = f.sources();
    store
        .respond(
            Arc::clone(&f.responder),
            i.initial_message(150).expect("wire"),
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("first consumption");
    let (next_i, next_r) = f.next_bundle_epoch();
    assert_ne!(next_r.digest(), f.responder.digest());
    let next = InitiatorOperation::start(next_i, &f.signer_i, 150).expect("next epoch initial");
    let initial = next.initial_message(150).expect("wire");
    assert!(matches!(
        store.respond(Arc::clone(&next_r), initial, &f.signer_r, pq, classic, 150),
        Err(DurableError::PrekeyClaimed)
    ));
    // Controlled comparison: these are valid primitive/identity inputs. The
    // earlier consumption in the authoritative journal causes the rejection.
    let empty = directory();
    let empty_dir = empty.path().canonicalize().expect("canonical");
    new_store(&empty_dir, f.local_device())
        .respond(next_r, initial, &f.signer_r, pq, classic, 150)
        .expect("otherwise valid second manifest");
}

#[test]
fn protected_file_key_and_ciphertext_failures_are_not_implicit_genesis() {
    let f = fixture(PrekeyQuality::ReusableBoth);
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    assert!(JournalKey::open(&dir.join("key")).is_err());
    let store = new_store(&dir, f.local_device());
    assert!(matches!(
        ResponderJournal::open(
            &dir.join("state.redb"),
            JournalKey::open(&dir.join("key")).expect("key"),
            f.local_device(),
            identity(&dir)
        ),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    assert!(JournalKey::provision(&dir.join("key")).is_err());
    drop(store);
    let wrong = JournalKey::provision(&dir.join("wrong-key")).expect("other key");
    assert!(matches!(
        ResponderJournal::open(
            &dir.join("state.redb"),
            wrong,
            f.local_device(),
            identity(&dir)
        ),
        Err(DurableError::Authentication)
    ));
    std::os::unix::fs::symlink(dir.join("state.redb"), dir.join("alias")).expect("symlink");
    assert!(ResponderJournal::open(
        &dir.join("alias"),
        JournalKey::open(&dir.join("key")).expect("key"),
        f.local_device(),
        identity(&dir)
    )
    .is_err());
    assert!(matches!(
        ResponderJournal::open(
            &dir.join("state.redb"),
            JournalKey::open(&dir.join("key")).expect("key"),
            f.local_device(),
            JournalIdentity::from_trusted_state([1; 32]).expect("other store")
        ),
        Err(DurableError::Conflict)
    ));
    let mut store = reopen(&dir, f.local_device());
    let image = store.image().expect("image");
    let active = store.active.as_ref().expect("active");
    let original = seal(&active.key, &image).expect("seal");
    for offset in [8, 80, HEADER, original.len() - 1] {
        let mut corrupt = original.clone();
        *corrupt.get_mut(offset).expect("field") ^= 1;
        assert!(matches!(
            unseal(&active.key, active.owner, &corrupt),
            Err(DurableError::Authentication)
        ));
    }
    let mut changed_owner = image.owner;
    *changed_owner.first_mut().expect("owner") ^= 1;
    assert!(matches!(
        unseal(&active.key, changed_owner, &original),
        Err(DurableError::Conflict)
    ));
    let tx = transaction(&active.db).expect("tx");
    {
        let mut table = tx.open_table(TABLE).expect("table");
        let mut corrupt = original;
        *corrupt.last_mut().expect("tag") ^= 1;
        table.insert("image", corrupt.as_slice()).expect("write");
    }
    tx.commit().expect("commit tamper");
    assert!(matches!(store.image(), Err(DurableError::Authentication)));
    assert!(store.active.is_none());
}

#[test]
fn authenticated_but_invalid_checkpoint_closes_the_journal() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    let mut store = new_store(&dir, f.local_device());
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire");
    let (pq, classic) = f.sources();
    store
        .respond(
            Arc::clone(&f.responder),
            initial,
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("response");
    // Simulate an authenticated writer/serialization defect, distinct from a
    // ciphertext-bit change. The restored protocol must still validate itself.
    let mut image = store.image().expect("image");
    let record = image.records.values_mut().next().expect("record");
    *record
        .payload
        .get_mut(40 + 5817 + 4633 - 1)
        .expect("response signature") ^= 1;
    store
        .persist(&mut image)
        .expect("seal defective checkpoint");
    assert!(matches!(
        store.resume(Arc::clone(&f.responder), initial, 150),
        Err(DurableError::InvalidCheckpoint(Error::Authentication))
    ));
    assert!(store.active.is_none());
}

#[derive(Debug)]
struct FaultBackend {
    inner: FileBackend,
    remaining: Arc<AtomicUsize>,
    count: Arc<AtomicUsize>,
    after_sync: bool,
    fail_write: Arc<std::sync::atomic::AtomicBool>,
}
impl StorageBackend for FaultBackend {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.inner.read(offset, len)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.fail_write.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected pre-write error"));
        }
        self.inner.write(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn sync_data(&self, eventual: bool) -> io::Result<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let last = self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .ok()
            == Some(1);
        if last && !self.after_sync {
            return Err(io::Error::other("injected pre-sync error"));
        }
        self.inner.sync_data(eventual)?;
        if last {
            Err(io::Error::other("injected lost sync acknowledgement"))
        } else {
            Ok(())
        }
    }
}
fn fault_store(
    dir: &Path,
    device: &VerifiedDevice,
    after_sync: bool,
) -> (
    ResponderJournal,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let file = open_private_file(&dir.join("state.redb"), false).expect("private file");
    let remaining = Arc::new(AtomicUsize::new(0));
    let count = Arc::new(AtomicUsize::new(0));
    let fail_write = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let db = Database::builder()
        .create_with_backend(FaultBackend {
            inner: FileBackend::new(file).expect("lock"),
            remaining: Arc::clone(&remaining),
            count: Arc::clone(&count),
            after_sync,
            fail_write: Arc::clone(&fail_write),
        })
        .expect("fault backend");
    let key = JournalKey::open(&dir.join("key")).expect("key");
    let owner = bootstrap::storage_owner(device);
    let image = load(&db, &key, owner).expect("existing authenticated image");
    count.store(0, Ordering::SeqCst);
    (
        ResponderJournal {
            active: Some(Active {
                db,
                key,
                owner,
                id: image.id,
            }),
        },
        remaining,
        count,
        fail_write,
    )
}

#[test]
fn every_sync_cut_closes_the_store_and_reconciles_without_repeating_crypto() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire");
    let (pq, classic) = f.sources();
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    drop(new_store(&dir, f.local_device()));
    let (mut normal, _, count, _) = fault_store(&dir, f.local_device(), false);
    normal
        .respond(
            Arc::clone(&f.responder),
            initial,
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("normal durable response");
    let syncs = count.load(Ordering::SeqCst);
    assert!(syncs >= 6, "three two-phase commits must sync");
    drop(normal);
    let mut statuses = BTreeSet::new();
    for after_sync in [false, true] {
        for cut in 1..=syncs {
            let folder = directory();
            let dir = folder.path().canonicalize().expect("canonical");
            drop(new_store(&dir, f.local_device()));
            let (mut store, remaining, _, _) = fault_store(&dir, f.local_device(), after_sync);
            remaining.store(cut, Ordering::SeqCst);
            assert!(
                matches!(
                    store.respond(
                        Arc::clone(&f.responder),
                        initial,
                        &f.signer_r,
                        pq,
                        classic,
                        150
                    ),
                    Err(DurableError::CommitUncertain(_))
                ),
                "cut={cut} after_sync={after_sync}"
            );
            assert!(store.active.is_none(), "uncertain writer stayed active");
            let mut recovered = reopen(&dir, f.local_device());
            let status = recovered
                .status(&f.responder, initial)
                .expect("exact query");
            statuses.insert(status as u8);
            match status {
                DurableStatus::Absent => assert!(matches!(
                    recovered.resume(Arc::clone(&f.responder), initial, 150),
                    Err(DurableError::Absent)
                )),
                DurableStatus::Executing => assert!(matches!(
                    recovered.resume(Arc::clone(&f.responder), initial, 150),
                    Err(DurableError::Suspended)
                )),
                DurableStatus::Prepared | DurableStatus::AwaitingFinal => {
                    recovered
                        .resume(Arc::clone(&f.responder), initial, 150)
                        .expect("replay pinned result");
                }
                _ => unreachable!("response commit cannot install another state"),
            }
        }
    }
    assert!(statuses.contains(&(DurableStatus::Executing as u8)));
    assert!(statuses.contains(&(DurableStatus::Prepared as u8)));
    assert!(statuses.contains(&(DurableStatus::AwaitingFinal as u8)));
    eprintln!(
        "durable sync fault matrix: sync_points={syncs}, cases={}, recovered={statuses:?}",
        syncs * 2
    );
}

#[test]
fn failed_first_write_reconciles_as_absent_before_any_crypto_execution() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire");
    let (pq, classic) = f.sources();
    let folder = directory();
    let dir = folder.path().canonicalize().expect("canonical");
    drop(new_store(&dir, f.local_device()));
    let (mut store, _, _, fail_write) = fault_store(&dir, f.local_device(), false);
    fail_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.respond(
            Arc::clone(&f.responder),
            initial,
            &f.signer_r,
            pq,
            classic,
            150
        ),
        Err(DurableError::CommitUncertain(_))
    ));
    assert!(store.active.is_none());
    let mut recovered = reopen(&dir, f.local_device());
    assert_eq!(
        recovered
            .status(&f.responder, initial)
            .expect("exact absence"),
        DurableStatus::Absent
    );
    recovered
        .respond(
            Arc::clone(&f.responder),
            initial,
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("safe first execution after exact absence");
}

#[test]
fn final_confirmation_commit_errors_recover_the_same_session_identity() {
    for after_sync in [false, true] {
        for cut in [1, 2] {
            let f = fixture(PrekeyQuality::OneTimeBoth);
            let folder = directory();
            let dir = folder.path().canonicalize().expect("canonical");
            let mut store = new_store(&dir, f.local_device());
            let mut i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
                .expect("initial");
            let initial = i.initial_message(150).expect("wire").to_vec();
            let (pq, classic) = f.sources();
            let reply = store
                .respond(
                    Arc::clone(&f.responder),
                    &initial,
                    &f.signer_r,
                    pq,
                    classic,
                    150,
                )
                .expect("response");
            let outcome = i.finish(&reply, 150).expect("confirmation");
            let mut bad = outcome.final_message().to_vec();
            *bad.last_mut().expect("MAC") ^= 1;
            let revision = store.image().expect("image").revision;
            assert!(matches!(
                store.finish(Arc::clone(&f.responder), &initial, &bad, 150),
                Err(DurableError::Protocol(Error::Authentication))
            ));
            assert_eq!(store.image().expect("unchanged image").revision, revision);
            drop(store);
            let (mut store, remaining, _, _) = fault_store(&dir, f.local_device(), after_sync);
            remaining.store(cut, Ordering::SeqCst);
            assert!(matches!(
                store.finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150
                ),
                Err(DurableError::CommitUncertain(_))
            ));
            assert!(store.active.is_none());
            let mut recovered = reopen(&dir, f.local_device());
            assert!(matches!(
                recovered
                    .status(&f.responder, &initial)
                    .expect("exact query"),
                DurableStatus::AwaitingFinal | DurableStatus::Complete
            ));
            assert_eq!(
                recovered
                    .finish(
                        Arc::clone(&f.responder),
                        &initial,
                        outcome.final_message(),
                        150
                    )
                    .expect("exact confirmation replay"),
                outcome.pending_session().id()
            );
        }
    }
}

pub(super) fn after_commit(image: &Image) {
    let Ok(target) = std::env::var("QPERIAPT_JOURNAL_CRASH_PHASE") else {
        return;
    };
    let record = image.records.values().next().expect("child record");
    if target != (record.phase as u8).to_string() {
        return;
    }
    let directory = std::env::var_os("QPERIAPT_JOURNAL_CRASH_DIR").expect("child directory");
    let marker = Path::new(&directory).join("ready");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .expect("owned marker");
    file.write_all(b"committed\n").expect("marker");
    file.sync_all().expect("sync marker");
    loop {
        std::thread::park();
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_JOURNAL_CRASH_DIR") else {
        return;
    };
    let dir = Path::new(&path);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let public = [
        f.reusable.public_key().expect("public").to_bytes(),
        f.once.public_key().expect("public").to_bytes(),
    ]
    .concat();
    fs::write(dir.join("public-keys"), public).expect("public fixture");
    let mut store = new_store(dir, f.local_device());
    let mut i =
        InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire").to_vec();
    fs::write(dir.join("initial"), &initial).expect("initial fixture");
    let (pq, classic) = f.sources();
    let reply = store
        .respond(
            Arc::clone(&f.responder),
            &initial,
            &f.signer_r,
            pq,
            classic,
            150,
        )
        .expect("respond");
    fs::write(dir.join("returned-reply"), &reply).expect("reply after commit");
    let result = i.finish(&reply, 150).expect("initiator confirmation");
    fs::write(dir.join("final"), result.final_message()).expect("final fixture");
    fs::write(dir.join("session-id"), result.pending_session().id()).expect("public session ID");
    store
        .finish(
            Arc::clone(&f.responder),
            &initial,
            result.final_message(),
            150,
        )
        .expect("complete");
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => eprintln!("owned test child status: {error}"),
        }
        if let Err(error) = self.0.kill() {
            eprintln!("owned test child cleanup: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("owned test child wait: {error}");
        }
    }
}
#[test]
fn process_kill_at_each_committed_boundary_preserves_exact_recovery_and_no_early_output() {
    for phase in [
        DurableStatus::Executing,
        DurableStatus::Prepared,
        DurableStatus::AwaitingFinal,
        DurableStatus::Complete,
    ] {
        let folder = directory();
        let dir = folder.path().canonicalize().expect("canonical");
        let log = fs::File::create(dir.join("child.log")).expect("log");
        let child = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", "durable::tests::crash_child", "--nocapture"])
            .env("QPERIAPT_JOURNAL_CRASH_DIR", &dir)
            .env("QPERIAPT_JOURNAL_CRASH_PHASE", (phase as u8).to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned test process");
        let mut child = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !dir.join("ready").exists() {
            let status = child.0.try_wait().expect("child state");
            if status.is_some() {
                eprintln!(
                    "child failure log: {}",
                    fs::read_to_string(dir.join("child.log")).expect("failure log")
                );
            }
            assert!(
                status.is_none(),
                "child exited before durability boundary: {status:?}"
            );
            assert!(
                Instant::now() < deadline,
                "child did not reach durability boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        if phase != DurableStatus::Complete {
            assert!(
                !dir.join("returned-reply").exists(),
                "response escaped before final commit return"
            );
        }
        child.0.kill().expect("kill exact child");
        assert!(!child.0.wait().expect("reap exact child").success());
        let public = fs::read(dir.join("public-keys")).expect("public fixture");
        let (left, right) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
        let mut f = fixture_from_public(
            PrekeyQuality::OneTimeBoth,
            Some((
                left.try_into().expect("public width"),
                right.try_into().expect("public width"),
            )),
        );
        f.signer_r.close();
        f.reusable.close();
        f.once.close();
        let initial = fs::read(dir.join("initial")).expect("initial fixture");
        let mut store = reopen(&dir, f.local_device());
        assert_eq!(
            store
                .status(&f.responder, &initial)
                .expect("authenticated recovered phase"),
            phase
        );
        if phase == DurableStatus::Executing {
            assert!(matches!(
                store.resume(Arc::clone(&f.responder), &initial, 150),
                Err(DurableError::Suspended)
            ));
        } else {
            let image = store.image().expect("image");
            let record = image.records.values().next().expect("record");
            let expected = record
                .payload
                .get(40 + 5817..40 + 5817 + 4633)
                .expect("pinned reply");
            assert_eq!(
                store
                    .resume(Arc::clone(&f.responder), &initial, 150)
                    .expect("recover without signer or prekeys"),
                expected
            );
            if phase == DurableStatus::Complete {
                let final_wire = fs::read(dir.join("final")).expect("final");
                assert_eq!(
                    store
                        .finish(Arc::clone(&f.responder), &initial, &final_wire, 150)
                        .expect("exact complete replay")
                        .as_slice(),
                    fs::read(dir.join("session-id")).expect("session ID")
                );
            }
        }
    }
}
