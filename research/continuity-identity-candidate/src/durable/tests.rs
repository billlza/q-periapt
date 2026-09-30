// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
pub(super) mod provisioning;
use crate::{
    bootstrap::tests::{fixture, fixture_from_public},
    crypto::{envelope, open_envelope, Purpose},
    InitiatorOperation, PrekeyQuality,
};
use q_periapt_host_store::filesystem::LockedFileBackend as FileBackend;
use redb::StorageBackend;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

pub(crate) fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("continuity-journal-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private directory")
}
pub(crate) fn new_store(dir: &Path, device: &VerifiedDevice) -> DeviceJournal {
    let key = JournalKey::provision(&dir.join("key")).expect("provision key");
    let identity = retain_new_identity(&dir.join("store-id"));
    DeviceJournal::provision(&dir.join("state.redb"), key, device, identity)
        .expect("provision store")
}
pub(crate) fn retain_new_identity(path: &Path) -> JournalIdentity {
    let identity = JournalIdentity::generate().expect("new journal identity");
    provisioning::retain_identity(path, identity);
    identity
}
pub(super) fn identity(dir: &Path) -> JournalIdentity {
    JournalIdentity::from_trusted_state(
        fs::read(dir.join("store-id"))
            .expect("independent identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("identity")
}
pub(crate) fn reopen(dir: &Path, device: &VerifiedDevice) -> DeviceJournal {
    DeviceJournal::open(
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
            if entry.kind != RecordKind::Responder {
                continue;
            }
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
    let untouched = store.image().expect("image");
    assert_eq!(untouched.revision, 1);
    assert!(rosters::is_genesis(&untouched, f.local_device()).expect("genesis authority"));
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
        DeviceJournal::open(
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
        DeviceJournal::open(
            &dir.join("state.redb"),
            wrong,
            f.local_device(),
            identity(&dir)
        ),
        Err(DurableError::Authentication)
    ));
    std::os::unix::fs::symlink(dir.join("state.redb"), dir.join("alias")).expect("symlink");
    assert!(DeviceJournal::open(
        &dir.join("alias"),
        JournalKey::open(&dir.join("key")).expect("key"),
        f.local_device(),
        identity(&dir)
    )
    .is_err());
    assert!(matches!(
        DeviceJournal::open(
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
    let record = image
        .records
        .values_mut()
        .find(|r| r.kind == RecordKind::Responder)
        .expect("record");
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
struct InjectedSyncFault {
    after_sync: bool,
}
impl fmt::Display for InjectedSyncFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.after_sync {
            "injected lost sync acknowledgement"
        } else {
            "injected pre-sync error"
        })
    }
}
impl std::error::Error for InjectedSyncFault {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SyncFailureSite {
    Commit,
    BeforeCommit,
}
/// redb may sync a growing allocation during insert, before commit() is called.
/// Accept only this test backend's exact typed injected I/O error, and keep its
/// before/after-sync identity; unrelated storage and protocol errors must fail.
pub(crate) fn assert_sync_failure<T>(
    result: Result<T, DurableError>,
    after_sync: bool,
) -> SyncFailureSite {
    let (site, error) = match result {
        Err(DurableError::CommitUncertain(redb::CommitError::Storage(redb::StorageError::Io(
            error,
        )))) => Ok((SyncFailureSite::Commit, error)),
        Err(DurableError::Storage(error)) => match *error {
            redb::Error::Io(error) => Ok((SyncFailureSite::BeforeCommit, error)),
            error => Err(format!("unexpected non-I/O storage failure: {error:?}")),
        },
        Err(error) => Err(format!(
            "unexpected failure instead of injected sync: {error:?}"
        )),
        Ok(_) => Err("injected sync fault did not fail the operation".to_owned()),
    }
    .expect("operation must return the injected storage or commit I/O fault");
    let injected = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<InjectedSyncFault>())
        .expect("the exact injected I/O fault must be preserved");
    assert_eq!(injected.after_sync, after_sync);
    site
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
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(offset, out)
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
    fn try_lock_range(
        &self,
        start: std::ops::Bound<u64>,
        end: std::ops::Bound<u64>,
    ) -> Result<bool, redb::BackendError> {
        self.inner.try_lock_range(start, end)
    }
    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let last = self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .ok()
            == Some(1);
        if last && std::env::var_os("QPERIAPT_TRACE_SYNC_FAULT").is_some() {
            eprintln!(
                "injected sync boundary: {}",
                std::backtrace::Backtrace::force_capture()
            );
        }
        if last && !self.after_sync {
            return Err(io::Error::other(InjectedSyncFault { after_sync: false }));
        }
        self.inner.sync_data()?;
        if last {
            Err(io::Error::other(InjectedSyncFault { after_sync: true }))
        } else {
            Ok(())
        }
    }
}
pub(super) fn fault_store(
    dir: &Path,
    device: &VerifiedDevice,
    after_sync: bool,
) -> (
    DeviceJournal,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let (db, remaining, count, fail_write) = fault_database(dir, after_sync);
    let key = JournalKey::open(&dir.join("key")).expect("key");
    let owner = bootstrap::storage_owner(device);
    let image = load(&db, &key, owner).expect("existing authenticated image");
    (
        DeviceJournal {
            active: Some(Active {
                db,
                key,
                owner,
                id: image.id,
                protection: image.protection,
                anchor: None,
            }),
        },
        remaining,
        count,
        fail_write,
    )
}
pub(super) fn fault_database(
    dir: &Path,
    after_sync: bool,
) -> (
    Database,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    fault_database_path(&dir.join("state.redb"), after_sync)
}
pub(crate) fn fault_database_path(
    path: &Path,
    after_sync: bool,
) -> (
    Database,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let file = open_private_file(path, false).expect("private file");
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
    count.store(0, Ordering::SeqCst);
    (db, remaining, count, fail_write)
}

#[test]
fn every_sync_cut_reconciles_exact_reserved_responder_computations() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let i = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
    let initial = i.initial_message(150).expect("wire");
    let saved_i = i.checkpoint().expect("original initiator state");
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
    assert_eq!(
        syncs, 20,
        "five intent/state pairs each use two two-phase commits"
    );
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
            let reply = match status {
                DurableStatus::Absent => {
                    assert!(matches!(
                        recovered.resume(Arc::clone(&f.responder), initial, 150),
                        Err(DurableError::Absent)
                    ));
                    continue;
                }
                DurableStatus::Executing => recovered
                    .respond(
                        Arc::clone(&f.responder),
                        initial,
                        &f.signer_r,
                        pq,
                        classic,
                        150,
                    )
                    .expect("repeat deterministic initial authentication"),
                DurableStatus::ResponseKemReserved | DurableStatus::ResponseSignatureReserved => {
                    recovered
                        .resume_response(Arc::clone(&f.responder), initial, &f.signer_r, 150)
                        .expect("same sealed contribution")
                }
                DurableStatus::Prepared | DurableStatus::AwaitingFinal => recovered
                    .resume(Arc::clone(&f.responder), initial, 150)
                    .expect("same pinned result"),
                _ => unreachable!("response commit cannot install another state"),
            };
            let mut peer =
                InitiatorOperation::restore_checkpoint(Arc::clone(&f.initiator), &saved_i)
                    .expect("original private initiator state");
            let outcome = peer.finish(&reply, 150).expect("real reply confirmation");
            assert_eq!(
                recovered
                    .finish(
                        Arc::clone(&f.responder),
                        initial,
                        outcome.final_message(),
                        150
                    )
                    .expect("real final confirmation"),
                outcome.pending_session().id()
            );
        }
    }
    assert!(statuses.contains(&(DurableStatus::Executing as u8)));
    assert!(statuses.contains(&(DurableStatus::ResponseKemReserved as u8)));
    assert!(statuses.contains(&(DurableStatus::ResponseSignatureReserved as u8)));
    assert!(statuses.contains(&(DurableStatus::Prepared as u8)));
    assert!(statuses.contains(&(DurableStatus::AwaitingFinal as u8)));
    eprintln!(
        "durable sync fault matrix: sync_points={syncs}, cases={}, recovered={statuses:?}",
        syncs * 2
    );
}

#[test]
fn staged_response_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_RESPONSE_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let public = [
        f.reusable.public_key().expect("public").to_bytes(),
        f.once.public_key().expect("public").to_bytes(),
    ]
    .concat();
    fs::write(path.join("keys-ready"), public).expect("public keys");
    fs::rename(path.join("keys-ready"), path.join("peer-public")).expect("publish public keys");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("peer-initial").exists() {
        assert!(Instant::now() < deadline, "initial deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    let initial = fs::read(path.join("peer-initial")).expect("live peer initial");
    let mut store = new_store(path, f.local_device());
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
    fs::write(path.join("reply-ready"), &reply).expect("committed response");
    fs::rename(path.join("reply-ready"), path.join("returned-response")).expect("publish reply");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("peer-final").exists() {
        assert!(Instant::now() < deadline, "final deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    let final_wire = fs::read(path.join("peer-final")).expect("live peer final");
    let session = store
        .finish(Arc::clone(&f.responder), &initial, &final_wire, 150)
        .expect("confirm");
    fs::write(path.join("returned-session"), session).expect("session after commit");
}

#[test]
fn eight_responder_process_cuts_preserve_exact_response_and_live_peer_confirmation() {
    let cuts = [
        DurableStatus::Executing,
        DurableStatus::ResponseKemReserved,
        DurableStatus::ResponseSignatureReserved,
        DurableStatus::Prepared,
        DurableStatus::AwaitingFinal,
        DurableStatus::Complete,
    ]
    .into_iter()
    .map(|phase| (phase, false))
    .chain([
        (DurableStatus::ResponseKemReserved, true),
        (DurableStatus::ResponseSignatureReserved, true),
    ]);
    for (phase, after_effect) in cuts {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let child = Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::tests::staged_response_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_RESPONSE_CRASH_DIR", &path)
            .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
            .env(
                if after_effect {
                    "QPERIAPT_RESPONSE_CRASH_EFFECT"
                } else {
                    "QPERIAPT_JOURNAL_CRASH_PHASE"
                },
                (phase as u8).to_string(),
            )
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned responder");
        let mut child = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("peer-public").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "public enrollment deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let public = fs::read(path.join("peer-public")).expect("public enrollment");
        let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
        let mut f = fixture_from_public(
            PrekeyQuality::OneTimeBoth,
            Some((
                a.try_into().expect("public width"),
                b.try_into().expect("public width"),
            )),
        );
        // These local dummy prekeys are unrelated to the child. Recovery must
        // use the committed authenticated contribution, not another private key.
        f.reusable.close();
        f.once.close();
        if matches!(
            phase,
            DurableStatus::Prepared | DurableStatus::AwaitingFinal | DurableStatus::Complete
        ) {
            f.signer_r.close(); // Pinned/committed recovery must not need the signer either.
        }
        let mut peer = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
            .expect("live initiator");
        let initial = peer.initial_message(150).expect("initial").to_vec();
        fs::write(path.join("initial-ready"), &initial).expect("initial");
        fs::rename(path.join("initial-ready"), path.join("peer-initial")).expect("publish initial");
        while !path.join("ready").exists() {
            let status = child.0.try_wait().expect("status");
            if status.is_some() {
                eprintln!(
                    "child log: {}",
                    fs::read_to_string(path.join("child.log")).expect("failure log")
                );
            }
            assert!(
                status.is_none() && Instant::now() < deadline,
                "responder did not reach {phase:?}"
            );
            if path.join("returned-response").exists() && !path.join("peer-final").exists() {
                let reply = fs::read(path.join("returned-response")).expect("committed reply");
                let final_wire = peer
                    .finish(&reply, 150)
                    .expect("live response MAC")
                    .final_message();
                fs::write(path.join("final-ready"), final_wire).expect("final");
                fs::rename(path.join("final-ready"), path.join("peer-final"))
                    .expect("publish final");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !path.join("returned-session").exists(),
            "session escaped before commit return"
        );
        if phase != DurableStatus::Complete {
            assert!(
                !path.join("returned-response").exists(),
                "reply escaped before outbox commit return"
            );
        }
        child.0.kill().expect("kill exact process");
        assert!(!child.0.wait().expect("reap").success());
        let mut store = reopen(&path, f.local_device());
        assert_eq!(store.status(&f.responder, &initial).expect("phase"), phase);
        if phase == DurableStatus::Executing {
            assert!(matches!(
                store.resume_response(Arc::clone(&f.responder), &initial, &f.signer_r, 150),
                Err(DurableError::Suspended)
            ));
            continue; // Original prekey recovery remains a separate obligation.
        }
        let pinned_reply = if matches!(
            phase,
            DurableStatus::Prepared | DurableStatus::AwaitingFinal | DurableStatus::Complete
        ) {
            let image = store.image().expect("pinned image");
            Some(
                image
                    .records
                    .get(&operation_id(&f.responder.digest(), &initial))
                    .expect("record")
                    .payload
                    .get(40 + 5817..40 + 5817 + 4633)
                    .expect("exact pinned reply")
                    .to_vec(),
            )
        } else {
            None
        };
        let reply = store
            .resume_response(Arc::clone(&f.responder), &initial, &f.signer_r, 150)
            .expect("recover without original prekeys");
        if let Some(expected) = pinned_reply {
            assert_eq!(reply, expected);
        }
        if after_effect {
            let expected =
                fs::read(path.join("computed-response")).expect("pre-crash public output");
            let actual = if phase == DurableStatus::ResponseKemReserved {
                open_envelope(&reply).expect("envelope").0
            } else {
                reply.as_slice()
            };
            assert_eq!(actual, expected);
        }
        let outcome = peer
            .finish(&reply, 150)
            .expect("same live initiator confirms recovered response");
        assert_eq!(
            store
                .finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150
                )
                .expect("real final MAC"),
            outcome.pending_session().id()
        );
        assert_eq!(
            store
                .resume(Arc::clone(&f.responder), &initial, 150)
                .expect("exact replay"),
            reply
        );
    }
}

#[test]
fn reserved_response_keeps_claims_and_rejects_corruption_without_original_prekeys() {
    for corrupt in [false, true] {
        let mut f = fixture(PrekeyQuality::OneTimeBoth);
        let mut peer =
            InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("initial");
        let initial = peer.initial_message(150).expect("wire").to_vec();
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        drop(new_store(&path, f.local_device()));
        let (mut store, fault, _, _) = fault_store(&path, f.local_device(), true);
        fault.store(8, Ordering::SeqCst); // Fail after the contribution state's second sync.
        let (pq, classic) = f.sources();
        assert!(matches!(
            store.respond(
                Arc::clone(&f.responder),
                &initial,
                &f.signer_r,
                pq,
                classic,
                150
            ),
            Err(DurableError::CommitUncertain(_))
        ));
        let mut store = reopen(&path, f.local_device());
        assert_eq!(
            store.status(&f.responder, &initial).expect("phase"),
            DurableStatus::ResponseKemReserved
        );
        let before = store.image().expect("image");
        let other = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
            .expect("other initial");
        assert!(matches!(
            store.respond(
                Arc::clone(&f.responder),
                other.initial_message(150).expect("other wire"),
                &f.signer_r,
                pq,
                classic,
                150
            ),
            Err(DurableError::PrekeyClaimed)
        ));
        assert!(matches!(
            store.resume_response(Arc::clone(&f.responder), &initial, &f.signer_i, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        f.reusable.close();
        f.once.close();
        f.signer_r.close();
        assert!(matches!(
            store.resume_response(Arc::clone(&f.responder), &initial, &f.signer_r, 150),
            Err(DurableError::Protocol(Error::Closed))
        ));
        let after = store.image().expect("retained record");
        assert_eq!(before.revision, after.revision);
        let op = operation_id(&f.responder.digest(), &initial);
        assert_eq!(
            before
                .records
                .get(&op)
                .expect("original")
                .payload
                .as_slice(),
            after.records.get(&op).expect("retained").payload.as_slice()
        );
        let signer = fixture(PrekeyQuality::OneTimeBoth).signer_r; // Same protected signer fixture, not the lost prekeys.
        if corrupt {
            let mut image = after;
            *image
                .records
                .get_mut(&op)
                .expect("record")
                .payload
                .last_mut()
                .expect("KEM token tag") ^= 1;
            store
                .persist(&mut image)
                .expect("authenticated writer defect");
            assert!(matches!(
                store.resume_response(Arc::clone(&f.responder), &initial, &signer, 150),
                Err(DurableError::InvalidCheckpoint(Error::Runtime(
                    q_periapt_sdk::Error::InvalidPrivateKey
                )))
            ));
            assert!(store.active.is_none());
        } else {
            drop(store);
            let mut store = reopen(&path, f.local_device());
            let reply = store
                .resume_response(Arc::clone(&f.responder), &initial, &signer, 150)
                .expect("same contribution without prekeys");
            let outcome = peer.finish(&reply, 150).expect("real response MAC");
            assert_eq!(
                store
                    .finish(
                        Arc::clone(&f.responder),
                        &initial,
                        outcome.final_message(),
                        150
                    )
                    .expect("real final MAC"),
                outcome.pending_session().id()
            );
        }
    }
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
    let measured_fixture = fixture(PrekeyQuality::OneTimeBoth);
    let measured_dir = directory();
    let measured_path = measured_dir.path().canonicalize().expect("path");
    let mut measured = new_store(&measured_path, measured_fixture.local_device());
    let mut initial_operation = InitiatorOperation::start(
        Arc::clone(&measured_fixture.initiator),
        &measured_fixture.signer_i,
        150,
    )
    .expect("initial");
    let initial = initial_operation
        .initial_message(150)
        .expect("wire")
        .to_vec();
    let (pq, classic) = measured_fixture.sources();
    let reply = measured
        .respond(
            Arc::clone(&measured_fixture.responder),
            &initial,
            &measured_fixture.signer_r,
            pq,
            classic,
            150,
        )
        .expect("reply");
    let final_outcome = initial_operation.finish(&reply, 150).expect("final");
    measured.close();
    let (mut measured, _, count, _) =
        fault_store(&measured_path, measured_fixture.local_device(), false);
    measured
        .finish(
            Arc::clone(&measured_fixture.responder),
            &initial,
            final_outcome.final_message(),
            150,
        )
        .expect("count final barriers");
    let syncs = count.load(Ordering::SeqCst);
    assert!((4..=64).contains(&syncs));
    for after_sync in [false, true] {
        for cut in 1..=syncs {
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
            assert_sync_failure(
                store.finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150,
                ),
                after_sync,
            );
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
    if !image
        .records
        .values()
        .any(|record| target == (record.phase as u8).to_string())
    {
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

pub(super) fn after_response_effect(phase: u8, public_output: &[u8]) {
    let Ok(target) = std::env::var("QPERIAPT_RESPONSE_CRASH_EFFECT") else {
        return;
    };
    if target != phase.to_string() {
        return;
    }
    let path = std::env::var_os("QPERIAPT_JOURNAL_CRASH_DIR").expect("owned directory");
    let path = Path::new(&path);
    fs::write(path.join("computed-response"), public_output).expect("public result");
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("ready"))
        .expect("marker");
    ready.write_all(b"computed\n").expect("marker data");
    ready.sync_all().expect("marker sync");
    loop {
        std::thread::park();
    }
}

pub(crate) struct ChildGuard(pub(crate) std::process::Child);
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
