// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "renewal_tests.rs"]
pub(crate) mod renewal;
use crate::{
    bootstrap::tests::fixture,
    durable::tests::{
        assert_sync_failure, directory, fault_store, identity, new_store, reopen, ChildGuard,
    },
    tests::interval,
    AccountPin, PrekeyQuality, RootSigningKey, Validity,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(crate) fn update(
    device: &VerifiedDevice,
    seed: u8,
    version: u64,
    keep: bool,
) -> VerifiedRoster {
    update_with_validity(device, seed, version, keep, interval())
}
pub(crate) fn update_with_validity(
    device: &VerifiedDevice,
    seed: u8,
    version: u64,
    keep: bool,
    validity: Validity,
) -> VerifiedRoster {
    let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("account signer");
    assert_eq!(root.account_id().expect("account"), device.account_id());
    let certificate = root
        .issue_device(device.description.clone(), device.key.clone())
        .expect("same credential");
    let members = if keep {
        vec![root.roster_entry(&certificate).expect("member")]
    } else {
        Vec::new()
    };
    let issued = root
        .issue_roster(version, validity, &members)
        .expect("signed update");
    AccountPin::new(
        device.account_id(),
        root.public_key().expect("root"),
        issued.checkpoint(),
        device.description.family,
    )
    .expect("independent updated head")
    .verify_roster(issued.as_bytes(), 150)
    .expect("authenticated roster")
}

#[test]
fn bootstrap_peer_preview_preserves_capacity_and_known_authority_without_writing() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let directory = directory();
    let path = directory.path().canonicalize().expect("path");
    let mut journal = new_store(&path, f.initiator_device());
    for index in 1..MAX_ROSTERS {
        let seed = u8::try_from(index).expect("bounded fixture seed");
        let next = seed.checked_add(1).expect("bounded second seed");
        let root = RootSigningKey::deterministic([seed; 32], [next; 32]).expect("root");
        let issued = root
            .issue_roster(1, interval(), &[])
            .expect("explicit empty roster");
        let pin = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("public"),
            issued.checkpoint(),
            f.initiator
                .current_policy()
                .expect("fixture policy owner")
                .family(),
        )
        .expect("independent pin");
        journal
            .install_roster(
                &pin.verify_roster(issued.as_bytes(), 150)
                    .expect("verified roster"),
                150,
            )
            .expect("fill exact account capacity");
    }
    let before = journal.image().expect("original head");
    assert_eq!(before.record_count(RecordKind::Roster), MAX_ROSTERS);
    authorize_bootstrap_peer(&before, f.initiator_device(), 150)
        .expect("known authority at capacity");
    assert!(matches!(
        journal.prepare_bootstrap_context(
            Arc::clone(&f.initiator),
            crate::BootstrapRole::Initiator,
            150
        ),
        Err(DurableError::Capacity)
    ));
    let after = journal.image().expect("same head");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.digest, before.digest);
    assert!(matches!(
        get(
            &after,
            &f.responder
                .device(crate::BootstrapRole::Responder)
                .account_id()
        ),
        Err(DurableError::Absent)
    ));
}

#[test]
fn every_roster_sync_cut_recovers_the_exact_head_before_new_work() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let device = f.initiator_device();
    let revoked = update(device, 90, 2, false);
    let baseline = directory();
    let path = baseline.path().canonicalize().expect("baseline path");
    new_store(&path, device).close();
    let (mut normal, _, count, _) = fault_store(&path, device, false);
    count.store(0, Ordering::SeqCst);
    normal
        .install_roster(&revoked, 150)
        .expect("baseline update");
    let barriers = count.load(Ordering::SeqCst);
    assert!(
        (4..=32).contains(&barriers),
        "observed barriers: {barriers}"
    );
    normal.close();
    let mut previous_heads = 0;
    let mut recovered_heads = 0;
    for cut in 1..=barriers {
        for after in [false, true] {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            new_store(&path, device).close();
            let (mut failed, remaining, _, _) = fault_store(&path, device, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(failed.install_roster(&revoked, 150), after);
            assert!(failed.active.is_none());
            assert!(matches!(
                failed.roster_checkpoint(device.account_id()),
                Err(DurableError::Closed)
            ));
            let mut restored = reopen(&path, device);
            let head = restored
                .roster_checkpoint(device.account_id())
                .expect("reconciled head");
            let image = restored.image().expect("reconciled image");
            if head == device.roster().checkpoint() {
                previous_heads += 1;
                assert_eq!(image.revision, 1);
            } else {
                recovered_heads += 1;
                assert_eq!(head, revoked.checkpoint());
                assert_eq!(image.revision, 2);
                assert_eq!(
                    get(&image, &device.account_id())
                        .expect("retained")
                        .roster
                        .as_bytes(),
                    revoked.as_bytes()
                );
                assert!(matches!(
                    authorize_device(&image, device, 150),
                    Err(DurableError::Protocol(Error::Scope))
                ));
            }
            restored.install_roster(&revoked, 150).expect("exact retry");
            let image = restored.image().expect("revocation installed");
            assert_eq!(image.revision, 2, "one canonical update only");
            assert_eq!(
                get(&image, &device.account_id())
                    .expect("exact bytes")
                    .roster
                    .as_bytes(),
                revoked.as_bytes()
            );
            assert!(matches!(
                restored.initiate(
                    Arc::clone(&f.initiator),
                    InitiationId::generate().expect("request"),
                    &f.signer_i,
                    150
                ),
                Err(DurableError::Protocol(Error::Scope))
            ));
        }
    }
    assert!(previous_heads > 0 && recovered_heads > 0);
    eprintln!("ROSTER_SYNC_RECOVERY barriers={barriers} faults={} previous={previous_heads} revoked={recovered_heads}", barriers * 2);
}

#[test]
fn replacement_generation_never_reuses_the_old_journal_owner() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let device = f.initiator_device();
    let root = RootSigningKey::deterministic([90; 32], [91; 32]).expect("root");
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut store = new_store(&path, device);
    store
        .install_roster(&update(device, 90, 2, false), 150)
        .expect("remove old generation");
    let mut description = device.description.clone();
    description.generation += 1;
    let replacement_key = DeviceSigningKey::deterministic([120; 32], [121; 32]).expect("new key");
    let certificate = root
        .issue_device(
            description,
            replacement_key.public_key().expect("new public"),
        )
        .expect("replacement credential");
    let members = [root.roster_entry(&certificate).expect("replacement entry")];
    let issued = root
        .issue_roster(3, interval(), &members)
        .expect("replacement roster");
    let pin = AccountPin::new(
        device.account_id(),
        root.public_key().expect("root"),
        issued.checkpoint(),
        device.description.family,
    )
    .expect("replacement pin");
    let roster = pin.verify_roster(issued.as_bytes(), 150).expect("roster");
    let replacement = pin
        .verify_device(&certificate, issued.as_bytes(), 150)
        .expect("new generation");
    store
        .install_roster(&roster, 150)
        .expect("advance generation");
    let image = store.image().expect("installed");
    authorize_device(&image, &replacement, 150).expect("new generation enrolled");
    assert!(matches!(
        authorize_device(&image, device, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        store.install_roster(&update(device, 90, 4, true), 150),
        Err(DurableError::Protocol(Error::Checkpoint))
    ));
    store.close();
    assert!(matches!(
        DeviceJournal::open(
            &path.join("state.redb"),
            JournalKey::open(&path.join("key")).expect("key"),
            &replacement,
            identity(&path)
        ),
        Err(DurableError::Conflict)
    ));
    store = reopen(&path, device);
    assert_eq!(
        store
            .roster_checkpoint(device.account_id())
            .expect("replacement persisted"),
        roster.checkpoint()
    );
    assert!(matches!(
        store.initiate(
            Arc::clone(&f.initiator),
            InitiationId::generate().expect("request"),
            &f.signer_i,
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

#[test]
fn sealed_records_require_canonical_retained_account_references() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut store = new_store(&path, f.initiator_device());
    let request = InitiationId::generate().expect("request");
    store
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("bootstrap");
    for mutation in 0..5 {
        let mut image = store.image().expect("image");
        if mutation == 0 {
            image.records.remove(&id(&f.local_device().account_id()));
        } else {
            let record = image
                .records
                .values_mut()
                .find(|r| r.kind == RecordKind::Initiator)
                .expect("initiator");
            match mutation {
                1 => record.authorities.clear(),
                2 => record.authorities.reverse(),
                3 => record.authorities = vec![image.local_account; 2],
                _ => record.authorities = vec![[0; 32]],
            }
        }
        let active = store.active.as_ref().expect("active");
        let wire = seal(&active.key, &image).expect("authenticated malformed fixture");
        assert!(
            matches!(
                unseal(&active.key, active.owner, &wire),
                Err(DurableError::Corrupt)
            ),
            "mutation {mutation}"
        );
    }
    let mut image = store.image().expect("image");
    let record = image
        .records
        .values_mut()
        .find(|r| r.kind == RecordKind::Initiator)
        .expect("initiator");
    record.authorities = vec![image.local_account];
    assert!(
        matches!(
            initiator::check_request(record, &f.initiator, request),
            Err(DurableError::Conflict)
        ),
        "context cannot drop its peer account"
    );
}

#[test]
fn roster_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ROSTER_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let mut store = new_store(path, f.initiator_device());
    let revoked = update(f.initiator_device(), 90, 2, false);
    fs::write(path.join("revoked-wire"), revoked.as_bytes()).expect("exact public update");
    store.install_roster(&revoked, 150).expect("update");
    fs::write(path.join("returned"), b"returned").expect("unexpected return marker");
}

#[test]
fn process_loss_at_roster_intent_or_commit_recovers_revocation_before_output() {
    for hook in [
        "QPERIAPT_WRITE_INTENT_CRASH_PHASE",
        "QPERIAPT_JOURNAL_CRASH_PHASE",
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "durable::rosters::tests::roster_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_ROSTER_CRASH_DIR", &path)
                .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
                .env(hook, (DurableStatus::Roster as u8).to_string())
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none(),
                "child exited before barrier"
            );
            assert!(Instant::now() < deadline, "roster crash barrier deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("returned").exists());
        child.0.kill().expect("terminate owned child");
        assert!(!child.0.wait().expect("reap child").success());
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let device = f.initiator_device();
        let mut restored = reopen(&path, device);
        let image = restored.image().expect("exact target recovered");
        assert_eq!(image.revision, 2);
        assert_eq!(
            get(&image, &device.account_id())
                .expect("head")
                .roster
                .as_bytes(),
            fs::read(path.join("revoked-wire")).expect("original bytes")
        );
        assert!(matches!(
            restored.initiate(
                Arc::clone(&f.initiator),
                InitiationId::generate().expect("request"),
                &f.signer_i,
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
}
