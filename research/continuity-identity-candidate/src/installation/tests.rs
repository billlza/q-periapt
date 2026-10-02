// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, Fixture},
    durable::tests::{assert_sync_failure, directory, fault_database_path, ChildGuard},
    DurableStatus, InitiationId,
};
use q_periapt_host_store::filesystem::PrivateDatabaseError;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

mod recovery;
mod reopen;

fn paths(root: &Path) -> InstallationPaths {
    InstallationPaths::new(
        &root.join("installation.redb"),
        &root.join("state.redb"),
        &root.join("archives.redb"),
    )
    .expect("configured paths")
}
fn key(root: &Path) -> JournalKey {
    JournalKey::open(&root.join("key")).expect("original key")
}
fn create(root: &Path, f: &Fixture) -> DeviceInstallation {
    DeviceInstallation::provision(
        paths(root),
        &key(root),
        f.initiator_device(),
        f.initiator.policy(),
        150,
    )
    .expect("explicit initialization")
}
fn open(root: &Path, f: &Fixture) -> DeviceInstallation {
    DeviceInstallation::open(
        paths(root),
        &key(root),
        f.initiator_device(),
        f.initiator.policy(),
        150,
    )
    .expect("same authoritative intent")
}
fn prepare(owner: &mut DeviceInstallation, root: &Path, f: &Fixture) {
    assert!(matches!(
        owner
            .prepare(key(root), f.initiator_device(), f.initiator.policy(), 150)
            .expect("exact preparation"),
        InstallationPreparation::Local
    ));
}
fn activate(owner: DeviceInstallation, root: &Path, f: &Fixture) -> DeviceService {
    owner
        .activate(
            key(root),
            f.initiator_device(),
            f.initiator.policy(),
            150,
            None,
        )
        .expect("active owner")
}

#[test]
fn installation_retains_identity_before_children_and_releases_only_after_activation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    assert!(DeviceInstallation::open(
        paths(&root),
        &key(&root),
        f.initiator_device(),
        f.initiator.policy(),
        150
    )
    .is_err());
    assert!(!paths(&root).configuration.exists());
    let mut owner = create(&root, &f);
    let id = owner.identity().expect("retained ID");
    assert_eq!(owner.status().expect("phase"), InstallationStatus::Creating);
    assert!(!paths(&root).journal.exists() && !paths(&root).archives.exists());
    owner.close();
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    owner = open(&root, &f);
    assert_eq!(owner.identity().expect("same ID"), id);
    prepare(&mut owner, &root, &f);
    prepare(&mut owner, &root, &f);
    let mut service = activate(owner, &root, &f);
    assert!(matches!(
        DeviceInstallation::open(
            paths(&root),
            &key(&root),
            f.initiator_device(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    let request = InitiationId::from_trusted_state([77; 32]).expect("request");
    let (journal, archives) = service.stores().expect("owned protocol engines");
    assert_eq!(journal.identity().expect("journal ID"), id);
    assert!(archives.session_ids().expect("index").is_empty());
    let initial = journal
        .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
        .expect("actual durable outbox");
    service.close();
    assert!(matches!(service.stores(), Err(DurableError::Closed)));
    let mut owner = open(&root, &f);
    assert_eq!(owner.status().expect("phase"), InstallationStatus::Active);
    let mut service = activate(owner, &root, &f);
    let (journal, _) = service.stores().expect("reopened engines");
    assert_eq!(
        journal
            .initiation_status(&f.initiator, request)
            .expect("retained phase"),
        DurableStatus::AwaitingReply
    );
    assert_eq!(
        journal
            .resume_initial(Arc::clone(&f.initiator), request, 150)
            .expect("exact original outbox"),
        initial
    );
}

#[test]
fn installation_active_loss_never_recreates_or_replaces_children() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    for leaf in ["state.redb", "archives.redb"] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        drop(JournalKey::provision(&root.join("key")).expect("key"));
        let mut owner = create(&root, &f);
        prepare(&mut owner, &root, &f);
        let mut running = activate(owner, &root, &f);
        let request = InitiationId::from_trusted_state([78; 32]).expect("request");
        let original = running
            .stores()
            .expect("stores")
            .0
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("committed original outbox");
        running.close();
        fs::rename(root.join(leaf), root.join("retained-original"))
            .expect("simulate missing active child");
        let owner = open(&root, &f);
        assert!(owner
            .activate(
                key(&root),
                f.initiator_device(),
                f.initiator.policy(),
                150,
                None
            )
            .is_err());
        assert!(!root.join(leaf).exists());
        let mut owner = open(&root, &f);
        assert!(matches!(
            owner.prepare(key(&root), f.initiator_device(), f.initiator.policy(), 150),
            Err(DurableError::Conflict)
        ));
        assert!(!root.join(leaf).exists());
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        fs::rename(root.join("retained-original"), root.join(leaf))
            .expect("restore exact original child");
        let mut recovered = activate(open(&root, &f), &root, &f);
        assert_eq!(
            recovered
                .stores()
                .expect("stores")
                .0
                .resume_initial(Arc::clone(&f.initiator), request, 150)
                .expect("same durable outbox"),
            original
        );
    }
}

#[test]
fn installation_invalid_configuration_and_stale_creating_phase_grant_no_service() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    for mutation in [
        "extra-table",
        "unknown-phase",
        "missing-row",
        "stale-creating",
    ] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        drop(JournalKey::provision(&root.join("key")).expect("key"));
        let mut owner = create(&root, &f);
        prepare(&mut owner, &root, &f);
        let scope = owner.scope.clone();
        let mut service = activate(owner, &root, &f);
        let request = InitiationId::from_trusted_state([79; 32]).expect("request");
        service
            .stores()
            .expect("stores")
            .0
            .initiate(Arc::clone(&f.initiator), request, &f.signer_i, 150)
            .expect("journal has operated");
        service.close();
        let db = open_private_database(&paths(&root).configuration).expect("owned test mutation");
        let tx = transaction(&db).expect("transaction");
        match mutation {
            "extra-table" => {
                tx.open_table(TableDefinition::<&str, &[u8]>::new("unknown_table"))
                    .expect("extra");
            }
            "missing-row" => {
                tx.open_table(TABLE)
                    .expect("table")
                    .remove("installation")
                    .expect("remove");
            }
            _ => {
                let mut row = scope;
                row.push(if mutation == "stale-creating" { 1 } else { 9 });
                tx.open_table(TABLE)
                    .expect("table")
                    .insert("installation", row.as_slice())
                    .expect("row");
            }
        }
        tx.commit().expect("commit mutation");
        drop(db);
        let result = DeviceInstallation::open(
            paths(&root),
            &key(&root),
            f.initiator_device(),
            f.initiator.policy(),
            150,
        );
        if mutation == "stale-creating" {
            let owner = result.expect("original scope, older phase");
            assert!(matches!(
                owner.activate(
                    key(&root),
                    f.initiator_device(),
                    f.initiator.policy(),
                    150,
                    None
                ),
                Err(DurableError::Conflict)
            ));
            let mut owner = open(&root, &f);
            assert!(matches!(
                owner.prepare(key(&root), f.initiator_device(), f.initiator.policy(), 150),
                Err(DurableError::Conflict)
            ));
        } else {
            assert!(
                result.is_err(),
                "unsupported configuration accepted: {mutation}"
            );
        }
    }
}

#[test]
fn installation_path_and_policy_failures_precede_child_creation() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    let valid = paths(&root);
    for path in [
        PathBuf::from("relative"),
        root.join("."),
        root.join("../state.redb"),
        root.join("./state.redb"),
        valid.archives.clone(),
    ] {
        assert!(InstallationPaths::new(&valid.configuration, &path, &valid.archives).is_err());
    }
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    let mut owner = create(&root, &f);
    f.initiator.policy().close();
    assert!(matches!(
        owner.prepare(key(&root), f.initiator_device(), f.initiator.policy(), 150),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert!(!valid.journal.exists() && !valid.archives.exists());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
}

#[test]
fn installation_scope_and_partial_state_fail_without_adoption_or_repair() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    let wrong = JournalKey::provision(&root.join("wrong-key")).expect("wrong key");
    let mut owner = create(&root, &f);
    let id = owner.identity().expect("ID");
    owner.close();
    assert!(matches!(
        DeviceInstallation::open(
            paths(&root),
            &wrong,
            f.initiator_device(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert!(DeviceInstallation::open(
        paths(&root),
        &key(&root),
        f.local_device(),
        f.responder.policy(),
        150
    )
    .is_err());
    let changed = InstallationPaths::new(
        &root.join("installation.redb"),
        &root.join("other.redb"),
        &root.join("archives.redb"),
    )
    .expect("changed path");
    assert!(matches!(
        DeviceInstallation::open(
            changed,
            &key(&root),
            f.initiator_device(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert!(!root.join("other.redb").exists());
    fs::write(root.join("state.redb"), b"partial original").expect("partial file");
    owner = open(&root, &f);
    assert!(owner
        .prepare(key(&root), f.initiator_device(), f.initiator.policy(), 150)
        .is_err());
    assert_eq!(
        fs::read(root.join("state.redb")).expect("retained partial"),
        b"partial original"
    );
    assert!(!root.join("archives.redb").exists());
    assert_eq!(open(&root, &f).identity().expect("no ID replacement"), id);
}

#[test]
fn installation_every_activation_sync_fault_returns_no_service_and_reconciles_exact_phase() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    let mut owner = create(&root, &f);
    prepare(&mut owner, &root, &f);
    owner.close();
    let (db, _, count, _) = fault_database_path(&paths(&root).configuration, false);
    owner = DeviceInstallation {
        active: Some(db),
        ..owner
    };
    count.store(0, Ordering::SeqCst);
    let mut measured = activate(owner, &root, &f);
    let barriers = count.load(Ordering::SeqCst);
    measured.close();
    assert!((2..=8).contains(&barriers));
    let mut phases = std::collections::BTreeSet::new();
    for cut in 1..=barriers {
        for after in [false, true] {
            let dir = directory();
            let root = dir.path().canonicalize().expect("path");
            drop(JournalKey::provision(&root.join("key")).expect("key"));
            let mut owner = create(&root, &f);
            let id = owner.identity().expect("ID");
            prepare(&mut owner, &root, &f);
            owner.close();
            let (db, remaining, _, _) = fault_database_path(&paths(&root).configuration, after);
            owner = DeviceInstallation {
                active: Some(db),
                ..owner
            };
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.activate(
                    key(&root),
                    f.initiator_device(),
                    f.initiator.policy(),
                    150,
                    None,
                ),
                after,
            );
            let mut reopened = open(&root, &f);
            phases.insert(reopened.status().expect("authoritative phase").byte());
            assert_eq!(reopened.identity().expect("same identity"), id);
            activate(reopened, &root, &f).close();
            assert_eq!(
                open(&root, &f).status().expect("reconciled"),
                InstallationStatus::Active
            );
        }
    }
    assert_eq!(phases, std::collections::BTreeSet::from([1, 2]));
    eprintln!(
        "INSTALLATION_ACTIVATION_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

pub(super) fn at_boundary(stage: &str) {
    let Some(root) = std::env::var_os("QPERIAPT_INSTALLATION_CUT_DIR") else {
        return;
    };
    if std::env::var("QPERIAPT_INSTALLATION_CUT_STAGE").expect("stage") != stage {
        return;
    }
    let root = Path::new(&root);
    let mut ready = fs::File::create_new(root.join("ready.pending")).expect("owned marker");
    ready.write_all(stage.as_bytes()).expect("marker");
    ready.sync_all().expect("sync");
    fs::rename(root.join("ready.pending"), root.join("ready")).expect("publish complete marker");
    loop {
        std::thread::park();
    }
}

#[test]
fn installation_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os("QPERIAPT_INSTALLATION_CUT_DIR") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let mut owner = create(root, &f);
    prepare(&mut owner, root, &f);
    let _service = activate(owner, root, &f);
    fs::write(root.join("returned-service"), b"unexpected").expect("observation");
    Err("expected process boundary was not reached".into())
}

#[test]
fn installation_busy_child() {
    let Some(root) = std::env::var_os("QPERIAPT_INSTALLATION_BUSY_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    assert!(matches!(
        DeviceInstallation::open(
            paths(root),
            &key(root),
            f.initiator_device(),
            f.initiator.policy(),
            150
        ),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    let stage = std::env::var("QPERIAPT_INSTALLATION_BUSY_STAGE").expect("stage");
    if stage.starts_with("activation-") {
        for path in [paths(root).journal, paths(root).archives] {
            assert!(matches!(
                open_private_database(&path),
                Err(PrivateDatabaseError::Busy)
            ));
        }
    }
}

#[test]
fn installation_process_cuts_preserve_intent_and_prevent_new_lineage() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    for stage in [
        "intent-before-commit",
        "intent",
        "journal",
        "archives",
        "activation-before-commit",
        "activation-after-commit",
    ] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        drop(JournalKey::provision(&root.join("key")).expect("key"));
        let log = fs::File::create_new(root.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::tests::installation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_INSTALLATION_CUT_DIR", &root)
                .env("QPERIAPT_INSTALLATION_CUT_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("child"),
        );
        let deadline = Instant::now() + Duration::from_secs(25);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("state").is_none() && Instant::now() < deadline,
                "boundary {stage}: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-service").exists());
        let busy_log = fs::File::create_new(root.join("contender.log")).expect("contender log");
        let mut contender = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::tests::installation_busy_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_INSTALLATION_BUSY_DIR", &root)
                .env("QPERIAPT_INSTALLATION_BUSY_STAGE", stage)
                .stdout(Stdio::from(busy_log.try_clone().expect("log")))
                .stderr(Stdio::from(busy_log))
                .spawn()
                .expect("competing owner"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = contender.0.try_wait().expect("contender status") {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(root.join("contender.log")).expect("log")
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "competing initialization owner blocked"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().expect("kill at actual boundary");
        child.0.wait().expect("reap");
        if stage == "intent-before-commit" {
            assert!(DeviceInstallation::open(
                paths(&root),
                &key(&root),
                f.initiator_device(),
                f.initiator.policy(),
                150
            )
            .is_err());
            assert!(paths(&root).configuration.exists());
            assert!(!paths(&root).journal.exists() && !paths(&root).archives.exists());
            assert!(DeviceInstallation::provision(
                paths(&root),
                &key(&root),
                f.initiator_device(),
                f.initiator.policy(),
                150
            )
            .is_err());
            eprintln!("INSTALLATION_PROCESS_CUT stage={stage} partial_configuration_refused=true");
            continue;
        }
        let mut owner = open(&root, &f);
        let id = owner.identity().expect("retained identity");
        let phase = owner.status().expect("recovered phase");
        if phase == InstallationStatus::Creating {
            prepare(&mut owner, &root, &f);
        }
        let mut service = activate(owner, &root, &f);
        assert_eq!(
            service
                .stores()
                .expect("owner")
                .0
                .identity()
                .expect("same lineage"),
            id
        );
        service.close();
        assert_eq!(
            open(&root, &f).status().expect("final phase"),
            InstallationStatus::Active
        );
        eprintln!("INSTALLATION_PROCESS_CUT stage={stage} recovered={phase:?}");
    }
}

struct Witness {
    store: crate::AnchorStore,
    calls: usize,
    fail: Option<(usize, bool)>,
}
struct Carrier(Arc<std::sync::Mutex<Witness>>);
impl crate::AnchorTransport for Carrier {
    fn exchange(&mut self, bytes: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        let mut server = self.0.lock().expect("witness lock");
        server.calls += 1;
        if server.fail == Some((server.calls, false)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        let reply = server.store.handle(bytes, 150).map_err(io::Error::other)?;
        if server.fail == Some((server.calls, true)) {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        Ok(reply)
    }
}
struct Anchored {
    _directory: tempfile::TempDir,
    root: PathBuf,
    peer: Fixture,
    pin: crate::AnchorPin,
    server: Arc<std::sync::Mutex<Witness>>,
}
fn required_genesis(preparation: InstallationPreparation) -> Result<AnchorGenesis, &'static str> {
    match preparation {
        InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
        InstallationPreparation::Local => Err("required witness became local-only"),
    }
}
impl Anchored {
    fn new() -> Self {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        let store = crate::AnchorStore::provision(
            &root.join("witness.redb"),
            JournalKey::provision(&root.join("witness-key")).expect("witness key"),
            crate::AnchorSigningKey::generate().expect("signer"),
            crate::AnchorIdentity::generate().expect("witness ID"),
        )
        .expect("witness");
        let pin = store.pin().expect("independent pin");
        let peer = crate::bootstrap::tests::fixture_with_anchor_and_budget(
            PrekeyQuality::OneTimeBoth,
            crate::AnchorRequirement::required(&pin),
            crate::ApplicationSendBudget::new(1024).expect("budget"),
        );
        drop(JournalKey::provision(&root.join("key")).expect("original device key"));
        Self {
            _directory: dir,
            root,
            peer,
            pin,
            server: Arc::new(std::sync::Mutex::new(Witness {
                store,
                calls: 0,
                fail: None,
            })),
        }
    }
    fn client(&self) -> AnchorClient {
        AnchorClient::new(
            self.pin.clone(),
            crate::DeviceSigningKey::deterministic([92; 32], [93; 32])
                .expect("original device signer"),
            Box::new(Carrier(Arc::clone(&self.server))),
            Duration::from_secs(10),
        )
        .expect("client")
    }
    fn prepare(&self) -> DeviceInstallation {
        let mut owner = create(&self.root, &self.peer);
        let mut original = None;
        for _ in 0..2 {
            let genesis = required_genesis(
                owner
                    .prepare(
                        key(&self.root),
                        self.peer.initiator_device(),
                        self.peer.initiator.policy(),
                        150,
                    )
                    .expect("required preparation"),
            )
            .expect("original witness enrollment required");
            if let Some(digest) = original {
                assert_eq!(genesis.image_digest(), digest);
            }
            original = Some(genesis.image_digest());
            self.server
                .lock()
                .expect("server")
                .store
                .enroll(
                    &genesis,
                    self.peer.initiator_device(),
                    self.peer.initiator.policy(),
                    150,
                )
                .expect("explicit exact enrollment");
        }
        assert_eq!(self.server.lock().expect("server").calls, 0);
        owner
    }
    fn activate(&self, owner: DeviceInstallation) -> Result<DeviceService, DurableError> {
        owner.activate(
            key(&self.root),
            self.peer.initiator_device(),
            self.peer.initiator.policy(),
            150,
            Some(self.client()),
        )
    }
}

#[test]
fn installation_required_witness_admission_and_release_refuse_every_lost_request_or_reply() {
    for already_active in [false, true] {
        let c = Anchored::new();
        let mut owner = c.prepare();
        assert!(matches!(
            owner.activate(
                key(&c.root),
                c.peer.initiator_device(),
                c.peer.initiator.policy(),
                150,
                None
            ),
            Err(DurableError::AnchorRequired)
        ));
        owner = open(&c.root, &c.peer);
        if already_active {
            c.activate(owner).expect("baseline activation").close();
            owner = open(&c.root, &c.peer);
        }
        c.server.lock().expect("server").calls = 0;
        c.activate(owner).expect("actual signed baseline").close();
        let calls = c.server.lock().expect("server").calls;
        assert_eq!(calls, if already_active { 3 } else { 5 });
        for call in 1..=calls {
            for after in [false, true] {
                let c = Anchored::new();
                let mut owner = c.prepare();
                if already_active {
                    c.activate(owner).expect("baseline activation").close();
                    owner = open(&c.root, &c.peer);
                }
                let id = owner.identity().expect("original ID");
                {
                    let mut server = c.server.lock().expect("server");
                    server.calls = 0;
                    server.fail = Some((call, after));
                }
                assert!(matches!(c.activate(owner), Err(DurableError::Anchor(_))));
                {
                    let mut server = c.server.lock().expect("server");
                    assert_eq!(server.calls, call);
                    server.fail = None;
                }
                let mut recovered = open(&c.root, &c.peer);
                assert_eq!(recovered.identity().expect("identity"), id);
                assert_eq!(
                    recovered.status().expect("phase after loss"),
                    if already_active || call > 3 {
                        InstallationStatus::Active
                    } else {
                        InstallationStatus::Creating
                    }
                );
                let mut service = c
                    .activate(recovered)
                    .expect("fresh original witness reconciliation");
                assert_eq!(
                    service.stores().expect("stores").0.identity().expect("ID"),
                    id
                );
            }
        }
        eprintln!("INSTALLATION_WITNESS already_active={already_active} calls={calls} request_reply_losses={}", calls*2);
    }
}

#[test]
fn installation_required_genesis_cannot_activate_before_independent_enrollment() {
    let c = Anchored::new();
    let mut owner = create(&c.root, &c.peer);
    let genesis = required_genesis(
        owner
            .prepare(
                key(&c.root),
                c.peer.initiator_device(),
                c.peer.initiator.policy(),
                150,
            )
            .expect("genesis"),
    )
    .expect("original witness enrollment required");
    assert!(c.activate(owner).is_err());
    let mut owner = open(&c.root, &c.peer);
    assert_eq!(owner.status().expect("phase"), InstallationStatus::Creating);
    c.server
        .lock()
        .expect("server")
        .store
        .enroll(
            &genesis,
            c.peer.initiator_device(),
            c.peer.initiator.policy(),
            150,
        )
        .expect("separate enrollment");
    c.activate(owner)
        .expect("fresh query accepts enrolled genesis")
        .close();
}
