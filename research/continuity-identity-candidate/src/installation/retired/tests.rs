// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture_with_anchor_and_budget, Fixture},
    durable::tests::{assert_sync_failure, directory, fault_database_path, ChildGuard},
    AccountPin, AnchorIdentity, AnchorRequirement, AnchorSigningKey, AnchorStore, AnchorTransport,
    ApplicationSendBudget, DeviceSigningKey, RootSigningKey, SigningKeyId,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

struct Transport(Arc<Mutex<AnchorStore>>, Arc<AtomicUsize>);
impl AnchorTransport for Transport {
    fn exchange(&mut self, wire: &[u8], _: Instant) -> io::Result<Vec<u8>> {
        if self.1.load(Ordering::SeqCst) > 0 && self.1.fetch_sub(1, Ordering::SeqCst) == 1 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original request unprocessed",
            ));
        }
        self.0
            .lock()
            .map_err(|_| io::Error::other("witness lock"))?
            .handle(wire, 150)
            .map_err(io::Error::other)
    }
}
struct Case {
    _directory: tempfile::TempDir,
    paths: InstallationPaths,
    key_path: PathBuf,
    peer: Fixture,
    store: Arc<Mutex<AnchorStore>>,
    pin: AnchorPin,
    retired: AnchorRetiredSubject,
}
fn journal_rows(path: &Path) -> Vec<(String, Vec<u8>)> {
    let db = open_private_database(path).expect("closed original journal");
    let tx = db.begin_read().expect("read");
    let table = tx
        .open_table(TableDefinition::<&str, &[u8]>::new(
            "continuity_device_candidate_v21",
        ))
        .expect("original journal table");
    table
        .iter()
        .expect("all rows")
        .map(|row| {
            let (name, bytes) = row.expect("row");
            (name.value().to_owned(), bytes.value().to_vec())
        })
        .collect()
}
impl Case {
    fn key(&self) -> JournalKey {
        JournalKey::open(&self.key_path).expect("original key")
    }
    fn open(&self) -> Result<RetiredInstallationRecovery, DurableError> {
        RetiredInstallationRecovery::open(self.paths.clone(), self.key(), self.retired)
    }
    fn new() -> Self {
        Self::with_pending(false)
    }
    fn with_pending(pending: bool) -> Self {
        let directory = directory();
        let root = directory.path().canonicalize().expect("root");
        let server = root.join("witness");
        let old = root.join("old");
        let new = root.join("new");
        for path in [&server, &old, &new] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .expect("private directory");
        }
        let wrapping = JournalKey::provision(&server.join("key")).expect("witness key");
        let signer = AnchorSigningKey::provision(
            &server.join("signer"),
            &wrapping,
            SigningKeyId::from_trusted_state([63; 32]).expect("signer ID"),
        )
        .expect("signer");
        let instance = AnchorIdentity::generate().expect("instance");
        fs::write(server.join("instance"), instance.as_bytes()).expect("retained witness identity");
        let mut store =
            AnchorStore::provision(&server.join("state.redb"), wrapping, signer, instance)
                .expect("independent witness");
        let pin = store.pin().expect("pin");
        let peer = fixture_with_anchor_and_budget(
            PrekeyQuality::OneTimeBoth,
            AnchorRequirement::required(&pin),
            ApplicationSendBudget::new(1024).expect("budget"),
        );
        let (policy, device, _) = peer
            .responder
            .inventory_inputs()
            .expect("original authority");
        let paths = InstallationPaths::new(
            &old.join("installation.redb"),
            &old.join("state.redb"),
            &old.join("archives.redb"),
        )
        .expect("paths");
        let key_path = old.join("key");
        let key = JournalKey::provision(&key_path).expect("original key");
        let mut installation =
            DeviceInstallation::provision(paths.clone(), &key, device, policy, 150)
                .expect("retain original installation first");
        let preparation = installation
            .prepare(key, device, policy, 150)
            .expect("prepare actual children");
        let genesis = match preparation {
            InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
            InstallationPreparation::Local => Err("unexpected local-only installation"),
        }
        .expect("required witness preparation");
        store
            .enroll(&genesis, device, policy, 150)
            .expect("independent enrollment");
        let store = Arc::new(Mutex::new(store));
        let client = AnchorClient::new(
            pin.clone(),
            DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("original signer"),
            Box::new(Transport(Arc::clone(&store), Arc::new(AtomicUsize::new(0)))),
            Duration::from_secs(5),
        )
        .expect("signed client");
        let mut service = installation
            .activate(
                JournalKey::open(&key_path).expect("key"),
                device,
                policy,
                150,
                Some(client),
            )
            .expect("actual original service");
        service.close();

        if pending {
            fs::copy(
                &paths.journal,
                paths.journal.with_extension("before-pending"),
            )
            .expect("closed backup before real intent");
            let remaining = Arc::new(AtomicUsize::new(0));
            let client = AnchorClient::new(
                pin.clone(),
                DeviceSigningKey::deterministic([96; 32], [97; 32]).expect("same original signer"),
                Box::new(Transport(Arc::clone(&store), Arc::clone(&remaining))),
                Duration::from_secs(5),
            )
            .expect("signed client");
            let installation = DeviceInstallation::open(
                paths.clone(),
                &JournalKey::open(&key_path).expect("key"),
                device,
                policy,
                150,
            )
            .expect("same active installation");
            let mut service = installation
                .activate(
                    JournalKey::open(&key_path).expect("key"),
                    device,
                    policy,
                    150,
                    Some(client),
                )
                .expect("original active service");
            let devices = peer.initiator.devices();
            let remote = devices.first().expect("other account").roster();
            assert_ne!(remote.account_id(), device.account_id());
            // image() performs Current, then persist() seals the actual pending
            // target before its second exchange, Advance. Refuse that exchange.
            remaining.store(2, Ordering::SeqCst);
            assert!(matches!(
                service
                    .stores()
                    .expect("original stores")
                    .0
                    .install_roster(remote, 150),
                Err(DurableError::Anchor(_))
            ));
            assert_eq!(remaining.load(Ordering::SeqCst), 0);
            service.close();
            let rows = journal_rows(&paths.journal);
            assert!(rows.iter().any(|(name, _)| name == "pending"));
            let backup = journal_rows(&paths.journal.with_extension("before-pending"));
            assert!(
                rows.iter().find(|(name, _)| name == "image")
                    == backup.iter().find(|(name, _)| name == "image")
            );
        }

        let root_signer =
            RootSigningKey::deterministic([94; 32], [95; 32]).expect("same account root");
        let next_signer =
            DeviceSigningKey::deterministic([212; 32], [213; 32]).expect("fresh device key");
        let mut description = device.description.clone();
        description.generation = 2;
        let certificate = root_signer
            .issue_device(
                description.clone(),
                next_signer.public_key().expect("public"),
            )
            .expect("new certificate");
        let roster = root_signer
            .issue_roster(
                2,
                device.roster_validity,
                &[root_signer.roster_entry(&certificate).expect("new member")],
            )
            .expect("new roster");
        let account = AccountPin::new(
            root_signer.account_id().expect("account"),
            root_signer.public_key().expect("root public"),
            roster.checkpoint(),
            description.family,
        )
        .expect("independent account pin");
        let next = account
            .verify_device(&certificate, roster.as_bytes(), 150)
            .expect("next identity");
        let mut next_journal = DeviceJournal::provision_anchored(
            &new.join("state.redb"),
            JournalKey::provision(&new.join("key")).expect("fresh wrapping"),
            &next,
            policy,
            JournalIdentity::generate().expect("fresh journal ID"),
            150,
        )
        .expect("inactive successor");
        let next_genesis = next_journal
            .anchor_genesis(&next, policy)
            .expect("successor genesis");
        let predecessors = [(
            genesis.subject(),
            device.roster().checkpoint(),
            policy.historical(),
        )];
        let retired = {
            let mut witness = store.lock().expect("witness");
            let proposal = witness
                .device_replacement_proposal(&next_genesis, &next, policy, &predecessors, 150)
                .expect("exact predecessor proposal");
            fs::write(
                server.join("replacement.bin"),
                proposal.to_bytes().expect("original request"),
            )
            .expect("retained replacement request");
            witness
                .replace_device(&proposal, &next_genesis, &next, policy, &predecessors, 150)
                .expect("retire original installation");
            let wire = witness
                .retired_subject_receipt(&proposal, genesis.subject())
                .expect("retirement proof");
            pin.verify_retired_subject(&proposal, genesis.subject(), &wire)
                .expect("verified permanent fact")
        };
        Self {
            _directory: directory,
            paths,
            key_path,
            peer,
            store,
            pin,
            retired,
        }
    }
}

#[test]
fn original_installation_retains_one_request_and_fences_ordinary_reopen() {
    let c = Case::new();
    let before = journal_rows(&c.paths.journal);
    let archives = fs::read(&c.paths.archives).expect("original index");
    let mut owner = c.open().expect("persist original request before release");
    let proposal = owner.proposal().expect("retained request");
    assert!(
        c.open().is_err(),
        "exclusive independent configuration lease"
    );
    owner.close();
    assert!(matches!(owner.proposal(), Err(DurableError::Closed)));
    let (policy, device, _) = c.peer.responder.inventory_inputs().expect("old authority");
    assert!(matches!(
        DeviceInstallation::open(c.paths.clone(), &c.key(), device, policy, 150),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        InstallationRecovery::open(c.paths.clone(), c.key()),
        Err(DurableError::Suspended)
    ));
    let mut reopened = c.open().expect("historical request reopen");
    assert_eq!(reopened.proposal().expect("same request"), proposal);
    let witness_proof = {
        let mut store = c.store.lock().expect("witness");
        store
            .retain_retired_cleanup(&proposal)
            .expect("independent inventory binding");
        store
            .retired_cleanup_receipt(&proposal)
            .expect("retained proof")
    };
    assert_eq!(
        reopened
            .verify_retained(&c.pin, &witness_proof)
            .expect("exact original retention")
            .proposal(),
        &proposal
    );
    reopened.close();
    assert!(
        journal_rows(&c.paths.journal) == before,
        "encrypted image and complete pending rows must remain exact"
    );
    assert_eq!(fs::read(&c.paths.archives).expect("same index"), archives);
}

#[test]
fn saved_request_reconciles_after_journal_loss_without_claiming_a_report() {
    let c = Case::new();
    let mut owner = c.open().expect("original durable capture");
    let proposal = owner.proposal().expect("request");
    owner.close();
    let retained = c.paths.journal.with_extension("retained-backup");
    fs::rename(&c.paths.journal, &retained).expect("simulate journal loss without deleting it");
    c.peer
        .responder
        .current_policy()
        .expect("old policy")
        .close();
    let mut reopened = c
        .open()
        .expect("original metadata independent of unavailable journal");
    assert_eq!(reopened.proposal().expect("exact old request"), proposal);
    let proof = {
        let mut witness = c.store.lock().expect("witness");
        witness
            .retain_retired_cleanup(&proposal)
            .expect("reconcile exact proposal");
        witness
            .retired_cleanup_receipt(&proposal)
            .expect("historical retention")
    };
    reopened
        .verify_retained(&c.pin, &proof)
        .expect("permanent fact, no current policy");
    assert!(
        !c.paths.journal.exists(),
        "metadata recovery cannot recreate missing data"
    );
    assert!(retained.exists());
}

#[test]
fn missing_original_state_wrong_key_and_foreign_retirement_do_not_write_a_request() {
    let c = Case::new();
    let other = Case::new();
    assert!(RetiredInstallationRecovery::open(c.paths.clone(), other.key(), c.retired).is_err());
    assert!(RetiredInstallationRecovery::open(c.paths.clone(), c.key(), other.retired).is_err());
    let backup = c.paths.journal.with_extension("held");
    fs::rename(&c.paths.journal, &backup).expect("original data unavailable");
    assert!(c.open().is_err());
    let db = open_private_database(&c.paths.configuration).expect("released configuration");
    assert!(read_configuration(&db)
        .expect("unchanged configuration")
        .retired
        .is_none());
    drop(db);
    fs::rename(backup, &c.paths.journal).expect("restore original file");
    c.open().expect("original state available again").close();
}

#[test]
fn every_configuration_sync_failure_preserves_the_original_request() {
    let calibration = Case::new();
    let (db, _, count, _) = fault_database_path(&calibration.paths.configuration, false);
    count.store(0, Ordering::SeqCst);
    let mut owner = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    let plan = owner.proposal().expect("original plan");
    owner.close();
    let (db, remaining, count, _) = fault_database_path(&calibration.paths.configuration, false);
    remaining.store(1, Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    let mut retry = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("exact retry writes nothing");
    assert_eq!(retry.proposal().expect("original plan"), plan);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    retry.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let c = Case::new();
            let expected = DeviceJournal::retired_cleanup_proposal(
                &c.paths.journal,
                c.key(),
                JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0)
                    .expect("ID"),
                c.retired,
            )
            .expect("actual original inventory");
            let (db, remaining, _, _) = fault_database_path(&c.paths.configuration, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                RetiredInstallationRecovery::open_database(db, c.paths.clone(), c.key(), c.retired),
                after,
            );
            let mut reopened = c.open().expect("reconcile original independent state");
            assert_eq!(
                reopened.proposal().expect("same original request"),
                expected
            );
        }
    }
    eprintln!("RETIRED_INSTALLATION_SYNC barriers={barriers} before_after_faults={} exact_retry_read_only=true", barriers * 2);
}

#[test]
fn restored_older_journal_cannot_replace_the_independently_saved_pending_inventory() {
    let c = Case::with_pending(true);
    let mut owner = c.open().expect("persist complete original inventory");
    let original = owner.proposal().expect("request");
    assert!(original.pending_intent_digest().is_some());
    owner.close();
    fs::rename(
        &c.paths.journal,
        c.paths.journal.with_extension("original-pending"),
    )
    .expect("retain actual pending state");
    fs::copy(
        c.paths.journal.with_extension("before-pending"),
        &c.paths.journal,
    )
    .expect("restore older backup");
    let mut owner = c.open().expect("reopen independent original request");
    assert_eq!(
        owner.proposal().expect("do not recapture stale backup"),
        original
    );
    let older = DeviceJournal::retired_cleanup_proposal(
        &c.paths.journal,
        c.key(),
        JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0).expect("ID"),
        c.retired,
    )
    .expect("same frozen image, genuinely different pending inventory");
    assert_eq!(older.stored_image_digest(), original.stored_image_digest());
    assert!(older.pending_intent_digest().is_none());
    let mut witness = c.store.lock().expect("witness");
    witness
        .retain_retired_cleanup(&original)
        .expect("reconcile original dispatch");
    assert!(matches!(
        witness.retain_retired_cleanup(&older),
        Err(DurableError::Conflict)
    ));
    let wire = witness
        .retired_cleanup_receipt(&original)
        .expect("retained inventory");
    owner
        .verify_retained(&c.pin, &wire)
        .expect("exact original binding only, no report");
    eprintln!("RETIRED_INSTALLATION_BACKUP real_pending=true same_frozen_image=true original_request_preserved=true older_inventory_conflicts=true");
}

#[test]
fn retired_installation_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_RETIRED_INSTALLATION_CHILD") else {
        return;
    };
    let root = Path::new(&root);
    let server = root.join("witness");
    let key = JournalKey::open(&server.join("key")).expect("witness key");
    let signer = AnchorSigningKey::open(
        &server.join("signer"),
        &key,
        SigningKeyId::from_trusted_state([63; 32]).expect("signer ID"),
    )
    .expect("signer");
    let identity = AnchorIdentity::from_trusted_state(
        fs::read(server.join("instance"))
            .expect("identity")
            .try_into()
            .expect("identity width"),
    )
    .expect("identity");
    let mut witness = AnchorStore::open(&server.join("state.redb"), key, signer, identity)
        .expect("original witness");
    let pin = witness.pin().expect("pin");
    let replacement = crate::AnchorDeviceReplacementProposal::from_trusted_state(
        &fs::read(server.join("replacement.bin")).expect("retained proposal"),
    )
    .expect("proposal");
    let (subject, _) = replacement
        .predecessor_checkpoints()
        .next()
        .expect("original subject");
    let wire = witness
        .retired_subject_receipt(&replacement, subject)
        .expect("permanent proof");
    let retired = pin
        .verify_retired_subject(&replacement, subject, &wire)
        .expect("verified retirement");
    witness.close();
    let old = root.join("old");
    let paths = InstallationPaths::new(
        &old.join("installation.redb"),
        &old.join("state.redb"),
        &old.join("archives.redb"),
    )
    .expect("original paths");
    let mut owner = RetiredInstallationRecovery::open(
        paths,
        JournalKey::open(&old.join("key")).expect("key"),
        retired,
    )
    .expect("retain original request");
    fs::write(
        root.join("returned-request"),
        owner.proposal().expect("durable request").to_bytes(),
    )
    .expect("caller-visible marker");
}

#[test]
fn process_loss_before_and_after_request_commit_reopens_only_the_original_inventory() {
    for stage in [
        "retired-cleanup-before-commit",
        "retired-cleanup-after-commit",
    ] {
        let c = Case::with_pending(true);
        let expected = DeviceJournal::retired_cleanup_proposal(
            &c.paths.journal,
            c.key(),
            JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0).expect("ID"),
            c.retired,
        )
        .expect("actual original inventory");
        c.store.lock().expect("witness").close();
        let root = c._directory.path().canonicalize().expect("root");
        let log = fs::File::create_new(root.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::retired::tests::retired_installation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_RETIRED_INSTALLATION_CHILD", &root)
                .env("QPERIAPT_INSTALLATION_CUT_DIR", &root)
                .env("QPERIAPT_INSTALLATION_CUT_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "process boundary deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-request").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let db = open_private_database(&c.paths.configuration)
            .expect("configuration after process loss");
        assert_eq!(
            read_configuration(&db)
                .expect("actual commit phase")
                .retired
                .is_some(),
            stage.ends_with("after-commit")
        );
        drop(db);
        c.peer.responder.current_policy().expect("policy").close();
        let mut reopened = c
            .open()
            .expect("exact recovery without current policy or signer");
        assert_eq!(
            reopened.proposal().expect("same original inventory"),
            expected
        );
    }
    eprintln!("RETIRED_INSTALLATION_PROCESS before_commit=true after_commit=true no_request_returned=true original_pending_preserved=true");
}
