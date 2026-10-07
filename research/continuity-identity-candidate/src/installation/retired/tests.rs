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
    messages: Option<ReportMessages>,
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
        Self::build(pending, false)
    }
    fn build(pending: bool, populated: bool) -> Self {
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
        let messages = if populated {
            Some(populate_messages(&mut service, &peer, &store, &pin, &root))
        } else {
            None
        };
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
            messages,
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
    let report_inventory = if std::env::var_os("QPERIAPT_RETIRED_REPORT_CHILD").is_some() {
        let proposal = Proposal::from_trusted_state(
            &fs::read(root.join("report-inventory.bin")).expect("original saved inventory"),
        )
        .expect("inventory");
        let wire = witness
            .retired_cleanup_receipt(&proposal)
            .expect("original permanent retention");
        Some(
            pin.verify_retired_cleanup(retired, &proposal, &wire)
                .expect("verified inventory"),
        )
    } else {
        None
    };
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
    if let Some(inventory) = report_inventory {
        if std::env::var_os("QPERIAPT_RETIRED_HOST_ACK_CHILD").is_some() {
            let proposal = owner
                .report_proposal()
                .expect("saved report")
                .expect("report request");
            let wire = fs::read(root.join("retained-report-receipt.bin"))
                .expect("independent report retention");
            let retained = pin
                .verify_retired_report(&inventory, &proposal, &wire)
                .expect("verified report");
            let body = fs::read(root.join("host-recorded-report.bin"))
                .expect("durable complete host record");
            let ack = owner
                .prepare_host_acknowledgement(&body, &retained)
                .expect("same original host decision");
            fs::write(root.join("returned-host-ack"), ack.to_bytes())
                .expect("caller visible expectation");
            return;
        }
        let report = owner
            .prepare_report(&inventory)
            .expect("complete original report preparation");
        fs::write(root.join("returned-report"), report.to_bytes())
            .expect("caller visible report request");
        return;
    }
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

struct ReportMessages {
    session: [u8; 32],
    inbox: crate::MessageId,
    consumed: crate::MessageId,
    outgoing: crate::MessageId,
}
fn populate_messages(
    service: &mut DeviceService,
    peer: &Fixture,
    store: &Arc<Mutex<AnchorStore>>,
    pin: &AnchorPin,
    root: &Path,
) -> ReportMessages {
    let dir = root.join("peer");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("peer directory");
    let policy = peer.initiator.current_policy().expect("peer policy");
    let device = peer.initiator_device();
    let mut initiator = DeviceJournal::provision_anchored(
        &dir.join("state.redb"),
        JournalKey::provision(&dir.join("key")).expect("peer key"),
        device,
        policy,
        JournalIdentity::generate().expect("peer ID"),
        150,
    )
    .expect("peer journal");
    let genesis = initiator
        .anchor_genesis(device, policy)
        .expect("actual peer genesis");
    store
        .lock()
        .expect("store")
        .enroll(&genesis, device, policy, 150)
        .expect("independent peer enrollment");
    let client = AnchorClient::new(
        pin.clone(),
        DeviceSigningKey::deterministic([92; 32], [93; 32]).expect("peer signer"),
        Box::new(Transport(Arc::clone(store), Arc::new(AtomicUsize::new(0)))),
        Duration::from_secs(5),
    )
    .expect("peer client");
    initiator
        .activate_anchor(device, policy, client)
        .expect("peer activation");
    let request = crate::InitiationId::generate().expect("original initiation");
    let initial = initiator
        .initiate(Arc::clone(&peer.initiator), request, &peer.signer_i, 150)
        .expect("initial");
    let (journal, archives) = service.stores().expect("real installation stores");
    let (pq, classical) = peer.sources();
    let reply = journal
        .respond(
            Arc::clone(&peer.responder),
            &initial,
            &peer.signer_r,
            pq,
            classical,
            150,
        )
        .expect("reply");
    let completion = initiator
        .accept_reply(Arc::clone(&peer.initiator), request, &reply, 150)
        .expect("final");
    let session = completion.session_id();
    journal
        .finish(
            Arc::clone(&peer.responder),
            &initial,
            completion.final_message(),
            150,
        )
        .expect("finish");
    let archive = journal
        .archive_session_closure(&peer.responder, session)
        .expect("authenticated original archive");
    archives
        .retain(journal, &peer.responder, session, &archive)
        .expect("independent archive before activation");
    initiator
        .activate_initiator_messages(Arc::clone(&peer.initiator), request, 150)
        .expect("initiator message state");
    journal
        .activate_responder_messages(Arc::clone(&peer.responder), &initial, 150)
        .expect("responder message state");
    let mut ids = Vec::new();
    for n in 0..3 {
        let id = initiator
            .next_message_id(&peer.initiator, session, 150)
            .expect("message ID");
        let wire = initiator
            .send_message(
                &peer.initiator,
                session,
                id,
                b"private incoming plaintext marker",
                b"original ad",
                150,
            )
            .expect("committed original send");
        if n != 1 {
            journal
                .receive_message(&peer.responder, session, &wire, b"original ad", 150)
                .expect("real inbound message");
        }
        if n == 2 {
            journal
                .consume_message(&peer.responder, session, id, 150)
                .expect("consume out of order");
        }
        ids.push(id);
    }
    let outgoing = journal
        .next_message_id(&peer.responder, session, 150)
        .expect("original outgoing");
    journal
        .send_message(
            &peer.responder,
            session,
            outgoing,
            b"private outgoing plaintext marker",
            b"original ad",
            150,
        )
        .expect("unconfirmed send");
    initiator.close();
    ReportMessages {
        session,
        inbox: *ids.first().expect("first received ID"),
        consumed: *ids.get(2).expect("out-of-order consumed ID"),
        outgoing,
    }
}
fn retained_inventory(c: &Case, owner: &mut RetiredInstallationRecovery) -> AnchorRetiredCleanup {
    let inventory = owner.proposal().expect("original inventory");
    let mut witness = c.store.lock().expect("witness");
    witness
        .retain_retired_cleanup(&inventory)
        .expect("independent inventory retention");
    let wire = witness
        .retired_cleanup_receipt(&inventory)
        .expect("inventory receipt");
    owner
        .verify_retained(&c.pin, &wire)
        .expect("verified inventory")
}
fn retained_report(c: &Case, proposal: &crate::AnchorRetiredReportProposal) -> Vec<u8> {
    let mut witness = c.store.lock().expect("witness");
    witness
        .retain_retired_report(proposal)
        .expect("independently bind exact report");
    witness
        .retired_report_receipt(proposal)
        .expect("report receipt")
}
#[test]
fn complete_report_retains_real_inbox_holes_unknown_sends_and_original_peer_without_mutation() {
    use crate::retired_device::{RecordMetadata, SessionState, ViewRole};
    let c = Case::build(false, true);
    let expected = c.messages.as_ref().expect("real message fixture");
    let before = journal_rows(&c.paths.journal);
    let mut owner = c.open().expect("retired installation");
    let inventory = retained_inventory(&c, &mut owner);
    let proposal = owner
        .prepare_report(&inventory)
        .expect("prepare all records");
    assert_eq!(
        owner.prepare_report(&inventory).expect("exact retry"),
        proposal
    );
    assert!(c
        .store
        .lock()
        .expect("witness")
        .retired_report_receipt(&proposal)
        .is_err());
    let receipt = retained_report(&c, &proposal);
    c.peer
        .responder
        .current_policy()
        .expect("old policy")
        .close();
    let report = owner
        .report(&inventory, &c.pin, &receipt)
        .expect("independently retained complete metadata");
    assert_eq!(report.proposal(), &proposal);
    assert_eq!(report.views().len(), 1);
    let view = report.views().first().expect("whole view");
    assert_eq!(view.role, ViewRole::Authoritative);
    let sessions: Vec<_> = view
        .records
        .iter()
        .filter_map(|r| match &r.metadata {
            RecordMetadata::Session(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(sessions.len(), 1);
    let session = sessions.first().expect("exact one session");
    assert_eq!(session.session, expected.session);
    let original_peer = c.peer.initiator_device();
    assert_eq!(
        (
            session.peer_account,
            session.peer_device,
            session.peer_generation
        ),
        (
            original_peer.account_id(),
            original_peer.device_id(),
            original_peer.generation()
        )
    );
    let epochs = match &session.state {
        SessionState::Live {
            epochs,
            previous_closure: None,
        } => Ok(epochs),
        _ => Err("expected original live metadata"),
    }
    .expect("state");
    let epoch = epochs.first().expect("retained epoch");
    assert_eq!(epoch.accounting.sent, 1);
    assert_eq!(epoch.accounting.acknowledged_before, 0);
    assert_eq!(epoch.accounting.consumed_before, 0);
    assert_eq!(epoch.accounting.received, 3);
    assert_eq!(epoch.accounting.skipped, vec![1]);
    assert_eq!(epoch.accounting.unconfirmed.len(), 1);
    assert_eq!(
        epoch
            .accounting
            .unconfirmed
            .first()
            .expect("exact one outstanding send")
            .message_id(),
        expected.outgoing
    );
    assert_eq!(epoch.accounting.deliveries.len(), 1);
    assert_eq!(
        epoch
            .accounting
            .deliveries
            .first()
            .expect("exact one unconsumed delivery")
            .message,
        expected.inbox
    );
    assert_eq!(
        epoch
            .accounting
            .deliveries
            .first()
            .expect("exact one unconsumed delivery")
            .plaintext_bytes,
        b"private incoming plaintext marker".len()
    );
    assert_eq!(epoch.consumed_out_of_order.len(), 1);
    assert_eq!(
        epoch
            .consumed_out_of_order
            .first()
            .expect("exact one consumed hole")
            .message,
        expected.consumed
    );
    assert!(view.records.iter().any(|r| matches!(&r.metadata, RecordMetadata::Bootstrap { flights, .. } if flights.session == Some(expected.session))));
    for secret in [
        b"private incoming plaintext marker".as_slice(),
        b"private outgoing plaintext marker".as_slice(),
    ] {
        assert!(!report.as_bytes().windows(secret.len()).any(|w| w == secret));
    }
    let original_bytes = report.as_bytes().to_vec();
    owner.close();
    let mut reopened = c.open().expect("same historical config");
    assert_eq!(
        reopened.report_proposal().expect("exact saved expectation"),
        Some(proposal)
    );
    assert_eq!(
        reopened
            .report(&inventory, &c.pin, &receipt)
            .expect("same report")
            .as_bytes(),
        original_bytes
    );
    reopened.close();
    assert_eq!(journal_rows(&c.paths.journal), before);
    eprintln!("RETIRED_REPORT actual_session=true consumed_hole_preserved=true skipped_index_preserved=true unconfirmed_send=true original_peer_authenticated=true no_plaintext=true");
}
#[test]
fn report_request_survives_missing_journal_but_body_is_never_replaced_by_empty_metadata() {
    let c = Case::new();
    let mut owner = c.open().expect("owner");
    let inventory = retained_inventory(&c, &mut owner);
    let proposal = owner
        .prepare_report(&inventory)
        .expect("complete report request");
    owner.close();
    fs::rename(
        &c.paths.journal,
        c.paths.journal.with_extension("retained-original"),
    )
    .expect("retain unavailable original");
    let mut owner = c.open().expect("independent config survives");
    assert_eq!(
        owner
            .prepare_report(&inventory)
            .expect("original proposal without recapture"),
        proposal
    );
    let receipt = retained_report(&c, &proposal);
    assert!(owner.report(&inventory, &c.pin, &receipt).is_err());
    assert!(matches!(owner.report_proposal(), Err(DurableError::Closed)));
    assert!(!c.paths.journal.exists());
}
#[test]
fn uncommitted_target_is_separate_and_a_missing_original_archive_refuses_the_whole_report() {
    use crate::retired_device::ViewRole;
    let c = Case::with_pending(true);
    let before = journal_rows(&c.paths.journal);
    let mut owner = c.open().expect("owner");
    let inventory = retained_inventory(&c, &mut owner);
    let proposal = owner
        .prepare_report(&inventory)
        .expect("original intent report");
    let receipt = retained_report(&c, &proposal);
    let report = owner
        .report(&inventory, &c.pin, &receipt)
        .expect("both complete views");
    assert_eq!(
        report.views().iter().map(|v| v.role).collect::<Vec<_>>(),
        vec![ViewRole::Authoritative, ViewRole::UncommittedTarget]
    );
    assert!(
        report
            .views()
            .get(1)
            .expect("candidate target")
            .records
            .len()
            > report
                .views()
                .first()
                .expect("authoritative source")
                .records
                .len()
    );
    owner.close();
    assert_eq!(journal_rows(&c.paths.journal), before);
    let c = Case::build(false, true);
    let mut owner = c.open().expect("owner");
    let inventory = retained_inventory(&c, &mut owner);
    fs::rename(
        &c.paths.archives,
        c.paths.archives.with_extension("retained-original"),
    )
    .expect("retain missing index");
    crate::SessionArchiveStore::provision(
        &c.paths.archives,
        JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0)
            .expect("original journal ID"),
    )
    .expect("older empty index")
    .close();
    assert!(matches!(
        owner.prepare_report(&inventory),
        Err(DurableError::ArchiveRequired)
    ));
    assert!(c
        .open()
        .expect("metadata reopen")
        .report_proposal()
        .expect("no partial request")
        .is_none());
}

#[test]
fn every_report_request_sync_cut_recovers_same_complete_report() {
    let calibration = Case::with_pending(true);
    let mut owner = calibration.open().expect("owner");
    let inventory = retained_inventory(&calibration, &mut owner);
    owner.close();
    let (db, _, count, _) = fault_database_path(&calibration.paths.configuration, false);
    let mut owner = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("original config");
    count.store(0, Ordering::SeqCst);
    let proposal = owner.prepare_report(&inventory).expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    let (db, remaining, count, _) = fault_database_path(&calibration.paths.configuration, false);
    let mut owner = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("original config");
    remaining.store(1, Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    assert_eq!(
        owner.prepare_report(&inventory).expect("read only retry"),
        proposal
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let c = Case::with_pending(true);
            let mut owner = c.open().expect("owner");
            let inventory = retained_inventory(&c, &mut owner);
            owner.close();
            let id = JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0)
                .expect("identity");
            let mut archives =
                crate::SessionArchiveStore::open(&c.paths.archives, id).expect("original archives");
            let expected = DeviceJournal::retired_report(
                &c.paths.journal,
                &c.key(),
                id,
                c.retired,
                &inventory,
                &mut archives,
            )
            .expect("complete original report")
            .proposal()
            .clone();
            archives.close();
            let before = journal_rows(&c.paths.journal);
            let (db, remaining, _, _) = fault_database_path(&c.paths.configuration, after);
            let mut owner =
                RetiredInstallationRecovery::open_database(db, c.paths.clone(), c.key(), c.retired)
                    .expect("original config");
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(owner.prepare_report(&inventory), after);
            assert!(matches!(owner.report_proposal(), Err(DurableError::Closed)));
            let mut reopened = c.open().expect("reconcile original request");
            assert_eq!(
                reopened.prepare_report(&inventory).expect("same report"),
                expected
            );
            let receipt = retained_report(&c, &expected);
            assert_eq!(
                reopened
                    .report(&inventory, &c.pin, &receipt)
                    .expect("full body")
                    .proposal(),
                &expected
            );
            reopened.close();
            assert_eq!(journal_rows(&c.paths.journal), before);
        }
    }
    eprintln!("RETIRED_REPORT_INSTALLATION_SYNC barriers={barriers} before_after_faults={} original_report_preserved=true",barriers*2);
}

#[test]
fn process_loss_before_and_after_report_request_commit_preserves_original_body() {
    for stage in [
        "retired-report-before-commit",
        "retired-report-after-commit",
    ] {
        let c = Case::with_pending(true);
        let mut owner = c.open().expect("owner");
        let inventory = retained_inventory(&c, &mut owner);
        owner.close();
        let id =
            JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0).expect("ID");
        let mut archives =
            crate::SessionArchiveStore::open(&c.paths.archives, id).expect("archives");
        let expected = DeviceJournal::retired_report(
            &c.paths.journal,
            &c.key(),
            id,
            c.retired,
            &inventory,
            &mut archives,
        )
        .expect("complete original body");
        archives.close();
        let root = c._directory.path().canonicalize().expect("root");
        fs::write(
            root.join("report-inventory.bin"),
            inventory.proposal().to_bytes(),
        )
        .expect("retained inventory");
        c.store.lock().expect("witness").close();
        let log = fs::File::create_new(root.join("report-child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::retired::tests::retired_installation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_RETIRED_INSTALLATION_CHILD", &root)
                .env("QPERIAPT_RETIRED_REPORT_CHILD", "1")
                .env("QPERIAPT_INSTALLATION_CUT_DIR", &root)
                .env("QPERIAPT_INSTALLATION_CUT_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "report cut deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-report").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let db = open_private_database(&c.paths.configuration).expect("configuration");
        assert_eq!(
            read_configuration(&db)
                .expect("actual saved state")
                .retired_report
                .is_some(),
            stage.ends_with("after-commit")
        );
        drop(db);
        let mut owner = c.open().expect("original recovery");
        assert_eq!(
            owner
                .prepare_report(&inventory)
                .expect("same complete expectation"),
            *expected.proposal()
        );
        let mut archives =
            crate::SessionArchiveStore::open(&c.paths.archives, id).expect("same archives");
        let reread = DeviceJournal::retired_report(
            &c.paths.journal,
            &c.key(),
            id,
            c.retired,
            &inventory,
            &mut archives,
        )
        .expect("same complete original body");
        assert_eq!(reread.as_bytes(), expected.as_bytes());
    }
    eprintln!("RETIRED_REPORT_INSTALLATION_PROCESS before_commit=true after_commit=true no_request_returned=true complete_body_preserved=true");
}

fn recorded_host_report(
    c: &Case,
    owner: &mut RetiredInstallationRecovery,
) -> (Vec<u8>, crate::AnchorRetiredReport) {
    let inventory = retained_inventory(c, owner);
    let proposal = owner.prepare_report(&inventory).expect("complete report");
    let receipt = retained_report(c, &proposal);
    let report = owner
        .report(&inventory, &c.pin, &receipt)
        .expect("verified full metadata");
    let retained = c
        .pin
        .verify_retired_report(&inventory, &proposal, &receipt)
        .expect("independent retention");
    let bytes = report.as_bytes().to_vec();
    let root = c._directory.path().canonicalize().expect("root");
    let mut file = fs::File::create_new(root.join("host-recorded-report.bin"))
        .expect("new host accounting record");
    use std::io::Write;
    file.write_all(&bytes).expect("complete host record");
    file.sync_all().expect("host data durable");
    fs::File::open(&root)
        .expect("host directory")
        .sync_all()
        .expect("host name durable");
    (bytes, retained)
}
#[test]
fn host_ack_requires_complete_original_record_and_recovers_without_journal_or_archives() {
    let c = Case::build(false, true);
    let before = journal_rows(&c.paths.journal);
    let mut owner = c.open().expect("owner");
    let (bytes, retained) = recorded_host_report(&c, &mut owner);
    owner.close();
    for altered in [
        bytes.get(..320).expect("short record").to_vec(),
        bytes
            .get(..bytes.len() - 1)
            .expect("missing final byte")
            .to_vec(),
        {
            let mut b = bytes.clone();
            *b.last_mut().expect("byte") ^= 1;
            b
        },
    ] {
        let mut owner = c.open().expect("owner");
        assert!(owner
            .prepare_host_acknowledgement(&altered, &retained)
            .is_err());
        assert!(matches!(
            owner.host_acknowledgement_proposal(),
            Err(DurableError::Closed)
        ));
        assert!(c
            .open()
            .expect("reopen")
            .host_acknowledgement_proposal()
            .expect("no incomplete host intent")
            .is_none());
    }
    fs::rename(
        &c.paths.journal,
        c.paths.journal.with_extension("retained-original"),
    )
    .expect("preserve unavailable journal");
    fs::rename(
        &c.paths.archives,
        c.paths.archives.with_extension("retained-original"),
    )
    .expect("preserve unavailable archives");
    c.peer.responder.current_policy().expect("policy").close();
    let mut owner = c.open().expect("independent metadata");
    let expected = owner
        .prepare_host_acknowledgement(&bytes, &retained)
        .expect("complete durable host record survives original data loss");
    assert_eq!(&expected, retained.proposal());
    assert_eq!(
        owner
            .prepare_host_acknowledgement(&bytes, &retained)
            .expect("exact retry"),
        expected
    );
    owner.close();
    let mut owner = c.open().expect("reconcile metadata");
    assert_eq!(
        owner
            .host_acknowledgement_proposal()
            .expect("same original host decision"),
        Some(expected.clone())
    );
    let wire = {
        let mut w = c.store.lock().expect("controller");
        w.acknowledge_retired_report(&expected)
            .expect("independent explicit ACK");
        w.retired_report_acknowledgement_receipt(&expected)
            .expect("ACK receipt")
    };
    assert_eq!(
        owner
            .verify_host_acknowledgement(&c.pin, &wire)
            .expect("purpose21")
            .proposal(),
        &expected
    );
    owner.close();
    assert!(!c.paths.journal.exists());
    assert!(!c.paths.archives.exists());
    assert_eq!(
        journal_rows(&c.paths.journal.with_extension("retained-original")),
        before
    );
    eprintln!("RETIRED_HOST_ACK complete_host_record=true partial_record_refused=true journal_archive_loss_recoverable=true no_data_erasure=true");
}
#[test]
fn every_host_ack_configuration_sync_cut_keeps_original_host_record() {
    let calibration = Case::new();
    let mut owner = calibration.open().expect("owner");
    let (bytes, retained) = recorded_host_report(&calibration, &mut owner);
    owner.close();
    let (db, _, count, _) = fault_database_path(&calibration.paths.configuration, false);
    let mut owner = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("config");
    count.store(0, Ordering::SeqCst);
    let expected = owner
        .prepare_host_acknowledgement(&bytes, &retained)
        .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    let (db, remaining, count, _) = fault_database_path(&calibration.paths.configuration, false);
    let mut owner = RetiredInstallationRecovery::open_database(
        db,
        calibration.paths.clone(),
        calibration.key(),
        calibration.retired,
    )
    .expect("config");
    remaining.store(1, Ordering::SeqCst);
    count.store(0, Ordering::SeqCst);
    assert_eq!(
        owner
            .prepare_host_acknowledgement(&bytes, &retained)
            .expect("read-only retry"),
        expected
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let c = Case::new();
            let mut owner = c.open().expect("owner");
            let (bytes, retained) = recorded_host_report(&c, &mut owner);
            owner.close();
            let before = journal_rows(&c.paths.journal);
            let (db, remaining, _, _) = fault_database_path(&c.paths.configuration, after);
            let mut owner =
                RetiredInstallationRecovery::open_database(db, c.paths.clone(), c.key(), c.retired)
                    .expect("config");
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(owner.prepare_host_acknowledgement(&bytes, &retained), after);
            assert!(matches!(
                owner.host_acknowledgement_proposal(),
                Err(DurableError::Closed)
            ));
            let mut reopened = c.open().expect("reopen original metadata");
            assert_eq!(
                &reopened
                    .prepare_host_acknowledgement(&bytes, &retained)
                    .expect("same exact host record"),
                retained.proposal()
            );
            reopened.close();
            assert_eq!(journal_rows(&c.paths.journal), before);
        }
    }
    eprintln!(
        "RETIRED_HOST_ACK_INSTALLATION_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn process_loss_before_and_after_host_ack_intent_recovers_without_original_journal() {
    for stage in ["retired-ack-before-commit", "retired-ack-after-commit"] {
        let c = Case::new();
        let mut owner = c.open().expect("owner");
        let (body, retained) = recorded_host_report(&c, &mut owner);
        let inventory = retained_inventory(&c, &mut owner);
        owner.close();
        let wire = c
            .store
            .lock()
            .expect("witness")
            .retired_report_receipt(retained.proposal())
            .expect("report retention");
        let root = c._directory.path().canonicalize().expect("root");
        fs::write(
            root.join("report-inventory.bin"),
            inventory.proposal().to_bytes(),
        )
        .expect("inventory");
        fs::write(root.join("retained-report-receipt.bin"), wire).expect("report proof");
        fs::rename(
            &c.paths.journal,
            c.paths.journal.with_extension("retained-original"),
        )
        .expect("retain unavailable original journal");
        fs::rename(
            &c.paths.archives,
            c.paths.archives.with_extension("retained-original"),
        )
        .expect("retain unavailable archives");
        c.store.lock().expect("witness").close();
        let log = fs::File::create_new(root.join("ack-child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::retired::tests::retired_installation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_RETIRED_INSTALLATION_CHILD", &root)
                .env("QPERIAPT_RETIRED_REPORT_CHILD", "1")
                .env("QPERIAPT_RETIRED_HOST_ACK_CHILD", "1")
                .env("QPERIAPT_INSTALLATION_CUT_DIR", &root)
                .env("QPERIAPT_INSTALLATION_CUT_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "host intent cut deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-host-ack").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let db = open_private_database(&c.paths.configuration).expect("configuration");
        assert_eq!(
            read_configuration(&db)
                .expect("actual host intent")
                .retired_ack
                .is_some(),
            stage.ends_with("after-commit")
        );
        drop(db);
        c.peer.responder.current_policy().expect("policy").close();
        let mut reopened = c.open().expect("original independent metadata");
        assert_eq!(
            &reopened
                .prepare_host_acknowledgement(&body, &retained)
                .expect("same original recorded report"),
            retained.proposal()
        );
        assert!(!c.paths.journal.exists());
        assert!(!c.paths.archives.exists());
    }
    eprintln!("RETIRED_HOST_ACK_INSTALLATION_PROCESS before_commit=true after_commit=true original_data_unavailable=true same_host_record=true");
}
