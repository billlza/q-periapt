// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{SessionClosureArchive, SessionClosureId, SessionClosureStatus};

fn seed(
    service: &mut DeviceService,
    peer: &mut DeviceJournal,
    f: &Fixture,
) -> ([u8; 32], SessionClosureArchive) {
    let (journal, index) = service.stores().expect("live original stores");
    let id = InitiationId::generate().expect("request");
    let initial = journal
        .initiate(Arc::clone(&f.initiator), id, &f.signer_i, 150)
        .expect("initial");
    let (pq, classical) = f.sources();
    let reply = peer
        .respond(
            Arc::clone(&f.responder),
            &initial,
            &f.signer_r,
            pq,
            classical,
            150,
        )
        .expect("reply");
    let completed = journal
        .accept_reply(Arc::clone(&f.initiator), id, &reply, 150)
        .expect("final");
    let session = completed.session_id();
    peer.finish(
        Arc::clone(&f.responder),
        &initial,
        completed.final_message(),
        150,
    )
    .expect("confirmation");
    let archive = journal
        .archive_session_closure(&f.initiator, session)
        .expect("original archive");
    index
        .retain(journal, &f.initiator, session, &archive)
        .expect("archive before activation");
    journal
        .activate_initiator_messages(Arc::clone(&f.initiator), id, 150)
        .expect("activation");
    let message = journal
        .next_message_id(&f.initiator, session, 150)
        .expect("message ID");
    journal
        .send_message(
            &f.initiator,
            session,
            message,
            b"unconfirmed original",
            b"recovery",
            150,
        )
        .expect("real committed outbox");
    (session, archive)
}

struct Local {
    _directory: tempfile::TempDir,
    root: PathBuf,
    f: Fixture,
    session: [u8; 32],
    archive: SessionClosureArchive,
}
impl Local {
    fn new() -> Self {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        drop(JournalKey::provision(&root.join("key")).expect("key"));
        let mut owner = create(&root, &f);
        prepare(&mut owner, &root, &f);
        let mut service = activate(owner, &root, &f);
        let peer_dir = directory();
        let peer_path = peer_dir.path().canonicalize().expect("peer path");
        let mut peer = crate::durable::tests::new_store(&peer_path, f.local_device());
        let (session, archive) = seed(&mut service, &mut peer, &f);
        service.close();
        Self {
            _directory: dir,
            root,
            f,
            session,
            archive,
        }
    }
    fn discover(&self) -> InstallationRecovery {
        InstallationRecovery::open(paths(&self.root), key(&self.root)).expect("same installation")
    }
}

#[test]
fn installation_recovery_preserves_closed_policy_accounting_and_original_catalogue() {
    let mut c = Local::new();
    assert!(matches!(
        DeviceInstallation::open(
            paths(&c.root),
            &key(&c.root),
            c.f.initiator_device(),
            c.f.initiator.policy(),
            2000
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    c.f.initiator.policy().close();
    c.f.signer_i.close();
    assert!(matches!(
        DeviceInstallation::open(
            paths(&c.root),
            &key(&c.root),
            c.f.initiator_device(),
            c.f.initiator.policy(),
            150
        ),
        Err(DurableError::Protocol(Error::Closed))
    ));
    let mut discovery = c.discover();
    assert_eq!(
        discovery.session_ids().expect("bounded hints"),
        vec![c.session]
    );
    assert!(matches!(
        InstallationRecovery::open(paths(&c.root), key(&c.root)),
        Err(DurableError::Database(PrivateDatabaseError::Busy))
    ));
    let mut owner = discovery
        .open_session(c.session, None)
        .expect("expired operational objects are unnecessary");
    let (journal, index) = owner.stores().expect("cleanup only");
    let report = journal.begin().expect("exact loss report");
    assert_eq!(report.session, c.session);
    assert_eq!(
        report
            .epochs
            .iter()
            .map(|e| e.unconfirmed.len())
            .sum::<usize>(),
        1
    );
    assert!(matches!(
        index.retire_closed(journal, report.report),
        Err(DurableError::Suspended)
    ));
    let mut record = fs::File::create_new(c.root.join("complete-report")).expect("host accounting");
    record
        .write_all(format!("{report:?}").as_bytes())
        .expect("complete report");
    record.sync_all().expect("durable host record");
    fs::File::open(&c.root)
        .expect("parent")
        .sync_all()
        .expect("record name");
    owner.close();
    assert!(matches!(owner.stores(), Err(DurableError::Closed)));
    let mut owner = c
        .discover()
        .open_session(c.session, None)
        .expect("original recovery restart");
    let (journal, index) = owner.stores().expect("cleanup");
    assert_eq!(journal.begin().expect("same immutable report"), report);
    let wrong = SessionClosureId::from_trusted_state([37; 32]).expect("different correlation");
    assert!(matches!(
        journal.acknowledge(wrong),
        Err(DurableError::Conflict)
    ));
    journal
        .acknowledge(report.report)
        .expect("after durable complete accounting");
    assert_eq!(
        journal.status().expect("status"),
        SessionClosureStatus::Closed(report.report)
    );
    assert!(index
        .retire_closed(journal, report.report)
        .expect("retire exact closed archive"));
    owner.close();
    assert!(c
        .discover()
        .session_ids()
        .expect("actual absence")
        .is_empty());
    assert!(matches!(
        c.discover().open_session(c.session, None),
        Err(DurableError::Absent)
    ));
    let mut restored = c
        .discover()
        .open_session_from_archive(&c.archive, None)
        .expect("explicit original archive still authenticated");
    let (journal, index) = restored.stores().expect("same terminal scope");
    assert_eq!(
        journal.status().expect("terminal"),
        SessionClosureStatus::Closed(report.report)
    );
    index.restore(journal).expect("restore exact catalogue row");
    assert_eq!(
        index.session_ids().expect("restored hints"),
        vec![c.session]
    );
    assert!(index
        .retire_closed(journal, report.report)
        .expect("same completed accounting"));
}

#[test]
fn installation_recovery_rejects_absent_creating_wrong_key_and_changed_scope_without_reset() {
    let c = Local::new();
    let different = JournalKey::provision(&c.root.join("different-key")).expect("different key");
    assert!(matches!(
        InstallationRecovery::open(paths(&c.root), different),
        Err(DurableError::Conflict)
    ));
    let mut forged = c.archive.as_bytes().to_vec();
    *forged.last_mut().expect("MAC") ^= 1;
    let forged = SessionClosureArchive::from_bytes(&forged).expect("untrusted canonical metadata");
    assert!(matches!(
        c.discover().open_session_from_archive(&forged, None),
        Err(DurableError::Authentication)
    ));
    for child in [paths(&c.root).journal, paths(&c.root).archives] {
        let backup = child.with_extension("original");
        fs::rename(&child, &backup).expect("simulate missing original");
        let result = InstallationRecovery::open(paths(&c.root), key(&c.root))
            .and_then(|owner| owner.open_session(c.session, None));
        assert!(result.is_err());
        assert!(!child.exists(), "no replacement of active storage");
        fs::rename(&backup, &child).expect("restore exact original");
    }
    let original = fs::read(paths(&c.root).configuration).expect("original config image");
    for field in [40usize, 136, 168, 169] {
        let db = open_private_database(&paths(&c.root).configuration).expect("test mutation");
        let (_, mut row, _) = read(&db).expect("scope");
        row.push(2);
        *row.get_mut(field).expect("field") ^= 1;
        let tx = transaction(&db).expect("write");
        tx.open_table(TABLE)
            .expect("row")
            .insert("installation", row.as_slice())
            .expect("change");
        tx.commit().expect("persist");
        drop(db);
        assert!(
            InstallationRecovery::open(paths(&c.root), key(&c.root))
                .and_then(|o| o.open_session(c.session, None))
                .is_err(),
            "field {field}"
        );
        fs::write(paths(&c.root).configuration, &original).expect("restore closed test fixture");
    }
    let d = directory();
    let root = d.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("key")).expect("key"));
    assert!(InstallationRecovery::open(paths(&root), key(&root)).is_err());
    assert!(!paths(&root).configuration.exists());
    let owner = create(&root, &c.f);
    drop(owner);
    assert!(matches!(
        InstallationRecovery::open(paths(&root), key(&root)),
        Err(DurableError::Suspended)
    ));
    assert!(!paths(&root).journal.exists() && !paths(&root).archives.exists());
}

fn anchored_session(c: &Anchored) -> ([u8; 32], SessionClosureArchive) {
    let owner = c.prepare();
    let mut service = c.activate(owner).expect("original service");
    let dir = directory();
    let path = dir.path().canonicalize().expect("peer path");
    let id = JournalIdentity::generate().expect("peer pin");
    let mut peer = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        JournalKey::provision(&path.join("key")).expect("peer key"),
        c.peer.local_device(),
        c.peer.responder.policy(),
        id,
        150,
    )
    .expect("peer genesis");
    let genesis = peer
        .anchor_genesis(c.peer.local_device(), c.peer.responder.policy())
        .expect("peer binding");
    c.server
        .lock()
        .expect("witness")
        .store
        .enroll(
            &genesis,
            c.peer.local_device(),
            c.peer.responder.policy(),
            150,
        )
        .expect("explicit peer enrollment");
    peer.close();
    let signer = crate::DeviceSigningKey::deterministic([96; 32], [97; 32])
        .expect("original responder signer");
    assert_eq!(
        signer.public_key().expect("signer"),
        c.peer.signer_r.public_key().expect("verified signer")
    );
    let client = AnchorClient::new(
        c.pin.clone(),
        signer,
        Box::new(Carrier(Arc::clone(&c.server))),
        Duration::from_secs(10),
    )
    .expect("peer witness client");
    let mut peer = DeviceJournal::open_anchored(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("key"),
        c.peer.local_device(),
        c.peer.responder.policy(),
        id,
        client,
    )
    .expect("peer open");
    let result = seed(&mut service, &mut peer, &c.peer);
    service.close();
    result
}

#[test]
fn installation_recovery_keeps_original_witness_and_refuses_each_lost_open_reply() {
    for after in [false, true] {
        let c = Anchored::new();
        let (session, archive) = anchored_session(&c);
        c.peer.initiator.policy().close();
        let recovery =
            || InstallationRecovery::open(paths(&c.root), key(&c.root)).expect("original config");
        assert!(matches!(
            recovery().open_session(session, None),
            Err(DurableError::AnchorRequired)
        ));
        let other = Anchored::new();
        assert!(matches!(
            recovery().open_session(session, Some(other.client())),
            Err(DurableError::Conflict)
        ));
        assert_eq!(other.server.lock().expect("unrelated witness").calls, 0);
        let wrong_signer = AnchorClient::new(
            c.pin.clone(),
            crate::DeviceSigningKey::generate().expect("different signing owner"),
            Box::new(Carrier(Arc::clone(&c.server))),
            Duration::from_secs(10),
        )
        .expect("client with unrelated signer");
        assert!(matches!(
            recovery().open_session(session, Some(wrong_signer)),
            Err(DurableError::Conflict)
        ));
        {
            let mut server = c.server.lock().expect("witness");
            server.calls = 0;
            server.fail = Some((1, after));
        }
        assert!(matches!(
            recovery().open_session(session, Some(c.client())),
            Err(DurableError::Anchor(_))
        ));
        {
            let mut server = c.server.lock().expect("witness");
            assert_eq!(server.calls, 1);
            server.fail = None;
        }
        let mut owner = recovery()
            .open_session_from_archive(&archive, Some(c.client()))
            .expect("same witness fresh retry");
        let (journal, index) = owner.stores().expect("restricted engines");
        assert_eq!(
            journal.status().expect("original session"),
            SessionClosureStatus::Open
        );
        let report = journal.begin().expect("freeze with witness");
        assert_eq!(
            report
                .epochs
                .iter()
                .map(|e| e.unconfirmed.len())
                .sum::<usize>(),
            1
        );
        assert!(matches!(
            index.retire_closed(journal, report.report),
            Err(DurableError::Suspended)
        ));
        owner.close();
        assert!(matches!(
            recovery().open_session(session, None),
            Err(DurableError::AnchorRequired)
        ));
    }
}
