// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{identity, ChildGuard};
use crate::SessionArchiveStore;
use crate::{BootstrapRole, SessionClosureArchive, SessionClosureJournal};

#[test]
fn archived_catalogue_restore_and_retirement_require_exact_terminal_accounting() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut p = populated();
        let (journal, context, path) = match role {
            BootstrapRole::Initiator => (&mut p.ji, &p.f.initiator, &p.pi),
            BootstrapRole::Responder => (&mut p.jr, &p.f.responder, &p.pr),
        };
        let expected = journal.identity().expect("independent journal pin");
        let archive = journal
            .archive_session_closure(context, p.session)
            .expect("original scope");
        retain(path, "cleanup.archive", archive.as_bytes());
        let file = path.join("archives.redb");
        let mut index = SessionArchiveStore::provision(&file, expected).expect("explicit index");
        assert!(index.session_ids().expect("actual empty index").is_empty());
        context
            .current_policy()
            .expect("fixture policy owner")
            .close();
        journal.close();
        let mut owner = archived(path);
        let wrong = SessionClosureId::from_trusted_state([99; 32]).expect("wrong report");
        assert!(matches!(
            index.retire_closed(&mut owner, wrong),
            Err(DurableError::Suspended)
        ));
        index
            .restore(&mut owner)
            .expect("restore without operational context");
        index.restore(&mut owner).expect("exact retry");
        assert_eq!(index.session_ids().expect("discovery"), vec![p.session]);
        assert_eq!(
            index.get(p.session).expect("original archive").as_bytes(),
            archive.as_bytes()
        );
        let report = owner.begin().expect("freeze");
        assert!(matches!(
            index.retire_closed(&mut owner, report.report),
            Err(DurableError::Suspended)
        ));
        account(path, &report);
        owner
            .acknowledge(report.report)
            .expect("after complete host accounting");
        assert!(matches!(
            index.retire_closed(&mut owner, wrong),
            Err(DurableError::Conflict)
        ));
        assert!(index
            .retire_closed(&mut owner, report.report)
            .expect("remove exact closed row"));
        assert!(!index
            .retire_closed(&mut owner, report.report)
            .expect("authenticated absence"));
        assert!(index.session_ids().expect("real absence").is_empty());
        assert_eq!(
            owner.status().expect("still closed"),
            SessionClosureStatus::Closed(report.report)
        );
        index
            .restore(&mut owner)
            .expect("terminal metadata restoration grants no authority");
        assert_eq!(
            index.get(p.session).expect("same bytes").as_bytes(),
            archive.as_bytes()
        );
        index.close();
        owner.close();
        index = SessionArchiveStore::open(&file, expected).expect("restart discovery");
        assert_eq!(index.session_ids().expect("persisted ID"), vec![p.session]);
        assert!(matches!(
            index.restore(&mut owner),
            Err(DurableError::Closed)
        ));
        let mut owner = archived(path);
        let other_id = JournalIdentity::from_trusted_state([81; 32]).expect("different pin");
        let mut other = SessionArchiveStore::provision(&path.join("other-index.redb"), other_id)
            .expect("other index");
        assert!(matches!(
            other.restore(&mut owner),
            Err(DurableError::Conflict)
        ));
        assert!(other.session_ids().expect("other remains empty").is_empty());
        index
            .retire_closed(&mut owner, report.report)
            .expect("exact terminal retry");
        owner.close();
        let device = match role {
            BootstrapRole::Initiator => p.f.initiator_device(),
            BootstrapRole::Responder => p.f.local_device(),
        };
        let mut ordinary = reopen(path, device);
        assert!(ordinary.next_message_id(context, p.session, 150).is_err());
        let image = ordinary.image().expect("original keyless journal");
        let record = image
            .records
            .get(&record_id(&p.session))
            .expect("terminal is never erased");
        assert_eq!(record.phase, DurableStatus::MessagesClosed);
        assert_eq!(
            Retired::decode(&record.payload)
                .expect("keyless state")
                .report,
            *report.report.as_bytes()
        );
    }
}

#[test]
fn archived_catalogue_refuses_conflicting_rows_without_replacement() {
    let mut p = Pair::new();
    p.activate();
    let expected = p.jr.identity().expect("pin");
    let archive =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("archive");
    retain(&p.pr, "cleanup.archive", archive.as_bytes());
    p.jr.close();
    let mut owner = archived(&p.pr);
    let file = p.pr.join("archives.redb");
    let mut index = SessionArchiveStore::provision(&file, expected).expect("index");
    index.restore(&mut owner).expect("original row");
    index.close();
    let mut changed = archive.as_bytes().to_vec();
    *changed.last_mut().expect("MAC byte") ^= 1;
    crate::session_archives::tests::rewrite_archive(&file, p.session, Some(&changed));
    index = SessionArchiveStore::open(&file, expected)
        .expect("public parsing alone is not authentication");
    assert_eq!(
        index.session_ids().expect("discovery only"),
        vec![p.session]
    );
    assert!(matches!(
        index.restore(&mut owner),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(index.session_ids(), Err(DurableError::Closed)));
    let report = owner
        .begin()
        .expect("original journal independent of index");
    account(&p.pr, &report);
    owner.acknowledge(report.report).expect("closed");
    index = SessionArchiveStore::open(&file, expected).expect("conflicting public row");
    assert!(matches!(
        index.retire_closed(&mut owner, report.report),
        Err(DurableError::Conflict)
    ));
    index = SessionArchiveStore::open(&file, expected).expect("no overwrite or deletion");
    assert_eq!(
        index.get(p.session).expect("retained conflict").as_bytes(),
        changed
    );
}

#[test]
fn archived_catalogue_unknown_restore_and_retirement_results_keep_exact_recovery() {
    use crate::session_archives::tests::fault_index;
    let mut p = Pair::new();
    p.activate();
    let expected = p.jr.identity().expect("pin");
    let archive =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("archive");
    retain(&p.pr, "cleanup.archive", archive.as_bytes());
    p.f.responder
        .current_policy()
        .expect("fixture policy owner")
        .close();
    p.jr.close();
    let mut owner = archived(&p.pr);
    let report = owner.begin().expect("freeze original");
    account(&p.pr, &report);
    owner.acknowledge(report.report).expect("terminal original");
    for retiring in [false, true] {
        let baseline = p.pr.join(format!("index-baseline-{retiring}.redb"));
        let mut index = SessionArchiveStore::provision(&baseline, expected).expect("baseline");
        if retiring {
            index.restore(&mut owner).expect("row to retire");
        }
        index.close();
        let (mut index, _, count) = fault_index(&baseline, expected, false);
        count.store(0, Ordering::SeqCst);
        if retiring {
            assert!(index
                .retire_closed(&mut owner, report.report)
                .expect("baseline retirement"));
        } else {
            index.restore(&mut owner).expect("baseline restoration");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        index.close();
        let mut outcomes = std::collections::BTreeSet::new();
        for cut in 1..=barriers {
            for after in [false, true] {
                let file =
                    p.pr.join(format!("catalogue-{retiring}-{cut}-{after}.redb"));
                let mut index =
                    SessionArchiveStore::provision(&file, expected).expect("fresh test index");
                if retiring {
                    index.restore(&mut owner).expect("original row");
                }
                index.close();
                let (mut failed, remaining, _) = fault_index(&file, expected, after);
                remaining.store(cut, Ordering::SeqCst);
                let result = if retiring {
                    failed.retire_closed(&mut owner, report.report).map(|_| ())
                } else {
                    failed.restore(&mut owner)
                };
                crate::durable::tests::assert_sync_failure(result, after);
                assert!(matches!(failed.session_ids(), Err(DurableError::Closed)));
                let mut recovered =
                    SessionArchiveStore::open(&file, expected).expect("exact redb recovery");
                let outcome = recovered.get(p.session);
                let found = !matches!(&outcome, Err(DurableError::Absent));
                if found {
                    assert_eq!(
                        outcome.expect("only exact or absent readback").as_bytes(),
                        archive.as_bytes()
                    );
                }
                outcomes.insert(found);
                if retiring {
                    assert_eq!(
                        recovered
                            .retire_closed(&mut owner, report.report)
                            .expect("same terminal report"),
                        found
                    );
                    assert!(!recovered
                        .retire_closed(&mut owner, report.report)
                        .expect("repeat absence"));
                } else {
                    recovered
                        .restore(&mut owner)
                        .expect("same admitted original");
                    recovered.restore(&mut owner).expect("exact repeat");
                    assert_eq!(
                        recovered
                            .get(p.session)
                            .expect("original metadata")
                            .as_bytes(),
                        archive.as_bytes()
                    );
                }
            }
        }
        assert_eq!(outcomes, std::collections::BTreeSet::from([false, true]));
        eprintln!("ARCHIVED_CATALOGUE_SYNC retiring={retiring} barriers={barriers} faults={} outcomes={outcomes:?}", barriers * 2);
    }
}

// The child imports only the original private key and independently retained
// public identity/archive/report. It creates no policy, device or context owner.
#[test]
fn archived_catalogue_recovery_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_CATALOGUE_RECOVERY_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let mut owner = archived(path);
    let mut index = SessionArchiveStore::open(&path.join("archives.redb"), identity(path))?;
    let action = std::env::var("QPERIAPT_CATALOGUE_ACTION")?;
    match action.as_str() {
        "restore" => {
            index.restore(&mut owner)?;
            assert_eq!(index.session_ids()?.len(), 1);
            assert_eq!(owner.status()?, SessionClosureStatus::Open);
        }
        "retire" | "retire-repeat" => {
            let report = SessionClosureId::from_trusted_state(
                fs::read(path.join("catalogue-report-id"))?
                    .try_into()
                    .map_err(|_| "report width")?,
            )?;
            assert_eq!(owner.status()?, SessionClosureStatus::Closed(report));
            assert_eq!(index.retire_closed(&mut owner, report)?, action == "retire");
            assert!(index.session_ids()?.is_empty());
        }
        _ => return Err("unknown catalogue recovery action".into()),
    }
    index.close();
    owner.close();
    println!("ARCHIVED_CATALOGUE_PROCESS_PASS {action}");
    Ok(())
}

#[test]
fn archived_catalogue_fresh_process_recovery_keeps_journal_tombstones() {
    let mut p = populated();
    let archive =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("original archive");
    retain(&p.pr, "cleanup.archive", archive.as_bytes());
    SessionArchiveStore::provision(&p.pr.join("archives.redb"), identity(&p.pr))
        .expect("empty recovery index")
        .close();
    p.f.responder
        .current_policy()
        .expect("fixture policy owner")
        .close();
    p.jr.close();
    let run = |action: &str| {
        let log_path = p.pr.join(format!("catalogue-{action}.log"));
        let log = fs::File::create_new(&log_path).expect("log");
        let mut child = ChildGuard(Command::new(std::env::current_exe().expect("binary"))
            .args(["--exact", "durable::messages::tests::closure::archive::archived_catalogue_recovery_process_child", "--nocapture"])
            .env("QPERIAPT_CATALOGUE_RECOVERY_DIR", &p.pr)
            .env("QPERIAPT_CATALOGUE_ACTION", action)
            .stdin(Stdio::null()).stdout(Stdio::from(log.try_clone().expect("log"))).stderr(Stdio::from(log))
            .spawn().expect("recovery child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.0.try_wait().expect("status") {
                assert!(
                    status.success(),
                    "catalogue {action}: {}",
                    fs::read_to_string(&log_path).expect("log")
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "catalogue child exceeded deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(fs::read_to_string(log_path)
            .expect("result")
            .contains(&format!("ARCHIVED_CATALOGUE_PROCESS_PASS {action}")));
    };
    run("restore");
    let mut index = SessionArchiveStore::open(&p.pr.join("archives.redb"), identity(&p.pr))
        .expect("independent readback");
    assert_eq!(
        index.get(p.session).expect("exact original").as_bytes(),
        archive.as_bytes()
    );
    index.close();
    let mut owner = archived(&p.pr);
    let report = owner.begin().expect("complete loss report");
    account(&p.pr, &report);
    retain(&p.pr, "catalogue-report-id", report.report.as_bytes());
    owner.acknowledge(report.report).expect("terminal");
    owner.close();
    p.jr = reopen(&p.pr, p.f.local_device());
    let terminal_digest = p.jr.image().expect("terminal snapshot").digest;
    p.jr.close();
    run("retire");
    run("retire-repeat");
    p.jr = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        p.jr.image().expect("unchanged journal").digest,
        terminal_digest
    );
    assert!(p
        .jr
        .next_message_id(&p.f.responder, p.session, 150)
        .is_err());
    assert_eq!(
        p.jr.message_status(&p.f.responder, p.session, id(p.session, 2, 1))
            .expect("unknown retained"),
        MessageStatus::DeliveryUnknown
    );
}

fn archived(path: &Path) -> SessionClosureJournal {
    SessionClosureJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("original key"),
        identity(path),
        &SessionClosureArchive::from_bytes(
            &fs::read(path.join("cleanup.archive")).expect("archive"),
        )
        .expect("bounded archive"),
    )
    .expect("archived exact session")
}
fn retain(path: &Path, name: &str, bytes: &[u8]) {
    let mut f = fs::File::create_new(path.join(name)).expect("new metadata");
    f.write_all(bytes).expect("write metadata");
    f.sync_all().expect("sync metadata");
    fs::File::open(path)
        .expect("directory")
        .sync_all()
        .expect("sync name");
}
// This subprocess never constructs a policy, VerifiedDevice or BootstrapContext.
#[test]
fn archived_closure_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_SESSION_ARCHIVE_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let archive = SessionClosureArchive::from_bytes(&fs::read(path.join("cleanup.archive"))?)?;
    let result = SessionClosureJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key"))?,
        identity(path),
        &archive,
    );
    if std::env::var_os("QPERIAPT_REQUEST_CONTENDER").is_some() {
        assert!(matches!(
            result,
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        return Ok(());
    }
    let mut owner = result?;
    match fs::read_to_string(path.join("archive-operation"))?.as_str() {
        "begin" => {
            owner.begin()?;
        }
        "ack" => {
            let report = SessionClosureId::from_trusted_state(
                fs::read(path.join("closure-id"))?
                    .try_into()
                    .map_err(|_| "report width")?,
            )?;
            owner.acknowledge(report)?;
        }
        _ => return Err("unrecognized archive child operation".into()),
    }
    Err("expected observed process cut".into())
}
fn cut(path: &Path, operation: &str, stage: &str) {
    fs::write(path.join("archive-operation"), operation).expect("operation");
    let spawn = |contender: bool| {
        let log = fs::File::create_new(path.join(format!("archive-{operation}-{contender}.log")))
            .expect("new log");
        let mut command = Command::new(std::env::current_exe().expect("executable"));
        command
            .args([
                "--exact",
                "durable::messages::tests::closure::archive::archived_closure_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_SESSION_ARCHIVE_DIR", path)
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log));
        if contender {
            command
                .env("QPERIAPT_REQUEST_CONTENDER", "1")
                .env_remove("QPERIAPT_MESSAGES_STAGE");
        } else {
            command
                .env("QPERIAPT_MESSAGES_STAGE", stage)
                .env_remove("QPERIAPT_REQUEST_CONTENDER");
        }
        ChildGuard(command.spawn().expect("child"))
    };
    let mut child = spawn(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "archive {operation} missed committed stage"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(path.join("ready")).expect("marker"),
        stage
    );
    let mut contender = spawn(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = contender.0.try_wait().expect("contender status") {
            assert!(status.success(), "contender did not observe Busy");
            break;
        }
        assert!(Instant::now() < deadline, "contender exceeded deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("kill after committed stage");
    assert!(!child.0.wait().expect("reap child").success());
    fs::remove_file(path.join("ready")).expect("consume marker");
}
#[test]
fn archived_session_closure_restarts_without_verified_context_for_both_roles() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut p = populated();
        let (journal, context, path) = match role {
            BootstrapRole::Initiator => (&mut p.ji, &p.f.initiator, &p.pi),
            BootstrapRole::Responder => (&mut p.jr, &p.f.responder, &p.pr),
        };
        let before = journal.image().expect("before archive").digest;
        let archive = journal
            .archive_session_closure(context, p.session)
            .expect("capture original admission");
        assert_eq!(journal.image().expect("no mutation").digest, before);
        retain(path, "cleanup.archive", archive.as_bytes());
        assert!(matches!(
            p.f.bundle.verify(
                p.f.policy_owner(role),
                p.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                1001
            ),
            Err(Error::Validity)
        ));
        context
            .current_policy()
            .expect("fixture policy owner")
            .close();
        assert!(matches!(
            p.f.bundle.verify(
                p.f.policy_owner(role),
                p.f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                150
            ),
            Err(Error::Closed)
        ));
        journal.close();
        cut(path, "begin", "session-closing");
        let mut cleanup = archived(path);
        let report = cleanup
            .begin()
            .expect("same frozen report after fresh process");
        assert_eq!(report.context, context.digest());
        assert_eq!(report.session, p.session);
        assert_eq!(report.progress.confirmed_epoch, 1);
        assert_eq!(report.epochs.len(), 2);
        assert_eq!(
            cleanup.status().expect("pending"),
            SessionClosureStatus::Pending(report.report)
        );
        assert_eq!(cleanup.begin().expect("immutable retry"), report);
        assert!(matches!(
            cleanup.acknowledge(SessionClosureId::from_trusted_state([77; 32]).expect("wrong ID")),
            Err(DurableError::Conflict)
        ));
        account(path, &report);
        retain(path, "closure-id", report.report.as_bytes());
        cleanup.close();
        assert!(matches!(cleanup.status(), Err(DurableError::Closed)));
        cut(path, "ack", "session-closed");
        let mut cleanup = archived(path);
        assert_eq!(
            cleanup.status().expect("terminal"),
            SessionClosureStatus::Closed(report.report)
        );
        cleanup
            .acknowledge(report.report)
            .expect("same ACK idempotent");
        assert!(matches!(
            cleanup.begin(),
            Err(DurableError::Protocol(Error::Retired))
        ));
        cleanup.close();
        let device = match role {
            BootstrapRole::Initiator => p.f.initiator_device(),
            BootstrapRole::Responder => p.f.local_device(),
        };
        let mut ordinary = reopen(path, device);
        assert!(ordinary.next_message_id(context, p.session, 150).is_err());
        let image = ordinary.image().expect("persisted keyless state");
        let record = image.records.get(&record_id(&p.session)).expect("record");
        assert_eq!(record.phase, DurableStatus::MessagesClosed);
        assert!(State::decode(&record.payload).is_err());
        Retired::decode(&record.payload).expect("keyless terminal");
        eprintln!(
            "ARCHIVED_SESSION_CLOSURE role={role:?} committed_process_kills=2 busy_contenders=2"
        );
    }
}
#[test]
fn archived_session_closure_refuses_tampering_wrong_key_store_and_unadmitted_session() {
    let mut p = Pair::new();
    let prepared =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("preactivation archive");
    p.jr.close();
    assert!(matches!(
        SessionClosureJournal::open(
            &p.pr.join("state.redb"),
            JournalKey::open(&p.pr.join("key")).expect("key"),
            identity(&p.pr),
            &prepared
        ),
        Err(DurableError::Absent)
    ));
    p.jr = reopen(&p.pr, p.f.local_device());
    p.activate();
    let absent =
        p.jr.archive_session_closure(&p.f.responder, [81; 32])
            .expect("preparation grants no admission");
    p.jr.close();
    assert!(matches!(
        SessionClosureJournal::open(
            &p.pr.join("state.redb"),
            JournalKey::open(&p.pr.join("key")).expect("key"),
            identity(&p.pr),
            &absent
        ),
        Err(DurableError::Absent)
    ));
    p.jr = reopen(&p.pr, p.f.local_device());
    let archive =
        p.jr.archive_session_closure(&p.f.responder, p.session)
            .expect("archive");
    let before = p.jr.image().expect("image").digest;
    let expected = identity(&p.pr);
    p.jr.close();
    for end in 0..archive.as_bytes().len() {
        assert!(SessionClosureArchive::from_bytes(
            archive.as_bytes().get(..end).expect("bounded prefix")
        )
        .is_err());
    }
    let mut extra = archive.as_bytes().to_vec();
    extra.push(0);
    assert!(SessionClosureArchive::from_bytes(&extra).is_err());
    for offset in 0..archive.as_bytes().len() {
        let mut corrupt = archive.as_bytes().to_vec();
        *corrupt.get_mut(offset).expect("bounded byte") ^= 1;
        if let Ok(parsed) = SessionClosureArchive::from_bytes(&corrupt) {
            assert!(
                matches!(
                    SessionClosureJournal::open(
                        &p.pr.join("state.redb"),
                        JournalKey::open(&p.pr.join("key")).expect("key"),
                        expected,
                        &parsed
                    ),
                    Err(DurableError::Authentication)
                ),
                "byte={offset}"
            );
        }
    }
    assert!(matches!(
        SessionClosureJournal::open(
            &p.pr.join("state.redb"),
            JournalKey::open(&p.pi.join("key")).expect("other key"),
            expected,
            &archive
        ),
        Err(DurableError::Authentication)
    ));
    assert!(matches!(
        SessionClosureJournal::open(
            &p.pr.join("state.redb"),
            JournalKey::open(&p.pr.join("key")).expect("key"),
            identity(&p.pi),
            &archive
        ),
        Err(DurableError::Conflict)
    ));
    assert!(SessionClosureJournal::open(
        &p.pr.join("missing.redb"),
        JournalKey::open(&p.pr.join("key")).expect("key"),
        expected,
        &archive
    )
    .is_err());
    assert!(!p.pr.join("missing.redb").exists());
    // Even a copied wrapping key must not turn this archive into a new store scope.
    let d = directory();
    let other = d.path().canonicalize().expect("path");
    let mut journal = DeviceJournal::provision(
        &other.join("state.redb"),
        JournalKey::open(&p.pr.join("key")).expect("same key"),
        p.f.local_device(),
        crate::durable::tests::retain_new_identity(&other.join("store-id")),
    )
    .expect("separate existing journal");
    let other_id = journal.identity().expect("other identity");
    journal.close();
    assert!(matches!(
        SessionClosureJournal::open(
            &other.join("state.redb"),
            JournalKey::open(&p.pr.join("key")).expect("same key"),
            other_id,
            &archive
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        SessionClosureJournal::open(
            &other.join("state.redb"),
            JournalKey::open(&p.pr.join("key")).expect("same key"),
            expected,
            &archive
        ),
        Err(DurableError::Conflict)
    ));
    let mut normal = reopen(&p.pr, p.f.local_device());
    assert_eq!(
        normal
            .image()
            .expect("unchanged after all rejections")
            .digest,
        before
    );
    eprintln!(
        "ARCHIVED_SESSION_CLOSURE rejected_truncations={} tampered_bytes={}",
        archive.as_bytes().len(),
        archive.as_bytes().len()
    );
}

#[test]
fn archived_session_closure_recovers_only_sealed_activation_after_sync_faults() {
    let mut baseline = Pair::new();
    baseline.jr.close();
    let (mut journal, _, count, _) = fault_store(&baseline.pr, baseline.f.local_device(), false);
    count.store(0, Ordering::SeqCst);
    journal
        .activate_responder_messages(Arc::clone(&baseline.f.responder), &baseline.initial, 150)
        .expect("measure activation");
    let barriers = count.load(Ordering::SeqCst);
    assert_eq!(barriers, 4, "observed activation barriers");
    journal.close();
    let mut restored = 0;
    let mut absent = 0;
    for cut in 1..=barriers {
        for after in [false, true] {
            let mut p = Pair::new();
            let archive =
                p.jr.archive_session_closure(&p.f.responder, p.session)
                    .expect("preactivation scope");
            retain(&p.pr, "cleanup.archive", archive.as_bytes());
            let revision = p.jr.image().expect("original state").revision;
            p.jr.close();
            let (mut failed, remaining, _, _) = fault_store(&p.pr, p.f.local_device(), after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                failed.activate_responder_messages(Arc::clone(&p.f.responder), &p.initial, 150),
                after,
            );
            assert!(failed.active.is_none());
            // Inspect the actual sealed transaction, not the injected cut number.
            let has_activation = {
                let db =
                    open_private_database(&p.pr.join("state.redb")).expect("exclusive inspection");
                let key = JournalKey::open(&p.pr.join("key")).expect("key");
                let (image, pending) = write_intent::load_snapshot(
                    &db,
                    &key,
                    bootstrap::storage_owner(p.f.local_device()),
                )
                .expect("authenticated snapshot");
                image.records.contains_key(&record_id(&p.session))
                    || pending
                        .as_ref()
                        .map(|intent| {
                            intent
                                .authenticated_target(&key, image.owner)
                                .expect("original target")
                                .records
                                .contains_key(&record_id(&p.session))
                        })
                        .unwrap_or(false)
            };
            p.f.responder
                .current_policy()
                .expect("fixture policy owner")
                .close();
            let outcome = SessionClosureJournal::open(
                &p.pr.join("state.redb"),
                JournalKey::open(&p.pr.join("key")).expect("key"),
                identity(&p.pr),
                &archive,
            );
            if has_activation {
                restored += 1;
                let mut owner = outcome.expect("only original sealed activation recovers");
                let report = owner.begin().expect("freeze after recovery");
                account(&p.pr, &report);
                owner.acknowledge(report.report).expect("terminal");
                owner.close();
                let mut stored = reopen(&p.pr, p.f.local_device());
                assert_eq!(
                    stored
                        .image()
                        .expect("one activation plus freeze and terminal")
                        .revision,
                    revision + 3
                );
            } else {
                absent += 1;
                assert!(
                    matches!(outcome, Err(DurableError::Absent)),
                    "archive cannot fabricate activation"
                );
                let mut stored = reopen(&p.pr, p.f.local_device());
                assert_eq!(stored.image().expect("unchanged").revision, revision);
            }
        }
    }
    assert!(
        restored > 0 && absent > 0,
        "must observe both actual persisted outcomes"
    );
    eprintln!("ARCHIVED_SESSION_ACTIVATION barriers={barriers} faults={} sealed_restored={restored} absent={absent}",barriers*2);
}
