// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
mod committed;
use crate::durable::tests::{identity, ChildGuard};
use crate::{FanoutAbandonmentJournal, SessionArchiveStore, SessionClosureJournal};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) fn retain(n: &mut Network) -> SessionArchiveStore {
    let mut index = SessionArchiveStore::provision(
        &n.sender_path.join("archives.redb"),
        n.sender.identity().expect("identity"),
    )
    .expect("archive index");
    for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
        let archive = n
            .sender
            .archive_session_closure(context, *session)
            .expect("original scope");
        index
            .retain(&n.sender, context, *session, &archive)
            .expect("durable archive");
    }
    index
}
fn index(path: &Path) -> SessionArchiveStore {
    SessionArchiveStore::open(&path.join("archives.redb"), identity(path)).expect("original index")
}
fn open(
    path: &Path,
    id: FanoutId,
    index: &mut SessionArchiveStore,
) -> Result<FanoutAbandonmentJournal, DurableError> {
    FanoutAbandonmentJournal::open(
        &path.join("state.redb"),
        JournalKey::open(&path.join("key")).expect("original key"),
        identity(path),
        id,
        index,
    )
}
fn observe(path: &Path, owner: [u8; 32]) -> ([u8; 32], Option<[u8; 32]>) {
    let db = open_private_database(&path.join("state.redb")).expect("exclusive inspection");
    let key = JournalKey::open(&path.join("key")).expect("key");
    let (image, pending) =
        write_intent::load_snapshot(&db, &key, owner).expect("authenticated snapshot");
    (
        image.digest,
        pending.map(|p| p.authenticated_target(&key, owner).expect("target").digest),
    )
}
pub(super) fn reserve(n: &mut Network) -> FanoutId {
    let id = n.sender.next_fanout_id().expect("ID");
    n.sender.close();
    let (failed, remaining, _, _) = fault_store(&n.sender_path, &n.f.local, false);
    n.sender = failed;
    // The first intent is durable, before the aggregate image's first barrier.
    remaining.store(3, Ordering::SeqCst);
    crate::durable::tests::assert_sync_failure(n.send(id, b"original whole-batch input"), false);
    n.sender = reopen(&n.sender_path, &n.f.local);
    assert_eq!(
        n.sender.fanout_status(id).expect("actual recovered phase"),
        FanoutStatus::Reserved
    );
    id
}

// Only retained public IDs/index, original wrapping key and the account ledger
// enter this fresh process. No verified identity, policy or context is built.
#[test]
fn archived_fanout_cleanup_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_FANOUT_ARCHIVE_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    if std::env::var_os("QPERIAPT_FANOUT_ARCHIVE_CONTENDER").is_some() {
        assert!(matches!(
            SessionArchiveStore::open(&path.join("archives.redb"), identity(path)),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        assert!(matches!(
            crate::BootstrapCancellationJournal::open(
                &path.join("state.redb"),
                JournalKey::open(&path.join("key"))?,
                identity(path)
            ),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        return Ok(());
    }
    let id = FanoutId::from_trusted_state(
        fs::read(path.join("fanout-id"))?
            .try_into()
            .map_err(|_| "ID width")?,
    )?;
    let mut index = index(path);
    let mut owner = open(path, id, &mut index)?;
    match fs::read_to_string(path.join("archive-action"))?.as_str() {
        "begin" => {
            owner.begin()?;
        }
        "ack" => {
            let report = FanoutAbandonmentId::from_trusted_state(
                fs::read(path.join("archive-report"))?
                    .try_into()
                    .map_err(|_| "report width")?,
            )?;
            assert!(!fs::read(path.join("abandonment-accounting"))?.is_empty());
            owner.acknowledge(report)?;
        }
        "retire" => {
            owner.retire_metadata()?;
        }
        _ => return Err("unknown cleanup action".into()),
    }
    Err("expected observed cleanup cut".into())
}
fn cut(path: &Path, action: &str, stage: &str) {
    fs::write(path.join("archive-action"), action).expect("action");
    let spawn = |contender: bool| {
        let log = fs::File::create_new(path.join(format!("archive-{action}-{contender}.log")))
            .expect("new log");
        let mut cmd = Command::new(std::env::current_exe().expect("binary"));
        cmd.args([
            "--exact",
            "durable::messages::tests::fanout::archive::archived_fanout_cleanup_process_child",
            "--nocapture",
        ])
        .env("QPERIAPT_FANOUT_ARCHIVE_DIR", path)
        .stdout(Stdio::from(log.try_clone().expect("log")))
        .stderr(Stdio::from(log));
        if contender {
            cmd.env("QPERIAPT_FANOUT_ARCHIVE_CONTENDER", "1");
        } else {
            cmd.env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage);
        }
        ChildGuard(cmd.spawn().expect("child"))
    };
    let mut child = spawn(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "cleanup missed {stage}: {}",
            fs::read_to_string(path.join(format!("archive-{action}-false.log"))).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut contender = spawn(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = contender.0.try_wait().expect("status") {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "contender must be bounded");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("kill observed commit");
    assert!(!child.0.wait().expect("reap").success());
    fs::rename(path.join("ready"), path.join(format!("observed-{stage}"))).expect("retain marker");
}

#[test]
fn archived_fanout_restart_closes_and_retires_the_whole_reserved_batch() {
    for (action, stage) in [
        ("begin", "fanout-abandoning"),
        ("ack", "fanout-abandoned"),
        ("retire", "fanout-archive-retired"),
    ] {
        let mut n = Network::new(4, false);
        let mut index = retain(&mut n);
        let id = process::reserved(&mut n, "fanout-computed");
        for context in &n.f.contexts {
            context
                .current_policy()
                .expect("fixture policy owner")
                .close();
        }
        n.sender.close();
        let archive = index
            .get(*n.sessions.first().expect("session"))
            .expect("single scope");
        let mut single = SessionClosureJournal::open(
            &n.sender_path.join("state.redb"),
            JournalKey::open(&n.sender_path.join("key")).expect("key"),
            identity(&n.sender_path),
            &archive,
        )
        .expect("individual owner");
        assert!(
            matches!(single.begin(), Err(DurableError::Suspended)),
            "single-session cleanup cannot split an aggregate"
        );
        single.close();
        let mut owner = open(&n.sender_path, id, &mut index).expect("complete indexed scope");
        assert_eq!(owner.status().expect("status"), FanoutStatus::Reserved);
        assert!(matches!(
            owner.retire_metadata(),
            Err(DurableError::Suspended)
        ));
        let mut saved = None;
        if action != "begin" {
            let report = owner.begin().expect("freeze all members");
            assert_eq!(report.sessions.len(), n.sessions.len());
            abandonment::account(&n.sender_path, &report);
            fs::write(
                n.sender_path.join("archive-report"),
                report.report.as_bytes(),
            )
            .expect("receipt");
            if action == "retire" {
                owner.acknowledge(report.report).expect("host accounted");
            }
            saved = Some(report);
        }
        owner.close();
        index.close();
        cut(&n.sender_path, action, stage);
        index = self::index(&n.sender_path);
        if action == "retire" {
            assert!(matches!(
                open(&n.sender_path, id, &mut index),
                Err(DurableError::Protocol(Error::Retired))
            ));
        } else {
            let mut owner = open(&n.sender_path, id, &mut index).expect("recover exact aggregate");
            let report = if let Some(report) = saved {
                report
            } else {
                let report = owner.begin().expect("original immutable report");
                assert_eq!(owner.begin().expect("duplicate report"), report);
                abandonment::account(&n.sender_path, &report);
                report
            };
            assert!(matches!(
                owner.acknowledge(
                    FanoutAbandonmentId::from_trusted_state([33; 32]).expect("wrong receipt")
                ),
                Err(DurableError::Conflict)
            ));
            owner.acknowledge(report.report).expect("terminal");
            owner.acknowledge(report.report).expect("exact duplicate");
            assert_eq!(
                owner.status().expect("terminal"),
                FanoutStatus::Abandoned(report.report)
            );
            owner.retire_metadata().expect("only metadata");
            owner.retire_metadata().expect("duplicate retirement");
            assert_eq!(owner.status().expect("retired"), FanoutStatus::Retired);
            owner.close();
            assert!(matches!(owner.status(), Err(DurableError::Closed)));
        }
        n.sender = reopen(&n.sender_path, &n.f.local);
        assert_eq!(
            n.sender.fanout_status(id).expect("retired ID"),
            FanoutStatus::Retired
        );
        let image = n.sender.image().expect("terminal image");
        for session in &n.sessions {
            let record = image
                .records
                .get(&record_id(session))
                .expect("terminal member");
            assert_eq!(record.phase, DurableStatus::MessagesAbandoned);
            assert!(State::decode(&record.payload).is_err());
            let terminal = Retired::decode(&record.payload).expect("keyless member");
            assert_eq!(terminal.batch, Some(id));
            assert!(image.records.contains_key(&terminal.source));
        }
        assert!(n.sender.next_fanout_id().expect("monotonic successor") > id);
        eprintln!("ARCHIVED_FANOUT_PROCESS cut={stage} original_members={} journal_and_index_contenders=Busy", n.sessions.len());
    }
}

#[test]
fn archived_fanout_catalogue_restores_frozen_and_terminal_members_without_split_authority() {
    for acknowledged in [false, true] {
        let mut n = Network::new(4, false);
        let mut index = retain(&mut n);
        let id = reserve(&mut n);
        let session = *n.sessions.first().expect("member");
        let backup = index.get(session).expect("independent original archive");
        for context in &n.f.contexts {
            context
                .current_policy()
                .expect("fixture policy owner")
                .close();
        }
        n.sender.close();
        let mut owner = open(&n.sender_path, id, &mut index).expect("complete original membership");
        let report = owner.begin().expect("freeze whole batch");
        if acknowledged {
            abandonment::account(&n.sender_path, &report);
            owner
                .acknowledge(report.report)
                .expect("complete host accounting");
        }
        owner.close();
        index.close();
        let before = observe(&n.sender_path, bootstrap::storage_owner(&n.f.local));
        crate::session_archives::tests::rewrite_archive(
            &n.sender_path.join("archives.redb"),
            session,
            None,
        );
        index = self::index(&n.sender_path);
        assert!(matches!(
            open(&n.sender_path, id, &mut index),
            Err(DurableError::ArchiveRequired)
        ));
        assert_eq!(
            observe(&n.sender_path, bootstrap::storage_owner(&n.f.local)),
            before
        );
        let mut single = SessionClosureJournal::open(
            &n.sender_path.join("state.redb"),
            JournalKey::open(&n.sender_path.join("key")).expect("original key"),
            identity(&n.sender_path),
            &backup,
        )
        .expect("exact original member admitted for metadata recovery");
        assert!(matches!(single.begin(), Err(DurableError::Suspended)));
        index
            .restore(&mut single)
            .expect("original metadata must remain recoverable after aggregate freeze");
        index.restore(&mut single).expect("same bytes idempotent");
        assert_eq!(
            index.get(session).expect("original row").as_bytes(),
            backup.as_bytes()
        );
        let wrong_kind = crate::SessionClosureId::from_trusted_state(*report.report.as_bytes())
            .expect("same bytes cannot change report kind");
        assert!(matches!(
            index.retire_closed(&mut single, wrong_kind),
            Err(DurableError::Suspended)
        ));
        assert!(matches!(
            single.acknowledge(wrong_kind),
            Err(DurableError::Conflict)
        ));
        single.close();
        assert_eq!(
            observe(&n.sender_path, bootstrap::storage_owner(&n.f.local)),
            before
        );
        let mut whole =
            open(&n.sender_path, id, &mut index).expect("all original members restored");
        assert_eq!(
            whole.status().expect("unchanged disposition"),
            if acknowledged {
                FanoutStatus::Abandoned(report.report)
            } else {
                FanoutStatus::Abandoning(report.report)
            }
        );
        if !acknowledged {
            abandonment::account(&n.sender_path, &report);
        }
        whole
            .acknowledge(report.report)
            .expect("same whole-batch report");
        whole
            .retire_metadata()
            .expect("original aggregate metadata");
        assert_eq!(whole.status().expect("terminal ID"), FanoutStatus::Retired);
        whole.close();
        n.sender = reopen(&n.sender_path, &n.f.local);
        let image = n.sender.image().expect("all terminal records retained");
        for member in &n.sessions {
            let record = image
                .records
                .get(&record_id(member))
                .expect("terminal member");
            assert_eq!(record.phase, DurableStatus::MessagesAbandoned);
            assert_eq!(
                Retired::decode(&record.payload)
                    .expect("keyless member")
                    .batch,
                Some(id)
            );
        }
        eprintln!(
            "AGGREGATE_CATALOGUE_RECOVERY acknowledged={acknowledged} original_members={}",
            n.sessions.len()
        );
    }
}

#[test]
fn archived_fanout_requires_every_original_archive_before_recovery_writes() {
    let mut n = Network::new(4, false);
    let mut index = retain(&mut n);
    let id = reserve(&mut n);
    let session = *n.sessions.first().expect("member");
    let original = index.get(session).expect("archive").as_bytes().to_vec();
    let wrong_context = n.f.contexts.get(1).expect("other original context");
    let substituted = n
        .sender
        .archive_session_closure(wrong_context, session)
        .expect("valid MAC for different scope")
        .as_bytes()
        .to_vec();
    n.sender.close();
    let (mut failed, remaining, _, _) = fault_store(&n.sender_path, &n.f.local, false);
    remaining.store(3, Ordering::SeqCst);
    crate::durable::tests::assert_sync_failure(
        failed.begin_fanout_abandonment(id, &targets(&n.f, &n.sessions)),
        false,
    );
    index.close();
    let before = observe(&n.sender_path, bootstrap::storage_owner(&n.f.local));
    assert!(
        before.1.is_some(),
        "real sealed freeze intent exists before archive admission"
    );
    let mut bad_mac = original.clone();
    *bad_mac.last_mut().expect("MAC") ^= 1;
    for (bytes, reason) in [
        (None, "missing"),
        (Some(bad_mac.as_slice()), "mac"),
        (Some(substituted.as_slice()), "context"),
    ] {
        crate::session_archives::tests::rewrite_archive(
            &n.sender_path.join("archives.redb"),
            session,
            bytes,
        );
        let mut index = self::index(&n.sender_path);
        let result = open(&n.sender_path, id, &mut index);
        assert!(
            match reason {
                "missing" => matches!(result, Err(DurableError::ArchiveRequired)),
                "mac" => matches!(result, Err(DurableError::Authentication)),
                "context" => matches!(result, Err(DurableError::Conflict)),
                _ => false,
            },
            "failure identity {reason}"
        );
        index.close();
        assert_eq!(
            observe(&n.sender_path, bootstrap::storage_owner(&n.f.local)),
            before
        );
    }
    crate::session_archives::tests::rewrite_archive(
        &n.sender_path.join("archives.redb"),
        session,
        Some(&original),
    );
    let mut index = self::index(&n.sender_path);
    let mut owner = open(&n.sender_path, id, &mut index).expect("restore only original metadata");
    let report = owner.begin().expect("whole report");
    assert_eq!(report.sessions.len(), n.sessions.len());
    owner.close();
}

#[test]
fn archived_fanout_never_relabels_a_committed_batch_as_reserved_abandonment() {
    let mut n = Network::new(4, false);
    let mut index = retain(&mut n);
    let id = n.sender.next_fanout_id().expect("ID");
    n.send(id, b"already committed").expect("commit");
    let before = n.sender.image().expect("image").digest;
    n.sender.close();
    let mut owner = open(&n.sender_path, id, &mut index).expect("scope");
    assert_eq!(owner.status().expect("status"), FanoutStatus::Committed);
    assert!(matches!(owner.begin(), Err(DurableError::Conflict)));
    assert!(matches!(
        owner.retire_metadata(),
        Err(DurableError::Suspended)
    ));
    owner.close();
    assert_eq!(
        observe(&n.sender_path, bootstrap::storage_owner(&n.f.local)).0,
        before
    );
}

#[test]
fn archived_fanout_admits_only_an_existing_or_exactly_sealed_reservation() {
    let mut n = Network::new(4, false);
    let mut index = retain(&mut n);
    let id = n.sender.next_fanout_id().expect("retained request");
    n.sender.close();
    assert!(
        matches!(
            open(&n.sender_path, id, &mut index),
            Err(DurableError::Absent)
        ),
        "an index never provisions a missing batch"
    );
    let wrong = directory();
    let wrong = canonical(&wrong);
    assert!(matches!(
        FanoutAbandonmentJournal::open(
            &n.sender_path.join("state.redb"),
            JournalKey::provision(&wrong.join("key")).expect("different key"),
            identity(&n.sender_path),
            id,
            &mut index
        ),
        Err(DurableError::Authentication)
    ));
    assert!(matches!(
        FanoutAbandonmentJournal::open(
            &n.sender_path.join("state.redb"),
            JournalKey::open(&n.sender_path.join("key")).expect("key"),
            JournalIdentity::from_trusted_state([67; 32]).expect("wrong journal"),
            id,
            &mut index
        ),
        Err(DurableError::Conflict)
    ));
    let (journal, remaining, _, _) = fault_store(&n.sender_path, &n.f.local, false);
    n.sender = journal;
    remaining.store(3, Ordering::SeqCst);
    crate::durable::tests::assert_sync_failure(n.send(id, b"sealed original reservation"), false);
    let before = observe(&n.sender_path, bootstrap::storage_owner(&n.f.local));
    assert!(before.1.is_some(), "exact reservation intent persisted");
    let session = *n.sessions.first().expect("member");
    let archive = index
        .get(session)
        .expect("original archive")
        .as_bytes()
        .to_vec();
    index.close();
    crate::session_archives::tests::rewrite_archive(
        &n.sender_path.join("archives.redb"),
        session,
        None,
    );
    index = self::index(&n.sender_path);
    assert!(matches!(
        open(&n.sender_path, id, &mut index),
        Err(DurableError::ArchiveRequired)
    ));
    assert_eq!(
        observe(&n.sender_path, bootstrap::storage_owner(&n.f.local)),
        before,
        "no reservation recovery before all archives authenticate"
    );
    index.close();
    crate::session_archives::tests::rewrite_archive(
        &n.sender_path.join("archives.redb"),
        session,
        Some(&archive),
    );
    index = self::index(&n.sender_path);
    let mut owner =
        open(&n.sender_path, id, &mut index).expect("only the original sealed reservation");
    assert_eq!(
        owner.status().expect("actual phase"),
        FanoutStatus::Reserved
    );
    let report = owner.begin().expect("all original inputs");
    assert!(report
        .sessions
        .iter()
        .all(|s| s.reserved.plaintext_bytes == b"sealed original reservation".len()));
    owner.close();
}

#[test]
fn archived_fanout_mixed_roles_and_committed_revocation_preserve_complete_loss_accounting() {
    let mut n = roles::mixed_roles();
    let mut index = retain(&mut n);
    let old = n.sender.next_fanout_id().expect("prior ID");
    n.send(old, b"prior unknown delivery")
        .expect("prior outboxes");
    for ((context, session), peer) in n.f.contexts.iter().zip(&n.sessions).zip(&mut n.receivers) {
        let id = peer
            .next_message_id(context, *session, 150)
            .expect("peer slot");
        let wire = peer
            .send_message(
                context,
                *session,
                id,
                b"unconsumed content",
                b"private AD",
                150,
            )
            .expect("peer output");
        n.sender
            .receive_message(context, *session, &wire, b"private AD", 150)
            .expect("durable inbox");
    }
    let id = reserve(&mut n);
    let entries: Vec<_> =
        n.f.certificates
            .iter()
            .take(1)
            .map(|c| n.f.root.roster_entry(c).expect("entry"))
            .collect();
    let issued =
        n.f.root
            .issue_roster(2, interval(), &entries)
            .expect("revocation");
    let pin = AccountPin::new(
        n.f.root.account_id().expect("account"),
        n.f.root.public_key().expect("root"),
        issued.checkpoint(),
        n.f.contexts
            .first()
            .expect("context")
            .current_policy()
            .expect("fixture policy owner")
            .family(),
    )
    .expect("pin");
    n.sender
        .install_roster(
            &pin.verify_roster(issued.as_bytes(), 150)
                .expect("verified update"),
            150,
        )
        .expect("durable revocation");
    for context in &n.f.contexts {
        context
            .current_policy()
            .expect("fixture policy owner")
            .close();
    }
    n.sender.close();
    let mut owner =
        open(&n.sender_path, id, &mut index).expect("original complete scope after revocation");
    let report = owner.begin().expect("whole report");
    assert_eq!(
        report
            .sessions
            .iter()
            .map(|s| s.role)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2])
    );
    for member in &report.sessions {
        assert_eq!(
            member
                .epochs
                .iter()
                .map(|e| e.unconfirmed.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            member
                .epochs
                .iter()
                .map(|e| e.deliveries.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            member.reserved.plaintext_bytes,
            b"original whole-batch input".len()
        );
        assert!(member
            .epochs
            .iter()
            .all(|e| e.acknowledged_before == 0 && e.consumed_before == 0));
    }
    owner.close();
    n.sender = reopen(&n.sender_path, &n.f.local);
    assert_eq!(
        n.sender
            .begin_fanout_abandonment(id, &targets(&n.f, &n.sessions))
            .expect("same shared engine"),
        report
    );
    n.sender.close();
    let mut owner = open(&n.sender_path, id, &mut index).expect("reopen frozen");
    abandonment::account(&n.sender_path, &report);
    owner.acknowledge(report.report).expect("terminal");
    owner.retire_metadata().expect("retire metadata");
    owner.close();
    n.sender = reopen(&n.sender_path, &n.f.local);
    for member in &report.sessions {
        assert_eq!(
            n.sender
                .message_status(
                    n.f.contexts
                        .iter()
                        .find(|c| c.digest() == member.context)
                        .expect("original context"),
                    member.session,
                    member.reserved.message
                )
                .expect("terminal reservation"),
            MessageStatus::ReservationAbandoned
        );
    }
}

#[test]
fn archived_fanout_reconciles_every_shared_lifecycle_sync_barrier() {
    fn prepare(
        stage: u8,
    ) -> (
        Network,
        FanoutId,
        SessionArchiveStore,
        Option<FanoutAbandonmentId>,
    ) {
        let mut n = Network::new(4, false);
        let index = retain(&mut n);
        let id = reserve(&mut n);
        let report = if stage > 0 {
            let report = n
                .sender
                .begin_fanout_abandonment(id, &targets(&n.f, &n.sessions))
                .expect("freeze");
            abandonment::account(&n.sender_path, &report);
            if stage == 2 {
                n.sender
                    .acknowledge_fanout_abandonment(id, report.report, &targets(&n.f, &n.sessions))
                    .expect("terminal");
            }
            Some(report.report)
        } else {
            None
        };
        n.sender.close();
        (n, id, index, report)
    }
    fn transition(
        n: &mut Network,
        id: FanoutId,
        stage: u8,
        report: Option<FanoutAbandonmentId>,
    ) -> Result<(), DurableError> {
        let selected = targets(&n.f, &n.sessions);
        match stage {
            0 => n.sender.begin_fanout_abandonment(id, &selected).map(|_| ()),
            1 => n.sender.acknowledge_fanout_abandonment(
                id,
                report.expect("accounted receipt"),
                &selected,
            ),
            2 => n.sender.retire_fanout(id, &selected),
            _ => unreachable!(),
        }
    }
    for stage in 0..3 {
        let (mut baseline, id, _, report) = prepare(stage);
        let (journal, _, count, _) = fault_store(&baseline.sender_path, &baseline.f.local, false);
        baseline.sender = journal;
        count.store(0, Ordering::SeqCst);
        transition(&mut baseline, id, stage, report).expect("measured transition");
        let barriers = count.load(Ordering::SeqCst);
        assert!(barriers > 0);
        baseline.sender.close();
        for after in [false, true] {
            for at in 1..=barriers {
                let (mut n, id, mut index, report) = prepare(stage);
                let (journal, remaining, _, _) = fault_store(&n.sender_path, &n.f.local, after);
                n.sender = journal;
                remaining.store(at, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    transition(&mut n, id, stage, report),
                    after,
                );
                assert!(n.sender.active.is_none());
                let restored = open(&n.sender_path, id, &mut index);
                if matches!(&restored, Err(DurableError::Protocol(Error::Retired))) {
                    assert_eq!(stage, 2);
                    continue;
                }
                let mut owner = restored.expect("exact indexed reconciliation");
                if stage == 0 {
                    let report = owner.begin().expect("complete frozen report");
                    assert_eq!(report.sessions.len(), n.sessions.len());
                    assert_eq!(owner.begin().expect("exact replay"), report);
                } else if stage == 1 {
                    let report = report.expect("receipt");
                    owner.acknowledge(report).expect("exact acknowledgement");
                    assert_eq!(
                        owner.status().expect("status"),
                        FanoutStatus::Abandoned(report)
                    );
                } else {
                    owner.retire_metadata().expect("exact retirement");
                    assert_eq!(owner.status().expect("status"), FanoutStatus::Retired);
                }
                owner.close();
            }
        }
        eprintln!("ARCHIVED_FANOUT_SYNC stage={stage} measured_barriers={barriers} before_after_faults={}",barriers*2);
    }
}

#[test]
fn historical_fanout_projection_covers_reserved_committed_and_abandoned_original_members() {
    use crate::retired_device::{MemberState, RecordMetadata};
    for reserved in [false, true] {
        let mut n = Network::new(4, false);
        let mut index = retain(&mut n);
        let batch = if reserved {
            reserve(&mut n)
        } else {
            let id = n.sender.next_fanout_id().expect("ID");
            n.send(id, b"original whole-batch input")
                .expect("committed aggregate");
            id
        };
        let key = JournalKey::open(&n.sender_path.join("key")).expect("key");
        for phase in 0..if reserved { 3 } else { 1 } {
            let image = n.sender.image().expect("authenticated actual image");
            let record_id = *image
                .records
                .iter()
                .find(|(_, record)| record.kind == RecordKind::Fanout)
                .expect("only actual batch")
                .0;
            let record = image.records.get(&record_id).expect("actual batch");
            let projected = super::super::super::fanout::historical_fanout(
                &image, &key, &record_id, record, &mut index,
            )
            .expect("all original members");
            let (status, members) = match projected {
                RecordMetadata::Fanout {
                    status, members, ..
                } => Ok((status, members)),
                _ => Err("expected batch"),
            }
            .expect("batch projection");
            assert_eq!(members.len(), n.sessions.len());
            for ((member, session), peer) in members.iter().zip(&n.sessions).zip(&n.f.peers) {
                assert_eq!(member.session, *session);
                assert_eq!(
                    (member.device, member.generation, member.credential),
                    (
                        peer.device_id(),
                        peer.generation(),
                        peer.credential_digest()
                    )
                );
                assert_eq!(
                    member.state,
                    if reserved {
                        if phase == 2 {
                            MemberState::Retained(FanoutMemberState::ReservationAbandoned)
                        } else {
                            MemberState::Reserved
                        }
                    } else {
                        MemberState::Retained(FanoutMemberState::Committed)
                    }
                );
                assert_eq!(member.ciphertext_digest.is_some(), !reserved);
            }
            if reserved && phase == 0 {
                assert_eq!(status, FanoutStatus::Reserved);
                n.sender
                    .begin_fanout_abandonment(batch, &targets(&n.f, &n.sessions))
                    .expect("original pending closure");
            }
            if reserved && phase == 1 {
                let report = match status {
                    FanoutStatus::Abandoning(id) => Ok(id),
                    _ => Err("expected original pending report"),
                }
                .expect("report");
                n.sender
                    .acknowledge_fanout_abandonment(batch, report, &targets(&n.f, &n.sessions))
                    .expect("prior host acknowledgment");
            }
            if reserved && phase == 2 {
                assert!(matches!(status, FanoutStatus::Abandoned(_)));
            }
        }
    }
}
