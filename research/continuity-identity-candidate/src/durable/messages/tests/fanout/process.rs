// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{identity, ChildGuard};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn account_fanout_crash_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_FANOUT_DIR") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let public = fs::read(path.join("fanout-public"))?;
    assert_eq!(public.len(), 2 * q_periapt_sdk::PUBLIC_KEY_LEN);
    let public = public
        .as_chunks::<{ q_periapt_sdk::PUBLIC_KEY_LEN }>()
        .0
        .to_vec();
    let budget = u16::from_be_bytes(
        fs::read(path.join("fanout-budget"))?
            .try_into()
            .expect("budget width"),
    );
    let f = fixture(budget, false, Some(public));
    if std::env::var_os("QPERIAPT_FANOUT_CONTENDER").is_some() {
        assert!(matches!(
            DeviceJournal::open(
                &path.join("state.redb"),
                JournalKey::open(&path.join("key"))?,
                &f.local,
                identity(path)
            ),
            Err(DurableError::Database(PrivateDatabaseError::Busy))
        ));
        return Ok(());
    }
    let sessions = fs::read(path.join("fanout-sessions"))?;
    assert_eq!(sessions.len(), 64);
    let sessions: Vec<[u8; 32]> = sessions.as_chunks::<32>().0.to_vec();
    let id = FanoutId::from_trusted_state(
        fs::read(path.join("fanout-id"))?
            .try_into()
            .expect("ID width"),
    )?;
    let selected = targets(&f, &sessions);
    let mut sender = reopen(path, &f.local);
    if std::env::var_os("QPERIAPT_FANOUT_ABANDON").is_some() {
        let report = sender.begin_fanout_abandonment(id, &selected)?;
        super::abandonment::account(path, &report);
        sender.acknowledge_fanout_abandonment(id, report.report, &selected)?;
    } else {
        sender.send_account_message(
            FanoutInput {
                id,
                account: f.peers.first().expect("peer").account_id(),
                targets: &selected,
                plaintext: b"durable multi-device process cut",
                associated_data: b"account-message",
            },
            150,
        )?;
    }
    fs::write(path.join("fanout-returned"), b"whole aggregate returned")?;
    Ok(())
}

fn spawn(path: &Path, stage: Option<&str>) -> ChildGuard {
    let name = if stage.is_some() {
        "fanout-child.log"
    } else {
        "fanout-contender.log"
    };
    let log = fs::File::create_new(path.join(name)).expect("owned log");
    let mut command = Command::new(std::env::current_exe().expect("binary"));
    command
        .args([
            "--exact",
            "durable::messages::tests::fanout::process::account_fanout_crash_child",
            "--nocapture",
        ])
        .env("QPERIAPT_FANOUT_DIR", path)
        .stdout(Stdio::from(log.try_clone().expect("log")))
        .stderr(Stdio::from(log));
    match stage {
        Some(stage) => {
            command
                .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
                .env("QPERIAPT_MESSAGES_STAGE", stage);
        }
        None => {
            command.env("QPERIAPT_FANOUT_CONTENDER", "1");
        }
    }
    ChildGuard(command.spawn().expect("owned child"))
}

#[test]
fn account_fanout_process_cuts_preserve_all_members_and_exclude_concurrent_writers() {
    for stage in ["fanout-reserved", "fanout-computed", "fanout-committed"] {
        let mut n = Network::new(4, false);
        let id = n.sender.next_fanout_id().expect("ID");
        n.sender.close();
        let path = &n.sender_path;
        let public: Vec<u8> =
            n.f.keys
                .iter()
                .flat_map(|key| key.public_key().expect("public").to_bytes())
                .collect();
        fs::write(path.join("fanout-public"), public).expect("public fixture");
        fs::write(path.join("fanout-sessions"), n.sessions.concat()).expect("sessions");
        fs::write(path.join("fanout-id"), id.as_bytes()).expect("ID");
        fs::write(
            path.join("fanout-budget"),
            n.f.contexts
                .first()
                .expect("context")
                .current_policy()
                .expect("fixture policy owner")
                .application_send_budget()
                .messages()
                .to_be_bytes(),
        )
        .expect("budget");
        let mut child = spawn(path, Some(stage));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "{stage}: {}",
                fs::read_to_string(path.join("fanout-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(path.join("ready")).expect("complete marker"),
            stage
        );
        let mut contender = spawn(path, None);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = contender.0.try_wait().expect("contender status") {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(path.join("fanout-contender.log")).expect("log")
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "competing writer blocked instead of refusing ownership"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.join("fanout-returned").exists());
        child.0.kill().expect("kill owned process");
        assert!(!child.0.wait().expect("reap").success());
        n.sender = reopen(path, &n.f.local);
        let status = n.sender.fanout_status(id).expect("phase");
        assert_eq!(
            status,
            if stage == "fanout-committed" {
                FanoutStatus::Committed
            } else {
                FanoutStatus::Reserved
            }
        );
        if status == FanoutStatus::Reserved {
            let before = n.sender.image().expect("original");
            assert!(matches!(
                n.send(id, b"replacement after cancellation"),
                Err(DurableError::Conflict)
            ));
            for (context, session) in n.f.contexts.iter().zip(&n.sessions) {
                let message = MessageId::for_epoch(session, 1, 0, 0).expect("member ID");
                assert!(matches!(
                    n.sender.resume_message(context, *session, message, 150),
                    Err(DurableError::Suspended)
                ));
                assert!(
                    n.sender
                        .application_send_progress(context, *session)
                        .expect("budget")
                        .reserved
                );
            }
            assert_eq!(n.sender.image().expect("not changed").digest, before.digest);
            // Both links are necessary. Missing metadata or an ordinary-plan
            // relabel cannot pass authenticated-image admission.
            let mut orphan = n.sender.image().expect("image");
            orphan
                .records
                .retain(|_, record| record.kind != RecordKind::Fanout);
            assert!(matches!(
                validate_image(&orphan),
                Err(DurableError::Corrupt)
            ));
            let mut relabel = n.sender.image().expect("image");
            let mut s = State::decode(
                &relabel
                    .records
                    .get(&record_id(n.sessions.first().expect("session")))
                    .expect("record")
                    .payload,
            )
            .expect("state");
            s.traffic_mut(0)
                .expect("traffic")
                .pending
                .as_mut()
                .expect("plan")
                .fanout = None;
            relabel
                .records
                .get_mut(&record_id(n.sessions.first().expect("session")))
                .expect("record")
                .payload = s.encode();
            assert!(matches!(
                validate_image(&relabel),
                Err(DurableError::Corrupt)
            ));
            let mut partial = n.sender.image().expect("image");
            partial
                .records
                .values_mut()
                .find(|record| record.kind == RecordKind::Fanout)
                .expect("batch")
                .phase = DurableStatus::FanoutCommitted;
            assert!(matches!(
                validate_image(&partial),
                Err(DurableError::Corrupt)
            ));
        }
        let results = n
            .send(id, b"durable multi-device process cut")
            .expect("whole aggregate recovery");
        let saved = wires(&results);
        if stage == "fanout-computed" {
            assert_eq!(
                fs::read(n.sender_path.join("fanout-computed-wire"))
                    .expect("actual pre-commit ciphertext"),
                *saved.first().expect("first computed wire")
            );
        }
        n.check_delivery(&results, b"durable multi-device process cut");
        n.reopen();
        assert_eq!(
            wires(
                &n.send(id, b"durable multi-device process cut")
                    .expect("exact replay")
            ),
            saved
        );
        eprintln!(
            "ACCOUNT_FANOUT_PROCESS_RECOVERY cut={stage} recipients={} competing_writer=Busy",
            results.len()
        );
    }
}

// Reuse the real reservation/computation path, killed before API return.
pub(super) fn reserved(n: &mut Network, stage: &str) -> FanoutId {
    let id = n.sender.next_fanout_id().expect("ID");
    n.sender.close();
    let path = &n.sender_path;
    let public: Vec<u8> =
        n.f.keys
            .iter()
            .flat_map(|k| k.public_key().expect("public").to_bytes())
            .collect();
    fs::write(path.join("fanout-public"), public).expect("public fixture");
    fs::write(path.join("fanout-sessions"), n.sessions.concat()).expect("sessions");
    fs::write(path.join("fanout-id"), id.as_bytes()).expect("ID");
    fs::write(
        path.join("fanout-budget"),
        n.f.contexts
            .first()
            .expect("context")
            .current_policy()
            .expect("fixture policy owner")
            .application_send_budget()
            .messages()
            .to_be_bytes(),
    )
    .expect("budget");
    let mut child = spawn(path, Some(stage));
    wait_ready(path, &mut child, stage, "fanout-child.log");
    child.0.kill().expect("kill owned child");
    assert!(!child.0.wait().expect("reap").success());
    fs::rename(path.join("ready"), path.join("reservation-cut-ready"))
        .expect("retain stage evidence");
    n.sender = reopen(path, &n.f.local);
    assert_eq!(
        n.sender.fanout_status(id).expect("reserved"),
        FanoutStatus::Reserved
    );
    id
}
fn wait_ready(path: &Path, child: &mut ChildGuard, stage: &str, log: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "{stage}: {}",
            fs::read_to_string(path.join(log)).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_to_string(path.join("ready")).expect("marker"),
        stage
    );
}
pub(super) fn abandonment_cut(n: &mut Network, stage: &str) {
    n.sender.close();
    let path = &n.sender_path;
    let log = fs::File::create_new(path.join("fanout-abandon-child.log")).expect("new log");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "durable::messages::tests::fanout::process::account_fanout_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_FANOUT_DIR", path)
            .env("QPERIAPT_FANOUT_ABANDON", "1")
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .env("QPERIAPT_MESSAGES_STAGE", stage)
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    wait_ready(path, &mut child, stage, "fanout-abandon-child.log");
    let mut contender = spawn(path, None);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = contender.0.try_wait().expect("contender") {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(path.join("fanout-contender.log")).expect("log")
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "competing writer must refuse ownership"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.join("fanout-returned").exists());
    child.0.kill().expect("kill child");
    assert!(!child.0.wait().expect("reap").success());
    n.sender = reopen(path, &n.f.local);
}
