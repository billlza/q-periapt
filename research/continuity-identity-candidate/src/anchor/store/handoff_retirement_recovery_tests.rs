// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn retirement_each_sync_failure_reconciles_original_frozen_or_retired_decision() {
    let mut calibration = case();
    let (f, _target, ack) = imported(&mut calibration);
    let (_, count) = with_fault_database(&mut calibration, false);
    count.store(0, Ordering::SeqCst);
    calibration
        .store
        .retire_handoff(&f.approval, &ack, || Ok(150))
        .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let (f, _target, ack) = imported(&mut c);
            let (remaining, _) = with_fault_database(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                c.store
                    .retire_handoff(&f.approval, &ack, || Ok(150))
                    .map(|_| ()),
                after,
            );
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            let observed = c
                .store
                .observe_handoff(&f.plan)
                .expect("actual original outcome");
            assert!(matches!(
                observed.state(),
                AnchorHandoffState::Frozen | AnchorHandoffState::Retired
            ));
            let receipt = c
                .store
                .retire_handoff(&f.approval, &ack, || Ok(150))
                .expect("exact original retry");
            if observed.state() == AnchorHandoffState::Retired {
                assert_eq!(receipt.as_bytes(), observed.as_bytes());
            }
            assert_eq!(
                c.store
                    .observe_handoff(&f.plan)
                    .expect("exact persisted certificate")
                    .as_bytes(),
                receipt.as_bytes()
            );
            assert_eq!(
                c.store
                    .frozen_handoff_state(&f.plan)
                    .expect("full unchanged original")
                    .as_bytes(),
                f.source
            );
            assert!(matches!(
                c.store.cancel_handoff(&f.plan),
                Err(DurableError::Protocol(Error::Retired))
            ));
        }
    }
    eprintln!(
        "HANDOFF_RETIRE_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn retirement_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_HANDOFF_RETIRE_TARGET") else {
        return;
    };
    let root = Path::new(&root);
    let source = super::super::recovery::trusted_pin(&root.join("source-pin"));
    let target = super::super::recovery::trusted_pin(&root.join("target-pin"));
    let approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("approved descriptor"),
        &source,
        &target,
    )
    .expect("independent retained pins and approval");
    let server = std::env::var_os("QPERIAPT_ANCHOR_SERVER_DIR").expect("source server");
    let server = Path::new(&server);
    let before = std::env::var("QPERIAPT_HANDOFF_RETIRE_PHASE").expect("cut") == "before";
    let mut store = reopen(server);
    let mut calls = 0;
    let receipt = store
        .retire_handoff(
            &approval,
            &fs::read(root.join("ack")).expect("exact imported ack"),
            || {
                calls += 1;
                if before && calls == 2 {
                    fs::write(server.join("ready"), b"signed but not committed")
                        .expect("test cut marker");
                    loop {
                        std::thread::park();
                    }
                }
                Ok(150)
            },
        )
        .expect("retirement commit");
    fs::write(server.join("returned-retirement"), receipt.as_bytes()).expect("API returned");
}

#[test]
fn retirement_sigkill_before_and_after_commit_preserves_exact_original_transaction() {
    use std::os::unix::process::ExitStatusExt;
    for phase in ["before", "after"] {
        let mut c = case();
        let (f, mut target, ack) = imported(&mut c);
        fs::write(f.directory.join("ack"), &ack).expect("retained public ack");
        let revision = c.store.handoff_image().expect("original revision").revision;
        c.store.close();
        let log = fs::File::create(c.server.join("retire-child.log")).expect("owned log");
        let mut command = Process::new(std::env::current_exe().expect("test binary"));
        command.args(["--exact", "anchor::store::tests::handoff_import::retirement::recovery::retirement_crash_child", "--nocapture"])
            .env("QPERIAPT_HANDOFF_RETIRE_TARGET", &f.directory)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_HANDOFF_RETIRE_PHASE", phase)
            .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log));
        if phase == "after" {
            command.env("QPERIAPT_ANCHOR_CRASH_REVISION", revision.to_string());
        }
        let mut child = ChildGuard(command.spawn().expect("owned child"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !c.server.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "retirement cut deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!c.server.join("returned-retirement").exists());
        let pid = child.0.id();
        child.0.kill().expect("kill owned child");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        if phase == "before" {
            c.store = reopen(&c.server);
            assert_eq!(
                c.store
                    .observe_handoff(&f.plan)
                    .expect("uncommitted result")
                    .state(),
                AnchorHandoffState::Frozen
            );
            assert_eq!(
                c.store
                    .frozen_handoff_state(&f.plan)
                    .expect("original contents")
                    .as_bytes(),
                f.source
            );
            c.store
                .cancel_handoff(&f.plan)
                .expect("known unretired source can cancel");
        } else {
            fs::remove_file(c.server.join("signer")).expect("remove only original test signer");
            let observer = AnchorHandoffObserver::open(
                &c.server.join("anchor.redb"),
                JournalKey::open(&c.server.join("wrapping")).expect("original key"),
                c.pin.clone(),
            )
            .expect("no signer required");
            let receipt = observer
                .observe(&f.plan)
                .expect("committed retained certificate");
            assert_eq!(receipt.state(), AnchorHandoffState::Retired);
            f.approval
                .verify_retirement_receipt(&f.freeze, &ack, receipt.as_bytes())
                .expect("recover exact transfer after deadline without signer");
            assert_eq!(
                observer
                    .retained_source_state(&f.plan)
                    .expect("retained whole state")
                    .as_bytes(),
                f.source
            );
        }
        assert_eq!(
            target.status().expect("not activated by source operation"),
            AnchorHandoffTargetState::ImportedInactive
        );
        assert_eq!(
            target
                .retained_source_state()
                .expect("original data preserved"),
            f.source
        );
        eprintln!("HANDOFF_RETIRE_SIGKILL phase={phase} pid={pid}");
    }
}
