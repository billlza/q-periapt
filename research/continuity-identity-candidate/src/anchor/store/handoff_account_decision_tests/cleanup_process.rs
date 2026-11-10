// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;

pub(in crate::anchor::store) fn execute_child(
    active: &mut AnchorStore,
    history: &AnchorHandoffHistory,
    replacement: &Approval,
    root: &Path,
) {
    let read =
        |name: &str| fs::read(root.join(name)).expect("independently retained exact public input");
    let stage: usize = std::env::var("QPERIAPT_CLEANUP_STAGE")
        .expect("stage")
        .parse()
        .expect("numeric stage");
    assert!(stage < 3);
    let decision = read("cleanup-decision");
    let inventory = AnchorRetiredCleanupProposal::from_trusted_state(&read("cleanup-inventory"))
        .expect("original inventory");
    let report = AnchorRetiredReportProposal::from_trusted_state(&read("cleanup-report"))
        .expect("original report expectation");
    let mut receipts = Vec::new();
    for index in 0..=stage {
        let approval = AnchorTransferredCleanupApproval::restore_trusted_state(
            &read(&format!("cleanup-approval-{index}")),
            &AnchorTransferredCleanupMaterials {
                history,
                replacement,
                decision: &decision,
                inventory: &inventory,
                report: if index == 0 { None } else { Some(&report) },
                previous: receipts.last(),
            },
        )
        .expect("full independent original approval");
        if index < stage {
            receipts.push(
                approval
                    .verify_receipt(history, &read(&format!("cleanup-proof-{index}")))
                    .expect("original preceding proof"),
            );
        } else {
            let outcome = active
                .retain_transferred_cleanup(&approval, || Ok(186))
                .expect("same approved stage");
            fs::write(root.join("returned-cleanup"), outcome.as_bytes()).expect("original return");
            fs::write(
                root.join("cleanup-recovery-pid"),
                std::process::id().to_string(),
            )
            .expect("actual process identity");
        }
    }
}

#[test]
fn transferred_cleanup_sigkill_before_and_after_each_commit_recovers_original_receipt() {
    const CHILD:&str="anchor::store::tests::handoff_import::account_decision::process::transferred_account_decision_process_child";
    for stage in 0..3 {
        for committed in [false, true] {
            let mut f = Case::new(stage);
            let old = f.c.old_entry();
            let revision = f.c.active.image().expect("original revision").revision;
            super::super::process::retain(&f.c, &f.n, &f.root);
            let root = &f.c.f.directory;
            fs::write(root.join("cleanup-decision"), f.decision.as_bytes())
                .expect("original decision");
            fs::write(root.join("cleanup-inventory"), f.inventory.to_bytes())
                .expect("original inventory");
            fs::write(
                root.join("cleanup-report"),
                AnchorRetiredReportProposal::from_report(f.inventory.clone(), [237; 32])
                    .expect("report")
                    .to_bytes(),
            )
            .expect("original report");
            for (index, a) in f.approvals.iter().enumerate() {
                fs::write(root.join(format!("cleanup-approval-{index}")), a.to_bytes())
                    .expect("exact stage approval");
            }
            for (index, r) in f.receipts.iter().enumerate() {
                fs::write(root.join(format!("cleanup-proof-{index}")), r.as_bytes())
                    .expect("exact previous receipt");
            }
            f.c.active.close();
            let command = || {
                let mut c = Process::new(std::env::current_exe().expect("test executable"));
                c.args(["--exact", CHILD, "--nocapture"])
                    .env("QPERIAPT_ACCOUNT_DECISION_DIR", root)
                    .env("QPERIAPT_ACCOUNT_DECISION_ACTION", "cleanup")
                    .env("QPERIAPT_CLEANUP_STAGE", stage.to_string());
                c
            };
            let log = fs::File::create_new(root.join("cleanup-kill.log")).expect("owned log");
            let mut child = ChildGuard(
                command()
                    .env("QPERIAPT_ANCHOR_SERVER_DIR", root)
                    .env(
                        if committed {
                            "QPERIAPT_ANCHOR_CRASH_REVISION"
                        } else {
                            "QPERIAPT_ANCHOR_BEFORE_COMMIT_REVISION"
                        },
                        (revision + 1).to_string(),
                    )
                    .stdout(Stdio::from(log.try_clone().expect("log")))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .expect("fresh process"),
            );
            let killed = child.0.id();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !root.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "bounded commit boundary"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                fs::read(root.join("ready")).expect("exact boundary"),
                if committed {
                    b"committed".as_slice()
                } else {
                    b"before-commit".as_slice()
                }
            );
            assert!(!root.join("returned-cleanup").exists());
            child.0.kill().expect("kill owned child");
            assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
            let observed =
                f.c.f
                    .open()
                    .transferred_cleanup_receipt(f.approvals.get(stage).expect("approved stage"));
            let retained = if committed {
                Some(
                    observed
                        .expect("committed original receipt")
                        .as_bytes()
                        .to_vec(),
                )
            } else {
                assert!(matches!(observed, Err(DurableError::Absent)));
                None
            };
            let log =
                fs::File::create_new(root.join("cleanup-recover.log")).expect("owned recovery log");
            let mut next = ChildGuard(
                command()
                    .stdout(Stdio::from(log.try_clone().expect("log")))
                    .stderr(Stdio::from(log))
                    .spawn()
                    .expect("new recovery process"),
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = next.0.try_wait().expect("new process status") {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "bounded recovery");
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid: u32 = fs::read_to_string(root.join("cleanup-recovery-pid"))
                .expect("new PID")
                .parse()
                .expect("PID");
            assert_ne!(pid, killed);
            assert_ne!(pid, std::process::id());
            let wire = fs::read(root.join("returned-cleanup")).expect("original result");
            if let Some(before) = retained {
                assert_eq!(wire, before);
            }
            f.approvals
                .get(stage)
                .expect("approved stage")
                .verify_receipt(&f.c.history, &wire)
                .expect("same approved result");
            f.c.reopen();
            assert_eq!(f.c.old_entry(), old);
            assert_eq!(
                f.c.active
                    .transferred_cleanup_receipt(f.approvals.get(stage).expect("approved stage"))
                    .expect("exact durable retry")
                    .as_bytes(),
                wire
            );
            eprintln!("TRANSFERRED_CLEANUP_SIGKILL stage={stage} committed={committed} killed={killed} recovered={pid} original_entry=true exact_receipt=true");
        }
    }
}
