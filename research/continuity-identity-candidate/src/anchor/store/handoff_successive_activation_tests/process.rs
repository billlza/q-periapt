// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;

fn approval(root: &Path) -> AnchorHandoffTargetApproval {
    let pin = super::super::super::super::super::super::recovery::trusted_pin;
    AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("retained approval"),
        &pin(&root.join("source-pin")),
        &pin(&root.join("target-pin")),
    )
    .expect("independent original pins")
}
fn approved_target(root: &Path) -> AnchorHandoffTarget {
    AnchorHandoffTarget::open(
        &root.join("import.redb"),
        JournalKey::open(&root.join("wrapping")).expect("original storage key"),
        approval(root),
    )
    .expect("original approved database")
}
fn signer(root: &Path) -> AnchorSigningKey {
    AnchorSigningKey::open(
        &root.join("signer"),
        &JournalKey::open(&root.join("wrapping")).expect("storage key"),
        target_key_id(),
    )
    .expect("original local signer")
}
#[test]
fn successive_activation_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_SUCCESSIVE_ACTIVATION_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let operation =
        std::env::var("QPERIAPT_SUCCESSIVE_ACTIVATION_OPERATION").expect("exact operation");
    let now = std::env::var("QPERIAPT_SUCCESSIVE_ACTIVATION_TIME")
        .expect("fixed clock")
        .parse::<u64>()
        .expect("clock integer");
    if operation == "retire" {
        let source =
            std::env::var_os("QPERIAPT_SUCCESSIVE_SOURCE_DIR").expect("original source directory");
        let source = Path::new(&source);
        let mut target = approved_target(source);
        let (mut active, _) = target
            .activate(
                &fs::read(source.join("retirement")).expect("prior retirement"),
                signer(source),
            )
            .expect("same current source");
        let receipt = active
            .retire_handoff(
                &approval(root),
                &fs::read(root.join("ack")).expect("exact import"),
                || Ok(now),
            )
            .expect("current source retirement");
        fs::write(root.join("returned"), receipt.as_bytes()).expect("returned retirement");
    } else {
        assert_eq!(operation, "activate");
        let (mut active, receipt) = approved_target(root)
            .activate(
                &fs::read(root.join("retirement")).expect("exact source retirement"),
                signer(root),
            )
            .expect("original target activation");
        fs::write(root.join("returned"), receipt.as_bytes()).expect("returned activation");
        active.close();
    }
}

#[test]
fn successive_retirement_and_activation_process_loss_recovers_original_p() {
    const CHILD: &str = "anchor::store::tests::handoff_import::adoption::authorization::successive_import::activation::recovery::process::successive_activation_crash_child";
    for archived in [false, true] {
        for operation in ["retire", "activate"] {
            for committed in [false, true] {
                let mut f = RecoveryCase::new(archived);
                let retirement = if operation == "activate" {
                    let receipt = f.retire();
                    fs::write(f.next.directory.join("retirement"), receipt.as_bytes())
                        .expect("exact source certificate");
                    Some(receipt)
                } else {
                    None
                };
                f.active.close();
                let stage = if operation == "retire" {
                    format!(
                        "source-retire-{}",
                        if committed { "after" } else { "before" }
                    )
                } else if committed {
                    "activate".to_owned()
                } else {
                    "activate-before".to_owned()
                };
                let log = fs::File::create(f.next.directory.join("child.log")).expect("owned log");
                let mut child = ChildGuard(
                    Process::new(std::env::current_exe().expect("test binary"))
                        .args(["--exact", CHILD, "--nocapture"])
                        .env("QPERIAPT_SUCCESSIVE_ACTIVATION_DIR", &f.next.directory)
                        .env("QPERIAPT_SUCCESSIVE_ACTIVATION_OPERATION", operation)
                        .env(
                            "QPERIAPT_SUCCESSIVE_ACTIVATION_TIME",
                            f.next.now.to_string(),
                        )
                        .env("QPERIAPT_SUCCESSIVE_SOURCE_DIR", &f.source.directory)
                        .env("QPERIAPT_SOURCE_CONTROL_DIR", &f.next.directory)
                        .env("QPERIAPT_SOURCE_CONTROL_CUT", &stage)
                        .env("QPERIAPT_HANDOFF_TARGET_DIR", &f.next.directory)
                        .env("QPERIAPT_HANDOFF_TARGET_STAGE", &stage)
                        .stdout(Stdio::from(log.try_clone().expect("clone log")))
                        .stderr(Stdio::from(log))
                        .spawn()
                        .expect("independent test process"),
                );
                let deadline = Instant::now() + Duration::from_secs(30);
                while !f.next.directory.join("ready").exists() {
                    assert!(
                        child.0.try_wait().expect("child status").is_none()
                            && Instant::now() < deadline,
                        "child must reach {stage}; archived={archived}"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(
                    fs::read(f.next.directory.join("ready")).expect("exact cut"),
                    if committed {
                        b"committed".as_slice()
                    } else {
                        b"before-commit".as_slice()
                    }
                );
                assert!(!f.next.directory.join("returned").exists());
                let pid = child.0.id();
                child.0.kill().expect("actual SIGKILL of owned child");
                assert_eq!(
                    child.0.wait().expect("reap killed process").signal(),
                    Some(9)
                );
                assert_ne!(pid, std::process::id());
                f.reopen_source();
                let retirement = if let Some(retirement) = retirement {
                    retirement
                } else {
                    let observed = f
                        .active
                        .observe_handoff(&f.next.plan)
                        .expect("actual durable decision");
                    assert_eq!(
                        observed.state(),
                        if committed {
                            AnchorHandoffState::Retired
                        } else {
                            AnchorHandoffState::Frozen
                        }
                    );
                    let receipt = f.retire();
                    if committed {
                        assert_eq!(observed.as_bytes(), receipt.as_bytes());
                    }
                    receipt
                };
                let mut target = f.next.open();
                let prior = if operation == "activate" && committed {
                    assert_eq!(
                        target.status().expect("committed state"),
                        AnchorHandoffTargetState::Activated
                    );
                    Some(
                        target
                            .activation_receipt()
                            .expect("exact receipt")
                            .as_bytes()
                            .to_vec(),
                    )
                } else {
                    assert_eq!(
                        target.status().expect("not activated"),
                        AnchorHandoffTargetState::ImportedInactive
                    );
                    None
                };
                target.close();
                f.finish(&retirement, prior.as_deref());
                eprintln!("SUCCESSIVE_ACTIVATION_SIGKILL archived={archived} stage={stage} killed_pid={pid} recovery_pid={} original_p_completed=true", std::process::id());
            }
        }
    }
}
