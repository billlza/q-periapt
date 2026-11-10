// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::ChildGuard;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
const CHILD:&str="enrollment::account_root::tests::transferred::client_cleanup::process::transferred_client_cleanup_process_child";

#[test]
fn transferred_client_cleanup_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_CLEANUP_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let (_, plan) = super::super::process::inputs::restore(&root);
    let subject = plan
        .proposal()
        .predecessors()
        .next()
        .expect("original sole subject");
    let decision = fs::read(root.join("root-decision")).expect("independent exact decision");
    let context =
        TransferredRetirementContext::new(plan.clone(), &decision, subject, plan.history().clone())
            .expect("full independent original context");
    let pin = context.accounting_pin().clone();
    let mut owner = RetiredInstallationRecovery::open_transferred(
        paths(&root).installation,
        JournalKey::open(&paths(&root).wrapping).expect("original key"),
        context.clone(),
    )
    .expect("same original cleanup");
    let action = std::env::var("QPERIAPT_TRANSFERRED_CLEANUP_ACTION").expect("test action");
    let inventory = owner.proposal().expect("original complete inventory");
    match action.as_str() {
        "capture" => {}
        "prepare" => {
            let raw = fs::read(root.join("independent-inventory-approval"))
                .expect("operator retained exact approval");
            let approval = AnchorTransferredCleanupApproval::restore_trusted_state(
                &raw,
                &context.materials(&inventory, None, None),
            )
            .expect("original independent approval");
            assert_eq!(
                owner
                    .prepare_transferred_stage(&approval)
                    .expect("durable before dispatch"),
                raw
            );
            assert_eq!(
                owner
                    .transferred_stage_approval(Inventory)
                    .expect("exact original bytes")
                    .to_bytes(),
                raw
            );
        }
        "ack" => {
            owner
                .verify_host_acknowledgement(
                    &pin,
                    &fs::read(root.join("independent-ack")).expect("original server response"),
                )
                .expect("durably retain exact ACK");
        }
        "erase" => {
            owner
                .erase_journal(
                    &pin,
                    &fs::read(root.join("independent-ack")).expect("original server response"),
                )
                .expect("same atomic erasure");
        }
        _ => {
            assert_eq!(action, "known test action");
        }
    }
    owner.close();
    fs::write(
        root.join("cleanup-returned"),
        std::process::id().to_string(),
    )
    .expect("new process result");
}
fn command(root: &Path, log: &str, action: &str) -> Command {
    let file = fs::File::create_new(root.join(log)).expect("owned child log");
    let mut command = Command::new(std::env::current_exe().expect("current test binary"));
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_TRANSFERRED_CLEANUP_DIR", root)
        .env("QPERIAPT_TRANSFERRED_CLEANUP_ACTION", action)
        .stdout(Stdio::from(file.try_clone().expect("stdout")))
        .stderr(Stdio::from(file));
    command
}
#[test]
fn transferred_client_cleanup_sigkill_reconciles_original_approval_ack_and_erasure() {
    for (action, boundary) in [
        ("capture", "retired-cleanup"),
        ("prepare", "retired-authority"),
        ("ack", "retired-authority"),
        ("erase", ""),
    ] {
        for after in [false, true] {
            let mut flow = Flow::new(Some(2), 2);
            let root = flow
                .t
                .f
                .original
                .paths
                .configuration
                .parent()
                .expect("original owned directory")
                .to_path_buf();
            let original = journal_rows(&flow.t);
            let signer = fs::read(&flow.t.f.original.paths.signer).expect("original signer");
            super::super::process::inputs::publish(&flow.t, flow.decision.as_bytes());
            if action == "prepare" {
                let mut owner = flow.open();
                let inventory = owner.proposal().expect("original inventory");
                owner.close();
                let approval = flow.approval(&inventory, None, None, Inventory, 221);
                fs::write(
                    root.join("independent-inventory-approval"),
                    approval.to_bytes(),
                )
                .expect("independent operator record");
            } else if action == "ack" || action == "erase" {
                let mut owner = flow.open();
                let (report, verified, previous) = flow.report(&mut owner);
                let ack = flow.account(&mut owner, &report, &verified, &previous);
                if action == "erase" {
                    owner
                        .verify_host_acknowledgement(flow.context.accounting_pin(), ack.as_bytes())
                        .expect("ACK before destructive transaction");
                }
                owner.close();
                fs::write(root.join("independent-ack"), ack.as_bytes())
                    .expect("retain same server response");
            }
            let mut cmd = command(&root, "cleanup-cut.log", action);
            let ready = if action == "erase" {
                cmd.env("QPERIAPT_RETIRED_ERASURE_CHILD", &root).env(
                    "QPERIAPT_RETIRED_ERASURE_STAGE",
                    if after {
                        "after-commit"
                    } else {
                        "before-commit"
                    },
                );
                root.join("erasure-ready")
            } else {
                cmd.env("QPERIAPT_INSTALLATION_CUT_DIR", &root).env(
                    "QPERIAPT_INSTALLATION_CUT_STAGE",
                    format!(
                        "{boundary}-{}-commit",
                        if after { "after" } else { "before" }
                    ),
                );
                root.join("ready")
            };
            let mut child = ChildGuard(cmd.spawn().expect("owned interrupted child"));
            let killed = child.0.id();
            let until = Instant::now() + Duration::from_secs(30);
            while !ready.exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < until,
                    "missing real boundary: {}",
                    fs::read_to_string(root.join("cleanup-cut.log")).expect("log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!root.join("cleanup-returned").exists());
            child.0.kill().expect("SIGKILL");
            assert_eq!(child.0.wait().expect("reap killed child").signal(), Some(9));
            let mut fresh = ChildGuard(
                command(&root, "cleanup-recover.log", action)
                    .spawn()
                    .expect("new process"),
            );
            let until = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = fresh.0.try_wait().expect("status") {
                    assert!(
                        status.success(),
                        "new-process recovery failed: {}",
                        fs::read_to_string(root.join("cleanup-recover.log")).expect("recovery log")
                    );
                    break;
                }
                assert!(Instant::now() < until, "new process did not finish");
                std::thread::sleep(Duration::from_millis(10));
            }
            let recovered = fs::read_to_string(root.join("cleanup-returned"))
                .expect("completed result")
                .parse::<u32>()
                .expect("PID");
            assert_ne!(recovered, killed);
            assert_ne!(recovered, std::process::id());
            let mut owner = flow.open();
            if action == "erase" {
                assert_eq!(
                    owner
                        .journal_erasure_status(flow.context.accounting_pin())
                        .expect("signed terminal"),
                    JournalErasureState::Erased
                );
            } else {
                assert!(
                    journal_rows(&flow.t) == original,
                    "original sealed data changed before ACK erasure"
                );
            }
            if action == "ack" {
                assert_eq!(
                    owner
                        .transferred_stage_receipt(Acknowledged)
                        .expect("exact stored ACK")
                        .as_bytes(),
                    fs::read(root.join("independent-ack")).expect("original response")
                );
            }
            owner.close();
            assert!(
                fs::read(&flow.t.f.original.paths.signer)
                    .expect("signer still requires separate explicit erasure")
                    == signer
            );
            eprintln!("TRANSFERRED_CLIENT_SIGKILL action={action} after={after} killed={killed} recovered={recovered} exact_original=true");
        }
    }
}
