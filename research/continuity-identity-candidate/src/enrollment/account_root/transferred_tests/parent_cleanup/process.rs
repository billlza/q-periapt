// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill the original controller at durable parent and signer-file boundaries.
use super::super::fixture::Work;
use super::super::{process::inputs, registry::RegistryRecovery};
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};

const CHILD: &str = "enrollment::account_root::tests::transferred::parent_cleanup::process::transferred_parent_cleanup_process_child";

#[test]
fn transferred_parent_cleanup_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_CLEANUP_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let saved = inputs::restore_registry(&root);
    let registry = RegistryRecovery::restore(&root);
    let family = fs::read(root.join("policy-family"))
        .expect("original family")
        .try_into()
        .expect("family width");
    let store = registry.open_with(family, saved.logical.clone());
    let history = saved.history.clone();
    let preparation = TransferredAccountRootPreparation::new(
        saved.preparation,
        saved.logical,
        saved.history,
        Some(saved.selected),
    )
    .expect("independent original context");
    let mut owner = ManagedAccountRootReplacement::resume_transferred_cleanup_original(
        store,
        registry.expected,
        preparation,
        paths(&root),
        saved.intent,
        history,
    )
    .expect("same original controller, even after journal or signer erasure");
    let action = fs::read_to_string(root.join("cleanup-action")).expect("fixed test action");
    owner
        .with_retired_cleanup(|parent| {
            match action.as_str() {
                "inventory" => {
                    parent.installation()?.proposal()?;
                }
                "signer-plan" => {
                    let ack = fs::read(root.join("cleanup-ack")).expect("original public ACK");
                    parent.prepare_signer_erasure(&ack)?;
                }
                "signer" => parent.erase_signer()?,
                _ => return Err(DurableError::Corrupt),
            }
            Ok(())
        })
        .expect("exact original cleanup action");
    owner
        .successor_authority()
        .expect("unchanged committed successor mapping");
    owner.close();
    fs::write(root.join("cleanup-returned"), action).expect("actual return marker");
    fs::write(root.join("cleanup-pid"), std::process::id().to_string()).expect("new PID");
}

fn command(root: &Path, log: &str) -> Command {
    let output = fs::File::create_new(root.join(log)).expect("owned process log");
    let mut command = Command::new(std::env::current_exe().expect("same test executable"));
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_TRANSFERRED_CLEANUP_DIR", root)
        .stdout(Stdio::from(output.try_clone().expect("stdout")))
        .stderr(Stdio::from(output));
    command
}

fn kill_and_recover(root: &Path, action: &str, stage: &str, after: bool) -> (u32, u32) {
    let cut = format!("{stage}-{}", if after { "after" } else { "before" });
    let signer = action == "signer";
    let ready = root.join(if signer { "signer-ready" } else { "ready" });
    let mut cmd = command(root, "cleanup-cut.log");
    cmd.env(
        if signer {
            "QPERIAPT_SIGNER_CUT_ROOT"
        } else {
            "QPERIAPT_ROOT_PARENT_DIR"
        },
        root,
    )
    .env(
        if signer {
            "QPERIAPT_SIGNER_CUT_STAGE"
        } else {
            "QPERIAPT_ROOT_PARENT_CUT"
        },
        &cut,
    );
    let mut child = crate::durable::tests::ChildGuard(cmd.spawn().expect("owned cut process"));
    let killed = child.0.id();
    let until = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < until,
            "cut not reached: {}",
            fs::read_to_string(root.join("cleanup-cut.log")).expect("log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read_to_string(&ready).expect("actual boundary"), cut);
    assert!(!root.join("cleanup-returned").exists());
    child.0.kill().expect("real SIGKILL");
    assert_eq!(child.0.wait().expect("reaped child").signal(), Some(9));
    let mut recovered = crate::durable::tests::ChildGuard(
        command(root, "cleanup-recover.log")
            .spawn()
            .expect("new recovery process"),
    );
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = recovered.0.try_wait().expect("recovery status") {
            assert!(
                status.success(),
                "recovery failed: {}",
                fs::read_to_string(root.join("cleanup-recover.log")).expect("log")
            );
            break;
        }
        assert!(Instant::now() < until, "bounded original process recovery");
        std::thread::sleep(Duration::from_millis(10));
    }
    let recovered_pid = fs::read_to_string(root.join("cleanup-pid"))
        .expect("new PID")
        .parse::<u32>()
        .expect("PID");
    assert_ne!(recovered_pid, killed);
    assert_ne!(recovered_pid, std::process::id());
    assert_eq!(
        fs::read_to_string(root.join("cleanup-returned")).expect("actual result"),
        action
    );
    (killed, recovered_pid)
}

fn run_original(work: Option<Work>) {
    for (action, stage) in [
        ("inventory", "cleanup-parent"),
        ("signer-plan", "cleanup-parent"),
        ("signer", "HeaderWrite"),
        ("signer", "HeaderSync"),
        ("signer", "Truncate"),
        ("signer", "TerminalSync"),
        ("signer", "DirectorySync"),
    ] {
        for after in [false, true] {
            let mut flow = match work {
                Some(work) => commit_managed(Transferred::with_pending(work, 2)),
                None => managed(Some(2), 2),
            };
            let original = original_parent(&flow.t);
            let roots = [
                crate::enrollment::account_root::ROW,
                crate::enrollment::witness_handoff::ROW,
            ]
            .map(|name| super::faults::row(&flow, name));
            let key = fs::read(&flow.t.f.original.paths.wrapping).expect("original wrapping key");
            let signer = fs::read(&flow.t.f.original.paths.signer).expect("original signer");
            let root = flow
                .t
                .f
                .original
                .paths
                .configuration
                .parent()
                .expect("original directory")
                .to_path_buf();
            if action != "inventory" {
                let mut owner = resume_managed(&flow).expect("original controller");
                let ack = owner
                    .with_retired_cleanup(|parent| {
                        let ack = report_ack(&mut flow, parent);
                        erase_journal(&flow, parent, &ack);
                        if action == "signer" {
                            parent.prepare_signer_erasure(&ack)?;
                        }
                        Ok(ack)
                    })
                    .expect("exact full report before erasure");
                owner.close();
                fs::write(root.join("cleanup-ack"), ack).expect("original public ACK");
            }
            inputs::publish(&flow.t, flow.decision.as_bytes());
            flow.t
                .registry_recovery
                .as_ref()
                .expect("original registry")
                .publish(&root);
            fs::write(root.join("cleanup-action"), action).expect("fixed action");
            let (killed, recovered) = kill_and_recover(&root, action, stage, after);
            let cut = format!("{stage}-{}", if after { "after" } else { "before" });
            if let Some(work) = work {
                eprintln!("TRANSFERRED_MIXED_SIGKILL work={work:?} action={action} cut={cut} killed={killed} recovered={recovered} same_registry=true same_operation=true");
            } else {
                eprintln!("TRANSFERRED_PARENT_SIGKILL action={action} cut={cut} killed={killed} recovered={recovered} same_registry=true same_operation=true");
            }
            assert!(original_parent(&flow.t) == original);
            assert!(fs::read(&flow.t.f.original.paths.wrapping).expect("original key") == key);
            for (name, original) in [
                crate::enrollment::account_root::ROW,
                crate::enrollment::witness_handoff::ROW,
            ]
            .into_iter()
            .zip(&roots)
            {
                assert!(
                    super::faults::row(&flow, name) == *original,
                    "original root and selection unchanged"
                );
            }
            assert!(
                fs::read(&flow.t.f.original.paths.signer).expect("same original inode")
                    == if action == "signer" {
                        b"QPSRET01".to_vec()
                    } else {
                        signer
                    }
            );
            let mut owner = resume_managed(&flow).expect("cold original controller");
            owner
                .with_retired_cleanup(|parent| {
                    let ack = if action == "inventory" {
                        let ack = report_ack(&mut flow, parent);
                        erase_journal(&flow, parent, &ack);
                        ack
                    } else {
                        fs::read(root.join("cleanup-ack")).expect("original ACK")
                    };
                    parent.prepare_signer_erasure(&ack)?;
                    parent.erase_signer()
                })
                .expect("same operation completes without new host accounting");
            owner.close();
            assert_eq!(
                fs::read(&flow.t.f.original.paths.signer).expect("terminal"),
                b"QPSRET01"
            );
        }
    }
}

#[test]
fn transferred_parent_cleanup_sigkill_reopens_original_controller_without_erased_secrets() {
    run_original(None);
}
#[test]
fn transferred_mixed_cleanup_process_credential_applied_without_local_ack() {
    run_original(Some(Work::Credential(1)));
}
#[test]
fn transferred_mixed_cleanup_process_roster_applied_without_local_ack() {
    run_original(Some(Work::Roster(1)));
}
#[test]
fn transferred_mixed_cleanup_process_cancellation_closed_without_local_ack() {
    run_original(Some(Work::Cancellation(true)));
}
