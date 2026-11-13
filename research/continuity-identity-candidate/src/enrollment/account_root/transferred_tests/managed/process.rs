// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::process::inputs;
use super::super::registry::RegistryRecovery;
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
};
const CHILD: &str = "enrollment::account_root::tests::transferred::managed::process::transferred_managed_process_child";

#[test]
fn transferred_managed_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_MANAGED_DIR") else {
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
    let plan = TransferredAccountRootPreparation::new(
        saved.preparation,
        saved.logical,
        saved.history,
        Some(saved.selected),
    )
    .expect("same independent original context");
    let mut owner = ManagedAccountRootReplacement::resume_transferred_original(
        store,
        registry.expected,
        plan,
        paths(&root),
        saved.intent,
    )
    .expect("same original managed owner");
    owner
        .bind_transferred_freeze(&saved.frozen, saved.approval)
        .expect("same approved full freeze");
    let wire = fs::read(root.join("root-decision")).expect("original purpose37 bytes");
    let state = owner
        .retain_transferred_decision(&wire)
        .expect("original child/parent/registry outcome");
    if state == State::Committed {
        owner
            .successor_authority()
            .expect("current exact successor mapping");
    } else {
        assert_eq!(state, State::Closed);
    }
    owner.close();
    fs::write(root.join("managed-returned"), wire).expect("exact returned result");
    fs::write(root.join("managed-pid"), std::process::id().to_string()).expect("actual PID");
}
fn command(root: &Path, name: &str) -> Command {
    let log = fs::File::create_new(root.join(name)).expect("owned child log");
    let mut command = Command::new(std::env::current_exe().expect("same test executable"));
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_TRANSFERRED_MANAGED_DIR", root)
        .stdout(Stdio::from(log.try_clone().expect("stdout")))
        .stderr(Stdio::from(log));
    command
}
#[test]
fn transferred_managed_sigkill_recovers_same_parent_child_registry_and_exact_result() {
    for closed in [false, true] {
        for (child_side, cut) in [
            (false, "managed-binding-after"),
            (false, "intent-before"),
            (false, "intent-after"),
            (true, "fence-before"),
            (true, "fence-after"),
            (true, "receipt-before"),
            (true, "receipt-after"),
            (false, "receipt-before"),
            (false, "receipt-after"),
            (false, "managed-decision-after"),
            (false, "managed-registry-after"),
        ] {
            let mut t = Transferred::with_controller(Some(2), 2);
            t.controller
                .take()
                .expect("actual original preparation")
                .close();
            let rows = journal_rows(&t);
            let parent = original_parent(&t);
            let keys = [&t.f.original.paths.wrapping, &t.f.original.paths.signer]
                .map(|p| fs::read(p).expect("original key file"));
            let decision = t.decide(closed);
            inputs::publish(&t, decision.as_bytes());
            let root =
                t.f.original
                    .paths
                    .configuration
                    .parent()
                    .expect("owned original directory");
            t.registry_recovery
                .as_ref()
                .expect("original registry")
                .publish(root);
            let mut cut_command = command(root, "managed-cut.log");
            cut_command
                .env(
                    if child_side {
                        "QPERIAPT_ROOT_FENCE_DIR"
                    } else {
                        "QPERIAPT_ROOT_PARENT_DIR"
                    },
                    root,
                )
                .env(
                    if child_side {
                        "QPERIAPT_ROOT_FENCE_CUT"
                    } else {
                        "QPERIAPT_ROOT_PARENT_CUT"
                    },
                    cut,
                );
            let mut child =
                crate::durable::tests::ChildGuard(cut_command.spawn().expect("owned cut process"));
            let killed = child.0.id();
            let until = Instant::now() + Duration::from_secs(30);
            while !root.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("status").is_none() && Instant::now() < until,
                    "cut not reached: {}",
                    fs::read_to_string(root.join("managed-cut.log")).expect("cut log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!root.join("managed-returned").exists());
            child.0.kill().expect("actual SIGKILL");
            assert_eq!(
                child.0.wait().expect("reaped killed process").signal(),
                Some(9)
            );
            let mut recovered = crate::durable::tests::ChildGuard(
                command(root, "managed-recover.log")
                    .spawn()
                    .expect("new process"),
            );
            let until = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = recovered.0.try_wait().expect("recovery status") {
                    assert!(
                        status.success(),
                        "recovery failed: {}",
                        fs::read_to_string(root.join("managed-recover.log")).expect("recovery log")
                    );
                    break;
                }
                assert!(Instant::now() < until, "bounded original recovery");
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid = fs::read_to_string(root.join("managed-pid"))
                .expect("new PID")
                .parse::<u32>()
                .expect("PID");
            assert_ne!(pid, killed);
            assert_ne!(pid, std::process::id());
            assert!(
                fs::read(root.join("managed-returned")).expect("actual returned result")
                    == decision.as_bytes()
            );
            assert!(
                journal_rows(&t) == rows && original_parent(&t) == parent,
                "original state retained"
            );
            for (path, expected) in [&t.f.original.paths.wrapping, &t.f.original.paths.signer]
                .into_iter()
                .zip(&keys)
            {
                assert!(fs::read(path).expect("same key file") == *expected);
            }
            let mut observer = resume(&t).expect("same original owner after lost process");
            assert_eq!(
                observer.state().expect("exact durable outcome"),
                if closed {
                    State::Closed
                } else {
                    State::Committed
                }
            );
            observer.close();
            eprintln!("TRANSFERRED_MANAGED_SIGKILL closed={closed} child={child_side} cut={cut} killed={killed} recovered={pid} original_pending=true same_registry=true");
        }
    }
}
