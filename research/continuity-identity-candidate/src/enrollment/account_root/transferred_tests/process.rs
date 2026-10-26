// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
#[path = "process_inputs.rs"]
pub(super) mod inputs;
const CHILD: &str =
    "enrollment::account_root::tests::transferred::process::transferred_root_parent_process_child";

#[test]
fn transferred_root_parent_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_PARENT_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let (intent, plan) = inputs::restore(&root);
    let mut owner =
        AccountRootEnrollmentRecovery::resume_transferred_original(paths(&root), intent, plan)
            .expect("recover same original parent and journal");
    let decision = fs::read(root.join("root-decision")).expect("original signed outcome");
    let outcome = owner
        .retain_account_decision(&decision)
        .expect("same child outcome before parent ACK");
    assert_eq!(owner.status().expect("retained exact outcome"), outcome);
    assert!(
        owner
            .account_decision()
            .expect("exact original signature")
            .as_bytes()
            == decision
    );
    owner.close();
    fs::write(root.join("returned-decision"), decision).expect("exact result returned");
    fs::write(root.join("recovery-pid"), std::process::id().to_string())
        .expect("new process identity");
}
fn command(root: &Path, log: &str) -> Command {
    let output = fs::File::create_new(root.join(log)).expect("owned process log");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_TRANSFERRED_PARENT_DIR", root)
        .stdout(Stdio::from(output.try_clone().expect("stdout")))
        .stderr(Stdio::from(output));
    command
}
fn wait(child: &mut crate::durable::tests::ChildGuard, root: &Path) -> std::process::ExitStatus {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("child status") {
            return status;
        }
        assert!(
            Instant::now() < until,
            "recovery did not finish: {}",
            fs::read_to_string(root.join("recover.log")).expect("recovery log")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn transferred_root_parent_sigkill_reopens_original_selection_pending_and_decision_in_new_process()
{
    for closed in [false, true] {
        for (child_side, stage) in [
            (false, "intent"),
            (true, "fence"),
            (true, "receipt"),
            (false, "receipt"),
        ] {
            for after in [false, true] {
                let mut t = Transferred::at(Some(2), 2);
                let rows = journal_rows(&t);
                let parent = original_parent(&t);
                let keys = [&t.f.original.paths.wrapping, &t.f.original.paths.signer]
                    .map(|p| fs::read(p).expect("original sealed keys"));
                let decision = t.decide(closed);
                inputs::publish(&t, decision.as_bytes());
                let root =
                    t.f.original
                        .paths
                        .configuration
                        .parent()
                        .expect("canonical original directory");
                let mut cmd = command(root, "cut.log");
                let cut = format!("{stage}-{}", if after { "after" } else { "before" });
                cmd.env(
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
                    &cut,
                );
                let mut process = crate::durable::tests::ChildGuard(
                    cmd.spawn().expect("owned interrupted process"),
                );
                let killed = process.0.id();
                let until = Instant::now() + Duration::from_secs(30);
                while !root.join("ready").exists() {
                    assert!(
                        process.0.try_wait().expect("status").is_none() && Instant::now() < until,
                        "checkpoint not reached: {}",
                        fs::read_to_string(root.join("cut.log")).expect("child log")
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(!root.join("returned-decision").exists());
                process.0.kill().expect("SIGKILL at actual commit boundary");
                assert_eq!(
                    process.0.wait().expect("reap killed process").signal(),
                    Some(9)
                );
                let mut recovered = crate::durable::tests::ChildGuard(
                    command(root, "recover.log")
                        .spawn()
                        .expect("fresh recovery process"),
                );
                assert!(
                    wait(&mut recovered, root).success(),
                    "recovery failed: {}",
                    fs::read_to_string(root.join("recover.log")).expect("recovery log")
                );
                let pid = fs::read_to_string(root.join("recovery-pid"))
                    .expect("recovery identity")
                    .parse::<u32>()
                    .expect("PID");
                assert_ne!(pid, killed);
                assert_ne!(pid, std::process::id());
                assert!(
                    fs::read(root.join("returned-decision")).expect("original result bytes")
                        == decision.as_bytes()
                );
                assert!(
                    journal_rows(&t) == rows,
                    "original sealed prekeys, pending and selection changed"
                );
                assert!(
                    original_parent(&t) == parent,
                    "original parent image changed"
                );
                for (path, bytes) in [&t.f.original.paths.wrapping, &t.f.original.paths.signer]
                    .into_iter()
                    .zip(&keys)
                {
                    assert!(
                        fs::read(path).expect("same original key file") == *bytes,
                        "original key changed"
                    );
                }
                for (name, bytes) in &t.public_inputs {
                    assert!(
                        fs::read(root.join(name)).expect("same public input") == *bytes,
                        "original public approval changed"
                    );
                }
                let mut observed = t
                    .open()
                    .expect("independent parent observation after child exit");
                assert_eq!(
                    observed.status().expect("permanent result"),
                    if closed {
                        AccountRootEnrollmentState::WitnessClosed
                    } else {
                        AccountRootEnrollmentState::WitnessCommitted
                    }
                );
                observed.close();
                t.f.assert_fenced();
                eprintln!("TRANSFERRED_ROOT_PARENT_SIGKILL closed={closed} child={child_side} cut={cut} killed={killed} recovered={pid} original_pending=true exact_decision=true");
            }
        }
    }
}
