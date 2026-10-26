// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::super::process::inputs as original;
use super::super::{faults::Case, process::inputs as next_inputs};
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
const CHILD: &str = "enrollment::account_root::tests::transferred::next_attempt::client::process::transferred_client_next_process_child";

#[test]
fn transferred_client_next_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_CLIENT_NEXT_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let (intent, old) = original::restore(&root);
    let (_, approval) = next_inputs::restore(&root, &intent.root, old.history());
    let next = TransferredAccountRootJournalPlan::new(
        old.logical_pin().clone(),
        approval,
        old.history().clone(),
        old.selection().cloned(),
    )
    .expect("independent next trust");
    let closed = fs::read(root.join("root-decision")).expect("exact original closure");
    let transition = TransferredAccountRootJournalTransition::verify(old, next, &closed)
        .expect("exact transition reconstruction");
    let mut owner = AccountRootEnrollmentRecovery::resume_transferred_transition(
        paths(&root),
        intent,
        &transition,
    )
    .expect("original parent and child exact transition");
    let decision = fs::read(root.join("next-decision")).expect("original next signed result");
    assert_eq!(
        owner
            .retain_account_decision(&decision)
            .expect("same next result"),
        AccountRootEnrollmentState::WitnessCommitted
    );
    assert_eq!(
        owner
            .account_decision()
            .expect("exact retained result")
            .as_bytes(),
        decision
    );
    owner.close();
    fs::write(root.join("client-next-returned"), decision).expect("returned exact result");
    fs::write(root.join("client-next-pid"), std::process::id().to_string())
        .expect("new process identity");
}
fn command(root: &Path, label: &str) -> Command {
    let log = fs::File::create_new(root.join(label)).expect("owned log");
    let mut cmd = Command::new(std::env::current_exe().expect("same test binary"));
    cmd.args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_CLIENT_NEXT_DIR", root)
        .stdout(Stdio::from(log.try_clone().expect("stdout")))
        .stderr(Stdio::from(log));
    cmd
}
#[test]
fn transferred_client_next_sigkill_reconciles_each_parent_child_commit_in_a_new_process() {
    for work in [
        Work::Policy(2),
        Work::Credential(1),
        Work::Roster(1),
        Work::Cancellation(true),
    ] {
        for (child, stage) in [
            (false, "transferred-handoff"),
            (true, "transferred-handoff"),
            (true, "receipt"),
            (false, "receipt"),
        ] {
            for after in [false, true] {
                let c = Case::new(work, 2, false);
                let rows = journal_rows(&c.s.t);
                let parent = original_parent(&c.s.t);
                let keys = [
                    &c.s.t.f.original.paths.wrapping,
                    &c.s.t.f.original.paths.signer,
                ]
                .map(|p| fs::read(p).expect("original keys"));
                let root =
                    c.s.t
                        .f
                        .original
                        .paths
                        .configuration
                        .parent()
                        .expect("same private directory");
                next_inputs::publish(&c, root);
                let mut cmd = command(root, "client-next-cut.log");
                let side = if child { "FENCE" } else { "PARENT" };
                cmd.env(format!("QPERIAPT_ROOT_{side}_DIR"), root).env(
                    format!("QPERIAPT_ROOT_{side}_CUT"),
                    format!("{stage}-{}", if after { "after" } else { "before" }),
                );
                let mut process =
                    crate::durable::tests::ChildGuard(cmd.spawn().expect("cut process"));
                let killed = process.0.id();
                let until = Instant::now() + Duration::from_secs(30);
                while !root.join("ready").exists() {
                    assert!(
                        process.0.try_wait().expect("cut state").is_none()
                            && Instant::now() < until,
                        "cut not reached: {}",
                        fs::read_to_string(root.join("client-next-cut.log")).expect("cut log")
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(!root.join("client-next-returned").exists());
                process.0.kill().expect("real SIGKILL");
                assert_eq!(process.0.wait().expect("reap").signal(), Some(9));
                let mut recovered = crate::durable::tests::ChildGuard(
                    command(root, "client-next-recover.log")
                        .spawn()
                        .expect("new process"),
                );
                let until = Instant::now() + Duration::from_secs(30);
                let status = loop {
                    if let Some(status) = recovered.0.try_wait().expect("recovery state") {
                        break status;
                    }
                    assert!(Instant::now() < until, "bounded recovery did not finish");
                    std::thread::sleep(Duration::from_millis(10));
                };
                assert!(
                    status.success(),
                    "recovery failed: {}",
                    fs::read_to_string(root.join("client-next-recover.log")).expect("recovery log")
                );
                let pid = fs::read_to_string(root.join("client-next-pid"))
                    .expect("PID")
                    .parse::<u32>()
                    .expect("PID integer");
                assert_ne!(pid, killed);
                assert_ne!(pid, std::process::id());
                assert!(
                    fs::read(root.join("client-next-returned")).expect("returned result")
                        == *c.wire.as_ref().expect("signed result")
                );
                assert!(journal_rows(&c.s.t) == rows && original_parent(&c.s.t) == parent);
                assert!(
                    keys == [
                        &c.s.t.f.original.paths.wrapping,
                        &c.s.t.f.original.paths.signer
                    ]
                    .map(|p| fs::read(p).expect("same sealed keys"))
                );
                c.s.t.f.assert_fenced();
                eprintln!("TRANSFERRED_CLIENT_NEXT_SIGKILL work={work:?} child={child} stage={stage} after={after} original_rows=true exact_result=true");
            }
        }
    }
}
