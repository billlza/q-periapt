// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::super::process::inputs as old_inputs;
use super::super::super::registry::RegistryRecovery;
use super::super::{faults::Case, process::inputs as next_inputs};
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
const CHILD: &str = "enrollment::account_root::tests::transferred::next_attempt::managed::process::transferred_next_managed_process_child";

fn restore(
    root: &Path,
) -> (
    EnrollmentIntent,
    TransferredAccountRootPreparation,
    AnchorFrozenAccount,
    AnchorTransferredAccountReplacementApproval,
    RegistryRecovery,
) {
    let old = old_inputs::restore_registry(root);
    let (target, approval) = next_inputs::restore(root, &old.intent.root, &old.history);
    let previous = TransferredAccountRootPreparation::new(
        old.preparation,
        old.logical.clone(),
        old.history.clone(),
        Some(old.selected.clone()),
    )
    .expect("independent previous preparation");
    let plan = TransferredAccountRootPreparation::new(
        target,
        old.logical,
        old.history,
        Some(old.selected),
    )
    .expect("independent next preparation")
    .after_closed(
        &previous,
        old.approval,
        approval.clone(),
        &old.frozen,
        &fs::read(root.join("root-decision")).expect("exact old Closed"),
    )
    .expect("same independently approved next context");
    (
        old.intent,
        plan,
        old.frozen,
        approval,
        RegistryRecovery::restore(root),
    )
}

#[test]
fn transferred_next_managed_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_MANAGED_NEXT_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let (intent, plan, frozen, approval, recovery) = restore(&root);
    let family = fs::read(root.join("policy-family"))
        .expect("family")
        .try_into()
        .expect("family width");
    let registry = recovery.open_with(family, plan.logical.clone());
    let phase = std::env::var("QPERIAPT_MANAGED_NEXT_PHASE")
        .expect("phase")
        .parse::<u8>()
        .expect("bounded phase");
    assert!(phase <= 2);
    let mut owner = if phase == 0 {
        ManagedAccountRootReplacement::begin_transferred(
            registry,
            recovery.expected,
            plan.clone(),
            paths(&root),
            intent,
        )
        .expect("original next preparation retry")
    } else {
        ManagedAccountRootReplacement::resume_transferred_original(
            registry,
            recovery.expected,
            plan.clone(),
            paths(&root),
            intent,
        )
        .expect("original next controller recovery")
    };
    let returned = match phase {
        0 => {
            assert_eq!(owner.state().expect("next intent"), State::Preparing);
            plan.target().to_bytes().expect("original next plan")
        }
        1 => {
            assert_eq!(
                owner
                    .bind_transferred_freeze(&frozen, approval.clone())
                    .expect("exact freeze and approval"),
                *approval.proposal()
            );
            assert_eq!(owner.state().expect("next bound"), State::Pending);
            plan.target().to_bytes().expect("same next plan")
        }
        2 => {
            let wire = fs::read(root.join("next-decision")).expect("exact signed next decision");
            assert_eq!(
                owner
                    .retain_transferred_decision(&wire)
                    .expect("same next decision"),
                State::Committed
            );
            assert_eq!(owner.state().expect("next committed"), State::Committed);
            wire
        }
        _ => unreachable!(),
    };
    owner.close();
    let mut registry = recovery.open_with(family, plan.logical.clone());
    let old = old_inputs::restore_registry(&root);
    assert_eq!(
        registry
            .transferred_account_decision(old.preparation.operation())
            .expect("exact old Closed remains")
            .as_bytes(),
        fs::read(root.join("root-decision")).expect("old proof")
    );
    assert_eq!(
        registry
            .transferred_preparation(plan.target().operation())
            .expect("exact next preparation")
            .2,
        plan.target()
    );
    registry.close();
    fs::write(root.join("managed-next-returned"), returned).expect("exact returned result");
    fs::write(
        root.join("managed-next-pid"),
        std::process::id().to_string(),
    )
    .expect("new process PID");
}
fn command(root: &Path, phase: u8, label: &str) -> Command {
    let log = fs::File::create_new(root.join(label)).expect("owned process log");
    let mut cmd = Command::new(std::env::current_exe().expect("same source test executable"));
    cmd.args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_MANAGED_NEXT_DIR", root)
        .env("QPERIAPT_MANAGED_NEXT_PHASE", phase.to_string())
        .stdout(Stdio::from(log.try_clone().expect("stdout")))
        .stderr(Stdio::from(log));
    cmd
}
pub(super) fn case(work: Work, phase: u8) -> (Case, TransferredAccountRootPreparation) {
    let mut c = Case::new(work, 0, false);
    let old = original(&c.s.t);
    let plan = context(&c.s, &c.next, &old);
    if phase >= 1 {
        begin(&mut c.s, &plan)
            .expect("original managed next intent")
            .close();
    }
    if phase >= 2 {
        let mut owner = resume(&c.s, &plan).expect("original next preparing owner");
        owner
            .bind_transferred_freeze(&c.s.t.frozen, c.next.approval.clone())
            .expect("original next full approval");
        owner.close();
        c.wire = Some(c.next.decide(&mut c.s, false));
    }
    c.s.registry.close();
    (c, plan)
}

#[test]
fn transferred_next_managed_sigkill_reconciles_registry_parent_child_and_exact_result() {
    let stages = [
        (0, false, "managed-preparation", true),
        (1, false, "managed-binding", true),
        (1, false, "transferred-handoff", false),
        (1, false, "transferred-handoff", true),
        (1, true, "transferred-handoff", false),
        (1, true, "transferred-handoff", true),
        (2, true, "receipt", false),
        (2, true, "receipt", true),
        (2, false, "receipt", false),
        (2, false, "receipt", true),
        (2, false, "managed-decision", true),
        (2, false, "managed-registry", true),
    ];
    for work in [
        Work::Policy(2),
        Work::Credential(1),
        Work::Roster(1),
        Work::Cancellation(true),
    ] {
        for (phase, child, stage, after) in stages {
            let (c, _) = case(work, phase);
            let before = retained(&c.s.t.f.original.paths);
            let root =
                c.s.t
                    .f
                    .original
                    .paths
                    .configuration
                    .parent()
                    .expect("original private directory");
            next_inputs::publish(&c, root);
            let mut cmd = command(root, phase, "managed-next-cut.log");
            let side = if child { "FENCE" } else { "PARENT" };
            cmd.env(format!("QPERIAPT_ROOT_{side}_DIR"), root).env(
                format!("QPERIAPT_ROOT_{side}_CUT"),
                format!("{stage}-{}", if after { "after" } else { "before" }),
            );
            let mut interrupted =
                crate::durable::tests::ChildGuard(cmd.spawn().expect("interrupted process"));
            let killed = interrupted.0.id();
            let until = Instant::now() + Duration::from_secs(30);
            while !root.join("ready").exists() {
                assert!(
                    interrupted.0.try_wait().expect("cut status").is_none()
                        && Instant::now() < until,
                    "cut not reached: {}",
                    fs::read_to_string(root.join("managed-next-cut.log")).expect("cut log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!root.join("managed-next-returned").exists());
            interrupted.0.kill().expect("actual SIGKILL");
            assert_eq!(interrupted.0.wait().expect("reap").signal(), Some(9));
            let mut recovered = crate::durable::tests::ChildGuard(
                command(root, phase, "managed-next-recover.log")
                    .spawn()
                    .expect("new recovery process"),
            );
            let until = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(s) = recovered.0.try_wait().expect("recover status") {
                    break s;
                }
                assert!(Instant::now() < until, "bounded recovery");
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(
                status.success(),
                "recovery failed: {}",
                fs::read_to_string(root.join("managed-next-recover.log")).expect("recovery log")
            );
            let pid = fs::read_to_string(root.join("managed-next-pid"))
                .expect("PID")
                .parse::<u32>()
                .expect("PID integer");
            assert_ne!(pid, killed);
            assert_ne!(pid, std::process::id());
            let expected = c
                .wire
                .clone()
                .unwrap_or_else(|| c.next.plan.to_bytes().expect("original next intent"));
            assert_eq!(
                fs::read(root.join("managed-next-returned")).expect("returned original result"),
                expected
            );
            assert!(retained(&c.s.t.f.original.paths) == before);
            c.s.t.f.assert_fenced();
            eprintln!("TRANSFERRED_MANAGED_NEXT_SIGKILL work={work:?} phase={phase} child={child} stage={stage} after={after} original_state=true exact_result=true");
        }
    }
}
