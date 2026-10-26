// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::super::process::inputs as original;
use super::super::registry::RegistryRecovery;
use super::faults::{original_rows, Case, Step};
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
};
#[path = "process_inputs.rs"]
mod inputs;
const CHILD: &str = "enrollment::account_root::tests::transferred::next_attempt::process::transferred_next_attempt_process_child";

#[test]
fn transferred_next_attempt_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_NEXT_ATTEMPT_DIR") else {
        return;
    };
    let root = PathBuf::from(root);
    let old = original::restore_registry(&root);
    let (plan, approval) = inputs::restore(&root, &old.intent.root, &old.history);
    let recovery = RegistryRecovery::restore(&root);
    let phase = std::env::var("QPERIAPT_NEXT_ATTEMPT_PHASE")
        .expect("bounded test phase")
        .parse::<u8>()
        .expect("phase");
    let closed = std::env::var("QPERIAPT_NEXT_ATTEMPT_CLOSED")
        .expect("expected actual outcome")
        .parse::<bool>()
        .expect("outcome");
    let wire = if phase == 2 {
        Some(fs::read(root.join("next-decision")).expect("original signed next result"))
    } else {
        None
    };
    let family = fs::read(root.join("policy-family"))
        .expect("original family")
        .try_into()
        .expect("family width");
    let mut registry = recovery.open_with(family, old.logical);
    let old_wire = fs::read(root.join("root-decision")).expect("original exact closure");
    assert_eq!(
        registry
            .transferred_account_decision(old.preparation.operation())
            .expect("required original Closed prefix")
            .as_bytes(),
        old_wire
    );
    let expected = *[
        State::Preparing,
        State::Pending,
        if closed {
            State::Closed
        } else {
            State::Committed
        },
    ]
    .get(usize::from(phase))
    .expect("bounded stage");
    assert_eq!(
        Step {
            history: &old.history,
            frozen: &old.frozen,
            plan: &plan,
            approval: &approval,
            phase,
            wire: wire.as_deref()
        }
        .apply(&mut registry, recovery.expected)
        .expect("exact original next operation retry"),
        expected
    );
    assert_eq!(
        registry
            .transferred_account_decision(old.preparation.operation())
            .expect("old closure remains exact")
            .as_bytes(),
        old_wire
    );
    assert_eq!(
        registry
            .transferred_preparation(plan.operation())
            .expect("same independently approved next intent")
            .2,
        &plan
    );
    assert!(registry
        .access()
        .expect("live registry")
        .admit(recovery.expected)
        .is_err());
    let returned = if let Some(wire) = wire {
        assert_eq!(
            registry
                .transferred_account_decision(plan.operation())
                .expect("exact signed next result")
                .as_bytes(),
            wire
        );
        wire
    } else {
        plan.to_bytes().expect("exact original next plan")
    };
    registry.close();
    fs::write(root.join("next-returned"), returned).expect("returned exact operation");
    fs::write(
        root.join("next-recovery-pid"),
        std::process::id().to_string(),
    )
    .expect("new PID");
}
fn command(root: &Path, c: &Case, label: &str) -> Command {
    let log = fs::File::create_new(root.join(label)).expect("owned process log");
    let mut cmd = Command::new(std::env::current_exe().expect("same source binary"));
    cmd.args(["--exact", CHILD, "--nocapture"])
        .env("QPERIAPT_NEXT_ATTEMPT_DIR", root)
        .env("QPERIAPT_TRANSFERRED_REGISTRY_DIR", root)
        .env("QPERIAPT_NEXT_ATTEMPT_PHASE", c.phase.to_string())
        .env("QPERIAPT_NEXT_ATTEMPT_CLOSED", c.closed.to_string())
        .stdout(Stdio::from(log.try_clone().expect("stdout")))
        .stderr(Stdio::from(log));
    cmd
}
#[test]
fn transferred_next_attempt_sigkill_recovers_original_closed_history_and_exact_next_operation() {
    for work in [
        Work::Credential(1),
        Work::Roster(1),
        Work::Cancellation(true),
    ] {
        for (phase, closed) in [(0, false), (1, false), (2, false), (2, true)] {
            for after in [false, true] {
                let mut c = Case::new(work, phase, closed);
                let root =
                    c.s.t
                        .f
                        .original
                        .paths
                        .configuration
                        .parent()
                        .expect("original directory")
                        .to_owned();
                let rows = original_rows(&c.s.t);
                let key_paths = [
                    c.s.recovery.path.with_file_name("original-registry-key"),
                    c.s.t.f.original.paths.wrapping.clone(),
                    c.s.t.f.original.paths.signer.clone(),
                ];
                let keys = key_paths
                    .each_ref()
                    .map(|p| fs::read(p).expect("original sealed keys"));
                inputs::publish(&c, &root);
                c.s.registry.close();
                let cut = format!("{phase}-{}", if after { "after" } else { "before" });
                let mut child = crate::durable::tests::ChildGuard(
                    command(&root, &c, "next-cut.log")
                        .env("QPERIAPT_TRANSFERRED_REGISTRY_CUT", &cut)
                        .spawn()
                        .expect("cut process"),
                );
                let killed = child.0.id();
                let until = Instant::now() + Duration::from_secs(30);
                while !root.join("ready").exists() {
                    assert!(
                        child.0.try_wait().expect("status").is_none() && Instant::now() < until,
                        "cut not reached: {}",
                        fs::read_to_string(root.join("next-cut.log")).expect("log")
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(!root.join("next-returned").exists());
                child.0.kill().expect("SIGKILL at actual registry boundary");
                assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
                let mut fresh = crate::durable::tests::ChildGuard(
                    command(&root, &c, "next-recover.log")
                        .spawn()
                        .expect("new independent recovery process"),
                );
                let until = Instant::now() + Duration::from_secs(30);
                loop {
                    if let Some(status) = fresh.0.try_wait().expect("new process status") {
                        assert!(
                            status.success(),
                            "recovery failed: {}",
                            fs::read_to_string(root.join("next-recover.log")).expect("log")
                        );
                        break;
                    }
                    assert!(Instant::now() < until, "bounded recovery");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let pid = fs::read_to_string(root.join("next-recovery-pid"))
                    .expect("PID")
                    .parse::<u32>()
                    .expect("PID number");
                assert_ne!(pid, killed);
                assert_ne!(pid, std::process::id());
                let expected = c
                    .wire
                    .clone()
                    .unwrap_or_else(|| c.next.plan.to_bytes().expect("exact plan"));
                assert_eq!(
                    fs::read(root.join("next-returned")).expect("result"),
                    expected
                );
                assert!(
                    original_rows(&c.s.t) == rows,
                    "original pending and all parent/child rows changed"
                );
                for (path, key) in key_paths.iter().zip(keys) {
                    assert!(fs::read(path).expect("same original keys") == key);
                }
                c.s.reopen();
                c.s.assert_old();
                assert_eq!(
                    c.apply().expect("same next operation after cold recovery"),
                    c.expected()
                );
                eprintln!("TRANSFERRED_NEXT_SIGKILL work={work:?} phase={phase} closed={closed} after={after} killed={killed} recovered={pid} original_pending=true exact_old_closed=true exact_next=true");
            }
        }
    }
}
