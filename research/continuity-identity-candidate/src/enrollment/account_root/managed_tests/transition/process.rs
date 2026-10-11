// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn managed_root_transition_process_loss_reconciles_each_original_commit() {
    for bound in [false, true] {
        let cuts: &[&str] = if bound {
            &[
                "managed-noncommit-after",
                "managed-next-preparation-after",
                "managed-next-binding-after",
                "handoff-before",
                "handoff-after",
                "child-handoff-before",
                "child-handoff-after",
                "managed-next-parent-after",
            ]
        } else {
            &[
                "managed-noncommit-after",
                "managed-next-preparation-after",
                "managed-next-binding-after",
                "intent-before",
                "intent-after",
                "managed-next-parent-after",
            ]
        };
        for cut in cuts {
            let (t, mut managed) = Transition::new(bound);
            managed.close();
            let path = super::super::process::original_inputs(&t.s);
            fs::write(
                path.join("managed-next-plan"),
                t.next.to_bytes().expect("independent next approval"),
            )
            .expect("retain next plan");
            fs::write(path.join("managed-noncommit"), &t.noncommit)
                .expect("retain signed original terminal result");
            fs::write(path.join("managed-freeze"), &t.freeze)
                .expect("retain signed original freeze");
            let log = fs::File::create_new(path.join("transition-child.log")).expect("owned log");
            let mut command = Command::new(std::env::current_exe().expect("current test binary"));
            command
                .args([
                    "--exact",
                    "enrollment::account_root::tests::managed::process::managed_root_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MANAGED_ROOT_DIR", path)
                .env("QPERIAPT_MANAGED_ROOT_TRANSITION", "1")
                .env("QPERIAPT_ROOT_PARENT_DIR", path)
                .env("QPERIAPT_ROOT_PARENT_CUT", cut)
                .stdout(Stdio::from(log.try_clone().expect("stdout")))
                .stderr(Stdio::from(log));
            let expected_marker = if let Some(suffix) = cut.strip_prefix("child-handoff-") {
                let marker = format!("parent-handoff-{suffix}");
                command
                    .env("QPERIAPT_ROOT_FENCE_DIR", path)
                    .env("QPERIAPT_ROOT_FENCE_CUT", &marker);
                marker
            } else {
                (*cut).to_owned()
            };
            let mut child =
                crate::durable::tests::ChildGuard(command.spawn().expect("owned child"));
            let deadline = Instant::now() + Duration::from_secs(30);
            while !path.join("ready").exists() {
                assert!(
                    child.0.try_wait().expect("child status").is_none()
                        && Instant::now() < deadline,
                    "transition boundary not reached: {}",
                    fs::read_to_string(path.join("transition-child.log")).expect("child log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                fs::read(path.join("ready")).expect("observed exact commit boundary"),
                expected_marker.as_bytes()
            );
            assert!(!path.join("returned").exists(), "kill before API return");
            child.0.kill().expect("kill only owned child");
            assert!(!child.0.wait().expect("reap owned child").success());
            let registry = t.s.registry();
            assert_eq!(
                registry
                    .preparation(t.s.plan.operation())
                    .expect("original terminal decision")
                    .1,
                State::Closed
            );
            match *cut {
                "managed-noncommit-after" => assert!(matches!(
                    registry.preparation(t.next.operation()),
                    Err(DurableError::Absent)
                )),
                "managed-next-preparation-after" => assert_eq!(
                    registry
                        .preparation(t.next.operation())
                        .expect("next preparation")
                        .1,
                    State::Preparing
                ),
                _ => assert_eq!(
                    registry
                        .preparation(t.next.operation())
                        .expect("bound next operation")
                        .1,
                    State::Pending
                ),
            }
            assert!(matches!(
                registry
                    .access()
                    .expect("registry")
                    .current(t.s.expected.application()),
                Err(DurableError::Suspended)
            ));
            drop(registry);
            let mut resumed = t.resume();
            assert_eq!(
                resumed.state().expect("same resumed target"),
                State::Pending
            );
            t.finish(&mut resumed);
            eprintln!("MANAGED_ROOT_TRANSITION_PROCESS bound={bound} cut={cut} original_registry=true original_parent=true revision=2 old_fenced=true successor_admitted=true");
        }
    }
}
