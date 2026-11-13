// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn managed_root_adoption_process_loss_preserves_original_approval_and_commit_order() {
    for bound in [false, true] {
        let cuts: &[&str] = if bound {
            &[
                "managed-adoption-closure-after",
                "handoff-before",
                "handoff-after",
                "child-handoff-before",
                "child-handoff-after",
                "managed-adoption-parent-after",
                "receipt-before",
                "receipt-after",
                "managed-adoption-retirement-after",
                "managed-adoption-registry-after",
            ]
        } else {
            &[
                "managed-adoption-closure-after",
                "intent-before",
                "intent-after",
                "managed-adoption-parent-after",
                "receipt-before",
                "receipt-after",
                "managed-adoption-retirement-after",
                "managed-adoption-registry-after",
            ]
        };
        for cut in cuts {
            let (a, mut managed) = Adoption::new(bound, 200, false);
            managed.close();
            let path = super::super::process::original_inputs(&a.s);
            fs::write(
                path.join("managed-winner"),
                a.proposal
                    .to_bytes()
                    .expect("exact independent winner expectation"),
            )
            .expect("retain winner");
            fs::write(path.join("managed-noncommit"), &a.noncommit)
                .expect("retain original terminal proof");
            fs::write(path.join("managed-receipt"), &a.receipt)
                .expect("retain authenticated winner proof");
            let log = fs::File::create_new(path.join("adoption-child.log")).expect("owned log");
            let mut command = Command::new(std::env::current_exe().expect("current actual binary"));
            command
                .args([
                    "--exact",
                    "enrollment::account_root::tests::managed::process::managed_root_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MANAGED_ROOT_DIR", path)
                .env("QPERIAPT_MANAGED_ROOT_ADOPTION", "1")
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
                    "adoption boundary not reached: {}",
                    fs::read_to_string(path.join("adoption-child.log")).expect("child log")
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                fs::read(path.join("ready")).expect("actual complete boundary"),
                expected_marker.as_bytes()
            );
            assert!(!path.join("returned").exists());
            child.0.kill().expect("kill only owned child");
            assert!(!child.0.wait().expect("reap child").success());
            let registry = a.s.registry();
            assert_eq!(
                registry
                    .preparation(a.s.plan.operation())
                    .expect("original losing plan")
                    .1,
                State::Closed
            );
            if *cut == "managed-adoption-registry-after" {
                assert_eq!(
                    registry
                        .replacement(a.proposal.operation())
                        .expect("adopted winner persisted")
                        .1,
                    State::Committed
                );
                assert_eq!(
                    registry
                        .access()
                        .expect("access")
                        .current(a.s.expected.application())
                        .expect("winner selected")
                        .revision(),
                    2
                );
            } else {
                assert!(matches!(
                    registry.replacement(a.proposal.operation()),
                    Err(DurableError::Absent)
                ));
                assert!(matches!(
                    registry
                        .access()
                        .expect("access")
                        .current(a.s.expected.application()),
                    Err(DurableError::Suspended)
                ));
            }
            drop(registry);
            let mut resumed = a.resume();
            a.finish(&mut resumed);
            eprintln!("MANAGED_ROOT_ADOPTION_PROCESS bound={bound} cut={cut} original_approval=true retirement_before_registry=true revision=2 no_fabricated_plan=true successor_admitted=true");
        }
    }
}
