// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn managed_root_cleanup_process_loss_retains_original_accounting_and_successor_revision() {
    for (action, cut) in [
        ("inventory", "cleanup-parent-before"),
        ("inventory", "cleanup-parent-after"),
        ("inventory", "managed-cleanup-parent-after"),
        ("inventory", "managed-cleanup-return-after"),
        ("journal", "journal-before"),
        ("journal", "journal-after"),
        ("signer", "managed-cleanup-owner-closed-after"),
        ("signer", "managed-cleanup-return-after"),
    ] {
        let (s, mut managed, _, receipt, checkpoint) = prepared();
        let path = super::super::process::original_inputs(&s);
        let ack = if action != "inventory" {
            let (_, ack) = managed
                .with_retired_cleanup(|old| {
                    Ok(super::super::super::cleanup::account_report(&s.f, old))
                })
                .expect("original independent report and host acknowledgement");
            fs::write(path.join("managed-cleanup-ack"), &ack)
                .expect("retain exact original signed ACK");
            if action == "signer" {
                managed
                    .with_retired_cleanup(|old| old.installation()?.erase_journal(&s.f.pin, &ack))
                    .expect("acknowledged journal erasure");
                managed
                    .with_retired_cleanup(|old| old.prepare_signer_erasure(&ack))
                    .expect("original signer plan");
            }
            Some(ack)
        } else {
            None
        };
        managed.close();
        let log =
            fs::File::create_new(path.join("managed-cleanup-child.log")).expect("owned child log");
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command
            .args([
                "--exact",
                "enrollment::account_root::tests::managed::process::managed_root_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MANAGED_ROOT_DIR", path)
            .env("QPERIAPT_MANAGED_ROOT_CLEANUP_ACTION", action)
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log));
        let (ready, expected) = if cut.starts_with("journal-") {
            let stage = if cut.ends_with("before") {
                "before-commit"
            } else {
                "after-commit"
            };
            command
                .env("QPERIAPT_RETIRED_ERASURE_CHILD", path)
                .env("QPERIAPT_RETIRED_ERASURE_STAGE", stage);
            (path.join("erasure-ready"), stage)
        } else {
            command
                .env("QPERIAPT_ROOT_PARENT_DIR", path)
                .env("QPERIAPT_ROOT_PARENT_CUT", cut);
            (path.join("ready"), cut)
        };
        let mut child =
            crate::durable::tests::ChildGuard(command.spawn().expect("owned cleanup process"));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "cleanup boundary not reached at {action}/{cut}: {}",
                fs::read_to_string(path.join("managed-cleanup-child.log")).expect("owned log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(&ready).expect("atomic checkpoint"),
            expected.as_bytes()
        );
        assert!(!path.join("returned").exists());
        child.0.kill().expect("kill only this owned child");
        assert!(!child.0.wait().expect("reap owned child").success());
        let mut managed = s.resume();
        assert_eq!(
            managed
                .retain_witness_retirement(&receipt)
                .expect("same original permanent decision"),
            checkpoint
        );
        if action == "signer" {
            assert_erased(&mut managed);
            managed
                .with_retired_cleanup(|old| old.erase_signer())
                .expect("idempotent logical erasure after lost return");
        } else if let Some(ack) = ack {
            managed
                .with_retired_cleanup(|old| old.installation()?.erase_journal(&s.f.pin, &ack))
                .expect("same acknowledged journal erasure");
        } else {
            managed
                .with_retired_cleanup(|old| old.installation()?.proposal())
                .expect("same original inventory");
        }
        let mut current = s
            .activate(&mut managed, 150)
            .expect("fresh actual successor after process recovery");
        current.next_prekey_publication_id().expect("current owner");
        managed.close();
        assert!(matches!(
            current.next_prekey_publication_id(),
            Err(DurableError::Closed)
        ));
        current.close();
        s.f.assert_fenced();
        eprintln!("MANAGED_ROOT_CLEANUP_PROCESS action={action} cut={cut} original_identity=true revision=2 successor_current=true old_fenced=true");
    }
}
