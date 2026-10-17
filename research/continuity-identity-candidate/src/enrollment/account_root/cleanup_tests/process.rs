// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::process::{Command, Stdio};

#[test]
fn account_root_cleanup_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ROOT_CLEANUP_PROCESS_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let (intent, pin, proposal) = super::super::process::read_inputs(&path);
    let cut = std::env::var("QPERIAPT_ROOT_CLEANUP_PROCESS_CUT").expect("selected boundary");
    if cut.starts_with("parent-") {
        AccountRootEnrollmentRecovery::resume_original(paths(&path), intent, pin, proposal)
            .expect("exact retained root decision")
            .into_retired()
            .expect("original inventory parent commit");
    } else {
        let retired = pin
            .verify_retired_account(
                &proposal,
                &fs::read(path.join("receipt")).expect("original signed retirement"),
            )
            .expect("purpose 22")
            .retired_subject(
                proposal
                    .predecessors()
                    .next()
                    .expect("single fixture original subject"),
            )
            .expect("verified original subject");
        let mut owner = RetiredDeviceEnrollment::open(paths(&path), intent, pin.clone(), retired)
            .expect("same cleanup identity");
        owner
            .installation()
            .expect("same original child")
            .erase_journal(
                &pin,
                &fs::read(path.join("host-ack")).expect("original purpose 21"),
            )
            .expect("atomic acknowledged erasure");
    }
    fs::write(path.join("returned"), b"returned").expect("actual return marker");
}

#[test]
fn account_root_cleanup_process_loss_recovers_parent_and_erasure_without_reactivation() {
    for cut in [
        "parent-before",
        "parent-after",
        "journal-before",
        "journal-after",
    ] {
        let f = fixture();
        let (mut root, retired) = committed(&f);
        let proposal = root.proposal().expect("original root approval");
        root.close();
        let path = f
            .original
            .paths
            .wrapping
            .parent()
            .expect("owned original directory");
        let mut public = f.original.intent.root.encode();
        f.original.intent.encode(&mut public);
        public.extend_from_slice(f.pin.identity().as_bytes());
        public.extend_from_slice(&f.pin.public_key().encode());
        fs::write(path.join("independent-inputs"), public).expect("original public expectations");
        fs::write(
            path.join("proposal"),
            proposal.to_bytes().expect("canonical proposal"),
        )
        .expect("original operation");
        fs::write(path.join("receipt"), f.receipt(&proposal)).expect("signed permanent retirement");
        let ack = if cut.starts_with("journal-") {
            let mut cleanup = reopen(&f, retired);
            let (_, ack) = account_report(&f, &mut cleanup);
            fs::write(path.join("host-ack"), &ack).expect("independent original acknowledgement");
            cleanup.close();
            Some(ack)
        } else {
            None
        };
        let log = fs::File::create_new(path.join("cleanup-child.log")).expect("owned child log");
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command.args(["--exact", "enrollment::account_root::tests::cleanup::process::account_root_cleanup_process_child", "--nocapture"])
            .env("QPERIAPT_ROOT_CLEANUP_PROCESS_DIR", path)
            .env("QPERIAPT_ROOT_CLEANUP_PROCESS_CUT", cut)
            .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log));
        let (ready, expected) = if cut.starts_with("parent-") {
            let expected = format!("cleanup-{cut}");
            command
                .env("QPERIAPT_ROOT_PARENT_DIR", path)
                .env("QPERIAPT_ROOT_PARENT_CUT", &expected);
            (path.join("ready"), expected)
        } else {
            let expected = if cut.ends_with("before") {
                "before-commit"
            } else {
                "after-commit"
            };
            command
                .env("QPERIAPT_RETIRED_ERASURE_CHILD", path)
                .env("QPERIAPT_RETIRED_ERASURE_STAGE", expected);
            (path.join("erasure-ready"), expected.to_owned())
        };
        let mut child = command.spawn().expect("owned cleanup process");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() && Instant::now() < deadline {
            let status = child.try_wait().expect("child status");
            assert!(
                status.is_none(),
                "cleanup child exited at {cut}: {status:?}; {}",
                fs::read_to_string(path.join("cleanup-child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            child.kill().expect("stop owned timed-out child");
            child.wait().expect("reap");
        }
        assert!(ready.exists(), "missing {cut} checkpoint");
        assert_eq!(
            fs::read(&ready).expect("atomic checkpoint"),
            expected.as_bytes()
        );
        child
            .kill()
            .expect("actual process loss at durable boundary");
        assert!(!child.wait().expect("reaped process").success());
        assert!(!path.join("returned").exists());
        let mut cleanup = reopen(&f, retired);
        if let Some(ack) = ack {
            cleanup
                .installation()
                .expect("same child")
                .erase_journal(&f.pin, &ack)
                .expect("exact erasure retry");
            assert_eq!(
                cleanup
                    .installation()
                    .expect("reopen same child")
                    .journal_erasure_status(&f.pin)
                    .expect("terminal"),
                JournalErasureState::Erased
            );
        } else {
            cleanup
                .installation()
                .expect("same original inventory")
                .proposal()
                .expect("retained expectation");
        }
        cleanup.close();
        f.assert_fenced();
    }
}
