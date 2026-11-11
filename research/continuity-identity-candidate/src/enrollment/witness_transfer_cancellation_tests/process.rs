// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::witness_handoff::process::{publish_case, restore};
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    time::Instant,
};

#[test]
fn transferred_cancellation_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFER_CANCEL_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let (mut owner, policy, plan) = restore(root);
    owner
        .prepare_witnessed_credential_cancellation_with_witness_plan(policy.historical(), plan, 290)
        .expect("original selected cancellation without device signer");
    fs::write(root.join("returned"), b"unexpected").expect("return marker");
}

#[test]
fn transferred_cancellation_sigkill_recovers_original_reservation_and_parent() {
    for cut in [
        "cancellation-reserve-before",
        "cancellation-reserve-after",
        "cancellation-parent-before",
        "cancellation-parent-after",
    ] {
        let (f, g, transfer) = staged_transfer();
        let before = disk(&f);
        let root =
            f.c.paths
                .configuration
                .parent()
                .expect("owned fixture root");
        publish_case(&f.c, &transfer, root);
        let retained = f.c.paths.signer.with_extension("retained-for-test");
        fs::rename(&f.c.paths.signer, &retained).expect("only fixture signer unavailable");
        let log = fs::File::create(root.join("child.log")).expect("owned child log");
        let mut child = crate::durable::tests::ChildGuard(Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "enrollment::tests::witness_renewal::witness_transfer_cancellation::process::transferred_cancellation_process_child", "--nocapture"])
            .env("QPERIAPT_TRANSFER_CANCEL_DIR", root)
            .env("QPERIAPT_ENROLLMENT_WITNESS_DIR", root).env("QPERIAPT_ENROLLMENT_WITNESS_CUT", cut)
            .env("QPERIAPT_WITNESS_ADOPTION_DIR", root).env("QPERIAPT_WITNESS_ADOPTION_CUT", cut)
            .stdout(Stdio::from(log.try_clone().expect("log clone"))).stderr(Stdio::from(log))
            .spawn().expect("owned process"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "missing cut {cut}: {}",
                fs::read_to_string(root.join("child.log")).expect("log")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned").exists());
        let pid = child.0.id();
        child.0.kill().expect("kill owned child");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        assert_ne!(pid, std::process::id());
        assert_eq!(disk(&f).0, before.0);
        let mut owner = open(&f.c);
        let cancellation = owner
            .prepare_witnessed_credential_cancellation_with_witness_plan(
                f.c.policy.historical(),
                transfer.plan.clone(),
                290,
            )
            .expect("same original recovery");
        assert_eq!(cancellation.operation(), g.operation());
        assert_eq!(
            owner
                .prepare_witnessed_credential_cancellation_with_witness_plan(
                    f.c.policy.historical(),
                    transfer.plan.clone(),
                    290
                )
                .expect("exact retry"),
            cancellation
        );
        assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
        fs::rename(retained, &f.c.paths.signer).expect("exact original signer restored");
        transfer
            .target
            .lock()
            .expect("target")
            .transferred_control(&transfer.control)
            .expect("independent target authorization")
            .close_unprepared_credential_renewal(
                cancellation,
                g.historical(),
                f.c.policy.historical(),
            )
            .expect("exact close");
        transfer.reopen_target();
        transfer.set_time(290);
        let mut client = transfer.client(&mut owner, &f.c);
        assert!(
            matches!(owner.reconcile_witnessed_credential_renewal(g.operation(), g.statement_digest(),
            f.c.policy.historical(), 290, &mut client).expect("closed and acknowledged"), CredentialRenewalStatus::Closed { operation, .. } if operation == g.operation())
        );
        owner.close();
        assert_eq!(disk(&f), before);
        eprintln!(
            "TRANSFER_CANCEL_PROCESS cut={cut} killed_pid={pid} new_parent={} exact_original=true",
            std::process::id()
        );
    }
}
