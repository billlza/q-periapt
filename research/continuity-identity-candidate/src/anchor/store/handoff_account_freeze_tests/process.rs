// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::os::unix::process::ExitStatusExt;

fn pin(path: &Path) -> AnchorPin {
    let bytes = fs::read(path).expect("independent public pin");
    let mut d = Decoder::new(&bytes);
    let pin = AnchorPin::new(
        AnchorIdentity::from_trusted_state(d.array().expect("identity")).expect("pin identity"),
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("key bytes")).expect("public key"),
    );
    d.finish().expect("exact public pin");
    pin
}
#[test]
fn transferred_account_freeze_process_child() {
    let Some(root) = std::env::var_os("QPERIAPT_TRANSFERRED_ACCOUNT_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let origin = pin(&root.join("source-pin"));
    let current = pin(&root.join("target-pin"));
    let target_approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("target approval"),
        &origin,
        &current,
    )
    .expect("independent target inputs");
    let checkpoint: [u8; 32] = fs::read(root.join("account-history-checkpoint"))
        .expect("retained checkpoint")
        .try_into()
        .expect("checkpoint size");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &fs::read(root.join("account-history")).expect("complete history"),
        &origin,
        &current,
        checkpoint,
    )
    .expect("independently verified history");
    let request = AnchorAccountFreezeRequest::from_bytes(
        &fs::read(root.join("account-request")).expect("original request"),
    )
    .expect("exact request");
    let approved = AnchorTransferredAccountFreezeApproval::restore_trusted_state(
        &fs::read(root.join("account-approval")).expect("independent account decision"),
        &request,
        &history,
    )
    .expect("exact retained approval");
    let wrapping = JournalKey::open(&root.join("wrapping")).expect("original key");
    let signer = AnchorSigningKey::open(&root.join("signer"), &wrapping, target_key_id())
        .expect("current signer");
    let mut target =
        AnchorHandoffTarget::open(&root.join("import.redb"), wrapping, target_approval)
            .expect("original imported state");
    let (mut active, _) = target
        .activate(
            &fs::read(root.join("account-source-retirement")).expect("retained source retirement"),
            signer,
        )
        .expect("original activation");
    let mode = std::env::var("QPERIAPT_TRANSFERRED_ACCOUNT_MODE").expect("child mode");
    let mut calls = 0;
    let wire = active
        .freeze_transferred_account(&approved, || {
            calls += 1;
            if mode == "before" && calls == 2 {
                fs::write(root.join("ready"), b"before-commit").expect("before-commit marker");
                loop {
                    std::thread::park();
                }
            }
            Ok(180)
        })
        .expect("original exact operation");
    fs::write(root.join("returned-account-freeze"), wire).expect("returned original proof");
    fs::write(
        root.join("account-recovery-pid"),
        std::process::id().to_string(),
    )
    .expect("fresh process identity");
}

#[test]
fn transferred_account_freeze_process_loss_before_and_after_commit_recovers_in_new_pid() {
    const CHILD: &str = "anchor::store::tests::handoff_import::adoption::authorization::account_freeze::recovery::process::transferred_account_freeze_process_child";
    for committed in [false, true] {
        let mut f = Prepared::new(Some(("P", false)));
        let approved = approval(&mut f, 223);
        let old = f.original_entry();
        let revision = f.active.image().expect("current revision").revision;
        let root = &f.f.directory;
        for (name, bytes) in [
            (
                "account-history",
                f.history.to_bytes().expect("full history"),
            ),
            (
                "account-history-checkpoint",
                f.history.checkpoint().to_vec(),
            ),
            ("account-request", approved.proposal().request().to_bytes()),
            (
                "account-approval",
                approved.to_bytes().expect("independent approval"),
            ),
            ("account-source-retirement", f.retired.clone()),
        ] {
            fs::write(root.join(name), bytes).expect("retained original public input");
        }
        assert_eq!(f.f.db_path(), root.join("import.redb"));
        f.active.close();
        let log = fs::File::create(root.join("account-crash.log")).expect("owned log");
        let mut command = Process::new(std::env::current_exe().expect("binary"));
        command
            .args(["--exact", CHILD, "--nocapture"])
            .env("QPERIAPT_TRANSFERRED_ACCOUNT_DIR", root)
            .env(
                "QPERIAPT_TRANSFERRED_ACCOUNT_MODE",
                if committed { "after" } else { "before" },
            )
            .stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log));
        if committed {
            command
                .env("QPERIAPT_ANCHOR_SERVER_DIR", root)
                .env("QPERIAPT_ANCHOR_CRASH_REVISION", (revision + 1).to_string());
        }
        let mut child = ChildGuard(command.spawn().expect("fresh process"));
        let old_pid = child.0.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child did not reach exact commit boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-account-freeze").exists());
        child.0.kill().expect("kill owned child");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        let observed = f.f.open().transferred_account_freeze_receipt(&approved);
        let before = if committed {
            Some(observed.expect("committed before crash"))
        } else {
            assert!(matches!(observed, Err(DurableError::Absent)));
            None
        };
        let log = fs::File::create(root.join("account-recover.log")).expect("owned recovery log");
        let mut recovery = ChildGuard(
            Process::new(std::env::current_exe().expect("binary"))
                .args(["--exact", CHILD, "--nocapture"])
                .env("QPERIAPT_TRANSFERRED_ACCOUNT_DIR", root)
                .env("QPERIAPT_TRANSFERRED_ACCOUNT_MODE", "recover")
                .stdout(Stdio::from(log.try_clone().expect("log")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("new recovery process"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = recovery.0.try_wait().expect("recovery status") {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "bounded recovery");
            std::thread::sleep(Duration::from_millis(10));
        }
        let new_pid: u32 = fs::read_to_string(root.join("account-recovery-pid"))
            .expect("PID")
            .parse()
            .expect("PID number");
        assert_ne!(new_pid, old_pid);
        assert_ne!(new_pid, std::process::id());
        let wire = fs::read(root.join("returned-account-freeze")).expect("recovered proof");
        if let Some(before) = before {
            assert_eq!(wire, before);
        }
        approved
            .verify_receipt(&f.history, &wire)
            .expect("exact independently retained transaction");
        f.reopen();
        assert_eq!(f.original_entry(), old);
        assert_eq!(
            f.active
                .transferred_account_freeze_receipt(&approved)
                .expect("same durable outcome"),
            wire
        );
        eprintln!("TRANSFERRED_ACCOUNT_FREEZE_PROCESS committed={committed} killed_pid={old_pid} recovery_pid={new_pid}");
    }
}
