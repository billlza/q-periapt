// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn client_authorization_each_sync_fault_keeps_index_and_proof_atomic() {
    let mut f = Prepared::new(None);
    f.active.close();
    let (db, _, count, _) = fault_database_path(&f.f.db_path(), false);
    let mut target = AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
        .expect("fault-backed target");
    f.active = target
        .activate(&f.retired, f.f.signer())
        .expect("already activated")
        .0;
    count.store(0, Ordering::SeqCst);
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    f.active.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut f = Prepared::new(Some(("P", false)));
            let original = f.original_entry();
            f.active.close();
            let (db, remaining, _, _) = fault_database_path(&f.f.db_path(), after);
            let mut target =
                AnchorHandoffTarget::from_database(db, f.f.key(), f.f.approval.clone())
                    .expect("original fault database");
            f.active = target
                .activate(&f.retired, f.f.signer())
                .expect("restore activated target")
                .0;
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                f.active
                    .authorize_handoff_client(&f.request, || Ok(180))
                    .map(|_| ()),
                after,
            );
            assert!(matches!(f.active.pin(), Err(DurableError::Closed)));
            let mut observer = f.f.open();
            let previous = match observer.client_authorization_receipt(f.c.subject) {
                Ok(r) => Some(r.as_bytes().to_vec()),
                Err(e) => {
                    assert!(
                        matches!(e, DurableError::Absent),
                        "partial primary/proof state: {e}"
                    );
                    None
                }
            };
            observer.close();
            f.reopen();
            let receipt = f
                .active
                .authorize_handoff_client(&f.request, || Ok(180))
                .expect("exact original recovery");
            if let Some(previous) = previous {
                assert_eq!(receipt.as_bytes(), previous);
            }
            assert_eq!(f.original_entry(), original);
        }
    }
    eprintln!(
        "HANDOFF_CLIENT_AUTHORIZATION_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}

#[test]
fn client_authorization_sigkill_after_commit_recovers_exact_target_decision() {
    use std::os::unix::process::ExitStatusExt;
    let mut f = Prepared::new(Some(("P", false)));
    f.active.close();
    f.c.store.close();
    fs::remove_file(f.c.server.join("signer")).expect("no old source private key");
    fs::write(f.f.directory.join("retirement"), &f.retired).expect("exact retirement");
    fs::write(f.f.directory.join("client-request"), &f.request).expect("public root approvals");
    let log = fs::File::create(f.f.directory.join("authorization-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "anchor::store::tests::handoff_import::recovery::target_import_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_HANDOFF_TARGET_DIR", &f.f.directory)
            .env("QPERIAPT_HANDOFF_TARGET_STAGE", "client-authorize")
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned test process"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !f.f.directory.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "authorization commit deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!f.f.directory.join("returned").exists());
    let pid = child.0.id();
    child.0.kill().expect("kill owned child");
    assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
    let mut observer = f.f.open();
    let committed = observer
        .client_authorization_receipt(f.c.subject)
        .expect("exact committed authorization")
        .as_bytes()
        .to_vec();
    assert_eq!(
        observer
            .retained_source_state()
            .expect("complete original source"),
        f.f.source
    );
    observer.close();
    f.reopen();
    assert_eq!(
        f.active
            .authorize_handoff_client(&f.request, || Err(DurableError::Conflict))
            .expect("no resign or clock")
            .as_bytes(),
        committed
    );
    eprintln!(
        "HANDOFF_CLIENT_AUTHORIZATION_KILLED pid={pid} parent={}",
        std::process::id()
    );
}
