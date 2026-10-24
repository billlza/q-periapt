// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn imported_cancellation_each_sync_failure_reconciles_original_exact_bytes() {
    let mut c = case();
    let f = TargetFixture::new(&mut c);
    let mut target = f.provision();
    let cancel = c.store.cancel_handoff(&f.plan).expect("source cancelled");
    target.close();
    let (db, _, count, _) = fault_database_path(&f.db_path(), false);
    let mut target = AnchorHandoffTarget::from_database(db, f.key(), f.approval.clone())
        .expect("calibration owner");
    count.store(0, Ordering::SeqCst);
    target
        .close_cancelled(cancel.as_bytes())
        .expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = case();
            let f = TargetFixture::new(&mut c);
            let mut target = f.provision();
            let cancel = c.store.cancel_handoff(&f.plan).expect("source cancelled");
            target.close();
            let (db, remaining, _, _) = fault_database_path(&f.db_path(), after);
            let mut target = AnchorHandoffTarget::from_database(db, f.key(), f.approval.clone())
                .expect("fault owner");
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                target.close_cancelled(cancel.as_bytes()).map(|_| ()),
                after,
            );
            assert!(matches!(target.status(), Err(DurableError::Closed)));
            let mut target = f.open();
            assert_eq!(
                target
                    .close_cancelled(cancel.as_bytes())
                    .expect("original reconciliation"),
                AnchorHandoffTargetState::Cancelled
            );
            assert_eq!(
                target
                    .retained_source_state()
                    .expect("same complete original source"),
                f.source
            );
            assert_eq!(
                target
                    .cancellation_receipt()
                    .expect("same exact cancellation"),
                cancel.as_bytes()
            );
        }
    }
    eprintln!(
        "HANDOFF_IMPORT_CANCEL_SYNC barriers={barriers} faults={}",
        barriers * 2
    );
}

pub(super) fn trusted_pin(path: &Path) -> AnchorPin {
    let bytes = fs::read(path).expect("retained public pin");
    let mut d = Decoder::new(&bytes);
    let pin = AnchorPin::new(
        AnchorIdentity::from_trusted_state(d.array().expect("identity")).expect("identity"),
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("public pair")).expect("public pair"),
    );
    d.finish().expect("exact pin");
    pin
}

#[test]
fn target_import_crash_child() {
    let Some(root) = std::env::var_os("QPERIAPT_HANDOFF_TARGET_DIR") else {
        return;
    };
    let root = Path::new(&root);
    let source = trusted_pin(&root.join("source-pin"));
    let target = trusted_pin(&root.join("target-pin"));
    let approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("retained approval"),
        &source,
        &target,
    )
    .expect("trusted original approval");
    let key = JournalKey::open(&root.join("wrapping")).expect("target storage key");
    let stage = std::env::var("QPERIAPT_HANDOFF_TARGET_STAGE").expect("stage");
    let mut owner = if stage.starts_with("import") {
        let signer = AnchorSigningKey::open(&root.join("signer"), &key, target_key_id())
            .expect("target key");
        AnchorHandoffTarget::provision_import(
            &root.join("import.redb"),
            key,
            &signer,
            approval,
            &fs::read(root.join("source")).expect("source"),
            &fs::read(root.join("freeze")).expect("freeze"),
            150,
        )
        .expect("target publication")
    } else {
        AnchorHandoffTarget::open(&root.join("import.redb"), key, approval)
            .expect("original import")
    };
    if stage == "activate" {
        let signer = AnchorSigningKey::open(
            &root.join("signer"),
            &JournalKey::open(&root.join("wrapping")).expect("target wrapping"),
            target_key_id(),
        )
        .expect("target signer");
        owner
            .activate(
                &fs::read(root.join("retirement")).expect("original retirement"),
                signer,
            )
            .expect("durable activation");
    }
    if stage == "cancel" {
        owner
            .close_cancelled(&fs::read(root.join("cancel")).expect("source terminal bytes"))
            .expect("durable closure");
    }
    fs::write(root.join("returned"), b"returned").expect("mark returned");
}

#[test]
fn import_publication_and_cancellation_process_loss_never_releases_uncommitted_result() {
    use std::os::unix::process::ExitStatusExt;
    for stage in ["import-unpublished", "import", "cancel"] {
        let mut c = case();
        let f = TargetFixture::new(&mut c);
        if stage == "cancel" {
            f.provision().close();
            let cancel = c
                .store
                .cancel_handoff(&f.plan)
                .expect("source cancellation");
            fs::write(f.directory.join("cancel"), cancel.as_bytes())
                .expect("exact public terminal certificate");
        }
        let log = fs::File::create(f.directory.join("child.log")).expect("test log");
        let mut child = ChildGuard(
            Process::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "anchor::store::tests::handoff_import::recovery::target_import_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_HANDOFF_TARGET_DIR", &f.directory)
                .env("QPERIAPT_HANDOFF_TARGET_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f.directory.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child commit deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!f.directory.join("returned").exists());
        let pid = child.0.id();
        child.0.kill().expect("kill only test child");
        assert_eq!(child.0.wait().expect("reap").signal(), Some(9));
        if stage == "import-unpublished" {
            assert!(!f.db_path().exists());
            assert!(AnchorHandoffTarget::open(&f.db_path(), f.key(), f.approval.clone()).is_err());
            assert!(
                fs::read_dir(&f.directory)
                    .expect("owned directory")
                    .any(|e| e
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".private-publication-")),
                "unpublished orphan retained, never selected for recovery"
            );
            // This fixture has never published. One explicit first-use retry is
            // authorized here; no reset/deletion or automatic retry is performed.
            let mut target = f.provision();
            assert_eq!(
                target.status().expect("one published retry"),
                AnchorHandoffTargetState::ImportedInactive
            );
        } else {
            let mut target = f.open();
            assert_eq!(
                target
                    .retained_source_state()
                    .expect("exact original after real kill"),
                f.source
            );
            assert_eq!(
                target.status().expect("actual durable result"),
                if stage == "cancel" {
                    AnchorHandoffTargetState::Cancelled
                } else {
                    AnchorHandoffTargetState::ImportedInactive
                }
            );
            if stage == "import" {
                f.approval
                    .verify_import_receipt(
                        &f.freeze,
                        target
                            .import_receipt()
                            .expect("retained receipt without resigning")
                            .as_bytes(),
                    )
                    .expect("original scope");
            }
        }
        eprintln!("HANDOFF_IMPORT_SIGKILL stage={stage} pid={pid}");
    }
}
