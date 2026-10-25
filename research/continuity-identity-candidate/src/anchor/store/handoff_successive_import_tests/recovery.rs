// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::Ordering;

#[test]
fn successive_import_cancellation_sync_faults_preserve_original_archive() {
    let (mut f, next) = setup("P", true, true);
    let mut target = next.provision();
    target.close();
    let cancel = f
        .active
        .cancel_handoff(&next.plan)
        .expect("exact B cancellation");
    let (db, _, count, _) = fault_database_path(&next.db_path(), false);
    let mut target = AnchorHandoffTarget::from_database(db, next.key(), next.approval.clone())
        .expect("calibration");
    count.store(0, Ordering::SeqCst);
    target
        .close_cancelled(cancel.as_bytes())
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    count.store(0, Ordering::SeqCst);
    target.close();
    let close_syncs = count.load(Ordering::SeqCst);
    for after in [false, true] {
        for cut in 1..=barriers {
            let (mut f, next) = setup("P", true, true);
            let mut target = next.provision();
            target.close();
            let cancel = f.active.cancel_handoff(&next.plan).expect("B cancellation");
            let (db, remaining, _, _) = fault_database_path(&next.db_path(), after);
            let mut target =
                AnchorHandoffTarget::from_database(db, next.key(), next.approval.clone())
                    .expect("fault owner");
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                target.close_cancelled(cancel.as_bytes()).map(|_| ()),
                after,
            );
            assert_eq!(
                remaining.load(Ordering::SeqCst),
                0,
                "exact fault cut consumed"
            );
            assert!(matches!(target.status(), Err(DurableError::Closed)));
            let mut target = next.open();
            assert_eq!(
                target
                    .close_cancelled(cancel.as_bytes())
                    .expect("same cancellation retry"),
                AnchorHandoffTargetState::Cancelled
            );
            assert_eq!(
                target
                    .retained_source_state()
                    .expect("complete original archive"),
                next.source
            );
            assert_eq!(
                target
                    .cancellation_receipt()
                    .expect("exact retained decision"),
                cancel.as_bytes()
            );
        }
    }
    eprintln!(
        "SUCCESSIVE_IMPORT_SYNC barriers={barriers} faults={} close_syncs={close_syncs}",
        barriers * 2
    );
}

#[test]
fn successive_import_crash_child() {
    if std::env::var_os("QPERIAPT_SUCCESSIVE_IMPORT_CHILD").is_none() {
        return;
    }
    let root = std::env::var_os("QPERIAPT_HANDOFF_TARGET_DIR").expect("owned test directory");
    let root = Path::new(&root);
    let pin = super::super::super::super::recovery::trusted_pin;
    let source = pin(&root.join("source-pin"));
    let target = pin(&root.join("target-pin"));
    let approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &fs::read(root.join("approval")).expect("retained plan"),
        &source,
        &target,
    )
    .expect("independent pins");
    let key = JournalKey::open(&root.join("wrapping")).expect("C key");
    let stage = std::env::var("QPERIAPT_HANDOFF_TARGET_STAGE").expect("cut");
    let mut owner = if stage.starts_with("import") {
        let signer =
            AnchorSigningKey::open(&root.join("signer"), &key, target_key_id()).expect("C signer");
        AnchorHandoffTarget::provision_import(
            &root.join("import.redb"),
            key,
            &signer,
            approval,
            &fs::read(root.join("source")).expect("complete source"),
            &fs::read(root.join("freeze")).expect("original freeze"),
            185,
        )
        .expect("same complete import")
    } else {
        AnchorHandoffTarget::open(&root.join("import.redb"), key, approval)
            .expect("original C import")
    };
    if stage == "cancel" {
        owner
            .close_cancelled(&fs::read(root.join("cancel")).expect("original B cancellation"))
            .expect("same cancellation");
    }
    fs::write(root.join("returned"), b"returned").expect("return marker");
}

#[test]
fn successive_import_process_loss_preserves_exact_archive_and_decision() {
    use std::os::unix::process::ExitStatusExt;
    for stage in ["import-unpublished", "import", "cancel"] {
        let (mut f, next) = setup("G", true, true);
        if stage == "cancel" {
            next.provision().close();
            let cancel = f.active.cancel_handoff(&next.plan).expect("B cancellation");
            fs::write(next.directory.join("cancel"), cancel.as_bytes()).expect("exact decision");
        }
        let log = fs::File::create(next.directory.join("child.log")).expect("owned child log");
        let mut child=ChildGuard(Process::new(std::env::current_exe().expect("test executable")).args(["--exact","anchor::store::tests::handoff_import::adoption::authorization::successive_import::recovery::successive_import_crash_child","--nocapture"]).env("QPERIAPT_SUCCESSIVE_IMPORT_CHILD","1").env("QPERIAPT_HANDOFF_TARGET_DIR",&next.directory).env("QPERIAPT_HANDOFF_TARGET_STAGE",stage).stdout(Stdio::from(log.try_clone().expect("clone log"))).stderr(Stdio::from(log)).spawn().expect("independent process"));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !next.directory.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
                "bounded commit wait"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!next.directory.join("returned").exists());
        let pid = child.0.id();
        child.0.kill().expect("stop owned child");
        assert_eq!(child.0.wait().expect("reap child").signal(), Some(9));
        assert_ne!(pid, std::process::id());
        let mut target = if stage == "import-unpublished" {
            assert!(!next.db_path().exists());
            assert!(
                AnchorHandoffTarget::open(&next.db_path(), next.key(), next.approval.clone())
                    .is_err()
            );
            assert!(fs::read_dir(&next.directory)
                .expect("owned directory")
                .any(|entry| entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".private-publication-")));
            // This owned fixture never published. Explicit first-use retry keeps
            // the unselected orphan; no automatic reset/recovery is introduced.
            next.provision()
        } else {
            next.open()
        };
        assert_eq!(
            target
                .retained_source_state()
                .expect("complete exact original archive"),
            next.source
        );
        assert_eq!(
            target.status().expect("actual durable result"),
            if stage == "cancel" {
                AnchorHandoffTargetState::Cancelled
            } else {
                AnchorHandoffTargetState::ImportedInactive
            }
        );
        if stage == "cancel" {
            assert_eq!(
                target.cancellation_receipt().expect("exact decision"),
                fs::read(next.directory.join("cancel")).expect("original cancellation")
            );
        } else {
            next.approval
                .verify_import_receipt(
                    &next.freeze,
                    target
                        .import_receipt()
                        .expect("exact acknowledgement")
                        .as_bytes(),
                )
                .expect("same plan/source/target");
        }
        eprintln!("SUCCESSIVE_IMPORT_PROCESS stage={stage} killed_pid={pid} recovery_pid={} exact_original=true",std::process::id());
    }
}
