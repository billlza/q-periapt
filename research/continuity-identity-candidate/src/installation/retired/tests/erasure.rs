// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::retired_device::JournalErasureState::{Erased, Retained};

fn identity(c: &Case) -> JournalIdentity {
    JournalIdentity::from_trusted_state(c.retired.subject().journal_parts().0).expect("identity")
}
fn acknowledged(c: &Case) -> (crate::AnchorRetiredReportProposal, Vec<u8>) {
    let mut owner = c.open().expect("original installation");
    let (body, retained) = recorded_host_report(c, &mut owner);
    let expected = owner
        .prepare_host_acknowledgement(&body, &retained)
        .expect("host intent");
    assert_eq!(
        owner.journal_erasure_status(&c.pin).expect("no erasure"),
        Retained
    );
    owner.close();
    let mut witness = c.store.lock().expect("controller");
    witness
        .acknowledge_retired_report(&expected)
        .expect("explicit host ACK");
    let wire = witness
        .retired_report_acknowledgement_receipt(&expected)
        .expect("purpose21");
    (expected, wire)
}
fn write_rows(c: &Case, rows: &[(String, Vec<u8>)]) {
    let db = open_private_database(&c.paths.journal).expect("test journal");
    let tx = transaction(&db).expect("transaction");
    {
        let mut table = tx
            .open_table(TableDefinition::<&str, &[u8]>::new(
                "continuity_device_candidate_v21",
            ))
            .expect("table");
        for name in ["image", "pending", "retired", "extra"] {
            table.remove(name).expect("remove");
        }
        for (name, bytes) in rows {
            table
                .insert(name.as_str(), bytes.as_slice())
                .expect("test row");
        }
    }
    tx.commit().expect("test state");
}

#[test]
fn journal_erasure_requires_host_ack_and_preserves_independent_accounting() {
    let c = Case::build(false, true);
    let original = journal_rows(&c.paths.journal);
    let mut owner = c.open().expect("owner");
    let (body, retained) = recorded_host_report(&c, &mut owner);
    let archives = fs::read(&c.paths.archives).expect("post-report archives");
    let device = c
        .peer
        .responder
        .inventory_inputs()
        .expect("device")
        .1
        .clone();
    let receipt20 = retained_report(&c, retained.proposal());
    assert!(matches!(
        owner.erase_journal(&c.pin, &receipt20),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(owner.proposal(), Err(DurableError::Closed)));
    let mut owner = c.open().expect("owner");
    let expected = owner
        .prepare_host_acknowledgement(&body, &retained)
        .expect("complete host record");
    assert!(owner.erase_journal(&c.pin, &receipt20).is_err());
    assert_eq!(journal_rows(&c.paths.journal), original);
    let wire = {
        let mut witness = c.store.lock().expect("controller");
        witness
            .acknowledge_retired_report(&expected)
            .expect("host ACK");
        witness
            .retired_report_acknowledgement_receipt(&expected)
            .expect("purpose21")
    };
    c.peer.responder.current_policy().expect("policy").close();
    let mut owner = c.open().expect("historical owner");
    owner
        .erase_journal(&c.pin, &wire)
        .expect("atomic logical erase");
    assert!(matches!(owner.proposal(), Err(DurableError::Closed)));
    let rows = journal_rows(&c.paths.journal);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.first().expect("terminal").0, "retired");
    assert_eq!(rows.first().expect("terminal").1.len(), 3770);
    assert!(
        fs::read(&c.paths.archives).expect("archives preserved") == archives,
        "erasure must not touch the archive file"
    );
    assert!(c.key_path.is_file());
    let mut owner = c.open().expect("independent metadata survives");
    assert_eq!(
        owner.journal_erasure_status(&c.pin).expect("terminal"),
        Erased
    );
    assert_eq!(
        owner.host_acknowledgement_proposal().expect("saved ACK"),
        Some(expected.clone())
    );
    assert_eq!(
        owner
            .prepare_host_acknowledgement(&body, &retained)
            .expect("same host record"),
        expected
    );
    owner.close();
    assert_eq!(
        fs::read(c._directory.path().join("host-recorded-report.bin")).expect("host record"),
        body
    );
    assert!(DeviceJournal::open(&c.paths.journal, c.key(), &device, identity(&c)).is_err());
    fs::rename(
        &c.paths.archives,
        c.paths.archives.with_extension("unavailable"),
    )
    .expect("archive unavailable");
    let mut owner = c.open().expect("metadata");
    let inventory = retained_inventory(&c, &mut owner);
    assert!(matches!(
        owner.report(&inventory, &c.pin, &receipt20),
        Err(DurableError::Protocol(Error::Retired))
    ));
    eprintln!(
        "RETIRED_JOURNAL_ERASURE full_session=true requires_purpose21=true exact_terminal=true separate_archives_key_host_record_preserved=true"
    );
}

#[test]
fn journal_erasure_rejects_missing_changed_and_locked_original_inventory() {
    let c = Case::with_pending(true);
    let (expected, wire) = acknowledged(&c);
    let original = journal_rows(&c.paths.journal);
    assert!(original.iter().any(|(n, _)| n == "pending"));
    let foreign = Case::new();
    let mut invalid = wire.clone();
    *invalid.last_mut().expect("signature") ^= 1;
    for (pin, receipt) in [
        (&foreign.pin, wire.as_slice()),
        (&c.pin, invalid.as_slice()),
    ] {
        assert!(c
            .open()
            .expect("owner")
            .erase_journal(pin, receipt)
            .is_err());
        assert_eq!(journal_rows(&c.paths.journal), original);
    }
    let lease = open_private_database(&c.paths.journal).expect("competing owner");
    assert!(c
        .open()
        .expect("owner")
        .erase_journal(&c.pin, &wire)
        .is_err());
    drop(lease);
    let without_pending: Vec<_> = original
        .iter()
        .filter(|(n, _)| n != "pending")
        .cloned()
        .collect();
    write_rows(&c, &without_pending);
    assert!(matches!(
        c.open().expect("owner").erase_journal(&c.pin, &wire),
        Err(DurableError::Conflict)
    ));
    assert_eq!(journal_rows(&c.paths.journal), without_pending);
    assert!(c
        .open()
        .expect("owner")
        .journal_erasure_status(&c.pin)
        .is_err());
    write_rows(&c, &original);
    let backup = c.paths.journal.with_extension("unavailable");
    fs::rename(&c.paths.journal, &backup).expect("preserve missing source");
    assert!(c
        .open()
        .expect("metadata")
        .erase_journal(&c.pin, &wire)
        .is_err());
    assert!(c
        .open()
        .expect("metadata")
        .journal_erasure_status(&c.pin)
        .is_err());
    assert!(!c.paths.journal.exists());
    fs::rename(backup, &c.paths.journal).expect("restore exact source");
    let mut owner = c.open().expect("owner");
    assert_eq!(
        owner
            .host_acknowledgement_proposal()
            .expect("original intent"),
        Some(expected)
    );
    owner
        .erase_journal(&c.pin, &wire)
        .expect("only exact original inventory");
}

// Deliberately model knowledge of the original wrapping-key FILE, never process memory.
// A valid local MAC alone must not fabricate the independent witness's host decision.
fn reseal_terminal(c: &Case, bytes: &mut Vec<u8>) {
    use hmac::Mac;
    let raw = zeroize::Zeroizing::new(fs::read(&c.key_path).expect("test wrapping key file"));
    let mut derived = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, raw.get(8..40).expect("key"))
        .expand(
            b"Q-PERIAPT-CONTINUITY-RETIRED-JOURNAL-TERMINAL-KEY/v1",
            derived.as_mut(),
        )
        .expect("derive");
    bytes.truncate(3738);
    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(derived.as_ref()).expect("MAC");
    mac.update(bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
}
#[test]
fn journal_erasure_terminal_requires_local_mac_and_exact_independent_ack_signature() {
    let c = Case::new();
    let (expected, wire) = acknowledged(&c);
    c.open()
        .expect("owner")
        .erase_journal(&c.pin, &wire)
        .expect("erase");
    let original = journal_rows(&c.paths.journal);
    let terminal = original.first().expect("terminal").1.clone();
    let purpose20 = retained_report(&c, &expected);
    let foreign = Case::new();
    let (_, other_wire) = acknowledged(&foreign);
    let mut cases = vec![terminal.get(..3769).expect("truncated").to_vec(), {
        let mut b = terminal.clone();
        *b.last_mut().expect("MAC") ^= 1;
        b
    }];
    for receipt in [purpose20, other_wire, {
        let mut b = wire.clone();
        *b.last_mut().expect("signature") ^= 1;
        b
    }] {
        let mut forged = b"QPRJER01".to_vec();
        forged.extend_from_slice(&receipt);
        reseal_terminal(&c, &mut forged);
        cases.push(forged);
    }
    for bytes in cases {
        let rows = vec![("retired".to_owned(), bytes)];
        write_rows(&c, &rows);
        assert!(c
            .open()
            .expect("metadata")
            .journal_erasure_status(&c.pin)
            .is_err());
        assert!(c
            .open()
            .expect("metadata")
            .erase_journal(&c.pin, &wire)
            .is_err());
        assert_eq!(journal_rows(&c.paths.journal), rows);
    }
    let extra = vec![
        ("retired".to_owned(), terminal),
        ("extra".to_owned(), vec![1]),
    ];
    write_rows(&c, &extra);
    assert!(c
        .open()
        .expect("metadata")
        .journal_erasure_status(&c.pin)
        .is_err());
    write_rows(&c, &original);
    assert_eq!(
        c.open()
            .expect("metadata")
            .journal_erasure_status(&c.pin)
            .expect("authentic terminal"),
        Erased
    );
}

#[test]
fn journal_erasure_every_sync_cut_is_exact_original_or_authenticated_terminal() {
    for pending in [false, true] {
        let calibration = Case::with_pending(pending);
        let (expected, wire) = acknowledged(&calibration);
        let (db, _, count, _) = fault_database_path(&calibration.paths.journal, false);
        count.store(0, Ordering::SeqCst);
        DeviceJournal::erase_retired_journal_in_database(
            &db,
            &calibration.key(),
            identity(&calibration),
            calibration.retired,
            &calibration.pin,
            &expected,
            &wire,
        )
        .expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        drop(db);
        let (db, remaining, count, _) = fault_database_path(&calibration.paths.journal, false);
        remaining.store(1, Ordering::SeqCst);
        count.store(0, Ordering::SeqCst);
        let fresh = calibration
            .store
            .lock()
            .expect("controller")
            .retired_report_acknowledgement_receipt(&expected)
            .expect("fresh same-proposal signature");
        DeviceJournal::erase_retired_journal_in_database(
            &db,
            &calibration.key(),
            identity(&calibration),
            calibration.retired,
            &calibration.pin,
            &expected,
            &fresh,
        )
        .expect("readonly repeat");
        assert_eq!(count.load(Ordering::SeqCst), 0);
        drop(db);
        for after in [false, true] {
            for cut in 1..=barriers {
                let c = Case::with_pending(pending);
                let (expected, wire) = acknowledged(&c);
                let original = journal_rows(&c.paths.journal);
                let (db, remaining, count, _) = fault_database_path(&c.paths.journal, after);
                count.store(0, Ordering::SeqCst);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    DeviceJournal::erase_retired_journal_in_database(
                        &db,
                        &c.key(),
                        identity(&c),
                        c.retired,
                        &c.pin,
                        &expected,
                        &wire,
                    ),
                    after,
                );
                assert_eq!(count.load(Ordering::SeqCst), cut);
                drop(db);
                let mut owner = c.open().expect("metadata");
                let state = owner
                    .journal_erasure_status(&c.pin)
                    .expect("no partial logical inventory");
                if state == Retained {
                    assert_eq!(journal_rows(&c.paths.journal), original);
                }
                owner
                    .erase_journal(&c.pin, &wire)
                    .expect("same original decision");
                assert_eq!(
                    c.open()
                        .expect("metadata")
                        .journal_erasure_status(&c.pin)
                        .expect("terminal"),
                    Erased
                );
            }
        }
        eprintln!(
            "RETIRED_JOURNAL_ERASURE_SYNC pending={pending} barriers={barriers} before_after_faults={} readonly_retry=true",
            barriers * 2
        );
    }
}

#[test]
fn journal_erasure_process_loss_before_and_after_commit_reconciles_same_decision() {
    for stage in ["before-commit", "after-commit"] {
        let c = Case::with_pending(true);
        let (expected, wire) = acknowledged(&c);
        let original = journal_rows(&c.paths.journal);
        let root = c._directory.path().canonicalize().expect("root");
        fs::write(root.join("erasure-ack.bin"), &wire).expect("original ACK");
        c.store.lock().expect("witness").close();
        let log = fs::File::create_new(root.join("erasure-child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "installation::retired::tests::retired_installation_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_RETIRED_INSTALLATION_CHILD", &root)
                .env("QPERIAPT_RETIRED_ERASURE_CHILD", &root)
                .env("QPERIAPT_RETIRED_ERASURE_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("erasure-ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "erasure child deadline; see {}",
                root.join("erasure-child.log").display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("returned-erasure").exists());
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let mut owner = c.open().expect("metadata");
        assert_eq!(
            owner.journal_erasure_status(&c.pin).expect("atomic state"),
            if stage == "after-commit" {
                Erased
            } else {
                Retained
            }
        );
        if stage == "before-commit" {
            assert_eq!(journal_rows(&c.paths.journal), original);
        }
        assert_eq!(
            owner
                .host_acknowledgement_proposal()
                .expect("original intent"),
            Some(expected)
        );
        owner
            .erase_journal(&c.pin, &wire)
            .expect("same original decision");
    }
    eprintln!(
        "RETIRED_JOURNAL_ERASURE_PROCESS before_commit=true after_commit=true no_early_success=true original_intent=true"
    );
}
