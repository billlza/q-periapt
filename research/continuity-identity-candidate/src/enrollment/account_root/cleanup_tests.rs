// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    retired_device::JournalErasureState, DeviceJournal, RetiredDeviceEnrollment,
    SigningFileErasureState,
};
use std::io::Write;
#[path = "cleanup_tests/faults.rs"]
mod faults;
#[path = "cleanup_tests/process.rs"]
mod process;

fn reopen(f: &Fixture, retired: crate::AnchorRetiredSubject) -> RetiredDeviceEnrollment {
    RetiredDeviceEnrollment::open(
        f.original.paths.clone(),
        f.original.intent.clone(),
        f.pin.clone(),
        retired,
    )
    .expect("same original enrollment and retirement")
}
fn committed(f: &Fixture) -> (AccountRootEnrollmentRecovery, crate::AnchorRetiredSubject) {
    let proposal = f.proposal(231);
    let mut owner = f
        .activate()
        .begin_account_root_replacement(f.pin.clone(), proposal.clone())
        .expect("parent and child fence");
    let receipt = f.receipt(&proposal);
    owner
        .retain_witness_retirement(&receipt)
        .expect("retained permanent retirement");
    let retired = f
        .pin
        .verify_retired_account(&proposal, &receipt)
        .expect("purpose 22")
        .retired_subject(f.original.genesis.subject())
        .expect("original frozen subject");
    (owner, retired)
}
pub(super) fn account_report(
    f: &Fixture,
    owner: &mut RetiredDeviceEnrollment,
) -> (Vec<u8>, Vec<u8>) {
    let cleanup = owner.installation().expect("existing cleanup engine");
    let inventory = cleanup.proposal().expect("original inventory");
    let receipt = {
        let mut witness = f.witness.lock().expect("controller");
        witness
            .retain_retired_cleanup(&inventory)
            .expect("independent inventory");
        witness
            .retired_cleanup_receipt(&inventory)
            .expect("inventory signature")
    };
    let retained = cleanup
        .verify_retained(&f.pin, &receipt)
        .expect("inventory authority");
    let expected = cleanup.prepare_report(&retained).expect("complete report");
    let report_receipt = {
        let mut witness = f.witness.lock().expect("controller");
        witness
            .retain_retired_report(&expected)
            .expect("independent report");
        witness
            .retired_report_receipt(&expected)
            .expect("purpose 20")
    };
    let report = cleanup
        .report(&retained, &f.pin, &report_receipt)
        .expect("complete original metadata");
    assert!(report
        .views()
        .iter()
        .all(|view| view.local_account == f.original.device.account_id()));
    let parent = f
        .original
        .paths
        .wrapping
        .parent()
        .expect("original private directory");
    let mut record =
        fs::File::create_new(parent.join("host-retirement-report")).expect("new host record");
    record
        .write_all(report.as_bytes())
        .expect("complete report record");
    record.sync_all().expect("host record sync");
    fs::File::open(parent)
        .expect("host directory")
        .sync_all()
        .expect("host name sync");
    let verified = f
        .pin
        .verify_retired_report(&retained, &expected, &report_receipt)
        .expect("report retention");
    cleanup
        .prepare_host_acknowledgement(report.as_bytes(), &verified)
        .expect("explicit host accounting");
    let ack = {
        let mut witness = f.witness.lock().expect("controller");
        witness
            .acknowledge_retired_report(&expected)
            .expect("independent host ACK");
        witness
            .retired_report_acknowledgement_receipt(&expected)
            .expect("purpose 21")
    };
    (report_receipt, ack)
}

#[test]
fn account_root_cleanup_keeps_original_parent_and_requires_host_ack_before_both_erasures() {
    let f = fixture();
    let signer = fs::read(&f.original.paths.signer).expect("original encrypted signer");
    let (owner, retired) = committed(&f);
    let original_rows = parent_rows(
        &owner
            .active
            .as_ref()
            .expect("owner")
            .enrollment
            .active
            .as_ref()
            .expect("parent")
            .database,
    );
    assert_ne!(retired.replacement_binding(), [0; 32]);
    let mut cleanup = owner.into_retired().expect("same parent lease transferred");
    assert!(
        RetiredDeviceEnrollment::open(
            f.original.paths.clone(),
            f.original.intent.clone(),
            f.pin.clone(),
            retired
        )
        .is_err(),
        "original parent remains exclusively held"
    );
    cleanup.close();
    f.assert_fenced();
    let mut cleanup = reopen(&f, retired);
    let (report_receipt, ack) = account_report(&f, &mut cleanup);
    assert!(
        cleanup
            .installation()
            .expect("restricted child")
            .erase_journal(&f.pin, &report_receipt)
            .is_err(),
        "report retention must not impersonate host acknowledgement"
    );
    cleanup.close();
    let mut cleanup = reopen(&f, retired);
    assert_eq!(
        cleanup
            .installation()
            .expect("child")
            .journal_erasure_status(&f.pin)
            .expect("read original"),
        JournalErasureState::Retained
    );
    assert!(
        cleanup.prepare_signer_erasure(&ack).is_err(),
        "journal must be erased first"
    );
    let mut cleanup = reopen(&f, retired);
    cleanup
        .installation()
        .expect("child")
        .erase_journal(&f.pin, &ack)
        .expect("explicit journal erasure");
    assert_eq!(
        fs::read(&f.original.paths.signer).expect("original signer"),
        signer
    );
    cleanup.close();
    let mut cleanup = reopen(&f, retired);
    assert_eq!(
        cleanup
            .installation()
            .expect("child")
            .journal_erasure_status(&f.pin)
            .expect("authenticated terminal"),
        JournalErasureState::Erased
    );
    cleanup
        .prepare_signer_erasure(&ack)
        .expect("exact original signer plan");
    cleanup.close();
    let mut cleanup = reopen(&f, retired);
    assert_eq!(
        cleanup.signer_erasure_status().expect("same file"),
        SigningFileErasureState::Retained
    );
    cleanup.erase_signer().expect("logical signer erasure");
    let mut cleanup = reopen(&f, retired);
    assert_eq!(
        cleanup
            .signer_erasure_status()
            .expect("same authenticated terminal"),
        SigningFileErasureState::Erased
    );
    cleanup
        .erase_signer()
        .expect("idempotent original logical erasure");
    f.assert_fenced();
    let db = open_private_database(&f.original.paths.configuration).expect("old parent");
    assert_eq!(
        parent_rows(&db),
        original_rows,
        "original enrollment and root history remain unchanged"
    );
    let snapshot = read_snapshot(
        &db,
        &JournalKey::open(&f.original.paths.wrapping).expect("original key"),
        f.original
            .paths
            .binding(
                &JournalKey::open(&f.original.paths.wrapping).expect("key"),
                &f.original.intent,
            )
            .expect("binding"),
    )
    .expect("root and cleanup records coexist under exact scope");
    assert!(snapshot.retirement.is_some() && snapshot.root_replacement.is_some());
}

#[test]
fn account_root_cleanup_refuses_uncommitted_or_different_local_root_operation() {
    let f = fixture();
    let original = f.proposal(232);
    let owner = f
        .activate()
        .begin_account_root_replacement(f.pin.clone(), original.clone())
        .expect("local fence");
    assert!(matches!(owner.into_retired(), Err(DurableError::Suspended)));
    f.assert_fenced();
    let competing = f.proposal(233);
    let receipt = f.receipt(&competing);
    let retired = f
        .pin
        .verify_retired_account(&competing, &receipt)
        .expect("real different commitment")
        .retired_subject(f.original.genesis.subject())
        .expect("same original subject");
    assert!(RetiredDeviceEnrollment::open(
        f.original.paths.clone(),
        f.original.intent.clone(),
        f.pin.clone(),
        retired
    )
    .is_err());
    assert!(DeviceJournal::retired_cleanup_proposal(
        f.original.paths.installation.files()[1],
        JournalKey::open(&f.original.paths.wrapping).expect("key"),
        JournalIdentity::from_trusted_state(f.original.genesis.subject().journal_parts().0)
            .expect("original journal"),
        retired
    )
    .is_err());
    let proof = f
        .pin
        .verify_retired_account(&competing, &receipt)
        .expect("retirement");
    assert!(
        proof.retired_subject(competing.successor()).is_err(),
        "successor is not a retired subject"
    );
    let db = open_private_database(&f.original.paths.configuration).expect("parent");
    let tx = db.begin_read().expect("read");
    assert!(tx
        .open_table(TABLE)
        .expect("table")
        .get("retirement")
        .expect("read")
        .is_none());
}
