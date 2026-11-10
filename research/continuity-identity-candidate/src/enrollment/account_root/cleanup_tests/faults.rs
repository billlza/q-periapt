// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Every observed storage barrier, before and after actual synchronization.
use super::*;
use crate::durable::tests::{assert_sync_failure, fault_database_path};

fn parent_faults(f: &Fixture, retired: crate::AnchorRetiredSubject, ack: Option<&[u8]>) {
    let path = &f.original.paths.configuration;
    let baseline = fs::read(path).expect("quiescent owned parent fixture");
    let signer = fs::read(&f.original.paths.signer).expect("original encrypted signer");
    let open = |db| {
        RetiredDeviceEnrollment::open_in_database(
            f.original.paths.clone(),
            f.original.intent.clone(),
            f.pin.clone(),
            retired,
            db,
        )
    };
    let (db, _, count, _) = fault_database_path(path, false);
    count.store(0, Ordering::SeqCst);
    let mut owner = open(db).expect("calibrate original parent mutation");
    if let Some(ack) = ack {
        owner
            .prepare_signer_erasure(ack)
            .expect("calibrate exact file plan");
    }
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &baseline).expect("restore closed original test fixture");
            let (db, remaining, count, _) = fault_database_path(path, after);
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            let result = open(db);
            if let Some(ack) = ack {
                let mut owner = result.expect("already retained inventory");
                assert_sync_failure(owner.prepare_signer_erasure(ack), after);
                assert!(matches!(
                    owner.signer_erasure_status(),
                    Err(DurableError::Closed)
                ));
            } else {
                assert_sync_failure(result, after);
            }
            assert_eq!(count.load(Ordering::SeqCst), cut);
            assert_eq!(
                fs::read(&f.original.paths.signer).expect("signer unchanged"),
                signer
            );
            let mut recovered = reopen(f, retired);
            if let Some(ack) = ack {
                recovered
                    .prepare_signer_erasure(ack)
                    .expect("exact original plan recovery");
                assert_eq!(
                    recovered.signer_erasure_status().expect("retained signer"),
                    SigningFileErasureState::Retained
                );
            }
            recovered.close();
            f.assert_fenced();
        }
    }
}

#[test]
fn account_root_cleanup_each_parent_and_journal_sync_cut_recovers_original_identity() {
    let f = fixture();
    let (mut owner, retired) = committed(&f);
    owner.close();
    parent_faults(&f, retired, None);
    let mut cleanup = reopen(&f, retired);
    let (_, ack) = account_report(&f, &mut cleanup);
    let report = cleanup
        .installation()
        .expect("child")
        .report_proposal()
        .expect("saved report")
        .expect("exact report");
    cleanup.close();
    let path = f.original.paths.installation.files()[1];
    let baseline = fs::read(path).expect("closed original journal including root fence");
    let key = JournalKey::open(&f.original.paths.wrapping).expect("original key");
    let identity = JournalIdentity::from_trusted_state(retired.subject().journal_parts().0)
        .expect("original journal");
    let erase = |db: &Database| {
        DeviceJournal::erase_retired_journal_in_database(
            db,
            &key,
            identity,
            retired,
            crate::retired_device::transferred::authority::ReceiptAuthority::Legacy(&f.pin),
            &report,
            &ack,
        )
    };
    let (db, _, count, _) = fault_database_path(path, false);
    count.store(0, Ordering::SeqCst);
    erase(&db).expect("calibrate atomic root-fence and journal erasure");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    drop(db);
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &baseline).expect("restore closed owned journal fixture");
            let (db, remaining, count, _) = fault_database_path(path, after);
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(erase(&db), after);
            assert_eq!(count.load(Ordering::SeqCst), cut);
            drop(db);
            let mut recovered = reopen(&f, retired);
            recovered
                .installation()
                .expect("same child")
                .erase_journal(&f.pin, &ack)
                .expect("original acknowledged erasure recovery");
            recovered.close();
            f.assert_fenced();
        }
    }
    parent_faults(&f, retired, Some(&ack));
}
