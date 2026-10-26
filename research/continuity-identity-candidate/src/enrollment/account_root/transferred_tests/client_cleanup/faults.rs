// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{assert_sync_failure, fault_database_path};
use crate::retired_device::transferred::{authority::ReceiptAuthority, control::Control};
use std::sync::atomic::Ordering;

fn control_wire(flow: &Flow) -> Vec<u8> {
    let db = open_private_database(flow.t.f.original.paths.installation.files()[0])
        .expect("closed original config");
    let tx = db.begin_read().expect("read");
    let table = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "continuity_installation_v1",
        ))
        .expect("config");
    let row = table
        .get("retired-authority")
        .expect("read control")
        .expect("required control");
    row.value().to_vec()
}
fn replace_control(flow: &Flow, wire: Option<&[u8]>) {
    let db = open_private_database(flow.t.f.original.paths.installation.files()[0])
        .expect("owned config");
    let tx = transaction(&db).expect("owned corruption transaction");
    {
        let mut table = tx
            .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "continuity_installation_v1",
            ))
            .expect("config");
        if let Some(wire) = wire {
            table
                .insert("retired-authority", wire)
                .expect("replace owned row");
        } else {
            table.remove("retired-authority").expect("remove owned row");
        }
    }
    tx.commit().expect("injected damaged metadata");
}
fn open_result(flow: &Flow) -> Result<RetiredInstallationRecovery, DurableError> {
    RetiredInstallationRecovery::open_transferred(
        flow.t.f.original.paths.installation.clone(),
        JournalKey::open(&flow.t.f.original.paths.wrapping).expect("key"),
        flow.context.clone(),
    )
}

#[test]
fn transferred_client_cleanup_rejects_missing_mac_valid_stale_or_wrong_selection_control() {
    let mut flow = Flow::new(Some(2), 2);
    let mut owner = flow.open();
    let inventory = owner.proposal().expect("actual original");
    owner.close();
    let original = journal_rows(&flow.t);
    let good = control_wire(&flow);
    let mut corrupt = good.clone();
    *corrupt.last_mut().expect("MAC") ^= 1;
    replace_control(&flow, Some(&corrupt));
    assert!(open_result(&flow).is_err());
    replace_control(&flow, None);
    assert!(open_result(&flow).is_err());
    replace_control(&flow, Some(&good));
    let alternate = TransferredAccountRootJournalPlan::new(
        flow.plan.logical_pin().clone(),
        flow.plan.approval().clone(),
        flow.plan.history().clone(),
        None,
    )
    .expect("alternative independently supplied plan with missing selection");
    let context = TransferredRetirementContext::new(
        alternate,
        flow.decision.as_bytes(),
        flow.t.f.original.genesis.subject(),
        flow.t.history.clone(),
    )
    .expect("original root decision alone is insufficient");
    assert!(RetiredInstallationRecovery::open_transferred(
        flow.t.f.original.paths.installation.clone(),
        JournalKey::open(&flow.t.f.original.paths.wrapping).expect("key"),
        context
    )
    .is_err());
    let mut owner = flow.open();
    flow.report(&mut owner);
    owner.close();
    let complete = control_wire(&flow);
    let stale = Control::new(&flow.context, &inventory)
        .expect("valid early prefix")
        .encode(&JournalKey::open(&flow.t.f.original.paths.wrapping).expect("original key"))
        .expect("valid MAC from original key");
    replace_control(&flow, Some(&stale));
    assert!(open_result(&flow).is_err(),"authenticated control rollback cannot omit report approval while retaining report metadata");
    replace_control(&flow, Some(&complete));
    flow.open().close();
    assert!(journal_rows(&flow.t) == original);
}

#[test]
fn transferred_client_cleanup_every_journal_sync_cut_keeps_exact_inventory_or_verified_terminal() {
    let mut flow = Flow::new(Some(2), 2);
    let mut owner = flow.open();
    let (report, verified, previous) = flow.report(&mut owner);
    let ack = flow.account(&mut owner, &report, &verified, &previous);
    owner
        .verify_host_acknowledgement(flow.context.accounting_pin(), ack.as_bytes())
        .expect("independent exact ACK durably retained before erasure");
    owner.close();
    let key = JournalKey::open(&flow.t.f.original.paths.wrapping).expect("key");
    let expected = report.proposal();
    let control = Control::decode(
        &key,
        &flow.context,
        expected.inventory(),
        Some(expected),
        Some(expected),
        &control_wire(&flow),
    )
    .expect("authenticated independent local expectation");
    let path = flow.t.f.original.paths.installation.files()[1];
    let baseline = fs::read(path).expect("owned closed original journal");
    let id = JournalIdentity::from_trusted_state(expected.inventory().subject().journal_parts().0)
        .expect("original journal");
    let apply = |db: &Database| {
        DeviceJournal::erase_retired_journal_in_database(
            db,
            &key,
            id,
            flow.context.retired_subject(),
            ReceiptAuthority::Transferred(&flow.context, &control),
            expected,
            ack.as_bytes(),
        )
    };
    let (db, _, count, _) = fault_database_path(path, false);
    apply(&db).expect("calibration");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    drop(db);
    for after in [false, true] {
        for cut in 1..=barriers {
            fs::write(path, &baseline).expect("same owned closed original");
            let (db, remaining, count, _) = fault_database_path(path, after);
            count.store(0, Ordering::SeqCst);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(apply(&db), after);
            assert_eq!(count.load(Ordering::SeqCst), cut);
            remaining.store(0, Ordering::SeqCst);
            drop(db);
            let mut owner = flow.open();
            let observed = owner
                .journal_erasure_status(flow.context.accounting_pin())
                .expect("exact authenticated original or terminal");
            assert!(matches!(
                observed,
                JournalErasureState::Retained | JournalErasureState::Erased
            ));
            owner
                .erase_journal(flow.context.accounting_pin(), ack.as_bytes())
                .expect("same ACK reconciles unknown commit");
            assert_eq!(
                flow.open()
                    .journal_erasure_status(flow.context.accounting_pin())
                    .expect("exact terminal"),
                JournalErasureState::Erased
            );
            eprintln!("TRANSFERRED_CLIENT_ERASURE_SYNC after={after} cut={cut} calibrated={barriers} exact_original_or_terminal=true");
        }
    }
}

#[test]
fn transferred_client_cleanup_rejects_report_as_ack_and_missing_local_approval() {
    let mut flow = Flow::new(Some(0), 1);
    let mut owner = flow.open();
    let inventory = owner.proposal().expect("actual inventory");
    let approval = flow.approval(&inventory, None, None, Inventory, 221);
    let receipt = flow
        .t
        .target
        .retain_transferred_cleanup(&approval, || Ok(185))
        .expect("independent server commit");
    assert!(
        owner
            .verify_retained(flow.context.accounting_pin(), receipt.as_bytes())
            .is_err(),
        "reply cannot choose client approval"
    );
    let mut owner = flow.open();
    owner
        .prepare_transferred_stage(&approval)
        .expect("explicit original independent approval");
    let (report, verified, second) = flow.report_after_inventory(&mut owner, &receipt);
    let ack = flow.account(&mut owner, &report, &verified, &second);
    let original = journal_rows(&flow.t);
    assert!(
        owner
            .erase_journal(flow.context.accounting_pin(), second.as_bytes())
            .is_err(),
        "Report must never substitute for ACK"
    );
    assert!(journal_rows(&flow.t) == original);
    flow.open()
        .erase_journal(flow.context.accounting_pin(), ack.as_bytes())
        .expect("same exact approved ACK remains usable");
}
