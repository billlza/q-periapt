// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{assert_sync_failure, fault_database_path};
use std::sync::atomic::Ordering;

enum Action {
    Approve(AnchorTransferredCleanupApproval),
    Inventory(Vec<u8>),
    PrepareReport(AnchorRetiredCleanup),
    Report(AnchorRetiredCleanup, Vec<u8>),
    Account(Vec<u8>, AnchorRetiredReport),
    Ack(Vec<u8>),
}
impl Action {
    fn apply(
        &self,
        owner: &mut RetiredInstallationRecovery,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        match self {
            Self::Approve(a) => owner.prepare_transferred_stage(a).map(|_| ()),
            Self::Inventory(w) => owner.verify_retained(pin, w).map(|_| ()),
            Self::PrepareReport(r) => owner.prepare_report(r).map(|_| ()),
            Self::Report(r, w) => owner.verify_report_retention(r, pin, w).map(|_| ()),
            Self::Account(w, r) => owner.prepare_host_acknowledgement(w, r).map(|_| ()),
            Self::Ack(w) => owner.verify_host_acknowledgement(pin, w).map(|_| ()),
        }
    }
}
fn config(flow: &Flow) -> &Path {
    flow.t.f.original.paths.installation.files()[0]
}
fn rows(flow: &Flow) -> Vec<(String, Vec<u8>)> {
    let db = open_private_database(config(flow)).expect("closed config");
    let tx = db.begin_read().expect("read");
    let table = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "continuity_installation_v1",
        ))
        .expect("config table");
    table
        .iter()
        .expect("all rows")
        .map(|v| {
            let (k, v) = v.expect("row");
            (k.value().to_owned(), v.value().to_vec())
        })
        .collect()
}
struct Step {
    name: &'static str,
    before: Vec<u8>,
    before_rows: Vec<(String, Vec<u8>)>,
    after_rows: Vec<(String, Vec<u8>)>,
    action: Action,
}
fn step(flow: &Flow, steps: &mut Vec<Step>, name: &'static str, action: Action) {
    let before = fs::read(config(flow)).expect("exact existing config");
    let before_rows = rows(flow);
    let mut owner = flow.open();
    action
        .apply(&mut owner, flow.context.accounting_pin())
        .expect("baseline action");
    owner.close();
    steps.push(Step {
        name,
        before,
        before_rows,
        after_rows: rows(flow),
        action,
    });
}
fn sequence(flow: &mut Flow) -> Vec<Step> {
    let mut owner = flow.open();
    let inventory = owner.proposal().expect("original inventory");
    owner.close();
    let mut steps = Vec::new();
    let first = flow.approval(&inventory, None, None, Inventory, 221);
    step(
        flow,
        &mut steps,
        "inventory-approval",
        Action::Approve(first.clone()),
    );
    let first = flow
        .t
        .target
        .retain_transferred_cleanup(&first, || Ok(185))
        .expect("inventory server commit");
    step(
        flow,
        &mut steps,
        "inventory-receipt",
        Action::Inventory(first.as_bytes().to_vec()),
    );
    let mut owner = flow.open();
    let inventory = owner
        .verify_retained(flow.context.accounting_pin(), first.as_bytes())
        .expect("saved inventory proof");
    owner.close();
    step(
        flow,
        &mut steps,
        "report-request",
        Action::PrepareReport(inventory.clone()),
    );
    let mut owner = flow.open();
    let expected = owner
        .report_proposal()
        .expect("original report")
        .expect("present");
    owner.close();
    let second = flow.approval(
        inventory.proposal(),
        Some(&expected),
        Some(&first),
        Report,
        222,
    );
    step(
        flow,
        &mut steps,
        "report-approval",
        Action::Approve(second.clone()),
    );
    let second = flow
        .t
        .target
        .retain_transferred_cleanup(&second, || Ok(185))
        .expect("report server commit");
    step(
        flow,
        &mut steps,
        "report-receipt",
        Action::Report(inventory.clone(), second.as_bytes().to_vec()),
    );
    let mut owner = flow.open();
    let report = owner
        .report(&inventory, flow.context.accounting_pin(), second.as_bytes())
        .expect("actual complete report");
    let verified = owner
        .verify_report_retention(&inventory, flow.context.accounting_pin(), second.as_bytes())
        .expect("exact independent report");
    owner.close();
    let root = flow
        .t
        .f
        .original
        .paths
        .configuration
        .parent()
        .expect("owned host path");
    let mut host =
        fs::File::create_new(root.join("fault-host-record")).expect("independent host record");
    host.write_all(report.as_bytes()).expect("complete data");
    host.sync_all().expect("durable host record");
    fs::File::open(root)
        .expect("host directory")
        .sync_all()
        .expect("host name durable");
    step(
        flow,
        &mut steps,
        "host-accounted-intent",
        Action::Account(report.as_bytes().to_vec(), verified),
    );
    let ack = flow.approval(
        expected.inventory(),
        Some(&expected),
        Some(&second),
        Acknowledged,
        223,
    );
    step(
        flow,
        &mut steps,
        "ack-approval",
        Action::Approve(ack.clone()),
    );
    let ack = flow
        .t
        .target
        .retain_transferred_cleanup(&ack, || Ok(185))
        .expect("independent ACK");
    step(
        flow,
        &mut steps,
        "ack-receipt",
        Action::Ack(ack.as_bytes().to_vec()),
    );
    steps
}
fn open_fault(flow: &Flow, db: Database) -> RetiredInstallationRecovery {
    RetiredInstallationRecovery::open_transferred_database(
        db,
        flow.t.f.original.paths.installation.clone(),
        JournalKey::open(&flow.t.f.original.paths.wrapping).expect("original key"),
        flow.context.clone(),
    )
    .expect("same owner with injected config I/O")
}
#[test]
fn transferred_client_cleanup_every_measured_config_sync_retains_an_atomic_prefix() {
    let mut flow = Flow::new(Some(2), 2);
    let original = journal_rows(&flow.t);
    let parent = original_parent(&flow.t);
    let steps = sequence(&mut flow);
    assert_eq!(steps.len(), 8);
    for step in steps {
        fs::write(config(&flow), &step.before).expect("restore owned closed calibration state");
        let (db, _, count, _) = fault_database_path(config(&flow), false);
        let mut owner = open_fault(&flow, db);
        count.store(0, Ordering::SeqCst);
        step.action
            .apply(&mut owner, flow.context.accounting_pin())
            .expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        owner.close();
        assert_eq!(rows(&flow), step.after_rows);
        for after in [false, true] {
            for cut in 1..=barriers {
                fs::write(config(&flow), &step.before).expect("same owned original prefix");
                let (db, remaining, count, _) = fault_database_path(config(&flow), after);
                let mut owner = open_fault(&flow, db);
                count.store(0, Ordering::SeqCst);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    step.action.apply(&mut owner, flow.context.accounting_pin()),
                    after,
                );
                assert!(
                    matches!(owner.proposal(), Err(DurableError::Closed)),
                    "uncertain operation must close all capabilities"
                );
                remaining.store(0, Ordering::SeqCst);
                drop(owner);
                let observed = rows(&flow);
                assert!(
                    observed == step.before_rows || observed == step.after_rows,
                    "mixed config and authenticated control prefix"
                );
                let mut owner = flow.open();
                step.action
                    .apply(&mut owner, flow.context.accounting_pin())
                    .expect("reconcile exact original decision");
                owner.close();
                assert_eq!(rows(&flow), step.after_rows);
                assert!(journal_rows(&flow.t) == original);
                assert!(original_parent(&flow.t) == parent);
                eprintln!("TRANSFERRED_CLIENT_CONFIG_SYNC stage={} after={after} cut={cut} calibrated={barriers} original_journal=true exact_prefix=true",step.name);
            }
        }
        let (db, remaining, count, _) = fault_database_path(config(&flow), false);
        let mut owner = open_fault(&flow, db);
        count.store(0, Ordering::SeqCst);
        remaining.store(1, Ordering::SeqCst);
        step.action
            .apply(&mut owner, flow.context.accounting_pin())
            .expect("completed exact retry performs no write");
        assert_eq!(count.load(Ordering::SeqCst), 0);
        remaining.store(0, Ordering::SeqCst);
        owner.close();
    }
}
