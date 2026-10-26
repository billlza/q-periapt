// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual original client inventory, report and explicitly accounted logical erasure.
use super::*;
use crate::retired_device::{Intent, JournalErasureState, RecordMetadata, Transaction, ViewRole};
use std::io::Write;
use AnchorTransferredCleanupStage::{Acknowledged, Inventory, Report};
#[path = "client_cleanup/faults.rs"]
mod faults;
#[path = "client_cleanup/process.rs"]
mod process;
#[path = "client_cleanup/sync.rs"]
mod sync;

pub(super) struct Flow {
    pub(super) t: Transferred,
    pub(super) plan: TransferredAccountRootJournalPlan,
    pub(super) decision: AnchorTransferredAccountDecision,
    pub(super) context: TransferredRetirementContext,
    pub(super) cleanup_time: u64,
}
impl Flow {
    fn new(stage: Option<u8>, selection: u8) -> Self {
        let mut t = Transferred::at(stage, selection);
        let plan = t.plan();
        let mut parent = t.open().expect("original parent and child fences");
        let decision = t.decide(false);
        parent
            .retain_account_decision(decision.as_bytes())
            .expect("original committed retirement in both stores");
        parent.close();
        Self::committed(t, plan, decision)
    }
    pub(super) fn committed(
        t: Transferred,
        plan: TransferredAccountRootJournalPlan,
        decision: AnchorTransferredAccountDecision,
    ) -> Self {
        let context = TransferredRetirementContext::new(
            plan.clone(),
            decision.as_bytes(),
            t.f.original.genesis.subject(),
            t.history.clone(),
        )
        .expect("independent original context");
        Self {
            t,
            plan,
            decision,
            context,
            cleanup_time: 185,
        }
    }
    fn open(&self) -> RetiredInstallationRecovery {
        RetiredInstallationRecovery::open_transferred(
            self.t.f.original.paths.installation.clone(),
            JournalKey::open(&self.t.f.original.paths.wrapping).expect("original key"),
            self.context.clone(),
        )
        .expect("same restricted installation")
    }
    pub(super) fn approval(
        &self,
        inventory: &AnchorRetiredCleanupProposal,
        report: Option<&AnchorRetiredReportProposal>,
        previous: Option<&AnchorTransferredCleanupReceipt>,
        stage: AnchorTransferredCleanupStage,
        operator: u8,
    ) -> AnchorTransferredCleanupApproval {
        AnchorTransferredCleanupApproval::from_trusted_state(
            &self.context.materials(inventory, report, previous),
            stage,
            Validity::new(180, 220).expect("approved interval"),
            [operator; 32],
        )
        .expect("independently approved exact stage")
    }
    pub(super) fn retain(
        &mut self,
        owner: &mut RetiredInstallationRecovery,
        approval: &AnchorTransferredCleanupApproval,
    ) -> AnchorTransferredCleanupReceipt {
        assert_eq!(
            owner
                .prepare_transferred_stage(approval)
                .expect("durable expectation before dispatch"),
            approval.to_bytes()
        );
        assert_eq!(
            owner
                .transferred_stage_approval(approval.stage())
                .expect("original expectation"),
            *approval
        );
        self.t
            .target
            .retain_transferred_cleanup(approval, || {
                Ok(
                    if self.context.history().checkpoint() == self.plan.history().checkpoint() {
                        self.cleanup_time
                    } else {
                        198
                    },
                )
            })
            .expect("actual independent Witness commit")
    }
    pub(super) fn report(
        &mut self,
        owner: &mut RetiredInstallationRecovery,
    ) -> (
        crate::retired_device::Report,
        AnchorRetiredReport,
        AnchorTransferredCleanupReceipt,
    ) {
        let inventory = owner.proposal().expect("complete original inventory");
        let approval = self.approval(&inventory, None, None, Inventory, 221);
        let first = self.retain(owner, &approval);
        self.report_after_inventory(owner, &first)
    }
    pub(super) fn report_after_inventory(
        &mut self,
        owner: &mut RetiredInstallationRecovery,
        first: &AnchorTransferredCleanupReceipt,
    ) -> (
        crate::retired_device::Report,
        AnchorRetiredReport,
        AnchorTransferredCleanupReceipt,
    ) {
        let pin = self.context.accounting_pin().clone();
        let retained = owner
            .verify_retained(&pin, first.as_bytes())
            .expect("exact original inventory receipt");
        let expected = owner
            .prepare_report(&retained)
            .expect("complete report generated from originals");
        let approval = self.approval(
            retained.proposal(),
            Some(&expected),
            Some(first),
            Report,
            222,
        );
        let second = self.retain(owner, &approval);
        let report = owner
            .report(&retained, &pin, second.as_bytes())
            .expect("complete authenticated metadata");
        let verified = owner
            .verify_report_retention(&retained, &pin, second.as_bytes())
            .expect("independent exact report retention");
        assert_eq!(report.intent(), &self.t.expected_intent);
        assert_eq!(report.proposal(), &expected);
        assert_eq!(verified.proposal(), &expected);
        (report, verified, second)
    }
    pub(super) fn account(
        &mut self,
        owner: &mut RetiredInstallationRecovery,
        report: &crate::retired_device::Report,
        verified: &AnchorRetiredReport,
        previous: &AnchorTransferredCleanupReceipt,
    ) -> AnchorTransferredCleanupReceipt {
        let root = self
            .t
            .f
            .original
            .paths
            .configuration
            .parent()
            .expect("owned root");
        let record = root.join("host-retirement-report");
        let mut host = fs::File::create_new(&record).expect("deduplicated host record");
        host.write_all(report.as_bytes())
            .expect("complete report record");
        host.sync_all().expect("host durable record");
        fs::File::open(root)
            .expect("host directory")
            .sync_all()
            .expect("host name durable");
        let saved = fs::read(record).expect("host reads its actual record");
        let expected = owner
            .prepare_host_acknowledgement(&saved, verified)
            .expect("explicit complete host accounting");
        let approval = self.approval(
            expected.inventory(),
            Some(&expected),
            Some(previous),
            Acknowledged,
            223,
        );
        self.retain(owner, &approval)
    }
}

#[test]
fn transferred_client_cleanup_actual_report_preserves_pending_and_selection_until_exact_ack() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for selection in 0..=2 {
            let mut flow = Flow::new(stage, selection);
            let original = journal_rows(&flow.t);
            let parent = original_parent(&flow.t);
            let signer = fs::read(&flow.t.f.original.paths.signer).expect("original signer bytes");
            let mut owner = flow.open();
            let (report, verified, second) = flow.report(&mut owner);
            assert!(report
                .views()
                .iter()
                .all(|view| view.local_account == flow.t.f.original.device.account_id()));
            assert!(report.views().iter().all(|view|view.records.iter().any(|entry|matches!(entry.metadata,RecordMetadata::Prekey{request,..} if request==PrekeyId::from_trusted_state([199;32]).expect("original prekey ID")))));
            let roles = report
                .views()
                .iter()
                .map(|view| view.role)
                .collect::<Vec<_>>();
            assert_eq!(
                roles,
                if stage == Some(0) {
                    vec![ViewRole::Authoritative, ViewRole::UncommittedTarget]
                } else if stage == Some(1) {
                    vec![ViewRole::SupersededSource, ViewRole::Authoritative]
                } else {
                    vec![ViewRole::Authoritative]
                }
            );
            assert!(
                matches!(
                    (stage, report.intent()),
                    (None, Intent::None)
                        | (
                            Some(_),
                            Intent::Write {
                                transaction: Transaction::Policy { .. },
                                ..
                            }
                        )
                ),
                "original P identity or absent state was lost"
            );
            assert!(
                journal_rows(&flow.t) == original,
                "report rewrote original pending or selection"
            );
            let ack = flow.account(&mut owner, &report, &verified, &second);
            let pin = flow.context.accounting_pin().clone();
            assert_eq!(
                owner
                    .journal_erasure_status(&pin)
                    .expect("unmodified original inventory"),
                JournalErasureState::Retained
            );
            owner
                .erase_journal(&pin, ack.as_bytes())
                .expect("exact authorized atomic logical erasure");
            let mut reopened = flow.open();
            assert_eq!(
                reopened
                    .journal_erasure_status(&pin)
                    .expect("cold terminal verification"),
                JournalErasureState::Erased
            );
            assert_eq!(
                reopened
                    .transferred_stage_receipt(Acknowledged)
                    .expect("exact retained ACK"),
                ack
            );
            reopened
                .erase_journal(&pin, ack.as_bytes())
                .expect("read-only exact erasure retry");
            let rows = journal_rows(&flow.t);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows.first().expect("terminal").0, "retired");
            assert!(
                original_parent(&flow.t) == parent,
                "installation cleanup changed parent"
            );
            assert!(
                fs::read(&flow.t.f.original.paths.signer)
                    .expect("signer remains for later explicit parent transaction")
                    == signer
            );
            assert!(
                RetiredInstallationRecovery::open(
                    flow.t.f.original.paths.installation.clone(),
                    JournalKey::open(&flow.t.f.original.paths.wrapping).expect("key"),
                    flow.context.retired_subject()
                )
                .is_err(),
                "legacy entry lost transferred context"
            );
        }
    }
}

#[test]
fn transferred_client_cleanup_never_replaces_prepared_approval_after_unknown_commit() {
    let mut flow = Flow::new(Some(2), 2);
    let mut owner = flow.open();
    let inventory = owner.proposal().expect("actual inventory");
    let first = flow.approval(&inventory, None, None, Inventory, 221);
    let receipt = flow.retain(&mut owner, &first);
    owner.close();
    let mut owner = flow.open();
    assert_eq!(
        owner
            .transferred_stage_approval(Inventory)
            .expect("before reply"),
        first
    );
    let other = flow.approval(&inventory, None, None, Inventory, 229);
    assert!(
        owner.prepare_transferred_stage(&other).is_err(),
        "unknown commit must not authorize a new decision"
    );
    let mut owner = flow.open();
    assert_eq!(
        owner
            .prepare_transferred_stage(&first)
            .expect("exact prepared retry"),
        first.to_bytes()
    );
    let mut corrupt = receipt.as_bytes().to_vec();
    *corrupt.last_mut().expect("signature") ^= 1;
    assert!(owner
        .verify_retained(flow.context.accounting_pin(), &corrupt)
        .is_err());
    let mut owner = flow.open();
    owner
        .verify_retained(flow.context.accounting_pin(), receipt.as_bytes())
        .expect("original response still recoverable");
    assert_eq!(
        owner
            .transferred_stage_receipt(Inventory)
            .expect("exact signature"),
        receipt
    );
}

#[test]
fn transferred_client_cleanup_continues_original_inventory_after_independent_history_extension() {
    let mut flow = Flow::new(Some(1), 2);
    let mut owner = flow.open();
    let inventory = owner.proposal().expect("actual inventory");
    let first = flow.approval(&inventory, None, None, Inventory, 221);
    let receipt = flow.retain(&mut owner, &first);
    owner.close();
    let old_context = flow.context.clone();
    super::cleanup::handoff(&mut flow.t);
    flow.context = TransferredRetirementContext::new(
        flow.plan.clone(),
        flow.decision.as_bytes(),
        flow.t.f.original.genesis.subject(),
        flow.t.history.clone(),
    )
    .expect("independent A-B-C history; same original retirement");
    assert_ne!(
        flow.context.accounting_pin().binding(),
        old_context.accounting_pin().binding()
    );
    let mut owner = flow.open();
    assert_eq!(
        owner
            .transferred_stage_approval(Inventory)
            .expect("B request survives"),
        first
    );
    let (report, verified, second) = flow.report_after_inventory(&mut owner, &receipt);
    let ack = flow.account(&mut owner, &report, &verified, &second);
    owner
        .erase_journal(flow.context.accounting_pin(), ack.as_bytes())
        .expect("C ACK closes original A journal after B account retirement");
    assert_eq!(
        flow.open()
            .journal_erasure_status(flow.context.accounting_pin())
            .expect("exact C acknowledgement cold verification"),
        JournalErasureState::Erased
    );
    let mut stale = RetiredInstallationRecovery::open_transferred(
        flow.t.f.original.paths.installation.clone(),
        JournalKey::open(&flow.t.f.original.paths.wrapping).expect("key"),
        old_context,
    );
    assert!(
        stale.is_err(),
        "old independently retained history cannot authenticate later signer"
    );
    if let Ok(owner) = stale.as_mut() {
        owner.close();
    }
}
