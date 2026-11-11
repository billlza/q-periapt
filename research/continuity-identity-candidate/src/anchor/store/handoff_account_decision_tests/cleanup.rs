// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server accounting transaction tests; client inventory/report construction is separate.
use super::*;
use std::sync::Arc;
use AnchorTransferredCleanupStage::{Acknowledged, Inventory, Report};
#[path = "cleanup_process.rs"]
mod process;
pub(super) use process::execute_child;

struct Case {
    c: RetirementCase,
    n: Next,
    root: Approval,
    decision: AnchorTransferredAccountDecision,
    inventory: AnchorRetiredCleanupProposal,
    approvals: Vec<AnchorTransferredCleanupApproval>,
    receipts: Vec<AnchorTransferredCleanupReceipt>,
}
impl Case {
    fn new(stage: usize) -> Self {
        let mut c = RetirementCase::new(None, false);
        let n = next(&c, 231);
        let root = approve(&mut c, &n, 234);
        let decision = c
            .active
            .replace_transferred_account_root(&root, &materials(&c.root, &n, &c.history), || {
                Ok(185)
            })
            .expect("actual account retirement");
        let retired = decision
            .retirement()
            .expect("Committed")
            .retired_subject(c.c.subject)
            .expect("original subject");
        let inventory = AnchorRetiredCleanupProposal::from_journal(
            retired,
            retired.observed_head().digest(),
            None,
        )
        .expect("exact independent inventory expectation");
        let mut value = Self {
            c,
            n,
            root,
            decision,
            inventory,
            approvals: Vec::new(),
            receipts: Vec::new(),
        };
        for i in 0..=stage {
            let a = value.approval(i);
            if i < stage {
                value.receipts.push(
                    value
                        .c
                        .active
                        .retain_transferred_cleanup(&a, || Ok(186))
                        .expect("prior stage"),
                );
            }
            value.approvals.push(a);
        }
        value
    }
    fn approval(&self, index: usize) -> AnchorTransferredCleanupApproval {
        let report = AnchorRetiredReportProposal::from_report(self.inventory.clone(), [237; 32])
            .expect("host report ID expectation");
        AnchorTransferredCleanupApproval::from_trusted_state(
            &AnchorTransferredCleanupMaterials {
                history: &self.c.history,
                replacement: &self.root,
                decision: self.decision.as_bytes(),
                inventory: &self.inventory,
                report: if index == 0 { None } else { Some(&report) },
                previous: self.receipts.last(),
            },
            [Inventory, Report, Acknowledged]
                .get(index)
                .copied()
                .expect("stage"),
            Validity::new(185, 200).expect("approved interval"),
            [240 + u8::try_from(index).expect("stage"); 32],
        )
        .expect("independent stage approval")
    }
    fn fault(
        &mut self,
        after: bool,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.c.active.close();
        let (db, remaining, count, _) = fault_database_path(&self.c.f.db_path(), after);
        self.c.active =
            AnchorHandoffTarget::from_database(db, self.c.f.key(), self.c.f.approval.clone())
                .expect("same fault-backed import")
                .activate(&self.c.retired, self.c.f.signer())
                .expect("same activation")
                .0;
        count.store(0, Ordering::SeqCst);
        (remaining, count)
    }
}

#[test]
fn transferred_cleanup_all_sync_faults_close_owner_and_recover_exact_stage() {
    for stage in 0..3 {
        let mut f = Case::new(stage);
        f.c.active.close();
        let baseline = fs::read(f.c.f.db_path()).expect("same pre-stage image");
        let (remaining, count) = f.fault(false);
        remaining.store(usize::MAX, Ordering::SeqCst);
        f.c.active
            .retain_transferred_cleanup(f.approvals.get(stage).expect("approved stage"), || Ok(186))
            .expect("calibration");
        let barriers = count.load(Ordering::SeqCst);
        assert!((2..=8).contains(&barriers));
        f.c.active.close();
        let closing = count.load(Ordering::SeqCst) - barriers;
        for after in [false, true] {
            for cut in 1..=barriers {
                fs::write(f.c.f.db_path(), &baseline).expect("restore same owned pre-stage image");
                let (remaining, _) = f.fault(after);
                remaining.store(cut, Ordering::SeqCst);
                crate::durable::tests::assert_sync_failure(
                    f.c.active.retain_transferred_cleanup(
                        f.approvals.get(stage).expect("approved stage"),
                        || Ok(186),
                    ),
                    after,
                );
                assert!(matches!(f.c.active.pin(), Err(DurableError::Closed)));
                f.c.reopen();
                let observed =
                    match f.c.active.transferred_cleanup_receipt(
                        f.approvals.get(stage).expect("approved stage"),
                    ) {
                        Err(DurableError::Absent) => None,
                        other => Some(other.expect("only exact authenticated proof or absence")),
                    };
                let receipt =
                    f.c.active
                        .retain_transferred_cleanup(
                            f.approvals.get(stage).expect("approved stage"),
                            || Ok(186),
                        )
                        .expect("same stage retry");
                if let Some(old) = observed {
                    assert_eq!(receipt, old, "committed signature never replaced");
                }
                f.c.reopen();
                assert_eq!(
                    f.c.active
                        .transferred_cleanup_receipt(
                            f.approvals.get(stage).expect("approved stage")
                        )
                        .expect("cold exact proof"),
                    receipt
                );
                for (a, r) in f.approvals.iter().zip(&f.receipts) {
                    assert_eq!(
                        f.c.active
                            .transferred_cleanup_receipt(a)
                            .expect("prior stage preserved"),
                        *r
                    );
                }
                f.c.active.close();
                eprintln!("TRANSFERRED_CLEANUP_SYNC stage={stage} after={after} cut={cut} barriers={barriers} close_syncs={closing} exact_original=true");
            }
        }
    }
}

#[test]
fn transferred_cleanup_preserves_completion_capacity_and_rejects_authenticated_phase_damage() {
    let mut f = Case::new(0);
    let mut budget = None;
    for stage in 0..3 {
        if stage > 0 {
            f.approvals.push(f.approval(stage));
        }
        let receipt = f
            .c
            .active
            .retain_transferred_cleanup(f.approvals.get(stage).expect("approved stage"), || Ok(186))
            .expect("next stage");
        f.receipts.push(receipt);
        let image = f.c.active.image().expect("complete authenticated image");
        let body =
            image_codec::encode_content(&f.c.history, &image).expect("complete canonical image");
        let reserve = image
            .retired_transfer_reserve()
            .expect("remaining reserved capacity");
        let full = body.len() + reserve;
        if let Some(before) = budget {
            assert_eq!(
                full, before,
                "later receipt and report fit the original reservation"
            );
        } else {
            budget = Some(full);
        }
        assert_eq!(reserve == 0, stage == 2);
        let wire = f.receipts.get(stage).expect("retained stage").as_bytes();
        let at = body
            .windows(wire.len())
            .position(|v| v == wire)
            .expect("original signed bytes retained");
        let mut bad = body.clone();
        *bad.get_mut(at + wire.len() - 1).expect("signature byte") ^= 1;
        assert!(
            image_codec::decode_content(&f.c.history, &bad).is_err(),
            "valid enclosing MAC cannot replace signature verification"
        );
    }
    for damage in 0..3 {
        let mut image = f.c.active.image().expect("same image");
        let before =
            f.c.active
                .handoff_source_state()
                .expect("exact current bytes")
                .as_bytes()
                .to_vec();
        let id = f.inventory.subject().id(&image.namespace);
        match damage {
            0 => {
                image.retired_transfers.clear();
            }
            1 => {
                image
                    .retired_reports
                    .get_mut(&id)
                    .expect("report")
                    .acknowledged = false;
            }
            _ => {
                image.retired_reports.get_mut(&id).expect("report").proposal =
                    AnchorRetiredReportProposal::from_report(f.inventory.clone(), [239; 32])
                        .expect("competing report");
            }
        }
        assert!(f.c.active.persist(&mut image).is_err());
        f.c.reopen();
        assert_eq!(
            f.c.active
                .handoff_source_state()
                .expect("original survived refusal")
                .as_bytes(),
            before
        );
    }
    let report = AnchorRetiredReportProposal::from_report(f.inventory.clone(), [237; 32])
        .expect("same report");
    assert!(matches!(
        f.c.active.retired_cleanup_receipt(&f.inventory),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        f.c.active.retired_report_receipt(&report),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        f.c.active.retired_report_acknowledgement_receipt(&report),
        Err(DurableError::Suspended)
    ));
}

#[test]
fn transferred_cleanup_checks_commit_time_and_rejects_skipped_stages() {
    for stage in 0..3 {
        let mut f = Case::new(stage);
        let mut time = [186, 200].into_iter();
        assert!(f
            .c
            .active
            .retain_transferred_cleanup(f.approvals.get(stage).expect("approved stage"), || Ok(
                time.next().expect("two time checks")
            ))
            .is_err());
        f.c.reopen();
        assert!(matches!(
            f.c.active
                .transferred_cleanup_receipt(f.approvals.get(stage).expect("approved stage")),
            Err(DurableError::Absent)
        ));
        f.c.active
            .retain_transferred_cleanup(f.approvals.get(stage).expect("approved stage"), || Ok(186))
            .expect("exact retry after refused commit");
    }
    let f = Case::new(1);
    let report = AnchorRetiredReportProposal::from_report(f.inventory.clone(), [237; 32])
        .expect("same report");
    assert!(
        AnchorTransferredCleanupApproval::from_trusted_state(
            &AnchorTransferredCleanupMaterials {
                history: &f.c.history,
                replacement: &f.root,
                decision: f.decision.as_bytes(),
                inventory: &f.inventory,
                report: Some(&report),
                previous: f.receipts.first(),
            },
            Acknowledged,
            Validity::new(185, 200).expect("window"),
            [244; 32]
        )
        .is_err(),
        "inventory is not a report-retention proof"
    );
}
