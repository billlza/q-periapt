// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use AnchorTransferredCleanupStage::{Acknowledged, Inventory, Report};

fn inventory(
    t: &Transferred,
    decision: &AnchorTransferredAccountDecision,
) -> AnchorRetiredCleanupProposal {
    let retired = decision
        .retirement()
        .expect("committed root")
        .retired_subject(t.f.original.genesis.subject())
        .expect("original subject");
    AnchorRetiredCleanupProposal::from_journal(retired, retired.observed_head().digest(), None)
        .expect("independent exact inventory")
}
fn approval(
    t: &Transferred,
    decision: &AnchorTransferredAccountDecision,
    inventory: &AnchorRetiredCleanupProposal,
    stage: AnchorTransferredCleanupStage,
    previous: Option<&AnchorTransferredCleanupReceipt>,
) -> AnchorTransferredCleanupApproval {
    let report = AnchorRetiredReportProposal::from_report(inventory.clone(), [227; 32])
        .expect("independent host report identity");
    AnchorTransferredCleanupApproval::from_trusted_state(
        &AnchorTransferredCleanupMaterials {
            history: &t.history,
            replacement: &t.approval,
            decision: decision.as_bytes(),
            inventory,
            report: if stage == Inventory {
                None
            } else {
                Some(&report)
            },
            previous,
        },
        stage,
        Validity::new(180, 220).expect("operator interval"),
        [match stage {
            Inventory => 221,
            Report => 222,
            Acknowledged => 223,
        }; 32],
    )
    .expect("independent stage approval")
}
fn handoff(t: &mut Transferred) -> (PathBuf, PathBuf, AnchorHandoffTargetApproval) {
    let base = t.f._dir.path().canonicalize().expect("owned directory");
    let path = base.join("C-store");
    let key_path = base.join("C-key");
    let key = JournalKey::provision(&key_path).expect("independent C storage key");
    let signer = AnchorSigningKey::generate().expect("independent C signer");
    let pin = AnchorPin::new(
        AnchorIdentity::generate().expect("C identity"),
        signer.public_key().expect("C key"),
    );
    let source = t
        .target
        .handoff_source_state()
        .expect("complete B with cleanup proofs");
    let plan = AnchorHandoffPlan::from_trusted_state(
        [230; 32],
        &source,
        pin.clone(),
        Validity::new(190, 210).expect("C window"),
        [231; 32],
    )
    .expect("B approval");
    let approved = AnchorHandoffTargetApproval::from_trusted_state(
        &plan,
        t.history.current_pin(),
        &pin,
        Validity::new(190, 210).expect("C window"),
        [232; 32],
    )
    .expect("independent C approval");
    let frozen = t.target.freeze_handoff(&plan, 195).expect("B freeze");
    let mut imported = AnchorHandoffTarget::provision_import(
        &path,
        key,
        &signer,
        approved.clone(),
        source.as_bytes(),
        frozen.as_bytes(),
        195,
    )
    .expect("full C import");
    let ack = imported.import_receipt().expect("C import ACK");
    let retired = t
        .target
        .retire_handoff(&approved, ack.as_bytes(), || Ok(195))
        .expect("B retirement");
    t.history = imported
        .verify_source_retirement(retired.as_bytes())
        .expect("A-B-C history");
    t.target = imported
        .activate(retired.as_bytes(), signer)
        .expect("C activation")
        .0;
    (path, key_path, approved)
}

#[test]
fn transferred_cleanup_stages_retain_exact_signatures_across_another_handoff() {
    let mut t = Transferred::new();
    let original = journal_rows(&t);
    let decision = t.decide(false);
    let inventory = inventory(&t, &decision);
    let inventory_approval = approval(&t, &decision, &inventory, Inventory, None);
    let first = t
        .target
        .retain_transferred_cleanup(&inventory_approval, || Ok(185))
        .expect("inventory and original signature commit");
    assert_eq!(first.stage(), Inventory);
    let original_history = t.history.clone();
    let stale_report = approval(&t, &decision, &inventory, Report, Some(&first));
    let (path, key, approved) = handoff(&mut t);
    let time_calls = std::cell::Cell::new(0);
    assert!(t
        .target
        .retain_transferred_cleanup(&stale_report, || {
            time_calls.set(time_calls.get() + 1);
            Err(DurableError::Conflict)
        })
        .is_err());
    assert_eq!(
        time_calls.get(),
        0,
        "retired authority must reject before clock"
    );
    assert_eq!(
        t.target
            .retain_transferred_cleanup(&inventory_approval, || {
                time_calls.set(time_calls.get() + 1);
                Err(DurableError::Conflict)
            })
            .expect("exact prior inventory"),
        first
    );
    assert_eq!(
        time_calls.get(),
        0,
        "historical retry must not consult time"
    );
    let material = AnchorTransferredCleanupMaterials {
        history: &t.history,
        replacement: &t.approval,
        decision: decision.as_bytes(),
        inventory: &inventory,
        report: None,
        previous: None,
    };
    assert_eq!(
        AnchorTransferredCleanupApproval::restore_trusted_state(
            &inventory_approval.to_bytes(),
            &material
        )
        .expect("restore old B approval under A-B-C"),
        inventory_approval
    );
    let report_approval = approval(&t, &decision, &inventory, Report, Some(&first));
    let second = t
        .target
        .retain_transferred_cleanup(&report_approval, || Ok(196))
        .expect("C report retention");
    let ack_approval = approval(&t, &decision, &inventory, Acknowledged, Some(&second));
    assert!(matches!(
        t.target.transferred_cleanup_receipt(&ack_approval),
        Err(DurableError::Absent)
    ));
    let third = t
        .target
        .retain_transferred_cleanup(&ack_approval, || Ok(197))
        .expect("explicit host ACK after report");
    assert_eq!(third.stage(), Acknowledged);
    assert!(ack_approval
        .verify_receipt(&original_history, third.as_bytes())
        .is_err());
    assert!(ack_approval
        .verify_receipt(&t.history, second.as_bytes())
        .is_err());
    t.target.close();
    let mut observer =
        AnchorHandoffTarget::open(&path, JournalKey::open(&key).expect("same C key"), approved)
            .expect("public observation without private signer");
    for (a, r) in [
        (&inventory_approval, &first),
        (&report_approval, &second),
        (&ack_approval, &third),
    ] {
        assert_eq!(
            observer
                .transferred_cleanup_receipt(a)
                .expect("exact durable original proof"),
            *r
        );
    }
    assert!(
        journal_rows(&t) == original,
        "server accounting cannot alter original keys or pending state"
    );
}

#[test]
fn transferred_cleanup_rejects_closure_foreign_proofs_and_conflicting_stage() {
    let mut closed = Transferred::new();
    let closure = closed.decide(true);
    let mut t = Transferred::new();
    let decision = t.decide(false);
    let inventory = inventory(&t, &decision);
    let materials = |wire| AnchorTransferredCleanupMaterials {
        history: &t.history,
        replacement: &t.approval,
        decision: wire,
        inventory: &inventory,
        report: None,
        previous: None,
    };
    assert!(AnchorTransferredCleanupApproval::from_trusted_state(
        &materials(closure.as_bytes()),
        Inventory,
        Validity::new(180, 220).expect("window"),
        [221; 32]
    )
    .is_err());
    let mut damaged = decision.as_bytes().to_vec();
    *damaged.last_mut().expect("signature") ^= 1;
    assert!(AnchorTransferredCleanupApproval::from_trusted_state(
        &materials(&damaged),
        Inventory,
        Validity::new(180, 220).expect("window"),
        [221; 32]
    )
    .is_err());
    let a = approval(&t, &decision, &inventory, Inventory, None);
    let before = t
        .target
        .handoff_source_state()
        .expect("original state")
        .as_bytes()
        .to_vec();
    assert!(
        t.target.retain_transferred_cleanup(&a, || Ok(184)).is_err(),
        "account retirement happened at185"
    );
    assert!(t.target.retain_transferred_cleanup(&a, || Ok(221)).is_err());
    assert_eq!(
        t.target
            .handoff_source_state()
            .expect("unchanged expired approval")
            .as_bytes(),
        before
    );
    let first = t
        .target
        .retain_transferred_cleanup(&a, || Ok(185))
        .expect("original admitted inventory");
    assert!(
        matches!(
            t.target.retired_cleanup_receipt(&inventory),
            Err(DurableError::Suspended)
        ),
        "new stages never issue legacy receipts"
    );
    let mut damaged = first.as_bytes().to_vec();
    *damaged.last_mut().expect("signature") ^= 1;
    assert!(a.verify_receipt(&t.history, &damaged).is_err());
    let alternative = AnchorTransferredCleanupApproval::from_trusted_state(
        &materials(decision.as_bytes()),
        Inventory,
        Validity::new(180, 220).expect("window"),
        [224; 32],
    )
    .expect("another independent decision");
    let time_calls = std::cell::Cell::new(0);
    assert!(matches!(
        t.target.retain_transferred_cleanup(&alternative, || {
            time_calls.set(time_calls.get() + 1);
            Err(DurableError::Conflict)
        }),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        time_calls.get(),
        0,
        "different committed approval is conflict before time"
    );
    let report = approval(&t, &decision, &inventory, Report, Some(&first));
    assert!(t
        .target
        .retain_transferred_cleanup(&report, || Ok(184))
        .is_err());
    let second = t
        .target
        .retain_transferred_cleanup(&report, || Ok(186))
        .expect("exact report");
    assert_eq!(second.stage(), Report);
    assert_eq!(
        t.target
            .transferred_cleanup_receipt(&a)
            .expect("first retained after errors"),
        first
    );
}
