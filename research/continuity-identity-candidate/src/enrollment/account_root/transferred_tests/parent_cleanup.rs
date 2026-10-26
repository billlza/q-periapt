// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original parent and registry survive retirement without the old signer or journal.
use super::client_cleanup::Flow;
use super::*;
use crate::retired_device::JournalErasureState;
#[path = "parent_cleanup/faults.rs"]
mod faults;
#[path = "parent_cleanup/process.rs"]
mod process;

fn prepared(stage: Option<u8>, selection: u8) -> (Flow, AccountRootEnrollmentRecovery) {
    let mut t = Transferred::at(stage, selection);
    let plan = t.plan();
    let mut parent = t.open().expect("original root owner");
    let decision = t.decide(false);
    parent
        .retain_account_decision(decision.as_bytes())
        .expect("permanent exact original decision");
    (Flow::committed(t, plan, decision), parent)
}
fn reopen(flow: &Flow) -> RetiredDeviceEnrollment {
    RetiredDeviceEnrollment::open_transferred(
        flow.t.f.original.paths.clone(),
        flow.t.f.original.intent.clone(),
        flow.context.clone(),
    )
    .expect("same original parent without signer admission")
}
fn report_ack(flow: &mut Flow, owner: &mut RetiredDeviceEnrollment) -> Vec<u8> {
    let child = owner.installation().expect("same restricted installation");
    let (report, verified, previous) = flow.report(child);
    flow.account(child, &report, &verified, &previous)
        .as_bytes()
        .to_vec()
}
fn erase_journal(flow: &Flow, owner: &mut RetiredDeviceEnrollment, ack: &[u8]) {
    owner
        .installation()
        .expect("same child")
        .erase_journal(flow.context.accounting_pin(), ack)
        .expect("exact acknowledged logical journal erasure");
}
fn original_preparation(flow: &Flow) -> TransferredAccountRootPreparation {
    TransferredAccountRootPreparation::new(
        flow.t.preparation.clone(),
        flow.plan.logical_pin().clone(),
        flow.plan.history().clone(),
        flow.plan.selection().cloned(),
    )
    .expect("original operation context, not later accounting history")
}
fn resume_managed(flow: &Flow) -> Result<ManagedAccountRootReplacement, DurableError> {
    let original = flow
        .t
        .registry_recovery
        .as_ref()
        .expect("original registry metadata");
    ManagedAccountRootReplacement::resume_transferred_cleanup_original(
        original.open(&flow.t.f),
        original.expected,
        original_preparation(flow),
        flow.t.f.original.paths.clone(),
        flow.t.f.original.intent.clone(),
        flow.context.history().clone(),
    )
}
fn managed(stage: Option<u8>, selection: u8) -> Flow {
    let mut t = Transferred::with_controller(stage, selection);
    let plan = t.plan();
    let mut owner = t
        .controller
        .take()
        .expect("same original preparing controller");
    owner
        .bind_transferred_freeze(&t.frozen, t.approval.clone())
        .expect("full independent root freeze");
    let decision = t.decide(false);
    owner
        .retain_transferred_decision(decision.as_bytes())
        .expect("same parent/child/registry commitment");
    owner.close();
    Flow::committed(t, plan, decision)
}

#[test]
fn transferred_parent_cleanup_original_parent_keeps_lease_and_enters_retirement() {
    let (mut flow, parent) = prepared(Some(2), 2);
    let mut retired = parent
        .into_retired()
        .expect("original parent transfers lease into cleanup");
    assert!(
        RetiredDeviceEnrollment::open_transferred(
            flow.t.f.original.paths.clone(),
            flow.t.f.original.intent.clone(),
            flow.context.clone()
        )
        .is_err(),
        "parent remains exclusively leased"
    );
    report_ack(&mut flow, &mut retired);
    retired.close();
    reopen(&flow).close();
}

#[test]
fn transferred_parent_cleanup_exact_ack_erases_signer_and_cold_reopens_original_pending_context() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for selection in 0..=2 {
            let (mut flow, parent) = prepared(stage, selection);
            let original = parent_rows(
                &parent
                    .active
                    .as_ref()
                    .expect("root owner")
                    .enrollment
                    .active
                    .as_ref()
                    .expect("original lease")
                    .database,
            )
            .0;
            let key = fs::read(&flow.t.f.original.paths.wrapping).expect("same wrapping key");
            let mut retired = parent
                .into_retired()
                .expect("same restricted original parent");
            let ack = report_ack(&mut flow, &mut retired);
            assert!(
                retired.prepare_signer_erasure(&ack).is_err(),
                "journal must be logically retired before signer capture"
            );
            let mut retired = reopen(&flow);
            erase_journal(&flow, &mut retired, &ack);
            retired
                .prepare_signer_erasure(&ack)
                .expect("exact original signer plan and full ACK prefix");
            assert_eq!(
                retired
                    .signer_erasure_status()
                    .expect("original signer remains"),
                SigningFileErasureState::Retained
            );
            retired.close();
            let mut retired = reopen(&flow);
            retired
                .prepare_signer_erasure(&ack)
                .expect("exact read-only signer plan retry");
            retired
                .erase_signer()
                .expect("explicit original signer logical erasure");
            assert_eq!(
                fs::read(&flow.t.f.original.paths.signer).expect("nonempty original terminal"),
                b"QPSRET01"
            );
            let mut retired = reopen(&flow);
            assert_eq!(
                retired
                    .signer_erasure_status()
                    .expect("cold original terminal"),
                SigningFileErasureState::Erased
            );
            assert_eq!(
                retired
                    .installation()
                    .expect("same original metadata")
                    .journal_erasure_status(flow.context.accounting_pin())
                    .expect("exact journal terminal"),
                JournalErasureState::Erased
            );
            retired
                .erase_signer()
                .expect("idempotent same original terminal");
            assert!(original_parent(&flow.t) == original);
            assert!(fs::read(&flow.t.f.original.paths.wrapping).expect("same key") == key);
            assert!(
                RetiredDeviceEnrollment::open(
                    flow.t.f.original.paths.clone(),
                    flow.t.f.original.intent.clone(),
                    flow.plan.witness_pin().expect("root signer").clone(),
                    flow.context.retired_subject()
                )
                .is_err(),
                "legacy contextless opener cannot bypass transferred proof"
            );
        }
    }
}

#[test]
fn transferred_parent_cleanup_managed_cold_recovery_preserves_registry_and_successor() {
    let mut flow = managed(Some(2), 2);
    let mut owner = resume_managed(&flow).expect("same committed original operation");
    let ack = owner
        .with_retired_cleanup(|parent| {
            let ack = report_ack(&mut flow, parent);
            erase_journal(&flow, parent, &ack);
            parent.prepare_signer_erasure(&ack)?;
            parent.erase_signer()?;
            Ok(ack)
        })
        .expect("same controller returns after reopening its erased historical parent");
    owner
        .successor_authority()
        .expect("old cleanup must preserve successor mapping");
    owner.close();
    let mut owner = resume_managed(&flow).expect("cold controller without old journal or signer");
    owner
        .retain_transferred_decision(flow.decision.as_bytes())
        .expect("same original decision retry after cleanup");
    owner
        .with_retired_cleanup(|parent| {
            assert_eq!(
                parent.signer_erasure_status()?,
                SigningFileErasureState::Erased
            );
            parent.prepare_signer_erasure(&ack)?;
            Ok(())
        })
        .expect("same historical terminal");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let carrier = target_activation::CurrentCarrier {
        store: Arc::new(Mutex::new(flow.t.target)),
        clock: Arc::new(std::sync::atomic::AtomicU64::new(185)),
        calls: Arc::clone(&calls),
    };
    let target = DeviceEnrollment::open(
        flow.t.successor.paths.clone(),
        flow.t.successor.intent.clone(),
    )
    .expect("independently enrolled target");
    let mut live = owner
        .activate_successor(
            target,
            &flow.t.policy,
            185,
            Box::new(carrier),
            Duration::from_secs(3),
        )
        .expect("actual target after original signer erasure");
    let (service, _, device) = live.parts().expect("real controlled target");
    service
        .stores()
        .expect("target stores")
        .0
        .generate_prekey(
            &flow.t.policy,
            device,
            PrekeyId::from_trusted_state([234; 32]).expect("target ID"),
            LeafKind::OneTimePq,
            Validity::new(185, 199).expect("window"),
            185,
        )
        .expect("real successor cryptography after full cleanup");
    owner.close();
    assert!(
        service
            .stores()
            .expect("owned stores")
            .0
            .generate_prekey(
                &flow.t.policy,
                device,
                PrekeyId::from_trusted_state([235; 32]).expect("target ID"),
                LeafKind::OneTimePq,
                Validity::new(185, 199).expect("window"),
                185
            )
            .is_err(),
        "controller closure revokes delegated successor"
    );
    live.close();
}

#[test]
fn transferred_parent_cleanup_later_accounting_history_does_not_replace_original_root_context() {
    let mut flow = managed(Some(1), 2);
    let mut owner = resume_managed(&flow).expect("original managed root");
    let first = owner
        .with_retired_cleanup(|parent| {
            let child = parent.installation()?;
            let inventory = child.proposal()?;
            let a = flow.approval(
                &inventory,
                None,
                None,
                AnchorTransferredCleanupStage::Inventory,
                221,
            );
            Ok(flow.retain(child, &a))
        })
        .expect("B inventory approval and original parent capture");
    owner.close();
    super::cleanup::handoff(&mut flow.t);
    flow.context = TransferredRetirementContext::new(
        flow.plan.clone(),
        flow.decision.as_bytes(),
        flow.t.f.original.genesis.subject(),
        flow.t.history.clone(),
    )
    .expect("independent accounting C with original root B");
    let mut owner = resume_managed(&flow).expect("current accounting history explicitly supplied");
    owner
        .with_retired_cleanup(|parent| {
            let child = parent.installation()?;
            let (report, verified, previous) = flow.report_after_inventory(child, &first);
            let ack = flow.account(child, &report, &verified, &previous);
            child.erase_journal(flow.context.accounting_pin(), ack.as_bytes())?;
            parent.prepare_signer_erasure(ack.as_bytes())?;
            parent.erase_signer()
        })
        .expect("C ACK with original B account decision and A journal");
    owner.close();
    let original = flow
        .t
        .registry_recovery
        .as_ref()
        .expect("original registry");
    assert!(
        ManagedAccountRootReplacement::resume_transferred_original(
            original.open(&flow.t.f),
            original.expected,
            original_preparation(&flow),
            flow.t.f.original.paths.clone(),
            flow.t.f.original.intent.clone()
        )
        .is_err(),
        "old independent history cannot authenticate the C ACK"
    );
    let mut owner =
        resume_managed(&flow).expect("explicit C history restores same original operation");
    owner
        .with_retired_cleanup(|parent| {
            assert_eq!(
                parent.signer_erasure_status()?,
                SigningFileErasureState::Erased
            );
            Ok(())
        })
        .expect("original terminal without new operation");
    owner.close();
}
