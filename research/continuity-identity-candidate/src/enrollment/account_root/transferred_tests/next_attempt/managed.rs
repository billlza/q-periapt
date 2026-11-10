// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same registry controller carries exact next approvals through original storage.
use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize};
#[path = "managed/process.rs"]
mod process;
#[path = "managed/successive.rs"]
mod successive;
#[path = "managed/sync.rs"]
mod sync;

fn original(t: &Transferred) -> TransferredAccountRootPreparation {
    TransferredAccountRootPreparation::new(
        t.preparation.clone(),
        t.f.pin.clone(),
        t.history.clone(),
        t.selected.clone(),
    )
    .expect("independent original preparation")
}
fn fresh(s: &Scenario, next: &Next) -> TransferredAccountRootPreparation {
    TransferredAccountRootPreparation::new(
        next.plan.clone(),
        s.t.f.pin.clone(),
        s.t.history.clone(),
        s.t.selected.clone(),
    )
    .expect("independent next target")
}
fn context(
    s: &Scenario,
    next: &Next,
    previous: &TransferredAccountRootPreparation,
) -> TransferredAccountRootPreparation {
    fresh(s, next)
        .after_closed(
            previous,
            s.t.approval.clone(),
            next.approval.clone(),
            &s.t.frozen,
            &s.closed,
        )
        .expect("exact old closure and both full approvals")
}
fn begin(
    s: &mut Scenario,
    plan: &TransferredAccountRootPreparation,
) -> Result<ManagedAccountRootReplacement, DurableError> {
    s.registry.close();
    ManagedAccountRootReplacement::begin_transferred(
        s.recovery.open(&s.t.f),
        s.recovery.expected,
        plan.clone(),
        s.t.f.original.paths.clone(),
        s.t.f.original.intent.clone(),
    )
}
fn resume(
    s: &Scenario,
    plan: &TransferredAccountRootPreparation,
) -> Result<ManagedAccountRootReplacement, DurableError> {
    ManagedAccountRootReplacement::resume_transferred_original(
        s.recovery.open(&s.t.f),
        s.recovery.expected,
        plan.clone(),
        s.t.f.original.paths.clone(),
        s.t.f.original.intent.clone(),
    )
}

type Rows = Vec<(String, Vec<u8>)>;
fn retained(paths: &EnrollmentPaths) -> (Rows, Vec<u8>, [Vec<u8>; 2]) {
    let db = open_private_database(paths.installation.files()[1]).expect("same original journal");
    let read = db.begin_read().expect("journal snapshot");
    let table = read.open_table(JOURNAL).expect("journal table");
    let rows = table
        .iter()
        .expect("rows")
        .map(|r| {
            let (k, v) = r.expect("row");
            (k.value().to_string(), v.value().to_vec())
        })
        .filter(|(name, _)| name != "account-root-fence")
        .collect();
    let parent = parent_rows(&open_private_database(&paths.configuration).expect("same parent")).0;
    (
        rows,
        parent,
        [&paths.wrapping, &paths.signer].map(|p| fs::read(p).expect("same original sealed keys")),
    )
}

fn finish(work: Work, closed: bool, later: bool) {
    let mut s = Scenario::new(work, true);
    let previous = original(&s.t);
    if later {
        s.extend_history();
    }
    let next = Next::new(&mut s, "managed-next", 211, if later { 196 } else { 186 });
    let plan = context(&s, &next, &previous);
    let paths = s.t.f.original.paths.clone();
    let bytes = retained(&paths);
    let full_before = faults::original_rows(&s.t);
    let mut owner = begin(&mut s, &plan).expect("same registry managed next preparation");
    assert_eq!(
        owner.state().expect("durable next intent"),
        State::Preparing
    );
    owner.close();
    assert!(
        faults::original_rows(&s.t) == full_before,
        "preparation does not mutate old parent or child fence"
    );
    let mut owner = resume(&s, &plan).expect("cold managed preparation");
    assert_eq!(
        owner
            .bind_transferred_freeze(&s.t.frozen, next.approval.clone())
            .expect("original freeze, exact next approval and parent-first handoff"),
        *next.approval.proposal()
    );
    assert_eq!(owner.state().expect("next bound"), State::Pending);
    owner.close();
    let mut owner = resume(&s, &plan).expect("cold bound next");
    let wire = next.decide(&mut s, closed);
    let expected = if closed {
        State::Closed
    } else {
        State::Committed
    };
    assert_eq!(
        owner
            .retain_transferred_decision(&wire)
            .expect("child, parent, registry exact next outcome"),
        expected
    );
    owner.close();
    assert!(retained(&paths) == bytes);
    s.reopen();
    s.assert_old();
    assert_eq!(
        s.registry
            .transferred_account_decision(next.plan.operation())
            .expect("same next proof")
            .as_bytes(),
        wire
    );
    s.registry.close();
    let mut owner = resume(&s, &plan).expect("cold complete next controller");
    assert_eq!(owner.state().expect("same outcome"), expected);
    assert_eq!(
        owner
            .retain_transferred_decision(&wire)
            .expect("exact same operation retry"),
        expected
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let carrier = target_activation::CurrentCarrier {
        store: Arc::new(Mutex::new(s.t.target)),
        clock: Arc::new(AtomicU64::new(next.now)),
        calls: Arc::clone(&calls),
    };
    let target = DeviceEnrollment::open(next.account.paths.clone(), next.account.intent.clone())
        .expect("independent actual target enrollment");
    let result = owner.activate_successor(
        target,
        &s.t.policy,
        next.now,
        Box::new(carrier),
        Duration::from_secs(3),
    );
    if closed {
        assert!(matches!(result, Err(DurableError::Suspended)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    } else {
        let mut live = result.expect("actual target owner from managed controller");
        assert!(calls.load(Ordering::SeqCst) > 0);
        let (service, _, device) = live.parts().expect("live target owners");
        for (id, allowed) in [(216, true), (217, false)] {
            if !allowed {
                owner.close();
            }
            let result = service.stores().expect("target store").0.generate_prekey(
                &s.t.policy,
                device,
                PrekeyId::from_trusted_state([id; 32]).expect("new target prekey"),
                LeafKind::OneTimePq,
                Validity::new(next.now, next.now + 2).expect("current window"),
                next.now,
            );
            if allowed {
                result.expect("real crypto after current admission");
            } else {
                assert!(result.is_err(), "controller closure revokes target crypto");
            }
        }
        live.close();
    }
    owner.close();
    assert!(retained(&paths) == bytes);
    s.t.f.assert_fenced();
    eprintln!("TRANSFERRED_MANAGED_NEXT work={work:?} closed={closed} later={later} original_state=true old_closed=true current_admission=true");
}
#[test]
fn transferred_next_managed_gpr_and_cancellation_keep_original_state_and_current_authority() {
    for work in [
        Work::None,
        Work::Policy(0),
        Work::Policy(1),
        Work::Policy(2),
        Work::Credential(0),
        Work::Credential(1),
        Work::Credential(2),
        Work::Roster(0),
        Work::Roster(1),
        Work::Roster(2),
        Work::Cancellation(false),
        Work::Cancellation(true),
    ] {
        for closed in [false, true] {
            finish(work, closed, false);
        }
    }
}
#[test]
fn transferred_next_managed_later_witness_uses_historical_closed_and_fresh_target_admission() {
    finish(Work::Roster(1), false, true);
}

#[test]
fn transferred_next_managed_rejects_different_full_approval_before_registry_binding() {
    let mut s = Scenario::new(Work::Policy(1), true);
    let previous = original(&s.t);
    let next = Next::new(&mut s, "managed-next", 211, 186);
    let plan = context(&s, &next, &previous);
    let root =
        s.t.f
            .original
            .root
            .public_key()
            .expect("old independent root");
    let altered = AnchorTransferredAccountReplacementApproval::from_trusted_state(
        next.approval.proposal().clone(),
        &AnchorTransferredAccountReplacementMaterials {
            previous_root: &root,
            genesis: &next.account.genesis,
            device: &next.account.device,
            policy: &s.t.policy,
            history: &s.t.history,
        },
        [225; 32],
        Validity::new(186, 191).expect("different authorization window"),
    )
    .expect("independently valid but different approval");
    let mut owner = begin(&mut s, &plan).expect("approved next preparation");
    assert!(owner
        .bind_transferred_freeze(&s.t.frozen, altered.clone())
        .is_err());
    assert_eq!(
        owner
            .state()
            .expect("wrong approval leaves original owner usable"),
        State::Preparing
    );
    owner.close();
    s.reopen();
    let backup = crate::account_authority::tests::snapshot_registry(&s.registry);
    s.registry
        .bind_transferred_preparation(next.plan.operation(), &s.t.frozen, altered)
        .expect("raw registry accepts the separately supplied approval");
    s.registry.close();
    assert!(
        resume(&s, &plan).is_err(),
        "managed resume must reject a different registry approval even if its proposal matches"
    );
    crate::account_authority::tests::restore_registry_snapshot(&s.recovery.path, &backup);
    let mut owner = resume(&s, &plan).expect("restore original preparation");
    owner
        .bind_transferred_freeze(&s.t.frozen, next.approval.clone())
        .expect("original exact full approval remains usable");
    owner.close();
}

#[test]
fn transferred_next_managed_plain_preparation_and_bad_closed_proof_cannot_cross_old_fence() {
    let mut s = Scenario::new(Work::Cancellation(true), true);
    let previous = original(&s.t);
    let next = Next::new(&mut s, "managed-next", 211, 186);
    let plain = fresh(&s, &next);
    let before = crate::account_authority::tests::snapshot_registry(&s.registry);
    assert!(begin(&mut s, &plain).is_err());
    s.reopen();
    assert_eq!(
        crate::account_authority::tests::snapshot_registry(&s.registry),
        before
    );
    let mut forged = s.closed.clone();
    *forged.last_mut().expect("old signature") ^= 1;
    assert!(plain
        .clone()
        .after_closed(
            &previous,
            s.t.approval.clone(),
            next.approval.clone(),
            &s.t.frozen,
            &forged
        )
        .is_err());
    let other = Scenario::new(Work::None, true);
    assert!(plain
        .after_closed(
            &previous,
            s.t.approval.clone(),
            next.approval.clone(),
            &other.t.frozen,
            &s.closed
        )
        .is_err());
    s.registry.close();
    s.t.open()
        .expect("old parent and child remain exactly recoverable")
        .close();
}
