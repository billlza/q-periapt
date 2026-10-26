// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AccountAuthorityReplacementState as State;
#[path = "managed/activation.rs"]
mod activation;
#[path = "managed/admission.rs"]
mod admission;
#[path = "managed/process.rs"]
mod process;
#[path = "managed/recovery.rs"]
mod recovery;

fn context(t: &Transferred) -> TransferredAccountRootPreparation {
    TransferredAccountRootPreparation::new(
        t.preparation.clone(),
        t.f.pin.clone(),
        t.history.clone(),
        t.selected.clone(),
    )
    .expect("independently retained exact original context")
}
pub(super) fn resume(t: &Transferred) -> Result<ManagedAccountRootReplacement, DurableError> {
    let registry = t
        .registry_recovery
        .as_ref()
        .expect("original registry metadata");
    ManagedAccountRootReplacement::resume_transferred_original(
        registry.open(&t.f),
        registry.expected,
        context(t),
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
    )
}
#[test]
fn transferred_managed_owner_recovers_original_pending_and_exact_decision() {
    for stage in [None, Some(0), Some(1), Some(2)] {
        for selection in 0..=2 {
            for closed in [false, true] {
                exact_original(stage, selection, closed);
            }
        }
    }
}
fn exact_original(stage: Option<u8>, selection: u8, closed: bool) {
    let mut t = Transferred::with_controller(stage, selection);
    let mut managed = t
        .controller
        .take()
        .expect("same owner prepared before freeze");
    assert_eq!(managed.state().expect("durable plan"), State::Preparing);
    managed.close();
    let rows = journal_rows(&t);
    let key = fs::read(&t.f.original.paths.wrapping).expect("original key");
    let signer = fs::read(&t.f.original.paths.signer).expect("original signer");
    let mut managed = resume(&t).expect("same original preparing owner");
    assert_eq!(
        managed
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("independent full freeze and approval"),
        *t.approval.proposal()
    );
    managed.close();
    let mut managed = resume(&t).expect("exact original fenced owner");
    let decision = t.decide(closed);
    let expected = if closed {
        State::Closed
    } else {
        State::Committed
    };
    assert_eq!(
        managed
            .retain_transferred_decision(decision.as_bytes())
            .expect("child, parent, original registry"),
        expected
    );
    managed.close();
    let mut managed = resume(&t).expect("cold original terminal owner");
    assert_eq!(managed.state().expect("original outcome"), expected);
    assert_eq!(
        managed
            .retain_transferred_decision(decision.as_bytes())
            .expect("exact outcome retry"),
        expected
    );
    if closed {
        assert!(managed.successor_authority().is_err());
    } else {
        managed
            .successor_authority()
            .expect("committed original registry authority");
    }
    managed.close();
    assert!(
        journal_rows(&t) == rows,
        "original image, pending and selection unchanged"
    );
    assert!(fs::read(&t.f.original.paths.wrapping).expect("same key") == key);
    assert!(fs::read(&t.f.original.paths.signer).expect("same signer") == signer);
}

#[test]
fn transferred_managed_preparation_rejects_parent_and_child_rollback_losing_pending() {
    for side in 0..=2 {
        let mut t = Transferred::with_controller(Some(0), 0);
        t.controller.take().expect("prepared owner").close();
        assert!(journal_rows(&t).iter().any(|(name, _)| name == "pending"));
        // Restore both original files to before the real P was prepared, retaining
        // the current independent registry. No new journal/key/account is created.
        let parent = fs::read(&t.f.original.paths.configuration).expect("original pending parent");
        let child =
            fs::read(t.f.original.paths.installation.files()[1]).expect("original pending child");
        if side != 1 {
            fs::write(&t.f.original.paths.configuration, &t.pre_parent)
                .expect("owned parent backup");
        }
        if side != 0 {
            fs::write(t.f.original.paths.installation.files()[1], &t.pre_pending)
                .expect("owned child backup");
        }
        let error = resume(&t).err();
        assert!(
            matches!(&error, Some(DurableError::Conflict)),
            "original registry must detect the lost pending operation: {error:?}"
        );
        fs::write(&t.f.original.paths.configuration, parent).expect("restore exact parent");
        fs::write(t.f.original.paths.installation.files()[1], child).expect("restore exact child");
        let mut owner = resume(&t).expect("same original operation after correct backup restored");
        owner
            .bind_transferred_freeze(&t.frozen, t.approval.clone())
            .expect("same original target");
        owner.close();
    }
}
