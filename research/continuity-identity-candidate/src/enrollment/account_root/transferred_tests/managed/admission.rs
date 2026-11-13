// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority::tests::{
    changed_managed_checkpoint, restore_registry_snapshot, snapshot_registry,
};

#[test]
fn transferred_managed_invalid_proofs_preserve_exact_controller_operation() {
    let mut t = Transferred::with_controller(Some(1), 2);
    let other = Transferred::new();
    let mut owner = t.controller.take().expect("prepared original");
    assert!(owner
        .bind_transferred_freeze(&other.frozen, t.approval.clone())
        .is_err());
    assert_eq!(owner.state().expect("no unknown write"), State::Preparing);
    assert!(owner
        .bind_transferred_freeze(&t.frozen, other.approval.clone())
        .is_err());
    assert_eq!(owner.state().expect("same original plan"), State::Preparing);
    owner
        .bind_transferred_freeze(&t.frozen, t.approval.clone())
        .expect("valid exact approval");
    let wire = t.decide(false);
    let mut damaged = wire.as_bytes().to_vec();
    *damaged.last_mut().expect("signature") ^= 1;
    assert!(owner.retain_transferred_decision(&damaged).is_err());
    assert_eq!(
        owner.state().expect("original pending owner remains"),
        State::Pending
    );
    assert_eq!(
        owner
            .retain_transferred_decision(wire.as_bytes())
            .expect("same signed result"),
        State::Committed
    );
    owner.close();
}

#[test]
fn transferred_managed_begin_rejects_a_new_registry_after_the_original_journal() {
    let t = Transferred::new();
    let original = super::super::registry::OriginalRegistry::new(&t.f);
    let rows = journal_rows(&t);
    let parent = original_parent(&t);
    let error = ManagedAccountRootReplacement::begin_transferred(
        original.owner,
        original.expected,
        context(&t),
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
    )
    .err();
    assert!(matches!(error, Some(DurableError::Conflict)));
    assert!(journal_rows(&t) == rows && original_parent(&t) == parent);

    let mut t = Transferred::with_controller(Some(2), 2);
    t.controller
        .take()
        .expect("original bound registry controller")
        .close();
    let rows = journal_rows(&t);
    let parent = original_parent(&t);
    let base =
        t.f.original
            .paths
            .configuration
            .parent()
            .expect("canonical owned directory");
    let mut substitute = AccountAuthorityStore::provision(
        &base.join("substitute-registry"),
        JournalKey::provision(&base.join("substitute-registry-key")).expect("distinct test key"),
        AccountAuthorityIdentity::generate().expect("distinct test registry identity"),
        t.f.policy.family(),
        t.f.pin.clone(),
    )
    .expect("separate approved test registry");
    let expected = substitute
        .associate(
            t.registry_recovery
                .as_ref()
                .expect("original registry")
                .expected
                .application(),
            &t.f.original.device,
        )
        .expect("same account and application but different registry");
    assert_eq!(
        expected,
        t.registry_recovery
            .as_ref()
            .expect("original checkpoint")
            .expected
    );
    let error = ManagedAccountRootReplacement::begin_transferred(
        substitute,
        expected,
        context(&t),
        t.f.original.paths.clone(),
        t.f.original.intent.clone(),
    )
    .err();
    assert!(matches!(error, Some(DurableError::Conflict)));
    assert!(journal_rows(&t) == rows && original_parent(&t) == parent);
    let mut original = resume(&t).expect("the real original registry still works");
    assert_eq!(
        original.state().expect("unchanged original operation"),
        State::Preparing
    );
    original.close();
}

#[test]
fn transferred_managed_missing_or_mac_valid_changed_checkpoint_never_rebases_originals() {
    let mut t = Transferred::with_controller(Some(0), 0);
    t.controller
        .take()
        .expect("original preparing owner")
        .close();
    let recovery = t.registry_recovery.as_ref().expect("original registry");
    let mut registry = recovery.open(&t.f);
    let original = snapshot_registry(&registry);
    for checkpoint in [None, Some([237; 32])] {
        let alternate = changed_managed_checkpoint(&registry, checkpoint);
        registry.close();
        restore_registry_snapshot(&recovery.path, &alternate);
        let error = resume(&t).err();
        if checkpoint.is_some() {
            assert!(matches!(error, Some(DurableError::Conflict)));
        } else {
            assert!(matches!(error, Some(DurableError::Suspended)));
        }
        restore_registry_snapshot(&recovery.path, &original);
        registry = recovery.open(&t.f);
    }
    registry.close();
    let mut owner =
        resume(&t).expect("exact original record restored without new key or operation");
    assert_eq!(owner.state().expect("original phase"), State::Preparing);
    owner.close();
}
