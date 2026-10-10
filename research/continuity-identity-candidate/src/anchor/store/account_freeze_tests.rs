// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorAccountFreezeId, AnchorAccountFreezeRequest, AnchorFrozenAccount};
#[path = "account_freeze_tests/process.rs"]
mod process;
#[path = "account_freeze_tests/receipt.rs"]
mod receipt;
#[path = "account_freeze_tests/recovery.rs"]
mod recovery;
#[path = "account_freeze_tests/refresh.rs"]
mod refresh;
fn freeze_request(c: &Case, root: PublicKey, seed: u8) -> AnchorAccountFreezeRequest {
    AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([seed; 32]).expect("original freeze operation"),
        root,
        &c.pin,
    )
    .expect("independent control-plane scope")
}
fn frozen_proposal(
    c: &mut Case,
    frozen: &AnchorFrozenAccount,
    next: &Fresh,
    seed: u8,
) -> RootProposal {
    c.store
        .frozen_account_replacement_proposal(
            RootId::from_trusted_state([seed; 32])
                .expect("separate approved replacement operation"),
            frozen,
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current target policy"),
            150,
        )
        .expect("complete descriptor bound to original freeze")
}
#[test]
fn account_freeze_captures_racing_head_blocks_namespace_and_enables_exact_replacement() {
    let mut c = required_case();
    let same_root = fresh(&c, 2, 2, 174);
    let device_proposal = first_proposal(&mut c, &same_root);
    let unseen = unseen_old_device(&c, 196);
    let next = root_target(&c, 190, 192);
    let other = root_target(&c, 200, 202);
    let legacy = root_proposal(&mut c, &next, 181);
    // Retain approval before activity changes the complete witness snapshot.
    let original = freeze_request(&c, original_root(&c), 180);
    let old_request = request(
        &c,
        AnchorOperation::advance(initial(&c), [173; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &old_request)
        .applied_head()
        .expect("advanced old head");
    let before = c.store.image().expect("original image").revision;
    let frozen = c
        .store
        .freeze_account(&original)
        .expect("atomic freeze after racing advance");
    let observed = frozen.subjects().collect::<Vec<_>>();
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed
            .first()
            .expect("one original frozen subject")
            .observed_head(),
        head
    );
    assert_eq!(
        observed
            .first()
            .expect("one original frozen subject")
            .last_command_id(),
        Some(old_request.command_id())
    );
    let image = c.store.image().expect("frozen image");
    assert_eq!(image.revision, before + 1);
    assert_eq!(
        image.entries.len(),
        1,
        "freeze never enrolls its future target"
    );
    assert!(image.account_replacements.is_empty());
    assert!(
        !image.subject_retired(c.genesis.subject()),
        "preparation is not retirement"
    );
    assert_retired(&mut c, AnchorOperation::query());
    assert_retired(
        &mut c,
        AnchorOperation::advance(head, [175; 32]).expect("later advance"),
    );
    assert!(matches!(
        c.store.handle(old_request.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
    for target in [&unseen, &same_root] {
        assert!(matches!(
            c.store.enroll(
                &target.genesis,
                &target.device,
                c.peer.responder.current_policy().expect("policy"),
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
    assert!(matches!(
        commit(&mut c, &device_proposal, &same_root, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        root_commit(&mut c, &legacy, &next, 150),
        Err(DurableError::Conflict)
    ));
    c.store
        .enroll(
            &other.genesis,
            &other.device,
            c.peer.responder.current_policy().expect("policy"),
            150,
        )
        .expect("unrelated account remains usable");
    assert_eq!(query(&mut c, &other).outcome(), AnchorOutcome::Current);
    let p = frozen_proposal(&mut c, &frozen, &next, 182);
    let bytes = p.to_bytes().expect("original descriptor");
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPARPL02");
    assert_eq!(
        RootProposal::from_trusted_state(&bytes).expect("canonical round trip"),
        p
    );
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("no implicit commit"),
        RootState::Unavailable
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .freeze_account(&original)
            .expect("original retry after reopen"),
        frozen
    );
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("exact independently approved target"),
        RootState::Committed
    );
    let receipt = c
        .store
        .retired_account_receipt(&p)
        .expect("separate retirement proof");
    assert_eq!(
        c.pin
            .verify_retired_account(&p, &receipt)
            .expect("retired fact")
            .subject_observation(c.genesis.subject())
            .expect("original head")
            .observed_head(),
        head
    );
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
    assert_eq!(query(&mut c, &other).outcome(), AnchorOutcome::Current);
    let committed_revision = c.store.image().expect("committed image").revision;
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .freeze_account(&original)
            .expect("historical freeze after retirement"),
        frozen
    );
    assert_eq!(
        root_commit(&mut c, &p, &next, 250).expect("exact historical replacement retry"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .image()
            .expect("historical retries do not advance")
            .revision,
        committed_revision
    );
    assert_retired(&mut c, AnchorOperation::query());
}
#[test]
fn account_freeze_rejects_changed_operation_scope_and_retains_expired_target_intent() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let original = freeze_request(&c, original_root(&c), 180);
    let changed = freeze_request(&c, original_root(&c), 181);
    let reused = freeze_request(&c, next.device.authority_key.clone(), 180);
    assert!(matches!(
        c.store.account_freeze(&original),
        Err(DurableError::Absent)
    ));
    let frozen = c.store.freeze_account(&original).expect("original freeze");
    let p = frozen_proposal(&mut c, &frozen, &next, 182);
    let revision = c.store.image().expect("frozen image").revision;
    for conflicting in [&changed, &reused] {
        assert!(matches!(
            c.store.freeze_account(conflicting),
            Err(DurableError::Conflict)
        ));
        assert!(matches!(
            c.store.account_freeze(conflicting),
            Err(DurableError::Conflict)
        ));
    }
    assert!(
        root_commit(&mut c, &p, &next, 250).is_err(),
        "freeze cannot override target expiry"
    );
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("still no commitment"),
        RootState::Unavailable
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .account_freeze(&original)
            .expect("original retained snapshot"),
        frozen
    );
    assert_eq!(c.store.image().expect("unchanged image").revision, revision);
    assert_retired(&mut c, AnchorOperation::query());
}
#[test]
fn account_freeze_blocks_future_unknown_devices_and_refuses_unclassified_legacy_entries() {
    let mut c = required_case();
    let unknown = root_target(&c, 190, 192);
    let original = freeze_request(&c, unknown.device.authority_key.clone(), 180);
    let frozen = c
        .store
        .freeze_account(&original)
        .expect("freeze unseen account namespace");
    assert_eq!(frozen.subjects().count(), 0);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .account_freeze(&original)
            .expect("retained empty snapshot"),
        frozen
    );
    assert!(matches!(
        c.store.enroll(
            &unknown.genesis,
            &unknown.device,
            c.peer.responder.current_policy().expect("policy"),
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let old_request = request(&c, AnchorOperation::query());
    assert_eq!(
        apply_request(&mut c, &old_request).outcome(),
        AnchorOutcome::Current
    );
    let mut legacy = required_case();
    let original = freeze_request(&legacy, original_root(&legacy), 183);
    let mut image = legacy.store.image().expect("original image");
    image
        .entries
        .values_mut()
        .next()
        .expect("legacy entry")
        .original_identity = None;
    legacy
        .store
        .persist(&mut image)
        .expect("explicit old-format fixture");
    let before = legacy.store.image().expect("legacy image").digest;
    assert!(matches!(
        legacy.store.freeze_account(&original),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        legacy.store.image().expect("unchanged legacy image").digest,
        before
    );
    legacy
        .store
        .retain_original_identity(
            legacy.genesis.subject(),
            legacy
                .peer
                .responder
                .inventory_inputs()
                .expect("original identity")
                .1,
        )
        .expect("explicit original classification");
    legacy
        .store
        .freeze_account(&original)
        .expect("classified account can freeze");
}

#[test]
fn account_freeze_requires_original_preparation_binding_even_when_heads_match() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let legacy = root_proposal(&mut c, &next, 180);
    let request = freeze_request(&c, original_root(&c), 181);
    let frozen = c
        .store
        .freeze_account(&request)
        .expect("freeze unchanged head");
    assert!(
        matches!(
            root_commit(&mut c, &legacy, &next, 150),
            Err(DurableError::Conflict)
        ),
        "an equal head does not bind the original freeze approval"
    );
    assert!(matches!(
        c.store.account_root_replacement_proposal(
            legacy.operation(),
            &original_root(&c),
            &next.genesis,
            &next.device,
            c.peer.responder.current_policy().expect("policy"),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let p = frozen_proposal(&mut c, &frozen, &next, 182);
    let mut changed = p.to_bytes().expect("canonical original proposal");
    *changed.get_mut(8).expect("preparation binding byte") ^= 1;
    let changed =
        RootProposal::from_trusted_state(&changed).expect("syntactically valid different binding");
    assert!(matches!(
        root_commit(&mut c, &changed, &next, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("exact bound approval"),
        RootState::Committed
    );
}
