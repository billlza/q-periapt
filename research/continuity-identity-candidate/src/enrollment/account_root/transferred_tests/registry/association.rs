// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_registry_new_association_uses_current_history_without_rebinding_old_accounts() {
    let mut t = Transferred::with_registry(None, 2);
    let mut r = t
        .registry
        .take()
        .expect("original A registry before handoff");
    let base = t.f._dir.path().canonicalize().expect("owned test parent");
    let new = account_at(&base.join("new-independent-B-account"), &t.policy, 200, 185);
    let current = r
        .owner
        .associate(
            ApplicationAccountId::from_trusted_state([224; 32])
                .expect("new host-approved application"),
            &new.device,
        )
        .expect("new association after history advanced");
    r.other.check().expect("unrelated A lease survives");
    crate::account_authority::tests::rejects_transferred_images(&r.owner);
    r.owner
        .access()
        .expect("live")
        .check_witness(current, t.history.current_pin().binding())
        .expect("fresh mapping uses current B");
    assert!(r
        .owner
        .access()
        .expect("live")
        .check_witness(current, t.f.pin.binding())
        .is_err());
    r.reopen(&t.f);
    let access = r.owner.access().expect("original same-pin database");
    access
        .check_witness(current, t.history.current_pin().binding())
        .expect("persisted new B mapping");
    access
        .check_witness(r.unrelated, t.f.pin.binding())
        .expect("persisted unrelated logical A");
    assert!(matches!(
        access.current(r.expected.application()),
        Err(DurableError::Suspended)
    ));
}

#[test]
fn transferred_registry_initial_pin_may_be_an_intermediate_historical_witness() {
    let mut t = Transferred::new();
    t.decide(false);
    let base = t.f._dir.path().canonicalize().expect("owned B host");
    let path = base.join("registry-created-under-B");
    let key = base.join("registry-B-key");
    let identity = AccountAuthorityIdentity::generate().expect("independent B registry identity");
    let pin = t.history.current_pin().clone();
    let mut registry = AccountAuthorityStore::provision(
        &path,
        JournalKey::provision(&key).expect("independent B key"),
        identity,
        t.policy.family(),
        pin.clone(),
    )
    .expect("fresh B registry");
    let expected = registry
        .associate(
            ApplicationAccountId::from_trusted_state([225; 32]).expect("B host association"),
            &t.successor.device,
        )
        .expect("actual existing B account");
    let next = account_at(&base.join("second-B-target"), &t.policy, 200, 185);
    let previous = t
        .successor
        .root
        .public_key()
        .expect("actual B account root");
    let m = AnchorTransferredAccountReplacementMaterials {
        previous_root: &previous,
        genesis: &next.genesis,
        device: &next.device,
        policy: &t.policy,
        history: &t.history,
    };
    let request = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([226; 32]).expect("freeze ID"),
        previous.clone(),
        &pin,
    )
    .expect("exact B request");
    let preparation = t
        .target
        .transferred_account_replacement_plan(
            AnchorAccountReplacementId::from_trusted_state([227; 32])
                .expect("original replacement ID"),
            request.clone(),
            &m,
            185,
        )
        .expect("current B target before freeze");
    registry
        .begin_transferred_preparation(expected, preparation.clone(), &t.history)
        .expect("retain original B intent against A-B history");
    let proposal = t
        .target
        .transferred_account_freeze_proposal(&request, &t.history)
        .expect("complete B account");
    let approval = AnchorTransferredAccountFreezeApproval::from_trusted_state(
        proposal,
        &request,
        &t.history,
        [228; 32],
        Validity::new(185, 195).expect("window"),
    )
    .expect("separate operator approval");
    let wire = t
        .target
        .freeze_transferred_account(&approval, || Ok(185))
        .expect("actual B account freeze");
    let frozen = approval
        .verify_receipt(&t.history, &wire)
        .expect("exact freeze");
    let approval = AnchorTransferredAccountReplacementApproval::from_trusted_state(
        preparation.bind(&frozen, &t.history).expect("same plan"),
        &m,
        [229; 32],
        Validity::new(185, 195).expect("window"),
    )
    .expect("full root approval");
    registry
        .bind_transferred_preparation(preparation.operation(), &frozen, approval.clone())
        .expect("original bound B intent");
    let result = t
        .target
        .replace_transferred_account_root(&approval, &m, || Ok(185))
        .expect("actual B retirement");
    registry
        .retain_transferred_account_decision(preparation.operation(), result.as_bytes())
        .expect("publish original B mapping");
    registry.close();
    let registry = AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key).expect("same key"),
        identity,
        t.policy.family(),
        pin.clone(),
    )
    .expect("cold original B pin, not encoded A origin");
    let current = registry
        .access()
        .expect("runtime")
        .current(expected.application())
        .expect("new mapping");
    assert_eq!(current.account(), next.device.account_id());
    registry
        .access()
        .expect("runtime")
        .check_witness(current, pin.binding())
        .expect("B logical target");
}
