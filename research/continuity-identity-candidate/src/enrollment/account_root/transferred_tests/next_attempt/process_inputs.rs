// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Carry independently approved public inputs, never export fixture secrets.
use super::super::super::process::inputs as original;
use super::*;

pub(in crate::enrollment::account_root::tests::transferred::next_attempt) fn publish(
    c: &Case,
    root: &Path,
) {
    original::publish(&c.s.t, &c.s.closed);
    c.s.recovery.publish(root);
    publish_next(&c.next, root);
    if let Some(wire) = &c.wire {
        fs::write(root.join("next-decision"), wire).expect("actual signed next result");
    }
}

pub(in crate::enrollment::account_root::tests::transferred::next_attempt) fn publish_next(
    next: &Next,
    root: &Path,
) {
    let account = &next.account;
    let mut parent =
        DeviceEnrollment::open_original_storage(account.paths.clone(), account.intent.clone())
            .expect("original next target enrollment");
    let active = parent.active.as_ref().expect("target parent lease");
    let snapshot = read_snapshot(&active.database, &active.key, parent.binding)
        .expect("authenticated original target image");
    let Phase::Accepted { admission, .. } = snapshot.image.phase else {
        unreachable!("fixture target is already accepted and prepared")
    };
    for (name, bytes) in [
        ("next-root", account.intent.root.encode()),
        ("next-certificate", admission.certificate),
        ("next-roster", admission.roster),
        (
            "next-subject",
            account.genesis.subject().to_bytes().to_vec(),
        ),
        ("next-image", account.genesis.image_digest().to_vec()),
        (
            "next-plan",
            next.plan.to_bytes().expect("original approved next target"),
        ),
        (
            "next-approval",
            next.approval.to_bytes().expect("independent full approval"),
        ),
    ] {
        fs::write(root.join(name), bytes).expect("retained independent public input");
    }
    let mut checkpoint = admission.checkpoint.version().to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&admission.checkpoint.digest());
    fs::write(root.join("next-checkpoint"), checkpoint).expect("independent target checkpoint");
    parent.close();
}

pub(in crate::enrollment::account_root::tests::transferred::next_attempt) fn restore(
    root: &Path,
    previous: &PublicKey,
    history: &AnchorHandoffHistory,
) -> (
    AnchorTransferredAccountReplacementPlan,
    AnchorTransferredAccountReplacementApproval,
) {
    restore_at(root, previous, history, 186)
}

pub(in crate::enrollment::account_root::tests::transferred::next_attempt) fn restore_at(
    root: &Path,
    previous: &PublicKey,
    history: &AnchorHandoffHistory,
    now: u64,
) -> (
    AnchorTransferredAccountReplacementPlan,
    AnchorTransferredAccountReplacementApproval,
) {
    let read = |name| fs::read(root.join(name)).expect("retained independent next input");
    let public = PublicKey::decode(&read("next-root")).expect("independent next account root");
    let bytes = read("next-checkpoint");
    let mut d = Decoder::new(&bytes);
    let checkpoint =
        RosterCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("exact original checkpoint");
    d.finish().expect("complete checkpoint");
    let policy = original::policy(root, "successor-policy");
    let device = AccountPin::new(
        crate::identity::account_id(&public),
        public,
        checkpoint,
        policy.family(),
    )
    .expect("independent root and checkpoint")
    .verify_device(&read("next-certificate"), &read("next-roster"), now)
    .expect("original signatures and membership");
    let genesis = AnchorGenesis::from_trusted_state(
        AnchorSubject::from_trusted_state(&read("next-subject")).expect("original subject"),
        read("next-image")
            .try_into()
            .expect("original image commitment"),
    )
    .expect("original prepared target genesis");
    let materials = AnchorTransferredAccountReplacementMaterials {
        previous_root: previous,
        genesis: &genesis,
        device: &device,
        policy: &policy,
        history,
    };
    (
        AnchorTransferredAccountReplacementPlan::restore_trusted_state(
            &read("next-plan"),
            &materials,
        )
        .expect("exact independently selected next plan"),
        AnchorTransferredAccountReplacementApproval::restore_trusted_state(
            &read("next-approval"),
            &materials,
        )
        .expect("exact independent next approval"),
    )
}
