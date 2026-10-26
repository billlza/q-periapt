// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact public approvals and signed metadata survive the test-process boundary.
use super::*;
use crate::enrollment::account_root::tests::process::read_inputs;

fn read(path: &Path, name: &str) -> Vec<u8> {
    fs::read(path.join(name)).expect("independently retained original public input")
}
fn publish_account(t: &Transferred, account: &Account) {
    let root = account
        .paths
        .configuration
        .parent()
        .expect("canonical owned account");
    let current = t.history.current_pin();
    let mut bytes = account.intent.root.encode();
    account.intent.encode(&mut bytes);
    bytes.extend_from_slice(current.identity().as_bytes());
    bytes.extend_from_slice(&current.public_key().encode());
    fs::write(root.join("independent-inputs"), bytes).expect("retain exact public intent");
    fs::write(
        root.join("proposal"),
        t.approval.proposal().to_bytes().expect("proposal bytes"),
    )
    .expect("retain exact proposal");
}
pub(crate) fn publish(t: &Transferred, decision: &[u8]) {
    publish_account(t, &t.f.original);
    publish_account(t, &t.successor);
    let root =
        t.f.original
            .paths
            .configuration
            .parent()
            .expect("original directory");
    for (name, bytes) in &t.public_inputs {
        fs::write(root.join(name), bytes).expect("retained independent public input");
    }
    fs::write(
        root.join("root-approval"),
        t.approval.to_bytes().expect("complete original approval"),
    )
    .expect("retained operator approval");
    fs::write(root.join("root-decision"), decision).expect("original signed outcome");
    fs::write(
        root.join("account-freeze"),
        t.frozen
            .transferred_record()
            .expect("original signed freeze"),
    )
    .expect("retained full freeze");
    fs::write(
        root.join("successor-subject"),
        t.successor.genesis.subject().to_bytes(),
    )
    .expect("original successor subject");
    fs::write(
        root.join("successor-image"),
        t.successor.genesis.image_digest(),
    )
    .expect("original successor image");
}
fn device(root: &Path, intent: &EnrollmentIntent) -> VerifiedDevice {
    let mut parent = DeviceEnrollment::open_original_storage(paths(root), intent.clone())
        .expect("original authenticated signer-free parent");
    let active = parent.active.as_ref().expect("original parent lease");
    let snapshot = read_snapshot(&active.database, &active.key, parent.binding)
        .expect("authenticated original image");
    let device = parent
        .original_device_metadata(&snapshot.image)
        .expect("same signed original metadata");
    parent.close();
    device
}
fn policy(root: &Path, name: &str) -> VerifiedSessionPolicy {
    let bytes = read(root, &format!("{name}-checkpoint"));
    let mut d = Decoder::new(&bytes);
    let checkpoint =
        PolicyCheckpoint::from_trusted_state(d.u64().expect("version"), d.array().expect("digest"))
            .expect("independent policy checkpoint");
    d.finish().expect("complete checkpoint");
    PolicyPin::new(
        read(root, "policy-family").try_into().expect("family"),
        PublicKey::decode(&read(root, "policy-root")).expect("independent policy root"),
        checkpoint,
    )
    .expect("exact policy pin")
    .verify(&read(root, name), crate::tests::sdk_runtime(), 185)
    .expect("original policy signatures, no re-signing")
}
pub(crate) struct RegistryInputs {
    pub(crate) intent: EnrollmentIntent,
    pub(crate) logical: AnchorPin,
    pub(crate) approval: AnchorTransferredAccountReplacementApproval,
    pub(crate) history: AnchorHandoffHistory,
    pub(crate) selected: WitnessJournalAdoptionPlan,
    pub(crate) preparation: AnchorTransferredAccountReplacementPlan,
    pub(crate) frozen: AnchorFrozenAccount,
}
pub(super) fn restore(root: &Path) -> (EnrollmentIntent, TransferredAccountRootJournalPlan) {
    let r = restore_registry(root);
    (
        r.intent,
        TransferredAccountRootJournalPlan::new(r.logical, r.approval, r.history, Some(r.selected))
            .expect("same root, history and selection expectations"),
    )
}
pub(crate) fn restore_registry(root: &Path) -> RegistryInputs {
    let (intent, current, proposal) = read_inputs(root);
    let original = device(root, &intent);
    let target_root = root
        .parent()
        .expect("fixture root")
        .join("after-transfer-target");
    let (target_intent, _, _) = read_inputs(&target_root);
    let successor = device(&target_root, &target_intent);
    let bytes = read(root, "origin-pin");
    let mut d = Decoder::new(&bytes);
    let logical = AnchorPin::new(
        AnchorIdentity::from_trusted_state(d.array().expect("identity"))
            .expect("original identity"),
        PublicKey::decode(d.take(PUBLIC_KEY_BYTES).expect("public bytes"))
            .expect("original public key"),
    );
    d.finish().expect("complete original pin");
    let history = AnchorHandoffHistory::restore_trusted_state(
        &read(root, "history"),
        &logical,
        &current,
        read(root, "history-checkpoint")
            .try_into()
            .expect("exact history checkpoint"),
    )
    .expect("original independent history");
    let target_approval = AnchorHandoffTargetApproval::restore_trusted_state(
        &read(root, "target-approval"),
        &logical,
        &current,
    )
    .expect("exact target approval");
    let activation = target_approval
        .verify_activation_receipt(
            &history,
            &read(root, "freeze"),
            &read(root, "import"),
            &read(root, "retired"),
            &read(root, "activated"),
        )
        .expect("original complete handoff");
    let original_policy = policy(root, "original-policy");
    let current_policy = policy(root, "current-policy");
    let selection_materials = AnchorHandoffAdoptionMaterials {
        original_device: &original,
        current_device: &original,
        original_policy: original_policy.historical(),
        current_policy: current_policy.historical(),
        history: &history,
        activation: &activation,
    };
    let scope = AnchorHandoffAdoptionScope::from_trusted_state(&read(root, "selection-scope"))
        .expect("independent exact selection scope");
    let approved = HistoricalAnchorHandoffAdoption::from_bytes(
        &read(root, "selection-approval"),
        &scope,
        &selection_materials,
    )
    .expect("original two-root approvals");
    let selected = WitnessJournalAdoptionPlan::new(&approved, &selection_materials)
        .expect("original verified selection plan");
    let successor_policy = policy(root, "successor-policy");
    let genesis = AnchorGenesis::from_trusted_state(
        AnchorSubject::from_trusted_state(&read(root, "successor-subject"))
            .expect("original subject"),
        read(root, "successor-image")
            .try_into()
            .expect("original digest"),
    )
    .expect("original successor genesis");
    let materials = AnchorTransferredAccountReplacementMaterials {
        previous_root: &intent.root,
        genesis: &genesis,
        device: &successor,
        policy: &successor_policy,
        history: &history,
    };
    let approval = AnchorTransferredAccountReplacementApproval::restore_trusted_state(
        &read(root, "root-approval"),
        &materials,
    )
    .expect("original independent root approval");
    assert_eq!(approval.proposal(), &proposal);
    let preparation = AnchorTransferredAccountReplacementPlan::restore_trusted_state(
        &read(root, "root-preparation"),
        &materials,
    )
    .expect("independent original target plan");
    let frozen =
        AnchorFrozenAccount::restore_transferred_record(&read(root, "account-freeze"), &history)
            .expect("original signed complete freeze");
    assert_eq!(
        preparation
            .bind(&frozen, &history)
            .expect("same planned transition"),
        proposal
    );
    RegistryInputs {
        intent,
        logical,
        approval,
        history,
        selected,
        preparation,
        frozen,
    }
}
