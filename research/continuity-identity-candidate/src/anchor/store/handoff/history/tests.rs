// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cryptographic history-unit fixtures, not activated stores or client adoption.
use super::*;

fn authority() -> (AnchorPin, AnchorSigningKey) {
    let signer = AnchorSigningKey::generate().expect("test signer");
    (
        AnchorPin::new(
            AnchorIdentity::generate().expect("instance"),
            signer.public_key().expect("public"),
        ),
        signer,
    )
}

fn proof(
    history: &AnchorHandoffHistory,
    source: &AnchorSigningKey,
    target: &(AnchorPin, AnchorSigningKey),
    operation: u8,
    legacy: bool,
) -> Transition {
    let plan = AnchorHandoffPlan {
        operation: [operation; 32],
        source: history.current_pin().clone(),
        target: target.0.clone(),
        revision: 1,
        commitment: [181; 32],
        validity: Validity::new(140, 160).expect("source interval"),
        authorization: [182; 32],
        history: if legacy { None } else { Some(history.context) },
    };
    plan.check().expect("shape");
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &plan,
        &plan.source,
        &plan.target,
        Validity::new(145, 155).expect("target interval"),
        [183; 32],
    )
    .expect("trusted test approval");
    let freeze = AnchorHandoffReceipt::sign(&plan, AnchorHandoffState::Frozen, source)
        .expect("source signature");
    let acknowledgement = approval
        .sign_import(freeze.as_bytes(), &target.1)
        .expect("target signature");
    let retirement = retirement::sign_retirement(
        &approval,
        freeze.as_bytes(),
        acknowledgement.as_bytes(),
        150,
        source,
    )
    .expect("source retirement signature");
    Transition {
        approval,
        freeze: freeze.as_bytes().to_vec(),
        acknowledgement: acknowledgement.as_bytes().to_vec(),
        retirement: retirement.as_bytes().to_vec(),
    }
}
fn append(history: &mut AnchorHandoffHistory, proof: &Transition) -> Result<(), DurableError> {
    history.append_verified(
        &proof.approval,
        &proof.freeze,
        &proof.acknowledgement,
        &proof.retirement,
    )
}

#[test]
fn signed_history_resolves_old_keys_but_never_as_current_authority() {
    let a = authority();
    let b = authority();
    let c = authority();
    let mut history = AnchorHandoffHistory::from_trusted_origin(a.0.clone());
    let genesis = history.checkpoint();
    let first = proof(&history, &a.1, &b, 184, false);
    append(&mut history, &first).expect("first authenticated edge");
    let first_checkpoint = history.checkpoint();
    let second = proof(&history, &b.1, &c, 185, false);
    append(&mut history, &second).expect("second metadata edge");
    assert_eq!(history.namespace_binding(), a.0.binding());
    assert_eq!(history.sequence(), 2);
    for pin in [&a.0, &b.0, &c.0] {
        assert_eq!(
            history
                .historical_pin(pin.binding())
                .expect("resolved exact key")
                .public_key(),
            pin.public_key()
        );
    }
    assert!(history.historical_pin([99; 32]).is_err());
    assert!(matches!(
        history.require_current(a.0.binding()),
        Err(Error::Retired)
    ));
    assert!(matches!(
        history.require_current(b.0.binding()),
        Err(Error::Retired)
    ));
    history
        .require_current(c.0.binding())
        .expect("current metadata authority only");
    let bytes = history.to_bytes().expect("complete proof");
    let restored =
        AnchorHandoffHistory::restore_trusted_state(&bytes, &a.0, &c.0, history.checkpoint())
            .expect("all signatures and exact checkpoint");
    assert_eq!(restored.to_bytes().expect("canonical"), bytes);
    for checkpoint in [genesis, first_checkpoint, [99; 32]] {
        assert!(
            AnchorHandoffHistory::restore_trusted_state(&bytes, &a.0, &c.0, checkpoint).is_err()
        );
    }
    assert!(
        AnchorHandoffHistory::restore_trusted_state(&bytes, &b.0, &c.0, history.checkpoint())
            .is_err()
    );
    assert!(
        AnchorHandoffHistory::restore_trusted_state(&bytes, &a.0, &b.0, history.checkpoint())
            .is_err()
    );
    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(AnchorHandoffHistory::restore_trusted_state(
        &truncated,
        &a.0,
        &c.0,
        history.checkpoint()
    )
    .is_err());
    let mut extended = bytes;
    extended.push(0);
    assert!(AnchorHandoffHistory::restore_trusted_state(
        &extended,
        &a.0,
        &c.0,
        history.checkpoint()
    )
    .is_err());
}

#[test]
fn valid_same_key_chain_cannot_splice_another_predecessor_or_namespace() {
    let a = authority();
    let b = authority();
    let c = authority();
    let foreign = authority();
    let mut actual = AnchorHandoffHistory::from_trusted_origin(a.0.clone());
    let first = proof(&actual, &a.1, &b, 186, false);
    append(&mut actual, &first).expect("approved first edge");
    let original = actual.to_bytes().expect("original history");
    let mut fork = AnchorHandoffHistory::from_trusted_origin(a.0.clone());
    let alternate = proof(&fork, &a.1, &b, 187, false);
    append(&mut fork, &alternate).expect("separate signed predecessor");
    let next = proof(&fork, &b.1, &c, 188, false);
    next.approval
        .verify_retirement_receipt(&next.freeze, &next.acknowledgement, &next.retirement)
        .expect("all signatures valid");
    assert_eq!(
        actual.current_pin().binding(),
        next.approval.plan.source.binding
    );
    assert!(
        append(&mut actual, &next).is_err(),
        "key continuity alone is insufficient"
    );
    let mut other_namespace = AnchorHandoffHistory::from_trusted_origin(foreign.0.clone());
    let different_origin = proof(&other_namespace, &foreign.1, &b, 189, false);
    append(&mut other_namespace, &different_origin).expect("separate original namespace");
    let next = proof(&other_namespace, &b.1, &c, 190, false);
    assert!(append(&mut actual, &next).is_err());
    assert_eq!(actual.to_bytes().expect("no partial mutation"), original);
}

#[test]
fn legacy_proof_can_only_be_first_and_retired_keys_or_operations_cannot_recur() {
    let a = authority();
    let b = authority();
    let c = authority();
    let mut history = AnchorHandoffHistory::from_trusted_origin(a.0.clone());
    let first = proof(&history, &a.1, &b, 191, true);
    assert_eq!(first.approval.plan.to_bytes().len(), LEGACY_PLAN_BYTES);
    append(&mut history, &first).expect("historical original v1 transition");
    let second = proof(&history, &b.1, &c, 192, true);
    assert!(
        append(&mut history, &second).is_err(),
        "v1 has no predecessor commitment"
    );
    let reused = proof(&history, &b.1, &a, 193, false);
    assert!(append(&mut history, &reused).is_err());
    let duplicate = proof(&history, &b.1, &c, 191, false);
    assert!(append(&mut history, &duplicate).is_err());
    let second = proof(&history, &b.1, &c, 194, false);
    append(&mut history, &second).expect("bound v2 successor after legacy first edge");
}

#[test]
fn history_bound_preserves_every_original_proof_and_rejects_ninth_transition() {
    let mut source = authority();
    let origin = source.0.clone();
    let mut history = AnchorHandoffHistory::from_trusted_origin(origin.clone());
    for operation in 1..=8 {
        let target = authority();
        let next = proof(&history, &source.1, &target, operation, false);
        append(&mut history, &next).expect("bounded full proof");
        source = target;
    }
    let before = history.to_bytes().expect("eight exact proofs");
    let next = proof(&history, &source.1, &authority(), 9, false);
    assert!(matches!(
        append(&mut history, &next),
        Err(DurableError::Capacity)
    ));
    assert_eq!(history.to_bytes().expect("nothing truncated"), before);
    AnchorHandoffHistory::restore_trusted_state(&before, &origin, &source.0, history.checkpoint())
        .expect("all eight historical edges reverified");
}
