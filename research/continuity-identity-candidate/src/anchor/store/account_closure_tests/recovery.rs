// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
fn plan(c: &mut Case, next: &Fresh) -> crate::AnchorAccountReplacementPlan {
    let request = crate::AnchorAccountFreezeRequest::from_trusted_state(
        crate::AnchorAccountFreezeId::from_trusted_state([179; 32])
            .expect("original freeze identity"),
        original_root(c),
        &c.pin,
    )
    .expect("independent freeze approval");
    c.store
        .account_replacement_plan(
            RootId::from_trusted_state([180; 32]).expect("original operation"),
            request,
            &next.genesis,
            &next.device,
            c.peer.responder.current_policy().expect("policy"),
            150,
        )
        .expect("original target plan")
}
fn at_cut(by_plan: bool, cut: usize, after: bool) -> usize {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let p = root_proposal(&mut c, &next, 180);
    let plan = plan(&mut c, &next);
    c.store
        .freeze_account(plan.request())
        .expect("original account remains frozen");
    let before = c.store.image().expect("original image").revision;
    let (remaining, count) = with_fault_database(&mut c, after);
    count.store(0, Ordering::SeqCst);
    remaining.store(cut, Ordering::SeqCst);
    let result = if by_plan {
        c.store.close_account_preparation(&plan)
    } else {
        c.store.close_account_replacement(&p)
    };
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        assert_eq!(result.expect("calibrate real barriers"), RootState::Closed);
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert!(c.store.active.is_none());
    }
    c.store.close();
    c.store = reopen(&c.server);
    let image = c.store.image().expect("original authenticated state");
    assert!(image.revision == before || image.revision == before + 1);
    assert_eq!(image.entries.len(), 1);
    assert!(image.account_replacements.is_empty());
    assert_eq!(image.account_freezes.len(), 1);
    assert!(image.account_closures.len() <= 1);
    assert_eq!(
        if by_plan {
            c.store.close_account_preparation(&plan)
        } else {
            c.store.close_account_replacement(&p)
        }
        .expect("same original retry"),
        RootState::Closed
    );
    assert_eq!(c.store.image().expect("one closure").revision, before + 1);
    assert_retired(&mut c, AnchorOperation::query());
    barriers
}
#[test]
fn account_closure_witness_sync_faults_preserve_original_noncommit_and_account_freeze() {
    for by_plan in [false, true] {
        let barriers = at_cut(by_plan, 0, false);
        assert!((2..=8).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                at_cut(by_plan, cut, after);
            }
        }
        eprintln!(
            "ACCOUNT_CLOSURE_WITNESS_SYNC plan={by_plan} barriers={barriers} faults={}",
            barriers * 2
        );
    }
}
#[test]
fn account_closure_plan_proof_binds_original_expectations_both_signatures_and_purpose() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let original = plan(&mut c, &next);
    let other = root_target(&c, 200, 202);
    let changed = plan(&mut c, &other);
    assert!(c
        .store
        .closed_account_preparation_receipt(&original)
        .is_err());
    c.store
        .close_account_preparation(&original)
        .expect("explicit permanent original decision");
    let wire = c
        .store
        .closed_account_preparation_receipt(&original)
        .expect("authentic receipt");
    assert_eq!(
        c.pin
            .verify_closed_account_preparation(&original, &wire)
            .expect("original proof")
            .plan(),
        &original
    );
    assert!(c
        .pin
        .verify_closed_account_preparation(&changed, &wire)
        .is_err());
    let other_witness = required_case();
    assert!(other_witness
        .pin
        .verify_closed_account_preparation(&original, &wire)
        .is_err());
    let (body, signature) = open_envelope(&wire).expect("signed frame");
    for index in [0, q_periapt_backends::ML_DSA_65_SIG_LEN + 63] {
        let mut altered = signature.to_vec();
        *altered.get_mut(index).expect("selected signature byte") ^= 1;
        assert!(matches!(
            c.pin.verify_closed_account_preparation(
                &original,
                &envelope(body, &altered).expect("bounded signature")
            ),
            Err(Error::Authentication)
        ));
    }
    let wrong = c
        .store
        .active
        .as_ref()
        .expect("owner")
        .signer
        .sign(Purpose::AnchorAccountReplacementClosure, body)
        .expect("other purpose signature");
    assert!(matches!(
        c.pin.verify_closed_account_preparation(
            &original,
            &envelope(body, &wrong).expect("bounded frame")
        ),
        Err(Error::Authentication)
    ));
    for length in [0, 8, wire.len() - 1] {
        assert!(c
            .pin
            .verify_closed_account_preparation(
                &original,
                wire.get(..length).expect("bounded truncation")
            )
            .is_err());
    }
    let mut extra = wire;
    extra.push(0);
    assert!(c
        .pin
        .verify_closed_account_preparation(&original, &extra)
        .is_err());
}
