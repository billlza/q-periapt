// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "account_closure_tests/recovery.rs"]
mod recovery;
#[test]
fn account_closure_permanently_denies_original_operation_and_conflicting_id_reuse() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let other = root_target(&c, 200, 202);
    let p = root_proposal(&mut c, &next, 180);
    let changed = root_proposal(&mut c, &other, 180);
    assert!(matches!(
        c.store.closed_account_replacement(&p),
        Err(DurableError::Absent)
    ));
    let before = c.store.image().expect("original image").revision;
    assert_eq!(
        c.store
            .close_account_replacement(&p)
            .expect("explicit durable original non-commit"),
        RootState::Closed
    );
    assert_eq!(c.store.image().expect("closed image").revision, before + 1);
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("exact terminal status"),
        RootState::Closed
    );
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("closed original cannot commit"),
        RootState::Closed
    );
    assert!(matches!(
        root_commit(&mut c, &changed, &other, 150),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.close_account_replacement(&changed),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.account_root_replacement_status(&changed),
        Err(DurableError::Conflict)
    ));
    let live = request(&c, AnchorOperation::query());
    assert_eq!(
        apply_request(&mut c, &live).outcome(),
        AnchorOutcome::Current,
        "closing one proposal does not retire its whole account"
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .close_account_replacement(&p)
            .expect("same original retry"),
        RootState::Closed
    );
    assert_eq!(
        root_commit(&mut c, &p, &next, 250).expect("historical close survives target expiry"),
        RootState::Closed
    );
    let image = c.store.image().expect("original non-commit persists");
    assert_eq!(image.revision, before + 1);
    assert_eq!(image.entries.len(), 1);
    assert!(image.account_replacements.is_empty());
    let active = c.store.active.as_ref().expect("original owner");
    let bytes =
        encode(&active.wrapping, &active.pin, &image).expect("canonical authenticated close image");
    assert_eq!(bytes.get(..8).expect("format tag"), b"QPANC017");
}
#[test]
fn account_closure_never_rewrites_committed_winner_and_can_close_a_competing_original() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let other = root_target(&c, 200, 202);
    let winner = root_proposal(&mut c, &next, 180);
    let losing = root_proposal(&mut c, &other, 181);
    assert_eq!(
        root_commit(&mut c, &winner, &next, 150).expect("actual winner commit"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .close_account_replacement(&winner)
            .expect("committed always wins over attempted close"),
        RootState::Committed
    );
    assert!(c.store.closed_account_replacement_receipt(&winner).is_err());
    assert_eq!(
        c.store
            .close_account_replacement(&losing)
            .expect("terminal non-commit of losing operation"),
        RootState::Closed
    );
    assert_eq!(
        root_commit(&mut c, &losing, &other, 150).expect("losing operation remains closed"),
        RootState::Closed
    );
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .close_account_replacement(&winner)
            .expect("original winner retained after reopen"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .close_account_replacement(&losing)
            .expect("original losing operation retained"),
        RootState::Closed
    );
    assert!(c.store.closed_account_replacement(&winner).is_err());
    let mut image = c.store.image().expect("original image");
    image.account_closures.insert(
        *winner.operation().as_bytes(),
        crate::anchor::store::account_replacement::closure::ClosureRecord::Exact(
            winner.binding().expect("proposal commitment"),
        ),
    );
    let active = c.store.active.as_ref().expect("original owner");
    assert!(
        matches!(
            encode(&active.wrapping, &active.pin, &image),
            Err(DurableError::Corrupt)
        ),
        "one operation cannot be both closed and committed"
    );
}
#[test]
fn account_closure_proof_requires_exact_proposal_witness_and_distinct_signature_purpose() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let p = root_proposal(&mut c, &next, 180);
    let other = root_proposal(&mut c, &next, 181);
    c.store
        .close_account_replacement(&p)
        .expect("original terminal decision");
    let wire = c
        .store
        .closed_account_replacement_receipt(&p)
        .expect("signed original non-commit");
    assert_eq!(wire.len(), 3449);
    assert_eq!(
        c.pin
            .verify_closed_account_replacement(&p, &wire)
            .expect("authenticated original proof")
            .proposal(),
        &p
    );
    assert!(c
        .pin
        .verify_closed_account_replacement(&other, &wire)
        .is_err());
    assert!(c.pin.verify_retired_account(&p, &wire).is_err());
    let request = request(&c, AnchorOperation::query());
    assert!(c.pin.verify_reply(&request, &wire).is_err());
    let other_witness = required_case();
    assert!(other_witness
        .pin
        .verify_closed_account_replacement(&p, &wire)
        .is_err());
    let (body, signature) = open_envelope(&wire).expect("exact signed frame");
    for index in [0, q_periapt_backends::ML_DSA_65_SIG_LEN + 63] {
        let mut damaged = signature.to_vec();
        *damaged
            .get_mut(index)
            .expect("selected signature component") ^= 1;
        assert!(matches!(
            c.pin.verify_closed_account_replacement(
                &p,
                &envelope(body, &damaged).expect("bounded signature frame")
            ),
            Err(Error::Authentication)
        ));
    }
    let wrong = c
        .store
        .active
        .as_ref()
        .expect("original signer")
        .signer
        .sign(Purpose::AnchorAccountRetirement, body)
        .expect("different purpose signature");
    assert!(matches!(
        c.pin
            .verify_closed_account_replacement(&p, &envelope(body, &wrong).expect("bounded frame")),
        Err(Error::Authentication)
    ));
    for length in [0, 8, wire.len() - 1] {
        assert!(c
            .pin
            .verify_closed_account_replacement(&p, wire.get(..length).expect("bounded truncation"))
            .is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(c.pin.verify_closed_account_replacement(&p, &extra).is_err());
}
