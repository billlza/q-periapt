// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent-P then G witness component tests, not journal-owner acceptance.
use super::*;
use crate::VerifiedCredentialRenewal;
use crate::{AnchorCredentialRenewalProposal as GProposal, AnchorCredentialRenewalState as GState};

fn adopted(c: &mut Case) -> (VerifiedPolicyRenewal, Proposal) {
    let approval = c.approval(&c.original, None, &c.target);
    let proposal = c.proposal(&approval, c.initial, 81);
    c.prepare(proposal, &approval)
        .expect("independent P approved");
    assert_eq!(
        c.exchange(
            &proposal,
            AnchorOperation::commit_policy_renewal(&proposal),
            170
        ),
        State::Applied
    );
    assert_eq!(
        c.exchange(
            &proposal,
            AnchorOperation::acknowledge_policy_renewal(&proposal),
            170
        ),
        State::Acknowledged
    );
    (approval, proposal)
}
fn grant(c: &Case, previous: &VerifiedDevice, version: u64) -> VerifiedCredentialRenewal {
    let predecessor = c
        .account
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("same predecessor");
    let mut description = previous.description.clone();
    description.validity = Validity::new(100, 400 + version * 20).expect("successor validity");
    let successor = c
        .account
        .issue_device(description, previous.key.clone())
        .expect("new same-key certificate");
    let roster = c
        .account
        .issue_roster(
            version,
            Validity::new(100, 600).expect("current roster interval"),
            &[c.account
                .roster_entry(&successor)
                .expect("successor member")],
        )
        .expect("signed target roster");
    let pin = AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.original.family(),
    )
    .expect("independent roster pin");
    let issued = c
        .account
        .issue_credential_renewal(
            crate::CredentialRenewalMaterials {
                original_credential: &c.certificate,
                previous_credential: &predecessor,
                successor_credential: &successor,
                previous_roster: previous.roster().as_bytes(),
                successor_roster: roster.as_bytes(),
            },
            &crate::CredentialRenewalAuthorization {
                operation: crate::CredentialRenewalId::generate().expect("operation"),
                previous: previous.roster().checkpoint(),
                policy_digest: c.original.checkpoint().digest(),
            },
            &pin,
            150,
        )
        .expect("explicit root grant");
    VerifiedCredentialRenewal::verify(
        issued.as_bytes(),
        &pin,
        c.original.checkpoint().digest(),
        150,
    )
    .expect("independent grant verification")
}
fn proposal(
    c: &Case,
    a: &VerifiedPolicyRenewal,
    g: &VerifiedCredentialRenewal,
    head: AnchorHead,
) -> GProposal {
    GProposal::from_journal(
        c.pin.binding(),
        c.subject,
        g.operation(),
        g.statement_digest(),
        head,
        AnchorHead::from_trusted_state(
            head.fence(),
            head.revision() + 1,
            [u8::try_from(g.successor_device().roster().checkpoint().version()).expect("digest");
                32],
        )
        .expect("opaque component target"),
    )
    .expect("G proposal")
    .with_retained_policy_renewal(&a.historical())
    .expect("exact P")
}
fn exchange(c: &mut Case, p: &GProposal, op: AnchorOperation, now: u64) -> GState {
    let request = AnchorRequest::new(&c.pin, c.subject, op, &c.signer)
        .expect("fresh original signer request");
    let wire = c
        .store
        .handle(request.as_bytes(), now)
        .expect("witness response");
    c.pin
        .verify_reply(&request, &wire)
        .expect("signature")
        .credential_renewal_state(p)
        .expect("bound G reply")
}
fn explicit_format(c: &mut Case) {
    let image = c.store.image().expect("authenticated image");
    let key = &c.store.active.as_ref().expect("active witness").wrapping;
    let bytes = super::super::super::encode(key, &c.pin, &image).expect("encode");
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPANC019");
    super::super::super::decode(key, &c.pin, &bytes).expect("roundtrip");
    let mut old = bytes
        .get(
            ..bytes
                .len()
                .checked_sub(32)
                .expect("authenticated wire length"),
        )
        .expect("authenticated body")
        .to_vec();
    old.get_mut(..8)
        .expect("complete format tag")
        .copy_from_slice(b"QPANC018");
    let mut mac = super::super::super::authenticator(key).expect("owned test authenticator");
    mac.update(&old);
    old.extend_from_slice(&mac.finalize().into_bytes());
    assert!(
        super::super::super::decode(key, &c.pin, &old).is_err(),
        "authenticated old container cannot carry P then G"
    );
}

#[test]
fn retained_policy_credential_witness_survives_two_g_cycles_and_expired_readback() {
    let mut c = Case::new();
    let (a, p) = adopted(&mut c);
    let mut previous = c.device.clone();
    let mut head = p.target_head();
    for version in [2, 3] {
        let g = grant(&c, &previous, version);
        let proposal = proposal(&c, &a, &g, head);
        assert_eq!(proposal.policy_continuation(), None);
        assert_eq!(proposal.policy_renewal(), Some(a.statement_digest()));
        assert_eq!(proposal.transaction_statement(), g.statement_digest());
        assert!(!proposal.adopts_policy());
        assert_eq!(
            c.store
                .prepare_policy_renewed_credential_renewal(
                    proposal,
                    &g,
                    &c.original,
                    &c.target,
                    180
                )
                .expect("independent current admission"),
            GState::Prepared
        );
        explicit_format(&mut c);
        c.reopen();
        assert_eq!(
            exchange(
                &mut c,
                &proposal,
                AnchorOperation::commit_credential_renewal(&proposal),
                180
            ),
            GState::Applied
        );
        c.reopen();
        assert_eq!(
            c.store
                .close_policy_renewed_credential_renewal(
                    proposal,
                    &g,
                    &c.original,
                    c.target.historical()
                )
                .expect("close cannot erase Applied"),
            GState::Applied
        );
        assert_eq!(
            exchange(
                &mut c,
                &proposal,
                AnchorOperation::credential_renewal_status(&proposal),
                500
            ),
            GState::Applied
        );
        assert_eq!(
            exchange(
                &mut c,
                &proposal,
                AnchorOperation::acknowledge_credential_renewal(&proposal),
                500
            ),
            GState::Acknowledged
        );
        c.reopen();
        explicit_format(&mut c);
        assert_eq!(
            c.admission(
                AnchorOperation::admit_policy_renewal(
                    g.successor_device().authority_binding(),
                    a.statement_digest()
                )
                .expect("P with C next"),
                180
            ),
            AnchorOutcome::AuthorityCurrent
        );
        assert_eq!(
            c.admission(
                AnchorOperation::admit_policy_renewal(
                    previous.authority_binding(),
                    a.statement_digest()
                )
                .expect("stale C"),
                180
            ),
            AnchorOutcome::AuthorityDenied
        );
        previous = g.successor_device().clone();
        head = proposal.target_head();
    }
}

#[test]
fn retained_policy_credential_metadata_has_a_distinct_canonical_domain() {
    let mut c = Case::new();
    let (a, p) = adopted(&mut c);
    let g = grant(&c, &c.device, 2);
    let p = proposal(&c, &a, &g, p.target_head());
    let bytes = p.to_bytes();
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPCRNP03");
    assert_eq!(GProposal::from_trusted_state(&bytes).expect("roundtrip"), p);
    for mutation in [0, 1, 2] {
        let mut invalid = bytes.clone();
        match mutation {
            0 => *invalid.get_mut(296).expect("carry mode") = 1,
            1 => invalid.get_mut(297..).expect("policy statement").fill(0),
            _ => invalid.push(0),
        }
        assert!(GProposal::from_trusted_state(&invalid).is_err());
    }
    let mut t = bytes.clone();
    t.get_mut(..8)
        .expect("complete format tag")
        .copy_from_slice(b"QPCRNP02");
    let t = GProposal::from_trusted_state(&t).expect("different metadata kind");
    assert_ne!(p.binding(), t.binding());
    assert!(t.with_retained_policy_renewal(&a.historical()).is_err());
    assert!(p
        .bind_policy_expectation(a.statement_digest(), false)
        .is_err());
    let before = c.fingerprint();
    assert!(c
        .store
        .prepare_continued_credential_renewal(t, &g, &c.original, &c.target, 180)
        .is_err());
    assert!(c
        .store
        .prepare_policy_renewed_credential_renewal(t, &g, &c.original, &c.target, 180)
        .is_err());
    let mut wrong = bytes;
    *wrong.get_mut(297).expect("policy statement") ^= 1;
    let wrong = GProposal::from_trusted_state(&wrong).expect("well-formed wrong P");
    assert!(c
        .store
        .prepare_policy_renewed_credential_renewal(wrong, &g, &c.original, &c.target, 180)
        .is_err());
    assert_eq!(
        c.fingerprint(),
        before,
        "all invalid approvals leave witness untouched"
    );
}

fn cancellation(
    p: GProposal,
    a: &VerifiedPolicyRenewal,
) -> crate::AnchorCredentialRenewalCancellation {
    let mut bytes = b"QPCRNC01".to_vec();
    bytes.extend_from_slice(
        p.to_bytes()
            .get(8..248)
            .expect("original target-free fields"),
    );
    crate::AnchorCredentialRenewalCancellation::from_trusted_state(&bytes)
        .expect("original G without target")
        .with_retained_policy_renewal(&a.historical())
        .expect("exact adopted P")
}

#[test]
fn retained_policy_credential_cancel_never_erases_a_prepared_or_applied_proposal() {
    for applied in [false, true] {
        let mut c = Case::new();
        let (a, p) = adopted(&mut c);
        let g = grant(&c, &c.device, 2);
        let p = proposal(&c, &a, &g, p.target_head());
        c.store
            .prepare_policy_renewed_credential_renewal(p, &g, &c.original, &c.target, 180)
            .expect("prepare G");
        if applied {
            assert_eq!(
                exchange(
                    &mut c,
                    &p,
                    AnchorOperation::commit_credential_renewal(&p),
                    180
                ),
                GState::Applied
            );
        }
        let before = c.fingerprint();
        assert!(c
            .store
            .close_unprepared_policy_renewed_credential_renewal(
                cancellation(p, &a),
                &g,
                &c.original,
                c.target.historical()
            )
            .is_err());
        assert_eq!(
            c.fingerprint(),
            before,
            "target-free cancellation must preserve original sealed history"
        );
        let expected = if applied {
            GState::Applied
        } else {
            GState::Closed
        };
        assert_eq!(
            c.store
                .close_policy_renewed_credential_renewal(p, &g, &c.original, c.target.historical())
                .expect("historical exact close"),
            expected
        );
        c.reopen();
        assert_eq!(
            exchange(
                &mut c,
                &p,
                AnchorOperation::close_credential_renewal(&p),
                500
            ),
            expected
        );
        assert_eq!(
            exchange(
                &mut c,
                &p,
                AnchorOperation::acknowledge_credential_renewal(&p),
                500
            ),
            GState::Acknowledged
        );
        explicit_format(&mut c);
    }
}

#[test]
fn retained_policy_credential_target_free_cancel_has_exact_retirement_and_no_policy_adoption() {
    use crate::{
        AnchorCredentialCancellationState as CState,
        AnchorCredentialRenewalCancellation as Cancellation,
    };
    let mut c = Case::new();
    let (a, p) = adopted(&mut c);
    let g = grant(&c, &c.device, 2);
    let p = proposal(&c, &a, &g, p.target_head());
    let cancel = cancellation(p, &a);
    let bytes = cancel.to_bytes();
    assert_eq!(bytes.get(..8).expect("complete format tag"), b"QPCRNC03");
    assert_eq!(
        Cancellation::from_trusted_state(&bytes).expect("roundtrip"),
        cancel
    );
    assert_eq!(cancel.policy_continuation(), None);
    assert!(!cancel.adopts_policy());
    assert_eq!(cancel.transaction_statement(), g.statement_digest());
    let mut adopt = bytes.clone();
    *adopt.get_mut(248).expect("carry mode") = 1;
    assert!(Cancellation::from_trusted_state(&adopt).is_err());
    let mut t = bytes;
    t.get_mut(..8)
        .expect("complete format tag")
        .copy_from_slice(b"QPCRNC02");
    let t = Cancellation::from_trusted_state(&t).expect("distinct T metadata");
    assert_ne!(cancel.binding(), t.binding());
    assert!(t.with_retained_policy_renewal(&a.historical()).is_err());
    let before = c.fingerprint();
    assert!(c
        .store
        .close_unprepared_credential_renewal(cancel, &g, &c.original)
        .is_err());
    assert!(c
        .store
        .close_unprepared_policy_renewed_credential_renewal(
            t,
            &g,
            &c.original,
            c.target.historical()
        )
        .is_err());
    assert_eq!(c.fingerprint(), before);
    for attempt in 0..2 {
        assert_eq!(
            c.store
                .close_unprepared_policy_renewed_credential_renewal(
                    cancel,
                    &g,
                    &c.original,
                    c.target.historical()
                )
                .expect("exact cancellation"),
            CState::Closed
        );
        if attempt == 0 {
            c.reopen();
        }
    }
    explicit_format(&mut c);
    for (op, expected) in [
        (
            AnchorOperation::credential_cancellation_status(&cancel),
            CState::Closed,
        ),
        (
            AnchorOperation::acknowledge_credential_cancellation(&cancel),
            CState::Acknowledged,
        ),
    ] {
        let rq = AnchorRequest::new(&c.pin, c.subject, op, &c.signer)
            .expect("signed original cancellation");
        let wire = c
            .store
            .handle(rq.as_bytes(), 500)
            .expect("historical response");
        let state = c
            .pin
            .verify_reply(&rq, &wire)
            .expect("witness signature")
            .credential_cancellation_state(&cancel)
            .expect("exact result");
        assert_eq!(state, expected);
    }
    c.reopen();
    explicit_format(&mut c);
    assert!(
        c.store
            .prepare_policy_renewed_credential_renewal(p, &g, &c.original, &c.target, 180)
            .is_err(),
        "retired target cannot reenter"
    );
    assert_eq!(
        c.admission(
            AnchorOperation::admit_policy_renewal(
                c.device.authority_binding(),
                a.statement_digest()
            )
            .expect("original C under retained P"),
            180
        ),
        AnchorOutcome::AuthorityCurrent
    );
}

#[test]
fn retained_policy_credential_requires_acknowledged_exact_live_policy() {
    let mut c = Case::new();
    let a = c.approval(&c.original, None, &c.target);
    let p = c.proposal(&a, c.initial, 84);
    c.prepare(p, &a).expect("P prepared");
    let g = grant(&c, &c.device, 2);
    for head in [p.expected_head(), p.target_head()] {
        if head == p.target_head() {
            assert_eq!(
                c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170),
                State::Applied
            );
        }
        let proposal = proposal(&c, &a, &g, head);
        let before = c.fingerprint();
        assert!(c
            .store
            .prepare_policy_renewed_credential_renewal(proposal, &g, &c.original, &c.target, 180)
            .is_err());
        assert_eq!(before, c.fingerprint(), "G cannot race unretired P");
    }
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 170),
        State::Acknowledged
    );
    let proposal = proposal(&c, &a, &g, p.target_head());
    let before = c.fingerprint();
    assert!(
        c.store
            .prepare_policy_renewed_credential_renewal(proposal, &g, &c.original, &c.target, 260)
            .is_err(),
        "P expiry closes fresh admission"
    );
    assert_eq!(before, c.fingerprint());
    assert_eq!(
        c.store
            .close_policy_renewed_credential_renewal(
                proposal,
                &g,
                &c.original,
                c.target.historical()
            )
            .expect("historical close remains available"),
        GState::Closed
    );
}

#[path = "credential_cycle_crash_tests.rs"]
mod crash;

#[test]
fn retained_policy_credential_composes_with_the_next_independent_policy_after_expiry() {
    let mut c = Case::new();
    let (a, p) = adopted(&mut c);
    let first = grant(&c, &c.device, 2);
    let p1 = proposal(&c, &a, &first, p.target_head());
    c.store
        .prepare_policy_renewed_credential_renewal(p1, &first, &c.original, &c.target, 180)
        .expect("first G");
    assert_eq!(
        exchange(
            &mut c,
            &p1,
            AnchorOperation::commit_credential_renewal(&p1),
            180
        ),
        GState::Applied
    );
    assert_eq!(
        exchange(
            &mut c,
            &p1,
            AnchorOperation::acknowledge_credential_renewal(&p1),
            180
        ),
        GState::Acknowledged
    );
    let p2 = policy(&c.issuer, &c.runtime, &c.pin, 3, 550, 270);
    let mut scope = a.scope().clone();
    scope.operation = PolicyRenewalId::generate().expect("next independent operation");
    scope.previous_policy = c.target.checkpoint();
    scope.previous_authorization = Some(a.statement_digest());
    scope.current_credential = first.successor_device().credential_digest();
    scope.current_roster = first.successor_device().roster().checkpoint();
    let materials = PolicyRenewalMaterials {
        original: &c.original,
        previous: c.target.historical(),
        target: &p2,
        original_device: &c.device,
        current_device: first.successor_device(),
    };
    let statement =
        PolicyRenewalStatement::new(&scope, &materials, 270).expect("P2 after real P1 expiry");
    let a2 = VerifiedPolicyRenewal::verify(
        &c.account
            .approve_policy_renewal(&statement)
            .expect("account approval"),
        &c.issuer
            .approve_policy_renewal(&statement)
            .expect("independent policy approval"),
        &scope,
        &materials,
        270,
    )
    .expect("P2 proof");
    let p = c.proposal(&a2, p1.target_head(), 97);
    assert_eq!(
        c.store
            .prepare_policy_renewal(p, &a2, &materials, 270)
            .expect("P2 original subject, current C1"),
        State::Prepared
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 270),
        State::Applied
    );
    assert_eq!(
        c.exchange(&p, AnchorOperation::acknowledge_policy_renewal(&p), 270),
        State::Acknowledged
    );
    c.reopen();
    explicit_format(&mut c);
    let second = grant(&c, first.successor_device(), 3);
    let p = proposal(&c, &a2, &second, p.target_head());
    assert!(
        first
            .successor_device()
            .description
            .validity
            .check(440)
            .is_err(),
        "C1 has expired"
    );
    assert!(
        c.device.description.validity.check(440).is_err(),
        "C0 has expired"
    );
    assert_eq!(
        c.store
            .prepare_policy_renewed_credential_renewal(p, &second, &c.original, &p2, 440)
            .expect("G2 under exact P2"),
        GState::Prepared
    );
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::commit_credential_renewal(&p),
            440
        ),
        GState::Applied
    );
    assert_eq!(
        exchange(
            &mut c,
            &p,
            AnchorOperation::acknowledge_credential_renewal(&p),
            440
        ),
        GState::Acknowledged
    );
    c.reopen();
    assert_eq!(
        c.admission(
            AnchorOperation::admit_policy_renewal(
                second.successor_device().authority_binding(),
                a2.statement_digest()
            )
            .expect("C2/P2"),
            440
        ),
        AnchorOutcome::AuthorityCurrent
    );
    assert_eq!(
        c.admission(
            AnchorOperation::admit_policy_renewal(
                second.successor_device().authority_binding(),
                a.statement_digest()
            )
            .expect("wrong old P"),
            440
        ),
        AnchorOutcome::AuthorityDenied
    );
}
