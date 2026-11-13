// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Staged approval without a sealed target is distinct from witness uncertainty.
use super::*;
#[path = "witness_independent_policy_unprepared_process_tests.rs"]
mod process;

fn abandon(f: &Fixture, a: &Approval) {
    let before = journal(f);
    let requests = f.carrier.requests.lock().expect("requests").len();
    let operation = a.proof.scope().operation;
    let statement = a.proof.statement_digest();
    let expected = Progress::AbandonedBeforePreparation {
        operation,
        statement,
        target: a.proof.target_policy(),
    };
    let mut owner = open(&f.c);
    assert_eq!(
        owner
            .abandon_unprepared_policy_renewal(operation, statement, f.c.policy.historical())
            .expect("unprepared abandonment"),
        expected
    );
    owner.close();
    let mut owner = open(&f.c);
    assert_eq!(
        owner.witnessed_policy_renewal_progress().expect("history"),
        Some(expected)
    );
    assert_eq!(
        owner
            .abandon_unprepared_policy_renewal(operation, statement, f.c.policy.historical())
            .expect("idempotent original result"),
        expected
    );
    owner.close();
    assert_eq!(journal(f), before);
    assert_eq!(
        f.carrier.requests.lock().expect("requests").len(),
        requests,
        "no witness assertion or request"
    );
}

#[test]
fn unprepared_policy_abandonment_needs_no_signer_or_live_policy() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    a.target.close();
    f.c.policy.close();
    fs::rename(
        &f.c.paths.signer,
        f.c.paths.signer.with_extension("retained"),
    )
    .expect("preserve signer outside active path");
    abandon(&f, &a);
    fs::rename(
        f.c.paths.signer.with_extension("retained"),
        &f.c.paths.signer,
    )
    .expect("restore same signer");
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    owner
        .witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("next operation"),
            f.c.policy.historical(),
            client,
        )
        .expect("original installation can request a new policy");
}

#[test]
fn unprepared_policy_abandonment_preserves_previous_p_and_allows_next_real_p() {
    let f = fixture();
    let first = approval(&f);
    stage(&f, &first);
    let p = prepare(&f, &first);
    approve_witness(&f, &first, p);
    operational::applied_at(&f, &first, p, 150);
    let second = operational::approved_at(&f, &first.target, 3, 400, 151);
    open(&f.c)
        .stage_policy_renewal(
            &second.proof,
            second.proof.scope().operation,
            f.c.policy.historical(),
            &second.target,
            151,
        )
        .expect("second stage");
    abandon(&f, &second);
    operational::activate(&f, &first.target, 151)
        .expect("prior real P remains active")
        .close();
    let third = operational::approved_at(&f, &first.target, 4, 500, 152);
    assert_eq!(
        third.request.scope().previous_authorization,
        Some(first.proof.statement_digest())
    );
    let p = operational::prepared_at(&f, &third, &first.target, 152);
    operational::applied_at(&f, &third, p, 152);
    operational::activate(&f, &third.target, 152)
        .expect("new actual P")
        .close();
}

fn credential(f: &Fixture) {
    use crate::enrollment::tests::witness_renewal as g;
    let proof = g::grant(f, &f.original, 2, 240);
    g::prepare(f, &proof, 170);
    let mut owner = open(&f.c);
    let mut client = g::client(f, &mut owner, 170);
    owner
        .commit_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            170,
            &mut client,
        )
        .expect("real G");
    owner.close();
    g::activate(f, 170)
        .expect("original signer/current G")
        .close();
}

#[test]
fn unprepared_policy_abandonment_composes_with_real_g_on_both_sides() {
    for before in [false, true] {
        let f = fixture();
        if before {
            credential(&f);
        }
        let now = if before { 170 } else { 150 };
        let a = operational::approved_at(&f, &f.c.policy, 2, 300, now);
        open(&f.c)
            .stage_policy_renewal(
                &a.proof,
                a.proof.scope().operation,
                f.c.policy.historical(),
                &a.target,
                now,
            )
            .expect("stage current credential");
        abandon(&f, &a);
        if !before {
            credential(&f);
        }
        let next = operational::approved_at(&f, &f.c.policy, 3, 400, 180);
        assert_ne!(
            next.request.scope().current_credential,
            next.request.scope().original_credential
        );
        let p = operational::prepared_at(&f, &next, &f.c.policy, 180);
        operational::applied_at(&f, &next, p, 180);
        operational::activate(&f, &next.target, 180)
            .expect("P after G and abandonment")
            .close();
    }
}

#[test]
fn unprepared_policy_abandonment_allows_real_roster_refresh_then_next_policy() {
    use crate::{AnchorRosterRefreshState, RosterRefreshId};
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    abandon(&f, &a);
    let mut owner = open(&f.c);
    let certificate = match owner.image().expect("original image").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("original accepted enrollment"),
    }
    .expect("original accepted enrollment");
    let roster =
        f.c.root
            .issue_roster(
                2,
                interval(),
                &[f.c.root.roster_entry(&certificate).expect("same C0")],
            )
            .expect("independent signed R2");
    let target = AccountPin::new(
        f.original.account_id(),
        f.c.intent.root.clone(),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("root-approved pin")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("same identity with new roster");
    let client = policy_client(&f, &mut owner);
    let proposal = owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("R operation"),
            f.c.policy.historical(),
            &f.c.policy,
            &target,
            150,
            client,
        )
        .expect("original R after local P abandonment");
    owner.close();
    assert_eq!(
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_roster_refresh(proposal, &f.original, &target, &f.c.policy, 150,)
            .expect("independent R preparation"),
        AnchorRosterRefreshState::Prepared
    );
    let mut owner = open(&f.c);
    let mut client = policy_client(&f, &mut owner);
    assert_eq!(
        owner
            .commit_witnessed_roster_refresh(
                &proposal,
                f.c.policy.historical(),
                &f.c.policy,
                150,
                &mut client,
            )
            .expect("real R commit"),
        AnchorRosterRefreshState::Applied
    );
    owner.close();
    abandon(&f, &a);
    let next = operational::approved_at(&f, &f.c.policy, 3, 400, 151);
    assert_eq!(next.request.scope().current_roster, roster.checkpoint());
    let p = operational::prepared_at(&f, &next, &f.c.policy, 151);
    operational::applied_at(&f, &next, p, 151);
    operational::activate(&f, &next.target, 151)
        .expect("same installation after abandonment, R and new P")
        .close();
}

#[test]
fn unprepared_policy_abandonment_rejects_wrong_identity_and_any_released_proposal() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    for (operation, statement) in [
        (
            PolicyRenewalId::generate().expect("other operation"),
            a.proof.statement_digest(),
        ),
        (a.proof.scope().operation, [99; 32]),
    ] {
        assert!(open(&f.c)
            .abandon_unprepared_policy_renewal(operation, statement, f.c.policy.historical())
            .is_err());
    }
    let p = prepare(&f, &a);
    let retained = journal(&f);
    assert!(open(&f.c)
        .abandon_unprepared_policy_renewal(p.operation(), p.statement(), f.c.policy.historical())
        .is_err());
    assert_eq!(journal(&f), retained);
    approve_witness(&f, &a, p);
    operational::applied_at(&f, &a, p, 150);
    assert!(open(&f.c)
        .abandon_unprepared_policy_renewal(p.operation(), p.statement(), f.c.policy.historical())
        .is_err());
}

#[test]
fn unprepared_policy_abandonment_rejects_sealed_target_before_enrollment_export() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    let lease = owner
        .witness_lease(&f.original, f.c.policy.historical(), f.id)
        .expect("original lease");
    let mut original = owner
        .open_original_journal(&f.original, f.c.policy.historical(), f.id, client)
        .expect("original journal");
    let materials =
        a.request
            .materials(f.c.policy.historical(), f.c.policy.historical(), &a.target);
    let proposal = original
        .prepare_policy_renewal(&a.proof, &materials, 150)
        .expect("actual sealed image before enrollment save");
    drop(original);
    drop(lease);
    owner.close();
    let retained = journal(&f);
    let mut owner = open(&f.c);
    assert!(owner
        .witnessed_policy_renewal_progress()
        .expect("no exported proposal")
        .is_none());
    assert!(matches!(
        owner.abandon_unprepared_policy_renewal(
            proposal.operation(),
            proposal.statement(),
            f.c.policy.historical()
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(journal(&f), retained);
    assert_eq!(
        open(&f.c)
            .recover_witnessed_policy_renewal_preparation(f.c.policy.historical())
            .expect("recover same proposal"),
        Some(proposal)
    );
}

#[test]
fn unprepared_policy_abandonment_recovers_before_and_after_sync_errors() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let (mut owner, _, count) = faulty(&f.c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .abandon_unprepared_policy_renewal(
            a.proof.scope().operation,
            a.proof.statement_digest(),
            f.c.policy.historical(),
        )
        .expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!(barriers > 0);
    owner.close();
    for after in [false, true] {
        for cut in 1..=barriers {
            let f = fixture();
            let a = approval(&f);
            stage(&f, &a);
            let before = journal(&f);
            let (mut owner, remaining, _) = faulty(&f.c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert!(owner
                .abandon_unprepared_policy_renewal(
                    a.proof.scope().operation,
                    a.proof.statement_digest(),
                    f.c.policy.historical()
                )
                .is_err());
            assert!(owner.active.is_none());
            abandon(&f, &a);
            assert_eq!(journal(&f), before);
        }
    }
}

#[test]
fn expired_unprepared_policy_has_no_witness_outcome() {
    let f = fixture();
    let a = approval(&f);
    stage(&f, &a);
    let original = journal(&f);
    let operation = a.proof.scope().operation;
    let statement = a.proof.statement_digest();
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    assert!(owner
        .prepare_witnessed_policy_renewal(
            f.c.policy.historical(),
            f.c.policy.historical(),
            &a.target,
            301,
            client
        )
        .is_err());
    let mut owner = open(&f.c);
    assert!(owner
        .recover_witnessed_policy_renewal_preparation(f.c.policy.historical())
        .expect("authenticated absence of local proposal")
        .is_none());
    let mut client = policy_client(&f, &mut owner);
    assert!(matches!(
        owner.close_witnessed_policy_renewal(
            operation,
            statement,
            f.c.policy.historical(),
            &mut client
        ),
        Err(DurableError::Suspended)
    ));
    let mut owner = open(&f.c);
    assert!(matches!(
        owner.resolve_policy_renewal(
            operation,
            statement,
            f.c.policy.historical(),
            a.target.historical(),
            301
        ),
        Err(DurableError::AnchorRequired)
    ));
    let mut owner = open(&f.c);
    let client = policy_client(&f, &mut owner);
    assert!(matches!(
        owner.witnessed_policy_renewal_request(
            PolicyRenewalId::generate().expect("next operation"),
            f.c.policy.historical(),
            client
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        journal(&f),
        original,
        "no sealed image or fabricated outcome"
    );
}
