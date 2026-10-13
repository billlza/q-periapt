// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Required G and independent P keep original ownership and current authority apart.
use super::*;
use crate::enrollment::tests::witness_renewal as credential;

pub(super) fn completed_g(f: &Fixture, at: u64) -> crate::VerifiedCredentialRenewal {
    let first = credential::grant(f, &f.original, 2, 240);
    credential::prepare(f, &first, at);
    let mut owner = open(&f.c);
    let mut client = credential::client(f, &mut owner, at);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                first.operation(),
                first.statement_digest(),
                &f.c.policy,
                at,
                &mut client,
            )
            .expect("original G terminal, ACK and cleanup"),
        renewal::committed(&first)
    );
    owner.close();
    first
}

#[test]
fn required_policy_after_committed_credential_uses_actual_successor_and_original_journal() {
    let f = fixture();
    let first = completed_g(&f, 170);
    credential::activate(&f, 170).expect("G active").close();
    let prior = journal(&f);
    let a = approved_at(&f, &f.c.policy, 2, 300, 170);
    assert_eq!(a.request.scope().journal, f.id);
    assert_eq!(
        a.request.original_device().credential_digest(),
        f.original.credential_digest()
    );
    assert_eq!(
        a.request.current_device().credential_digest(),
        first.successor_device().credential_digest()
    );
    assert_eq!(
        a.request.scope().current_roster,
        first.successor_device().roster().checkpoint()
    );
    assert_eq!(journal(&f), prior, "request grants no policy permission");
    let proposal = prepared_at(&f, &a, &f.c.policy, 170);
    applied_at(&f, &a, proposal, 170);
    let committed = journal(&f);
    let mut active = activate(&f, &a.target, 170).expect("same owner under C1 and P1");
    let (service, signer, device) = active.parts().expect("current owners");
    assert_eq!(
        device.credential_digest(),
        first.successor_device().credential_digest()
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("journal"),
        f.id
    );
    signer
        .check_device(device)
        .expect("same original signing key");
    active.close();
    assert_eq!(
        journal(&f),
        committed,
        "activation does not rewrite original receipt"
    );
}

#[test]
fn required_policy_after_g_preserves_actual_outcome_across_commit_and_ack_loss() {
    for (opcode, processed) in [(11, false), (11, true), (14, false), (14, true)] {
        let f = fixture();
        completed_g(&f, 170);
        let a = approved_at(&f, &f.c.policy, 2, 300, 170);
        let p = prepared_at(&f, &a, &f.c.policy, 170);
        let sealed = journal(&f);
        *f.carrier.cut.lock().expect("cut") = Some((opcode, processed));
        let mut owner = open(&f.c);
        let mut client = policy_client(&f, &mut owner);
        assert!(owner
            .commit_witnessed_policy_renewal(
                &p,
                f.c.policy.historical(),
                &a.target,
                170,
                &mut client
            )
            .is_err());
        assert!(owner.active.is_none());
        let mut owner = open(&f.c);
        let mut client = policy_client(&f, &mut owner);
        let expected = if opcode == 11 && !processed {
            State::Closed
        } else {
            State::Applied
        };
        assert_eq!(
            owner
                .close_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    f.c.policy.historical(),
                    &mut client
                )
                .expect("original close preserves an actual commit"),
            expected
        );
        assert_eq!(
            owner
                .reconcile_witnessed_policy_renewal(
                    p.operation(),
                    p.statement(),
                    f.c.policy.historical(),
                    &mut client
                )
                .expect("same exact terminal retry"),
            expected
        );
        owner.close();
        assert_eq!(
            journal(&f),
            (
                if expected == State::Applied {
                    target(&sealed)
                } else {
                    sealed.0
                },
                None
            )
        );
        if expected == State::Applied {
            activate(&f, &a.target, 170)
                .expect("P active with C1")
                .close();
            let next = approved_at(&f, &a.target, 3, 400, 180);
            assert_eq!(next.request.scope().previous_policy, a.target.checkpoint());
            assert_eq!(
                next.request.scope().previous_authorization,
                Some(a.proof.statement_digest())
            );
            assert_eq!(
                next.request.current_device().credential_digest(),
                a.request.current_device().credential_digest()
            );
        } else {
            credential::activate(&f, 170)
                .expect("closed P did not revoke committed G")
                .close();
            assert!(activate(&f, &a.target, 170).is_err());
        }
    }
}

#[test]
fn required_policy_never_uses_a_pending_g_or_a_pre_g_approval() {
    let f = fixture();
    let stale = approval(&f);
    let first = credential::grant(&f, &f.original, 2, 240);
    credential::prepare(&f, &first, 170);
    let mut owner = open(&f.c);
    assert!(owner
        .policy_renewal_anchor_client(
            f.c.policy.historical(),
            f.pin.clone(),
            Box::new(f.carrier.clone()),
            Duration::from_secs(3)
        )
        .is_err());
    assert!(owner.active.is_none());
    let mut owner = open(&f.c);
    let mut client = credential::client(&f, &mut owner, 170);
    owner
        .commit_witnessed_credential_renewal(
            first.operation(),
            first.statement_digest(),
            &f.c.policy,
            170,
            &mut client,
        )
        .expect("finish original G");
    owner.close();
    let before = journal(&f);
    let mut owner = open(&f.c);
    assert!(owner
        .stage_policy_renewal(
            &stale.proof,
            stale.proof.scope().operation,
            f.c.policy.historical(),
            &stale.target,
            170
        )
        .is_err());
    assert!(owner.active.is_none());
    assert_eq!(journal(&f), before);
    credential::activate(&f, 170)
        .expect("stale approval did not change G")
        .close();
}

#[test]
fn required_policy_after_g_does_not_revive_stale_or_revoked_membership() {
    for witness_only in [true, false] {
        let f = fixture();
        let first = completed_g(&f, 170);
        let a = approved_at(&f, &f.c.policy, 2, 300, 170);
        let p = prepared_at(&f, &a, &f.c.policy, 170);
        applied_at(&f, &a, p, 170);
        let mut owner = open(&f.c);
        let image = owner.image().expect("authenticated original enrollment");
        let certificate = match image.phase {
            Phase::Accepted { admission, .. } => Ok(admission.certificate),
            _ => Err("original accepted registration"),
        }
        .expect("authenticated accepted registration");
        let entries = if witness_only {
            vec![f.c.root.roster_entry(&certificate).expect("C1 member")]
        } else {
            Vec::new()
        };
        let roster =
            f.c.root
                .issue_roster(3, interval(), &entries)
                .expect("independent R3");
        let pin = AccountPin::new(
            f.original.account_id(),
            f.c.intent.root.clone(),
            roster.checkpoint(),
            a.target.family(),
        )
        .expect("independent pin");
        if witness_only {
            let next = pin
                .verify_device(&certificate, roster.as_bytes(), 170)
                .expect("current C1/R3");
            f.carrier
                .store
                .lock()
                .expect("witness")
                .update_roster_authority(
                    p.subject(),
                    first.successor_device().roster().checkpoint(),
                    &next,
                    &a.target,
                    170,
                )
                .expect("actual witness head update");
            owner.close();
        } else {
            let current = pin
                .verify_roster(roster.as_bytes(), 170)
                .expect("actual revocation");
            let client = policy_client(&f, &mut owner);
            let mut journal = DeviceJournal::open_anchored_retained(
                f.c.paths.installation.files()[1],
                owner.key().expect("key"),
                &f.original,
                f.c.policy.historical(),
                f.id,
                client,
            )
            .expect("original journal");
            journal
                .install_roster(&current, 170)
                .expect("durable revocation");
            journal.close();
            owner.close();
        }
        assert!(
            activate(&f, &a.target, 170).is_err(),
            "P cannot supersede current membership or witness authority"
        );
        assert!(
            matches!(open(&f.c).policy_renewal_status().expect("read original historical completion"), crate::PolicyRenewalStatus::Committed { operation, statement, .. } if operation == p.operation() && statement == p.statement())
        );
    }
}
