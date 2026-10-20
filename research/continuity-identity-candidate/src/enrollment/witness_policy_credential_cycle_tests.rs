// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual original enrollment/journal/witness cycles after independent policy adoption.
use super::*;
use crate::{AnchorCredentialRenewalProposal as GProposal, CredentialRenewalStatus as GStatus};

fn credential_target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("exact G intent");
    assert_eq!(pending.get(..8), Some(b"QPWINT08".as_slice()));
    pending
        .get(253..pending.len().checked_sub(32).expect("MAC"))
        .expect("actual sealed G target")
        .to_vec()
}
fn adopted() -> (Fixture, Approval) {
    let f = fixture();
    let a = approved_at(&f, &f.c.policy, 2, 300, 155);
    let p = prepared_at(&f, &a, &f.c.policy, 155);
    applied_at(&f, &a, p, 155);
    activate(&f, &a.target, 155)
        .expect("original P active")
        .close();
    (f, a)
}
fn stage_g(f: &Fixture, a: &Approval, g: &crate::VerifiedCredentialRenewal) {
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(g, g.operation(), &a.target, 180)
        .expect("original G staged");
    owner.close();
}
fn prepared_g(f: &Fixture, a: &Approval, g: &crate::VerifiedCredentialRenewal) -> GProposal {
    stage_g(f, a, g);
    let mut owner = open(&f.c);
    let client = credential::client(f, &mut owner, 180);
    let p = owner
        .prepare_witnessed_policy_continuation(f.c.policy.historical(), &a.target, 180, client)
        .expect("actual sealed original G target");
    owner.close();
    f.carrier.clock.store(180, Ordering::SeqCst);
    f.carrier
        .store
        .lock()
        .expect("store")
        .prepare_policy_renewed_credential_renewal(p, g, f.c.policy.historical(), &a.target, 180)
        .expect("independent approval");
    p
}
fn committed_g(f: &Fixture, a: &Approval, g: &crate::VerifiedCredentialRenewal, p: GProposal) {
    let mut owner = open(&f.c);
    let mut client = credential::client(f, &mut owner, 180);
    assert_eq!(
        owner
            .commit_witnessed_policy_continuation(
                &p,
                f.c.policy.historical(),
                &a.target,
                180,
                &mut client
            )
            .expect("durable original commit"),
        renewal::committed(g)
    );
    owner.close();
}

#[test]
fn required_policy_credential_cycle_preserves_original_receipts_across_commit_and_ack_loss() {
    for (opcode, processed) in [(5, false), (5, true), (8, false), (8, true)] {
        let (f, a) = adopted();
        let g = credential::grant(&f, &f.original, 2, 280);
        let p = prepared_g(&f, &a, &g);
        let pending = journal(&f);
        assert!(
            activate(&f, &a.target, 180).is_err(),
            "unresolved G cannot release an owner"
        );
        *f.carrier.cut.lock().expect("cut") = Some((opcode, processed));
        let mut owner = open(&f.c);
        let mut client = credential::client(&f, &mut owner, 180);
        assert!(owner
            .commit_witnessed_policy_continuation(
                &p,
                f.c.policy.historical(),
                &a.target,
                180,
                &mut client
            )
            .is_err());
        assert!(owner.active.is_none());
        let mut owner = open(&f.c);
        let mut client = credential::client(&f, &mut owner, 500);
        let outcome = owner
            .close_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                500,
                &mut client,
            )
            .expect("historical exact close preserves commit");
        let applied = opcode != 5 || processed;
        if applied {
            assert_eq!(outcome, renewal::committed(&g));
        } else {
            assert!(
                matches!(outcome,GStatus::Closed{operation,statement,..} if operation==g.operation() && statement==g.statement_digest())
            );
        }
        assert_eq!(
            owner
                .reconcile_witnessed_credential_renewal(
                    g.operation(),
                    g.statement_digest(),
                    &f.c.policy,
                    500,
                    &mut client
                )
                .expect("same original historical retry"),
            outcome
        );
        owner.close();
        assert_eq!(
            journal(&f),
            (
                if applied {
                    credential_target(&pending)
                } else {
                    pending.0
                },
                None
            )
        );
        if applied {
            let mut active = activate(&f, &a.target, 180).expect("committed C1 with unchanged P");
            assert_eq!(
                active.parts().expect("owners").2.credential_digest(),
                g.successor_device().credential_digest()
            );
            active.close();
        } else {
            assert!(
                activate(&f, &a.target, 180).is_err(),
                "C0 remains expired; close cannot create live C1"
            );
        }
    }
}

#[test]
fn required_policy_credential_cycle_target_free_cancellation_retires_only_the_original_g() {
    let (f, a) = adopted();
    let g = credential::grant(&f, &f.original, 2, 280);
    stage_g(&f, &a, &g);
    let before = journal(&f);
    let mut owner = open(&f.c);
    let c = owner
        .prepare_witnessed_credential_cancellation(&f.c.policy, 500)
        .expect("target-free original cancellation with completed P");
    assert_eq!(c.policy_renewal(), Some(a.proof.statement_digest()));
    owner.close();
    assert_eq!(
        journal(&f).0,
        before.0,
        "cancellation does not create a target image"
    );
    f.carrier
        .store
        .lock()
        .expect("witness")
        .close_unprepared_policy_renewed_credential_renewal(
            c,
            &g,
            f.c.policy.historical(),
            a.target.historical(),
        )
        .expect("independent cancellation");
    let mut owner = open(&f.c);
    let mut client = credential::client(&f, &mut owner, 500);
    assert!(
        matches!(owner.reconcile_witnessed_credential_renewal(g.operation(),g.statement_digest(),&f.c.policy,500,&mut client).expect("original durable closed terminal"),GStatus::Closed{operation,statement,..} if operation==g.operation() && statement==g.statement_digest())
    );
    owner.close();
    assert_eq!(journal(&f), (before.0, None));
    let mut owner = open(&f.c);
    assert!(
        owner
            .stage_credential_renewal(&g, g.operation(), &a.target, 180)
            .is_err(),
        "retired operation cannot reenter"
    );
    let next = credential::grant(&f, &f.original, 3, 320);
    let p = prepared_g(&f, &a, &next);
    committed_g(&f, &a, &next, p);
    let mut active =
        activate(&f, &a.target, 180).expect("fresh higher-version G after cancellation retains P1");
    assert_eq!(
        active.parts().expect("owners").2.credential_digest(),
        next.successor_device().credential_digest()
    );
    active.close();
}

#[test]
fn required_policy_credential_cycle_supports_next_policy_and_next_g_from_actual_current_identity() {
    let (f, a) = adopted();
    let g = credential::grant(&f, &f.original, 2, 280);
    let p = prepared_g(&f, &a, &g);
    committed_g(&f, &a, &g, p);
    let a2 = approved_at(&f, &a.target, 3, 400, 180);
    assert_eq!(
        a2.request.current_device().credential_digest(),
        g.successor_device().credential_digest()
    );
    assert_eq!(
        a2.request.scope().previous_authorization,
        Some(a.proof.statement_digest())
    );
    let p2 = prepared_at(&f, &a2, &a.target, 180);
    applied_at(&f, &a2, p2, 180);
    let g2 = credential::grant(&f, g.successor_device(), 3, 350);
    let p3 = prepared_g(&f, &a2, &g2);
    committed_g(&f, &a2, &g2, p3);
    let mut active = activate(&f, &a2.target, 180).expect("same original owner after P1 G1 P2 G2");
    let (service, _, device) = active.parts().expect("owners");
    assert_eq!(
        device.credential_digest(),
        g2.successor_device().credential_digest()
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
    active.close();
}

#[path = "witness_policy_credential_cycle_process_tests.rs"]
mod process;

#[test]
fn required_policy_credential_cycle_authenticated_old_enrollment_format_cannot_claim_new_order() {
    use crate::enrollment::tests::policy_renewal::{replace_authenticated, row};
    let (f, a) = adopted();
    let g = credential::grant(&f, &f.original, 2, 280);
    let p = prepared_g(&f, &a, &g);
    let mut owner = open(&f.c);
    let bytes = row(&owner);
    owner.close();
    assert_eq!(bytes.get(..8), Some(b"QPENST18".as_slice()));
    let mut old = bytes.clone();
    old.drain(..8);
    let before = journal(&f);
    replace_authenticated(&f.c, &old);
    assert!(DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err());
    assert_eq!(
        journal(&f),
        before,
        "authenticated container downgrade does not touch original journal"
    );
    replace_authenticated(&f.c, &bytes);
    committed_g(&f, &a, &g, p);
    activate(&f, &a.target, 180)
        .expect("original bytes remain recoverable")
        .close();
}

#[path = "witness_policy_credential_cycle_retirement_tests.rs"]
mod retirement;
#[path = "witness_credential_roster_tests.rs"]
mod roster;

#[test]
fn required_policy_credential_cycle_closed_g_with_live_predecessor_allows_next_independent_policy()
{
    let (f, a) = adopted();
    let g = credential::grant(&f, &f.original, 2, 280);
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(&g, g.operation(), &a.target, 155)
        .expect("stage G while C0 is live");
    let client = credential::client(&f, &mut owner, 155);
    let p = owner
        .prepare_witnessed_policy_continuation(f.c.policy.historical(), &a.target, 155, client)
        .expect("original preparation");
    f.carrier.clock.store(155, Ordering::SeqCst);
    f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_policy_renewed_credential_renewal(p, &g, f.c.policy.historical(), &a.target, 155)
        .expect("independent preparation");
    let mut client = credential::client(&f, &mut owner, 155);
    assert!(matches!(
        owner
            .close_witnessed_credential_renewal(
                g.operation(),
                g.statement_digest(),
                &f.c.policy,
                155,
                &mut client
            )
            .expect("durable Closed then ACK"),
        GStatus::Closed { .. }
    ));
    owner.close();
    let a2 = approved_at(&f, &a.target, 3, 400, 156);
    assert_eq!(
        a2.request.current_device().credential_digest(),
        f.original.credential_digest()
    );
    let p2 = prepared_at(&f, &a2, &a.target, 156);
    applied_at(&f, &a2, p2, 156);
    let mut active =
        activate(&f, &a2.target, 156).expect("next policy with still-live original credential");
    assert_eq!(
        active.parts().expect("owners").2.credential_digest(),
        f.original.credential_digest()
    );
    active.close();
    assert!(
        matches!(open(&f.c).credential_renewal_status().expect("closed G retained"),GStatus::Closed{operation,statement,..} if operation==g.operation() && statement==g.statement_digest())
    );
}
