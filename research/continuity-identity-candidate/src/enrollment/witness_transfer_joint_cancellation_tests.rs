// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::enrollment::tests::witness_handoff::transfer::Transfer;

#[test]
fn transferred_cancellation_keeps_joint_g_t_statement_after_expiry() {
    cancel(false);
}
#[test]
fn transferred_cancellation_keeps_previously_adopted_t_and_exact_later_g() {
    cancel(true);
}

fn cancel(continued: bool) {
    let f = fixture_with_policy_expiry(Some(160));
    let first = grant(&f, &f.original, 2, 180);
    let policy = super::super::super::super::policy_continuation::policy(&f.c, 2, 190, 170);
    let scope = super::super::super::super::policy_continuation::scope(&f.c, &first, f.id);
    let joint = super::super::super::super::policy_continuation::joint(
        &f.c,
        &first,
        &scope,
        &f.c.policy,
        &policy,
    );
    let g = if continued {
        let proposal = prepare_policy(&f, &first, Some(&joint), &policy);
        let mut owner = open(&f.c);
        let mut carrier = client(&f, &mut owner, 170);
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                f.c.policy.historical(),
                &policy,
                170,
                &mut carrier,
            )
            .expect("actual earlier G/T adoption");
        owner.close();
        let next = grant(&f, first.successor_device(), 3, 220);
        open(&f.c)
            .stage_credential_renewal(&next, next.operation(), &policy, 170)
            .expect("later G under retained T");
        next
    } else {
        open(&f.c)
            .stage_policy_continuation(&first, &joint, first.operation(), &policy, 170)
            .expect("original staged G/T");
        first
    };
    let subject =
        crate::AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
    let transfer = Transfer::new(
        &mut f.carrier.store.lock().expect("source"),
        &f.c,
        &f.original,
        g.previous_device(),
        if continued {
            policy.historical()
        } else {
            f.c.policy.historical()
        },
        subject,
        175,
    );
    transfer.adopt_parent(&f.c, 180).close();
    let before = disk(&f);
    policy.close();
    f.c.policy.close();
    let mut owner = open(&f.c);
    let cancellation = owner
        .prepare_witnessed_credential_cancellation_with_witness_plan(
            f.c.policy.historical(),
            transfer.plan.clone(),
            250,
        )
        .expect("historical exact local cancellation");
    assert_eq!(cancellation.adopts_policy(), !continued);
    assert_eq!(
        cancellation.policy_continuation(),
        Some(joint.statement_digest())
    );
    assert_eq!(cancellation.operation(), g.operation());
    assert_eq!(
        cancellation.transaction_statement(),
        if continued {
            g.statement_digest()
        } else {
            joint.statement_digest()
        }
    );
    assert!(disk(&f).0 == before.0);
    assert_eq!(
        disk(&f).1.as_ref().expect("G/T cancellation").get(..8),
        Some(b"QPWINT05".as_slice())
    );
    assert_eq!(transfer.requests.load(Ordering::SeqCst), 0);
    {
        let mut target = transfer.target.lock().expect("target");
        let mut control = target
            .transferred_control(&transfer.control)
            .expect("exact target approval");
        assert!(
            control
                .close_unprepared_credential_renewal(
                    cancellation,
                    g.historical(),
                    f.c.policy.historical()
                )
                .is_err(),
            "cannot discard T binding"
        );
        let state = if continued {
            control.close_unprepared_continued_credential_renewal(
                cancellation,
                g.historical(),
                f.c.policy.historical(),
                &joint.historical(),
                policy.historical(),
            )
        } else {
            control.close_unprepared_policy_continuation(
                cancellation,
                &joint.historical(),
                &HistoricalPolicyContinuationMaterials {
                    original: f.c.policy.historical(),
                    previous: f.c.policy.historical(),
                    target: policy.historical(),
                    credential: g.historical(),
                },
            )
        }
        .expect("independent historical exact closure");
        assert_eq!(state, State::Closed);
    }
    transfer.reopen_target();
    transfer.set_time(250);
    let mut carrier = transfer.client(&mut owner, &f.c);
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                g.operation(),
                cancellation.transaction_statement(),
                f.c.policy.historical(),
                250,
                &mut carrier
            )
            .expect("original closed terminal and ACK"),
        CredentialRenewalStatus::Closed {
            operation: g.operation(),
            statement: cancellation.transaction_statement(),
            target: g.successor_device().roster().checkpoint()
        }
    );
    owner.close();
    assert!(disk(&f) == before);
    assert!(transfer
        .target
        .lock()
        .expect("target")
        .transferred_control(&transfer.control)
        .expect("same control")
        .close_unprepared_credential_renewal(cancellation, g.historical(), f.c.policy.historical())
        .is_err());
}
