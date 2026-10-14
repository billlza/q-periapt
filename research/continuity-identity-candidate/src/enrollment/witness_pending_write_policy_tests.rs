// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ordinary pending recovery must retain the original independent P completion.
use super::super::super::recovery_renewal::{
    pending_write_recovery::{confirm, retain},
    session,
};
use super::*;
use crate::AnchorPendingWriteRecoveryProposal;

#[test]
fn public_pending_write_recovery_preserves_independent_policy_completion() {
    for expired in [false, true] {
        for applied in [false, true] {
            let (f, id) = session(fixture_with_policy_expiry(Some(160)));
            let a = approved_at(&f, &f.c.policy, 2, if expired { 169 } else { 220 }, 155);
            let p = prepared_at(&f, &a, &f.c.policy, 155);
            let bound = journal(&f);
            assert!(
                matches!(
                    open(&f.c).pending_write_recovery_request(f.c.policy.historical(), &f.pin),
                    Err(DurableError::Suspended)
                ),
                "bound P intent is not ordinary recovery"
            );
            assert_eq!(journal(&f), bound);
            applied_at(&f, &a, p, 155);
            activate(&f, &a.target, 155)
                .expect("actual original P active")
                .close();
            let mut cleanup = open(&f.c)
                .recover_session(
                    id,
                    f.c.policy.historical(),
                    Some((
                        f.pin.clone(),
                        Box::new(f.carrier.clone()),
                        Duration::from_secs(3),
                    )),
                )
                .expect("historical cleanup");
            *f.carrier.cut.lock().expect("cut") = Some((2, applied));
            assert!(matches!(
                cleanup.session().expect("session").begin(),
                Err(DurableError::Anchor(_))
            ));
            cleanup.close();
            f.carrier.clock.store(170, Ordering::SeqCst);
            let staged = if expired {
                None
            } else {
                let g = crate::enrollment::tests::witness_renewal::grant(&f, &f.original, 2, 190);
                open(&f.c)
                    .stage_credential_renewal(&g, g.operation(), &a.target, 170)
                    .expect("independent G staged after P");
                Some(g)
            };
            f.c.policy.close();
            a.target.close();
            let before = journal(&f);
            let mut owner = open(&f.c);
            let pending = owner
                .pending_write_recovery_request(f.c.policy.historical(), &f.pin)
                .expect("authenticated original independent P completion remains inspectable");
            owner.close();
            assert_eq!(journal(&f), before);
            assert_eq!(
                pending.proposal().expected_policy_digest(),
                a.target.checkpoint().digest()
            );
            assert_eq!(
                pending.proposal().expected_policy_authorization(),
                Some(a.proof.statement_digest())
            );
            let dir = f.c.paths.wrapping.parent().expect("host directory");
            let approved = AnchorPendingWriteRecoveryProposal::from_trusted_state(&retain(
                dir,
                "approved-proposal",
                &pending.proposal().to_bytes(),
            ))
            .expect("exact proposal");
            let metadata = retain(dir, "approved-metadata", pending.metadata());
            let signed = retain(dir, "original-request", pending.signed_request());
            f.carrier
                .store
                .lock()
                .expect("independent controller")
                .complete_pending_write_recovery(&approved, &signed, &metadata, 170)
                .expect("exact expired C completion with retained P");
            for _ in 0..2 {
                assert_eq!(
                    confirm(&f, &approved, &metadata).expect("original target confirmed"),
                    approved.target_head()
                );
            }
            assert!(journal(&f).1.is_none());
            if let Some(g) = &staged {
                // The original policy object was closed before recovery. Only
                // a separately verified current copy can complete the staged G.
                let current = policy(&f.c, 2, 220, 170);
                assert_eq!(current.checkpoint(), a.target.checkpoint());
                let mut owner = open(&f.c);
                assert_eq!(
                    owner.credential_renewal_status().expect("same staged G"),
                    crate::CredentialRenewalStatus::Pending {
                        operation: g.operation(),
                        statement: g.statement_digest()
                    }
                );
                let client = crate::enrollment::tests::witness_renewal::client(&f, &mut owner, 170);
                let proposal = owner
                    .prepare_witnessed_policy_continuation(
                        f.c.policy.historical(),
                        &current,
                        170,
                        client,
                    )
                    .expect("original G target");
                let bound = journal(&f);
                assert!(
                    matches!(
                        owner.pending_write_recovery_request(f.c.policy.historical(), &f.pin),
                        Err(DurableError::Suspended)
                    ),
                    "bound G intent is not ordinary recovery"
                );
                assert_eq!(journal(&f), bound);
                owner = open(&f.c);
                f.carrier
                    .store
                    .lock()
                    .expect("independent witness")
                    .prepare_policy_renewed_credential_renewal(
                        proposal,
                        g,
                        f.c.policy.historical(),
                        &current,
                        170,
                    )
                    .expect("independently admit original G");
                let mut client =
                    crate::enrollment::tests::witness_renewal::client(&f, &mut owner, 170);
                owner
                    .commit_witnessed_policy_continuation(
                        &proposal,
                        f.c.policy.historical(),
                        &current,
                        170,
                        &mut client,
                    )
                    .expect("same G after exact ordinary recovery");
                owner.close();
            }
            let mut owner = open(&f.c);
            let client = owner
                .credential_renewal_request_anchor_client(
                    f.c.policy.historical(),
                    f.pin.clone(),
                    Box::new(f.carrier.clone()),
                    Duration::from_secs(3),
                )
                .expect("historical client");
            let next = owner
                .witnessed_credential_renewal_request(
                    crate::CredentialRenewalId::generate().expect("next G"),
                    f.c.policy.historical(),
                    client,
                )
                .expect("next request preserves actual P");
            assert_eq!(next.current_policy(), a.target.checkpoint());
            assert_eq!(
                next.current_policy_authorization(),
                Some(a.proof.statement_digest())
            );
            owner.close();
            eprintln!("PUBLIC_PENDING_INDEPENDENT_POLICY policy_expired={expired} originally_applied={applied} historical_completion_retained=true original_target_confirmed=true");
        }
    }
}
