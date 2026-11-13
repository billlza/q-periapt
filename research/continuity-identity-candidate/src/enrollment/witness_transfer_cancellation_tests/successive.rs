// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::Ordering;

#[test]
fn enrollment_witness_successive_cancellation_preserves_original_reservation_without_signer() {
    for reserved_before in [false, true] {
        for missing_signer in [false, true] {
            let (f, g, first) = staged_transfer();
            let before = disk(&f);
            let first_reservation = if reserved_before {
                Some(
                    open(&f.c)
                        .prepare_witnessed_credential_cancellation_with_witness_plan(
                            f.c.policy.historical(),
                            first.plan.clone(),
                            181,
                        )
                        .expect("reserve original G at B"),
                )
            } else {
                None
            };
            let retained_signer = f.c.paths.signer.with_extension("successive-retained");
            if missing_signer {
                fs::rename(&f.c.paths.signer, &retained_signer)
                    .expect("hold owned original signer");
            }
            let reserved = disk(&f);
            let subject =
                AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("same subject");
            let second = first.successor(
                &f.c,
                &f.original,
                &f.original,
                f.c.policy.historical(),
                subject,
                (185, 98),
            );
            second.adopt_parent(&f.c, 186).close();
            assert_eq!(
                disk(&f),
                reserved,
                "second selection cannot reset old cancellation intent"
            );
            let mut stale = open(&f.c);
            assert!(stale
                .prepare_witnessed_credential_cancellation_with_witness_plan(
                    f.c.policy.historical(),
                    first.plan.clone(),
                    290
                )
                .is_err());
            assert!(matches!(stale.status(), Err(DurableError::Closed)));
            assert_eq!(disk(&f), reserved);
            let mut owner = open(&f.c);
            let cancellation = owner
                .prepare_witnessed_credential_cancellation_with_witness_plan(
                    f.c.policy.historical(),
                    second.plan.clone(),
                    290,
                )
                .expect("same original grant-only reservation");
            if let Some(first_reservation) = first_reservation {
                assert_eq!(cancellation, first_reservation);
            }
            assert_eq!(cancellation.operation(), g.operation());
            assert_eq!(cancellation.transaction_statement(), g.statement_digest());
            let current = disk(&f);
            assert_eq!(current.0, before.0);
            assert!(current.1.is_some());
            assert_eq!(
                owner
                    .prepare_witnessed_credential_cancellation_with_witness_plan(
                        f.c.policy.historical(),
                        second.plan.clone(),
                        290
                    )
                    .expect("exact repeat"),
                cancellation
            );
            assert_eq!(disk(&f), current);
            owner.close();
            assert_eq!(second.requests.load(Ordering::SeqCst), 0);
            assert_eq!(first.requests.load(Ordering::SeqCst), 0);
            if missing_signer {
                assert!(
                    !f.c.paths.signer.exists(),
                    "metadata must not reprovision a signer"
                );
                fs::rename(&retained_signer, &f.c.paths.signer)
                    .expect("restore exact owned signer");
            }
            second.set_time(290);
            let mut owner = open(&f.c);
            let mut carrier = second.client(&mut owner, &f.c);
            assert_eq!(
                owner
                    .reconcile_witnessed_credential_renewal(
                        g.operation(),
                        g.statement_digest(),
                        f.c.policy.historical(),
                        290,
                        &mut carrier
                    )
                    .expect("unknown remains pending"),
                renewal::pending(&g)
            );
            assert_eq!(disk(&f), current);
            {
                let mut target = second.target.lock().expect("C");
                assert!(
                    target.transferred_control(&first.control).is_err(),
                    "old target receipt cannot authorize new current target"
                );
                assert_eq!(
                    target
                        .transferred_control(&second.control)
                        .expect("current independent authorization")
                        .close_unprepared_credential_renewal(
                            cancellation,
                            g.historical(),
                            f.c.policy.historical()
                        )
                        .expect("original issuer approved close"),
                    crate::AnchorCredentialCancellationState::Closed
                );
            }
            second.reopen_target();
            assert_eq!(
                owner
                    .reconcile_witnessed_credential_renewal(
                        g.operation(),
                        g.statement_digest(),
                        f.c.policy.historical(),
                        290,
                        &mut carrier
                    )
                    .expect("original close and parent ACK"),
                CredentialRenewalStatus::Closed {
                    operation: g.operation(),
                    statement: g.statement_digest(),
                    target: g.successor_device().roster().checkpoint()
                }
            );
            owner.close();
            assert_eq!(
                disk(&f),
                before,
                "cleanup preserves original encrypted state and prekey"
            );
            eprintln!("SUCCESSIVE_CANCEL reserved_before={reserved_before} missing_signer={missing_signer} original_intent=true parent_ack=true");
        }
    }
}
