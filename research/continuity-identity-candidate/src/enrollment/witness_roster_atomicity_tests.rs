// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Why required roster/head coordination cannot use two separately committed mutations.
use super::*;
#[test]
fn separate_roster_and_head_updates_leave_no_admissible_policy_predecessor_after_expiry() {
    for use_actual_root_roster in [false, true] {
        let f = fixture_with_policy_expiry(Some(151));
        let a = approved_at(&f, &f.c.policy, 2, 154, 150);
        let p = prepared_at(&f, &a, &f.c.policy, 150);
        applied_at(&f, &a, p, 150);
        let mut owner = open(&f.c);
        let certificate = match owner.image().expect("original").phase {
            Phase::Accepted { admission, .. } => Ok(admission.certificate),
            _ => Err("accepted original"),
        }
        .expect("certificate");
        owner.close();
        let next_roster =
            f.c.root
                .issue_roster(
                    2,
                    interval(),
                    &[f.c
                        .root
                        .roster_entry(&certificate)
                        .expect("original member")],
                )
                .expect("root authorizes R2");
        let pin = AccountPin::new(
            f.original.account_id(),
            f.c.intent.root.clone(),
            next_roster.checkpoint(),
            a.target.family(),
        )
        .expect("independent R2 pin");
        let next = pin
            .verify_device(&certificate, next_roster.as_bytes(), 150)
            .expect("same C0 and actual R2");
        let before = journal(&f);
        f.carrier
            .store
            .lock()
            .expect("witness")
            .update_roster_authority(
                p.subject(),
                f.original.roster().checkpoint(),
                &next,
                &a.target,
                150,
            )
            .expect("standalone R2 update committed");
        assert_eq!(
            journal(&f),
            before,
            "standalone witness update did not adopt R2 in journal"
        );
        f.carrier.clock.store(155, Ordering::SeqCst);
        let b = approved_at(&f, &a.target, 3, 159, 155);
        assert_eq!(
            b.request.scope().current_roster,
            f.original.roster().checkpoint()
        );
        let mut scope = b.request.scope().clone();
        if use_actual_root_roster {
            scope.current_roster = next.roster().checkpoint();
        }
        let materials = crate::PolicyRenewalMaterials {
            original: f.c.policy.historical(),
            previous: a.target.historical(),
            target: &b.target,
            original_device: &f.original,
            current_device: if use_actual_root_roster {
                &next
            } else {
                &f.original
            },
        };
        let statement = PolicyRenewalStatement::new(&scope, &materials, 155)
            .expect("root-approved P2 expectation");
        let issuer =
            crate::PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy root");
        let proof = VerifiedPolicyRenewal::verify(
            &f.c.root
                .approve_policy_renewal(&statement)
                .expect("account approval"),
            &issuer
                .approve_policy_renewal(&statement)
                .expect("policy approval"),
            &scope,
            &materials,
            155,
        )
        .expect("authentic approval");
        let mut owner = open(&f.c);
        let client = policy_client(&f, &mut owner);
        let mut journal = DeviceJournal::open_anchored_retained(
            f.c.paths.installation.files()[1],
            owner.key().expect("key"),
            &f.original,
            f.c.policy.historical(),
            f.id,
            client,
        )
        .expect("same original journal head");
        let image = owner.image().expect("actual enrollment completion");
        let completed = owner
            .policy_enrollment_completion(&image, f.c.policy.historical())
            .expect("completed P1")
            .expect("completion");
        journal
            .retain_enrollment_policy_completion(completed)
            .expect("original completed P1");
        let proposal = journal.prepare_policy_renewal(&proof, &materials, 155);
        if use_actual_root_roster {
            assert!(
                matches!(proposal, Err(DurableError::Conflict)),
                "actual root R2 cannot substitute for actual journal R1"
            );
        } else {
            let proposal = proposal.expect("journal R1 target");
            assert!(
                matches!(
                    f.carrier
                        .store
                        .lock()
                        .expect("witness")
                        .prepare_policy_renewal(proposal, &proof, &materials, 155),
                    Err(DurableError::Conflict)
                ),
                "journal R1 cannot substitute for witness R2"
            );
        }
    }
    eprintln!("ROSTER_HEAD_EXPIRY_COUNTEREXAMPLE witness_R2_journal_R1=true actual_R2_refused_locally=true stale_R1_refused_by_witness=true");
}

#[path = "witness_roster_journal_tests.rs"]
mod journal;
