// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn historical_policy_recovery_after_process_cuts_needs_no_current_runtime() {
    let mut cuts = 0;
    for carry in [false, true] {
        for stage in ["journal", "completion", "acknowledgement"] {
            let (c, original, id) = local();
            let g1 = renewal::grant(&c, &original, &original, 2, 220);
            let p1 = policy(&c, 2, 190, 170);
            let t1 = joint(&c, &g1, &scope(&c, &g1, id), &c.policy, &p1);
            let mut owner = open(&c);
            owner
                .stage_policy_continuation(&g1, &t1, g1.operation(), &p1, 170)
                .expect("original joint Pending");
            let (operation, statement, expected) = if carry {
                owner
                    .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
                    .expect("first exact T1 completes");
                let g2 = renewal::grant(&c, &original, g1.successor_device(), 3, 230);
                owner
                    .stage_credential_renewal(&g2, g2.operation(), &p1, 170)
                    .expect("credential-only Pending under actual T1");
                (
                    g2.operation(),
                    g2.statement_digest(),
                    renewal::committed(&g2),
                )
            } else {
                (g1.operation(), t1.statement_digest(), committed(&t1, &g1))
            };
            owner.close();
            let original_history = c.policy.historical().clone();
            let target_history = p1.historical().clone();
            let signer = fs::read(&c.paths.signer).expect("original signing owner bytes");
            kill_at(&c, 2, 190, stage);
            p1.close();
            c.policy.close();
            assert!(p1.check_mode(PrekeyQuality::OneTimeBoth, 195).is_err());
            for _ in 0..2 {
                let mut owner = open(&c);
                assert_eq!(
                    owner
                        .recover_historical_policy_continuation(
                            operation,
                            statement,
                            &original_history,
                            &target_history,
                            195,
                        )
                        .expect("history-only completion and original receipt ACK"),
                    expected
                );
                owner.close();
            }
            assert!(fs::read(&c.paths.signer).expect("same signer") == signer);
            let mut service = journal(&c, &original);
            let journal = service.stores().expect("historical stores").0;
            assert_eq!(journal.identity().expect("original journal"), id);
            let authority =
                RetainedInstallationAuthority::active_installation(&original, &original_history);
            journal
                .check_local_policy_continuation(&authority, &t1.historical())
                .expect("actual T1 survives completion and carry");
            cuts += 1;
        }
    }
    assert_eq!(cuts, 6);
    eprintln!("HISTORICAL_POLICY_RECOVERY process_cuts=6 joint_and_carry=true current_runtimes_closed=true target_expired=true original_receipt_ack=true");
}

#[test]
fn historical_policy_recovery_leaves_uncommitted_pending_unchanged() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 220);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let mut owner = open(&c);
    owner
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("original uncommitted Pending");
    let saved = row(&owner);
    owner.close();
    let before = snapshot(&c, &original, id);
    let p0 = c.policy.historical().clone();
    let history = p1.historical().clone();
    p1.close();
    c.policy.close();
    for at in [175, 195] {
        let mut owner = open(&c);
        assert!(matches!(
            owner.recover_historical_policy_continuation(
                g.operation(),
                t.statement_digest(),
                &p0,
                &history,
                at,
            ),
            Err(DurableError::Suspended)
        ));
        assert!(
            owner.active.is_none(),
            "failed historical call releases its owner"
        );
        let mut owner = open(&c);
        assert_eq!(
            owner.credential_renewal_status().expect("original Pending"),
            pending(&t)
        );
        assert_eq!(row(&owner), saved);
        owner.close();
        assert_eq!(snapshot(&c, &original, id), before);
    }
}
