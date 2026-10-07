// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture,
    durable::tests::{assert_sync_failure, directory, fault_store, new_store, reopen},
    PrekeyQuality, RootSigningKey,
};
use std::sync::atomic::Ordering;

#[test]
fn every_local_transition_and_receipt_ack_io_cut_keeps_atomic_original_commit_fact() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let original = f.initiator_device();
    let root = RootSigningKey::deterministic([90; 32], [91; 32]).expect("original root");
    let certificate = root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original body");
    let grant = crate::durable::rosters::tests::renewal::grant(
        &root,
        &certificate,
        original,
        300,
        2,
        [231; 32],
        f.initiator
            .current_policy()
            .expect("fixture policy owner")
            .checkpoint()
            .digest(),
    );
    let authority = crate::RetainedInstallationAuthority::active_installation(
        original,
        f.initiator.current_policy().expect("fixture policy owner"),
    );
    let mut faults = 0;
    let mut present = 0;
    let mut absent = 0;
    for acknowledging in [false, true] {
        let folder = directory();
        let path = folder.path().canonicalize().expect("path");
        new_store(&path, original).close();
        if acknowledging {
            reopen(&path, original)
                .commit_local_credential_renewal(
                    &authority,
                    &grant,
                    grant.operation(),
                    f.initiator.current_policy().expect("fixture policy owner"),
                    150,
                )
                .expect("committed target");
        }
        let (mut journal, _, count, _) = fault_store(&path, original, false);
        let receipt = LocalRenewalCommit::for_grant(&grant);
        count.store(0, Ordering::SeqCst);
        if acknowledging {
            journal
                .acknowledge_local_credential_renewal(&authority, &receipt)
                .expect("ack baseline");
        } else {
            journal
                .commit_local_credential_renewal(
                    &authority,
                    &grant,
                    grant.operation(),
                    f.initiator.current_policy().expect("fixture policy owner"),
                    150,
                )
                .expect("commit baseline");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((4..=32).contains(&barriers));
        journal.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let folder = directory();
                let path = folder.path().canonicalize().expect("path");
                new_store(&path, original).close();
                if acknowledging {
                    reopen(&path, original)
                        .commit_local_credential_renewal(
                            &authority,
                            &grant,
                            grant.operation(),
                            f.initiator.current_policy().expect("fixture policy owner"),
                            150,
                        )
                        .expect("commit first");
                }
                let (mut journal, remaining, _, _) = fault_store(&path, original, after);
                remaining.store(cut, Ordering::SeqCst);
                if acknowledging {
                    assert_sync_failure(
                        journal.acknowledge_local_credential_renewal(&authority, &receipt),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        journal.commit_local_credential_renewal(
                            &authority,
                            &grant,
                            grant.operation(),
                            f.initiator.current_policy().expect("fixture policy owner"),
                            150,
                        ),
                        after,
                    );
                }
                assert!(journal.active.is_none());
                faults += 1;
                let mut recovered = reopen(&path, original);
                let image = recovered.image().expect("recovered same image");
                let saved = get(&image, &image.local_account).expect("local roster");
                if let Some(actual) = saved.local_commit {
                    present += 1;
                    assert_eq!(actual, receipt);
                    assert_eq!(
                        saved.roster.checkpoint(),
                        grant.successor_device().roster().checkpoint()
                    );
                } else {
                    absent += 1;
                    let expected = if acknowledging {
                        grant.successor_device().roster().checkpoint()
                    } else {
                        original.roster().checkpoint()
                    };
                    assert_eq!(saved.roster.checkpoint(), expected);
                }
                if acknowledging {
                    recovered
                        .acknowledge_local_credential_renewal(&authority, &receipt)
                        .expect("same durable completion ack");
                } else {
                    assert_eq!(
                        recovered
                            .commit_local_credential_renewal(
                                &authority,
                                &grant,
                                grant.operation(),
                                f.initiator.current_policy().expect("fixture policy owner"),
                                150
                            )
                            .expect("same original operation"),
                        receipt
                    );
                }
                let final_image = recovered.image().expect("complete image");
                assert_eq!(final_image.revision, if acknowledging { 3 } else { 2 });
                assert_eq!(final_image.owner, crate::bootstrap::storage_owner(original));
            }
        }
    }
    assert!(present > 0 && absent > 0);
    eprintln!("LOCAL_RENEWAL_JOURNAL_IO faults={faults} receipt_present={present} receipt_absent={absent}");
}

#[test]
fn every_joint_journal_commit_and_ack_sync_cut_keeps_t_credential_and_receipt_atomic() {
    let c = crate::session_policy::PolicyContinuationTestCase::new();
    let (a, p) = c.approvals();
    let t = crate::VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("independent joint approval");
    let history = t.historical();
    let target = LocalRenewalTarget {
        policy_renewal: None,
        grant: &c.grant,
        continuation: Some(&history),
    };
    let receipt = target.receipt().expect("joint receipt");
    let original = c.grant.previous_device();
    let policy = c.materials().target;
    let authority = crate::RetainedInstallationAuthority::active_installation(original, &c.old);
    let provision = |path: &Path| {
        let key = JournalKey::provision(&path.join("key")).expect("original key");
        std::fs::write(path.join("store-id"), c.scope.journal.as_bytes())
            .expect("retain public journal identity");
        DeviceJournal::provision(&path.join("state.redb"), key, original, c.scope.journal)
            .expect("original journal")
    };
    let (mut cuts, mut before_commit, mut after_commit) = (0, 0, 0);
    for acknowledging in [false, true] {
        let folder = directory();
        let path = folder.path().canonicalize().expect("path");
        let mut baseline = provision(&path);
        if acknowledging {
            baseline
                .commit_local_renewal(&authority, &target, policy, 170)
                .expect("commit before ACK");
        }
        baseline.close();
        let (mut j, _, count, _) = fault_store(&path, original, false);
        count.store(0, Ordering::SeqCst);
        if acknowledging {
            j.acknowledge_local_credential_renewal(&authority, &receipt)
                .expect("calibrate ACK");
        } else {
            j.commit_local_renewal(&authority, &target, policy, 170)
                .expect("calibrate commit");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((4..=32).contains(&barriers));
        j.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let folder = directory();
                let path = folder.path().canonicalize().expect("path");
                let mut initial = provision(&path);
                if acknowledging {
                    initial
                        .commit_local_renewal(&authority, &target, policy, 170)
                        .expect("original commit");
                }
                initial.close();
                let (mut j, remaining, _, _) = fault_store(&path, original, after);
                remaining.store(cut, Ordering::SeqCst);
                if acknowledging {
                    assert_sync_failure(
                        j.acknowledge_local_credential_renewal(&authority, &receipt),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        j.commit_local_renewal(&authority, &target, policy, 170),
                        after,
                    );
                }
                assert!(j.active.is_none());
                let mut j = reopen(&path, original);
                let image = j.image().expect("authenticated recovered image");
                let saved = get(&image, &image.local_account).expect("same roster");
                if let Some(retained) = &saved.policy_continuation {
                    after_commit += 1;
                    assert_eq!(retained.journal_bytes(), history.journal_bytes());
                    assert_eq!(
                        saved.roster.checkpoint(),
                        c.grant.successor_device().roster().checkpoint()
                    );
                    assert_eq!(
                        saved
                            .renewals
                            .get(&original.device_id())
                            .expect("atomic G")
                            .statement_digest(),
                        c.grant.statement_digest()
                    );
                    if !acknowledging {
                        assert_eq!(saved.local_commit.as_ref(), Some(&receipt));
                    }
                } else {
                    before_commit += 1;
                    assert!(
                        !acknowledging,
                        "ACK must never erase independently retained T"
                    );
                    assert_eq!(saved.roster.checkpoint(), original.roster().checkpoint());
                    assert!(saved.local_commit.is_none() && saved.renewals.is_empty());
                }
                if acknowledging {
                    j.acknowledge_local_credential_renewal(&authority, &receipt)
                        .expect("exact ACK retry");
                } else {
                    let now = if saved.policy_continuation.is_some() {
                        195
                    } else {
                        175
                    };
                    assert_eq!(
                        j.commit_local_renewal(&authority, &target, policy, now)
                            .expect("exact commit retry or historical expired readback"),
                        receipt
                    );
                }
                let final_image = j.image().expect("final image");
                assert_eq!(final_image.revision, if acknowledging { 3 } else { 2 });
                assert_eq!(final_image.owner, c.scope.original_owner);
                j.check_local_policy_continuation(&authority, &history)
                    .expect("T survives every cut and ACK");
                cuts += 1;
            }
        }
    }
    assert!(before_commit > 0 && after_commit > 0);
    eprintln!("JOINT_POLICY_JOURNAL_SYNC cuts={cuts} before_commit={before_commit} after_commit={after_commit}");
}
