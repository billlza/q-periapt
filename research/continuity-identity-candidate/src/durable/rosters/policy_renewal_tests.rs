// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::tests::{assert_sync_failure, directory, fault_store, reopen};
use crate::{
    session_policy::PolicyRenewalTestCase, AnchorRequirement, Validity, VerifiedPolicyRenewal,
};
use std::sync::atomic::Ordering;

fn approval(c: &PolicyRenewalTestCase) -> HistoricalPolicyRenewal {
    let (a, p) = c.approvals();
    VerifiedPolicyRenewal::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("independent roots")
        .historical()
}
fn target<'a>(
    c: &'a PolicyRenewalTestCase,
    a: &'a HistoricalPolicyRenewal,
) -> LocalPolicyRenewalTarget<'a> {
    LocalPolicyRenewalTarget {
        approval: a,
        original: &c.device,
        current: &c.device,
        original_policy: &c.old,
    }
}
fn provision(path: &Path, c: &PolicyRenewalTestCase) -> DeviceJournal {
    let key = JournalKey::provision(&path.join("key")).expect("wrapping key");
    std::fs::write(path.join("store-id"), c.scope.journal.as_bytes())
        .expect("retained original ID");
    DeviceJournal::provision(&path.join("state.redb"), key, &c.device, c.scope.journal)
        .expect("original journal")
}

#[test]
fn policy_only_journal_commit_preserves_cr_history_and_existing_prekey() {
    let c = PolicyRenewalTestCase::new(240, 240);
    let a = approval(&c);
    let target = target(&c, &a);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut j = provision(&path, &c);
    let p0 = c.policy(1, 160, 3, AnchorRequirement::local_only(), 150);
    j.generate_prekey(
        &p0,
        &c.device,
        crate::PrekeyId::from_trusted_state([55; 32]).expect("prekey ID"),
        crate::LeafKind::OneTimePq,
        Validity::new(100, 155).expect("validity"),
        150,
    )
    .expect("real prekey record");
    let before = j.image().expect("before");
    let original = get(&before, &before.local_account).expect("roster");
    let receipt = j
        .commit_local_policy_renewal(&target, &c.target, 170, None)
        .expect("same C/R policy commit");
    let after = j.image().expect("after");
    let saved = get(&after, &after.local_account).expect("adopted roster");
    assert_eq!(
        saved.roster.journal_bytes(),
        original.roster.journal_bytes()
    );
    assert_eq!(saved.history, original.history);
    assert!(
        saved.renewals.is_empty()
            && saved.local_commit.is_none()
            && saved.policy_continuation.is_none()
    );
    assert_eq!(before.records.len(), after.records.len());
    let preserved = before
        .records
        .iter()
        .filter(|(_, r)| r.kind != RecordKind::Roster)
        .count();
    assert_eq!(preserved, 1);
    for (key, record) in &before.records {
        if record.kind != RecordKind::Roster {
            let next = after.records.get(key).expect("same original record");
            assert!(record.kind == next.kind && record.phase == next.phase);
            assert_eq!(
                (
                    record.context,
                    &record.authorities,
                    &record.keys,
                    &record.prekeys
                ),
                (next.context, &next.authorities, &next.keys, &next.prekeys)
            );
            assert!(record.cancellation.is_none() && next.cancellation.is_none());
            assert_eq!(
                digest(b"test-record", &record.payload),
                digest(b"test-record", &next.payload)
            );
        }
    }
    assert_eq!(
        (after.id, after.owner, after.next_fanout),
        (before.id, before.owner, before.next_fanout)
    );
    assert_eq!(after.revision, before.revision + 1);
    assert!(!is_genesis(&after, &c.device).expect("adoption is not genesis"));
    assert!(require_original_operational_policy(&after).is_err());
    assert!(matches!(
        check_continuation_completion(&after, &saved),
        Err(DurableError::Suspended)
    ));
    let mut record = saved.record().expect("new codec");
    assert_eq!(record.payload.get(..8), Some(b"QPRHST05".as_slice()));
    let original_length = original.record().expect("old codec").payload.len();
    let phase_at = 8 + original_length;
    *record.payload.get_mut(phase_at).expect("receipt phase") = 2;
    assert!(matches!(
        decode(&id(&c.device.account_id()), &record),
        Err(DurableError::Corrupt)
    ));
    j.close();
    let mut j = reopen(&path, &c.device);
    assert_eq!(
        j.inspect_local_policy_renewal(&target)
            .expect("exact commit after reopen"),
        receipt
    );
    let authority = crate::RetainedInstallationAuthority::active_installation(&c.device, &c.old);
    j.acknowledge_local_policy_renewal(&authority, &receipt)
        .expect("exact completion ACK");
    let revision = j.image().expect("acked").revision;
    j.acknowledge_local_policy_renewal(&authority, &receipt)
        .expect("idempotent ACK");
    assert_eq!(j.image().expect("same revision").revision, revision);
    let revoked = c
        .account
        .issue_roster(2, Validity::new(100, 300).expect("roster time"), &[])
        .expect("signed revocation");
    let pin = crate::AccountPin::new(
        c.device.account_id(),
        c.device.authority_key.clone(),
        revoked.checkpoint(),
        c.old.family(),
    )
    .expect("new independent head");
    let revoked = pin
        .verify_roster(revoked.as_bytes(), 175)
        .expect("current revocation");
    j.install_roster(&revoked, 175)
        .expect("record revocation after policy-only adoption");
    assert_eq!(
        j.inspect_local_policy_renewal(&target)
            .expect("history survives revocation"),
        receipt
    );
    j.acknowledge_local_policy_renewal(&authority, &receipt)
        .expect("history ACK after revocation");
    assert_eq!(
        j.roster_checkpoint(c.device.account_id())
            .expect("revocation retained"),
        revoked.checkpoint()
    );
}

#[test]
fn policy_only_commit_and_ack_sync_faults_preserve_exact_original_fact() {
    let c = PolicyRenewalTestCase::new(240, 240);
    let a = approval(&c);
    let target = target(&c, &a);
    let receipt = LocalPolicyRenewalCommit::for_approval(&a);
    let authority = crate::RetainedInstallationAuthority::active_installation(&c.device, &c.old);
    let (mut faults, mut present, mut absent) = (0, 0, 0);
    for acknowledging in [false, true] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut j = provision(&path, &c);
        if acknowledging {
            j.commit_local_policy_renewal(&target, &c.target, 170, None)
                .expect("commit before ACK");
        }
        j.close();
        let (mut j, _, count, _) = fault_store(&path, &c.device, false);
        count.store(0, Ordering::SeqCst);
        if acknowledging {
            j.acknowledge_local_policy_renewal(&authority, &receipt)
                .expect("ACK calibration");
        } else {
            j.commit_local_policy_renewal(&target, &c.target, 170, None)
                .expect("commit calibration");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((4..=32).contains(&barriers));
        j.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let dir = directory();
                let path = dir.path().canonicalize().expect("path");
                let mut j = provision(&path, &c);
                if acknowledging {
                    j.commit_local_policy_renewal(&target, &c.target, 170, None)
                        .expect("original commit");
                }
                j.close();
                let (mut j, remaining, _, _) = fault_store(&path, &c.device, after);
                remaining.store(cut, Ordering::SeqCst);
                if acknowledging {
                    assert_sync_failure(
                        j.acknowledge_local_policy_renewal(&authority, &receipt),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        j.commit_local_policy_renewal(&target, &c.target, 170, None),
                        after,
                    );
                }
                assert!(j.active.is_none());
                faults += 1;
                let mut j = reopen(&path, &c.device);
                let image = j.image().expect("recovered image");
                let saved = get(&image, &image.local_account).expect("original C/R");
                assert_eq!(
                    saved.roster.journal_bytes(),
                    c.device.roster().journal_bytes()
                );
                assert!(saved.renewals.is_empty() && saved.local_commit.is_none());
                if let Some(current) = &saved.policy_renewal {
                    present += 1;
                    assert_eq!(current.receipt(), receipt);
                    assert_eq!(current.approval.journal_bytes(), a.journal_bytes());
                } else {
                    assert!(!acknowledging);
                    absent += 1;
                }
                if acknowledging {
                    j.acknowledge_local_policy_renewal(&authority, &receipt)
                        .expect("same ACK retry");
                } else {
                    assert_eq!(
                        j.commit_local_policy_renewal(&target, &c.target, 170, None)
                            .expect("same commit retry"),
                        receipt
                    );
                }
                let final_image = j.image().expect("settled original");
                assert_eq!(final_image.revision, if acknowledging { 3 } else { 2 });
                assert_eq!(final_image.id, *c.scope.journal.as_bytes());
            }
        }
    }
    assert!(present > 0 && absent > 0);
    eprintln!("POLICY_ONLY_JOURNAL_IO faults={faults} committed={present} uncommitted={absent} same_cr=true exact_approvals=true");
}

#[test]
fn roster_advance_between_approval_and_commit_fails_exact_policy_cas() {
    let c = PolicyRenewalTestCase::new(240, 240);
    let a = approval(&c);
    let target = target(&c, &a);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut j = provision(&path, &c);
    let certificate = c
        .account
        .issue_device(c.device.description.clone(), c.device.key.clone())
        .expect("same credential body");
    let next = c
        .account
        .issue_roster(
            2,
            Validity::new(100, 260).expect("validity"),
            &[c.account
                .roster_entry(&certificate)
                .expect("unchanged member")],
        )
        .expect("new signed roster");
    let pin = crate::AccountPin::new(
        c.device.account_id(),
        c.device.authority_key.clone(),
        next.checkpoint(),
        c.old.family(),
    )
    .expect("new independent head");
    let next = pin
        .verify_roster(next.as_bytes(), 175)
        .expect("current roster");
    next.authorize_device(&c.device, 175)
        .expect("same credential still authorized");
    j.install_roster(&next, 175)
        .expect("concurrent authorized update");
    let before = j.test_snapshot();
    assert!(matches!(
        j.commit_local_policy_renewal(&target, &c.target, 175, None),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        j.inspect_local_policy_renewal(&target),
        Err(DurableError::Suspended)
    ));
    let after = j.test_snapshot();
    assert_eq!(
        (before.revision, before.digest),
        (after.revision, after.digest)
    );
    assert_eq!(
        j.roster_checkpoint(c.device.account_id())
            .expect("new head"),
        next.checkpoint()
    );
}

#[test]
fn issuer_scope_requires_acknowledged_actual_policy_receipt_and_preserves_journal() {
    let c = PolicyRenewalTestCase::new(240, 240);
    let a = approval(&c);
    let target = target(&c, &a);
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let mut j = provision(&path, &c);
    let authority = crate::RetainedInstallationAuthority::active_installation(&c.device, &c.old);
    let scope = crate::installation::PolicyScope {
        authority: &authority,
        original_policy: &c.old,
        original_device: &c.device,
    };
    let operation = PolicyRenewalId::generate().expect("retained request ID");
    let first = j
        .policy_renewal_request_scope(&scope, &c.device, operation, None, None)
        .expect("original P0 scope");
    assert_eq!(first.previous_policy, c.old.checkpoint());
    assert_eq!(first.previous_authorization, None);
    let receipt = j
        .commit_local_policy_renewal(&target, &c.target, 170, None)
        .expect("commit without enrollment ACK");
    let before = j.test_snapshot();
    assert!(matches!(
        j.policy_renewal_request_scope(&scope, &c.device, operation, Some(&a), None),
        Err(DurableError::Suspended)
    ));
    let after = j.test_snapshot();
    assert_eq!(
        (before.revision, before.digest),
        (after.revision, after.digest)
    );
    j.acknowledge_local_policy_renewal(&authority, &receipt)
        .expect("exact original completion ACK");
    let before = j.test_snapshot();
    let next = j
        .policy_renewal_request_scope(&scope, &c.device, operation, Some(&a), None)
        .expect("exact completed scope");
    assert_eq!(next.previous_policy, a.target_policy());
    assert_eq!(next.previous_authorization, Some(a.statement_digest()));
    assert_eq!(next.current_roster, c.scope.current_roster);
    assert_eq!(next.current_credential, c.scope.current_credential);
    assert!(matches!(
        j.policy_renewal_request_scope(&scope, &c.device, operation, None, None),
        Err(DurableError::Conflict)
    ));
    let after = j.test_snapshot();
    assert_eq!(
        (before.revision, before.digest),
        (after.revision, after.digest)
    );
}

#[test]
fn real_g_commit_and_ack_sync_failures_keep_policy_approval_and_credential_atomic() {
    let c = PolicyRenewalTestCase::new(240, 240);
    let a = approval(&c);
    let policy_target = target(&c, &a);
    let origin = c
        .account
        .issue_device(c.device.description.clone(), c.device.key.clone())
        .expect("original credential");
    let g = crate::durable::tests::grant(
        &c.account,
        &origin,
        &c.device,
        280,
        2,
        [93; 32],
        c.old.checkpoint().digest(),
    );
    let target = LocalRenewalTarget {
        grant: &g,
        continuation: None,
        policy_renewal: Some((&a, &c.device)),
    };
    let authority = crate::RetainedInstallationAuthority::active_installation(&c.device, &c.old);
    let receipt = LocalRenewalCommit::for_grant(&g);
    let prepare = |path: &Path, acknowledging: bool| {
        let mut j = provision(path, &c);
        let p = j
            .commit_local_policy_renewal(&policy_target, &c.target, 170, None)
            .expect("original policy adoption");
        j.acknowledge_local_policy_renewal(&authority, &p)
            .expect("original completion ACK");
        if acknowledging {
            j.commit_local_renewal(&authority, &target, &c.target, 175)
                .expect("real G before ACK");
        }
        j.close();
    };
    let (mut faults, mut old, mut applied) = (0, 0, 0);
    for acknowledging in [false, true] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        prepare(&path, acknowledging);
        let (mut j, _, count, _) = fault_store(&path, &c.device, false);
        count.store(0, Ordering::SeqCst);
        if acknowledging {
            j.acknowledge_local_credential_renewal(&authority, &receipt)
                .expect("ACK calibration");
        } else {
            j.commit_local_renewal(&authority, &target, &c.target, 175)
                .expect("G calibration");
        }
        let barriers = count.load(Ordering::SeqCst);
        assert!((1..=32).contains(&barriers));
        j.close();
        for cut in 1..=barriers {
            for after in [false, true] {
                let dir = directory();
                let path = dir.path().canonicalize().expect("path");
                prepare(&path, acknowledging);
                let (mut j, remaining, _, _) = fault_store(&path, &c.device, after);
                remaining.store(cut, Ordering::SeqCst);
                if acknowledging {
                    assert_sync_failure(
                        j.acknowledge_local_credential_renewal(&authority, &receipt),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        j.commit_local_renewal(&authority, &target, &c.target, 175),
                        after,
                    );
                }
                assert!(j.active.is_none());
                faults += 1;
                let mut j = reopen(&path, &c.device);
                let image = j.image().expect("authenticated original state");
                let saved = get(&image, &image.local_account).expect("typed G/policy record");
                let retained = saved
                    .policy_renewal
                    .as_ref()
                    .expect("original policy survives");
                assert_eq!(retained.approval.journal_bytes(), a.journal_bytes());
                assert!(retained.phase == ReceiptPhase::Acknowledged);
                if let Some(actual) = saved.renewals.get(&c.device.device_id()) {
                    applied += 1;
                    assert_eq!(actual.as_bytes(), g.as_bytes());
                    assert!(retained.carried_grant.is_some());
                    assert_eq!(
                        saved.roster.checkpoint(),
                        g.successor_device().roster().checkpoint()
                    );
                    assert_eq!(
                        saved.record().expect("new encoding").payload.get(..8),
                        Some(b"QPRHST06".as_slice())
                    );
                    assert!(saved.local_commit.as_ref().is_none_or(|r| r == &receipt));
                    j.check_policy_credential_completion(&a, &c.device, &receipt)
                        .expect("exact existing fact");
                } else {
                    old += 1;
                    assert!(
                        !acknowledging
                            && !retained.carried_grant.is_some()
                            && saved.local_commit.is_none()
                    );
                    assert_eq!(saved.roster.checkpoint(), c.device.roster().checkpoint());
                    assert_eq!(
                        j.commit_local_renewal(&authority, &target, &c.target, 175)
                            .expect("same original G retry under current authority"),
                        receipt
                    );
                }
                j.acknowledge_local_credential_renewal(&authority, &receipt)
                    .expect("same completion ACK");
                j.check_policy_credential_completion(&a, &c.device, &receipt)
                    .expect("exact fact after ACK");
                let settled = j.image().expect("settled");
                let saved = get(&settled, &settled.local_account).expect("settled original record");
                assert_eq!(settled.id, *c.scope.journal.as_bytes());
                assert_eq!(
                    saved
                        .policy_renewal
                        .as_ref()
                        .expect("P1")
                        .approval
                        .journal_bytes(),
                    a.journal_bytes()
                );
                assert!(saved.local_commit.is_none());
            }
        }
    }
    assert!(old > 0 && applied > 0);
    eprintln!("POLICY_ONLY_CREDENTIAL_JOURNAL_IO faults={faults} original_predecessor={old} exact_g_applied={applied} original_policy_preserved=true");
}
