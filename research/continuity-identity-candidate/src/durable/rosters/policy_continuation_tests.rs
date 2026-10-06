// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    session_policy::PolicyContinuationTestCase, AccountPin, RootSigningKey, Validity,
    VerifiedPolicyContinuation,
};

fn retained(c: &PolicyContinuationTestCase) -> Stored {
    let (a, p) = c.approvals();
    let joint = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("both current root approvals");
    let mut stored = Stored::initial(c.grant.previous_device().roster())
        .advance_with_renewal(c.grant.successor_device().roster(), Some(&c.grant))
        .expect("exact credential transition");
    // This codec fixture directly supplies retained T to exercise ordinary
    // record updates; owning transaction admission is checked in separate tests.
    stored.policy_continuation = Some(joint.historical());
    stored.local_commit = Some(LocalRenewalCommit::for_grant(&c.grant));
    stored
}
fn roundtrip(stored: &Stored) -> Stored {
    let record = stored.record().expect("canonical retained roster");
    assert_eq!(record.payload.get(..8), Some(b"QPRHST04".as_slice()));
    decode(&id(&stored.roster.account_id()), &record).expect("authenticate retained authorization")
}
fn assert_same(stored: &Stored, wire: &[u8], statement: [u8; 32]) {
    let retained = stored
        .policy_continuation
        .as_ref()
        .expect("policy authorization retained independently");
    assert_eq!(retained.as_bytes(), wire);
    assert_eq!(retained.statement_digest(), statement);
}

#[test]
fn authenticated_policy_record_cannot_move_to_another_journal_of_the_same_owner() {
    let mut c = PolicyContinuationTestCase::new();
    let stored = retained(&c);
    let account = stored.roster.account_id();
    let mut image = Image {
        local_account: account,
        next_fanout: 0,
        id: *c.scope.journal.as_bytes(),
        owner: c.scope.original_owner,
        revision: 1,
        digest: [17; 32],
        protection: Protection::Local,
        records: BTreeMap::from([(id(&account), stored.record().expect("original record"))]),
        enrollment_completion: None,
    };
    assert!(get(&image, &account).is_ok());
    assert!(validate_image(&image).is_ok());
    c.scope.journal =
        crate::JournalIdentity::generate().expect("independently approved other journal");
    let mut other = retained(&c);
    other.local_commit = None; // A completed/ACKed T must keep its own binding.
    let record = other.record().expect("valid same-root historical T for B");
    assert!(
        decode(&id(&account), &record).is_ok(),
        "pure signature grammar is not installation admission"
    );
    image.records.insert(id(&account), record);
    assert!(
        get(&image, &account).is_err(),
        "same-root T_B accepted by journal A"
    );
    assert!(
        validate_image(&image).is_err(),
        "grafted T survived whole-image validation"
    );
}

#[test]
fn policy_authorization_survives_receipt_retirement_and_ordinary_roster_updates() {
    let c = PolicyContinuationTestCase::new();
    let mut stored = retained(&c);
    let original = stored
        .policy_continuation
        .as_ref()
        .expect("T1")
        .as_bytes()
        .to_vec();
    let statement = stored
        .policy_continuation
        .as_ref()
        .expect("T1")
        .statement_digest();
    stored = roundtrip(&stored);
    assert!(stored.local_commit.is_some());
    stored.local_commit = None;
    stored = roundtrip(&stored);
    assert!(stored.local_commit.is_none());
    assert_same(&stored, &original, statement);
    let successor = c.grant.successor_device();
    let credential = c
        .account
        .issue_device(successor.description.clone(), successor.key.clone())
        .expect("same credential");
    let roster = c
        .account
        .issue_roster(
            3,
            Validity::new(100, 200).expect("new roster time"),
            &[c.account.roster_entry(&credential).expect("same member")],
        )
        .expect("fresh roster");
    let pin = AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.old.family(),
    )
    .expect("current pin");
    let current = pin
        .verify_roster(roster.as_bytes(), 170)
        .expect("current signed roster");
    stored = roundtrip(&stored.advance(&current).expect("ordinary roster update"));
    assert_same(&stored, &original, statement);
    let revoked = c
        .account
        .issue_roster(4, Validity::new(100, 200).expect("revocation time"), &[])
        .expect("revocation");
    let pin = AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        revoked.checkpoint(),
        c.old.family(),
    )
    .expect("independent revocation pin");
    let current = pin
        .verify_roster(revoked.as_bytes(), 170)
        .expect("authenticated revocation");
    stored = roundtrip(&stored.advance(&current).expect("retain revoked history"));
    assert_same(&stored, &original, statement);
    assert!(stored.roster.authorize_device(successor, 170).is_err());
}

#[test]
fn later_credential_renewal_replaces_its_grant_without_replacing_policy_authorization() {
    let c = PolicyContinuationTestCase::new();
    let mut stored = retained(&c);
    let original = stored
        .policy_continuation
        .as_ref()
        .expect("T1")
        .as_bytes()
        .to_vec();
    let statement = stored
        .policy_continuation
        .as_ref()
        .expect("T1")
        .statement_digest();
    let previous = c.grant.previous_device();
    let origin = c
        .account
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("original credential body");
    let next = super::tests::renewal::grant(
        &c.account,
        &origin,
        c.grant.successor_device(),
        195,
        3,
        [44; 32],
        c.old.checkpoint().digest(),
    );
    stored = stored
        .advance_with_renewal(next.successor_device().roster(), Some(&next))
        .expect("C1 to C2");
    stored.local_commit = Some(LocalRenewalCommit::for_grant(&next));
    stored = roundtrip(&stored);
    assert_eq!(
        stored
            .renewals
            .get(&next.successor_device().device_id())
            .expect("G2")
            .statement_digest(),
        next.statement_digest()
    );
    assert_ne!(next.statement_digest(), c.grant.statement_digest());
    assert_same(&stored, &original, statement);
    stored.local_commit = None;
    stored = roundtrip(&stored);
    assert_same(&stored, &original, statement);
}

#[test]
fn retained_policy_history_rejects_corruption_wrong_authority_and_noncanonical_receipt() {
    let c = PolicyContinuationTestCase::new();
    let stored = retained(&c);
    let saved = stored.policy_continuation.as_ref().expect("T1");
    let wire = saved.journal_bytes();
    assert!(crate::HistoricalPolicyContinuation::from_journal(&wire, &stored.roster).is_ok());
    for index in [0, crate::PUBLIC_KEY_BYTES - 1, wire.len() - 1] {
        let mut bytes = wire.clone();
        *bytes.get_mut(index).expect("bounded field") ^= 1;
        assert!(crate::HistoricalPolicyContinuation::from_journal(&bytes, &stored.roster).is_err());
    }
    let other = RootSigningKey::generate().expect("other account root");
    let roster = other
        .issue_roster(1, Validity::new(100, 200).expect("time"), &[])
        .expect("other roster");
    let pin = AccountPin::new(
        other.account_id().expect("account"),
        other.public_key().expect("root"),
        roster.checkpoint(),
        c.old.family(),
    )
    .expect("same policy family different account");
    let other = pin
        .verify_roster(roster.as_bytes(), 170)
        .expect("other authenticated roster");
    assert!(crate::HistoricalPolicyContinuation::from_journal(&wire, &other).is_err());
    let mut record = stored.record().expect("record");
    let suffix = wire.len() + 4 + 200; // LocalRenewalCommit is exactly 200 bytes.
    let flag = record
        .payload
        .len()
        .checked_sub(suffix + 1)
        .expect("presence flag");
    assert_eq!(record.payload.get(flag), Some(&1));
    *record.payload.get_mut(flag).expect("presence flag") = 2;
    assert!(decode(&id(&stored.roster.account_id()), &record).is_err());
    let legacy = Stored::initial(c.grant.previous_device().roster());
    let decoded = decode(
        &id(&legacy.roster.account_id()),
        &legacy.record().expect("legacy record"),
    )
    .expect("original format");
    assert!(decoded.policy_continuation.is_none());
}

fn continued_peer_case(
    revoke_local: bool,
) -> (
    PolicyContinuationTestCase,
    tempfile::TempDir,
    VerifiedCredentialRenewal,
    crate::HistoricalPolicyContinuation,
) {
    let mut c = PolicyContinuationTestCase::new();
    let directory = crate::durable::tests::directory();
    let path = directory
        .path()
        .canonicalize()
        .expect("private journal directory");
    let mut journal = crate::durable::tests::new_store(&path, c.grant.previous_device());
    c.scope.journal = journal.identity().expect("actual original journal");
    let (a, p) = c.approvals();
    let t = VerifiedPolicyContinuation::verify(&a, &p, &c.scope, &c.materials(), 170)
        .expect("actual journal-bound dual approval");
    let historical = t.historical();
    let authority = crate::RetainedInstallationAuthority::active_installation(
        c.grant.previous_device(),
        &c.old,
    );
    let policy = c.materials().target;
    let receipt = journal
        .commit_local_renewal(
            &authority,
            &LocalRenewalTarget {
                policy_renewal: None,
                grant: &c.grant,
                continuation: Some(&historical),
            },
            policy,
            170,
        )
        .expect("actual local T/G commit");
    journal
        .acknowledge_local_credential_renewal(&authority, &receipt)
        .expect("component fixture acknowledges original completion");
    let local = c.grant.successor_device();
    let local_certificate = c
        .account
        .issue_device(local.description.clone(), local.key.clone())
        .expect("same local credential body");
    let peer_signer = crate::DeviceSigningKey::generate().expect("different controlled device key");
    let peer_certificate = c
        .account
        .issue_device(
            crate::DeviceDescription::new(
                [6; 16],
                1,
                c.old.family(),
                Validity::new(100, 180).expect("peer C0 interval"),
            )
            .expect("same account different device"),
            peer_signer.public_key().expect("peer key"),
        )
        .expect("same account peer C0");
    let previous = c
        .account
        .issue_roster(
            3,
            Validity::new(100, 190).expect("current roster interval"),
            &[
                c.account
                    .roster_entry(&peer_certificate)
                    .expect("peer sorts before local"),
                c.account
                    .roster_entry(&local_certificate)
                    .expect("local current C1"),
            ],
        )
        .expect("independent complete current roster");
    let pin = AccountPin::new(
        local.account_id(),
        c.account.public_key().expect("same account root"),
        previous.checkpoint(),
        c.old.family(),
    )
    .expect("independent current checkpoint");
    let roster = pin
        .verify_roster(previous.as_bytes(), 170)
        .expect("root-signed current roster");
    journal
        .install_roster(&roster, 170)
        .expect("observe same-account peer membership");
    let peer = pin
        .verify_device(&peer_certificate, previous.as_bytes(), 170)
        .expect("peer C0 under current roster");
    let mut description = peer.description.clone();
    description.validity = Validity::new(100, 185).expect("peer C1 validity extension");
    let successor = c
        .account
        .issue_device(description, peer.key.clone())
        .expect("same complete peer signing key");
    let mut entries = vec![c.account.roster_entry(&successor).expect("peer C1")];
    if !revoke_local {
        entries.push(
            c.account
                .roster_entry(&local_certificate)
                .expect("retain local C1"),
        );
    }
    let target = c
        .account
        .issue_roster(
            4,
            Validity::new(100, 190).expect("target roster interval"),
            &entries,
        )
        .expect("explicit next root authority");
    let next_pin = AccountPin::new(
        local.account_id(),
        c.account.public_key().expect("root"),
        target.checkpoint(),
        c.old.family(),
    )
    .expect("independent target checkpoint");
    let operation = CredentialRenewalId::generate().expect("original peer operation");
    let issued = c
        .account
        .issue_credential_renewal(
            crate::CredentialRenewalMaterials {
                original_credential: &peer_certificate,
                previous_credential: &peer_certificate,
                successor_credential: &successor,
                previous_roster: previous.as_bytes(),
                successor_roster: target.as_bytes(),
            },
            &crate::CredentialRenewalAuthorization {
                operation,
                previous: previous.checkpoint(),
                policy_digest: c.old.checkpoint().digest(),
            },
            &next_pin,
            181,
        )
        .expect("root grant after peer C0 and P0 expire");
    let renewal = VerifiedCredentialRenewal::verify(
        issued.as_bytes(),
        &next_pin,
        c.old.checkpoint().digest(),
        181,
    )
    .expect("independent peer grant verification");
    assert_ne!(
        renewal.original_storage_owner(),
        authority.owner,
        "peer does not own local storage"
    );
    journal.close();
    (c, directory, renewal, historical)
}

#[test]
fn continued_same_account_peer_updates_preserve_t_and_durably_observe_local_revocation() {
    for revoke_local in [false, true] {
        let (c, directory, renewal, historical) = continued_peer_case(revoke_local);
        let path = directory.path().canonicalize().expect("original path");
        let mut journal = crate::durable::tests::reopen(&path, c.grant.previous_device());
        let local = c.grant.successor_device();
        let policy = c.materials().target;
        let authority = crate::RetainedInstallationAuthority::active_installation(
            c.grant.previous_device(),
            &c.old,
        );
        let target = renewal.successor_device().roster().checkpoint();
        let operation = renewal.operation();
        let scope = crate::installation::PolicyScope {
            authority: &authority,
            original_policy: &c.old,
            original_device: c.grant.previous_device(),
        };
        journal
            .admit_continued_local_device(&scope, local, policy, 181)
            .expect("current local G/T before mutation");
        let result =
            journal.install_peer_credential_renewal(&scope, &renewal, operation, policy, 181);
        if revoke_local {
            assert!(
                result.is_err(),
                "no success after root-authorized local revocation"
            );
        } else {
            assert_eq!(result.expect("same-account peer update"), target);
            journal
                .admit_continued_local_device(&scope, local, policy, 181)
                .expect("choose local G, not earlier-sorting peer G");
        }
        assert_eq!(
            journal
                .roster_checkpoint(local.account_id())
                .expect("truthful observed authority"),
            target,
            "post-commit local denial must not discard the root-signed revocation"
        );
        let saved = get(
            &journal.image().expect("actual current image"),
            &local.account_id(),
        )
        .expect("actual retained roster");
        assert_same(&saved, historical.as_bytes(), historical.statement_digest());
        assert!(saved.local_commit.is_none());
        assert_eq!(
            saved
                .renewals
                .get(&local.device_id())
                .expect("original local G still distinct")
                .statement_digest(),
            c.grant.statement_digest()
        );
        assert_eq!(
            saved
                .renewals
                .get(&renewal.successor_device().device_id())
                .expect("independent peer G")
                .statement_digest(),
            renewal.statement_digest()
        );
        let before = journal.image().expect("committed target");
        let retry =
            journal.install_peer_credential_renewal(&scope, &renewal, operation, policy, 181);
        if revoke_local {
            assert!(
                retry.is_err(),
                "exact retry cannot revive the revoked local owner"
            );
            assert!(journal
                .admit_continued_local_device(&scope, local, policy, 181)
                .is_err());
        } else {
            assert_eq!(retry.expect("same original retry"), target);
        }
        let after = journal.image().expect("same target after retry");
        assert_eq!(
            (before.revision, before.digest),
            (after.revision, after.digest)
        );
    }
}

#[test]
fn continued_peer_renewal_sync_cuts_recover_exact_peer_operation_and_preserve_local_t() {
    use std::sync::atomic::Ordering;
    let (baseline, directory, grant, _) = continued_peer_case(false);
    let path = directory.path().canonicalize().expect("baseline path");
    let authority = crate::RetainedInstallationAuthority::active_installation(
        baseline.grant.previous_device(),
        &baseline.old,
    );
    let scope = crate::installation::PolicyScope {
        authority: &authority,
        original_policy: &baseline.old,
        original_device: baseline.grant.previous_device(),
    };
    let (mut journal, _, count, _) =
        crate::durable::tests::fault_store(&path, baseline.grant.previous_device(), false);
    count.store(0, Ordering::SeqCst);
    journal
        .install_peer_credential_renewal(
            &scope,
            &grant,
            grant.operation(),
            baseline.materials().target,
            181,
        )
        .expect("calibrate actual continued peer commit");
    let barriers = count.load(Ordering::SeqCst);
    assert!((1..=32).contains(&barriers));
    journal.close();
    let mut previous = 0;
    let mut committed = 0;
    for cut in 1..=barriers {
        for after_sync in [false, true] {
            let (c, directory, grant, t) = continued_peer_case(false);
            let path = directory
                .path()
                .canonicalize()
                .expect("original journal path");
            let local = c.grant.previous_device();
            let account = local.account_id();
            let authority =
                crate::RetainedInstallationAuthority::active_installation(local, &c.old);
            let scope = crate::installation::PolicyScope {
                authority: &authority,
                original_policy: &c.old,
                original_device: local,
            };
            let (mut journal, remaining, _, _) =
                crate::durable::tests::fault_store(&path, local, after_sync);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                journal.install_peer_credential_renewal(
                    &scope,
                    &grant,
                    grant.operation(),
                    c.materials().target,
                    181,
                ),
                after_sync,
            );
            assert!(journal.active.is_none());
            let mut restored = crate::durable::tests::reopen(&path, local);
            let before = restored.image().expect("authenticated original recovery");
            let saved = get(&before, &account).expect("atomic local T and peer grant history");
            assert_same(&saved, t.as_bytes(), t.statement_digest());
            assert!(saved.local_commit.is_none());
            assert_eq!(
                saved
                    .renewals
                    .get(&local.device_id())
                    .expect("unchanged local G")
                    .statement_digest(),
                c.grant.statement_digest()
            );
            if saved.roster.checkpoint() == grant.previous_device().roster().checkpoint() {
                previous += 1;
                assert!(!saved
                    .renewals
                    .contains_key(&grant.successor_device().device_id()));
            } else {
                committed += 1;
                assert_eq!(
                    saved.roster.checkpoint(),
                    grant.successor_device().roster().checkpoint()
                );
                assert_eq!(
                    saved
                        .renewals
                        .get(&grant.successor_device().device_id())
                        .expect("same committed peer G")
                        .statement_digest(),
                    grant.statement_digest()
                );
            }
            restored
                .install_peer_credential_renewal(
                    &scope,
                    &grant,
                    grant.operation(),
                    c.materials().target,
                    181,
                )
                .expect("only original peer operation recovery");
            let once = restored.image().expect("completed original peer target");
            let wrong = CredentialRenewalId::generate().expect("different operation");
            assert_ne!(wrong, grant.operation());
            assert!(restored
                .install_peer_credential_renewal(&scope, &grant, wrong, c.materials().target, 181)
                .is_err());
            restored
                .install_peer_credential_renewal(
                    &scope,
                    &grant,
                    grant.operation(),
                    c.materials().target,
                    181,
                )
                .expect("exact retry does not replace T or G");
            let twice = restored.image().expect("same exact completion");
            assert_eq!((once.revision, once.digest), (twice.revision, twice.digest));
        }
    }
    assert!(previous > 0 && committed > 0);
    eprintln!("CONTINUED_PEER_SYNC barriers={barriers} previous={previous} committed={committed} exact_T_preserved=true");
}
