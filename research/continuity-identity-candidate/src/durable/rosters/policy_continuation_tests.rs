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
    // The coordinator has not been connected yet. This fixture exercises the
    // real record codec/ordinary updates; it does not claim durable T admission.
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
