// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "historical_policy_recovery_tests.rs"]
mod historical_recovery;
use crate::{
    CredentialRenewalStatus, PolicyContinuationMaterials, PolicyContinuationScope,
    PolicyContinuationStatement, PolicyPin, PolicySigningKey, RetainedInstallationAuthority,
    SessionPolicyParameters, Validity, VerifiedCredentialRenewal, VerifiedPolicyContinuation,
};

pub(super) fn policy(c: &Case, version: u64, until: u64, now: u64) -> VerifiedSessionPolicy {
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32])
        .expect("original independent policy authority");
    let issued = issuer
        .issue_session_policy(
            &c.policy.runtime,
            SessionPolicyParameters::new(
                version,
                Validity::new(100, until).expect("validity"),
                c.policy.allowed_modes(),
                c.policy.anchor_requirement(),
                c.policy.application_send_budget(),
            )
            .expect("parameters"),
        )
        .expect("signed extension");
    PolicyPin::new(
        c.policy.family(),
        issuer.public_key().expect("policy key"),
        issued.checkpoint(),
    )
    .expect("independently approved target pin")
    .verify(issued.as_bytes(), Arc::clone(&c.policy.runtime), now)
    .expect("actual policy owner")
}
fn local() -> (Case, VerifiedDevice, JournalIdentity) {
    let mut c = case();
    c.policy = policy(&c, 1, 160, 150);
    c.intent.description.validity = Validity::new(100, 160).expect("original credential expires");
    let (mut owner, _, journal) = accepted(&c);
    let image = owner.image().expect("image");
    let original = owner
        .admitted(&image, &c.policy, 150)
        .expect("original credential");
    owner.prepare(&c.policy, 150).expect("original children");
    owner
        .activate(&c.policy, 150, None)
        .expect("original live installation")
        .close();
    (c, original, journal)
}
pub(super) fn scope(
    c: &Case,
    g: &VerifiedCredentialRenewal,
    journal: JournalIdentity,
) -> PolicyContinuationScope {
    PolicyContinuationScope {
        operation: g.operation(),
        journal,
        original_owner: g.original_storage_owner(),
        original_credential: g.original_credential_digest(),
        previous_credential: g.previous_device().credential_digest(),
        previous_roster: g.previous_device().roster().checkpoint(),
        original_policy: c.policy.checkpoint(),
        previous_policy: c.policy.checkpoint(),
        previous_authorization: None,
    }
}
pub(super) fn joint(
    c: &Case,
    g: &VerifiedCredentialRenewal,
    scope: &PolicyContinuationScope,
    previous: &VerifiedSessionPolicy,
    target: &VerifiedSessionPolicy,
) -> VerifiedPolicyContinuation {
    let materials = PolicyContinuationMaterials {
        original: c.policy.historical(),
        previous: previous.historical(),
        target,
        credential: g,
    };
    let statement =
        PolicyContinuationStatement::new(scope, &materials, 170).expect("joint request");
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy authority");
    let a = c
        .root
        .approve_policy_continuation(&statement)
        .expect("independent account approval");
    let p = issuer
        .approve_policy_continuation(&statement)
        .expect("independent policy approval");
    VerifiedPolicyContinuation::verify(&a, &p, scope, &materials, 170)
        .expect("complete joint proof")
}
fn row(owner: &DeviceEnrollment) -> Vec<u8> {
    let tx = owner
        .active
        .as_ref()
        .expect("configuration lease")
        .database
        .begin_read()
        .expect("read transaction");
    tx.open_table(TABLE)
        .expect("configuration table")
        .get("enrollment")
        .expect("row")
        .expect("existing row")
        .value()
        .to_vec()
}
fn pending(t: &VerifiedPolicyContinuation) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Pending {
        operation: t.scope().operation,
        statement: t.statement_digest(),
    }
}

#[test]
fn authenticated_pending_record_cannot_substitute_another_valid_joint_target() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let p2 = policy(&c, 3, 195, 170);
    let expected = scope(&c, &g, id);
    let t1 = joint(&c, &g, &expected, &c.policy, &p1);
    let t2 = joint(&c, &g, &expected, &c.policy, &p2);
    let mut owner = open(&c);
    owner
        .stage_policy_continuation(&g, &t1, g.operation(), &p1, 170)
        .expect("original T1 intent");
    let mut bytes = row(&owner);
    let first = t1.historical().journal_bytes();
    let second = t2.historical().journal_bytes();
    assert_eq!(first.len(), second.len());
    assert_eq!(
        bytes
            .windows(first.len())
            .filter(|part| *part == first)
            .count(),
        1
    );
    let offset = bytes
        .windows(first.len())
        .position(|part| part == first)
        .expect("saved exact T1");
    bytes
        .get_mut(offset..offset + second.len())
        .expect("same-width T field")
        .copy_from_slice(&second);
    // Model access to the wrapping key and a second genuinely approved T; do
    // not forge either authority signature. The original Pending header stays T1.
    let body_len = bytes.len().checked_sub(32).expect("authenticated row");
    let active = owner.active.as_ref().expect("original config lease");
    let mut mac = auth(&active.key).expect("fixture wrapping-key capability");
    mac.update(bytes.get(..body_len).expect("row body"));
    bytes
        .get_mut(body_len..)
        .expect("MAC slot")
        .copy_from_slice(&mac.finalize().into_bytes());
    write(&active.database, &bytes).expect("retain authenticated inconsistent fixture");
    assert!(matches!(
        owner.stage_policy_continuation(&g, &t1, g.operation(), &p1, 170),
        Err(DurableError::Conflict)
    ));
    let recovered = open(&c);
    assert_eq!(
        row(&recovered),
        bytes,
        "no silent repair or replacement of the original intent"
    );
}

#[test]
fn joint_pending_survives_original_enrollment_reopen_after_both_expiries() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let original_files = c
        .paths
        .installation
        .files()
        .map(|path| fs::read(path).expect("original installation bytes"));
    assert!(c
        .policy
        .check_mode(PrekeyQuality::OneTimeBoth, 170)
        .is_err());
    assert!(original.description.validity.check(170).is_err());
    assert!(open(&c)
        .stage_credential_renewal(&g, g.operation(), &c.policy, 170)
        .is_err());
    let mut owner = open(&c);
    assert_eq!(
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
            .expect("first durable joint intent"),
        pending(&t)
    );
    let saved = row(&owner);
    assert_eq!(saved.get(..8), Some(b"QPENST06".as_slice()));
    let material = t.historical().journal_bytes();
    assert_eq!(
        saved
            .windows(material.len())
            .filter(|window| *window == material)
            .count(),
        1
    );
    assert_eq!(
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p1, 175)
            .expect("same original intent"),
        pending(&t)
    );
    assert_eq!(row(&owner), saved);
    owner.close();
    let mut owner = open(&c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("read original progress"),
        pending(&t)
    );
    assert_eq!(row(&owner), saved);
    assert_eq!(
        c.paths
            .installation
            .files()
            .map(|path| fs::read(path).expect("installation remains unchanged")),
        original_files
    );
    // Readback of saved history does not grant a new lease at target expiry.
    assert_eq!(
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p1, 195)
            .expect("historical exact intent"),
        pending(&t)
    );
    assert_eq!(row(&owner), saved);
}

#[test]
fn same_credential_operation_cannot_replace_the_first_saved_policy_authorization() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let p2 = policy(&c, 3, 195, 170);
    let expected = scope(&c, &g, id);
    let t1 = joint(&c, &g, &expected, &c.policy, &p1);
    let t2 = joint(&c, &g, &expected, &c.policy, &p2);
    assert_ne!(t1.statement_digest(), t2.statement_digest());
    let mut owner = open(&c);
    owner
        .stage_policy_continuation(&g, &t1, g.operation(), &p1, 170)
        .expect("save T1");
    let saved = row(&owner);
    assert!(matches!(
        owner.stage_policy_continuation(&g, &t2, g.operation(), &p2, 170),
        Err(DurableError::Conflict)
    ));
    let mut owner = open(&c);
    assert_eq!(row(&owner), saved);
    assert_eq!(
        owner.credential_renewal_status().expect("still original"),
        pending(&t1)
    );
    assert!(matches!(
        owner.stage_credential_renewal(&g, g.operation(), &c.policy, 150),
        Err(DurableError::Conflict)
    ));
    let owner = open(&c);
    assert_eq!(row(&owner), saved);
}

#[test]
fn credential_only_pending_cannot_acquire_a_later_policy_approval() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let mut owner = open(&c);
    owner
        .stage_credential_renewal(&g, g.operation(), &c.policy, 150)
        .expect("original credential-only operation");
    let saved = row(&owner);
    assert_eq!(saved.get(..8), Some(b"QPENST02".as_slice()));
    assert!(matches!(
        owner.stage_policy_continuation(&g, &t, g.operation(), &p1, 170),
        Err(DurableError::Conflict)
    ));
    let mut owner = open(&c);
    assert_eq!(row(&owner), saved);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("unchanged original statement"),
        renewal::pending(&g)
    );
}

#[test]
fn authentic_foreign_journal_and_invented_policy_predecessor_never_create_pending() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let p2 = policy(&c, 3, 195, 170);
    let mut expected = scope(&c, &g, JournalIdentity::generate().expect("other journal"));
    let other = joint(&c, &g, &expected, &c.policy, &p1);
    let mut owner = open(&c);
    let saved = row(&owner);
    assert!(matches!(
        owner.stage_policy_continuation(&g, &other, g.operation(), &p1, 170),
        Err(DurableError::Conflict)
    ));
    expected.journal = id;
    expected.previous_policy = p1.checkpoint();
    expected.previous_authorization = Some([9; 32]);
    let invented = joint(&c, &g, &expected, &p1, &p2); // Both signatures are authentic.
    let mut owner = open(&c);
    assert_eq!(row(&owner), saved);
    assert!(matches!(
        owner.stage_policy_continuation(&g, &invented, g.operation(), &p2, 170),
        Err(DurableError::Conflict)
    ));
    let mut owner = open(&c);
    assert_eq!(row(&owner), saved);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("no adopted predecessor"),
        CredentialRenewalStatus::Absent
    );
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    p1.close();
    assert!(matches!(
        owner.stage_policy_continuation(&g, &t, g.operation(), &p1, 170),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(row(&open(&c)), saved);
}

#[test]
fn joint_intent_sync_failures_preserve_the_exact_original_approvals() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let (mut owner, _, count) = faulty(&c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("calibrate exact joint intent");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=16).contains(&syncs));
    let (mut absent, mut pending_count) = (0, 0);
    for cut in 1..=syncs {
        for after in [false, true] {
            let (c, original, id) = local();
            let g = renewal::grant(&c, &original, &original, 2, 190);
            let p1 = policy(&c, 2, 190, 170);
            let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
            let children = c
                .paths
                .installation
                .files()
                .map(|p| fs::read(p).expect("original child"));
            let signer = fs::read(&c.paths.signer).expect("original controlled signer");
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.stage_policy_continuation(&g, &t, g.operation(), &p1, 170),
                after,
            );
            assert!(owner.active.is_none());
            let mut recovered = open(&c);
            let before = row(&recovered);
            let material = t.historical().journal_bytes();
            let status = recovered
                .credential_renewal_status()
                .expect("actual persisted outcome");
            if status == CredentialRenewalStatus::Absent {
                absent += 1;
                assert!(!before.windows(material.len()).any(|w| w == material));
            } else {
                assert_eq!(
                    status,
                    pending(&t),
                    "intent write cannot create terminal state"
                );
                pending_count += 1;
                assert_eq!(
                    before
                        .windows(material.len())
                        .filter(|w| *w == material)
                        .count(),
                    1
                );
            }
            assert_eq!(
                recovered
                    .stage_policy_continuation(&g, &t, g.operation(), &p1, 175)
                    .expect("same original authorization retry"),
                pending(&t)
            );
            assert_eq!(
                row(&recovered)
                    .windows(material.len())
                    .filter(|w| *w == material)
                    .count(),
                1
            );
            assert_eq!(
                c.paths
                    .installation
                    .files()
                    .map(|p| fs::read(p).expect("unchanged child")),
                children
            );
            assert_eq!(fs::read(&c.paths.signer).expect("same signer"), signer);
        }
    }
    assert!(absent > 0 && pending_count > 0);
    eprintln!("JOINT_POLICY_INTENT_SYNC barriers={syncs} absent={absent} pending={pending_count}");
}

fn committed(
    t: &VerifiedPolicyContinuation,
    g: &VerifiedCredentialRenewal,
) -> CredentialRenewalStatus {
    CredentialRenewalStatus::Committed {
        operation: g.operation(),
        statement: t.statement_digest(),
        target: g.successor_device().roster().checkpoint(),
    }
}
fn journal(c: &Case, original: &VerifiedDevice) -> crate::DeviceService {
    DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        open(c).key().expect("original wrapping key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original historical installation, no operational admission")
}
#[test]
fn local_joint_commit_retains_exact_policy_after_ack_without_releasing_an_owner() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 200);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let mut owner = open(&c);
    let identity = owner.identity().expect("original signer id");
    let signer = fs::read(&c.paths.signer).expect("signer bytes");
    owner
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("durable joint intent");
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
            .expect("local joint commit"),
        committed(&t, &g)
    );
    let saved = row(&owner);
    assert_eq!(saved.get(..8), Some(b"QPENST06".as_slice()));
    let material = t.historical().journal_bytes();
    assert_eq!(
        saved
            .windows(material.len())
            .filter(|w| *w == material)
            .count(),
        1
    );
    assert_eq!(owner.identity().expect("same signer id"), identity);
    assert_eq!(fs::read(&c.paths.signer).expect("same signer"), signer);
    owner.close();
    let mut owner = open(&c);
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p1, 195)
            .expect("historical committed readback after P1 expiry"),
        committed(&t, &g)
    );
    assert_eq!(row(&owner), saved);
    owner.close();
    assert!(matches!(
        open(&c).activate(&p1, 175, None),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        open(&c).activate(&c.policy, 150, None),
        Err(DurableError::Suspended)
    ));
    let mut service = journal(&c, &original);
    let j = service.stores().expect("leased stores").0;
    assert_eq!(j.identity().expect("same journal"), id);
    assert_eq!(
        j.roster_checkpoint(original.account_id())
            .expect("installed C1 roster"),
        g.successor_device().roster().checkpoint()
    );
    let authority =
        RetainedInstallationAuthority::active_installation(&original, c.policy.historical());
    j.check_local_policy_continuation(&authority, &t.historical())
        .expect("exact T survives receipt ACK");
    assert!(
        j.check_enrollment_authority(g.successor_device(), &p1, 175)
            .is_err(),
        "plain account admission has no exact-T capability"
    );
}

fn snapshot(
    c: &Case,
    original: &VerifiedDevice,
    id: JournalIdentity,
) -> ([u8; 32], [u8; 32], u64, [u8; 32]) {
    let mut j = crate::DeviceJournal::open(
        c.paths.installation.files()[1],
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        id,
    )
    .expect("original authenticated journal");
    let s = j.test_snapshot();
    (s.id, s.owner, s.revision, s.digest)
}
#[test]
fn expired_or_closed_target_never_creates_a_joint_journal_commit() {
    for closed in [false, true] {
        let (c, original, id) = local();
        let g = renewal::grant(&c, &original, &original, 2, 220);
        let p1 = policy(&c, 2, 190, 170);
        let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
        let mut owner = open(&c);
        owner
            .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
            .expect("intent");
        let saved = row(&owner);
        let before = snapshot(&c, &original, id);
        let physical = c
            .paths
            .installation
            .files()
            .map(|p| fs::read(p).expect("child bytes"));
        assert_eq!(snapshot(&c, &original, id), before);
        let read_only_changes = c
            .paths
            .installation
            .files()
            .into_iter()
            .zip(&physical)
            .filter(|(path, old)| fs::read(path).expect("read-only reopen bytes") != **old)
            .count();
        eprintln!("JOINT_READ_ONLY_REOPEN physical_files_changed={read_only_changes} authenticated_head_unchanged=true");
        if closed {
            p1.close();
        }
        let at = if closed { 175 } else { 195 };
        g.successor_device()
            .description
            .validity
            .check(at)
            .expect("C1 is still live: refusal must come from P1");
        assert!(matches!(
            owner.reconcile_policy_continuation(c.policy.historical(), &p1, at),
            Err(DurableError::Protocol(Error::Closed | Error::Validity))
        ));
        let mut owner = open(&c);
        assert_eq!(row(&owner), saved);
        assert_eq!(
            owner
                .credential_renewal_status()
                .expect("unresolved exact intent"),
            pending(&t)
        );
        // redb open/close may update file bookkeeping. Exact authenticated
        // image digest/revision/owner is the protocol mutation boundary.
        assert_eq!(snapshot(&c, &original, id), before);
    }
}

#[test]
fn joint_completion_configuration_faults_recover_exact_commit_after_policy_expiry() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 220);
    let p1 = policy(&c, 2, 190, 170);
    let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    open(&c)
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("intent");
    let (mut owner, _, count) = faulty(&c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
        .expect("calibrate completion");
    let syncs = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=12).contains(&syncs));
    let (mut pending_count, mut completed_count) = (0, 0);
    for cut in 1..=syncs {
        for after in [false, true] {
            let (c, original, id) = local();
            let g = renewal::grant(&c, &original, &original, 2, 220);
            let p1 = policy(&c, 2, 190, 170);
            let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
            open(&c)
                .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
                .expect("intent");
            let signer = fs::read(&c.paths.signer).expect("original signer");
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.reconcile_policy_continuation(c.policy.historical(), &p1, 170),
                after,
            );
            assert!(owner.active.is_none());
            let mut owner = open(&c);
            let state = owner.credential_renewal_status().expect("durable outcome");
            if state == pending(&t) {
                pending_count += 1;
            } else {
                assert_eq!(state, committed(&t, &g));
                completed_count += 1;
            }
            // The journal commit precedes every injected configuration cut.
            // It may be completed after P1 expires without creating new work.
            assert_eq!(
                owner
                    .reconcile_policy_continuation(c.policy.historical(), &p1, 195)
                    .expect("exact historical journal commit"),
                committed(&t, &g)
            );
            assert_eq!(fs::read(&c.paths.signer).expect("unchanged signer"), signer);
            let material = t.historical().journal_bytes();
            assert_eq!(
                row(&owner)
                    .windows(material.len())
                    .filter(|w| *w == material)
                    .count(),
                1
            );
        }
    }
    assert!(pending_count > 0 && completed_count > 0);
    eprintln!("JOINT_POLICY_COMPLETION_SYNC barriers={syncs} pending={pending_count} completed={completed_count}");
}

#[test]
fn credential_only_successor_preserves_t_then_next_joint_update_uses_exact_policy_predecessor() {
    let (c, original, id) = local();
    let g1 = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 200, 170);
    let t1 = joint(&c, &g1, &scope(&c, &g1, id), &c.policy, &p1);
    let mut owner = open(&c);
    owner
        .stage_policy_continuation(&g1, &t1, g1.operation(), &p1, 170)
        .expect("first T");
    owner
        .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
        .expect("commit first T");
    let g2 = renewal::grant(&c, &original, g1.successor_device(), 3, 210);
    owner
        .stage_credential_renewal(&g2, g2.operation(), &p1, 175)
        .expect("credential-only next intent");
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p1, 175)
            .expect("same adopted policy, new G"),
        renewal::committed(&g2)
    );
    owner.close();
    let authority =
        RetainedInstallationAuthority::active_installation(&original, c.policy.historical());
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .check_local_policy_continuation(&authority, &t1.historical())
        .expect("T1 survives replacement of G and two ACKs");
    service.close();
    let p2 = policy(&c, 3, 230, 180);
    let g3 = renewal::grant(&c, &original, g2.successor_device(), 4, 230);
    let mut predecessor = scope(&c, &g3, id);
    predecessor.previous_policy = p1.checkpoint();
    predecessor.previous_authorization = Some(t1.statement_digest());
    let t2 = joint(&c, &g3, &predecessor, &p1, &p2);
    let mut owner = open(&c);
    owner
        .stage_policy_continuation(&g3, &t2, g3.operation(), &p2, 180)
        .expect("joint T2 follows exact adopted T1, not G2");
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p2, 180)
            .expect("second joint commit"),
        committed(&t2, &g3)
    );
    owner.close();
    let mut service = journal(&c, &original);
    let j = service.stores().expect("stores").0;
    j.check_local_policy_continuation(&authority, &t2.historical())
        .expect("T2 adopted");
    assert!(matches!(
        j.check_local_policy_continuation(&authority, &t1.historical()),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn committed_joint_receipt_cannot_be_reinterpreted_as_another_valid_policy_target() {
    let (c, original, id) = local();
    let g = renewal::grant(&c, &original, &original, 2, 220);
    let p1 = policy(&c, 2, 190, 170);
    let p2 = policy(&c, 3, 195, 170);
    let t1 = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
    let t2 = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p2);
    open(&c)
        .stage_policy_continuation(&g, &t1, g.operation(), &p1, 170)
        .expect("durable T1 intent");
    let mut service = journal(&c, &original);
    let j = service.stores().expect("stores").0;
    let authority =
        RetainedInstallationAuthority::active_installation(&original, c.policy.historical());
    let h1 = t1.historical();
    let h2 = t2.historical();
    let target1 = crate::durable::LocalRenewalTarget {
        grant: &g,
        continuation: Some(&h1),
    };
    let target2 = crate::durable::LocalRenewalTarget {
        grant: &g,
        continuation: Some(&h2),
    };
    let receipt = j
        .commit_local_renewal(&authority, &target1, &p1, 170)
        .expect("journal T1 committed; configuration still Pending");
    assert_eq!(receipt.statement, t1.statement_digest());
    let before = j.test_snapshot();
    assert!(matches!(
        j.reconcile_prior_local_target(&authority, &target2, None),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        j.commit_local_renewal(&authority, &target2, &p2, 175),
        Err(DurableError::Conflict)
    ));
    let after = j.test_snapshot();
    assert_eq!(
        (after.revision, after.digest),
        (before.revision, before.digest)
    );
    service.close();
    let mut owner = open(&c);
    assert_eq!(
        owner.credential_renewal_status().expect("original pending"),
        pending(&t1)
    );
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p1, 195)
            .expect("only exact T1 recovers, even after P1 expiry"),
        committed(&t1, &g)
    );
}

#[test]
fn joint_policy_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_JOINT_POLICY_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let original = policy(&template, 1, 160, 150);
    let shape = fs::read(root.join("trusted-policy-shape")).expect("independent target profile");
    let mut d = Decoder::new(&shape);
    let version = d.u64().expect("target version");
    let until = d.u64().expect("target expiry");
    d.finish().expect("exact target shape");
    let target = policy(&template, version, until, 170);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent original root"))
            .expect("account root"),
        DeviceDescription::new(
            [7; 16],
            1,
            original.family(),
            Validity::new(100, 160).expect("original interval"),
        )
        .expect("original intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    owner
        .reconcile_policy_continuation(original.historical(), &target, 170)
        .expect("same joint coordinator");
    Err("requested joint boundary did not suspend the child")
}

#[test]
fn real_process_cuts_recover_joint_target_after_policy_expiry_at_each_commit_boundary() {
    let mut cuts = 0;
    for stage in ["journal", "completion", "acknowledgement"] {
        let (c, original, id) = local();
        let g = renewal::grant(&c, &original, &original, 2, 220);
        let p1 = policy(&c, 2, 190, 170);
        let t = joint(&c, &g, &scope(&c, &g, id), &c.policy, &p1);
        open(&c)
            .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
            .expect("original Pending");
        let signer = fs::read(&c.paths.signer).expect("original controlled signer");
        kill_at(&c, 2, 190, stage);
        let mut owner = open(&c);
        let observed = owner
            .credential_renewal_status()
            .expect("persisted boundary");
        assert_eq!(
            observed,
            if stage == "journal" {
                pending(&t)
            } else {
                committed(&t, &g)
            }
        );
        assert_eq!(
            owner
                .reconcile_policy_continuation(c.policy.historical(), &p1, 195)
                .expect("historical exact completion after P1 expiry"),
            committed(&t, &g)
        );
        assert_eq!(fs::read(&c.paths.signer).expect("same signer"), signer);
        owner.close();
        let mut service = journal(&c, &original);
        let j = service.stores().expect("original stores").0;
        assert_eq!(j.identity().expect("same journal"), id);
        let authority =
            RetainedInstallationAuthority::active_installation(&original, c.policy.historical());
        j.check_local_policy_continuation(&authority, &t.historical())
            .expect("original approvals survive process kill and ACK");
        cuts += 1;
    }
    eprintln!("JOINT_POLICY_PROCESS_CUTS cuts={cuts} expired_exact_recovery=true operational_owner_released=false");
}

fn kill_at(c: &Case, version: u64, until: u64, stage: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent account pin");
    let shape = [version.to_be_bytes(), until.to_be_bytes()].concat();
    fs::write(root.join("trusted-policy-shape"), shape).expect("independent target profile");
    if root.join("renewal-ready").exists() {
        fs::remove_file(root.join("renewal-ready")).expect("consume prior test marker");
    }
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "enrollment::tests::policy_continuation::joint_policy_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_JOINT_POLICY_CUT_ROOT", root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("renewal-ready").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "joint child did not reach {stage}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("real process cut");
    assert!(!child.0.wait().expect("reap child").success());
}

#[test]
fn second_joint_intent_retires_only_completed_t1_receipt_and_recovers_its_own_t2_receipt() {
    let (c, original, id) = local();
    let g1 = renewal::grant(&c, &original, &original, 2, 190);
    let p1 = policy(&c, 2, 190, 170);
    let t1 = joint(&c, &g1, &scope(&c, &g1, id), &c.policy, &p1);
    open(&c)
        .stage_policy_continuation(&g1, &t1, g1.operation(), &p1, 170)
        .expect("T1 Pending");
    kill_at(&c, 2, 190, "completion");
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("T1 config durable, ACK not run"),
        committed(&t1, &g1)
    );
    let g2 = renewal::grant(&c, &original, g1.successor_device(), 3, 230);
    let p2 = policy(&c, 3, 230, 170);
    let mut predecessor = scope(&c, &g2, id);
    predecessor.previous_policy = p1.checkpoint();
    predecessor.previous_authorization = Some(t1.statement_digest());
    let t2 = joint(&c, &g2, &predecessor, &p1, &p2);
    open(&c)
        .stage_policy_continuation(&g2, &t2, g2.operation(), &p2, 170)
        .expect("T2 staged while T1 receipt is retained");
    kill_at(&c, 3, 230, "journal");
    let mut owner = open(&c);
    assert_eq!(
        owner
            .credential_renewal_status()
            .expect("T2 config still Pending"),
        pending(&t2)
    );
    assert_eq!(
        owner
            .reconcile_policy_continuation(c.policy.historical(), &p2, 240)
            .expect("exact T2 receipt after P2 expiry"),
        committed(&t2, &g2)
    );
    owner.close();
    let mut service = journal(&c, &original);
    let j = service.stores().expect("original stores").0;
    let authority =
        RetainedInstallationAuthority::active_installation(&original, c.policy.historical());
    j.check_local_policy_continuation(&authority, &t2.historical())
        .expect("T2, not the previously completed T1");
    assert!(matches!(
        j.check_local_policy_continuation(&authority, &t1.historical()),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        j.test_snapshot().revision,
        5,
        "two commits and two distinct receipt ACKs"
    );
    eprintln!("JOINT_POLICY_CHAIN_PROCESS cuts=2 t1_completion_before_ack=true t2_journal_before_completion=true expired_t2_recovered=true");
}

#[path = "policy_continuation_owner_tests.rs"]
mod owner;
