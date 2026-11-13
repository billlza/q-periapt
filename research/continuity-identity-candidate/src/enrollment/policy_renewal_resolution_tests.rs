// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::PolicyRenewalAbandonment;
#[path = "policy_renewal_resolution_recovery_tests.rs"]
mod recovery;

fn journal(c: &Case, original: &VerifiedDevice) -> DeviceService {
    DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original service metadata")
}
fn snapshot(c: &Case, original: &VerifiedDevice) -> (u64, [u8; 32]) {
    let mut service = journal(c, original);
    let image = service.stores().expect("stores").0.test_snapshot();
    service.close();
    (image.revision, image.digest)
}
fn resolve(
    c: &Case,
    a: &VerifiedPolicyRenewal,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<PolicyRenewalStatus, DurableError> {
    open(c).resolve_policy_renewal(
        a.scope().operation,
        a.statement_digest(),
        c.policy.historical(),
        policy.historical(),
        now,
    )
}
fn abandoned(
    a: &VerifiedPolicyRenewal,
    reason: PolicyRenewalAbandonment,
    observed: RosterCheckpoint,
    now: u64,
) -> PolicyRenewalStatus {
    PolicyRenewalStatus::AbandonedUncommitted {
        operation: a.scope().operation,
        statement: a.statement_digest(),
        target: a.target_policy(),
        reason,
        observed_roster: observed,
        observed_at: now,
    }
}

fn committed(a: &VerifiedPolicyRenewal) -> PolicyRenewalStatus {
    PolicyRenewalStatus::Committed {
        operation: a.scope().operation,
        statement: a.statement_digest(),
        target: a.target_policy(),
    }
}

fn expiring() -> (
    Case,
    VerifiedDevice,
    VerifiedSessionPolicy,
    VerifiedPolicyRenewal,
) {
    let (c, original, id) = local(160, 200);
    let p1 = policy(&c, 2, 190, 170);
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &a, &p1, 170);
    (c, original, p1, a)
}

fn advance(c: &Case, original: &VerifiedDevice, kind: &str, now: u64) -> RosterCheckpoint {
    let mut description = original.description.clone();
    if kind == "generation" {
        description.generation += 1;
    }
    let certificate = c
        .root
        .issue_device(description, original.key.clone())
        .expect("root-signed member");
    let members = if kind == "revoked" {
        Vec::new()
    } else {
        vec![c.root.roster_entry(&certificate).expect("member")]
    };
    let roster = c
        .root
        .issue_roster(2, Validity::new(100, 280).expect("interval"), &members)
        .expect("later roster");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent pin");
    let mut service = journal(c, original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(roster.as_bytes(), now)
                .expect("verified roster"),
            now,
        )
        .expect("actual concurrent roster");
    service.close();
    roster.checkpoint()
}

#[test]
fn actual_commit_wins_over_expiry_roster_advance_and_revocation_without_restoring_owner() {
    for kind in ["retained", "revoked", "generation"] {
        let (c, original, p1, a) = expiring();
        super::recovery::kill_at(&c, "policy-only-journal");
        assert_eq!(
            open(&c).policy_renewal_status().expect("original Pending"),
            pending(&a)
        );
        advance(&c, &original, kind, 175);
        let before = snapshot(&c, &original);
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let held = c.paths.signer.with_extension("resolution-commit-held");
        fs::rename(&c.paths.signer, &held).expect("unavailable private signer");
        assert_eq!(
            resolve(&c, &a, &p1, 195).expect("exact journal adoption"),
            committed(&a)
        );
        let after = snapshot(&c, &original);
        assert_eq!(after.0, before.0 + 1, "only exact policy receipt ACK");
        assert_eq!(
            resolve(&c, &a, &p1, 210).expect("idempotent historical result"),
            committed(&a)
        );
        assert_eq!(snapshot(&c, &original), after);
        fs::rename(held, &c.paths.signer).expect("restore signer");
        assert!(open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 195)
            .is_err());
    }
    eprintln!("POLICY_RESOLUTION_COMMITTED retained=true revoked=true generation=true exact_original=true");
}

#[test]
fn exact_predecessor_can_abandon_uncommitted_policy_even_after_member_revocation() {
    for kind in ["retained", "revoked", "generation"] {
        let (c, original, p1, a) = expiring();
        let head = advance(&c, &original, kind, 175);
        let before = snapshot(&c, &original);
        assert_eq!(
            resolve(&c, &a, &p1, 175).expect("exact unchanged policy predecessor"),
            abandoned(&a, PolicyRenewalAbandonment::RosterAdvanced, head, 175)
        );
        assert_eq!(snapshot(&c, &original), before);
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("no synthetic credential history"),
            CredentialRenewalStatus::Absent
        );
        assert!(open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 175)
            .is_err());
    }
}

#[test]
fn next_pending_resolution_preserves_actual_previous_policy_and_its_exact_approval() {
    let (c, original, id) = local(160, 240);
    let p1 = policy(&c, 2, 260, 170);
    let first = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &first, &p1, 170);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("adopt P1")
        .close();
    let p2 = policy(&c, 3, 300, 175);
    let second = super::credential::approve_successor(&c, &original, &original, &p1, &p2, 175);
    stage(&c, &second, &p2, 175);
    let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 280);
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), 180)
                .expect("verified R2"),
            180,
        )
        .expect("concurrent R2");
    service.close();
    let before = snapshot(&c, &original);
    assert_eq!(
        resolve(&c, &second, &p2, 180).expect("P1 proves P2 absent"),
        abandoned(
            &second,
            PolicyRenewalAbandonment::RosterAdvanced,
            next.checkpoint(),
            180
        )
    );
    assert_eq!(snapshot(&c, &original), before);
    let mut enrollment = open(&c);
    let image = enrollment.image().expect("original completion preserved");
    assert_eq!(
        enrollment
            .completed_policy_approval(&image)
            .expect("approval")
            .expect("P1")
            .journal_bytes(),
        first.historical().journal_bytes()
    );
    enrollment.close();
    open(&c)
        .refresh_roster(
            original.roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &p1,
            180,
        )
        .expect("P1 roster maintenance");
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 180)
        .expect("P1 remains actual policy")
        .close();
    let request = open(&c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("fresh ID"),
            c.policy.historical(),
        )
        .expect("new issuer request");
    assert_eq!(request.previous_policy, p1.checkpoint());
    assert_eq!(
        request.previous_authorization,
        Some(first.statement_digest())
    );
    assert_eq!(request.current_roster, next.checkpoint());
}

#[test]
fn later_actual_policy_never_becomes_no_commit_for_a_rolled_back_pending() {
    let (c, original, id) = local(160, 240);
    let p1 = policy(&c, 2, 260, 170);
    let first = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &first, &p1, 170);
    let old_pending = row(&open(&c));
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("P1")
        .close();
    let p2 = policy(&c, 3, 300, 175);
    let second = super::credential::approve_successor(&c, &original, &original, &p1, &p2, 175);
    stage(&c, &second, &p2, 175);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 175)
        .expect("P2")
        .close();
    let actual_config = row(&open(&c));
    let before = snapshot(&c, &original);
    replace_authenticated(&c, &old_pending);
    assert!(matches!(
        resolve(&c, &first, &p1, 270),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&c)), old_pending);
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("original unresolved state"),
        pending(&first)
    );
    assert_eq!(snapshot(&c, &original), before);
    replace_authenticated(&c, &actual_config);
    assert_eq!(
        resolve(&c, &second, &p2, 270).expect("actual P2 history"),
        committed(&second)
    );
}

#[test]
fn exact_policy_predecessor_and_new_roster_allow_original_operation_resolution_and_fresh_approval()
{
    let (c, original, id) = local(220, 240);
    let p1 = policy(&c, 2, 260, 170);
    let first = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &first, &p1, 170);
    let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 280);
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), 175)
                .expect("independently pinned roster"),
            175,
        )
        .expect("actual concurrent advancement");
    service.close();
    assert!(matches!(
        open(&c).reconcile_policy_renewal(c.policy.historical(), &p1, 175),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("unresolved original operation"),
        pending(&first)
    );
    let before = snapshot(&c, &original);
    let expected = abandoned(
        &first,
        PolicyRenewalAbandonment::RosterAdvanced,
        next.checkpoint(),
        175,
    );
    assert_eq!(
        resolve(&c, &first, &p1, 175).expect("policy predecessor proves no adoption"),
        expected
    );
    assert_eq!(
        snapshot(&c, &original),
        before,
        "no journal reset or guessed policy mutation"
    );
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("retained original outcome"),
        expected
    );
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("no synthetic G"),
        CredentialRenewalStatus::Absent
    );
    let encoded = row(&open(&c));
    assert_eq!(encoded.get(..8), Some(b"QPENST13".as_slice()));
    assert_eq!(encoded.get(8..16), Some(b"QPENST01".as_slice()));
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &first,
            first.scope().operation,
            c.policy.historical(),
            &p1,
            175
        ),
        Err(DurableError::Conflict)
    ));
    open(&c)
        .refresh_roster(
            original.roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &c.policy,
            175,
        )
        .expect("original P0 roster reconciliation");
    let mut active = open(&c)
        .activate(&c.policy, 175, None)
        .expect("original P0 remains actual policy");
    let current = active.parts().expect("parts").2.clone();
    active.close();
    assert!(
        matches!(
            open(&c).activate(&c.policy, 174, None),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "P-only observation floor guards legacy P0 owner"
    );
    let request = open(&c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("new operation"),
            c.policy.historical(),
        )
        .expect("actual original policy and new roster");
    assert_eq!(request.previous_policy, c.policy.checkpoint());
    assert_eq!(request.previous_authorization, None);
    let second = approved(&c, &original, &current, &p1, &request, 175);
    stage(&c, &second, &p1, 175);
    assert_eq!(
        resolve(&c, &first, &p1, 180).expect("old exact outcome while successor pending"),
        expected
    );
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 175)
        .expect("new exact approval from actual R2")
        .close();
    assert!(
        matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 174),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "floor survives policy completion"
    );
    assert!(
        matches!(resolve(&c, &first, &p1, 180), Err(DurableError::Conflict)),
        "retired old outcome not invented"
    );
}

#[test]
fn expired_policy_pending_is_resolved_without_runtime_or_private_signer_but_live_target_is_not_cancelled(
) {
    let (c, original, id) = local(160, 200);
    let p1 = policy(&c, 2, 190, 170);
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &a, &p1, 170);
    let before = snapshot(&c, &original);
    let pending_row = row(&open(&c));
    assert!(matches!(
        resolve(&c, &a, &p1, 175),
        Err(DurableError::Suspended)
    ));
    assert_eq!(row(&open(&c)), pending_row);
    p1.close();
    c.policy.close();
    c.policy.runtime.close();
    let held = c.paths.signer.with_extension("policy-resolution-held");
    fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
    let expected = abandoned(
        &a,
        PolicyRenewalAbandonment::Expired,
        original.roster().checkpoint(),
        195,
    );
    assert_eq!(
        resolve(&c, &a, &p1, 195).expect("signed target expiry plus exact P0 predecessor"),
        expected
    );
    assert_eq!(
        resolve(&c, &a, &p1, 210).expect("same original terminal"),
        expected
    );
    assert_eq!(snapshot(&c, &original), before);
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("G remains absent"),
        CredentialRenewalStatus::Absent
    );
    fs::rename(held, &c.paths.signer).expect("restore original signer");
}

#[test]
fn expired_unchanged_credential_unblocks_real_joint_renewal_from_original_policy() {
    let (c, original, id) = local(160, 180);
    let p1 = policy(&c, 2, 280, 170);
    let first = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &first, &p1, 170);
    let before = snapshot(&c, &original);
    let expected = abandoned(
        &first,
        PolicyRenewalAbandonment::Expired,
        original.roster().checkpoint(),
        185,
    );
    assert_eq!(
        resolve(&c, &first, &p1, 185).expect("expired unchanged C proves fixed target unusable"),
        expected
    );
    assert_eq!(snapshot(&c, &original), before);
    let g = renewal::grant(&c, &original, &original, 2, 240);
    let next = policy(&c, 3, 300, 185);
    let joint = super::super::policy_continuation::joint(
        &c,
        &g,
        &super::super::policy_continuation::scope(&c, &g, id),
        &c.policy,
        &next,
    );
    assert!(matches!(
        open(&c).stage_policy_continuation(&g, &joint, g.operation(), &next, 184),
        Err(DurableError::Protocol(Error::Validity))
    ));
    open(&c)
        .stage_policy_continuation(&g, &joint, g.operation(), &next, 185)
        .expect("actual new joint authorization from P0");
    let mut active = open(&c)
        .activate_policy_continuation(c.policy.historical(), &next, 185)
        .expect("original owner with real renewed C and policy");
    assert_eq!(
        active.parts().expect("owner").2.credential_digest(),
        g.successor_device().credential_digest()
    );
    active.close();
    assert_eq!(
        resolve(&c, &first, &p1, 190).expect("old exact policy outcome survives real G/T"),
        expected
    );
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("real credential history"),
        CredentialRenewalStatus::Committed {
            operation: g.operation(),
            statement: joint.statement_digest(),
            target: g.successor_device().roster().checkpoint(),
        }
    );
    assert!(matches!(
        open(&c).activate_policy_continuation(c.policy.historical(), &next, 184),
        Err(DurableError::Protocol(Error::Validity))
    ));
}

#[test]
fn expired_fixed_roster_and_mismatched_resolution_inputs_are_distinguished() {
    let (c, original, _) = local(220, 240);
    let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 180);
    open(&c)
        .refresh_roster(
            original.roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &c.policy,
            170,
        )
        .expect("shorter live R2");
    let mut active = open(&c).activate(&c.policy, 170, None).expect("R2 owner");
    let current = active.parts().expect("current").2.clone();
    active.close();
    let p1 = policy(&c, 2, 280, 175);
    let request = open(&c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("ID"),
            c.policy.historical(),
        )
        .expect("actual R2 request");
    let first = approved(&c, &original, &current, &p1, &request, 175);
    stage(&c, &first, &p1, 175);
    let saved = row(&open(&c));
    let wrong = policy(&c, 3, 300, 175);
    assert!(matches!(
        resolve(&c, &first, &wrong, 185),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let mut wrong_statement = first.statement_digest();
    *wrong_statement.first_mut().expect("statement") ^= 1;
    assert!(matches!(
        open(&c).resolve_policy_renewal(
            first.scope().operation,
            wrong_statement,
            c.policy.historical(),
            p1.historical(),
            185
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        open(&c).resolve_policy_renewal(
            PolicyRenewalId::generate().expect("different ID"),
            first.statement_digest(),
            c.policy.historical(),
            p1.historical(),
            185
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&c)), saved, "bad inputs leave exact Pending");
    let before = snapshot(&c, &original);
    let expected = abandoned(
        &first,
        PolicyRenewalAbandonment::Expired,
        next.checkpoint(),
        185,
    );
    assert_eq!(
        resolve(&c, &first, &p1, 185).expect("only signed R2 has expired"),
        expected
    );
    assert_eq!(snapshot(&c, &original), before);
    assert!(matches!(
        resolve(&c, &first, &wrong, 190),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        resolve(&c, &first, &p1, 190).expect("exact cached terminal"),
        expected
    );
}
