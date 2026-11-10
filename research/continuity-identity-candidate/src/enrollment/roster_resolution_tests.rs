// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{IssuedRoster, RosterRefreshOutcome, RosterRefreshResolution};
#[path = "roster_resolution_recovery_tests.rs"]
mod recovery;

fn head(
    c: &Case,
    current: &VerifiedDevice,
    version: u64,
    until: u64,
) -> (IssuedRoster, AccountPin) {
    super::policy_roster::next_roster(c, current, version, until)
}
fn begin(
    c: &Case,
    current: &VerifiedDevice,
    next: &IssuedRoster,
    pin: &AccountPin,
    policy: &VerifiedSessionPolicy,
    now: u64,
) {
    assert!(matches!(
        open(c)
            .refresh_roster(
                current.roster().checkpoint(),
                next.as_bytes(),
                pin,
                policy,
                now
            )
            .expect("original roster intent"),
        EnrollmentStatus::Refreshing { .. }
    ));
}
fn journal(c: &Case, original: &VerifiedDevice) -> DeviceService {
    DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original metadata service")
}
fn install(c: &Case, original: &VerifiedDevice, next: &IssuedRoster, pin: &AccountPin, now: u64) {
    let mut service = journal(c, original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), now)
                .expect("independent current roster"),
            now,
        )
        .expect("actual journal advance");
    service.close();
}
fn snapshot(c: &Case, original: &VerifiedDevice) -> (u64, [u8; 32]) {
    let mut service = journal(c, original);
    let s = service.stores().expect("stores").0.test_snapshot();
    service.close();
    (s.revision, s.digest)
}
fn resolve(
    c: &Case,
    previous: RosterCheckpoint,
    target: RosterCheckpoint,
    now: u64,
) -> Result<RosterRefreshResolution, DurableError> {
    open(c).resolve_roster_refresh(previous, target, c.policy.historical(), now)
}
fn expected(
    id: JournalIdentity,
    previous: RosterCheckpoint,
    target: RosterCheckpoint,
    outcome: RosterRefreshOutcome,
    observed: RosterCheckpoint,
    observed_at: u64,
) -> RosterRefreshResolution {
    RosterRefreshResolution {
        journal: id,
        previous,
        target,
        outcome,
        observed,
        observed_at,
    }
}

#[test]
fn expired_absent_roster_restores_actual_predecessor_and_allows_fresh_original_refresh() {
    let (c, original, id) = local(220, 240);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 2, 180);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    let (next, next_pin) = head(&c, &original, 3, 280);
    assert!(matches!(
        open(&c).refresh_roster(previous, next.as_bytes(), &next_pin, &c.policy, 185),
        Err(DurableError::Conflict)
    ));
    let before = snapshot(&c, &original);
    let result = expected(
        id,
        previous,
        target.checkpoint(),
        RosterRefreshOutcome::ExpiredUncommitted,
        previous,
        185,
    );
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 185).expect("proof of signed target expiry"),
        result
    );
    assert_eq!(snapshot(&c, &original), before, "journal unchanged");
    let mut enrollment = open(&c);
    let image = enrollment.image().expect("reconciled config");
    assert!(
        matches!(image.phase, Phase::Accepted { ref admission, stage: AdmissionPhase::Active, .. } if admission.checkpoint==previous)
    );
    assert_eq!(row(&enrollment).get(..8), Some(b"QPENST14".as_slice()));
    enrollment.close();
    assert!(matches!(
        open(&c).activate(&c.policy, 184, None),
        Err(DurableError::Protocol(Error::Validity))
    ));
    open(&c)
        .activate(&c.policy, 185, None)
        .expect("actual P0/R1 owner")
        .close();
    open(&c)
        .refresh_roster(previous, next.as_bytes(), &next_pin, &c.policy, 185)
        .expect("new R3 from actual predecessor");
    open(&c)
        .activate(&c.policy, 185, None)
        .expect("original owner with R3")
        .close();
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 190)
            .expect("retained exact outcome after next commit"),
        result
    );
}

#[test]
fn exact_roster_commit_is_recovered_after_expiry_without_runtime_or_private_signer() {
    let (c, original, id) = local(190, 200);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 2, 180);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    install(&c, &original, &target, &pin, 175);
    let before = snapshot(&c, &original);
    c.policy.close();
    c.policy.runtime.close();
    let held = c.paths.signer.with_extension("roster-resolution-held");
    fs::rename(&c.paths.signer, &held).expect("no private signer");
    let result = expected(
        id,
        previous,
        target.checkpoint(),
        RosterRefreshOutcome::Committed,
        target.checkpoint(),
        205,
    );
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 205).expect("exact actual head"),
        result
    );
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 210).expect("exact cached result"),
        result
    );
    assert_eq!(snapshot(&c, &original), before);
    assert_eq!(
        open(&c).status().expect("completed metadata"),
        EnrollmentStatus::Active(id)
    );
    fs::rename(held, &c.paths.signer).expect("restore signer");
    assert!(open(&c).activate(&c.policy, 205, None).is_err());
}

#[test]
fn same_version_competitor_is_proven_uncommitted_and_next_update_uses_actual_head() {
    let (c, original, id) = local(220, 240);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 2, 190);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    let (other, other_pin) = head(&c, &original, 2, 280);
    install(&c, &original, &other, &other_pin, 175);
    let before = snapshot(&c, &original);
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 175).expect("same-version exclusion"),
        expected(
            id,
            previous,
            target.checkpoint(),
            RosterRefreshOutcome::SupersededUncommitted,
            other.checkpoint(),
            175
        )
    );
    assert_eq!(snapshot(&c, &original), before);
    open(&c)
        .activate(&c.policy, 175, None)
        .expect("actual competing roster")
        .close();
    let (next, next_pin) = head(&c, &original, 3, 300);
    assert!(matches!(
        open(&c).refresh_roster(
            target.checkpoint(),
            next.as_bytes(),
            &next_pin,
            &c.policy,
            180
        ),
        Err(DurableError::Conflict)
    ));
    open(&c)
        .refresh_roster(
            other.checkpoint(),
            next.as_bytes(),
            &next_pin,
            &c.policy,
            180,
        )
        .expect("exact actual predecessor");
    open(&c)
        .activate(&c.policy, 180, None)
        .expect("fresh R3 owner")
        .close();
}

#[test]
fn higher_roster_head_retains_unknown_past_outcome_for_both_committed_and_skipped_targets() {
    for committed_before in [false, true] {
        let (c, original, id) = local(220, 240);
        let previous = original.roster().checkpoint();
        let (target, pin) = head(&c, &original, 2, 190);
        begin(&c, &original, &target, &pin, &c.policy, 170);
        if committed_before {
            install(&c, &original, &target, &pin, 172);
        }
        let (later, later_pin) = head(&c, &original, 3, 280);
        install(&c, &original, &later, &later_pin, 175);
        let before = snapshot(&c, &original);
        assert_eq!(
            resolve(&c, previous, target.checkpoint(), 175).expect("honest supersession"),
            expected(
                id,
                previous,
                target.checkpoint(),
                RosterRefreshOutcome::SupersededUnknown,
                later.checkpoint(),
                175
            )
        );
        assert_eq!(snapshot(&c, &original), before);
        open(&c)
            .activate(&c.policy, 175, None)
            .expect("actual R3 owner")
            .close();
    }
}

#[test]
fn revocation_and_generation_replacement_leave_queryable_resolution_without_an_owner() {
    for replace in [false, true] {
        let (c, original, id) = local(220, 240);
        let previous = original.roster().checkpoint();
        let (target, pin) = head(&c, &original, 2, 190);
        begin(&c, &original, &target, &pin, &c.policy, 170);
        let mut description = original.description.clone();
        description.generation += 1;
        let certificate = c
            .root
            .issue_device(description, original.key.clone())
            .expect("replacement credential");
        let entries = if replace {
            vec![c.root.roster_entry(&certificate).expect("new generation")]
        } else {
            Vec::new()
        };
        let later = c
            .root
            .issue_roster(3, Validity::new(100, 280).expect("interval"), &entries)
            .expect("revocation head");
        let later_pin = AccountPin::new(
            original.account_id(),
            c.intent.root.clone(),
            later.checkpoint(),
            c.policy.family(),
        )
        .expect("independent pin");
        install(&c, &original, &later, &later_pin, 175);
        let before = snapshot(&c, &original);
        let result = expected(
            id,
            previous,
            target.checkpoint(),
            RosterRefreshOutcome::SupersededUnknown,
            later.checkpoint(),
            175,
        );
        assert_eq!(
            resolve(&c, previous, target.checkpoint(), 175)
                .expect("metadata survives lost membership"),
            result
        );
        assert_eq!(
            open(&c).status().expect("explicit blocked membership"),
            EnrollmentStatus::RosterResolved(result)
        );
        assert!(matches!(
            open(&c).activate(&c.policy, 175, None),
            Err(DurableError::Suspended)
        ));
        assert_eq!(
            resolve(&c, previous, target.checkpoint(), 185).expect("same exact result"),
            result
        );
        assert_eq!(snapshot(&c, &original), before);
    }
}

#[test]
fn a_live_target_is_not_cancelled_when_journal_has_only_an_intermediate_head() {
    let (c, original, _) = local(220, 240);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 4, 280);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    let (middle, middle_pin) = head(&c, &original, 2, 260);
    install(&c, &original, &middle, &middle_pin, 175);
    let saved = row(&open(&c));
    let before = snapshot(&c, &original);
    assert!(matches!(
        resolve(&c, previous, target.checkpoint(), 175),
        Err(DurableError::Suspended)
    ));
    assert_eq!(row(&open(&c)), saved);
    assert_eq!(snapshot(&c, &original), before);
}

#[test]
fn expired_roster_resolution_preserves_adopted_policy_and_real_credential_history() {
    for prior_g in [false, true] {
        let (c, original, id) = local(160, 240);
        let p1 = policy(&c, 2, 300, 170);
        let a = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, id),
            170,
        );
        stage(&c, &a, &p1, 170);
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 170)
            .expect("adopt independent P1")
            .close();
        let grant = if prior_g {
            Some(super::credential::current_grant(
                &c, &original, &original, 2, 320, 190,
            ))
        } else {
            None
        };
        if let Some(g) = &grant {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &p1, 190)
                .expect("real G intent");
            open(&c)
                .activate_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("real G adoption")
                .close();
        }
        let current = grant.as_ref().map_or(&original, |g| g.successor_device());
        let previous = current.roster().checkpoint();
        let (target, pin) = head(&c, current, previous.version() + 1, 200);
        let mut owner = open(&c);
        let original_g = owner.credential_renewal_status().expect("existing G state");
        let mut g_bytes = Vec::new();
        if let Some(g) = owner.image().expect("before").renewal {
            g.encode(&mut g_bytes).expect("exact G");
        }
        owner.close();
        begin(&c, current, &target, &pin, &p1, 195);
        let before = snapshot(&c, &original);
        assert_eq!(
            resolve(&c, previous, target.checkpoint(), 205)
                .expect("original independent-policy refresh"),
            expected(
                id,
                previous,
                target.checkpoint(),
                RosterRefreshOutcome::ExpiredUncommitted,
                previous,
                205
            )
        );
        assert_eq!(snapshot(&c, &original), before);
        let mut owner = open(&c);
        let image = owner.image().expect("retained histories");
        assert_eq!(
            owner
                .completed_policy_approval(&image)
                .expect("approval")
                .expect("P1")
                .journal_bytes(),
            a.historical().journal_bytes()
        );
        let mut after_g = Vec::new();
        if let Some(g) = image.renewal {
            g.encode(&mut after_g).expect("retained G");
        }
        assert_eq!(after_g, g_bytes);
        assert_eq!(
            owner.credential_renewal_status().expect("same G"),
            original_g
        );
        owner.close();
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 204),
            Err(DurableError::Protocol(Error::Validity))
        ));
        let (fresh_roster, fresh_pin) = head(&c, current, target.checkpoint().version() + 1, 340);
        open(&c)
            .refresh_roster(previous, fresh_roster.as_bytes(), &fresh_pin, &p1, 205)
            .expect("fresh independent roster after old snapshots expired");
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 205)
            .expect("same original owner under P1 and fresh roster");
        let fresh_current = active.parts().expect("current owner").2.clone();
        active.close();
        let p2 = policy(&c, 3, 360, 210);
        let next =
            super::credential::approve_successor(&c, &original, &fresh_current, &p1, &p2, 210);
        stage(&c, &next, &p2, 210);
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p2, 210)
            .expect("fresh exact policy approval after resolution")
            .close();
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p2, 204),
            Err(DurableError::Protocol(Error::Validity))
        ));
    }
}

#[test]
fn resolved_expired_roster_does_not_block_real_joint_renewal_after_c0_and_p0_expire() {
    let (c, original, id) = local(220, 240);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 2, 180);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    let result = resolve(&c, previous, target.checkpoint(), 245).expect("expired signed target");
    assert_eq!(result.outcome, RosterRefreshOutcome::ExpiredUncommitted);
    let g = super::credential::current_grant(&c, &original, &original, 3, 320, 245);
    let next = policy(&c, 2, 380, 245);
    let joint = super::super::policy_continuation::joint(
        &c,
        &g,
        &super::super::policy_continuation::scope(&c, &g, id),
        &c.policy,
        &next,
    );
    open(&c)
        .stage_policy_continuation(&g, &joint, g.operation(), &next, 245)
        .expect("real joint continuation from original head");
    let mut active = open(&c)
        .activate_policy_continuation(c.policy.historical(), &next, 245)
        .expect("current C and policy owner");
    assert_eq!(
        active.parts().expect("owner").2.credential_digest(),
        g.successor_device().credential_digest()
    );
    active.close();
    assert_eq!(
        resolve(&c, previous, target.checkpoint(), 250)
            .expect("original roster result remains readable"),
        result
    );
    assert!(matches!(
        open(&c).activate_policy_continuation(c.policy.historical(), &next, 244),
        Err(DurableError::Protocol(Error::Validity))
    ));
}

#[test]
fn roster_and_policy_results_keep_independent_floors_and_original_outcomes_in_one_enrollment() {
    let (c, original, id) = local(220, 240);
    let p1 = policy(&c, 2, 300, 170);
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, id),
        170,
    );
    stage(&c, &a, &p1, 170);
    let (r2, pin2) = head(&c, &original, 2, 280);
    install(&c, &original, &r2, &pin2, 175);
    let policy_result = open(&c)
        .resolve_policy_renewal(
            a.scope().operation,
            a.statement_digest(),
            c.policy.historical(),
            p1.historical(),
            175,
        )
        .expect("policy absent under old R1");
    open(&c)
        .refresh_roster(
            original.roster().checkpoint(),
            r2.as_bytes(),
            &pin2,
            &c.policy,
            175,
        )
        .expect("actual R2 config");
    let mut active = open(&c).activate(&c.policy, 175, None).expect("R2 owner");
    let current = active.parts().expect("parts").2.clone();
    active.close();
    let (r3, pin3) = head(&c, &current, 3, 180);
    begin(&c, &current, &r3, &pin3, &c.policy, 176);
    let roster_result = resolve(&c, r2.checkpoint(), r3.checkpoint(), 185).expect("expired R3");
    let encoded = row(&open(&c));
    assert_eq!(encoded.get(..8), Some(b"QPENST14".as_slice()));
    assert_eq!(encoded.get(8..16), Some(b"QPENST13".as_slice()));
    assert_eq!(
        open(&c)
            .resolve_policy_renewal(
                a.scope().operation,
                a.statement_digest(),
                c.policy.historical(),
                p1.historical(),
                190
            )
            .expect("original policy result"),
        policy_result
    );
    let request = open(&c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("new ID"),
            c.policy.historical(),
        )
        .expect("actual R2 request");
    let fresh = approved(&c, &original, &current, &p1, &request, 185);
    stage(&c, &fresh, &p1, 185);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 185)
        .expect("new policy adoption")
        .close();
    assert_eq!(
        resolve(&c, r2.checkpoint(), r3.checkpoint(), 190)
            .expect("roster result survives policy retirement"),
        roster_result
    );
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p1, 184),
        Err(DurableError::Protocol(Error::Validity))
    ));
}

#[test]
fn revoked_resolution_preserves_independent_policy_and_carried_g_without_releasing_their_owner() {
    for prior_g in [false, true] {
        let (c, original, id) = local(160, 240);
        let p1 = policy(&c, 2, 300, 170);
        let a = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, id),
            170,
        );
        stage(&c, &a, &p1, 170);
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 170)
            .expect("P1")
            .close();
        let g = if prior_g {
            Some(super::credential::current_grant(
                &c, &original, &original, 2, 320, 190,
            ))
        } else {
            None
        };
        if let Some(g) = &g {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &p1, 190)
                .expect("real G");
            open(&c)
                .activate_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("adopt G")
                .close();
        }
        let current = g.as_ref().map_or(&original, |g| g.successor_device());
        let previous = current.roster().checkpoint();
        let (target, pin) = head(&c, current, previous.version() + 1, 220);
        begin(&c, current, &target, &pin, &p1, 195);
        let revoked = c
            .root
            .issue_roster(
                target.checkpoint().version() + 1,
                Validity::new(100, 340).expect("interval"),
                &[],
            )
            .expect("current revocation");
        let pin = AccountPin::new(
            original.account_id(),
            c.intent.root.clone(),
            revoked.checkpoint(),
            c.policy.family(),
        )
        .expect("independent pin");
        install(&c, &original, &revoked, &pin, 200);
        let before = snapshot(&c, &original);
        let result = resolve(&c, previous, target.checkpoint(), 205)
            .expect("original result after revocation");
        assert_eq!(result.outcome, RosterRefreshOutcome::SupersededUnknown);
        assert_eq!(
            open(&c).status().expect("metadata still readable"),
            EnrollmentStatus::RosterResolved(result)
        );
        assert_eq!(
            open(&c).policy_renewal_status().expect("P1 retained"),
            PolicyRenewalStatus::Committed {
                operation: a.scope().operation,
                statement: a.statement_digest(),
                target: p1.checkpoint()
            }
        );
        assert_eq!(
            open(&c).credential_renewal_status().expect("exact G"),
            g.as_ref()
                .map_or(CredentialRenewalStatus::Absent, renewal::committed)
        );
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 205),
            Err(DurableError::Suspended)
        ));
        assert_eq!(snapshot(&c, &original), before);
    }
}
