// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn committed(a: &VerifiedPolicyRenewal) -> PolicyRenewalStatus {
    PolicyRenewalStatus::Committed {
        operation: a.scope().operation,
        statement: a.statement_digest(),
        target: a.target_policy(),
    }
}

#[test]
fn policy_only_owner_preserves_original_lease_signer_and_current_credential_with_or_without_g() {
    for prior_g in [false, true] {
        let (c, original, journal) = local(180, if prior_g { 160 } else { 200 });
        let g = prior_g.then(|| renewal::grant(&c, &original, &original, 2, 240));
        if let Some(g) = &g {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &c.policy, 170)
                .expect("G intent");
            open(&c)
                .activate(&c.policy, 170, None)
                .expect("original G completion")
                .close();
        }
        let current = g.as_ref().map_or(&original, |g| g.successor_device());
        let p1 = policy(&c, 2, 260, 190);
        let a = approved(
            &c,
            &original,
            current,
            &p1,
            &scope(&c, &original, current, journal),
            190,
        );
        let before_signer = fs::read(&c.paths.signer).expect("original signer bytes");
        let before_status = open(&c)
            .credential_renewal_status()
            .expect("original G status");
        stage(&c, &a, &p1, 190);
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 190)
            .expect("current policy-only owner");
        assert!(
            DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err(),
            "same exclusive enrollment lease"
        );
        let (service, signer, admitted) = active.parts().expect("controlled original owners");
        signer.check_device(admitted).expect("same private signer");
        assert_eq!(admitted.credential_digest(), current.credential_digest());
        assert_eq!(
            admitted.roster().checkpoint(),
            current.roster().checkpoint()
        );
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("original journal"),
            journal
        );
        active.close();
        assert!(active.parts().is_err());
        assert_eq!(
            fs::read(&c.paths.signer).expect("same signer bytes"),
            before_signer
        );
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("unchanged G status"),
            before_status
        );
        assert_eq!(
            open(&c)
                .policy_renewal_status()
                .expect("durable policy state"),
            committed(&a)
        );
    }
}

#[test]
fn completed_policy_only_fact_never_revives_expired_credential_roster_or_policy() {
    for (credential_until, policy_until, now) in [(180, 230, 190), (240, 260, 200), (200, 190, 195)]
    {
        let (c, original, journal) = local(160, credential_until);
        let p1 = policy(&c, 2, policy_until, 170);
        let a = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, journal),
            170,
        );
        stage(&c, &a, &p1, 170);
        open(&c)
            .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
            .expect("historical completion");
        let before = row(&open(&c));
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, now),
            Err(DurableError::Protocol(Error::Validity))
        ));
        assert_eq!(row(&open(&c)), before);
        assert_eq!(
            open(&c)
                .policy_renewal_status()
                .expect("fact survives failed admission"),
            committed(&a)
        );
    }
}

#[test]
fn policy_close_at_completion_withholds_owner_and_preserves_exact_committed_fact() {
    let (c, original, journal) = local(160, 200);
    let p1 = Arc::new(policy(&c, 2, 230, 170));
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal),
        170,
    );
    stage(&c, &a, &p1, 170);
    CLOSE_POLICY_AFTER_ACTIVE.with(|pending| *pending.borrow_mut() = Some(Arc::clone(&p1)));
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p1, 170),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("completion committed before policy close"),
        committed(&a)
    );
    assert_eq!(
        open(&c)
            .recover_historical_policy_renewal(
                a.scope().operation,
                a.statement_digest(),
                c.policy.historical()
            )
            .expect("historical readback under closed target"),
        committed(&a)
    );
}

#[test]
fn current_journal_revocation_denies_policy_only_owner_despite_retained_current_cr() {
    let (c, original, journal) = local(160, 200);
    let p1 = policy(&c, 2, 230, 170);
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal),
        170,
    );
    stage(&c, &a, &p1, 170);
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("completion");
    let revoked = c
        .root
        .issue_roster(2, interval(), &[])
        .expect("explicit root revocation");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        revoked.checkpoint(),
        c.policy.family(),
    )
    .expect("current pin");
    let revoked = pin
        .verify_roster(revoked.as_bytes(), 175)
        .expect("authenticated new head");
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original service metadata");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(&revoked, 175)
        .expect("persist current revocation");
    service.close();
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p1, 175),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        open(&c).policy_renewal_status().expect("historical fact"),
        committed(&a)
    );
}

#[test]
fn policy_only_owner_uses_current_journal_roster_after_retained_snapshot_expires() {
    let (c, original, journal) = local(160, 240);
    let p1 = policy(&c, 2, 260, 170);
    let a = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal),
        170,
    );
    stage(&c, &a, &p1, 170);
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("original completion");
    let certificate = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("unchanged credential body");
    let next = c
        .root
        .issue_roster(
            2,
            Validity::new(100, 280).expect("roster interval"),
            &[c.root.roster_entry(&certificate).expect("same member")],
        )
        .expect("current signed roster");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        next.checkpoint(),
        c.policy.family(),
    )
    .expect("independent current head");
    let next = pin
        .verify_roster(next.as_bytes(), 175)
        .expect("current roster");
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original service metadata");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(&next, 175)
        .expect("advance current roster");
    service.close();
    assert!(original.roster_validity.check(205).is_err());
    original
        .description
        .validity
        .check(205)
        .expect("unchanged credential current");
    p1.check_mode(PrekeyQuality::OneTimeBoth, 205)
        .expect("current target runtime");
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 205)
        .expect("owner under actual current head");
    let (_, signer, current) = active.parts().expect("original owners");
    signer.check_device(current).expect("same key");
    assert_eq!(current.credential_digest(), original.credential_digest());
    assert_eq!(current.roster().checkpoint(), next.checkpoint());
}

#[test]
fn another_valid_approval_in_forged_completion_cannot_release_an_owner_or_replace_journal() {
    let (c, original, journal) = local(160, 200);
    let p1 = policy(&c, 2, 230, 170);
    let first = approved(
        &c,
        &original,
        &original,
        &p1,
        &scope(&c, &original, &original, journal),
        170,
    );
    stage(&c, &first, &p1, 170);
    open(&c)
        .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("actual original completion");
    let p2 = policy(&c, 3, 260, 170);
    let second = approved(
        &c,
        &original,
        &original,
        &p2,
        &scope(&c, &original, &original, journal),
        170,
    );
    let mut owner = open(&c);
    let mut before = row(&owner);
    let image = owner.image().expect("completed image");
    let mut original_record = Vec::new();
    image
        .policy_completed
        .as_ref()
        .expect("completion")
        .encode(&mut original_record)
        .expect("original record");
    let offset = before
        .windows(original_record.len())
        .position(|w| w == original_record)
        .expect("unique original record");
    assert_eq!(
        before
            .windows(original_record.len())
            .filter(|w| *w == original_record)
            .count(),
        1
    );
    let mut substitution = second.scope().operation.as_bytes().to_vec();
    substitution.extend_from_slice(&second.statement_digest());
    substitution.extend_from_slice(&second.target_policy().version().to_be_bytes());
    substitution.extend_from_slice(&second.target_policy().digest());
    substitution.extend_from_slice(&second.historical().journal_bytes());
    assert_eq!(substitution.len(), original_record.len());
    before
        .get_mut(offset..offset + substitution.len())
        .expect("completion slot")
        .copy_from_slice(&substitution);
    owner.close();
    // Model wrapping-key access plus a second authentic two-root approval; do
    // not forge signatures or claim that local metadata alone proves adoption.
    replace_authenticated(&c, &before);
    let retained = row(&open(&c));
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p2, 170),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        row(&open(&c)),
        retained,
        "no implicit repair or replacement of config"
    );
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("original service metadata");
    let original_approval = first.historical();
    let receipt = service
        .stores()
        .expect("stores")
        .0
        .inspect_local_policy_renewal(&crate::durable::LocalPolicyRenewalTarget {
            approval: &original_approval,
            original: &original,
            current: &original,
            original_policy: c.policy.historical(),
        })
        .expect("actual journal still retains first approval");
    assert_eq!(receipt.statement, first.statement_digest());
}
