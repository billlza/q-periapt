// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{CredentialRenewalId, CredentialRenewalRequest, VerifiedCredentialRenewal};

fn prepare(
    c: &Case,
    operation: CredentialRenewalId,
) -> Result<CredentialRenewalRequest, DurableError> {
    open(c).credential_renewal_request(operation, c.policy.historical())
}
fn issued(
    c: &Case,
    request: &CredentialRenewalRequest,
    until: u64,
    now: u64,
) -> VerifiedCredentialRenewal {
    let successor = c
        .root
        .issue_credential_extension(request.previous_device(), until, now)
        .expect("public same-key successor issuance");
    let roster = c
        .root
        .issue_roster(
            request.authorization().previous.version() + 1,
            Validity::new(100, until + 20).expect("current roster interval"),
            &[c.root.roster_entry(&successor).expect("successor entry")],
        )
        .expect("independent target roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent target pin");
    let authorization = request.authorization();
    let grant = c
        .root
        .issue_credential_renewal(
            request.materials(&successor, roster.as_bytes()),
            &authorization,
            &pin,
            now,
        )
        .expect("explicit independent root approval");
    VerifiedCredentialRenewal::verify(grant.as_bytes(), &pin, authorization.policy_digest, now)
        .expect("current real G verification")
}
fn journal(c: &Case, original: &VerifiedDevice) -> DeviceService {
    DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original service")
}

#[test]
fn original_issuer_materials_preserve_exact_bytes_and_all_logical_assets_without_a_signer(
) -> Result<(), &'static str> {
    let (c, original, id) = local(260, 180);
    let operation = CredentialRenewalId::generate().expect("retained G operation");
    let before = super::request::assets(&c, &original);
    let request = prepare(&c, operation).expect("actual original predecessor");
    let mut owner = open(&c);
    let image = owner.image().expect("source");
    let Phase::Accepted { admission, .. } = image.phase else {
        return Err("expected accepted original enrollment");
    };
    assert_eq!(request.original_credential(), admission.certificate);
    assert_eq!(request.previous_credential(), admission.certificate);
    assert_eq!(request.previous_roster(), admission.roster);
    assert_eq!(request.operation(), operation);
    assert_eq!(request.journal(), id);
    assert_eq!(
        request.original_owner(),
        crate::bootstrap::storage_owner(&original)
    );
    assert_eq!(
        request.previous_validity(),
        Validity::new(100, 180).expect("old validity")
    );
    assert_eq!(
        request.authorization().previous,
        original.roster().checkpoint()
    );
    assert_eq!(
        request.authorization().policy_digest,
        c.policy.checkpoint().digest()
    );
    assert_eq!(request.current_policy(), c.policy.checkpoint());
    assert_eq!(request.current_policy_authorization(), None);
    owner.close();
    assert_eq!(super::request::assets(&c, &original), before);
    c.policy.close();
    c.policy.runtime.close();
    let held = c.paths.signer.with_extension("issuer-request-held");
    fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
    let retry = prepare(&c, operation).expect("same original metadata without runtime or signer");
    assert_eq!(retry.original_credential(), request.original_credential());
    assert_eq!(retry.previous_credential(), request.previous_credential());
    assert_eq!(retry.previous_roster(), request.previous_roster());
    assert_eq!(retry.operation(), operation);
    fs::rename(held, &c.paths.signer).expect("restore signer");
    assert_eq!(super::request::assets(&c, &original), before);
    Ok(())
}

#[test]
fn public_preparation_issues_real_successive_g_under_original_and_independent_policies() {
    for independent in [false, true] {
        let (c, original, id) = local(if independent { 160 } else { 360 }, 180);
        let p1 = policy(&c, 2, 380, 170);
        let policy_approval = if independent {
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
                .expect("independent adoption")
                .close();
            Some(a)
        } else {
            None
        };
        let active = if independent { &p1 } else { &c.policy };
        for (now, until) in [(190, 240), (245, 320)] {
            let operation = CredentialRenewalId::generate().expect("unique operation");
            let request = prepare(&c, operation).expect("actual G predecessor");
            assert_eq!(request.current_policy(), active.checkpoint());
            assert_eq!(
                request.current_policy_authorization(),
                policy_approval
                    .as_ref()
                    .map(VerifiedPolicyRenewal::statement_digest)
            );
            assert_eq!(
                request.authorization().policy_digest,
                c.policy.checkpoint().digest(),
                "G still binds original P0"
            );
            let g = issued(&c, &request, until, now);
            open(&c)
                .stage_credential_renewal(&g, operation, active, now)
                .expect("real original G intent");
            let mut owner = if independent {
                open(&c)
                    .activate_policy_renewal(c.policy.historical(), active, now)
                    .expect("independent-policy original owner")
            } else {
                open(&c)
                    .activate(active, now, None)
                    .expect("P0 original owner")
            };
            assert_eq!(
                owner.parts().expect("same service").2.credential_digest(),
                g.successor_device().credential_digest()
            );
            owner.close();
            assert!(
                matches!(prepare(&c, operation), Err(DurableError::Conflict)),
                "completed ID is not a fresh request"
            );
            let next = prepare(&c, CredentialRenewalId::generate().expect("next request"))
                .expect("current acknowledged predecessor");
            assert_eq!(
                next.previous_device().credential_digest(),
                g.successor_device().credential_digest()
            );
            assert_eq!(next.original_credential(), request.original_credential());
        }
    }
}

#[test]
fn known_expired_g_operation_cannot_be_reissued_by_preparation() {
    let (c, original, id) = local(160, 240);
    let p1 = policy(&c, 2, 280, 170);
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
    let operation = CredentialRenewalId::generate().expect("original operation");
    let request = prepare(&c, operation).expect("original request");
    let g = issued(&c, &request, 260, 190);
    open(&c)
        .stage_credential_renewal(&g, operation, &p1, 190)
        .expect("original Pending");
    open(&c)
        .reconcile_expired_policy_credential(
            operation,
            g.statement_digest(),
            c.policy.historical(),
            p1.historical(),
            270,
        )
        .expect("proven original expiry");
    assert!(matches!(
        prepare(&c, operation),
        Err(DurableError::Conflict)
    ));
    let fresh = prepare(
        &c,
        CredentialRenewalId::generate().expect("fresh operation"),
    )
    .expect("new historical preparation");
    assert_eq!(
        fresh.previous_device().credential_digest(),
        original.credential_digest()
    );
}

#[test]
fn pending_roster_policy_or_g_and_unacknowledged_policy_completion_refuse_new_requests() {
    for kind in 0..4 {
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
        if kind == 0 {
            let (next, pin) = super::policy_roster::next_roster(&c, &original, 2, 190);
            open(&c)
                .refresh_roster(
                    original.roster().checkpoint(),
                    next.as_bytes(),
                    &pin,
                    &c.policy,
                    155,
                )
                .expect("roster Pending");
        } else if kind == 1 || kind == 3 {
            stage(&c, &a, &p1, 170);
            if kind == 3 {
                super::recovery::kill_at(&c, "policy-only-completion");
            }
        } else {
            let request =
                prepare(&c, CredentialRenewalId::generate().expect("ID")).expect("before G");
            let g = issued(&c, &request, 240, 155);
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &c.policy, 155)
                .expect("G Pending");
        }
        let saved = row(&open(&c));
        assert!(matches!(
            prepare(&c, CredentialRenewalId::generate().expect("new operation")),
            Err(DurableError::Suspended)
        ));
        assert_eq!(row(&open(&c)), saved);
        if kind == 3 {
            open(&c)
                .recover_historical_policy_renewal(
                    a.scope().operation,
                    a.statement_digest(),
                    c.policy.historical(),
                )
                .expect("exact original ACK");
            assert!(prepare(&c, CredentialRenewalId::generate().expect("after ACK")).is_ok());
        }
    }
}

#[test]
fn issuer_snapshot_is_not_a_reservation_and_a_racing_head_never_changes_original_g() {
    let (c, original, _) = local(280, 200);
    let operation = CredentialRenewalId::generate().expect("caller operation");
    let request = prepare(&c, operation).expect("original snapshot");
    let g = issued(&c, &request, 260, 170);
    let (other, pin) = super::policy_roster::next_roster(&c, &original, 2, 300);
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(other.as_bytes(), 175)
                .expect("current competing head"),
            175,
        )
        .expect("concurrent actual head");
    service.close();
    let newer = prepare(
        &c,
        CredentialRenewalId::generate().expect("other operation"),
    )
    .expect("actual newer roster for unchanged credential");
    assert_eq!(newer.authorization().previous, other.checkpoint());
    assert_eq!(newer.previous_roster(), other.as_bytes());
    assert!(
        matches!(
            open(&c).policy_renewal_scope(
                PolicyRenewalId::generate().expect("policy ID"),
                c.policy.historical()
            ),
            Err(DurableError::Conflict)
        ),
        "P-only request keeps its existing exact enrollment-roster fence"
    );
    open(&c)
        .stage_credential_renewal(&g, operation, &c.policy, 175)
        .expect("original G intent, not journal admission");
    assert!(open(&c).activate(&c.policy, 175, None).is_err());
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("same unresolved grant"),
        renewal::pending(&g)
    );
    let mut owner = open(&c);
    let image = owner.image().expect("retained G");
    let mut bytes = Vec::new();
    image
        .renewal
        .expect("original G")
        .encode(&mut bytes)
        .expect("retained encoding");
    assert!(
        bytes.windows(g.as_bytes().len()).any(|b| b == g.as_bytes()),
        "exact first grant survives"
    );
}

#[test]
fn successor_issuance_rejects_wrong_root_nonextension_and_invalid_current_interval() {
    let (c, _, _) = local(260, 200);
    let request = prepare(&c, CredentialRenewalId::generate().expect("ID")).expect("original");
    let other = RootSigningKey::generate().expect("other root");
    assert_eq!(
        other
            .issue_credential_extension(request.previous_device(), 240, 170)
            .err(),
        Some(Error::Scope)
    );
    for (until, now) in [
        (200, 170),
        (190, 170),
        (240, 99),
        (240, 240),
        (u64::MAX, 170),
    ] {
        assert_eq!(
            c.root
                .issue_credential_extension(request.previous_device(), until, now)
                .err(),
            Some(Error::Validity)
        );
    }
}

#[test]
fn expired_current_credential_renews_from_actual_new_roster_without_a_live_credential_refresh() {
    let (c, original, _) = local(300, 180);
    let (new_roster, pin) = super::policy_roster::next_roster(&c, &original, 2, 280);
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(new_roster.as_bytes(), 190)
                .expect("current account head"),
            190,
        )
        .expect("actual roster advancement");
    service.close();
    assert!(matches!(
        open(&c).refresh_roster(
            original.roster().checkpoint(),
            new_roster.as_bytes(),
            &pin,
            &c.policy,
            190
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let before = super::request::assets(&c, &original);
    let operation = CredentialRenewalId::generate().expect("retained operation");
    let request = prepare(&c, operation).expect("actual same-credential predecessor after expiry");
    assert_eq!(request.authorization().previous, new_roster.checkpoint());
    assert_eq!(request.previous_roster(), new_roster.as_bytes());
    assert_eq!(
        request.previous_device().credential_digest(),
        original.credential_digest()
    );
    assert_eq!(super::request::assets(&c, &original), before);
    let g = issued(&c, &request, 260, 190);
    open(&c)
        .stage_credential_renewal(&g, operation, &c.policy, 190)
        .expect("real G from independently approved actual head");
    let mut active = open(&c)
        .activate(&c.policy, 190, None)
        .expect("original owner without reviving expired C");
    assert_eq!(
        active.parts().expect("owner").2.credential_digest(),
        g.successor_device().credential_digest()
    );
    active.close();
}

#[test]
fn adopted_joint_policy_is_reported_and_a_real_g_uses_its_original_policy_binding() {
    let (c, original, id) = local(160, 160);
    let g = renewal::grant(&c, &original, &original, 2, 220);
    let p1 = policy(&c, 2, 320, 170);
    let t = super::super::policy_continuation::joint(
        &c,
        &g,
        &super::super::policy_continuation::scope(&c, &g, id),
        &c.policy,
        &p1,
    );
    open(&c)
        .stage_policy_continuation(&g, &t, g.operation(), &p1, 170)
        .expect("actual original joint intent");
    open(&c)
        .activate_policy_continuation(c.policy.historical(), &p1, 170)
        .expect("joint adoption")
        .close();
    let request = prepare(&c, CredentialRenewalId::generate().expect("new G ID"))
        .expect("actual T predecessor");
    assert_eq!(request.current_policy(), p1.checkpoint());
    assert_eq!(
        request.current_policy_authorization(),
        Some(t.statement_digest())
    );
    assert_eq!(
        request.authorization().policy_digest,
        c.policy.checkpoint().digest()
    );
    let next = issued(&c, &request, 300, 225);
    open(&c)
        .stage_credential_renewal(&next, next.operation(), &p1, 225)
        .expect("real new G carrying existing T");
    open(&c)
        .activate_policy_continuation(c.policy.historical(), &p1, 225)
        .expect("same original owner")
        .close();
}

#[test]
fn actual_roster_revocation_and_generation_replacement_cannot_supply_issuer_materials() {
    for replace in [false, true] {
        let (c, original, _) = local(300, 180);
        let mut description = original.description.clone();
        description.generation += 1;
        let replacement = c
            .root
            .issue_device(description, original.key.clone())
            .expect("replacement credential");
        let entries = if replace {
            vec![c.root.roster_entry(&replacement).expect("member")]
        } else {
            Vec::new()
        };
        let revoked = c
            .root
            .issue_roster(2, Validity::new(100, 280).expect("interval"), &entries)
            .expect("new authority head");
        let pin = AccountPin::new(
            original.account_id(),
            c.intent.root.clone(),
            revoked.checkpoint(),
            c.policy.family(),
        )
        .expect("independent pin");
        let mut service = journal(&c, &original);
        service
            .stores()
            .expect("stores")
            .0
            .install_roster(
                &pin.verify_roster(revoked.as_bytes(), 190)
                    .expect("current head"),
                190,
            )
            .expect("actual revocation or generation change");
        service.close();
        assert!(matches!(
            prepare(&c, CredentialRenewalId::generate().expect("operation")),
            Err(DurableError::Conflict)
        ));
    }
}

#[test]
fn nonoverlapping_credential_and_actual_roster_intervals_are_not_fabricated_into_a_predecessor() {
    let (c, original, _) = local(300, 180);
    let certificate = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("same signed credential");
    let later = c
        .root
        .issue_roster(
            2,
            Validity::new(190, 280).expect("after credential expiry"),
            &[c.root
                .roster_entry(&certificate)
                .expect("root-approved historical member")],
        )
        .expect("current roster");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        later.checkpoint(),
        c.policy.family(),
    )
    .expect("independent pin");
    let mut service = journal(&c, &original);
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(later.as_bytes(), 195)
                .expect("current actual roster"),
            195,
        )
        .expect("actual advance");
    service.close();
    let before = super::request::assets(&c, &original);
    assert!(matches!(
        prepare(&c, CredentialRenewalId::generate().expect("operation")),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert!(
        matches!(
            open(&c).policy_renewal_scope(
                PolicyRenewalId::generate().expect("policy operation"),
                c.policy.historical()
            ),
            Err(DurableError::Conflict)
        ),
        "existing policy-only exact-roster error precedes alternate roster validity"
    );
    assert_eq!(super::request::assets(&c, &original), before);
}
