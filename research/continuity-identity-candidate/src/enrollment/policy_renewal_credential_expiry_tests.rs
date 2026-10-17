// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::HistoricalSessionPolicy;

fn outcome(g: &crate::VerifiedCredentialRenewal, now: u64) -> CredentialRenewalStatus {
    CredentialRenewalStatus::ExpiredUncommitted {
        operation: g.operation(),
        statement: g.statement_digest(),
        observed_head: g.previous_device().roster().checkpoint(),
        observed_at: now,
    }
}
fn resolve(
    c: &Case,
    g: &crate::VerifiedCredentialRenewal,
    p: &HistoricalSessionPolicy,
    now: u64,
) -> Result<CredentialRenewalStatus, DurableError> {
    open(c).reconcile_expired_policy_credential(
        g.operation(),
        g.statement_digest(),
        c.policy.historical(),
        p,
        now,
    )
}
fn snapshot(c: &Case, original: &VerifiedDevice) -> (u64, [u8; 32]) {
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original metadata");
    let value = service.stores().expect("stores").0.test_snapshot();
    service.close();
    (value.revision, value.digest)
}

#[test]
fn expired_fixed_credential_or_roster_target_can_be_abandoned_then_original_g_successor_completes()
{
    for roster_expires_first in [false, true] {
        let (c, original, p1, a) = adopted();
        let g = if roster_expires_first {
            renewal::grant(&c, &original, &original, 2, 240)
        } else {
            current_grant(&c, &original, &original, 2, 200, 190)
        };
        open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("original intent");
        assert!(
            matches!(
                open(&c).reconcile_expired_credential_renewal(
                    g.operation(),
                    g.statement_digest(),
                    &c.policy,
                    205
                ),
                Err(DurableError::Suspended)
            ),
            "legacy P0 route stays fenced"
        );
        let before = snapshot(&c, &original);
        let config = row(&open(&c));
        assert!(matches!(
            resolve(&c, &g, p1.historical(), 195),
            Err(DurableError::Protocol(Error::Validity))
        ));
        assert_eq!(row(&open(&c)), config);
        assert_eq!(snapshot(&c, &original), before);
        assert!(p1.check_mode(PrekeyQuality::OneTimeBoth, 205).is_ok());
        assert_eq!(
            g.successor_device().description.validity.check(205).is_ok(),
            roster_expires_first
        );
        assert_eq!(
            g.successor_device().roster_validity.check(205).is_err(),
            roster_expires_first
        );
        assert_eq!(
            resolve(&c, &g, p1.historical(), 205)
                .expect("exact no-commit proof and signed target expiry"),
            outcome(&g, 205)
        );
        assert_eq!(
            snapshot(&c, &original),
            before,
            "abandonment changes original config only"
        );
        assert_eq!(
            resolve(&c, &g, p1.historical(), 215).expect("exact terminal retry"),
            outcome(&g, 205)
        );
        assert_eq!(
            open(&c).policy_renewal_status().expect("unchanged P1"),
            PolicyRenewalStatus::Committed {
                operation: a.scope().operation,
                statement: a.statement_digest(),
                target: p1.checkpoint(),
            }
        );
        let next = current_grant(&c, &original, &original, 3, 260, 205);
        assert!(open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .is_err());
        assert!(matches!(
            open(&c).stage_credential_renewal(&next, next.operation(), &p1, 204),
            Err(DurableError::Protocol(Error::Validity))
        ));
        open(&c)
            .stage_credential_renewal(&next, next.operation(), &p1, 205)
            .expect("independent new operation from exact original predecessor");
        assert_eq!(
            resolve(&c, &g, p1.historical(), 205)
                .expect("retained old outcome while next is Pending"),
            outcome(&g, 205)
        );
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 205)
            .expect("same original installation completes new G");
        assert_eq!(
            active.parts().expect("parts").2.credential_digest(),
            next.successor_device().credential_digest()
        );
        active.close();
        assert!(
            resolve(&c, &g, p1.historical(), 215).is_err(),
            "forgotten terminal is not invented"
        );
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 204),
            Err(DurableError::Protocol(Error::Validity))
        ));
    }
}

#[test]
fn adopted_policy_expiry_unblocks_next_policy_and_time_floor_survives_that_adoption() {
    let (c, original, journal) = local(160, 300);
    let p1 = policy(&c, 2, 185, 170);
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
        .activate_policy_renewal(c.policy.historical(), &p1, 170)
        .expect("P1")
        .close();
    let g = current_grant(&c, &original, &original, 2, 340, 175);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 175)
        .expect("G under P1");
    assert!(g.successor_device().description.validity.check(190).is_ok());
    assert!(g.successor_device().roster_validity.check(190).is_ok());
    assert!(p1.check_mode(PrekeyQuality::OneTimeBoth, 190).is_err());
    assert_eq!(
        resolve(&c, &g, p1.historical(), 190).expect("only adopted P1 has expired"),
        outcome(&g, 190)
    );
    let p2 = policy(&c, 3, 400, 190);
    let second = approve_successor(&c, &original, &original, &p1, &p2, 190);
    assert!(matches!(
        open(&c).stage_policy_renewal(
            &second,
            second.scope().operation,
            c.policy.historical(),
            &p2,
            189
        ),
        Err(DurableError::Protocol(Error::Validity))
    ));
    stage(&c, &second, &p2, 190);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 190)
        .expect("same original credential under P2")
        .close();
    assert!(
        matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p2, 189),
            Err(DurableError::Protocol(Error::Validity))
        ),
        "time floor survives new policy and codec reset"
    );
    assert_eq!(
        resolve(&c, &g, p1.historical(), 190).expect("old exact outcome after P2"),
        outcome(&g, 190)
    );
    assert!(
        matches!(
            open(&c).stage_credential_renewal(&g, g.operation(), &p2, 190),
            Err(DurableError::Conflict)
        ),
        "new policy cannot revive the abandoned G operation"
    );
    let next = current_grant(&c, &original, &original, 3, 370, 191);
    open(&c)
        .stage_credential_renewal(&next, next.operation(), &p2, 191)
        .expect("new G under P2");
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 191)
        .expect("original owner after new G/P2")
        .close();
}

#[test]
fn expiry_resolution_uses_public_history_without_signer_or_live_runtime() {
    let (c, original, p1, _) = adopted();
    let g = current_grant(&c, &original, &original, 2, 200, 190);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original pending");
    let wrong = policy(&c, 3, 300, 190);
    let before = snapshot(&c, &original);
    assert!(matches!(
        resolve(&c, &g, wrong.historical(), 205),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(snapshot(&c, &original), before);
    p1.close();
    c.policy.close();
    c.policy.runtime.close();
    let held = c.paths.signer.with_extension("expired-held");
    fs::rename(&c.paths.signer, &held).expect("signer unavailable");
    assert_eq!(
        resolve(&c, &g, p1.historical(), 205).expect("public exact historical classification"),
        outcome(&g, 205)
    );
    fs::rename(held, &c.paths.signer).expect("restore original signer");
    assert_eq!(snapshot(&c, &original), before);
}

fn later_head(c: &Case, device: &VerifiedDevice, kind: &str) -> crate::VerifiedRoster {
    let mut description = device.description.clone();
    if kind == "generation" {
        description.generation += 1;
    }
    let certificate = c
        .root
        .issue_device(description, device.key.clone())
        .expect("root-signed historical member");
    let members = if kind == "revoked" {
        Vec::new()
    } else {
        vec![c.root.roster_entry(&certificate).expect("member")]
    };
    let roster = c
        .root
        .issue_roster(
            3,
            Validity::new(100, 280).expect("roster interval"),
            &members,
        )
        .expect("independent later head");
    AccountPin::new(
        device.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent pin")
    .verify_roster(roster.as_bytes(), 195)
    .expect("authenticated current roster")
}
fn install_head(c: &Case, original: &VerifiedDevice, roster: &crate::VerifiedRoster) {
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original metadata service");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(roster, 195)
        .expect("actual root-authorized later head");
    service.close();
}

#[test]
fn current_roster_history_distinguishes_committed_expiry_from_proven_no_commit_and_unknown() {
    for committed in [false, true] {
        for kind in ["retained", "revoked", "generation"] {
            let (c, original, p1, _) = adopted();
            let g = current_grant(&c, &original, &original, 2, 200, 190);
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &p1, 190)
                .expect("original G intent");
            if committed {
                fs::write(
                    c.paths
                        .configuration
                        .parent()
                        .expect("root")
                        .join("trusted-root"),
                    c.intent.root.encode(),
                )
                .expect("root pin");
                kill_credential_at(&c, "journal");
            }
            let later = later_head(
                &c,
                if committed {
                    g.successor_device()
                } else {
                    &original
                },
                kind,
            );
            install_head(&c, &original, &later);
            let before = snapshot(&c, &original);
            p1.close();
            c.policy.close();
            c.policy.runtime.close();
            let result = resolve(&c, &g, p1.historical(), 205);
            if committed {
                assert_eq!(
                    result.expect("actual old commit remains a commit after expiry and later head"),
                    renewal::committed(&g)
                );
            } else if kind == "generation" {
                assert!(matches!(result, Err(DurableError::Conflict)));
                assert_eq!(
                    open(&c)
                        .credential_renewal_status()
                        .expect("unknown intent survives"),
                    renewal::pending(&g)
                );
                assert_eq!(snapshot(&c, &original), before);
            } else {
                assert_eq!(
                    result.expect("exact same-generation predecessor proves no commit"),
                    CredentialRenewalStatus::ExpiredUncommitted {
                        operation: g.operation(),
                        statement: g.statement_digest(),
                        observed_head: later.checkpoint(),
                        observed_at: 205,
                    }
                );
                assert_eq!(snapshot(&c, &original), before);
            }
        }
    }
}

#[test]
fn pending_config_rollback_after_g_receipt_ack_never_creates_a_false_no_commit() {
    let (c, original, p1, _) = adopted();
    let g = current_grant(&c, &original, &original, 2, 200, 190);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original pending");
    let retained_pending = row(&open(&c));
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 190)
        .expect("actual G and completion ACK")
        .close();
    replace_authenticated(&c, &retained_pending);
    let before = snapshot(&c, &original);
    assert!(matches!(
        resolve(&c, &g, p1.historical(), 205),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&c)), retained_pending);
    assert_eq!(snapshot(&c, &original), before);
}

#[test]
fn unacknowledged_previous_g_is_reconciled_before_expired_successor_is_classified() {
    let (c, original, p1, _) = adopted();
    let first = current_grant(&c, &original, &original, 2, 195, 190);
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    open(&c)
        .stage_credential_renewal(&first, first.operation(), &p1, 190)
        .expect("first intent");
    kill_credential_at(&c, "completion");
    let expired = current_grant(&c, &original, first.successor_device(), 3, 210, 192);
    open(&c)
        .stage_credential_renewal(&expired, expired.operation(), &p1, 192)
        .expect("new intent after durable first completion");
    assert_eq!(
        resolve(&c, &expired, p1.historical(), 215)
            .expect("ACK known first G, prove absent next G"),
        outcome(&expired, 215)
    );
    assert_eq!(
        resolve(&c, &first, p1.historical(), 215).expect("retained first completion"),
        renewal::committed(&first)
    );
    let next = current_grant(&c, &original, first.successor_device(), 4, 270, 215);
    open(&c)
        .stage_credential_renewal(&next, next.operation(), &p1, 215)
        .expect("next independent G");
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 215)
        .expect("same original owner")
        .close();
}

#[test]
fn a_next_policy_can_reconcile_the_exact_prior_g_completion_ack() {
    let (c, original, p1, a) = adopted();
    let g = current_grant(&c, &original, &original, 2, 240, 190);
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("root pin");
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("G intent");
    kill_credential_at(&c, "completion");
    let p2 = policy(&c, 3, 320, 191);
    // Independent issuers already have the exact retained inputs; the request
    // snapshot API correctly refuses a new request until the old ACK completes.
    let mut expected = scope(&c, &original, g.successor_device(), a.scope().journal);
    expected.previous_policy = p1.checkpoint();
    expected.previous_authorization = Some(a.statement_digest());
    let materials = PolicyRenewalMaterials {
        original: c.policy.historical(),
        previous: p1.historical(),
        target: &p2,
        original_device: &original,
        current_device: g.successor_device(),
    };
    let statement =
        PolicyRenewalStatement::new(&expected, &materials, 191).expect("independent request");
    let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy root");
    let second = VerifiedPolicyRenewal::verify(
        &c.root
            .approve_policy_renewal(&statement)
            .expect("account approval"),
        &issuer
            .approve_policy_renewal(&statement)
            .expect("policy approval"),
        &expected,
        &materials,
        191,
    )
    .expect("independent exact approvals");
    stage(&c, &second, &p2, 191);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 191)
        .expect("exact prior G ACK and next P2 completion")
        .close();
}

#[test]
fn every_expiry_config_sync_error_recovers_original_pending_or_exact_terminal_without_journal_change(
) {
    let (c, original, p1, _) = adopted();
    let g = current_grant(&c, &original, &original, 2, 200, 190);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original pending");
    let (mut owner, _, count) = faulty(&c, false);
    count.store(0, Ordering::SeqCst);
    owner
        .reconcile_expired_policy_credential(
            g.operation(),
            g.statement_digest(),
            c.policy.historical(),
            p1.historical(),
            205,
        )
        .expect("calibrate expiry save");
    let barriers = count.load(Ordering::SeqCst);
    owner.close();
    assert!((1..=16).contains(&barriers));
    let (mut faults, mut pending, mut terminal) = (0, 0, 0);
    for cut in 1..=barriers {
        for after in [false, true] {
            let (c, original, p1, _) = adopted();
            let g = current_grant(&c, &original, &original, 2, 200, 190);
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &p1, 190)
                .expect("original intent");
            let before = snapshot(&c, &original);
            p1.close();
            c.policy.close();
            c.policy.runtime.close();
            let held = c.paths.signer.with_extension("expiry-sync-held");
            fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
            let (mut owner, remaining, _) = faulty(&c, after);
            remaining.store(cut, Ordering::SeqCst);
            assert_sync_failure(
                owner.reconcile_expired_policy_credential(
                    g.operation(),
                    g.statement_digest(),
                    c.policy.historical(),
                    p1.historical(),
                    205,
                ),
                after,
            );
            assert!(owner.active.is_none());
            faults += 1;
            let status = open(&c)
                .credential_renewal_status()
                .expect("unknown save result");
            assert!(
                status == renewal::pending(&g) || status == outcome(&g, 205),
                "only exact original Pending or terminal is possible"
            );
            if status == renewal::pending(&g) {
                pending += 1;
            } else {
                terminal += 1;
            }
            assert_eq!(
                resolve(&c, &g, p1.historical(), 205).expect("same original expiry recovery"),
                outcome(&g, 205)
            );
            assert_eq!(snapshot(&c, &original), before);
            fs::rename(held, &c.paths.signer).expect("restore original signer");
        }
    }
    assert_eq!(pending + terminal, faults);
    eprintln!("POLICY_ONLY_CREDENTIAL_EXPIRY_IO barriers={barriers} faults={faults} pending={pending} terminal={terminal} exact_operation=true journal_unchanged=true closed_runtime_no_signer=true");
}

#[test]
fn policy_credential_expiry_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_CREDENTIAL_EXPIRY_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 160, 150);
    let p1 = policy(&template, 2, 280, 170);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root pin")).expect("root"),
        DeviceDescription::new(
            [7; 16],
            1,
            p0.family(),
            Validity::new(100, 180).expect("original interval"),
        )
        .expect("original intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    let image = owner.image().expect("original image");
    let original = owner
        .original_device_metadata(&image)
        .expect("original metadata");
    let g = crate::VerifiedCredentialRenewal::from_journal(
        &fs::read(root.join("real-grant")).expect("original public G"),
        original.roster(),
    )
    .expect("real grant");
    p1.close();
    p0.close();
    p0.runtime.close();
    owner
        .reconcile_expired_policy_credential(
            g.operation(),
            g.statement_digest(),
            p0.historical(),
            p1.historical(),
            205,
        )
        .expect("original historical expiry recovery");
    Err("expected original expiry boundary did not stop the child")
}

fn kill_expiry_at(c: &Case, cut: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    if root.join("renewal-ready").exists() {
        fs::remove_file(root.join("renewal-ready")).expect("retire previous owned child marker");
    }
    let mut child = ChildGuard(Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "enrollment::tests::policy_renewal::credential::expiry::policy_credential_expiry_process_child", "--nocapture"])
        .env("QPERIAPT_POLICY_CREDENTIAL_EXPIRY_ROOT", root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", cut)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("child"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("renewal-ready").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "missing {cut} boundary"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("real process interruption");
    assert!(!child.0.wait().expect("reaped child").success());
}

#[test]
fn actual_expiry_process_cuts_keep_no_commit_or_exact_commit_and_complete_ack_without_owner() {
    for cut in [
        "expiry-before-save",
        "expiry-after-save",
        "expiry-completion",
    ] {
        let (c, original, p1, _) = adopted();
        let g = current_grant(&c, &original, &original, 2, 200, 190);
        let root = c.paths.configuration.parent().expect("root");
        fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
        fs::write(root.join("real-grant"), g.as_bytes()).expect("original G");
        open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("original pending");
        if cut == "expiry-completion" {
            kill_credential_at(&c, "journal");
        }
        let before = snapshot(&c, &original);
        let held = c.paths.signer.with_extension("expiry-process-held");
        fs::rename(&c.paths.signer, &held).expect("signer unavailable during child recovery");
        kill_expiry_at(&c, cut);
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let observed = resolve(&c, &g, p1.historical(), 205)
            .expect("same original recovery after real process interruption");
        if cut == "expiry-completion" {
            assert_eq!(observed, renewal::committed(&g));
            let scope = open(&c)
                .policy_renewal_scope(
                    PolicyRenewalId::generate().expect("future request ID"),
                    c.policy.historical(),
                )
                .expect("exact G receipt ACK completed, no operational owner");
            assert_eq!(
                scope.current_credential,
                g.successor_device().credential_digest()
            );
        } else {
            assert_eq!(observed, outcome(&g, 205));
            assert_eq!(snapshot(&c, &original), before);
        }
        fs::rename(held, &c.paths.signer).expect("restore original signer");
    }
    eprintln!("POLICY_ONLY_CREDENTIAL_EXPIRY_PROCESS cuts=3 no_commit_proven=true actual_commit_preserved=true original_ack_finished=true closed_runtime_no_signer=true no_owner_released=true");
}
