// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "policy_renewal_credential_expiry_tests.rs"]
mod expiry;

fn adopted() -> (
    Case,
    VerifiedDevice,
    VerifiedSessionPolicy,
    VerifiedPolicyRenewal,
) {
    let (c, original, journal) = local(160, 180);
    let p1 = policy(&c, 2, 280, 170);
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
        .expect("initial independent adoption")
        .close();
    (c, original, p1, a)
}

pub(super) fn current_grant(
    c: &Case,
    original: &VerifiedDevice,
    previous: &VerifiedDevice,
    version: u64,
    until: u64,
    now: u64,
) -> crate::VerifiedCredentialRenewal {
    let origin = c
        .root
        .issue_device(original.description.clone(), original.key.clone())
        .expect("original signed body");
    let predecessor = c
        .root
        .issue_device(previous.description.clone(), previous.key.clone())
        .expect("same previous credential");
    let mut description = previous.description.clone();
    description.validity =
        Validity::new(description.validity.from(), until).expect("credential extension");
    let successor = c
        .root
        .issue_device(description, previous.key.clone())
        .expect("same-key successor");
    let roster = c
        .root
        .issue_roster(
            version,
            Validity::new(100, until + 20).expect("current target roster interval"),
            &[c.root.roster_entry(&successor).expect("current member")],
        )
        .expect("new independently signed roster");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent target head");
    let authorization = crate::CredentialRenewalAuthorization {
        operation: crate::CredentialRenewalId::generate().expect("retained real operation"),
        previous: previous.roster().checkpoint(),
        policy_digest: c.policy.checkpoint().digest(),
    };
    let issued = c
        .root
        .issue_credential_renewal(
            crate::CredentialRenewalMaterials {
                original_credential: &origin,
                previous_credential: &predecessor,
                successor_credential: &successor,
                previous_roster: previous.roster().as_bytes(),
                successor_roster: roster.as_bytes(),
            },
            &authorization,
            &pin,
            now,
        )
        .expect("real current G approval");
    crate::VerifiedCredentialRenewal::verify(
        issued.as_bytes(),
        &pin,
        authorization.policy_digest,
        now,
    )
    .expect("independent current G verification")
}

pub(super) fn approve_successor(
    c: &Case,
    original: &VerifiedDevice,
    current: &VerifiedDevice,
    previous: &VerifiedSessionPolicy,
    target: &VerifiedSessionPolicy,
    now: u64,
) -> VerifiedPolicyRenewal {
    let scope = open(c)
        .policy_renewal_scope(
            PolicyRenewalId::generate().expect("new policy operation"),
            c.policy.historical(),
        )
        .expect("actual journal predecessor");
    let materials = PolicyRenewalMaterials {
        original: c.policy.historical(),
        previous: previous.historical(),
        target,
        original_device: original,
        current_device: current,
    };
    let statement =
        PolicyRenewalStatement::new(&scope, &materials, now).expect("exact successor request");
    let issuer =
        PolicySigningKey::deterministic([82; 32], [83; 32]).expect("independent policy root");
    VerifiedPolicyRenewal::verify(
        &c.root
            .approve_policy_renewal(&statement)
            .expect("account approval"),
        &issuer
            .approve_policy_renewal(&statement)
            .expect("policy approval"),
        &scope,
        &materials,
        now,
    )
    .expect("independent exact successor")
}

#[test]
fn real_credential_renewal_after_policy_only_adoption_keeps_original_policy_and_owner() {
    let (c, original, journal) = local(160, 180);
    let p1 = policy(&c, 2, 280, 170);
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
        .expect("independent policy adoption")
        .close();
    let original_signer = fs::read(&c.paths.signer).expect("original signer");
    let g = renewal::grant(&c, &original, &original, 2, 240);
    assert_eq!(
        open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("real G after independent policy adoption"),
        CredentialRenewalStatus::Pending {
            operation: g.operation(),
            statement: g.statement_digest(),
        }
    );
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 190)
        .expect("original owner under real G and unchanged P1 approval");
    let (service, signer, current) = active.parts().expect("original owners");
    signer
        .check_device(current)
        .expect("original full device key");
    assert_eq!(
        current.credential_digest(),
        g.successor_device().credential_digest()
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("journal"),
        journal
    );
    active.close();
    assert_eq!(
        fs::read(&c.paths.signer).expect("same signer"),
        original_signer
    );
    assert_eq!(
        open(&c)
            .policy_renewal_status()
            .expect("same independent authorization"),
        PolicyRenewalStatus::Committed {
            operation: a.scope().operation,
            statement: a.statement_digest(),
            target: p1.checkpoint(),
        }
    );
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("real G completion"),
        CredentialRenewalStatus::Committed {
            operation: g.operation(),
            statement: g.statement_digest(),
            target: g.successor_device().roster().checkpoint(),
        }
    );
}

#[test]
fn repeated_real_grants_and_roster_then_next_policy_keep_the_same_original_lineage() {
    let (c, original, journal) = local(160, 180);
    let p1 = policy(&c, 2, 280, 170);
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
        .expect("P1 owner")
        .close();
    let g1 = current_grant(&c, &original, &original, 2, 240, 190);
    let g2 = current_grant(&c, &original, g1.successor_device(), 3, 260, 245);
    for (g, now) in [(&g1, 190), (&g2, 245)] {
        open(&c)
            .stage_credential_renewal(g, g.operation(), &p1, now)
            .expect("next real G");
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, now)
            .expect("same original owner");
        assert_eq!(
            active.parts().expect("parts").2.credential_digest(),
            g.successor_device().credential_digest()
        );
        active.close();
        assert_eq!(row(&open(&c)).get(..8), Some(b"QPENST12".as_slice()));
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("real completion"),
            renewal::committed(g)
        );
    }
    let (next, pin) = super::policy_roster::next_roster(&c, g2.successor_device(), 4, 320);
    open(&c)
        .refresh_roster(
            g2.successor_device().roster().checkpoint(),
            next.as_bytes(),
            &pin,
            &p1,
            250,
        )
        .expect("roster maintenance after actual G");
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 250)
        .expect("same original owner after R4");
    let current = active.parts().expect("parts").2.clone();
    active.close();
    let p2 = policy(&c, 3, 330, 250);
    let second = approve_successor(&c, &original, &current, &p1, &p2, 250);
    assert_eq!(
        second.scope().previous_authorization,
        Some(a.statement_digest())
    );
    stage(&c, &second, &p2, 250);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 250)
        .expect("P2 after real G and roster")
        .close();
    assert_eq!(
        row(&open(&c)).get(..8),
        Some(b"QPENST10".as_slice()),
        "new approval binds exact current C/R"
    );
    let g3 = current_grant(&c, &original, &current, 5, 350, 265);
    open(&c)
        .stage_credential_renewal(&g3, g3.operation(), &p2, 265)
        .expect("real G after P2");
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 265)
        .expect("G3 under exact P2");
    assert_eq!(
        active.parts().expect("parts").2.credential_digest(),
        g3.successor_device().credential_digest()
    );
    active.close();
    assert_eq!(
        open(&c).policy_renewal_status().expect("P2 history"),
        PolicyRenewalStatus::Committed {
            operation: second.scope().operation,
            statement: second.statement_digest(),
            target: p2.checkpoint(),
        }
    );
}

#[test]
fn real_grant_after_policy_only_does_not_reactivate_retained_older_joint_policy() {
    let (c, original, journal) = local(160, 160);
    let g0 = renewal::grant(&c, &original, &original, 2, 180);
    let p1 = policy(&c, 2, 220, 170);
    let t = super::super::policy_continuation::joint(
        &c,
        &g0,
        &super::super::policy_continuation::scope(&c, &g0, journal),
        &c.policy,
        &p1,
    );
    open(&c)
        .stage_policy_continuation(&g0, &t, g0.operation(), &p1, 170)
        .expect("old genuine G/T");
    open(&c)
        .reconcile_policy_continuation(c.policy.historical(), &p1, 170)
        .expect("old G/T completion");
    let p2 = policy(&c, 3, 300, 175);
    let a = approve_successor(&c, &original, g0.successor_device(), &p1, &p2, 175);
    stage(&c, &a, &p2, 175);
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 175)
        .expect("independent P2")
        .close();
    let g1 = renewal::grant(&c, &original, g0.successor_device(), 3, 260);
    assert!(matches!(
        open(&c).stage_credential_renewal(&g1, g1.operation(), &p1, 190),
        Err(DurableError::Protocol(Error::Scope))
    ));
    open(&c)
        .stage_credential_renewal(&g1, g1.operation(), &p2, 190)
        .expect("real G carries P2");
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 190)
        .expect("owner under exact P2")
        .close();
    assert_eq!(
        open(&c).policy_renewal_status().expect("P2 retained"),
        PolicyRenewalStatus::Committed {
            operation: a.scope().operation,
            statement: a.statement_digest(),
            target: p2.checkpoint(),
        }
    );
}

#[test]
fn policy_credential_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_CREDENTIAL_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 160, 150);
    let p1 = policy(&template, 2, 280, 190);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("independent root"))
            .expect("root key"),
        DeviceDescription::new(
            [7; 16],
            1,
            p0.family(),
            Validity::new(100, 180).expect("original validity"),
        )
        .expect("original intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    if std::env::var("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE").expect("cut") == "intent" {
        let image = owner.image().expect("original image");
        let original = owner
            .original_device_metadata(&image)
            .expect("original metadata");
        let g = crate::VerifiedCredentialRenewal::from_journal(
            &fs::read(root.join("real-grant")).expect("original public grant"),
            original.roster(),
        )
        .expect("actual root-signed G");
        owner
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("original intent");
    } else {
        owner
            .activate_policy_renewal(p0.historical(), &p1, 190)
            .expect("original owner path")
            .close();
    }
    Err("expected original boundary was not reached")
}

fn kill_credential_at(c: &Case, cut: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("original root");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "enrollment::tests::policy_renewal::credential::policy_credential_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_POLICY_CREDENTIAL_CUT_ROOT", root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
            .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", cut)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("renewal-ready").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "missing {cut} boundary"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("real process interruption");
    assert!(!child.0.wait().expect("reap child").success());
}

#[test]
fn real_process_cuts_distinguish_uncommitted_g_from_exact_historical_completion() {
    for cut in ["intent", "journal", "completion", "acknowledgement"] {
        let (c, original, p1, a) = adopted();
        let g = renewal::grant(&c, &original, &original, 2, 240);
        let root = c.paths.configuration.parent().expect("original root");
        fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
        fs::write(root.join("real-grant"), g.as_bytes()).expect("original grant");
        if cut != "intent" {
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &p1, 190)
                .expect("durable G intent");
        }
        kill_credential_at(&c, cut);
        if cut == "intent" {
            let before = row(&open(&c));
            assert!(matches!(
                open(&c).recover_historical_policy_credential(
                    g.operation(),
                    g.statement_digest(),
                    c.policy.historical(),
                    p1.historical()
                ),
                Err(DurableError::Suspended)
            ));
            assert_eq!(row(&open(&c)), before);
            assert_eq!(
                open(&c)
                    .credential_renewal_status()
                    .expect("original pending"),
                renewal::pending(&g)
            );
            open(&c)
                .activate_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("same original G with current permission")
                .close();
        }
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let held = c.paths.signer.with_extension("credential-held");
        fs::rename(&c.paths.signer, &held).expect("private signer unavailable");
        assert_eq!(
            open(&c)
                .recover_historical_policy_credential(
                    g.operation(),
                    g.statement_digest(),
                    c.policy.historical(),
                    p1.historical()
                )
                .expect("exact historical G completion without signer or runtime"),
            renewal::committed(&g)
        );
        assert_eq!(
            open(&c)
                .policy_renewal_status()
                .expect("unchanged independent P1"),
            PolicyRenewalStatus::Committed {
                operation: a.scope().operation,
                statement: a.statement_digest(),
                target: p1.checkpoint(),
            }
        );
        fs::rename(held, &c.paths.signer).expect("restore original signer");
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 190),
            Err(DurableError::Protocol(Error::Closed))
        ));
    }
    eprintln!("POLICY_ONLY_CREDENTIAL_PROCESS cuts=4 original_grant=true original_policy=true uncommitted_history_suspended=true closed_runtime_no_signer_completion=true no_owner_from_history=true");
}

#[test]
fn closing_policy_at_real_g_completion_withholds_owner_but_preserves_both_facts() {
    let (c, original, p1, a) = adopted();
    let p1 = Arc::new(p1);
    let g = renewal::grant(&c, &original, &original, 2, 240);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original G intent");
    CLOSE_POLICY_AFTER_ACTIVE.with(|p| *p.borrow_mut() = Some(Arc::clone(&p1)));
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p1, 190),
        Err(DurableError::Protocol(Error::Closed))
    ));
    assert_eq!(
        open(&c).credential_renewal_status().expect("G fact"),
        renewal::committed(&g)
    );
    assert_eq!(
        open(&c)
            .recover_historical_policy_credential(
                g.operation(),
                g.statement_digest(),
                c.policy.historical(),
                p1.historical()
            )
            .expect("historical completion"),
        renewal::committed(&g)
    );
    assert_eq!(
        open(&c).policy_renewal_status().expect("P1 fact"),
        PolicyRenewalStatus::Committed {
            operation: a.scope().operation,
            statement: a.statement_digest(),
            target: p1.checkpoint(),
        }
    );
}

#[test]
fn real_g_enrollment_sync_errors_preserve_original_pending_or_exact_completion() {
    let (mut faults, mut pending_count, mut completed_count) = (0, 0, 0);
    for completing in [false, true] {
        let (c, original, p1, _) = adopted();
        let g = renewal::grant(&c, &original, &original, 2, 240);
        if completing {
            open(&c)
                .stage_credential_renewal(&g, g.operation(), &p1, 190)
                .expect("intent before completion");
        }
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        if completing {
            owner
                .reconcile_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("completion calibration");
        } else {
            owner
                .stage_credential_renewal(&g, g.operation(), &p1, 190)
                .expect("intent calibration");
        }
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        assert!((1..=16).contains(&barriers));
        for cut in 1..=barriers {
            for after in [false, true] {
                let (c, original, p1, a) = adopted();
                let g = renewal::grant(&c, &original, &original, 2, 240);
                if completing {
                    open(&c)
                        .stage_credential_renewal(&g, g.operation(), &p1, 190)
                        .expect("original intent");
                }
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(
                        owner.reconcile_policy_renewal(c.policy.historical(), &p1, 190),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        owner.stage_credential_renewal(&g, g.operation(), &p1, 190),
                        after,
                    );
                }
                assert!(owner.active.is_none());
                faults += 1;
                let status = open(&c)
                    .credential_renewal_status()
                    .expect("unknown save result");
                if completing {
                    match status {
                        CredentialRenewalStatus::Pending { .. } => {
                            assert_eq!(status, renewal::pending(&g));
                            pending_count += 1;
                            Ok(())
                        }
                        CredentialRenewalStatus::Committed { .. } => {
                            assert_eq!(status, renewal::committed(&g));
                            completed_count += 1;
                            Ok(())
                        }
                        _ => Err("journal G was committed but enrollment lost original operation"),
                    }
                    .expect("every unknown result retains the exact original G");
                    p1.close();
                    c.policy.close();
                    c.policy.runtime.close();
                    assert_eq!(
                        open(&c)
                            .recover_historical_policy_credential(
                                g.operation(),
                                g.statement_digest(),
                                c.policy.historical(),
                                p1.historical()
                            )
                            .expect("exact already-committed G after runtime close"),
                        renewal::committed(&g)
                    );
                } else {
                    assert!(
                        status == CredentialRenewalStatus::Absent || status == renewal::pending(&g)
                    );
                    open(&c)
                        .stage_credential_renewal(&g, g.operation(), &p1, 190)
                        .expect("same original intent retry");
                    open(&c)
                        .activate_policy_renewal(c.policy.historical(), &p1, 190)
                        .expect("current completion")
                        .close();
                }
                assert_eq!(
                    open(&c).credential_renewal_status().expect("exact final G"),
                    renewal::committed(&g)
                );
                assert_eq!(
                    open(&c).policy_renewal_status().expect("exact original P1"),
                    PolicyRenewalStatus::Committed {
                        operation: a.scope().operation,
                        statement: a.statement_digest(),
                        target: p1.checkpoint(),
                    }
                );
            }
        }
    }
    eprintln!("POLICY_ONLY_CREDENTIAL_CONFIG_IO faults={faults} pending_after_completion_error={pending_count} committed_after_completion_error={completed_count} exact_original_g_and_policy=true");
}

#[test]
fn original_roster_update_retires_exact_real_g_receipt_after_completion_process_loss() {
    let (c, original, p1, _) = adopted();
    let g = renewal::grant(&c, &original, &original, 2, 240);
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original G intent");
    kill_credential_at(&c, "completion");
    assert_eq!(
        open(&c)
            .credential_renewal_status()
            .expect("completed G before ACK"),
        renewal::committed(&g)
    );
    let (roster, pin) = super::policy_roster::next_roster(&c, g.successor_device(), 3, 280);
    open(&c)
        .refresh_roster(
            g.successor_device().roster().checkpoint(),
            roster.as_bytes(),
            &pin,
            &p1,
            191,
        )
        .expect("original roster intent after G completion");
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 191)
        .expect("ACK exact G and complete original roster");
    assert_eq!(
        active.parts().expect("parts").2.roster().checkpoint(),
        roster.checkpoint()
    );
    assert_eq!(
        active.parts().expect("parts").2.credential_digest(),
        g.successor_device().credential_digest()
    );
}

#[test]
fn a_config_only_g_receipt_substitution_cannot_release_owner_before_or_after_roster_refresh() {
    for refreshing in [false, true] {
        let (c, original, p1, _) = adopted();
        let g = renewal::grant(&c, &original, &original, 2, 240);
        open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("G intent");
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 190)
            .expect("actual G owner")
            .close();
        let mut owner = open(&c);
        let image = owner.image().expect("completed G image");
        let mut completion = image
            .renewal
            .as_ref()
            .and_then(LocalRenewal::policy_prior_credential_completion)
            .expect("G completion")
            .clone();
        let mut exact = Vec::new();
        completion.encode(&mut exact);
        let mut bytes = row(&owner);
        assert_eq!(
            bytes.windows(exact.len()).filter(|w| *w == exact).count(),
            1
        );
        let offset = bytes
            .windows(exact.len())
            .position(|w| w == exact)
            .expect("exact completion slot");
        completion.operation = crate::CredentialRenewalId::generate().expect("different operation");
        completion.statement = [91; 32];
        let mut substituted = Vec::new();
        completion.encode(&mut substituted);
        bytes
            .get_mut(offset..offset + substituted.len())
            .expect("same-width receipt")
            .copy_from_slice(&substituted);
        owner.close();
        replace_authenticated(&c, &bytes);
        if refreshing {
            let (roster, pin) = super::policy_roster::next_roster(&c, g.successor_device(), 3, 280);
            open(&c)
                .refresh_roster(
                    g.successor_device().roster().checkpoint(),
                    roster.as_bytes(),
                    &pin,
                    &p1,
                    191,
                )
                .expect("metadata intent is not G adoption proof");
        }
        let before = row(&open(&c));
        assert!(matches!(
            open(&c).activate_policy_renewal(c.policy.historical(), &p1, 191),
            Err(DurableError::Conflict)
        ));
        assert_eq!(
            row(&open(&c)),
            before,
            "do not replace config with guessed completion"
        );
    }
}

#[test]
fn current_expiry_and_journal_revocation_still_deny_owner_after_real_g() {
    for revoking in [false, true] {
        let (c, original, p1, _) = adopted();
        let g = current_grant(&c, &original, &original, 2, 195, 190);
        open(&c)
            .stage_credential_renewal(&g, g.operation(), &p1, 190)
            .expect("G intent");
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 190)
            .expect("actual G owner");
        if revoking {
            let revoked = c
                .root
                .issue_roster(
                    3,
                    Validity::new(100, 280).expect("revocation interval"),
                    &[],
                )
                .expect("signed revocation");
            let pin = AccountPin::new(
                original.account_id(),
                c.intent.root.clone(),
                revoked.checkpoint(),
                c.policy.family(),
            )
            .expect("independent head");
            active
                .parts()
                .expect("parts")
                .0
                .stores()
                .expect("stores")
                .0
                .install_roster(
                    &pin.verify_roster(revoked.as_bytes(), 191)
                        .expect("revoked roster"),
                    191,
                )
                .expect("actual journal revocation");
        }
        active.close();
        let now = if revoking { 191 } else { 196 };
        assert!(g.successor_device().roster_validity.check(now).is_ok());
        assert!(p1.check_mode(PrekeyQuality::OneTimeBoth, now).is_ok());
        let result = open(&c).activate_policy_renewal(c.policy.historical(), &p1, now);
        if revoking {
            assert!(matches!(result, Err(DurableError::Protocol(Error::Scope))));
        } else {
            assert!(matches!(
                result,
                Err(DurableError::Protocol(Error::Validity))
            ));
        }
        assert_eq!(
            open(&c)
                .recover_historical_policy_credential(
                    g.operation(),
                    g.statement_digest(),
                    c.policy.historical(),
                    p1.historical()
                )
                .expect("historical G fact only"),
            renewal::committed(&g)
        );
    }
}

#[test]
fn committed_g_history_survives_replacement_by_a_higher_device_generation() {
    let (c, original, p1, _) = adopted();
    let g = renewal::grant(&c, &original, &original, 2, 240);
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("original G intent");
    kill_credential_at(&c, "journal");
    let mut service = DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        &original,
        c.policy.historical(),
        None,
    )
    .expect("same original service");
    let other_key = DeviceSigningKey::generate().expect("new independently authorized key");
    let certificate = c
        .root
        .issue_device(
            DeviceDescription::new(
                original.device_id(),
                2,
                c.policy.family(),
                Validity::new(100, 280).expect("new generation interval"),
            )
            .expect("new generation"),
            other_key.public_key().expect("full new key"),
        )
        .expect("new root-authorized device generation");
    let roster = c
        .root
        .issue_roster(
            3,
            Validity::new(100, 280).expect("roster interval"),
            &[c.root.roster_entry(&certificate).expect("new member")],
        )
        .expect("signed replacement roster");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent replacement head");
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(roster.as_bytes(), 191)
                .expect("authenticated replacement"),
            191,
        )
        .expect("monotonic generation replacement");
    service.close();
    assert_eq!(
        open(&c)
            .recover_historical_policy_credential(
                g.operation(),
                g.statement_digest(),
                c.policy.historical(),
                p1.historical()
            )
            .expect("exact old commit remains provable after current generation changes"),
        renewal::committed(&g)
    );
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p1, 191),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

#[test]
fn a_later_exact_policy_completion_remains_readable_after_active_g_history_is_superseded() {
    let (c, original, p1, _) = adopted();
    let g = renewal::grant(&c, &original, &original, 2, 240);
    open(&c)
        .stage_credential_renewal(&g, g.operation(), &p1, 190)
        .expect("G intent");
    open(&c)
        .activate_policy_renewal(c.policy.historical(), &p1, 190)
        .expect("G completion")
        .close();
    let p2 = policy(&c, 3, 320, 191);
    let second = approve_successor(&c, &original, g.successor_device(), &p1, &p2, 191);
    stage(&c, &second, &p2, 191);
    let mut active = open(&c)
        .activate_policy_renewal(c.policy.historical(), &p2, 191)
        .expect("P2 exact C/R completion");
    let key = DeviceSigningKey::generate().expect("independent next key");
    let certificate = c
        .root
        .issue_device(
            DeviceDescription::new(
                original.device_id(),
                2,
                c.policy.family(),
                Validity::new(100, 280).expect("new interval"),
            )
            .expect("new generation"),
            key.public_key().expect("new full key"),
        )
        .expect("signed replacement");
    let roster = c
        .root
        .issue_roster(
            3,
            Validity::new(100, 280).expect("current interval"),
            &[c.root.roster_entry(&certificate).expect("member")],
        )
        .expect("new root-signed head");
    let pin = AccountPin::new(
        original.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent head");
    active
        .parts()
        .expect("parts")
        .0
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(roster.as_bytes(), 192)
                .expect("current roster"),
            192,
        )
        .expect("generation replacement");
    active.close();
    assert!(matches!(
        open(&c).activate_policy_renewal(c.policy.historical(), &p2, 192),
        Err(DurableError::Protocol(Error::Scope))
    ));
    p1.close();
    p2.close();
    c.policy.close();
    c.policy.runtime.close();
    assert_eq!(
        open(&c)
            .recover_historical_policy_renewal(
                second.scope().operation,
                second.statement_digest(),
                c.policy.historical()
            )
            .expect("exact P2 completion survives superseded G"),
        PolicyRenewalStatus::Committed {
            operation: second.scope().operation,
            statement: second.statement_digest(),
            target: p2.checkpoint(),
        }
    );
}
