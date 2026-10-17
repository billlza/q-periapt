// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn next_roster(
    c: &Case,
    current: &VerifiedDevice,
    version: u64,
    until: u64,
) -> (crate::IssuedRoster, AccountPin) {
    let certificate = c
        .root
        .issue_device(current.description.clone(), current.key.clone())
        .expect("unchanged credential");
    let roster = c
        .root
        .issue_roster(
            version,
            Validity::new(100, until).expect("current roster interval"),
            &[c.root
                .roster_entry(&certificate)
                .expect("same current member")],
        )
        .expect("independent root update");
    let pin = AccountPin::new(
        current.account_id(),
        c.intent.root.clone(),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("independent current pin");
    (roster, pin)
}

#[test]
fn same_credential_roster_refresh_after_policy_only_uses_original_enrollment() {
    for prior_g in [false, true] {
        let (c, original, journal) = local(180, if prior_g { 160 } else { 240 });
        let g = prior_g.then(|| renewal::grant(&c, &original, &original, 2, 240));
        if let Some(g) = &g {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &c.policy, 170)
                .expect("original G");
            open(&c)
                .activate(&c.policy, 170, None)
                .expect("current G owner")
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
        stage(&c, &a, &p1, 190);
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 190)
            .expect("first policy-only owner")
            .close();
        let previous = current.roster().checkpoint();
        let (next, pin) = next_roster(&c, current, previous.version() + 1, 280);
        let original_signer = fs::read(&c.paths.signer).expect("original signer");
        let g_status = open(&c)
            .credential_renewal_status()
            .expect("original G progress");
        let mut owner = open(&c);
        assert_eq!(
            owner
                .refresh_roster(previous, next.as_bytes(), &pin, &p1, 205)
                .expect("policy-only enrollment can retain a current same-C roster"),
            EnrollmentStatus::Refreshing {
                journal,
                previous,
                next: next.checkpoint(),
            }
        );
        owner.close();
        let mut active = open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 205)
            .expect("same owner reconciles original roster intent");
        let (service, signer, observed) = active.parts().expect("original owners");
        signer.check_device(observed).expect("same key");
        assert_eq!(observed.credential_digest(), current.credential_digest());
        assert_eq!(observed.roster().checkpoint(), next.checkpoint());
        assert_eq!(
            service
                .stores()
                .expect("same journal")
                .0
                .identity()
                .expect("journal"),
            journal
        );
        active.close();
        assert_eq!(
            open(&c).status().expect("roster transaction completed"),
            EnrollmentStatus::Active(journal)
        );
        assert_eq!(
            open(&c)
                .credential_renewal_status()
                .expect("G remains unchanged"),
            g_status
        );
        assert_eq!(
            fs::read(&c.paths.signer).expect("same original signer bytes"),
            original_signer
        );
    }
}

struct Continued {
    c: Case,
    original: VerifiedDevice,
    journal: JournalIdentity,
    p1: VerifiedSessionPolicy,
    approval: VerifiedPolicyRenewal,
}
impl Continued {
    fn new() -> Self {
        let (c, original, journal) = local(160, 240);
        let p1 = policy(&c, 2, 260, 170);
        let approval = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, journal),
            170,
        );
        stage(&c, &approval, &p1, 170);
        open(&c)
            .activate_policy_renewal(c.policy.historical(), &p1, 170)
            .expect("continued owner")
            .close();
        Self {
            c,
            original,
            journal,
            p1,
            approval,
        }
    }
    fn service(&self) -> DeviceService {
        DeviceInstallation::reconcile_original_enrollment(
            self.c.paths.installation.clone(),
            JournalKey::open(&self.c.paths.wrapping).expect("original key"),
            &self.original,
            self.c.policy.historical(),
            None,
        )
        .expect("original service metadata")
    }
    fn refresh(&self) -> (crate::IssuedRoster, AccountPin) {
        let (next, pin) = next_roster(&self.c, &self.original, 2, 280);
        assert_eq!(
            open(&self.c)
                .refresh_roster(
                    self.original.roster().checkpoint(),
                    next.as_bytes(),
                    &pin,
                    &self.p1,
                    205
                )
                .expect("retain original roster intent"),
            EnrollmentStatus::Refreshing {
                journal: self.journal,
                previous: self.original.roster().checkpoint(),
                next: next.checkpoint(),
            }
        );
        (next, pin)
    }
}

#[test]
fn refreshed_roster_permits_next_policy_and_preserves_original_approval() {
    let f = Continued::new();
    let (next, pin) = f.refresh();
    let certificate =
        f.c.root
            .issue_device(f.original.description.clone(), f.original.key.clone())
            .expect("same credential body");
    let current = pin
        .verify_device(&certificate, next.as_bytes(), 205)
        .expect("current same-C input");
    let p2 = policy(&f.c, 3, 290, 210);
    let mut expected = scope(&f.c, &f.original, &current, f.journal);
    expected.previous_policy = f.p1.checkpoint();
    expected.previous_authorization = Some(f.approval.statement_digest());
    let m = PolicyRenewalMaterials {
        original: f.c.policy.historical(),
        previous: f.p1.historical(),
        target: &p2,
        original_device: &f.original,
        current_device: &current,
    };
    let statement = PolicyRenewalStatement::new(&expected, &m, 210)
        .expect("next exact policy request under R2");
    let root = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("same policy root");
    let a =
        f.c.root
            .approve_policy_renewal(&statement)
            .expect("account approval");
    let p = root
        .approve_policy_renewal(&statement)
        .expect("policy approval");
    let second =
        VerifiedPolicyRenewal::verify(&a, &p, &expected, &m, 210).expect("two-root authorization");
    assert!(
        matches!(
            open(&f.c).stage_policy_renewal(
                &second,
                expected.operation,
                f.c.policy.historical(),
                &p2,
                210
            ),
            Err(DurableError::Protocol(Error::State))
        ),
        "roster intent must finish before another policy intent"
    );
    open(&f.c)
        .activate_policy_renewal(f.c.policy.historical(), &f.p1, 205)
        .expect("finish R2 first")
        .close();
    let before = row(&open(&f.c));
    assert_eq!(before.get(..8), Some(b"QPENST11".as_slice()));
    assert!(before
        .windows(f.approval.as_bytes().len())
        .any(|w| w == f.approval.as_bytes()));
    stage(&f.c, &second, &p2, 210);
    let mut active = open(&f.c)
        .activate_policy_renewal(f.c.policy.historical(), &p2, 210)
        .expect("next policy under same C and new R2");
    let (service, signer, device) = active.parts().expect("original owners");
    signer.check_device(device).expect("same signer");
    assert_eq!(device.credential_digest(), f.original.credential_digest());
    assert_eq!(device.roster().checkpoint(), next.checkpoint());
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .identity()
            .expect("same journal"),
        f.journal
    );
    active.close();
    assert_eq!(
        open(&f.c)
            .credential_renewal_status()
            .expect("no G manufactured"),
        CredentialRenewalStatus::Absent
    );
}

#[test]
fn roster_pending_retry_preserves_first_bytes_and_rejects_another_target() {
    let f = Continued::new();
    let (next, pin) = f.refresh();
    let mut owner = open(&f.c);
    let before = row(&owner);
    let status = owner.status().expect("exact progress");
    assert_eq!(
        owner
            .refresh_roster(
                f.original.roster().checkpoint(),
                next.as_bytes(),
                &pin,
                &f.p1,
                205
            )
            .expect("exact retry"),
        status
    );
    assert_eq!(row(&owner), before);
    let (resigned, resigned_pin) = next_roster(&f.c, &f.original, 2, 280);
    assert_eq!(resigned.checkpoint(), next.checkpoint());
    assert_ne!(
        resigned.as_bytes(),
        next.as_bytes(),
        "distinct valid root signatures"
    );
    assert_eq!(
        owner
            .refresh_roster(
                f.original.roster().checkpoint(),
                resigned.as_bytes(),
                &resigned_pin,
                &f.p1,
                205
            )
            .expect("same canonical target retry"),
        status
    );
    assert_eq!(row(&owner), before, "preserve first target signature bytes");
    owner.close();
    let (fork, fork_pin) = next_roster(&f.c, &f.original, 2, 281);
    assert!(matches!(
        open(&f.c).refresh_roster(
            f.original.roster().checkpoint(),
            fork.as_bytes(),
            &fork_pin,
            &f.p1,
            205
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&f.c)), before);
    let mut wrong_version = before.clone();
    wrong_version
        .get_mut(..8)
        .expect("tag")
        .copy_from_slice(b"QPENST10");
    replace_authenticated(&f.c, &wrong_version);
    assert!(
        DeviceEnrollment::open(f.c.paths.clone(), f.c.intent.clone()).is_err(),
        "old10 must not reinterpret Refreshing"
    );
    replace_authenticated(&f.c, &before);
    assert_eq!(row(&open(&f.c)), before);
}

#[test]
fn historical_roster_recovery_finishes_only_an_exact_already_installed_target() {
    let f = Continued::new();
    let (next, pin) = f.refresh();
    let before = row(&open(&f.c));
    assert!(matches!(
        open(&f.c).recover_historical_policy_renewal(
            f.approval.scope().operation,
            f.approval.statement_digest(),
            f.c.policy.historical()
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(row(&open(&f.c)), before);
    let mut service = f.service();
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(next.as_bytes(), 205)
                .expect("current root target"),
            205,
        )
        .expect("independent actual root update");
    service.close();
    f.p1.close();
    f.c.policy.close();
    f.c.policy.runtime.close();
    let held = f.c.paths.signer.with_extension("held");
    fs::rename(&f.c.paths.signer, &held).expect("signer unavailable");
    open(&f.c)
        .recover_historical_policy_renewal(
            f.approval.scope().operation,
            f.approval.statement_digest(),
            f.c.policy.historical(),
        )
        .expect("complete already-applied roster without runtime or signer");
    assert_eq!(
        open(&f.c).status().expect("completed original roster fact"),
        EnrollmentStatus::Active(f.journal)
    );
    let mut service = f.service();
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .roster_checkpoint(f.original.account_id())
            .expect("actual target"),
        next.checkpoint()
    );
    service.close();
    fs::rename(held, &f.c.paths.signer).expect("restore original signer");
}

#[test]
fn a_later_journal_head_never_gets_rolled_back_by_an_old_roster_intent() {
    let f = Continued::new();
    let _ = f.refresh();
    let (later, pin) = next_roster(&f.c, &f.original, 3, 290);
    let mut service = f.service();
    service
        .stores()
        .expect("stores")
        .0
        .install_roster(
            &pin.verify_roster(later.as_bytes(), 205)
                .expect("later root head"),
            205,
        )
        .expect("advance to R3");
    let before = service.stores().expect("stores").0.test_snapshot();
    service.close();
    let saved = row(&open(&f.c));
    assert!(matches!(
        open(&f.c).activate_policy_renewal(f.c.policy.historical(), &f.p1, 205),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        open(&f.c).recover_historical_policy_renewal(
            f.approval.scope().operation,
            f.approval.statement_digest(),
            f.c.policy.historical()
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(row(&open(&f.c)), saved);
    let mut service = f.service();
    let after = service.stores().expect("stores").0.test_snapshot();
    assert_eq!(
        (before.revision, before.digest),
        (after.revision, after.digest)
    );
    assert_eq!(
        service
            .stores()
            .expect("stores")
            .0
            .roster_checkpoint(f.original.account_id())
            .expect("preserved R3"),
        later.checkpoint()
    );
}

#[test]
fn policy_roster_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_ROSTER_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 160, 150);
    let p1 = policy(&template, 2, 260, 205);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root pin")).expect("root"),
        DeviceDescription::new(
            [7; 16],
            1,
            p0.family(),
            Validity::new(100, 240).expect("original credential interval"),
        )
        .expect("original intent"),
    );
    DeviceEnrollment::open(paths(root), intent)
        .expect("original record")
        .reconcile_policy_renewal(p0.historical(), &p1, 205)
        .expect("original roster coordinator");
    Err("requested original roster boundary did not stop the child")
}

#[test]
fn real_process_roster_cuts_resume_exact_original_update_after_runtime_close() {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for cut in ["policy-roster-journal", "policy-roster-completion"] {
        let f = Continued::new();
        let (next, _) = f.refresh();
        let signer = fs::read(&f.c.paths.signer).expect("signer bytes");
        let root = f.c.paths.configuration.parent().expect("root");
        fs::write(root.join("trusted-root"), f.c.intent.root.encode())
            .expect("independent root pin");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "enrollment::tests::policy_renewal::policy_roster::policy_roster_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_POLICY_ROSTER_CUT_ROOT", root)
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
        let observed = open(&f.c).status().expect("retained original boundary");
        assert_eq!(
            observed,
            if cut == "policy-roster-journal" {
                EnrollmentStatus::Refreshing {
                    journal: f.journal,
                    previous: f.original.roster().checkpoint(),
                    next: next.checkpoint(),
                }
            } else {
                EnrollmentStatus::Active(f.journal)
            }
        );
        f.p1.close();
        f.c.policy.close();
        f.c.policy.runtime.close();
        open(&f.c)
            .recover_historical_policy_renewal(
                f.approval.scope().operation,
                f.approval.statement_digest(),
                f.c.policy.historical(),
            )
            .expect("historical exact root-update completion");
        assert_eq!(
            open(&f.c).status().expect("completed state"),
            EnrollmentStatus::Active(f.journal)
        );
        assert_eq!(fs::read(&f.c.paths.signer).expect("same signer"), signer);
        let mut service = f.service();
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .roster_checkpoint(f.original.account_id())
                .expect("same target"),
            next.checkpoint()
        );
    }
    eprintln!("POLICY_ONLY_ROSTER_PROCESS_CUTS cuts=2 original_journal=true exact_target=true closed_runtime_recovery=true no_operational_owner=true");
}

#[test]
fn roster_intent_and_completion_sync_errors_preserve_exact_original_target() {
    let (mut faults, mut active_after_error, mut refreshing_after_error) = (0, 0, 0);
    for completing in [false, true] {
        let f = Continued::new();
        let (next, pin) = if completing {
            f.refresh()
        } else {
            next_roster(&f.c, &f.original, 2, 280)
        };
        let (mut owner, _, count) = faulty(&f.c, false);
        count.store(0, Ordering::SeqCst);
        if completing {
            owner
                .reconcile_policy_renewal(f.c.policy.historical(), &f.p1, 205)
                .expect("completion calibration");
        } else {
            owner
                .refresh_roster(
                    f.original.roster().checkpoint(),
                    next.as_bytes(),
                    &pin,
                    &f.p1,
                    205,
                )
                .expect("intent calibration");
        }
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        assert!((1..=16).contains(&barriers));
        for cut in 1..=barriers {
            for after in [false, true] {
                let f = Continued::new();
                let (next, pin) = if completing {
                    f.refresh()
                } else {
                    next_roster(&f.c, &f.original, 2, 280)
                };
                let (mut owner, remaining, _) = faulty(&f.c, after);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(
                        owner.reconcile_policy_renewal(f.c.policy.historical(), &f.p1, 205),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        owner.refresh_roster(
                            f.original.roster().checkpoint(),
                            next.as_bytes(),
                            &pin,
                            &f.p1,
                            205,
                        ),
                        after,
                    );
                }
                assert!(owner.active.is_none());
                faults += 1;
                let mut owner = open(&f.c);
                let observed = owner.status().expect("published config result");
                match observed {
                    EnrollmentStatus::Active(id) if id == f.journal => {
                        active_after_error += 1;
                        Ok(())
                    }
                    EnrollmentStatus::Refreshing {
                        journal,
                        previous,
                        next: target,
                    } if journal == f.journal
                        && previous == f.original.roster().checkpoint()
                        && target == next.checkpoint() =>
                    {
                        refreshing_after_error += 1;
                        Ok(())
                    }
                    _ => Err("fault lost the original enrollment or roster intent"),
                }
                .expect("exact original public state");
                let mut service = f.service();
                assert_eq!(
                    service
                        .stores()
                        .expect("stores")
                        .0
                        .roster_checkpoint(f.original.account_id())
                        .expect("actual journal head"),
                    if completing {
                        next.checkpoint()
                    } else {
                        f.original.roster().checkpoint()
                    }
                );
                service.close();
                if completing {
                    let image = owner.image().expect("retained target");
                    let recorded = match image.phase {
                        Phase::Accepted { admission, .. } => Ok(admission),
                        _ => Err("missing accepted phase"),
                    }
                    .expect("original target retained");
                    assert_eq!(recorded.checkpoint, next.checkpoint());
                    assert_eq!(recorded.roster, next.as_bytes());
                    f.p1.close();
                    f.c.policy.close();
                    f.c.policy.runtime.close();
                    owner
                        .recover_historical_policy_renewal(
                            f.approval.scope().operation,
                            f.approval.statement_digest(),
                            f.c.policy.historical(),
                        )
                        .expect("finish exact already-applied target without current runtime");
                } else {
                    owner
                        .refresh_roster(
                            f.original.roster().checkpoint(),
                            next.as_bytes(),
                            &pin,
                            &f.p1,
                            205,
                        )
                        .expect("same original target retry");
                    owner
                        .reconcile_policy_renewal(f.c.policy.historical(), &f.p1, 205)
                        .expect("finish original update");
                }
                assert_eq!(
                    owner.status().expect("completed roster state"),
                    EnrollmentStatus::Active(f.journal)
                );
                assert_eq!(
                    owner.credential_renewal_status().expect("G remains absent"),
                    CredentialRenewalStatus::Absent
                );
                let mut service = f.service();
                assert_eq!(
                    service
                        .stores()
                        .expect("stores")
                        .0
                        .roster_checkpoint(f.original.account_id())
                        .expect("same final target"),
                    next.checkpoint()
                );
            }
        }
    }
    assert_eq!(active_after_error + refreshing_after_error, faults);
    eprintln!("POLICY_ONLY_ROSTER_CONFIG_IO faults={faults} active_after_error={active_after_error} refreshing_after_error={refreshing_after_error} exact_journal_target=true historical_completion=true");
}
