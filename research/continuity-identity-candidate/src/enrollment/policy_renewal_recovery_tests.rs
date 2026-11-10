// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn committed(a: &VerifiedPolicyRenewal) -> PolicyRenewalStatus {
    PolicyRenewalStatus::Committed {
        operation: a.scope().operation,
        statement: a.statement_digest(),
        target: a.target_policy(),
    }
}
fn journal(c: &Case, original: &VerifiedDevice) -> DeviceService {
    DeviceInstallation::reconcile_original_enrollment(
        c.paths.installation.clone(),
        JournalKey::open(&c.paths.wrapping).expect("original key"),
        original,
        c.policy.historical(),
        None,
    )
    .expect("original installation metadata")
}
fn admission(
    owner: &mut DeviceEnrollment,
) -> (
    Vec<u8>,
    Vec<u8>,
    RosterCheckpoint,
    [u8; 32],
    JournalIdentity,
) {
    match owner.image().expect("authenticated enrollment").phase {
        Phase::Accepted { admission, .. } => Ok((
            admission.certificate,
            admission.roster,
            admission.checkpoint,
            admission.policy,
            admission.journal,
        )),
        _ => Err("expected active admission"),
    }
    .expect("admission")
}

#[test]
fn original_enrollment_commits_policy_only_and_preserves_cr_and_g_history() {
    for prior_g in [false, true] {
        let (c, original, id) = local(180, if prior_g { 160 } else { 200 });
        let g = if prior_g {
            Some(renewal::grant(&c, &original, &original, 2, 240))
        } else {
            None
        };
        if let Some(g) = &g {
            open(&c)
                .stage_credential_renewal(g, g.operation(), &c.policy, 170)
                .expect("G intent");
            open(&c)
                .activate(&c.policy, 170, None)
                .expect("real G commit")
                .close();
        }
        let current = g.as_ref().map_or(&original, |g| g.successor_device());
        let p1 = policy(&c, 2, 260, 190);
        let a = approved(
            &c,
            &original,
            current,
            &p1,
            &scope(&c, &original, current, id),
            190,
        );
        let mut owner = open(&c);
        let retained = admission(&mut owner);
        let original_g = owner.credential_renewal_status().expect("G status");
        let mut before_history = Vec::new();
        if let Some(g) = &owner.image().expect("image").renewal {
            g.encode(&mut before_history).expect("exact G history");
        }
        owner.close();
        let original_signer = fs::read(&c.paths.signer).expect("signer bytes");
        stage(&c, &a, &p1, 190);
        assert_eq!(
            open(&c)
                .reconcile_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("original journal/config/ACK"),
            committed(&a)
        );
        let mut owner = open(&c);
        assert_eq!(
            owner.policy_renewal_status().expect("completed state"),
            committed(&a)
        );
        assert_eq!(
            owner.credential_renewal_status().expect("same G state"),
            original_g
        );
        assert_eq!(admission(&mut owner), retained);
        let mut history = Vec::new();
        if let Some(g) = &owner.image().expect("image").renewal {
            g.encode(&mut history).expect("G history");
        }
        assert_eq!(history, before_history);
        assert_eq!(
            fs::read(&c.paths.signer).expect("same signing file"),
            original_signer
        );
        let config = row(&owner);
        assert_eq!(config.get(..8), Some(b"QPENST10".as_slice()));
        owner.close();
        let mut service = journal(&c, &original);
        let before = service.stores().expect("stores").0.test_snapshot();
        assert_eq!(before.id, *id.as_bytes());
        service.close();
        assert_eq!(
            open(&c)
                .reconcile_policy_renewal(c.policy.historical(), &p1, 190)
                .expect("exact idempotent retry"),
            committed(&a)
        );
        assert_eq!(row(&open(&c)), config);
        let mut service = journal(&c, &original);
        let after = service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            (before.revision, before.digest),
            (after.revision, after.digest)
        );
        service.close();
        assert!(
            matches!(
                open(&c).activate(&c.policy, 150, None),
                Err(DurableError::Suspended)
            ),
            "cached P0 cannot regain permission at an earlier time"
        );
    }
}

#[test]
fn historical_recovery_cannot_create_an_uncommitted_policy_target() {
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
    let saved = row(&open(&c));
    let mut service = journal(&c, &original);
    let before = service.stores().expect("stores").0.test_snapshot();
    service.close();
    assert!(matches!(
        open(&c).recover_historical_policy_renewal(
            a.scope().operation,
            a.statement_digest(),
            c.policy.historical()
        ),
        Err(DurableError::Suspended)
    ));
    assert!(matches!(
        open(&c).reconcile_policy_renewal(c.policy.historical(), &p1, 195),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_eq!(row(&open(&c)), saved);
    let mut service = journal(&c, &original);
    let after = service.stores().expect("stores").0.test_snapshot();
    assert_eq!(
        (before.revision, before.digest),
        (after.revision, after.digest)
    );
}

#[test]
fn second_policy_only_operation_retains_previous_completion_and_advances_same_cr() {
    for first_ack in [true, false] {
        let (c, original, id) = local(160, 200);
        let p1 = policy(&c, 2, 190, 170);
        let first = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, id),
            170,
        );
        stage(&c, &first, &p1, 170);
        if first_ack {
            open(&c)
                .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
                .expect("P1 complete");
        } else {
            kill_at(&c, "policy-only-completion");
        }
        let p2 = policy(&c, 3, 260, 175);
        let mut next = scope(&c, &original, &original, id);
        next.previous_policy = p1.checkpoint();
        next.previous_authorization = Some(first.statement_digest());
        let materials = PolicyRenewalMaterials {
            original: c.policy.historical(),
            previous: p1.historical(),
            target: &p2,
            original_device: &original,
            current_device: &original,
        };
        let statement =
            PolicyRenewalStatement::new(&next, &materials, 175).expect("exact adopted predecessor");
        let issuer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("same policy root");
        let a = c
            .root
            .approve_policy_renewal(&statement)
            .expect("account approval");
        let p = issuer
            .approve_policy_renewal(&statement)
            .expect("policy approval");
        let second =
            VerifiedPolicyRenewal::verify(&a, &p, &next, &materials, 175).expect("P2 approval");
        let mut service = journal(&c, &original);
        let before_revision = service.stores().expect("stores").0.test_snapshot().revision;
        service.close();
        let before = admission(&mut open(&c));
        stage(&c, &second, &p2, 175);
        let mut owner = open(&c);
        assert_eq!(
            owner.policy_renewal_status().expect("Pending P2"),
            pending(&second)
        );
        let retained = owner.image().expect("both original policy operations");
        let mut completed_bytes = Vec::new();
        retained
            .policy_completed
            .as_ref()
            .expect("P1 completion")
            .encode(&mut completed_bytes)
            .expect("retained P1 bytes");
        assert_eq!(
            completed_bytes.get(..32),
            Some(first.scope().operation.as_bytes().as_slice())
        );
        assert!(completed_bytes.ends_with(&first.historical().journal_bytes()));
        owner.close();
        assert_eq!(
            open(&c)
                .reconcile_policy_renewal(c.policy.historical(), &p2, 175)
                .expect("same C/R P2 commit"),
            committed(&second)
        );
        assert_eq!(admission(&mut open(&c)), before);
        let mut service = journal(&c, &original);
        assert_eq!(
            service.stores().expect("stores").0.test_snapshot().revision,
            before_revision + 2,
            "new commit and ACK only; known prior completion retires atomically"
        );
        service.close();
        assert!(matches!(
            open(&c).recover_historical_policy_renewal(
                first.scope().operation,
                first.statement_digest(),
                c.policy.historical()
            ),
            Err(DurableError::Conflict)
        ));
        assert_eq!(
            open(&c)
                .recover_historical_policy_renewal(
                    second.scope().operation,
                    second.statement_digest(),
                    c.policy.historical()
                )
                .expect("retained P2 historical recovery"),
            committed(&second)
        );
    }
    eprintln!("POLICY_ONLY_SUCCESSOR prior_acknowledged=true prior_unacknowledged=true exact_predecessor=true original_cr=true");
}

#[test]
fn policy_only_coordinator_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_COORDINATOR_CUT_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 160, 150);
    let p1 = policy(&template, 2, 190, 170);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root pin")).expect("root"),
        DeviceDescription::new([7; 16], 1, p0.family(), interval()).expect("original intent"),
    );
    DeviceEnrollment::open(paths(root), intent)
        .expect("original enrollment")
        .reconcile_policy_renewal(p0.historical(), &p1, 170)
        .expect("same original coordinator");
    Err("expected commit boundary did not stop the child")
}

pub(super) fn kill_at(c: &Case, cut: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    let mut child = ChildGuard(Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "enrollment::tests::policy_renewal::recovery::policy_only_coordinator_process_child", "--nocapture"])
        .env("QPERIAPT_POLICY_COORDINATOR_CUT_ROOT", root)
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
    child.0.kill().expect("real interruption");
    assert!(!child.0.wait().expect("reaped child").success());
}

#[test]
fn real_process_cuts_finish_exact_policy_only_commit_after_expiry_without_signer() {
    for cut in [
        "policy-only-journal",
        "policy-only-completion",
        "policy-only-acknowledgement",
    ] {
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
        let before = admission(&mut open(&c));
        kill_at(&c, cut);
        let mut owner = open(&c);
        assert_eq!(
            owner
                .policy_renewal_status()
                .expect("durable original phase"),
            if cut == "policy-only-journal" {
                pending(&a)
            } else {
                committed(&a)
            }
        );
        owner.close();
        assert!(p1.check_mode(PrekeyQuality::OneTimeBoth, 195).is_err());
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let held = c.paths.signer.with_extension("held");
        fs::rename(&c.paths.signer, &held).expect("signer unavailable");
        assert_eq!(
            open(&c)
                .recover_historical_policy_renewal(
                    a.scope().operation,
                    a.statement_digest(),
                    c.policy.historical()
                )
                .expect("historical original commit without runtime or signer"),
            committed(&a)
        );
        assert_eq!(admission(&mut open(&c)), before);
        let mut service = journal(&c, &original);
        assert_eq!(
            service
                .stores()
                .expect("stores")
                .0
                .identity()
                .expect("same journal"),
            id
        );
        service.close();
        fs::rename(held, &c.paths.signer).expect("restore original signer");
    }
    eprintln!("POLICY_ONLY_COORDINATOR_CUTS cuts=3 expired_target=true closed_runtime=true signer_unavailable=true exact_completion=true operational_owner_released=false");
}

#[test]
fn policy_only_enrollment_sync_failures_preserve_pending_or_committed_fact_after_revocation() {
    let (mut faults, mut pending_count, mut committed_count, mut completion_faults) = (0, 0, 0, 0);
    for completing in [false, true] {
        let (c, original, id) = local(160, 200);
        let p1 = policy(&c, 2, 230, 170);
        let a = approved(
            &c,
            &original,
            &original,
            &p1,
            &scope(&c, &original, &original, id),
            170,
        );
        if completing {
            stage(&c, &a, &p1, 170);
        }
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        if completing {
            owner
                .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
                .expect("calibrate completion");
        } else {
            owner
                .stage_policy_renewal(&a, a.scope().operation, c.policy.historical(), &p1, 170)
                .expect("calibrate Pending");
        }
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        assert!((1..=16).contains(&barriers));
        eprintln!("POLICY_ONLY_CONFIG_BARRIERS completing={completing} operation={barriers}");
        for cut in 1..=barriers {
            for after in [false, true] {
                let (c, original, id) = local(160, 200);
                let p1 = policy(&c, 2, 230, 170);
                let a = approved(
                    &c,
                    &original,
                    &original,
                    &p1,
                    &scope(&c, &original, &original, id),
                    170,
                );
                let retained = admission(&mut open(&c));
                if completing {
                    stage(&c, &a, &p1, 170);
                }
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                if completing {
                    assert_sync_failure(
                        owner.reconcile_policy_renewal(c.policy.historical(), &p1, 170),
                        after,
                    );
                } else {
                    assert_sync_failure(
                        owner.stage_policy_renewal(
                            &a,
                            a.scope().operation,
                            c.policy.historical(),
                            &p1,
                            170,
                        ),
                        after,
                    );
                }
                assert!(owner.active.is_none());
                faults += 1;
                let mut owner = open(&c);
                if completing {
                    let observed = owner
                        .policy_renewal_status()
                        .expect("unknown config result");
                    completion_faults += 1;
                    match observed {
                        PolicyRenewalStatus::Pending { .. } => {
                            assert_eq!(observed, pending(&a));
                            assert_eq!(
                                owner
                                    .pending_policy_renewal_approval(a.scope().operation)
                                    .expect("exact original Pending bytes"),
                                a.as_bytes()
                            );
                            pending_count += 1;
                            Ok(())
                        }
                        PolicyRenewalStatus::Committed { .. } => {
                            assert_eq!(observed, committed(&a));
                            let image = owner.image().expect("exact completion record");
                            let mut bytes = Vec::new();
                            image
                                .policy_completed
                                .as_ref()
                                .expect("committed record")
                                .encode(&mut bytes)
                                .expect("completion bytes");
                            assert!(bytes.ends_with(&a.historical().journal_bytes()));
                            committed_count += 1;
                            Ok(())
                        }
                        PolicyRenewalStatus::Absent
                        | PolicyRenewalStatus::AbandonedUncommitted { .. } => {
                            Err("journal committed but original enrollment intent disappeared")
                        }
                    }
                    .expect("every unknown config result retains the exact operation");
                    let mut service = journal(&c, &original);
                    let revoked = c
                        .root
                        .issue_roster(2, interval(), &[])
                        .expect("signed current revocation");
                    let pin = AccountPin::new(
                        original.account_id(),
                        c.intent.root.clone(),
                        revoked.checkpoint(),
                        c.policy.family(),
                    )
                    .expect("independent new head");
                    service
                        .stores()
                        .expect("stores")
                        .0
                        .install_roster(
                            &pin.verify_roster(revoked.as_bytes(), 175)
                                .expect("current revocation"),
                            175,
                        )
                        .expect("persist revocation");
                    service.close();
                    p1.close();
                    c.policy.close();
                    c.policy.runtime.close();
                    assert_eq!(
                        owner
                            .recover_historical_policy_renewal(
                                a.scope().operation,
                                a.statement_digest(),
                                c.policy.historical()
                            )
                            .expect("finish exact fact after revocation"),
                        committed(&a)
                    );
                    let mut service = journal(&c, &original);
                    assert_eq!(
                        service
                            .stores()
                            .expect("stores")
                            .0
                            .roster_checkpoint(original.account_id())
                            .expect("retained new head"),
                        revoked.checkpoint()
                    );
                    service.close();
                } else {
                    owner
                        .stage_policy_renewal(
                            &a,
                            a.scope().operation,
                            c.policy.historical(),
                            &p1,
                            170,
                        )
                        .expect("retry original Pending");
                    assert_eq!(
                        owner
                            .reconcile_policy_renewal(c.policy.historical(), &p1, 170)
                            .expect("same operation completed"),
                        committed(&a)
                    );
                }
                assert_eq!(admission(&mut owner), retained);
                assert_eq!(
                    owner.credential_renewal_status().expect("G stays absent"),
                    CredentialRenewalStatus::Absent
                );
            }
        }
    }
    eprintln!("POLICY_ONLY_ENROLLMENT_IO faults={faults} pending_after_error={pending_count} committed_after_error={committed_count} revocation_preserved=true");
    // The storage contract does not prescribe how many injected sync errors
    // recover each legal result. Assert every exact result, not an outcome
    // distribution inferred from another record layout. The real process-cut
    // test above separately forces and checks both sides of config publication.
    assert!(completion_faults > 0);
    assert_eq!(pending_count + committed_count, completion_faults);
}
