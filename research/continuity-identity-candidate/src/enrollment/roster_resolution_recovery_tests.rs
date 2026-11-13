// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CaseKind {
    Expired,
    Committed,
    Revoked,
}

fn fixture(kind: CaseKind) -> (Case, VerifiedDevice, IssuedRoster, RosterRefreshResolution) {
    let (c, original, id) = local(220, 240);
    let previous = original.roster().checkpoint();
    let (target, pin) = head(&c, &original, 2, 180);
    begin(&c, &original, &target, &pin, &c.policy, 170);
    let (outcome, observed) = match kind {
        CaseKind::Expired => (RosterRefreshOutcome::ExpiredUncommitted, previous),
        CaseKind::Committed => {
            install(&c, &original, &target, &pin, 175);
            (RosterRefreshOutcome::Committed, target.checkpoint())
        }
        CaseKind::Revoked => {
            let revoked = c
                .root
                .issue_roster(3, Validity::new(100, 280).expect("interval"), &[])
                .expect("signed revocation");
            let pin = AccountPin::new(
                original.account_id(),
                c.intent.root.clone(),
                revoked.checkpoint(),
                c.policy.family(),
            )
            .expect("pin");
            install(&c, &original, &revoked, &pin, 175);
            (
                RosterRefreshOutcome::SupersededUnknown,
                revoked.checkpoint(),
            )
        }
    };
    let result = expected(id, previous, target.checkpoint(), outcome, observed, 185);
    (c, original, target, result)
}

#[test]
fn every_roster_resolution_config_sync_fault_preserves_original_pending_or_exact_outcome() {
    let (mut faults, mut pending_count, mut resolved_count) = (0, 0, 0);
    for kind in [CaseKind::Expired, CaseKind::Committed, CaseKind::Revoked] {
        let (c, _, _, expected) = fixture(kind);
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        owner
            .resolve_roster_refresh(
                expected.previous,
                expected.target,
                c.policy.historical(),
                185,
            )
            .expect("calibrate");
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        assert!((1..=16).contains(&barriers));
        for cut in 1..=barriers {
            for after in [false, true] {
                let (c, original, _, expected) = fixture(kind);
                let pending_row = row(&open(&c));
                let before = snapshot(&c, &original);
                c.policy.close();
                c.policy.runtime.close();
                let held = c.paths.signer.with_extension("roster-sync-held");
                fs::rename(&c.paths.signer, &held).expect("no signer");
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    owner.resolve_roster_refresh(
                        expected.previous,
                        expected.target,
                        c.policy.historical(),
                        185,
                    ),
                    after,
                );
                assert!(owner.active.is_none());
                let status = open(&c).status().expect("read unknown save result");
                if matches!(status, EnrollmentStatus::Refreshing { .. }) {
                    pending_count += 1;
                    assert_eq!(row(&open(&c)), pending_row);
                } else {
                    resolved_count += 1;
                    assert_eq!(
                        status,
                        if kind == CaseKind::Revoked {
                            EnrollmentStatus::RosterResolved(expected)
                        } else {
                            EnrollmentStatus::Active(expected.journal)
                        }
                    );
                }
                faults += 1;
                assert_eq!(
                    resolve(&c, expected.previous, expected.target, 185).expect("original retry"),
                    expected
                );
                assert_eq!(
                    resolve(&c, expected.previous, expected.target, 190)
                        .expect("idempotent result"),
                    expected
                );
                assert_eq!(snapshot(&c, &original), before);
                fs::rename(held, &c.paths.signer).expect("restore signer");
            }
        }
    }
    assert_eq!(faults, pending_count + resolved_count);
    eprintln!("ROSTER_RESOLUTION_IO faults={faults} pending={pending_count} resolved={resolved_count} three_outcomes=true journal_unchanged=true");
}

#[test]
fn roster_resolution_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_ROSTER_RESOLUTION_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 220, 150);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root")).expect("key"),
        DeviceDescription::new(
            [7; 16],
            1,
            p0.family(),
            Validity::new(100, 240).expect("interval"),
        )
        .expect("intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    let (previous, target) = match owner.status().expect("original pending") {
        EnrollmentStatus::Refreshing { previous, next, .. } => Ok((previous, next)),
        _ => Err("expected original refreshing"),
    }?;
    p0.close();
    p0.runtime.close();
    owner
        .resolve_roster_refresh(previous, target, p0.historical(), 185)
        .expect("original resolver");
    Err("expected boundary was not reached")
}

fn kill_at(c: &Case, cut: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    let mut child=ChildGuard(Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact","enrollment::tests::policy_renewal::roster_resolution::recovery::roster_resolution_process_child","--nocapture"])
        .env("QPERIAPT_ROSTER_RESOLUTION_ROOT",root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT",root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE",cut)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("child"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("renewal-ready").exists() {
        assert!(
            child.0.try_wait().expect("child state").is_none() && Instant::now() < deadline,
            "missing {cut}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("actual interruption");
    assert!(!child.0.wait().expect("reaped").success());
}

#[test]
fn actual_process_loss_retains_expired_committed_or_unknown_result_without_restoring_revoked_owner()
{
    for kind in [CaseKind::Expired, CaseKind::Committed, CaseKind::Revoked] {
        for cut in [
            "roster-resolution-before-save",
            "roster-resolution-after-save",
        ] {
            let (c, original, _, expected) = fixture(kind);
            let before = snapshot(&c, &original);
            let held = c.paths.signer.with_extension("roster-process-held");
            fs::rename(&c.paths.signer, &held).expect("no child signer");
            kill_at(&c, cut);
            c.policy.close();
            c.policy.runtime.close();
            let status = open(&c).status().expect("durable cut");
            if cut == "roster-resolution-before-save" {
                assert_eq!(
                    status,
                    EnrollmentStatus::Refreshing {
                        journal: expected.journal,
                        previous: expected.previous,
                        next: expected.target
                    }
                );
            } else {
                assert_eq!(
                    status,
                    if kind == CaseKind::Revoked {
                        EnrollmentStatus::RosterResolved(expected)
                    } else {
                        EnrollmentStatus::Active(expected.journal)
                    }
                );
            }
            assert_eq!(
                resolve(&c, expected.previous, expected.target, 185)
                    .expect("same original operation"),
                expected
            );
            assert_eq!(snapshot(&c, &original), before);
            fs::rename(held, &c.paths.signer).expect("restore signer");
            if kind == CaseKind::Revoked {
                assert!(open(&c).activate(&c.policy, 185, None).is_err());
            }
        }
    }
    eprintln!("ROSTER_RESOLUTION_PROCESS cuts=6 closed_runtime_no_signer=true honest_unknown=true journal_unchanged=true");
}

#[test]
fn authenticated_roster_resolution_codec_rejects_false_outcome_regression_and_malformed_wrappers() {
    let (c, _, _, expected) = fixture(CaseKind::Revoked);
    resolve(&c, expected.previous, expected.target, 185).expect("retained unknown outcome");
    let mut owner = open(&c);
    let saved = row(&owner);
    let image = owner.image().expect("original result");
    let mut suffix = Vec::new();
    image
        .roster_resolution
        .as_ref()
        .expect("result")
        .encode(&mut suffix)
        .expect("suffix");
    owner.close();
    let start = saved.len() - 32 - suffix.len();
    assert_eq!(saved.get(start..saved.len() - 32), Some(suffix.as_slice()));
    let mut malformed = Vec::new();
    for (offset, bytes) in [
        (start, vec![99; 32]),
        (start + 32, expected.target.version().to_be_bytes().to_vec()),
        (start + 152, 0u64.to_be_bytes().to_vec()),
        (start + 160, vec![1]),
        (start + 160, vec![2]),
        (start + 160, vec![3]),
        (start + 160, vec![255]),
        (8, b"QPENST14".to_vec()),
        (8, b"QPENST99".to_vec()),
        (80, vec![4]),
    ] {
        let mut bad = saved.clone();
        bad.get_mut(offset..offset + bytes.len())
            .expect("bounded mutation")
            .copy_from_slice(&bytes);
        malformed.push(bad);
    }
    let mut signature = saved.clone();
    *signature
        .get_mut(saved.len() - 33)
        .expect("observed roster signature") ^= 1;
    malformed.push(signature);
    let mut tail = saved.clone();
    tail.insert(tail.len() - 32, 0);
    malformed.push(tail);
    let mut short = saved.clone();
    short.remove(short.len() - 33);
    malformed.push(short);
    for bad in malformed {
        replace_authenticated(&c, &bad);
        assert!(DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err());
        replace_authenticated(&c, &saved);
        assert_eq!(row(&open(&c)), saved);
        assert_eq!(
            resolve(&c, expected.previous, expected.target, 190).expect("exact original unknown"),
            expected
        );
    }
    eprintln!("ROSTER_RESOLUTION_CODEC malformed=13 fresh_macs=true unknown_not_relabelled=true no_implicit_repair=true");
}
