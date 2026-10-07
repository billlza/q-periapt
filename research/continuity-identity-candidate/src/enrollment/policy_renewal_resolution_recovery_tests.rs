// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn resolution_codec_rejects_authenticated_malformed_terminal_and_wrapper_without_repair() {
    let (c, original, p1, a) = expiring();
    let expected = abandoned(
        &a,
        PolicyRenewalAbandonment::Expired,
        original.roster().checkpoint(),
        195,
    );
    assert_eq!(resolve(&c, &a, &p1, 195).expect("terminal"), expected);
    let mut owner = open(&c);
    let saved = row(&owner);
    let image = owner.image().expect("exact terminal image");
    let mut suffix = Vec::new();
    image
        .policy_resolution
        .as_ref()
        .expect("resolution")
        .encode(&mut suffix)
        .expect("suffix");
    owner.close();
    let offset = saved.len() - 32 - suffix.len();
    assert_eq!(saved.get(offset..saved.len() - 32), Some(suffix.as_slice()));
    let mut malformed = Vec::new();
    for (start, bytes) in [
        (offset, 0u64.to_be_bytes().to_vec()),
        (offset + 8, vec![2]),
        (saved.len() - 32 - 57, vec![9]),
        (saved.len() - 32 - 57, vec![2]),
        (saved.len() - 32 - 16, 0u64.to_be_bytes().to_vec()),
        (saved.len() - 32 - 16, 196u64.to_be_bytes().to_vec()),
        (saved.len() - 32 - 8, 194u64.to_be_bytes().to_vec()),
        (8, b"QPENST13".to_vec()),
        (8, b"QPENST99".to_vec()),
    ] {
        let mut bad = saved.clone();
        bad.get_mut(start..start + bytes.len())
            .expect("bounded mutation")
            .copy_from_slice(&bytes);
        malformed.push(bad);
    }
    let mut tail = saved.clone();
    tail.insert(tail.len() - 32, 0);
    malformed.push(tail);
    let mut short = saved.clone();
    short.remove(short.len() - 33);
    malformed.push(short);
    let mut signature = saved.clone();
    *signature
        .get_mut(saved.len() - 32 - 58)
        .expect("last retained approval byte") ^= 1;
    malformed.push(signature);
    for bad in malformed {
        replace_authenticated(&c, &bad);
        assert!(DeviceEnrollment::open(c.paths.clone(), c.intent.clone()).is_err());
        replace_authenticated(&c, &saved);
        assert_eq!(row(&open(&c)), saved, "no implicit repair");
        assert_eq!(
            resolve(&c, &a, &p1, 210).expect("original terminal unchanged"),
            expected
        );
    }
    eprintln!("POLICY_RESOLUTION_CODEC malformed=12 fresh_macs=true original_bytes_preserved=true");
}

#[test]
fn every_resolution_configuration_sync_failure_retains_exact_pending_or_original_outcome() {
    let (mut faults, mut pending_count, mut saved_count) = (0, 0, 0);
    for committed_before in [false, true] {
        let (c, _, p1, a) = expiring();
        if committed_before {
            super::super::recovery::kill_at(&c, "policy-only-journal");
        }
        let (mut owner, _, count) = faulty(&c, false);
        count.store(0, Ordering::SeqCst);
        owner
            .resolve_policy_renewal(
                a.scope().operation,
                a.statement_digest(),
                c.policy.historical(),
                p1.historical(),
                195,
            )
            .expect("calibrate exact config save");
        let barriers = count.load(Ordering::SeqCst);
        owner.close();
        assert!((1..=16).contains(&barriers));
        for cut in 1..=barriers {
            for after in [false, true] {
                let (c, original, p1, a) = expiring();
                if committed_before {
                    super::super::recovery::kill_at(&c, "policy-only-journal");
                }
                let before = snapshot(&c, &original);
                let expected = if committed_before {
                    committed(&a)
                } else {
                    abandoned(
                        &a,
                        PolicyRenewalAbandonment::Expired,
                        original.roster().checkpoint(),
                        195,
                    )
                };
                p1.close();
                c.policy.close();
                c.policy.runtime.close();
                let held = c.paths.signer.with_extension("resolution-sync-held");
                fs::rename(&c.paths.signer, &held).expect("unavailable signer");
                let (mut owner, remaining, _) = faulty(&c, after);
                remaining.store(cut, Ordering::SeqCst);
                assert_sync_failure(
                    owner.resolve_policy_renewal(
                        a.scope().operation,
                        a.statement_digest(),
                        c.policy.historical(),
                        p1.historical(),
                        195,
                    ),
                    after,
                );
                assert!(owner.active.is_none());
                let status = open(&c)
                    .policy_renewal_status()
                    .expect("unknown save outcome");
                assert!(
                    status == pending(&a) || status == expected,
                    "original Pending or exact outcome"
                );
                if status == pending(&a) {
                    pending_count += 1;
                } else {
                    saved_count += 1;
                }
                faults += 1;
                assert_eq!(
                    resolve(&c, &a, &p1, 195).expect("original operation retry"),
                    expected
                );
                let settled = snapshot(&c, &original);
                if committed_before {
                    assert_eq!(settled.0, before.0 + 1, "exact ACK completes");
                } else {
                    assert_eq!(settled, before, "abandonment does not change journal");
                }
                assert_eq!(
                    resolve(&c, &a, &p1, 210).expect("idempotent retry"),
                    expected
                );
                assert_eq!(snapshot(&c, &original), settled);
                fs::rename(held, &c.paths.signer).expect("restore signer");
            }
        }
    }
    assert_eq!(pending_count + saved_count, faults);
    eprintln!("POLICY_RESOLUTION_IO faults={faults} pending={pending_count} saved={saved_count} exact_original=true both_commit_branches=true");
}

#[test]
fn policy_resolution_process_child() -> Result<(), &'static str> {
    let Some(root) = std::env::var_os("QPERIAPT_POLICY_RESOLUTION_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let template = case();
    let p0 = policy(&template, 1, 160, 150);
    let p1 = policy(&template, 2, 190, 170);
    let intent = EnrollmentIntent::new(
        PublicKey::decode(&fs::read(root.join("trusted-root")).expect("root pin")).expect("root"),
        DeviceDescription::new(
            [7; 16],
            1,
            p0.family(),
            Validity::new(100, 200).expect("interval"),
        )
        .expect("original intent"),
    );
    let mut owner = DeviceEnrollment::open(paths(root), intent).expect("original enrollment");
    let (operation, statement) = match owner.policy_renewal_status().expect("original status") {
        PolicyRenewalStatus::Pending {
            operation,
            statement,
            ..
        } => Ok((operation, statement)),
        _ => Err("child requires original Pending"),
    }?;
    p0.close();
    p1.close();
    p0.runtime.close();
    owner
        .resolve_policy_renewal(operation, statement, p0.historical(), p1.historical(), 195)
        .expect("same original resolver");
    Err("expected process boundary was not reached")
}

fn kill_resolution_at(c: &Case, cut: &str) {
    use crate::durable::tests::ChildGuard;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = c.paths.configuration.parent().expect("root");
    fs::write(root.join("trusted-root"), c.intent.root.encode()).expect("independent root");
    if root.join("renewal-ready").exists() {
        fs::remove_file(root.join("renewal-ready")).expect("retire previous owned marker");
    }
    let mut child = ChildGuard(Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "enrollment::tests::policy_renewal::resolution::recovery::policy_resolution_process_child", "--nocapture"])
        .env("QPERIAPT_POLICY_RESOLUTION_ROOT", root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_ROOT", root)
        .env("QPERIAPT_LOCAL_RENEWAL_CUT_STAGE", cut)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("child"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("renewal-ready").exists() {
        assert!(
            child.0.try_wait().expect("child state").is_none() && Instant::now() < deadline,
            "missing {cut} boundary"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().expect("actual interruption");
    assert!(!child.0.wait().expect("reaped").success());
}

#[test]
fn real_resolution_process_cuts_preserve_proven_no_commit_or_actual_commit_and_finish_ack() {
    for cut in [
        "policy-resolution-before-save",
        "policy-resolution-after-save",
        "policy-resolution-completion",
    ] {
        let (c, original, p1, a) = expiring();
        let committed_before = cut == "policy-resolution-completion";
        if committed_before {
            super::super::recovery::kill_at(&c, "policy-only-journal");
        }
        let before = snapshot(&c, &original);
        let held = c.paths.signer.with_extension("resolution-process-held");
        fs::rename(&c.paths.signer, &held).expect("signer unavailable during child");
        kill_resolution_at(&c, cut);
        p1.close();
        c.policy.close();
        c.policy.runtime.close();
        let expected = if committed_before {
            committed(&a)
        } else {
            abandoned(
                &a,
                PolicyRenewalAbandonment::Expired,
                original.roster().checkpoint(),
                195,
            )
        };
        let persisted = open(&c).policy_renewal_status().expect("durable cut");
        assert_eq!(
            persisted,
            if cut == "policy-resolution-before-save" {
                pending(&a)
            } else {
                expected
            }
        );
        assert_eq!(
            resolve(&c, &a, &p1, 195).expect("exact original recovery"),
            expected
        );
        let settled = snapshot(&c, &original);
        if committed_before {
            assert_eq!(settled.0, before.0 + 1, "exact ACK finished");
        } else {
            assert_eq!(settled, before, "no journal mutation");
        }
        assert_eq!(resolve(&c, &a, &p1, 210).expect("original retry"), expected);
        assert_eq!(snapshot(&c, &original), settled);
        fs::rename(held, &c.paths.signer).expect("restore signer");
    }
    eprintln!("POLICY_RESOLUTION_PROCESS cuts=3 closed_runtime_no_signer=true exact_original=true");
}
