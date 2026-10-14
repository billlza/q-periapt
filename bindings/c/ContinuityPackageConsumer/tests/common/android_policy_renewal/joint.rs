// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Joint G/T is distinct from independent P followed by G. No native journal edits.
use super::*;
use std::time::{Duration, Instant};

#[path = "joint_issuer.rs"]
mod issuer;
#[path = "joint_witness.rs"]
mod witness;

fn wait_expiry(until: u64) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
    while fixture::now()? < until {
        if Instant::now() >= deadline {
            return Err("joint policy real expiry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(fixture::now()?)
}

struct Prepared {
    issued: issuer::Issued,
    pending: Vec<u8>,
    applied: Vec<u8>,
    original_until: u64,
    original_at: u64,
}
fn prepare(case: &Case<'_>, identity: &[u8]) -> Result<Prepared> {
    let original_until = case.policy.validity().until();
    let original_at = wait_expiry(original_until)?;
    assert_eq!(
        case.run("policy-activate-expired", "expired-activation")?,
        104u32.to_be_bytes()
    );
    let issued = issuer::issue(case, identity)?;
    let mut pending = 1u32.to_be_bytes().to_vec();
    pending.extend_from_slice(issued.operation.as_bytes());
    pending.extend_from_slice(&issued.statement);
    pending.extend_from_slice(&[0; 48]);
    let mut applied = 2u32.to_be_bytes().to_vec();
    applied.extend_from_slice(issued.operation.as_bytes());
    applied.extend_from_slice(&issued.statement);
    applied.extend_from_slice(&issued.roster.version().to_be_bytes());
    applied.extend_from_slice(&issued.roster.digest());
    applied.extend_from_slice(&[0; 8]);
    assert_eq!(case.run("policy-joint-status", "joint-absent")?, [0; 116]);
    for (mode, label, code) in [
        ("policy-joint-stage-refused", "joint-bad-approval", 102u32),
        (
            "policy-joint-stage-predecessor",
            "joint-bad-predecessor",
            105,
        ),
        ("policy-joint-unselected", "joint-unselected", 1),
    ] {
        assert_eq!(case.run(mode, label)?, code.to_be_bytes());
        assert_eq!(
            case.run("policy-joint-status", &format!("{label}-status"))?,
            [0; 116]
        );
    }
    for label in ["joint-staged", "joint-stage-replayed"] {
        assert_eq!(case.run("policy-joint-stage", label)?, pending);
    }
    assert_eq!(
        case.run("policy-joint-status", "joint-pending-reopened")?,
        pending
    );
    Ok(Prepared {
        issued,
        pending,
        applied,
        original_until,
        original_at,
    })
}

pub(super) fn exercise(
    case: &Case<'_>,
    identity: &[u8],
    traffic: &traffic::Traffic,
    committed: bool,
) -> Result<()> {
    if case.witness.is_some() {
        return witness::exercise(case, identity, traffic, committed);
    }
    let Prepared {
        issued,
        pending,
        applied,
        original_until,
        original_at,
    } = prepare(case, identity)?;
    if committed {
        assert_eq!(
            case.run("policy-joint-reconcile", "joint-committed")?,
            applied
        );
        assert_eq!(
            case.run("policy-joint-status", "joint-committed-reopened")?,
            applied
        );
        for label in ["joint-activated", "joint-activated-reopened"] {
            assert_eq!(case.run("policy-joint-activate", label)?, identity);
        }
        credential::admit_peer(case)?;
        traffic.resume_with(case, "policy-joint-peer-retry")?;
    }
    let target_at = wait_expiry(issued.until)?;
    let mut times = original_until.to_be_bytes().to_vec();
    times.extend_from_slice(&original_at.to_be_bytes());
    times.extend_from_slice(&issued.until.to_be_bytes());
    times.extend_from_slice(&target_at.to_be_bytes());
    publish_private_bytes(&case.base.join("joint-expiry-observation"), &times)?;
    assert_eq!(
        case.run("policy-joint-current-expired", "joint-expired-current")?,
        104u32.to_be_bytes()
    );
    let expected = if committed { &applied } else { &pending };
    for index in 0..2 {
        if committed {
            assert_eq!(
                case.run("policy-joint-history", &format!("joint-history-{index}"))?,
                applied
            );
        } else {
            assert_eq!(
                case.run(
                    "policy-joint-history-pending",
                    &format!("joint-history-{index}")
                )?,
                215u32.to_be_bytes()
            );
        }
        assert_eq!(
            case.run(
                "policy-joint-status",
                &format!("joint-history-status-{index}")
            )?,
            *expected
        );
    }
    if committed {
        next_request(case, identity, &issued, true)?;
    }
    Ok(())
}

fn next_request(
    case: &Case<'_>,
    identity: &[u8],
    issued: &issuer::Issued,
    adopted: bool,
) -> Result<()> {
    // A new issuer request is available only after terminal coordination.
    assert_eq!(
        case.run("policy-joint-request-reused", "joint-request-reused")?,
        211u32.to_be_bytes()
    );
    let next = p::CredentialRenewalId::generate()?;
    assert_ne!(next, issued.operation);
    publish_private_bytes(
        &case.inputs.join("credential-next-operation"),
        next.as_bytes(),
    )?;
    case.run("policy-joint-next-request", "joint-final-request")?;
    let parsed = crate::credential_request::read_credential_request(
        &case.base.join("joint-final-request"),
        true,
    )?;
    assert_eq!(parsed.operation, next);
    assert_eq!(
        parsed.journal.as_bytes(),
        identity.get(32..).ok_or("journal")?
    );
    assert_eq!(parsed.original_c, case.certificate);
    assert_eq!(parsed.original_r, case.roster.as_bytes());
    assert_eq!(parsed.original_policy, case.policy.checkpoint().digest());
    if adopted {
        assert_eq!(parsed.authorization, Some(issued.statement));
        assert_eq!(parsed.previous, issued.roster);
        assert_eq!(
            parsed.previous_c,
            fs::read(case.inputs.join("renewed-certificate"))?
        );
        assert_eq!(
            parsed.previous_r,
            fs::read(case.inputs.join("renewed-roster"))?
        );
    } else {
        assert_eq!(parsed.authorization, None);
        assert_eq!(parsed.previous, case.roster.checkpoint());
        assert_eq!(parsed.previous_c, case.certificate);
        assert_eq!(parsed.previous_r, case.roster.as_bytes());
        assert_eq!(parsed.current_policy, case.policy.checkpoint());
    }
    Ok(())
}

fn route(profile: &str, committed: bool) -> Result<()> {
    run_route(profile, "local", committed)
}
fn run_route(profile: &str, carrier: &str, committed: bool) -> Result<()> {
    let parent = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("joint policy cases")?);
    let output = if carrier == "local" {
        parent
    } else {
        parent.join(format!(
            "{carrier}-{profile}-{}",
            if committed { "applied" } else { "closed" }
        ))
    };
    let driver =
        PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("joint policy driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    super::exercise(
        &output,
        &driver,
        profile,
        carrier,
        Some(Maintenance::Joint { committed }),
    )
}
#[test]
fn fixed_applied() -> Result<()> {
    route("fixed", true)
}
#[test]
fn fixed_pending() -> Result<()> {
    route("fixed", false)
}
#[test]
fn recoverable_applied() -> Result<()> {
    route("recoverable", true)
}
#[test]
fn recoverable_pending() -> Result<()> {
    route("recoverable", false)
}
