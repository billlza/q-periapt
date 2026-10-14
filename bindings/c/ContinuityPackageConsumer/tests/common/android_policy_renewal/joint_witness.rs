// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual signed/TLS witness outcomes, including lost Commit reply and closure.
use super::*;
#[path = "joint_witness_authority.rs"]
mod authority;

fn observed(case: &Case<'_>, mode: &str, label: &str, expected: &[u8]) -> Result<()> {
    assert_eq!(case.run(mode, label)?, expected);
    Ok(())
}
pub(super) fn history(
    case: &Case<'_>,
    start: usize,
    name: &str,
    cached_terminal: bool,
) -> Result<()> {
    let captures = case.captures()?;
    let trace = captures
        .get(start..)
        .ok_or("joint witness history offset")?;
    crate::android_credential::write_exchanges(&case.output(name), trace)?;
    assert!(
        (cached_terminal || !trace.is_empty())
            && trace
                .iter()
                .all(|r| r.delivered && !matches!(r.request.get(204), Some(5 | 7)))
    );
    Ok(())
}
pub(super) fn applied(
    case: &Case<'_>,
    prepared: &Prepared,
    identity: &[u8],
    traffic: &traffic::Traffic,
    previous: &p::HistoricalSessionPolicy,
    retry: bool,
) -> Result<()> {
    let proposal = case.run("policy-joint-witness-prepare", "joint-proposal")?;
    assert_eq!(proposal.len(), 329);
    assert_eq!(proposal.get(..8), Some(b"QPCRNP02".as_slice()));
    observed(
        case,
        "policy-joint-witness-prepare",
        "joint-proposal-replayed",
        &proposal,
    )?;
    observed(
        case,
        "policy-joint-witness-recover",
        "joint-proposal-recovered",
        &proposal,
    )?;
    authority::approve(case, &prepared.issued, &proposal, previous)?;
    let before = case.captures()?.len();
    authority::commit_reply_loss(case)?;
    observed(
        case,
        "policy-joint-witness-commit-unknown",
        "joint-commit-unknown",
        &218u32.to_be_bytes(),
    )?;
    let captures = case.captures()?;
    let commits: Vec<_> = captures
        .get(before..)
        .ok_or("joint commit offset")?
        .iter()
        .filter(|r| r.request.get(204) == Some(&5))
        .collect();
    assert_eq!(commits.len(), 1);
    let commit = commits.first().ok_or("joint Commit missing")?;
    assert!(!commit.delivered);
    assert_eq!(commit.reply.get(204), Some(&8));
    publish_private_bytes(&case.output("joint-lost-commit-request"), &commit.request)?;
    publish_private_bytes(&case.output("joint-lost-commit-reply"), &commit.reply)?;
    observed(
        case,
        "policy-joint-status",
        "joint-unknown-pending",
        &prepared.pending,
    )?;
    let start = case.captures()?.len();
    // The caller still has Pending. Close must discover Applied, not turn it into Closed.
    observed(
        case,
        "policy-joint-witness-close",
        "joint-close-loses-to-applied",
        &prepared.applied,
    )?;
    let captures = case.captures()?;
    let closing = captures.get(start..).ok_or("explicit Close offset")?;
    crate::android_credential::write_exchanges(
        &case.output("joint-explicit-close-transcript"),
        closing,
    )?;
    assert_eq!(
        closing
            .iter()
            .filter(|r| r.request.get(204) == Some(&7))
            .count(),
        1
    );
    assert!(closing
        .iter()
        .all(|r| r.delivered && r.request.get(204) != Some(&5)));
    // Terminal metadata is now durable. Later observations may be entirely local.
    let start = captures.len();
    observed(
        case,
        "policy-joint-witness-reconcile",
        "joint-applied-recovered",
        &prepared.applied,
    )?;
    observed(
        case,
        "policy-joint-witness-commit-replay",
        "joint-commit-replayed",
        &prepared.applied,
    )?;
    history(case, start, "joint-commit-recovery-transcript", true)?;
    for label in ["joint-activated", "joint-activated-reopened"] {
        observed(case, "policy-joint-activate", label, identity)?;
    }
    credential::admit_peer(case)?;
    if retry {
        traffic.resume_with(case, "policy-joint-peer-retry")?;
    }
    Ok(())
}
fn cancellation(case: &Case<'_>, prepared: &Prepared) -> Result<Vec<u8>> {
    let before = case.captures()?.len();
    let bytes = case.run("policy-joint-witness-cancel-prepare", "joint-cancellation")?;
    assert_eq!(bytes.len(), 281);
    assert_eq!(bytes.get(..8), Some(b"QPCRNC02".as_slice()));
    observed(
        case,
        "policy-joint-witness-cancel-prepare",
        "joint-cancellation-replayed",
        &bytes,
    )?;
    // Reservation is local; configuration/registry reads can query the witness,
    // but reservation must never dispatch a Commit or Close.
    let captures = case.captures()?;
    assert!(captures
        .get(before..)
        .ok_or("cancellation offset")?
        .iter()
        .all(|r| !matches!(r.request.get(204), Some(5 | 7))));
    observed(
        case,
        "policy-joint-witness-reserved-commit-refused",
        "joint-reserved-commit-refused",
        &215u32.to_be_bytes(),
    )?;
    observed(
        case,
        "policy-joint-witness-reserved-activate-refused",
        "joint-reserved-activate-refused",
        &215u32.to_be_bytes(),
    )?;
    observed(
        case,
        "policy-joint-status",
        "joint-reserved-pending",
        &prepared.pending,
    )?;
    Ok(bytes)
}

pub(super) fn exercise(
    case: &Case<'_>,
    identity: &[u8],
    traffic: &traffic::Traffic,
    committed: bool,
    retry: bool,
) -> Result<issuer::Issued> {
    let prepared = prepare(case, identity)?;
    for (mode, label) in [
        (
            "policy-joint-witness-local-refused",
            "joint-local-reconcile-refused",
        ),
        (
            "policy-joint-witness-history-local-refused",
            "joint-local-history-refused",
        ),
    ] {
        observed(case, mode, label, &216u32.to_be_bytes())?;
        observed(
            case,
            "policy-joint-status",
            &format!("{label}-status"),
            &prepared.pending,
        )?;
    }
    let cancellation = if committed {
        let previous = crate::receiver_policy::historical(case.inputs)?;
        applied(case, &prepared, identity, traffic, &previous, retry)?;
        None
    } else {
        Some(cancellation(case, &prepared)?)
    };
    let at = wait_expiry(prepared.issued.until)?;
    let mut times = prepared.original_until.to_be_bytes().to_vec();
    times.extend_from_slice(&prepared.original_at.to_be_bytes());
    times.extend_from_slice(&prepared.issued.until.to_be_bytes());
    times.extend_from_slice(&at.to_be_bytes());
    publish_private_bytes(&case.base.join("joint-expiry-observation"), &times)?;
    observed(
        case,
        "policy-joint-current-expired",
        "joint-expired-current",
        &104u32.to_be_bytes(),
    )?;
    let mut terminal = prepared.applied.clone();
    if let Some(bytes) = cancellation {
        authority::close(case, &prepared, &bytes)?;
        terminal
            .get_mut(..4)
            .ok_or("status tag")?
            .copy_from_slice(&4u32.to_be_bytes());
    }
    let start = case.captures()?.len();
    observed(
        case,
        "policy-joint-witness-close",
        "joint-expired-close",
        &terminal,
    )?;
    for index in 0..2 {
        observed(
            case,
            "policy-joint-witness-reconcile",
            &format!("joint-history-{index}"),
            &terminal,
        )?;
        observed(
            case,
            "policy-joint-status",
            &format!("joint-history-status-{index}"),
            &terminal,
        )?;
    }
    if committed {
        observed(
            case,
            "policy-joint-witness-commit-replay",
            "joint-expired-commit-replayed",
            &terminal,
        )?;
    }
    history(case, start, "joint-expired-history-transcript", committed)?;
    next_request(case, identity, &prepared.issued, committed)?;
    Ok(prepared.issued)
}

#[test]
fn signed_fixed_applied() -> Result<()> {
    run_route("fixed", "signed", true)
}
#[test]
fn signed_fixed_closed() -> Result<()> {
    run_route("fixed", "signed", false)
}
#[test]
fn tls_fixed_applied() -> Result<()> {
    run_route("fixed", "tls", true)
}
#[test]
fn tls_fixed_closed() -> Result<()> {
    run_route("fixed", "tls", false)
}
#[test]
fn signed_recoverable_applied() -> Result<()> {
    run_route("recoverable", "signed", true)
}
#[test]
fn signed_recoverable_closed() -> Result<()> {
    run_route("recoverable", "signed", false)
}
#[test]
fn tls_recoverable_applied() -> Result<()> {
    run_route("recoverable", "tls", true)
}
#[test]
fn tls_recoverable_closed() -> Result<()> {
    run_route("recoverable", "tls", false)
}
