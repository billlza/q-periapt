// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Roster advancement under independently selected P2 after actual P0 expiry.
use super::*;
use crate::{android_roster_traffic, android_roster_witness::progress};

pub(super) fn advance(case: &Case<'_>, identity: &[u8], closed: bool) -> Result<()> {
    let witness = case.witness.ok_or("required roster witness")?;
    let target_policy = fixture::protocol_policy(&case.inputs.join("policy-target"), case.sdk)?;
    let statement = fixture::array::<32>(case.inputs, "renewal-statement")?;
    assert!(fixture::now()? >= case.policy.validity().until());
    let previous = p::AccountPin::new(
        case.root.account_id()?,
        case.root.public_key()?,
        case.roster.checkpoint(),
        target_policy.family(),
    )?
    .verify_device(case.certificate, case.roster.as_bytes(), fixture::now()?)?;
    let issued = case.root.issue_roster(
        2,
        case.validity,
        &[case.root.roster_entry(case.certificate)?],
    )?;
    let current = p::AccountPin::new(
        case.root.account_id()?,
        case.root.public_key()?,
        issued.checkpoint(),
        target_policy.family(),
    )?
    .verify_device(case.certificate, issued.as_bytes(), fixture::now()?)?;
    let operation = p::RosterRefreshId::generate()?;
    for (name, bytes) in [
        ("renewal-roster", issued.as_bytes().to_vec()),
        (
            "renewal-version",
            issued.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", issued.checkpoint().digest().to_vec()),
        ("roster-operation", operation.as_bytes().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &bytes)?;
    }
    let run = |mode: &str, label: &str| {
        case.run(
            &format!("roster-witness-selected-{mode}"),
            &format!("roster-{label}"),
        )
    };
    for (mode, label, code) in [
        ("prepare-bad", "bad-roster", 102u32),
        ("prepare-cancelled", "cancelled", 302),
        ("prepare-unselected", "no-policy-fallback", 1),
        ("prepare-original-expired", "original-expired", 104),
    ] {
        assert_eq!(run(mode, label)?, code.to_be_bytes());
        assert_eq!(run("progress", &format!("{label}-absent"))?, vec![0; 624]);
    }
    let bytes = run("prepare", "proposal")?;
    assert_eq!(bytes.len(), 417);
    publish_private_bytes(&case.inputs.join("roster-proposal"), &bytes)?;
    assert_eq!(run("prepare", "proposal-replayed")?, bytes);
    assert_eq!(run("recover", "proposal-recovered")?, bytes);
    let proposal = p::AnchorRosterRefreshProposal::from_trusted_state(&bytes)?;
    assert_eq!(
        proposal.scope(),
        &p::RosterRefreshScope {
            operation,
            previous: case.roster.checkpoint(),
            target: issued.checkpoint(),
            policy: target_policy.checkpoint(),
            policy_authorization: Some(statement),
        }
    );
    assert_eq!(
        proposal.subject(),
        p::AnchorSubject::from_trusted_state(&fs::read(case.inputs.join("witness-subject"))?)?
    );
    assert_eq!(run("progress", "reserved")?, progress(&proposal, 2, false));
    assert_eq!(run("reconcile", "unavailable")?, 5u32.to_be_bytes());
    assert_eq!(
        run("abandon-refused", "no-local-abandon")?,
        211u32.to_be_bytes()
    );
    assert_eq!(
        run("substitute", "substitution-refused")?,
        211u32.to_be_bytes()
    );
    assert_eq!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "independent roster approval")?
            .prepare_roster_refresh(
                proposal,
                &previous,
                &current,
                &target_policy,
                fixture::now()?
            )?,
        p::AnchorRosterRefreshState::Prepared
    );
    assert_eq!(run("reconcile", "prepared-at-witness")?, 1u32.to_be_bytes());
    let before = case.captures()?.len();
    let kind = if closed { 18 } else { 16 };
    if let Some(tls) = case.tls {
        tls.arm(None)?;
    } else {
        witness.arm(20 + kind)?;
    }
    assert_eq!(
        run(
            if closed {
                "close-unknown"
            } else {
                "commit-unknown"
            },
            "unknown"
        )?,
        218u32.to_be_bytes()
    );
    let records = case.captures()?;
    let lost: Vec<_> = records
        .get(before..)
        .ok_or("roster lost exchange range")?
        .iter()
        .filter(|r| r.request.get(204) == Some(&kind))
        .collect();
    assert_eq!(lost.len(), 1);
    let lost = lost.first().ok_or("roster lost exchange")?;
    assert!(!lost.delivered);
    publish_private_bytes(
        &case.base.join("roster-lost-terminal-request"),
        &lost.request,
    )?;
    publish_private_bytes(&case.base.join("roster-lost-terminal-reply"), &lost.reply)?;
    let historical = records.len();
    let terminal = if closed { 3u32 } else { 2u32 };
    for (mode, label) in [
        ("history-unmanaged", "historical-unmanaged"),
        ("reconcile", "reconciled"),
        ("close", "close-exact"),
        ("commit", "commit-exact"),
    ] {
        assert_eq!(run(mode, label)?, terminal.to_be_bytes());
    }
    assert_eq!(
        run("progress", "retired")?,
        progress(&proposal, if closed { 4 } else { 3 }, true)
    );
    assert_eq!(
        run("resolve-local", "no-local-resolve")?,
        216u32.to_be_bytes()
    );
    assert_eq!(
        run("activate-unmanaged", "registry-required")?,
        211u32.to_be_bytes()
    );
    assert_eq!(
        case.run("policy-activate-renewed", "roster-renewed-identity")?,
        identity
    );
    let after = case.captures()?;
    let trace = after.get(historical..).ok_or("roster history range")?;
    assert!(
        !trace.is_empty()
            && trace
                .iter()
                .all(|r| r.delivered && !matches!(r.request.get(204), Some(16 | 18)))
    );
    crate::android_credential::write_exchanges(
        &case.base.join("roster-historical-transcript"),
        trace,
    )?;
    android_roster_traffic::admit_peer(
        &android_roster_traffic::Case {
            base: case.base,
            inputs: case.inputs,
            reference: case.reference,
            witness: Some(&witness.configured),
        },
        case.root,
        if closed { case.roster } else { &issued },
        true,
    )?;
    publish_private_bytes(&case.base.join("roster-terminal"), &terminal.to_be_bytes())?;
    target_policy.close();
    Ok(())
}
