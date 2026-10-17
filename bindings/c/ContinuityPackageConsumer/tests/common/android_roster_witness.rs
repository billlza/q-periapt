// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Required-witness R under P0: exact original terminal recovery over signed TCP and TLS.
use crate::android_roster_traffic as traffic;
use crate::{
    android_witness::witness, fixture, independent_inputs, issue_grant, p, run_foreign,
    witness_tls_faults, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    cell::Cell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
};
fn captures(
    w: &witness::Witness,
    tls: Option<&witness_tls_faults::FaultWitness>,
) -> Result<Vec<witness::Capture>> {
    if let Some(tls) = tls {
        Ok(tls
            .captured
            .lock()
            .map_err(|_| "TLS capture")?
            .iter()
            .map(|r| witness::Capture {
                request: r.record.request().to_vec(),
                reply: r.record.reply().to_vec(),
                delivered: r.delivered,
            })
            .collect())
    } else {
        Ok(w.captured
            .lock()
            .map_err(|_| "signed capture")?
            .iter()
            .map(|r| witness::Capture {
                request: r.request.clone(),
                reply: r.reply.clone(),
                delivered: r.delivered,
            })
            .collect())
    }
}
pub(crate) fn progress(p: &p::AnchorRosterRefreshProposal, phase: u32, retired: bool) -> Vec<u8> {
    let scope = p.scope();
    let mut out = phase.to_be_bytes().to_vec();
    out.extend_from_slice(&u32::from(retired).to_be_bytes());
    out.extend_from_slice(scope.operation.as_bytes());
    for checkpoint in [scope.previous, scope.target] {
        out.extend_from_slice(&checkpoint.version().to_be_bytes());
        out.extend_from_slice(&checkpoint.digest());
    }
    out.extend_from_slice(&scope.policy.version().to_be_bytes());
    out.extend_from_slice(&scope.policy.digest());
    out.extend_from_slice(&scope.policy_authorization.unwrap_or([0; 32]));
    out.extend_from_slice(&u32::from(scope.policy_authorization.is_some()).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&p.to_bytes());
    out.extend_from_slice(&[0; 7]);
    out
}
#[test]
fn original_terminal_recovery() -> Result<()> {
    let out = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("roster witness cases")?);
    let driver =
        PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("roster witness driver")?);
    fs::DirBuilder::new().mode(0o700).create(&out)?;
    for profile in ["fixed", "recoverable"] {
        for carrier in ["signed", "tls"] {
            for closed in [false, true] {
                route(&out, &driver, profile, carrier, closed)?;
            }
        }
    }
    Ok(())
}
fn route(out: &Path, driver: &Path, profile: &str, carrier: &str, closed: bool) -> Result<()> {
    let label = format!(
        "{carrier}-{profile}-{}",
        if closed { "closed" } else { "applied" }
    );
    let base = out.join(&label);
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut w = witness::Witness::start()?;
    let reference = fixture::setup_expiring_policy(Some(&w.configured), 1800)?;
    let (root, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&inputs, &sdk)?;
    let pin = w
        .configured
        .store
        .lock()
        .map_err(|_| "witness pin")?
        .pin()?;
    for (name, bytes) in [
        ("witness-carrier", b"signed".to_vec()),
        ("witness-id", pin.identity().as_bytes().to_vec()),
        ("witness-public", pin.public_key().encode().to_vec()),
        (
            "witness-address",
            w.configured.address.to_string().into_bytes(),
        ),
        (
            "authority-id",
            p::AccountAuthorityIdentity::generate()?.as_bytes().to_vec(),
        ),
        ("authority-application", vec![141; 32]),
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    let calls = Cell::new(0u64);
    let run = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let result = run_foreign(driver, profile, &inputs, &base, mode, name)?;
        calls.set(calls.get().checked_add(1).ok_or("call census")?);
        Ok(result)
    };
    let request = run("policy-create", "original.request")?;
    let (certificate, original) = issue_grant(&inputs, &root, &intent, validity, &request)?;
    let registry = run("authority-create", "authority-created")?;
    publish_private_bytes(&inputs.join("authority-checkpoint"), &registry)?;
    let prepared = run("policy-prepare", "prepared")?;
    assert_eq!(prepared.len(), 164);
    assert_eq!(
        prepared.get(..4).ok_or("storage protection")?,
        2u32.to_be_bytes()
    );
    let journal =
        p::JournalIdentity::from_trusted_state(prepared.get(4..36).ok_or("journal")?.try_into()?)?;
    let subject = p::AnchorSubject::from_trusted_state(prepared.get(36..132).ok_or("subject")?)?;
    let genesis = p::AnchorGenesis::from_trusted_state(
        subject,
        prepared.get(132..).ok_or("genesis")?.try_into()?,
    )?;
    let previous_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        original.checkpoint(),
        policy.family(),
    )?;
    let previous =
        previous_pin.verify_device(&certificate, original.as_bytes(), fixture::now()?)?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, &previous, policy.as_ref())?
    );
    w.configured.store.lock().map_err(|_| "witness")?.enroll(
        &genesis,
        &previous,
        &policy,
        fixture::now()?,
    )?;
    publish_private_bytes(&inputs.join("witness-subject"), &subject.to_bytes())?;
    let mut tls = if carrier == "tls" {
        let tls = witness_tls_faults::FaultWitness::start(
            Arc::clone(&w.configured.store),
            [
                inputs.as_path(),
                reference.initiator.as_path(),
                reference.responder.as_path(),
            ],
            w._directory.path().join("witness.redb"),
        )?;
        fs::write(inputs.join("witness-address"), tls.address.to_string())?;
        fs::write(inputs.join("witness-carrier"), b"tls")?;
        Some(tls)
    } else {
        None
    };
    assert_eq!(run("policy-activate", "activated.request")?, request);
    let identity = run("policy-identity", "original.identity")?;
    assert_eq!(
        identity.get(32..).ok_or("original journal")?,
        journal.as_bytes()
    );
    let traffic_case = traffic::Case {
        base: &base,
        inputs: &inputs,
        reference: &reference,
        witness: Some(&w.configured),
    };
    let traffic = traffic::Traffic::begin(&traffic_case, &root, &certificate, &original, &run)?;
    let issued = root.issue_roster(2, validity, &[root.roster_entry(&certificate)?])?;
    let current_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        issued.checkpoint(),
        policy.family(),
    )?;
    let current = current_pin.verify_device(&certificate, issued.as_bytes(), fixture::now()?)?;
    let operation = p::RosterRefreshId::generate()?;
    for (name, bytes) in [
        ("renewal-roster", issued.as_bytes().to_vec()),
        ("renewal-version", 2u64.to_be_bytes().to_vec()),
        ("renewal-digest", issued.checkpoint().digest().to_vec()),
        ("roster-operation", operation.as_bytes().to_vec()),
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    for (mode, name, code) in [
        ("roster-witness-prepare-bad", "bad-roster", 102u32),
        ("roster-witness-prepare-cancelled", "cancelled", 302u32),
        (
            "roster-witness-prepare-unselected",
            "no-policy-fallback",
            1u32,
        ),
    ] {
        assert_eq!(run(mode, name)?, code.to_be_bytes());
        assert_eq!(
            run("roster-witness-progress", &format!("{name}-absent"))?,
            vec![0; 624]
        );
    }
    let bytes = run("roster-witness-prepare", "proposal")?;
    assert_eq!(bytes.len(), 417);
    publish_private_bytes(&inputs.join("roster-proposal"), &bytes)?;
    assert_eq!(run("roster-witness-prepare", "proposal-replayed")?, bytes);
    assert_eq!(run("roster-witness-recover", "proposal-recovered")?, bytes);
    let proposal = p::AnchorRosterRefreshProposal::from_trusted_state(&bytes)?;
    assert_eq!(
        proposal.scope(),
        &p::RosterRefreshScope {
            operation,
            previous: original.checkpoint(),
            target: issued.checkpoint(),
            policy: policy.checkpoint(),
            policy_authorization: None
        }
    );
    assert_eq!(
        run("roster-witness-progress", "reserved")?,
        progress(&proposal, 2, false)
    );
    assert_eq!(
        run("roster-witness-reconcile", "unavailable")?,
        5u32.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-abandon-refused", "no-local-abandon")?,
        211u32.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-substitute", "substitution-refused")?,
        211u32.to_be_bytes()
    );
    assert_eq!(
        w.configured
            .store
            .lock()
            .map_err(|_| "witness approval")?
            .prepare_roster_refresh(proposal, &previous, &current, &policy, fixture::now()?)?,
        p::AnchorRosterRefreshState::Prepared
    );
    assert_eq!(
        run("roster-witness-reconcile", "prepared-at-witness")?,
        1u32.to_be_bytes()
    );
    let before = captures(&w, tls.as_ref())?.len();
    let kind = if closed { 18 } else { 16 };
    if let Some(tls) = &tls {
        tls.arm(None)?;
    } else {
        w.arm(20 + kind)?;
    }
    assert_eq!(
        run(
            if closed {
                "roster-witness-close-unknown"
            } else {
                "roster-witness-commit-unknown"
            },
            "unknown"
        )?,
        218u32.to_be_bytes()
    );
    let records = captures(&w, tls.as_ref())?;
    let lost: Vec<_> = records
        .get(before..)
        .ok_or("lost exchange range")?
        .iter()
        .filter(|r| r.request.get(204) == Some(&kind))
        .collect();
    assert_eq!(lost.len(), 1);
    let lost = lost.first().ok_or("lost terminal exchange")?;
    assert!(!lost.delivered);
    publish_private_bytes(&base.join("lost-terminal-request"), &lost.request)?;
    publish_private_bytes(&base.join("lost-terminal-reply"), &lost.reply)?;
    let history = records.len();
    let terminal = if closed { 3u32 } else { 2u32 };
    assert_eq!(
        run("roster-witness-history-unmanaged", "historical-unmanaged")?,
        terminal.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-reconcile", "reconciled")?,
        terminal.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-close", "close-exact")?,
        terminal.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-commit", "commit-exact")?,
        terminal.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-progress", "retired")?,
        progress(&proposal, if closed { 4 } else { 3 }, true)
    );
    assert_eq!(
        run("roster-witness-resolve-local", "no-local-resolve")?,
        216u32.to_be_bytes()
    );
    assert_eq!(
        run("roster-witness-activate-unmanaged", "registry-required")?,
        211u32.to_be_bytes()
    );
    assert_eq!(run("policy-activate", "active-original-request")?, request);
    traffic.resume(
        &traffic_case,
        &root,
        if closed { &original } else { &issued },
        &run,
    )?;
    assert_eq!(run("policy-identity", "final.identity")?, identity);
    let after = captures(&w, tls.as_ref())?;
    let trace = after.get(history..).ok_or("history capture range")?;
    assert!(
        !trace.is_empty()
            && trace
                .iter()
                .all(|r| r.delivered && !matches!(r.request.get(204), Some(16 | 18)))
    );
    crate::android_credential::write_exchanges(&base.join("historical-transcript"), trace)?;
    publish_private_bytes(&base.join("process-count"), &calls.get().to_be_bytes())?;
    policy.close();
    sdk.close();
    if let Some(tls) = tls.as_mut() {
        tls.finish()?;
    }
    w.join()?;
    println!("qualified roster witness {label}: {} Java processes; original R terminal and original session message with one effect",calls.get());
    Ok(())
}
