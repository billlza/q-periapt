// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent closure after real target-roster expiry and a lost cleanup ACK.
use crate::{
    android_credential::Renewal, android_credential_traffic as traffic, fixture, p, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs, thread,
    time::{Duration, Instant},
};

fn status(bytes: &[u8], proof: &p::VerifiedCredentialRenewal, phase: u32) -> Result<()> {
    assert_eq!(bytes.len(), 116);
    assert_eq!(bytes.get(..4), Some(phase.to_be_bytes().as_slice()));
    assert_eq!(
        bytes.get(4..36),
        Some(proof.operation().as_bytes().as_slice())
    );
    assert_eq!(bytes.get(36..68), Some(proof.statement_digest().as_slice()));
    if phase == 1 {
        assert_eq!(bytes.get(68..108), Some([0; 40].as_slice()));
    } else {
        let cp = proof.successor_device().roster().checkpoint();
        assert_eq!(
            bytes.get(68..76),
            Some(cp.version().to_be_bytes().as_slice())
        );
        assert_eq!(bytes.get(76..108), Some(cp.digest().as_slice()));
    }
    assert_eq!(bytes.get(108..), Some([0; 8].as_slice()));
    Ok(())
}
fn issue(case: &Renewal<'_>) -> Result<(p::VerifiedCredentialRenewal, p::AccountPin, u64, u64)> {
    let now = fixture::now()?;
    let until = now.checked_add(30).ok_or("roster expiry overflow")?;
    let credential_until = case
        .validity
        .until()
        .checked_add(1200)
        .ok_or("credential expiry overflow")?;
    let family = fixture::array(case.inputs, "family")?;
    let successor = case.root.issue_device(
        p::DeviceDescription::new(
            case.original.device_id(),
            case.original.generation(),
            family,
            p::Validity::new(case.validity.from(), credential_until)?,
        )?,
        case.public_key.clone(),
    )?;
    let roster = case.root.issue_roster(
        3,
        p::Validity::new(case.validity.from(), until)?,
        &[case.root.roster_entry(&successor)?],
    )?;
    let pin = p::AccountPin::new(
        case.root.account_id()?,
        case.root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let previous = fs::read(case.inputs.join("renewed-certificate"))?;
    let previous_roster = fs::read(case.inputs.join("renewed-roster"))?;
    let old = p::RosterCheckpoint::from_trusted_state(
        u64::from_be_bytes(fixture::array(case.inputs, "renewal-version")?),
        fixture::array(case.inputs, "renewal-digest")?,
    )?;
    let operation = p::CredentialRenewalId::generate()?;
    let grant = case.root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: case.certificate,
            previous_credential: &previous,
            successor_credential: &successor,
            previous_roster: &previous_roster,
            successor_roster: roster.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: old,
            policy_digest: case.policy.checkpoint().digest(),
        },
        &pin,
        now,
    )?;
    let proof = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &pin,
        case.policy.checkpoint().digest(),
        now,
    )?;
    for (name, bytes) in [
        ("terminal-grant", grant.as_bytes().to_vec()),
        ("terminal-operation", operation.as_bytes().to_vec()),
        ("terminal-statement", proof.statement_digest().to_vec()),
        ("terminal-version", 3u64.to_be_bytes().to_vec()),
        ("terminal-digest", roster.checkpoint().digest().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &bytes)?;
    }
    Ok((proof, pin, until, credential_until))
}
pub(crate) fn run(case: &Renewal<'_>, run: &impl Fn(&str, &str) -> Result<Vec<u8>>) -> Result<()> {
    let committed = fs::read(case.base.join("credential-recovered"))?;
    for (mode, label) in [
        (
            "credential-terminal-close-committed",
            "terminal-close-committed",
        ),
        (
            "credential-terminal-expiry-committed",
            "terminal-expiry-committed",
        ),
    ] {
        assert_eq!(run(mode, label)?, committed);
    }
    let (proof, pin, until, credential_until) = issue(case)?;
    status(
        &run("credential-terminal-stage", "terminal-staged")?,
        &proof,
        1,
    )?;
    let before = case.exchanges()?.len();
    let bytes = run(
        "credential-terminal-cancel-prepare",
        "terminal-cancellation",
    )?;
    assert_eq!(
        run(
            "credential-terminal-cancel-prepare",
            "terminal-cancellation-replayed"
        )?,
        bytes
    );
    assert_eq!(
        case.exchanges()?.len(),
        before,
        "cancellation reservation must not dispatch"
    );
    let cancellation = p::AnchorCredentialRenewalCancellation::from_trusted_state(&bytes)?;
    assert_eq!(cancellation.operation(), proof.operation());
    assert_eq!(cancellation.statement(), proof.statement_digest());
    status(
        &run("credential-terminal-pending", "terminal-pending")?,
        &proof,
        1,
    )?;
    assert_eq!(
        run(
            "credential-terminal-commit-reserved-refused",
            "terminal-reserved-refused"
        )?,
        215u32.to_be_bytes()
    );
    assert_eq!(
        run(
            "credential-terminal-activate-refused",
            "terminal-activate-refused"
        )?,
        215u32.to_be_bytes()
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    while fixture::now()? < until {
        if Instant::now() >= deadline {
            return Err("real target-roster expiry deadline".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let observed = fixture::now()?;
    assert!(
        observed >= until
            && observed < credential_until
            && observed < case.policy.validity().until()
    );
    let raw = fs::read(case.inputs.join("terminal-grant"))?;
    assert!(matches!(
        p::VerifiedCredentialRenewal::verify(
            &raw,
            &pin,
            case.policy.checkpoint().digest(),
            observed
        ),
        Err(p::Error::Validity)
    ));
    let historical =
        p::HistoricalCredentialRenewal::verify(&raw, &pin, case.policy.checkpoint().digest())?;
    let mut observation = until.to_be_bytes().to_vec();
    observation.extend_from_slice(&observed.to_be_bytes());
    observation.extend_from_slice(&credential_until.to_be_bytes());
    observation.extend_from_slice(&case.policy.validity().until().to_be_bytes());
    publish_private_bytes(&case.base.join("terminal-expiry-observation"), &observation)?;
    assert_eq!(
        run(
            "credential-terminal-commit-expired-refused",
            "terminal-expired-refused"
        )?,
        215u32.to_be_bytes()
    );
    assert_eq!(
        run(
            "credential-terminal-expired-stage-refused",
            "terminal-expired-stage-refused"
        )?,
        104u32.to_be_bytes()
    );
    status(
        &run("credential-terminal-pending", "terminal-pending-expired")?,
        &proof,
        1,
    )?;
    assert_eq!(
        case.witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness store")?
            .close_unprepared_credential_renewal(cancellation, &historical, case.policy)?,
        p::AnchorCredentialCancellationState::Closed
    );
    let before_ack = case.exchanges()?.len();
    if let Some(tls) = case.tls {
        tls.arm(None)?;
    } else {
        case.witness.arm(28)?;
    }
    assert_eq!(
        run(
            "credential-terminal-reconcile-unknown",
            "terminal-cleanup-unknown"
        )?,
        218u32.to_be_bytes()
    );
    let exchanges = case.exchanges()?;
    let lost: Vec<_> = exchanges
        .get(before_ack..)
        .ok_or("cleanup capture")?
        .iter()
        .filter(|r| !r.delivered)
        .collect();
    assert_eq!(lost.len(), 1);
    let ack = lost.first().ok_or("lost ACK")?;
    assert_eq!(ack.request.get(204), Some(&8));
    assert_eq!(ack.reply.get(204), Some(&11));
    publish_private_bytes(&case.base.join("terminal-lost-ack-request"), &ack.request)?;
    publish_private_bytes(&case.base.join("terminal-lost-ack-reply"), &ack.reply)?;
    for (mode, label) in [
        (
            "credential-terminal-status-closed",
            "terminal-status-closed",
        ),
        ("credential-terminal-reconcile", "terminal-reconciled"),
        (
            "credential-terminal-close-replay",
            "terminal-close-replayed",
        ),
        (
            "credential-terminal-commit-replay",
            "terminal-commit-replayed",
        ),
    ] {
        status(&run(mode, label)?, &proof, 4)?;
    }
    let all = case.exchanges()?;
    let terminal = all.get(before..).ok_or("terminal exchanges")?;
    assert!(!terminal.is_empty());
    assert!(terminal
        .iter()
        .all(|r| !matches!(r.request.get(204), Some(&5) | Some(&7))));
    let mut transcript = Vec::new();
    for r in terminal {
        assert_eq!(r.request.len(), 3674);
        assert_eq!(r.reply.len(), 3659);
        transcript.push(u8::from(r.delivered));
        transcript.extend_from_slice(&r.request);
        transcript.extend_from_slice(&r.reply);
    }
    publish_private_bytes(
        &case.base.join("terminal-no-commit-transcript"),
        &transcript,
    )?;
    let mut expected = fs::read(case.base.join("credential-original-identity"))?;
    expected.extend_from_slice(&fixture::array::<32>(case.inputs, "remote-next")?);
    assert_eq!(
        run("credential-terminal-active", "terminal-active")?,
        expected
    );
    let session = fixture::array::<32>(case.inputs, "connection-session")?;
    let message = fixture::array::<32>(case.inputs, "remote-next")?;
    let (server, address) = traffic::start_labelled(
        case,
        "message",
        Some(session),
        "terminal-credential-message",
    )?;
    fs::write(case.inputs.join("connection-address"), address.to_string())?;
    let mut sent = session.to_vec();
    sent.extend_from_slice(&message);
    assert_eq!(run("credential-terminal-send", "terminal-sent")?, sent);
    traffic::received_new(server, session, message)?;
    fixture::effect(
        case.receiver,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    for (name, original) in [
        ("connection-message", "credential-effect-before"),
        ("remote-message", "remote-effect-before"),
    ] {
        assert_eq!(
            fs::read(case.receiver.join(format!(
                "application-{}",
                fixture::hex(&fixture::array::<32>(case.inputs, name)?)
            )))?,
            fs::read(case.base.join(original))?
        );
    }
    let effects = fs::read_dir(case.receiver)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|e| e.file_name().to_string_lossy().starts_with("application-"))
        .count();
    assert_eq!(effects, 3);
    publish_private_bytes(
        &case.base.join("terminal-effect-count"),
        &3u32.to_be_bytes(),
    )?;
    let effect = fs::read(
        case.receiver
            .join(format!("application-{}", fixture::hex(&message))),
    )?;
    publish_private_bytes(&case.base.join("terminal-effect"), &effect)?;
    Ok(())
}
