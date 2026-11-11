// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The native counterparty renews through its installed C enrollment API.
use crate::{
    android_credential::Renewal, android_credential_traffic as traffic, fixture, p, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    process::{Command, Stdio},
};

pub(crate) fn receiver_metadata(case: &Renewal<'_>) -> Result<()> {
    let path = case.receiver;
    let mut intent = fixture::array::<16>(path, "responder-device")?.to_vec();
    intent.extend_from_slice(&fixture::array::<8>(path, "responder-generation")?);
    intent.extend_from_slice(&fixture::array::<32>(path, "family")?);
    intent.extend_from_slice(&fixture::array::<16>(path, "enrollment-validity")?);
    publish_private_bytes(
        &path.join("enrollment-root"),
        &case.receiver_root.public_key()?.encode(),
    )?;
    publish_private_bytes(&path.join("enrollment-intent"), &intent)?;
    publish_private_bytes(
        &path.join("trusted-account"),
        &case.receiver_root.account_id()?,
    )?;
    Ok(())
}
fn invoke(case: &Renewal<'_>, mode: &str) -> Result<String> {
    let name = format!("remote-native-{mode}");
    let mut command = Command::new(traffic::executable()?);
    command
        .args(traffic::witness_args(case)?)
        .arg(format!("enrollment-{mode}"))
        .arg(case.receiver);
    command.stdout(Stdio::from(fs::File::create(
        case.base.join(format!("{name}.stdout")),
    )?));
    command.stderr(Stdio::from(fs::File::create(
        case.base.join(format!("{name}.stderr")),
    )?));
    let mut child = fixture::OwnedChild(command.spawn()?);
    let status = fixture::wait(&mut child)?;
    let diagnostic = fs::read_to_string(case.base.join(format!("{name}.stderr")))?;
    assert!(
        status.success() && diagnostic.is_empty(),
        "counterparty {mode} {status}: {diagnostic}"
    );
    Ok(fs::read_to_string(
        case.base.join(format!("{name}.stdout")),
    )?)
}
fn expected_status(proof: &p::VerifiedCredentialRenewal, phase: u32) -> String {
    let cp = proof.successor_device().roster().checkpoint();
    let version = if phase == 1 { 0 } else { cp.version() };
    let digest = if phase == 1 { [0; 32] } else { cp.digest() };
    format!(
        "credential-phase:{phase}\n{}\n{}\ncredential-head:{version}\n{}\ncredential-observed:0\n",
        fixture::hex(proof.operation().as_bytes()),
        fixture::hex(&proof.statement_digest()),
        fixture::hex(&digest)
    )
}
fn renew(case: &Renewal<'_>) -> Result<p::VerifiedCredentialRenewal> {
    let path = case.receiver;
    let root = case.receiver_root;
    let family = fixture::array(path, "family")?;
    let validity = fixture::array::<16>(path, "enrollment-validity")?;
    let from = u64::from_be_bytes(validity.get(..8).ok_or("validity start")?.try_into()?);
    let until = u64::from_be_bytes(validity.get(8..).ok_or("validity end")?.try_into()?);
    let validity = p::Validity::new(
        from,
        until.checked_add(600).ok_or("credential expiry overflow")?,
    )?;
    let original = fixture::read(path, "local-certificate", 8192)?;
    let roster = fixture::read(path, "local-roster", 65536)?;
    let before = p::RosterCheckpoint::from_trusted_state(
        u64::from_be_bytes(fixture::array(path, "local-roster-version")?),
        fixture::array(path, "local-roster-digest")?,
    )?;
    let successor = root.issue_device(
        p::DeviceDescription::new(
            fixture::array(path, "local-device")?,
            u64::from_be_bytes(fixture::array(path, "local-generation")?),
            family,
            validity,
        )?,
        p::PublicKey::decode(&fixture::read(path, "public-key", 1985)?)?,
    )?;
    let target = root.issue_roster(2, validity, &[root.roster_entry(&successor)?])?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        target.checkpoint(),
        family,
    )?;
    let operation = p::CredentialRenewalId::generate()?;
    let now = fixture::now()?;
    let grant = root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &original,
            previous_credential: &original,
            successor_credential: &successor,
            previous_roster: &roster,
            successor_roster: target.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: before,
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
    for (native, android, bytes) in [
        (
            "credential-renewal",
            "remote-grant",
            grant.as_bytes().to_vec(),
        ),
        (
            "credential-operation",
            "remote-operation",
            operation.as_bytes().to_vec(),
        ),
        (
            "credential-statement",
            "remote-statement",
            proof.statement_digest().to_vec(),
        ),
        (
            "renewal-version",
            "remote-version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "renewal-digest",
            "remote-digest",
            target.checkpoint().digest().to_vec(),
        ),
    ] {
        publish_private_bytes(&path.join(native), &bytes)?;
        publish_private_bytes(&case.inputs.join(android), &bytes)?;
    }
    assert_eq!(
        invoke(case, "credential-stage")?,
        expected_status(&proof, 1)
    );
    assert_eq!(
        invoke(case, "credential-witness-prepare")?,
        "credential-witness-prepared\n"
    );
    let bytes = fs::read(path.join("credential-proposal"))?;
    publish_private_bytes(&case.base.join("remote-native-proposal"), &bytes)?;
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&bytes)?;
    assert_eq!(proposal.operation(), operation);
    assert_eq!(proposal.statement(), proof.statement_digest());
    assert!(matches!(
        case.witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness store")?
            .prepare_credential_renewal(proposal, &proof, case.policy, fixture::now()?)?,
        p::AnchorCredentialRenewalState::Prepared
    ));
    assert_eq!(
        invoke(case, "credential-witness-commit")?,
        expected_status(&proof, 2)
    );
    assert_eq!(
        invoke(case, "credential-witness-reconcile")?,
        expected_status(&proof, 2)
    );
    Ok(proof)
}
pub(crate) fn run(case: &Renewal<'_>, run: &impl Fn(&str, &str) -> Result<Vec<u8>>) -> Result<()> {
    let session = fixture::array::<32>(case.inputs, "connection-session")?;
    let (server, address) = traffic::start_labelled(
        case,
        "crash-after",
        Some(session),
        "remote-credential-crash",
    )?;
    fs::write(case.inputs.join("connection-address"), address.to_string())?;
    let uncertain = run("credential-remote-uncertain", "remote-uncertain")?;
    traffic::received(server, 77, None)?;
    assert_eq!(uncertain.len(), 64);
    assert_eq!(uncertain.get(..32), Some(session.as_slice()));
    let message: [u8; 32] = uncertain
        .get(32..)
        .ok_or("remote pending message")?
        .try_into()?;
    assert_ne!(
        message,
        fixture::array::<32>(case.inputs, "connection-message")?
    );
    publish_private_bytes(&case.inputs.join("remote-message"), &message)?;
    let effect_path = case
        .receiver
        .join(format!("application-{}", fixture::hex(&message)));
    let effect = fs::read(&effect_path)?;
    publish_private_bytes(&case.base.join("remote-effect-before"), &effect)?;
    let proof = renew(case)?;
    assert_eq!(
        run("credential-remote-self-refused", "remote-self-refused")?,
        211u32.to_be_bytes()
    );
    let admitted = run("credential-remote-admit", "remote-admitted")?;
    assert_eq!(admitted.len(), 72);
    let checkpoint = proof.successor_device().roster().checkpoint();
    assert_eq!(
        admitted.get(..8),
        Some(checkpoint.version().to_be_bytes().as_slice())
    );
    assert_eq!(admitted.get(8..40), Some(checkpoint.digest().as_slice()));
    let next = admitted.get(40..).ok_or("next message slot")?;
    assert!(next.iter().any(|v| *v != 0));
    publish_private_bytes(&case.inputs.join("remote-next"), next)?;
    assert_eq!(
        run("credential-remote-reopen", "remote-reopened")?,
        admitted
    );
    let (server, address) =
        traffic::start_labelled(case, "message", Some(session), "remote-credential-message")?;
    fs::write(case.inputs.join("connection-address"), address.to_string())?;
    assert_eq!(
        run("credential-remote-retry", "remote-acknowledged")?,
        uncertain
    );
    traffic::received(server, 0, Some((session, message)))?;
    assert_eq!(fs::read(&effect_path)?, effect);
    fixture::effect(
        case.receiver,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    let preceding = fixture::array::<32>(case.inputs, "connection-message")?;
    assert_eq!(
        fs::read(
            case.receiver
                .join(format!("application-{}", fixture::hex(&preceding)))
        )?,
        fs::read(case.base.join("credential-effect-before"))?
    );
    let count = fs::read_dir(case.receiver)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|e| e.file_name().to_string_lossy().starts_with("application-"))
        .count();
    assert_eq!(count, 2);
    publish_private_bytes(&case.base.join("remote-effect-after"), &effect)?;
    publish_private_bytes(&case.base.join("remote-effect-count"), &2u32.to_be_bytes())?;
    Ok(())
}
