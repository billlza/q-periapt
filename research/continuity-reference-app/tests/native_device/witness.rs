// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual CLI, TCP witness and clock expiry; no implicit remote authorization.
use super::recovery::{issue_recovery, recovery_args};
use super::*;
use q_periapt_continuity_reference_app::native_device::RetainedCredentialRequest;
use std::{
    process::Stdio,
    time::{Duration, Instant},
};

#[test]
fn witness_cli_observes_original_closed_after_policy_expiry_and_lost_stdout() -> Result<()> {
    witness_outcome(false)
}
#[test]
fn witness_cli_observes_original_applied_after_policy_expiry_and_lost_stdout() -> Result<()> {
    witness_outcome(true)
}
fn lose_response(c: &Case, args: &[OsString], name: &str) -> Result<()> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-native-device"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let output = child.wait_with_output()?;
    fs::write(c.path.join(name), &output.stderr)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .to_ascii_lowercase()
        .contains("broken pipe"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    Ok(())
}
fn witness_outcome(apply: bool) -> Result<()> {
    let mut server = witness_support::Server::start()?;
    let c = Case::open_with_profile(20, 30, Some(&server))?;
    let accepted = c.accept()?;
    let preparation = c.call(
        "prepare",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    )?;
    assert_eq!(preparation["preparation"], "RequiresWitnessEnrollment");
    let subject: Vec<u8> = serde_json::from_value(preparation["subject"].clone())?;
    let genesis = sdk::AnchorGenesis::from_trusted_state(
        sdk::AnchorSubject::from_trusted_state(&subject)?,
        serde_json::from_value(preparation["head"].clone())?,
    )?;
    let old_pin = sdk::AccountPin::new(
        c.current.account,
        c.root.public_key()?,
        c.issued.checkpoint.as_sdk()?,
        c.invitation.family,
    )?;
    let original = old_pin.verify_device(&c.issued.certificate, &c.issued.roster, clock()?)?;
    let (pins, materials) = c.publisher.export([65; 32])?;
    let (policy, _) = pins.verify(&materials, c.invitation.family, clock()?)?;
    server.store.lock().map_err(|_| "witness lock")?.enroll(
        &genesis,
        &original,
        &policy,
        clock()?,
    )?;
    let mut activate = c.args(
        "activate",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    );
    activate.push(server.address.to_string().into());
    invoke(&activate, true)?;
    let signing = fs::read(c.path.join("device/device.key"))?;
    let wrapping = fs::read(c.path.join("wrap.key"))?;
    let mut request = c.args("renewal-request", &[]);
    request.extend([
        URL_SAFE_NO_PAD.encode([118; 32]).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        server.address.to_string().into(),
        c.path.join("retained-witness.json").into_os_string(),
    ]);
    invoke(&request, true)?;
    let retained: RetainedCredentialRequest =
        serde_json::from_slice(&fs::read(c.path.join("retained-witness.json"))?)?;
    let r = issue_recovery(&c, retained, c.start + 25)?;
    let mut stage = recovery_args(
        &c,
        "renewal-stage",
        "grant-approval.json",
        "grant-issued.json",
        "current2.json",
    );
    *stage.last_mut().ok_or("endpoint")? = server.address.to_string().into();
    let pending: serde_json::Value = serde_json::from_slice(&invoke(&stage, true)?)?;
    assert_eq!(pending["state"], "Pending");
    let mut prepare = stage.clone();
    prepare[0] = "renewal-witness-prepare".into();
    prepare.push(c.path.join("witness-proposal.json").into_os_string());
    invoke(&prepare, true)?;
    let exported: serde_json::Value =
        serde_json::from_slice(&fs::read(c.path.join("witness-proposal.json"))?)?;
    let proposal = sdk::AnchorCredentialRenewalProposal::from_trusted_state(
        &URL_SAFE_NO_PAD.decode(exported["proposal"].as_str().ok_or("proposal")?)?,
    )?;
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &r.issued.grant,
        &r.pin,
        r.approval.retained.original_policy.digest,
        clock()?,
    )?;
    let mut observe = c.args("renewal-witness-observe", &[]);
    observe.extend([
        URL_SAFE_NO_PAD.encode(r.approval.retained.operation).into(),
        URL_SAFE_NO_PAD.encode(r.issued.statement).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        server.address.to_string().into(),
    ]);
    let mut wrong = observe.clone();
    wrong[4] = URL_SAFE_NO_PAD.encode([119; 32]).into();
    invoke(&wrong, false)?;
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = unavailable.local_addr()?;
    drop(unavailable);
    let mut offline = observe.clone();
    offline[8] = address.to_string().into();
    invoke(&offline, false)?;
    assert_eq!(c.call("renewal-status", &[])?, pending);
    // An unavailable witness slot must remain Pending, not become NoCommit.
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&observe, true)?)?,
        pending
    );
    assert_eq!(
        server
            .store
            .lock()
            .map_err(|_| "witness lock")?
            .prepare_credential_renewal(proposal, &grant, &policy, clock()?)?,
        sdk::AnchorCredentialRenewalState::Prepared
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&observe, true)?)?,
        pending
    );
    // Detect an accidental Commit or Close after independent preparation.
    assert_eq!(
        server
            .store
            .lock()
            .map_err(|_| "witness lock")?
            .prepare_credential_renewal(proposal, &grant, &policy, clock()?)?,
        sdk::AnchorCredentialRenewalState::Prepared
    );
    if apply {
        let mut commit = stage.clone();
        commit[0] = "renewal-activate".into();
        lose_response(&c, &commit, "applied-lost-stdout.stderr")?;
        assert_eq!(c.call("renewal-status", &[])?["state"], "Committed");
    }
    let limit = Instant::now() + Duration::from_secs(40);
    while clock()? < c.start + 30 {
        if Instant::now() >= limit {
            return Err("Actual witness policy expiry did not occur within bound".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(pins
        .verify(&materials, c.invitation.family, clock()?)
        .is_err());
    policy.close();
    if !apply {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&invoke(&observe, true)?)?,
            pending
        );
        assert_eq!(
            server
                .store
                .lock()
                .map_err(|_| "witness lock")?
                .close_credential_renewal(proposal, &grant, &policy)?,
            sdk::AnchorCredentialRenewalState::Closed
        );
        lose_response(&c, &observe, "closed-lost-stdout.stderr")?;
    }
    let terminal = c.call("renewal-status", &[])?;
    assert_eq!(
        terminal["state"],
        if apply { "Committed" } else { "Closed" }
    );
    assert_eq!(
        terminal["operation"],
        serde_json::json!(r.approval.retained.operation)
    );
    assert_eq!(terminal["statement"], serde_json::json!(r.issued.statement));
    for _ in 0..2 {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&invoke(&observe, true)?)?,
            terminal
        );
    }
    assert_eq!(c.call("status", &[])?["journal"], accepted["journal"]);
    assert_eq!(fs::read(c.path.join("device/device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    assert!(server.close()? > 0);
    Ok(())
}
