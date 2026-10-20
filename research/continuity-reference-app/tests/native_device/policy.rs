// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit test issuers plus actual consumer CLI, protected keys and OS time.
use super::*;
use q_periapt_continuity_reference_app::policy_renewal::Request as PolicyRequest;
use std::{
    process::Stdio,
    time::{Duration, Instant},
};

// This fixture owns both independent test authorities. Opening its protected
// policy signer is test issuer setup, not a production publisher approval API.
fn policy_signer(c: &Case) -> Result<sdk::PolicySigningKey> {
    let mut found = Vec::new();
    for item in fs::read_dir(&c.path)? {
        let item = item?;
        let name = item.file_name();
        let name = name.to_str().ok_or("test filename")?;
        if let Some(id) = name
            .strip_prefix("policy-")
            .and_then(|n| n.strip_suffix(".signer"))
        {
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(id)?
                .try_into()
                .map_err(|_| "signer identity")?;
            let key = sdk::PolicySigningKey::open(
                &item.path(),
                &sdk::JournalKey::open(&c.path.join(format!("policy-{id}.wrap")))?,
                sdk::SigningKeyId::from_trusted_state(bytes)?,
            )?;
            assert_eq!(
                key.public_key()?.encode(),
                c.publisher.authority()?.policy_root
            );
            found.push(key);
        }
    }
    if found.len() != 1 {
        return Err("Expected one original test policy signer".into());
    }
    found
        .pop()
        .ok_or_else(|| "Missing original policy signer".into())
}
fn request_args(c: &Case, operation: [u8; 32], output: &str) -> Vec<OsString> {
    let mut args = c.args("policy-request", &[]);
    args.extend([
        URL_SAFE_NO_PAD.encode(operation).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        c.path.join(output).into_os_string(),
    ]);
    args
}
fn policy_args(c: &Case, command: &str, request: &str, account: &str) -> Vec<OsString> {
    c.args(
        command,
        &[
            request,
            account,
            "policy-approval.bin",
            "current.json",
            "policy-pins.json",
            "policy-materials.json",
            "policy-pins.json",
            "policy-materials.json",
            "next-pins.json",
            "next-materials.json",
        ],
    )
}
#[test]
fn native_policy_adoption_survives_lost_output_and_historical_expiry_without_signer() -> Result<()>
{
    exercise(true)
}
#[test]
fn native_policy_history_does_not_adopt_an_uncommitted_expired_target() -> Result<()> {
    exercise(false)
}
fn exercise(adopt: bool) -> Result<()> {
    let mut c = Case::open_with_profile(600, 20, None)?;
    let accepted = c.accept()?;
    c.call(
        "prepare",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    )?;
    let mut activate = c.args(
        "activate",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    );
    activate.push("none".into());
    invoke(&activate, true)?;
    let signing = fs::read(c.path.join("device/device.key"))?;
    let wrapping = fs::read(c.path.join("wrap.key"))?;
    assert_eq!(c.call("policy-status", &[])?["state"], "Absent");
    invoke(&request_args(&c, [120; 32], "policy-request.json"), true)?;
    invoke(
        &request_args(&c, [120; 32], "policy-request-retry.json"),
        true,
    )?;
    let bytes = fs::read(c.path.join("policy-request.json"))?;
    assert_eq!(bytes, fs::read(c.path.join("policy-request-retry.json"))?);
    let request: PolicyRequest = serde_json::from_slice(&bytes)?;
    assert_eq!(
        serde_json::json!(request.scope.journal),
        accepted["journal"]
    );
    assert_eq!(request.scope.original_policy, request.scope.previous_policy);
    assert!(request.scope.previous_authorization.is_none());
    let mut missing = serde_json::to_value(&request)?;
    missing["scope"]
        .as_object_mut()
        .ok_or("scope")?
        .remove("previous_authorization");
    assert!(serde_json::from_value::<PolicyRequest>(missing).is_err());
    c.publisher.issue(
        [121; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: c.start,
            valid_until: c.start + 40,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        clock()?,
    )?;
    c.policy_files([121; 32], "next")?;
    let (original_pins, original_materials) = c.publisher.export([65; 32])?;
    let (original, _) =
        original_pins.verify_historical(&original_materials, c.invitation.family)?;
    let (target_pins, target_materials) = c.publisher.export([121; 32])?;
    let (target, _) = target_pins.verify(&target_materials, c.invitation.family, clock()?)?;
    let verified = request.verify_identities(&c.current, clock()?)?;
    let statement = sdk::PolicyRenewalStatement::new(
        verified.scope(),
        &verified.materials(&original, &original, &target),
        clock()?,
    )?;
    let account = c.root.approve_policy_renewal(&statement)?;
    let authority = policy_signer(&c)?.approve_policy_renewal(&statement)?;
    publish_private_bytes(&c.path.join("account-approval.bin"), account.as_bytes())?;
    publish_private_bytes(&c.path.join("policy-approval.bin"), authority.as_bytes())?;
    let mut forged = account.as_bytes().to_vec();
    let end = forged.len() - 1;
    forged[end] ^= 1;
    publish_private_bytes(&c.path.join("forged-account.bin"), &forged)?;
    invoke(
        &policy_args(
            &c,
            "policy-stage",
            "policy-request.json",
            "forged-account.bin",
        ),
        false,
    )?;
    assert_eq!(c.call("policy-status", &[])?["state"], "Absent");
    let mut wrong = request.clone();
    wrong.scope.journal[0] ^= 1;
    write(&c.path.join("wrong-request.json"), &wrong)?;
    invoke(
        &policy_args(
            &c,
            "policy-stage",
            "wrong-request.json",
            "account-approval.bin",
        ),
        false,
    )?;
    let stage = policy_args(
        &c,
        "policy-stage",
        "policy-request.json",
        "account-approval.bin",
    );
    let mut wrong_policy = stage.clone();
    wrong_policy[6] = c.path.join("account-approval.bin").into_os_string();
    invoke(&wrong_policy, false)?;
    assert_eq!(c.call("policy-status", &[])?["state"], "Absent");
    let pending: serde_json::Value = serde_json::from_slice(&invoke(&stage, true)?)?;
    assert_eq!(pending["state"], "Pending");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&stage, true)?)?,
        pending
    );
    assert_eq!(pending["statement"], serde_json::json!(statement.digest()));
    let mut recover = c.args("policy-recover", &[]);
    recover.extend([
        URL_SAFE_NO_PAD.encode(request.scope.operation).into(),
        URL_SAFE_NO_PAD.encode(statement.digest()).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
    ]);
    invoke(&recover, false)?;
    assert_eq!(c.call("policy-status", &[])?, pending);
    let apply = policy_args(
        &c,
        "policy-adopt",
        "policy-request.json",
        "account-approval.bin",
    );
    if adopt {
        let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-native-device"))
            .args(&apply)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        drop(child.stdout.take());
        let output = child.wait_with_output()?;
        fs::write(c.path.join("policy-lost-output.stderr"), &output.stderr)?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("broken pipe"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        let committed = c.call("policy-status", &[])?;
        assert_eq!(committed["state"], "Committed");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&invoke(&apply, true)?)?,
            committed
        );
        invoke(&activate, false)?; // Legacy activation cannot ignore adopted P.
    }
    let before = c.call("policy-status", &[])?;
    let limit = Instant::now() + Duration::from_secs(50);
    while clock()? < c.start + 40 {
        if Instant::now() >= limit {
            return Err("Policy expiry outside bound".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(target_pins
        .verify(&target_materials, c.invitation.family, clock()?)
        .is_err());
    target.close();
    invoke(&apply, false)?;
    fs::rename(
        c.path.join("device/device.key"),
        c.path.join("original-device.key"),
    )?;
    for _ in 0..2 {
        let outcome = invoke(&recover, adopt)?;
        if adopt {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&outcome)?,
                before
            );
        }
        assert_eq!(c.call("policy-status", &[])?, before);
    }
    if adopt {
        invoke(&request_args(&c, [122; 32], "next-request.json"), true)?;
        let next: PolicyRequest =
            serde_json::from_slice(&fs::read(c.path.join("next-request.json"))?)?;
        assert_eq!(
            next.scope.previous_policy,
            q_periapt_continuity_reference_app::policy_renewal::checkpoint(target.checkpoint())
        );
        assert_eq!(next.scope.previous_authorization, Some(statement.digest()));
        assert_eq!(next.scope.journal, request.scope.journal);
        assert_eq!(next.scope.original_owner, request.scope.original_owner);
        assert_eq!(next.current_certificate, request.current_certificate);
        assert_eq!(next.current_roster, request.current_roster);
    } else {
        invoke(&request_args(&c, [122; 32], "blocked-request.json"), false)?;
        assert!(!c.path.join("blocked-request.json").exists());
    }
    assert_eq!(fs::read(c.path.join("original-device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    fs::rename(
        c.path.join("original-device.key"),
        c.path.join("device/device.key"),
    )?;
    assert_eq!(c.call("status", &[])?["journal"], accepted["journal"]);
    Ok(())
}
