// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit test issuers plus actual consumer CLI, protected keys and OS time.
use super::*;
use q_periapt_continuity_reference_app::policy_renewal::Request as PolicyRequest;
use std::{
    process::Stdio,
    time::{Duration, Instant},
};

pub(super) fn policy_approval(
    c: &mut Case,
    retained: &PolicyRequest,
    previous: [u8; 32],
    target: [u8; 32],
) -> Result<Vec<u8>> {
    c.publisher.enable_renewals()?;
    let request = RenewalRequest {
        retained: retained.clone(),
        original_publication: [65; 32],
        previous_publication: previous,
        target_publication: target,
    };
    let result = c.publisher.approve_renewal(&request, &c.current)?;
    assert_eq!(c.publisher.approve_renewal(&request, &c.current)?, result);
    assert_eq!(
        c.publisher.renewal_status(&request, &c.current)?,
        RenewalStatus::Issued {
            result: result.clone()
        }
    );
    Ok(result.approval)
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
pub(super) fn lose_response(c: &Case, args: &[OsString], name: &str) -> Result<()> {
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
    let authority = policy_approval(&mut c, &request, [65; 32], [121; 32])?;
    publish_private_bytes(&c.path.join("account-approval.bin"), account.as_bytes())?;
    publish_private_bytes(&c.path.join("policy-approval.bin"), &authority)?;
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
    let mut resolve = recover.clone();
    resolve[0] = "policy-resolve".into();
    resolve.extend([
        c.path.join("next-pins.json").into_os_string(),
        c.path.join("next-materials.json").into_os_string(),
    ]);
    // Neither a live uncommitted target nor an unrelated signed target permits
    // abandoning this operation. Failure must retain its exact Pending record.
    invoke(&resolve, false)?;
    assert_eq!(c.call("policy-status", &[])?, pending);
    let mut wrong_statement = resolve.clone();
    wrong_statement[5] = URL_SAFE_NO_PAD.encode([123; 32]).into();
    invoke(&wrong_statement, false)?;
    let mut wrong_target = resolve.clone();
    wrong_target[8] = c.path.join("policy-pins.json").into_os_string();
    wrong_target[9] = c.path.join("policy-materials.json").into_os_string();
    invoke(&wrong_target, false)?;
    assert_eq!(c.call("policy-status", &[])?, pending);
    let apply = policy_args(
        &c,
        "policy-adopt",
        "policy-request.json",
        "account-approval.bin",
    );
    if adopt {
        lose_response(&c, &apply, "policy-lost-output.stderr")?;
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
    if !adopt {
        invoke(&request_args(&c, [122; 32], "blocked-request.json"), false)?;
        assert!(!c.path.join("blocked-request.json").exists());
    }
    invoke(&wrong_statement, false)?;
    invoke(&wrong_target, false)?;
    assert_eq!(c.call("policy-status", &[])?, before);
    if !adopt {
        lose_response(&c, &resolve, "policy-resolution-lost-output.stderr")?;
    }
    let resolved: serde_json::Value = serde_json::from_slice(&invoke(&resolve, true)?)?;
    if adopt {
        assert_eq!(resolved, before);
    } else {
        assert_eq!(resolved["state"], "AbandonedUncommitted");
        assert_eq!(resolved["reason"], "Expired");
        assert_eq!(resolved["operation"], pending["operation"]);
        assert_eq!(resolved["statement"], pending["statement"]);
        assert_eq!(resolved["target"], pending["target"]);
        assert_eq!(
            resolved["observed_roster"],
            serde_json::to_value(request.scope.current_roster)?
        );
        assert!(resolved["observed_at"].as_u64().ok_or("observed time")? >= c.start + 40);
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&resolve, true)?)?,
        resolved
    );
    assert_eq!(c.call("policy-status", &[])?, resolved);
    // The caller retains this receipt before a subsequent policy completion can
    // retire the SDK's bounded last-abandoned record.
    write(&c.path.join("original-policy-outcome.json"), &resolved)?;
    invoke(&request_args(&c, [122; 32], "next-request.json"), true)?;
    let next: PolicyRequest = serde_json::from_slice(&fs::read(c.path.join("next-request.json"))?)?;
    let previous = if adopt {
        target.historical()
    } else {
        &original
    };
    assert_eq!(
        next.scope.previous_policy,
        q_periapt_continuity_reference_app::policy_renewal::checkpoint(previous.checkpoint())
    );
    assert_eq!(
        next.scope.previous_authorization,
        adopt.then_some(statement.digest())
    );
    assert_eq!(next.scope.journal, request.scope.journal);
    assert_eq!(next.scope.original_owner, request.scope.original_owner);
    assert_eq!(next.current_certificate, request.current_certificate);
    assert_eq!(next.current_roster, request.current_roster);
    assert_eq!(fs::read(c.path.join("original-device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    fs::rename(
        c.path.join("original-device.key"),
        c.path.join("device/device.key"),
    )?;
    adopt_fresh_policy(&mut c, &next, &original, previous, adopt)?;
    assert_eq!(fs::read(c.path.join("device/device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(
            c.path.join("original-policy-outcome.json")
        )?)?,
        resolved
    );
    assert_eq!(c.call("status", &[])?["journal"], accepted["journal"]);
    let path = c.path.clone();
    drop(c);
    publisher_cli_recovery(&path)?;
    Ok(())
}

fn adopt_fresh_policy(
    c: &mut Case,
    request: &PolicyRequest,
    original: &sdk::HistoricalSessionPolicy,
    previous: &sdk::HistoricalSessionPolicy,
    previously_committed: bool,
) -> Result<()> {
    c.publisher.issue(
        [125; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: c.start,
            valid_until: c.start + 120,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        clock()?,
    )?;
    c.policy_files([125; 32], "third")?;
    c.policy_files(
        if previously_committed {
            [121; 32]
        } else {
            [65; 32]
        },
        "previous",
    )?;
    let (pins, materials) = c.publisher.export([125; 32])?;
    let (target, _) = pins.verify(&materials, c.invitation.family, clock()?)?;
    let verified = request.verify_identities(&c.current, clock()?)?;
    let statement = sdk::PolicyRenewalStatement::new(
        verified.scope(),
        &verified.materials(original, previous, &target),
        clock()?,
    )?;
    publish_private_bytes(
        &c.path.join("third-account.bin"),
        c.root.approve_policy_renewal(&statement)?.as_bytes(),
    )?;
    let authority = policy_approval(
        c,
        request,
        if previously_committed {
            [121; 32]
        } else {
            [65; 32]
        },
        [125; 32],
    )?;
    publish_private_bytes(&c.path.join("third-policy.bin"), &authority)?;
    let mut apply = policy_args(c, "policy-adopt", "next-request.json", "third-account.bin");
    apply[6] = c.path.join("third-policy.bin").into_os_string();
    apply[10] = c.path.join("previous-pins.json").into_os_string();
    apply[11] = c.path.join("previous-materials.json").into_os_string();
    apply[12] = c.path.join("third-pins.json").into_os_string();
    apply[13] = c.path.join("third-materials.json").into_os_string();
    let committed: serde_json::Value = serde_json::from_slice(&invoke(&apply, true)?)?;
    assert_eq!(committed["state"], "Committed");
    assert_eq!(request.scope.operation, [122; 32]);
    assert_eq!(
        committed["operation"],
        serde_json::json!(request.scope.operation)
    );
    assert_eq!(
        committed["statement"],
        serde_json::json!(statement.digest())
    );
    assert_eq!(
        committed["target"],
        serde_json::to_value(
            q_periapt_continuity_reference_app::policy_renewal::checkpoint(target.checkpoint())
        )?
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&apply, true)?)?,
        committed
    );
    Ok(())
}

fn publisher_cli_recovery(path: &Path) -> Result<()> {
    let bundle = path.join("policy-inputs.json");
    let export = [
        OsString::from("renewal-policies"),
        path.join("publisher.redb").into_os_string(),
        URL_SAFE_NO_PAD.encode([60; 32]).into(),
        URL_SAFE_NO_PAD.encode([65; 32]).into(),
        URL_SAFE_NO_PAD.encode([65; 32]).into(),
        URL_SAFE_NO_PAD.encode([121; 32]).into(),
        bundle.clone().into_os_string(),
    ];
    let exported = Command::new(env!("CARGO_BIN_EXE_q-periapt-policy-publisher"))
        .args(&export)
        .output()?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(exported.stderr.is_empty());
    let public: q_periapt_continuity_reference_app::policy_publisher::PolicyApprovalInputs =
        serde_json::from_slice(&fs::read(&bundle)?)?;
    let publisher = Publisher::open(&path.join("publisher.redb"), [60; 32])?;
    assert_eq!(public.schema, "qperiapt-policy-approval-inputs/1");
    assert_eq!(public.family, publisher.authority()?.family);
    let expected = publisher.renewal_inputs([65; 32], [65; 32], [121; 32])?;
    assert_eq!(serde_json::to_vec(&public)?, serde_json::to_vec(&expected)?);
    let (_, original) = publisher.export([65; 32])?;
    assert!(public.original.materials == original && public.previous == public.original);
    drop(publisher);
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_q-periapt-policy-publisher"))
            .args(&export)
            .output()?
            .status
            .success()
    );
    let args = [
        OsString::from("renewal-approve"),
        path.join("publisher.redb").into_os_string(),
        URL_SAFE_NO_PAD.encode([60; 32]).into(),
        path.join("policy-request.json").into_os_string(),
        path.join("current.json").into_os_string(),
        URL_SAFE_NO_PAD.encode([65; 32]).into(),
        URL_SAFE_NO_PAD.encode([65; 32]).into(),
        URL_SAFE_NO_PAD.encode([121; 32]).into(),
        path.join("recovered-policy-approval.bin").into_os_string(),
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-policy-publisher"))
        .args(&args)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read(path.join("recovered-policy-approval.bin"))?,
        fs::read(path.join("policy-approval.bin"))?
    );
    // Output publication failure must not regenerate the durable decision.
    let failed = Command::new(env!("CARGO_BIN_EXE_q-periapt-policy-publisher"))
        .args(&args)
        .output()?;
    assert!(!failed.status.success());
    let mut status = args[..8].to_vec();
    status[0] = "renewal-status".into();
    let observed = Command::new(env!("CARGO_BIN_EXE_q-periapt-policy-publisher"))
        .args(status)
        .output()?;
    assert!(observed.status.success());
    assert_eq!(observed.stdout, output.stdout);
    Ok(())
}
