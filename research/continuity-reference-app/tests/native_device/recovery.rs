// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual expiry, process reopen and lost stdout, without changing the OS clock.
use super::*;
use q_periapt_continuity_reference_app::{
    credential_grant::{CredentialGrantRequest, IssuedCredentialGrant},
    native_device::RetainedCredentialRequest,
};
use std::{
    process::Stdio,
    time::{Duration, Instant},
};

fn recovery_args(
    c: &Case,
    command: &str,
    approval: &str,
    issued: &str,
    current: &str,
) -> Vec<OsString> {
    let mut args = c.args(
        command,
        &[
            approval,
            issued,
            current,
            "policy-pins.json",
            "policy-materials.json",
            "policy-pins.json",
            "policy-materials.json",
        ],
    );
    args.push("none".into());
    args
}
fn result(args: &[OsString]) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&invoke(args, true)?)?)
}

struct Recovery {
    approval: CredentialGrantRequest,
    issued: IssuedCredentialGrant,
    current: RootInfo,
    certificate: Vec<u8>,
    roster: Vec<u8>,
    pin: sdk::AccountPin,
}
fn issue_recovery(
    c: &Case,
    retained: RetainedCredentialRequest,
    valid_until: u64,
) -> Result<Recovery> {
    let old_pin = sdk::AccountPin::new(
        c.current.account,
        c.root.public_key()?,
        c.issued.checkpoint.as_sdk()?,
        c.invitation.family,
    )?;
    let original = old_pin.verify_historical_device(&c.issued.certificate, &c.issued.roster)?;
    let certificate = c
        .root
        .issue_credential_extension(&original, valid_until, clock()?)?;
    let roster = c.root.issue_roster(
        2,
        sdk::Validity::new(c.start, c.start + 1800)?,
        &[c.root.roster_entry(&certificate)?],
    )?;
    let pin = sdk::AccountPin::new(
        c.current.account,
        c.root.public_key()?,
        roster.checkpoint(),
        c.invitation.family,
    )?;
    let signed = c.root.issue_credential_renewal(
        sdk::CredentialRenewalMaterials {
            original_credential: &retained.original_certificate,
            previous_credential: &retained.previous_certificate,
            successor_credential: &certificate,
            previous_roster: &retained.previous_roster,
            successor_roster: roster.as_bytes(),
        },
        &sdk::CredentialRenewalAuthorization {
            operation: sdk::CredentialRenewalId::from_trusted_state(retained.operation)?,
            previous: retained.previous_checkpoint.as_sdk()?,
            policy_digest: retained.original_policy.digest,
        },
        &pin,
        clock()?,
    )?;
    let grant = sdk::VerifiedCredentialRenewal::verify(
        signed.as_bytes(),
        &pin,
        retained.original_policy.digest,
        clock()?,
    )?;
    let approval = CredentialGrantRequest {
        retained,
        original_extension: None,
        previous_extension: None,
        successor_extension: [115; 32],
        target_checkpoint: roster.checkpoint().into(),
    };
    let issued = IssuedCredentialGrant {
        enrollment: c.invitation.operation,
        operation: approval.retained.operation,
        journal: approval.retained.journal,
        root_revision: 1,
        statement: grant.statement_digest(),
        checkpoint: approval.target_checkpoint,
        grant: signed.as_bytes().to_vec(),
    };
    let mut current = c.current.clone();
    current.roster = Some(RosterSnapshot {
        checkpoint: issued.checkpoint,
        bytes: roster.as_bytes().to_vec(),
    });
    write(&c.path.join("grant-approval.json"), &approval)?;
    write(&c.path.join("grant-issued.json"), &issued)?;
    write(&c.path.join("current2.json"), &current)?;
    Ok(Recovery {
        approval,
        issued,
        current,
        certificate,
        roster: roster.as_bytes().to_vec(),
        pin,
    })
}

#[test]
fn actual_expired_native_recovers_original_g_after_lost_stdout_and_publishes_current_admission(
) -> Result<()> {
    let c = Case::open_with_validity(20)?;
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
    let mut request = c.args("renewal-request", &[]);
    request.extend([
        URL_SAFE_NO_PAD.encode([114; 32]).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        "none".into(),
        c.path.join("retained.json").into_os_string(),
    ]);
    invoke(&request, true)?;
    let retained: RetainedCredentialRequest =
        serde_json::from_slice(&fs::read(c.path.join("retained.json"))?)?;
    assert_eq!(c.call("renewal-status", &[])?["state"], "Absent");
    let limit = Instant::now() + Duration::from_secs(30);
    while clock()? < c.invitation.valid_until {
        if Instant::now() >= limit {
            return Err("Actual credential expiry did not occur within bound".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    invoke(&activate, false)?;
    assert!(sdk::AccountPin::new(
        c.current.account,
        c.root.public_key()?,
        c.issued.checkpoint.as_sdk()?,
        c.invitation.family,
    )?
    .verify_device(&c.issued.certificate, &c.issued.roster, clock()?)
    .is_err());
    let Recovery {
        approval,
        issued,
        current,
        certificate,
        roster,
        pin,
    } = issue_recovery(&c, retained, c.start + 1200)?;
    activate[5] = c.path.join("current2.json").into_os_string();
    invoke(&activate, false)?; // New certificate/roster alone cannot reactivate old state.
    let stage = recovery_args(
        &c,
        "renewal-stage",
        "grant-approval.json",
        "grant-issued.json",
        "current2.json",
    );
    let mut wrong = approval.clone();
    wrong.retained.journal[0] ^= 1;
    write(&c.path.join("wrong-approval.json"), &wrong)?;
    invoke(
        &recovery_args(
            &c,
            "renewal-stage",
            "wrong-approval.json",
            "grant-issued.json",
            "current2.json",
        ),
        false,
    )?;
    let mut different_root = current.clone();
    different_root.revision += 1;
    write(&c.path.join("different-root.json"), &different_root)?;
    invoke(
        &recovery_args(
            &c,
            "renewal-stage",
            "grant-approval.json",
            "grant-issued.json",
            "different-root.json",
        ),
        false,
    )?;
    let mut forged = serde_json::to_value(&issued)?;
    forged["statement"] = serde_json::to_value([99u8; 32])?;
    write(&c.path.join("forged-grant.json"), &forged)?;
    invoke(
        &recovery_args(
            &c,
            "renewal-stage",
            "grant-approval.json",
            "forged-grant.json",
            "current2.json",
        ),
        false,
    )?;
    assert_eq!(c.call("renewal-status", &[])?["state"], "Absent");
    let pending = result(&stage)?;
    assert_eq!(pending["state"], "Pending");
    assert_eq!(result(&stage)?, pending);
    assert_eq!(c.call("renewal-status", &[])?, pending);
    let renew = recovery_args(
        &c,
        "renewal-activate",
        "grant-approval.json",
        "grant-issued.json",
        "current2.json",
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-native-device"))
        .args(&renew)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take()); // Close the actual output pipe before commit/response.
    let output = child.wait_with_output()?;
    fs::write(c.path.join("lost-response.stderr"), &output.stderr)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .to_ascii_lowercase()
        .contains("broken pipe"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    let status = c.call("renewal-status", &[])?;
    assert_eq!(status["state"], "Committed");
    assert_eq!(
        c.call(
            "renewal-reconcile-expired",
            &[
                "grant-issued.json",
                "policy-pins.json",
                "policy-materials.json"
            ]
        )?,
        status
    );

    assert_eq!(
        status["operation"],
        serde_json::json!(approval.retained.operation)
    );
    let recovered = result(&renew)?;
    assert_eq!(recovered["state"], "Active");
    assert_eq!(recovered["journal"], accepted["journal"]);
    assert_eq!(result(&renew)?, recovered);
    assert_eq!(result(&stage)?["state"], "Committed");
    assert_eq!(c.call("status", &[])?["signing_id"], accepted["signing_id"]);
    assert_eq!(fs::read(c.path.join("device/device.key"))?, signing);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    let mut publication = c.args(
        "publication-next",
        &["current2.json", "policy-pins.json", "policy-materials.json"],
    );
    publication.push("none".into());
    let id: [u8; 32] = serde_json::from_value(result(&publication)?["publication"].clone())?;
    write(
        &c.path.join("grant-plan.json"),
        &serde_json::json!({"schema":"qperiapt-native-publication-plan/1","directory":([68u8;32]),"valid_from":clock()?,"valid_until":c.start+600}),
    )?;
    private_dir(&c.path.join("grant-publication"))?;
    publication[0] = "publish".into();
    publication.extend([
        URL_SAFE_NO_PAD.encode(id).into(),
        c.path.join("grant-plan.json").into_os_string(),
        c.path.join("grant-publication").into_os_string(),
    ]);
    invoke(&publication, true)?;
    let artifact: serde_json::Value = serde_json::from_slice(&fs::read(
        c.path.join("grant-publication/publication.json"),
    )?)?;
    assert_eq!(
        URL_SAFE_NO_PAD.decode(artifact["certificate"].as_str().ok_or("certificate")?)?,
        certificate
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(artifact["roster"].as_str().ok_or("roster")?)?,
        roster.as_slice()
    );
    assert_eq!(artifact["journal"], accepted["journal"]);
    let live = pin.verify_device(&certificate, &roster, clock()?)?;
    let (pins, materials) = c.publisher.export([65; 32])?;
    let (policy, _) = pins.verify(&materials, c.invitation.family, clock()?)?;
    publication::verify(
        &URL_SAFE_NO_PAD.decode(artifact["artifact"].as_str().ok_or("artifact")?)?,
        id,
        &live,
        &policy,
        clock()?,
    )?;
    Ok(())
}

#[test]
fn actual_uncommitted_renewal_expiry_retains_exact_outcome_and_allows_new_original_request(
) -> Result<()> {
    let c = Case::open_with_validity(20)?;
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
    let request_args = |operation: [u8; 32], output: &str| {
        let mut args = c.args("renewal-request", &[]);
        args.extend([
            URL_SAFE_NO_PAD.encode(operation).into(),
            c.path.join("policy-pins.json").into_os_string(),
            c.path.join("policy-materials.json").into_os_string(),
            "none".into(),
            c.path.join(output).into_os_string(),
        ]);
        args
    };
    invoke(&request_args([116; 32], "retained-expiry.json"), true)?;
    let retained: RetainedCredentialRequest =
        serde_json::from_slice(&fs::read(c.path.join("retained-expiry.json"))?)?;
    let Recovery {
        approval, issued, ..
    } = issue_recovery(&c, retained.clone(), c.start + 25)?;
    let stage = recovery_args(
        &c,
        "renewal-stage",
        "grant-approval.json",
        "grant-issued.json",
        "current2.json",
    );
    assert_eq!(result(&stage)?["state"], "Pending");
    let reconcile = c.args(
        "renewal-reconcile-expired",
        &[
            "grant-issued.json",
            "policy-pins.json",
            "policy-materials.json",
        ],
    );
    invoke(&reconcile, false)?; // A still-live pending target is not abandonment evidence.
    assert_eq!(c.call("renewal-status", &[])?["state"], "Pending");
    let limit = Instant::now() + Duration::from_secs(35);
    while clock()? < c.start + 25 {
        if Instant::now() >= limit {
            return Err("Target expiry did not occur within bound".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut wrong = serde_json::to_value(&issued)?;
    wrong["journal"] = serde_json::to_value([99u8; 32])?;
    write(&c.path.join("wrong-expiry-journal.json"), &wrong)?;
    invoke(
        &c.args(
            "renewal-reconcile-expired",
            &[
                "wrong-expiry-journal.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        ),
        false,
    )?;
    wrong["journal"] = serde_json::to_value(issued.journal)?;
    wrong["statement"] = serde_json::to_value([99u8; 32])?;
    write(&c.path.join("wrong-expiry-statement.json"), &wrong)?;
    invoke(
        &c.args(
            "renewal-reconcile-expired",
            &[
                "wrong-expiry-statement.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        ),
        false,
    )?;
    assert_eq!(c.call("renewal-status", &[])?["state"], "Pending");
    // The unchanged-policy SDK path still requires the original signer.
    fs::rename(
        c.path.join("device/device.key"),
        c.path.join("preserved-device.key"),
    )?;
    invoke(&reconcile, false)?;
    fs::rename(
        c.path.join("preserved-device.key"),
        c.path.join("device/device.key"),
    )?;
    let resolved = result(&reconcile)?;
    assert_eq!(resolved["state"], "ExpiredUncommitted");
    assert_eq!(
        resolved["operation"],
        serde_json::json!(approval.retained.operation)
    );
    assert_eq!(resolved["statement"], serde_json::json!(issued.statement));
    assert_eq!(
        resolved["observed_head"],
        serde_json::to_value(retained.previous_checkpoint)?
    );
    assert!(resolved["observed_at"].as_u64().ok_or("time")? >= c.start + 25);
    assert_eq!(result(&reconcile)?, resolved);
    assert_eq!(c.call("renewal-status", &[])?, resolved);
    invoke(&stage, false)?;
    assert_eq!(c.call("renewal-status", &[])?, resolved);
    invoke(&request_args([117; 32], "retained-next.json"), true)?;
    let next: RetainedCredentialRequest =
        serde_json::from_slice(&fs::read(c.path.join("retained-next.json"))?)?;
    assert_eq!(next.journal, retained.journal);
    assert_eq!(next.original_owner, retained.original_owner);
    assert_eq!(next.previous_checkpoint, retained.previous_checkpoint);
    assert_eq!(next.previous_certificate, retained.previous_certificate);
    assert_eq!(c.call("status", &[])?["journal"], accepted["journal"]);
    assert!(c.path.join("device/device.key").exists());
    assert!(!c.path.join("preserved-device.key").exists());
    Ok(())
}
