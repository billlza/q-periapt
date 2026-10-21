// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original witness operator G, exact retries and G after independent P.
use super::*;
use crate::recovery::{issue_recovery, recovery_args};
use q_periapt_continuity_reference_app::{
    credential_grant::witness::Preparation as CredentialPreparation,
    native_device::RetainedCredentialRequest,
    witness::{CredentialPolicy, CredentialRenewalTrust},
};

struct Renewal {
    trust: CredentialRenewalTrust,
    preparation: CredentialPreparation,
    activate: Vec<OsString>,
}

fn adopt(u: &Update) -> Result<()> {
    invoke(&u.stage_args(), true)?;
    invoke(&u.prepare("p-preparation.json"), true)?;
    let p = serde_json::from_slice(&fs::read(u.r.case.path.join("p-preparation.json"))?)?;
    write(&u.r.case.path.join("p-trust.json"), &u.trust(&p))?;
    assert_eq!(u.witness("policy-prepare")?["state"], "Prepared");
    u.outcome("policy-witness-commit", "Applied")?;
    u.activate(true)?;
    Ok(())
}

fn prepare(u: &Update, independent: bool) -> Result<Renewal> {
    let c = &u.r.case;
    let mut request = c.args("renewal-request", &[]);
    request.extend([
        URL_SAFE_NO_PAD.encode([130; 32]).into(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        u.r.server.address.to_string().into(),
        c.path.join("g-request.json").into_os_string(),
    ]);
    invoke(&request, true)?;
    let retained: RetainedCredentialRequest =
        serde_json::from_slice(&fs::read(c.path.join("g-request.json"))?)?;
    let recovery = issue_recovery(c, retained, c.start + 1500)?;
    let mut args = recovery_args(
        c,
        "renewal-stage",
        "grant-approval.json",
        "grant-issued.json",
        "current2.json",
    );
    if independent {
        args[9] = c.path.join("next-pins.json").into_os_string();
        args[10] = c.path.join("next-materials.json").into_os_string();
    }
    *args.last_mut().ok_or("endpoint")? = u.r.server.address.to_string().into();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&args, true)?)?["state"],
        "Pending"
    );
    args[0] = "renewal-witness-prepare".into();
    args.push(c.path.join("occupied-g.json").into_os_string());
    publish_private_bytes(&c.path.join("occupied-g.json"), b"retain original output")?;
    invoke(&args, false)?;
    assert_eq!(
        fs::read(c.path.join("occupied-g.json"))?,
        b"retain original output"
    );
    *args.last_mut().ok_or("output")? = c.path.join("g-preparation.json").into_os_string();
    invoke(&args, true)?;
    *args.last_mut().ok_or("output")? = c.path.join("g-retry.json").into_os_string();
    invoke(&args, true)?;
    let bytes = fs::read(c.path.join("g-preparation.json"))?;
    assert_eq!(bytes, fs::read(c.path.join("g-retry.json"))?);
    let preparation: CredentialPreparation = serde_json::from_slice(&bytes)?;
    let proposal = preparation.as_proposal()?;
    assert_eq!(
        proposal.policy_renewal(),
        independent.then_some(u.statement)
    );
    let trust = CredentialRenewalTrust {
        schema: "qperiapt-witness-credential-renewal-trust/1".into(),
        account: recovery.current,
        enrollment: c.invitation.operation,
        operation: recovery.issued.operation,
        statement: recovery.issued.statement,
        subject: u.r.original.subject.clone(),
        proposal_binding: proposal.binding(),
        lineage: if independent {
            CredentialPolicy::Independent {
                statement: u.statement,
            }
        } else {
            CredentialPolicy::Original
        },
        original: u.r.policy.clone(),
        policy: if independent {
            u.target.clone()
        } else {
            u.r.policy.clone()
        },
    };
    write(&c.path.join("g-trust.json"), &trust)?;
    args.pop();
    args[0] = "renewal-activate".into();
    invoke(&args, false)?; // No operator approval, no activation.
    Ok(Renewal {
        trust,
        preparation,
        activate: args,
    })
}

fn operator(u: &Update, command: &str, trust: &str, preparation: &str) -> Vec<OsString> {
    witness_args(
        &u.r.host,
        command,
        &[
            &u.r.case.path.join(trust),
            &u.r.case.path.join(preparation),
            &u.r.case.path.join("grant-issued.json"),
        ],
    )
}
fn result(u: &Update, command: &str) -> Result<serde_json::Value> {
    witness_call(
        &u.r.host,
        command,
        &[
            &u.r.case.path.join("g-trust.json"),
            &u.r.case.path.join("g-preparation.json"),
            &u.r.case.path.join("grant-issued.json"),
        ],
    )
}
fn refusal(args: &[OsString]) -> Result<()> {
    let out = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(args)
        .output()?;
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
    Ok(())
}

// Device ACK retires the witness slot. Re-creating or closing that old target
// must be refused; the authenticated device journal retains its Committed result.
fn retired(u: &Update) -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(operator(
            u,
            "credential-close",
            "g-trust.json",
            "g-preparation.json",
        ))
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Protocol(Retired)"));
    Ok(())
}

#[test]
fn original_policy_credential_operator_preserves_selected_subject() -> Result<()> {
    let mut u = Update::new(2400)?;
    let g = prepare(&u, false)?;
    assert_eq!(result(&u, "credential-prepare")?["state"], "Prepared");
    invoke(&g.activate, true)?;
    retired(&u)?;
    assert_eq!(u.r.case.call("renewal-status", &[])?["state"], "Committed");
    u.r.server.close()?;
    Ok(())
}

#[test]
fn independent_policy_then_credential_operator_rejects_retarget_and_recovers_lost_results(
) -> Result<()> {
    let mut u = Update::new(2400)?;
    adopt(&u)?;
    let c = &u.r.case;
    let status = c.call("status", &[])?;
    let keys = ["wrap.key", "device/device.key"]
        .map(|name| fs::read(c.path.join(name)).map(zeroize::Zeroizing::new));
    let [wrap, key] = keys;
    let wrap = wrap?;
    let key = key?;
    let g = prepare(&u, true)?;
    for name in [
        "original-lineage",
        "other-policy",
        "subject",
        "binding",
        "roster",
    ] {
        let mut t = g.trust.clone();
        match name {
            "original-lineage" => t.lineage = CredentialPolicy::Original,
            "other-policy" => {
                t.lineage = CredentialPolicy::Independent {
                    statement: [131; 32],
                }
            }
            "subject" => t.subject[0] ^= 1,
            "binding" => t.proposal_binding[0] ^= 1,
            "roster" => {
                *t.account
                    .roster
                    .as_mut()
                    .ok_or("roster")?
                    .bytes
                    .last_mut()
                    .ok_or("signature")? ^= 1
            }
            _ => unreachable!(),
        }
        let name = format!("g-bad-{name}.json");
        write(&c.path.join(&name), &t)?;
        refusal(&operator(
            &u,
            "credential-prepare",
            &name,
            "g-preparation.json",
        ))?;
    }
    let mut changed = g.preparation.clone();
    changed.journal[0] ^= 1;
    write(&c.path.join("g-bad-preparation.json"), &changed)?;
    refusal(&operator(
        &u,
        "credential-prepare",
        "g-trust.json",
        "g-bad-preparation.json",
    ))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(operator(
            &u,
            "credential-prepare",
            "g-trust.json",
            "g-preparation.json",
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let lost = child.wait_with_output()?;
    assert!(!lost.status.success());
    assert!(String::from_utf8_lossy(&lost.stderr)
        .to_ascii_lowercase()
        .contains("broken pipe"));
    assert_eq!(result(&u, "credential-prepare")?["state"], "Prepared");
    crate::witness::lose_response(c, &g.activate, "g-lost-activation.stderr")?;
    assert_eq!(c.call("renewal-status", &[])?["state"], "Committed");
    retired(&u)?;
    let active: serde_json::Value = serde_json::from_slice(&invoke(&g.activate, true)?)?;
    assert_eq!(active["journal"], status["journal"]);
    assert_eq!(c.call("policy-witness-status", &[])?["state"], "Applied");
    assert!(
        zeroize::Zeroizing::new(fs::read(c.path.join("wrap.key"))?) == wrap,
        "wrapping key changed"
    );
    assert!(
        zeroize::Zeroizing::new(fs::read(c.path.join("device/device.key"))?) == key,
        "signing key changed"
    );
    u.r.server.close()?;
    Ok(())
}

#[test]
fn expired_independent_policy_allows_only_historical_credential_closure() -> Result<()> {
    let mut u = Update::new(20)?;
    adopt(&u)?;
    let g = prepare(&u, true)?;
    assert_eq!(result(&u, "credential-prepare")?["state"], "Prepared");
    let policy = u
        .target
        .pins
        .verify_historical(&u.target.materials, u.r.case.invitation.family)?
        .0;
    while clock()? <= policy.validity().until() {
        thread::sleep(Duration::from_millis(100));
    }
    refusal(&operator(
        &u,
        "credential-prepare",
        "g-trust.json",
        "g-preparation.json",
    ))?;
    invoke(&g.activate, false)?;
    assert_eq!(result(&u, "credential-close")?["state"], "Closed");
    assert_eq!(result(&u, "credential-close")?["state"], "Closed");
    let mut observe = u.r.case.args("renewal-witness-observe", &[]);
    observe.extend([
        URL_SAFE_NO_PAD.encode(g.trust.operation).into(),
        URL_SAFE_NO_PAD.encode(g.trust.statement).into(),
        u.r.case.path.join("policy-pins.json").into_os_string(),
        u.r.case.path.join("policy-materials.json").into_os_string(),
        u.r.server.address.to_string().into(),
    ]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invoke(&observe, true)?)?["state"],
        "Closed"
    );
    assert_eq!(
        u.r.case.call("policy-witness-status", &[])?["state"],
        "Applied"
    );
    u.r.server.close()?;
    Ok(())
}
