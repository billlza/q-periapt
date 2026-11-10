// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real CLI/state/OS time, separately selected account, publisher and witness.
use super::*;
use super::{
    replacement::{witness_args, witness_call},
    roster::Refresh,
};
use q_periapt_continuity_reference_app::{
    policy_renewal::{witness::Preparation, Request as PolicyRequest},
    witness::{Pin, PolicyRenewalTrust},
};
use std::{process::Stdio, thread, time::Duration};

#[path = "policy_witness_credential.rs"]
mod credential;

struct Update {
    r: Refresh,
    request: PolicyRequest,
    statement: [u8; 32],
    target: PolicyInput,
}
impl Update {
    fn new(seconds: u64) -> Result<Self> {
        let mut r = Refresh::open_with_policy_duration(seconds / 2)?;
        let c = &mut r.case;
        let mut args = c.args("policy-witness-request", &[]);
        args.extend([
            URL_SAFE_NO_PAD.encode([121; 32]).into(),
            c.path.join("original-policy.json").into_os_string(),
            r.server.address.to_string().into(),
            c.path.join("p-request.json").into_os_string(),
        ]);
        invoke(&args, true)?;
        let request: PolicyRequest =
            serde_json::from_slice(&fs::read(c.path.join("p-request.json"))?)?;
        let pin: Pin = serde_json::from_value(witness_call(&r.host, "pin", &[])?)?;
        c.publisher.issue(
            [122; 32],
            Request {
                bootstrap_mode: BootstrapMode::ReusableBoth,
                valid_from: c.start,
                valid_until: clock()? + seconds,
                send_budget: 8,
                anchor: Anchor::Required {
                    identity: pin.identity,
                    key: pin.key,
                },
            },
            clock()?,
        )?;
        c.policy_files([122; 32], "next")?;
        let (pins, materials) = c.publisher.export([122; 32])?;
        let target = PolicyInput { pins, materials };
        write(&c.path.join("target-policy.json"), &target)?;
        write(
            &c.path.join("p-selection.json"),
            &c.publisher.renewal_inputs([65; 32], [65; 32], [122; 32])?,
        )?;
        let original = r
            .policy
            .pins
            .verify_historical(&r.policy.materials, c.invitation.family)?
            .0;
        let live = target
            .pins
            .verify(&target.materials, c.invitation.family, clock()?)?
            .0;
        let identities = request.verify_identities(&c.current, clock()?)?;
        let statement = sdk::PolicyRenewalStatement::new(
            identities.scope(),
            &identities.materials(&original, &original, &live),
            clock()?,
        )?;
        let account = c.root.approve_policy_renewal(&statement)?;
        let authority = super::policy::policy_approval(c, &request, [65; 32], [122; 32])?;
        publish_private_bytes(&c.path.join("p-account.bin"), account.as_bytes())?;
        publish_private_bytes(&c.path.join("p-policy.bin"), &authority)?;
        let verified = sdk::VerifiedPolicyRenewal::verify(
            &account,
            &sdk::PolicyRenewalApproval::from_bytes(&authority)?,
            identities.scope(),
            &identities.materials(&original, &original, &live),
            clock()?,
        )?;
        Ok(Self {
            r,
            request,
            statement: verified.statement_digest(),
            target,
        })
    }
    fn stage_args(&self) -> Vec<OsString> {
        self.r.case.args(
            "policy-witness-stage",
            &[
                "p-request.json",
                "p-account.bin",
                "p-policy.bin",
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
    fn identities(&self) -> [OsString; 2] {
        [
            URL_SAFE_NO_PAD.encode(self.request.scope.operation).into(),
            URL_SAFE_NO_PAD.encode(self.statement).into(),
        ]
    }
    fn prepare(&self, output: &str) -> Vec<OsString> {
        let mut a = self.r.case.args("policy-witness-prepare", &[]);
        a.extend(self.identities());
        a.extend([
            self.r.case.path.join("p-selection.json").into_os_string(),
            self.r.server.address.to_string().into(),
            self.r.case.path.join(output).into_os_string(),
        ]);
        a
    }
    fn historical(&self, command: &str, output: Option<&str>) -> Vec<OsString> {
        let mut a = self.r.case.args(command, &[]);
        a.extend(self.identities());
        a.push(
            self.r
                .case
                .path
                .join("original-policy.json")
                .into_os_string(),
        );
        if let Some(output) = output {
            a.push(self.r.case.path.join(output).into_os_string());
        }
        a
    }
    fn operation(&self, command: &str) -> Vec<OsString> {
        let mut a = self.r.case.args(
            command,
            &[
                "p-preparation.json",
                if command == "policy-witness-commit" {
                    "p-selection.json"
                } else {
                    "original-policy.json"
                },
            ],
        );
        a.push(self.r.server.address.to_string().into());
        a
    }
    fn outcome(&self, command: &str, state: &str) -> Result<()> {
        let value: serde_json::Value =
            serde_json::from_slice(&invoke(&self.operation(command), true)?)?;
        assert_eq!(value["state"], state);
        Ok(())
    }
    fn trust(&self, p: &Preparation) -> PolicyRenewalTrust {
        PolicyRenewalTrust {
            schema: "qperiapt-witness-policy-renewal-trust/1".into(),
            account: self.r.case.current.clone(),
            device: self.r.case.invitation.device,
            generation: self.r.case.invitation.generation,
            subject: self.r.original.subject.clone(),
            proposal_binding: p.binding,
            request: self.request.clone(),
            original: self.r.policy.clone(),
            previous: self.r.policy.clone(),
            target: self.target.clone(),
        }
    }
    fn witness_args(&self, command: &str, trust: &str, p: &str) -> Vec<OsString> {
        witness_args(
            &self.r.host,
            command,
            &[&self.r.case.path.join(trust), &self.r.case.path.join(p)],
        )
    }
    fn witness(&self, command: &str) -> Result<serde_json::Value> {
        witness_call(
            &self.r.host,
            command,
            &[
                &self.r.case.path.join("p-trust.json"),
                &self.r.case.path.join("p-preparation.json"),
            ],
        )
    }
    fn activate(&self, success: bool) -> Result<serde_json::Value> {
        let mut a = self.r.case.args(
            "policy-witness-activate",
            &["current.json", "original-policy.json", "target-policy.json"],
        );
        a.push(self.r.server.address.to_string().into());
        let data = invoke(&a, success)?;
        if success {
            Ok(serde_json::from_slice(&data)?)
        } else {
            Ok(serde_json::Value::String(String::from_utf8(data)?))
        }
    }
}

#[test]
fn witnessed_policy_cli_preserves_original_proposal_and_recovers_lost_operator_and_commit_output(
) -> Result<()> {
    let mut u = Update::new(2400)?;
    let c = &u.r.case;
    let before = c.call("status", &[])?;
    let keys = [c.path.join("wrap.key"), c.path.join("device/device.key")]
        .map(|p| fs::read(&p).map(|b| (p, zeroize::Zeroizing::new(b))))
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut bad = fs::read(c.path.join("p-account.bin"))?;
    *bad.last_mut().ok_or("signature")? ^= 1;
    publish_private_bytes(&c.path.join("bad-account.bin"), &bad)?;
    let mut args = u.stage_args();
    args[6] = c.path.join("bad-account.bin").into_os_string();
    invoke(&args, false)?;
    assert_eq!(c.call("policy-status", &[])?["state"], "Absent");
    invoke(&u.stage_args(), true)?;
    publish_private_bytes(&c.path.join("occupied.json"), b"preserve original export")?;
    invoke(&u.prepare("occupied.json"), false)?;
    assert_eq!(
        fs::read(c.path.join("occupied.json"))?,
        b"preserve original export"
    );
    assert_eq!(c.call("policy-witness-status", &[])?["state"], "Reserved");
    invoke(
        &u.historical(
            "policy-witness-recover-preparation",
            Some("p-preparation.json"),
        ),
        true,
    )?;
    invoke(&u.prepare("p-retry.json"), true)?;
    let bytes = fs::read(c.path.join("p-preparation.json"))?;
    assert_eq!(bytes, fs::read(c.path.join("p-retry.json"))?);
    let p: Preparation = serde_json::from_slice(&bytes)?;
    let mut wrong = u.historical("policy-witness-recover-preparation", Some("wrong.json"));
    wrong[6] = URL_SAFE_NO_PAD.encode([99; 32]).into();
    invoke(&wrong, false)?;
    invoke(
        &u.historical("policy-witness-abandon-unprepared", None),
        false,
    )?;
    u.outcome("policy-witness-commit", "Unavailable")?;
    u.activate(false)?;
    let trust = u.trust(&p);
    write(&c.path.join("p-trust.json"), &trust)?;
    for (name, changed) in [
        ("device", {
            let mut t = trust.clone();
            t.device[0] ^= 1;
            t
        }),
        ("binding", {
            let mut t = trust.clone();
            t.proposal_binding[0] ^= 1;
            t
        }),
        ("subject", {
            let mut t = trust.clone();
            t.subject[0] ^= 1;
            t
        }),
    ] {
        let file = format!("bad-{name}.json");
        write(&c.path.join(&file), &changed)?;
        let out = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
            .args(u.witness_args("policy-prepare", &file, "p-preparation.json"))
            .output()?;
        assert!(!out.status.success());
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(u.witness_args("policy-prepare", "p-trust.json", "p-preparation.json"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let lost = child.wait_with_output()?;
    assert!(!lost.status.success());
    assert!(String::from_utf8_lossy(&lost.stderr)
        .to_ascii_lowercase()
        .contains("broken pipe"));
    assert_eq!(u.witness("policy-prepare")?["state"], "Prepared");
    super::policy::lose_response(
        c,
        &u.operation("policy-witness-commit"),
        "p-lost-commit.stderr",
    )?;
    u.outcome("policy-witness-observe", "Applied")?;
    let status = c.call("policy-witness-status", &[])?;
    assert_eq!(status["state"], "Applied");
    assert_eq!(status["retired"], true);
    assert_eq!(u.activate(true)?["journal"], before["journal"]);
    // A changed complete proposal must fail even though operation/statement match.
    let mut changed = p.clone();
    *changed.proposal.last_mut().ok_or("proposal")? ^= 1;
    changed.binding =
        sdk::AnchorPolicyRenewalProposal::from_trusted_state(&changed.proposal)?.binding();
    write(&c.path.join("changed-preparation.json"), &changed)?;
    let mut observe = u.operation("policy-witness-observe");
    observe[5] = c.path.join("changed-preparation.json").into_os_string();
    invoke(&observe, false)?;
    u.outcome("policy-witness-close", "Applied")?;
    for (path, bytes) in keys {
        let observed = zeroize::Zeroizing::new(fs::read(path)?);
        assert!(observed == bytes, "original key file changed");
    }
    u.r.server.close()?;
    Ok(())
}

#[test]
fn witnessed_policy_cli_expired_target_uses_historical_closure_without_activation() -> Result<()> {
    let mut u = Update::new(20)?;
    invoke(&u.stage_args(), true)?;
    invoke(&u.prepare("p-preparation.json"), true)?;
    let p: Preparation =
        serde_json::from_slice(&fs::read(u.r.case.path.join("p-preparation.json"))?)?;
    write(&u.r.case.path.join("p-trust.json"), &u.trust(&p))?;
    assert_eq!(u.witness("policy-prepare")?["state"], "Prepared");
    let target = u
        .target
        .pins
        .verify_historical(&u.target.materials, u.r.case.invitation.family)?
        .0;
    while clock()? <= target.validity().until() {
        thread::sleep(Duration::from_millis(100));
    }
    invoke(&u.operation("policy-witness-commit"), false)?;
    u.activate(false)?;
    u.outcome("policy-witness-observe", "Prepared")?;
    assert_eq!(u.witness("policy-close")?["state"], "Closed");
    u.outcome("policy-witness-observe", "Closed")?;
    let status = u.r.case.call("policy-witness-status", &[])?;
    assert_eq!(status["state"], "Closed");
    assert_eq!(status["retired"], true);
    u.r.server.close()?;
    Ok(())
}

#[test]
fn witnessed_policy_cli_abandons_unprepared_exact_approval_offline_without_signer() -> Result<()> {
    let mut u = Update::new(2400)?;
    invoke(&u.stage_args(), true)?;
    let value: serde_json::Value = serde_json::from_slice(&invoke(
        &u.historical("policy-witness-recover-preparation", Some("absent.json")),
        true,
    )?)?;
    assert_eq!(value["state"], "NoLocalPreparation");
    assert!(!u.r.case.path.join("absent.json").exists());
    u.r.server.close()?;
    let key = u.r.case.path.join("device/device.key");
    let preserved = u.r.case.path.join("device/original-key.retained");
    fs::rename(&key, &preserved)?;
    let status = u.historical("policy-witness-abandon-unprepared", None);
    let first: serde_json::Value = serde_json::from_slice(&invoke(&status, true)?)?;
    assert_eq!(first["state"], "AbandonedBeforePreparation");
    assert_eq!(
        first,
        serde_json::from_slice::<serde_json::Value>(&invoke(&status, true)?)?
    );
    assert_eq!(first, u.r.case.call("policy-witness-status", &[])?);
    fs::rename(preserved, key)?;
    Ok(())
}
