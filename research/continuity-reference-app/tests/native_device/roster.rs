// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual native/operator CLIs, original private stores and signed TCP recovery.
use super::replacement::{trust, witness_args, witness_call, HostServer};
use super::*;
use q_periapt_continuity_reference_app::{
    roster_refresh::Request as RosterRequest,
    witness::{EnrollmentRequest, Pin, RosterRefreshTrust},
};
use std::{process::Stdio, thread, time::Duration};

pub(super) struct Refresh {
    pub(super) case: Case,
    pub(super) host: PathBuf,
    pub(super) server: HostServer,
    pub(super) original: EnrollmentRequest,
    pub(super) policy: PolicyInput,
}
impl Refresh {
    pub(super) fn open() -> Result<Self> {
        Self::open_with_policy_duration(2400)
    }
    pub(super) fn open_with_policy_duration(policy_seconds: u64) -> Result<Self> {
        let host = tempfile::tempdir()?.keep().canonicalize()?;
        fs::set_permissions(&host, fs::Permissions::from_mode(0o700))?;
        eprintln!("Roster CLI witness fixture retained: {}", host.display());
        let pin: Pin = serde_json::from_value(witness_call(&host, "init", &[])?)?;
        let case = Case::open_with_anchor(1200, policy_seconds, Some(&pin.as_sdk()?))?;
        case.accept()?;
        let original: EnrollmentRequest = serde_json::from_value(case.call(
            "prepare",
            &["current.json", "policy-pins.json", "policy-materials.json"],
        )?)?;
        let (pins, materials) = case.publisher.export([65; 32])?;
        let policy = PolicyInput { pins, materials };
        write(&case.path.join("original-policy.json"), &policy)?;
        write(&case.path.join("enroll.json"), &original)?;
        write(
            &case.path.join("enroll-trust.json"),
            &trust(
                case.current.clone(),
                &case.invitation,
                &case.issued,
                &original,
                policy.clone(),
            )?,
        )?;
        witness_call(
            &host,
            "enroll",
            &[
                &case.path.join("enroll-trust.json"),
                &case.path.join("enroll.json"),
            ],
        )?;
        let server = HostServer::start(host.clone())?;
        let value = Self {
            case,
            host,
            server,
            original,
            policy,
        };
        value.activate("current.json", true)?;
        assert_eq!(value.case.call("roster-status", &[])?["state"], "Absent");
        Ok(value)
    }
    fn target(&self, version: u64, expiry: u64, name: &str) -> Result<RootInfo> {
        let roster = self.case.root.issue_roster(
            version,
            sdk::Validity::new(self.case.start, expiry)?,
            &[self.case.root.roster_entry(&self.case.issued.certificate)?],
        )?;
        let mut target = self.case.current.clone();
        target.roster = Some(RosterSnapshot {
            checkpoint: roster.checkpoint().into(),
            bytes: roster.as_bytes().to_vec(),
        });
        write(&self.case.path.join(format!("{name}-root.json")), &target)?;
        write(
            &self.case.path.join(format!("{name}-inputs.json")),
            &serde_json::json!({
                "schema":"qperiapt-roster-refresh-inputs/1", "target":target,
                "original":self.policy, "policy":self.policy
            }),
        )?;
        Ok(target)
    }
    fn activate(&self, root: &str, success: bool) -> Result<Vec<u8>> {
        let mut args = self.case.args(
            "activate",
            &[root, "policy-pins.json", "policy-materials.json"],
        );
        args.push(self.server.address.to_string().into());
        invoke(&args, success)
    }
    fn prepare_args(&self, operation: u8, target: &str, output: &str) -> Vec<OsString> {
        let mut args = self.case.args("roster-prepare", &[]);
        args.extend([
            URL_SAFE_NO_PAD.encode([operation; 32]).into(),
            self.case.path.join(target).into_os_string(),
            self.server.address.to_string().into(),
            self.case.path.join(output).into_os_string(),
        ]);
        args
    }
    fn operation_args(&self, command: &str, policy: &str) -> Vec<OsString> {
        let mut args = self.case.args(command, &["request.json", policy]);
        args.push(self.server.address.to_string().into());
        args
    }
    fn outcome(&self, command: &str, policy: &str, expected: &str) -> Result<()> {
        let value: serde_json::Value =
            serde_json::from_slice(&invoke(&self.operation_args(command, policy), true)?)?;
        assert_eq!(value["state"], expected);
        Ok(())
    }
    fn operator(&self, target: RootInfo, request: &RosterRequest) -> Result<()> {
        // Controller independently selects its own original enrollment and the
        // exact signed target/binding; the witness never derives these from input.
        write(
            &self.case.path.join("trust.json"),
            &RosterRefreshTrust {
                schema: "qperiapt-witness-roster-refresh-trust/1".into(),
                account: target,
                device: self.case.invitation.device,
                generation: self.case.invitation.generation,
                subject: self.original.subject.clone(),
                proposal_binding: request.binding,
                policy: self.policy.clone(),
            },
        )
    }
    fn witness(&self, command: &str) -> Result<serde_json::Value> {
        witness_call(
            &self.host,
            command,
            &[
                &self.case.path.join("trust.json"),
                &self.case.path.join("request.json"),
            ],
        )
    }
}

#[test]
fn roster_cli_recovers_export_failure_unapproved_target_and_lost_commit_output() -> Result<()> {
    let mut r = Refresh::open()?;
    let c = &r.case;
    let target = r.target(2, c.start + 1200, "next")?;
    let original_status = c.call("status", &[])?;
    let keys = [c.path.join("wrap.key"), c.path.join("device/device.key")]
        .map(|p| fs::read(&p).map(|bytes| (p, bytes)))
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()?;
    invoke(
        &c.args(
            "refresh-roster",
            &[
                "next-root.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        ),
        false,
    )?;
    r.activate("next-root.json", false)?;
    publish_private_bytes(&c.path.join("occupied.json"), b"retain me")?;
    invoke(
        &r.prepare_args(81, "next-inputs.json", "occupied.json"),
        false,
    )?;
    assert_eq!(fs::read(c.path.join("occupied.json"))?, b"retain me");
    assert_eq!(c.call("roster-status", &[])?["state"], "Reserved");
    let mut recover = c.args("roster-recover-preparation", &[]);
    recover.extend([
        URL_SAFE_NO_PAD.encode([81; 32]).into(),
        c.path.join("original-policy.json").into_os_string(),
        c.path.join("request.json").into_os_string(),
    ]);
    invoke(&recover, true)?;
    let request: RosterRequest = serde_json::from_slice(&fs::read(c.path.join("request.json"))?)?;
    invoke(&r.prepare_args(81, "next-inputs.json", "retry.json"), true)?;
    assert_eq!(
        fs::read(c.path.join("request.json"))?,
        fs::read(c.path.join("retry.json"))?
    );
    r.target(3, c.start + 1200, "different")?;
    invoke(
        &r.prepare_args(81, "different-inputs.json", "retarget.json"),
        false,
    )?;
    let mut wrong = recover.clone();
    wrong[5] = URL_SAFE_NO_PAD.encode([82; 32]).into();
    invoke(&wrong, false)?;
    let mut abandon = c.args("roster-abandon-unprepared", &[]);
    abandon.extend([
        URL_SAFE_NO_PAD.encode([81; 32]).into(),
        c.path.join("original-policy.json").into_os_string(),
    ]);
    invoke(&abandon, false)?;
    r.outcome("roster-commit", "next-inputs.json", "Unavailable")?;
    r.activate("current.json", false)?;
    r.activate("next-root.json", false)?;
    r.operator(target, &request)?;
    let mut bad = request.clone();
    bad.binding[0] ^= 1;
    write(&c.path.join("bad-request.json"), &bad)?;
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-continuity-witness"))
        .args(witness_args(
            &r.host,
            "roster-prepare",
            &[&c.path.join("trust.json"), &c.path.join("bad-request.json")],
        ))
        .output()?;
    assert!(!output.status.success());
    assert_eq!(r.witness("roster-prepare")?["state"], "Prepared");
    assert_eq!(r.witness("roster-prepare")?["state"], "Prepared");
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-native-device"))
        .args(r.operation_args("roster-commit", "next-inputs.json"))
        .stdout(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    r.outcome("roster-observe", "original-policy.json", "Applied")?;
    let progress = c.call("roster-status", &[])?;
    assert_eq!(progress["state"], "Applied");
    assert_eq!(progress["retired"], true);
    r.activate("next-root.json", true)?;
    r.activate("current.json", false)?;
    assert_eq!(
        c.call("status", &[])?["journal"],
        original_status["journal"]
    );
    for (path, bytes) in keys {
        assert_eq!(fs::read(path)?, bytes);
    }
    // Closing exact retired history never changes a committed result to Closed.
    r.outcome("roster-close", "original-policy.json", "Applied")?;
    r.server.close()?;
    Ok(())
}

#[test]
fn roster_cli_closes_expired_prepared_target_without_fresh_permission() -> Result<()> {
    let mut r = Refresh::open()?;
    let expiry = clock()? + 20;
    let target = r.target(2, expiry, "next")?;
    invoke(
        &r.prepare_args(83, "next-inputs.json", "request.json"),
        true,
    )?;
    let request: RosterRequest =
        serde_json::from_slice(&fs::read(r.case.path.join("request.json"))?)?;
    r.operator(target, &request)?;
    assert_eq!(r.witness("roster-prepare")?["state"], "Prepared");
    while clock()? <= expiry {
        thread::sleep(Duration::from_millis(100));
    }
    invoke(
        &r.operation_args("roster-commit", "next-inputs.json"),
        false,
    )?;
    r.outcome("roster-observe", "original-policy.json", "Prepared")?;
    assert_eq!(r.witness("roster-close")?["state"], "Closed");
    r.outcome("roster-observe", "original-policy.json", "Closed")?;
    let progress = r.case.call("roster-status", &[])?;
    assert_eq!(progress["state"], "Closed");
    assert_eq!(progress["retired"], true);
    r.activate("next-root.json", false)?;
    r.activate("current.json", true)?;
    r.server.close()?;
    Ok(())
}
