// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual CLI subprocesses and current OS time; authority is an explicit test root.
#![cfg(unix)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::*, native_device::clock, policy_publisher::*, sdk_inputs,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
#[path = "native_device/publication.rs"]
mod publication;
#[path = "native_device/recovery.rs"]
mod recovery;
#[path = "native_device/renewal.rs"]
mod renewal;
#[path = "../src/test_support.rs"]
mod test_support;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn write<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    publish_private_bytes(path, &serde_json::to_vec(value)?)?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn invoke(args: &[OsString], success: bool) -> Result<Vec<u8>> {
    let output = Command::new(env!("CARGO_BIN_EXE_q-periapt-native-device"))
        .args(args)
        .output()?;
    assert_eq!(
        output.status.success(),
        success,
        "native command {:?}: {}",
        args.first(),
        String::from_utf8_lossy(&output.stderr)
    );
    if success {
        assert!(
            output.stderr.is_empty(),
            "unexpected diagnostics: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(if success {
        output.stdout
    } else {
        output.stderr
    })
}
struct Case {
    path: PathBuf,
    root: sdk::RootSigningKey,
    invitation: Invitation,
    publisher: Publisher,
    issued: IssuedEnrollment,
    current: RootInfo,
    start: u64,
}
impl Case {
    fn args(&self, command: &str, tail: &[&str]) -> Vec<OsString> {
        let mut args = vec![
            command.into(),
            self.path.join("device").into_os_string(),
            self.path.join("wrap.key").into_os_string(),
            self.path.join("invitation.json").into_os_string(),
        ];
        args.extend(
            tail.iter()
                .map(|name| self.path.join(name).into_os_string()),
        );
        args
    }
    fn call(&self, command: &str, tail: &[&str]) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&invoke(
            &self.args(command, tail),
            true,
        )?)?)
    }
    fn policy_files(&self, operation: [u8; 32], prefix: &str) -> Result<()> {
        let (pins, materials) = self.publisher.export(operation)?;
        write(&self.path.join(format!("{prefix}-pins.json")), &pins)?;
        write(
            &self.path.join(format!("{prefix}-materials.json")),
            &materials,
        )
    }
    fn open() -> Result<Self> {
        Self::open_with_validity(1200)
    }
    fn open_with_validity(seconds: u64) -> Result<Self> {
        let path = tempfile::tempdir()?.keep().canonicalize()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        eprintln!(
            "Native device CLI private fixture retained: {}",
            path.display()
        );
        private_dir(&path.join("device"))?;
        let mut publisher = Publisher::provision(
            &path.join("publisher.redb"),
            [60; 32],
            test_support::sdk_input()?,
        )?;
        let authority = publisher.prepare()?;
        let root = sdk::RootSigningKey::generate()?;
        let start = clock()?;
        let invitation = Invitation {
            operation: [61; 32],
            request_id: [62; 32],
            application: [63; 32],
            root_revision: 1,
            root: root.public_key()?.encode().to_vec(),
            family: authority.family,
            device: [64; 16],
            generation: 1,
            valid_from: start,
            valid_until: start + seconds,
            deadline: start + seconds.min(600),
            predecessor: None,
        };
        write(&path.join("invitation.json"), &invitation)?;
        invoke(
            &[
                "provision-key".into(),
                path.join("wrap.key").into_os_string(),
            ],
            true,
        )?;
        let common = |command: &str| {
            vec![
                command.into(),
                path.join("device").into_os_string(),
                path.join("wrap.key").into_os_string(),
                path.join("invitation.json").into_os_string(),
            ]
        };
        let status: serde_json::Value = serde_json::from_slice(&invoke(&common("begin"), true)?)?;
        assert_eq!(status["persisted_phase"], "Preparing");
        let mut request_args = common("request");
        request_args.push(path.join("request.bin").into_os_string());
        invoke(&request_args, true)?;
        let request = sdk::VerifiedEnrollmentRequest::verify(
            &fs::read(path.join("request.bin"))?,
            &invitation.intent()?,
            clock()?,
        )?;
        let certificate = root.issue_enrollment(&request, clock()?)?;
        let roster = root.issue_roster(
            1,
            sdk::Validity::new(start, start + 2400)?,
            &[root.roster_entry(&certificate)?],
        )?;
        let issued = IssuedEnrollment {
            operation: invitation.operation,
            root_revision: 1,
            certificate,
            roster: roster.as_bytes().to_vec(),
            checkpoint: roster.checkpoint().into(),
        };
        let current = RootInfo {
            revision: 1,
            account: root.account_id()?,
            public_key: root.public_key()?.encode().to_vec(),
            family: authority.family,
            suspended: false,
            roster: Some(RosterSnapshot {
                checkpoint: issued.checkpoint,
                bytes: issued.roster.clone(),
            }),
        };
        publisher.issue(
            [65; 32],
            Request {
                bootstrap_mode: BootstrapMode::ReusableBoth,
                valid_from: start,
                valid_until: start + 2400,
                send_budget: 8,
                anchor: Anchor::LocalOnly {},
            },
            clock()?,
        )?;
        let c = Self {
            path,
            root,
            invitation,
            publisher,
            issued,
            current,
            start,
        };
        write(&c.path.join("issued.json"), &c.issued)?;
        write(&c.path.join("current.json"), &c.current)?;
        c.policy_files([65; 32], "policy")?;
        Ok(c)
    }
    fn accept(&self) -> Result<serde_json::Value> {
        self.call(
            "accept",
            &[
                "issued.json",
                "current.json",
                "policy-pins.json",
                "policy-materials.json",
            ],
        )
    }
}

#[test]
fn real_cli_adopts_extension_refreshes_unprepared_roster_and_publishes_original_artifact(
) -> Result<()> {
    let mut c = Case::open()?;
    let accepted = c.accept()?;
    assert_eq!(accepted["persisted_phase"], "Accepted");
    invoke(&c.args("begin", &[]), false)?;
    let pin = sdk::AccountPin::new(
        c.current.account,
        c.root.public_key()?,
        c.issued.checkpoint.as_sdk()?,
        c.invitation.family,
    )?;
    let original = pin.verify_device(&c.issued.certificate, &c.issued.roster, clock()?)?;
    let certificate = c
        .root
        .issue_credential_extension(&original, c.start + 1800, clock()?)?;
    let roster = c.root.issue_roster(
        2,
        sdk::Validity::new(c.start, c.start + 2400)?,
        &[c.root.roster_entry(&certificate)?],
    )?;
    let approval = CredentialExtensionRequest {
        request_id: [66; 32],
        enrollment: c.invitation.operation,
        previous_extension: None,
        predecessor: c.issued.checkpoint,
        valid_until: c.start + 1800,
    };
    let extended = IssuedCredentialExtension {
        request: approval.clone(),
        root_revision: 1,
        certificate: certificate.clone(),
        roster: roster.as_bytes().to_vec(),
        checkpoint: roster.checkpoint().into(),
    };
    let mut current = c.current.clone();
    current.roster = Some(RosterSnapshot {
        checkpoint: extended.checkpoint,
        bytes: extended.roster.clone(),
    });
    c.publisher.issue(
        [67; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: c.start,
            valid_until: c.start + 3600,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        clock()?,
    )?;
    c.policy_files([67; 32], "policy2")?;
    write(&c.path.join("approval.json"), &approval)?;
    write(&c.path.join("extension.json"), &extended)?;
    write(&c.path.join("current2.json"), &current)?;
    let target = c.call(
        "extend",
        &[
            "approval.json",
            "extension.json",
            "current2.json",
            "policy2-pins.json",
            "policy2-materials.json",
        ],
    )?;
    assert_eq!(target["signing_id"], accepted["signing_id"]);
    assert_eq!(target["journal"], accepted["journal"]);
    let roster = c.root.issue_roster(
        3,
        sdk::Validity::new(c.start, c.start + 2400)?,
        &[c.root.roster_entry(&certificate)?],
    )?;
    current.roster = Some(RosterSnapshot {
        checkpoint: roster.checkpoint().into(),
        bytes: roster.as_bytes().to_vec(),
    });
    write(&c.path.join("current3.json"), &current)?;
    c.call(
        "prepare",
        &[
            "current3.json",
            "policy2-pins.json",
            "policy2-materials.json",
        ],
    )?;
    let mut args = c.args(
        "publication-next",
        &[
            "current3.json",
            "policy2-pins.json",
            "policy2-materials.json",
        ],
    );
    args.push("none".into());
    let id: serde_json::Value = serde_json::from_slice(&invoke(&args, true)?)?;
    let identity: [u8; 32] = serde_json::from_value(id["publication"].clone())?;
    write(
        &c.path.join("plan.json"),
        &serde_json::json!({"schema":"qperiapt-native-publication-plan/1","directory":vec![68u8;32],"valid_from":c.start,"valid_until":c.start+600}),
    )?;
    for output in ["export1", "export2"] {
        private_dir(&c.path.join(output))?;
        let mut args = c.args(
            "publish",
            &[
                "current3.json",
                "policy2-pins.json",
                "policy2-materials.json",
            ],
        );
        args.extend([
            "none".into(),
            URL_SAFE_NO_PAD.encode(identity).into(),
            c.path.join("plan.json").into_os_string(),
            c.path.join(output).into_os_string(),
        ]);
        invoke(&args, true)?;
    }
    let first = fs::read(c.path.join("export1/publication.json"))?;
    assert_eq!(first, fs::read(c.path.join("export2/publication.json"))?);
    let public: serde_json::Value = serde_json::from_slice(&first)?;
    assert_eq!(public["schema"], "qperiapt-native-publication/1");
    assert_eq!(public["journal"], accepted["journal"]);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(public["certificate"].as_str().ok_or("certificate")?)?,
        certificate
    );
    let artifact = URL_SAFE_NO_PAD.decode(public["artifact"].as_str().ok_or("artifact")?)?;
    assert_eq!(public["checkpoint"]["version"], 3);
    let pin = sdk::AccountPin::new(
        current.account,
        c.root.public_key()?,
        roster.checkpoint(),
        c.invitation.family,
    )?;
    let device = pin.verify_device(
        &URL_SAFE_NO_PAD.decode(public["certificate"].as_str().ok_or("certificate")?)?,
        &URL_SAFE_NO_PAD.decode(public["roster"].as_str().ok_or("roster")?)?,
        clock()?,
    )?;
    let (pins, materials) = c.publisher.export([67; 32])?;
    let (policy, _) = pins.verify(&materials, c.invitation.family, clock()?)?;
    publication::verify(&artifact, identity, &device, &policy, clock()?)?;
    // A well-framed output still fails when its signed manifest or a Merkle
    // proof is changed. This checks the file readback, not in-memory objects.
    for offset in [108, artifact.len() - 1] {
        let mut tampered = artifact.clone();
        tampered[offset] ^= 1;
        assert!(publication::verify(&tampered, identity, &device, &policy, clock()?).is_err());
    }
    assert_eq!(c.call("status", &[])?["persisted_phase"], "Active");
    Ok(())
}

#[test]
fn real_cli_refuses_expired_policy_and_missing_signer_without_replacing_original_state(
) -> Result<()> {
    let mut c = Case::open()?;
    c.publisher.issue(
        [70; 32],
        Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: c.start - 120,
            valid_until: c.start - 60,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        },
        c.start - 90,
    )?;
    c.policy_files([70; 32], "expired")?;
    let failed = invoke(
        &c.args(
            "accept",
            &[
                "issued.json",
                "current.json",
                "expired-pins.json",
                "expired-materials.json",
            ],
        ),
        false,
    )?;
    assert!(String::from_utf8(failed)?.contains("Current protocol policy"));
    assert_eq!(c.call("status", &[])?["persisted_phase"], "Requested");
    c.call("request", &["request-retry.bin"])?;
    assert_eq!(
        fs::read(c.path.join("request.bin"))?,
        fs::read(c.path.join("request-retry.bin"))?
    );
    c.accept()?;
    fs::rename(
        c.path.join("device/device.key"),
        c.path.join("device/device.retained"),
    )?;
    invoke(
        &c.args(
            "prepare",
            &["current.json", "policy-pins.json", "policy-materials.json"],
        ),
        false,
    )?;
    assert_eq!(c.call("status", &[])?["persisted_phase"], "Accepted");
    assert!(!c.path.join("device/device.key").exists());
    assert!(c.path.join("device/device.retained").exists());
    Ok(())
}

#[test]
fn malformed_publication_inputs_do_not_select_an_unprepared_installation() -> Result<()> {
    for invalid_id in [true, false] {
        let c = Case::open()?;
        let before = c.accept()?;
        private_dir(&c.path.join("rejected-export"))?;
        let schema = if invalid_id {
            "qperiapt-native-publication-plan/1"
        } else {
            "unknown"
        };
        write(
            &c.path.join("bad-plan.json"),
            &serde_json::json!({"schema":schema,"directory":vec![71u8;32],"valid_from":c.start,"valid_until":c.start+600}),
        )?;
        let mut args = c.args(
            "publish",
            &["current.json", "policy-pins.json", "policy-materials.json"],
        );
        args.extend([
            "none".into(),
            if invalid_id {
                "invalid!".into()
            } else {
                URL_SAFE_NO_PAD.encode([72u8; 32]).into()
            },
            c.path.join("bad-plan.json").into_os_string(),
            c.path.join("rejected-export").into_os_string(),
        ]);
        invoke(&args, false)?;
        assert_eq!(
            c.call("status", &[])?,
            before,
            "invalid input selected an installation"
        );
        assert!(fs::read_dir(c.path.join("rejected-export"))?
            .next()
            .is_none());
    }
    Ok(())
}
