// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::test_support::sdk_input as input;
use std::os::unix::fs::PermissionsExt;

struct Directory(std::path::PathBuf);
impl Directory {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
fn directory() -> Result<Directory, std::io::Error> {
    let path = tempfile::tempdir()?;
    std::fs::set_permissions(path.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = path.keep().canonicalize()?;
    eprintln!(
        "Policy publisher private fixture retained: {}",
        path.display()
    );
    Ok(Directory(path))
}
fn request() -> Request {
    Request {
        bootstrap_mode: BootstrapMode::ReusableBoth,
        valid_from: 100,
        valid_until: 200,
        send_budget: 100,
        anchor: Anchor::LocalOnly {},
    }
}

#[test]
fn actual_sdk_signature_and_exact_pin_are_required() -> Result<(), Box<dyn std::error::Error>> {
    let good = input()?;
    good.verify()?;
    let mut bad = good.clone();
    bad.signature[0] ^= 1;
    assert!(bad.verify().is_err());
    let mut bad = good.clone();
    bad.state[4] ^= 1;
    assert!(bad.verify().is_err());
    let mut bad = good;
    bad.document.push(b' ');
    assert!(bad.verify().is_err());
    Ok(())
}

#[test]
fn exported_policy_consumer_requires_exact_scope_time_and_witness_pin(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    let mut publisher =
        Publisher::provision(&directory.path().join("consumer.redb"), [44; 32], input()?)?;
    let authority = publisher.prepare()?;
    publisher.issue([45; 32], request(), 150)?;
    let (pins, materials) = publisher.export([45; 32])?;
    let pins_json = serde_json::to_value(&pins)?;
    let pins: PolicyPins = serde_json::from_value(pins_json.clone())?;
    let materials: PolicyMaterials = serde_json::from_slice(&serde_json::to_vec(&materials)?)?;
    let (verified, witness) = pins.verify(&materials, authority.family, 150)?;
    assert!(witness.is_none());
    assert_eq!(verified.checkpoint().version(), 1);
    assert!(pins.verify(&materials, authority.family, 200).is_err());
    assert!(pins.verify(&materials, [9; 32], 150).is_err());
    let mut missing = pins_json.clone();
    missing.as_object_mut().ok_or("object")?.remove("witness");
    assert!(serde_json::from_value::<PolicyPins>(missing).is_err());
    let mut bad = pins_json;
    bad["sdk_state"] = serde_json::json!("AA");
    assert!(serde_json::from_value::<PolicyPins>(bad)?
        .verify(&materials, authority.family, 150)
        .is_err());
    let signer = sdk::AnchorSigningKey::generate()?;
    let identity = sdk::AnchorIdentity::generate()?;
    let mut witnessed = request();
    witnessed.anchor = Anchor::Required {
        identity: *identity.as_bytes(),
        key: signer.public_key()?.encode().to_vec(),
    };
    publisher.issue([46; 32], witnessed, 150)?;
    let (pins, materials) = publisher.export([46; 32])?;
    assert!(pins.verify(&materials, authority.family, 150)?.1.is_some());
    let mut altered = serde_json::to_value(&pins)?;
    altered["witness"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<PolicyPins>(altered)?
        .verify(&materials, authority.family, 150)
        .is_err());
    Ok(())
}

#[test]
fn original_publication_reopen_and_monotonic_versions() -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    let path = directory.path().join("publisher.redb");
    let mut owner = Publisher::provision(&path, [1; 32], input()?)?;
    let authority = owner.prepare()?;
    let first = owner.issue([2; 32], request(), 150)?;
    assert_eq!(first.version, 1);
    assert_eq!(owner.issue([2; 32], request(), 250)?, first);
    assert!(owner
        .issue(
            [2; 32],
            Request {
                send_budget: 99,
                ..request()
            },
            150
        )
        .is_err());
    drop(owner);
    let mut owner = Publisher::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    assert_eq!(owner.prepare()?.policy_root, authority.policy_root);
    let second = owner.issue([3; 32], request(), 150)?;
    assert_eq!(second.version, 2);
    assert!(owner.cancel([2; 32]).is_err());
    drop(owner);
    assert!(Publisher::open(&path, [9; 32]).is_err());
    Ok(())
}

#[test]
fn historical_result_survives_missing_signer_but_new_issuance_does_not(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    let path = directory.path().join("publisher.redb");
    let mut owner = Publisher::provision(&path, [1; 32], input()?)?;
    owner.prepare()?;
    let first = owner.issue([2; 32], request(), 150)?;
    let (wrapping, signer) = owner.paths(&owner.config()?)?;
    drop(owner);
    std::fs::rename(&signer, signer.with_extension("retained"))?;
    let mut owner = Publisher::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    assert_eq!(owner.issue([2; 32], request(), 250)?, first);
    assert!(owner.issue([3; 32], request(), 150).is_err());
    assert!(!signer.exists());
    drop(owner);
    std::fs::rename(&wrapping, wrapping.with_extension("wrap.retained"))?;
    let mut owner = Publisher::open(&path, [1; 32])?;
    assert_eq!(owner.result([2; 32])?, first);
    assert!(owner.prepare().is_err());
    assert!(!wrapping.exists() && !signer.exists());
    Ok(())
}

#[test]
fn explicit_disable_witness_separation_and_missing_choices(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    let path = directory.path().join("publisher.redb");
    let mut owner = Publisher::provision(&path, [1; 32], input()?)?;
    let authority = owner.prepare()?;
    let independent = sdk::AnchorSigningKey::generate()?.public_key()?.encode();
    let mut shared_classic = independent.clone();
    shared_classic[1952..].copy_from_slice(&authority.policy_root[1952..]);
    let mut shared_sdk = independent;
    shared_sdk[..1952].copy_from_slice(&authority.sdk_root);
    for key in [authority.policy_root.clone(), shared_classic, shared_sdk] {
        let invalid = Request {
            anchor: Anchor::Required {
                identity: [8; 32],
                key,
            },
            ..request()
        };
        assert!(owner.issue([2; 32], invalid, 150).is_err());
        assert_eq!(owner.config()?.version, 0);
    }
    let disabled = owner.issue(
        [3; 32],
        Request {
            bootstrap_mode: BootstrapMode::Disabled,
            ..request()
        },
        150,
    )?;
    let cfg = owner.config()?;
    let verified = sdk::PolicyPin::new(
        authority.family,
        sdk::PublicKey::decode(&authority.policy_root)?,
        sdk::PolicyCheckpoint::from_trusted_state(disabled.version, disabled.digest)?,
    )?
    .verify(&disabled.policy, cfg.sdk.verify()?, 150)?;
    assert!(verified
        .check_mode(sdk::PrekeyQuality::ReusableBoth, 150)
        .is_err());
    let mut value = serde_json::to_value(request())?;
    value
        .as_object_mut()
        .ok_or("Expected object")?
        .remove("anchor");
    assert!(serde_json::from_value::<Request>(value).is_err());
    let mut value = serde_json::to_value(request())?;
    value
        .as_object_mut()
        .ok_or("Expected object")?
        .remove("bootstrap_mode");
    assert!(serde_json::from_value::<Request>(value).is_err());
    assert!(serde_json::from_value::<Anchor>(serde_json::json!({
        "kind":"local_only", "identity":vec![8u8;32], "key":"AQ"
    }))
    .is_err());
    assert!(
        serde_json::from_value::<store::SignerPhase>(serde_json::json!({
            "phase":"Signing", "public":"AQ"
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<store::Cursor>(serde_json::json!({
        "phase":"Idle", "operation":vec![8u8;32]
    }))
    .is_err());
    for phase in ["Pending", "Cancelled"] {
        assert!(serde_json::from_value::<store::State>(serde_json::json!({
            "phase":phase, "policy":"AQ"
        }))
        .is_err());
    }
    Ok(())
}

fn kill(
    path: &std::path::Path,
    action: &str,
    stage: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let marker = path.with_extension(format!("{stage}.marker"));
    let output = std::fs::File::create(path.with_extension(format!("{stage}.stdout")))?;
    let errors = std::fs::File::create(path.with_extension(format!("{stage}.stderr")))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "policy_publisher::tests::policy_publisher_child",
            "--nocapture",
        ])
        .env("QPERIAPT_POLICY_TEST_DATABASE", path)
        .env("QPERIAPT_POLICY_TEST_ACTION", action)
        .env("QPERIAPT_ISSUER_BARRIER", stage)
        .env("QPERIAPT_ISSUER_MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("Publisher child exited before {stage}: {status}").into());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(format!("Publisher child never reached {stage}; state retained").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let bytes = std::fs::read(marker)?;
    child.kill()?;
    let status = child.wait()?;
    assert_eq!(status.signal(), Some(9));
    Ok(bytes)
}

#[test]
fn original_policy_key_creation_survives_four_process_cuts(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    for stage in [
        "policy-wrapping-published",
        "policy-signing-prepared",
        "policy-signer-published",
        "policy-ready-committed",
    ] {
        let path = directory.path().join(format!("{stage}.redb"));
        drop(Publisher::provision(&path, [1; 32], input()?)?);
        let marker = kill(&path, "prepare", stage)?;
        let mut owner = Publisher::open(&path, [1; 32])?;
        let cfg = owner.config()?;
        let (wrapping, signing) = owner.paths(&cfg)?;
        let original_wrapping = std::fs::read(&wrapping)?;
        let original_signer = if signing.exists() {
            Some(std::fs::read(&signing)?)
        } else {
            None
        };
        let authority = owner.prepare()?;
        assert_eq!(std::fs::read(wrapping)?, original_wrapping);
        if let Some(original) = original_signer {
            assert_eq!(std::fs::read(signing)?, original);
        }
        if stage == "policy-signer-published" || stage == "policy-ready-committed" {
            assert_eq!(authority.policy_root, marker);
        }
        drop(owner);
        let mut owner = Publisher::open(&path, [1; 32])?;
        assert_eq!(owner.prepare()?.family, authority.family);
    }
    Ok(())
}

#[test]
fn original_publication_survives_three_commit_cuts() -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    for stage in [
        "policy-intent-committed",
        "policy-signed-before-commit",
        "policy-result-committed",
    ] {
        let path = directory.path().join(format!("{stage}.redb"));
        let mut owner = Publisher::provision(&path, [1; 32], input()?)?;
        owner.prepare()?;
        drop(owner);
        let marker = kill(&path, "issue", stage)?;
        let mut owner = Publisher::open(&path, [1; 32])?;
        assert!(owner
            .issue(
                [2; 32],
                Request {
                    send_budget: 99,
                    ..request()
                },
                150
            )
            .is_err());
        if stage != "policy-result-committed" {
            assert!(owner.result([2; 32]).is_err());
            assert!(owner.issue([3; 32], request(), 150).is_err());
        }
        let issued = owner.issue([2; 32], request(), 150)?;
        assert_eq!(issued.version, 1);
        if stage == "policy-result-committed" {
            assert_eq!(issued.policy, marker);
        }
        if stage == "policy-signed-before-commit" {
            // An unreleased signing attempt may use different randomness on
            // retry, but its authenticated original body/checkpoint cannot change.
            let a = owner.authority()?;
            sdk::PolicyPin::new(
                a.family,
                sdk::PublicKey::decode(&a.policy_root)?,
                sdk::PolicyCheckpoint::from_trusted_state(issued.version, issued.digest)?,
            )?
            .verify_historical(&marker)?;
        }
        drop(owner);
        let mut owner = Publisher::open(&path, [1; 32])?;
        assert_eq!(owner.issue([2; 32], request(), 250)?, issued);
    }
    Ok(())
}

#[test]
fn expired_pending_intent_requires_explicit_cancellation_and_keeps_version(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory()?;
    let path = directory.path().join("publisher.redb");
    let mut owner = Publisher::provision(&path, [1; 32], input()?)?;
    owner.prepare()?;
    drop(owner);
    kill(&path, "issue", "policy-intent-committed")?;
    let mut owner = Publisher::open(&path, [1; 32])?;
    assert!(owner.issue([2; 32], request(), 210).is_err());
    assert!(owner.issue([3; 32], request(), 150).is_err());
    owner.cancel([2; 32])?;
    owner.cancel([2; 32])?;
    assert!(owner.issue([2; 32], request(), 150).is_err());
    let next = owner.issue(
        [3; 32],
        Request {
            valid_from: 200,
            valid_until: 300,
            ..request()
        },
        210,
    )?;
    assert_eq!(next.version, 2);
    Ok(())
}

#[test]
fn policy_publisher_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("QPERIAPT_POLICY_TEST_DATABASE") else {
        return Ok(());
    };
    let mut owner = Publisher::open(std::path::Path::new(&path), [1; 32])?;
    match std::env::var("QPERIAPT_POLICY_TEST_ACTION")?.as_str() {
        "prepare" => {
            owner.prepare()?;
        }
        "issue" => {
            owner.issue([2; 32], request(), 150)?;
        }
        _ => return Err("Unknown child action".into()),
    }
    Err("Child failed to stop at requested cut".into())
}
