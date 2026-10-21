// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    enrollment::{RootInfo, RosterSnapshot},
    policy_publisher,
};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn directory() -> Result<PathBuf> {
    let path = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?
        .keep()
        .canonicalize()?;
    eprintln!("Retained witness host fixture: {}", path.display());
    Ok(path)
}
fn open(path: &Path) -> Result<Witness> {
    Witness::open(&path.join("host.redb"), [91; 32])
}
fn provision(path: &Path) -> Result<Witness> {
    Witness::provision(&path.join("host.redb"), [91; 32])
}

#[test]
fn preparation_child() -> Result<()> {
    let Some(path) = std::env::var_os("QPERIAPT_WITNESS_TEST_ROOT") else {
        return Ok(());
    };
    open(Path::new(&path))?.prepare()?;
    Ok(())
}
#[test]
fn original_preparation_survives_every_published_phase_and_process_kill() -> Result<()> {
    for stage in [
        "witness-wrapping-published",
        "witness-signing-prepared",
        "witness-signer-published",
        "witness-store-prepared",
        "witness-store-published",
        "witness-ready-committed",
    ] {
        let path = directory()?;
        drop(provision(&path)?);
        let marker = path.join("boundary");
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("child.log"))?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "witness::tests::preparation_child",
                "--nocapture",
            ])
            .env("QPERIAPT_WITNESS_TEST_ROOT", &path)
            .env("QPERIAPT_ISSUER_BARRIER", stage)
            .env("QPERIAPT_ISSUER_MARKER", &marker)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            if let Some(status) = child.try_wait()? {
                return Err(format!("Witness child exited before {stage}: {status}").into());
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err(format!("Witness boundary not reached: {stage}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill()?;
        assert!(!child.wait()?.success());
        // Files published before the kill must not change on preparation retry.
        let retained: Vec<_> = fs::read_dir(&path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|p| {
                matches!(
                    p.extension().and_then(|v| v.to_str()),
                    Some("wrap" | "signer")
                )
            })
            .map(|p| fs::read(&p).map(|bytes| (p, bytes)))
            .collect::<std::io::Result<_>>()?;
        let mut owner = open(&path)?;
        let pin = owner.prepare()?;
        assert_eq!(owner.prepare()?, pin);
        drop(owner);
        assert_eq!(open(&path)?.pin()?, pin);
        for (p, bytes) in retained {
            assert_eq!(fs::read(p)?, bytes, "original key changed after {stage}");
        }
        assert!(Witness::provision(&path.join("host.redb"), [91; 32]).is_err());
        assert!(Witness::open(&path.join("host.redb"), [92; 32]).is_err());
    }
    Ok(())
}

#[test]
fn ready_preparation_never_regenerates_missing_or_corrupt_state() -> Result<()> {
    for extension in ["wrap", "signer", "redb"] {
        let path = directory()?;
        let mut owner = provision(&path)?;
        owner.prepare()?;
        drop(owner);
        let file = fs::read_dir(&path)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .find(|p| {
                p.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("witness-"))
                    && p.extension().and_then(|v| v.to_str()) == Some(extension)
            })
            .ok_or("original witness file")?;
        let retained = file.with_extension(format!("{extension}.retained"));
        fs::rename(&file, &retained)?;
        let mut owner = open(&path)?;
        assert!(owner.pin().is_err());
        assert!(owner.prepare().is_err());
        assert!(!file.exists(), "ready host recreated missing {extension}");
        drop(owner);
        // Keep both the original and deliberately corrupt file in this fixture.
        let mut bytes = fs::read(&retained)?;
        *bytes.first_mut().ok_or("original bytes")? ^= 1;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)?
            .write_all(&bytes)?;
        let mut owner = open(&path)?;
        assert!(owner.prepare().is_err(), "accepted corrupt {extension}");
        assert_eq!(fs::read(&file)?, bytes);
    }
    Ok(())
}
use std::io::Write;

struct Device {
    root: sdk::RootSigningKey,
    signer: sdk::DeviceSigningKey,
    trust: EnrollmentTrust,
    request: EnrollmentRequest,
    pin: sdk::AnchorPin,
    subject: sdk::AnchorSubject,
}
fn device(path: &Path, pin: Pin) -> Result<Device> {
    let now = crate::native_device::clock()?;
    let root = sdk::RootSigningKey::generate()?;
    let signer = sdk::DeviceSigningKey::generate()?;
    let mut publisher = policy_publisher::Publisher::provision(
        &path.join("policy.redb"),
        [92; 32],
        crate::test_support::sdk_input()?,
    )?;
    let authority = publisher.prepare()?;
    publisher.issue(
        [93; 32],
        policy_publisher::Request {
            bootstrap_mode: policy_publisher::BootstrapMode::ReusableBoth,
            valid_from: now,
            valid_until: now + 600,
            send_budget: 8,
            anchor: policy_publisher::Anchor::Required {
                identity: pin.identity,
                key: pin.key.clone(),
            },
        },
        now,
    )?;
    let interval = sdk::Validity::new(now, now + 600)?;
    let certificate = root.issue_device(
        sdk::DeviceDescription::new([94; 16], 1, authority.family, interval)?,
        signer.public_key()?,
    )?;
    let roster = root.issue_roster(1, interval, &[root.roster_entry(&certificate)?])?;
    let account = RootInfo {
        revision: 1,
        account: root.account_id()?,
        public_key: root.public_key()?.encode(),
        family: authority.family,
        suspended: false,
        roster: Some(RosterSnapshot {
            checkpoint: roster.checkpoint().into(),
            bytes: roster.as_bytes().to_vec(),
        }),
    };
    let account_pin = sdk::AccountPin::new(
        account.account,
        root.public_key()?,
        roster.checkpoint(),
        authority.family,
    )?;
    let verified = account_pin.verify_device(&certificate, roster.as_bytes(), now)?;
    let (pins, materials) = publisher.export([93; 32])?;
    let policy = pins.verify(&materials, authority.family, now)?.0;
    let journal = sdk::JournalIdentity::generate()?;
    let subject = sdk::AnchorSubject::for_device(journal, &verified, &policy)?;
    let mut stored = sdk::DeviceJournal::provision_anchored(
        &path.join("device.redb"),
        sdk::JournalKey::provision(&path.join("device.wrap"))?,
        &verified,
        &policy,
        journal,
        now,
    )?;
    let genesis = stored.anchor_genesis(&verified, &policy)?;
    let head = genesis.image_digest();
    stored.close();
    let trust = EnrollmentTrust {
        schema: "qperiapt-witness-enrollment-trust/1".into(),
        account,
        device: [94; 16],
        generation: 1,
        journal: *journal.as_bytes(),
        genesis_head: head,
        certificate,
        policy: policy_publisher::PolicyInput { pins, materials },
    };
    let request = EnrollmentRequest {
        preparation: "RequiresWitnessEnrollment".into(),
        subject: subject.to_bytes(),
        head,
    };
    Ok(Device {
        root,
        signer,
        trust,
        request,
        pin: pin.as_sdk()?,
        subject,
    })
}

#[path = "account_root_tests.rs"]
mod account_root;
#[path = "replacement_tests.rs"]
mod device_replacement;
#[test]
fn trusted_enrollment_signed_advance_reopen_and_exact_retry_preserve_head() -> Result<()> {
    let path = directory()?;
    let mut owner = provision(&path)?;
    let pin = owner.prepare()?;
    let device = device(&path, pin.clone())?;
    let now = crate::native_device::clock()?;
    for field in [
        "head",
        "journal",
        "device",
        "generation",
        "root",
        "suspended",
        "policy",
        "certificate",
    ] {
        let mut trust = device.trust.clone();
        match field {
            "head" => trust.genesis_head[0] ^= 1,
            "journal" => trust.journal[0] ^= 1,
            "device" => trust.device[0] ^= 1,
            "generation" => trust.generation += 1,
            "root" => trust.account.public_key[0] ^= 1,
            "suspended" => trust.account.suspended = true,
            "policy" => trust.account.family[0] ^= 1,
            "certificate" => *trust.certificate.last_mut().ok_or("signature")? ^= 1,
            _ => return Err("case".into()),
        };
        assert!(
            owner.enroll(&trust, &device.request, now).is_err(),
            "accepted {field}"
        );
    }
    owner.enroll(&device.trust, &device.request, now)?;
    let cancel = sdk::Cancellation::default();
    let run = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(30))?;
    let request =
        |operation| sdk::AnchorRequest::new(&device.pin, device.subject, operation, &device.signer);
    let query = request(sdk::AnchorOperation::query())?;
    let initial = device
        .pin
        .verify_reply(&query, &owner.handle(query.as_bytes(), &run, now)?)?;
    assert_eq!(initial.observed_head().revision(), 1);
    let advance = sdk::AnchorOperation::advance(initial.observed_head(), [96; 32])?;
    let first = request(advance)?;
    // Lose the response after the actual durable advance and reopen this owner.
    owner.handle(first.as_bytes(), &run, now)?;
    drop(owner);
    let mut owner = open(&path)?;
    assert_eq!(owner.pin()?, pin);
    owner.enroll(&device.trust, &device.request, now)?;
    let retry = request(advance)?;
    let result = device
        .pin
        .verify_reply(&retry, &owner.handle(retry.as_bytes(), &run, now)?)?;
    assert_eq!(result.outcome(), sdk::AnchorOutcome::AlreadyAppliedExact);
    assert_eq!(result.observed_head().revision(), 2);
    let query = request(sdk::AnchorOperation::query())?;
    let mut forged = query.as_bytes().to_vec();
    *forged.last_mut().ok_or("signature")? ^= 1;
    assert!(owner.handle(&forged, &run, now).is_err());
    let current = device
        .pin
        .verify_reply(&query, &owner.handle(query.as_bytes(), &run, now)?)?;
    assert_eq!(current.observed_head(), result.observed_head());
    cancel.cancel();
    let query = request(sdk::AnchorOperation::query())?;
    assert!(owner.handle(query.as_bytes(), &run, now).is_err());
    Ok(())
}
