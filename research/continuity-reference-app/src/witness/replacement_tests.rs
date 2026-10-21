// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn journal(
    path: &Path,
    name: &str,
    mut trust: EnrollmentTrust,
    now: u64,
) -> Result<(EnrollmentTrust, EnrollmentRequest)> {
    let roster = trust.account.roster.as_ref().ok_or("roster")?;
    let pin = sdk::AccountPin::new(
        trust.account.account,
        sdk::PublicKey::decode(&trust.account.public_key)?,
        roster.checkpoint.as_sdk()?,
        trust.account.family,
    )?;
    let device = pin.verify_device(&trust.certificate, &roster.bytes, now)?;
    let policy = trust
        .policy
        .pins
        .verify(&trust.policy.materials, trust.account.family, now)?
        .0;
    let identity = sdk::JournalIdentity::generate()?;
    let mut stored = sdk::DeviceJournal::provision_anchored(
        &path.join(format!("{name}.redb")),
        sdk::JournalKey::provision(&path.join(format!("{name}.wrap")))?,
        &device,
        &policy,
        identity,
        now,
    )?;
    let genesis = stored.anchor_genesis(&device, &policy)?;
    trust.journal = *identity.as_bytes();
    trust.genesis_head = genesis.image_digest();
    let request = EnrollmentRequest {
        preparation: "RequiresWitnessEnrollment".into(),
        subject: genesis.subject().to_bytes(),
        head: genesis.image_digest(),
    };
    stored.close();
    Ok((trust, request))
}

fn fresh(
    path: &Path,
    name: &str,
    original: &Device,
    signer: &sdk::DeviceSigningKey,
    generation: u64,
    now: u64,
) -> Result<(EnrollmentTrust, EnrollmentRequest)> {
    let validity = sdk::Validity::new(now, now + 600)?;
    let certificate = original.root.issue_device(
        sdk::DeviceDescription::new(
            original.trust.device,
            generation,
            original.trust.account.family,
            validity,
        )?,
        signer.public_key()?,
    )?;
    let roster =
        original
            .root
            .issue_roster(2, validity, &[original.root.roster_entry(&certificate)?])?;
    let mut trust = original.trust.clone();
    trust.generation = generation;
    trust.certificate = certificate;
    trust.account.roster = Some(RosterSnapshot {
        checkpoint: roster.checkpoint().into(),
        bytes: roster.as_bytes().to_vec(),
    });
    journal(path, name, trust, now)
}

fn predecessor(
    trust: &EnrollmentTrust,
    request: &EnrollmentRequest,
) -> Result<DevicePredecessorTrust> {
    Ok(DevicePredecessorTrust {
        subject: request.subject.clone(),
        checkpoint: trust.account.roster.as_ref().ok_or("roster")?.checkpoint,
        policy: trust.policy.clone(),
    })
}
fn approved(original: &Device, next: EnrollmentTrust) -> Result<DeviceReplacementTrust> {
    Ok(DeviceReplacementTrust {
        schema: "qperiapt-witness-device-replacement-trust/1".into(),
        successor: next,
        predecessors: vec![predecessor(&original.trust, &original.request)?],
    })
}
fn exchange(
    owner: &mut Witness,
    pin: &sdk::AnchorPin,
    request: &EnrollmentRequest,
    signer: &sdk::DeviceSigningKey,
    operation: sdk::AnchorOperation,
    now: u64,
) -> Result<(sdk::AnchorOutcome, sdk::AnchorHead)> {
    let subject = sdk::AnchorSubject::from_trusted_state(&request.subject)?;
    let signed = sdk::AnchorRequest::new(pin, subject, operation, signer)?;
    let cancel = sdk::Cancellation::default();
    let run = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(10))?;
    let reply = pin.verify_reply(&signed, &owner.handle(signed.as_bytes(), &run, now)?)?;
    Ok((reply.outcome(), reply.observed_head()))
}

#[test]
fn complete_fresh_generation_requires_exact_predecessors_and_survives_expiry() -> Result<()> {
    let path = directory()?;
    let mut owner = provision(&path)?;
    let pin = owner.prepare()?;
    let old = device(&path, pin)?;
    let now = crate::native_device::clock()?;
    owner.enroll(&old.trust, &old.request, now)?;
    // Ordinary enrollment already forbids another journal under this credential.
    // An unadmitted journal cannot substitute for the actual predecessor either.
    let (second, second_request) = journal(&path, "second-original", old.trust.clone(), now)?;
    assert!(owner.enroll(&second, &second_request, now).is_err());
    let next_signer = sdk::DeviceSigningKey::generate()?;
    let (next, request) = fresh(&path, "next", &old, &next_signer, 2, now)?;
    let trust = approved(&old, next)?;
    let mut incomplete = trust.clone();
    incomplete.predecessors.clear();
    assert!(
        owner
            .prepare_device_replacement(&incomplete, &request, now)
            .is_err(),
        "incomplete predecessor set"
    );
    incomplete
        .predecessors
        .push(predecessor(&second, &second_request)?);
    assert!(
        owner
            .prepare_device_replacement(&incomplete, &request, now)
            .is_err(),
        "different original journal"
    );
    let mut duplicate = trust.clone();
    duplicate.predecessors.push(trust.predecessors[0].clone());
    assert!(owner
        .prepare_device_replacement(&duplicate, &request, now)
        .is_err());
    for (name, signer, generation) in [
        ("same-key", &old.signer, 2),
        ("same-generation", &next_signer, 1),
    ] {
        let (bad, bad_request) = fresh(&path, name, &old, signer, generation, now)?;
        let mut wrong = trust.clone();
        wrong.successor = bad;
        assert!(
            owner
                .prepare_device_replacement(&wrong, &bad_request, now)
                .is_err(),
            "accepted {name}"
        );
    }
    let stale = owner.prepare_device_replacement(&trust, &request, now)?;
    assert_eq!(
        owner
            .prepare_device_replacement(&trust, &request, now)?
            .proposal,
        stale.proposal
    );
    assert_eq!(
        owner.device_replacement_status(&stale)?.status,
        DeviceReplacementStatus::Unavailable
    );
    let (_, head) = exchange(
        &mut owner,
        &old.pin,
        &old.request,
        &old.signer,
        sdk::AnchorOperation::query(),
        now,
    )?;
    let advance = sdk::AnchorOperation::advance(head, [96; 32])?;
    assert_eq!(
        exchange(
            &mut owner,
            &old.pin,
            &old.request,
            &old.signer,
            advance,
            now
        )?
        .0,
        sdk::AnchorOutcome::Advanced
    );
    assert!(
        owner
            .commit_device_replacement(&trust, &request, &stale, now)
            .is_err(),
        "stale state commitment"
    );
    assert_eq!(
        owner.device_replacement_status(&stale)?.status,
        DeviceReplacementStatus::Unavailable
    );
    assert_eq!(
        exchange(
            &mut owner,
            &old.pin,
            &old.request,
            &old.signer,
            sdk::AnchorOperation::query(),
            now
        )?
        .1
        .revision(),
        2
    );
    assert!(exchange(
        &mut owner,
        &old.pin,
        &request,
        &next_signer,
        sdk::AnchorOperation::query(),
        now
    )
    .is_err());
    let decision = owner.prepare_device_replacement(&trust, &request, now)?;
    assert_ne!(decision.binding, stale.binding);
    let decoded: DeviceReplacementDecision =
        serde_json::from_slice(&serde_json::to_vec(&decision)?)?;
    let mut wrong = decoded.clone();
    wrong.binding[0] ^= 1;
    assert!(owner
        .commit_device_replacement(&trust, &request, &wrong, now)
        .is_err());
    assert_eq!(
        owner
            .commit_device_replacement(&trust, &request, &decoded, now)?
            .status,
        DeviceReplacementStatus::Committed
    );
    drop(owner);
    let mut owner = open(&path)?;
    assert_eq!(
        owner.device_replacement_status(&decision)?.status,
        DeviceReplacementStatus::Committed
    );
    assert_eq!(
        owner
            .commit_device_replacement(&trust, &request, &decision, now)?
            .status,
        DeviceReplacementStatus::Committed
    );
    assert_eq!(
        exchange(
            &mut owner,
            &old.pin,
            &request,
            &next_signer,
            sdk::AnchorOperation::query(),
            now
        )?
        .1
        .digest(),
        request.head
    );
    assert!(exchange(
        &mut owner,
        &old.pin,
        &old.request,
        &old.signer,
        sdk::AnchorOperation::query(),
        now
    )
    .is_err());
    assert!(
        exchange(
            &mut owner,
            &old.pin,
            &old.request,
            &old.signer,
            advance,
            now
        )
        .is_err(),
        "old exact advance revived"
    );
    assert!(
        owner.enroll(&old.trust, &old.request, now).is_err(),
        "enrollment revived retired state"
    );
    assert!(
        owner
            .commit_device_replacement(&trust, &request, &decision, now + 601)
            .is_err(),
        "expired authority dispatched commit"
    );
    assert_eq!(
        owner.device_replacement_status(&decision)?.status,
        DeviceReplacementStatus::Committed
    );
    assert_eq!(
        owner.device_replacement_status(&stale)?.status,
        DeviceReplacementStatus::Unavailable
    );
    Ok(())
}

#[test]
fn commit_child() -> Result<()> {
    let Some(path) = std::env::var_os("QPERIAPT_REPLACEMENT_TEST_ROOT") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let trust: DeviceReplacementTrust =
        serde_json::from_slice(&fs::read(path.join("trust.json"))?)?;
    let request: EnrollmentRequest = serde_json::from_slice(&fs::read(path.join("request.json"))?)?;
    let decision: DeviceReplacementDecision =
        serde_json::from_slice(&fs::read(path.join("decision.json"))?)?;
    open(path)?.commit_device_replacement(
        &trust,
        &request,
        &decision,
        crate::native_device::clock()?,
    )?;
    Ok(())
}

#[test]
fn committed_process_cut_reopens_exact_result_without_reset() -> Result<()> {
    let path = directory()?;
    let mut owner = provision(&path)?;
    let pin = owner.prepare()?;
    let old = device(&path, pin)?;
    let now = crate::native_device::clock()?;
    owner.enroll(&old.trust, &old.request, now)?;
    let next_signer = sdk::DeviceSigningKey::generate()?;
    let (next, request) = fresh(&path, "replacement", &old, &next_signer, 2, now)?;
    let trust = approved(&old, next)?;
    let decision = owner.prepare_device_replacement(&trust, &request, now)?;
    for (name, bytes) in [
        ("trust.json", serde_json::to_vec(&trust)?),
        ("request.json", serde_json::to_vec(&request)?),
        ("decision.json", serde_json::to_vec(&decision)?),
    ] {
        q_periapt_host_store::filesystem::publish_private_bytes(&path.join(name), &bytes)?;
    }
    let original = fs::read(path.join("device.redb"))?;
    let fresh = fs::read(path.join("replacement.redb"))?;
    drop(owner);
    let marker = path.join("replacement-boundary");
    let log = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("replacement-child.log"))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "witness::tests::device_replacement::commit_child",
            "--nocapture",
        ])
        .env("QPERIAPT_REPLACEMENT_TEST_ROOT", &path)
        .env(
            "QPERIAPT_ISSUER_BARRIER",
            "witness-device-replacement-committed",
        )
        .env("QPERIAPT_ISSUER_MARKER", &marker)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("Replacement child exited before cut: {status}").into());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("Replacement commit cut deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill()?;
    assert!(!child.wait()?.success());
    let mut owner = open(&path)?;
    assert_eq!(
        owner.device_replacement_status(&decision)?.status,
        DeviceReplacementStatus::Committed
    );
    assert!(exchange(
        &mut owner,
        &old.pin,
        &old.request,
        &old.signer,
        sdk::AnchorOperation::query(),
        now
    )
    .is_err());
    assert_eq!(
        exchange(
            &mut owner,
            &old.pin,
            &request,
            &next_signer,
            sdk::AnchorOperation::query(),
            now
        )?
        .1
        .digest(),
        request.head
    );
    assert!(
        fs::read(path.join("device.redb"))? == original,
        "original device image changed"
    );
    assert!(
        fs::read(path.join("replacement.redb"))? == fresh,
        "fresh device image changed"
    );
    assert_eq!(
        owner
            .commit_device_replacement(&trust, &request, &decision, now)?
            .status,
        DeviceReplacementStatus::Committed
    );
    Ok(())
}
