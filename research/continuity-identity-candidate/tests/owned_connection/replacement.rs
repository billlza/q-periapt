// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh enrolled generation, independently trusted roster and original loss accounting.
use super::*;

pub(super) struct Replacement {
    pub(super) path: PathBuf,
    pub(super) peer: PathBuf,
    pub(super) roster: p::VerifiedRoster,
}

fn foreign_enrollment(
    client: &Path,
    path: &Path,
    label: &str,
    operation: &str,
    witness: Option<&WitnessFixture>,
    trace: &mut Vec<u8>,
) -> Result<()> {
    let stdout_path = path.join(format!("successor-{label}.stdout"));
    let stderr_path = path.join(format!("successor-{label}.stderr"));
    let create = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let mut command = Command::new(client);
    if let Some(witness) = witness {
        command.arg("--witness").arg(witness.address.to_string());
    }
    command.arg(format!("enrollment-{operation}")).arg(path);
    if operation == "activate-error" {
        command.arg("218");
    }
    let mut child = OwnedChild(
        command
            .stdout(Stdio::from(create(&stdout_path)?))
            .stderr(Stdio::from(create(&stderr_path)?))
            .spawn()?,
    );
    let pid = child.0.id();
    let status = wait(&mut child)?;
    assert!(fs::metadata(&stdout_path)?.len() <= 8192 && fs::metadata(&stderr_path)?.len() <= 8192);
    let stderr = fs::read(&stderr_path)?;
    assert!(
        status.success() && stderr.is_empty(),
        "foreign successor {label}: {status}; {}",
        String::from_utf8_lossy(&stderr)
    );
    let stdout = String::from_utf8(fs::read(&stdout_path)?)?;
    let lines: Vec<_> = stdout.lines().collect();
    let identifier = |line: &str| {
        line.len() == 64
            && line
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && line.bytes().any(|b| b != b'0')
    };
    match operation {
        "key" => assert_eq!(stdout, "enrollment-key\n"),
        "activate-error" => assert_eq!(stdout, "enrollment-activation-refused:218\n"),
        "activate" => {
            let [state, batch] = lines.as_slice() else {
                return Err("foreign activation result shape".into());
            };
            assert_eq!(*state, "enrollment-active");
            assert!(identifier(batch));
        }
        "create" | "request" | "request-retry" | "accept" | "storage" => {
            let phase = match operation {
                "create" => 1,
                "request" | "request-retry" => 2,
                _ => 3,
            };
            let [state, signer, journal] = lines.as_slice() else {
                return Err("foreign enrollment status shape".into());
            };
            assert_eq!(*state, format!("enrollment-phase:{phase}"));
            assert!(identifier(signer));
            if phase <= 2 {
                assert_eq!(*journal, "0".repeat(64));
            } else {
                assert!(identifier(journal));
            }
        }
        _ => return Err("unqualified successor enrollment operation".into()),
    }
    trace.extend_from_slice(format!("{label} {pid}\n").as_bytes());
    Ok(())
}

fn refuse_before_replacement(
    client: &Path,
    path: &Path,
    witness: &WitnessFixture,
    subject: p::AnchorSubject,
    trace: &mut Vec<u8>,
) -> Result<()> {
    // The general workload's witness treats unexpected scope errors as fatal.
    // This one-exchange carrier expects exactly the not-yet-enrolled successor,
    // invokes the same real store, and must observe its Scope refusal. It sends
    // no acknowledgement and does not alter the normal witness error handling.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let store = Arc::clone(&witness.store);
    let binding = witness.pin()?.binding();
    let worker = std::thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut size = [0; 4];
        stream.read_exact(&mut size)?;
        assert_eq!(u32::from_be_bytes(size), 3674);
        let mut request = [0; 3674];
        stream.read_exact(&mut request)?;
        assert_eq!(&request[4..12], b"QPANRQ01");
        assert_eq!(&request[12..44], &binding);
        assert_eq!(&request[44..140], &subject.to_bytes());
        assert!(matches!(
            store
                .lock()
                .map_err(|_| "witness store poisoned")?
                .handle(&request, now()?),
            Err(p::AnchorError::Rejected(p::Error::Scope))
        ));
        Ok(())
    });
    let expected = WitnessFixture {
        store: Arc::clone(&witness.store),
        address,
    };
    let called = foreign_enrollment(
        client,
        path,
        "activate-before-replacement",
        "activate-error",
        Some(&expected),
        trace,
    );
    let observed = worker
        .join()
        .map_err(|_| "successor refusal witness panicked")?;
    called?;
    observed
}

pub(super) fn prepare(s: &Setup, witness: Option<&WitnessFixture>) -> Result<Replacement> {
    prepare_with_client(s, witness, None)
}

/// The account issuer and witness controller retain their independent authority.
/// Only device-side enrollment is delegated to the selected foreign executable.
pub(super) fn prepare_with_client(
    s: &Setup,
    witness: Option<&WitnessFixture>,
    client: Option<&Path>,
) -> Result<Replacement> {
    let root = s
        .responder_issuer
        .as_ref()
        .ok_or("independent account issuer")?;
    let parent = s.responder.parent().ok_or("reference root")?;
    let path = parent.join("replacement");
    let peer = parent.join("replacement-peer");
    for destination in [&path, &peer] {
        fs::DirBuilder::new().mode(0o700).create(destination)?;
        for name in [
            "sdk-policy",
            "sdk-signature",
            "sdk-root",
            "family",
            "policy-root",
            "policy-version",
            "policy-digest",
            "protocol-policy",
            "directory",
        ] {
            store(destination, name, &read(&s.responder, name, 8192)?)?;
        }
    }
    store(&path, "role", &[2])?;
    store(&path, "owner-mode", &[2])?;
    store(&peer, "role", &[1])?;
    // Activation admits the host TLS configuration before contacting the witness.
    // Install this independent application input before either activation check.
    let tls = rcgen::generate_simple_self_signed(vec!["responder.test".into()])?;
    store(&path, "tls-cert", tls.cert.der())?;
    store(
        &path,
        "tls-key",
        &Zeroizing::new(tls.signing_key.serialize_der()),
    )?;
    if client.is_none() {
        p::JournalKey::provision(&path.join("wrap.key"))?;
    }
    let mut sdk = PolicyStore::provision(
        &path.join("sdk.redb"),
        &read(&path, "sdk-policy", 4096)?,
        &read(&path, "sdk-signature", 8192)?,
        &read(&path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    let mut policy = protocol_policy(&path, &sdk)?;
    let at = now()?;
    let validity = p::Validity::new(
        at.saturating_sub(1).max(policy.validity().from()),
        policy.validity().until(),
    )?;
    let device_id = array::<16>(&s.responder, "local-device")?;
    let generation = u64::from_be_bytes(array(&s.responder, "local-generation")?)
        .checked_add(1)
        .ok_or("generation overflow")?;
    assert_eq!(generation, 2);
    let family = array(&path, "family")?;
    assert_eq!(
        root.public_key()?.encode(),
        read(&s.responder, "local-root", 8192)?
    );
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new(device_id, generation, family, validity)?,
    );
    let mut foreign_trace = Vec::new();
    let mut enrollment = if let Some(client) = client {
        let mut bytes = device_id.to_vec();
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&family);
        bytes.extend_from_slice(&validity.from().to_be_bytes());
        bytes.extend_from_slice(&validity.until().to_be_bytes());
        store(&path, "enrollment-root", &root.public_key()?.encode())?;
        store(&path, "enrollment-intent", &bytes)?;
        policy.close();
        sdk.close();
        for operation in ["key", "create", "request", "request-retry"] {
            foreign_enrollment(
                client,
                &path,
                operation,
                operation,
                None,
                &mut foreign_trace,
            )?;
        }
        assert_eq!(
            read(&path, "enrollment-request", 8192)?,
            read(&path, "enrollment-reopened-request", 8192)?,
            "foreign successor recreated its original enrollment request"
        );
        sdk = super::sdk(&path)?;
        policy = protocol_policy(&path, &sdk)?;
        p::DeviceEnrollment::open(enrollment::paths(&path)?, intent.clone())?
    } else {
        p::DeviceEnrollment::provision(enrollment::paths(&path)?, intent.clone())?
    };
    let identity = enrollment.identity()?;
    let request = enrollment.request(at)?;
    if client.is_some() {
        assert_eq!(request, read(&path, "enrollment-request", 8192)?);
        for (label, phase) in [("create", 1), ("request", 2), ("request-retry", 2)] {
            assert_eq!(
                fs::read(path.join(format!("successor-{label}.stdout")))?,
                format!(
                    "enrollment-phase:{phase}\n{}\n{}\n",
                    hex(identity.as_bytes()),
                    hex(&[0; 32])
                )
                .as_bytes(),
                "foreign successor status changed its original signer"
            );
        }
    }
    enrollment.close();
    let mut enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent.clone())?;
    assert_eq!(enrollment.identity()?, identity);
    assert_eq!(
        enrollment.request(at)?,
        request,
        "replacement retry changed its original identity request"
    );
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, at)?;
    assert_ne!(
        verified.identity().as_bytes(),
        &array::<32>(&s.responder, "signer-id")?
    );
    assert_ne!(
        verified.public_key().encode(),
        read(&s.responder, "public-key", 8192)?
    );
    let certificate = root.issue_enrollment(&verified, at)?;
    let issued = root.issue_roster(2, validity, &[root.roster_entry(&certificate)?])?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        issued.checkpoint(),
        family,
    )?;
    let roster = pin.verify_roster(issued.as_bytes(), at)?;
    let device = pin.verify_device(&certificate, issued.as_bytes(), at)?;
    assert_eq!(device.device_id(), device_id);
    assert_eq!(device.generation(), generation);
    if let Some(client) = client {
        for (name, bytes) in [
            ("grant-certificate", certificate.clone()),
            ("grant-roster", issued.as_bytes().to_vec()),
            ("trusted-account", root.account_id()?.to_vec()),
            (
                "trusted-roster-version",
                issued.checkpoint().version().to_be_bytes().to_vec(),
            ),
            (
                "trusted-roster-digest",
                issued.checkpoint().digest().to_vec(),
            ),
        ] {
            store(&path, name, &bytes)?;
        }
        enrollment.close();
        policy.close();
        sdk.close();
        for (label, operation) in [
            ("accept", "accept"),
            ("accept-retry", "accept"),
            ("storage", "storage"),
        ] {
            foreign_enrollment(client, &path, label, operation, None, &mut foreign_trace)?;
        }
        sdk = super::sdk(&path)?;
        policy = protocol_policy(&path, &sdk)?;
        enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent.clone())?;
        assert_eq!(enrollment.identity()?, identity);
    }
    let journal = enrollment.accept(&certificate, issued.as_bytes(), &pin, &policy, at)?;
    if client.is_some() {
        for label in ["accept", "accept-retry", "storage"] {
            assert_eq!(
                fs::read(path.join(format!("successor-{label}.stdout")))?,
                format!(
                    "enrollment-phase:3\n{}\n{}\n",
                    hex(identity.as_bytes()),
                    hex(journal.as_bytes())
                )
                .as_bytes(),
                "foreign successor acceptance or preparation changed the original journal"
            );
        }
    }
    assert_ne!(
        journal.as_bytes(),
        &array::<32>(&s.responder, "accepted-journal")?
    );
    enrollment.close();
    let mut enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent.clone())?;
    assert_eq!(
        enrollment.accept(&certificate, issued.as_bytes(), &pin, &policy, at)?,
        journal
    );
    for (name, bytes) in [
        ("signer-id", identity.as_bytes().to_vec()),
        ("request", request),
        ("public-key", verified.public_key().encode()),
        (
            "enrollment-validity",
            [
                validity.from().to_be_bytes(),
                validity.until().to_be_bytes(),
            ]
            .concat(),
        ),
        ("accepted-journal", journal.as_bytes().to_vec()),
        ("local-account", root.account_id()?.to_vec()),
        ("local-root", root.public_key()?.encode()),
        (
            "local-roster-version",
            issued.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("local-roster-digest", issued.checkpoint().digest().to_vec()),
        ("local-device", device_id.to_vec()),
        ("local-generation", generation.to_be_bytes().to_vec()),
        ("local-certificate", certificate.clone()),
        ("local-roster", issued.as_bytes().to_vec()),
    ] {
        store(&path, name, &bytes)?;
    }
    let preparation = enrollment.prepare(&policy, at)?;
    if let Some(client) = client {
        let witness = witness.ok_or("foreign successor requires witness qualification")?;
        let witness_pin = witness.pin()?;
        store(&path, "witness-id", witness_pin.identity().as_bytes())?;
        store(&path, "witness-public", &witness_pin.public_key().encode())?;
        let p::InstallationPreparation::RequiresEnrollment(genesis) = &preparation else {
            return Err("foreign successor lost required witness".into());
        };
        assert_eq!(
            read(&path, "enrollment-genesis-subject", 96)?,
            genesis.subject().to_bytes()
        );
        assert_eq!(
            read(&path, "enrollment-genesis-digest", 32)?,
            genesis.image_digest()
        );
        enrollment.close();
        policy.close();
        sdk.close();
        refuse_before_replacement(
            client,
            &path,
            witness,
            genesis.subject(),
            &mut foreign_trace,
        )?;
        sdk = super::sdk(&path)?;
        policy = protocol_policy(&path, &sdk)?;
        enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent.clone())?;
        assert_eq!(
            enrollment.status()?,
            p::EnrollmentStatus::Activating(journal)
        );
        // Keep the exact previously prepared genesis. Activating is recovery of
        // that original operation and intentionally does not permit prepare().
    }
    let anchor_pin = match (witness, preparation) {
        (None, p::InstallationPreparation::Local) => None,
        (Some(witness), p::InstallationPreparation::RequiresEnrollment(genesis)) => {
            let previous =
                p::AnchorSubject::from_trusted_state(&read(&s.responder, "witness-subject", 96)?)?;
            let old_roster = p::RosterCheckpoint::from_trusted_state(
                u64::from_be_bytes(array(&s.responder, "local-roster-version")?),
                array(&s.responder, "local-roster-digest")?,
            )?;
            let proofs = [(previous, old_roster, policy.historical())];
            let mut controller = witness.store.lock().map_err(|_| "witness store poisoned")?;
            let proposal =
                controller.device_replacement_proposal(&genesis, &device, &policy, &proofs, at)?;
            // Retain the original plan before its independently authorized commit.
            store(&s.responder, "retirement-proposal", &proposal.to_bytes()?)?;
            assert_eq!(
                controller.replace_device(&proposal, &genesis, &device, &policy, &proofs, at)?,
                p::AnchorDeviceReplacementState::Committed
            );
            store(
                &s.responder,
                "retirement-receipt",
                &controller.retired_subject_receipt(&proposal, previous)?,
            )?;
            drop(controller);
            let witness_pin = witness.pin()?;
            for destination in [&path, &peer] {
                if client.is_some() && destination == &path {
                    continue; // The independently pinned bytes were installed before the refusal check.
                }
                store(destination, "witness-id", witness_pin.identity().as_bytes())?;
                store(
                    destination,
                    "witness-public",
                    &witness_pin.public_key().encode(),
                )?;
            }
            store(&path, "witness-subject", &genesis.subject().to_bytes())?;
            Some(witness_pin)
        }
        _ => return Err("replacement changed the required witness profile".into()),
    };
    if let Some(client) = client {
        let witness = witness.ok_or("foreign successor witness disappeared")?;
        enrollment.close();
        policy.close();
        sdk.close();
        for label in ["activate", "activate-reopen"] {
            foreign_enrollment(
                client,
                &path,
                label,
                "activate",
                Some(witness),
                &mut foreign_trace,
            )?;
        }
        sdk = super::sdk(&path)?;
        policy = protocol_policy(&path, &sdk)?;
        enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent)?;
        assert_eq!(enrollment.identity()?, identity);
        assert_eq!(enrollment.status()?, p::EnrollmentStatus::Active(journal));
        assert_eq!(
            enrollment.accept(&certificate, issued.as_bytes(), &pin, &policy, now()?)?,
            journal
        );
    }
    store(
        &path,
        "successor-enrollment-trace",
        if client.is_some() {
            &foreign_trace
        } else {
            b"native\n"
        },
    )?;
    let anchor = match (witness, anchor_pin) {
        (Some(witness), Some(pin)) => Some(enrollment.anchor_client(
            &policy,
            now()?,
            pin,
            Box::new(p::AnchorTcpTransport::new(witness.address)),
            Duration::from_secs(3),
        )?),
        (None, None) => None,
        _ => return Err("replacement witness configuration changed".into()),
    };
    let mut active = enrollment.activate(&policy, at, anchor)?;
    let (service, _, admitted) = active.parts()?;
    assert_eq!(admitted.credential_digest(), device.credential_digest());
    assert_eq!(service.stores()?.0.identity()?, journal);
    store(&path, "active-journal", journal.as_bytes())?;
    let mut plan = vec![99; 32];
    plan.extend_from_slice(&validity.from().to_be_bytes());
    plan.extend_from_slice(&validity.until().to_be_bytes());
    store(&path, "publication-plan", &plan)?;
    if let Some(client) = client {
        active.close();
        policy.close();
        sdk.close();
        publication::foreign(
            client,
            &path,
            witness.ok_or("successor publication witness")?,
        )?;
    } else {
        publication::native(&path, &mut active, &policy, validity)?;
    }
    let advertisement = publication::decode(
        &read(&path, "publication-artifact", 2 * 1024 * 1024)?,
        array(&path, "publication-id")?,
        &device,
        now()?,
    )?;
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: &read(&s.initiator, "local-certificate", 8192)?,
            initiator_roster: &read(&s.initiator, "local-roster", 8192)?,
            responder_credential: &certificate,
            responder_roster: issued.as_bytes(),
            responder_manifest: &advertisement.manifest,
            signed_classical: advertisement.proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: advertisement.proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(advertisement.proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(advertisement.proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    store(&path, "tls-peer", &read(&s.initiator, "tls-cert", 8192)?)?;
    store(&path, "tls-peer-name", b"initiator.test")?;
    store(&peer, "tls-peer", tls.cert.der())?;
    store(&peer, "tls-peer-name", b"responder.test")?;
    for destination in [&path, &peer] {
        store(destination, "bootstrap.bundle", bundle.as_bytes())?;
        for (label, source) in [("initiator", &s.initiator), ("responder", &path)] {
            for name in [
                "account",
                "root",
                "roster-version",
                "roster-digest",
                "device",
                "generation",
            ] {
                store(
                    destination,
                    &format!("{label}-{name}"),
                    &read(source, &format!("local-{name}"), 8192)?,
                )?;
            }
        }
    }
    active.close();
    policy.close();
    sdk.close();
    Ok(Replacement { path, peer, roster })
}

pub(super) fn exercise() -> Result<()> {
    let s = setup(enrollment::SetupKind::DeviceReplacement)?;
    let mut client = Peer::open(&s.initiator)?;
    let old_context = Arc::clone(&client.context);
    let endpoint = ConnectionEndpoint::client(&old_context, client.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&s.responder, 0, "bootstrap")?;
    let name = client.peer_name.clone();
    let established = endpoint.establish(
        client.actor()?,
        p::InitiationId::generate()?,
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        now,
    )?;
    assert!(wait(&mut server)?.success());
    store(&s.initiator, "session", &established.session)?;
    let id =
        client
            .service
            .stores()?
            .0
            .next_message_id(&old_context, established.session, now()?)?;
    let payload = b"old device effect with unavailable receipt";
    let (mut server, address) = spawn(&s.responder, 1, "crash-after-application")?;
    assert!(send(
        &mut client,
        &endpoint,
        address,
        established.session,
        id,
        payload
    )
    .is_err());
    assert_eq!(wait(&mut server)?.code(), Some(77));
    effect(&s.responder, established.session, id, payload)?;
    assert_eq!(
        client
            .service
            .stores()?
            .0
            .message_status(&old_context, established.session, id)?,
        p::MessageStatus::Committed
    );
    let old_wire =
        client
            .service
            .stores()?
            .0
            .resume_message(&old_context, established.session, id, now()?)?;
    let replacement = prepare(&s, None)?;
    let policy = old_context.current_policy()?;
    let checkpoint =
        client
            .service
            .parts()?
            .0
            .admit_peer_roster(&replacement.roster, policy, now()?)?;
    assert_eq!(checkpoint, replacement.roster.checkpoint());
    assert!(
        matches!(
            client.service.stores()?.0.resume_message(
                &old_context,
                established.session,
                id,
                now()?
            ),
            Err(p::DurableError::Protocol(p::Error::Scope))
        ),
        "new generation permitted cached old-session release"
    );
    client.close();
    let mut cleanup = child(&s.initiator, 2, "cleanup-freeze")?;
    assert_eq!(wait(&mut cleanup)?.code(), Some(77));
    let loss_digest = {
        let recovery =
            p::InstallationRecovery::open(super::paths(&s.initiator)?, key(&s.initiator)?)?;
        let mut owner = recovery.open_session(established.session, None)?;
        let report = owner.stores()?.0.begin()?;
        assert_eq!(report.peer_generation, 1);
        assert_eq!(
            report.peer_device,
            array::<16>(&s.responder, "local-device")?
        );
        assert_eq!(report.session, established.session);
        assert!(report.reserved.is_empty());
        assert_eq!(report.epochs.len(), 1);
        let epoch = report.epochs.first().ok_or("original epoch")?;
        assert_eq!(
            (epoch.epoch, epoch.acknowledged_before, epoch.sent),
            (0, 0, 1)
        );
        assert_eq!(epoch.unconfirmed.len(), 1);
        assert_eq!(
            epoch
                .unconfirmed
                .first()
                .ok_or("original unconfirmed message")?
                .message_id(),
            id
        );
        assert_eq!(
            report.report.as_bytes(),
            &array::<32>(&s.initiator, "closure-id")?
        );
        let digest = *epoch
            .unconfirmed
            .first()
            .ok_or("original unconfirmed message")?
            .ciphertext_digest();
        owner.close();
        digest
    };
    for (attempt, mode) in [(3, "cleanup-finish"), (4, "cleanup-verify")] {
        let mut cleanup = child(&s.initiator, attempt, mode)?;
        assert!(wait(&mut cleanup)?.success());
    }
    client = Peer::open(&s.initiator)?;
    let new_context = context(&replacement.peer, &client.policy_store, now()?)?;
    client.context = Arc::clone(&new_context);
    client.peer_certificate = read(&replacement.peer, "tls-peer", 8192)?;
    client.peer_name = String::from_utf8(read(&replacement.peer, "tls-peer-name", 256)?)?;
    let endpoint = ConnectionEndpoint::client(&new_context, client.credentials(), tls_limits())?;
    let (mut server, address) = spawn(&replacement.path, 0, "bootstrap")?;
    let name = client.peer_name.clone();
    let current = endpoint.establish(
        client.actor()?,
        p::InitiationId::generate()?,
        Run {
            address,
            server_name: &name,
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        now,
    )?;
    assert!(wait(&mut server)?.success());
    assert_ne!(current.session, established.session);
    assert_eq!(
        new_context.device(p::BootstrapRole::Responder).generation(),
        2
    );
    let next = client
        .service
        .stores()?
        .0
        .next_message_id(&new_context, current.session, now()?)?;
    let (mut server, address) = spawn(&replacement.path, 1, "application")?;
    let delivered = send(
        &mut client,
        &endpoint,
        address,
        current.session,
        next,
        b"fresh replacement session",
    )?;
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    assert!(wait(&mut server)?.success());
    effect(
        &replacement.path,
        current.session,
        next,
        b"fresh replacement session",
    )?;
    effect(&s.responder, established.session, id, payload)?;
    let root = s.responder_issuer.as_ref().ok_or("account issuer")?;
    let retired = root.issue_roster(
        3,
        p::Validity::new(
            now()?.saturating_sub(1),
            now()?.checked_add(600).ok_or("clock")?,
        )?,
        &[root.roster_entry(&read(&s.responder, "local-certificate", 8192)?)?],
    )?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        retired.checkpoint(),
        array(&s.responder, "family")?,
    )?;
    let retired = pin.verify_roster(retired.as_bytes(), now()?)?;
    assert!(matches!(
        client.service.parts()?.0.admit_peer_roster(
            &retired,
            new_context.current_policy()?,
            now()?
        ),
        Err(p::DurableError::Protocol(p::Error::Checkpoint))
    ));
    client.close();
    let parent = s.initiator.parent().ok_or("reference root")?;
    let public = parent.join("public");
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    for (role, source) in [("old", &s.responder), ("new", &replacement.path)] {
        let destination = public.join(role);
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        for name in [
            "request",
            "reopened-request",
            "signer-id",
            "public-key",
            "local-account",
            "local-root",
            "local-device",
            "local-generation",
            "enrollment-validity",
            "family",
            "local-certificate",
            "local-roster",
            "local-roster-version",
            "local-roster-digest",
            "accepted-journal",
            "active-journal",
            "reopened-journal",
        ] {
            store(&destination, name, &read(source, name, 8192)?)?;
        }
    }
    store(&public, "old-ciphertext", &old_wire)?;
    store(&public, "loss-ciphertext-digest", &loss_digest)?;
    for (name, source, leaf) in [
        (
            "old-effect",
            &s.responder,
            format!("application-{}", hex(id.as_bytes())),
        ),
        (
            "new-effect",
            &replacement.path,
            format!("application-{}", hex(next.as_bytes())),
        ),
        ("old-journal", &s.responder, "accepted-journal".into()),
        ("new-journal", &replacement.path, "accepted-journal".into()),
        ("request", &replacement.path, "request".into()),
        (
            "reopened-request",
            &replacement.path,
            "reopened-request".into(),
        ),
        ("old-signing-id", &s.responder, "signer-id".into()),
        ("new-signing-id", &replacement.path, "signer-id".into()),
        ("loss-report", &s.initiator, "closure-report".into()),
        ("loss-id", &s.initiator, "closure-id".into()),
        ("loss-complete", &s.initiator, "cleanup-complete".into()),
        ("loss-verified", &s.initiator, "cleanup-verified".into()),
    ] {
        store(&public, name, &read(source, &leaf, 65536)?)?;
    }
    let receipt = format!("{{\"old_session\":\"{}\",\"new_session\":\"{}\",\"old_message\":\"{}\",\"new_message\":\"{}\",\"old_generation\":1,\"new_generation\":2,\"old_acknowledged\":0,\"old_unconfirmed\":1,\"receiver_exit\":77,\"cleanup_exit\":77,\"request_reopened\":true,\"old_generation_refused\":true,\"same_account_root\":true,\"independent_new_owner\":true,\"old_effect_unchanged\":true}}\n",
        hex(&established.session), hex(&current.session), hex(id.as_bytes()), hex(next.as_bytes()));
    store(&public, "result.json", receipt.as_bytes())?;
    eprintln!("PUBLIC_DEVICE_REPLACEMENT local_only=true enrolled_generation_2=true distinct_owner=true original_unknown_delivery=true cleanup_process_exit=true fresh_session=true retired_generation_refused=true");
    Ok(())
}
