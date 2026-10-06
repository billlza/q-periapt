// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh enrolled generation, independently trusted roster and original loss accounting.
use super::*;

struct Replacement {
    path: PathBuf,
    peer: PathBuf,
    roster: p::VerifiedRoster,
}

fn prepare(s: &Setup) -> Result<Replacement> {
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
    p::JournalKey::provision(&path.join("wrap.key"))?;
    let mut sdk = PolicyStore::provision(
        &path.join("sdk.redb"),
        &read(&path, "sdk-policy", 4096)?,
        &read(&path, "sdk-signature", 8192)?,
        &read(&path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    let policy = protocol_policy(&path, &sdk)?;
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
    let mut enrollment = p::DeviceEnrollment::provision(enrollment::paths(&path)?, intent.clone())?;
    let identity = enrollment.identity()?;
    let request = enrollment.request(at)?;
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
    let journal = enrollment.accept(&certificate, issued.as_bytes(), &pin, &policy, at)?;
    assert_ne!(
        journal.as_bytes(),
        &array::<32>(&s.responder, "accepted-journal")?
    );
    enrollment.close();
    let mut enrollment = p::DeviceEnrollment::open(enrollment::paths(&path)?, intent)?;
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
    enrollment.prepare(&policy, at)?;
    let mut active = enrollment.activate(&policy, at, None)?;
    let (service, signer, admitted) = active.parts()?;
    assert_eq!(admitted.credential_digest(), device.credential_digest());
    assert_eq!(service.stores()?.0.identity()?, journal);
    store(&path, "active-journal", journal.as_bytes())?;
    let mut leaves = Vec::new();
    for (index, kind) in [
        p::LeafKind::SignedClassical,
        p::LeafKind::OneTimeClassical,
        p::LeafKind::LastResortPq,
        p::LeafKind::OneTimePq,
    ]
    .into_iter()
    .enumerate()
    {
        leaves.push(service.stores()?.0.generate_prekey(
            &policy,
            &device,
            p::PrekeyId::from_trusted_state([u8::try_from(index + 1)?; 32])?,
            kind,
            validity,
            at,
        )?);
    }
    let manifest = signer.issue_manifest(
        &device,
        p::ManifestContext::new(
            1,
            sdk.runtime()?.trusted_state().digest(),
            p::bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &leaves,
    )?;
    let checked = device.verify_manifest(manifest.as_bytes(), at)?;
    let mut proofs = BTreeMap::new();
    for index in 0..manifest.leaf_count() {
        let proof = manifest.proof(index)?;
        proofs.insert(
            checked.verify_leaf(&proof, at)?.kind() as u8,
            proof.encode()?,
        );
    }
    let proof = |kind: p::LeafKind| -> Result<&[u8]> {
        Ok(proofs
            .get(&(kind as u8))
            .ok_or("replacement prekey proof")?)
    };
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: &read(&s.initiator, "local-certificate", 8192)?,
            initiator_roster: &read(&s.initiator, "local-roster", 8192)?,
            responder_credential: &certificate,
            responder_roster: issued.as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    let tls = rcgen::generate_simple_self_signed(vec!["responder.test".into()])?;
    store(&path, "tls-cert", tls.cert.der())?;
    store(
        &path,
        "tls-key",
        &Zeroizing::new(tls.signing_key.serialize_der()),
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
    let replacement = prepare(&s)?;
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
