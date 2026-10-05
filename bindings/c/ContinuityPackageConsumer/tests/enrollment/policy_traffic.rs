// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Two original foreign registrations continue only after independent local and peer grants.
use super::*;

fn peer_inputs(left: &Registered, right: &Registered) -> Result<(PathBuf, PathBuf)> {
    let mut sdk = fixture::sdk(&right.path)?;
    let policy = fixture::protocol_policy(&right.path, &sdk)?;
    let at = fixture::now()?;
    let advertisement = p::Validity::new(
        at.saturating_sub(1),
        left.validity
            .until()
            .min(right.validity.until())
            .min(policy.validity().until()),
    )?;
    let intent = p::EnrollmentIntent::new(
        right.root.public_key()?,
        p::DeviceDescription::new([71; 16], 1, right.family, right.validity)?,
    );
    let mut owner = p::DeviceEnrollment::open(
        p::EnrollmentPaths::new(
            &right.path.join("wrap.key"),
            &right.path.join("signer.key"),
            &right.path.join("enrollment.redb"),
            p::InstallationPaths::new(
                &right.path.join("installation.redb"),
                &right.path.join("journal.redb"),
                &right.path.join("archives.redb"),
            )?,
        )?,
        intent,
    )?
    .activate(&policy, at, None)?;
    let (service, signer, device) = owner.parts()?;
    let mut leaves = Vec::new();
    for (ordinal, kind) in [
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
            device,
            p::PrekeyId::from_trusted_state([u8::try_from(ordinal + 71)?; 32])?,
            kind,
            advertisement,
            at,
        )?);
    }
    let manifest = signer.issue_manifest(
        device,
        p::ManifestContext::new(
            1,
            sdk.runtime()?.trusted_state().digest(),
            p::bootstrap_suite_digest(),
            [99; 32],
            advertisement,
        )?,
        &leaves,
    )?;
    let verified = device.verify_manifest(manifest.as_bytes(), at)?;
    let mut proofs = BTreeMap::new();
    for ordinal in 0..manifest.leaf_count() {
        let proof = manifest.proof(ordinal)?;
        proofs.insert(
            verified.verify_leaf(&proof, at)?.kind() as u8,
            proof.encode()?,
        );
    }
    let proof =
        |kind: p::LeafKind| -> Result<&[u8]> { Ok(proofs.get(&(kind as u8)).ok_or("proof")?) };
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: &left.certificate,
            initiator_roster: left.roster.as_bytes(),
            responder_credential: &right.certificate,
            responder_roster: right.roster.as_bytes(),
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    owner.close();
    policy.close();
    drop(policy);
    sdk.close();
    let peers = (left.path.join("peer"), right.path.join("peer"));
    for peer in [&peers.0, &peers.1] {
        fs::DirBuilder::new().mode(0o700).create(peer)?;
        fixture::store(peer, "bootstrap.bundle", bundle.as_bytes())?;
        fixture::store(peer, "directory", &[99; 32])?;
        for (label, side) in [("initiator", left), ("responder", right)] {
            for (name, bytes) in [
                ("account", side.root.account_id()?.to_vec()),
                ("root", side.root.public_key()?.encode()),
                (
                    "roster-version",
                    side.roster.checkpoint().version().to_be_bytes().to_vec(),
                ),
                ("roster-digest", side.roster.checkpoint().digest().to_vec()),
                ("device", vec![71; 16]),
                ("generation", 1u64.to_be_bytes().to_vec()),
            ] {
                fixture::store(peer, &format!("{label}-{name}"), &bytes)?;
            }
        }
    }
    for (peer, remote, name) in [
        (&peers.0, right, "responder.test"),
        (&peers.1, left, "initiator.test"),
    ] {
        fixture::store(
            peer,
            "tls-peer",
            &fixture::read(&remote.path, "tls-cert", 8192)?,
        )?;
        fixture::store(peer, "tls-peer-name", name.as_bytes())?;
    }
    Ok(peers)
}

fn peer_args(
    c: &Registered,
    peer: &Path,
    role: u8,
    continued: bool,
    session: Option<[u8; 32]>,
    operation: &str,
    tail: Vec<OsString>,
) -> Vec<OsString> {
    let mut args = vec![
        if continued {
            "--continued-enrollment-parent"
        } else {
            "--enrollment-parent"
        }
        .into(),
        c.path.as_os_str().into(),
        role.to_string().into(),
    ];
    if let Some(session) = session {
        args.extend(["--session".into(), fixture::hex(&session).into()]);
    }
    args.extend([operation.into(), peer.as_os_str().into()]);
    args.extend(tail);
    args
}

struct Server {
    child: fixture::OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
}
fn serve(c: &Registered, label: &str, args: &[OsString]) -> Result<(Server, std::net::SocketAddr)> {
    let stdout = c.path.join(format!("two-ended-{label}.stdout"));
    let stderr = c.path.join(format!("two-ended-{label}.stderr"));
    let file = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let mut server = Server {
        child: fixture::OwnedChild(
            Command::new(executable()?)
                .args(args)
                .stdout(Stdio::from(file(&stdout)?))
                .stderr(Stdio::from(file(&stderr)?))
                .spawn()?,
        ),
        stdout,
        stderr,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let output = fs::read_to_string(&server.stdout)?;
        if let Some((line, _)) = output.split_once('\n') {
            let port: u16 = line
                .strip_prefix("listening:")
                .ok_or("peer readiness shape")?
                .parse()?;
            assert_ne!(port, 0);
            return Ok((server, ([127, 0, 0, 1], port).into()));
        }
        if server.child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "foreign peer did not listen: {output}; {}",
                fs::read_to_string(&server.stderr)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn finish(mut server: Server, session: [u8; 32], message: [u8; 32]) -> Result<()> {
    let status = fixture::wait(&mut server.child)?;
    let stderr = fs::read_to_string(&server.stderr)?;
    assert!(
        status.success() && stderr.is_empty(),
        "foreign peer: {status}; {stderr}"
    );
    let stdout = fs::read_to_string(&server.stdout)?;
    let output = stdout.split_once('\n').ok_or("readiness line")?.1;
    let (kind, effects) = if message == [0; 32] { (1, 0) } else { (2, 1) };
    assert_eq!(
        output,
        format!(
            "served:{kind}:0:{effects}:{effects}\n{}\n{}\n",
            fixture::hex(&session),
            fixture::hex(&message)
        )
    );
    Ok(())
}
fn grant_inputs(local: &Registered, remote: &PreparedJoint) -> Result<PathBuf> {
    let path = local.path.join("peer-renewal");
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    for name in ["enrollment-root", "enrollment-intent", "trusted-account"] {
        fixture::store(&path, name, &fixture::read(&remote.c.path, name, 8192)?)?;
    }
    for (name, bytes) in [
        ("credential-renewal", remote.g1.wire.clone()),
        (
            "credential-operation",
            remote.g1.grant.operation().as_bytes().to_vec(),
        ),
        (
            "renewal-version",
            remote
                .g1
                .roster
                .checkpoint()
                .version()
                .to_be_bytes()
                .to_vec(),
        ),
        (
            "renewal-digest",
            remote.g1.roster.checkpoint().digest().to_vec(),
        ),
    ] {
        fixture::store(&path, name, &bytes)?;
    }
    Ok(path)
}

#[test]
fn c_both_expired_owners_resume_original_session_with_independent_peer_grants() -> Result<()> {
    let policy_root = Arc::new(p::PolicySigningKey::generate()?);
    let left = registered_with_policy_duration(120, Some(&policy_root), 120)?;
    let right = registered_with_policy_inputs(
        120,
        None,
        120,
        Some(&left.path),
        p::BootstrapRole::Responder,
    )?;
    assert_ne!(left.root.account_id()?, right.root.account_id()?);
    assert_ne!(left.accepted.1, right.accepted.1);
    assert_ne!(left.accepted.2, right.accepted.2);
    for name in POLICY_DOCUMENT_FILES {
        assert_eq!(
            fs::read(left.path.join(name))?,
            fs::read(right.path.join(name))?
        );
    }
    let (left_peer, right_peer) = peer_inputs(&left, &right)?;
    let bundle = fixture::read(
        &left_peer,
        "bootstrap.bundle",
        p::MAX_BOOTSTRAP_BUNDLE_BYTES,
    )?;
    let (server, address) = serve(
        &right,
        "bootstrap",
        &peer_args(
            &right,
            &right_peer,
            2,
            false,
            None,
            "serve",
            vec!["bootstrap".into()],
        ),
    )?;
    let initiation = p::InitiationId::generate()?;
    let session = decode_id(
        run(
            &left.path,
            "two-connect",
            &peer_args(
                &left,
                &left_peer,
                1,
                false,
                None,
                "connect",
                vec![
                    address.to_string().into(),
                    fixture::hex(initiation.as_bytes()).into(),
                ],
            ),
        )?
        .trim_end(),
    )?;
    finish(server, session, [0; 32])?;
    let message = decode_id(
        run(
            &left.path,
            "two-original-message",
            &peer_args(
                &left,
                &left_peer,
                1,
                false,
                Some(session),
                "next",
                vec![fixture::hex(&session).into()],
            ),
        )?
        .trim_end(),
    )?;
    let left = prepare_joint_for(left, Arc::clone(&policy_root), Some(120), 2400)?;
    let right = prepare_joint_with_target(
        right,
        policy_root,
        Some(120),
        2400,
        Some(&left.c.path.join("continued-sdk")),
    )?;
    assert_eq!(left.original_checkpoint, right.original_checkpoint);
    assert_eq!(left.target_checkpoint, right.target_checkpoint);
    assert_ne!(left.t1_statement, right.t1_statement);
    let originals = [&left, &right]
        .into_iter()
        .map(|side| {
            Ok((
                Zeroizing::new(fs::read(side.c.path.join("signer.key"))?),
                Zeroizing::new(fs::read(side.c.path.join("wrap.key"))?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let sdk = fixture::sdk(&left.c.path)?;
    let old = fixture::protocol_policy(&left.c.path, &sdk)?;
    let p0_until = old.validity().until();
    old.close();
    drop(old);
    drop(sdk);
    let expires = p0_until
        .max(left.c.validity.until())
        .max(right.c.validity.until());
    let deadline = Instant::now() + Duration::from_secs(180);
    while fixture::now()? < expires {
        if Instant::now() >= deadline {
            return Err("both-endpoint expiry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let expired_at = fixture::now()?;
    for side in [&left, &right] {
        let c = &side.c;
        let mut sdk = fixture::sdk(&c.path)?;
        let pin = p::PolicyPin::new(
            c.family,
            side.policy_root.public_key()?,
            side.original_checkpoint,
        )?;
        assert!(matches!(
            pin.verify(
                &fixture::read(&c.path, "protocol-policy", 8192)?,
                sdk.runtime()?,
                expired_at
            ),
            Err(p::Error::Validity)
        ));
        sdk.close();
        let account = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            c.roster.checkpoint(),
            c.family,
        )?;
        assert!(matches!(
            account.verify_device(&c.certificate, c.roster.as_bytes(), expired_at),
            Err(p::Error::Validity)
        ));
        let mut current_sdk = fixture::sdk(&c.path.join("continued-sdk"))?;
        let current = fixture::protocol_policy(&c.path.join("continued-sdk"), &current_sdk)?;
        assert_eq!(current.checkpoint(), side.target_checkpoint);
        let current_account = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            side.g1.roster.checkpoint(),
            c.family,
        )?;
        let current_device = current_account.verify_device(
            &side.g1.certificate,
            side.g1.roster.as_bytes(),
            expired_at,
        )?;
        assert_eq!(
            current_device.credential_digest(),
            side.g1.grant.successor_device().credential_digest()
        );
        current.close();
        drop(current);
        current_sdk.close();
        assert_eq!(
            observed(c, "two-expired-stage", "policy-stage")?,
            pending(&side.g1, side.t1_statement)
        );
        assert_eq!(
            observed(c, "two-expired-reconcile", "policy-reconcile")?,
            committed(&side.g1, side.t1_statement)
        );
        assert_eq!(
            run(
                &c.path,
                "two-local-active",
                &command(&c.path, "policy-activate")
            )?,
            "policy-device-active\n"
        );
    }
    for (side, peer, role) in [(&left, &left_peer, "1"), (&right, &right_peer, "2")] {
        assert_eq!(
            run(
                &side.c.path,
                "two-peer-missing",
                &[
                    "continued-peer-refused".into(),
                    side.c.path.as_os_str().into(),
                    peer.as_os_str().into(),
                    role.into(),
                    fixture::hex(&session).into()
                ]
            )?,
            "continued-peer-expired-refused\n"
        );
    }
    for (side, remote) in [(&left, &right), (&right, &left)] {
        let grant = grant_inputs(&side.c, remote)?;
        for label in ["two-peer-admit", "two-peer-admit-reopen"] {
            assert_eq!(
                run(
                    &side.c.path,
                    label,
                    &[
                        "continued-peer-admit".into(),
                        side.c.path.as_os_str().into(),
                        grant.as_os_str().into()
                    ]
                )?,
                "continued-peer-admitted\n"
            );
        }
    }
    let (server, address) = serve(
        &right.c,
        "continued",
        &peer_args(
            &right.c,
            &right_peer,
            2,
            true,
            Some(session),
            "serve",
            vec!["message".into()],
        ),
    )?;
    assert_eq!(
        run(
            &left.c.path,
            "two-send",
            &peer_args(
                &left.c,
                &left_peer,
                1,
                true,
                Some(session),
                "send",
                vec![
                    address.to_string().into(),
                    fixture::hex(&session).into(),
                    fixture::hex(&message).into()
                ]
            )
        )?,
        "consumed\n"
    );
    finish(server, session, message)?;
    fixture::effect(
        &right_peer,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    assert_eq!(
        run(
            &left.c.path,
            "two-ack-reopen",
            &peer_args(
                &left.c,
                &left_peer,
                1,
                true,
                Some(session),
                "status",
                vec![fixture::hex(&session).into(), fixture::hex(&message).into()]
            )
        )?,
        "3\n"
    );
    for ((side, peer), (signer, wrapping)) in [(&left, &left_peer), (&right, &right_peer)]
        .into_iter()
        .zip(originals)
    {
        original_identity(&side.c, "two-original-identity", &signer, &wrapping)?;
        assert_eq!(
            fixture::read(peer, "bootstrap.bundle", p::MAX_BOOTSTRAP_BUNDLE_BYTES)?,
            bundle
        );
        for (name, bytes) in &side.original_inputs {
            assert_eq!(fs::read(side.c.path.join(name))?, *bytes);
        }
        for (name, bytes) in &side.target_inputs {
            assert_eq!(
                fs::read(side.c.path.join("continued-sdk").join(name))?,
                *bytes
            );
        }
    }
    println!("C_BOTH_EXPIRED_POLICY_TRAFFIC original_session=true original_message=true both_current_refused=true missing_peer_grants_refused=true independent_grants=true peer_effect=true acknowledged_after_reopen=true immutable_originals=true");
    println!("C_BOTH_EXPIRED_POLICY_CLOCK p0_until={p0_until} left_until={} right_until={} resumed_at={} expired_at={expired_at}", left.c.validity.until(), right.c.validity.until(), fixture::now()?);
    Ok(())
}
