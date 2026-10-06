// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C registration from an empty device directory and separately approved root.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/openssl_host.rs"]
mod openssl_host;
#[path = "common/witness.rs"]
mod witness;
#[path = "common/witness_tls.rs"]
mod witness_tls;
#[path = "common/witness_tls_faults.rs"]
mod witness_tls_faults;
#[path = "common/witness_tls_relay.rs"]
mod witness_tls_relay;
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{
    filesystem::{open_private_database, PrivateDatabaseError},
    PolicyStore,
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct PolicyClient {
    executable: PathBuf,
    language: &'static str,
}
impl PolicyClient {
    fn selected() -> Result<Option<Self>> {
        Self::selected_for("POLICY")
    }
    fn selected_for(component: &str) -> Result<Option<Self>> {
        match (
            std::env::var_os(format!("QPERIAPT_{component}_LIFECYCLE_CLIENT")),
            std::env::var_os(format!("QPERIAPT_{component}_LIFECYCLE_LANGUAGE")),
        ) {
            (None, None) => Ok(None),
            (Some(path), Some(language)) => {
                let executable = PathBuf::from(path);
                if !executable.is_absolute() || !executable.is_file() {
                    return Err("foreign policy executable is not an absolute file".into());
                }
                let language = match language.to_str() {
                    Some("Swift") => "Swift",
                    Some("Kotlin") => "Kotlin",
                    _ => return Err("unqualified policy lifecycle language".into()),
                };
                Ok(Some(Self {
                    executable,
                    language,
                }))
            }
            _ => Err("foreign policy client and language must be selected together".into()),
        }
    }
}

fn executable() -> Result<PathBuf> {
    let path =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C executable missing")?);
    if !path.is_absolute() || !path.is_file() {
        return Err("C executable path".into());
    }
    Ok(path)
}
fn command(path: &Path, operation: &str) -> Vec<OsString> {
    vec![
        format!("enrollment-{operation}").into(),
        path.as_os_str().into(),
    ]
}
fn run(path: &Path, label: &str, args: &[OsString]) -> Result<String> {
    run_client(&executable()?, path, label, args)
}
fn run_client(client: &Path, path: &Path, label: &str, args: &[OsString]) -> Result<String> {
    let output = Command::new(client).args(args).output()?;
    fixture::store(path, &format!("enrollment-{label}.stdout"), &output.stdout)?;
    fixture::store(path, &format!("enrollment-{label}.stderr"), &output.stderr)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "C registration {label}: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn decode_id(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err("ID width".into());
    }
    let mut result = [0; 32];
    for (out, part) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digits = std::str::from_utf8(part)?;
        if !digits
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("ID encoding".into());
        }
        *out = u8::from_str_radix(digits, 16)?;
    }
    Ok(result)
}
fn state(text: &str) -> Result<(u32, [u8; 32], [u8; 32])> {
    let mut lines = text.lines();
    let phase = lines
        .next()
        .ok_or("phase")?
        .strip_prefix("enrollment-phase:")
        .ok_or("phase prefix")?
        .parse()?;
    let signing = decode_id(lines.next().ok_or("signing ID")?)?;
    let journal = decode_id(lines.next().ok_or("journal ID")?)?;
    if lines.next().is_some() {
        return Err("extra status lines".into());
    }
    Ok((phase, signing, journal))
}
fn lease(path: &Path, busy: bool) -> Result<()> {
    match open_private_database(&path.join("enrollment.redb")) {
        Err(PrivateDatabaseError::Busy) if busy => Ok(()),
        Ok(database) if !busy => {
            drop(database);
            Ok(())
        }
        Ok(_) => Err("registration lease released while C owner is alive".into()),
        Err(error) => Err(error.into()),
    }
}
fn peer_bundle(
    s: &fixture::Setup,
    client: &Path,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
) -> Result<PathBuf> {
    peer_bundle_with_witness(s, client, root, certificate, roster, None)
}
fn peer_bundle_with_witness(
    s: &fixture::Setup,
    client: &Path,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
    witness: Option<&fixture::WitnessFixture>,
) -> Result<PathBuf> {
    peer_bundle_at(
        &s.responder,
        &client.join("peer"),
        root,
        certificate,
        roster,
        witness,
    )
}
fn peer_bundle_at(
    remote: &Path,
    peer: &Path,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
    witness: Option<&fixture::WitnessFixture>,
) -> Result<PathBuf> {
    let mut sdk = fixture::sdk(remote)?;
    let policy_digest = sdk.runtime()?.trusted_state().digest();
    sdk.close();
    let mut server = fixture::Peer::open_with_witness(remote, witness)?;
    let context = Arc::clone(&server.context);
    let device = context.device(p::BootstrapRole::Responder);
    let at = fixture::now()?;
    let validity = p::Validity::new(
        at.saturating_sub(1),
        at.checked_add(600).ok_or("clock overflow")?,
    )?;
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
        leaves.push(server.service.stores()?.0.generate_prekey(
            context.current_policy()?,
            device,
            p::PrekeyId::from_trusted_state([u8::try_from(index + 71)?; 32])?,
            kind,
            validity,
            at,
        )?);
    }
    let manifest = server.service.parts()?.1.issue_manifest(
        device,
        p::ManifestContext::new(
            2,
            policy_digest,
            p::bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &leaves,
    )?;
    let verified = device.verify_manifest(manifest.as_bytes(), at)?;
    let mut proofs = BTreeMap::new();
    for index in 0..manifest.leaf_count() {
        let proof = manifest.proof(index)?;
        proofs.insert(
            verified.verify_leaf(&proof, at)?.kind() as u8,
            proof.encode()?,
        );
    }
    let proof =
        |kind: p::LeafKind| -> Result<&[u8]> { Ok(proofs.get(&(kind as u8)).ok_or("proof")?) };
    let remote_certificate = fixture::read(remote, "local-certificate", 8192)?;
    let remote_roster = fixture::read(remote, "local-roster", 8192)?;
    let bundle = p::BootstrapBundle::from_materials(
        p::PrekeyQuality::OneTimeBoth,
        p::BootstrapMaterials {
            initiator_credential: certificate,
            initiator_roster: roster.as_bytes(),
            responder_credential: &remote_certificate,
            responder_roster: &remote_roster,
            responder_manifest: manifest.as_bytes(),
            signed_classical: proof(p::LeafKind::SignedClassical)?,
            last_resort_pq: proof(p::LeafKind::LastResortPq)?,
            one_time_classical: Some(proof(p::LeafKind::OneTimeClassical)?),
            one_time_pq: Some(proof(p::LeafKind::OneTimePq)?),
        },
    )?;
    server.close();
    fs::DirBuilder::new().mode(0o700).create(peer)?;
    for name in [
        "responder-account",
        "responder-root",
        "responder-roster-version",
        "responder-roster-digest",
        "responder-device",
        "responder-generation",
        "directory",
    ] {
        fixture::store(peer, name, &fixture::read(remote, name, 8192)?)?;
    }
    for (name, bytes) in [
        ("initiator-account", root.account_id()?.to_vec()),
        ("initiator-root", root.public_key()?.encode()),
        (
            "initiator-roster-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "initiator-roster-digest",
            roster.checkpoint().digest().to_vec(),
        ),
        ("initiator-device", vec![71; 16]),
        ("initiator-generation", 1u64.to_be_bytes().to_vec()),
        ("bootstrap.bundle", bundle.as_bytes().to_vec()),
    ] {
        fixture::store(peer, name, &bytes)?;
        // Independently approved new remote peer inputs; the server's local identity is unchanged.
        fs::write(remote.join(name), bytes)?;
    }
    fixture::store(peer, "tls-peer", &fixture::read(remote, "tls-cert", 8192)?)?;
    fixture::store(peer, "tls-peer-name", b"responder.test")?;
    Ok(peer.to_owned())
}

#[test]
fn c_registration_owns_original_identity_through_connection_and_roster_refresh() -> Result<()> {
    let s = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let path = s.initiator.parent().ok_or("fixture root")?.join("enrolled");
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    // Only the independently provisioned SDK/policy and application TLS configuration
    // are reused. No wrapping key, signer, credential, roster or device DB is copied.
    for name in [
        "sdk-policy",
        "sdk-signature",
        "sdk-root",
        "family",
        "policy-root",
        "policy-version",
        "policy-digest",
        "protocol-policy",
        "tls-cert",
        "tls-key",
    ] {
        fs::copy(s.initiator.join(name), path.join(name))?;
    }
    let mut sdk = PolicyStore::provision(
        &path.join("sdk.redb"),
        &fixture::read(&path, "sdk-policy", 4096)?,
        &fixture::read(&path, "sdk-signature", 8192)?,
        &fixture::read(&path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    sdk.close();
    let mut root = p::RootSigningKey::generate()?;
    let family = fixture::array(&path, "family")?;
    let at = fixture::now()?;
    let until = at.checked_add(1800).ok_or("clock overflow")?;
    let validity = p::Validity::new(at.saturating_sub(1), until)?;
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new([71; 16], 1, family, validity)?,
    );
    let mut intent_bytes = vec![71; 16];
    intent_bytes.extend_from_slice(&1u64.to_be_bytes());
    intent_bytes.extend_from_slice(&family);
    intent_bytes.extend_from_slice(&validity.from().to_be_bytes());
    intent_bytes.extend_from_slice(&validity.until().to_be_bytes());
    fixture::store(&path, "enrollment-root", &root.public_key()?.encode())?;
    fixture::store(&path, "enrollment-intent", &intent_bytes)?;
    assert_eq!(
        run(&path, "key", &command(&path, "key"))?,
        "enrollment-key\n"
    );
    let wrapping = Zeroizing::new(fs::read(path.join("wrap.key"))?);
    let creating = state(&run(&path, "create", &command(&path, "create"))?)?;
    assert_eq!(creating.0, 1);
    assert!(!path.join("signer.key").exists() && !path.join("installation.redb").exists());
    let requested = state(&run(&path, "request", &command(&path, "request"))?)?;
    assert_eq!(requested.0, 2);
    assert_eq!(requested.1, creating.1);
    assert_eq!(
        state(&run(
            &path,
            "request-retry",
            &command(&path, "request-retry")
        )?)?,
        requested
    );
    let request = fixture::read(&path, "enrollment-request", 8192)?;
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, fixture::now()?)?;
    assert_eq!(*verified.identity().as_bytes(), requested.1);
    let certificate = root.issue_enrollment(&verified, fixture::now()?)?;
    let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
    let renewal = root.issue_roster(2, validity, &[root.roster_entry(&certificate)?])?;
    for (name, bytes) in [
        ("grant-certificate", certificate.clone()),
        ("grant-roster", roster.as_bytes().to_vec()),
        ("trusted-account", root.account_id()?.to_vec()),
        ("trusted-roster-version", 1u64.to_be_bytes().to_vec()),
        (
            "trusted-roster-digest",
            roster.checkpoint().digest().to_vec(),
        ),
        ("renewal-roster", renewal.as_bytes().to_vec()),
        ("renewal-version", 2u64.to_be_bytes().to_vec()),
        ("renewal-digest", renewal.checkpoint().digest().to_vec()),
    ] {
        fixture::store(&path, name, &bytes)?;
    }
    assert_eq!(
        run(&path, "reject", &command(&path, "reject-signature"))?,
        "enrollment-signature-refused\n"
    );
    lease(&path, false)?;
    assert_eq!(
        state(&run(&path, "after-reject", &command(&path, "status"))?)?,
        requested
    );
    let accepted = state(&run(&path, "accept", &command(&path, "accept"))?)?;
    assert_eq!(accepted.0, 3);
    assert_eq!(accepted.1, requested.1);
    assert_ne!(accepted.2, [0; 32]);
    assert_eq!(
        state(&run(&path, "storage", &command(&path, "storage"))?)?,
        accepted
    );
    let peer = peer_bundle(&s, &path, &root, &certificate, &roster)?;
    let release = path.join("release-enrollment");
    let stdout = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("enrollment-held.stdout"))?;
    let stderr = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("enrollment-held.stderr"))?;
    let mut held = fixture::OwnedChild(
        Command::new(executable()?)
            .args(command(&path, "hold"))
            .arg(&release)
            .arg(&peer)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("enrollment-held").exists() {
        if held.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("C enrolled lease owner failed".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    lease(&path, true)?;
    let mut observation = u64::from(held.0.id()).to_be_bytes().to_vec();
    observation.extend_from_slice(&u64::from(std::process::id()).to_be_bytes());
    fixture::store(&path, "enrollment-lease-observation", &observation)?;
    fixture::publish_marker(&path, "release-enrollment")?;
    let held_status = fixture::wait(&mut held)?;
    let held_error = fs::read(path.join("enrollment-held.stderr"))?;
    assert!(
        held_status.success() && held_error.is_empty(),
        "held enrolled owner: {held_status}; {}",
        String::from_utf8_lossy(&held_error)
    );
    lease(&path, false)?;
    let active = state(&run(&path, "active", &command(&path, "status"))?)?;
    assert_eq!((active.0, active.1, active.2), (5, accepted.1, accepted.2));
    assert_eq!(
        run(&path, "cancel", &command(&path, "cancel"))?,
        "enrollment-cancelled\n"
    );
    lease(&path, false)?;
    let (mut server, address) = fixture::spawn(&s.responder, 71, "bootstrap")?;
    let initiation = p::InitiationId::generate()?;
    let mut args = vec![
        "--enrollment-parent".into(),
        path.as_os_str().into(),
        "1".into(),
        "connect".into(),
        peer.as_os_str().into(),
        address.to_string().into(),
        fixture::hex(initiation.as_bytes()).into(),
    ];
    let session = decode_id(run(&path, "connect", &args)?.trim_end())?;
    assert!(fixture::wait(&mut server)?.success());
    assert_eq!(fixture::array::<32>(&s.responder, "session")?, session);
    let (mut server, address) = fixture::spawn(&s.responder, 72, "crash-after-application")?;
    args = vec![
        "--enrollment-parent".into(),
        path.as_os_str().into(),
        "1".into(),
        "--session".into(),
        fixture::hex(&session).into(),
        "next".into(),
        peer.as_os_str().into(),
        fixture::hex(&session).into(),
    ];
    let message = decode_id(run(&path, "next", &args)?.trim_end())?;
    args = vec![
        "--enrollment-parent".into(),
        path.as_os_str().into(),
        "1".into(),
        "--session".into(),
        fixture::hex(&session).into(),
        "uncertain-send".into(),
        peer.as_os_str().into(),
        address.to_string().into(),
        fixture::hex(&session).into(),
        fixture::hex(&message).into(),
    ];
    assert_eq!(
        run(&path, "uncertain", &args)?,
        "delivery-unknown-committed\n"
    );
    assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
    let refreshed = state(&run(&path, "refresh", &command(&path, "refresh"))?)?;
    assert_eq!(
        (refreshed.0, refreshed.1, refreshed.2),
        (6, accepted.1, accepted.2)
    );
    assert!(run(&path, "activate-current", &command(&path, "activate"))?
        .starts_with("enrollment-active\n"));
    let (mut server, address) = fixture::spawn(&s.responder, 73, "application")?;
    args = vec![
        "--enrollment-parent".into(),
        path.as_os_str().into(),
        "1".into(),
        "--session".into(),
        fixture::hex(&session).into(),
        "send".into(),
        peer.as_os_str().into(),
        address.to_string().into(),
        fixture::hex(&session).into(),
        fixture::hex(&message).into(),
    ];
    assert_eq!(run(&path, "retry", &args)?, "consumed\n");
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &s.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    let effects = fs::read_dir(&s.responder)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("application-")
        })
        .count();
    assert_eq!(effects, 1);
    assert!(
        wrapping.as_slice() == Zeroizing::new(fs::read(path.join("wrap.key"))?).as_slice(),
        "wrapping identity changed"
    );
    assert_eq!(fixture::read(&path, "enrollment-request", 8192)?, request);
    let mut registered = p::DeviceEnrollment::open(
        p::EnrollmentPaths::new(
            &path.join("wrap.key"),
            &path.join("signer.key"),
            &path.join("enrollment.redb"),
            p::InstallationPaths::new(
                &path.join("installation.redb"),
                &path.join("journal.redb"),
                &path.join("archives.redb"),
            )?,
        )?,
        intent,
    )?;
    assert_eq!(
        registered.status()?,
        p::EnrollmentStatus::Active(p::JournalIdentity::from_trusted_state(accepted.2)?)
    );
    registered.close();
    let final_status = state(&run(&path, "final-status", &command(&path, "status"))?)?;
    assert_eq!(
        (final_status.0, final_status.1, final_status.2),
        (5, accepted.1, accepted.2)
    );
    fs::rename(
        path.join("enrollment.redb"),
        path.join("enrollment-retained.redb"),
    )?;
    assert_eq!(
        run(
            &path,
            "missing-registration",
            &command(&path, "refuse-resume")
        )?,
        "enrollment-open-refused:204\n"
    );
    assert_eq!(
        run(&path, "creation-refused", &command(&path, "refuse-create"))?,
        "enrollment-open-refused:211\n"
    );
    assert_eq!(
        run(&path, "key-conflict", &command(&path, "key-conflict"))?,
        "enrollment-key-refused:211\n"
    );
    assert!(!path.join("enrollment.redb").exists());
    fs::rename(
        path.join("enrollment-retained.redb"),
        path.join("enrollment.redb"),
    )?;
    assert_eq!(
        state(&run(
            &path,
            "after-missing-registration",
            &command(&path, "status")
        )?)?,
        final_status
    );
    root.close();
    println!("C_ENROLLMENT_COMPLETE original_identity=true lease_retained=true original_session=true roster_refresh=true delivery_exact=true");
    Ok(())
}

#[path = "enrollment/credential_renewal.rs"]
mod credential_renewal;
