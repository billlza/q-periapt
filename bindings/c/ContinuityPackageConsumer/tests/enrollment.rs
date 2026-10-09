// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C registration from an empty device directory and separately approved root.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/openssl_host.rs"]
mod openssl_host;
#[path = "common/peer_bundle.rs"]
mod peer_bundle;
#[path = "common/witness.rs"]
mod witness;
#[path = "common/witness_tls.rs"]
mod witness_tls;
#[path = "common/witness_tls_faults.rs"]
mod witness_tls_faults;
#[path = "common/witness_tls_relay.rs"]
mod witness_tls_relay;
use peer_bundle::peer_bundle_at;
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

#[test]
fn c_registration_owns_original_identity_through_connection_and_roster_refresh() -> Result<()> {
    registration_workload(false, false)
}
#[test]
fn c_registered_publication_recovers_exact_artifact_before_normal_connection() -> Result<()> {
    registration_workload(true, false)
}
#[test]
fn c_registered_configured_peer_reopens_original_session_after_roster_refresh() -> Result<()> {
    registration_workload(false, true)
}
fn registration_workload(publication: bool, configured: bool) -> Result<()> {
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
    let run_peer = |path: &Path, label: &str, arguments: &[OsString]| {
        let mut selected = arguments.to_vec();
        if configured {
            selected.insert(0, "--peer-configured".into());
        }
        run(path, label, &selected)
    };
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
    if publication {
        publication_workload(&path, &root, &certificate, &roster, validity)?;
    }

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
    let session = decode_id(run_peer(&path, "connect", &args)?.trim_end())?;
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
    let message = decode_id(run_peer(&path, "next", &args)?.trim_end())?;
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
        run_peer(&path, "uncertain", &args)?,
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
    assert_eq!(run_peer(&path, "retry", &args)?, "consumed\n");
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

fn publication_workload(
    path: &Path,
    root: &p::RootSigningKey,
    certificate: &[u8],
    roster: &p::IssuedRoster,
    validity: p::Validity,
) -> Result<()> {
    let mut sdk = fixture::sdk(path)?;
    let policy = fixture::protocol_policy(path, &sdk)?;
    let from = fixture::now()?
        .max(policy.validity().from())
        .max(validity.from());
    let until = policy.validity().until().min(validity.until());
    sdk.close();
    drop(policy);
    let mut plan = vec![99; 32];
    plan.extend_from_slice(&from.to_be_bytes());
    plan.extend_from_slice(&until.to_be_bytes());
    fixture::store(path, "publication-plan", &plan)?;
    let args = |command: &str, id: Option<&str>| {
        let mut out: Vec<OsString> = vec![
            "--enrollment-parent".into(),
            path.as_os_str().into(),
            "1".into(),
            command.into(),
            path.as_os_str().into(),
        ];
        if let Some(id) = id {
            out.push(id.into());
        }
        out
    };
    let id_text = run(path, "publication-next", &args("publication-next", None))?;
    let id = decode_id(id_text.trim_end())?;
    fixture::store(path, "publication-id", &id)?;
    let prepared = run(
        path,
        "publication-prepare",
        &args("publication-prepare", Some(id_text.trim_end())),
    )?;
    assert!(prepared.starts_with("publication-state:2\n"));
    assert_eq!(
        run(
            path,
            "publication-retry",
            &args("publication-retry", Some(id_text.trim_end()))
        )?,
        prepared
    );
    let wire = fixture::read(path, "publication-artifact", 2 * 1024 * 1024)?;
    assert_eq!(
        fixture::read(path, "publication-retry", 2 * 1024 * 1024)?,
        wire
    );
    let family = fixture::array(path, "family")?;
    let pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let device = pin.verify_device(certificate, roster.as_bytes(), fixture::now()?)?;
    fixture::publication::decode(&wire, id, &device, fixture::now()?)?;
    let next = run(path, "publication-next-2", &args("publication-next", None))?;
    assert_ne!(next, id_text);
    assert_eq!(
        run(
            path,
            "publication-cancel",
            &args("publication-cancel", Some(next.trim_end()))
        )?,
        "publication-cancelled\n"
    );
    assert!(run(
        path,
        "publication-absent",
        &args("publication-status", Some(next.trim_end()))
    )?
    .starts_with("publication-state:0\n"));
    assert!(run(
        path,
        "publication-retire",
        &args("publication-retire", Some(id_text.trim_end()))
    )?
    .starts_with("publication-state:3\n"));
    assert_eq!(
        run(
            path,
            "publication-next-retained",
            &args("publication-next", None)
        )?,
        next
    );
    println!("C_PUBLICATION original_id=true exact_artifact=true all_proofs_verified=true short_buffer_no_mutation=true cancelled_next_absent=true retirement_floor=true");
    Ok(())
}
