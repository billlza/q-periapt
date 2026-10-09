// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent foreign executables consume signed inputs, never a copied store/identity.
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{filesystem::publish_private_bytes, PolicyRecoveryTrust};
use q_periapt_sig::Signer;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[path = "common/first_connection.rs"]
mod first_connection;
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/peer_bundle.rs"]
mod peer_bundle;
#[path = "common/receiver_process.rs"]
mod receiver_process;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn client_language() -> Result<&'static str> {
    match std::env::var("QPC_CONFIGURATION_LANGUAGE") {
        Err(std::env::VarError::NotPresent) => Ok("C"),
        Ok(value) if value == "C" => Ok("C"),
        Ok(value) if value == "Swift" => Ok("Swift"),
        Ok(value) if value == "Kotlin" => Ok("Kotlin"),
        _ => Err("unsupported explicit configuration client language".into()),
    }
}

fn run(
    client: &Path,
    mode: &str,
    profile: &str,
    source: &Path,
    target: &Path,
    output: &Path,
) -> Result<()> {
    run_carrier(client, mode, profile, source, target, output, None)
}
fn run_carrier(
    client: &Path,
    mode: &str,
    profile: &str,
    source: &Path,
    target: &Path,
    output: &Path,
    carrier: Option<&str>,
) -> Result<()> {
    let log = output.with_extension("stdout");
    let error = output.with_extension("stderr");
    let mut command = Command::new(client);
    command
        .arg(mode)
        .arg(profile)
        .arg(source)
        .arg(target)
        .arg(output);
    if let Some(carrier) = carrier {
        command.arg(carrier);
    }
    let mut child = fixture::OwnedChild(
        command
            .stdout(Stdio::from(fs::File::create(&log)?))
            .stderr(Stdio::from(fs::File::create(&error)?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err("foreign configuration child deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stderr = fs::read(&error)?;
    assert!(
        status.success(),
        "foreign configuration failed: {status}; {}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        stderr.is_empty(),
        "foreign configuration stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let expected = match mode {
        "enroll-local" => "QPC_CONFIGURATION_LOCAL_ACTIVE\n",
        "connect" => "QPC_CONFIGURATION_CONNECTION_PASS\n",
        "uncertain-send" => "QPC_CONFIGURATION_UNKNOWN_COMMITTED\n",
        "retry-send" => "QPC_CONFIGURATION_ORIGINAL_ACKNOWLEDGED\n",
        "prepare" => "QPC_CONFIGURATION_GENESIS_PASS\n",
        "activate" => "QPC_CONFIGURATION_ACTIVATION_PASS\n",
        "activate-missing" => "QPC_CONFIGURATION_WITNESS_REQUIRED\n",
        "activate-bad-receipt" => "QPC_CONFIGURATION_WITNESS_RECEIPT_REFUSED\n",
        "wrong-witness" => "QPC_CONFIGURATION_WITNESS_SCOPE_REFUSED\n",
        "cancel" => "QPC_CONFIGURATION_CANCELLED\n",
        "cancel-create" => "QPC_CONFIGURATION_CREATE_CANCELLED\n",
        "gc-capacity" => "QPC_CONFIGURATION_GC_PASS\n",
        "arc-capacity" => "QPC_CONFIGURATION_ARC_PASS\n",
        "select-target" => "QPC_CONFIGURATION_TARGET_LEASE_PASS\n",
        "select-target-reject" => "QPC_CONFIGURATION_TARGET_FAILURE_PASS\n",
        "reconcile-refused" => "QPC_CONFIGURATION_RECONCILE_REFUSED\n",
        _ => "QPC_CONFIGURATION_REQUEST_PASS\n",
    };
    assert_eq!(fs::read_to_string(log)?, expected);
    Ok(())
}

// Export only public registration material. Private configuration and identity
// files remain in the temporary installation and are never copied into evidence.
fn export_public(
    source: &Path,
    base: &Path,
    language: &str,
    profile: &str,
    carrier: &str,
) -> Result<()> {
    let Some(root) = std::env::var_os("QPERIAPT_CONFIGURATION_EVIDENCE") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    if !root.is_absolute() || !root.is_dir() {
        return Err("explicit public configuration evidence directory".into());
    }
    let target = root.join(format!("{carrier}-{profile}"));
    fs::DirBuilder::new().mode(0o700).create(&target)?;
    let (original, repeated) = if carrier == "local" {
        ("first.request", "resumed.request")
    } else {
        ("request", "active-reopened")
    };
    for (name, path) in [
        ("request.bin", base.join(original)),
        ("replayed.bin", base.join(repeated)),
        ("root.bin", source.join("enrollment-root")),
        ("intent.bin", source.join("enrollment-intent")),
    ] {
        publish_private_bytes(&target.join(name), &fs::read(path)?)?;
    }
    {
        for (name, original) in [
            ("session.bin", "connected"),
            ("unknown.bin", "uncertain"),
            ("acknowledged.bin", "acknowledged"),
            ("after-traffic.bin", "after-traffic.request"),
            ("effect.bin", "effect-public"),
        ] {
            publish_private_bytes(&target.join(name), &fs::read(base.join(original))?)?;
        }
    }
    if carrier != "local" {
        publish_private_bytes(
            &target.join("genesis.bin"),
            &fs::read(base.join("genesis"))?,
        )?;
    }
    // All interpolated values are selected from the closed test enums above.
    let metadata = format!(
        "{{\"schema_version\":1,\"language\":\"{language}\",\"profile\":\"{profile}\",\"carrier\":\"{carrier}\",\"release_claim_eligible\":false}}\n"
    );
    publish_private_bytes(&target.join("manifest.json"), metadata.as_bytes())?;
    Ok(())
}

fn install_recovery(source: &Path) -> Result<()> {
    let (key, public) = q_periapt_backends::MlDsa65::generate([101; 32]);
    let key = Zeroizing::new(key);
    let scope = [102; 32];
    let trust = PolicyRecoveryTrust::new(scope, &fs::read(source.join("sdk-root"))?, &public)?;
    let mut proof = vec![0; 3309];
    q_periapt_backends::MlDsa65
        .sign(
            key.as_ref(),
            &trust.enrollment_message(),
            &[103; 32],
            &mut proof,
        )
        .map_err(|e| format!("test recovery proof: {e:?}"))?;
    publish_private_bytes(&source.join("recovery-scope"), &scope)?;
    publish_private_bytes(&source.join("recovery-root"), &public)?;
    publish_private_bytes(&source.join("recovery-enrollment"), &proof)?;
    Ok(())
}

#[test]
fn independent_c_configuration_creates_and_resumes_original_identity() -> Result<()> {
    let language = client_language()?;
    let client = PathBuf::from(
        std::env::var_os("QPC_CONFIGURATION_CLIENT").ok_or("explicit C client path is required")?,
    );
    assert!(client.is_absolute() && client.is_file());
    for recoverable in [false, true] {
        let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let base = dir.path().canonicalize()?;
        let source = base.join("independent-inputs");
        let target = base.join("new-installation");
        fs::DirBuilder::new().mode(0o700).create(&source)?;
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
            let input = Zeroizing::new(fs::read(reference.initiator.join(name))?);
            publish_private_bytes(&source.join(name), &input)?;
        }
        if recoverable {
            install_recovery(&source)?;
        }
        let authority = p::RootSigningKey::generate()?;
        let family = fixture::array(&source, "family")?;
        let now = fixture::now()?;
        let validity =
            p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
        let intent = p::EnrollmentIntent::new(
            authority.public_key()?,
            p::DeviceDescription::new([104; 16], 1, family, validity)?,
        );
        let mut wire = vec![104; 16];
        wire.extend_from_slice(&1u64.to_be_bytes());
        wire.extend_from_slice(&family);
        wire.extend_from_slice(&validity.from().to_be_bytes());
        wire.extend_from_slice(&validity.until().to_be_bytes());
        publish_private_bytes(
            &source.join("enrollment-root"),
            &authority.public_key()?.encode(),
        )?;
        publish_private_bytes(&source.join("enrollment-intent"), &wire)?;
        let profile = if recoverable { "recoverable" } else { "fixed" };
        let first = base.join("first.request");
        assert!(!target.exists());
        if language != "C" {
            // Language runtime disposal, not native process exit, must return prepared slots.
            run(
                &client,
                if language == "Swift" {
                    "arc-capacity"
                } else {
                    "gc-capacity"
                },
                profile,
                &source,
                &base.join("arc"),
                &base.join("arc-result"),
            )?;
            run(
                &client,
                "cancel-create",
                profile,
                &source,
                &base.join("cancel-create"),
                &base.join("cancel-create-result"),
            )?;
        }
        run(&client, "create", profile, &source, &target, &first)?;
        let original = fs::read(&first)?;
        let verified = p::VerifiedEnrollmentRequest::verify(&original, &intent, fixture::now()?)?;
        if language != "C" {
            let continuation = source.join("continuation");
            fs::DirBuilder::new().mode(0o700).create(&continuation)?;
            for file in fs::read_dir(&source)? {
                let file = file?;
                if file.file_type()?.is_file() {
                    let bytes = Zeroizing::new(fs::read(file.path())?);
                    publish_private_bytes(&continuation.join(file.file_name()), &bytes)?;
                }
            }
            let mut sdk = fixture::sdk(&reference.initiator)?;
            let previous = fixture::protocol_policy(&reference.initiator, &sdk)?;
            let issued = reference
                .policy_issuer
                .as_ref()
                .ok_or("policy issuer")?
                .issue_session_policy(
                    sdk.runtime()?.as_ref(),
                    p::SessionPolicyParameters::new(
                        2,
                        p::Validity::new(
                            previous.validity().from(),
                            previous
                                .validity()
                                .until()
                                .checked_add(3600)
                                .ok_or("clock")?,
                        )?,
                        p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                        p::AnchorRequirement::local_only(),
                        p::ApplicationSendBudget::new(1024)?,
                    )?,
                )?;
            previous.close();
            sdk.close();
            fs::write(continuation.join("protocol-policy"), issued.as_bytes())?;
            fs::write(
                continuation.join("policy-version"),
                issued.checkpoint().version().to_be_bytes(),
            )?;
            fs::write(
                continuation.join("policy-digest"),
                issued.checkpoint().digest(),
            )?;
            for action in ["select-target-reject", "select-target"] {
                let output = base.join(action);
                run(&client, action, profile, &source, &target, &output)?;
                assert_eq!(fs::read(output)?, original);
            }
        }

        assert!(
            target.join("wrap.key").is_file()
                && target.join("signer.key").is_file()
                && target.join("enrollment.redb").is_file()
        );
        assert!(!target.join("installation.redb").exists());
        if language != "C" {
            let reconciled = base.join("reconciled.request");
            run(&client, "reconcile", profile, &source, &target, &reconciled)?;
            assert_eq!(fs::read(reconciled)?, original);
        }
        // Mutable files inside the target cannot replace the explicit host trust.
        fs::write(target.join("sdk-root"), vec![0; 1952])?;
        fs::write(target.join("policy-root"), vec![0; p::PUBLIC_KEY_BYTES])?;
        if language != "C" {
            run(
                &client,
                "reconcile-refused",
                profile,
                &source,
                &target,
                &base.join("reconcile-refused"),
            )?;
        }
        let resumed = base.join("resumed.request");
        run(&client, "resume", profile, &source, &target, &resumed)?;
        let repeated = fs::read(resumed)?;
        assert_eq!(repeated, original);
        let reopened = p::VerifiedEnrollmentRequest::verify(&repeated, &intent, fixture::now()?)?;
        assert_eq!(reopened.identity(), verified.identity());
        // Continue the independently created identity through actual TLS. No SDK,
        // wrapping key, signer, enrollment, installation or journal is copied in.
        let certificate = authority.issue_enrollment(&reopened, fixture::now()?)?;
        let roster =
            authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
        for (name, bytes) in [
            ("grant-certificate", certificate.clone()),
            ("grant-roster", roster.as_bytes().to_vec()),
            ("trusted-account", authority.account_id()?.to_vec()),
            (
                "trusted-roster-version",
                roster.checkpoint().version().to_be_bytes().to_vec(),
            ),
            (
                "trusted-roster-digest",
                roster.checkpoint().digest().to_vec(),
            ),
        ] {
            publish_private_bytes(&source.join(name), &bytes)?;
        }
        run(
            &client,
            "enroll-local",
            profile,
            &source,
            &target,
            &base.join("active-local"),
        )?;
        assert_eq!(fs::read(base.join("active-local"))?, original);
        assert!(target.join("installation.redb").is_file());
        let connection = first_connection::Case {
            client: &client,
            source: &source,
            target: &target,
            base: &base,
            receiver: &reference.responder,
            language,
            profile,
            carrier: None,
        };
        connection.prepare(&authority, &certificate, &roster, None)?;
        connection.run(&original)?;
        export_public(&source, &base, language, profile, "local")?;
        println!(
            "\nINDEPENDENT_CONFIGURATION_PASS language={language} profile={profile} original_request_replayed=true"
        );
    }
    Ok(())
}

#[path = "common/witness.rs"]
mod witness;
#[path = "common/witness_tls.rs"]
mod witness_tls;

#[test]
fn independent_c_required_witness_registration_uses_original_host_trust() -> Result<()> {
    let language = client_language()?;
    let client = PathBuf::from(
        std::env::var_os("QPC_CONFIGURATION_CLIENT").ok_or("explicit C client path")?,
    );
    assert!(client.is_absolute() && client.is_file());
    for carrier in ["signed", "tls"] {
        for recoverable in [false, true] {
            let profile = if recoverable { "recoverable" } else { "fixed" };
            let mut witness = witness::Witness::start()?;
            let reference = fixture::setup_with_witness(Some(&witness.configured))?;
            let witness_pin = witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .pin()?;
            let dir = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()?;
            let base = dir.path().canonicalize()?;
            let source = base.join("independent-inputs");
            let target = base.join("new-installation");
            fs::DirBuilder::new().mode(0o700).create(&source)?;
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
                let bytes = Zeroizing::new(fs::read(reference.initiator.join(name))?);
                publish_private_bytes(&source.join(name), &bytes)?;
            }
            if recoverable {
                install_recovery(&source)?;
            }
            for (name, bytes) in [
                ("witness-id", witness_pin.identity().as_bytes().to_vec()),
                ("witness-public", witness_pin.public_key().encode()),
                (
                    "witness-address",
                    witness.configured.address.to_string().into_bytes(),
                ),
            ] {
                publish_private_bytes(&source.join(name), &bytes)?;
            }
            let authority = p::RootSigningKey::generate()?;
            let family = fixture::array::<32>(&source, "family")?;
            let now = fixture::now()?;
            let validity =
                p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
            let device_id = [117; 16];
            let intent = p::EnrollmentIntent::new(
                authority.public_key()?,
                p::DeviceDescription::new(device_id, 1, family, validity)?,
            );
            let mut intent_bytes = device_id.to_vec();
            intent_bytes.extend_from_slice(&1u64.to_be_bytes());
            intent_bytes.extend_from_slice(&family);
            intent_bytes.extend_from_slice(&validity.from().to_be_bytes());
            intent_bytes.extend_from_slice(&validity.until().to_be_bytes());
            publish_private_bytes(
                &source.join("enrollment-root"),
                &authority.public_key()?.encode(),
            )?;
            publish_private_bytes(&source.join("enrollment-intent"), &intent_bytes)?;
            assert!(!target.exists());
            run_carrier(
                &client,
                "create",
                profile,
                &source,
                &target,
                &base.join("request"),
                Some("signed"),
            )?;
            run_carrier(
                &client,
                "wrong-witness",
                profile,
                &source,
                &target,
                &base.join("wrong"),
                Some("signed"),
            )?;
            run_carrier(
                &client,
                "resume",
                profile,
                &source,
                &target,
                &base.join("request-replayed"),
                Some("signed"),
            )?;
            run_carrier(
                &client,
                "cancel",
                profile,
                &source,
                &target,
                &base.join("cancelled"),
                Some("signed"),
            )?;
            let request = fs::read(base.join("request"))?;
            assert_eq!(fs::read(base.join("request-replayed"))?, request);
            let verified =
                p::VerifiedEnrollmentRequest::verify(&request, &intent, fixture::now()?)?;
            let certificate = authority.issue_enrollment(&verified, fixture::now()?)?;
            let roster =
                authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
            for (name, bytes) in [
                ("grant-certificate", certificate.clone()),
                ("grant-roster", roster.as_bytes().to_vec()),
                ("trusted-account", authority.account_id()?.to_vec()),
                (
                    "trusted-roster-version",
                    roster.checkpoint().version().to_be_bytes().to_vec(),
                ),
                (
                    "trusted-roster-digest",
                    roster.checkpoint().digest().to_vec(),
                ),
            ] {
                publish_private_bytes(&source.join(name), &bytes)?;
            }
            run_carrier(
                &client,
                "prepare",
                profile,
                &source,
                &target,
                &base.join("genesis"),
                Some("signed"),
            )?;
            let before = witness.captured.lock().map_err(|_| "capture")?.len();
            run_carrier(
                &client,
                "activate-missing",
                profile,
                &source,
                &target,
                &base.join("missing"),
                None,
            )?;
            assert_eq!(
                before,
                witness.captured.lock().map_err(|_| "capture")?.len()
            );
            // The separate control-plane operator approves only the exported public
            // genesis and independently authenticated account/policy. It never opens
            // the C device's wrapping key, signer, enrollment or journal databases.
            let exported = fs::read(base.join("genesis"))?;
            assert_eq!(exported.len(), 164);
            assert_eq!(exported.get(..4), Some(&2u32.to_be_bytes()[..]));
            let journal = p::JournalIdentity::from_trusted_state(
                exported.get(4..36).ok_or("journal")?.try_into()?,
            )?;
            let subject =
                p::AnchorSubject::from_trusted_state(exported.get(36..132).ok_or("subject")?)?;
            let genesis = p::AnchorGenesis::from_trusted_state(
                subject,
                exported.get(132..164).ok_or("digest")?.try_into()?,
            )?;
            let account = p::AccountPin::new(
                authority.account_id()?,
                authority.public_key()?,
                roster.checkpoint(),
                family,
            )?;
            let device = account.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
            let mut sdk = fixture::sdk(&reference.initiator)?;
            let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
            assert_eq!(
                subject,
                p::AnchorSubject::for_device(journal, &device, policy.as_ref())?
            );
            witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .enroll(&genesis, &device, &policy, fixture::now()?)?;
            let connection = first_connection::Case {
                client: &client,
                source: &source,
                target: &target,
                base: &base,
                receiver: &reference.responder,
                language,
                profile,
                carrier: Some(carrier),
            };
            // Prepare responder prekeys before measuring TLS traffic. Its original
            // setup witness uses signed TCP; runtime traffic must use selected TLS.
            connection.prepare(&authority, &certificate, &roster, Some(&witness.configured))?;
            let mut tls = if carrier == "tls" {
                publish_private_bytes(&source.join("witness-subject"), &subject.to_bytes())?;
                let server = witness_tls::TlsWitness::start(
                    std::sync::Arc::clone(&witness.configured.store),
                    [source.as_path(), reference.responder.as_path()],
                )?;
                fs::write(source.join("witness-address"), server.address.to_string())?;
                Some(server)
            } else {
                None
            };
            if carrier == "signed" {
                witness.arm(2)?;
                run_carrier(
                    &client,
                    "activate-bad-receipt",
                    profile,
                    &source,
                    &target,
                    &base.join("bad-receipt"),
                    Some("signed"),
                )?;
                assert_eq!(fs::read(base.join("bad-receipt"))?, request);
            }
            let measured_start = witness.captured.lock().map_err(|_| "capture")?.len();
            run_carrier(
                &client,
                "activate",
                profile,
                &source,
                &target,
                &base.join("active"),
                Some(carrier),
            )?;
            assert_eq!(fs::read(base.join("active"))?, request);
            for child in fs::read_dir(&target)? {
                assert!(!child?.file_name().to_string_lossy().starts_with("witness-"));
            }
            // These mutable files must never replace explicit host trust on reopen.
            for name in [
                "witness-id",
                "witness-public",
                "witness-tls-peer",
                "witness-tls-key",
            ] {
                publish_private_bytes(&target.join(name), &[0; 32])?;
            }
            run_carrier(
                &client,
                "activate",
                profile,
                &source,
                &target,
                &base.join("active-reopened"),
                Some(carrier),
            )?;
            assert_eq!(fs::read(base.join("active-reopened"))?, request);
            connection.run(&request)?;
            if let Some(server) = &mut tls {
                assert!(server.admitted.load(std::sync::atomic::Ordering::Acquire) >= 2);
                assert_eq!(
                    witness.captured.lock().map_err(|_| "capture")?.len(),
                    measured_start,
                    "TLS must not fall back to signed TCP"
                );
                assert!(server.finish()?.is_empty());
            } else {
                // Preserve the actual witness exchange records for this configured path.
                let records = witness.captured.lock().map_err(|_| "capture")?;
                assert!(records.len() > measured_start);
                for record in records.iter().skip(measured_start) {
                    assert!(record.delivered);
                    assert!(!record.request.is_empty() && !record.reply.is_empty());
                }
                drop(records);
            }
            witness.join()?;
            policy.close();
            sdk.close();
            export_public(&source, &base, language, profile, carrier)?;
            println!("\nINDEPENDENT_WITNESS_CONFIGURATION_PASS language={language} carrier={carrier} profile={profile} remote_genesis_only=true original_request_replayed=true");
        }
    }
    Ok(())
}
