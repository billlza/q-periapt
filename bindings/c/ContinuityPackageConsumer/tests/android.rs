// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public JNI/ART consumers generate their own identities and use real transport.
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/peer_bundle.rs"]
mod peer_bundle;
#[path = "common/recovery_inputs.rs"]
mod recovery_inputs;
use recovery_inputs::install_recovery;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[path = "common/android_credential.rs"]
mod android_credential;
#[path = "common/android_credential_traffic.rs"]
mod android_credential_traffic;
#[path = "common/android_remote_credential.rs"]
mod android_remote_credential;
#[path = "common/android_witness.rs"]
mod android_witness;
#[path = "common/receiver_process.rs"]
mod receiver_process;
#[path = "common/witness_tls.rs"]
mod witness_tls;
#[path = "common/witness_tls_faults.rs"]
mod witness_tls_faults;
#[path = "common/witness_tls_relay.rs"]
mod witness_tls_relay;

fn independent_inputs(
    source: &Path,
    inputs: &Path,
) -> Result<(p::RootSigningKey, p::EnrollmentIntent, p::Validity)> {
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
        let bytes = Zeroizing::new(fs::read(source.join(name))?);
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    install_recovery(inputs)?;
    let authority = p::RootSigningKey::generate()?;
    let family = fixture::array(inputs, "family")?;
    let now = fixture::now()?;
    let validity = p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
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
        &inputs.join("enrollment-root"),
        &authority.public_key()?.encode(),
    )?;
    publish_private_bytes(&inputs.join("enrollment-intent"), &wire)?;
    Ok((authority, intent, validity))
}

fn run_foreign(
    client: &Path,
    profile: &str,
    inputs: &Path,
    base: &Path,
    mode: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let result = base.join(label);
    let stdout = base.join(format!("{label}.stdout"));
    let stderr = base.join(format!("{label}.stderr"));
    let mut child = fixture::OwnedChild(
        Command::new(client)
            .arg(mode)
            .arg(profile)
            .arg(inputs)
            .arg(base.join("installation"))
            .arg(&result)
            .stdout(Stdio::from(fs::File::create(&stdout)?))
            .stderr(Stdio::from(fs::File::create(&stderr)?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err("Android consumer process deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let diagnostic = fs::read(&stderr)?;
    assert!(
        status.success() && diagnostic.is_empty(),
        "{profile}/{label}: {status}; {}",
        String::from_utf8_lossy(&diagnostic)
    );
    assert_eq!(
        fs::read_to_string(stdout)?.trim(),
        format!("{profile}:{mode}:passed")
    );
    Ok(fs::read(result)?)
}

fn issue_grant(
    inputs: &Path,
    authority: &p::RootSigningKey,
    intent: &p::EnrollmentIntent,
    validity: p::Validity,
    original: &[u8],
) -> Result<(Vec<u8>, p::IssuedRoster)> {
    let verified = p::VerifiedEnrollmentRequest::verify(original, intent, fixture::now()?)?;
    let certificate = authority.issue_enrollment(&verified, fixture::now()?)?;
    let roster = authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
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
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    Ok((certificate, roster))
}

#[test]
fn android_lifecycle() -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let client = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("client driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for profile in ["fixed", "recoverable"] {
        let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
        let base = output.join(profile);
        fs::DirBuilder::new().mode(0o700).create(&base)?;
        let inputs = base.join("inputs");
        fs::DirBuilder::new().mode(0o700).create(&inputs)?;
        let (authority, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
        let run =
            |mode: &str, label: &str| run_foreign(&client, profile, &inputs, &base, mode, label);
        let original = run("enrollment-create", "original.request")?;
        assert_eq!(run("enrollment-resume", "resumed.request")?, original);
        let (certificate, roster) = issue_grant(&inputs, &authority, &intent, validity, &original)?;
        assert_eq!(run("enrollment-reject", "rejected")?, vec![1]);
        assert_eq!(
            run("enrollment-resume", "after-rejection.request")?,
            original
        );
        assert_eq!(run("enrollment-activate", "activated.request")?, original);
        assert_eq!(run("enrollment-active-reopen", "active-reopened")?, vec![1]);

        peer_bundle::peer_bundle_at(
            &reference.responder,
            &inputs.join("peer"),
            &authority,
            &certificate,
            &roster,
            None,
        )?;
        let initiation = p::InitiationId::generate()?;
        publish_private_bytes(&inputs.join("connection-initiation"), initiation.as_bytes())?;
        let (mut server, address) = fixture::spawn(&reference.responder, 81, "bootstrap")?;
        publish_private_bytes(
            &inputs.join("connection-address"),
            address.to_string().as_bytes(),
        )?;
        let session: [u8; 32] = run("peer-connect", "connected.session")?
            .try_into()
            .map_err(|_| "session width")?;
        assert!(fixture::wait(&mut server)?.success());
        assert_eq!(
            fixture::array::<32>(&reference.responder, "session")?,
            session
        );
        publish_private_bytes(&inputs.join("connection-session"), &session)?;
        let (mut server, address) =
            fixture::spawn(&reference.responder, 82, "crash-after-application")?;
        fs::write(inputs.join("connection-address"), address.to_string())?;
        let uncertain = run("peer-uncertain", "uncertain.message")?;
        assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
        assert_eq!(uncertain.len(), 64);
        assert_eq!(uncertain.get(..32).ok_or("session")?, session);
        let message: [u8; 32] = uncertain.get(32..).ok_or("message")?.try_into()?;
        publish_private_bytes(&inputs.join("connection-message"), &message)?;
        let effect_path = reference
            .responder
            .join(format!("application-{}", fixture::hex(&message)));
        let effect = fs::read(&effect_path)?;
        let (mut server, address) = fixture::spawn(&reference.responder, 83, "application")?;
        fs::write(inputs.join("connection-address"), address.to_string())?;
        assert_eq!(run("peer-retry", "acknowledged.message")?, uncertain);
        assert!(fixture::wait(&mut server)?.success());
        assert_eq!(fs::read(effect_path)?, effect);
        fixture::effect(
            &reference.responder,
            session,
            p::MessageId::from_trusted_state(message)?,
            b"persisted before process exit",
        )?;
        let (mut server, address) = fixture::spawn(&reference.responder, 84, "rekey")?;
        fs::write(inputs.join("connection-address"), address.to_string())?;
        assert_eq!(run("peer-rekey", "rekeyed")?, vec![1]);
        assert!(fixture::wait(&mut server)?.success());
        let reverse = base.join("reverse.result");
        let mut listener = fixture::OwnedChild(
            Command::new(&client)
                .arg("peer-serve")
                .arg(profile)
                .arg(&inputs)
                .arg(base.join("installation"))
                .arg(&reverse)
                .stdout(Stdio::from(fs::File::create(base.join("reverse.stdout"))?))
                .stderr(Stdio::from(fs::File::create(base.join("reverse.stderr"))?))
                .spawn()?,
        );
        let ready = base.join("reverse.result.ready");
        let deadline = Instant::now() + Duration::from_secs(60);
        let port: u16 = loop {
            match fs::read_to_string(&ready) {
                Ok(value) => break value.parse()?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            if listener.0.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err(format!(
                    "receiver readiness: {}",
                    fs::read_to_string(base.join("reverse.stderr"))?
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_ne!(port, 0);
        let mut remote = fixture::Peer::open(&reference.responder)?;
        let endpoint = p::connection_transport::ConnectionEndpoint::client(
            &remote.context,
            remote.credentials(),
            fixture::tls_limits(),
        )?;
        let context = std::sync::Arc::clone(&remote.context);
        let id = remote
            .service
            .stores()?
            .0
            .next_message_id(&context, session, fixture::now()?)?;
        let body = b"reverse delivery after rekey";
        let delivered = fixture::send(
            &mut remote,
            &endpoint,
            format!("127.0.0.1:{port}").parse()?,
            session,
            id,
            body,
        )?;
        assert_eq!(
            delivered.consumption,
            p::connection_transport::Consumption::Confirmed
        );
        remote.close();
        assert!(
            fixture::wait(&mut listener)?.success(),
            "{}",
            fs::read_to_string(base.join("reverse.stderr"))?
        );
        assert!(fs::read(base.join("reverse.stderr"))?.is_empty());
        assert_eq!(
            fs::read_to_string(base.join("reverse.stdout"))?.trim(),
            format!("{profile}:peer-serve:passed")
        );
        let mut expected = session.to_vec();
        expected.extend_from_slice(id.as_bytes());
        expected.extend_from_slice(body);
        assert_eq!(fs::read(reverse)?, expected);
        assert_eq!(run("peer-cancel", "cancelled")?, vec![1]);
        println!("qualified {profile}: 12 foreign processes; registration, original retry, rekey, reverse callback retry, cancellation and concurrent close");
    }
    Ok(())
}
