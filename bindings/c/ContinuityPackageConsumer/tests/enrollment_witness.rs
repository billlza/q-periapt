// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real C registration and its original independently enrolled TCP/TLS witness.
#[path = "../packages/q-periapt-continuity-identity-candidate-0.0.0/tests/owned_connection.rs"]
mod fixture;
#[path = "common/witness.rs"]
mod witness;
#[path = "enrollment/witness_cancellation.rs"]
mod witness_cancellation;
#[path = "enrollment/witness_commit_error.rs"]
mod witness_commit_error;
#[path = "enrollment/witness_credential_renewal.rs"]
mod witness_credential_renewal;
#[path = "enrollment/witness_policy_continuation.rs"]
mod witness_policy_continuation;
#[path = "enrollment/witness_policy_expiry.rs"]
mod witness_policy_expiry;
#[path = "common/witness_tls.rs"]
mod witness_tls;

#[path = "common/witness_tls_relay.rs"]
mod witness_tls_relay;
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{filesystem::open_private_database, PolicyStore};
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::Ordering, Arc},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy)]
struct Endpoint {
    address: SocketAddr,
    tls: bool,
}
#[derive(Debug, Eq, PartialEq)]
struct State {
    phase: u32,
    signer: [u8; 32],
    journal: [u8; 32],
}
struct Registration {
    root: p::RootSigningKey,
    validity: p::Validity,
    path: PathBuf,
    intent: p::EnrollmentIntent,
    original: p::VerifiedDevice,
    next: p::VerifiedDevice,
    accepted: State,
    request: Vec<u8>,
    subject: p::AnchorSubject,
}

fn executable() -> Result<PathBuf> {
    let path =
        PathBuf::from(std::env::var_os("QPERIAPT_C_OWNER_CLIENT").ok_or("C executable missing")?);
    if !path.is_absolute() || !path.is_file() {
        return Err("C executable path".into());
    }
    Ok(path)
}
fn arguments(path: &Path, operation: &str, endpoint: Option<Endpoint>) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(endpoint) = endpoint {
        args.push(if endpoint.tls {
            "--witness-tls".into()
        } else {
            "--witness".into()
        });
        args.push(endpoint.address.to_string().into());
    }
    args.extend([
        format!("enrollment-{operation}").into(),
        path.as_os_str().into(),
    ]);
    args
}
fn run(path: &Path, label: &str, args: &[OsString]) -> Result<String> {
    let output = Command::new(executable()?).args(args).output()?;
    fixture::store(
        path,
        &format!("witness-enrollment-{label}.stdout"),
        &output.stdout,
    )?;
    fixture::store(
        path,
        &format!("witness-enrollment-{label}.stderr"),
        &output.stderr,
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "C witnessed registration {label}: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn decode_id(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("public ID width".into());
    }
    let mut result = [0; 32];
    for (out, bytes) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("public ID encoding".into());
        }
        *out = u8::from_str_radix(std::str::from_utf8(bytes)?, 16)?;
    }
    Ok(result)
}
fn state(value: &str) -> Result<State> {
    let mut lines = value.lines();
    let phase = lines
        .next()
        .ok_or("phase")?
        .strip_prefix("enrollment-phase:")
        .ok_or("phase prefix")?
        .parse()?;
    let signer = decode_id(lines.next().ok_or("signing identity")?)?;
    let journal = decode_id(lines.next().ok_or("journal identity")?)?;
    if lines.next().is_some() || signer == [0; 32] {
        return Err("registration status shape".into());
    }
    Ok(State {
        phase,
        signer,
        journal,
    })
}
fn account(value: &str) -> Result<[u8; 32]> {
    let mut lines = value.lines();
    if lines.next() != Some("enrollment-active") {
        return Err("activation output".into());
    }
    let account = decode_id(lines.next().ok_or("next account identity")?)?;
    if lines.next().is_some() || account == [0; 32] {
        return Err("next account shape".into());
    }
    Ok(account)
}
fn lease_released(path: &Path) -> Result<()> {
    drop(open_private_database(&path.join("enrollment.redb"))?);
    Ok(())
}

fn prepare(s: &fixture::Setup, witness: &witness::Witness) -> Result<Registration> {
    prepare_with_policy_lifetime(s, witness, None)
}
// Sign the original policy before any registration request or journal exists.
// This test option never replaces a policy already bound to an installation.
fn prepare_with_policy_lifetime(
    s: &fixture::Setup,
    witness: &witness::Witness,
    lifetime: Option<u64>,
) -> Result<Registration> {
    if let Some(seconds) = lifetime {
        let mut authority = p::PolicySigningKey::generate()?;
        let result = prepare_with_original_policy(s, witness, Some((seconds, &authority)));
        authority.close();
        result
    } else {
        prepare_with_original_policy(s, witness, None)
    }
}
fn prepare_with_original_policy(
    s: &fixture::Setup,
    witness: &witness::Witness,
    policy: Option<(u64, &p::PolicySigningKey)>,
) -> Result<Registration> {
    let path = s
        .initiator
        .parent()
        .ok_or("fixture root")?
        .join("enrolled-witness");
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    // Only policy and application-TLS configuration are reused. The registration,
    // signer, credential, roster, installation and every database are new.
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
        if policy.is_some()
            && matches!(
                name,
                "family" | "policy-root" | "policy-version" | "policy-digest" | "protocol-policy"
            )
        {
            continue;
        }
        fs::copy(s.initiator.join(name), path.join(name))?;
    }
    let mut sdk = PolicyStore::provision(
        &path.join("sdk.redb"),
        &fixture::read(&path, "sdk-policy", 4096)?,
        &fixture::read(&path, "sdk-signature", 8192)?,
        &fixture::read(&path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    if let Some((seconds, authority)) = policy {
        let at = fixture::now()?;
        let pin = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?
            .pin()?;
        let runtime = sdk.runtime()?;
        let issued = authority.issue_session_policy(
            &runtime,
            p::SessionPolicyParameters::new(
                1,
                p::Validity::new(
                    at.saturating_sub(1),
                    at.checked_add(seconds).ok_or("policy time overflow")?,
                )?,
                p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                p::AnchorRequirement::required(&pin),
                p::ApplicationSendBudget::new(1024)?,
            )?,
        )?;
        for (name, bytes) in [
            ("family", authority.policy_family()?.to_vec()),
            ("policy-root", authority.public_key()?.encode()),
            (
                "policy-version",
                issued.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("policy-digest", issued.checkpoint().digest().to_vec()),
            ("protocol-policy", issued.as_bytes().to_vec()),
        ] {
            fixture::store(&path, name, &bytes)?;
        }
    }
    sdk.close();
    let root = p::RootSigningKey::generate()?;
    let at = fixture::now()?;
    let validity = p::Validity::new(
        at.saturating_sub(1),
        at.checked_add(1800).ok_or("clock overflow")?,
    )?;
    let family = fixture::array(&path, "family")?;
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new([72; 16], 1, family, validity)?,
    );
    let mut encoded = vec![72; 16];
    encoded.extend_from_slice(&1u64.to_be_bytes());
    encoded.extend_from_slice(&family);
    encoded.extend_from_slice(&validity.from().to_be_bytes());
    encoded.extend_from_slice(&validity.until().to_be_bytes());
    fixture::store(&path, "enrollment-root", &root.public_key()?.encode())?;
    fixture::store(&path, "enrollment-intent", &encoded)?;
    assert_eq!(
        run(&path, "key", &arguments(&path, "key", None))?,
        "enrollment-key\n"
    );
    let creating = state(&run(&path, "create", &arguments(&path, "create", None))?)?;
    assert_eq!(creating.phase, 1);
    assert_eq!(creating.journal, [0; 32]);
    assert!(!path.join("signer.key").exists());
    let requested = state(&run(&path, "request", &arguments(&path, "request", None))?)?;
    assert_eq!(requested.phase, 2);
    assert_eq!(requested.signer, creating.signer);
    assert_eq!(
        state(&run(
            &path,
            "request-retry",
            &arguments(&path, "request-retry", None)
        )?)?,
        requested
    );
    assert!(!path.join("installation.redb").exists());
    let request = fixture::read(&path, "enrollment-request", 8192)?;
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, fixture::now()?)?;
    assert_eq!(verified.identity().as_bytes(), &requested.signer);
    let certificate = root.issue_enrollment(&verified, fixture::now()?)?;
    let entries = [root.roster_entry(&certificate)?];
    let roster = root.issue_roster(1, validity, &entries)?;
    let renewal = root.issue_roster(2, validity, &entries)?;
    let verify = |roster: &p::IssuedRoster| -> Result<p::VerifiedDevice> {
        Ok(p::AccountPin::new(
            root.account_id()?,
            root.public_key()?,
            roster.checkpoint(),
            family,
        )?
        .verify_device(&certificate, roster.as_bytes(), fixture::now()?)?)
    };
    let original = verify(&roster)?;
    let next = verify(&renewal)?;
    assert_eq!(original.credential_digest(), next.credential_digest());
    for (name, bytes) in [
        ("grant-certificate", certificate),
        ("grant-roster", roster.as_bytes().to_vec()),
        ("trusted-account", root.account_id()?.to_vec()),
        (
            "trusted-roster-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "trusted-roster-digest",
            roster.checkpoint().digest().to_vec(),
        ),
        ("renewal-roster", renewal.as_bytes().to_vec()),
        (
            "renewal-version",
            renewal.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", renewal.checkpoint().digest().to_vec()),
    ] {
        fixture::store(&path, name, &bytes)?;
    }
    let accepted = state(&run(&path, "accept", &arguments(&path, "accept", None))?)?;
    assert_eq!(accepted.phase, 3);
    assert_eq!(accepted.signer, requested.signer);
    assert_ne!(accepted.journal, [0; 32]);
    assert_eq!(
        state(&run(&path, "storage", &arguments(&path, "storage", None))?)?,
        accepted
    );
    let mut sdk = fixture::sdk(&path)?;
    let policy = fixture::protocol_policy(&path, &sdk)?;
    let genesis = p::DeviceJournal::recover_anchor_genesis(
        &path.join("journal.redb"),
        p::JournalKey::open(&path.join("wrap.key"))?,
        &original,
        &policy,
        p::JournalIdentity::from_trusted_state(accepted.journal)?,
    )?;
    let subject = genesis.subject();
    assert_eq!(
        fixture::read(&path, "enrollment-genesis-subject", 96)?,
        subject.to_bytes()
    );
    assert_eq!(
        fixture::array::<32>(&path, "enrollment-genesis-digest")?,
        genesis.image_digest()
    );
    let pin = {
        let mut store = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?;
        store.enroll(&genesis, &original, &policy, fixture::now()?)?;
        store.pin()?
    };
    fixture::store(&path, "witness-subject", &subject.to_bytes())?;
    fixture::store(&path, "witness-id", pin.identity().as_bytes())?;
    fixture::store(&path, "witness-public", &pin.public_key().encode())?;
    policy.close();
    sdk.close();
    Ok(Registration {
        root,
        validity,
        path,
        intent,
        original,
        next,
        accepted,
        request,
        subject,
    })
}

fn exercise(tls: bool) -> Result<()> {
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let registration = prepare(&setup, &witness)?;
    let path = &registration.path;
    let mut tls_witness = if tls {
        Some(witness_tls::TlsWitness::start(
            Arc::clone(&witness.configured.store),
            [path.as_path()],
        )?)
    } else {
        None
    };
    let endpoint = Endpoint {
        address: tls_witness
            .as_ref()
            .map_or(witness.configured.address, |w| w.address),
        tls,
    };
    let first = account(&run(
        path,
        "activate",
        &arguments(path, "activate", Some(endpoint)),
    )?)?;
    let active = state(&run(
        path,
        "active",
        &arguments(path, "status", Some(endpoint)),
    )?)?;
    assert_eq!(
        active,
        State {
            phase: 5,
            signer: registration.accepted.signer,
            journal: registration.accepted.journal
        }
    );
    let mut absent = arguments(path, "activate-error", None);
    absent.push("216".into());
    assert_eq!(
        run(path, "missing-required", &absent)?,
        "enrollment-activation-refused:216\n"
    );
    lease_released(path)?;
    assert_eq!(
        state(&run(
            path,
            "after-missing-required",
            &arguments(path, "status", None)
        )?)?,
        active
    );
    let refreshing = state(&run(
        path,
        "refresh",
        &arguments(path, "refresh", Some(endpoint)),
    )?)?;
    assert_eq!(
        refreshing,
        State {
            phase: 6,
            signer: active.signer,
            journal: active.journal
        }
    );
    let tls_before_denial = tls_witness
        .as_ref()
        .map(|w| w.admitted.load(Ordering::Acquire));
    let mut args = arguments(path, "activate-error", Some(endpoint));
    args.push("218".into());
    assert_eq!(
        run(path, "denied", &args)?,
        "enrollment-activation-refused:218\n"
    );
    assert!(
        String::from_utf8(fixture::read(path, "enrollment-authority-refusal", 512)?)?
            .contains("witness enrollment authority is not current or valid")
    );
    lease_released(path)?;
    // The local target may commit before the required signed authority denial.
    // Active is a durable phase, never evidence that C published a device owner.
    assert_eq!(
        state(&run(
            path,
            "after-denial",
            &arguments(path, "status", Some(endpoint))
        )?)?,
        active
    );
    if let (Some(w), Some(before)) = (&tls_witness, tls_before_denial) {
        let after = w.admitted.load(Ordering::Acquire);
        assert!(after > before);
        let mut observed = u64::try_from(before)?.to_be_bytes().to_vec();
        observed.extend_from_slice(&u64::try_from(after)?.to_be_bytes());
        fixture::store(path, "enrollment-tls-denial-admissions", &observed)?;
    } else {
        let subject = registration.subject.to_bytes();
        let authority = registration.next.authority_binding();
        let captures = witness
            .captured
            .lock()
            .map_err(|_| "witness capture poisoned")?;
        assert!(
            captures.iter().any(|capture| capture.delivered
                && capture.request.get(44..140) == Some(subject.as_slice())
                && capture.request.get(204) == Some(&4)
                && capture.request.get(205..237) == Some(authority.as_slice())
                && capture.reply.get(204) == Some(&6)),
            "refusal must be the exact signed target-authority denial"
        );
    }
    let mut sdk = fixture::sdk(path)?;
    let policy = fixture::protocol_policy(path, &sdk)?;
    assert_eq!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?
            .update_roster_authority(
                registration.subject,
                registration.original.roster().checkpoint(),
                &registration.next,
                &policy,
                fixture::now()?
            )?,
        registration.next.roster().checkpoint()
    );
    policy.close();
    sdk.close();
    assert_eq!(
        account(&run(
            path,
            "renewed",
            &arguments(path, "activate", Some(endpoint))
        )?)?,
        first
    );
    assert_eq!(
        state(&run(
            path,
            "renewed-status",
            &arguments(path, "status", Some(endpoint))
        )?)?,
        active
    );

    if !tls {
        let marker = path.join("enrollment-cancel-query");
        let mut pending = witness
            .hold_marker
            .lock()
            .map_err(|_| "hold marker poisoned")?;
        if pending.replace(marker.clone()).is_some() {
            return Err("unconsumed enrollment cancellation barrier".into());
        }
        drop(pending);
        witness.arm(4)?;
        let mut args = arguments(path, "cancel-activate", Some(endpoint));
        args.push(marker.as_os_str().into());
        assert_eq!(
            run(path, "cancel-activate", &args)?,
            "enrollment-activation-cancelled\n"
        );
        assert!(marker.is_file());
        lease_released(path)?;
        assert_eq!(
            state(&run(
                path,
                "cancelled-status",
                &arguments(path, "status", Some(endpoint))
            )?)?,
            active
        );
        assert_eq!(
            account(&run(
                path,
                "cancelled-reopen",
                &arguments(path, "activate", Some(endpoint))
            )?)?,
            first
        );
    }
    assert_eq!(
        fixture::read(path, "enrollment-request", 8192)?,
        registration.request
    );
    let mut original = p::DeviceEnrollment::open(
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
        registration.intent,
    )?;
    assert_eq!(*original.identity()?.as_bytes(), active.signer);
    assert_eq!(
        original.status()?,
        p::EnrollmentStatus::Active(p::JournalIdentity::from_trusted_state(active.journal)?)
    );
    original.close();
    if let Some(tls) = &mut tls_witness {
        assert!(tls.admitted.load(Ordering::Acquire) > 0);
        assert!(
            tls.finish()?.is_empty(),
            "TLS endpoint failures cannot explain authority refusal"
        );
        fixture::store(
            path,
            "enrollment-tls-admissions",
            &u64::try_from(tls.admitted.load(Ordering::Acquire))?.to_be_bytes(),
        )?;
    }
    witness.join()?;
    if !tls {
        assert_eq!(witness.fault.load(Ordering::Acquire), 0);
        let subject = registration.subject.to_bytes();
        let captures = witness
            .captured
            .lock()
            .map_err(|_| "witness capture poisoned")?;
        assert!(
            captures.iter().any(|capture| !capture.delivered
                && capture.request.get(44..140) == Some(subject.as_slice())
                && capture.request.get(204) == Some(&1)
                && capture.reply.get(204) == Some(&1)),
            "cancellation must interrupt the original real signed head query"
        );
        let mut trace = Vec::new();
        for capture in captures
            .iter()
            .filter(|capture| capture.request.get(44..140) == Some(subject.as_slice()))
        {
            trace.push(u8::from(capture.delivered));
            trace.extend_from_slice(&capture.request);
            trace.extend_from_slice(&capture.reply);
        }
        fixture::store(path, "enrollment-witness-transcript", &trace)?;
    }
    println!(
        "C_ENROLLMENT_WITNESS_COMPLETE carrier={} journal={} next_account={}",
        if tls { "mutual-tls" } else { "signed-tcp" },
        fixture::hex(&active.journal),
        fixture::hex(&first)
    );
    Ok(())
}

#[test]
fn c_registration_signed_tcp_requires_current_witness_and_recovers_cancelled_activation(
) -> Result<()> {
    exercise(false)
}

#[test]
fn c_registration_mutual_tls_requires_current_witness_authority() -> Result<()> {
    exercise(true)
}
