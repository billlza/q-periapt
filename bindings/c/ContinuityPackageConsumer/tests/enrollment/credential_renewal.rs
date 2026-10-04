// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[path = "peer_credential_renewal.rs"]
mod peer_credential_renewal;

#[derive(Debug, PartialEq, Eq)]
struct RenewalObservation {
    phase: u32,
    operation: [u8; 32],
    statement: [u8; 32],
    version: u64,
    digest: [u8; 32],
    observed_at: u64,
}
fn observation(text: &str) -> Result<RenewalObservation> {
    let mut lines = text.lines();
    let phase = lines
        .next()
        .ok_or("renewal phase")?
        .strip_prefix("credential-phase:")
        .ok_or("renewal phase prefix")?
        .parse()?;
    let operation = decode_id(lines.next().ok_or("operation")?)?;
    let statement = decode_id(lines.next().ok_or("statement")?)?;
    let version = lines
        .next()
        .ok_or("head")?
        .strip_prefix("credential-head:")
        .ok_or("head prefix")?
        .parse()?;
    let digest = decode_id(lines.next().ok_or("head digest")?)?;
    let observed_at = lines
        .next()
        .ok_or("observed time")?
        .strip_prefix("credential-observed:")
        .ok_or("time prefix")?
        .parse()?;
    if lines.next().is_some() {
        return Err("trailing renewal observation".into());
    }
    Ok(RenewalObservation {
        phase,
        operation,
        statement,
        version,
        digest,
        observed_at,
    })
}

fn wait_until_expired(target_until: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(100);
    while fixture::now()? < target_until {
        if Instant::now() >= deadline {
            return Err("real clock did not reach bounded credential expiry".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

struct Registered {
    _setup: fixture::Setup,
    path: PathBuf,
    root: p::RootSigningKey,
    family: [u8; 32],
    at: u64,
    validity: p::Validity,
    roster_validity: p::Validity,
    certificate: Vec<u8>,
    roster: p::IssuedRoster,
    verified: p::VerifiedEnrollmentRequest,
    accepted: (u32, [u8; 32], [u8; 32]),
}
fn registered(lifetime: u64) -> Result<Registered> {
    let s = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let path = s
        .initiator
        .parent()
        .ok_or("fixture root")?
        .join("renewed-enrollment");
    fs::DirBuilder::new().mode(0o700).create(&path)?;
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
    let root = p::RootSigningKey::generate()?;
    let family = fixture::array(&path, "family")?;
    let at = fixture::now()?;
    let validity = p::Validity::new(
        at.saturating_sub(1),
        at.checked_add(lifetime).ok_or("clock overflow")?,
    )?;
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
    run(&path, "key", &command(&path, "key"))?;
    let created = state(&run(&path, "create", &command(&path, "create"))?)?;
    let empty = observation(&run(
        &path,
        "initial-renewal",
        &command(&path, "credential-status"),
    )?)?;
    assert_eq!(
        (
            empty.phase,
            empty.operation,
            empty.statement,
            empty.version,
            empty.digest,
            empty.observed_at
        ),
        (0, [0; 32], [0; 32], 0, [0; 32], 0)
    );
    run(&path, "request", &command(&path, "request"))?;
    let request = fixture::read(&path, "enrollment-request", 8192)?;
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, fixture::now()?)?;
    let certificate = root.issue_enrollment(&verified, fixture::now()?)?;
    let roster_validity = p::Validity::new(
        validity.from(),
        at.checked_add(3000).ok_or("clock overflow")?,
    )?;
    let roster = root.issue_roster(1, roster_validity, &[root.roster_entry(&certificate)?])?;
    for (name, bytes) in [
        ("grant-certificate", certificate.clone()),
        ("grant-roster", roster.as_bytes().to_vec()),
        ("trusted-account", root.account_id()?.to_vec()),
        ("trusted-roster-version", 1u64.to_be_bytes().to_vec()),
        (
            "trusted-roster-digest",
            roster.checkpoint().digest().to_vec(),
        ),
    ] {
        fixture::store(&path, name, &bytes)?;
    }
    let accepted = state(&run(&path, "accept", &command(&path, "accept"))?)?;
    assert_eq!(accepted.1, created.1);
    run(&path, "storage", &command(&path, "storage"))?;
    run(&path, "activate-original", &command(&path, "activate"))?;
    Ok(Registered {
        _setup: s,
        path,
        root,
        family,
        at,
        validity,
        roster_validity,
        certificate,
        roster,
        verified,
        accepted,
    })
}

#[test]
fn c_original_registration_stages_current_root_grant_and_retains_signer_and_installation(
) -> Result<()> {
    let Registered {
        _setup,
        path,
        root,
        family,
        at,
        validity,
        roster_validity,
        certificate,
        roster,
        verified,
        accepted,
    } = registered(60)?;
    let signer_before = Zeroizing::new(fs::read(path.join("signer.key"))?);
    let wrapping_before = Zeroizing::new(fs::read(path.join("wrap.key"))?);
    let original_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let device = original_pin.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    let renewed_validity =
        p::Validity::new(validity.from(), at.checked_add(75).ok_or("clock overflow")?)?;
    let successor = root.issue_device(
        p::DeviceDescription::new(
            device.device_id(),
            device.generation(),
            family,
            renewed_validity,
        )?,
        verified.public_key().clone(),
    )?;
    let target = root.issue_roster(2, roster_validity, &[root.roster_entry(&successor)?])?;
    let target_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        target.checkpoint(),
        family,
    )?;
    let sdk = fixture::sdk(&path)?;
    let policy = fixture::protocol_policy(&path, &sdk)?;
    let operation = p::CredentialRenewalId::generate()?;
    let grant = root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &certificate,
            previous_credential: &certificate,
            successor_credential: &successor,
            previous_roster: roster.as_bytes(),
            successor_roster: target.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: roster.checkpoint(),
            policy_digest: policy.checkpoint().digest(),
        },
        &target_pin,
        fixture::now()?,
    )?;
    let checked = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &target_pin,
        policy.checkpoint().digest(),
        fixture::now()?,
    )?;
    policy.close();
    drop(sdk);
    for (name, bytes) in [
        ("credential-renewal", grant.as_bytes().to_vec()),
        ("credential-operation", operation.as_bytes().to_vec()),
        ("credential-statement", checked.statement_digest().to_vec()),
        (
            "renewal-version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", target.checkpoint().digest().to_vec()),
    ] {
        fixture::store(&path, name, &bytes)?;
    }
    assert_eq!(
        run(&path, "bad-signature", &command(&path, "credential-reject"))?,
        "credential-signature-refused\n"
    );
    assert_eq!(
        observation(&run(
            &path,
            "after-refusal",
            &command(&path, "credential-status")
        )?)?
        .phase,
        0
    );
    let pending = observation(&run(&path, "stage", &command(&path, "credential-stage"))?)?;
    assert_eq!(
        (
            pending.phase,
            pending.operation,
            pending.statement,
            pending.version,
            pending.digest,
            pending.observed_at
        ),
        (
            1,
            *operation.as_bytes(),
            checked.statement_digest(),
            0,
            [0; 32],
            0
        )
    );
    let replay = observation(&run(
        &path,
        "stage-retry",
        &command(&path, "credential-stage"),
    )?)?;
    assert_eq!(replay, pending);
    run(&path, "activate-renewed", &command(&path, "activate"))?;
    let committed = observation(&run(
        &path,
        "committed",
        &command(&path, "credential-status"),
    )?)?;
    assert_eq!(
        (
            committed.phase,
            committed.operation,
            committed.statement,
            committed.version,
            committed.digest,
            committed.observed_at
        ),
        (
            2,
            *operation.as_bytes(),
            checked.statement_digest(),
            target.checkpoint().version(),
            target.checkpoint().digest(),
            0
        )
    );
    wait_until_expired(renewed_validity.until())?;
    let historical = observation(&run(
        &path,
        "committed-after-expiry",
        &command(&path, "credential-status"),
    )?)?;
    assert_eq!(historical, committed);
    let reconciled = observation(&run(
        &path,
        "reconcile-committed-expiry",
        &command(&path, "credential-reconcile"),
    )?)?;
    assert_eq!(
        reconciled, committed,
        "an expired committed renewal cannot become uncommitted"
    );
    assert_eq!(
        run(
            &path,
            "committed-expired-activation",
            &command(&path, "credential-activate-refused")
        )?,
        "credential-expired-activation-refused\n"
    );
    let after = state(&run(
        &path,
        "original-registration",
        &command(&path, "status"),
    )?)?;
    assert_eq!((after.0, after.1, after.2), (5, accepted.1, accepted.2));
    assert_eq!(
        fs::read(path.join("signer.key"))?.as_slice(),
        signer_before.as_slice()
    );
    assert_eq!(
        fs::read(path.join("wrap.key"))?.as_slice(),
        wrapping_before.as_slice()
    );
    assert!(
        !path.join("local-certificate").exists(),
        "no replacement credential files choose a new installation"
    );
    lease(&path, false)?;
    println!("C_CREDENTIAL_RENEWAL original_registration=true same_signer=true same_journal=true pending_readback=true committed_readback=true expired_committed_preserved=true expired_owner_refused=true admitted_signature_failure_closed_owner=true");
    Ok(())
}

#[test]
fn c_real_clock_expired_pending_reconciles_without_policy_or_tls_for_status_and_recovers_original_registration(
) -> Result<()> {
    let c = registered(60)?;
    let signer_before = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping_before = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    let target_until = c.at.checked_add(75).ok_or("clock overflow")?;
    let publish = |version: u64, until: u64| -> Result<p::VerifiedCredentialRenewal> {
        let successor = c.root.issue_device(
            p::DeviceDescription::new(
                [71; 16],
                1,
                c.family,
                p::Validity::new(c.validity.from(), until)?,
            )?,
            c.verified.public_key().clone(),
        )?;
        let target = c.root.issue_roster(
            version,
            c.roster_validity,
            &[c.root.roster_entry(&successor)?],
        )?;
        let pin = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            target.checkpoint(),
            c.family,
        )?;
        let sdk = fixture::sdk(&c.path)?;
        let policy = fixture::protocol_policy(&c.path, &sdk)?;
        let operation = p::CredentialRenewalId::generate()?;
        let grant = c.root.issue_credential_renewal(
            p::CredentialRenewalMaterials {
                original_credential: &c.certificate,
                previous_credential: &c.certificate,
                successor_credential: &successor,
                previous_roster: c.roster.as_bytes(),
                successor_roster: target.as_bytes(),
            },
            &p::CredentialRenewalAuthorization {
                operation,
                previous: c.roster.checkpoint(),
                policy_digest: policy.checkpoint().digest(),
            },
            &pin,
            fixture::now()?,
        )?;
        let verified = p::VerifiedCredentialRenewal::verify(
            grant.as_bytes(),
            &pin,
            policy.checkpoint().digest(),
            fixture::now()?,
        )?;
        policy.close();
        drop(sdk);
        for (name, bytes) in [
            ("credential-renewal", grant.as_bytes().to_vec()),
            ("credential-operation", operation.as_bytes().to_vec()),
            ("credential-statement", verified.statement_digest().to_vec()),
            (
                "renewal-version",
                target.checkpoint().version().to_be_bytes().to_vec(),
            ),
            ("renewal-digest", target.checkpoint().digest().to_vec()),
        ] {
            let path = c.path.join(name);
            if path.try_exists()? {
                fs::write(path, bytes)?;
            } else {
                fixture::store(&c.path, name, &bytes)?;
            }
        }
        Ok(verified)
    };
    let first = publish(2, target_until)?;
    let pending = observation(&run(
        &c.path,
        "pending-expiry",
        &command(&c.path, "credential-stage"),
    )?)?;
    assert_eq!(
        (pending.phase, pending.operation, pending.statement),
        (1, *first.operation().as_bytes(), first.statement_digest())
    );
    wait_until_expired(target_until)?;
    assert_eq!(
        run(
            &c.path,
            "expired-activation",
            &command(&c.path, "credential-activate-refused")
        )?,
        "credential-expired-activation-refused\n"
    );
    for name in ["sdk.redb", "protocol-policy", "tls-cert", "tls-key"] {
        fs::rename(c.path.join(name), c.path.join(format!("{name}.held")))?;
    }
    let observed = observation(&run(
        &c.path,
        "passive-without-policy",
        &command(&c.path, "credential-status"),
    )?)?;
    assert_eq!(observed, pending);
    for name in ["sdk.redb", "protocol-policy", "tls-cert", "tls-key"] {
        fs::rename(c.path.join(format!("{name}.held")), c.path.join(name))?;
    }
    let expired = observation(&run(
        &c.path,
        "explicit-expiry",
        &command(&c.path, "credential-reconcile"),
    )?)?;
    assert_eq!(
        (
            expired.phase,
            expired.operation,
            expired.statement,
            expired.version,
            expired.digest
        ),
        (
            3,
            *first.operation().as_bytes(),
            first.statement_digest(),
            c.roster.checkpoint().version(),
            c.roster.checkpoint().digest()
        )
    );
    assert!(expired.observed_at >= target_until);
    let replay = observation(&run(
        &c.path,
        "expiry-retry",
        &command(&c.path, "credential-reconcile"),
    )?)?;
    assert_eq!(replay, expired);
    let next = publish(3, c.at.checked_add(1200).ok_or("clock overflow")?)?;
    assert_ne!(first.operation(), next.operation());
    assert_ne!(first.statement_digest(), next.statement_digest());
    let next_pending = observation(&run(
        &c.path,
        "next-stage",
        &command(&c.path, "credential-stage"),
    )?)?;
    assert_eq!(
        next_pending,
        RenewalObservation {
            phase: 1,
            operation: *next.operation().as_bytes(),
            statement: next.statement_digest(),
            version: 0,
            digest: [0; 32],
            observed_at: 0
        }
    );
    run(&c.path, "next-activate", &command(&c.path, "activate"))?;
    let final_status = state(&run(
        &c.path,
        "original-identities",
        &command(&c.path, "status"),
    )?)?;
    assert_eq!(
        (final_status.1, final_status.2),
        (c.accepted.1, c.accepted.2)
    );
    let complete = observation(&run(
        &c.path,
        "next-committed",
        &command(&c.path, "credential-status"),
    )?)?;
    let target = next.successor_device().roster().checkpoint();
    assert_eq!(
        complete,
        RenewalObservation {
            phase: 2,
            operation: *next.operation().as_bytes(),
            statement: next.statement_digest(),
            version: target.version(),
            digest: target.digest(),
            observed_at: 0
        }
    );
    assert_eq!(
        fs::read(c.path.join("signer.key"))?.as_slice(),
        signer_before.as_slice()
    );
    assert_eq!(
        fs::read(c.path.join("wrap.key"))?.as_slice(),
        wrapping_before.as_slice()
    );
    lease(&c.path, false)?;
    println!("C_CREDENTIAL_EXPIRY actual_wall_clock=true target_until={target_until} observed_at={} no_policy_status=true same_registration=true separate_root_operation=true",expired.observed_at);
    Ok(())
}
