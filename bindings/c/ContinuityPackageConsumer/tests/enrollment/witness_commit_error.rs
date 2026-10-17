// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A live foreign caller observes unknown Commit result, closes, then reopens.
use super::witness_credential_renewal::{
    expected, image_digest, pending_journal, provision_renewal, public_file,
};
use super::witness_policy_expiry::{
    enrollment_paths, expired_authority, policy_pin, transport, validate_commit_exchange,
    CommitReplyLoss, CommitTlsWitness,
};
use super::*;
use std::{
    io, thread,
    time::{Duration, Instant},
};

const POLICY_SECONDS: u64 = 120;
const MATERIALS: &[&str] = &[
    "enrollment-root",
    "enrollment-intent",
    "enrollment-request",
    "enrollment-reopened-request",
    "grant-certificate",
    "grant-roster",
    "trusted-account",
    "trusted-roster-version",
    "trusted-roster-digest",
    "family",
    "policy-root",
    "policy-version",
    "policy-digest",
    "protocol-policy",
    "witness-id",
    "witness-public",
    "witness-subject",
    "enrollment-genesis-subject",
    "enrollment-genesis-digest",
    "credential-renewal",
    "credential-operation",
    "credential-statement",
    "renewal-version",
    "renewal-digest",
    "credential-proposal",
    "credential-proposal-original",
    "error-image-digests",
    "error-observations",
    "error-witness-transcript",
    "error-tcp-transcript",
    "error-observer-request",
    "error-observer-reply",
    "error-cut-prefix",
];
const LABELS: &[&str] = &[
    "key",
    "create",
    "request",
    "request-retry",
    "accept",
    "storage",
    "error-original-active",
    "error-original-status",
    "error-stage",
    "error-prepare",
    "error-return",
    "error-pending",
    "error-recovered",
    "error-repeat",
    "error-final-status",
    "error-activation",
];
fn calls(
    witness: &witness::Witness,
    tls: Option<&CommitTlsWitness>,
    subject: p::AnchorSubject,
) -> Result<usize> {
    Ok(if let Some(server) = tls {
        server.admitted.load(Ordering::Acquire)
    } else {
        witness
            .captured
            .lock()
            .map_err(|_| "TCP capture lock")?
            .iter()
            .filter(|r| r.request.get(44..140) == Some(subject.to_bytes().as_slice()))
            .count()
    })
}
fn observe_applied(
    registration: &Registration,
    endpoint: Endpoint,
    pin: &p::AnchorPin,
    proposal: p::AnchorCredentialRenewalProposal,
) -> Result<()> {
    let path = &registration.path;
    let before = pending_journal(path)?;
    let mut owner =
        p::DeviceEnrollment::open(enrollment_paths(path)?, registration.intent.clone())?;
    let id = owner.identity()?;
    assert_eq!(id.as_bytes(), &registration.accepted.signer);
    assert_eq!(
        owner.credential_renewal_status()?,
        p::CredentialRenewalStatus::Pending {
            operation: proposal.operation(),
            statement: proposal.statement(),
        }
    );
    let key = p::JournalKey::open(&path.join("wrap.key"))?;
    let signer = p::DeviceSigningKey::open(&path.join("signer.key"), &key, id)?;
    let request = p::AnchorRequest::new(
        pin,
        proposal.subject(),
        p::AnchorOperation::credential_renewal_status(&proposal),
        &signer,
    )?;
    let reply = transport(path, endpoint)?
        .exchange(request.as_bytes(), Instant::now() + Duration::from_secs(3))?;
    assert_eq!(
        pin.verify_reply(&request, &reply)?
            .credential_renewal_state(&proposal)?,
        p::AnchorCredentialRenewalState::Applied
    );
    fixture::store(path, "error-observer-request", request.as_bytes())?;
    fixture::store(path, "error-observer-reply", &reply)?;
    drop(signer);
    drop(key);
    owner.close();
    assert_eq!(pending_journal(path)?, before);
    Ok(())
}
fn exercise(tls: bool, expired: bool, output: Option<PathBuf>) -> Result<String> {
    let name = format!(
        "{}-{}",
        if tls { "tls" } else { "tcp" },
        if expired { "expired" } else { "live" }
    );
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let registration =
        prepare_with_policy_lifetime(&setup, &witness, expired.then_some(POLICY_SECONDS))?;
    let path = &registration.path;
    let mut tls_witness = if tls {
        Some(CommitTlsWitness::start(
            Arc::clone(&witness.configured.store),
            path,
        )?)
    } else {
        None
    };
    let endpoint = Endpoint {
        tls,
        address: tls_witness
            .as_ref()
            .map_or(witness.configured.address, |s| s.address),
    };
    run(
        path,
        "error-original-active",
        &arguments(path, "activate", Some(endpoint)),
    )?;
    let active = state(&run(
        path,
        "error-original-status",
        &arguments(path, "status", None),
    )?)?;
    let original = pending_journal(path)?;
    let (proof, target, credential) = provision_renewal(&registration)?;
    let pin = policy_pin(path)?;
    let historical = pin.verify_historical(&fixture::read(path, "protocol-policy", 8192)?)?;
    assert_eq!(
        run(
            path,
            "error-stage",
            &arguments(path, "credential-stage", Some(endpoint))
        )?,
        expected(&proof, 1)
    );
    assert_eq!(
        run(
            path,
            "error-prepare",
            &arguments(path, "credential-witness-prepare", Some(endpoint))
        )?,
        "credential-witness-prepared\n"
    );
    let proposal_bytes = fixture::read(path, "credential-proposal", 296)?;
    fixture::store(path, "credential-proposal-original", &proposal_bytes)?;
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&proposal_bytes)?;
    assert_eq!(proposal.subject(), registration.subject);
    assert_eq!(proposal.operation(), proof.operation());
    assert_eq!(proposal.statement(), proof.statement_digest());
    let pending = pending_journal(path)?;
    assert_eq!(pending.0, original.0);
    assert!(pending.1.is_some());
    let mut sdk = fixture::sdk(path)?;
    let policy = fixture::protocol_policy(path, &sdk)?;
    let witness_pin = {
        let mut store = witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness lock")?;
        store.prepare_credential_renewal(proposal, &proof, &policy, fixture::now()?)?;
        store.pin()?
    };
    policy.close();
    sdk.close();
    let prepared_at = fixture::now()?;
    assert!(prepared_at < historical.validity().until());
    let before = calls(&witness, tls_witness.as_ref(), registration.subject)?;
    let marker = path.join("commit-error-ready");
    let release = if let Some(server) = &tls_witness {
        Some(server.arm(proposal, marker.clone(), CommitReplyLoss::TransportError)?)
    } else {
        let mut saved = witness.hold_marker.lock().map_err(|_| "TCP hold lock")?;
        if saved.replace(marker.clone()).is_some() {
            return Err("unconsumed TCP Commit fault".into());
        }
        drop(saved);
        witness.arm(9)?;
        None
    };
    // Normal process exit is required. The selected CLI asserts exact 218,
    // same-handle Closed and successful close; C additionally retains its output sentinel.
    assert_eq!(
        run(
            path,
            "error-return",
            &arguments(
                path,
                "credential-witness-commit-transport-error",
                Some(endpoint)
            )
        )?,
        "credential-witness-commit-refused:218\n"
    );
    assert!(marker.is_file());
    drop(release);
    let returned_at = fixture::now()?;
    assert!(returned_at < historical.validity().until());
    let after_error = calls(&witness, tls_witness.as_ref(), registration.subject)?;
    assert_eq!(after_error, before + 2);
    assert_eq!(pending_journal(path)?, pending);
    assert_eq!(
        run(
            path,
            "error-pending",
            &arguments(path, "credential-status", None)
        )?,
        expected(&proof, 1)
    );
    assert_eq!(pending_journal(path)?, pending);
    observe_applied(&registration, endpoint, &witness_pin, proposal)?;
    let observed_at = fixture::now()?;
    let after_observer = calls(&witness, tls_witness.as_ref(), registration.subject)?;
    assert_eq!(after_observer, before + 3);
    let encrypted = if tls {
        u64::from_be_bytes(fixture::array(path, "expiry-encrypted-reply-bytes")?)
    } else {
        0
    };
    assert_eq!(encrypted > 0, tls);
    {
        let rows = if let Some(server) = &tls_witness {
            server.records.lock().map_err(|_| "TLS cut records")?
        } else {
            witness.captured.lock().map_err(|_| "TCP cut records")?
        };
        let lost = rows.iter().filter(|r| !r.delivered).collect::<Vec<_>>();
        assert_eq!(lost.len(), 1);
        let cut = lost.first().ok_or("missing Commit loss")?;
        validate_commit_exchange(proposal, &cut.request, &cut.reply)?;
        let mut prefix = Vec::new();
        if !tls {
            prefix.extend_from_slice(&3659u32.to_be_bytes());
            prefix.extend_from_slice(cut.reply.get(..1800).ok_or("Commit prefix")?);
            assert_eq!(
                fixture::read(path, "witness-cancelled-prefix", 8192)?,
                prefix
            );
        }
        fixture::store(path, "error-cut-prefix", &prefix)?;
    }
    if expired {
        let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
        while fixture::now()? < historical.validity().until() {
            if Instant::now() >= deadline {
                return Err("real policy expiry wait exhausted".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        expired_authority(path, &pin, &historical, &target)?;
    } else {
        let mut sdk = fixture::sdk(path)?;
        let policy = fixture::protocol_policy(path, &sdk)?;
        policy.close();
        sdk.close();
    }
    let recovery_at = fixture::now()?;
    assert_eq!(recovery_at >= historical.validity().until(), expired);
    assert!(recovery_at < credential.until());
    assert_eq!(pending_journal(path)?, pending);
    assert_eq!(
        run(
            path,
            "error-recovered",
            &arguments(path, "credential-witness-reconcile", Some(endpoint))
        )?,
        expected(&proof, 2)
    );
    let recovered = pending_journal(path)?;
    assert!(recovered.1.is_none());
    assert_eq!(image_digest(&recovered.0)?, proposal.target_head().digest());
    let after_recovery = calls(&witness, tls_witness.as_ref(), registration.subject)?;
    assert_eq!(after_recovery, before + 5);
    assert_eq!(
        run(
            path,
            "error-repeat",
            &arguments(path, "credential-witness-commit", Some(endpoint))
        )?,
        expected(&proof, 2)
    );
    if expired {
        let mut args = arguments(path, "activate-error", Some(endpoint));
        args.push("104".into());
        assert_eq!(
            run(path, "error-activation", &args)?,
            "enrollment-activation-refused:104\n"
        );
    } else {
        // The live branch's required authority observation is the fresh policy
        // verification above; it does not claim another runtime activation.
        for suffix in ["stdout", "stderr"] {
            fixture::store(
                path,
                &format!("witness-enrollment-error-activation.{suffix}"),
                &[],
            )?;
        }
    }
    assert_eq!(
        state(&run(
            path,
            "error-final-status",
            &arguments(path, "status", None)
        )?)?,
        active
    );
    assert_eq!(pending_journal(path)?, recovered);
    assert_eq!(
        fixture::read(path, "enrollment-request", 8192)?,
        registration.request
    );
    assert_eq!(
        fixture::read(path, "credential-proposal", 296)?,
        proposal_bytes
    );
    let final_count = calls(&witness, tls_witness.as_ref(), registration.subject)?;
    assert_eq!(final_count, after_recovery);
    let finished_at = fixture::now()?;
    if !expired {
        assert!(finished_at < historical.validity().until());
    }
    witness.join()?;
    if let Some(server) = &mut tls_witness {
        server.finish()?;
    }
    let tcp = {
        let rows = witness.captured.lock().map_err(|_| "TCP records")?;
        let mut bytes = Vec::new();
        for r in rows
            .iter()
            .filter(|r| r.request.get(44..140) == Some(registration.subject.to_bytes().as_slice()))
        {
            bytes.push(u8::from(r.delivered));
            bytes.extend_from_slice(&r.request);
            bytes.extend_from_slice(&r.reply);
        }
        bytes
    };
    let transcript = if let Some(server) = &tls_witness {
        assert!(tcp.is_empty(), "TLS used plaintext fallback");
        let rows = server.records.lock().map_err(|_| "TLS records")?;
        let mut bytes = Vec::new();
        for r in rows.iter() {
            assert_eq!(
                r.request.get(44..140),
                Some(registration.subject.to_bytes().as_slice())
            );
            bytes.push(u8::from(r.delivered));
            bytes.extend_from_slice(&r.request);
            bytes.extend_from_slice(&r.reply);
        }
        bytes
    } else {
        tcp.clone()
    };
    assert_eq!(transcript.len(), final_count * 7334);
    fixture::store(path, "error-witness-transcript", &transcript)?;
    fixture::store(path, "error-tcp-transcript", &tcp)?;
    let mut images = image_digest(&original.0)?.to_vec();
    images.extend_from_slice(&image_digest(&pending.0)?);
    images.extend_from_slice(&image_digest(&recovered.0)?);
    fixture::store(path, "error-image-digests", &images)?;
    let mut observed = b"QPCEER01".to_vec();
    observed.extend_from_slice(&[u8::from(tls), u8::from(expired), 218, 2]);
    for value in [
        historical.validity().from(),
        historical.validity().until(),
        credential.until(),
        prepared_at,
        returned_at,
        observed_at,
        recovery_at,
        finished_at,
        u64::try_from(before)?,
        u64::try_from(after_error)?,
        u64::try_from(after_observer)?,
        u64::try_from(after_recovery)?,
        u64::try_from(final_count)?,
        0,
        encrypted,
    ] {
        observed.extend_from_slice(&value.to_be_bytes());
    }
    fixture::store(path, "error-observations", &observed)?;
    if let Some(root) = output {
        let out = root.join(&name);
        fs::DirBuilder::new().mode(0o700).create(&out)?;
        for file in MATERIALS {
            fixture::store(&out, file, &public_file(path, file, 32 * 1024 * 1024)?)?;
        }
        for label in LABELS {
            for suffix in ["stdout", "stderr"] {
                let file = format!("witness-enrollment-{label}.{suffix}");
                fixture::store(&out, &file, &public_file(path, &file, 65536)?)?;
            }
        }
    }
    Ok(format!("WITNESSED_COMMIT_ERROR case={name} returned=218 owner_closed=true normal_exit=true original_pending=true committed=true policy_expired={expired}"))
}
#[test]
fn foreign_commit_transport_error_closes_and_reopens_original_owner() -> Result<()> {
    let public = std::env::var_os("QPERIAPT_WITNESSED_COMMIT_ERROR_EVIDENCE").map(PathBuf::from);
    if let Some(path) = &public {
        if !path.is_absolute() {
            return Err("absolute Commit error evidence path required".into());
        }
        q_periapt_host_store::filesystem::OwnedPrivateDirectory::open(
            path.parent().ok_or("evidence parent")?,
        )?;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let mut tasks = Vec::new();
    for tls in [false, true] {
        for expired in [false, true] {
            let output = public.clone();
            tasks.push(thread::spawn(move || exercise(tls, expired, output)));
        }
    }
    let results = tasks
        .into_iter()
        .map(|t| {
            t.join().unwrap_or_else(|_| {
                Err(io::Error::other("Commit error case panicked; see diagnostic").into())
            })
        })
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(report) => println!("{report}"),
            Err(error) => failures.push(error.to_string()),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}
