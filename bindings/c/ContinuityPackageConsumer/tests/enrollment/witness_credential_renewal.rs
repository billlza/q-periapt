// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Foreign owner operations use the original controlled signer and real witness.
use super::*;
use redb::{ReadableDatabase, TableDefinition};
use sha3::{Digest, Sha3_256};
use std::{io::Read, os::unix::fs::MetadataExt};

pub(super) fn public_file(path: &Path, name: &str, maximum: usize) -> Result<Vec<u8>> {
    // This closed private test fixture includes legitimate empty stderr and TLS
    // plaintext-transcript files. The product's nonempty state opener must not
    // be relaxed for evidence. Bind the opened regular file to its observed inode.
    let path = path.join(name);
    let before = fs::symlink_metadata(&path)?;
    if !before.is_file() {
        return Err("public evidence must be a regular file".into());
    }
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err("public evidence changed during opening".into());
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("public evidence file exceeds bound".into());
    }
    Ok(bytes)
}

pub(super) fn image_digest(image: &[u8]) -> Result<[u8; 32]> {
    let domain = b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2";
    let mut hash = Sha3_256::new();
    hash.update(u64::try_from(domain.len())?.to_be_bytes());
    hash.update(domain);
    hash.update(u64::try_from(image.len())?.to_be_bytes());
    hash.update(image);
    Ok(hash.finalize().into())
}

// Explicit public-only allowlist. Never export any database, wrapping key,
// protected signing record or private TLS credential from the temporary fixture.
fn export_public(path: &Path, output: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(output)?;
    for name in [
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
        "renewal-image-digests",
        "renewal-witness-transcript",
        "renewal-tls-transcript",
        "renewal-carrier-observations",
    ] {
        fixture::store(output, name, &public_file(path, name, 32 * 1024 * 1024)?)?;
    }
    for label in [
        "key",
        "create",
        "request",
        "request-retry",
        "accept",
        "storage",
        "renewal-original-active",
        "renewal-original-status",
        "renewal-stage",
        "renewal-prepare",
        "renewal-prepare-reopened",
        "pending-no-sdk-commit",
        "pending-no-sdk-history",
        "renewal-terminal",
        "history",
        "retry",
        "runtime-unavailable",
        "renewal-current-activation",
        "renewal-final-status",
    ] {
        for extension in ["stdout", "stderr"] {
            let name = format!("witness-enrollment-{label}.{extension}");
            fixture::store(output, &name, &public_file(path, &name, 65536)?)?;
        }
    }
    Ok(())
}

pub(super) fn pending_journal(path: &Path) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let db = open_private_database(&path.join("journal.redb"))?;
    let read = db.begin_read()?;
    let table = read.open_table(TableDefinition::<&str, &[u8]>::new(
        "continuity_device_candidate_v21",
    ))?;
    let image = table
        .get("image")?
        .ok_or("missing journal image")?
        .value()
        .to_vec();
    let pending = table.get("pending")?.map(|v| v.value().to_vec());
    Ok((image, pending))
}
pub(super) fn expected(proof: &p::VerifiedCredentialRenewal, phase: u32) -> String {
    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let checkpoint = proof.successor_device().roster().checkpoint();
    format!(
        "credential-phase:{phase}\n{}\n{}\ncredential-head:{}\n{}\ncredential-observed:0\n",
        hex(proof.operation().as_bytes()),
        hex(&proof.statement_digest()),
        if phase == 1 { 0 } else { checkpoint.version() },
        hex(&if phase == 1 {
            [0; 32]
        } else {
            checkpoint.digest()
        })
    )
}
pub(super) fn provision_renewal(
    registration: &Registration,
) -> Result<(p::VerifiedCredentialRenewal, p::AccountPin, p::Validity)> {
    let path = &registration.path;
    let request = p::VerifiedEnrollmentRequest::verify(
        &registration.request,
        &registration.intent,
        fixture::now()?,
    )?;
    let family = fixture::array(path, "family")?;
    let original_certificate = fixture::read(path, "grant-certificate", 8192)?;
    let original_roster = fixture::read(path, "grant-roster", 8192)?;
    let at = fixture::now()?;
    let validity = p::Validity::new(
        registration.validity.from(),
        at.checked_add(2100).ok_or("clock overflow")?,
    )?;
    let root = &registration.root;
    let successor = root.issue_device(
        p::DeviceDescription::new(
            registration.original.device_id(),
            registration.original.generation(),
            family,
            validity,
        )?,
        request.public_key().clone(),
    )?;
    let target = root.issue_roster(2, validity, &[root.roster_entry(&successor)?])?;
    let target_pin = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        target.checkpoint(),
        family,
    )?;
    let mut sdk = fixture::sdk(path)?;
    let policy = fixture::protocol_policy(path, &sdk)?;
    let operation = p::CredentialRenewalId::generate()?;
    let grant = root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &original_certificate,
            previous_credential: &original_certificate,
            successor_credential: &successor,
            previous_roster: &original_roster,
            successor_roster: target.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: registration.original.roster().checkpoint(),
            policy_digest: policy.checkpoint().digest(),
        },
        &target_pin,
        at,
    )?;
    let proof = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &target_pin,
        policy.checkpoint().digest(),
        at,
    )?;
    policy.close();
    sdk.close();
    for name in ["renewal-version", "renewal-digest"] {
        fs::rename(
            path.join(name),
            path.join(format!("unused-roster-refresh-{name}")),
        )?;
    }
    for (name, bytes) in [
        ("credential-renewal", grant.as_bytes().to_vec()),
        ("credential-operation", operation.as_bytes().to_vec()),
        ("credential-statement", proof.statement_digest().to_vec()),
        (
            "renewal-version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", target.checkpoint().digest().to_vec()),
    ] {
        fixture::store(path, name, &bytes)?;
    }
    Ok((proof, target_pin, validity))
}

#[test]
fn original_witnessed_credential_renewal_recovers_applied_and_closed_without_sdk_runtime(
) -> Result<()> {
    let public = std::env::var_os("QPERIAPT_WITNESSED_RENEWAL_EVIDENCE").map(PathBuf::from);
    if let Some(path) = &public {
        if !path.is_absolute() {
            return Err("absolute witnessed renewal evidence path required".into());
        }
        q_periapt_host_store::filesystem::OwnedPrivateDirectory::open(
            path.parent().ok_or("evidence parent")?,
        )?;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    for tls in [false, true] {
        for closed in [false, true] {
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
                    .map_or(witness.configured.address, |v| v.address),
                tls,
            };
            let admissions = || {
                tls_witness
                    .as_ref()
                    .map_or(0, |server| server.admitted.load(Ordering::Acquire))
            };
            let initial_admissions = admissions();
            run(
                path,
                "renewal-original-active",
                &arguments(path, "activate", Some(endpoint)),
            )?;
            let active = state(&run(
                path,
                "renewal-original-status",
                &arguments(path, "status", Some(endpoint)),
            )?)?;
            let original_journal = pending_journal(path)?;
            let (proof, _, _) = provision_renewal(&registration)?;
            let operation = proof.operation();
            assert_eq!(
                run(
                    path,
                    "renewal-stage",
                    &arguments(path, "credential-stage", Some(endpoint))
                )?,
                expected(&proof, 1)
            );
            assert_eq!(
                run(
                    path,
                    "renewal-prepare",
                    &arguments(path, "credential-witness-prepare", Some(endpoint))
                )?,
                "credential-witness-prepared\n"
            );
            let bytes = fixture::read(path, "credential-proposal", 296)?;
            let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&bytes)?;
            assert_eq!(proposal.subject(), registration.subject);
            assert_eq!(proposal.operation(), operation);
            assert_eq!(proposal.statement(), proof.statement_digest());
            let pending = pending_journal(path)?;
            assert_eq!(pending.0, original_journal.0);
            assert!(pending.1.is_some());
            // A fresh owner must recover the exact persisted 296-byte target.
            fs::rename(
                path.join("credential-proposal"),
                path.join("credential-proposal-original"),
            )?;
            assert_eq!(
                run(
                    path,
                    "renewal-prepare-reopened",
                    &arguments(path, "credential-witness-prepare", Some(endpoint))
                )?,
                "credential-witness-prepared\n"
            );
            assert_eq!(fixture::read(path, "credential-proposal", 296)?, bytes);
            assert_eq!(pending_journal(path)?, pending);
            let mut sdk = fixture::sdk(path)?;
            let policy = fixture::protocol_policy(path, &sdk)?;
            witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness poisoned")?
                .prepare_credential_renewal(proposal, &proof, &policy, fixture::now()?)?;
            policy.close();
            sdk.close();
            let phase = if closed { 4 } else { 2 };
            // A prepared target has no terminal authority to read back. Metadata
            // alone must not permit a new Commit through the historical facade.
            fs::rename(
                path.join("sdk.redb"),
                path.join("sdk-pending-retained.redb"),
            )?;
            let before = witness.captured.lock().map_err(|_| "capture lock")?.len();
            let pending_admissions = admissions();
            assert_eq!(
                run(
                    path,
                    "pending-no-sdk-commit",
                    &arguments(path, "credential-witness-commit-no-sdk", Some(endpoint))
                )?,
                "credential-witness-commit-refused:702\n"
            );
            assert_eq!(pending_journal(path)?, pending);
            assert_eq!(
                run(
                    path,
                    "pending-no-sdk-history",
                    &arguments(path, "credential-witness-reconcile", Some(endpoint))
                )?,
                expected(&proof, 1)
            );
            assert_eq!(pending_journal(path)?, pending);
            let captures = witness.captured.lock().map_err(|_| "capture lock")?;
            let after_pending_admissions = admissions();
            let after_pending = captures.len();
            let attempted = captures.get(before..).ok_or("lost capture prefix")?;
            assert!(
                attempted.iter().all(|c| c.request.get(204) != Some(&5)),
                "Commit sent without current SDK authority"
            );
            if tls {
                assert!(attempted.is_empty(), "TLS operation used plaintext witness");
            }
            drop(captures);
            assert!(!path.join("sdk.redb").exists());
            fs::rename(
                path.join("sdk-pending-retained.redb"),
                path.join("sdk.redb"),
            )?;
            let command = if closed {
                "credential-witness-close"
            } else {
                "credential-witness-commit"
            };
            assert_eq!(
                run(
                    path,
                    "renewal-terminal",
                    &arguments(path, command, Some(endpoint))
                )?,
                expected(&proof, phase)
            );
            let terminal = pending_journal(path)?;
            assert!(terminal.1.is_none());
            if closed {
                assert_eq!(terminal.0, original_journal.0);
            } else {
                assert_ne!(terminal.0, original_journal.0);
            }
            // The historical facade must not require reopening an SDK runtime.
            fs::rename(path.join("sdk.redb"), path.join("sdk-retained.redb"))?;
            for (label, command) in [
                ("history", "credential-witness-reconcile"),
                ("retry", "credential-witness-commit"),
            ] {
                assert_eq!(
                    run(path, label, &arguments(path, command, Some(endpoint)))?,
                    expected(&proof, phase)
                );
                assert_eq!(pending_journal(path)?, terminal);
            }
            let mut refused = arguments(path, "activate-error", Some(endpoint));
            assert!(
                !path.join("sdk.redb").exists(),
                "historical operations recreated SDK state"
            );
            refused.push("702".into());
            assert_eq!(
                run(path, "runtime-unavailable", &refused)?,
                "enrollment-activation-refused:702\n"
            );
            fs::rename(path.join("sdk-retained.redb"), path.join("sdk.redb"))?;
            run(
                path,
                "renewal-current-activation",
                &arguments(path, "activate", Some(endpoint)),
            )?;
            assert_eq!(
                state(&run(
                    path,
                    "renewal-final-status",
                    &arguments(path, "status", Some(endpoint))
                )?)?,
                active
            );
            assert_eq!(pending_journal(path)?, terminal);
            let final_admissions = admissions();
            let mut digests = image_digest(&original_journal.0)?.to_vec();
            digests.extend_from_slice(&image_digest(&pending.0)?);
            digests.extend_from_slice(&image_digest(&terminal.0)?);
            assert_eq!(
                image_digest(&original_journal.0)?,
                proposal.expected_head().digest()
            );
            assert_eq!(
                image_digest(&terminal.0)?,
                if closed {
                    proposal.expected_head().digest()
                } else {
                    proposal.target_head().digest()
                }
            );
            fixture::store(path, "renewal-image-digests", &digests)?;
            let captures = witness.captured.lock().map_err(|_| "capture lock")?;
            let subject = registration.subject.to_bytes();
            let scoped_count = |limit: usize| {
                captures
                    .iter()
                    .take(limit)
                    .filter(|c| c.request.get(44..140) == Some(subject.as_slice()))
                    .count()
            };
            let tcp_counts = [
                0,
                scoped_count(before),
                scoped_count(after_pending),
                scoped_count(captures.len()),
            ];
            let mut transcript = Vec::new();
            for capture in captures
                .iter()
                .filter(|c| c.request.get(44..140) == Some(subject.as_slice()))
            {
                transcript.push(u8::from(capture.delivered));
                transcript.extend_from_slice(&capture.request);
                transcript.extend_from_slice(&capture.reply);
            }
            assert_eq!(transcript.is_empty(), tls, "wrong witness carrier trace");
            drop(captures);
            fixture::store(path, "renewal-witness-transcript", &transcript)?;
            let mut observations = Vec::new();
            for value in [
                initial_admissions,
                pending_admissions,
                after_pending_admissions,
                final_admissions,
            ] {
                observations.extend_from_slice(&u64::try_from(value)?.to_be_bytes());
            }
            for value in tcp_counts {
                observations.extend_from_slice(&u64::try_from(value)?.to_be_bytes());
            }
            fixture::store(path, "renewal-carrier-observations", &observations)?;
            let mut tls_transcript = Vec::new();
            if let Some(server) = tls_witness.as_mut() {
                assert!(server.finish()?.is_empty());
                let records = server.records.lock().map_err(|_| "TLS records poisoned")?;
                assert_eq!(
                    records.len(),
                    final_admissions,
                    "TLS admission without a completed authenticated record"
                );
                for record in records.iter() {
                    assert_eq!(record.request().get(44..140), Some(subject.as_slice()));
                    tls_transcript.push(1);
                    tls_transcript.extend_from_slice(record.request());
                    tls_transcript.extend_from_slice(record.reply());
                }
            }
            fixture::store(path, "renewal-tls-transcript", &tls_transcript)?;
            witness.join()?;
            if let Some(directory) = &public {
                export_public(
                    path,
                    &directory.join(format!(
                        "{}-{}",
                        if tls { "tls" } else { "tcp" },
                        if closed { "closed" } else { "applied" }
                    )),
                )?;
            }
            println!("C_WITNESSED_RENEWAL carrier={} terminal={} original_proposal=true original_owner=true no_sdk_historical=true current_activation=true",
                if tls { "tls" } else { "tcp" }, if closed { "closed" } else { "applied" });
        }
    }
    Ok(())
}
