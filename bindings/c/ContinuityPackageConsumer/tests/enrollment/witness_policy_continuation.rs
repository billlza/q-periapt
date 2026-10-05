// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual foreign-owner G/T adoption with an independent TCP or TLS witness.
use super::*;
use witness_credential_renewal::{image_digest, pending_journal, provision_renewal};
use zeroize::Zeroizing;

const DOCUMENT_FILES: [&str; 5] = [
    "family",
    "policy-root",
    "policy-version",
    "policy-digest",
    "protocol-policy",
];

fn expected(grant: &p::VerifiedCredentialRenewal, statement: [u8; 32], phase: u32) -> String {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let target = grant.successor_device().roster().checkpoint();
    format!(
        "credential-phase:{phase}\n{}\n{}\ncredential-head:{}\n{}\ncredential-observed:0\n",
        hex(grant.operation().as_bytes()),
        hex(&statement),
        if phase == 1 { 0 } else { target.version() },
        hex(&if phase == 1 { [0; 32] } else { target.digest() })
    )
}

fn exercise(tls: bool) -> Result<()> {
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let authority = p::PolicySigningKey::generate()?;
    // P0 is signed by this independent issuer before registration begins.
    let registration = prepare_with_original_policy(&setup, &witness, Some((1800, &authority)))?;
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
            .map_or(witness.configured.address, |server| server.address),
        tls,
    };
    run(
        path,
        "joint-original-active",
        &arguments(path, "activate", Some(endpoint)),
    )?;
    let active = state(&run(
        path,
        "joint-original-status",
        &arguments(path, "status", Some(endpoint)),
    )?)?;
    let original_image = pending_journal(path)?;
    assert!(original_image.1.is_none());
    let signer = Zeroizing::new(fs::read(path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(path.join("wrap.key"))?);
    let original_inputs = DOCUMENT_FILES
        .into_iter()
        .map(|name| Ok((name, fs::read(path.join(name))?)))
        .collect::<Result<Vec<_>>>()?;
    let (grant, _, _) = provision_renewal(&registration)?;
    let target = path.join("continued-sdk");
    let previous = path.join("previous-policy");
    for directory in [&target, &previous] {
        fs::DirBuilder::new().mode(0o700).create(directory)?;
    }
    for (name, bytes) in &original_inputs {
        fixture::store(&previous, name, bytes)?;
    }
    for name in ["sdk-policy", "sdk-signature", "sdk-root"] {
        fixture::store(&target, name, &fs::read(path.join(name))?)?;
    }

    let mut original_sdk = fixture::sdk(path)?;
    let original_policy = fixture::protocol_policy(path, &original_sdk)?;
    let mut target_sdk = PolicyStore::provision(
        &target.join("sdk.redb"),
        &fixture::read(&target, "sdk-policy", 4096)?,
        &fixture::read(&target, "sdk-signature", 8192)?,
        &fixture::read(&target, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    let runtime = target_sdk.runtime()?;
    let issued = authority.issue_session_policy(
        &runtime,
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(
                original_policy.validity().from(),
                fixture::now()?.checked_add(2400).ok_or("clock overflow")?,
            )?,
            original_policy.allowed_modes(),
            original_policy.anchor_requirement(),
            original_policy.application_send_budget(),
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
        fixture::store(&target, name, &bytes)?;
    }
    let target_policy = fixture::protocol_policy(&target, &target_sdk)?;
    assert_eq!(original_policy.sdk_binding(), target_policy.sdk_binding());
    let scope = p::PolicyContinuationScope {
        operation: grant.operation(),
        journal: p::JournalIdentity::from_trusted_state(active.journal)?,
        original_owner: grant.original_storage_owner(),
        original_credential: grant.original_credential_digest(),
        previous_credential: grant.previous_device().credential_digest(),
        previous_roster: registration.original.roster().checkpoint(),
        original_policy: original_policy.checkpoint(),
        previous_policy: original_policy.checkpoint(),
        previous_authorization: None,
    };
    let materials = p::PolicyContinuationMaterials {
        original: original_policy.historical(),
        previous: original_policy.historical(),
        target: &target_policy,
        credential: &grant,
    };
    let statement = p::PolicyContinuationStatement::new(&scope, &materials, fixture::now()?)?;
    let continuation = p::VerifiedPolicyContinuation::verify(
        &registration.root.approve_policy_continuation(&statement)?,
        &authority.approve_policy_continuation(&statement)?,
        &scope,
        &materials,
        fixture::now()?,
    )?;
    let transaction = continuation.statement_digest();
    assert_ne!(transaction, grant.statement_digest());
    fixture::store(path, "policy-approvals", continuation.as_bytes())?;
    fixture::store(path, "policy-predecessor-kind", &[0])?;
    // Invocation material is public. This replaces only G's transaction selector
    // with independently approved T; it never changes persisted enrollment state.
    fs::write(path.join("credential-statement"), transaction)?;
    target_policy.close();
    original_policy.close();
    drop(target_policy);
    drop(original_policy);
    drop(runtime);
    target_sdk.close();
    original_sdk.close();
    drop(target_sdk);
    drop(original_sdk);

    assert_eq!(
        run(
            path,
            "joint-stage",
            &arguments(path, "policy-stage", Some(endpoint))
        )?,
        expected(&grant, transaction, 1)
    );
    assert_eq!(
        run(
            path,
            "joint-prepare",
            &arguments(path, "policy-witness-prepare", Some(endpoint))
        )?,
        "policy-witness-prepared\n"
    );
    let encoded = fixture::read(path, "policy-proposal", 329)?;
    assert_eq!(encoded.len(), 329);
    assert_eq!(encoded.get(..8), Some(b"QPCRNP02".as_slice()));
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&encoded)?;
    assert_eq!(proposal.subject(), registration.subject);
    assert_eq!(proposal.operation(), grant.operation());
    assert_eq!(proposal.statement(), grant.statement_digest());
    assert!(proposal.adopts_policy());
    assert_eq!(proposal.transaction_statement(), transaction);
    assert_eq!(proposal.policy_continuation(), Some(transaction));
    let pending = pending_journal(path)?;
    assert_eq!(pending.0, original_image.0);
    assert!(pending.1.is_some());
    fs::rename(
        path.join("policy-proposal"),
        path.join("policy-proposal-original"),
    )?;
    assert_eq!(
        run(
            path,
            "joint-prepare-reopen",
            &arguments(path, "policy-witness-prepare", Some(endpoint))
        )?,
        "policy-witness-prepared\n"
    );
    assert_eq!(fixture::read(path, "policy-proposal", 329)?, encoded);
    assert_eq!(pending_journal(path)?, pending);

    // Independent witness admission reconstructs both pinned documents and G/T.
    let mut original_sdk = fixture::sdk(path)?;
    let original_policy = fixture::protocol_policy(path, &original_sdk)?;
    let mut target_sdk = fixture::sdk(&target)?;
    let target_policy = fixture::protocol_policy(&target, &target_sdk)?;
    let materials = p::PolicyContinuationMaterials {
        original: original_policy.historical(),
        previous: original_policy.historical(),
        target: &target_policy,
        credential: &grant,
    };
    let continuation = p::VerifiedPolicyContinuation::from_bytes(
        &fixture::read(path, "policy-approvals", 7746)?,
        &scope,
        &materials,
        fixture::now()?,
    )?;
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness poisoned")?
        .prepare_policy_continuation(proposal, &continuation, &materials, fixture::now()?)?;
    target_policy.close();
    original_policy.close();
    drop(target_policy);
    drop(original_policy);
    target_sdk.close();
    original_sdk.close();
    drop(target_sdk);
    drop(original_sdk);
    assert_eq!(
        run(
            path,
            "joint-commit",
            &arguments(path, "policy-witness-commit", Some(endpoint))
        )?,
        expected(&grant, transaction, 2)
    );
    let terminal = pending_journal(path)?;
    assert!(terminal.1.is_none());
    assert_ne!(terminal.0, original_image.0);
    assert_eq!(image_digest(&terminal.0)?, proposal.target_head().digest());
    assert_eq!(
        run(
            path,
            "joint-commit-retry",
            &arguments(path, "policy-witness-commit", Some(endpoint))
        )?,
        expected(&grant, transaction, 2)
    );
    assert_eq!(pending_journal(path)?, terminal);
    assert_eq!(
        run(
            path,
            "joint-activate",
            &arguments(path, "policy-activate", Some(endpoint))
        )?,
        "policy-device-active\n"
    );
    assert_eq!(
        state(&run(
            path,
            "joint-final-status",
            &arguments(path, "status", Some(endpoint))
        )?)?,
        active
    );
    assert_eq!(pending_journal(path)?, terminal);
    assert!(
        Zeroizing::new(fs::read(path.join("signer.key"))?).as_slice() == signer.as_slice(),
        "original signer changed"
    );
    assert!(
        Zeroizing::new(fs::read(path.join("wrap.key"))?).as_slice() == wrapping.as_slice(),
        "original wrapping key changed"
    );
    for (name, bytes) in original_inputs {
        assert_eq!(fs::read(path.join(name))?, bytes);
    }
    for directory in [path.as_path(), target.as_path()] {
        drop(open_private_database(&directory.join("sdk.redb"))?);
    }
    lease_released(path)?;

    let subject = registration.subject.to_bytes();
    let captured = witness.captured.lock().map_err(|_| "capture poisoned")?;
    let tcp: Vec<_> = captured
        .iter()
        .filter(|c| c.request.get(44..140) == Some(subject.as_slice()))
        .collect();
    if tls {
        assert!(tcp.is_empty(), "TLS invocation fell back to plaintext");
    } else {
        assert!(
            tcp.iter().any(|c| c.delivered
                && c.request.get(204) == Some(&5)
                && c.reply.get(204) == Some(&8)),
            "real witness Commit/Applied exchange not observed"
        );
    }
    drop(captured);
    if let Some(server) = tls_witness.as_mut() {
        assert!(server.finish()?.is_empty());
        let records = server.records.lock().map_err(|_| "TLS records poisoned")?;
        assert_eq!(records.len(), server.admitted.load(Ordering::Acquire));
        assert!(
            records
                .iter()
                .any(|r| r.request().get(204) == Some(&5) && r.reply().get(204) == Some(&8)),
            "authenticated TLS Commit/Applied exchange not observed"
        );
        assert!(records
            .iter()
            .all(|r| r.request().get(44..140) == Some(subject.as_slice())));
    }
    witness.join()?;
    println!("C_WITNESSED_POLICY_CONTINUATION carrier={} original_329_byte_proposal=true independent_G_T_approval=true committed_readback=true original_owner=true current_activation=true", if tls { "tls" } else { "tcp" });
    Ok(())
}

#[test]
fn foreign_policy_continuation_commits_with_independent_tcp_and_tls_witness() -> Result<()> {
    exercise(false)?;
    exercise(true)
}
