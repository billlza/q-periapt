// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual foreign-owner G/T adoption with an independent TCP or TLS witness.
use super::*;
use std::{
    io, thread,
    time::{Duration, Instant},
};
use witness_credential_renewal::{
    image_digest, pending_journal, provision_renewal_materials, ProvisionedRenewal,
};
use zeroize::Zeroizing;

const DOCUMENT_FILES: [&str; 5] = [
    "family",
    "policy-root",
    "policy-version",
    "policy-digest",
    "protocol-policy",
];
const EXPIRING_POLICY_SECONDS: u64 = 120;

#[derive(Clone, Copy)]
enum Scenario {
    Commit,
    Cancel,
    CancelStatusCut,
    CancelAckCut,
}
impl Scenario {
    fn cancellation(self) -> bool {
        !matches!(self, Self::Commit)
    }
    fn acknowledge_cut(self) -> Option<bool> {
        match self {
            Self::CancelStatusCut => Some(false),
            Self::CancelAckCut => Some(true),
            Self::Commit | Self::Cancel => None,
        }
    }
    fn cut_name(self) -> &'static str {
        match self {
            Self::CancelStatusCut => "status",
            Self::CancelAckCut => "ack",
            Self::Commit | Self::Cancel => "none",
        }
    }
}
struct CancellationCut {
    pause: Arc<witness_cancellation::Pause>,
    acknowledge: bool,
    admission_index: usize,
}

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

fn carry_renewal(
    registration: &Registration,
    first: &ProvisionedRenewal,
    witness: &witness::Witness,
    endpoint: Endpoint,
    target: &Path,
    retained: [u8; 32],
) -> Result<()> {
    let path = &registration.path;
    let first_image = pending_journal(path)?;
    assert!(first_image.1.is_none());
    let p1_inputs = DOCUMENT_FILES
        .into_iter()
        .map(|name| Ok((name, fs::read(target.join(name))?)))
        .collect::<Result<Vec<_>>>()?;
    let t1_wire = fixture::read(path, "policy-approvals", 7746)?;
    let request = p::VerifiedEnrollmentRequest::verify(
        &registration.request,
        &registration.intent,
        fixture::now()?,
    )?;
    let family = fixture::array(path, "family")?;
    let validity = p::Validity::new(
        first.validity.from(),
        first
            .validity
            .until()
            .checked_add(120)
            .ok_or("clock overflow")?,
    )?;
    let certificate = registration.root.issue_device(
        p::DeviceDescription::new(
            registration.original.device_id(),
            registration.original.generation(),
            family,
            validity,
        )?,
        request.public_key().clone(),
    )?;
    let roster = registration.root.issue_roster(
        3,
        validity,
        &[registration.root.roster_entry(&certificate)?],
    )?;
    let pin = p::AccountPin::new(
        registration.root.account_id()?,
        registration.root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let operation = p::CredentialRenewalId::generate()?;
    let issued = registration.root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &fixture::read(path, "grant-certificate", 8192)?,
            previous_credential: &first.certificate,
            successor_credential: &certificate,
            previous_roster: first.roster.as_bytes(),
            successor_roster: roster.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: first.roster.checkpoint(),
            policy_digest: first.proof.policy_digest(),
        },
        &pin,
        fixture::now()?,
    )?;
    let grant = p::VerifiedCredentialRenewal::verify(
        issued.as_bytes(),
        &pin,
        first.proof.policy_digest(),
        fixture::now()?,
    )?;
    assert_ne!(operation, first.proof.operation());
    assert_ne!(grant.statement_digest(), retained);
    assert_eq!(
        grant.original_storage_owner(),
        first.proof.original_storage_owner()
    );
    assert_eq!(
        grant.previous_device().credential_digest(),
        first.proof.successor_device().credential_digest()
    );
    for (name, bytes) in [
        ("credential-renewal", issued.as_bytes().to_vec()),
        ("credential-operation", operation.as_bytes().to_vec()),
        ("credential-statement", grant.statement_digest().to_vec()),
        (
            "renewal-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", roster.checkpoint().digest().to_vec()),
    ] {
        fs::write(path.join(name), bytes)?;
    }
    fixture::store(path, "policy-retained-statement", &retained)?;
    fs::rename(
        path.join("policy-proposal"),
        path.join("policy-g1-proposal-retained"),
    )?;
    let pending = expected(&grant, grant.statement_digest(), 1);
    let committed = expected(&grant, grant.statement_digest(), 2);
    assert_eq!(
        run(
            path,
            "carry-stage",
            &arguments(path, "policy-carry-stage", Some(endpoint))
        )?,
        pending
    );
    assert_eq!(
        run(
            path,
            "carry-pending-reopen",
            &arguments(path, "credential-status", Some(endpoint))
        )?,
        pending
    );
    assert_eq!(
        run(
            path,
            "carry-prepare",
            &arguments(path, "policy-witness-carry-prepare", Some(endpoint))
        )?,
        "policy-witness-prepared\n"
    );
    let bytes = fixture::read(path, "policy-proposal", 329)?;
    let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&bytes)?;
    assert_eq!(bytes.len(), 329);
    assert_eq!(proposal.subject(), registration.subject);
    assert_eq!(proposal.operation(), operation);
    assert_eq!(proposal.statement(), grant.statement_digest());
    assert_eq!(proposal.transaction_statement(), grant.statement_digest());
    assert_eq!(proposal.policy_continuation(), Some(retained));
    assert!(!proposal.adopts_policy());
    let prepared = pending_journal(path)?;
    assert_eq!(prepared.0, first_image.0);
    assert!(prepared.1.is_some());
    assert_eq!(
        image_digest(&first_image.0)?,
        proposal.expected_head().digest()
    );
    fs::rename(
        path.join("policy-proposal"),
        path.join("policy-g2-proposal-original"),
    )?;
    assert_eq!(
        run(
            path,
            "carry-prepare-reopen",
            &arguments(path, "policy-witness-carry-prepare", Some(endpoint))
        )?,
        "policy-witness-prepared\n"
    );
    assert_eq!(fixture::read(path, "policy-proposal", 329)?, bytes);
    assert_eq!(pending_journal(path)?, prepared);
    let mut original_sdk = fixture::sdk(path)?;
    let original = fixture::protocol_policy(path, &original_sdk)?;
    let mut target_sdk = fixture::sdk(target)?;
    let current = fixture::protocol_policy(target, &target_sdk)?;
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness poisoned")?
        .prepare_continued_credential_renewal(
            proposal,
            &grant,
            original.historical(),
            &current,
            fixture::now()?,
        )?;
    current.close();
    original.close();
    drop(current);
    drop(original);
    target_sdk.close();
    original_sdk.close();
    drop(target_sdk);
    drop(original_sdk);
    assert_eq!(
        run(
            path,
            "carry-commit",
            &arguments(path, "policy-witness-commit", Some(endpoint))
        )?,
        committed
    );
    let terminal = pending_journal(path)?;
    assert!(terminal.1.is_none());
    assert_ne!(terminal.0, first_image.0);
    assert_eq!(image_digest(&terminal.0)?, proposal.target_head().digest());
    assert_eq!(
        run(
            path,
            "carry-commit-retry",
            &arguments(path, "policy-witness-commit", Some(endpoint))
        )?,
        committed
    );
    assert_eq!(pending_journal(path)?, terminal);
    assert_eq!(
        run(
            path,
            "carry-activate",
            &arguments(path, "policy-activate", Some(endpoint))
        )?,
        "policy-device-active\n"
    );
    assert_eq!(pending_journal(path)?, terminal);
    assert_eq!(fixture::read(path, "policy-approvals", 7746)?, t1_wire);
    for (name, bytes) in p1_inputs {
        assert_eq!(fs::read(target.join(name))?, bytes);
    }
    Ok(())
}

fn cancel_pending(
    registration: &Registration,
    first: &ProvisionedRenewal,
    witness: &witness::Witness,
    endpoint: Endpoint,
    scope: &p::PolicyContinuationScope,
    transaction: [u8; 32],
    cut: Option<&CancellationCut>,
) -> Result<(u64, u64)> {
    let path = &registration.path;
    let target = path.join("continued-sdk");
    let original = pending_journal(path)?;
    assert!(
        original.1.is_none(),
        "staging sealed a target before cancellation"
    );
    let historical = witness_policy_expiry::policy_pin(path)?.verify_historical(&fixture::read(
        path,
        "protocol-policy",
        8192,
    )?)?;
    let target_policy = witness_policy_expiry::policy_pin(&target)?
        .verify_historical(&fixture::read(&target, "protocol-policy", 8192)?)?;
    let grant = p::HistoricalCredentialRenewal::verify(
        &fixture::read(path, "credential-renewal", 65536)?,
        &first.pin,
        historical.checkpoint().digest(),
    )?;
    let materials = p::HistoricalPolicyContinuationMaterials {
        original: &historical,
        previous: &historical,
        target: &target_policy,
        credential: &grant,
    };
    let continuation = p::HistoricalPolicyContinuation::from_bytes(
        &fixture::read(path, "policy-approvals", 7746)?,
        scope,
        &materials,
    )?;
    fixture::store(
        path,
        "policy-credential-statement",
        &first.proof.statement_digest(),
    )?;
    fs::rename(path.join("sdk.redb"), path.join("sdk-cancel-retained.redb"))?;
    fs::rename(&target, path.join("continued-sdk-cancel-retained"))?;
    let prepared_at = fixture::now()?;
    assert_eq!(
        run(
            path,
            "joint-cancel-prepare",
            &arguments(path, "policy-witness-cancel-prepare", Some(endpoint))
        )?,
        "policy-witness-cancellation-prepared\n"
    );
    let bytes = fixture::read(path, "policy-cancellation", 281)?;
    assert_eq!(bytes.len(), 281);
    let cancellation = p::AnchorCredentialRenewalCancellation::from_trusted_state(&bytes)?;
    assert_eq!(cancellation.subject(), registration.subject);
    assert_eq!(cancellation.operation(), first.proof.operation());
    assert_eq!(cancellation.statement(), first.proof.statement_digest());
    assert_eq!(cancellation.transaction_statement(), transaction);
    assert_eq!(cancellation.policy_continuation(), Some(transaction));
    assert!(cancellation.adopts_policy());
    assert_eq!(
        cancellation.expected_head().digest(),
        image_digest(&original.0)?
    );
    let reserved = pending_journal(path)?;
    assert_eq!(reserved.0, original.0);
    assert!(reserved.1.is_some());
    assert!(!path.join("policy-proposal").exists());
    fs::rename(
        path.join("policy-cancellation"),
        path.join("policy-cancellation-original"),
    )?;
    assert_eq!(
        run(
            path,
            "joint-cancel-prepare-reopen",
            &arguments(path, "policy-witness-cancel-prepare", Some(endpoint))
        )?,
        "policy-witness-cancellation-prepared\n"
    );
    assert_eq!(fixture::read(path, "policy-cancellation", 281)?, bytes);
    assert_eq!(pending_journal(path)?, reserved);
    assert_eq!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness poisoned")?
            .close_unprepared_policy_continuation(cancellation, &continuation, &materials)?,
        p::AnchorCredentialCancellationState::Closed
    );
    if let Some(cut) = cut {
        let _ = witness_cancellation::kill_reconcile(
            path,
            witness,
            &cut.pause,
            endpoint,
            cut.acknowledge,
        )?;
        assert_eq!(pending_journal(path)?, reserved);
        assert_eq!(
            run(
                path,
                "joint-cancel-cut-status",
                &arguments(path, "credential-status", None)
            )?,
            expected(
                &first.proof,
                transaction,
                if cut.acknowledge { 4 } else { 1 }
            )
        );
        assert_eq!(pending_journal(path)?, reserved);
    }
    for label in ["joint-cancel-reconcile", "joint-cancel-reconcile-reopen"] {
        assert_eq!(
            run(
                path,
                label,
                &arguments(path, "credential-witness-reconcile", Some(endpoint))
            )?,
            expected(&first.proof, transaction, 4)
        );
        assert_eq!(pending_journal(path)?, original);
    }
    assert_eq!(
        run(
            path,
            "joint-cancel-closed-readback",
            &arguments(path, "credential-status", Some(endpoint))
        )?,
        expected(&first.proof, transaction, 4)
    );
    assert!(!target.exists());
    assert!(!path.join("sdk.redb").exists());
    let recovered_at = fixture::now()?;
    fs::rename(path.join("sdk-cancel-retained.redb"), path.join("sdk.redb"))?;
    fs::rename(path.join("continued-sdk-cancel-retained"), &target)?;
    Ok((prepared_at, recovered_at))
}

fn exercise(tls: bool, scenario: Scenario, expired: bool) -> Result<String> {
    let cancellation = scenario.cancellation();
    assert!(!expired || cancellation);
    let mut witness = witness::Witness::start()?;
    let setup = fixture::setup_with_witness(Some(&witness.configured))?;
    let authority = p::PolicySigningKey::generate()?;
    // P0 is signed by this independent issuer before registration begins.
    let registration = prepare_with_original_policy(
        &setup,
        &witness,
        Some((
            if expired {
                EXPIRING_POLICY_SECONDS
            } else {
                1800
            },
            &authority,
        )),
    )?;
    let path = &registration.path;
    let pause = Arc::new(witness_cancellation::Pause::new());
    let clock = Arc::clone(&pause);
    let mut tls_witness = if tls {
        Some(witness_tls::TlsWitness::start_with_clock(
            Arc::clone(&witness.configured.store),
            [path.as_path()],
            move || clock.now(),
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
    let first = provision_renewal_materials(&registration)?;
    let grant = &first.proof;
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
    let original_until = original_policy.validity().until();
    let target_until = target_policy.validity().until();
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
        credential: grant,
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
        expected(grant, transaction, 1)
    );
    let staged_at = fixture::now()?;
    assert!(
        staged_at < original_until,
        "setup missed original policy lifetime"
    );
    if expired {
        let before = pending_journal(path)?;
        let deadline = Instant::now() + Duration::from_secs(EXPIRING_POLICY_SECONDS + 5);
        while fixture::now()? < original_until {
            if Instant::now() >= deadline {
                return Err("real G/T policy expiry wait exceeded".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let pin = witness_policy_expiry::policy_pin(path)?;
        let historical = pin.verify_historical(&fixture::read(path, "protocol-policy", 8192)?)?;
        let now = witness_policy_expiry::expired_authority(path, &pin, &historical, &first.pin)?;
        let mut sdk = fixture::sdk(&target)?;
        let current = witness_policy_expiry::policy_pin(&target)?.verify(
            &fixture::read(&target, "protocol-policy", 8192)?,
            sdk.runtime()?,
            now,
        )?;
        let current_grant = p::VerifiedCredentialRenewal::verify(
            &fixture::read(path, "credential-renewal", 65536)?,
            &first.pin,
            historical.checkpoint().digest(),
            now,
        )?;
        assert!(now < current.validity().until());
        let materials = p::PolicyContinuationMaterials {
            original: &historical,
            previous: &historical,
            target: &current,
            credential: &current_grant,
        };
        let checked = p::VerifiedPolicyContinuation::from_bytes(
            &fixture::read(path, "policy-approvals", 7746)?,
            &scope,
            &materials,
            now,
        )?;
        assert_eq!(checked.statement_digest(), transaction);
        current.close();
        drop(current);
        sdk.close();
        drop(sdk);
        assert_eq!(pending_journal(path)?, before);
        assert_eq!(
            run(
                path,
                "expired-joint-pending",
                &arguments(path, "credential-status", None)
            )?,
            expected(grant, transaction, 1)
        );
    }
    let before_cancellation =
        witness_cancellation::current_calls(&witness, tls_witness.as_ref(), registration.subject)?;
    let cut = scenario
        .acknowledge_cut()
        .map(|acknowledge| CancellationCut {
            pause,
            acknowledge,
            admission_index: before_cancellation + usize::from(acknowledge),
        });
    let mut cancellation_clock = None;
    if cancellation {
        cancellation_clock = Some(cancel_pending(
            &registration,
            &first,
            &witness,
            endpoint,
            &scope,
            transaction,
            cut.as_ref(),
        )?);
        let (prepared_at, recovered_at) = cancellation_clock.ok_or("missing cancellation clock")?;
        assert_eq!(prepared_at >= original_until, expired);
        assert_eq!(recovered_at >= original_until, expired);
        assert!(
            prepared_at <= recovered_at
                && recovered_at < target_until
                && recovered_at < first.validity.until()
        );
        assert_eq!(pending_journal(path)?, original_image);
        assert_eq!(
            witness_cancellation::current_calls(
                &witness,
                tls_witness.as_ref(),
                registration.subject
            )?,
            before_cancellation + if cut.is_some() { 3 } else { 2 }
        );
        assert_eq!(
            state(&run(
                path,
                "cancel-final-status",
                &arguments(path, "status", Some(endpoint))
            )?)?,
            active
        );
    } else {
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
            credential: grant,
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
            expected(grant, transaction, 2)
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
            expected(grant, transaction, 2)
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
        carry_renewal(
            &registration,
            &first,
            &witness,
            endpoint,
            &target,
            transaction,
        )?;
        assert_eq!(
            state(&run(
                path,
                "carry-final-status",
                &arguments(path, "status", Some(endpoint))
            )?)?,
            active
        );
    }
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
                && c.request.get(204) == Some(&(if cancellation { 6 } else { 5 }))
                && c.reply.get(204) == Some(&(if cancellation { 9 } else { 8 }))),
            "real witness terminal exchange not observed"
        );
        if cancellation {
            assert!(
                tcp.iter()
                    .all(|c| !matches!(c.request.get(204), Some(5 | 7))),
                "cancellation dispatched Commit/Close"
            );
            assert!(tcp.iter().any(|c| c.delivered
                && c.request.get(204) == Some(&8)
                && c.reply.get(204) == Some(&11)));
            if let Some(cut) = cut.as_ref() {
                assert_eq!(
                    tcp.iter()
                        .filter(|c| !c.delivered
                            && c.request.get(204) == Some(&(if cut.acknowledge { 8 } else { 6 })))
                        .count(),
                    1
                );
            }
        }
    }
    drop(captured);
    if let Some(server) = tls_witness.as_mut() {
        let failures = server.finish()?;
        if let Some(cut) = cut.as_ref() {
            let failed_admissions = server
                .failed_admissions
                .lock()
                .map_err(|_| "TLS failure lock")?;
            witness_cancellation::require_cut_tls_failures(
                &failures,
                &failed_admissions,
                cut.admission_index,
            )?;
        } else {
            assert!(failures.is_empty());
        }
        let records = server.records.lock().map_err(|_| "TLS records poisoned")?;
        assert_eq!(
            records.len() + failures.len(),
            server.admitted.load(Ordering::Acquire)
        );
        assert!(
            records.iter().any(|r| r.request().get(204)
                == Some(&(if cancellation { 6 } else { 5 }))
                && r.reply().get(204) == Some(&(if cancellation { 9 } else { 8 }))),
            "authenticated TLS terminal exchange not observed"
        );
        if cancellation {
            assert!(
                records
                    .iter()
                    .all(|r| !matches!(r.request().get(204), Some(5 | 7))),
                "TLS cancellation dispatched Commit/Close"
            );
            assert!(records
                .iter()
                .any(|r| r.request().get(204) == Some(&8) && r.reply().get(204) == Some(&11)));
        }
        assert!(records
            .iter()
            .all(|r| r.request().get(44..140) == Some(subject.as_slice())));
    }
    witness.join()?;
    if cancellation {
        let (prepared_at, recovered_at) = cancellation_clock.ok_or("missing cancellation clock")?;
        Ok(format!("C_WITNESSED_POLICY_CANCELLATION carrier={} cut={} policy_expired={} original_281_byte_reservation=true independent_G_T_close=true no_target_or_SDK=true closed_readback=true original_owner=true no_commit=true\nC_POLICY_CANCELLATION_CLOCK carrier={} cut={} policy_expired={} staged_at={} p0_until={} prepared_at={} recovered_at={} credential_until={} target_until={}",
            if tls { "tls" } else { "tcp" }, scenario.cut_name(), expired,
            if tls { "tls" } else { "tcp" }, scenario.cut_name(), expired,
            staged_at, original_until, prepared_at, recovered_at, first.validity.until(), target_until))
    } else {
        Ok(format!("C_WITNESSED_POLICY_CONTINUATION carrier={} original_329_byte_proposal=true independent_G_T_approval=true committed_readback=true original_owner=true current_activation=true credential_successor_carries_t1=true", if tls { "tls" } else { "tcp" }))
    }
}

#[test]
fn foreign_policy_continuation_commits_with_independent_tcp_and_tls_witness() -> Result<()> {
    println!("{}", exercise(false, Scenario::Commit, false)?);
    println!("{}", exercise(true, Scenario::Commit, false)?);
    Ok(())
}

#[test]
fn foreign_policy_continuation_cancels_without_target_or_sdk() -> Result<()> {
    let mut tasks = Vec::new();
    for tls in [false, true] {
        for expired in [false, true] {
            for scenario in [
                Scenario::Cancel,
                Scenario::CancelStatusCut,
                Scenario::CancelAckCut,
            ] {
                tasks.push(thread::spawn(move || exercise(tls, scenario, expired)));
            }
        }
    }
    let results = tasks
        .into_iter()
        .map(|t| {
            t.join().unwrap_or_else(|_| {
                Err(io::Error::other("joint cancellation case panicked; see diagnostic").into())
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
