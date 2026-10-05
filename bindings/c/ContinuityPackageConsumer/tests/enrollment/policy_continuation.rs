// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual C owner integration with independent account and policy issuers.
//!
//! Requires registered_with_policy(lifetime, Some(&policy_root)): the supplied
//! independent root signs P0 before the original C registration starts. This
//! test never rewrites the original installation's protocol-policy inputs.
//! The C policy commands select continued-sdk using its independent P1 pin.
//! All stage/reconcile/activate operations run in actual client subprocesses;
//! Rust acts only as the independent account and policy issuer.
use super::*;

const POLICY_DOCUMENT_FILES: [&str; 5] = [
    "family",
    "policy-root",
    "policy-version",
    "policy-digest",
    "protocol-policy",
];

struct Successor {
    certificate: Vec<u8>,
    roster: p::IssuedRoster,
    wire: Vec<u8>,
    grant: p::VerifiedCredentialRenewal,
}

fn successor(
    c: &Registered,
    previous_certificate: &[u8],
    previous_roster: &p::IssuedRoster,
    version: u64,
    until: u64,
    original_policy: p::PolicyCheckpoint,
) -> Result<Successor> {
    let previous_pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        previous_roster.checkpoint(),
        c.family,
    )?;
    let previous = previous_pin.verify_device(
        previous_certificate,
        previous_roster.as_bytes(),
        fixture::now()?,
    )?;
    let certificate = c.root.issue_device(
        p::DeviceDescription::new(
            previous.device_id(),
            previous.generation(),
            c.family,
            p::Validity::new(c.validity.from(), until)?,
        )?,
        c.verified.public_key().clone(),
    )?;
    let roster = c.root.issue_roster(
        version,
        c.roster_validity,
        &[c.root.roster_entry(&certificate)?],
    )?;
    let target_pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        roster.checkpoint(),
        c.family,
    )?;
    let issued = c.root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &c.certificate,
            previous_credential: previous_certificate,
            successor_credential: &certificate,
            previous_roster: previous_roster.as_bytes(),
            successor_roster: roster.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation: p::CredentialRenewalId::generate()?,
            previous: previous_roster.checkpoint(),
            policy_digest: original_policy.digest(),
        },
        &target_pin,
        fixture::now()?,
    )?;
    let grant = p::VerifiedCredentialRenewal::verify(
        issued.as_bytes(),
        &target_pin,
        original_policy.digest(),
        fixture::now()?,
    )?;
    Ok(Successor {
        certificate,
        roster,
        wire: issued.as_bytes().to_vec(),
        grant,
    })
}

fn publish_grant(path: &Path, target: &Successor, transaction: [u8; 32]) -> Result<()> {
    // These are public, independently provisioned invocation inputs. Updating
    // them never changes an enrollment, installation, signer or journal file.
    for (name, bytes) in [
        ("credential-renewal", target.wire.clone()),
        (
            "credential-operation",
            target.grant.operation().as_bytes().to_vec(),
        ),
        ("credential-statement", transaction.to_vec()),
        (
            "renewal-version",
            target.roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "renewal-digest",
            target.roster.checkpoint().digest().to_vec(),
        ),
    ] {
        if path.join(name).try_exists()? {
            fs::write(path.join(name), bytes)?;
        } else {
            fixture::store(path, name, &bytes)?;
        }
    }
    Ok(())
}

fn observed(c: &Registered, label: &str, operation: &str) -> Result<RenewalObservation> {
    observation(&run(&c.path, label, &command(&c.path, operation))?)
}

fn pending(target: &Successor, statement: [u8; 32]) -> RenewalObservation {
    RenewalObservation {
        phase: 1,
        operation: *target.grant.operation().as_bytes(),
        statement,
        version: 0,
        digest: [0; 32],
        observed_at: 0,
    }
}

fn committed(target: &Successor, statement: [u8; 32]) -> RenewalObservation {
    RenewalObservation {
        phase: 2,
        operation: *target.grant.operation().as_bytes(),
        statement,
        version: target.roster.checkpoint().version(),
        digest: target.roster.checkpoint().digest(),
        observed_at: 0,
    }
}

fn original_identity(c: &Registered, label: &str, signer: &[u8], wrapping: &[u8]) -> Result<()> {
    assert_eq!(
        state(&run(&c.path, label, &command(&c.path, "status"))?)?,
        (5, c.accepted.1, c.accepted.2),
        "continued activation must retain the original registration and journal"
    );
    let current_signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let current_wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    // Avoid printing secret bytes in a failed assertion's diagnostic.
    assert!(
        current_signer.as_slice() == signer,
        "original signer changed"
    );
    assert!(
        current_wrapping.as_slice() == wrapping,
        "original wrapping key changed"
    );
    assert!(
        !c.path.join("local-certificate").exists(),
        "continued activation must not choose a replacement device-file layout"
    );
    lease(&c.path, false)
}

struct PreparedJoint {
    policy_root: p::PolicySigningKey,
    c: Registered,
    g1: Successor,
    original_checkpoint: p::PolicyCheckpoint,
    t1_statement: [u8; 32],
    t1_wire: Vec<u8>,
    original_inputs: BTreeMap<&'static str, Vec<u8>>,
    target_inputs: BTreeMap<&'static str, Vec<u8>>,
    target_checkpoint: p::PolicyCheckpoint,
    target_until: u64,
}
fn prepare_joint(original_seconds: u64, target_seconds: u64) -> Result<PreparedJoint> {
    let policy_root = p::PolicySigningKey::generate()?;
    let c = registered_with_policy_duration(600, Some(&policy_root), original_seconds)?;
    prepare_joint_for(c, policy_root, Some(original_seconds), target_seconds)
}

fn prepare_joint_for(
    c: Registered,
    policy_root: p::PolicySigningKey,
    original_seconds: Option<u64>,
    target_seconds: u64,
) -> Result<PreparedJoint> {
    assert_eq!(c.family, policy_root.policy_family()?);
    assert_ne!(c.accepted.1, [0; 32]);
    assert_ne!(c.accepted.2, [0; 32]);
    let original_inputs: BTreeMap<_, _> = POLICY_DOCUMENT_FILES
        .into_iter()
        .chain([
            "sdk-policy",
            "sdk-signature",
            "sdk-root",
            "enrollment-root",
            "enrollment-intent",
            "enrollment-request",
            "grant-certificate",
            "grant-roster",
        ])
        .map(|name| Ok((name, fs::read(c.path.join(name))?)))
        .collect::<Result<_>>()?;

    let target_path = c.path.join("continued-sdk");
    let previous_path = c.path.join("previous-policy");
    for path in [&target_path, &previous_path] {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    for name in POLICY_DOCUMENT_FILES {
        fixture::store(&previous_path, name, &fs::read(c.path.join(name))?)?;
    }
    for name in ["sdk-policy", "sdk-signature", "sdk-root"] {
        fixture::store(&target_path, name, &fs::read(c.path.join(name))?)?;
    }

    // Both runtimes are real PolicyStores with the same authenticated SDK
    // binding. Neither runtime nor an open database lease crosses a C command.
    let mut original_sdk = fixture::sdk(&c.path)?;
    let original_policy = fixture::protocol_policy(&c.path, &original_sdk)?;
    let original_checkpoint = original_policy.checkpoint();
    assert_eq!(original_checkpoint.version(), 1);
    // The fixture signs P0 before it timestamps the device intent; these two
    // real wall-clock reads need not fall in the same second.
    if let Some(original_seconds) = original_seconds {
        assert_eq!(
            original_policy.validity().until(),
            original_policy
                .validity()
                .from()
                .checked_add(original_seconds.checked_add(1).ok_or("clock overflow")?)
                .ok_or("clock overflow")?
        );
    }
    assert_eq!(
        original_policy.anchor_requirement(),
        p::AnchorRequirement::local_only()
    );
    let mut target_sdk = PolicyStore::provision(
        &target_path.join("sdk.redb"),
        &fixture::read(&target_path, "sdk-policy", 4096)?,
        &fixture::read(&target_path, "sdk-signature", 8192)?,
        &fixture::read(&target_path, "sdk-root", 8192)?,
        q_periapt_sdk::Limits::default(),
    )?;
    let target_runtime = target_sdk.runtime()?;
    let target_until = c.at.checked_add(target_seconds).ok_or("clock overflow")?;
    let issued_policy = policy_root.issue_session_policy(
        &target_runtime,
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(original_policy.validity().from(), target_until)?,
            original_policy.allowed_modes(),
            original_policy.anchor_requirement(),
            original_policy.application_send_budget(),
        )?,
    )?;
    for (name, bytes) in [
        ("family", c.family.to_vec()),
        ("policy-root", policy_root.public_key()?.encode()),
        (
            "policy-version",
            issued_policy.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "policy-digest",
            issued_policy.checkpoint().digest().to_vec(),
        ),
        ("protocol-policy", issued_policy.as_bytes().to_vec()),
    ] {
        fixture::store(&target_path, name, &bytes)?;
    }
    let target_policy = fixture::protocol_policy(&target_path, &target_sdk)?;
    assert_eq!(original_policy.sdk_binding(), target_policy.sdk_binding());
    assert_eq!(original_policy.family(), target_policy.family());
    let target_inputs: BTreeMap<_, _> = POLICY_DOCUMENT_FILES
        .into_iter()
        .chain(["sdk-policy", "sdk-signature", "sdk-root"])
        .map(|name| Ok((name, fs::read(target_path.join(name))?)))
        .collect::<Result<_>>()?;

    let g1 = successor(
        &c,
        &c.certificate,
        &c.roster,
        2,
        c.at.checked_add(1200).ok_or("clock overflow")?,
        original_checkpoint,
    )?;
    let scope = p::PolicyContinuationScope {
        operation: g1.grant.operation(),
        journal: p::JournalIdentity::from_trusted_state(c.accepted.2)?,
        original_owner: g1.grant.original_storage_owner(),
        original_credential: g1.grant.original_credential_digest(),
        previous_credential: g1.grant.previous_device().credential_digest(),
        previous_roster: c.roster.checkpoint(),
        original_policy: original_checkpoint,
        previous_policy: original_checkpoint,
        previous_authorization: None,
    };
    let materials = p::PolicyContinuationMaterials {
        original: original_policy.historical(),
        previous: original_policy.historical(),
        target: &target_policy,
        credential: &g1.grant,
    };
    let statement = p::PolicyContinuationStatement::new(&scope, &materials, fixture::now()?)?;
    let account_approval = c.root.approve_policy_continuation(&statement)?;
    let policy_approval = policy_root.approve_policy_continuation(&statement)?;
    let t1 = p::VerifiedPolicyContinuation::verify(
        &account_approval,
        &policy_approval,
        &scope,
        &materials,
        fixture::now()?,
    )?;
    let t1_statement = t1.statement_digest();
    let t1_wire = t1.as_bytes().to_vec();
    assert_ne!(t1_statement, g1.grant.statement_digest());
    fixture::store(&c.path, "policy-approvals", &t1_wire)?;
    fixture::store(&c.path, "policy-predecessor-kind", &[0])?;
    assert!(!c.path.join("policy-predecessor-statement").exists());
    publish_grant(&c.path, &g1, t1_statement)?;
    target_policy.close();
    original_policy.close();
    drop(target_policy);
    drop(original_policy);
    drop(target_runtime);
    target_sdk.close();
    original_sdk.close();
    drop(target_sdk);
    drop(original_sdk);

    Ok(PreparedJoint {
        policy_root,
        c,
        g1,
        original_checkpoint,
        t1_statement,
        t1_wire,
        original_inputs,
        target_inputs,
        target_checkpoint: issued_policy.checkpoint(),
        target_until,
    })
}

#[test]
fn c_policy_continuation_delivers_on_original_session_after_owner_reopen() -> Result<()> {
    continued_original_session_delivery(false)?;
    continued_original_session_delivery(true)?;
    println!("C_POLICY_CONTINUED_TRAFFIC original_session=true original_message=true peer_effect=true acknowledged_after_reopen=true original_owner=true immutable_p0=true current_p1=true");
    Ok(())
}

fn continued_original_session_delivery(unknown_delivery: bool) -> Result<()> {
    // Both peers were installed under this issuer's original P0. Transfer only
    // the independent control-plane owner; never rewrite the installed peer.
    let mut registered = registered(600)?;
    let policy_root = registered
        ._setup
        .policy_issuer
        .take()
        .ok_or("missing original policy issuer")?;
    let PreparedJoint {
        c,
        g1,
        t1_statement,
        original_inputs,
        target_inputs,
        ..
    } = prepare_joint_for(registered, policy_root, None, 7200)?;
    let peer = peer_bundle(&c._setup, &c.path, &c.root, &c.certificate, &c.roster)?;
    let bundle = fixture::read(&peer, "bootstrap.bundle", p::MAX_BOOTSTRAP_BUNDLE_BYTES)?;
    let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    for name in POLICY_DOCUMENT_FILES {
        assert_eq!(
            fs::read(c._setup.responder.join(name))?,
            fs::read(c.path.join(name))?
        );
    }
    let (mut server, address) = fixture::spawn(&c._setup.responder, 81, "bootstrap")?;
    let initiation = p::InitiationId::generate()?;
    let session = decode_id(
        run(
            &c.path,
            "traffic-connect",
            &[
                "--enrollment-parent".into(),
                c.path.as_os_str().into(),
                "1".into(),
                "connect".into(),
                peer.as_os_str().into(),
                address.to_string().into(),
                fixture::hex(initiation.as_bytes()).into(),
            ],
        )?
        .trim_end(),
    )?;
    assert!(fixture::wait(&mut server)?.success());
    assert_eq!(
        fixture::array::<32>(&c._setup.responder, "session")?,
        session
    );
    let args = |continued: bool, operation: &str, tail: Vec<OsString>| {
        let mut values = vec![
            if continued {
                "--continued-enrollment-parent"
            } else {
                "--enrollment-parent"
            }
            .into(),
            c.path.as_os_str().into(),
            "1".into(),
            "--session".into(),
            fixture::hex(&session).into(),
            operation.into(),
            peer.as_os_str().into(),
        ];
        values.extend(tail);
        values
    };
    let message = decode_id(
        run(
            &c.path,
            "traffic-original-next",
            &args(false, "next", vec![fixture::hex(&session).into()]),
        )?
        .trim_end(),
    )?;
    assert_eq!(
        observed(&c, "traffic-stage", "policy-stage")?,
        pending(&g1, t1_statement)
    );
    assert_eq!(
        observed(&c, "traffic-pending-reopen", "credential-status")?,
        pending(&g1, t1_statement)
    );
    assert_eq!(
        observed(&c, "traffic-reconcile", "policy-reconcile")?,
        committed(&g1, t1_statement)
    );
    assert_eq!(
        observed(&c, "traffic-committed-reopen", "credential-status")?,
        committed(&g1, t1_statement)
    );
    let effect_path = c
        ._setup
        .responder
        .join(format!("application-{}", fixture::hex(&message)));
    let original_effect = if unknown_delivery {
        let (mut server, address) =
            fixture::spawn(&c._setup.responder, 82, "crash-after-application")?;
        assert_eq!(
            run(
                &c.path,
                "traffic-uncertain-send",
                &args(
                    true,
                    "uncertain-send",
                    vec![
                        address.to_string().into(),
                        fixture::hex(&session).into(),
                        fixture::hex(&message).into(),
                    ]
                )
            )?,
            "delivery-unknown-committed\n"
        );
        assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
        fixture::effect(
            &c._setup.responder,
            session,
            p::MessageId::from_trusted_state(message)?,
            b"persisted before process exit",
        )?;
        // A separate foreign process must still report Committed (2), even
        // though the independently observed receiver effect already exists.
        assert_eq!(
            run(
                &c.path,
                "traffic-committed-message-reopen",
                &args(
                    true,
                    "status",
                    vec![fixture::hex(&session).into(), fixture::hex(&message).into()]
                )
            )?,
            "2\n"
        );
        Some(fs::metadata(&effect_path)?)
    } else {
        None
    };
    let (mut server, address) = fixture::spawn(&c._setup.responder, 83, "application")?;
    assert_eq!(
        run(
            &c.path,
            "traffic-send",
            &args(
                true,
                "send",
                vec![
                    address.to_string().into(),
                    fixture::hex(&session).into(),
                    fixture::hex(&message).into(),
                ]
            )
        )?,
        "consumed\n"
    );
    assert!(fixture::wait(&mut server)?.success());
    fixture::effect(
        &c._setup.responder,
        session,
        p::MessageId::from_trusted_state(message)?,
        b"persisted before process exit",
    )?;
    if let Some(original_effect) = original_effect {
        use std::os::unix::fs::MetadataExt;
        let recovered_effect = fs::metadata(&effect_path)?;
        assert_eq!(original_effect.dev(), recovered_effect.dev());
        assert_eq!(original_effect.ino(), recovered_effect.ino());
        assert_eq!(original_effect.len(), recovered_effect.len());
        assert_eq!(original_effect.mtime(), recovered_effect.mtime());
        assert_eq!(original_effect.mtime_nsec(), recovered_effect.mtime_nsec());
    }
    // A fresh foreign process activates the same continued parent and reopens
    // the existing session. 3 is QPC_MESSAGE_ACKNOWLEDGED, not an inferred ACK.
    assert_eq!(
        run(
            &c.path,
            "traffic-ack-reopen",
            &args(
                true,
                "status",
                vec![fixture::hex(&session).into(), fixture::hex(&message).into(),]
            )
        )?,
        "3\n"
    );
    let effects = fs::read_dir(&c._setup.responder)?
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
    assert_eq!(
        fixture::read(&peer, "bootstrap.bundle", p::MAX_BOOTSTRAP_BUNDLE_BYTES)?,
        bundle
    );
    assert_eq!(
        fixture::array::<32>(&c._setup.responder, "session")?,
        session
    );
    original_identity(&c, "traffic-original-identity", &signer, &wrapping)?;
    for (name, bytes) in original_inputs {
        assert_eq!(fs::read(c.path.join(name))?, bytes);
    }
    for (name, bytes) in target_inputs {
        assert_eq!(fs::read(c.path.join("continued-sdk").join(name))?, bytes);
    }
    drop(open_private_database(
        &c.path.join("continued-sdk/sdk.redb"),
    )?);
    if unknown_delivery {
        println!("C_POLICY_UNKNOWN_DELIVERY_RECOVERY receiver_exit_after_effect=true committed_after_reopen=true original_message_retry=true acknowledged_after_reopen=true original_effect_unchanged=true");
    }
    Ok(())
}

#[test]
fn c_local_policy_continuation_reopens_original_enrollment_and_carries_t1_into_g2() -> Result<()> {
    let PreparedJoint {
        c,
        g1,
        original_checkpoint,
        t1_statement,
        t1_wire,
        original_inputs,
        target_inputs,
        target_checkpoint,
        ..
    } = prepare_joint(300, 2400)?;
    let target_path = c.path.join("continued-sdk");
    let previous_path = c.path.join("previous-policy");
    let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    let pending1 = pending(&g1, t1_statement);
    let committed1 = committed(&g1, t1_statement);
    assert_eq!(observed(&c, "policy-g1-stage", "policy-stage")?, pending1);
    lease(&c.path, false)?;
    // A different executable invocation reopens the original registration.
    assert_eq!(
        observed(&c, "policy-g1-pending-reopen", "credential-status")?,
        pending1
    );
    assert_eq!(
        observed(&c, "policy-g1-reconcile", "policy-reconcile")?,
        committed1
    );
    assert_eq!(
        observed(&c, "policy-g1-committed-reopen", "credential-status")?,
        committed1
    );
    assert_eq!(
        run(
            &c.path,
            "policy-g1-activate",
            &command(&c.path, "policy-activate")
        )?,
        "policy-device-active\n"
    );
    original_identity(&c, "policy-g1-original-identity", &signer, &wrapping)?;

    // Only the account root signs this second transition. No T2 is constructed,
    // issued or staged: the independently pinned P1 and original T1 stay exact.
    let g2 = successor(
        &c,
        &g1.certificate,
        &g1.roster,
        3,
        c.at.checked_add(1800).ok_or("clock overflow")?,
        original_checkpoint,
    )?;
    assert_eq!(
        g2.grant.original_storage_owner(),
        g1.grant.original_storage_owner()
    );
    assert_eq!(
        g2.grant.original_credential_digest(),
        g1.grant.original_credential_digest()
    );
    assert_eq!(
        g2.grant.previous_device().credential_digest(),
        g1.grant.successor_device().credential_digest()
    );
    assert_ne!(g2.grant.operation(), g1.grant.operation());
    let g2_statement = g2.grant.statement_digest();
    publish_grant(&c.path, &g2, g2_statement)?;
    let pending2 = pending(&g2, g2_statement);
    let committed2 = committed(&g2, g2_statement);
    assert_eq!(
        observed(&c, "policy-g2-carry-stage", "policy-carry-stage")?,
        pending2
    );
    lease(&c.path, false)?;
    assert_eq!(
        observed(&c, "policy-g2-pending-reopen", "credential-status")?,
        pending2
    );
    assert_eq!(
        observed(&c, "policy-g2-reconcile", "policy-reconcile")?,
        committed2
    );
    assert_eq!(
        observed(&c, "policy-g2-committed-reopen", "credential-status")?,
        committed2
    );
    assert_eq!(
        run(
            &c.path,
            "policy-g2-activate",
            &command(&c.path, "policy-activate")
        )?,
        "policy-device-active\n"
    );
    original_identity(&c, "policy-g2-original-identity", &signer, &wrapping)?;
    assert_eq!(fs::read(c.path.join("policy-approvals"))?, t1_wire);
    for (name, bytes) in original_inputs {
        assert_eq!(
            fs::read(c.path.join(name))?,
            bytes,
            "original input {name} changed"
        );
    }
    for (name, bytes) in target_inputs {
        assert_eq!(
            fs::read(target_path.join(name))?,
            bytes,
            "independently pinned P1 input {name} changed"
        );
    }
    for name in POLICY_DOCUMENT_FILES {
        assert_eq!(
            fs::read(previous_path.join(name))?,
            fs::read(c.path.join(name))?,
            "independently retained P0 document {name} changed"
        );
    }
    assert_eq!(
        fixture::array::<32>(&target_path, "policy-digest")?,
        target_checkpoint.digest()
    );
    println!("C_POLICY_CONTINUATION local_only=true joint_stage_readback=true joint_commit_readback=true current_owner=true same_signer=true same_wrapping_key=true same_journal=true credential_successor_carries_t1=true original_policy_inputs_unchanged=true");
    Ok(())
}

#[test]
fn c_second_policy_adoption_uses_original_owner_and_explicit_t1_predecessor() -> Result<()> {
    let prepared = prepare_joint(300, 2400)?;
    let c = &prepared.c;
    let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
    let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
    assert_eq!(
        observed(c, "t1-stage", "policy-stage")?,
        pending(&prepared.g1, prepared.t1_statement)
    );
    assert_eq!(
        observed(c, "t1-commit", "policy-reconcile")?,
        committed(&prepared.g1, prepared.t1_statement)
    );
    assert_eq!(
        run(&c.path, "t1-activate", &command(&c.path, "policy-activate"))?,
        "policy-device-active\n"
    );
    original_identity(c, "t1-identity", &signer, &wrapping)?;

    let g2 = successor(
        c,
        &prepared.g1.certificate,
        &prepared.g1.roster,
        3,
        c.at.checked_add(1800).ok_or("clock overflow")?,
        prepared.original_checkpoint,
    )?;
    assert_ne!(g2.grant.operation(), prepared.g1.grant.operation());
    assert_eq!(
        g2.grant.previous_device().credential_digest(),
        prepared.g1.grant.successor_device().credential_digest()
    );
    let target = c.path.join("continued-sdk");
    let previous = c.path.join("previous-policy");
    // Change only the explicitly provisioned public invocation documents. The
    // original enrollment's P0 and the existing SDK database remain in place.
    for name in POLICY_DOCUMENT_FILES {
        fs::write(
            previous.join(name),
            prepared
                .target_inputs
                .get(name)
                .ok_or("retained P1 document")?,
        )?;
    }
    let mut original_sdk = fixture::sdk(&c.path)?;
    let original_policy = fixture::protocol_policy(&c.path, &original_sdk)?;
    let mut target_sdk = fixture::sdk(&target)?;
    let previous_policy = fixture::protocol_policy(&target, &target_sdk)?;
    assert_eq!(previous_policy.checkpoint(), prepared.target_checkpoint);
    let target_runtime = target_sdk.runtime()?;
    let issued = prepared.policy_root.issue_session_policy(
        &target_runtime,
        p::SessionPolicyParameters::new(
            3,
            p::Validity::new(
                previous_policy.validity().from(),
                c.at.checked_add(3600).ok_or("clock overflow")?,
            )?,
            previous_policy.allowed_modes(),
            previous_policy.anchor_requirement(),
            previous_policy.application_send_budget(),
        )?,
    )?;
    let p2_inputs = [
        ("family", c.family.to_vec()),
        ("policy-root", prepared.policy_root.public_key()?.encode()),
        (
            "policy-version",
            issued.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("policy-digest", issued.checkpoint().digest().to_vec()),
        ("protocol-policy", issued.as_bytes().to_vec()),
    ];
    for (name, bytes) in &p2_inputs {
        fs::write(target.join(name), bytes)?;
    }
    let target_policy = fixture::protocol_policy(&target, &target_sdk)?;
    let scope = p::PolicyContinuationScope {
        operation: g2.grant.operation(),
        journal: p::JournalIdentity::from_trusted_state(c.accepted.2)?,
        original_owner: g2.grant.original_storage_owner(),
        original_credential: g2.grant.original_credential_digest(),
        previous_credential: g2.grant.previous_device().credential_digest(),
        previous_roster: prepared.g1.roster.checkpoint(),
        original_policy: prepared.original_checkpoint,
        previous_policy: prepared.target_checkpoint,
        previous_authorization: Some(prepared.t1_statement),
    };
    let materials = p::PolicyContinuationMaterials {
        original: original_policy.historical(),
        previous: previous_policy.historical(),
        target: &target_policy,
        credential: &g2.grant,
    };
    let statement = p::PolicyContinuationStatement::new(&scope, &materials, fixture::now()?)?;
    let t2 = p::VerifiedPolicyContinuation::verify(
        &c.root.approve_policy_continuation(&statement)?,
        &prepared
            .policy_root
            .approve_policy_continuation(&statement)?,
        &scope,
        &materials,
        fixture::now()?,
    )?;
    let t2_statement = t2.statement_digest();
    assert_ne!(t2_statement, prepared.t1_statement);
    assert_ne!(t2_statement, g2.grant.statement_digest());
    // Both roots also sign a structurally valid but incorrect predecessor.
    // Public signature verification alone cannot establish retained T history.
    let wrong_predecessor = prepared.g1.grant.statement_digest();
    assert_ne!(wrong_predecessor, prepared.t1_statement);
    let wrong_scope = p::PolicyContinuationScope {
        previous_authorization: Some(wrong_predecessor),
        ..scope.clone()
    };
    let wrong_statement =
        p::PolicyContinuationStatement::new(&wrong_scope, &materials, fixture::now()?)?;
    let wrong_t2 = p::VerifiedPolicyContinuation::verify(
        &c.root.approve_policy_continuation(&wrong_statement)?,
        &prepared
            .policy_root
            .approve_policy_continuation(&wrong_statement)?,
        &wrong_scope,
        &materials,
        fixture::now()?,
    )?;
    assert_ne!(wrong_t2.statement_digest(), t2_statement);
    fs::write(c.path.join("policy-approvals"), t2.as_bytes())?;
    fs::write(c.path.join("policy-predecessor-kind"), [1])?;
    fixture::store(
        &c.path,
        "policy-predecessor-statement",
        &prepared.t1_statement,
    )?;
    publish_grant(&c.path, &g2, t2_statement)?;
    target_policy.close();
    previous_policy.close();
    original_policy.close();
    drop(target_policy);
    drop(previous_policy);
    drop(original_policy);
    drop(target_runtime);
    target_sdk.close();
    original_sdk.close();
    drop(target_sdk);
    drop(original_sdk);

    fs::write(c.path.join("policy-approvals"), wrong_t2.as_bytes())?;
    fs::write(
        c.path.join("policy-predecessor-statement"),
        wrong_predecessor,
    )?;
    publish_grant(&c.path, &g2, wrong_t2.statement_digest())?;
    assert_eq!(
        run(
            &c.path,
            "t2-wrong-predecessor",
            &command(&c.path, "policy-stage-conflict")
        )?,
        "policy-stage-conflict\n"
    );
    assert_eq!(
        observed(c, "t1-retained-after-conflict", "credential-status")?,
        committed(&prepared.g1, prepared.t1_statement)
    );
    original_identity(c, "t1-identity-after-conflict", &signer, &wrapping)?;
    // Resume the same G2 operation using its correct independently approved T2.
    fs::write(c.path.join("policy-approvals"), t2.as_bytes())?;
    fs::write(
        c.path.join("policy-predecessor-statement"),
        prepared.t1_statement,
    )?;
    publish_grant(&c.path, &g2, t2_statement)?;
    let pending2 = pending(&g2, t2_statement);
    let committed2 = committed(&g2, t2_statement);
    assert_eq!(observed(c, "t2-stage", "policy-stage")?, pending2);
    lease(&c.path, false)?;
    assert_eq!(
        observed(c, "t2-pending-reopen", "credential-status")?,
        pending2
    );
    assert_eq!(observed(c, "t2-commit", "policy-reconcile")?, committed2);
    assert_eq!(
        observed(c, "t2-committed-reopen", "credential-status")?,
        committed2
    );
    assert_eq!(
        run(&c.path, "t2-activate", &command(&c.path, "policy-activate"))?,
        "policy-device-active\n"
    );
    original_identity(c, "t2-identity", &signer, &wrapping)?;
    for (name, bytes) in &prepared.original_inputs {
        assert_eq!(fs::read(c.path.join(name))?, *bytes);
    }
    for name in POLICY_DOCUMENT_FILES {
        assert_eq!(
            fs::read(previous.join(name))?,
            *prepared.target_inputs.get(name).ok_or("P1 readback")?
        );
    }
    for (name, bytes) in p2_inputs {
        assert_eq!(fs::read(target.join(name))?, bytes);
    }
    for name in ["sdk-policy", "sdk-signature", "sdk-root"] {
        assert_eq!(
            fs::read(target.join(name))?,
            *prepared.target_inputs.get(name).ok_or("SDK input")?
        );
    }
    assert_eq!(
        fixture::array::<32>(&c.path, "policy-predecessor-statement")?,
        prepared.t1_statement
    );
    println!("C_SECOND_POLICY_ADOPTION explicit_nonnull_t1=true approved_wrong_predecessor_refused=true g2_t2_committed=true same_original_owner=true current_activation=true immutable_p0=true retained_p1=true independent_p2=true");
    Ok(())
}

#[test]
fn c_historical_policy_recovery_after_real_p1_expiry_needs_no_sdk_or_tls() -> Result<()> {
    let cases = [prepare_joint(60, 75)?, prepare_joint(60, 75)?];
    for (index, prepared) in cases.iter().enumerate() {
        assert_eq!(
            observed(&prepared.c, "history-stage", "policy-stage")?,
            pending(&prepared.g1, prepared.t1_statement)
        );
        if index == 0 {
            assert_eq!(
                observed(&prepared.c, "history-commit", "policy-reconcile")?,
                committed(&prepared.g1, prepared.t1_statement)
            );
        }
    }
    let until = cases
        .iter()
        .map(|p| p.target_until)
        .max()
        .ok_or("no target interval")?;
    wait_until_expired(until)?;
    for (index, prepared) in cases.iter().enumerate() {
        let c = &prepared.c;
        assert!(fixture::now()? >= prepared.target_until);
        assert_eq!(
            run(
                &c.path,
                "expired-current",
                &command(&c.path, "policy-current-refused")
            )?,
            "policy-expired-current-refused\n"
        );
        let signer = Zeroizing::new(fs::read(c.path.join("signer.key"))?);
        let wrapping = Zeroizing::new(fs::read(c.path.join("wrap.key"))?);
        let target = c.path.join("continued-sdk");
        for directory in [&c.path, &target] {
            for name in ["sdk.redb", "sdk-policy", "sdk-signature", "sdk-root"] {
                fs::rename(
                    directory.join(name),
                    directory.join(format!("retained-{name}")),
                )?;
                assert!(!directory.join(name).exists());
            }
        }
        for name in ["tls-cert", "tls-key"] {
            fs::rename(c.path.join(name), c.path.join(format!("retained-{name}")))?;
            assert!(!c.path.join(name).exists());
        }
        for attempt in 0..2 {
            if index == 0 {
                assert_eq!(
                    observed(
                        c,
                        &format!("historical-committed-{attempt}"),
                        "policy-recover-history"
                    )?,
                    committed(&prepared.g1, prepared.t1_statement)
                );
            } else {
                assert_eq!(
                    run(
                        &c.path,
                        &format!("historical-pending-{attempt}"),
                        &command(&c.path, "policy-history-pending")
                    )?,
                    "policy-history-pending\n"
                );
                assert_eq!(
                    observed(
                        c,
                        &format!("pending-readback-{attempt}"),
                        "credential-status"
                    )?,
                    pending(&prepared.g1, prepared.t1_statement)
                );
            }
            original_identity(c, &format!("history-owner-{attempt}"), &signer, &wrapping)?;
        }
        let pin = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            c.roster.checkpoint(),
            c.family,
        )?;
        let original = pin.verify_device(&c.certificate, c.roster.as_bytes(), fixture::now()?)?;
        let mut journal = p::DeviceJournal::open(
            &c.path.join("journal.redb"),
            p::JournalKey::open(&c.path.join("wrap.key"))?,
            &original,
            p::JournalIdentity::from_trusted_state(c.accepted.2)?,
        )?;
        assert_eq!(
            journal.roster_checkpoint(c.root.account_id()?)?,
            if index == 0 {
                prepared.g1.roster.checkpoint()
            } else {
                c.roster.checkpoint()
            }
        );
        journal.close();
        for name in POLICY_DOCUMENT_FILES {
            assert_eq!(
                fs::read(c.path.join(name))?,
                *prepared
                    .original_inputs
                    .get(name)
                    .ok_or("original policy input")?
            );
            assert_eq!(
                fs::read(target.join(name))?,
                *prepared
                    .target_inputs
                    .get(name)
                    .ok_or("target policy input")?
            );
        }
    }
    println!("C_HISTORICAL_POLICY_RECOVERY actual_P1_expiry=true expired_current_refused=true SDK_and_TLS_unavailable=true committed_preserved=true uncommitted_remains_pending=true same_original_owners=true");
    Ok(())
}
