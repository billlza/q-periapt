// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn exercise(carrier: &str, profile: &str, applied: bool) -> Result<()> {
    exercise_with_cut(carrier, profile, applied, Cut::None)
}
pub(super) fn exercise_with_cut(
    carrier: &str,
    profile: &str,
    applied: bool,
    cut: Cut,
) -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let client = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("public client")?);
    // The runner owns a fresh batch root; each route claims its own directory
    // exclusively, so a repeated route cannot reopen any earlier cohort.
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&output)?;
    let outcome = if applied { "applied" } else { "unapplied" };
    let suffix = cut.suffix();
    let base = output.join(format!("{carrier}-{profile}-{outcome}{suffix}"));
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut witness = witness::Witness::start()?;
    let reference = fixture::setup_expiring_policy(Some(&witness.configured), POLICY_SECONDS)?;
    let (authority, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
    let pin = witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness")?
        .pin()?;
    for (name, bytes) in [
        ("witness-id", pin.identity().as_bytes().to_vec()),
        ("witness-public", pin.public_key().encode()),
        (
            "witness-address",
            witness.configured.address.to_string().into_bytes(),
        ),
        ("witness-carrier", b"signed".to_vec()),
    ] {
        retain(&inputs.join(name), &bytes)?;
    }
    let run = |mode: &str, label: &str| run_foreign(&client, profile, &inputs, &base, mode, label);
    let interrupted = |mode: &str, label: &str| {
        crate::android_retirement::interrupted(&client, profile, &inputs, &base, mode, label)
    };
    let original = run("managed-witness-create", "original.request")?;
    let (certificate, roster) = issue_grant(&inputs, &authority, &intent, validity, &original)?;
    retain(
        &inputs.join("authority-id"),
        p::AccountAuthorityIdentity::generate()?.as_bytes(),
    )?;
    retain(&inputs.join("authority-application"), &[133; 32])?;
    let association = run("authority-create", "authority-created")?;
    assert_eq!(association.len(), 72);
    retain(&inputs.join("authority-checkpoint"), &association)?;
    let genesis = run("managed-witness-prepare", "genesis")?;
    assert_eq!(genesis.len(), 164);
    assert_eq!(genesis.get(..4), Some(&2u32.to_be_bytes()[..]));
    let subject = p::AnchorSubject::from_trusted_state(genesis.get(36..132).ok_or("subject")?)?;
    let journal =
        p::JournalIdentity::from_trusted_state(genesis.get(4..36).ok_or("journal")?.try_into()?)?;
    let account = p::AccountPin::new(
        authority.account_id()?,
        authority.public_key()?,
        roster.checkpoint(),
        fixture::array(&inputs, "family")?,
    )?;
    let device = account.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
    let until = policy.validity().until();
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, &device, policy.as_ref())?
    );
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness")?
        .enroll(
            &p::AnchorGenesis::from_trusted_state(
                subject,
                genesis.get(132..164).ok_or("genesis digest")?.try_into()?,
            )?,
            &device,
            &policy,
            fixture::now()?,
        )?;
    let mut transport = transport::Carrier::start(
        carrier,
        applied,
        &base,
        &inputs,
        &reference.responder,
        subject,
        &witness,
    )?;
    assert_eq!(
        run("managed-witness-activate", "activated.request")?,
        original
    );
    let traffic = android_roster_traffic::Case {
        base: &base,
        inputs: &inputs,
        reference: &reference,
        witness: Some(&witness.configured),
    };
    let _original_delivery =
        android_roster_traffic::Traffic::begin(&traffic, &authority, &certificate, &roster, &run)?;
    let session = fixture::array(&inputs, "connection-session")?;
    let message = p::MessageId::from_trusted_state(fixture::array(&inputs, "connection-message")?)?;
    let remote = reference
        .responder_issuer
        .as_ref()
        .ok_or("independent remote root")?;
    let peer = inputs.join("peer");
    let family = fixture::array(&inputs, "family")?;
    let previous = p::RosterCheckpoint::from_trusted_state(
        u64::from_be_bytes(fixture::array(&peer, "responder-roster-version")?),
        fixture::array(&peer, "responder-roster-digest")?,
    )?;
    let remote_certificate = fixture::read(&reference.responder, "local-certificate", 8192)?;
    let previous_wire = fixture::read(&reference.responder, "local-roster", 65536)?;
    let original_peer =
        p::AccountPin::new(remote.account_id()?, remote.public_key()?, previous, family)?
            .verify_device(&remote_certificate, &previous_wire, fixture::now()?)?;
    let now = fixture::now()?;
    let target = remote.issue_roster(
        previous.version() + 1,
        p::Validity::new(now, now + 1200)?,
        &[remote.roster_entry(&remote_certificate)?],
    )?;
    let target_peer = p::AccountPin::new(
        remote.account_id()?,
        remote.public_key()?,
        target.checkpoint(),
        family,
    )?
    .verify_device(&remote_certificate, target.as_bytes(), now)?;
    let expected_source =
        roster_metadata(remote, family, &previous_wire, previous, &original_peer)?;
    let expected_target = roster_metadata(
        remote,
        family,
        target.as_bytes(),
        target.checkpoint(),
        &target_peer,
    )?;
    for (name, bytes) in [
        ("remote-roster", target.as_bytes().to_vec()),
        (
            "remote-roster-version",
            target.checkpoint().version().to_be_bytes().to_vec(),
        ),
        (
            "remote-roster-digest",
            target.checkpoint().digest().to_vec(),
        ),
    ] {
        retain(&inputs.join(name), &bytes)?;
    }
    let expected = ExpectedEffect {
        account: remote.account_id()?,
        previous,
        target: target.checkpoint(),
        before: &expected_source,
        after: &expected_target,
        session,
        message,
    };
    let captured_before = transport.captures(&witness)?.len();
    transport.arm(&witness, applied)?;
    assert_eq!(
        run("pending-roster-unknown", "original-roster-unknown")?,
        218u32.to_be_bytes()
    );
    let original_request = Request::parse(&run("pending-request", "pending-before-expiry")?)?;
    assert_eq!(original_request.proposal.subject(), subject);
    expected.check(&original_request)?;
    retain(
        &inputs.join("pending-proposal"),
        &original_request.proposal.to_bytes(),
    )?;
    retain(&inputs.join("pending-metadata"), &original_request.metadata)?;
    transport.retain_original(&witness, applied, captured_before, &base)?;
    assert!(fixture::now()? < until, "setup missed real P0 validity");
    let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
    while fixture::now()? <= until {
        if Instant::now() >= deadline {
            return Err("actual policy expiry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = transport.captures(&witness)?.len();
    let restored = Request::parse(&run("pending-request", "pending-after-expiry")?)?;
    assert_eq!(restored.proposal, original_request.proposal);
    assert_eq!(restored.metadata, original_request.metadata);
    assert_eq!(
        run("pending-confirm-damaged", "damaged-metadata")?,
        102u32.to_be_bytes()
    );
    assert_eq!(transport.captures(&witness)?.len(), before);
    assert_eq!(
        run("pending-confirm-cancelled", "cancelled")?,
        302u32.to_be_bytes()
    );
    assert_eq!(transport.captures(&witness)?.len(), before);
    let after_cancel = Request::parse(&run("pending-request", "pending-after-cancel")?)?;
    assert_eq!(after_cancel.proposal, original_request.proposal);
    assert_eq!(after_cancel.metadata, original_request.metadata);
    if !applied {
        assert_eq!(
            run("pending-confirm-unapproved", "unapproved")?,
            103u32.to_be_bytes()
        );
    }
    // An already-applied original Advance needs no new authorization. Verify
    // that exact controller completion is read-only in this branch; fresh
    // unapplied completion still requires independent approval and mutation.
    let before_completion =
        crate::witness_tls_faults::snapshot(&witness._directory.path().join("witness.redb"))?;
    let before = transport.captures(&witness)?.len();
    let before_confirm = || match cut {
        Cut::None => Ok(()),
        Cut::Cancellation => cancellation::exercise(
            &base,
            &inputs,
            &transport,
            &witness,
            &original_request,
            &run,
        ),
        Cut::ProcessLoss => process_loss::exercise(
            &base,
            &inputs,
            &transport,
            &witness,
            &original_request,
            &run,
            &interrupted,
        ),
    };
    if applied {
        before_confirm()?;
        // Confirm existing signed history before calling any privileged recovery
        // method: no independent fresh approval is needed for an earlier commit.
        assert_eq!(run("pending-confirm", "confirmed")?, [1]);
    }
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "independent controller")?
        .complete_pending_write_recovery(
            &original_request.proposal,
            &original_request.signed,
            &original_request.metadata,
            fixture::now()?,
        )?;
    let after_completion =
        crate::witness_tls_faults::snapshot(&witness._directory.path().join("witness.redb"))?;
    assert_eq!(before_completion == after_completion, applied);
    retain(&base.join("controller-read-only"), &[u8::from(applied)])?;
    if !applied {
        before_confirm()?;
        assert_eq!(run("pending-confirm", "confirmed")?, [1]);
    }
    assert_eq!(run("pending-confirm", "retried")?, [1]);
    let captured = transport.captures(&witness)?;
    let queries = captured.get(before..).ok_or("confirmation Query records")?;
    assert_eq!(queries.len(), cut.query_count());
    let first = queries.first().ok_or("first Query")?;
    let mut challenges = std::collections::BTreeSet::new();
    let mut transcript = Vec::new();
    for (index, record) in queries.iter().enumerate() {
        assert_eq!(record.request.get(204), Some(&1));
        assert_eq!(record.reply.get(204), Some(&1));
        assert_eq!(record.delivered, cut == Cut::None || index != 0);
        assert_eq!(record.request.get(4..12), Some(&b"QPANRQ01"[..]));
        assert_eq!(record.request.get(140..172), first.request.get(140..172));
        let challenge = record.request.get(172..204).ok_or("Query challenge")?;
        assert!(challenge.iter().any(|byte| *byte != 0));
        assert!(challenges.insert(challenge.to_vec()));
        transcript.push(u8::from(record.delivered));
        transcript.extend_from_slice(&record.request);
        transcript.extend_from_slice(&record.reply);
    }
    if cut != Cut::None {
        retain(&base.join("query-confirmation-transcript"), &transcript)?;
    }
    drop(captured);
    assert_eq!(
        run("pending-request-absent", "pending-absent")?,
        201u32.to_be_bytes()
    );
    assert_eq!(
        run("pending-activate-expired", "still-expired")?,
        104u32.to_be_bytes()
    );
    assert_eq!(
        run("pending-identity", "original-identity-after")?,
        original
    );
    let effect = reference
        .responder
        .join(format!("application-{}", fixture::hex(message.as_bytes())));
    assert_eq!(
        fs::read(effect)?,
        fs::read(base.join("roster-effect-before"))?
    );
    retain(
        &base.join("expiry-observation"),
        &[until.to_be_bytes(), fixture::now()?.to_be_bytes()].concat(),
    )?;
    policy.close();
    sdk.close();
    transport.finish()?;
    witness.join()?;
    retain(
        &base.join("completed"),
        b"original-configuration;exact-roster;unknown-message-retained;query-only;no-activation\n",
    )?;
    println!("qualified original pending write {carrier}/{profile}/{outcome}: public configuration, original unknown delivery, exact R2 effect, pre-cancel retained intent, query-only retry, expired activation refused");
    if cut == Cut::Cancellation {
        println!("qualified pending Query cancellation {carrier}/{profile}/{outcome}: remote reply barrier, native cancellation with witness uncertainty, unchanged witness, retained original intent, distinct retry challenges");
    }
    if cut == Cut::ProcessLoss {
        println!("qualified pending process loss {carrier}/{profile}/{outcome}: held Query process exit, lost confirmation result, original intent and target, fresh Query retries, expired activation refused");
    }
    Ok(())
}
