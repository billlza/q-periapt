// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configured Android recovery preserves one real unknown delivery and R2 intent.
use crate::{
    android_roster_traffic, android_witness::witness, fixture, independent_inputs, issue_grant, p,
    run_foreign, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes as retain;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{Duration, Instant},
};

const POLICY_SECONDS: u64 = 180;

struct Request {
    proposal: p::AnchorPendingWriteRecoveryProposal,
    metadata: Vec<u8>,
    signed: Vec<u8>,
}
impl Request {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1006 || bytes.len() > 436 + 8388608 + 8192 {
            return Err("complete request bound".into());
        }
        let size = |offset| -> Result<usize> {
            Ok(usize::try_from(u32::from_be_bytes(
                bytes.get(offset..offset + 4).ok_or("length")?.try_into()?,
            ))?)
        };
        let metadata = size(0)?;
        let signed = size(4)?;
        if !(569..=8388608).contains(&metadata)
            || !(1..=8192).contains(&signed)
            || bytes.len() != 436 + metadata + signed
            || bytes.get(401..404) != Some(&[0; 3])
        {
            return Err("complete request fields".into());
        }
        let proposal = p::AnchorPendingWriteRecoveryProposal::from_trusted_state(
            bytes.get(8..401).ok_or("proposal")?,
        )?;
        assert_eq!(bytes.get(404..436).ok_or("binding")?, proposal.binding());
        Ok(Self {
            proposal,
            metadata: bytes.get(436..436 + metadata).ok_or("metadata")?.to_vec(),
            signed: bytes
                .get(436 + metadata..)
                .ok_or("signed request")?
                .to_vec(),
        })
    }
}

// Independent public-format oracle for this deliberately single-member R1 -> R2
// operation. It uses only the issuer's approved signed materials and verified
// device, never the Android enrollment, signer, wrapping key or journal files.
fn roster_metadata(
    root: &p::RootSigningKey,
    family: [u8; 32],
    wire: &[u8],
    checkpoint: p::RosterCheckpoint,
    device: &p::VerifiedDevice,
) -> Result<Vec<u8>> {
    let mut roster = b"QPROWR01".to_vec();
    roster.extend_from_slice(&root.account_id()?);
    roster.extend_from_slice(&family);
    roster.extend_from_slice(&checkpoint.version().to_be_bytes());
    roster.extend_from_slice(&checkpoint.digest());
    roster.extend_from_slice(&root.public_key()?.encode());
    roster.extend_from_slice(&u32::try_from(wire.len())?.to_be_bytes());
    roster.extend_from_slice(wire);
    let mut metadata = b"QPRHST01".to_vec();
    metadata.extend_from_slice(&u32::try_from(roster.len())?.to_be_bytes());
    metadata.extend_from_slice(&roster);
    metadata.extend_from_slice(&1u16.to_be_bytes());
    metadata.extend_from_slice(&device.device_id());
    metadata.extend_from_slice(&device.generation().to_be_bytes());
    metadata.extend_from_slice(&device.credential_digest());
    Ok(metadata)
}

#[derive(Clone, Copy)]
struct ExpectedEffect<'a> {
    account: [u8; 32],
    previous: p::RosterCheckpoint,
    target: p::RosterCheckpoint,
    before: &'a [u8],
    after: &'a [u8],
    session: [u8; 32],
    message: p::MessageId,
}
impl ExpectedEffect<'_> {
    fn check(&self, request: &Request) -> Result<()> {
        let Self {
            account,
            previous,
            target,
            before,
            after,
            session,
            message,
        } = *self;
        let inspected = request.proposal.inspect_metadata(&request.metadata)?;
        let source = inspected.source();
        let destination = inspected.target();
        assert_eq!(source.local_account, destination.local_account);
        assert_eq!(source.next_fanout_ordinal, destination.next_fanout_ordinal);
        assert_eq!(source.records.len(), destination.records.len());
        let mut roster_changes = 0;
        let mut unknown = 0;
        for (a, b) in source.records.iter().zip(&destination.records) {
            let mut expected = a.clone();
            if let p::retired_device::RecordMetadata::Roster {
                account: owner,
                checkpoint,
                public_history,
            } = &mut expected.metadata
            {
                if *owner == account {
                    assert_eq!(*checkpoint, previous);
                    assert_eq!(public_history, before);
                    assert_eq!(expected.context, previous.digest());
                    expected.context = target.digest();
                    *checkpoint = target;
                    *public_history = after.to_vec();
                    roster_changes += 1;
                }
            }
            assert_eq!(
                &expected, b,
                "only the independently approved remote roster may change"
            );
            if let p::retired_device::RecordMetadata::Session(value) = &a.metadata {
                if value.session == session {
                    let p::retired_device::SessionState::Live { epochs, .. } = &value.state else {
                        return Err("original unknown message lost its retained session".into());
                    };
                    unknown += epochs
                        .iter()
                        .flat_map(|e| &e.accounting.unconfirmed)
                        .filter(|m| m.message_id() == message)
                        .count();
                }
            }
        }
        assert_eq!((roster_changes, unknown), (1, 1));
        Ok(())
    }
}

#[test]
fn signed_fixed_unapplied() -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let client = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("public client")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let base = output.join("signed-fixed-unapplied");
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
    let run = |mode: &str, label: &str| run_foreign(&client, "fixed", &inputs, &base, mode, label);
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
    witness.arm(42)?;
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
    let mut withheld = witness.unprocessed.lock().map_err(|_| "unprocessed")?;
    assert_eq!(withheld.len(), 1);
    let original_advance = withheld.remove(0);
    assert_eq!(original_advance.get(204), Some(&2));
    retain(
        &base.join("unprocessed-original-advance"),
        &original_advance,
    )?;
    drop(withheld);
    assert!(fixture::now()? < until, "setup missed real P0 validity");
    let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
    while fixture::now()? <= until {
        if Instant::now() >= deadline {
            return Err("actual policy expiry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = witness.captured.lock().map_err(|_| "capture")?.len();
    let restored = Request::parse(&run("pending-request", "pending-after-expiry")?)?;
    assert_eq!(restored.proposal, original_request.proposal);
    assert_eq!(restored.metadata, original_request.metadata);
    assert_eq!(
        run("pending-confirm-damaged", "damaged-metadata")?,
        102u32.to_be_bytes()
    );
    assert_eq!(
        witness.captured.lock().map_err(|_| "capture")?.len(),
        before
    );
    assert_eq!(
        run("pending-confirm-unapproved", "unapproved")?,
        103u32.to_be_bytes()
    );
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
    let before = witness.captured.lock().map_err(|_| "capture")?.len();
    for (mode, label) in [
        ("pending-confirm", "confirmed"),
        ("pending-confirm", "retried"),
    ] {
        assert_eq!(run(mode, label)?, [1]);
    }
    let captured = witness.captured.lock().map_err(|_| "capture")?;
    assert_eq!(captured.len() - before, 2);
    assert!(captured
        .iter()
        .skip(before)
        .all(|r| r.request.get(204) == Some(&1) && r.reply.get(204) == Some(&1) && r.delivered));
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
    witness.join()?;
    retain(
        &base.join("completed"),
        b"original-configuration;exact-roster;unknown-message-retained;query-only;no-activation\n",
    )?;
    println!("qualified original pending write signed/fixed/unapplied: public configuration, original unknown delivery, independent exact R2 approval, query-only retry, expired activation refused");
    Ok(())
}
