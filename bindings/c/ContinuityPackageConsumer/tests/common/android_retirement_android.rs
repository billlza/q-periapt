// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The next Android installation owns its keys; the issuer handles only public material.
use crate::{fixture, p, run_foreign, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{cell::Cell, fs, os::unix::fs::DirBuilderExt, path::Path};

pub(crate) struct Scope<'a> {
    pub(crate) root: &'a p::RootSigningKey,
    pub(crate) previous: &'a p::VerifiedDevice,
    pub(crate) previous_subject: p::AnchorSubject,
    pub(crate) policy: &'a p::VerifiedSessionPolicy,
    pub(crate) validity: p::Validity,
    pub(crate) witness: &'a fixture::WitnessFixture,
}

pub(crate) struct Successor {
    pub(crate) certificate: Vec<u8>,
    pub(crate) roster: p::IssuedRoster,
    pub(crate) calls: u64,
}

pub(crate) fn replace(
    original: &Path,
    base: &Path,
    driver: &Path,
    profile: &str,
    scope: Scope<'_>,
) -> Result<Successor> {
    let Scope {
        root,
        previous,
        previous_subject,
        policy,
        validity,
        witness,
    } = scope;
    fs::DirBuilder::new().mode(0o700).create(base)?;
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
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
        "recovery-scope",
        "recovery-root",
        "recovery-enrollment",
        "enrollment-root",
        "witness-carrier",
        "witness-id",
        "witness-public",
        "witness-address",
    ] {
        let bytes = zeroize::Zeroizing::new(fs::read(original.join(name))?);
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    let generation = previous
        .generation()
        .checked_add(1)
        .ok_or("generation exhausted")?;
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new(previous.device_id(), generation, policy.family(), validity)?,
    );
    let mut wire = previous.device_id().to_vec();
    wire.extend_from_slice(&generation.to_be_bytes());
    wire.extend_from_slice(&policy.family());
    wire.extend_from_slice(&validity.from().to_be_bytes());
    wire.extend_from_slice(&validity.until().to_be_bytes());
    publish_private_bytes(&inputs.join("enrollment-intent"), &wire)?;
    publish_private_bytes(
        &inputs.join("authority-id"),
        p::AccountAuthorityIdentity::generate()?.as_bytes(),
    )?;
    publish_private_bytes(&inputs.join("authority-application"), &[142; 32])?;
    let calls = Cell::new(0u64);
    let run = |mode: &str, name: &str| -> Result<Vec<u8>> {
        let result = run_foreign(driver, profile, &inputs, base, mode, name)?;
        calls.set(
            calls
                .get()
                .checked_add(1)
                .ok_or("successor process census")?,
        );
        Ok(result)
    };
    let request = run("policy-create", "original.request")?;
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &intent, fixture::now()?)?;
    let certificate = root.issue_enrollment(&verified, fixture::now()?)?;
    let roster = root.issue_roster(
        previous
            .roster()
            .checkpoint()
            .version()
            .checked_add(1)
            .ok_or("roster exhausted")?,
        validity,
        &[root.roster_entry(&certificate)?],
    )?;
    let account = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        policy.family(),
    )?;
    let device = account.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    assert_eq!(device.device_id(), previous.device_id());
    assert_eq!(device.generation(), generation);
    assert_ne!(device.credential_digest(), previous.credential_digest());
    for (name, bytes) in [
        ("grant-certificate", certificate.clone()),
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
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    let registry = run("authority-create", "authority-created")?;
    publish_private_bytes(&inputs.join("authority-checkpoint"), &registry)?;
    let prepared = run("policy-prepare", "prepared")?;
    assert_eq!(prepared.len(), 164);
    assert_eq!(
        prepared.get(..4).ok_or("storage protection")?,
        2u32.to_be_bytes()
    );
    let journal =
        p::JournalIdentity::from_trusted_state(prepared.get(4..36).ok_or("journal")?.try_into()?)?;
    let subject = p::AnchorSubject::from_trusted_state(prepared.get(36..132).ok_or("subject")?)?;
    let genesis = p::AnchorGenesis::from_trusted_state(
        subject,
        prepared.get(132..).ok_or("genesis")?.try_into()?,
    )?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, &device, policy)?
    );
    assert_ne!(subject, previous_subject);
    let (proposal, receipt) = {
        let mut controller = witness.store.lock().map_err(|_| "replacement authority")?;
        let proofs = [(
            previous_subject,
            previous.roster().checkpoint(),
            policy.historical(),
        )];
        let proposal = controller.device_replacement_proposal(
            &genesis,
            &device,
            policy,
            &proofs,
            fixture::now()?,
        )?;
        assert_eq!(
            controller.replace_device(
                &proposal,
                &genesis,
                &device,
                policy,
                &proofs,
                fixture::now()?
            )?,
            p::AnchorDeviceReplacementState::Committed
        );
        let receipt = controller.retired_subject_receipt(&proposal, previous_subject)?;
        assert_eq!(
            controller
                .pin()?
                .verify_retired_subject(&proposal, previous_subject, &receipt)?
                .subject(),
            previous_subject
        );
        (proposal, receipt)
    };
    assert_eq!(run("policy-activate", "activated.request")?, request);
    assert_eq!(run("policy-activate", "reopened.request")?, request);
    let identity = run("policy-identity", "original.identity")?;
    assert_eq!(
        identity.get(32..).ok_or("successor journal")?,
        journal.as_bytes()
    );
    for (name, bytes) in [
        ("retirement-proposal", proposal.to_bytes()?),
        ("retirement-receipt", receipt),
        ("successor-request", request),
        ("successor-certificate", certificate.clone()),
        ("successor-roster", roster.as_bytes().to_vec()),
        ("successor-journal", journal.as_bytes().to_vec()),
        ("successor-subject", subject.to_bytes().to_vec()),
    ] {
        publish_private_bytes(&original.join(name), &bytes)?;
    }
    assert_eq!(calls.get(), 6);
    Ok(Successor {
        certificate,
        roster,
        calls: calls.get(),
    })
}
