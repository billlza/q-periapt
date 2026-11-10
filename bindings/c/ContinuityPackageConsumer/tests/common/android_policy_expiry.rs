// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real P0 expiry with live SDK and credentials; historical cleanup never grants traffic.
use crate::{
    android_credential, android_witness::witness, fixture, independent_inputs, issue_grant, p,
    run_foreign, witness_tls_faults, Result,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
const POLICY_SECONDS: u64 = 120;

#[test]
fn fixed() -> Result<()> {
    run_profile("fixed")
}
#[test]
fn recoverable() -> Result<()> {
    run_profile("recoverable")
}
fn run_profile(profile: &str) -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let driver = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("client driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for carrier in ["signed", "tls"] {
        for applied in [false, true] {
            exercise(&output, &driver, profile, carrier, applied)?;
        }
    }
    Ok(())
}
fn exchanges(
    witness: &witness::Witness,
    tls: Option<&witness_tls_faults::FaultWitness>,
) -> Result<Vec<witness::Capture>> {
    Ok(if let Some(tls) = tls {
        tls.captured
            .lock()
            .map_err(|_| "TLS capture")?
            .iter()
            .map(|r| witness::Capture {
                request: r.record.request().to_vec(),
                reply: r.record.reply().to_vec(),
                delivered: r.delivered,
            })
            .collect()
    } else {
        witness
            .captured
            .lock()
            .map_err(|_| "TCP capture")?
            .iter()
            .map(|r| witness::Capture {
                request: r.request.clone(),
                reply: r.reply.clone(),
                delivered: r.delivered,
            })
            .collect()
    })
}
struct Pending<'a> {
    base: &'a Path,
    inputs: &'a Path,
    witness: &'a witness::Witness,
    tls: Option<&'a witness_tls_faults::FaultWitness>,
    proof: &'a p::VerifiedCredentialRenewal,
    policy: &'a p::VerifiedSessionPolicy,
    proposal: Vec<u8>,
    identity: Vec<u8>,
    applied: bool,
}
impl Pending<'_> {
    fn historical(&self, run: &impl Fn(&str, &str) -> Result<Vec<u8>>) -> Result<()> {
        let until = self.policy.validity().until();
        let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
        assert!(
            fixture::now()? < until,
            "setup missed original policy validity"
        );
        while fixture::now()? < until {
            if Instant::now() >= deadline {
                return Err("real original-policy expiry deadline".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let at = fixture::now()?;
        let target = self.proof.successor_device();
        let raw = fs::read(self.inputs.join("credential-renewal"))?;
        let pin = p::AccountPin::new(
            target.account_id(),
            p::PublicKey::decode(&fs::read(self.inputs.join("enrollment-root"))?)?,
            target.roster().checkpoint(),
            fixture::array(self.inputs, "family")?,
        )?;
        // The signed grant still verifies now; only original P0 has expired.
        p::VerifiedCredentialRenewal::verify(&raw, &pin, self.policy.checkpoint().digest(), at)?;
        let credential_until =
            u64::from_be_bytes(fixture::array(self.inputs, "expiry-credential-until")?);
        let roster_until = u64::from_be_bytes(fixture::array(self.inputs, "expiry-roster-until")?);
        assert!(until <= at && at < credential_until && at < roster_until);
        let mut observation = Vec::new();
        for value in [until, at, credential_until, roster_until, 1] {
            observation.extend_from_slice(&value.to_be_bytes());
        }
        publish_private_bytes(&self.base.join("expiry-observation"), &observation)?;
        let before = exchanges(self.witness, self.tls)?.len();
        assert_eq!(
            run(
                "credential-policy-prepare-replay",
                "expiry-proposal-replayed"
            )?,
            self.proposal
        );
        assert_eq!(
            run(
                "credential-policy-activate-expired",
                "expiry-activation-before"
            )?,
            104u32.to_be_bytes()
        );
        assert_eq!(
            run("credential-policy-stage-expired", "expiry-stage-refused")?,
            104u32.to_be_bytes()
        );
        if self.applied {
            android_credential::status(
                &run("credential-policy-commit-recover", "expiry-transition")?,
                self.proof,
                2,
            )?;
        } else {
            assert_eq!(
                run("credential-policy-commit-expired", "expiry-transition")?,
                104u32.to_be_bytes()
            );
        }
        android_credential::status(
            &run("credential-policy-reconcile", "expiry-history")?,
            self.proof,
            if self.applied { 2 } else { 1 },
        )?;
        let phase = if self.applied { 2 } else { 4 };
        for (mode, label) in [
            ("credential-policy-close", "expiry-close"),
            ("credential-policy-reconcile", "expiry-terminal"),
            (
                "credential-policy-commit-terminal",
                "expiry-terminal-replayed",
            ),
        ] {
            android_credential::status(&run(mode, label)?, self.proof, phase)?;
        }
        assert_eq!(
            run(
                "credential-policy-activate-expired",
                "expiry-activation-after"
            )?,
            104u32.to_be_bytes()
        );
        assert_eq!(
            run("credential-policy-identity", "expiry-original-after")?,
            self.identity
        );
        let all = exchanges(self.witness, self.tls)?;
        let history = all.get(before..).ok_or("historical transcript")?;
        assert!(!history.is_empty());
        assert!(
            !history.iter().any(|r| r.request.get(204) == Some(&5)),
            "expired recovery dispatched a new Commit"
        );
        let closes = history
            .iter()
            .filter(|r| r.request.get(204) == Some(&7))
            .count();
        assert_eq!(closes, usize::from(!self.applied));
        android_credential::write_exchanges(
            &self.base.join("expiry-historical-transcript"),
            history,
        )?;
        Ok(())
    }
}
fn exercise(
    output: &Path,
    driver: &Path,
    profile: &str,
    carrier: &str,
    applied: bool,
) -> Result<()> {
    let outcome = if applied { "applied" } else { "closed" };
    let base = output.join(format!("{carrier}-{profile}-{outcome}"));
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    let inputs = base.join("inputs");
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    let mut witness = witness::Witness::start()?;
    let reference = fixture::setup_with_witness(Some(&witness.configured))?;
    let (root, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let pin = witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness store")?
        .pin()?;
    let at = fixture::now()?;
    let issuer = reference.policy_issuer.as_ref().ok_or("policy issuer")?;
    let short = issuer.issue_session_policy(
        sdk.runtime()?.as_ref(),
        p::SessionPolicyParameters::new(
            1,
            p::Validity::new(
                at.saturating_sub(1),
                at.checked_add(POLICY_SECONDS).ok_or("policy expiry")?,
            )?,
            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
            p::AnchorRequirement::required(&pin),
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    // Only unpublished inputs are replaced, before any Android registration exists.
    fs::write(inputs.join("policy-digest"), short.checkpoint().digest())?;
    fs::write(inputs.join("protocol-policy"), short.as_bytes())?;
    let policy = fixture::protocol_policy(&inputs, &sdk)?;
    for (name, bytes) in [
        ("witness-id", pin.identity().as_bytes().to_vec()),
        ("witness-public", pin.public_key().encode()),
        (
            "witness-address",
            witness.configured.address.to_string().into_bytes(),
        ),
        ("witness-carrier", b"signed".to_vec()),
        (
            "authority-id",
            p::AccountAuthorityIdentity::generate()?.as_bytes().to_vec(),
        ),
        ("authority-application", vec![141; 32]),
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    let run = |mode: &str, label: &str| run_foreign(driver, profile, &inputs, &base, mode, label);
    let original = run("managed-witness-create", "original.request")?;
    let (certificate, roster) = issue_grant(&inputs, &root, &intent, validity, &original)?;
    let checkpoint = run("authority-create", "authority-created")?;
    assert_eq!(checkpoint.len(), 72);
    publish_private_bytes(&inputs.join("authority-checkpoint"), &checkpoint)?;
    let genesis = run("managed-witness-prepare", "genesis")?;
    assert_eq!(genesis.len(), 164);
    assert_eq!(genesis.get(..4), Some(2u32.to_be_bytes().as_slice()));
    let subject = p::AnchorSubject::from_trusted_state(genesis.get(36..132).ok_or("subject")?)?;
    let journal =
        p::JournalIdentity::from_trusted_state(genesis.get(4..36).ok_or("journal")?.try_into()?)?;
    let genesis = p::AnchorGenesis::from_trusted_state(
        subject,
        genesis.get(132..164).ok_or("head")?.try_into()?,
    )?;
    let account = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        fixture::array(&inputs, "family")?,
    )?;
    let device = account.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(journal, &device, policy.as_ref())?
    );
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness store")?
        .enroll(&genesis, &device, &policy, fixture::now()?)?;
    let mut tls = if carrier == "tls" {
        publish_private_bytes(&inputs.join("witness-subject"), &subject.to_bytes())?;
        let server = witness_tls_faults::FaultWitness::start(
            Arc::clone(&witness.configured.store),
            [inputs.as_path()],
            witness._directory.path().join("witness.redb"),
        )?;
        fs::write(inputs.join("witness-address"), server.address.to_string())?;
        fs::write(inputs.join("witness-carrier"), b"tls")?;
        Some(server)
    } else {
        None
    };
    assert_eq!(
        run("managed-witness-activate", "activated.request")?,
        original
    );
    let identity = run("credential-policy-identity", "expiry-original")?;
    assert_eq!(identity.len(), 64);
    assert_eq!(identity.get(32..), Some(journal.as_bytes().as_slice()));
    let request = p::VerifiedEnrollmentRequest::verify(&original, &intent, fixture::now()?)?;
    let until = validity
        .until()
        .checked_add(1200)
        .ok_or("credential expiry")?;
    let successor = root.issue_device(
        p::DeviceDescription::new(
            device.device_id(),
            device.generation(),
            fixture::array(&inputs, "family")?,
            p::Validity::new(validity.from(), until)?,
        )?,
        request.public_key().clone(),
    )?;
    let next = root.issue_roster(
        2,
        p::Validity::new(validity.from(), until)?,
        &[root.roster_entry(&successor)?],
    )?;
    let target = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        next.checkpoint(),
        fixture::array(&inputs, "family")?,
    )?;
    let operation = p::CredentialRenewalId::generate()?;
    let grant = root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &certificate,
            previous_credential: &certificate,
            successor_credential: &successor,
            previous_roster: roster.as_bytes(),
            successor_roster: next.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: roster.checkpoint(),
            policy_digest: policy.checkpoint().digest(),
        },
        &target,
        fixture::now()?,
    )?;
    let proof = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &target,
        policy.checkpoint().digest(),
        fixture::now()?,
    )?;
    for (name, bytes) in [
        ("credential-renewal", grant.as_bytes().to_vec()),
        ("credential-operation", operation.as_bytes().to_vec()),
        ("credential-statement", proof.statement_digest().to_vec()),
        (
            "renewal-version",
            next.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", next.checkpoint().digest().to_vec()),
        ("expiry-credential-until", until.to_be_bytes().to_vec()),
        ("expiry-roster-until", until.to_be_bytes().to_vec()),
    ] {
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    android_credential::status(&run("credential-policy-stage", "expiry-staged")?, &proof, 1)?;
    let proposal = run("credential-policy-prepare", "expiry-proposal")?;
    let parsed = p::AnchorCredentialRenewalProposal::from_trusted_state(&proposal)?;
    assert_eq!(parsed.operation(), operation);
    assert_eq!(parsed.statement(), proof.statement_digest());
    assert!(matches!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness store")?
            .prepare_credential_renewal(parsed, &proof, &policy, fixture::now()?)?,
        p::AnchorCredentialRenewalState::Prepared
    ));
    let before = exchanges(&witness, tls.as_ref())?.len();
    if applied {
        if let Some(tls) = tls.as_ref() {
            tls.arm(None)?;
        } else {
            let mut held = witness.hold_marker.lock().map_err(|_| "hold barrier")?;
            if held
                .replace(base.join("expiry-commit-error-ready"))
                .is_some()
            {
                return Err("unconsumed hold barrier".into());
            }
            drop(held);
            witness.arm(9)?;
        }
        assert_eq!(
            run(
                "credential-policy-commit-unknown",
                "expiry-before-expiration"
            )?,
            218u32.to_be_bytes()
        );
        let capture = exchanges(&witness, tls.as_ref())?;
        let commits: Vec<_> = capture
            .get(before..)
            .ok_or("commit capture")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&5))
            .collect();
        assert_eq!(commits.len(), 1);
        let commit = commits.first().ok_or("commit")?;
        assert!(!commit.delivered);
        assert_eq!(commit.reply.get(204), Some(&8));
        publish_private_bytes(&base.join("expiry-lost-commit-request"), &commit.request)?;
        publish_private_bytes(&base.join("expiry-lost-commit-reply"), &commit.reply)?;
    } else {
        android_credential::status(
            &run("credential-policy-status", "expiry-before-expiration")?,
            &proof,
            1,
        )?;
    }
    Pending {
        base: &base,
        inputs: &inputs,
        witness: &witness,
        tls: tls.as_ref(),
        proof: &proof,
        policy: &policy,
        proposal,
        identity,
        applied,
    }
    .historical(&run)?;
    let now = fixture::now()?;
    let runtime = sdk.runtime()?;
    assert!(runtime.is_enabled()?);
    let policy_pin = p::PolicyPin::new(
        fixture::array(&inputs, "family")?,
        issuer.public_key()?,
        policy.checkpoint(),
    )?;
    assert!(matches!(
        policy_pin.verify(short.as_bytes(), runtime, now),
        Err(p::Error::Validity)
    ));
    assert_eq!(
        policy_pin.verify_historical(short.as_bytes())?.checkpoint(),
        policy.checkpoint()
    );
    publish_private_bytes(
        &base.join("expiry-sdk-binding"),
        &policy.historical().sdk_binding(),
    )?;
    policy.close();
    sdk.close();
    if let Some(tls) = tls.as_mut() {
        tls.finish()?;
    }
    witness.join()?;
    println!("qualified policy expiry {carrier}/{profile}/{outcome}: 18 foreign processes; live SDK and target, expired P0, original history, no fresh commit or activation");
    Ok(())
}
