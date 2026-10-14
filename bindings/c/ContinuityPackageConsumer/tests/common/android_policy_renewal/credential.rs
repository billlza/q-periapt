// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real issuer input, independent approval, G recovery and original traffic after P.
use super::*;
use crate::{android_credential, credential_request, receiver_policy};
use std::process::{Command, Stdio};

fn issue(case: &Case<'_>, identity: &[u8]) -> Result<p::VerifiedCredentialRenewal> {
    let operation = p::CredentialRenewalId::generate()?;
    publish_private_bytes(
        &case.inputs.join("credential-operation"),
        operation.as_bytes(),
    )?;
    let bytes = case.run("policy-credential-request", "credential-request")?;
    assert_eq!(
        case.run("policy-credential-request", "credential-request-replayed")?,
        bytes
    );
    if case.witness.is_some() {
        assert_eq!(
            case.run(
                "policy-credential-request-local-refused",
                "credential-request-no-downgrade"
            )?,
            216u32.to_be_bytes()
        );
    }
    let request =
        credential_request::read_credential_request(&case.base.join("credential-request"), true)?;
    let registered =
        crate::policy_request::read_request(&case.inputs.join("renewal-request"), true)?;
    let target = fixture::protocol_policy(&case.inputs.join("policy-target"), case.sdk)?;
    assert_eq!(request.operation, operation);
    assert_eq!(
        request.journal.as_bytes(),
        identity.get(32..).ok_or("original journal")?
    );
    assert_eq!(request.original_owner, registered.scope.original_owner);
    assert_eq!(request.original_policy, case.policy.checkpoint().digest());
    assert_eq!(request.current_policy, target.checkpoint());
    assert_eq!(
        request.authorization,
        Some(fixture::array(case.inputs, "renewal-statement")?)
    );
    assert_eq!(request.account, case.root.account_id()?);
    assert_eq!(request.original, case.roster.checkpoint());
    assert_eq!(request.previous, case.roster.checkpoint());
    assert_eq!(request.validity, case.validity);
    assert_eq!(request.original_c, case.certificate);
    assert_eq!(request.previous_c, case.certificate);
    assert_eq!(request.original_r, case.roster.as_bytes());
    assert_eq!(request.previous_r, case.roster.as_bytes());
    let account = p::AccountPin::new(
        request.account,
        case.root.public_key()?,
        request.original,
        target.family(),
    )?;
    let original = account.verify_historical_device(&request.original_c, &request.original_r)?;
    let registration = p::VerifiedEnrollmentRequest::verify(
        &fs::read(case.base.join("original.request"))?,
        case.intent,
        fixture::now()?,
    )?;
    assert_eq!(
        registration.identity().as_bytes(),
        identity.get(..32).ok_or("signing identity")?
    );
    let validity = p::Validity::new(
        request.validity.from(),
        request
            .validity
            .until()
            .checked_add(600)
            .ok_or("expiry overflow")?,
    )?;
    let successor = case.root.issue_device(
        p::DeviceDescription::new(
            original.device_id(),
            original.generation(),
            target.family(),
            validity,
        )?,
        registration.public_key().clone(),
    )?;
    let roster = case.root.issue_roster(
        request
            .previous
            .version()
            .checked_add(1)
            .ok_or("roster overflow")?,
        validity,
        &[case.root.roster_entry(&successor)?],
    )?;
    let pin = p::AccountPin::new(
        request.account,
        case.root.public_key()?,
        roster.checkpoint(),
        target.family(),
    )?;
    let grant = case.root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &request.original_c,
            previous_credential: &request.previous_c,
            successor_credential: &successor,
            previous_roster: &request.previous_r,
            successor_roster: roster.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation: request.operation,
            previous: request.previous,
            policy_digest: request.original_policy,
        },
        &pin,
        fixture::now()?,
    )?;
    let proof = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &pin,
        request.original_policy,
        fixture::now()?,
    )?;
    for (name, value) in [
        ("credential-renewal", grant.as_bytes().to_vec()),
        ("credential-statement", proof.statement_digest().to_vec()),
        (
            "renewal-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", roster.checkpoint().digest().to_vec()),
        ("renewed-certificate", successor),
        ("renewed-roster", roster.as_bytes().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &value)?;
    }
    target.close();
    Ok(proof)
}

pub(super) fn admit_peer(case: &Case<'_>) -> Result<()> {
    let mut command = Command::new(crate::android_credential_traffic::executable()?);
    if case.carrier != "local" {
        command
            .arg(if case.carrier == "tls" {
                "--witness-tls"
            } else {
                "--witness"
            })
            .arg(fs::read_to_string(case.inputs.join("witness-address"))?);
    }
    command
        .arg("independent-peer-admit")
        .arg(&case.reference.responder)
        .arg(case.inputs)
        .stdout(Stdio::from(fs::File::create(
            case.base.join("credential-peer-admit.stdout"),
        )?))
        .stderr(Stdio::from(fs::File::create(
            case.base.join("credential-peer-admit.stderr"),
        )?));
    let mut child = fixture::OwnedChild(command.spawn()?);
    let status = fixture::wait(&mut child)?;
    let diagnostic = fs::read_to_string(case.base.join("credential-peer-admit.stderr"))?;
    assert!(
        status.success() && diagnostic.is_empty(),
        "peer G admission {status}: {diagnostic}"
    );
    assert_eq!(
        fs::read(case.base.join("credential-peer-admit.stdout"))?,
        b"independent-peer-admitted\n"
    );
    Ok(())
}

pub(super) fn renew(case: &Case<'_>, identity: &[u8]) -> Result<()> {
    let proof = issue(case, identity)?;
    assert_eq!(
        case.run("policy-credential-status", "credential-absent")?,
        [0; 116]
    );
    assert_eq!(
        case.run("policy-credential-stage-refused", "credential-refused")?,
        102u32.to_be_bytes()
    );
    assert_eq!(
        case.run("policy-credential-status", "credential-after-refusal")?,
        [0; 116]
    );
    for label in ["credential-staged", "credential-stage-replayed"] {
        android_credential::status(&case.run("policy-credential-stage", label)?, &proof, 1)?;
    }
    if let Some(witness) = case.witness {
        let bytes = case.run("policy-credential-prepare", "credential-proposal")?;
        assert_eq!(
            bytes,
            case.run("policy-credential-prepare", "credential-proposal-replayed")?
        );
        assert_eq!(bytes.len(), 329);
        assert_eq!(bytes.get(..8), Some(b"QPCRNP03".as_slice()));
        let proposal = p::AnchorCredentialRenewalProposal::from_trusted_state(&bytes)?;
        assert_eq!(proposal.operation(), proof.operation());
        assert_eq!(proposal.statement(), proof.statement_digest());
        assert_eq!(
            proposal.policy_renewal(),
            Some(fixture::array(case.inputs, "renewal-statement")?)
        );
        assert_eq!(proposal.policy_continuation(), None);
        let original = receiver_policy::historical(case.inputs)?;
        let target = fixture::protocol_policy(&case.inputs.join("policy-target"), case.sdk)?;
        assert_eq!(
            witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness G approval")?
                .prepare_policy_renewed_credential_renewal(
                    proposal,
                    &proof,
                    &original,
                    &target,
                    fixture::now()?
                )?,
            p::AnchorCredentialRenewalState::Prepared
        );
        let before = case.captures()?.len();
        if let Some(tls) = case.tls {
            tls.arm(None)?;
        } else {
            let mut held = witness.hold_marker.lock().map_err(|_| "G commit barrier")?;
            if held
                .replace(case.base.join("credential-commit-error-ready"))
                .is_some()
            {
                return Err("unconsumed G commit barrier".into());
            }
            drop(held);
            witness.arm(9)?;
        }
        assert_eq!(
            case.run("policy-credential-commit-unknown", "credential-unknown")?,
            218u32.to_be_bytes()
        );
        let captures = case.captures()?;
        let commits: Vec<_> = captures
            .get(before..)
            .ok_or("G commit capture start")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&5))
            .collect();
        assert_eq!(commits.len(), 1);
        let commit = commits.first().ok_or("G commit")?;
        assert!(!commit.delivered);
        publish_private_bytes(
            &case.base.join("credential-lost-commit-request"),
            &commit.request,
        )?;
        publish_private_bytes(
            &case.base.join("credential-lost-commit-reply"),
            &commit.reply,
        )?;
        let start = captures.len();
        for (mode, label) in [
            ("policy-credential-reconcile", "credential-recovered"),
            ("policy-credential-commit", "credential-commit-replayed"),
            ("policy-credential-close", "credential-close-applied"),
        ] {
            android_credential::status(&case.run(mode, label)?, &proof, 2)?;
        }
        let captures = case.captures()?;
        let trace = captures.get(start..).ok_or("G historical capture")?;
        assert!(
            !trace.is_empty()
                && trace
                    .iter()
                    .all(|r| r.delivered && !matches!(r.request.get(204), Some(5 | 7)))
        );
        android_credential::write_exchanges(
            &case.base.join("credential-historical-transcript"),
            trace,
        )?;
        target.close();
    } else {
        for (activation, status) in [
            ("credential-local-activated", "credential-committed"),
            (
                "credential-local-activated-replayed",
                "credential-commit-replayed",
            ),
        ] {
            assert_eq!(case.run("policy-credential-local", activation)?, identity);
            android_credential::status(&case.run("policy-credential-status", status)?, &proof, 2)?;
        }
        android_credential::status(
            &case.run("policy-credential-status", "credential-historical")?,
            &proof,
            2,
        )?;
    }
    assert_eq!(
        case.run("policy-activate-renewed", "credential-active-identity")?,
        identity
    );
    android_credential::status(
        &case.run("policy-credential-status", "credential-terminal")?,
        &proof,
        2,
    )?;
    // The next issuer sees C1/R1 as predecessor, while original identity/P0 remain immutable.
    let next_operation = p::CredentialRenewalId::generate()?;
    publish_private_bytes(
        &case.inputs.join("credential-next-operation"),
        next_operation.as_bytes(),
    )?;
    case.run("policy-credential-next-request", "credential-next-request")?;
    let next = credential_request::read_credential_request(
        &case.base.join("credential-next-request"),
        true,
    )?;
    assert_eq!(next.operation, next_operation);
    assert_eq!(next.original_c, case.certificate);
    assert_eq!(next.original_r, case.roster.as_bytes());
    assert_eq!(
        next.previous_c,
        fs::read(case.inputs.join("renewed-certificate"))?
    );
    assert_eq!(
        next.previous_r,
        fs::read(case.inputs.join("renewed-roster"))?
    );
    assert_eq!(
        next.previous,
        proof.successor_device().roster().checkpoint()
    );
    assert_eq!(next.original_policy, case.policy.checkpoint().digest());
    assert_eq!(
        next.authorization,
        Some(fixture::array(case.inputs, "renewal-statement")?)
    );
    admit_peer(case)
}
