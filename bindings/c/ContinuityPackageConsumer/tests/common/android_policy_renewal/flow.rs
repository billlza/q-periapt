// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::time::{Duration, Instant};

fn status(
    phase: u32,
    operation: p::PolicyRenewalId,
    statement: [u8; 32],
    target: p::PolicyCheckpoint,
) -> Vec<u8> {
    let mut value = phase.to_be_bytes().to_vec();
    value.extend_from_slice(&0u32.to_be_bytes());
    value.extend_from_slice(operation.as_bytes());
    value.extend_from_slice(&statement);
    value.extend_from_slice(&target.version().to_be_bytes());
    value.extend_from_slice(&target.digest());
    value.extend_from_slice(&[0; 48]);
    value
}
pub(super) fn target_inputs(case: &Case<'_>, issued: &p::IssuedSessionPolicy) -> Result<()> {
    let path = case.inputs.join("policy-target");
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    for name in [
        "sdk-policy",
        "sdk-signature",
        "sdk-root",
        "family",
        "policy-root",
        "tls-cert",
        "tls-key",
    ] {
        let value = zeroize::Zeroizing::new(fs::read(case.inputs.join(name))?);
        publish_private_bytes(&path.join(name), &value)?;
    }
    if case.profile == "recoverable" {
        for name in ["recovery-scope", "recovery-root", "recovery-enrollment"] {
            publish_private_bytes(&path.join(name), &fs::read(case.inputs.join(name))?)?;
        }
    }
    publish_private_bytes(
        &path.join("policy-version"),
        &issued.checkpoint().version().to_be_bytes(),
    )?;
    publish_private_bytes(&path.join("policy-digest"), &issued.checkpoint().digest())?;
    publish_private_bytes(&path.join("protocol-policy"), issued.as_bytes())?;
    assert_eq!(
        case.run("policy-target-create", "policy-target-created")?,
        [1]
    );
    Ok(())
}
pub(super) fn renew(case: &Case<'_>, identity: &[u8]) -> Result<()> {
    let until = case.policy.validity().until();
    assert!(
        fixture::now()? < until,
        "original traffic and receiver renewal missed P0 validity"
    );
    let deadline = Instant::now() + Duration::from_secs(POLICY_SECONDS + 5);
    while fixture::now()? < until {
        if Instant::now() >= deadline {
            return Err("real P0 expiry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let at = fixture::now()?;
    assert_eq!(
        case.run("policy-activate-expired", "expired-activation")?,
        104u32.to_be_bytes()
    );
    assert_eq!(case.run("policy-identity", "expired-identity")?, identity);
    let operation = p::PolicyRenewalId::generate()?;
    publish_private_bytes(&case.inputs.join("renewal-operation"), operation.as_bytes())?;
    let request_bytes = case.run("policy-request", "policy-request")?;
    assert_eq!(
        case.run("policy-request", "policy-request-replayed")?,
        request_bytes
    );
    publish_private_bytes(&case.inputs.join("renewal-request"), &request_bytes)?;
    let request = crate::policy_request::read_request(&case.inputs.join("renewal-request"), true)?;
    assert_eq!(request.scope.operation, operation);
    assert_eq!(
        request.scope.journal.as_bytes(),
        identity.get(32..).ok_or("identity journal width")?
    );
    assert_eq!(request.account, case.root.account_id()?);
    assert_eq!(request.original_checkpoint, case.roster.checkpoint());
    assert_eq!(request.scope.current_roster, case.roster.checkpoint());
    assert_eq!(request.original_c, case.certificate);
    assert_eq!(request.current_c, case.certificate);
    assert_eq!(request.original_r, case.roster.as_bytes());
    assert_eq!(request.current_r, case.roster.as_bytes());
    let original = crate::receiver_policy::historical(case.inputs)?;
    assert_eq!(request.scope.original_policy, original.checkpoint());
    assert_eq!(request.scope.previous_policy, original.checkpoint());
    assert_eq!(request.scope.previous_authorization, None);
    let account = p::AccountPin::new(
        case.root.account_id()?,
        case.root.public_key()?,
        case.roster.checkpoint(),
        original.family(),
    )?;
    let device = account.verify_historical_device(case.certificate, case.roster.as_bytes())?;
    assert_eq!(
        request.scope.original_credential,
        device.credential_digest()
    );
    assert_eq!(request.scope.current_credential, device.credential_digest());
    let issuer = case
        .reference
        .policy_issuer
        .as_ref()
        .ok_or("independent policy root")?;
    let issued = issuer.issue_session_policy(
        case.sdk.runtime()?.as_ref(),
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(
                original.validity().from(),
                until.checked_add(600).ok_or("target expiry")?,
            )?,
            original.allowed_modes(),
            original.anchor_requirement(),
            original.application_send_budget(),
        )?,
    )?;
    target_inputs(case, &issued)?;
    let target = p::PolicyPin::new(original.family(), issuer.public_key()?, issued.checkpoint())?
        .verify(issued.as_bytes(), case.sdk.runtime()?, fixture::now()?)?;
    let materials = p::PolicyRenewalMaterials {
        original: &original,
        previous: &original,
        target: &target,
        original_device: &device,
        current_device: &device,
    };
    let statement = p::PolicyRenewalStatement::new(&request.scope, &materials, fixture::now()?)?;
    let approved = p::VerifiedPolicyRenewal::verify(
        &case.root.approve_policy_renewal(&statement)?,
        &issuer.approve_policy_renewal(&statement)?,
        &request.scope,
        &materials,
        fixture::now()?,
    )?;
    publish_private_bytes(&case.inputs.join("renewal-approvals"), approved.as_bytes())?;
    publish_private_bytes(&case.inputs.join("renewal-statement"), &statement.digest())?;
    for (mode, label, code) in [
        ("policy-stage-refused", "bad-approval", 102u32),
        ("policy-stage-scope", "bad-scope", 103),
        ("policy-stage-cancelled", "cancelled-stage", 302),
    ] {
        assert_eq!(case.run(mode, label)?, code.to_be_bytes());
        assert_eq!(
            case.run("policy-status", &format!("{label}-status"))?,
            [0; 160]
        );
        assert_eq!(
            case.run("policy-request", &format!("{label}-request"))?,
            request_bytes
        );
    }
    let pending = status(1, operation, statement.digest(), issued.checkpoint());
    for label in ["policy-staged", "policy-stage-replayed"] {
        assert_eq!(case.run("policy-stage", label)?, pending);
    }
    assert_eq!(
        case.run("policy-approval", "retained-approvals")?,
        approved.as_bytes()
    );
    let committed = status(2, operation, statement.digest(), issued.checkpoint());
    if let Some(witness) = case.witness {
        let proposal = case.run("policy-witness-prepare", "policy-proposal")?;
        publish_private_bytes(&case.inputs.join("renewal-proposal"), &proposal)?;
        assert_eq!(
            case.run("policy-witness-prepare", "policy-proposal-replayed")?,
            proposal
        );
        assert_eq!(
            case.run("policy-witness-recover", "policy-proposal-recovered")?,
            proposal
        );
        let parsed = p::AnchorPolicyRenewalProposal::from_trusted_state(&proposal)?;
        assert_eq!(parsed.operation(), operation);
        assert_eq!(parsed.statement(), statement.digest());
        assert_eq!(
            witness
                .configured
                .store
                .lock()
                .map_err(|_| "independent witness")?
                .prepare_policy_renewal(parsed, &approved, &materials, fixture::now()?)?,
            p::AnchorPolicyRenewalState::Prepared
        );
        let mut progress = 1u32.to_be_bytes().to_vec();
        progress.extend_from_slice(&0u32.to_be_bytes());
        progress.extend_from_slice(&proposal);
        progress.extend_from_slice(&issued.checkpoint().version().to_be_bytes());
        progress.extend_from_slice(&issued.checkpoint().digest());
        assert_eq!(case.run("policy-progress", "policy-reserved")?, progress);
        let before = case.captures()?.len();
        if let Some(tls) = case.tls {
            tls.arm(None)?;
        } else {
            witness.arm(31)?;
        }
        assert_eq!(
            case.run("policy-witness-commit-unknown", "policy-unknown")?,
            218u32.to_be_bytes()
        );
        let records = case.captures()?;
        let commits: Vec<_> = records
            .get(before..)
            .ok_or("captured commit start")?
            .iter()
            .filter(|r| r.request.get(204) == Some(&11))
            .collect();
        assert_eq!(commits.len(), 1);
        let commit = commits.first().ok_or("missing captured commit")?;
        assert!(!commit.delivered);
        publish_private_bytes(
            &case.base.join("policy-lost-commit-request"),
            &commit.request,
        )?;
        publish_private_bytes(&case.base.join("policy-lost-commit-reply"), &commit.reply)?;
        let historical = records.len();
        for (mode, label) in [
            ("policy-witness-reconcile", "policy-applied"),
            ("policy-witness-reconcile", "policy-applied-replayed"),
            ("policy-witness-close", "policy-close-applied"),
            ("policy-witness-commit-replay", "policy-commit-replayed"),
        ] {
            assert_eq!(case.run(mode, label)?, 2u32.to_be_bytes());
        }
        progress
            .get_mut(..4)
            .ok_or("progress phase width")?
            .copy_from_slice(&2u32.to_be_bytes());
        progress
            .get_mut(4..8)
            .ok_or("progress retirement width")?
            .copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(case.run("policy-progress", "policy-retired")?, progress);
        let after = case.captures()?;
        let trace = after.get(historical..).ok_or("history capture start")?;
        assert!(
            !trace.is_empty()
                && trace
                    .iter()
                    .all(|r| r.delivered && !matches!(r.request.get(204), Some(11 | 13)))
        );
        crate::android_credential::write_exchanges(
            &case.base.join("policy-historical-transcript"),
            trace,
        )?;
    } else {
        for label in ["policy-committed", "policy-commit-replayed"] {
            assert_eq!(case.run("policy-reconcile", label)?, committed);
        }
    }
    assert_eq!(case.run("policy-status", "policy-terminal")?, committed);
    assert_eq!(
        case.run("policy-resolve", "policy-resolved")?,
        if case.witness.is_some() {
            216u32.to_be_bytes().to_vec()
        } else {
            committed
        }
    );
    assert_eq!(
        case.run("policy-activate-unselected", "policy-unselected-refused")?,
        1u32.to_be_bytes()
    );
    if case.witness.is_some() {
        assert_eq!(
            case.run("policy-activate-unmanaged", "policy-unmanaged-refused")?,
            211u32.to_be_bytes()
        );
    }
    assert_eq!(
        case.run("policy-activate-renewed", "policy-renewed-identity")?,
        identity
    );
    let mut observation = until.to_be_bytes().to_vec();
    observation.extend_from_slice(&at.to_be_bytes());
    observation.extend_from_slice(&fixture::now()?.to_be_bytes());
    observation.extend_from_slice(&target.validity().until().to_be_bytes());
    assert!(at >= until && fixture::now()? < target.validity().until());
    publish_private_bytes(&case.base.join("policy-expiry-observation"), &observation)?;
    target.close();
    Ok(())
}
