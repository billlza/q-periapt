// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent account and policy approval from the public Android issuer request.
use super::*;

pub(super) struct Issued {
    pub(super) operation: p::CredentialRenewalId,
    pub(super) statement: [u8; 32],
    pub(super) roster: p::RosterCheckpoint,
    pub(super) until: u64,
}
pub(super) fn issue(case: &Case<'_>, identity: &[u8]) -> Result<Issued> {
    let operation = p::CredentialRenewalId::generate()?;
    publish_private_bytes(
        &case.inputs.join("credential-operation"),
        operation.as_bytes(),
    )?;
    let request = case.run("policy-joint-request", "joint-request")?;
    assert_eq!(
        case.run("policy-joint-request", "joint-request-replayed")?,
        request
    );
    let request =
        crate::credential_request::read_credential_request(&case.base.join("joint-request"), true)?;
    assert_eq!(request.operation, operation);
    assert_eq!(
        request.journal.as_bytes(),
        identity.get(32..).ok_or("journal")?
    );
    assert_eq!(request.account, case.root.account_id()?);
    assert_eq!(request.original_c, case.certificate);
    assert_eq!(request.previous_c, case.certificate);
    assert_eq!(request.original_r, case.roster.as_bytes());
    assert_eq!(request.previous_r, case.roster.as_bytes());
    assert_eq!(request.authorization, None);
    assert_eq!(request.current_policy, case.policy.checkpoint());
    assert_eq!(request.original_policy, case.policy.checkpoint().digest());
    assert_eq!(request.previous, case.roster.checkpoint());
    let original = crate::receiver_policy::historical(case.inputs)?;
    let original_pin = p::AccountPin::new(
        request.account,
        case.root.public_key()?,
        request.previous,
        original.family(),
    )?;
    let previous =
        original_pin.verify_historical_device(&request.previous_c, &request.previous_r)?;
    let registration = p::VerifiedEnrollmentRequest::verify(
        &fs::read(case.base.join("original.request"))?,
        case.intent,
        fixture::now()?,
    )?;
    let validity = p::Validity::new(
        request.validity.from(),
        request
            .validity
            .until()
            .checked_add(600)
            .ok_or("credential expiry")?,
    )?;
    let certificate = case.root.issue_device(
        p::DeviceDescription::new(
            previous.device_id(),
            previous.generation(),
            original.family(),
            validity,
        )?,
        registration.public_key().clone(),
    )?;
    let roster = case.root.issue_roster(
        request
            .previous
            .version()
            .checked_add(1)
            .ok_or("roster version")?,
        validity,
        &[case.root.roster_entry(&certificate)?],
    )?;
    let pin = p::AccountPin::new(
        request.account,
        case.root.public_key()?,
        roster.checkpoint(),
        original.family(),
    )?;
    let grant = case.root.issue_credential_renewal(
        p::CredentialRenewalMaterials {
            original_credential: &request.original_c,
            previous_credential: &request.previous_c,
            successor_credential: &certificate,
            previous_roster: &request.previous_r,
            successor_roster: roster.as_bytes(),
        },
        &p::CredentialRenewalAuthorization {
            operation,
            previous: request.previous,
            policy_digest: request.original_policy,
        },
        &pin,
        fixture::now()?,
    )?;
    let grant = p::VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &pin,
        request.original_policy,
        fixture::now()?,
    )?;
    let until = fixture::now()?
        .checked_add(POLICY_SECONDS)
        .ok_or("target expiry")?;
    let issuer = case
        .reference
        .policy_issuer
        .as_ref()
        .ok_or("independent policy root")?;
    let issued = issuer.issue_session_policy(
        case.sdk.runtime()?.as_ref(),
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(original.validity().from(), until)?,
            original.allowed_modes(),
            original.anchor_requirement(),
            original.application_send_budget(),
        )?,
    )?;
    flow::target_inputs(case, &issued)?;
    let target = p::PolicyPin::new(original.family(), issuer.public_key()?, issued.checkpoint())?
        .verify(issued.as_bytes(), case.sdk.runtime()?, fixture::now()?)?;
    let scope = p::PolicyContinuationScope {
        operation,
        journal: request.journal,
        original_owner: request.original_owner,
        original_credential: grant.original_credential_digest(),
        previous_credential: grant.previous_device().credential_digest(),
        previous_roster: request.previous,
        original_policy: original.checkpoint(),
        previous_policy: original.checkpoint(),
        previous_authorization: None,
    };
    let materials = p::PolicyContinuationMaterials {
        original: &original,
        previous: &original,
        target: &target,
        credential: &grant,
    };
    let statement = p::PolicyContinuationStatement::new(&scope, &materials, fixture::now()?)?;
    let approved = p::VerifiedPolicyContinuation::verify(
        &case.root.approve_policy_continuation(&statement)?,
        &issuer.approve_policy_continuation(&statement)?,
        &scope,
        &materials,
        fixture::now()?,
    )?;
    assert_ne!(approved.statement_digest(), grant.statement_digest());
    for (name, value) in [
        ("credential-renewal", grant.as_bytes().to_vec()),
        ("credential-statement", approved.statement_digest().to_vec()),
        ("joint-approvals", approved.as_bytes().to_vec()),
        (
            "joint-credential-statement",
            grant.statement_digest().to_vec(),
        ),
        (
            "renewal-version",
            roster.checkpoint().version().to_be_bytes().to_vec(),
        ),
        ("renewal-digest", roster.checkpoint().digest().to_vec()),
        ("renewed-certificate", certificate),
        ("renewed-roster", roster.as_bytes().to_vec()),
    ] {
        publish_private_bytes(&case.inputs.join(name), &value)?;
    }
    target.close();
    Ok(Issued {
        operation,
        statement: approved.statement_digest(),
        roster: roster.checkpoint(),
        until,
    })
}
