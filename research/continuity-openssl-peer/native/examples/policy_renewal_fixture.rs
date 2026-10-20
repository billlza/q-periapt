// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public interoperability material derived from an actual original installation.
//! Private issuers and the installation are retained outside the artifact tree.
use q_periapt_continuity_identity_candidate::{
    AccountPin, AllowedPrekeyModes, AnchorRequirement, ApplicationSendBudget,
    CredentialRenewalAuthorization, CredentialRenewalId, CredentialRenewalMaterials,
    DeviceDescription, DeviceEnrollment, EnrollmentIntent, EnrollmentPaths, InstallationPaths,
    InstallationPreparation, JournalKey, PolicyPin, PolicyRenewalId, PolicyRenewalRequest,
    PolicyRenewalStatement, PolicyRenewalStatus, PolicySigningKey, PrekeyQuality, RootSigningKey,
    SdkPolicySigningKey, SessionPolicyParameters, SigningKeyId, Validity,
    VerifiedCredentialRenewal, VerifiedEnrollmentRequest, VerifiedPolicyRenewal,
    VerifiedSessionPolicy,
};
use q_periapt_sdk::{Limits, Runtime};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn save(path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path.join(name))?
        .write_all(bytes)?;
    Ok(())
}

fn runtime(public: &Path, private: &Path, wrapping: &JournalKey) -> Result<Arc<Runtime>> {
    let identity = SigningKeyId::generate()?;
    save(private, "sdk-identity", identity.as_bytes())?;
    let issuer = SdkPolicySigningKey::provision(&private.join("sdk"), wrapping, identity)?;
    let document = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let signature = issuer.sign_policy(document)?;
    let root = issuer.public_key()?;
    let runtime = Arc::new(Runtime::from_signed_policy(
        document,
        &signature,
        &root,
        None,
        Limits::default(),
    )?);
    save(public, "sdk-document", document)?;
    save(public, "sdk-signature", &signature)?;
    save(public, "pin-sdk-root", &root)?;
    save(public, "pin-sdk-state", &runtime.trusted_state().encode())?;
    Ok(runtime)
}

fn policy(
    path: &Path,
    issuer: &PolicySigningKey,
    runtime: &Arc<Runtime>,
    version: u64,
    until: u64,
    now: u64,
) -> Result<VerifiedSessionPolicy> {
    issue_policy(
        path,
        issuer,
        runtime,
        SessionPolicyParameters::new(
            version,
            Validity::new(100, until)?,
            AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
            AnchorRequirement::local_only(),
            ApplicationSendBudget::new(8)?,
        )?,
        now,
    )
}

fn issue_policy(
    path: &Path,
    issuer: &PolicySigningKey,
    runtime: &Arc<Runtime>,
    parameters: SessionPolicyParameters,
    now: u64,
) -> Result<VerifiedSessionPolicy> {
    let issued = issuer.issue_session_policy(runtime, parameters)?;
    let version = issued.checkpoint().version();
    let pin = PolicyPin::new(
        issuer.policy_family()?,
        issuer.public_key()?,
        issued.checkpoint(),
    )?;
    save(path, &format!("policy-{version}"), issued.as_bytes())?;
    let mut checkpoint = version.to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&issued.checkpoint().digest());
    save(path, &format!("policy-head-{version}"), &checkpoint)?;
    Ok(pin.verify(issued.as_bytes(), Arc::clone(runtime), now)?)
}

fn incompatible_policies(
    path: &Path,
    issuer: &PolicySigningKey,
    runtime: &Arc<Runtime>,
) -> Result<()> {
    // Authentic issuer signatures are insufficient for a policy-only extension
    // if another immutable profile field changes, or validity does not extend.
    for (version, from, until, budget, modes) in [
        (4, 100, 180, 8, vec![PrekeyQuality::ReusableBoth]),
        (5, 100, 350, 9, vec![PrekeyQuality::ReusableBoth]),
        (6, 101, 350, 8, vec![PrekeyQuality::ReusableBoth]),
        (
            7,
            100,
            350,
            8,
            vec![PrekeyQuality::ReusableBoth, PrekeyQuality::OneTimeBoth],
        ),
    ] {
        issue_policy(
            path,
            issuer,
            runtime,
            SessionPolicyParameters::new(
                version,
                Validity::new(from, until)?,
                AllowedPrekeyModes::new(&modes)?,
                AnchorRequirement::local_only(),
                ApplicationSendBudget::new(budget)?,
            )?,
            150,
        )?;
    }
    Ok(())
}

fn save_request(path: &Path, request: &PolicyRenewalRequest) -> Result<()> {
    let scope = request.scope();
    for (name, bytes) in [
        ("operation", scope.operation.as_bytes().as_slice()),
        ("journal", scope.journal.as_bytes().as_slice()),
        ("owner", scope.original_owner.as_slice()),
        (
            "original-credential-digest",
            scope.original_credential.as_slice(),
        ),
        (
            "current-credential-digest",
            scope.current_credential.as_slice(),
        ),
        ("original-credential", request.original_credential()),
        ("current-credential", request.current_credential()),
        ("original-roster", request.original_roster()),
        ("current-roster", request.current_roster()),
    ] {
        save(path, name, bytes)?;
    }
    for (name, version, digest) in [
        (
            "original-roster-head",
            request.original_device().roster().checkpoint().version(),
            request.original_device().roster().checkpoint().digest(),
        ),
        (
            "current-roster-head",
            scope.current_roster.version(),
            scope.current_roster.digest(),
        ),
        (
            "original-policy-head",
            scope.original_policy.version(),
            scope.original_policy.digest(),
        ),
        (
            "previous-policy-head",
            scope.previous_policy.version(),
            scope.previous_policy.digest(),
        ),
    ] {
        let mut wire = version.to_be_bytes().to_vec();
        wire.extend_from_slice(&digest);
        save(path, name, &wire)?;
    }
    let mut predecessor = vec![u8::from(scope.previous_authorization.is_some())];
    predecessor.extend_from_slice(&scope.previous_authorization.unwrap_or([0; 32]));
    save(path, "previous-authorization", &predecessor)?;
    Ok(())
}

fn scenario(public: &Path, prior_g: bool) -> Result<()> {
    fs::create_dir(public)?;
    let private = tempfile::Builder::new()
        .prefix("qperiapt-policy-proof-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?
        .keep()
        .canonicalize()?;
    if private.starts_with(public.canonicalize()?.parent().ok_or("public parent")?) {
        return Err("private issuer inside public artifact tree".into());
    }
    save(
        public,
        "private-fixture-path",
        private.as_os_str().as_encoded_bytes(),
    )?;
    let issuer_key = JournalKey::provision(&private.join("issuer-key"))?;
    let account_id = SigningKeyId::generate()?;
    let policy_id = SigningKeyId::generate()?;
    save(&private, "account-identity", account_id.as_bytes())?;
    save(&private, "policy-identity", policy_id.as_bytes())?;
    let account = RootSigningKey::provision(&private.join("account"), &issuer_key, account_id)?;
    let issuer = PolicySigningKey::provision(&private.join("policy"), &issuer_key, policy_id)?;
    let runtime = runtime(public, &private, &issuer_key)?;
    let family = issuer.policy_family()?;
    save(public, "pin-policy-root", &issuer.public_key()?.encode())?;
    save(public, "account-root", &account.public_key()?.encode())?;
    save(public, "account", &account.account_id()?)?;
    let original_policy = policy(public, &issuer, &runtime, 1, 180, 150)?;
    let policies = [
        policy(public, &issuer, &runtime, 2, 260, 190)?,
        policy(public, &issuer, &runtime, 3, 330, 270)?,
    ];
    incompatible_policies(public, &issuer, &runtime)?;
    JournalKey::provision(&private.join("device-key"))?;
    let paths = EnrollmentPaths::new(
        &private.join("device-key"),
        &private.join("device-signer"),
        &private.join("enrollment"),
        InstallationPaths::new(
            &private.join("installation"),
            &private.join("journal"),
            &private.join("archives"),
        )?,
    )?;
    let intent = EnrollmentIntent::new(
        account.public_key()?,
        DeviceDescription::new(
            [1; 16],
            1,
            family,
            Validity::new(100, if prior_g { 160 } else { 400 })?,
        )?,
    );
    let mut owner = DeviceEnrollment::provision(paths.clone(), intent.clone())?;
    let request_wire = owner.request(150)?;
    let request = VerifiedEnrollmentRequest::verify(&request_wire, &intent, 150)?;
    let certificate = account.issue_enrollment(&request, 150)?;
    let roster = account.issue_roster(
        1,
        Validity::new(100, 450)?,
        &[account.roster_entry(&certificate)?],
    )?;
    let pin = AccountPin::new(
        account.account_id()?,
        account.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    owner.accept(&certificate, roster.as_bytes(), &pin, &original_policy, 150)?;
    if !matches!(
        owner.prepare(&original_policy, 150)?,
        InstallationPreparation::Local
    ) {
        return Err("expected local original installation".into());
    }
    owner.activate(&original_policy, 150, None)?.close();
    if prior_g {
        let original = pin.verify_historical_device(&certificate, roster.as_bytes())?;
        let extended = account.issue_credential_extension(&original, 400, 170)?;
        let next = account.issue_roster(
            2,
            Validity::new(100, 450)?,
            &[account.roster_entry(&extended)?],
        )?;
        let next_pin = AccountPin::new(
            account.account_id()?,
            account.public_key()?,
            next.checkpoint(),
            family,
        )?;
        let authorization = CredentialRenewalAuthorization {
            operation: CredentialRenewalId::generate()?,
            previous: roster.checkpoint(),
            policy_digest: original_policy.checkpoint().digest(),
        };
        let issued = account.issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: &certificate,
                previous_credential: &certificate,
                successor_credential: &extended,
                previous_roster: roster.as_bytes(),
                successor_roster: next.as_bytes(),
            },
            &authorization,
            &next_pin,
            170,
        )?;
        let grant = VerifiedCredentialRenewal::verify(
            issued.as_bytes(),
            &next_pin,
            original_policy.checkpoint().digest(),
            170,
        )?;
        save(public, "prior-credential-grant", issued.as_bytes())?;
        let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone())?;
        owner.stage_credential_renewal(&grant, grant.operation(), &original_policy, 170)?;
        owner.activate(&original_policy, 170, None)?.close();
    }
    let mut previous = &original_policy;
    let mut previous_statement = None;
    let mut original_scope = None;
    for (index, target) in policies.iter().enumerate() {
        let now = if index == 0 { 190 } else { 270 };
        let operation = PolicyRenewalId::generate()?;
        save(
            &private,
            &format!("operation-{index}"),
            operation.as_bytes(),
        )?;
        let mut owner = DeviceEnrollment::open(paths.clone(), intent.clone())?;
        let request = owner.policy_renewal_request(operation, original_policy.historical())?;
        let scope = request.scope();
        if scope.previous_policy != previous.checkpoint()
            || scope.previous_authorization != previous_statement
        {
            return Err("request did not derive actual adopted predecessor".into());
        }
        let immutable = (
            scope.journal,
            scope.original_owner,
            scope.original_credential,
        );
        if original_scope.is_some_and(|prior| prior != immutable) {
            return Err("original installation changed across policy adoption".into());
        }
        original_scope = Some(immutable);
        let path = public.join(format!("renewal-{}", index + 1));
        fs::create_dir(&path)?;
        save_request(&path, &request)?;
        let materials =
            request.materials(original_policy.historical(), previous.historical(), target);
        let statement = PolicyRenewalStatement::new(scope, &materials, now)?;
        let approve = || -> Result<VerifiedPolicyRenewal> {
            Ok(VerifiedPolicyRenewal::verify(
                &account.approve_policy_renewal(&statement)?,
                &issuer.approve_policy_renewal(&statement)?,
                scope,
                &materials,
                now,
            )?)
        };
        let approval = approve()?;
        save(&path, "approval", approval.as_bytes())?;
        save(&path, "approval-resigned", approve()?.as_bytes())?;
        save(&path, "statement", &approval.statement_digest())?;
        owner.stage_policy_renewal(
            &approval,
            operation,
            original_policy.historical(),
            target,
            now,
        )?;
        let status = owner.reconcile_policy_renewal(original_policy.historical(), target, now)?;
        if status
            != (PolicyRenewalStatus::Committed {
                operation,
                statement: approval.statement_digest(),
                target: target.checkpoint(),
            })
        {
            return Err("native original journal did not commit exact policy".into());
        }
        owner
            .activate_policy_renewal(original_policy.historical(), target, now)?
            .close();
        previous_statement = Some(approval.statement_digest());
        previous = target;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("expected new public output directory".into());
    }
    let output = Path::new(&args[1]);
    fs::create_dir(output)?;
    scenario(&output.join("unchanged-credential"), false)?;
    scenario(&output.join("after-credential-renewal"), true)
}
