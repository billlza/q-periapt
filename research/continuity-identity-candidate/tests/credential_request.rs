// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Separate-crate consumer: no internal enrollment, credential or request fields.
#![cfg(unix)]
use q_periapt_continuity_identity_candidate as p;
use q_periapt_sig::Signer;
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};
use zeroize::Zeroize;

fn runtime() -> Arc<q_periapt_sdk::Runtime> {
    let policy=b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let (mut secret, public) = q_periapt_backends::MlDsa65::generate([80; 32]);
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    let result = q_periapt_backends::MlDsa65.sign(
        &secret,
        &q_periapt_policy::policy_signature_message(policy),
        &[81; 32],
        &mut signature,
    );
    secret.zeroize();
    result.expect("real algorithm policy signature");
    Arc::new(
        q_periapt_sdk::Runtime::from_signed_policy(
            policy,
            &signature,
            &public,
            None,
            q_periapt_sdk::Limits::default(),
        )
        .expect("actual SDK runtime"),
    )
}

#[test]
fn public_original_enrollment_prepares_issuer_materials_and_repeats_real_renewal_after_expiry() {
    public_request_lifecycle(false);
}

#[test]
fn public_policy_request_uses_actual_exported_identity_after_two_real_credential_renewals() {
    public_request_lifecycle(true);
}

fn public_request_lifecycle(with_policy_renewal: bool) {
    let directory = tempfile::tempdir().expect("owned test directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private test assets");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical original directory");
    let signer_path = root.join("signer.key");
    let wrapping_path = root.join("wrap.key");
    drop(p::JournalKey::provision(&wrapping_path).expect("explicit original wrapping key"));
    let paths = p::EnrollmentPaths::new(
        &wrapping_path,
        &signer_path,
        &root.join("enrollment.redb"),
        p::InstallationPaths::new(
            &root.join("installation.redb"),
            &root.join("journal.redb"),
            &root.join("archives.redb"),
        )
        .expect("original child paths"),
    )
    .expect("original paths");
    let runtime = runtime();
    let policy_root = p::PolicySigningKey::generate().expect("independent policy authority");
    let policy_bytes = policy_root
        .issue_session_policy(
            &runtime,
            p::SessionPolicyParameters::new(
                1,
                p::Validity::new(100, 400).expect("policy interval"),
                p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])
                    .expect("permitted modes"),
                p::AnchorRequirement::local_only(),
                p::ApplicationSendBudget::new(1024).expect("bounded budget"),
            )
            .expect("policy parameters"),
        )
        .expect("actual signed protocol policy");
    let policy = p::PolicyPin::new(
        policy_root.policy_family().expect("family"),
        policy_root.public_key().expect("policy root"),
        policy_bytes.checkpoint(),
    )
    .expect("independent policy pin")
    .verify(policy_bytes.as_bytes(), Arc::clone(&runtime), 150)
    .expect("verified policy");
    let account = p::RootSigningKey::generate().expect("independent account authority");
    let intent = p::EnrollmentIntent::new(
        account.public_key().expect("account root"),
        p::DeviceDescription::new(
            [7; 16],
            1,
            policy.family(),
            p::Validity::new(100, 180).expect("original credential interval"),
        )
        .expect("approved metadata"),
    );
    let mut enrollment = p::DeviceEnrollment::provision(paths.clone(), intent.clone())
        .expect("explicit first enrollment");
    let request_bytes = enrollment
        .request(150)
        .expect("retained proof of possession");
    let verified_request = p::VerifiedEnrollmentRequest::verify(&request_bytes, &intent, 150)
        .expect("independently checked original request");
    let original_public = verified_request.public_key().clone();
    // The reference test's issuer explicitly approves this account/user action.
    // Network user authentication and issuer dedup are separate host duties.
    let original_certificate = account
        .issue_enrollment(&verified_request, 150)
        .expect("approved original credential");
    let original_roster = account
        .issue_roster(
            1,
            p::Validity::new(100, 220).expect("original roster interval"),
            &[account
                .roster_entry(&original_certificate)
                .expect("original member")],
        )
        .expect("initial account head");
    let initial_pin = p::AccountPin::new(
        account.account_id().expect("account"),
        account.public_key().expect("root"),
        original_roster.checkpoint(),
        policy.family(),
    )
    .expect("independent initial pin");
    let journal = enrollment
        .accept(
            &original_certificate,
            original_roster.as_bytes(),
            &initial_pin,
            &policy,
            150,
        )
        .expect("original acceptance");
    enrollment
        .prepare(&policy, 150)
        .expect("original installation");
    enrollment
        .activate(&policy, 150, None)
        .expect("initial controlled owner")
        .close();
    let signer_bytes = fs::read(&signer_path).expect("original controlled signer file");
    let wrapping_bytes = fs::read(&wrapping_path).expect("original wrapping file");
    let open = || {
        p::DeviceEnrollment::open(paths.clone(), intent.clone())
            .expect("original enrollment reopen")
    };
    let mut expected_certificate = original_certificate.clone();
    let mut expected_roster = original_roster.as_bytes().to_vec();
    for (now, until) in [(190, 240), (245, 320)] {
        let operation =
            p::CredentialRenewalId::generate().expect("caller-retained unique operation");
        let request = open()
            .credential_renewal_request(operation, policy.historical())
            .expect("actual acknowledged issuer materials");
        assert_eq!(request.journal(), journal);
        assert_eq!(request.original_credential(), original_certificate);
        assert_eq!(request.original_roster(), original_roster.as_bytes());
        assert_eq!(request.original_device().device_id(), [7; 16]);
        assert_eq!(request.previous_credential(), expected_certificate);
        assert_eq!(request.previous_roster(), expected_roster);
        assert_eq!(request.current_policy(), policy.checkpoint());
        assert_eq!(request.current_policy_authorization(), None);
        assert!(request.previous_validity().until() < now);
        let authorization = request.authorization();
        assert_eq!(authorization.operation, operation);
        assert_eq!(authorization.policy_digest, policy.checkpoint().digest());
        let successor = account
            .issue_credential_extension(request.previous_device(), until, now)
            .expect("same-key public extension API");
        let target = account
            .issue_roster(
                authorization.previous.version() + 1,
                p::Validity::new(100, until + 20).expect("live target roster"),
                &[account
                    .roster_entry(&successor)
                    .expect("successor membership")],
            )
            .expect("approved successor head");
        let pin = p::AccountPin::new(
            account.account_id().expect("account"),
            account.public_key().expect("root"),
            target.checkpoint(),
            policy.family(),
        )
        .expect("independent target expectation");
        let issued = account
            .issue_credential_renewal(
                request.materials(&successor, target.as_bytes()),
                &authorization,
                &pin,
                now,
            )
            .expect("independent root G authorization");
        let grant = p::VerifiedCredentialRenewal::verify(
            issued.as_bytes(),
            &pin,
            authorization.policy_digest,
            now,
        )
        .expect("actual current grant verification");
        open()
            .stage_credential_renewal(&grant, operation, &policy, now)
            .expect("original Pending");
        let mut owner = open()
            .activate(&policy, now, None)
            .expect("original controlled owner after expiry");
        let (service, signer, current) = owner.parts().expect("same original owner objects");
        assert_eq!(
            service
                .stores()
                .expect("same stores")
                .0
                .identity()
                .expect("journal ID"),
            journal
        );
        assert_eq!(signer.public_key().expect("public key"), original_public);
        signer
            .check_device(current)
            .expect("same original private signer matches renewed credential");
        assert_eq!(
            current.credential_digest(),
            grant.successor_device().credential_digest()
        );
        owner.close();
        expected_certificate = successor;
        expected_roster = target.as_bytes().to_vec();
        assert!(matches!(
            open().credential_renewal_request(operation, policy.historical()),
            Err(p::DurableError::Conflict)
        ));
        assert!(fs::read(&signer_path).expect("same signer file") == signer_bytes);
        assert!(fs::read(&wrapping_path).expect("same wrapping file") == wrapping_bytes);
    }
    if with_policy_renewal {
        let operation =
            p::PolicyRenewalId::generate().expect("independent policy request identity");
        let request = open()
            .policy_renewal_request(operation, policy.historical())
            .expect("actual independent request, no fabricated G");
        assert_eq!(request.scope().journal, journal);
        assert_eq!(request.original_credential(), original_certificate);
        assert_eq!(request.original_roster(), original_roster.as_bytes());
        assert_eq!(request.current_credential(), expected_certificate);
        assert_eq!(request.current_roster(), expected_roster);
        let scope = request.scope().clone();
        let original_checkpoint = request.original_device().roster().checkpoint();
        // Preserve public signed material independently of the SDK object. This
        // is a reference caller's retained request, not a network trust source.
        for (name, bytes) in [
            ("request-original-credential", request.original_credential()),
            ("request-original-roster", request.original_roster()),
            ("request-current-credential", request.current_credential()),
            ("request-current-roster", request.current_roster()),
        ] {
            fs::write(root.join(name), bytes).expect("retain exact public request bytes");
        }
        drop(request);
        let original_material = p::AccountPin::new(
            account.account_id().expect("trusted account"),
            account.public_key().expect("trusted root"),
            original_checkpoint,
            policy.family(),
        )
        .expect("independently retained original pin")
        .verify_historical_device(
            &fs::read(root.join("request-original-credential"))
                .expect("retained original credential"),
            &fs::read(root.join("request-original-roster")).expect("retained original roster"),
        )
        .expect("reverify expired original identity from signed bytes");
        let current_material = p::AccountPin::new(
            account.account_id().expect("trusted account"),
            account.public_key().expect("trusted root"),
            scope.current_roster,
            policy.family(),
        )
        .expect("independently retained predecessor pin")
        .verify_historical_device(
            &fs::read(root.join("request-current-credential"))
                .expect("retained current credential"),
            &fs::read(root.join("request-current-roster")).expect("retained current roster"),
        )
        .expect("reverify exact current identity from signed bytes");
        let target_wire = policy_root
            .issue_session_policy(
                &runtime,
                p::SessionPolicyParameters::new(
                    2,
                    p::Validity::new(100, 600).expect("extension"),
                    p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth]).expect("modes"),
                    p::AnchorRequirement::local_only(),
                    p::ApplicationSendBudget::new(1024).expect("budget"),
                )
                .expect("target parameters"),
            )
            .expect("independently issued policy");
        let target = p::PolicyPin::new(
            policy.family(),
            policy_root.public_key().expect("root"),
            target_wire.checkpoint(),
        )
        .expect("independent target pin")
        .verify(target_wire.as_bytes(), Arc::clone(&runtime), 270)
        .expect("verified target runtime");
        let materials = p::PolicyRenewalMaterials {
            original: policy.historical(),
            previous: policy.historical(),
            target: &target,
            original_device: &original_material,
            current_device: &current_material,
        };
        let statement = p::PolicyRenewalStatement::new(&scope, &materials, 270)
            .expect("exact current relation");
        let account_approval = account
            .approve_policy_renewal(&statement)
            .expect("account approval");
        let policy_approval = policy_root
            .approve_policy_renewal(&statement)
            .expect("independent policy approval");
        let approved = p::VerifiedPolicyRenewal::verify(
            &account_approval,
            &policy_approval,
            &scope,
            &materials,
            270,
        )
        .expect("both issuer signatures");
        open()
            .stage_policy_renewal(&approved, operation, policy.historical(), &target, 270)
            .expect("same original policy intent");
        let mut owner = open()
            .activate_policy_renewal(policy.historical(), &target, 270)
            .expect("same controlled owner after exact independent adoption");
        let (service, signer, current) = owner.parts().expect("real original owner");
        assert_eq!(
            service
                .stores()
                .expect("original stores")
                .0
                .identity()
                .expect("journal"),
            journal
        );
        assert_eq!(
            signer.public_key().expect("public signer identity"),
            original_public
        );
        assert_eq!(current.credential_digest(), scope.current_credential);
        owner.close();
        let next = open()
            .policy_renewal_request(
                p::PolicyRenewalId::generate().expect("next operation"),
                policy.historical(),
            )
            .expect("actual acknowledged independent policy predecessor");
        assert_eq!(next.scope().previous_policy, target.checkpoint());
        assert_eq!(
            next.scope().previous_authorization,
            Some(approved.statement_digest())
        );
        assert_eq!(next.current_credential(), expected_certificate);
        assert_eq!(next.current_roster(), expected_roster);
        target.close();
        eprintln!("POLICY_REQUEST_PUBLIC_CONSUMER real_prior_g=2 signed_identity_materials=true same_original_owner=true independent_two_root_adoption=true identity_bytes_reverified=true private_fields=false");
    }
    policy.close();
    runtime.close();
    let held = root.join("signer-held.key");
    fs::rename(&signer_path, &held).expect("private signer unavailable");
    let metadata = open()
        .credential_renewal_request(
            p::CredentialRenewalId::generate().expect("fresh caller operation"),
            policy.historical(),
        )
        .expect("historical preparation without signer/runtime");
    assert_eq!(metadata.previous_validity().until(), 320);
    fs::rename(held, &signer_path).expect("restore owned test signer");
    assert!(fs::read(&signer_path).expect("final original signer") == signer_bytes);
    assert!(fs::read(&wrapping_path).expect("final original wrapping key") == wrapping_bytes);
    eprintln!("CREDENTIAL_REQUEST_PUBLIC_CONSUMER renewals=2 original_journal=true same_signer=true same_wrapping=true expired_predecessors=true private_fields=false closed_runtime_metadata=true");
}
