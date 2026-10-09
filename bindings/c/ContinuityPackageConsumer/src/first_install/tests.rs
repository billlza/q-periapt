use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

use crate::native_fixture as fixture;

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn configuration_reconciliation_never_regenerates_a_missing_wrapping_key() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let input = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    input.provision(&target)?.close();
    let retained = root.path().canonicalize()?.join("retained-wrap.key");
    fs::rename(target.join("wrap.key"), &retained)?;
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Durable(p::DurableError::PrivateFile))
    ));
    assert!(!target.join("wrap.key").exists());
    p::JournalKey::open(&retained)?;
    for (name, expected) in input.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

fn inputs(path: &Path) -> TestResult<FirstInstallConfiguration> {
    Ok(FirstInstallConfiguration::new(
        SdkConfiguration::new(
            &fixture::read(path, "sdk-policy", MAX_SIGNED_POLICY_BYTES)?,
            &fixture::read(path, "sdk-signature", 8192)?,
            &fixture::read(path, "sdk-root", 8192)?,
        )?,
        ProtocolConfiguration::new(
            fixture::array(path, "family")?,
            &fixture::read(path, "policy-root", 8192)?,
            p::PolicyCheckpoint::from_trusted_state(
                u64::from_be_bytes(fixture::array(path, "policy-version")?),
                fixture::array(path, "policy-digest")?,
            )?,
            &fixture::read(path, "protocol-policy", 8192)?,
        )?,
        TlsConfiguration::new(
            &fixture::read(path, "tls-cert", 8192)?,
            &fixture::read(path, "tls-key", 8192)?,
        )?,
    ))
}

#[test]
fn configuration_publishes_exact_inputs_and_owned_sdk_without_signing_identity() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let original = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("new-installation");
    let mut store = original.provision(&target)?;
    let floor = store.runtime()?.trusted_state();
    assert!(store.runtime()?.is_enabled()?);
    assert!(matches!(
        original.reconcile(&target),
        Err(Error::Store(StoreError::Busy))
    ));
    p::JournalKey::open(&target.join("wrap.key"))?;
    assert!(!target.join("signer.key").exists());
    assert!(!target.join("enrollment.redb").exists());
    assert_eq!(fs::read_dir(&target)?.count(), 12);
    store.close();
    let mut reopened = original.reconcile(&target)?;
    assert_eq!(reopened.runtime()?.trusted_state(), floor);
    reopened.close();
    assert!(matches!(
        original.provision(&target),
        Err(Error::Publication(_))
    ));
    for (name, expected) in original.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

#[test]
fn configuration_invalid_signature_or_tls_key_publishes_nothing() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    for case in 0..3 {
        let mut input = inputs(&reference.initiator)?;
        match case {
            0 => {
                let byte = input.sdk.signature.first_mut().ok_or("signature")?;
                *byte ^= 1;
            }
            1 => {
                let byte = input
                    .protocol
                    .policy
                    .last_mut()
                    .ok_or("protocol signature")?;
                *byte ^= 1;
            }
            _ => input.tls.key.fill(0),
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        assert!(input
            .provision(&root.path().canonicalize()?.join("installation"))
            .is_err());
        assert_eq!(fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn configuration_reconciliation_never_recreates_missing_database_or_changes_files() -> TestResult<()>
{
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let input = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    input.provision(&target)?.close();
    let state = fs::read(target.join("sdk.redb"))?;
    fs::rename(target.join("sdk.redb"), root.path().join("retained.redb"))?;
    assert!(matches!(input.reconcile(&target), Err(Error::Store(_))));
    assert!(!target.join("sdk.redb").exists());
    assert_eq!(fs::read(root.path().join("retained.redb"))?, state);
    for (name, expected) in input.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

#[test]
fn configuration_preparation_does_not_authorize_expired_or_future_policy() -> TestResult<()> {
    let now = fixture::now()?;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    for at in [
        now.checked_sub(7200).ok_or("clock")?,
        now.checked_add(7200).ok_or("clock")?,
    ] {
        let mut input = inputs(&reference.initiator)?;
        let mut sdk = fixture::sdk(&reference.initiator)?;
        let authority = reference.policy_issuer.as_ref().ok_or("policy issuer")?;
        let issued = authority.issue_session_policy(
            sdk.runtime()?.as_ref(),
            p::SessionPolicyParameters::new(
                2,
                p::Validity::new(at, at.checked_add(3600).ok_or("clock")?)?,
                p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                p::AnchorRequirement::local_only(),
                p::ApplicationSendBudget::new(1024)?,
            )?,
        )?;
        sdk.close();
        input.protocol = ProtocolConfiguration::new(
            input.protocol.family,
            &input.protocol.root,
            issued.checkpoint(),
            issued.as_bytes(),
        )?;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let target = root.path().canonicalize()?.join("installation");
        input.provision(&target)?.close();
        input.reconcile(&target)?.close();
        let directory = OwnedPrivateDirectory::open(&target)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let result = crate::owner::configured_policy(
            &target,
            &directory,
            &crate::Cancellation::default(),
            deadline,
        );
        assert!(matches!(result, Err(crate::Failure { code: 104, .. })));
        assert!(!target.join("enrollment.redb").exists());
    }
    Ok(())
}

#[test]
fn configuration_reconciliation_preserves_genuine_advanced_policy() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let input = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let mut store = input.provision(&target)?;
    let old = store.runtime()?.trusted_state();
    let (policy, signature) = reference.issuer.policy(2, false)?;
    let updated = store.replace_policy(old, &policy, &signature)?;
    let advanced = updated.trusted_state();
    assert!(!updated.is_enabled()?);
    store.close();
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Changed("SDK authority or policy differs"))
    ));
    let mut reopened =
        PolicyStore::open(&target.join("sdk.redb"), &input.sdk.root, Limits::default())?;
    assert_eq!(reopened.runtime()?.trusted_state(), advanced);
    assert!(!reopened.runtime()?.is_enabled()?);
    reopened.close();
    for (name, expected) in input.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

#[test]
fn configuration_rejects_substituted_pins_key_and_sdk_binding_before_publication() -> TestResult<()>
{
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    for case in 0..5 {
        let mut input = inputs(&reference.initiator)?;
        match case {
            0 => {
                *input.protocol.family.first_mut().ok_or("family")? ^= 1;
            }
            1 => {
                *input.protocol.digest.first_mut().ok_or("digest")? ^= 1;
            }
            2 => input.protocol.version = 2u64.to_be_bytes(),
            3 => {
                input.tls.key =
                    Zeroizing::new(fixture::read(&reference.responder, "tls-key", 8192)?)
            }
            _ => {
                let (policy, signature) = reference.issuer.policy(2, true)?;
                input.sdk = SdkConfiguration::new(&policy, &signature, &input.sdk.root)?;
            }
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let result = input.provision(&root.path().canonicalize()?.join("installation"));
        match case {
            0 | 4 => assert!(matches!(result, Err(Error::Protocol(p::Error::Scope)))),
            1 | 2 => assert!(matches!(result, Err(Error::Protocol(p::Error::Checkpoint)))),
            _ => assert!(matches!(result, Err(Error::Tls(_)))),
        }
        assert_eq!(fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn configuration_changed_file_is_not_repaired_by_reconciliation() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let input = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    input.provision(&target)?.close();
    let file = target.join("tls-cert");
    let mut changed = fs::read(&file)?;
    *changed.last_mut().ok_or("certificate")? ^= 1;
    fs::write(&file, &changed)?;
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Changed("tls-cert"))
    ));
    assert_eq!(fs::read(file)?, changed);
    Ok(())
}

#[test]
fn configuration_inputs_are_bounded_and_snapshot_caller_buffers() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let input = inputs(&reference.initiator)?;
    assert!(matches!(
        SdkConfiguration::new(
            &vec![0; MAX_SIGNED_POLICY_BYTES + 1],
            &input.sdk.signature,
            &input.sdk.root
        ),
        Err(Error::Input(_))
    ));
    assert!(matches!(
        SdkConfiguration::new(&[], &input.sdk.signature, &input.sdk.root),
        Err(Error::Input(_))
    ));
    assert!(matches!(
        TlsConfiguration::new(&input.tls.certificate, &vec![0; 8193]),
        Err(Error::Input(_))
    ));
    let mut policy = input.sdk.policy.clone();
    let mut signature = input.sdk.signature.clone();
    let mut root = input.sdk.root.clone();
    let sdk = SdkConfiguration::new(&policy, &signature, &root)?;
    policy.fill(0);
    signature.fill(0);
    root.fill(0);
    let mut certificate = input.tls.certificate.clone();
    let mut key = Zeroizing::new(input.tls.key.to_vec());
    let tls = TlsConfiguration::new(&certificate, &key)?;
    certificate.fill(0);
    key.fill(0);
    assert_eq!(sdk.policy, input.sdk.policy);
    assert_eq!(sdk.signature, input.sdk.signature);
    assert_eq!(sdk.root, input.sdk.root);
    assert_eq!(tls.certificate, input.tls.certificate);
    assert_eq!(*tls.key, *input.tls.key);
    Ok(())
}

fn bind_protocol_configuration(
    input: &mut FirstInstallConfiguration,
    authority: &p::PolicySigningKey,
    modes: &[p::PrekeyQuality],
) -> TestResult<()> {
    let runtime = Runtime::from_signed_policy(
        &input.sdk.policy,
        &input.sdk.signature,
        &input.sdk.root,
        None,
        Limits::default(),
    )?;
    let now = fixture::now()?;
    let issued = authority.issue_session_policy(
        &runtime,
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(now.saturating_sub(1), now.checked_add(3600).ok_or("clock")?)?,
            p::AllowedPrekeyModes::new(modes)?,
            p::AnchorRequirement::local_only(),
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    runtime.close();
    input.protocol = ProtocolConfiguration::new(
        input.protocol.family,
        &input.protocol.root,
        issued.checkpoint(),
        issued.as_bytes(),
    )?;
    Ok(())
}

#[test]
fn configuration_disabled_signed_profile_never_grants_bootstrap_permission() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let (policy, signature) = reference.issuer.policy(2, false)?;
    input.sdk = SdkConfiguration::new(&policy, &signature, &input.sdk.root)?;
    bind_protocol_configuration(
        &mut input,
        reference.policy_issuer.as_ref().ok_or("issuer")?,
        &[],
    )?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let mut initial = input.provision(&target)?;
    assert!(!initial.runtime()?.is_enabled()?);
    initial.close();
    let directory = OwnedPrivateDirectory::open(&target)?;
    let (mut store, policy, _) = crate::owner::configured_policy(
        &target,
        &directory,
        &crate::Cancellation::default(),
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .map_err(|e| format!("policy load failed: {}", e.code))?;
    assert!(matches!(
        policy.check_mode(p::PrekeyQuality::OneTimeBoth, fixture::now()?),
        Err(p::Error::PolicyDenied)
    ));
    assert!(!store.runtime()?.is_enabled()?);
    store.close();
    Ok(())
}

#[test]
fn configuration_full_sdk_policy_bound_survives_operational_loader() -> TestResult<()> {
    use q_periapt_sig::Signer;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let mut text = input.sdk.policy.clone();
    text.push(b'#');
    text.resize(MAX_SIGNED_POLICY_BYTES - 1, b'x');
    text.push(b'\n');
    let (key, public) = q_periapt_backends::MlDsa65::generate([42; 32]);
    let key = Zeroizing::new(key);
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    q_periapt_backends::MlDsa65
        .sign(
            key.as_ref(),
            &q_periapt_policy::policy_signature_message(&text),
            &[43; 32],
            &mut signature,
        )
        .map_err(|e| format!("test signing failed: {e:?}"))?;
    input.sdk = SdkConfiguration::new(&text, &signature, &public)?;
    bind_protocol_configuration(
        &mut input,
        reference.policy_issuer.as_ref().ok_or("issuer")?,
        &[p::PrekeyQuality::OneTimeBoth],
    )?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    input.provision(&target)?.close();
    let directory = OwnedPrivateDirectory::open(&target)?;
    let (mut store, policy, _) = crate::owner::configured_policy(
        &target,
        &directory,
        &crate::Cancellation::default(),
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .map_err(|e| format!("policy load failed: {}", e.code))?;
    policy.check_mode(p::PrekeyQuality::OneTimeBoth, fixture::now()?)?;
    assert!(store.runtime()?.is_enabled()?);
    store.close();
    input.reconcile(&target)?.close();
    Ok(())
}

fn sign_recovery_material(key: &[u8], message: &[u8], entropy: u8) -> TestResult<Vec<u8>> {
    use q_periapt_sig::Signer;
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    q_periapt_backends::MlDsa65
        .sign(key, message, &[entropy; 32], &mut signature)
        .map_err(|e| format!("test recovery signing failed: {e:?}"))?;
    Ok(signature)
}

#[test]
fn configuration_recoverable_first_use_requires_independent_trust_on_reopen() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let fixed = inputs(&reference.initiator)?;
    let (recovery_key, recovery_root) = q_periapt_backends::MlDsa65::generate([61; 32]);
    let recovery_key = Zeroizing::new(recovery_key);
    let trust = PolicyRecoveryTrust::new([62; 32], &input.sdk.root, &recovery_root)?;
    let mut proof = sign_recovery_material(recovery_key.as_ref(), &trust.enrollment_message(), 63)?;
    input.sdk =
        SdkConfiguration::new_recoverable(&input.sdk.policy, &input.sdk.signature, &trust, &proof)?;
    proof.fill(0); // The prepared configuration owns its input snapshot.
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let mut store = input.provision(&target)?;
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Store(StoreError::Busy))
    ));
    store.close();
    assert_eq!(fs::read_dir(&target)?.count(), 14);
    assert!(matches!(
        fixed.reconcile(&target),
        Err(Error::Store(StoreError::RecoveryRequired))
    ));
    let wrong_scope = PolicyRecoveryTrust::new([64; 32], &input.sdk.root, &recovery_root)?;
    assert!(matches!(
        PolicyStore::open_recoverable(&target.join("sdk.redb"), &wrong_scope, Limits::default()),
        Err(StoreError::RootMismatch)
    ));
    input.reconcile(&target)?.close();
    for (name, expected) in input.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

#[test]
fn configuration_invalid_recovery_proof_leaves_no_staging_directory() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let (key, recovery_root) = q_periapt_backends::MlDsa65::generate([65; 32]);
    let _key = Zeroizing::new(key);
    let trust = PolicyRecoveryTrust::new([66; 32], &input.sdk.root, &recovery_root)?;
    input.sdk = SdkConfiguration::new_recoverable(
        &input.sdk.policy,
        &input.sdk.signature,
        &trust,
        &vec![0; 3309],
    )?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    assert!(matches!(
        input.provision(&root.path().canonicalize()?.join("installation")),
        Err(Error::Store(StoreError::RecoveryDenied))
    ));
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn configuration_reconciliation_rejects_changed_root_with_identical_policy_floor() -> TestResult<()>
{
    use q_periapt_host_store::{PolicyRecoveryAuthorization, PolicyRecoveryOutcome};
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let (recovery_key, recovery_root) = q_periapt_backends::MlDsa65::generate([67; 32]);
    let recovery_key = Zeroizing::new(recovery_key);
    let trust = PolicyRecoveryTrust::new([68; 32], &input.sdk.root, &recovery_root)?;
    let proof = sign_recovery_material(recovery_key.as_ref(), &trust.enrollment_message(), 69)?;
    input.sdk =
        SdkConfiguration::new_recoverable(&input.sdk.policy, &input.sdk.signature, &trust, &proof)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let mut store = input.provision(&target)?;
    let original = store.runtime()?;
    let floor = original.trusted_state();
    let binding = original.policy_binding()?;
    let (incoming_key, incoming_root) = q_periapt_backends::MlDsa65::generate([70; 32]);
    let incoming_key = Zeroizing::new(incoming_key);
    let new_signature = sign_recovery_material(
        incoming_key.as_ref(),
        &q_periapt_policy::policy_signature_message(&input.sdk.policy),
        71,
    )?;
    let request = store.prepare_authority_recovery(
        [72; 32],
        &input.sdk.policy,
        &new_signature,
        &incoming_root,
    )?;
    let authorization = PolicyRecoveryAuthorization::new(
        request.clone(),
        &sign_recovery_material(recovery_key.as_ref(), &request.authorization_message(), 73)?,
        &sign_recovery_material(incoming_key.as_ref(), &request.possession_message(), 74)?,
    )?;
    assert_eq!(
        store.recover_authority(&authorization, &input.sdk.policy, &new_signature)?,
        PolicyRecoveryOutcome::Applied
    );
    assert!(matches!(
        original.is_enabled(),
        Err(q_periapt_sdk::Error::Closed)
    ));
    assert_eq!(store.runtime()?.trusted_state(), floor);
    assert_ne!(store.runtime()?.policy_binding()?, binding);
    let replacement_binding = store.runtime()?.policy_binding()?;
    store.close();
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Changed("SDK authority or policy differs"))
    ));
    let mut reopened =
        PolicyStore::open_recoverable(&target.join("sdk.redb"), &trust, Limits::default())?;
    assert_eq!(reopened.runtime()?.policy_binding()?, replacement_binding);
    assert_eq!(
        reopened.recover_authority(&authorization, &input.sdk.policy, &new_signature)?,
        PolicyRecoveryOutcome::AlreadyApplied
    );
    reopened.close();
    for (name, expected) in input.fields() {
        assert_eq!(fs::read(target.join(name))?, expected);
    }
    Ok(())
}

#[test]
fn configuration_reconciliation_requires_exact_original_enrollment_proof() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let (key, public) = q_periapt_backends::MlDsa65::generate([75; 32]);
    let key = Zeroizing::new(key);
    let trust = PolicyRecoveryTrust::new([76; 32], &input.sdk.root, &public)?;
    let original = sign_recovery_material(key.as_ref(), &trust.enrollment_message(), 77)?;
    let another = sign_recovery_material(key.as_ref(), &trust.enrollment_message(), 78)?;
    assert_ne!(original, another);
    trust.verify_enrollment(&original)?;
    trust.verify_enrollment(&another)?;
    input.sdk = SdkConfiguration::new_recoverable(
        &input.sdk.policy,
        &input.sdk.signature,
        &trust,
        &original,
    )?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    input.provision(&target)?.close();
    let mut different = inputs(&reference.initiator)?;
    different.sdk = SdkConfiguration::new_recoverable(
        &different.sdk.policy,
        &different.sdk.signature,
        &trust,
        &another,
    )?;
    assert!(matches!(
        different.reconcile(&target),
        Err(Error::Store(StoreError::RecoveryDenied))
    ));
    input.reconcile(&target)?.close();
    assert_eq!(fs::read(target.join("sdk-recovery-enrollment"))?, original);
    Ok(())
}

#[test]
fn configuration_recoverable_reconciliation_does_not_enroll_a_fixed_store() -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut input = inputs(&reference.initiator)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let mut store = input.provision(&target)?;
    let binding = store.runtime()?.policy_binding()?;
    store.close();
    let (key, public) = q_periapt_backends::MlDsa65::generate([79; 32]);
    let key = Zeroizing::new(key);
    let trust = PolicyRecoveryTrust::new([80; 32], &input.sdk.root, &public)?;
    let proof = sign_recovery_material(key.as_ref(), &trust.enrollment_message(), 81)?;
    input.sdk =
        SdkConfiguration::new_recoverable(&input.sdk.policy, &input.sdk.signature, &trust, &proof)?;
    assert!(matches!(
        input.reconcile(&target),
        Err(Error::Store(StoreError::RecoveryRequired))
    ));
    assert_eq!(fs::read_dir(&target)?.count(), 12);
    let mut reopened =
        PolicyStore::open(&target.join("sdk.redb"), &input.sdk.root, Limits::default())?;
    assert_eq!(reopened.runtime()?.policy_binding()?, binding);
    reopened.close();
    Ok(())
}

#[test]
fn configuration_reconciliation_matches_enrollment_inside_database_not_only_sidecar(
) -> TestResult<()> {
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut original = inputs(&reference.initiator)?;
    let mut other = inputs(&reference.initiator)?;
    let (key, public) = q_periapt_backends::MlDsa65::generate([82; 32]);
    let key = Zeroizing::new(key);
    let trust = PolicyRecoveryTrust::new([83; 32], &original.sdk.root, &public)?;
    let first_proof = sign_recovery_material(key.as_ref(), &trust.enrollment_message(), 84)?;
    let second_proof = sign_recovery_material(key.as_ref(), &trust.enrollment_message(), 85)?;
    assert_ne!(first_proof, second_proof);
    original.sdk = SdkConfiguration::new_recoverable(
        &original.sdk.policy,
        &original.sdk.signature,
        &trust,
        &first_proof,
    )?;
    other.sdk = SdkConfiguration::new_recoverable(
        &other.sdk.policy,
        &other.sdk.signature,
        &trust,
        &second_proof,
    )?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let second = root.path().canonicalize()?.join("other-installation");
    original.provision(&target)?.close();
    other.provision(&second)?.close();
    fs::rename(
        target.join("sdk.redb"),
        root.path().join("retained-original.redb"),
    )?;
    fs::rename(second.join("sdk.redb"), target.join("sdk.redb"))?;
    // Policy, root and public sidecar are original, but the authenticated database
    // carries another valid enrollment proof. No original-result claim is valid.
    assert!(matches!(
        original.reconcile(&target),
        Err(Error::Store(StoreError::RecoveryDenied))
    ));
    assert_eq!(
        fs::read(target.join("sdk-recovery-enrollment"))?,
        first_proof
    );
    assert!(root.path().join("retained-original.redb").is_file());
    PolicyStore::open_recoverable(&target.join("sdk.redb"), &trust, Limits::default())?.close();
    Ok(())
}
