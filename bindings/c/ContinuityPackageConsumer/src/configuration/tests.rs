use super::*;
use crate::native_fixture as fixture;
use q_periapt_host_store::{PolicyStore, StoreError};
use std::{fs, os::unix::fs::PermissionsExt};

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn configuration_historical_snapshot_does_not_authorize_credential_acceptance() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut materials = Materials::load(&reference.initiator, true)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let now = fixture::now()?;
    let issued = reference
        .policy_issuer
        .as_ref()
        .ok_or("issuer")?
        .issue_session_policy(
            sdk.runtime()?.as_ref(),
            p::SessionPolicyParameters::new(
                2,
                p::Validity::new(
                    now.checked_sub(7200).ok_or("clock")?,
                    now.checked_sub(3600).ok_or("clock")?,
                )?,
                p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                p::AnchorRequirement::local_only(),
                p::ApplicationSendBudget::new(1024)?,
            )?,
        )?;
    sdk.close();
    materials.protocol_version = issued.checkpoint().version();
    materials.protocol_digest = issued.checkpoint().digest();
    materials.protocol_policy = issued.as_bytes().to_vec();
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = root.path().canonicalize()?.join("installation");
    let path = target.to_str().ok_or("path")?.as_bytes();
    let input = materials.create()?;
    let mut error = diagnostic();
    let mut handle = 0;
    let authority = p::RootSigningKey::generate()?;
    let public = authority.public_key()?.encode();
    let validity = p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
    let approved = p::EnrollmentIntent::new(
        authority.public_key()?,
        p::DeviceDescription::new([105; 16], 1, materials.family, validity)?,
    );
    let intent = enrollment::Intent {
        root: public.as_ptr(),
        root_length: public.len(),
        device: [105; 16],
        generation: 1,
        family: materials.family,
        valid_from: validity.from(),
        valid_until: validity.until(),
    };
    let mut request = enrollment::RequestBytes {
        length: 0,
        bytes: [0; 8192],
    };
    // SAFETY: all input buffers are live and immutable; outputs are disjoint.
    unsafe {
        checked(
            qpc_configuration_v1_prepare_create(
                path.as_ptr(),
                path.len(),
                &input,
                &mut handle,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(handle, &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_begin_enrollment(handle, &intent, 1, std::ptr::null(), &mut error),
            &error,
        )?;
        checked(
            enrollment::qpc_enrollment_v1_request(handle, &mut request, &mut error),
            &error,
        )?;
    }
    let verified = p::VerifiedEnrollmentRequest::verify(
        request
            .bytes
            .get(..usize::try_from(request.length)?)
            .ok_or("request")?,
        &approved,
        fixture::now()?,
    )?;
    let certificate = authority.issue_enrollment(&verified, fixture::now()?)?;
    let roster = authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
    let pin = enrollment::Pin {
        account: authority.account_id()?,
        root: public.as_ptr(),
        root_length: public.len(),
        family: materials.family,
        checkpoint: enrollment::Checkpoint {
            version: roster.checkpoint().version(),
            digest: roster.checkpoint().digest(),
        },
    };
    let mut journal = [0; 32];
    unsafe {
        assert_eq!(
            enrollment::qpc_enrollment_v1_accept(
                handle,
                certificate.as_ptr(),
                certificate.len(),
                roster.as_bytes().as_ptr(),
                roster.as_bytes().len(),
                &pin,
                &mut journal,
                &mut error
            ),
            104
        );
        assert_eq!(
            enrollment::qpc_enrollment_v1_request(handle, &mut request, &mut error),
            2
        );
        checked(qpc_owner_v1_close(handle, &mut error), &error)?;
    }
    assert!(!target.join("installation.redb").exists() && !target.join("journal.redb").exists());
    Ok(())
}
fn diagnostic() -> ErrorRecord {
    ErrorRecord {
        code: 0,
        length: 0,
        truncated: 0,
        message: [0; 512],
    }
}
fn checked(code: i32, error: &ErrorRecord) -> TestResult<()> {
    if code == 0 {
        return Ok(());
    }
    let message = error
        .message
        .get(..usize::try_from(error.length)?)
        .ok_or("diagnostic length")?;
    Err(format!("C status {code}: {}", String::from_utf8_lossy(message)).into())
}
fn blob(bytes: &[u8]) -> Blob {
    Blob {
        data: if bytes.is_empty() {
            std::ptr::null()
        } else {
            bytes.as_ptr()
        },
        length: bytes.len(),
    }
}

#[derive(Clone)]
struct Materials {
    mode: u32,
    scope: [u8; 32],
    sdk_root: Vec<u8>,
    recovery_root: Vec<u8>,
    sdk_policy: Vec<u8>,
    sdk_signature: Vec<u8>,
    recovery_enrollment: Vec<u8>,
    family: [u8; 32],
    protocol_root: Vec<u8>,
    protocol_version: u64,
    protocol_digest: [u8; 32],
    protocol_policy: Vec<u8>,
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
}
impl Materials {
    fn load(path: &Path, recoverable: bool) -> TestResult<Self> {
        use q_periapt_sig::Signer;
        let sdk_root = fixture::read(path, "sdk-root", 1952)?;
        let (mode, scope, recovery_root, recovery_enrollment) = if recoverable {
            let (key, public) = q_periapt_backends::MlDsa65::generate([91; 32]);
            let key = Zeroizing::new(key);
            let scope = [92; 32];
            let trust = PolicyRecoveryTrust::new(scope, &sdk_root, &public)?;
            let mut proof = vec![0; 3309];
            q_periapt_backends::MlDsa65
                .sign(
                    key.as_ref(),
                    &trust.enrollment_message(),
                    &[93; 32],
                    &mut proof,
                )
                .map_err(|e| format!("test proof signing: {e:?}"))?;
            (2, scope, public.to_vec(), proof)
        } else {
            (1, [0; 32], Vec::new(), Vec::new())
        };
        Ok(Self {
            mode,
            scope,
            sdk_root,
            recovery_root,
            recovery_enrollment,
            sdk_policy: fixture::read(
                path,
                "sdk-policy",
                q_periapt_policy::MAX_SIGNED_POLICY_BYTES,
            )?,
            sdk_signature: fixture::read(path, "sdk-signature", 3309)?,
            family: fixture::array(path, "family")?,
            protocol_root: fixture::read(path, "policy-root", p::PUBLIC_KEY_BYTES)?,
            protocol_version: u64::from_be_bytes(fixture::array(path, "policy-version")?),
            protocol_digest: fixture::array(path, "policy-digest")?,
            protocol_policy: fixture::read(path, "protocol-policy", 8192)?,
            certificate: fixture::read(path, "tls-cert", 8192)?,
            key: Zeroizing::new(fixture::read(path, "tls-key", 8192)?),
        })
    }
    fn sdk(&self) -> SdkTrustInput {
        SdkTrustInput {
            mode: self.mode,
            scope: self.scope,
            initial_root: blob(&self.sdk_root),
            recovery_root: blob(&self.recovery_root),
        }
    }
    fn protocol(&self) -> ProtocolInput {
        ProtocolInput {
            family: self.family,
            root: blob(&self.protocol_root),
            version: self.protocol_version,
            digest: self.protocol_digest,
            policy: blob(&self.protocol_policy),
        }
    }
    fn create(&self) -> TestResult<CreateInput> {
        Ok(CreateInput {
            header: Header {
                struct_size: u32::try_from(std::mem::size_of::<CreateInput>())?,
                version: 1,
            },
            sdk: self.sdk(),
            sdk_policy: blob(&self.sdk_policy),
            sdk_signature: blob(&self.sdk_signature),
            recovery_enrollment: blob(&self.recovery_enrollment),
            protocol: self.protocol(),
            tls_certificate: blob(&self.certificate),
            tls_key: blob(&self.key),
        })
    }
    fn open(&self) -> TestResult<OpenInput> {
        Ok(OpenInput {
            header: Header {
                struct_size: u32::try_from(std::mem::size_of::<OpenInput>())?,
                version: 1,
            },
            sdk: self.sdk(),
            protocol: self.protocol(),
        })
    }
    fn erase_caller_copies(&mut self) {
        self.sdk_root.fill(0);
        self.recovery_root.fill(0);
        self.sdk_policy.fill(0);
        self.sdk_signature.fill(0);
        self.recovery_enrollment.fill(0);
        self.protocol_root.fill(0);
        self.protocol_policy.fill(0);
        self.certificate.fill(0);
        self.key.fill(0);
    }
}

#[test]
fn configuration_headers_reject_short_structures_before_payload_reads() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let short = 4u32;
    let mut error = diagnostic();
    let mut handle = 99;
    let path = b"/does-not-exist";
    // SAFETY: four readable bytes suffice to reject the declared short size.
    unsafe {
        assert_eq!(
            qpc_configuration_v1_prepare_create(
                path.as_ptr(),
                path.len(),
                std::ptr::from_ref(&short).cast(),
                &mut handle,
                &mut error
            ),
            1
        );
        assert_eq!(handle, 0);
        assert_eq!(
            qpc_configuration_v1_prepare_open(
                path.as_ptr(),
                path.len(),
                std::ptr::from_ref(&short).cast(),
                &mut handle,
                &mut error
            ),
            1
        );
        assert_eq!(handle, 0);
    }
    Ok(())
}

#[test]
fn configuration_cancel_before_finish_has_no_filesystem_effect() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let materials = Materials::load(&reference.initiator, true)?;
    let input = materials.create()?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = root.path().canonicalize()?.join("installation");
    let path = path.to_str().ok_or("path")?.as_bytes();
    let mut error = diagnostic();
    let mut handle = 0;
    // SAFETY: immutable live input regions and separate caller-owned outputs.
    unsafe {
        checked(
            qpc_configuration_v1_prepare_create(
                path.as_ptr(),
                path.len(),
                &input,
                &mut handle,
                &mut error,
            ),
            &error,
        )?;
        assert_eq!(fs::read_dir(root.path())?.count(), 0);
        checked(qpc_owner_v1_cancel(handle, &mut error), &error)?;
        assert_eq!(opening::qpc_owner_v1_finish_open(handle, &mut error), 302);
        assert_eq!(opening::qpc_owner_v1_finish_open(handle, &mut error), 2);
        checked(qpc_owner_v1_close(handle, &mut error), &error)?;
    }
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn configuration_owned_store_reaches_real_enrollment_activation_and_reopen() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    for recoverable in [false, true] {
        let trusted = Materials::load(&reference.initiator, recoverable)?;
        let mut caller = trusted.clone();
        let initial = caller.create()?;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = root.path().canonicalize()?.join("installation");
        let path_bytes = path.to_str().ok_or("path")?.as_bytes();
        let mut error = diagnostic();
        let mut handle = 0;
        // SAFETY: input regions stay readable during preparation, then may change.
        unsafe {
            checked(
                qpc_configuration_v1_prepare_create(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    &initial,
                    &mut handle,
                    &mut error,
                ),
                &error,
            )?;
        }
        caller.erase_caller_copies();
        assert!(!path.exists());
        unsafe {
            checked(
                opening::qpc_owner_v1_finish_open(handle, &mut error),
                &error,
            )?;
        }
        assert!(matches!(
            PolicyStore::open(
                &path.join("sdk.redb"),
                &trusted.sdk_root,
                q_periapt_sdk::Limits::default()
            ),
            Err(StoreError::Busy)
        ));
        assert!(!path.join("signer.key").exists() && !path.join("enrollment.redb").exists());
        let authority = p::RootSigningKey::generate()?;
        let public = authority.public_key()?.encode();
        let now = fixture::now()?;
        let validity =
            p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
        let native_intent = p::EnrollmentIntent::new(
            authority.public_key()?,
            p::DeviceDescription::new([94; 16], 1, trusted.family, validity)?,
        );
        let mut intent = enrollment::Intent {
            root: public.as_ptr(),
            root_length: public.len(),
            device: [94; 16],
            generation: 1,
            family: trusted.family,
            valid_from: validity.from(),
            valid_until: validity.until(),
        };
        intent.family = [95; 32];
        unsafe {
            assert_eq!(
                qpc_configuration_v1_begin_enrollment(
                    handle,
                    &intent,
                    1,
                    std::ptr::null(),
                    &mut error
                ),
                103
            );
        }
        assert!(!path.join("enrollment.redb").exists());
        intent.family = trusted.family;
        unsafe {
            checked(
                qpc_configuration_v1_begin_enrollment(
                    handle,
                    &intent,
                    1,
                    std::ptr::null(),
                    &mut error,
                ),
                &error,
            )?;
        }
        let mut request = enrollment::RequestBytes {
            length: 0,
            bytes: [0; 8192],
        };
        unsafe {
            checked(
                enrollment::qpc_enrollment_v1_request(handle, &mut request, &mut error),
                &error,
            )?;
        }
        let wire = request
            .bytes
            .get(..usize::try_from(request.length)?)
            .ok_or("request length")?
            .to_vec();
        let verified =
            p::VerifiedEnrollmentRequest::verify(&wire, &native_intent, fixture::now()?)?;
        let certificate = authority.issue_enrollment(&verified, fixture::now()?)?;
        let roster =
            authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
        let pin = enrollment::Pin {
            account: authority.account_id()?,
            root: public.as_ptr(),
            root_length: public.len(),
            family: trusted.family,
            checkpoint: enrollment::Checkpoint {
                version: roster.checkpoint().version(),
                digest: roster.checkpoint().digest(),
            },
        };
        let mut journal = [0; 32];
        unsafe {
            checked(
                enrollment::qpc_enrollment_v1_accept(
                    handle,
                    certificate.as_ptr(),
                    certificate.len(),
                    roster.as_bytes().as_ptr(),
                    roster.as_bytes().len(),
                    &pin,
                    &mut journal,
                    &mut error,
                ),
                &error,
            )?;
        }
        let mut prepared = setup::Preparation {
            protection: 0,
            journal: [0; 32],
            subject: [0; 96],
            image_digest: [0; 32],
        };
        unsafe {
            checked(
                enrollment::qpc_enrollment_v1_prepare_storage(handle, &mut prepared, &mut error),
                &error,
            )?;
            assert_eq!(prepared.protection, 1);
            assert_eq!(prepared.journal, journal);
            checked(
                enrollment::qpc_enrollment_v1_activate(handle, &mut error),
                &error,
            )?;
            checked(qpc_owner_v1_close(handle, &mut error), &error)?;
        }
        // Reopen using independent trust and protocol metadata, not stored root files.
        fs::write(path.join("sdk-root"), vec![0; 1952])?;
        fs::write(path.join("policy-root"), vec![0; p::PUBLIC_KEY_BYTES])?;
        let current = trusted.open()?;
        unsafe {
            checked(
                qpc_configuration_v1_prepare_open(
                    path_bytes.as_ptr(),
                    path_bytes.len(),
                    &current,
                    &mut handle,
                    &mut error,
                ),
                &error,
            )?;
            checked(
                opening::qpc_owner_v1_finish_open(handle, &mut error),
                &error,
            )?;
            checked(
                qpc_configuration_v1_begin_enrollment(
                    handle,
                    &intent,
                    2,
                    std::ptr::null(),
                    &mut error,
                ),
                &error,
            )?;
            checked(
                enrollment::qpc_enrollment_v1_request(handle, &mut request, &mut error),
                &error,
            )?;
            assert_eq!(
                request
                    .bytes
                    .get(..usize::try_from(request.length)?)
                    .ok_or("request")?,
                wire
            );
            checked(
                enrollment::qpc_enrollment_v1_activate(handle, &mut error),
                &error,
            )?;
            checked(qpc_owner_v1_close(handle, &mut error), &error)?;
        }
        continue_policy(
            &path,
            &trusted,
            &intent,
            &pin,
            &authority,
            reference.policy_issuer.as_ref().ok_or("policy issuer")?,
        )?;
    }
    Ok(())
}

// Exercise the original two-root transaction after transferring the exact
// configured SDK lease. Native issuers remain outside the C owner registry.
fn continue_policy(
    original_path: &Path,
    original: &Materials,
    intent: &enrollment::Intent,
    account_pin: &enrollment::Pin,
    account_root: &p::RootSigningKey,
    policy_root: &p::PolicySigningKey,
) -> TestResult<()> {
    use crate::enrollment::policy::{self, renewal};
    use std::mem::MaybeUninit;
    let runtime = q_periapt_sdk::Runtime::from_signed_policy(
        &original.sdk_policy,
        &original.sdk_signature,
        &original.sdk_root,
        None,
        q_periapt_sdk::Limits::default(),
    )?;
    let original_policy = p::PolicyPin::new(
        original.family,
        policy_root.public_key()?,
        p::PolicyCheckpoint::from_trusted_state(
            original.protocol_version,
            original.protocol_digest,
        )?,
    )?
    .verify_historical(&original.protocol_policy)?;
    let issued = policy_root.issue_session_policy(
        &runtime,
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(
                original_policy.validity().from(),
                original_policy
                    .validity()
                    .until()
                    .checked_add(3600)
                    .ok_or("clock")?,
            )?,
            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
            p::AnchorRequirement::local_only(),
            p::ApplicationSendBudget::new(1024)?,
        )?,
    )?;
    let mut target = original.clone();
    target.protocol_version = issued.checkpoint().version();
    target.protocol_digest = issued.checkpoint().digest();
    target.protocol_policy = issued.as_bytes().to_vec();
    let target_path = original_path.parent().ok_or("parent")?.join("continuation");
    let mut error = diagnostic();
    let path = original_path.to_str().ok_or("original path")?.as_bytes();
    let target_bytes = target_path.to_str().ok_or("target path")?.as_bytes();
    let current = original.open()?;
    let target_input = target.create()?;
    let mut handle = 0;
    let mut configuration = 0;
    // SAFETY: all caller-owned inputs remain immutable; outputs are disjoint.
    unsafe {
        checked(
            qpc_configuration_v1_prepare_open(
                path.as_ptr(),
                path.len(),
                &current,
                &mut handle,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(handle, &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_begin_enrollment(handle, intent, 2, std::ptr::null(), &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_prepare_create(
                target_bytes.as_ptr(),
                target_bytes.len(),
                &target_input,
                &mut configuration,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(configuration, &mut error),
            &error,
        )?;
        assert_eq!(
            qpc_configuration_v1_select_continued_policy(configuration, configuration, &mut error),
            1
        );
        let enrolled = entry(handle).map_err(|e| e.message)?;
        let guard = enrolled.owner.lock().map_err(|_| "owner mutex")?;
        assert_eq!(
            qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
            3
        );
        drop(guard);
        checked(
            qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
            &error,
        )?;
        assert_eq!(
            qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
            2
        );
        checked(qpc_owner_v1_close(configuration, &mut error), &error)?;
    }
    assert!(matches!(
        PolicyStore::open(
            &target_path.join("sdk.redb"),
            &target.sdk_root,
            q_periapt_sdk::Limits::default()
        ),
        Err(StoreError::Busy)
    ));
    let operation = p::PolicyRenewalId::generate()?;
    let mut request = MaybeUninit::<renewal::PolicyRequest>::uninit();
    let mut status = MaybeUninit::<renewal::PolicyStatus>::uninit();
    unsafe {
        checked(
            renewal::qpc_enrollment_v1_policy_renewal_status(
                handle,
                status.as_mut_ptr(),
                &mut error,
            ),
            &error,
        )?;
        assert_eq!(
            status.assume_init_ref().phase,
            0,
            "target selection must not commit policy"
        );
        checked(
            renewal::qpc_enrollment_v1_policy_renewal_request(
                handle,
                operation.as_bytes().as_ptr(),
                request.as_mut_ptr(),
                &mut error,
            ),
            &error,
        )?;
    }
    // SAFETY: the successful call initialized the complete caller-owned record.
    let request = unsafe { request.assume_init() };
    assert_eq!(request.scope.has_previous_authorization, 0);
    let cp = |x: &renewal::PolicyCheckpoint| {
        p::PolicyCheckpoint::from_trusted_state(x.version, x.digest)
    };
    let scope = p::PolicyRenewalScope {
        operation,
        journal: p::JournalIdentity::from_trusted_state(request.scope.journal)?,
        original_owner: request.scope.original_owner,
        original_credential: request.scope.original_credential,
        current_credential: request.scope.current_credential,
        current_roster: p::RosterCheckpoint::from_trusted_state(
            request.scope.current_roster.version,
            request.scope.current_roster.digest,
        )?,
        original_policy: cp(&request.scope.original_policy)?,
        previous_policy: cp(&request.scope.previous_policy)?,
        previous_authorization: None,
    };
    let account = p::AccountPin::new(
        account_root.account_id()?,
        account_root.public_key()?,
        scope.current_roster,
        original.family,
    )?;
    let record = |r: &renewal::PublicRecord| -> TestResult<Vec<u8>> {
        Ok(r.bytes
            .get(..usize::try_from(r.length)?)
            .ok_or("public record")?
            .to_vec())
    };
    let device = account.verify_device(
        &record(&request.original_credential)?,
        &record(&request.original_roster)?,
        fixture::now()?,
    )?;
    let target_pin = p::PolicyPin::new(
        target.family,
        policy_root.public_key()?,
        issued.checkpoint(),
    )?;
    let runtime = Arc::new(runtime);
    let target_policy =
        target_pin.verify(issued.as_bytes(), Arc::clone(&runtime), fixture::now()?)?;
    let material = p::PolicyRenewalMaterials {
        original: &original_policy,
        previous: &original_policy,
        target: &target_policy,
        original_device: &device,
        current_device: &device,
    };
    let statement = p::PolicyRenewalStatement::new(&scope, &material, fixture::now()?)
        .map_err(|e| format!("independent issuer policy statement: {e:?}"))?;
    let approvals = p::VerifiedPolicyRenewal::verify(
        &account_root.approve_policy_renewal(&statement)?,
        &policy_root.approve_policy_renewal(&statement)?,
        &scope,
        &material,
        fixture::now()?,
    )?;
    let previous = policy::Document {
        root: original.protocol_root.as_ptr(),
        root_length: original.protocol_root.len(),
        family: original.family,
        version: original.protocol_version,
        digest: original.protocol_digest,
        wire: original.protocol_policy.as_ptr(),
        wire_length: original.protocol_policy.len(),
    };
    unsafe {
        checked(
            renewal::qpc_enrollment_v1_stage_policy_renewal(
                handle,
                &request,
                account_pin,
                account_pin,
                approvals.as_bytes().as_ptr(),
                approvals.as_bytes().len(),
                &previous,
                status.as_mut_ptr(),
                &mut error,
            ),
            &error,
        )?;
        assert_eq!(status.assume_init_ref().phase, 1);
        checked(
            renewal::qpc_enrollment_v1_reconcile_policy_renewal(
                handle,
                status.as_mut_ptr(),
                &mut error,
            ),
            &error,
        )?;
        assert_eq!(status.assume_init_ref().phase, 2);
        assert_eq!(status.assume_init_ref().operation, *operation.as_bytes());
        assert_eq!(
            status.assume_init_ref().statement,
            approvals.statement_digest()
        );
        checked(qpc_owner_v1_close(handle, &mut error), &error)?;
    }
    // Current target reopening still uses independent trust after the sidecar
    // roots have changed. It must retain the same original operation and device.
    fs::write(target_path.join("sdk-root"), vec![0; 1952])?;
    fs::write(
        target_path.join("policy-root"),
        vec![0; p::PUBLIC_KEY_BYTES],
    )?;
    let target_open = target.open()?;
    unsafe {
        checked(
            qpc_configuration_v1_prepare_open(
                path.as_ptr(),
                path.len(),
                &current,
                &mut handle,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(handle, &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_begin_enrollment(handle, intent, 2, std::ptr::null(), &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_prepare_open(
                target_bytes.as_ptr(),
                target_bytes.len(),
                &target_open,
                &mut configuration,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(configuration, &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
            &error,
        )?;
        checked(qpc_owner_v1_close(configuration, &mut error), &error)?;
        checked(
            renewal::qpc_enrollment_v1_policy_renewal_status(
                handle,
                status.as_mut_ptr(),
                &mut error,
            ),
            &error,
        )?;
        assert_eq!(status.assume_init_ref().phase, 2);
        assert_eq!(
            status.assume_init_ref().statement,
            approvals.statement_digest()
        );
        checked(
            renewal::qpc_enrollment_v1_activate_policy_renewal(handle, &mut error),
            &error,
        )?;
        checked(qpc_owner_v1_close(handle, &mut error), &error)?;
    }
    let mut target_store = if target.mode == 2 {
        PolicyStore::open_recoverable(
            &target_path.join("sdk.redb"),
            &PolicyRecoveryTrust::new(target.scope, &target.sdk_root, &target.recovery_root)?,
            q_periapt_sdk::Limits::default(),
        )?
    } else {
        PolicyStore::open(
            &target_path.join("sdk.redb"),
            &target.sdk_root,
            q_periapt_sdk::Limits::default(),
        )?
    };
    target_store.close();
    target_policy.close();
    runtime.close();
    Ok(())
}

#[test]
fn failed_continuation_handoff_releases_both_original_leases() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let reference = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let authority = p::RootSigningKey::generate()?;
    let public = authority.public_key()?.encode();
    let now = fixture::now()?;
    for recoverable in [false, true] {
        for expired in [false, true] {
            let original = Materials::load(&reference.initiator, recoverable)?;
            let mut target = original.clone();
            if expired {
                let mut sdk = fixture::sdk(&reference.initiator)?;
                let issued = reference
                    .policy_issuer
                    .as_ref()
                    .ok_or("issuer")?
                    .issue_session_policy(
                        sdk.runtime()?.as_ref(),
                        p::SessionPolicyParameters::new(
                            2,
                            p::Validity::new(
                                now.checked_sub(7200).ok_or("clock")?,
                                now.checked_sub(3600).ok_or("clock")?,
                            )?,
                            p::AllowedPrekeyModes::new(&[p::PrekeyQuality::OneTimeBoth])?,
                            p::AnchorRequirement::local_only(),
                            p::ApplicationSendBudget::new(1024)?,
                        )?,
                    )?;
                sdk.close();
                target.protocol_version = issued.checkpoint().version();
                target.protocol_digest = issued.checkpoint().digest();
                target.protocol_policy = issued.as_bytes().to_vec();
            }
            let root = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()?;
            let parent = root.path().canonicalize()?;
            let original_path = parent.join("original");
            let target_path = parent.join("target");
            let a = original_path.to_str().ok_or("path")?.as_bytes();
            let b = target_path.to_str().ok_or("path")?.as_bytes();
            let initial = original.create()?;
            let next = target.create()?;
            let intent = enrollment::Intent {
                root: public.as_ptr(),
                root_length: public.len(),
                device: [111; 16],
                generation: 1,
                family: original.family,
                valid_from: now.saturating_sub(1),
                valid_until: now.checked_add(3600).ok_or("clock")?,
            };
            let mut error = diagnostic();
            let mut handle = 0;
            let mut configuration = 0;
            unsafe {
                checked(
                    qpc_configuration_v1_prepare_create(
                        a.as_ptr(),
                        a.len(),
                        &initial,
                        &mut handle,
                        &mut error,
                    ),
                    &error,
                )?;
                checked(
                    opening::qpc_owner_v1_finish_open(handle, &mut error),
                    &error,
                )?;
                checked(
                    qpc_configuration_v1_begin_enrollment(
                        handle,
                        &intent,
                        1,
                        std::ptr::null(),
                        &mut error,
                    ),
                    &error,
                )?;
                checked(
                    qpc_configuration_v1_prepare_create(
                        b.as_ptr(),
                        b.len(),
                        &next,
                        &mut configuration,
                        &mut error,
                    ),
                    &error,
                )?;
                checked(
                    opening::qpc_owner_v1_finish_open(configuration, &mut error),
                    &error,
                )?;
                assert_eq!(
                    qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
                    if expired { 104 } else { 103 }
                );
                assert_eq!(
                    qpc_configuration_v1_select_continued_policy(configuration, handle, &mut error),
                    2
                );
                let mut request = enrollment::RequestBytes {
                    length: 0,
                    bytes: [0; 8192],
                };
                assert_eq!(
                    enrollment::qpc_enrollment_v1_request(handle, &mut request, &mut error),
                    2
                );
            }
            // Both stores must be reopenable before closing the empty handles;
            // a failed selection cannot strand an SDK lease in either registry slot.
            for (path, material) in [(&original_path, &original), (&target_path, &target)] {
                let mut store = if recoverable {
                    PolicyStore::open_recoverable(
                        &path.join("sdk.redb"),
                        &PolicyRecoveryTrust::new(
                            material.scope,
                            &material.sdk_root,
                            &material.recovery_root,
                        )?,
                        q_periapt_sdk::Limits::default(),
                    )?
                } else {
                    PolicyStore::open(
                        &path.join("sdk.redb"),
                        &material.sdk_root,
                        q_periapt_sdk::Limits::default(),
                    )?
                };
                store.close();
                assert!(!path.join("installation.redb").exists());
            }
            unsafe {
                checked(qpc_owner_v1_close(handle, &mut error), &error)?;
                checked(qpc_owner_v1_close(configuration, &mut error), &error)?;
            }
        }
    }
    Ok(())
}

#[test]
fn configured_witness_snapshots_trust_without_files_and_checks_tls_identity() -> TestResult<()> {
    let signing = p::AnchorSigningKey::generate()?;
    let identity = p::AnchorIdentity::generate()?;
    let mut public = signing.public_key()?.encode();
    let expected = p::AnchorPin::new(identity, signing.public_key()?);
    let mut address = b"127.0.0.1:9".to_vec();
    let peer = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let local = rcgen::generate_simple_self_signed(vec!["client.test".into()])?;
    let other = rcgen::generate_simple_self_signed(vec!["other.test".into()])?;
    let mut certificate = local.cert.der().to_vec();
    let mut key = Zeroizing::new(local.signing_key.serialize_der());
    let wrong_key = Zeroizing::new(other.signing_key.serialize_der());
    let malformed_key = [0; 8];
    let mut peer_der = peer.cert.der().to_vec();
    let mut name = b"localhost".to_vec();
    let mut input = WitnessInput {
        header: Header {
            struct_size: u32::try_from(std::mem::size_of::<WitnessInput>())?,
            version: 1,
        },
        carrier: 2,
        options: witness::Options {
            address: address.as_ptr(),
            address_length: address.len(),
            timeout_ms: 1000,
        },
        identity: *identity.as_bytes(),
        public_key: blob(&public),
        tls_peer: blob(&peer_der),
        tls_certificate: blob(&certificate),
        tls_key: blob(&key),
        tls_name: blob(&name),
    };
    // SAFETY: exact header and all immutable input regions remain live for each call.
    unsafe {
        input.tls_key = blob(&wrong_key);
        assert!(
            WitnessInput::read(&input).is_err(),
            "mismatched TLS identity admitted"
        );
        input.tls_key = blob(&malformed_key);
        assert!(
            WitnessInput::read(&input).is_err(),
            "malformed private key admitted"
        );
        input.tls_key = blob(&key);
        input.carrier = 1;
        assert!(
            WitnessInput::read(&input).is_err(),
            "signed TCP accepted TLS fields"
        );
        input.carrier = 2;
    }
    let configured = unsafe { WitnessInput::read(&input) }
        .map_err(|e| e.message)?
        .ok_or("configured witness")?;
    public.fill(0);
    address.fill(0);
    certificate.fill(0);
    key.fill(0);
    peer_der.fill(0);
    name.fill(0);
    let root = tempfile::tempdir()?;
    let absent = root.path().join("no-witness-files");
    let parameters = configured
        .parameters(
            &absent,
            Cancellation::default(),
            invocation::Scope::default(),
        )
        .map_err(|e| e.message)?;
    assert_eq!(parameters.pin.binding(), expected.binding());
    assert!(!absent.exists());
    let short = 4u32;
    assert!(unsafe { WitnessInput::read(std::ptr::from_ref(&short).cast()) }.is_err());
    Ok(())
}
