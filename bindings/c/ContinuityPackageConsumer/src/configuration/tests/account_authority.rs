// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::account_authority as registry;
#[path = "../../../tests/common/witness.rs"]
mod support_witness;
type Result<T> = TestResult<T>;

struct Handle(u64);
impl Handle {
    fn close(&mut self) -> TestResult<()> {
        let mut error = diagnostic();
        checked(unsafe { qpc_owner_v1_close(self.0, &mut error) }, &error)?;
        self.0 = 0;
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let mut error = diagnostic();
            assert_eq!(unsafe { qpc_owner_v1_close(self.0, &mut error) }, 0);
        }
    }
}

fn begin(
    path: &Path,
    material: &Materials,
    intent: &enrollment::Intent,
    witness: &WitnessInput,
    create: bool,
) -> TestResult<Handle> {
    let wire = path.to_str().ok_or("path")?.as_bytes();
    let mut owner = Handle(0);
    let mut error = diagnostic();
    // SAFETY: owned source material and exclusive diagnostics outlive each call.
    unsafe {
        if create {
            checked(
                qpc_configuration_v1_prepare_create(
                    wire.as_ptr(),
                    wire.len(),
                    &material.create()?,
                    &mut owner.0,
                    &mut error,
                ),
                &error,
            )?;
        } else {
            checked(
                qpc_configuration_v1_prepare_open(
                    wire.as_ptr(),
                    wire.len(),
                    &material.open()?,
                    &mut owner.0,
                    &mut error,
                ),
                &error,
            )?;
        }
        checked(
            opening::qpc_owner_v1_finish_open(owner.0, &mut error),
            &error,
        )?;
        checked(
            qpc_configuration_v1_begin_enrollment(
                owner.0,
                intent,
                if create { 1 } else { 2 },
                witness,
                &mut error,
            ),
            &error,
        )?;
    }
    Ok(owner)
}
fn request(owner: &Handle) -> TestResult<Vec<u8>> {
    let mut error = diagnostic();
    let mut output = enrollment::RequestBytes {
        length: 0,
        bytes: [0; 8192],
    };
    checked(
        unsafe { enrollment::qpc_enrollment_v1_request(owner.0, &mut output, &mut error) },
        &error,
    )?;
    Ok(output
        .bytes
        .get(..usize::try_from(output.length)?)
        .ok_or("request size")?
        .to_vec())
}
fn select(owner: &Handle, selection: &registry::EnrollmentSelection) -> TestResult<()> {
    let mut error = diagnostic();
    checked(
        unsafe { registry::qpc_authority_v1_select_enrollment(owner.0, selection, &mut error) },
        &error,
    )
}

fn provision_registry(
    path: &Path,
    family: [u8; 32],
    witness: [u8; 32],
    public: &[u8],
) -> TestResult<Handle> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let options = registry::Options {
        struct_size: u32::try_from(std::mem::size_of::<registry::Options>())?,
        identity: *p::AccountAuthorityIdentity::generate()?.as_bytes(),
        family,
        witness,
        public_key: public.as_ptr(),
        public_key_length: public.len(),
    };
    let mut registry_owner = Handle(0);
    let mut error = diagnostic();
    let wire = path.to_str().ok_or("path")?.as_bytes();
    unsafe {
        checked(
            registry::qpc_authority_v1_provision_wrapping_key(
                wire.as_ptr(),
                wire.len(),
                &mut error,
            ),
            &error,
        )?;
        checked(
            registry::qpc_authority_v1_prepare_create(
                wire.as_ptr(),
                wire.len(),
                &options,
                &mut registry_owner.0,
                &mut error,
            ),
            &error,
        )?;
        checked(
            opening::qpc_owner_v1_finish_open(registry_owner.0, &mut error),
            &error,
        )?;
    }
    Ok(registry_owner)
}
fn associate(
    owner: &Handle,
    application: [u8; 32],
    pin: &enrollment::Pin,
    certificate: &[u8],
    roster: &[u8],
) -> TestResult<registry::Checkpoint> {
    let input = registry::Association {
        struct_size: u32::try_from(std::mem::size_of::<registry::Association>())?,
        application,
        pin,
        certificate: certificate.as_ptr(),
        certificate_length: certificate.len(),
        roster: roster.as_ptr(),
        roster_length: roster.len(),
    };
    let mut checkpoint = registry::Checkpoint {
        application: [0; 32],
        revision: 0,
        account: [0; 32],
    };
    let mut error = diagnostic();
    checked(
        unsafe {
            registry::qpc_authority_v1_associate(owner.0, &input, &mut checkpoint, &mut error)
        },
        &error,
    )?;
    Ok(checkpoint)
}

#[test]
fn configured_first_account_selects_registry_after_request_and_requires_it_on_reopen(
) -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let mut witness = support_witness::Witness::start()?;
    let reference = fixture::setup_with_witness(Some(&witness.configured))?;
    let material = Materials::load(&reference.initiator, true)?;
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root_path = root.path().canonicalize()?;
    let device_path = root_path.join("device");
    let registry_path = root_path.join("registry");
    let witness_public =
        fixture::read(&reference.initiator, "witness-public", p::PUBLIC_KEY_BYTES)?;
    let witness_identity = fixture::array(&reference.initiator, "witness-id")?;
    let address = witness.configured.address.to_string();
    let supplied_witness = WitnessInput {
        header: Header {
            struct_size: u32::try_from(std::mem::size_of::<WitnessInput>())?,
            version: 1,
        },
        carrier: 1,
        options: crate::witness::Options {
            address: address.as_ptr(),
            address_length: address.len(),
            timeout_ms: 3000,
        },
        identity: witness_identity,
        public_key: blob(&witness_public),
        tls_peer: blob(&[]),
        tls_certificate: blob(&[]),
        tls_key: blob(&[]),
        tls_name: blob(&[]),
    };
    let registry_owner = provision_registry(
        &registry_path,
        material.family,
        witness_identity,
        &witness_public,
    )?;
    let mut error = diagnostic();
    // This account has no device certificate or registry association yet.
    let authority = p::RootSigningKey::generate()?;
    let public = authority.public_key()?.encode();
    let now = fixture::now()?;
    let validity = p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
    let native_intent = p::EnrollmentIntent::new(
        authority.public_key()?,
        p::DeviceDescription::new([94; 16], 1, material.family, validity)?,
    );
    let intent = enrollment::Intent {
        root: public.as_ptr(),
        root_length: public.len(),
        device: [94; 16],
        generation: 1,
        family: material.family,
        valid_from: validity.from(),
        valid_until: validity.until(),
    };
    let mut device = begin(&device_path, &material, &intent, &supplied_witness, true)?;
    let original_request = request(&device)?;
    let verified =
        p::VerifiedEnrollmentRequest::verify(&original_request, &native_intent, fixture::now()?)?;
    let certificate = authority.issue_enrollment(&verified, fixture::now()?)?;
    let roster = authority.issue_roster(1, validity, &[authority.roster_entry(&certificate)?])?;
    let pin = enrollment::Pin {
        account: authority.account_id()?,
        root: public.as_ptr(),
        root_length: public.len(),
        family: material.family,
        checkpoint: enrollment::Checkpoint {
            version: roster.checkpoint().version(),
            digest: roster.checkpoint().digest(),
        },
    };
    let checkpoint = associate(
        &registry_owner,
        [242; 32],
        &pin,
        &certificate,
        roster.as_bytes(),
    )?;
    let selection = registry::EnrollmentSelection {
        struct_size: u32::try_from(std::mem::size_of::<registry::EnrollmentSelection>())?,
        registry: registry_owner.0,
        checkpoint,
    };
    #[repr(align(8))]
    struct Short(u32);
    let short = Short(4);
    unsafe {
        assert_eq!(
            registry::qpc_authority_v1_select_enrollment(
                device.0,
                std::ptr::addr_of!(short.0).cast(),
                &mut error
            ),
            1
        );
    }
    assert_eq!(request(&device)?, original_request);
    let other_public = fixture::read(&reference.initiator, "local-root", p::PUBLIC_KEY_BYTES)?;
    let other_certificate = fixture::read(&reference.initiator, "local-certificate", 8192)?;
    let other_roster = fixture::read(&reference.initiator, "local-roster", 8192)?;
    let other_pin = enrollment::Pin {
        account: fixture::array(&reference.initiator, "local-account")?,
        root: other_public.as_ptr(),
        root_length: other_public.len(),
        family: material.family,
        checkpoint: enrollment::Checkpoint {
            version: u64::from_be_bytes(fixture::array(
                &reference.initiator,
                "local-roster-version",
            )?),
            digest: fixture::array(&reference.initiator, "local-roster-digest")?,
        },
    };
    let wrong_checkpoint = associate(
        &registry_owner,
        [243; 32],
        &other_pin,
        &other_certificate,
        &other_roster,
    )?;
    let wrong = registry::EnrollmentSelection {
        checkpoint: wrong_checkpoint,
        ..selection
    };
    unsafe {
        assert_eq!(
            registry::qpc_authority_v1_select_enrollment(device.0, &wrong, &mut error),
            211
        );
    }
    assert_eq!(
        request(&device)?,
        original_request,
        "a no-I/O selection refusal retains the original owner"
    );
    select(&device, &selection)?;
    select(&device, &selection)?;
    let mut journal = [0; 32];
    unsafe {
        checked(
            enrollment::qpc_enrollment_v1_accept(
                device.0,
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
            enrollment::qpc_enrollment_v1_prepare_storage(device.0, &mut prepared, &mut error),
            &error,
        )?;
    }
    assert_eq!(prepared.protection, 2);
    assert_eq!(prepared.journal, journal);
    let subject = p::AnchorSubject::from_trusted_state(&prepared.subject)?;
    let genesis = p::AnchorGenesis::from_trusted_state(subject, prepared.image_digest)?;
    let independent_pin = p::AccountPin::new(
        authority.account_id()?,
        authority.public_key()?,
        roster.checkpoint(),
        material.family,
    )?;
    let credential =
        independent_pin.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
    let mut sdk = fixture::sdk(&reference.initiator)?;
    let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
    assert_eq!(
        subject,
        p::AnchorSubject::for_device(
            p::JournalIdentity::from_trusted_state(journal)?,
            &credential,
            policy.as_ref()
        )?
    );
    witness
        .configured
        .store
        .lock()
        .map_err(|_| "witness store")?
        .enroll(&genesis, &credential, &policy, fixture::now()?)?;
    policy.close();
    sdk.close();
    witness.arm(2)?;
    unsafe {
        assert_eq!(
            enrollment::qpc_enrollment_v1_activate(device.0, &mut error),
            218
        );
    }
    device.close()?;
    for managed in [true, false, true] {
        device = begin(&device_path, &material, &intent, &supplied_witness, false)?;
        assert_eq!(request(&device)?, original_request);
        if managed {
            select(&device, &selection)?;
        }
        unsafe {
            let code = enrollment::qpc_enrollment_v1_activate(device.0, &mut error);
            if managed {
                checked(code, &error)?;
                assert_eq!(
                    registry::qpc_authority_v1_select_enrollment(device.0, &selection, &mut error),
                    6
                );
            } else {
                assert_eq!(
                    code, 211,
                    "managed original journal cannot open without its original registry"
                );
            }
        }
        device.close()?;
    }
    assert!(!device_path.join("witness-id").exists());
    assert!(!device_path.join("witness-public").exists());
    witness.join()?;
    let captures = witness.captured.lock().map_err(|_| "captures")?;
    assert!(!captures.is_empty());
    assert!(captures
        .iter()
        .all(|entry| entry.delivered && entry.request.len() == 3674 && entry.reply.len() == 3659));
    assert!(witness
        .unprocessed
        .lock()
        .map_err(|_| "unprocessed")?
        .is_empty());
    Ok(())
}

#[path = "account_authority/root_replacement.rs"]
mod root_replacement;
