// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh signed accounts and real witness socket; enrollment goes through C entries.
use super::*;

pub(super) struct Device {
    pub(super) handle: Handle,
    pub(super) path: std::path::PathBuf,
    pub(super) root: p::RootSigningKey,
    public: Vec<u8>,
    validity: p::Validity,
    family: [u8; 32],
    pub(super) genesis: p::AnchorGenesis,
    pub(super) credential: p::VerifiedDevice,
}
impl Device {
    pub(super) fn intent(&self) -> enrollment::Intent {
        enrollment::Intent {
            root: self.public.as_ptr(),
            root_length: self.public.len(),
            device: [94; 16],
            generation: 1,
            family: self.family,
            valid_from: self.validity.from(),
            valid_until: self.validity.until(),
        }
    }
}
pub(super) struct Case {
    pub(super) witness: support_witness::Witness,
    pub(super) material: Materials,
    pub(super) reference: fixture::Setup,
    pub(super) _directory: tempfile::TempDir,
    pub(super) old: Device,
    pub(super) target: Device,
    pub(super) registry: Handle,
    pub(super) checkpoint: registry::Checkpoint,
    pub(super) plan: p::AnchorAccountReplacementPlan,
    pub(super) registry_path: std::path::PathBuf,
    identity: [u8; 32],
    pub(super) witness_public: Vec<u8>,
    pub(super) witness_id: [u8; 32],
}
impl Case {
    pub(super) fn new() -> TestResult<Self> {
        let witness = support_witness::Witness::start()?;
        let reference = fixture::setup_with_witness(Some(&witness.configured))?;
        let material = Materials::load(&reference.initiator, true)?;
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?;
        let registry_path = path.join("registry");
        let witness_public =
            fixture::read(&reference.initiator, "witness-public", p::PUBLIC_KEY_BYTES)?;
        let witness_id = fixture::array(&reference.initiator, "witness-id")?;
        let identity = *p::AccountAuthorityIdentity::generate()?.as_bytes();
        let options = registry::Options {
            struct_size: std::mem::size_of::<registry::Options>() as u32,
            identity,
            family: material.family,
            witness: witness_id,
            public_key: witness_public.as_ptr(),
            public_key_length: witness_public.len(),
        };
        let registry = registry_open(&registry_path, &options, true)?;
        let address = witness.configured.address.to_string();
        let input = witness_input(&address, witness_id, &witness_public)?;
        let (old, checkpoint) = device(&path.join("old"), &material, &input, Some(&registry))?;
        let checkpoint = checkpoint.ok_or("original checkpoint")?;
        let (target, _) = device(&path.join("target"), &material, &input, None)?;
        let mut sdk = fixture::sdk(&reference.initiator)?;
        let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
        let plan = {
            let mut store = witness.configured.store.lock().map_err(|_| "witness")?;
            store.enroll(&old.genesis, &old.credential, &policy, fixture::now()?)?;
            let request = p::AnchorAccountFreezeRequest::from_trusted_state(
                p::AnchorAccountFreezeId::from_trusted_state([94; 32])?,
                old.root.public_key()?,
                &store.pin()?,
            )?;
            store.account_replacement_plan(
                p::AnchorAccountReplacementId::from_trusted_state([95; 32])?,
                request,
                &target.genesis,
                &target.credential,
                &policy,
                fixture::now()?,
            )?
        };
        policy.close();
        sdk.close();
        let mut error = diagnostic();
        checked(
            unsafe { enrollment::qpc_enrollment_v1_activate(old.handle.0, &mut error) },
            &error,
        )?;
        Ok(Self {
            witness,
            material,
            reference,
            _directory: directory,
            old,
            target,
            registry,
            checkpoint,
            plan,
            registry_path,
            identity,
            witness_public,
            witness_id,
        })
    }
    pub(super) fn prepare_new_target(&mut self) -> TestResult<()> {
        let address = self.witness.configured.address.to_string();
        let witness = witness_input(&address, self.witness_id, &self.witness_public)?;
        let (next, _) = device(
            &self._directory.path().canonicalize()?.join("approved-next"),
            &self.material,
            &witness,
            None,
        )?;
        self.target.handle.close()?;
        self.target = next;
        Ok(())
    }
    pub(super) fn scope(&self) -> root_api::Scope {
        root_api::Scope {
            struct_size: std::mem::size_of::<root_api::Scope>() as u32,
            checkpoint: self.checkpoint,
            witness: self.witness_id,
            public_key: self.witness_public.as_ptr(),
            public_key_length: self.witness_public.len(),
        }
    }
    pub(super) fn begin(&self) -> TestResult<()> {
        let wire = self.plan.to_bytes()?;
        let mut error = diagnostic();
        checked(
            unsafe {
                root_api::qpc_root_v1_begin(
                    self.registry.0,
                    self.old.handle.0,
                    &self.scope(),
                    wire.as_ptr(),
                    wire.len(),
                    &mut error,
                )
            },
            &error,
        )
    }
    pub(super) fn freeze(&self) -> TestResult<Vec<u8>> {
        let mut store = self
            .witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness")?;
        store.freeze_account(self.plan.request())?;
        Ok(store.account_freeze_receipt(self.plan.request())?)
    }
    pub(super) fn bind(&self, receipt: &[u8]) -> TestResult<p::AnchorAccountReplacementProposal> {
        let mut error = diagnostic();
        let mut wire = vec![0; 65536];
        let mut written = 0;
        checked(
            unsafe {
                root_api::qpc_root_v1_bind_freeze(
                    self.registry.0,
                    receipt.as_ptr(),
                    receipt.len(),
                    wire.as_mut_ptr(),
                    wire.len(),
                    &mut written,
                    &mut error,
                )
            },
            &error,
        )?;
        Ok(p::AnchorAccountReplacementProposal::from_trusted_state(
            wire.get(..written).ok_or("proposal length")?,
        )?)
    }
    pub(super) fn commit(
        &self,
        proposal: &p::AnchorAccountReplacementProposal,
    ) -> TestResult<Vec<u8>> {
        let mut sdk = fixture::sdk(&self.reference.initiator)?;
        let policy = fixture::protocol_policy(&self.reference.initiator, &sdk)?;
        let receipt = {
            let mut store = self
                .witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness")?;
            store.replace_account_root(
                proposal,
                &self.old.root.public_key()?,
                &self.target.genesis,
                &self.target.credential,
                &policy,
                fixture::now()?,
            )?;
            store.retired_account_receipt(proposal)?
        };
        policy.close();
        sdk.close();
        Ok(receipt)
    }
    pub(super) fn retain(&self, receipt: &[u8]) -> TestResult<registry::Checkpoint> {
        let mut output = self.checkpoint;
        let mut error = diagnostic();
        checked(
            unsafe {
                root_api::qpc_root_v1_retain_retirement(
                    self.registry.0,
                    receipt.as_ptr(),
                    receipt.len(),
                    &mut output,
                    &mut error,
                )
            },
            &error,
        )?;
        Ok(output)
    }
    pub(super) fn activate(&self) -> TestResult<()> {
        let mut error = diagnostic();
        checked(
            unsafe {
                root_api::qpc_root_v1_activate_successor(
                    self.registry.0,
                    self.target.handle.0,
                    &mut error,
                )
            },
            &error,
        )
    }
    pub(super) fn reopen_registry(&mut self) -> TestResult<()> {
        if self.registry.0 != 0 {
            self.registry.close()?;
        }
        let options = registry::Options {
            struct_size: std::mem::size_of::<registry::Options>() as u32,
            identity: self.identity,
            family: self.material.family,
            witness: self.witness_id,
            public_key: self.witness_public.as_ptr(),
            public_key_length: self.witness_public.len(),
        };
        self.registry = registry_open(&self.registry_path, &options, false)?;
        Ok(())
    }
    pub(super) fn resume(&mut self) -> TestResult<()> {
        self.reopen_registry()?;
        let path = self.old.path.to_str().ok_or("path")?.as_bytes();
        let wire = self.plan.to_bytes()?;
        let mut error = diagnostic();
        checked(
            unsafe {
                root_api::qpc_root_v1_resume(
                    self.registry.0,
                    path.as_ptr(),
                    path.len(),
                    &self.old.intent(),
                    &self.scope(),
                    wire.as_ptr(),
                    wire.len(),
                    &mut error,
                )
            },
            &error,
        )
    }
}
fn registry_open(path: &Path, options: &registry::Options, create: bool) -> TestResult<Handle> {
    if create {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let path = path.to_str().ok_or("path")?.as_bytes();
    let mut error = diagnostic();
    let mut handle = Handle(0);
    unsafe {
        if create {
            checked(
                registry::qpc_authority_v1_provision_wrapping_key(
                    path.as_ptr(),
                    path.len(),
                    &mut error,
                ),
                &error,
            )?;
            checked(
                registry::qpc_authority_v1_prepare_create(
                    path.as_ptr(),
                    path.len(),
                    options,
                    &mut handle.0,
                    &mut error,
                ),
                &error,
            )?;
        } else {
            checked(
                registry::qpc_authority_v1_prepare_open(
                    path.as_ptr(),
                    path.len(),
                    options,
                    &mut handle.0,
                    &mut error,
                ),
                &error,
            )?;
        }
        checked(
            opening::qpc_owner_v1_finish_open(handle.0, &mut error),
            &error,
        )?;
    }
    Ok(handle)
}
pub(super) fn witness_input(
    address: &str,
    identity: [u8; 32],
    public: &[u8],
) -> TestResult<WitnessInput> {
    Ok(WitnessInput {
        header: Header {
            struct_size: std::mem::size_of::<WitnessInput>() as u32,
            version: 1,
        },
        carrier: 1,
        options: crate::witness::Options {
            address: address.as_ptr(),
            address_length: address.len(),
            timeout_ms: 3000,
        },
        identity,
        public_key: blob(public),
        tls_peer: blob(&[]),
        tls_certificate: blob(&[]),
        tls_key: blob(&[]),
        tls_name: blob(&[]),
    })
}
fn device(
    path: &Path,
    material: &Materials,
    witness: &WitnessInput,
    registry: Option<&Handle>,
) -> TestResult<(Device, Option<registry::Checkpoint>)> {
    let root = p::RootSigningKey::generate()?;
    let public = root.public_key()?.encode();
    let now = fixture::now()?;
    let validity = p::Validity::new(now.saturating_sub(1), now.checked_add(1800).ok_or("clock")?)?;
    let native_intent = p::EnrollmentIntent::new(
        root.public_key()?,
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
    let handle = begin(path, material, &intent, witness, true)?;
    let verified = p::VerifiedEnrollmentRequest::verify(&request(&handle)?, &native_intent, now)?;
    let certificate = root.issue_enrollment(&verified, now)?;
    let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
    let pin = enrollment::Pin {
        account: root.account_id()?,
        root: public.as_ptr(),
        root_length: public.len(),
        family: material.family,
        checkpoint: enrollment::Checkpoint {
            version: roster.checkpoint().version(),
            digest: roster.checkpoint().digest(),
        },
    };
    let checkpoint = if let Some(registry) = registry {
        let checkpoint = associate(registry, [242; 32], &pin, &certificate, roster.as_bytes())?;
        select(
            &handle,
            &registry::EnrollmentSelection {
                struct_size: std::mem::size_of::<registry::EnrollmentSelection>() as u32,
                registry: registry.0,
                checkpoint,
            },
        )?;
        Some(checkpoint)
    } else {
        None
    };
    let mut error = diagnostic();
    let mut journal = [0; 32];
    let mut prepared = setup::Preparation {
        protection: 0,
        journal: [0; 32],
        subject: [0; 96],
        image_digest: [0; 32],
    };
    unsafe {
        checked(
            enrollment::qpc_enrollment_v1_accept(
                handle.0,
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
        checked(
            enrollment::qpc_enrollment_v1_prepare_storage(handle.0, &mut prepared, &mut error),
            &error,
        )?;
    }
    assert_eq!(prepared.protection, 2);
    let credential = p::AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        material.family,
    )?
    .verify_device(&certificate, roster.as_bytes(), now)?;
    let genesis = p::AnchorGenesis::from_trusted_state(
        p::AnchorSubject::from_trusted_state(&prepared.subject)?,
        prepared.image_digest,
    )?;
    Ok((
        Device {
            handle,
            path: path.to_owned(),
            root,
            public,
            validity,
            family: material.family,
            genesis,
            credential,
        },
        checkpoint,
    ))
}
