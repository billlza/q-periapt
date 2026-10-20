// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test counterpart lifecycle through the public original-enrollment API.
use crate::{fixture::Fixture, Result, NOW};
use q_periapt_continuity_identity_candidate::{
    AccountPin, BootstrapBundle, BootstrapContext, BootstrapMaterials, BootstrapRequirements,
    BootstrapRole, DeviceDescription, DeviceEnrollment, DeviceSigningKey, DurableError,
    EnrolledDevice, EnrollmentIntent, EnrollmentPaths, ExpectedDevice, InstallationPaths,
    InstallationPreparation, JournalKey, PrekeyQuality, PublicKey, RosterCheckpoint,
    RosterRefreshId, Validity, VerifiedCredentialRenewal, VerifiedEnrollmentRequest,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(super) struct Configuration {
    pub path: PathBuf,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    root: PublicKey,
    request: VerifiedEnrollmentRequest,
    public: PathBuf,
    members: usize,
}

impl Configuration {
    pub fn provision(
        public: &Path,
        root: PublicKey,
        family: [u8; 32],
        members: usize,
    ) -> Result<(Self, DeviceSigningKey)> {
        let path = tempfile::Builder::new()
            .prefix("qperiapt-enrolled-peer-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?
            .keep()
            .canonicalize()?;
        let public = public.canonicalize()?;
        if path.starts_with(public.parent().ok_or("artifact boundary")?) {
            return Err("private enrollment inside artifact directory".into());
        }
        fs::write(
            public.join("private-fixture-path"),
            path.as_os_str().as_encoded_bytes(),
        )?;
        let wrapping = path.join("key");
        let key = JournalKey::provision(&wrapping)?;
        let paths = EnrollmentPaths::new(
            &wrapping,
            &path.join("signer"),
            &path.join("enrollment"),
            InstallationPaths::new(
                &path.join("installation"),
                &path.join("journal"),
                &path.join("archives"),
            )?,
        )?;
        let intent = EnrollmentIntent::new(
            root.clone(),
            DeviceDescription::new([2; 16], 1, family, Validity::new(100, 200)?)?,
        );
        let mut owner = DeviceEnrollment::provision(paths.clone(), intent.clone())?;
        let wire = owner.request(NOW)?;
        let request = VerifiedEnrollmentRequest::verify(&wire, &intent, NOW)?;
        let signer = DeviceSigningKey::open(&path.join("signer"), &key, request.identity())?;
        fs::write(public.join("native-enrollment-request"), wire)?;
        owner.close();
        Ok((
            Self {
                path,
                paths,
                intent,
                root,
                request,
                public,
                members,
            },
            signer,
        ))
    }

    pub fn request(&self) -> &VerifiedEnrollmentRequest {
        &self.request
    }

    fn open(&self) -> std::result::Result<DeviceEnrollment, DurableError> {
        DeviceEnrollment::open(self.paths.clone(), self.intent.clone())
    }

    fn pin(
        &self,
        fixture: &Fixture,
        checkpoint: RosterCheckpoint,
    ) -> std::result::Result<AccountPin, DurableError> {
        Ok(AccountPin::new(
            fixture.responder.account_id(),
            self.root.clone(),
            checkpoint,
            fixture.context.current_policy()?.family(),
        )?)
    }

    pub fn initialize(&self, fixture: &Fixture) -> Result<EnrolledDevice> {
        let mut owner = self.open()?;
        let policy = fixture.context.current_policy()?;
        let pin = self.pin(fixture, fixture.responder.roster().checkpoint())?;
        owner.accept(
            &fs::read(self.public.join("r-credential"))?,
            fixture.responder.roster().as_bytes(),
            &pin,
            policy,
            NOW,
        )?;
        let client = match owner.prepare(policy, NOW)? {
            InstallationPreparation::Local => None,
            InstallationPreparation::RequiresEnrollment(genesis) => {
                let witness = fixture
                    .witness
                    .as_ref()
                    .ok_or("required witness unavailable")?;
                witness.enroll(&genesis, fixture, BootstrapRole::Responder)?;
                Some(owner.anchor_client(
                    policy,
                    NOW,
                    witness.pin.clone(),
                    witness.transport(),
                    Duration::from_secs(10),
                )?)
            }
        };
        Ok(owner.activate(policy, NOW, client)?)
    }

    pub fn activate(
        &self,
        fixture: &Fixture,
        now: u64,
    ) -> std::result::Result<EnrolledDevice, DurableError> {
        self.activate_owner(self.open()?, fixture, now)
    }

    fn activate_owner(
        &self,
        mut owner: DeviceEnrollment,
        fixture: &Fixture,
        now: u64,
    ) -> std::result::Result<EnrolledDevice, DurableError> {
        let policy = fixture.context.current_policy()?;
        // This historical client authenticates only the original signer. The
        // activation API still checks the actually installed live grant/roster.
        let client = fixture
            .witness
            .as_ref()
            .map(|w| {
                owner.credential_renewal_anchor_client(
                    policy,
                    now,
                    w.pin.clone(),
                    w.transport(),
                    Duration::from_secs(10),
                )
            })
            .transpose()?;
        owner.activate(policy, now, client)
    }

    fn bundle(&self) -> std::result::Result<BootstrapBundle, DurableError> {
        let read = |name| fs::read(self.public.join(name));
        let i = read("i-credential")?;
        let ir = read("i-roster")?;
        let r = read("r-credential")?;
        let rr = read("r-roster")?;
        let manifest = read("manifest")?;
        let classical = read("proof-1")?;
        let pq = read("proof-3")?;
        let bundle = BootstrapBundle::from_materials(
            PrekeyQuality::ReusableBoth,
            BootstrapMaterials {
                initiator_credential: &i,
                initiator_roster: &ir,
                responder_credential: &r,
                responder_roster: &rr,
                responder_manifest: &manifest,
                signed_classical: &classical,
                last_resort_pq: &pq,
                one_time_classical: None,
                one_time_pq: None,
            },
        )?;
        Ok(bundle)
    }

    pub fn context(
        &self,
        active: &mut EnrolledDevice,
        fixture: &Fixture,
        session: [u8; 32],
        now: u64,
    ) -> std::result::Result<Arc<BootstrapContext>, DurableError> {
        let pin = self.pin(fixture, fixture.responder.roster().checkpoint())?;
        let peer = active.parts()?.0.reopen_peer_bundle(&self.bundle()?, Arc::clone(&fixture.policy),
            BootstrapRequirements {
                initiator: ExpectedDevice::new(&pin, [1;16], 1)?,
                responder: ExpectedDevice::new(&pin, [2;16], 1)?,
                quality: PrekeyQuality::ReusableBoth,
                directory: q_periapt_continuity_identity_candidate::DirectoryExpectation::from_trusted_state([99;32])?,
            }, BootstrapRole::Responder, session, now)?;
        if peer.session_id() != session || peer.context().digest() != fixture.context.digest() {
            return Err(DurableError::Conflict);
        }
        Ok(Arc::clone(peer.context()))
    }

    fn checkpoint(&self, version: u64) -> Result<RosterCheckpoint> {
        let wire = fs::read(
            self.public
                .join("account")
                .join(format!("checkpoint-{version}")),
        )?;
        let encoded_version =
            u64::from_be_bytes(wire.get(..8).ok_or("checkpoint size")?.try_into()?);
        if encoded_version != version {
            return Err("independent checkpoint version differs".into());
        }
        Ok(RosterCheckpoint::from_trusted_state(
            version,
            wire.get(8..).ok_or("checkpoint digest")?.try_into()?,
        )?)
    }

    /// Explicit test controller selects pre-issued root grants. No peer message
    /// can trigger this operation or choose the account pin.
    pub fn renew(&self, fixture: &Fixture, cycle: u64, now: u64) -> Result<EnrolledDevice> {
        let (version, count) = match cycle {
            1 => (2, self.members),
            2 => (3, self.members),
            18 => (18, self.members - 1),
            _ => return Err("unissued native renewal cycle".into()),
        };
        let policy = fixture.context.current_policy()?;
        let pin = self.pin(fixture, self.checkpoint(version)?)?;
        let grants = (1..=count)
            .map(|id| {
                let wire = fs::read(
                    self.public
                        .join("account")
                        .join(format!("grant-{cycle}-{id}")),
                )?;
                Ok(VerifiedCredentialRenewal::verify(
                    &wire,
                    &pin,
                    policy.checkpoint().digest(),
                    now,
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        let local = grants.get(1).ok_or("native local grant missing")?;
        let companions = grants
            .iter()
            .enumerate()
            .filter_map(|(i, g)| (i != 1).then_some(g))
            .collect::<Vec<_>>();
        let mut owner = self.open()?;
        owner.stage_account_credential_renewal(
            local,
            &companions,
            local.operation(),
            policy,
            now,
        )?;
        if let Some(w) = &fixture.witness {
            let client = owner.credential_renewal_anchor_client(
                policy,
                now,
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            let proposal = owner.prepare_witnessed_credential_renewal(policy, now, client)?;
            w.approve_credential(proposal, local, policy)?;
            let mut client = owner.credential_renewal_anchor_client(
                policy,
                now,
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            owner.commit_witnessed_credential_renewal(
                local.operation(),
                local.statement_digest(),
                policy,
                now,
                &mut client,
            )?;
        }
        Ok(self.activate_owner(owner, fixture, now)?)
    }

    pub fn refresh(&self, fixture: &Fixture, now: u64) -> Result<EnrolledDevice> {
        let policy = fixture.context.current_policy()?;
        let mut owner = self.open()?;
        let admission = owner.public_admission()?;
        let previous = self
            .pin(fixture, admission.checkpoint())?
            .verify_historical_device(admission.certificate(), admission.roster())?;
        let pin = self.pin(fixture, self.checkpoint(4)?)?;
        let roster = fs::read(self.public.join("account/roster-4"))?;
        let target = pin.verify_device(admission.certificate(), &roster, now)?;
        if let Some(w) = &fixture.witness {
            let client = owner.roster_refresh_anchor_client(
                policy.historical(),
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            let proposal = owner.prepare_witnessed_roster_refresh(
                RosterRefreshId::generate()?,
                policy.historical(),
                policy,
                &target,
                now,
                client,
            )?;
            w.approve_roster(proposal, &previous, &target, policy)?;
            let mut client = owner.roster_refresh_anchor_client(
                policy.historical(),
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            owner.commit_witnessed_roster_refresh(
                &proposal,
                policy.historical(),
                policy,
                now,
                &mut client,
            )?;
        } else {
            owner.refresh_roster(admission.checkpoint(), &roster, &pin, policy, now)?;
        }
        Ok(self.activate_owner(owner, fixture, now)?)
    }
}
