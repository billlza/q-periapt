// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual persistent witness and explicit test control plane, never peer enrollment.
#[path = "witness_root.rs"]
mod root;
use crate::{fixture::Fixture, Result};
use q_periapt_continuity_identity_candidate::{
    AnchorClient, AnchorCredentialRenewalProposal, AnchorGenesis, AnchorIdentity,
    AnchorPendingWriteRecoveryProposal, AnchorPin, AnchorRosterRefreshProposal, AnchorSigningKey,
    AnchorStore, AnchorSubject, AnchorTransport, BootstrapContext, BootstrapRole, DeviceSigningKey,
    DurableError, JournalKey, SigningKeyId,
};
use std::{
    fs, io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub(super) struct Witness {
    store: Mutex<Option<AnchorStore>>,
    pub pin: AnchorPin,
    path: PathBuf,
    witness_key: SigningKeyId,
    device_key: SigningKeyId,
    now: AtomicU64,
}

impl Witness {
    pub fn open(public: &Path, now: u64) -> Result<Arc<Self>> {
        let path = crate::restart::private_path(public, "private-witness-path")?;
        let read_id = |name: &str| -> Result<[u8; 32]> {
            Ok(crate::restart::read(&path.join(name), 32)?
                .as_slice()
                .try_into()?)
        };
        let identity = AnchorIdentity::from_trusted_state(read_id("witness-id")?)?;
        let witness_key = SigningKeyId::from_trusted_state(read_id("witness-key-id")?)?;
        let device_key = SigningKeyId::from_trusted_state(read_id("device-key-id")?)?;
        let wrapping = JournalKey::open(&path.join("key"))?;
        let signer = AnchorSigningKey::open(&path.join("witness-signer"), &wrapping, witness_key)?;
        let store = AnchorStore::open(&path.join("witness.redb"), wrapping, signer, identity)?;
        let pin = store.pin()?;
        if pin.public_key().encode() != crate::restart::read(&public.join("pin-witness-key"), 1985)?
            || identity.as_bytes().as_slice()
                != crate::restart::read(&public.join("pin-witness-id"), 32)?
        {
            return Err("original witness pin changed".into());
        }
        Ok(Arc::new(Self {
            store: Mutex::new(Some(store)),
            pin,
            path,
            witness_key,
            device_key,
            now: AtomicU64::new(now),
        }))
    }

    pub fn open_device(&self) -> Result<DeviceSigningKey> {
        Ok(DeviceSigningKey::open(
            &self.path.join("device-signer"),
            &JournalKey::open(&self.path.join("key"))?,
            self.device_key,
        )?)
    }

    pub fn prekey(
        &self,
        runtime: &q_periapt_sdk::Runtime,
        create: bool,
    ) -> Result<q_periapt_sdk::HybridKey> {
        crate::restart::prekey(&self.path, runtime, create)
    }

    pub fn approve_credential_under_policy(
        &self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &q_periapt_continuity_identity_candidate::VerifiedCredentialRenewal,
        original: &q_periapt_continuity_identity_candidate::HistoricalSessionPolicy,
        policy: &q_periapt_continuity_identity_candidate::VerifiedSessionPolicy,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .prepare_policy_renewed_credential_renewal(
                proposal,
                grant,
                original,
                policy,
                self.now.load(Ordering::SeqCst),
            )?;
        Ok(())
    }

    pub fn approve_policy(
        &self,
        proposal: q_periapt_continuity_identity_candidate::AnchorPolicyRenewalProposal,
        proof: &q_periapt_continuity_identity_candidate::VerifiedPolicyRenewal,
        materials: &q_periapt_continuity_identity_candidate::PolicyRenewalMaterials<'_>,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .prepare_policy_renewal(proposal, proof, materials, self.now.load(Ordering::SeqCst))?;
        Ok(())
    }

    pub fn transport(self: &Arc<Self>) -> Box<dyn AnchorTransport> {
        Box::new(Carrier(Arc::clone(self)))
    }

    pub fn approve_credential(
        &self,
        proposal: AnchorCredentialRenewalProposal,
        grant: &q_periapt_continuity_identity_candidate::VerifiedCredentialRenewal,
        policy: &q_periapt_continuity_identity_candidate::VerifiedSessionPolicy,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .prepare_credential_renewal(proposal, grant, policy, self.now.load(Ordering::SeqCst))?;
        Ok(())
    }

    pub fn approve_roster(
        &self,
        proposal: AnchorRosterRefreshProposal,
        previous: &q_periapt_continuity_identity_candidate::VerifiedDevice,
        target: &q_periapt_continuity_identity_candidate::VerifiedDevice,
        policy: &q_periapt_continuity_identity_candidate::VerifiedSessionPolicy,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .prepare_roster_refresh(
                proposal,
                previous,
                target,
                policy,
                self.now.load(Ordering::SeqCst),
            )?;
        Ok(())
    }

    pub fn create(public: &Path, now: u64) -> Result<Arc<Self>> {
        let path = tempfile::Builder::new()
            .prefix("qperiapt-independent-witness-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?
            .keep()
            .canonicalize()?;
        if path.starts_with(public.canonicalize()?.parent().ok_or("artifact boundary")?) {
            return Err("witness private state inside public output".into());
        }
        let wrapping = JournalKey::provision(&path.join("key"))?;
        let witness_key = SigningKeyId::generate()?;
        let device_key = SigningKeyId::generate()?;
        let identity = AnchorIdentity::generate()?;
        for (name, bytes) in [
            ("witness-id", identity.as_bytes()),
            ("witness-key-id", witness_key.as_bytes()),
            ("device-key-id", device_key.as_bytes()),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::File::open(&path)?.sync_all()?;
        let signer =
            AnchorSigningKey::provision(&path.join("witness-signer"), &wrapping, witness_key)?;
        let store = AnchorStore::provision(&path.join("witness.redb"), wrapping, signer, identity)?;
        let pin = store.pin()?;
        fs::write(public.join("pin-witness-id"), identity.as_bytes())?;
        fs::write(public.join("pin-witness-key"), pin.public_key().encode())?;
        fs::write(
            public.join("private-witness-path"),
            path.as_os_str().as_encoded_bytes(),
        )?;
        Ok(Arc::new(Self {
            store: Mutex::new(Some(store)),
            pin,
            path,
            witness_key,
            device_key,
            now: AtomicU64::new(now),
        }))
    }

    pub fn provision_device(&self) -> Result<DeviceSigningKey> {
        Ok(DeviceSigningKey::provision(
            &self.path.join("device-signer"),
            &JournalKey::open(&self.path.join("key"))?,
            self.device_key,
        )?)
    }

    pub fn client(self: &Arc<Self>) -> std::result::Result<AnchorClient, DurableError> {
        let signer = DeviceSigningKey::open(
            &self.path.join("device-signer"),
            &JournalKey::open(&self.path.join("key"))?,
            self.device_key,
        )?;
        Ok(AnchorClient::new(
            self.pin.clone(),
            signer,
            Box::new(Carrier(Arc::clone(self))),
            Duration::from_secs(10),
        )?)
    }

    pub fn enroll(
        &self,
        genesis: &AnchorGenesis,
        fixture: &Fixture,
        role: BootstrapRole,
    ) -> Result<()> {
        self.enroll_context(genesis, &fixture.context, role)
    }

    pub fn enroll_context(
        &self,
        genesis: &AnchorGenesis,
        context: &BootstrapContext,
        role: BootstrapRole,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .enroll(
                genesis,
                context.device(role),
                context.current_policy()?,
                self.now.load(Ordering::SeqCst),
            )?;
        Ok(())
    }

    pub fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .handle(wire, self.now.load(Ordering::SeqCst))?)
    }

    pub fn command(&self, fixture: &Fixture, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        match command {
            30 if payload.len() == 128 => {
                let genesis = AnchorGenesis::from_trusted_state(
                    AnchorSubject::from_trusted_state(&payload[..96])?,
                    payload[96..].try_into()?,
                )?;
                self.enroll(&genesis, fixture, BootstrapRole::Initiator)?;
                Ok(b"enrolled".to_vec())
            }
            31 => self.exchange(payload),
            32 if payload.is_empty() => {
                let mut store = self.store.lock().map_err(|_| "witness lock poisoned")?;
                store.take().ok_or("closed witness")?.close();
                let wrapping = JournalKey::open(&self.path.join("key"))?;
                let signer = AnchorSigningKey::open(
                    &self.path.join("witness-signer"),
                    &wrapping,
                    self.witness_key,
                )?;
                *store = Some(AnchorStore::open(
                    &self.path.join("witness.redb"),
                    wrapping,
                    signer,
                    self.pin.identity(),
                )?);
                Ok(b"witness reopened".to_vec())
            }
            33 if payload.len() == 8 => {
                self.now
                    .store(u64::from_be_bytes(payload.try_into()?), Ordering::SeqCst);
                Ok(b"witness clock set".to_vec())
            }
            34 | 35 if matches!(payload.len(), 296 | 337) => {
                let continued = payload.len() == 337;
                let size = if continued { 329 } else { 296 };
                let proposal = AnchorCredentialRenewalProposal::from_trusted_state(
                    payload.get(..size).ok_or("credential proposal size")?,
                )?;
                let policy = if continued {
                    let version = u64::from_be_bytes(
                        payload
                            .get(size..)
                            .ok_or("credential policy version")?
                            .try_into()?,
                    );
                    Some(
                        fixture
                            .policy_renewal
                            .as_ref()
                            .ok_or("policy test issuer unavailable")?
                            .policy(version)?,
                    )
                } else {
                    None
                };
                if proposal.policy_renewal().is_some() != continued {
                    return Err("credential policy profile differs".into());
                }
                let grant = fixture
                    .local_grants
                    .iter()
                    .find(|g| g.operation() == proposal.operation())
                    .ok_or("unknown independently retained local grant")?;
                let mut store = self.store.lock().map_err(|_| "witness lock poisoned")?;
                let store = store.as_mut().ok_or("closed witness")?;
                let result = if let Some(policy) = policy {
                    if command == 34 {
                        store.prepare_policy_renewed_credential_renewal(
                            proposal,
                            grant,
                            fixture.policy.historical(),
                            &policy,
                            self.now.load(Ordering::SeqCst),
                        )?
                    } else {
                        store.close_policy_renewed_credential_renewal(
                            proposal,
                            grant.historical(),
                            fixture.policy.historical(),
                            policy.historical(),
                        )?
                    }
                } else if command == 34 {
                    store.prepare_credential_renewal(
                        proposal,
                        grant,
                        fixture.context.current_policy()?,
                        self.now.load(Ordering::SeqCst),
                    )?
                } else {
                    store.close_credential_renewal(
                        proposal,
                        grant.historical(),
                        fixture.context.original_policy(),
                    )?
                };
                Ok(format!("{result:?}").into_bytes())
            }
            36 => self.approve_pending(fixture, payload),
            37 => self.complete_pending(payload),
            39 if matches!(payload.len(), 417 | 425) => {
                let proposal = AnchorRosterRefreshProposal::from_trusted_state(
                    payload.get(..417).ok_or("roster proposal size")?,
                )?;
                let continued = if payload.len() == 425 {
                    let version = u64::from_be_bytes(
                        payload
                            .get(417..)
                            .ok_or("roster policy version")?
                            .try_into()?,
                    );
                    Some(
                        fixture
                            .policy_renewal
                            .as_ref()
                            .ok_or("policy test issuer unavailable")?
                            .policy(version)?,
                    )
                } else {
                    None
                };
                if proposal.scope().policy_authorization.is_some() != continued.is_some() {
                    return Err("roster policy profile differs".into());
                }
                let policy = continued
                    .as_deref()
                    .unwrap_or(fixture.context.current_policy()?);
                let target = fixture
                    .local_rosters
                    .iter()
                    .find(|d| d.roster().checkpoint() == proposal.scope().target)
                    .ok_or("unknown independently selected roster target")?;
                let original = fixture.context.device(BootstrapRole::Initiator);
                let previous = std::iter::once(original)
                    .chain(fixture.local_grants.iter().map(|g| g.successor_device()))
                    .chain(fixture.local_rosters.iter())
                    .find(|d| d.roster().checkpoint() == proposal.scope().previous)
                    .ok_or("unknown independently retained roster predecessor")?;
                let result = self
                    .store
                    .lock()
                    .map_err(|_| "witness lock poisoned")?
                    .as_mut()
                    .ok_or("closed witness")?
                    .prepare_roster_refresh(
                        proposal,
                        previous,
                        target,
                        policy,
                        self.now.load(Ordering::SeqCst),
                    )?;
                Ok(format!("{result:?}").into_bytes())
            }
            43 | 44 => {
                let issuer = fixture
                    .policy_renewal
                    .as_ref()
                    .ok_or("policy issuer unavailable")?;
                let mut store = self.store.lock().map_err(|_| "witness lock poisoned")?;
                issuer.witness_request(
                    fixture,
                    store.as_mut().ok_or("closed witness")?,
                    payload,
                    command == 44,
                    self.now.load(Ordering::SeqCst),
                )
            }
            _ => Err("witness test command shape".into()),
        }
    }

    fn approval_path(&self, proposal: &AnchorPendingWriteRecoveryProposal) -> PathBuf {
        let mut name = String::from("pending-approval-");
        for byte in proposal.binding() {
            name.push_str(&format!("{byte:02x}"));
        }
        self.path.join(name)
    }

    // These two commands are the harness's independently authorized controller,
    // outside the ordinary signed device endpoint31. Approval has no device
    // signature input and is durably retained before completion can be invoked.
    fn approve_pending(&self, fixture: &Fixture, payload: &[u8]) -> Result<Vec<u8>> {
        let size = AnchorPendingWriteRecoveryProposal::ENCODED_BYTES;
        let proposal = AnchorPendingWriteRecoveryProposal::from_trusted_state(
            payload.get(..size).ok_or("pending approval shape")?,
        )?;
        let metadata = payload.get(size..).ok_or("pending approval metadata")?;
        let inspection = proposal.inspect_metadata(metadata)?;
        let account = fixture
            .context
            .device(BootstrapRole::Initiator)
            .account_id();
        for view in [inspection.source(), inspection.target()] {
            if view.local_account != account
                || view
                    .records
                    .iter()
                    .any(|r| r.context != fixture.context.digest())
            {
                return Err("independent approval account/context differs".into());
            }
        }
        if proposal.expected_policy_digest()
            != fixture.context.original_policy().checkpoint().digest()
        {
            return Err("independent approval policy differs".into());
        }
        let path = self.approval_path(&proposal);
        if path.try_exists()? {
            if fs::read(&path)? != payload {
                return Err("conflicting retained pending approval".into());
            }
        } else {
            let count = fs::read_dir(&self.path)?.try_fold(0usize, |count, item| {
                let item = item?;
                Ok::<_, io::Error>(
                    count
                        + usize::from(
                            item.file_name()
                                .as_encoded_bytes()
                                .starts_with(b"pending-approval-"),
                        ),
                )
            })?;
            if count >= 4 {
                return Err("pending approval fixture capacity".into());
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(payload)?;
            file.sync_all()?;
            fs::File::open(&self.path)?.sync_all()?;
        }
        if fs::read(&path)? != payload {
            return Err("pending approval durable readback differs".into());
        }
        let mut result = proposal.binding().to_vec();
        result.extend_from_slice(&(inspection.source().records.len() as u64).to_be_bytes());
        result.extend_from_slice(&(inspection.target().records.len() as u64).to_be_bytes());
        Ok(result)
    }

    fn complete_pending(&self, signed: &[u8]) -> Result<Vec<u8>> {
        let size = AnchorPendingWriteRecoveryProposal::ENCODED_BYTES;
        if signed.get(..4) != Some(&(size as u32).to_be_bytes()) {
            return Err("pending signed request shape".into());
        }
        let proposal = AnchorPendingWriteRecoveryProposal::from_trusted_state(
            signed.get(4..4 + size).ok_or("pending signed body")?,
        )?;
        let recorded = fs::read(self.approval_path(&proposal))?;
        if recorded.get(..size) != Some(proposal.to_bytes().as_slice()) {
            return Err("independently retained pending approval differs".into());
        }
        let metadata = recorded
            .get(size..)
            .ok_or("missing retained pending metadata")?;
        let head = self
            .store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .complete_pending_write_recovery(
                &proposal,
                signed,
                metadata,
                self.now.load(Ordering::SeqCst),
            )?;
        let mut result = head.fence().to_be_bytes().to_vec();
        result.extend_from_slice(&head.revision().to_be_bytes());
        result.extend_from_slice(&head.digest());
        Ok(result)
    }
}

struct Carrier(Arc<Witness>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, wire: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let reply = self
            .0
            .exchange(wire)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(reply)
    }
}
