// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual Rust storage boundary, separate from the independent Python state.
use crate::{fixture::Fixture, Result};
use q_periapt_continuity_identity_candidate::{
    BootstrapContext, BootstrapRole, DeviceJournal, DurableError, EnrolledDevice, Error,
    JournalIdentity, JournalKey, MessageId, RekeyControlStep,
};
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) struct Journal {
    owner: Owner,
    context: Arc<BootstrapContext>,
    now: u64,
    bootstrap_time: u64,
    path: PathBuf,
    identity: JournalIdentity,
    initial: Option<Vec<u8>>,
    session: Option<[u8; 32]>,
    policy_version: Option<u64>,
}

// Only the enrolled mode supports lifecycle control. Legacy byte-interoperability
// fixtures retain their original raw-journal contract.
enum Owner {
    Raw(Box<DeviceJournal>),
    Enrolled(Option<EnrolledDevice>),
}
impl Owner {
    fn journal(&mut self) -> std::result::Result<&mut DeviceJournal, DurableError> {
        match self {
            Self::Raw(journal) => Ok(journal),
            Self::Enrolled(active) => Ok(active
                .as_mut()
                .ok_or(DurableError::Closed)?
                .parts()?
                .0
                .stores()?
                .0),
        }
    }
    fn close(&mut self) {
        match self {
            Self::Raw(journal) => journal.close(),
            Self::Enrolled(active) => {
                if let Some(mut owner) = active.take() {
                    owner.close();
                }
            }
        }
    }
    fn retain_archive(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> std::result::Result<(), DurableError> {
        if let Self::Enrolled(active) = self {
            let (journal, archives) = active
                .as_mut()
                .ok_or(DurableError::Closed)?
                .parts()?
                .0
                .stores()?;
            let archive = journal.archive_session_closure(context, session)?;
            archives.retain(journal, context, session, &archive)?;
        }
        Ok(())
    }
}

fn encoding() -> DurableError {
    DurableError::Protocol(Error::Encoding)
}

fn ad_and_payload(input: &[u8]) -> std::result::Result<(&[u8], &[u8]), DurableError> {
    let prefix: [u8; 2] = input
        .get(..2)
        .ok_or_else(encoding)?
        .try_into()
        .map_err(|_| encoding())?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length > 1024 {
        return Err(encoding());
    }
    let ad = input.get(2..2 + length).ok_or_else(encoding)?;
    let payload = input.get(2 + length..).ok_or_else(encoding)?;
    Ok((ad, payload))
}

fn id(input: &[u8]) -> std::result::Result<MessageId, DurableError> {
    MessageId::from_trusted_state(input.try_into().map_err(|_| encoding())?).map_err(Into::into)
}

fn control(step: RekeyControlStep) -> Vec<u8> {
    match step {
        RekeyControlStep::Output(message) => {
            let mut wire = vec![1];
            wire.extend_from_slice(&message.target_epoch().to_be_bytes());
            wire.extend_from_slice(message.as_bytes());
            wire
        }
        RekeyControlStep::LocallyConfirmed(target) => {
            let mut wire = vec![0];
            wire.extend_from_slice(&target.to_be_bytes());
            wire
        }
    }
}

impl Journal {
    pub(super) fn open_successor(
        fixture: &Fixture,
        public: &Path,
        context: Arc<BootstrapContext>,
        now: u64,
    ) -> Result<Self> {
        let path = crate::restart::private_path(public, "private-fixture-path")?;
        if path
            != crate::restart::private_path(&public.join("root-successor"), "private-fixture-path")?
        {
            return Err("successor journal differs from original native journal".into());
        }
        let identity = JournalIdentity::from_trusted_state(
            crate::restart::read(&path.join("identity"), 32)?
                .as_slice()
                .try_into()?,
        )?;
        let witness = fixture
            .witness
            .as_ref()
            .ok_or("restart requires original witness")?;
        let owner = DeviceJournal::open_anchored(
            &path.join("journal"),
            JournalKey::open(&path.join("key"))?,
            &fixture.responder,
            context.current_policy()?,
            identity,
            witness.client()?,
        )?;
        Ok(Self {
            owner: Owner::Raw(Box::new(owner)),
            context,
            now,
            bootstrap_time: now,
            path,
            identity,
            initial: None,
            session: None,
            policy_version: None,
        })
    }

    pub(super) fn create(fixture: &Fixture, public: &Path) -> Result<Self> {
        if let Some(configuration) = &fixture.enrolled_peer {
            let mut active = configuration.initialize(fixture)?;
            let identity = active.parts()?.0.stores()?.0.identity()?;
            return Ok(Self {
                owner: Owner::Enrolled(Some(active)),
                path: configuration.path.clone(),
                identity,
                initial: None,
                session: None,
                policy_version: None,
                context: Arc::clone(&fixture.context),
                now: fixture.times.traffic,
                bootstrap_time: fixture.times.bootstrap,
            });
        }
        Self::create_raw(
            fixture,
            public,
            Arc::clone(&fixture.context),
            fixture.times.bootstrap,
            fixture.times.traffic,
        )
    }

    pub(super) fn verify_successor(
        &self,
        context: &BootstrapContext,
        previous_account: [u8; 32],
    ) -> Result<()> {
        let previous = self.context.device(BootstrapRole::Responder);
        let current = context.device(BootstrapRole::Responder);
        if !matches!(self.owner, Owner::Raw(_))
            || self.session.is_none()
            || self.context.device(BootstrapRole::Initiator).account_id() != previous_account
            || previous.credential_digest() != current.credential_digest()
            || previous.authority_binding() != current.authority_binding()
            || self.context.current_policy()?.checkpoint() != context.current_policy()?.checkpoint()
        {
            return Err("successor peer requires the original native device and policy".into());
        }
        Ok(())
    }

    pub(super) fn select_successor(
        &mut self,
        public: &Path,
        context: Arc<BootstrapContext>,
        now: u64,
        previous_account: [u8; 32],
    ) -> Result<()> {
        self.verify_successor(&context, previous_account)?;
        // A device has one original witness lineage. Start another session in
        // that same journal; never re-enroll or replace its persisted history.
        crate::fixture::save(
            public,
            "private-fixture-path",
            self.path.as_os_str().as_encoded_bytes(),
        )?;
        self.context = context;
        self.bootstrap_time = now;
        self.now = now;
        self.initial = None;
        self.session = None;
        Ok(())
    }

    pub(super) fn matches_context(&self, context: &BootstrapContext, now: u64) -> bool {
        self.context.digest() == context.digest() && self.bootstrap_time == now
    }

    pub(super) fn peer_account(&self) -> [u8; 32] {
        self.context.device(BootstrapRole::Initiator).account_id()
    }

    fn create_raw(
        fixture: &Fixture,
        public: &Path,
        context: Arc<BootstrapContext>,
        bootstrap_time: u64,
        now: u64,
    ) -> Result<Self> {
        // Keep the private fixture even on failure. It is outside the public
        // artifact directory; no wrapping key or sealed secret is uploaded.
        let path = tempfile::Builder::new()
            .prefix("qperiapt-independent-journal-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?
            .keep()
            .canonicalize()?;
        let public_path = public.canonicalize()?;
        let artifact_root = public_path
            .parent()
            .ok_or("missing experiment artifact boundary")?;
        if path.starts_with(artifact_root) {
            return Err("private fixture must remain outside the artifact tree".into());
        }
        fs::write(
            public.join("private-fixture-path"),
            path.as_os_str().as_encoded_bytes(),
        )?;
        let identity = JournalIdentity::generate()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("identity"))?;
        file.write_all(identity.as_bytes())?;
        file.sync_all()?;
        fs::File::open(&path)?.sync_all()?;
        let owner = if let Some(witness) = &fixture.witness {
            let mut owner = DeviceJournal::provision_anchored(
                &path.join("journal"),
                JournalKey::provision(&path.join("key"))?,
                &fixture.responder,
                context.current_policy()?,
                identity,
                bootstrap_time,
            )?;
            let genesis = owner.anchor_genesis(&fixture.responder, context.current_policy()?)?;
            witness.enroll_context(&genesis, &context, BootstrapRole::Responder)?;
            owner.activate_anchor(
                &fixture.responder,
                context.current_policy()?,
                witness.client()?,
            )?;
            owner
        } else {
            DeviceJournal::provision(
                &path.join("journal"),
                JournalKey::provision(&path.join("key"))?,
                &fixture.responder,
                identity,
            )?
        };
        Ok(Self {
            owner: Owner::Raw(Box::new(owner)),
            context,
            now,
            bootstrap_time,
            path,
            identity,
            initial: None,
            session: None,
            policy_version: None,
        })
    }

    pub(super) fn command(
        &mut self,
        fixture: &Fixture,
        command: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, DurableError> {
        let held_context = Arc::clone(&self.context);
        let context = &held_context;
        let now = self.now;
        match command {
            4 => {
                if self
                    .initial
                    .as_ref()
                    .is_some_and(|initial| initial != payload)
                {
                    return Err(DurableError::Conflict);
                }
                let reply = self.owner.journal()?.respond(
                    Arc::clone(context),
                    payload,
                    &fixture.signer,
                    PqKeySource::from_key(&fixture.prekey),
                    TraditionalKeySource::from_key(&fixture.prekey),
                    self.bootstrap_time,
                )?;
                self.initial = Some(payload.to_vec());
                Ok(reply)
            }
            5 => {
                let initial = self.initial.as_deref().ok_or(DurableError::Suspended)?;
                let session = self.owner.journal()?.finish(
                    Arc::clone(context),
                    initial,
                    payload,
                    self.bootstrap_time,
                )?;
                self.session = Some(session);
                Ok(session.to_vec())
            }
            6 if payload.is_empty() => {
                let initial = self.initial.as_deref().ok_or(DurableError::Suspended)?;
                let session = self.owner.journal()?.activate_responder_messages(
                    Arc::clone(context),
                    initial,
                    self.bootstrap_time,
                )?;
                if Some(session) != self.session {
                    return Err(DurableError::Conflict);
                }
                self.owner.retain_archive(context, session)?;
                Ok(session.to_vec())
            }
            7 => {
                let (ad, wire) = ad_and_payload(payload)?;
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .journal()?
                    .receive_message(context, session, wire, ad, now)?
                    .as_bytes()
                    .to_vec())
            }
            8 if payload.is_empty() => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .journal()?
                    .next_message_id(context, session, now)?
                    .as_bytes()
                    .to_vec())
            }
            9 => {
                let identity = id(payload.get(..32).ok_or_else(encoding)?)?;
                let (ad, plaintext) = ad_and_payload(payload.get(32..).ok_or_else(encoding)?)?;
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner
                    .journal()?
                    .send_message(context, session, identity, plaintext, ad, now)
            }
            10 => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner
                    .journal()?
                    .consume_message(context, session, id(payload)?, now)?;
                self.owner
                    .journal()?
                    .message_acknowledgement(context, session, now)
            }
            11 => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .journal()?
                    .accept_message_acknowledgement(context, session, payload, now)?
                    .to_be_bytes()
                    .to_vec())
            }
            12 if payload.is_empty() => {
                if self.policy_version.is_some() {
                    return Err(DurableError::Conflict);
                }
                self.owner.close();
                if let Some(configuration) = &fixture.enrolled_peer {
                    let mut active = configuration.activate(fixture, now)?;
                    self.context = configuration.context(
                        &mut active,
                        fixture,
                        self.session.ok_or(DurableError::Suspended)?,
                        now,
                    )?;
                    if active.parts()?.0.stores()?.0.identity()? != self.identity {
                        return Err(DurableError::Conflict);
                    }
                    self.owner = Owner::Enrolled(Some(active));
                    return Ok(b"reopened".to_vec());
                }
                self.owner = Owner::Raw(Box::new(if let Some(witness) = &fixture.witness {
                    DeviceJournal::open_anchored(
                        &self.path.join("journal"),
                        JournalKey::open(&self.path.join("key"))?,
                        &fixture.responder,
                        context.current_policy()?,
                        self.identity,
                        witness.client()?,
                    )?
                } else {
                    DeviceJournal::open(
                        &self.path.join("journal"),
                        JournalKey::open(&self.path.join("key"))?,
                        &fixture.responder,
                        self.identity,
                    )?
                }));
                Ok(b"reopened".to_vec())
            }
            13 if payload.is_empty() => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner
                    .journal()?
                    .message_acknowledgement(context, session, now)
            }
            14..=23 => self.rekey_command(fixture, command, payload),
            24..=27 => crate::resolution::command(
                self.owner.journal()?,
                context,
                self.session.ok_or(DurableError::Suspended)?,
                command,
                payload,
                now,
            ),
            _ => Err(encoding()),
        }
    }

    fn rekey_command(
        &mut self,
        fixture: &Fixture,
        command: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, DurableError> {
        let held_context = Arc::clone(&self.context);
        let context = &held_context;
        let now = self.now;
        let session = self.session.ok_or(DurableError::Suspended)?;
        match command {
            14 => self.owner.journal()?.respond_rekey_offer(
                context,
                session,
                payload,
                &fixture.signer,
                now,
            ),
            15 => {
                self.owner
                    .journal()?
                    .finish_rekey(context, session, payload, &fixture.signer, now)
            }
            16 if payload.is_empty() => {
                let progress = self.owner.journal()?.rekey_progress(context, session)?;
                Ok([
                    progress.confirmed_epoch,
                    progress.sending_epoch,
                    progress.receiving_epoch,
                    progress.pending_epoch.unwrap_or(0),
                ]
                .into_iter()
                .flat_map(u64::to_be_bytes)
                .collect())
            }
            17 if payload.is_empty() => {
                self.owner
                    .journal()?
                    .prepare_rekey_offer(context, session, &fixture.signer, now)
            }
            18 => self.owner.journal()?.accept_rekey_response(
                context,
                session,
                payload,
                &fixture.signer,
                now,
            ),
            19 => Ok(self
                .owner
                .journal()?
                .accept_rekey_receipt(context, session, payload, now)?
                .to_be_bytes()
                .to_vec()),
            20 => {
                let epoch = u64::from_be_bytes(payload.try_into().map_err(|_| encoding())?);
                self.owner
                    .journal()?
                    .message_acknowledgement_for_epoch(context, session, epoch, now)
            }
            21 => {
                let target = u64::from_be_bytes(payload.try_into().map_err(|_| encoding())?);
                self.owner
                    .journal()?
                    .advance_rekey_control(context, session, target, &fixture.signer, now)
                    .map(control)
            }
            22 => self
                .owner
                .journal()?
                .receive_rekey_control(context, session, payload, &fixture.signer, now)
                .map(control),
            23 if payload.is_empty() => Ok(format!(
                "{:?}",
                self.owner
                    .journal()?
                    .rekey_request_status(context, session)?
            )
            .into_bytes()),
            _ => Err(encoding()),
        }
    }

    pub(super) fn maintain(&mut self, fixture: &Fixture, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() != 16 {
            return Err("native maintenance shape".into());
        }
        let cycle = u64::from_be_bytes(payload.get(..8).ok_or("maintenance cycle")?.try_into()?);
        let now = u64::from_be_bytes(payload.get(8..).ok_or("maintenance time")?.try_into()?);
        if now < self.now {
            return Err("native trusted time rollback".into());
        }
        let configuration = fixture
            .enrolled_peer
            .as_ref()
            .ok_or("native original enrollment unavailable")?;
        if !matches!(self.owner, Owner::Enrolled(_)) {
            return Err("native enrollment owner mismatch".into());
        }
        self.now = now;
        self.owner.close();
        let (mut active, continued_context) = if let Some(version) = self.policy_version {
            let session = self.session.ok_or("missing original session")?;
            let (active, context) = if cycle == 4 {
                configuration.refresh_under_policy(fixture, version, now, session)?
            } else {
                configuration.renew_under_policy(fixture, cycle, version, now, session)?
            };
            (active, Some(context))
        } else if cycle == 4 {
            (configuration.refresh(fixture, now)?, None)
        } else {
            (configuration.renew(fixture, cycle, now)?, None)
        };
        if active.parts()?.0.stores()?.0.identity()? != self.identity {
            return Err("native original journal changed".into());
        }
        self.context = match continued_context {
            Some(context) => context,
            None => configuration.context(
                &mut active,
                fixture,
                self.session.ok_or("missing original session")?,
                now,
            )?,
        };
        self.owner = Owner::Enrolled(Some(active));
        let mut receipt = self.identity.as_bytes().to_vec();
        receipt.extend_from_slice(&self.session.ok_or("missing original session")?);
        receipt.extend_from_slice(&now.to_be_bytes());
        Ok(receipt)
    }

    pub(super) fn renew_policy(&mut self, fixture: &Fixture, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() != 16 {
            return Err("native policy maintenance shape".into());
        }
        let version = u64::from_be_bytes(payload.get(..8).ok_or("policy version")?.try_into()?);
        let now = u64::from_be_bytes(payload.get(8..).ok_or("policy time")?.try_into()?);
        if now < self.now {
            return Err("native trusted time rollback".into());
        }
        let configuration = fixture
            .enrolled_peer
            .as_ref()
            .ok_or("original native enrollment absent")?;
        self.now = now;
        self.owner.close();
        let session = self.session.ok_or("missing original native session")?;
        let (mut active, context) = configuration.renew_policy(fixture, version, now, session)?;
        if active.parts()?.0.stores()?.0.identity()? != self.identity {
            return Err("native journal changed".into());
        }
        self.owner = Owner::Enrolled(Some(active));
        self.context = context;
        self.policy_version = Some(version);
        let mut receipt = self.identity.as_bytes().to_vec();
        receipt.extend_from_slice(&session);
        receipt.extend_from_slice(&now.to_be_bytes());
        Ok(receipt)
    }

    pub(super) fn has_policy(&self) -> bool {
        self.policy_version.is_some()
    }

    pub(super) fn reopen_policy(&mut self, fixture: &Fixture) -> Result<Vec<u8>> {
        let mut request = self
            .policy_version
            .ok_or("no adopted native policy")?
            .to_be_bytes()
            .to_vec();
        request.extend_from_slice(&self.now.to_be_bytes());
        self.renew_policy(fixture, &request)?;
        Ok(b"reopened".to_vec())
    }

    pub(super) fn close(mut self) {
        self.owner.close();
    }
}
