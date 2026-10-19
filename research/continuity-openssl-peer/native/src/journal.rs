// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual Rust storage boundary, separate from the independent Python state.
use crate::{fixture::Fixture, Result};
use q_periapt_continuity_identity_candidate::{
    BootstrapRole, DeviceJournal, DurableError, Error, JournalIdentity, JournalKey, MessageId,
    RekeyControlStep,
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
    owner: DeviceJournal,
    path: PathBuf,
    identity: JournalIdentity,
    initial: Option<Vec<u8>>,
    session: Option<[u8; 32]>,
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
    pub(super) fn create(fixture: &Fixture, public: &Path) -> Result<Self> {
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
                fixture.context.current_policy()?,
                identity,
                fixture.times.bootstrap,
            )?;
            let genesis =
                owner.anchor_genesis(&fixture.responder, fixture.context.current_policy()?)?;
            witness.enroll(&genesis, fixture, BootstrapRole::Responder)?;
            owner.activate_anchor(
                &fixture.responder,
                fixture.context.current_policy()?,
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
            owner,
            path,
            identity,
            initial: None,
            session: None,
        })
    }

    pub(super) fn command(
        &mut self,
        fixture: &Fixture,
        command: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, DurableError> {
        let context = &fixture.context;
        match command {
            4 => {
                if self
                    .initial
                    .as_ref()
                    .is_some_and(|initial| initial != payload)
                {
                    return Err(DurableError::Conflict);
                }
                let reply = self.owner.respond(
                    Arc::clone(context),
                    payload,
                    &fixture.signer,
                    PqKeySource::from_key(&fixture.prekey),
                    TraditionalKeySource::from_key(&fixture.prekey),
                    fixture.times.bootstrap,
                )?;
                self.initial = Some(payload.to_vec());
                Ok(reply)
            }
            5 => {
                let initial = self.initial.as_deref().ok_or(DurableError::Suspended)?;
                let session = self.owner.finish(
                    Arc::clone(context),
                    initial,
                    payload,
                    fixture.times.bootstrap,
                )?;
                self.session = Some(session);
                Ok(session.to_vec())
            }
            6 if payload.is_empty() => {
                let initial = self.initial.as_deref().ok_or(DurableError::Suspended)?;
                let session = self.owner.activate_responder_messages(
                    Arc::clone(context),
                    initial,
                    fixture.times.bootstrap,
                )?;
                if Some(session) != self.session {
                    return Err(DurableError::Conflict);
                }
                Ok(session.to_vec())
            }
            7 => {
                let (ad, wire) = ad_and_payload(payload)?;
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .receive_message(context, session, wire, ad, fixture.times.traffic)?
                    .as_bytes()
                    .to_vec())
            }
            8 if payload.is_empty() => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .next_message_id(context, session, fixture.times.traffic)?
                    .as_bytes()
                    .to_vec())
            }
            9 => {
                let identity = id(payload.get(..32).ok_or_else(encoding)?)?;
                let (ad, plaintext) = ad_and_payload(payload.get(32..).ok_or_else(encoding)?)?;
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner.send_message(
                    context,
                    session,
                    identity,
                    plaintext,
                    ad,
                    fixture.times.traffic,
                )
            }
            10 => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner.consume_message(
                    context,
                    session,
                    id(payload)?,
                    fixture.times.traffic,
                )?;
                self.owner
                    .message_acknowledgement(context, session, fixture.times.traffic)
            }
            11 => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                Ok(self
                    .owner
                    .accept_message_acknowledgement(
                        context,
                        session,
                        payload,
                        fixture.times.traffic,
                    )?
                    .to_be_bytes()
                    .to_vec())
            }
            12 if payload.is_empty() => {
                self.owner.close();
                self.owner = if let Some(witness) = &fixture.witness {
                    DeviceJournal::open_anchored(
                        &self.path.join("journal"),
                        JournalKey::open(&self.path.join("key"))?,
                        &fixture.responder,
                        fixture.context.current_policy()?,
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
                };
                Ok(b"reopened".to_vec())
            }
            13 if payload.is_empty() => {
                let session = self.session.ok_or(DurableError::Suspended)?;
                self.owner
                    .message_acknowledgement(context, session, fixture.times.traffic)
            }
            14..=23 => self.rekey_command(fixture, command, payload),
            24..=27 => crate::resolution::command(
                &mut self.owner,
                context,
                self.session.ok_or(DurableError::Suspended)?,
                command,
                payload,
                fixture.times.traffic,
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
        let context = &fixture.context;
        let session = self.session.ok_or(DurableError::Suspended)?;
        match command {
            14 => self.owner.respond_rekey_offer(
                context,
                session,
                payload,
                &fixture.signer,
                fixture.times.traffic,
            ),
            15 => self.owner.finish_rekey(
                context,
                session,
                payload,
                &fixture.signer,
                fixture.times.traffic,
            ),
            16 if payload.is_empty() => {
                let progress = self.owner.rekey_progress(context, session)?;
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
            17 if payload.is_empty() => self.owner.prepare_rekey_offer(
                context,
                session,
                &fixture.signer,
                fixture.times.traffic,
            ),
            18 => self.owner.accept_rekey_response(
                context,
                session,
                payload,
                &fixture.signer,
                fixture.times.traffic,
            ),
            19 => Ok(self
                .owner
                .accept_rekey_receipt(context, session, payload, fixture.times.traffic)?
                .to_be_bytes()
                .to_vec()),
            20 => {
                let epoch = u64::from_be_bytes(payload.try_into().map_err(|_| encoding())?);
                self.owner.message_acknowledgement_for_epoch(
                    context,
                    session,
                    epoch,
                    fixture.times.traffic,
                )
            }
            21 => {
                let target = u64::from_be_bytes(payload.try_into().map_err(|_| encoding())?);
                self.owner
                    .advance_rekey_control(
                        context,
                        session,
                        target,
                        &fixture.signer,
                        fixture.times.traffic,
                    )
                    .map(control)
            }
            22 => self
                .owner
                .receive_rekey_control(
                    context,
                    session,
                    payload,
                    &fixture.signer,
                    fixture.times.traffic,
                )
                .map(control),
            23 if payload.is_empty() => Ok(format!(
                "{:?}",
                self.owner.rekey_request_status(context, session)?
            )
            .into_bytes()),
            _ => Err(encoding()),
        }
    }

    pub(super) fn close(mut self) {
        self.owner.close();
    }
}
