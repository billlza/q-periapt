// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact, identity-authenticated first control flight. Preparing an offer does
//! not install an epoch, advance traffic chains, or establish peer confirmation.
use super::*;
use crate::crypto::{envelope, open_envelope, Purpose, SigningReservation, SIGNATURE_BYTES};
use q_periapt_sdk::{
    expert::replay::{RecoveryKey, SealedOperation},
    PublicKey, PUBLIC_KEY_LEN,
};

const TAG: &[u8; 8] = b"QPRKOF01";
const CONTROL_TAG: &[u8; 8] = b"QPRKST01";
const DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/";
const KEY_TOKEN_LEN: usize = 277;
const BODY_LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 1 + 32 + PUBLIC_KEY_LEN;
const WIRE_LEN: usize = 4 + BODY_LEN + SIGNATURE_BYTES;

fn hash(label: &[u8], data: &[u8]) -> [u8; 32] {
    digest(&[DOMAIN, label].concat(), data)
}
fn profile() -> [u8; 32] {
    hash(
        b"offer-profile",
        b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;accountable-epoch-offer/v1",
    )
}
fn genesis(session: &[u8; 32], context: &[u8; 32]) -> [u8; 32] {
    hash(
        b"genesis",
        &[session.as_slice(), context.as_slice()].concat(),
    )
}
fn proposer(epoch: u64) -> Result<u8, Error> {
    crate::codec::generation(epoch)?;
    Ok(if epoch % 2 == 1 { 1 } else { 2 })
}

/// Read-only state of the exact pending rekey offer; none implies peer confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyOfferStatus {
    /// No local offer reservation exists.
    Absent,
    /// Fresh hybrid key-generation randomness is durably reserved.
    KeyReserved,
    /// Exact public body and purpose-bound signature randomness are durable.
    SignatureReserved,
    /// Exact signed public offer is committed and can be conditionally replayed.
    Committed,
}

enum Plan {
    Key(SealedOperation),
    Signing {
        key: SealedOperation,
        body: Vec<u8>,
        signing: SigningReservation,
    },
    Ready {
        key: SealedOperation,
        wire: Vec<u8>,
    },
}
impl Plan {
    fn status(&self) -> RekeyOfferStatus {
        match self {
            Self::Key(_) => RekeyOfferStatus::KeyReserved,
            Self::Signing { .. } => RekeyOfferStatus::SignatureReserved,
            Self::Ready { .. } => RekeyOfferStatus::Committed,
        }
    }
    fn key(&self) -> &SealedOperation {
        match self {
            Self::Key(key) | Self::Signing { key, .. } | Self::Ready { key, .. } => key,
        }
    }
}

pub(super) struct Control {
    epoch: u64,
    parent: [u8; 32],
    plan: Option<Plan>,
}
impl Control {
    pub(super) fn genesis(session: &[u8; 32], context: &[u8; 32]) -> Self {
        Self {
            epoch: 0,
            parent: genesis(session, context),
            plan: None,
        }
    }
    fn target(&self) -> Result<u64, Error> {
        self.epoch
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Capacity)
    }
    fn prefix(&self, session: &[u8; 32], context: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let target = self.target()?;
        let mut out = TAG.to_vec();
        out.extend_from_slice(&profile());
        out.extend_from_slice(context);
        out.extend_from_slice(session);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&target.to_be_bytes());
        out.push(proposer(target)?);
        out.extend_from_slice(&self.parent);
        Ok(out)
    }
    fn scope(
        &self,
        journal: &[u8; 32],
        session: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        Ok(hash(
            b"operation",
            &[journal.as_slice(), &self.prefix(session, context)?].concat(),
        ))
    }
    fn check_body(&self, session: &[u8; 32], context: &[u8; 32], body: &[u8]) -> Result<(), Error> {
        let prefix = self.prefix(session, context)?;
        if body.len() != BODY_LEN || !body.starts_with(&prefix) {
            return Err(Error::Scope);
        }
        PublicKey::from_bytes(body.get(prefix.len()..).ok_or(Error::Encoding)?)?;
        Ok(())
    }
    pub(super) fn validate(
        &self,
        session: &[u8; 32],
        role: u8,
        context: &[u8; 32],
    ) -> Result<(), Error> {
        // Only offer preparation is implemented at this checkpoint. Neither an
        // authenticated image nor a caller can invent a completed epoch.
        if self.epoch != 0 || self.parent != genesis(session, context) {
            return Err(Error::State);
        }
        if let Some(plan) = &self.plan {
            if role != proposer(self.target()?)? {
                return Err(Error::Scope);
            }
            match plan {
                Plan::Key(_) => {}
                Plan::Signing { body, .. } => self.check_body(session, context, body)?,
                Plan::Ready { wire, .. } => {
                    let (body, _) = open_envelope(wire)?;
                    self.check_body(session, context, body)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self, bytes: &mut Zeroizing<Vec<u8>>) {
        bytes.extend_from_slice(CONTROL_TAG);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.parent);
        bytes.push(match &self.plan {
            None => 0,
            Some(Plan::Key(_)) => 1,
            Some(Plan::Signing { .. }) => 2,
            Some(Plan::Ready { .. }) => 3,
        });
        if let Some(plan) = &self.plan {
            bytes.extend_from_slice(plan.key().as_bytes());
            match plan {
                Plan::Key(_) => {}
                Plan::Signing { body, signing, .. } => {
                    bytes.extend_from_slice(body);
                    signing.encode(bytes);
                }
                Plan::Ready { wire, .. } => bytes.extend_from_slice(wire),
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.array::<8>()? != *CONTROL_TAG {
            return Err(Error::Encoding);
        }
        let epoch = d.u64()?;
        let parent = d.array()?;
        let [phase] = d.array()?;
        let plan = match phase {
            0 => None,
            1..=3 => {
                let key = SealedOperation::from_bytes(d.take(KEY_TOKEN_LEN)?)?;
                Some(match phase {
                    1 => Plan::Key(key),
                    2 => Plan::Signing {
                        key,
                        body: d.take(BODY_LEN)?.to_vec(),
                        signing: SigningReservation::decode(d.take(64)?)?,
                    },
                    3 => Plan::Ready {
                        key,
                        wire: d.take(WIRE_LEN)?.to_vec(),
                    },
                    _ => return Err(Error::Encoding),
                })
            }
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            epoch,
            parent,
            plan,
        })
    }
}

fn device(context: &BootstrapContext, role: u8) -> Result<&VerifiedDevice, Error> {
    let [initiator, responder] = context.devices();
    match role {
        1 => Ok(initiator),
        2 => Ok(responder),
        _ => Err(Error::Scope),
    }
}
fn verify_offer(state: &State, context: &BootstrapContext, wire: &[u8]) -> Result<(), Error> {
    let (body, signature) = open_envelope(wire)?;
    state
        .control
        .check_body(&state.session, &context.digest(), body)?;
    device(context, proposer(state.control.target()?)?)?
        .key
        .verify(Purpose::RekeyOffer, body, signature)
}

#[cfg(all(test, unix))]
fn after_effect(stage: &str, public: &[u8]) {
    if std::env::var("QPERIAPT_MESSAGES_STAGE").ok().as_deref() != Some(stage) {
        return;
    }
    let directory = std::env::var_os("QPERIAPT_MESSAGES_CRASH_DIR").expect("owned test path");
    let mut file = std::fs::File::create_new(std::path::Path::new(&directory).join("rekey-effect"))
        .expect("public effect file");
    file.write_all(public).expect("public effect");
    file.sync_all().expect("sync effect");
    super::tests::after_stage(stage);
}

impl DeviceJournal {
    fn store_rekey_offer(&mut self, image: &mut Image, state: &State) -> Result<(), DurableError> {
        image
            .records
            .get_mut(&record_id(&state.session))
            .ok_or(DurableError::Corrupt)?
            .payload = state.encode();
        self.persist(image)
    }
    /// Prepare and commit the exact identity-signed first rekey flight. This
    /// reserves randomness before computation and replays the same bytes after
    /// restart. It does not install traffic keys or report a confirmed epoch.
    pub fn prepare_rekey_offer(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if state.role != proposer(state.control.target()?)? {
            return Err(Error::State.into());
        }
        if let Some(Plan::Ready { wire, .. }) = &state.control.plan {
            if let Err(error) = verify_offer(&state, context, wire) {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
            self.check_context_release(&image, context, now)?;
            return Ok(wire.clone());
        }
        if signer.public_key()? != device(context, state.role)?.key {
            return Err(Error::Scope.into());
        }
        let recovery = RecoveryKey::from_host_key(
            self.active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .key
                .0
                .as_bytes(),
        )
        .map_err(Error::from)?;
        let scope = state
            .control
            .scope(&image.id, &session, &context.digest())?;
        let key_scope = hash(b"key", &scope);
        let sign_scope = hash(b"sign", &scope);
        if state.control.plan.is_none() {
            let key = recovery
                .reserve_key(&context.policy().runtime, &key_scope)
                .map_err(Error::from)?;
            state.control.plan = Some(Plan::Key(key));
            self.store_rekey_offer(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("rekey-key-reserved");
        }
        rosters::authorize_context(&image, context, now)?;
        let key = match recovery.generate_key(
            &context.policy().runtime,
            &key_scope,
            state
                .control
                .plan
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .key(),
        ) {
            Ok(key) => key,
            Err(q_periapt_sdk::Error::InvalidPrivateKey) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(Error::Runtime(
                    q_periapt_sdk::Error::InvalidPrivateKey,
                )));
            }
            Err(error) => return Err(Error::from(error).into()),
        };
        let mut body = state.control.prefix(&session, &context.digest())?;
        body.extend_from_slice(&key.public_key().map_err(Error::from)?.to_bytes());
        drop(key);
        #[cfg(all(test, unix))]
        after_effect("rekey-key-computed", &body);
        if matches!(state.control.plan, Some(Plan::Key(_))) {
            let signing = SigningReservation::reserve(
                &device(context, state.role)?.key,
                &sign_scope,
                Purpose::RekeyOffer,
                &body,
            )?;
            let Some(Plan::Key(key)) = state.control.plan.take() else {
                return Err(DurableError::Corrupt);
            };
            state.control.plan = Some(Plan::Signing {
                key,
                body: body.clone(),
                signing,
            });
            self.store_rekey_offer(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("rekey-signature-reserved");
        }
        rosters::authorize_context(&image, context, now)?;
        let Some(Plan::Signing {
            body: saved,
            signing,
            ..
        }) = &state.control.plan
        else {
            return Err(DurableError::Corrupt);
        };
        if *saved != body {
            self.close();
            return Err(DurableError::Corrupt);
        }
        let signature = match signing.sign(signer, &sign_scope, Purpose::RekeyOffer, &body) {
            Ok(signature) => signature,
            Err(Error::Scope | Error::Encoding) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(Error::Scope));
            }
            Err(error) => return Err(error.into()),
        };
        let wire = envelope(&body, &signature)?;
        #[cfg(all(test, unix))]
        after_effect("rekey-signature-computed", &wire);
        let Some(Plan::Signing { key, .. }) = state.control.plan.take() else {
            return Err(DurableError::Corrupt);
        };
        state.control.plan = Some(Plan::Ready {
            key,
            wire: wire.clone(),
        });
        self.store_rekey_offer(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::tests::after_stage("rekey-offer-committed");
        self.check_context_release(&image, context, now)?;
        Ok(wire)
    }
    /// Inspect the authenticated offer phase after failure or revocation. This
    /// grants no permission to generate, sign, dispatch or advance an epoch.
    pub fn rekey_offer_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<RekeyOfferStatus, DurableError> {
        self.check_policy(context.policy())?;
        let image = self.image()?;
        let record = image
            .records
            .get(&record_id(&session))
            .ok_or(DurableError::Absent)?;
        if record.kind != RecordKind::Messages
            || record.context != context.digest()
            || record.authorities != rosters::context_accounts(context)
        {
            return Err(DurableError::Conflict);
        }
        let state = State::decode(&record.payload)?;
        if bootstrap::storage_owner(device(context, state.role)?) != image.owner {
            return Err(DurableError::Conflict);
        }
        Ok(state
            .control
            .plan
            .as_ref()
            .map_or(RekeyOfferStatus::Absent, Plan::status))
    }
}
