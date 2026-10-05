// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact identity-authenticated offer and response preparation. These flights
//! are completed by signed, journal-owned epoch cutovers.
use super::*;
use crate::crypto::{envelope, open_envelope, Purpose, SigningReservation, SIGNATURE_BYTES};
use q_periapt_sdk::{
    expert::replay::{RecoveryKey, SealedOperation},
    PublicKey, PUBLIC_KEY_LEN,
};
mod completion;
mod driver;
mod request;
mod response;
pub use completion::{RekeyFlight, RekeyProgress};
pub use driver::{RekeyControlMessage, RekeyControlStep};
pub use request::RekeyRequestStatus;
pub use response::RekeyResponseStatus;

const TAG: &[u8; 8] = b"QPRKOF01";
const CONTROL_TAG: &[u8; 8] = b"QPRKST03";
use crate::contract::REKEY_DOMAIN as DOMAIN;
const KEY_TOKEN_LEN: usize = 277;
const BODY_LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 1 + 32 + PUBLIC_KEY_LEN;
const WIRE_LEN: usize = 4 + BODY_LEN + SIGNATURE_BYTES;

fn hash(label: &[u8], data: &[u8]) -> [u8; 32] {
    digest(&[DOMAIN, label].concat(), data)
}
fn profile() -> [u8; 32] {
    crate::contract::rekey_profile_digest()
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
    Response(response::Plan),
    Completing(completion::Plan),
}
impl Plan {
    fn status(&self) -> RekeyOfferStatus {
        match self {
            Self::Key(_) => RekeyOfferStatus::KeyReserved,
            Self::Signing { .. } => RekeyOfferStatus::SignatureReserved,
            Self::Ready { .. } => RekeyOfferStatus::Committed,
            Self::Response(_) => RekeyOfferStatus::Absent,
            Self::Completing(plan) => plan.offer_status(),
        }
    }
    fn key(&self) -> Result<&SealedOperation, Error> {
        match self {
            Self::Key(key) | Self::Signing { key, .. } | Self::Ready { key, .. } => Ok(key),
            Self::Response(_) | Self::Completing(_) => Err(Error::State),
        }
    }
}

pub(super) struct Control {
    epoch: u64,
    parent: [u8; 32],
    plan: Option<Plan>,
    last: Option<completion::Completed>,
    request: Option<request::Plan>,
}
impl Control {
    pub(super) fn confirmed_epoch(&self) -> u64 {
        self.epoch
    }
    pub(super) fn genesis(session: &[u8; 32], context: &[u8; 32]) -> Self {
        Self {
            epoch: 0,
            parent: genesis(session, context),
            plan: None,
            last: None,
            request: None,
        }
    }
    pub(super) fn send_fenced(&self) -> bool {
        matches!(&self.plan, Some(Plan::Completing(plan)) if plan.send_fenced())
    }
    pub(super) fn has_pending(&self) -> bool {
        self.plan.is_some()
    }
    pub(super) fn pending_epoch(&self) -> Result<Option<u64>, Error> {
        if self.plan.is_some() || self.request.is_some() {
            Ok(Some(self.target()?))
        } else {
            Ok(None)
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
        root: &ZeroizingBytes<32>,
    ) -> Result<(), Error> {
        if let Some(request) = &self.request {
            request.validate(self, session, role, context)?;
        }
        match (self.epoch, &self.last) {
            (0, None) if self.parent == genesis(session, context) => {}
            (epoch, Some(last)) if epoch != 0 => {
                last.validate(session, context, epoch)?;
                if self.parent != last.digest() {
                    return Err(Error::Scope);
                }
            }
            _ => return Err(Error::State),
        }
        if let Some(plan) = &self.plan {
            if let Plan::Completing(completing) = plan {
                return completing.validate(self, session, role, context, root);
            }
            if let Plan::Response(response) = plan {
                if role == proposer(self.target()?)? {
                    return Err(Error::Scope);
                }
                return response.validate(self, session, context);
            }
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
                Plan::Response(_) | Plan::Completing(_) => return Err(Error::State),
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self, bytes: &mut Zeroizing<Vec<u8>>) {
        bytes.extend_from_slice(CONTROL_TAG);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.parent);
        bytes.push(u8::from(self.last.is_some()));
        if let Some(last) = &self.last {
            last.encode(bytes);
        }
        request::encode(&self.request, bytes);
        bytes.push(match &self.plan {
            None => 0,
            Some(Plan::Key(_)) => 1,
            Some(Plan::Signing { .. }) => 2,
            Some(Plan::Ready { .. }) => 3,
            Some(Plan::Response(response)) => response.phase(),
            Some(Plan::Completing(plan)) => plan.phase(),
        });
        if let Some(plan) = &self.plan {
            match plan {
                Plan::Key(key) => bytes.extend_from_slice(key.as_bytes()),
                Plan::Signing { key, body, signing } => {
                    bytes.extend_from_slice(key.as_bytes());
                    bytes.extend_from_slice(body);
                    signing.encode(bytes);
                }
                Plan::Ready { key, wire } => {
                    bytes.extend_from_slice(key.as_bytes());
                    bytes.extend_from_slice(wire);
                }
                Plan::Response(response) => response.encode(bytes),
                Plan::Completing(plan) => plan.encode(bytes),
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.array::<8>()? != *CONTROL_TAG {
            return Err(Error::Encoding);
        }
        let epoch = d.u64()?;
        let parent = d.array()?;
        let last = match d.array::<1>()? {
            [0] => None,
            [1] => Some(completion::Completed::decode(d)?),
            _ => return Err(Error::Encoding),
        };
        let request = request::decode(d)?;
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
            4..=6 => Some(Plan::Response(response::Plan::decode(d, phase)?)),
            7..=9 => Some(Plan::Completing(completion::Plan::decode(d, phase)?)),
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            epoch,
            parent,
            plan,
            last,
            request,
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
        if matches!(state.control.plan, Some(Plan::Completing(_))) {
            return Err(DurableError::Suspended);
        }
        if let Some(Plan::Ready { wire, .. }) = &state.control.plan {
            if let Err(error) = verify_offer(&state, context, wire) {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
            self.check_session_context_release(&image, context, now)?;
            return Ok(wire.clone());
        }
        if signer.public_key()? != device(context, state.role)?.key {
            return Err(Error::Scope.into());
        }
        state.admit_history_retirement()?;
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
                .reserve_key(&context.current_policy()?.runtime, &key_scope)
                .map_err(Error::from)?;
            state.control.plan = Some(Plan::Key(key));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("rekey-key-reserved");
        }
        rosters::authorize_session_context(&image, context, now)?;
        let key = match recovery.generate_key(
            &context.current_policy()?.runtime,
            &key_scope,
            state
                .control
                .plan
                .as_ref()
                .ok_or(DurableError::Corrupt)?
                .key()?,
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
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("rekey-signature-reserved");
        }
        rosters::authorize_session_context(&image, context, now)?;
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
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::tests::after_stage("rekey-offer-committed");
        self.check_session_context_release(&image, context, now)?;
        Ok(wire)
    }
    /// Inspect the authenticated offer phase after failure or revocation. This
    /// grants no permission to generate, sign, dispatch or advance an epoch.
    pub fn rekey_offer_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<RekeyOfferStatus, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(state
            .control
            .plan
            .as_ref()
            .map_or(RekeyOfferStatus::Absent, Plan::status))
    }
}
