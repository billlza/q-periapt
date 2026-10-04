// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact responder contribution, pending final confirmation and epoch installation.
use super::*;
use hmac::{Hmac, Mac};
use q_periapt_sdk::{Ciphertext, CIPHERTEXT_LEN};

pub(super) const TAG: &[u8; 8] = b"QPRKRP01";
const TOKEN_LEN: usize = 245;
pub(super) const PREFIX_LEN: usize = BODY_LEN - PUBLIC_KEY_LEN + 32;
pub(super) const CORE_LEN: usize = PREFIX_LEN + CIPHERTEXT_LEN;
pub(super) const RESPONSE_BODY_LEN: usize = CORE_LEN + 32;
pub(super) const RESPONSE_WIRE_LEN: usize = 4 + RESPONSE_BODY_LEN + SIGNATURE_BYTES;

/// Local preparation state; a committed response is not a confirmed new epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyResponseStatus {
    /// No remote-offer response reservation exists.
    Absent,
    /// The exact authenticated offer and encapsulation randomness are durable.
    EncapsulationReserved,
    /// The computed ciphertext, pending root and signature reservation are durable.
    SignatureReserved,
    /// The exact signed response is durable and may be conditionally replayed.
    Committed,
}

pub(super) enum Stage {
    Encapsulation(SealedOperation),
    Signing {
        body: Vec<u8>,
        root: ZeroizingBytes<32>,
        signing: SigningReservation,
    },
    Ready {
        wire: Vec<u8>,
        root: ZeroizingBytes<32>,
    },
}
pub(super) struct Plan {
    pub(super) offer: Vec<u8>,
    pub(super) stage: Stage,
}
impl Plan {
    pub(super) fn phase(&self) -> u8 {
        match self.stage {
            Stage::Encapsulation(_) => 4,
            Stage::Signing { .. } => 5,
            Stage::Ready { .. } => 6,
        }
    }
    fn status(&self) -> RekeyResponseStatus {
        match self.stage {
            Stage::Encapsulation(_) => RekeyResponseStatus::EncapsulationReserved,
            Stage::Signing { .. } => RekeyResponseStatus::SignatureReserved,
            Stage::Ready { .. } => RekeyResponseStatus::Committed,
        }
    }
    pub(super) fn validate(
        &self,
        control: &Control,
        session: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<(), Error> {
        let (offer_body, _) = open_envelope(&self.offer)?;
        control.check_body(session, context, offer_body)?;
        let prefix = prefix(control, session, context, &self.offer)?;
        match &self.stage {
            Stage::Encapsulation(_) => Ok(()),
            Stage::Signing { body, root, .. } => check_body(&prefix, body, root),
            Stage::Ready { wire, root } => {
                let (body, _) = open_envelope(wire)?;
                check_body(&prefix, body, root)
            }
        }
    }
    pub(super) fn encode(&self, bytes: &mut Zeroizing<Vec<u8>>) {
        bytes.extend_from_slice(&self.offer);
        match &self.stage {
            Stage::Encapsulation(token) => bytes.extend_from_slice(token.as_bytes()),
            Stage::Signing {
                body,
                root,
                signing,
            } => {
                bytes.extend_from_slice(body);
                bytes.extend_from_slice(root.as_bytes());
                signing.encode(bytes);
            }
            Stage::Ready { wire, root } => {
                bytes.extend_from_slice(wire);
                bytes.extend_from_slice(root.as_bytes());
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>, phase: u8) -> Result<Self, Error> {
        let offer = d.take(WIRE_LEN)?.to_vec();
        let stage = match phase {
            4 => Stage::Encapsulation(SealedOperation::from_bytes(d.take(TOKEN_LEN)?)?),
            5 => Stage::Signing {
                body: d.take(RESPONSE_BODY_LEN)?.to_vec(),
                root: key(d.take(32)?)?,
                signing: SigningReservation::decode(d.take(64)?)?,
            },
            6 => Stage::Ready {
                wire: d.take(RESPONSE_WIRE_LEN)?.to_vec(),
                root: key(d.take(32)?)?,
            },
            _ => return Err(Error::Encoding),
        };
        Ok(Self { offer, stage })
    }
}

pub(super) fn prefix(
    control: &Control,
    session: &[u8; 32],
    context: &[u8; 32],
    offer: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut bytes = TAG.to_vec();
    bytes.extend_from_slice(&profile());
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(&control.epoch.to_be_bytes());
    bytes.extend_from_slice(&control.target()?.to_be_bytes());
    bytes.push(3 - proposer(control.target()?)?);
    bytes.extend_from_slice(&control.parent);
    bytes.extend_from_slice(&hash(b"offer-wire", offer));
    Ok(bytes)
}
pub(super) fn kem_context(offer: &[u8]) -> [u8; 32] {
    hash(b"response-kem", offer)
}
pub(super) fn derive_root(
    previous: &ZeroizingBytes<32>,
    shared: &ZeroizingBytes<32>,
    core: &[u8],
) -> Result<ZeroizingBytes<32>, Error> {
    let mut info = [DOMAIN, b"pending-root/HKDF-SHA256/"].concat();
    info.extend_from_slice(&hash(b"response-core", core));
    let mut root = ZeroizingBytes::zeroed();
    Hkdf::<Sha256>::new(Some(previous.as_bytes()), shared.as_bytes())
        .expand(&info, root.as_mut_bytes())
        .map_err(|_| Error::Provider)?;
    Ok(root)
}
fn confirmation(root: &ZeroizingBytes<32>, core: &[u8]) -> Result<Hmac<Sha256>, Error> {
    let mut secret = ZeroizingBytes::<32>::zeroed();
    Hkdf::<Sha256>::new(None, root.as_bytes())
        .expand(
            &[DOMAIN, b"responder-confirmation"].concat(),
            secret.as_mut_bytes(),
        )
        .map_err(|_| Error::Provider)?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::Provider)?;
    mac.update(&hash(b"response-core", core));
    Ok(mac)
}
pub(super) fn check_body(
    prefix: &[u8],
    body: &[u8],
    root: &ZeroizingBytes<32>,
) -> Result<(), Error> {
    if body.len() != RESPONSE_BODY_LEN || !body.starts_with(prefix) {
        return Err(Error::Scope);
    }
    Ciphertext::from_bytes(body.get(PREFIX_LEN..CORE_LEN).ok_or(Error::Encoding)?)?;
    let (core, tag) = body.split_at(CORE_LEN);
    confirmation(root, core)?
        .verify_slice(tag)
        .map_err(|_| Error::Authentication)
}

impl DeviceJournal {
    /// Authenticate a peer offer, durably reserve its hybrid encapsulation and
    /// signing plan, and return only the exact committed response. This does not
    /// install traffic keys or report the target epoch as confirmed.
    pub fn respond_rekey_offer(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        offer: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if let Some(last) = &state.control.last {
            if last.offer == offer && state.role == 3 - proposer(state.control.epoch)? {
                self.check_completed(context, last)?;
                self.check_session_context_release(&image, context, now)?;
                return Ok(last.response.clone());
            }
        }
        if state.role == proposer(state.control.target()?)? {
            return Err(Error::State.into());
        }
        // Authenticate before any entropy reservation or persistent mutation.
        verify_offer(&state, context, offer)?;
        if let Some(super::Plan::Completing(plan)) = &state.control.plan {
            let (saved_offer, saved_response) = plan.inputs();
            if saved_offer != offer {
                return Err(DurableError::Conflict);
            }
            self.check_session_context_release(&image, context, now)?;
            return Ok(saved_response.to_vec());
        }
        if let Some(super::Plan::Response(saved)) = &state.control.plan {
            if saved.offer != offer {
                return Err(DurableError::Conflict);
            }
            if let Stage::Ready { wire, .. } = &saved.stage {
                let (body, signature) = open_envelope(wire)?;
                if let Err(error) =
                    device(context, state.role)?
                        .key
                        .verify(Purpose::RekeyResponse, body, signature)
                {
                    self.close();
                    return Err(DurableError::InvalidCheckpoint(error));
                }
                self.check_session_context_release(&image, context, now)?;
                return Ok(wire.clone());
            }
        }
        if signer.public_key()? != device(context, state.role)?.key {
            return Err(Error::Scope.into());
        }
        state.admit_history_retirement()?;
        let scope = hash(
            b"response-operation",
            &[
                image.id.as_slice(),
                &state
                    .control
                    .scope(&image.id, &session, &context.digest())?,
                &hash(b"offer-wire", offer),
            ]
            .concat(),
        );
        let signing_scope = hash(b"response-sign", &scope);
        if state.control.plan.is_none() {
            let recovery = self.rekey_recovery_key()?;
            let (offer_body, _) = open_envelope(offer)?;
            let peer = PublicKey::from_bytes(
                offer_body
                    .get(BODY_LEN - PUBLIC_KEY_LEN..)
                    .ok_or(Error::Encoding)?,
            )
            .map_err(Error::from)?;
            let reservation = recovery
                .reserve_encapsulation(
                    &context.policy().runtime,
                    &scope,
                    &peer,
                    &kem_context(offer),
                )
                .map_err(Error::from)?;
            state.control.plan = Some(super::Plan::Response(Plan {
                offer: offer.to_vec(),
                stage: Stage::Encapsulation(reservation),
            }));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::super::tests::after_stage("rekey-response-kem-reserved");
        }
        rosters::authorize_session_context(&image, context, now)?;
        let Some(super::Plan::Response(plan)) = &mut state.control.plan else {
            return Err(DurableError::Corrupt);
        };
        if let Stage::Encapsulation(token) = &plan.stage {
            let recovery = self.rekey_recovery_key()?;
            let (offer_body, _) = open_envelope(offer)?;
            let peer = PublicKey::from_bytes(
                offer_body
                    .get(BODY_LEN - PUBLIC_KEY_LEN..)
                    .ok_or(Error::Encoding)?,
            )
            .map_err(Error::from)?;
            let result = match recovery.encapsulate(
                &context.policy().runtime,
                &scope,
                &peer,
                &kem_context(offer),
                token,
            ) {
                Ok(result) => result,
                Err(q_periapt_sdk::Error::InvalidPrivateKey) => {
                    self.close();
                    return Err(DurableError::InvalidCheckpoint(Error::Runtime(
                        q_periapt_sdk::Error::InvalidPrivateKey,
                    )));
                }
                Err(error) => return Err(Error::from(error).into()),
            };
            // End the mutable plan borrow before binding the immutable control.
            let mut body = prefix(&state.control, &session, &context.digest(), offer)?;
            body.extend_from_slice(&result.ciphertext.to_bytes());
            let root = derive_root(
                &state.rekey,
                &result.secret.export_for_protocol().map_err(Error::from)?,
                &body,
            )?;
            let tag = confirmation(&root, &body)?.finalize().into_bytes();
            body.extend_from_slice(&tag);
            #[cfg(all(test, unix))]
            after_effect("rekey-response-kem-computed", &body);
            let signing = SigningReservation::reserve(
                &device(context, state.role)?.key,
                &signing_scope,
                Purpose::RekeyResponse,
                &body,
            )?;
            state.control.plan = Some(super::Plan::Response(Plan {
                offer: offer.to_vec(),
                stage: Stage::Signing {
                    body,
                    root,
                    signing,
                },
            }));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::super::tests::after_stage("rekey-response-signature-reserved");
        }
        rosters::authorize_session_context(&image, context, now)?;
        let Some(super::Plan::Response(plan)) = &mut state.control.plan else {
            return Err(DurableError::Corrupt);
        };
        let Stage::Signing { body, signing, .. } = &plan.stage else {
            return Err(DurableError::Corrupt);
        };
        let signature = match signing.sign(signer, &signing_scope, Purpose::RekeyResponse, body) {
            Ok(signature) => signature,
            Err(error @ (Error::Scope | Error::Encoding)) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
            Err(error) => return Err(error.into()),
        };
        let wire = envelope(body, &signature)?;
        #[cfg(all(test, unix))]
        after_effect("rekey-response-signature-computed", &wire);
        let Some(super::Plan::Response(Plan {
            offer,
            stage: Stage::Signing { root, .. },
        })) = state.control.plan.take()
        else {
            return Err(DurableError::Corrupt);
        };
        state.control.plan = Some(super::Plan::Response(Plan {
            offer,
            stage: Stage::Ready {
                wire: wire.clone(),
                root,
            },
        }));
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::super::tests::after_stage("rekey-response-committed");
        self.check_session_context_release(&image, context, now)?;
        Ok(wire)
    }
    pub(super) fn rekey_recovery_key(&self) -> Result<RecoveryKey, DurableError> {
        RecoveryKey::from_host_key(
            self.active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .key
                .0
                .as_bytes(),
        )
        .map_err(|error| Error::from(error).into())
    }
    /// Inspect the authenticated pending response after failure or revocation;
    /// this grants no permission to release bytes or advance the epoch.
    pub fn rekey_response_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<RekeyResponseStatus, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(match state.control.plan {
            Some(super::Plan::Response(response)) => response.status(),
            Some(super::Plan::Completing(plan)) => plan.response_status(),
            _ => RekeyResponseStatus::Absent,
        })
    }
}
