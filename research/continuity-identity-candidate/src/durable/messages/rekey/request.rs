// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable non-proposer requests; requests do not attest to settled history.
use super::*;

pub(super) const TAG: &[u8; 8] = b"QPRKRQ01";
const BODY_LEN: usize = 153;
const WIRE_LEN: usize = 4 + BODY_LEN + SIGNATURE_BYTES;

/// Read-only request preparation state, not evidence of peer or fresh-key progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyRequestStatus {
    /// No request is retained for the current target.
    Absent,
    /// The exact purpose/body-bound signature randomness is durably reserved.
    SignatureReserved,
    /// Exact identity-signed request bytes are committed.
    Committed,
}

pub(super) enum Plan {
    Signing(SigningReservation),
    Ready(Vec<u8>),
}
impl Plan {
    pub(super) fn validate(
        &self,
        control: &Control,
        session: &[u8; 32],
        role: u8,
        context: &[u8; 32],
    ) -> Result<(), Error> {
        if role == proposer(control.target()?)? {
            return Err(Error::Scope);
        }
        if let Self::Ready(wire) = self {
            let (body, _) = open_envelope(wire)?;
            if body != prefix(&control.prefix(session, context)?)? {
                return Err(Error::Scope);
            }
        }
        Ok(())
    }
}

pub(super) fn encode(plan: &Option<Plan>, bytes: &mut Zeroizing<Vec<u8>>) {
    match plan {
        None => bytes.push(0),
        Some(Plan::Signing(signing)) => {
            bytes.push(1);
            signing.encode(bytes);
        }
        Some(Plan::Ready(wire)) => {
            bytes.push(2);
            bytes.extend_from_slice(wire);
        }
    }
}
pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Option<Plan>, Error> {
    match d.array()? {
        [0] => Ok(None),
        [1] => Ok(Some(Plan::Signing(SigningReservation::decode(
            d.take(64)?,
        )?))),
        [2] => Ok(Some(Plan::Ready(d.take(WIRE_LEN)?.to_vec()))),
        _ => Err(Error::Encoding),
    }
}

fn prefix(offer: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = offer.get(..BODY_LEN).ok_or(Error::Encoding)?.to_vec();
    if body.get(..8) != Some(super::TAG.as_slice()) {
        return Err(Error::Scope);
    }
    body.get_mut(..8)
        .ok_or(Error::Encoding)?
        .copy_from_slice(TAG);
    let role = body.get_mut(120).ok_or(Error::Encoding)?;
    *role = match *role {
        1 => 2,
        2 => 1,
        _ => return Err(Error::Scope),
    };
    Ok(body)
}

impl DeviceJournal {
    /// Commit the non-proposer's identity-authenticated request for this exact
    /// next epoch. It consumes no application slot and installs no key material.
    pub fn prepare_rekey_request(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if state.role == proposer(state.control.target()?)? {
            return Err(Error::State.into());
        }
        let body = prefix(&state.control.prefix(&session, &context.digest())?)?;
        let key = &device(context, state.role)?.key;
        if let Some(Plan::Ready(wire)) = &state.control.request {
            let (saved, signature) = open_envelope(wire)?;
            if let Err(error) = key.verify(Purpose::RekeyRequest, saved, signature) {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
            self.check_session_context_release(&image, context, now)?;
            return Ok(wire.clone());
        }
        if signer.public_key()? != *key {
            return Err(Error::Scope.into());
        }
        let scope = hash(b"request-sign", &[image.id.as_slice(), &body].concat());
        if state.control.request.is_none() {
            // Once an offer is admitted, its exact response drives this exchange.
            if state.control.plan.is_some() {
                return Err(DurableError::Suspended);
            }
            state.control.request = Some(Plan::Signing(SigningReservation::reserve(
                key,
                &scope,
                Purpose::RekeyRequest,
                &body,
            )?));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::super::tests::after_stage("rekey-request-reserved");
        }
        rosters::authorize_session_context(&image, context, now)?;
        let Some(Plan::Signing(signing)) = &state.control.request else {
            return Err(DurableError::Corrupt);
        };
        let signature = match signing.sign(signer, &scope, Purpose::RekeyRequest, &body) {
            Ok(signature) => signature,
            Err(error @ (Error::Scope | Error::Encoding)) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
            Err(error) => return Err(error.into()),
        };
        let wire = envelope(&body, &signature)?;
        #[cfg(all(test, unix))]
        after_effect("rekey-request-computed", &wire);
        state.control.request = Some(Plan::Ready(wire.clone()));
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::super::tests::after_stage("rekey-request-committed");
        self.check_session_context_release(&image, context, now)?;
        Ok(wire)
    }

    /// Authenticate before any local reservation, then prepare/replay the one
    /// designated offer. A retained completed target only replays its old offer.
    pub fn respond_rekey_request(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        request: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        let (body, signature) = open_envelope(request)?;
        if body.len() != BODY_LEN || body.get(..8) != Some(TAG.as_slice()) {
            return Err(Error::Encoding.into());
        }
        let target = driver::target(body)?;
        if state.role != proposer(target)? {
            return Err(Error::Scope.into());
        }
        // Replaying the last completed target must not require capacity for a
        // further epoch; the counter may already be at its final valid value.
        let expected = if target == state.control.epoch {
            let last = state.control.last.as_ref().ok_or(Error::Scope)?;
            prefix(open_envelope(&last.offer)?.0)?
        } else if target < state.control.epoch {
            return Err(Error::Retired.into());
        } else if target == state.control.target()? {
            prefix(&state.control.prefix(&session, &context.digest())?)?
        } else {
            return Err(Error::Scope.into());
        };
        if body != expected {
            return Err(Error::Scope.into());
        }
        device(context, 3 - state.role)?
            .key
            .verify(Purpose::RekeyRequest, body, signature)?;
        if target == state.control.epoch
            || matches!(state.control.plan, Some(super::Plan::Completing(_)))
        {
            return self.rekey_outbox(context, session, target, RekeyFlight::Offer, now);
        }
        self.prepare_rekey_offer(context, session, signer, now)
    }

    /// Inspect retained request state even after authority loss; grants no release.
    pub fn rekey_request_status(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<RekeyRequestStatus, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(match state.control.request {
            None => RekeyRequestStatus::Absent,
            Some(Plan::Signing(_)) => RekeyRequestStatus::SignatureReserved,
            Some(Plan::Ready(_)) => RekeyRequestStatus::Committed,
        })
    }
}
