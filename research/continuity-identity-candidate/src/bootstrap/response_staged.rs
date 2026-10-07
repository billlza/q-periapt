// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated responder contribution retained by the encrypted journal.
use super::*;
use crate::crypto::SigningReservation;
use q_periapt_sdk::expert::replay::{RecoveryKey, SealedOperation};
use zeroize::Zeroizing;

pub(crate) const KEM_RESERVED: u8 = 13;
pub(crate) const SIGNATURE_RESERVED: u8 = 14;
pub(crate) const INITIAL_OFFSET: usize = 73;

pub(crate) struct ResponsePlan {
    context: [u8; 32],
    scope: [u8; 32],
    initial: Vec<u8>,
    // Admitted only by real decapsulation + initial MAC validation, or by the
    // authenticated local image. No public raw shared-secret constructor exists.
    first: ZeroizingBytes<32>,
    nonce: [u8; 32],
    kem: SealedOperation,
    signature: Option<(Vec<u8>, SigningReservation)>,
    cached: Option<Schedule>,
}
impl ResponsePlan {
    pub(crate) fn check_signer(
        context: &BootstrapContext,
        signer: &DeviceSigningKey,
    ) -> Result<(), Error> {
        if signer.public_key()? != context.responder.key {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn check_prekeys(
        context: &BootstrapContext,
        pq: PqKeySource<'_>,
        classical: TraditionalKeySource<'_>,
    ) -> Result<(), Error> {
        if expert::component_public_key(&context.current_policy()?.runtime, pq, classical)?
            .to_bytes()
            != context.peer.to_bytes()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn reserve(
        context: &BootstrapContext,
        scope: [u8; 32],
        initial: &[u8],
        pq: PqKeySource<'_>,
        classical: TraditionalKeySource<'_>,
        recovery: &RecoveryKey,
    ) -> Result<Self, Error> {
        // Executing admits only deterministic authentication. No responder KEM
        // or signature executes until the complete next plan commits.
        let (peer, first) = authenticate_initial(context, initial, pq, classical)?;
        let nonce = nonce()?;
        let prefix = response_prefix(context, initial, &nonce);
        let kem = recovery.reserve_encapsulation(
            &context.current_policy()?.runtime,
            &hash(b"durable-reply-kem", &scope),
            &peer,
            &hash(b"kem-reply", &prefix),
        )?;
        Ok(Self {
            context: context.digest,
            scope,
            initial: initial.to_vec(),
            first: first.export_for_protocol()?,
            nonce,
            kem,
            signature: None,
            cached: None,
        })
    }
    pub(crate) fn phase(&self) -> u8 {
        if self.signature.is_some() {
            SIGNATURE_RESERVED
        } else {
            KEM_RESERVED
        }
    }
    fn check(&self, context: &BootstrapContext, scope: &[u8; 32]) -> Result<(), Error> {
        if self.context != context.digest || self.scope != *scope {
            return Err(Error::Scope);
        }
        context.validate_initial_signature(&self.initial)
    }
    fn compute(
        &self,
        context: &BootstrapContext,
        recovery: &RecoveryKey,
    ) -> Result<(Vec<u8>, Schedule), Error> {
        let (initial, _) = open_envelope(&self.initial)?;
        let peer = PublicKey::from_bytes(initial.get(72..INITIAL_PREFIX).ok_or(Error::Encoding)?)?;
        let prefix = response_prefix(context, &self.initial, &self.nonce);
        let result = recovery.encapsulate(
            &context.current_policy()?.runtime,
            &hash(b"durable-reply-kem", &self.scope),
            &peer,
            &hash(b"kem-reply", &prefix),
            &self.kem,
        )?;
        response_body(prefix, &self.first, result)
    }
    pub(crate) fn advance(
        mut self,
        context: &BootstrapContext,
        scope: &[u8; 32],
        recovery: &RecoveryKey,
    ) -> Result<Self, Error> {
        self.check(context, scope)?;
        if self.signature.is_some() {
            return Err(Error::State);
        }
        let (body, keys) = self.compute(context, recovery)?;
        let reservation = SigningReservation::reserve(
            &context.responder.key,
            &hash(b"durable-reply-sign", &self.scope),
            Purpose::BootstrapResponder,
            &body,
        )?;
        self.signature = Some((body, reservation));
        self.cached = Some(keys);
        Ok(self)
    }
    pub(crate) fn complete(
        mut self,
        context: Arc<BootstrapContext>,
        scope: &[u8; 32],
        recovery: &RecoveryKey,
        signer: &DeviceSigningKey,
    ) -> Result<ResponderOperation, Error> {
        self.check(&context, scope)?;
        Self::check_signer(&context, signer)?;
        let (body, reservation) = self.signature.as_ref().ok_or(Error::State)?;
        let keys = if let Some(keys) = self.cached.take() {
            keys
        } else {
            let (expected, keys) = self.compute(&context, recovery)?;
            if expected != *body {
                return Err(Error::Conflict);
            }
            keys
        };
        let signature = reservation.sign(
            signer,
            &hash(b"durable-reply-sign", &self.scope),
            Purpose::BootstrapResponder,
            body,
        )?;
        let prepared = prepared_response(&context, &self.initial, body, &signature, keys)?;
        Ok(ResponderOperation {
            context,
            state: ResponderState::Prepared(Box::new(prepared)),
        })
    }
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"QPRPLN01".to_vec());
        bytes.push(self.phase());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&self.initial);
        bytes.extend_from_slice(self.first.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(self.kem.as_bytes());
        if let Some((body, reservation)) = &self.signature {
            bytes.extend_from_slice(body);
            reservation.encode(&mut bytes);
        }
        bytes
    }
    pub(crate) fn decode(
        context: &[u8; 32],
        scope: &[u8; 32],
        phase: u8,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPRPLN01"
            || d.array::<1>()? != [phase]
            || d.array::<32>()? != *context
            || d.array::<32>()? != *scope
        {
            return Err(Error::Scope);
        }
        let initial = d.take(5817)?.to_vec();
        let mut first = ZeroizingBytes::zeroed();
        first.as_mut_bytes().copy_from_slice(d.take(32)?);
        let nonce = d.array()?;
        let kem = SealedOperation::from_bytes(d.take(245)?)?;
        let signature = match phase {
            KEM_RESERVED => None,
            SIGNATURE_RESERVED => {
                let body = d.take(REPLY_CORE + 32)?.to_vec();
                let mut expected = prefix(REPLY_TAG, context);
                expected.extend_from_slice(&hash(b"initial-wire", &initial));
                expected.extend_from_slice(&nonce);
                if body.get(..REPLY_PREFIX) != Some(expected.as_slice()) {
                    return Err(Error::Scope);
                }
                Some((body, SigningReservation::decode(d.take(64)?)?))
            }
            _ => return Err(Error::State),
        };
        d.finish()?;
        Ok(Self {
            context: *context,
            scope: *scope,
            initial,
            first,
            nonce,
            kem,
            signature,
            cached: None,
        })
    }
    #[cfg(all(test, unix))]
    pub(crate) fn public_effect(&self) -> Result<&[u8], Error> {
        self.signature
            .as_ref()
            .map(|(body, _)| body.as_slice())
            .ok_or(Error::State)
    }
}
