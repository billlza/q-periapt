// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Private initiator computation plan; only the authenticated journal restores it.
use super::*;
use crate::crypto::SigningReservation;
use q_periapt_sdk::expert::replay::{RecoveryKey, SealedOperation};
use zeroize::Zeroizing;

pub(crate) const KEY_RESERVED: u8 = 10;
pub(crate) const KEM_RESERVED: u8 = 11;
pub(crate) const SIGNATURE_RESERVED: u8 = 12;

enum Cached {
    Key(HybridKey),
    Complete(HybridKey, ZeroizingBytes<32>),
}

pub(crate) struct InitiationPlan {
    context: [u8; 32],
    scope: [u8; 32],
    nonce: [u8; 32],
    key: SealedOperation,
    kem: Option<SealedOperation>,
    signature: Option<(Vec<u8>, SigningReservation)>,
    // Volatile acceleration only. Restoring a plan reconstructs the same values
    // from its sealed, committed command; no raw key is cached outside this owner.
    cached: Option<Cached>,
}
impl InitiationPlan {
    pub(crate) fn check_signer(
        context: &BootstrapContext,
        signer: &DeviceSigningKey,
    ) -> Result<(), Error> {
        if signer.public_key()? != context.initiator.key {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn reserve(
        context: &BootstrapContext,
        scope: [u8; 32],
        recovery: &RecoveryKey,
    ) -> Result<Self, Error> {
        let key = recovery.reserve_key(
            &context.current_policy()?.runtime,
            &hash(b"durable-initial-key", &scope),
        )?;
        Ok(Self {
            context: context.digest,
            scope,
            nonce: nonce()?,
            key,
            kem: None,
            signature: None,
            cached: None,
        })
    }
    pub(crate) fn phase(&self) -> u8 {
        if self.signature.is_some() {
            SIGNATURE_RESERVED
        } else if self.kem.is_some() {
            KEM_RESERVED
        } else {
            KEY_RESERVED
        }
    }
    fn check(&self, context: &BootstrapContext, scope: &[u8; 32]) -> Result<(), Error> {
        if self.context != context.digest || self.scope != *scope {
            return Err(Error::Scope);
        }
        Ok(())
    }
    fn key(
        &mut self,
        context: &BootstrapContext,
        recovery: &RecoveryKey,
    ) -> Result<HybridKey, Error> {
        match self.cached.take() {
            Some(Cached::Key(key)) => Ok(key),
            None => Ok(recovery.generate_key(
                &context.current_policy()?.runtime,
                &hash(b"durable-initial-key", &self.scope),
                &self.key,
            )?),
            Some(Cached::Complete(_, _)) => Err(Error::State),
        }
    }
    fn compute(
        &self,
        context: &BootstrapContext,
        recovery: &RecoveryKey,
        key: &HybridKey,
    ) -> Result<(Vec<u8>, ZeroizingBytes<32>), Error> {
        let body = initial_prefix(context, key, &self.nonce)?;
        let result = recovery.encapsulate(
            &context.current_policy()?.runtime,
            &hash(b"durable-initial-kem", &self.scope),
            &context.peer,
            &hash(b"kem-initial", &body),
            self.kem.as_ref().ok_or(Error::State)?,
        )?;
        initial_body(body, result)
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
        let key = self.key(context, recovery)?;
        if self.kem.is_none() {
            let prefix = initial_prefix(context, &key, &self.nonce)?;
            self.kem = Some(recovery.reserve_encapsulation(
                &context.current_policy()?.runtime,
                &hash(b"durable-initial-kem", &self.scope),
                &context.peer,
                &hash(b"kem-initial", &prefix),
            )?);
            self.cached = Some(Cached::Key(key));
        } else {
            let (body, first) = self.compute(context, recovery, &key)?;
            let reservation = SigningReservation::reserve(
                &context.initiator.key,
                &hash(b"durable-initial-sign", &self.scope),
                Purpose::BootstrapInitiator,
                &body,
            )?;
            self.signature = Some((body, reservation));
            self.cached = Some(Cached::Complete(key, first));
        }
        Ok(self)
    }
    pub(crate) fn complete(
        mut self,
        context: Arc<BootstrapContext>,
        scope: &[u8; 32],
        recovery: &RecoveryKey,
        signer: &DeviceSigningKey,
    ) -> Result<InitiatorOperation, Error> {
        self.check(&context, scope)?;
        Self::check_signer(&context, signer)?;
        let (body, reservation) = self.signature.as_ref().ok_or(Error::State)?;
        let (key, first) = match self.cached.take() {
            Some(Cached::Complete(key, first)) => (key, first),
            None => {
                let key = recovery.generate_key(
                    &context.current_policy()?.runtime,
                    &hash(b"durable-initial-key", &self.scope),
                    &self.key,
                )?;
                let (expected, first) = self.compute(&context, recovery, &key)?;
                if expected != *body {
                    return Err(Error::Conflict);
                }
                (key, first)
            }
            Some(Cached::Key(_)) => return Err(Error::State),
        };
        let signature = reservation.sign(
            signer,
            &hash(b"durable-initial-sign", &self.scope),
            Purpose::BootstrapInitiator,
            body,
        )?;
        InitiatorOperation::from_initial(context, key, body.clone(), first, &signature)
    }
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"QPIPLN01".to_vec());
        bytes.push(self.phase());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(self.key.as_bytes());
        if let Some(kem) = &self.kem {
            bytes.extend_from_slice(kem.as_bytes());
        }
        if let Some((body, signature)) = &self.signature {
            bytes.extend_from_slice(body);
            signature.encode(&mut bytes);
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
        if d.array::<8>()? != *b"QPIPLN01"
            || d.array::<1>()? != [phase]
            || d.array::<32>()? != *context
            || d.array::<32>()? != *scope
        {
            return Err(Error::Scope);
        }
        let nonce = d.array()?;
        let key = SealedOperation::from_bytes(d.take(277)?)?;
        let kem = match phase {
            KEY_RESERVED => None,
            KEM_RESERVED | SIGNATURE_RESERVED => Some(SealedOperation::from_bytes(d.take(245)?)?),
            _ => return Err(Error::State),
        };
        let signature = if phase == SIGNATURE_RESERVED {
            let body = d.take(INITIAL_CORE + 32)?.to_vec();
            if body.get(..8) != Some(INITIAL_TAG.as_slice())
                || body.get(8..40) != Some(context.as_slice())
            {
                return Err(Error::Scope);
            }
            Some((body, SigningReservation::decode(d.take(64)?)?))
        } else {
            None
        };
        d.finish()?;
        Ok(Self {
            context: *context,
            scope: *scope,
            nonce,
            key,
            kem,
            signature,
            cached: None,
        })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn public_effect(&self) -> Result<Vec<u8>, Error> {
        match (&self.cached, &self.signature) {
            (_, Some((body, _))) => Ok(body.clone()),
            (Some(Cached::Key(key)), None) => Ok(key.public_key()?.to_bytes().to_vec()),
            _ => Err(Error::State),
        }
    }
}
