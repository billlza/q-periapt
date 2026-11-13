// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test-only classical-component disclosure; never part of a product build.
use super::*;
use p256::ecdsa::signature::{
    rand_core::{TryCryptoRng, TryRng},
    RandomizedSigner,
};

struct SystemRandom;
impl TryRng for SystemRandom {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(bytes)
    }
}
impl TryCryptoRng for SystemRandom {}

// Give the experiment only the fixture's classical signing component.
pub(crate) fn capture_classical(key: &DeviceSigningKey) -> Result<SigningKey, Error> {
    Ok(key
        .0
        .as_ref()
        .ok_or(Error::Closed)?
        .classic
        .as_ref()
        .clone())
}

pub(crate) fn sign_classical_only(
    classic: &SigningKey,
    purpose: Purpose,
    body: &[u8],
) -> Result<[u8; CLASSIC_SIGNATURE_BYTES], Error> {
    let message = signed_message(purpose, body)?;
    let signature: Signature = classic
        .try_sign_with_rng(&mut SystemRandom, &message)
        .map_err(|_| Error::Provider)?;
    let mut bytes = [0; CLASSIC_SIGNATURE_BYTES];
    bytes.copy_from_slice(&signature.normalize_s().to_bytes());
    Ok(bytes)
}
