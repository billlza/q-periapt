// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{codec::Decoder, Error};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use q_periapt_backends::{
    MlDsa65, ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN,
};
use q_periapt_core::ZeroizingBytes;
use sha3::{Digest, Sha3_256};
use std::fmt;
use zeroize::Zeroize;

mod persistence;
pub(crate) use persistence::retirement::SigningFilePlan;
#[cfg(all(test, unix))]
pub(crate) use persistence::retirement::{
    inject as inject_signer_io, IoFault as SignerIoFault, IoStage as SignerIoStage,
};
pub use persistence::SigningKeyId;

const CLASSIC_PUBLIC_BYTES: usize = 33;
const CLASSIC_SIGNATURE_BYTES: usize = 64;
/// Exact ML-DSA-65 public key followed by a compressed SEC1 P-256 public key.
pub const PUBLIC_KEY_BYTES: usize = ML_DSA_65_VK_LEN + CLASSIC_PUBLIC_BYTES;
pub(crate) const SIGNATURE_BYTES: usize = ML_DSA_65_SIG_LEN + CLASSIC_SIGNATURE_BYTES;
pub(crate) use crate::contract::MAX_SIGNED_BODY_BYTES;
use crate::contract::SIGNATURE_CONTEXT;

#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    Credential = 1,
    Roster = 2,
    Manifest = 3,
    SessionPolicy = 4,
    BootstrapInitiator = 5,
    BootstrapResponder = 6,
    AnchorRequest = 7,
    AnchorReply = 8,
    RekeyOffer = 9,
    RekeyResponse = 10,
    RekeyFinal = 11,
    RekeyReceipt = 12,
    RekeyRequest = 13,
    EnrollmentRequest = 14,
    CredentialRenewal = 15,
    PolicyContinuation = 16,
    PolicyRenewal = 17,
    AnchorRetirement = 18,
    AnchorRetiredCleanup = 19,
    AnchorRetiredReport = 20,
    AnchorRetiredReportAcknowledgement = 21,
    AnchorAccountRetirement = 22,
    AnchorAccountFreeze = 23,
    AnchorAccountReplacementClosure = 24,
    AnchorAccountPreparationClosure = 25,
}

/// Public verification keys for the fixed two-signature candidate profile.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey {
    pq: [u8; ML_DSA_65_VK_LEN],
    classic: [u8; CLASSIC_PUBLIC_BYTES],
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

impl PublicKey {
    pub(crate) fn shares_component(&self, other: &Self) -> bool {
        self.pq == other.pq || self.classic == other.classic
    }
    /// Parse one exact, canonical public-key pair; no algorithm negotiation.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let pq = decoder.array()?;
        let classic = decoder.array()?;
        decoder.finish()?;
        let key = VerifyingKey::from_sec1_bytes(&classic).map_err(|_| Error::Encoding)?;
        if key.to_sec1_point(true).as_bytes() != classic {
            return Err(Error::Encoding);
        }
        Ok(Self { pq, classic })
    }

    /// Return public key bytes in the fixed candidate encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(PUBLIC_KEY_BYTES);
        result.extend_from_slice(&self.pq);
        result.extend_from_slice(&self.classic);
        result
    }

    pub(crate) fn verify(
        &self,
        purpose: Purpose,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let bound = signed_message(purpose, body)?;
        let mut decoder = Decoder::new(signature);
        let pq_signature = decoder.take(ML_DSA_65_SIG_LEN)?;
        let classic_signature = decoder.take(CLASSIC_SIGNATURE_BYTES)?;
        decoder.finish()?;
        let classic_signature =
            Signature::from_slice(classic_signature).map_err(|_| Error::Authentication)?;
        // One canonical signature representation: reject high-s aliases.
        if classic_signature.normalize_s() != classic_signature {
            return Err(Error::Authentication);
        }
        let key = VerifyingKey::from_sec1_bytes(&self.classic).map_err(|_| Error::Encoding)?;
        key.verify(&bound, &classic_signature)
            .map_err(|_| Error::Authentication)?;
        MlDsa65
            .verify_ctx(&self.pq, &bound, SIGNATURE_CONTEXT, pq_signature)
            .map_err(|_| Error::Authentication)
    }
}

fn signed_message(purpose: Purpose, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_SIGNED_BODY_BYTES {
        return Err(Error::Capacity);
    }
    let length = u32::try_from(body.len()).map_err(|_| Error::Capacity)?;
    let mut message = Vec::with_capacity(SIGNATURE_CONTEXT.len() + 5 + body.len());
    message.extend_from_slice(SIGNATURE_CONTEXT);
    message.push(purpose as u8);
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

pub(crate) fn envelope(body: &[u8], signature: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_SIGNED_BODY_BYTES || signature.len() != SIGNATURE_BYTES {
        return Err(Error::Capacity);
    }
    let length = u32::try_from(body.len()).map_err(|_| Error::Capacity)?;
    let mut wire = Vec::with_capacity(4 + body.len() + signature.len());
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(body);
    wire.extend_from_slice(signature);
    Ok(wire)
}

pub(crate) fn open_envelope(wire: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if wire.len() > 4 + MAX_SIGNED_BODY_BYTES + SIGNATURE_BYTES {
        return Err(Error::Capacity);
    }
    let mut decoder = Decoder::new(wire);
    let length =
        usize::try_from(u32::from_be_bytes(decoder.array()?)).map_err(|_| Error::Encoding)?;
    if length > MAX_SIGNED_BODY_BYTES {
        return Err(Error::Capacity);
    }
    let body = decoder.take(length)?;
    let signature = decoder.take(SIGNATURE_BYTES)?;
    decoder.finish()?;
    Ok((body, signature))
}

pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

struct Material {
    pq: Box<ZeroizingBytes<ML_DSA_65_SK_LEN>>,
    classic: Box<SigningKey>,
    public: PublicKey,
}

struct SigningSeed {
    pq: ZeroizingBytes<32>,
    classic: ZeroizingBytes<32>,
}
impl SigningSeed {
    fn generate() -> Result<Self, Error> {
        // Rejection sampling preserves the scalar distribution. A failed source
        // or exhausted bounded sampling attempt produces no signing owner.
        for _ in 0..8 {
            let mut classic_seed = ZeroizingBytes::<32>::zeroed();
            getrandom::fill(classic_seed.as_mut_bytes()).map_err(|_| Error::Entropy)?;
            if SigningKey::from_slice(classic_seed.as_bytes()).is_ok() {
                let mut pq_seed = ZeroizingBytes::<32>::zeroed();
                getrandom::fill(pq_seed.as_mut_bytes()).map_err(|_| Error::Entropy)?;
                return Ok(Self {
                    pq: pq_seed,
                    classic: classic_seed,
                });
            }
        }
        Err(Error::Provider)
    }

    fn materialize(&self) -> Result<Material, Error> {
        let classic =
            SigningKey::from_slice(self.classic.as_bytes()).map_err(|_| Error::Encoding)?;
        Material::from_seed(ZeroizingBytes::from_bytes(*self.pq.as_bytes()), classic)
    }
}

impl Material {
    fn generate() -> Result<Self, Error> {
        SigningSeed::generate()?.materialize()
    }

    fn from_seed(pq_seed: ZeroizingBytes<32>, classic: SigningKey) -> Result<Self, Error> {
        let (mut expanded, pq_public) = MlDsa65::generate(*pq_seed.as_bytes());
        let mut pq = Box::new(ZeroizingBytes::zeroed());
        pq.as_mut_bytes().copy_from_slice(&expanded);
        expanded.zeroize();
        let classic_public = classic
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Provider)?;
        Ok(Self {
            pq,
            classic: Box::new(classic),
            public: PublicKey {
                pq: pq_public,
                classic: classic_public,
            },
        })
    }

    fn sign(&self, purpose: Purpose, body: &[u8]) -> Result<Vec<u8>, Error> {
        let message = signed_message(purpose, body)?;
        let mut randomness = ZeroizingBytes::<ML_DSA_65_SIGN_RAND_LEN>::zeroed();
        getrandom::fill(randomness.as_mut_bytes()).map_err(|_| Error::Entropy)?;
        self.sign_message(&message, &randomness)
    }

    fn sign_with(
        &self,
        purpose: Purpose,
        body: &[u8],
        randomness: &ZeroizingBytes<ML_DSA_65_SIGN_RAND_LEN>,
    ) -> Result<Vec<u8>, Error> {
        let message = signed_message(purpose, body)?;
        self.sign_message(&message, randomness)
    }

    fn sign_message(
        &self,
        message: &[u8],
        randomness: &ZeroizingBytes<ML_DSA_65_SIGN_RAND_LEN>,
    ) -> Result<Vec<u8>, Error> {
        let mut pq_signature = [0u8; ML_DSA_65_SIG_LEN];
        let written = MlDsa65
            .sign_ctx(
                self.pq.as_bytes(),
                message,
                SIGNATURE_CONTEXT,
                randomness.as_bytes(),
                &mut pq_signature,
            )
            .map_err(|_| Error::Provider)?;
        if written != ML_DSA_65_SIG_LEN {
            return Err(Error::Provider);
        }
        let signature: Signature = self
            .classic
            .try_sign(message)
            .map_err(|_| Error::Provider)?;
        let canonical = signature.normalize_s();
        let mut result = Vec::with_capacity(SIGNATURE_BYTES);
        result.extend_from_slice(&pq_signature);
        result.extend_from_slice(&canonical.to_bytes());
        Ok(result)
    }
}

/// Owned account-root signer. It has no raw-key export or arbitrary-message API.
pub struct RootSigningKey(Option<Material>);

/// Owned device signer, distinct from the authority allowed to enroll devices.
pub struct DeviceSigningKey(Option<Material>);

// Private authenticated-journal representation, never a public raw-coin API.
// Its binding covers the signer, operation, purpose and complete signed message.
pub(crate) struct SigningReservation {
    binding: [u8; 32],
    randomness: ZeroizingBytes<ML_DSA_65_SIGN_RAND_LEN>,
}
impl SigningReservation {
    fn binding(
        key: &PublicKey,
        operation: &[u8; 32],
        purpose: Purpose,
        body: &[u8],
    ) -> Result<[u8; 32], Error> {
        let mut bytes = key.encode();
        bytes.extend_from_slice(operation);
        bytes.extend_from_slice(&signed_message(purpose, body)?);
        Ok(digest(
            b"Q-PERIAPT-CONTINUITY-SIGNING-RESERVATION/v1",
            &bytes,
        ))
    }
    pub(crate) fn reserve(
        key: &PublicKey,
        operation: &[u8; 32],
        purpose: Purpose,
        body: &[u8],
    ) -> Result<Self, Error> {
        let binding = Self::binding(key, operation, purpose, body)?;
        let mut randomness = ZeroizingBytes::zeroed();
        getrandom::fill(randomness.as_mut_bytes()).map_err(|_| Error::Entropy)?;
        Ok(Self {
            binding,
            randomness,
        })
    }
    pub(crate) fn encode(&self, out: &mut zeroize::Zeroizing<Vec<u8>>) {
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(self.randomness.as_bytes());
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let binding = d.array()?;
        let mut randomness = ZeroizingBytes::zeroed();
        randomness
            .as_mut_bytes()
            .copy_from_slice(d.take(ML_DSA_65_SIGN_RAND_LEN)?);
        d.finish()?;
        Ok(Self {
            binding,
            randomness,
        })
    }
    pub(crate) fn sign(
        &self,
        key: &DeviceSigningKey,
        operation: &[u8; 32],
        purpose: Purpose,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let material = key.0.as_ref().ok_or(Error::Closed)?;
        if self.binding != Self::binding(&material.public, operation, purpose, body)? {
            return Err(Error::Scope);
        }
        material.sign_with(purpose, body, &self.randomness)
    }
}

/// Owned application protocol-policy signer, distinct from account and device roles.
pub struct PolicySigningKey(Option<Material>);

/// Owned witness signer, separate from account/device/protocol-policy roles.
pub struct AnchorSigningKey(Option<Material>);

macro_rules! owner {
    ($name:ident, $role:expr) => {
        impl $name {
            /// Generate fresh independent signing keys with platform randomness.
            pub fn generate() -> Result<Self, Error> {
                Ok(Self(Some(Material::generate()?)))
            }

            /// Generate into a new encrypted private file and sync it before
            /// returning an owner. Retain `identity` independently before calling.
            /// Existing files are never replaced; keep the wrapping key separate.
            pub fn provision(
                path: &std::path::Path,
                wrapping: &crate::JournalKey,
                identity: SigningKeyId,
            ) -> Result<Self, crate::DurableError> {
                persistence::provision(path, wrapping, identity, $role)
                    .map(|material| Self(Some(material)))
            }

            /// Authenticate an existing exact role/identity, reconstruct and check
            /// both public components, and sync the file before returning an owner.
            /// Missing or partial files never cause replacement key generation.
            pub fn open(
                path: &std::path::Path,
                wrapping: &crate::JournalKey,
                identity: SigningKeyId,
            ) -> Result<Self, crate::DurableError> {
                persistence::open(path, wrapping, identity, $role)
                    .map(|material| Self(Some(material)))
            }

            /// Obtain only the public key pair of an open owner.
            pub fn public_key(&self) -> Result<PublicKey, Error> {
                Ok(self.0.as_ref().ok_or(Error::Closed)?.public.clone())
            }

            /// Close the owner and erase its secret storage; repeated close is valid.
            pub fn close(&mut self) {
                self.0 = None;
            }

            pub(crate) fn sign(&self, purpose: Purpose, body: &[u8]) -> Result<Vec<u8>, Error> {
                self.0.as_ref().ok_or(Error::Closed)?.sign(purpose, body)
            }

            #[cfg(test)]
            pub(crate) fn deterministic(pq: [u8; 32], classic: [u8; 32]) -> Result<Self, Error> {
                let classic_seed = ZeroizingBytes::from_bytes(classic);
                let classic =
                    SigningKey::from_slice(classic_seed.as_bytes()).map_err(|_| Error::Encoding)?;
                Ok(Self(Some(Material::from_seed(
                    ZeroizingBytes::from_bytes(pq),
                    classic,
                )?)))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("closed", &self.0.is_none())
                    .finish_non_exhaustive()
            }
        }
    };
}
owner!(RootSigningKey, 1);
owner!(DeviceSigningKey, 2);
owner!(PolicySigningKey, 3);
owner!(AnchorSigningKey, 4);

impl DeviceSigningKey {
    /// Require this live controlled signer to match an independently verified
    /// device credential. This checks key identity only; current policy, roster,
    /// time and durable admission remain the caller's separate obligations.
    pub fn check_device(&self, device: &crate::VerifiedDevice) -> Result<(), Error> {
        if self.public_key()? != device.key {
            return Err(Error::Scope);
        }
        Ok(())
    }
}
