// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent SDK policy role using the existing protected signing-file owner.
use super::{persistence, Material, SigningKeyId};
use crate::{DurableError, Error, JournalKey};
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_policy::{policy_signature_message, Policy, MAX_SIGNED_POLICY_BYTES};
use std::{fmt, path::Path};

const ROLE: u8 = 5;

/// Protected SDK policy signer, distinct from all Continuity signing roles.
///
/// It signs only validated SDK policy documents, using the SDK's established
/// ML-DSA-65 encoding and empty external context. The existing encrypted signing
/// file retains its two-seed format; only its PQ component is exposed or used by
/// this role. No hybrid signature or protocol-signing capability is granted.
/// Version allocation, retained requests and authorization belong to the issuer.
pub struct SdkPolicySigningKey(Option<Material>);

impl SdkPolicySigningKey {
    /// Publish a new private signing file before returning a capability.
    /// Retain the independent file identity before calling; existing files fail.
    pub fn provision(
        path: &Path,
        wrapping: &JournalKey,
        identity: SigningKeyId,
    ) -> Result<Self, DurableError> {
        persistence::provision(path, wrapping, identity, ROLE).map(|material| Self(Some(material)))
    }

    /// Reopen only the original role and identity; never regenerate missing keys.
    pub fn open(
        path: &Path,
        wrapping: &JournalKey,
        identity: SigningKeyId,
    ) -> Result<Self, DurableError> {
        persistence::open(path, wrapping, identity, ROLE).map(|material| Self(Some(material)))
    }

    /// Raw ML-DSA-65 root verification key expected by the existing SDK.
    pub fn public_key(&self) -> Result<[u8; ML_DSA_65_VK_LEN], Error> {
        Ok(self.0.as_ref().ok_or(Error::Closed)?.public.pq)
    }

    /// Sign the exact validated SDK policy bytes, then verify before release.
    /// This does not select consumer trust or provide a monotonic issuance ledger.
    pub fn sign_policy(&self, document: &[u8]) -> Result<Vec<u8>, Error> {
        let material = self.0.as_ref().ok_or(Error::Closed)?;
        if document.is_empty() || document.len() > MAX_SIGNED_POLICY_BYTES {
            return Err(Error::Encoding);
        }
        let text = std::str::from_utf8(document).map_err(|_| Error::Encoding)?;
        let policy = Policy::from_toml(text).map_err(|_| Error::Encoding)?;
        if policy.min_nist_level() > 3 {
            return Err(Error::Scope);
        }
        let mut randomness = ZeroizingBytes::<ML_DSA_65_SIGN_RAND_LEN>::zeroed();
        getrandom::fill(randomness.as_mut_bytes()).map_err(|_| Error::Entropy)?;
        let message = policy_signature_message(document);
        let mut signature = vec![0; ML_DSA_65_SIG_LEN];
        let written = MlDsa65
            .sign_ctx(
                material.pq.as_bytes(),
                &message,
                &[],
                randomness.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Provider)?;
        if written != ML_DSA_65_SIG_LEN {
            return Err(Error::Provider);
        }
        Policy::load_signed(&MlDsa65, &material.public.pq, document, &signature)
            .map_err(|_| Error::Provider)?;
        Ok(signature)
    }

    /// Revoke this capability and clear its secret material; repeated close is valid.
    pub fn close(&mut self) {
        self.0 = None;
    }
}

impl fmt::Debug for SdkPolicySigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdkPolicySigningKey")
            .field("closed", &self.0.is_none())
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, unix))]
mod tests;
