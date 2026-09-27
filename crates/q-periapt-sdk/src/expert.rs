// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit plaintext transfer of expanded ContextBound private keys.
//! No encryption, storage authentication, entropy certification or permission to
//! reuse ephemeral keys is implied. Imports bind to a separately verified runtime.

use crate::{reserve, Error, HybridKey, KeyLease, KeyMaterial, PublicKey, Runtime};
use q_periapt_backends::{ExpandedKeyImportError, MlKem768, ML_KEM_768_SK_LEN, X25519};
use q_periapt_core::ZeroizingBytes;
use std::sync::Arc;

// QPK + format version 1, suite 1, ContextBound 2, expanded 1, reserved 0.
const HEADER: [u8; 8] = [b'Q', b'P', b'K', 1, 1, 2, 1, 0];
/// Exact transfer size: 8-byte format header, 2400-byte ML-KEM key, 32-byte X25519 scalar.
pub const EXPANDED_KEY_LEN: usize = HEADER.len() + ML_KEM_768_SK_LEN + 32;

/// One explicit private-key export. Its heap storage is erased on drop/close.
/// No clone, debug, serialization or plaintext persistence implementation is supplied.
pub struct ExportedKey {
    bytes: Box<ZeroizingBytes<EXPANDED_KEY_LEN>>,
}
impl ExportedKey {
    /// Borrow the explicitly exported plaintext. Copies are the caller's responsibility.
    pub fn as_bytes(&self) -> &[u8; EXPANDED_KEY_LEN] {
        self.bytes.as_bytes()
    }
    /// Erase the export immediately. Re-importing the cleared representation fails.
    pub fn close(&mut self) {
        self.bytes.clear();
    }
}

/// Export an open hybrid key in the fixed expanded format. All external copies
/// remain usable after runtime revocation; the application must protect/erase them.
pub fn export_expanded(key: &HybridKey) -> Result<ExportedKey, Error> {
    let material = key.material.as_ref().ok_or(Error::Closed)?;
    let _operation = material.lease.0.begin()?;
    let mut bytes = Box::new(ZeroizingBytes::<EXPANDED_KEY_LEN>::zeroed());
    let (header, payload) = bytes.as_mut_bytes().split_at_mut(HEADER.len());
    header.copy_from_slice(&HEADER);
    let (pq, traditional) = payload.split_at_mut(ML_KEM_768_SK_LEN);
    material
        .pq
        .export_expanded_for_expert(pq.try_into().map_err(|_| Error::Backend)?);
    traditional.copy_from_slice(material.traditional.as_bytes());
    Ok(ExportedKey { bytes })
}

/// Import plaintext into a separately verified runtime. Reconstructs both public
/// keys, uses fresh platform coins for ML-KEM pairwise validation, and never
/// accepts this format as a seed-derived/X-Wing key or as an authorization token.
pub fn import_expanded(runtime: &Runtime, bytes: &[u8]) -> Result<HybridKey, Error> {
    import_with(runtime, bytes, |out| {
        getrandom::fill(out).map_err(|_| Error::Entropy)
    })
}

pub(super) fn import_with(
    runtime: &Runtime,
    bytes: &[u8],
    mut rng: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<HybridKey, Error> {
    let _operation = runtime.state.begin()?;
    if bytes.len() != EXPANDED_KEY_LEN {
        return Err(Error::InvalidLength);
    }
    let (header, payload) = bytes.split_at(HEADER.len());
    if header != HEADER {
        return Err(Error::InvalidPrivateKey);
    }
    reserve(&runtime.state.keys, runtime.state.limits.max_live_keys)?;
    let lease = KeyLease(Arc::clone(&runtime.state));
    let (pq, traditional) = payload.split_at(ML_KEM_768_SK_LEN);
    let mut decapsulation_key = Box::new(ZeroizingBytes::<ML_KEM_768_SK_LEN>::zeroed());
    decapsulation_key.as_mut_bytes().copy_from_slice(pq);
    let mut scalar = Box::new(ZeroizingBytes::<32>::zeroed());
    scalar.as_mut_bytes().copy_from_slice(traditional);
    let mut coins = ZeroizingBytes::<32>::zeroed();
    rng(coins.as_mut_bytes())?;
    let pq = MlKem768::import_expanded_for_expert(decapsulation_key, coins.as_bytes()).map_err(
        |error| match error {
            ExpandedKeyImportError::InvalidKey => Error::InvalidPrivateKey,
            ExpandedKeyImportError::ResourceLimit => Error::ResourceLimit,
            ExpandedKeyImportError::Backend => Error::Backend,
        },
    )?;
    let public = PublicKey {
        pq: *pq.encapsulation_key(),
        traditional: X25519::public_key(scalar.as_bytes()),
    };
    Ok(HybridKey {
        material: Some(KeyMaterial {
            pq,
            traditional: scalar,
            public,
            lease,
        }),
    })
}
