// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit protocol integration with owned ContextBound keys.
//! Role-typed component borrowing does not export private bytes. Expanded-key
//! transfer is a separate, explicit plaintext operation.
//! No encryption, storage authentication, entropy certification or permission to
//! reuse ephemeral keys is implied. Imports bind to a separately verified runtime.

use crate::{
    check_context, reserve, Ciphertext, Error, HybridKey, KeyLease, KeyMaterial, PublicKey,
    Runtime, SharedSecret,
};
use q_periapt_backends::{ExpandedKeyImportError, MlKem768, ML_KEM_768_SK_LEN, X25519};
use q_periapt_core::ZeroizingBytes;
use q_periapt_kem::{PqCiphertext, TradCiphertext, TradPublicKey, TradSecretKey};
use std::sync::Arc;

/// Borrow only an owner's PQ component for an explicit protocol operation.
/// The owner and its runtime remain responsible for storage and revocation.
#[derive(Clone, Copy)]
pub struct PqKeySource<'a>(&'a HybridKey);
impl<'a> PqKeySource<'a> {
    /// Select the PQ component without exporting or cloning its secret storage.
    pub fn from_key(key: &'a HybridKey) -> Self {
        Self(key)
    }
}

/// Borrow only an owner's traditional component, distinct from the PQ role.
#[derive(Clone, Copy)]
pub struct TraditionalKeySource<'a>(&'a HybridKey);
impl<'a> TraditionalKeySource<'a> {
    /// Select the traditional component without exporting private bytes.
    pub fn from_key(key: &'a HybridKey) -> Self {
        Self(key)
    }
}

fn component_material<'a, 'b>(
    runtime: &Runtime,
    pq: PqKeySource<'a>,
    traditional: TraditionalKeySource<'b>,
) -> Result<(&'a KeyMaterial, &'b KeyMaterial), Error> {
    let pq = pq.0.material.as_ref().ok_or(Error::Closed)?;
    let traditional = traditional.0.material.as_ref().ok_or(Error::Closed)?;
    // Exact runtime identity preserves one admission budget and one revocation
    // authority for the resulting SharedSecret. Equal policy bytes alone would
    // not make independent runtime lifetimes interchangeable.
    if !Arc::ptr_eq(&pq.lease.0, &traditional.lease.0) || !Arc::ptr_eq(&pq.lease.0, &runtime.state)
    {
        return Err(Error::PolicyDenied);
    }
    pq.lease.0.ensure_open()?;
    Ok((pq, traditional))
}

/// Compose the public key corresponding to two explicitly selected components.
/// Both owners must belong to the specified runtime, not merely equivalent policies.
/// This grants no protocol-level key reuse or one-time consumption permission.
///
/// ```compile_fail
/// use q_periapt_sdk::{expert, HybridKey, Runtime};
/// fn reversed(runtime: &Runtime, key: &HybridKey) {
///     expert::component_public_key(
///         runtime,
///         expert::TraditionalKeySource::from_key(key),
///         expert::PqKeySource::from_key(key),
///     );
/// }
/// ```
pub fn component_public_key(
    runtime: &Runtime,
    pq: PqKeySource<'_>,
    traditional: TraditionalKeySource<'_>,
) -> Result<PublicKey, Error> {
    let (pq, traditional) = component_material(runtime, pq, traditional)?;
    Ok(PublicKey {
        pq: pq.public.pq,
        traditional: traditional.public.traditional,
    })
}

/// Decapsulate against explicitly selected owned components in one runtime.
///
/// The same ContextBound implementation binds both selected public keys and
/// ciphertexts. Private key bytes remain inside the owners; the operation uses
/// one admission slot, and the result retains their shared runtime revocation.
/// Invalid PQ ciphertexts preserve implicit rejection. Protocol authentication,
/// key-use policy and atomic prekey consumption remain the protocol's duties.
pub fn decapsulate_components(
    runtime: &Runtime,
    pq: PqKeySource<'_>,
    traditional: TraditionalKeySource<'_>,
    ciphertext: &Ciphertext,
    application_context: &[u8],
) -> Result<SharedSecret, Error> {
    let (pq, traditional) = component_material(runtime, pq, traditional)?;
    let _operation = pq.lease.0.begin()?;
    check_context(application_context)?;
    let secret = pq.lease.0.kem()?.decapsulate_prepared(
        &pq.pq,
        PqCiphertext::new(&ciphertext.pq),
        TradSecretKey::new(traditional.traditional.as_bytes()),
        TradCiphertext::new(&ciphertext.traditional),
        TradPublicKey::new(&traditional.public.traditional),
        application_context,
    )?;
    Ok(SharedSecret {
        inner: Some(secret),
        state: Arc::clone(&pq.lease.0),
    })
}

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
