// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Platform-random, sealed KEM operation reservations.
//!
//! The integrating service must durably reserve the operation before execution,
//! and reconcile unknown commits before replay. This module authenticates the
//! exact policy, operation ID, kind and inputs; it does not implement a journal,
//! one-time consumption, rollback detection or protocol freshness. A replay is
//! the same operation, never permission to reuse randomness for a new connection.
//!
//! Only the sealing key is imported from a trusted host keystore. KEM randomness
//! is generated internally; no public API accepts plaintext coins or a custom RNG.
//! A host controlling the sealing key can forge records, so this boundary assumes
//! the same trusted host as the SDK runtime and private-key transfer API.

use crate::{check_context, Encapsulation, Error, HybridKey, PublicKey, Runtime};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use q_periapt_core::ZeroizingBytes;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"QPSOP001";
const BINDING_LEN: usize = 8 + 1 + 68 + 32 + 32;
const HEADER_LEN: usize = BINDING_LEN + 24;
const TAG_LEN: usize = 16;

#[derive(Clone, Copy)]
enum Kind {
    Generate = 1,
    Encapsulate = 2,
}
impl Kind {
    fn entropy_len(self) -> usize {
        match self {
            Self::Generate => 64 + 32,
            Self::Encapsulate => 32 + 32,
        }
    }
}

/// Encrypted reservation bytes. The header is public; private coins are sealed.
/// Parsing checks only format/size. Execution authenticates the complete binding.
pub struct SealedOperation(Vec<u8>);
impl SealedOperation {
    /// Read an exact versioned record from the protocol's authenticated storage.
    /// Malformed records are errors, never requests to generate fresh randomness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(Error::InvalidPrivateKey);
        }
        let kind = match bytes.get(MAGIC.len()) {
            Some(1) => Kind::Generate,
            Some(2) => Kind::Encapsulate,
            _ => return Err(Error::InvalidPrivateKey),
        };
        if bytes.len() != HEADER_LEN + kind.entropy_len() + TAG_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Exact encrypted bytes to persist together with the operation's state.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Non-cloneable sealing owner derived from a trusted 256-bit host storage key.
/// Closing it erases this owner, not external key copies or existing sealed files.
pub struct RecoveryKey(Option<Box<ZeroizingBytes<32>>>);
impl RecoveryKey {
    /// Import a CSPRNG-generated key from the host's protected storage/keystore.
    /// This is a wrapping key, never caller-supplied KEM entropy. The host must
    /// protect it separately from database backups; entropy quality is not inferred
    /// from its length. Domain derivation separates this use from other host storage.
    pub fn from_host_key(key: &[u8; 32]) -> Result<Self, Error> {
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(None, key);
        prk.zeroize();
        let mut derived = Box::new(ZeroizingBytes::zeroed());
        hkdf.expand(
            b"Q-PERIAPT-SDK-SEALED-OPERATIONS-KEY/v1",
            derived.as_mut_bytes(),
        )
        .map_err(|_| Error::Backend)?;
        Ok(Self(Some(derived)))
    }

    /// Revoke use of this owner and erase its local key allocation.
    pub fn close(&mut self) {
        self.0 = None;
    }

    /// Reserve platform randomness for one key-generation operation.
    /// Persist the returned record before calling `generate_key`.
    pub fn reserve_key(
        &self,
        runtime: &Runtime,
        operation_id: &[u8; 32],
    ) -> Result<SealedOperation, Error> {
        self.reserve(runtime, operation_id, Kind::Generate, &[0; 32])
    }

    /// Generate the exact reserved key in the specified verified runtime.
    /// Reopening with the same policy is supported; key quota and runtime close
    /// still apply. No new randomness is drawn during this computation.
    pub fn generate_key(
        &self,
        runtime: &Runtime,
        operation_id: &[u8; 32],
        operation: &SealedOperation,
    ) -> Result<HybridKey, Error> {
        let entropy = self.open(runtime, operation_id, Kind::Generate, &[0; 32], operation)?;
        let mut remaining = entropy.as_slice();
        let key = runtime.generate_with(|out| take(&mut remaining, out))?;
        if !remaining.is_empty() {
            return Err(Error::Backend);
        }
        Ok(key)
    }

    /// Reserve an encapsulation for the exact recipient key and application context.
    /// These inputs must already be known; a token cannot be moved to a different
    /// peer, context, operation ID, signed policy or operation kind.
    pub fn reserve_encapsulation(
        &self,
        runtime: &Runtime,
        operation_id: &[u8; 32],
        peer: &PublicKey,
        application_context: &[u8],
    ) -> Result<SealedOperation, Error> {
        let inputs = encapsulation_binding(peer, application_context)?;
        self.reserve(runtime, operation_id, Kind::Encapsulate, &inputs)
    }

    /// Recompute exactly one reserved encapsulation, retaining the SDK's existing
    /// ContextBound combiner, validation, runtime admission and secret ownership.
    pub fn encapsulate(
        &self,
        runtime: &Runtime,
        operation_id: &[u8; 32],
        peer: &PublicKey,
        application_context: &[u8],
        operation: &SealedOperation,
    ) -> Result<Encapsulation, Error> {
        let inputs = encapsulation_binding(peer, application_context)?;
        let entropy = self.open(runtime, operation_id, Kind::Encapsulate, &inputs, operation)?;
        let mut remaining = entropy.as_slice();
        let result =
            runtime.encapsulate_with(peer, application_context, |out| take(&mut remaining, out))?;
        if !remaining.is_empty() {
            return Err(Error::Backend);
        }
        Ok(result)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, Error> {
        let key = self.0.as_ref().ok_or(Error::Closed)?;
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::Backend)
    }

    fn reserve(
        &self,
        runtime: &Runtime,
        operation: &[u8; 32],
        kind: Kind,
        inputs: &[u8; 32],
    ) -> Result<SealedOperation, Error> {
        let _admission = runtime.state.begin()?;
        let cipher = self.cipher()?;
        let mut wire = binding(runtime, operation, kind, inputs)?;
        let mut entropy = Zeroizing::new(vec![0; kind.entropy_len()]);
        getrandom::fill(&mut entropy).map_err(|_| Error::Entropy)?;
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
        wire.extend_from_slice(&nonce);
        let tag = cipher
            .encrypt_inout_detached(&XNonce::from(nonce), &wire, entropy.as_mut_slice().into())
            .map_err(|_| Error::Backend)?;
        wire.extend_from_slice(&entropy);
        wire.extend_from_slice(&tag);
        Ok(SealedOperation(wire))
    }

    fn open(
        &self,
        runtime: &Runtime,
        operation: &[u8; 32],
        kind: Kind,
        inputs: &[u8; 32],
        sealed: &SealedOperation,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let cipher = self.cipher()?;
        let expected = binding(runtime, operation, kind, inputs)?;
        let bytes = sealed.as_bytes();
        if bytes.len() != HEADER_LEN + kind.entropy_len() + TAG_LEN
            || bytes.get(..BINDING_LEN) != Some(expected.as_slice())
        {
            return Err(Error::InvalidPrivateKey);
        }
        let header = bytes.get(..HEADER_LEN).ok_or(Error::InvalidLength)?;
        let nonce: [u8; 24] = header
            .get(BINDING_LEN..)
            .ok_or(Error::InvalidLength)?
            .try_into()
            .map_err(|_| Error::InvalidLength)?;
        let (payload, tag) = bytes
            .get(HEADER_LEN..)
            .ok_or(Error::InvalidLength)?
            .split_at(kind.entropy_len());
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::InvalidLength)?;
        let mut entropy = Zeroizing::new(payload.to_vec());
        cipher
            .decrypt_inout_detached(
                &XNonce::from(nonce),
                header,
                entropy.as_mut_slice().into(),
                &Tag::from(tag),
            )
            .map_err(|_| Error::InvalidPrivateKey)?;
        Ok(entropy)
    }
}

fn take(remaining: &mut &[u8], out: &mut [u8]) -> Result<(), Error> {
    let prefix = remaining.get(..out.len()).ok_or(Error::Backend)?;
    out.copy_from_slice(prefix);
    *remaining = remaining.get(out.len()..).ok_or(Error::Backend)?;
    Ok(())
}

fn binding(
    runtime: &Runtime,
    operation: &[u8; 32],
    kind: Kind,
    inputs: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if operation == &[0; 32] {
        return Err(Error::InvalidLength);
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.push(kind as u8);
    bytes.extend_from_slice(&runtime.policy_binding()?);
    bytes.extend_from_slice(operation);
    bytes.extend_from_slice(inputs);
    Ok(bytes)
}

fn encapsulation_binding(peer: &PublicKey, context: &[u8]) -> Result<[u8; 32], Error> {
    check_context(context)?;
    let mut digest = Sha256::new();
    digest.update(b"Q-PERIAPT-SDK-SEALED-ENCAPSULATION-INPUT/v1");
    digest.update(peer.to_bytes());
    digest.update((context.len() as u32).to_be_bytes());
    digest.update(context);
    Ok(digest.finalize().into())
}
